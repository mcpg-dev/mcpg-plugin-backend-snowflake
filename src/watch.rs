//! `watch_strategy` entity (`snowflake_poll`) — the POLLING change-watch path.
//!
//! Snowflake has no native change-push channel, so this strategy polls a cheap
//! read-only scalar "high-water" query (`SELECT max(updated_at) FROM events`,
//! `SELECT count(*) FROM …`, a monotonic sequence, …) on a cadence and signals
//! a change whenever that scalar advances. The poll thread, the cursor diff, the
//! stop signal and the opaque handle round-trip all live in the shared
//! [`mcpg_plugin_sdk::watch`] helper — this entity only supplies the per-tick
//! `poll` closure over its own connection.
//!
//! `snowflake-api` is async (reqwest-based) and the `Arc<SnowflakeApi>` caches /
//! refreshes auth, so the client is built ONCE in [`watch`] and moved into the
//! closure; the helper's loop is synchronous, so a single current-thread tokio
//! runtime is held and `block_on`s one tracking query (max_rows=1) per tick
//! (sequential ticks, so a single-thread runtime is enough). Each tick is
//! wrapped in a per-tick `timeout_ms` budget. Connect / query failures map to
//! the closure's `Err(String)` — the helper logs and retries on the next tick.

use std::sync::Arc;
use std::time::Duration;

use mcpg_plugin_protocol::backend::WatchError;
use mcpg_plugin_protocol::{PluginManifest, firstparty_manifest};
use mcpg_plugin_sdk::HostHandle;
use mcpg_plugin_sdk::ffi::{SyncWatchStrategyPlugin, WatchHandleBox};
use mcpg_plugin_sdk::watch::{cancel_polling_watch, spawn_polling_watch};
use serde::Deserialize;
use serde_json::Value;

use crate::snowflake::{QueryOutcome, build_client, enforce_read_only, run_query};
use crate::types::{SnowflakeAuth, SnowflakeAuthMode};

pub const PLUGIN_ID: &str = "dev.mcpg.backend.snowflake";

/// The strategy discriminator this entity handles.
pub const WATCH_KIND: &str = "snowflake_poll";

/// Default poll cadence when `interval_ms` is omitted (1 minute).
fn default_interval_ms() -> u64 {
    60_000
}

/// Default per-tick query budget when `timeout_ms` is omitted (10 seconds).
fn default_timeout_ms() -> u64 {
    10_000
}

/// Per-watch spec: the connection + auth fields needed to build a client
/// (reusing the backend's connection shape: account / warehouse / database /
/// schema / role / auth) plus the read-only scalar high-water `tracking_query`
/// and the poll cadence. The connection is carried per-watch (not at plugin
/// level), so a watcher is self-contained.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchSpec {
    /// Snowflake account identifier (e.g. `xy12345.eu-central-1`). Determines
    /// the REST host. Operator-fixed (never caller-templated). REQUIRED.
    account: String,
    /// Default warehouse for the session.
    #[serde(default)]
    warehouse: Option<String>,
    /// Default database for the session.
    #[serde(default)]
    database: Option<String>,
    /// Default schema for the session.
    #[serde(default)]
    schema: Option<String>,
    /// Session role.
    #[serde(default)]
    role: Option<String>,
    /// Auth block (key-pair JWT or password), identical to the backend binding.
    auth: SnowflakeAuth,
    /// The read-only scalar high-water query whose first-row first-column value
    /// is the cursor (e.g. `SELECT max(updated_at) FROM events`). REQUIRED.
    tracking_query: String,
    /// Poll cadence in milliseconds (default 60000; floored by the SDK helper).
    #[serde(default = "default_interval_ms")]
    interval_ms: u64,
    /// Per-tick wall-clock query budget in milliseconds (default 10000).
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
}

/// `watch_strategy` entity. Stateless beyond its manifest — every watcher's
/// connection + tracking query arrive on the per-watch spec.
pub struct SnowflakeWatchCdylib {
    manifest: PluginManifest,
}

impl SnowflakeWatchCdylib {
    /// Infallible cdylib factory. `config_json` + host are ignored — the watch
    /// carries no plugin-level config (the connection + `tracking_query` arrive
    /// via the per-watch spec).
    pub fn from_host_config(_config_json: &str, _host: HostHandle) -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.snowflake",
                name: "Snowflake Poll Watch Strategy",
                class: WatchStrategy,
            },
        }
    }
}

/// Extract the cursor scalar from a high-water query outcome: the first column
/// of the first row, stringified. `None` when the query returned zero rows (no
/// signal this tick) or the first value is null. The first row may be a JSON
/// object (Arrow result sets, decoded by column name) or a JSON array
/// (passthrough JSON results); both are handled. JSON-string values yield the
/// bare string; everything else its JSON rendering, so the cursor comparison is
/// stable across ticks.
fn cursor_from_outcome(outcome: &QueryOutcome) -> Option<String> {
    let first = outcome.rows.first()?;
    let scalar = match first {
        Value::Object(map) => map.values().next()?,
        Value::Array(arr) => arr.first()?,
        // A bare scalar row (a non-array/object passthrough value) is itself the
        // cursor.
        other => other,
    };
    Some(match scalar {
        Value::String(s) => s.clone(),
        Value::Null => return None,
        other => other.to_string(),
    })
}

impl SyncWatchStrategyPlugin for SnowflakeWatchCdylib {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        WATCH_KIND
    }

    fn watch(
        &self,
        resource_uri: &str,
        spec: &Value,
        emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, WatchError> {
        let parsed: WatchSpec =
            serde_json::from_value(spec.clone()).map_err(|e| WatchError::InvalidSpec {
                message: format!("invalid snowflake_poll watch spec: {e}"),
            })?;

        let invalid = |m: String| WatchError::InvalidSpec { message: m };
        if parsed.account.trim().is_empty() {
            return Err(invalid("account must not be empty".into()));
        }
        if parsed.auth.username.trim().is_empty() {
            return Err(invalid("auth.username must not be empty".into()));
        }
        if parsed.tracking_query.trim().is_empty() {
            return Err(invalid("tracking_query must not be empty".into()));
        }
        // The tracking query is read-only by contract — reuse the backend guard
        // so a polling watcher can never mutate the warehouse.
        enforce_read_only(&parsed.tracking_query).map_err(invalid)?;

        // The secret used depends on the auth mode (mirrors the backend binding).
        let secret = match parsed.auth.mode {
            SnowflakeAuthMode::KeyPair => parsed.auth.private_key_pem.clone(),
            SnowflakeAuthMode::Password => parsed.auth.password.clone(),
        };
        // A bare per-caller `cred://` is rejected: the connection is one service
        // identity (matching the backend register guard).
        if secret.starts_with("cred://") {
            return Err(invalid(format!(
                "auth.{} must not be a cred:// URI — per-caller credentials are \
                 unsupported (the connection is one service identity); use ${{env.X}} / \
                 vault:// (resolved at config load) instead",
                match parsed.auth.mode {
                    SnowflakeAuthMode::KeyPair => "private_key_pem",
                    SnowflakeAuthMode::Password => "password",
                }
            )));
        }
        if secret.trim().is_empty() {
            return Err(invalid(format!(
                "auth.{} must not be empty for mode {}",
                match parsed.auth.mode {
                    SnowflakeAuthMode::KeyPair => "private_key_pem",
                    SnowflakeAuthMode::Password => "password",
                },
                parsed.auth.mode.as_str()
            )));
        }

        // Build the client ONCE — the Arc<SnowflakeApi> caches / refreshes auth
        // across ticks. Construction is pure (auth happens on the first exec);
        // a malformed account / key is a Subscribe failure.
        let api = build_client(
            &parsed.account,
            parsed.warehouse.as_deref(),
            parsed.database.as_deref(),
            parsed.schema.as_deref(),
            parsed.role.as_deref(),
            &parsed.auth.username,
            parsed.auth.mode,
            &secret,
        )
        .map_err(|e| WatchError::Subscribe {
            message: format!("snowflake_poll: client init failed: {e}"),
        })?;
        let api = Arc::new(api);

        // One current-thread runtime, moved into the closure: ticks are
        // sequential, so a single-thread runtime is enough to `block_on` each
        // async query.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| WatchError::Subscribe {
                message: format!("snowflake_poll: tokio runtime init failed: {e}"),
            })?;

        let tracking_query = parsed.tracking_query;
        let timeout = Duration::from_millis(parsed.timeout_ms);

        let poll = move || -> Result<Option<String>, String> {
            // Per-tick budget over auth + statement + read; Snowflake needs its
            // own timeout (run_query carries none).
            let outcome = rt.block_on(async {
                match tokio::time::timeout(timeout, run_query(&api, &tracking_query, 1)).await {
                    Ok(inner) => inner,
                    Err(_) => Err("snowflake_poll: tracking query timed out".to_owned()),
                }
            })?;
            Ok(cursor_from_outcome(&outcome))
        };

        Ok(spawn_polling_watch(
            resource_uri,
            Duration::from_millis(parsed.interval_ms),
            emit_event,
            poll,
        ))
    }

    fn cancel(&self, watch_handle: WatchHandleBox) {
        cancel_polling_watch(watch_handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn stub_host() -> HostHandle {
        // SAFETY: `stub_host_ref` returns a process-static no-op host ref; the
        // factory ignores the host entirely.
        #[allow(unsafe_code)]
        unsafe {
            HostHandle::from_ffi(mcpg_plugin_sdk::testing::stub_host_ref())
        }
    }

    fn plugin() -> SnowflakeWatchCdylib {
        SnowflakeWatchCdylib::from_host_config("", stub_host())
    }

    fn emit_noop() -> Box<dyn Fn(&str) + Send + Sync + 'static> {
        Box::new(|_| {})
    }

    fn minimal_spec() -> Value {
        json!({
            "account": "xy12345.eu-central-1",
            "auth": { "mode": "key_pair", "username": "svc", "private_key_pem": "dummy" },
            "tracking_query": "SELECT max(updated_at) FROM events",
        })
    }

    #[test]
    fn manifest_and_kind_are_correct() {
        use mcpg_plugin_protocol::PluginClass;
        let p = plugin();
        let m = SyncWatchStrategyPlugin::manifest(&p);
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.plugin_class, PluginClass::WatchStrategy);
        assert_eq!(p.kind(), WATCH_KIND);
    }

    #[test]
    fn spec_parses_with_defaults() {
        let parsed: WatchSpec = serde_json::from_value(minimal_spec()).unwrap();
        assert_eq!(parsed.interval_ms, 60_000);
        assert_eq!(parsed.timeout_ms, 10_000);
        assert!(parsed.warehouse.is_none());
        assert!(parsed.database.is_none());
        assert_eq!(parsed.auth.mode, SnowflakeAuthMode::KeyPair);
    }

    #[test]
    fn spec_parses_overrides() {
        let parsed: WatchSpec = serde_json::from_value(json!({
            "account": "acct",
            "warehouse": "WH",
            "database": "analytics",
            "schema": "PUBLIC",
            "role": "READER",
            "auth": { "mode": "password", "username": "reader", "password": "pw" },
            "tracking_query": "SELECT count(*) FROM events",
            "interval_ms": 30_000,
            "timeout_ms": 5_000,
        }))
        .unwrap();
        assert_eq!(parsed.warehouse.as_deref(), Some("WH"));
        assert_eq!(parsed.database.as_deref(), Some("analytics"));
        assert_eq!(parsed.role.as_deref(), Some("READER"));
        assert_eq!(parsed.auth.mode, SnowflakeAuthMode::Password);
        assert_eq!(parsed.auth.username, "reader");
        assert_eq!(parsed.interval_ms, 30_000);
        assert_eq!(parsed.timeout_ms, 5_000);
    }

    #[test]
    fn unknown_field_is_invalid_spec() {
        let p = plugin();
        let mut spec = minimal_spec();
        spec["bogus"] = json!(true);
        assert!(matches!(
            p.watch("snowflake://events", &spec, emit_noop()),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn empty_account_is_invalid_spec() {
        let p = plugin();
        let mut spec = minimal_spec();
        spec["account"] = json!("   ");
        assert!(matches!(
            p.watch("snowflake://events", &spec, emit_noop()),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn empty_tracking_query_is_invalid_spec() {
        let p = plugin();
        let mut spec = minimal_spec();
        spec["tracking_query"] = json!("   ");
        assert!(matches!(
            p.watch("snowflake://events", &spec, emit_noop()),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn non_read_only_tracking_query_is_invalid_spec() {
        let p = plugin();
        let mut spec = minimal_spec();
        spec["tracking_query"] = json!("INSERT INTO events VALUES (current_timestamp())");
        assert!(matches!(
            p.watch("snowflake://events", &spec, emit_noop()),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn bare_cred_secret_is_invalid_spec() {
        let p = plugin();
        let mut spec = minimal_spec();
        spec["auth"]["private_key_pem"] = json!("cred://x");
        assert!(matches!(
            p.watch("snowflake://events", &spec, emit_noop()),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn empty_secret_is_invalid_spec() {
        let p = plugin();
        let mut spec = minimal_spec();
        spec["auth"]["private_key_pem"] = json!("  ");
        assert!(matches!(
            p.watch("snowflake://events", &spec, emit_noop()),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn cursor_from_outcome_extracts_first_scalar_from_object_row() {
        // Arrow → JSON object row keyed by column name.
        let outcome = QueryOutcome {
            rows: vec![json!({ "MAX(UPDATED_AT)": "2026-06-23 10:00:00" })],
            truncated: false,
            row_count: 1,
        };
        assert_eq!(
            cursor_from_outcome(&outcome).as_deref(),
            Some("2026-06-23 10:00:00")
        );

        // A numeric high-water value stringifies to its JSON rendering.
        let outcome = QueryOutcome {
            rows: vec![json!({ "COUNT(*)": 42 })],
            truncated: false,
            row_count: 1,
        };
        assert_eq!(cursor_from_outcome(&outcome).as_deref(), Some("42"));
    }

    #[test]
    fn cursor_from_outcome_extracts_first_scalar_from_array_row() {
        // JSON passthrough rows are arrays — take the first column.
        let outcome = QueryOutcome {
            rows: vec![json!([99, "ignored"])],
            truncated: false,
            row_count: 1,
        };
        assert_eq!(cursor_from_outcome(&outcome).as_deref(), Some("99"));
    }

    #[test]
    fn cursor_from_outcome_none_on_zero_rows_or_null() {
        let empty = QueryOutcome {
            rows: vec![],
            truncated: false,
            row_count: 0,
        };
        assert_eq!(cursor_from_outcome(&empty), None);

        let null = QueryOutcome {
            rows: vec![json!({ "MAX(T)": Value::Null })],
            truncated: false,
            row_count: 1,
        };
        assert_eq!(cursor_from_outcome(&null), None);
    }
}
