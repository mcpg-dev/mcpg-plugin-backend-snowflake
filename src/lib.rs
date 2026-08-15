//! Snowflake cloud-warehouse backend binding plugin for mcpg.
//!
//! Implements [`SnowflakeBackendPlugin`] — `BackendPlugin` for
//! `kind: "snowflake"`. Runs one operator-fixed analytical SQL statement
//! against a Snowflake warehouse over the REST API and returns the rows (Arrow
//! result sets decoded to JSON). Auth is key-pair JWT or password, resolved
//! through the gateway secret-resolver. Snowflake-specific machinery lives in
//! [`snowflake`] + [`envelope`]. The driver is async (reqwest-based) and
//! authenticates on the first request, so the client is built lazily on first
//! `execute` (and cached) — `register_profile` never touches the network or
//! parses a key, and the unit tests run with a dummy key and no credentials.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{
    BackendError, BackendHost, BackendPlugin, BackendRequest, BackendResponse, PluginManifest,
    firstparty_manifest,
};
use mcpg_plugin_sdk::{HostHandle, SpanGuard};
use serde_json::{Value, json};
use tokio::sync::{OnceCell, RwLock};
use tracing::debug;

/// cdylib sync bridge.
pub mod cdylib;
mod envelope;
mod surface;
/// `watch_strategy` entity (`snowflake_poll`) — the polling change-watch path.
pub mod watch;
// The driver-facing module shadows the `snowflake_api` crate name only in
// `snowflake.rs`, which reaches the crate via its full path.
mod snowflake;
mod types;

use envelope::{build_result_envelope, classify_error};
use mcpg_plugin_protocol::ResourcePage;
use snowflake::{QueryOutcome, build_client, enforce_read_only, run_query};
pub use types::{
    ListQueryConfig as SnowflakeListQueryConfig, SnowflakeAuth, SnowflakeAuthMode,
    SnowflakeBackendSpec, SnowflakeOperation, SnowflakeQueryConfig, validate_list_query,
};
use types::{QUERY_ID_ARG, build_result_scan_sql, validate_query_id};

/// Embedded plugin descriptor.
pub const BINDING_DESCRIPTOR_YAML: &str = include_str!("../plugin.yaml");

// --------------------------------------------------------------------- obs

fn audit_action_for_outcome(label: &str) -> Option<&'static str> {
    match label {
        "timeout" => Some("dev.mcpg.backend.snowflake.request_timeout"),
        "transport_error" => Some("dev.mcpg.backend.snowflake.request_failed"),
        "snowflake_error" => Some("dev.mcpg.backend.snowflake.query_rejected"),
        "invalid_spec" => Some("dev.mcpg.backend.snowflake.request_failed"),
        _ => None,
    }
}

fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn synthetic_system_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "system".into(),
        trust_level: "verified".into(),
        subject_id: Some("dev.mcpg.backend.snowflake".into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: Default::default(),
    }
}

fn finalize_payload(envelope: Value) -> Result<BackendResponse, BackendError> {
    let payload = serde_json::to_vec(&envelope).map_err(|e| BackendError::Transport {
        message: format!("Snowflake plugin envelope serialization failed: {e}"),
    })?;
    Ok(BackendResponse {
        payload,
        truncated: false,
    })
}

// ------------------------------------------------------------------ plugin

/// Per-binding Snowflake runtime — connection parameters + the secret + the
/// statement, plus a lazily-built, cached REST client. The client is built on
/// first `execute` (parsing the key only then), so `register_profile` stays
/// offline. Cheap to clone (the `OnceCell` is shared behind `Arc`).
#[derive(Clone)]
struct SnowflakeProfile {
    account: String,
    warehouse: Option<String>,
    database: Option<String>,
    schema: Option<String>,
    role: Option<String>,
    username: String,
    auth_mode: SnowflakeAuthMode,
    /// The resolved secret (private key PEM, or password), per `auth_mode`.
    secret: String,
    operation: SnowflakeOperation,
    statement: String,
    read_only: bool,
    max_rows: usize,
    timeout: Duration,
    surface: surface::Surface,
    surface_uri: Option<String>,
    list_query: Option<SnowflakeListQueryConfig>,
    /// Built on first use; shared across calls.
    client: Arc<OnceCell<Arc<snowflake_api::SnowflakeApi>>>,
}

impl SnowflakeProfile {
    /// Return the cached client, building (and caching) it on first use. The
    /// build is pure (auth happens on the first `exec`), so this only errors on
    /// a malformed account / key.
    async fn client(&self) -> Result<Arc<snowflake_api::SnowflakeApi>, String> {
        self.client
            .get_or_try_init(|| async {
                let api = build_client(
                    &self.account,
                    self.warehouse.as_deref(),
                    self.database.as_deref(),
                    self.schema.as_deref(),
                    self.role.as_deref(),
                    &self.username,
                    self.auth_mode,
                    &self.secret,
                )?;
                Ok::<_, String>(Arc::new(api))
            })
            .await
            .cloned()
    }
}

/// `BackendPlugin` implementation for `kind: "snowflake"`.
pub struct SnowflakeBackendPlugin {
    manifest: PluginManifest,
    profiles: RwLock<BTreeMap<String, SnowflakeProfile>>,
    host_handle: OnceLock<HostHandle>,
}

impl Default for SnowflakeBackendPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl SnowflakeBackendPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.snowflake",
                name: "Snowflake Binding",
                class: Backend,
            },
            profiles: RwLock::new(BTreeMap::new()),
            host_handle: OnceLock::new(),
        }
    }

    pub fn set_host_handle(&self, host: HostHandle) -> bool {
        self.host_handle.set(host).is_ok()
    }

    fn host_handle(&self) -> Option<&HostHandle> {
        self.host_handle.get()
    }

    /// Per-call observability triad (latency + counter + optional audit).
    async fn emit_host_observability(
        &self,
        backend_name: &str,
        outcome_label: &'static str,
        reason: Option<&str>,
        identity: Option<&PluginIdentity>,
        request_id: &str,
        duration: Duration,
    ) {
        let Some(host) = self.host_handle() else {
            return;
        };
        host.histogram(
            "mcpg_snowflake_backend_latency_seconds",
            duration.as_secs_f64(),
            &[("outcome", outcome_label)],
        );
        host.counter(
            "mcpg_snowflake_backend_calls_total",
            1,
            &[("outcome", outcome_label)],
        );
        if let Some(action) = audit_action_for_outcome(outcome_label) {
            let actor = identity.cloned().unwrap_or_else(synthetic_system_identity);
            let mut details = json!({
                "backend": backend_name,
                "duration_ms": duration.as_millis() as u64,
                "outcome": outcome_label,
                "alias": host.alias(),
            });
            if let Some(reason) = reason {
                details
                    .as_object_mut()
                    .expect("json object")
                    .insert("reason".into(), Value::String(reason.to_owned()));
            }
            let event = AuditEvent {
                event_id: format!("snowflake-{}-{}", request_id, duration.as_nanos()),
                occurred_at: rfc3339_now(),
                actor,
                action: action.to_owned(),
                resource: Some(format!("snowflake-binding://{backend_name}")),
                outcome: AuditOutcome::Failure,
                request_id: Some(request_id.to_owned()),
                node_id: None,
                details,
                prev_event_hash: None,
            };
            let host_for_audit = host.clone();
            if let Err(join_err) = tokio::task::spawn_blocking(move || {
                let _ = host_for_audit.audit_event(event);
            })
            .await
            {
                debug!(target: "mcpg::snowflake::host_handle", error = %join_err, "audit spawn_blocking failed");
            }
        }
    }

    /// Build an error envelope, emit the triad, and return it as a normal
    /// payload — matching the oracle/mssql/http backends.
    #[allow(clippy::too_many_arguments)]
    async fn finish_error(
        &self,
        profile: &SnowflakeProfile,
        backend_name: &str,
        tool_name: &str,
        message: &str,
        label: &'static str,
        identity: Option<&PluginIdentity>,
        request_id: &str,
        started: Instant,
        host_span: Option<SpanGuard>,
    ) -> Result<BackendResponse, BackendError> {
        let downstream = classify_error(message);
        let envelope = build_result_envelope(
            tool_name,
            backend_name,
            &profile.account,
            profile.database.as_deref(),
            profile.schema.as_deref(),
            None,
            None,
            false,
            started.elapsed().as_millis(),
            Some(&downstream),
            Some(message),
        );
        self.emit_host_observability(
            backend_name,
            label,
            Some(message),
            identity,
            request_id,
            started.elapsed(),
        )
        .await;
        drop(host_span);
        finalize_payload(envelope)
    }
}

impl std::fmt::Debug for SnowflakeBackendPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnowflakeBackendPlugin")
            .field("id", &self.manifest.id)
            .finish()
    }
}

#[async_trait]
impl BackendPlugin for SnowflakeBackendPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        "snowflake"
    }

    async fn register_profile(
        &self,
        backend_name: &str,
        spec: &Value,
        _host: Arc<dyn BackendHost>,
    ) -> Result<(), BackendError> {
        let parsed: SnowflakeBackendSpec =
            serde_json::from_value(spec.clone()).map_err(|e| BackendError::InvalidSpec {
                message: format!("Snowflake binding spec: {e}"),
            })?;

        let invalid = |m: String| BackendError::InvalidSpec { message: m };
        if parsed.account.trim().is_empty() {
            return Err(invalid("account must not be empty".into()));
        }
        if parsed.auth.username.trim().is_empty() {
            return Err(invalid("auth.username must not be empty".into()));
        }
        // `result_scan` re-reads a prior result by query id (from the call
        // argument) and runs no operator-fixed statement, so `statement` is
        // required only for `operation: query`.
        if parsed.operation == SnowflakeOperation::Query && parsed.statement.trim().is_empty() {
            return Err(invalid(
                "statement must not be empty for operation: query".into(),
            ));
        }
        if parsed.query.statement_timeout_ms == 0 {
            return Err(invalid(
                "query.statement_timeout_ms must be greater than 0".into(),
            ));
        }
        if parsed.query.max_rows == 0 {
            return Err(invalid("query.max_rows must be greater than 0".into()));
        }

        // The secret used depends on the auth mode.
        let secret = match parsed.auth.mode {
            SnowflakeAuthMode::KeyPair => parsed.auth.private_key_pem.clone(),
            SnowflakeAuthMode::Password => parsed.auth.password.clone(),
        };
        // Per-caller `cred://` is unsupported (the connection is one service
        // identity). Point operators at the config secret-resolver.
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

        // Fail-closed read-only guard on the operator-fixed statement, validated
        // at registration (no network). `result_scan` runs no operator statement
        // and is inherently read-only (it only re-reads a prior result), so the
        // statement guard applies to `operation: query` only.
        if parsed.operation == SnowflakeOperation::Query && parsed.query.read_only {
            enforce_read_only(&parsed.statement).map_err(invalid)?;
        }

        // Surface coherence: `uri` is only meaningful on the resource surface;
        // a static `uri` on a tool/prompt binding is a config mistake worth a
        // fail-closed rejection at register rather than a silent no-op.
        if parsed.uri.is_some() && parsed.surface != surface::Surface::Resource {
            return Err(invalid(format!(
                "`uri` is only valid with `surface: resource` (this binding is `surface: {}`)",
                parsed.surface.as_str()
            )));
        }
        if let Some(u) = &parsed.uri
            && u.trim().is_empty()
        {
            return Err(invalid("`uri` must not be empty".into()));
        }

        // Listing is an operator-fixed read surface; fail-closed at register so
        // misconfig never reaches a `resources/list` call. The list statement
        // is also subject to the read-only guard when enabled.
        if let Some(lq) = &parsed.list_query {
            validate_list_query(lq).map_err(invalid)?;
            if parsed.query.read_only {
                enforce_read_only(&lq.sql).map_err(invalid)?;
            }
        }

        debug!(
            backend = %backend_name,
            account = %parsed.account,
            mode = parsed.auth.mode.as_str(),
            operation = parsed.operation.as_str(),
            read_only = parsed.query.read_only,
            "registered Snowflake binding profile"
        );

        self.profiles.write().await.insert(
            backend_name.to_owned(),
            SnowflakeProfile {
                account: parsed.account,
                warehouse: parsed.warehouse,
                database: parsed.database,
                schema: parsed.schema,
                role: parsed.role,
                username: parsed.auth.username,
                auth_mode: parsed.auth.mode,
                secret,
                operation: parsed.operation,
                statement: parsed.statement,
                read_only: parsed.query.read_only,
                max_rows: parsed.query.max_rows,
                timeout: Duration::from_millis(parsed.query.statement_timeout_ms),
                surface: parsed.surface,
                surface_uri: parsed.uri,
                list_query: parsed.list_query,
                client: Arc::new(OnceCell::new()),
            },
        );
        Ok(())
    }

    async fn execute(
        &self,
        backend_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        let started = Instant::now();
        let request_id = request.request_id.clone();
        let identity = request.identity.clone();
        let host_span = self.host_handle().map(|h| {
            h.span(
                "snowflake_backend.execute",
                json!({ "backend": backend_name, "request_id": request_id }),
            )
        });

        let profile = {
            let guard = self.profiles.read().await;
            match guard.get(backend_name).cloned() {
                Some(p) => p,
                None => {
                    let err = BackendError::ProfileNotFound {
                        backend_name: backend_name.to_owned(),
                    };
                    self.emit_host_observability(
                        backend_name,
                        "profile_not_found",
                        Some(&err.to_string()),
                        identity.as_ref(),
                        &request_id,
                        started.elapsed(),
                    )
                    .await;
                    drop(host_span);
                    return Err(err);
                }
            }
        };

        let tool_name = request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("mcpg-tool-name"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| backend_name.to_owned());

        // The statement is operator-fixed and caller args are not interpolated,
        // but the resource surface needs the requested `uri` the gateway passes
        // in the call arguments. Parse it best-effort (only used by the resource
        // surface; never reaches the SQL).
        let request_args: Value = if request.payload.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(&request.payload).unwrap_or_else(|_| json!({}))
        };

        // Resolve the SQL to run for this call. `query` runs the operator-fixed
        // statement verbatim (caller args are not interpolated); `result_scan`
        // re-fetches a prior result by the strictly-validated `query_id` call
        // argument, embedded as a quoted literal (the REST driver has no bind).
        let statement: String = match profile.operation {
            SnowflakeOperation::Query => {
                // The statement is operator-fixed; caller args are not
                // interpolated. Re-assert the read-only guard at call time as a
                // defense in depth.
                if profile.read_only
                    && let Err(message) = enforce_read_only(&profile.statement)
                {
                    return self
                        .finish_error(
                            &profile,
                            backend_name,
                            &tool_name,
                            &message,
                            "snowflake_error",
                            identity.as_ref(),
                            &request_id,
                            started,
                            host_span,
                        )
                        .await;
                }
                profile.statement.clone()
            }
            SnowflakeOperation::ResultScan => {
                let query_id = request_args
                    .get(QUERY_ID_ARG)
                    .and_then(Value::as_str)
                    .unwrap_or("");
                // Strict charset validation is the security boundary: the id is
                // embedded as a quoted SQL literal (no server-side bind), so a
                // non-id value is rejected before it can reach the SQL.
                if let Err(message) = validate_query_id(query_id) {
                    return self
                        .finish_error(
                            &profile,
                            backend_name,
                            &tool_name,
                            &message,
                            "snowflake_error",
                            identity.as_ref(),
                            &request_id,
                            started,
                            host_span,
                        )
                        .await;
                }
                build_result_scan_sql(query_id)
            }
        };

        // Build (or reuse) the cached client, then run the query under an
        // overall timeout covering auth + statement + read.
        let client = match profile.client().await {
            Ok(c) => c,
            Err(message) => {
                return self
                    .finish_error(
                        &profile,
                        backend_name,
                        &tool_name,
                        &message,
                        "snowflake_error",
                        identity.as_ref(),
                        &request_id,
                        started,
                        host_span,
                    )
                    .await;
            }
        };

        let result: Result<QueryOutcome, String> = match tokio::time::timeout(
            profile.timeout,
            run_query(&client, &statement, profile.max_rows),
        )
        .await
        {
            Ok(inner) => inner,
            Err(_) => Err("Snowflake call timed out".to_owned()),
        };

        let (envelope, outcome_label, audit_reason): (Value, &'static str, Option<String>) =
            match result {
                Ok(outcome) => {
                    // On the resource/prompt surfaces the gateway decoder
                    // requires a surface-shaped body; the tool surface keeps the
                    // historical envelope. A resource read with no resolvable URI
                    // falls back to the tool error envelope (carries
                    // `downstreamError` → gateway `is_error`) so the decoder sees
                    // a clean error rather than an invalid `{contents}`.
                    match profile.surface {
                        surface::Surface::Tool => (
                            build_result_envelope(
                                &tool_name,
                                backend_name,
                                &profile.account,
                                profile.database.as_deref(),
                                profile.schema.as_deref(),
                                Some(&outcome.rows),
                                Some(outcome.row_count),
                                outcome.truncated,
                                started.elapsed().as_millis(),
                                None,
                                None,
                            ),
                            "ok",
                            None,
                        ),
                        surface::Surface::Resource => {
                            match surface::resolve_resource_uri(
                                profile.surface_uri.as_deref(),
                                &request_args,
                            ) {
                                Some(uri) => (
                                    surface::resource_contents_body(uri, &outcome.rows),
                                    "ok",
                                    None,
                                ),
                                None => {
                                    let message = "resource surface requires a `uri` (set a static `uri` on the binding or invoke via a resources/read request)".to_owned();
                                    let downstream = classify_error(&message);
                                    let env = build_result_envelope(
                                        &tool_name,
                                        backend_name,
                                        &profile.account,
                                        profile.database.as_deref(),
                                        profile.schema.as_deref(),
                                        None,
                                        None,
                                        false,
                                        started.elapsed().as_millis(),
                                        Some(&downstream),
                                        Some(&message),
                                    );
                                    (env, "snowflake_error", Some(message))
                                }
                            }
                        }
                        surface::Surface::Prompt => {
                            (surface::prompt_messages_body(&outcome.rows), "ok", None)
                        }
                    }
                }
                Err(message) => {
                    let downstream = classify_error(&message);
                    let lower = message.to_ascii_lowercase();
                    let label = if lower.contains("timed out") || lower.contains("timeout") {
                        "timeout"
                    } else if downstream["kind"] == json!("transport_error") {
                        "transport_error"
                    } else {
                        "snowflake_error"
                    };
                    let env = build_result_envelope(
                        &tool_name,
                        backend_name,
                        &profile.account,
                        profile.database.as_deref(),
                        profile.schema.as_deref(),
                        None,
                        None,
                        false,
                        started.elapsed().as_millis(),
                        Some(&downstream),
                        Some(&message),
                    );
                    (env, label, Some(message))
                }
            };

        self.emit_host_observability(
            backend_name,
            outcome_label,
            audit_reason.as_deref(),
            identity.as_ref(),
            &request_id,
            started.elapsed(),
        )
        .await;
        drop(host_span);
        finalize_payload(envelope)
    }

    fn audit_metadata(&self, _backend_name: &str) -> serde_json::Map<String, Value> {
        let mut map = serde_json::Map::new();
        map.insert("snowflake.transport".to_owned(), json!("plugin"));
        map
    }

    /// JSON Schema for the fixed result envelope this binding emits.
    fn output_schema(&self, _backend_name: &str) -> Option<Value> {
        Some(envelope::result_envelope_schema())
    }

    /// JSON Schema for the tool arguments. For `operation: query` the statement
    /// is operator-fixed (no CEL `params` surface yet), so the schema is the
    /// permissive open object. For `operation: result_scan` the binding surfaces
    /// the required `query_id` string argument (the prior query's id to
    /// re-fetch). The object stays open (`additionalProperties: true`) so the
    /// schema never rejects valid args.
    fn input_schema(&self, backend_name: &str) -> Option<Value> {
        // `try_read` (sync, non-blocking): `input_schema` is called from the
        // gateway's registration path with no concurrent writer.
        let is_result_scan = self
            .profiles
            .try_read()
            .ok()
            .and_then(|g| g.get(backend_name).map(|p| p.operation))
            .map(|op| op == SnowflakeOperation::ResultScan)
            .unwrap_or(false);
        if is_result_scan {
            Some(json!({
                "type": "object",
                "properties": {
                    QUERY_ID_ARG: {
                        "type": "string",
                        "description": "Snowflake query id of a prior query whose result set to re-fetch (UUID-like: hex digits and hyphens only).",
                    }
                },
                "required": [QUERY_ID_ARG],
                "additionalProperties": true,
            }))
        } else {
            Some(json!({ "type": "object", "additionalProperties": true }))
        }
    }

    /// Enumerate resources for `resources/list` via the operator-fixed
    /// `list_query`. The statement runs verbatim (Snowflake has no positional
    /// bind protocol) and the page is taken client-side by `page_size` — the
    /// opaque cursor is the integer offset into the full result. Bindings
    /// without a `list_query` inherit the empty page.
    async fn list_resources(
        &self,
        backend_name: &str,
        cursor: Option<&str>,
    ) -> Result<ResourcePage, BackendError> {
        let profile = {
            let guard = self.profiles.read().await;
            guard
                .get(backend_name)
                .cloned()
                .ok_or_else(|| BackendError::ProfileNotFound {
                    backend_name: backend_name.to_owned(),
                })?
        };
        let Some(list_cfg) = profile.list_query.clone() else {
            return Ok(ResourcePage::empty());
        };
        let offset = match cursor {
            Some(c) => c.parse::<u64>().map_err(|_| BackendError::InvalidSpec {
                message: format!("list cursor '{c}' is not a non-negative integer"),
            })?,
            None => 0,
        };

        let client = profile
            .client()
            .await
            .map_err(|message| BackendError::Transport { message })?;
        let outcome = tokio::time::timeout(
            profile.timeout,
            run_query(&client, &list_cfg.sql, profile.max_rows),
        )
        .await
        .map_err(|_| BackendError::Timeout {
            timeout_ms: profile.timeout.as_millis() as u64,
        })?
        .map_err(|message| BackendError::Transport { message })?;

        Ok(surface::page_from_full_result(
            &outcome.rows,
            offset,
            list_cfg.page_size,
        ))
    }

    // `complete_template_variable` is intentionally NOT overridden: Snowflake's
    // REST connector has no positional bind protocol, so the caller-typed
    // prefix could only reach the query by string interpolation — an injection
    // surface. The binding inherits the trait default (empty completion list).
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_op_host() -> Arc<dyn BackendHost> {
        Arc::new(NoOpHost)
    }

    fn minimal_spec() -> Value {
        json!({
            "account": "xy12345.eu-central-1",
            "warehouse": "WH",
            "database": "DB",
            "schema": "PUBLIC",
            "role": "ANALYST",
            "auth": {
                "mode": "key_pair",
                "username": "svc",
                "private_key_pem": "dummy",
            },
            "statement": "SELECT 1 AS one",
        })
    }

    #[test]
    fn kind_is_snowflake() {
        assert_eq!(SnowflakeBackendPlugin::new().kind(), "snowflake");
    }

    #[test]
    fn manifest_id() {
        assert_eq!(
            SnowflakeBackendPlugin::new().manifest().id,
            "dev.mcpg.backend.snowflake"
        );
    }

    #[test]
    fn output_schema_is_object() {
        let schema = BackendPlugin::output_schema(&SnowflakeBackendPlugin::new(), "rpt").unwrap();
        assert_eq!(schema["type"], json!("object"));
    }

    #[test]
    fn input_schema_is_permissive_object() {
        let schema = BackendPlugin::input_schema(&SnowflakeBackendPlugin::new(), "rpt").unwrap();
        assert_eq!(schema["type"], json!("object"));
        assert_eq!(schema["additionalProperties"], json!(true));
    }

    #[tokio::test]
    async fn register_accepts_minimal_spec() {
        let plugin = SnowflakeBackendPlugin::new();
        plugin
            .register_profile("rpt", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("rpt").unwrap();
        assert_eq!(p.account, "xy12345.eu-central-1");
        assert_eq!(p.auth_mode, SnowflakeAuthMode::KeyPair);
        assert!(p.read_only);
        assert_eq!(p.statement, "SELECT 1 AS one");
        // No client built at registration (offline).
        assert!(p.client.get().is_none());
        // Default surface is the unchanged tool envelope.
        assert_eq!(p.surface, surface::Surface::Tool);
        assert!(p.surface_uri.is_none());
    }

    #[tokio::test]
    async fn register_stores_resource_surface_and_uri() {
        let plugin = SnowflakeBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["surface"] = json!("resource");
        spec["uri"] = json!("snowflake://docs/all");
        plugin
            .register_profile("r", &spec, no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("r").unwrap();
        assert_eq!(p.surface, surface::Surface::Resource);
        assert_eq!(p.surface_uri.as_deref(), Some("snowflake://docs/all"));
    }

    #[tokio::test]
    async fn register_rejects_uri_on_tool_surface() {
        let plugin = SnowflakeBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["uri"] = json!("snowflake://x");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("uri on tool surface");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_cred_secret() {
        let plugin = SnowflakeBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["auth"]["private_key_pem"] = json!("cred://x");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("cred secret");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_non_select_when_read_only() {
        let plugin = SnowflakeBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["statement"] = json!("DROP TABLE t");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("non-select under read_only");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_allows_non_select_when_not_read_only() {
        let plugin = SnowflakeBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["statement"] = json!("CREATE TABLE t (a INT)");
        spec["query"] = json!({ "read_only": false });
        plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect("register write under read_only=false");
    }

    #[tokio::test]
    async fn register_rejects_empty_statement() {
        let plugin = SnowflakeBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["statement"] = json!("   ");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("empty statement");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn execute_unknown_profile_is_profile_not_found() {
        let plugin = SnowflakeBackendPlugin::new();
        let req = BackendRequest {
            payload: vec![],
            headers: vec![],
            request_id: "rq-1".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let err = plugin.execute("missing", req).await.expect_err("missing");
        assert!(matches!(err, BackendError::ProfileNotFound { .. }));
    }

    #[tokio::test]
    async fn list_resources_empty_when_unconfigured() {
        let plugin = SnowflakeBackendPlugin::new();
        plugin
            .register_profile("q", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let page = BackendPlugin::list_resources(&plugin, "q", None)
            .await
            .expect("list");
        assert!(page.resources.is_empty());
        assert!(page.next_cursor.is_none());
    }

    #[tokio::test]
    async fn complete_template_variable_is_empty_safe_subset() {
        let plugin = SnowflakeBackendPlugin::new();
        plugin
            .register_profile("q", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let got = BackendPlugin::complete_template_variable(
            &plugin,
            "q",
            "v",
            "x",
            &json!({}),
            &BTreeMap::new(),
        )
        .await
        .expect("complete");
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn register_accepts_result_scan_without_statement() {
        let plugin = SnowflakeBackendPlugin::new();
        let spec = json!({
            "account": "acct",
            "auth": { "mode": "key_pair", "username": "svc", "private_key_pem": "dummy" },
            "operation": "result_scan",
        });
        plugin
            .register_profile("rs", &spec, no_op_host())
            .await
            .expect("register result_scan");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("rs").unwrap();
        assert_eq!(p.operation, SnowflakeOperation::ResultScan);
        assert!(p.statement.is_empty());
    }

    #[tokio::test]
    async fn register_rejects_query_op_without_statement() {
        let plugin = SnowflakeBackendPlugin::new();
        let spec = json!({
            "account": "acct",
            "auth": { "username": "svc", "private_key_pem": "dummy" },
        });
        let err = plugin
            .register_profile("q", &spec, no_op_host())
            .await
            .expect_err("query op needs statement");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn result_scan_input_schema_surfaces_query_id() {
        let plugin = SnowflakeBackendPlugin::new();
        let spec = json!({
            "account": "acct",
            "auth": { "username": "svc", "private_key_pem": "dummy" },
            "operation": "result_scan",
        });
        plugin
            .register_profile("rs", &spec, no_op_host())
            .await
            .expect("register");
        let schema = BackendPlugin::input_schema(&plugin, "rs").unwrap();
        assert_eq!(schema["properties"]["query_id"]["type"], json!("string"));
        assert_eq!(schema["required"], json!(["query_id"]));
    }

    #[tokio::test]
    async fn result_scan_rejects_injection_query_id_before_any_network() {
        // A malformed query id is rejected by the strict validator, returning an
        // error envelope without ever building a client / touching the network.
        let plugin = SnowflakeBackendPlugin::new();
        let spec = json!({
            "account": "acct",
            "auth": { "username": "svc", "private_key_pem": "dummy" },
            "operation": "result_scan",
        });
        plugin
            .register_profile("rs", &spec, no_op_host())
            .await
            .expect("register");
        let payload = serde_json::to_vec(&json!({ "query_id": "x'); DROP TABLE t; --" })).unwrap();
        let req = BackendRequest {
            payload,
            headers: vec![],
            request_id: "rq-1".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let resp = plugin.execute("rs", req).await.expect("error envelope");
        let env: Value = serde_json::from_slice(&resp.payload).unwrap();
        assert!(
            !env["downstreamError"].is_null(),
            "must carry a downstream error"
        );
        assert!(env["error"].as_str().unwrap().contains("query_id"));
        // The client was never built (no network reached).
        let profiles = plugin.profiles.read().await;
        assert!(profiles.get("rs").unwrap().client.get().is_none());
    }

    #[tokio::test]
    async fn result_scan_rejects_missing_query_id() {
        let plugin = SnowflakeBackendPlugin::new();
        let spec = json!({
            "account": "acct",
            "auth": { "username": "svc", "private_key_pem": "dummy" },
            "operation": "result_scan",
        });
        plugin
            .register_profile("rs", &spec, no_op_host())
            .await
            .expect("register");
        let req = BackendRequest {
            payload: vec![],
            headers: vec![],
            request_id: "rq-2".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let resp = plugin.execute("rs", req).await.expect("error envelope");
        let env: Value = serde_json::from_slice(&resp.payload).unwrap();
        assert!(!env["downstreamError"].is_null());
    }

    #[tokio::test]
    async fn register_stores_list_query() {
        let plugin = SnowflakeBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["surface"] = json!("resource");
        spec["list_query"] = json!({ "sql": "SELECT uri FROM docs", "page_size": 10 });
        plugin
            .register_profile("r", &spec, no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        assert!(profiles.get("r").unwrap().list_query.is_some());
    }

    #[tokio::test]
    async fn register_rejects_empty_list_query_sql() {
        let plugin = SnowflakeBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["list_query"] = json!({ "sql": "  " });
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("empty list sql");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    struct NoOpHost;

    #[async_trait]
    impl BackendHost for NoOpHost {
        async fn invoke_tool(
            &self,
            _ctx: &mcpg_plugin_protocol::BackendInvocationContext,
            _tool_name: &str,
            _args: &serde_json::Value,
        ) -> Result<serde_json::Value, mcpg_plugin_protocol::BackendHostError> {
            Err(mcpg_plugin_protocol::BackendHostError::NotImplemented)
        }
    }
}
