//! Operator-facing spec for the Snowflake backend plugin.
//!
//! One binding = one operator-fixed analytical statement = one MCP tool (or
//! resource). The connection (account / warehouse / database / schema / role),
//! the auth (key-pair JWT or password), the statement and the query bounds all
//! live on the per-binding spec, mirroring the http/oracle/mssql
//! one-profile-per-binding shape.

use serde::Deserialize;

/// Which operation a Snowflake binding performs.
///
/// Mirrors the ODBC backend's `operation` enum shape for cross-backend
/// consistency.
#[derive(Debug, Default, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnowflakeOperation {
    /// Run the operator-fixed `statement` (the default).
    #[default]
    Query,
    /// Re-fetch a prior query's result set by its Snowflake query id. The id
    /// arrives in the `query_id` tool argument; the binding runs
    /// `SELECT * FROM TABLE(RESULT_SCAN('<id>'))`. Inherently read-only.
    ResultScan,
}

impl SnowflakeOperation {
    /// Lowercase wire token (matches the `serde` rename).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SnowflakeOperation::Query => "query",
            SnowflakeOperation::ResultScan => "result_scan",
        }
    }

    /// Whether this operation is inherently read-only (re-reads only — never
    /// mutates the warehouse).
    #[must_use]
    pub fn is_read_only(self) -> bool {
        matches!(self, SnowflakeOperation::ResultScan)
    }
}

/// How the binding authenticates to Snowflake.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SnowflakeAuthMode {
    /// Key-pair JWT auth — `username` + RSA `private_key_pem`.
    #[default]
    KeyPair,
    /// Password auth — `username` + `password`.
    Password,
}

impl SnowflakeAuthMode {
    pub fn as_str(self) -> &'static str {
        match self {
            SnowflakeAuthMode::KeyPair => "key_pair",
            SnowflakeAuthMode::Password => "password",
        }
    }
}

/// Auth block. The secret field used depends on `mode`: `key_pair` uses
/// `private_key_pem`, `password` uses `password`. The unused one may be empty.
#[derive(Debug, Clone, Deserialize)]
pub struct SnowflakeAuth {
    /// Auth mechanism (default `key_pair`).
    #[serde(default)]
    pub mode: SnowflakeAuthMode,

    /// Snowflake login username.
    pub username: String,

    /// PEM-encoded RSA private key (key-pair mode). A literal, or a `${env.X}`
    /// / `vault://...` reference the gateway secret-resolver expands at config
    /// load — never plaintext in committed config. A bare per-caller `cred://`
    /// is rejected (the connection is one service identity).
    #[serde(default)]
    pub private_key_pem: String,

    /// Login password (password mode). Same secret-resolver rules as
    /// `private_key_pem`.
    #[serde(default)]
    pub password: String,
}

/// Query-execution bounds.
#[derive(Debug, Clone, Deserialize)]
pub struct SnowflakeQueryConfig {
    /// When true (default), the statement is rejected unless its first SQL
    /// keyword is SELECT / WITH / SHOW / DESCRIBE / EXPLAIN — fail-closed
    /// before sending anything to Snowflake.
    #[serde(default = "default_read_only")]
    pub read_only: bool,

    /// Per-call ceiling (ms) on the whole REST round-trip (default 60 s).
    #[serde(default = "default_statement_timeout_ms")]
    pub statement_timeout_ms: u64,

    /// Client-side cap on returned rows (default 10000). Extra rows set the
    /// envelope `truncated` flag.
    #[serde(default = "default_max_rows")]
    pub max_rows: usize,
}

impl Default for SnowflakeQueryConfig {
    fn default() -> Self {
        Self {
            read_only: default_read_only(),
            statement_timeout_ms: default_statement_timeout_ms(),
            max_rows: default_max_rows(),
        }
    }
}

fn default_read_only() -> bool {
    true
}
fn default_statement_timeout_ms() -> u64 {
    60_000
}
fn default_max_rows() -> usize {
    10_000
}

/// Operator-facing spec the gateway serializes when calling `register_profile`.
/// Mirrors `SnowflakeBackendConfig` in the gateway crate.
// NOTE: intentionally NOT #[serde(deny_unknown_fields)] — the gateway injects
// the reserved `__mcpg_secret_refs` hint key into this spec at register_profile
// (secret-rotation scoping); denying unknown fields would reject it. The
// operator-facing schema is closed on the gateway-side *BackendConfig instead.
#[derive(Debug, Clone, Deserialize)]
pub struct SnowflakeBackendSpec {
    /// Snowflake account identifier (e.g. `xy12345.eu-central-1`). This
    /// determines the Snowflake REST host. Operator-configured (never
    /// caller-templated), so there is no SSRF / arg-injection vector.
    pub account: String,

    /// Default warehouse for the session.
    #[serde(default)]
    pub warehouse: Option<String>,
    /// Default database for the session.
    #[serde(default)]
    pub database: Option<String>,
    /// Default schema for the session.
    #[serde(default)]
    pub schema: Option<String>,
    /// Session role.
    #[serde(default)]
    pub role: Option<String>,

    /// Auth block (key-pair JWT or password).
    pub auth: SnowflakeAuth,

    /// Query-execution bounds (read-only guard, timeout, max rows). A bare
    /// `query:` or an omitted block applies all defaults.
    #[serde(default)]
    pub query: SnowflakeQueryConfig,

    /// Which operation this binding performs. `query` (default) runs the
    /// operator-fixed `statement`; `result_scan` re-fetches a prior query's
    /// result set by the `query_id` tool argument (pagination / large-result
    /// re-read). The `result_scan` operation is inherently read-only and
    /// ignores `statement` (which may be omitted).
    #[serde(default)]
    pub operation: SnowflakeOperation,

    /// The operator-fixed SQL statement to run for `operation: query`. The
    /// Snowflake REST connector has no positional bind protocol, so this
    /// statement is run verbatim — caller arguments are NOT templated into it
    /// (CEL-bound params are a deferred follow-on, see README). Ignored (and
    /// may be omitted) for `operation: result_scan`.
    #[serde(default)]
    pub statement: String,

    /// MCP surface this binding serves. `tool` (default) emits the unchanged
    /// tool envelope; `resource` reshapes successful rows into the
    /// `resources/read` `{contents:[…]}` body; `prompt` reshapes them into the
    /// `prompts/get` `{messages:[…]}` body. Set to match the capability list the
    /// binding is placed under (`resources[]` / `prompts[]`).
    #[serde(default)]
    pub surface: crate::surface::Surface,

    /// Optional static resource URI for `surface: resource`. When set it is used
    /// verbatim as the emitted content `uri`; when omitted the binding uses the
    /// requested URI the gateway passes in the call arguments (`uri`). Ignored
    /// for `tool` / `prompt` surfaces.
    #[serde(default)]
    pub uri: Option<String>,

    /// Optional listing statement for `resources/list`. On a
    /// `surface: resource` binding this operator-fixed SELECT runs at list time
    /// to enumerate concrete resource URIs (one `uri` column, optional `name`
    /// / `description` / `mime_type`). The Snowflake REST connector has no
    /// positional bind protocol, so the statement runs verbatim — pagination is
    /// applied client-side over the full result by `page_size`. Empty → the
    /// binding returns no dynamic listing (the trait default).
    #[serde(default)]
    pub list_query: Option<ListQueryConfig>,
}

/// Operator-fixed listing statement + client-side page bound for
/// `resources/list`.
///
/// Snowflake exposes no positional bind protocol, so the statement is run
/// verbatim (no caller-derived value reaches the SQL) and the page is taken
/// client-side: the opaque cursor is the integer offset into the full result.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ListQueryConfig {
    /// SELECT returning one row per resource. Required column: `uri`. Optional:
    /// `name`, `description`, `mime_type`. Operator-fixed — NOT templated from
    /// caller input.
    pub sql: String,
    /// Rows per page (1..=1000), applied client-side. Defaults to 100.
    #[serde(default = "default_list_page_size")]
    pub page_size: u64,
}

fn default_list_page_size() -> u64 {
    100
}

/// Fail-closed validation for an operator-fixed [`ListQueryConfig`].
pub fn validate_list_query(cfg: &ListQueryConfig) -> Result<(), String> {
    if cfg.sql.trim().is_empty() {
        return Err("list_query.sql must not be empty".into());
    }
    if cfg.page_size == 0 || cfg.page_size > 1_000 {
        return Err(format!(
            "list_query.page_size ({}) must be in 1..=1000",
            cfg.page_size
        ));
    }
    Ok(())
}

/// The tool-argument name carrying the Snowflake query id for
/// `operation: result_scan`.
pub const QUERY_ID_ARG: &str = "query_id";

/// Validate a caller-supplied Snowflake query id with a strict charset
/// allowlist.
///
/// `snowflake-api` 0.14 has no server-side bind protocol, so the query id is
/// embedded into the `RESULT_SCAN('<id>')` SQL as a quoted literal. A query id
/// is NOT free-form SQL — it is a server-generated UUID — so the safe approach
/// (absent a bind) is to reject anything that is not strictly a Snowflake
/// query-id token: ASCII hex digits and hyphens only, non-empty, length-bounded.
/// Anything carrying a quote, whitespace, semicolon, comment marker or any other
/// SQL metacharacter is rejected, so no injection can reach the embedded
/// literal.
pub fn validate_query_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("query_id must not be empty".into());
    }
    // A Snowflake query id is a UUID-like token; cap the length well above a
    // 36-char UUID to reject anything pathological while tolerating future
    // id shapes that stay within the hex+hyphen charset.
    if id.len() > 64 {
        return Err(format!(
            "query_id ('{id}') is too long to be a Snowflake query id"
        ));
    }
    // Strict allowlist: ASCII hex digits and hyphens ONLY. This is the security
    // boundary — it admits no quote, whitespace, parenthesis, semicolon, comment
    // marker or any other SQL metacharacter, so the id can be safely embedded as
    // a quoted literal without a server-side bind.
    let ok = id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-');
    if !ok {
        return Err(format!(
            "query_id ('{id}') is not a valid Snowflake query id \
             (only hex digits and hyphens are allowed)"
        ));
    }
    Ok(())
}

/// Build the `RESULT_SCAN` SQL for a strict, already-validated query id.
///
/// MUST be called only after [`validate_query_id`] has accepted `id`; the id is
/// embedded as a quoted literal because the REST driver exposes no bind. The
/// strict hex+hyphen charset guarantees the literal cannot be broken out of.
pub fn build_result_scan_sql(id: &str) -> String {
    format!("SELECT * FROM TABLE(RESULT_SCAN('{id}'))")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_mode_defaults_to_key_pair() {
        assert_eq!(SnowflakeAuthMode::default(), SnowflakeAuthMode::KeyPair);
    }

    #[test]
    fn spec_applies_query_defaults_when_omitted() {
        let spec: SnowflakeBackendSpec = serde_json::from_value(serde_json::json!({
            "account": "xy12345.eu-central-1",
            "auth": { "username": "svc", "private_key_pem": "dummy" },
            "statement": "SELECT 1 AS one",
        }))
        .unwrap();
        assert_eq!(spec.auth.mode, SnowflakeAuthMode::KeyPair);
        assert!(spec.query.read_only);
        assert_eq!(spec.query.statement_timeout_ms, 60_000);
        assert_eq!(spec.query.max_rows, 10_000);
    }

    #[test]
    fn parses_password_mode_and_query_overrides() {
        let spec: SnowflakeBackendSpec = serde_json::from_value(serde_json::json!({
            "account": "acct",
            "auth": { "mode": "password", "username": "svc", "password": "${env.SNOW_PW}" },
            "query": { "read_only": false, "statement_timeout_ms": 5000, "max_rows": 50 },
            "statement": "INSERT INTO t VALUES (1)",
        }))
        .unwrap();
        assert_eq!(spec.auth.mode, SnowflakeAuthMode::Password);
        assert!(!spec.query.read_only);
        assert_eq!(spec.query.statement_timeout_ms, 5000);
        assert_eq!(spec.query.max_rows, 50);
    }

    #[test]
    fn parses_list_query() {
        let spec: SnowflakeBackendSpec = serde_json::from_value(serde_json::json!({
            "account": "acct",
            "auth": { "username": "svc", "private_key_pem": "dummy" },
            "statement": "SELECT 1 AS one",
            "surface": "resource",
            "list_query": { "sql": "SELECT uri FROM docs", "page_size": 25 },
        }))
        .unwrap();
        let lq = spec.list_query.expect("list_query");
        assert_eq!(lq.page_size, 25);
        assert_eq!(lq.sql, "SELECT uri FROM docs");
    }

    #[test]
    fn operation_defaults_to_query() {
        let spec: SnowflakeBackendSpec = serde_json::from_value(serde_json::json!({
            "account": "acct",
            "auth": { "username": "svc", "private_key_pem": "dummy" },
            "statement": "SELECT 1 AS one",
        }))
        .unwrap();
        assert_eq!(spec.operation, SnowflakeOperation::Query);
        assert!(!spec.operation.is_read_only());
    }

    #[test]
    fn parses_result_scan_operation_without_statement() {
        let spec: SnowflakeBackendSpec = serde_json::from_value(serde_json::json!({
            "account": "acct",
            "auth": { "username": "svc", "private_key_pem": "dummy" },
            "operation": "result_scan",
        }))
        .unwrap();
        assert_eq!(spec.operation, SnowflakeOperation::ResultScan);
        assert_eq!(spec.operation.as_str(), "result_scan");
        assert!(spec.operation.is_read_only());
        // `statement` may be omitted for result_scan.
        assert!(spec.statement.is_empty());
    }

    #[test]
    fn validate_query_id_accepts_uuid_like_ids() {
        for id in [
            "01b2c3d4-0000-0000-0000-0123456789ab",
            "0123456789abcdef0123456789abcdef",
            "abc-def-123",
            "ABCDEF",
        ] {
            assert!(validate_query_id(id).is_ok(), "should accept: {id}");
        }
    }

    #[test]
    fn validate_query_id_rejects_injection_attempts() {
        for id in [
            "",                                 // empty
            "01b2'); DROP TABLE t; --",         // quote + statement break
            "01b2c3d4' OR '1'='1",              // quote injection
            "id with spaces",                   // whitespace
            "01b2c3d4)) UNION SELECT * FROM x", // parens/keyword
            "01b2;c3d4",                        // semicolon
            "01b2/*comment*/c3d4",              // comment marker + slash/star
            "01b2\nc3d4",                       // newline
            "ghijkl",                           // non-hex letters
            "01b2c3d4_extra",                   // underscore not in charset
            "тест",                             // non-ascii
            &"a".repeat(65),                    // over the length cap
        ] {
            assert!(validate_query_id(id).is_err(), "should reject: {id:?}");
        }
    }

    #[test]
    fn build_result_scan_sql_embeds_quoted_literal() {
        let sql = build_result_scan_sql("01b2c3d4-0000-0000-0000-0123456789ab");
        assert_eq!(
            sql,
            "SELECT * FROM TABLE(RESULT_SCAN('01b2c3d4-0000-0000-0000-0123456789ab'))"
        );
    }

    #[test]
    fn validate_list_query_enforces_bounds() {
        let mut cfg = ListQueryConfig {
            sql: "SELECT uri FROM docs".into(),
            page_size: 100,
        };
        assert!(validate_list_query(&cfg).is_ok());
        cfg.page_size = 0;
        assert!(validate_list_query(&cfg).is_err());
        cfg.page_size = 100;
        cfg.sql = "  ".into();
        assert!(validate_list_query(&cfg).is_err());
    }
}
