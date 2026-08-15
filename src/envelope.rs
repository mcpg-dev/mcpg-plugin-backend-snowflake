//! Snowflake structured response envelope — the `BackendResponse.payload` the
//! gateway projects onto `tools/call`. A non-null `downstreamError` slot is
//! the gateway's `isError` signal (same contract as the http/oracle/mssql
//! backends).

use serde_json::{Value, json};

/// Build a downstream-error object for the envelope's `downstreamError` slot.
pub fn snowflake_downstream_error(kind: &str, message: &str, retryable: bool) -> Value {
    json!({
        "kind": kind,
        "code": format!("mcpg.downstream_snowflake.{kind}"),
        "message": message,
        "retryable": retryable,
        "retryClass": if retryable { "with_backoff" } else { "do_not_retry" },
        "suggestedAction": if retryable { "check_warehouse_connectivity_and_retry" } else { "inspect_sql_error" },
    })
}

/// Classify a `run_query` error string. Transport-level failures (connection /
/// timeout / rate-limit / 5xx) are retryable; SQL compilation, auth and
/// permission failures are caller/config problems and are not.
pub fn classify_error(message: &str) -> Value {
    let lower = message.to_ascii_lowercase();
    // Non-retryable markers win: a "compilation error" containing the word
    // "timeout" must still classify as a SQL rejection, not transport.
    let non_retryable = lower.contains("compilation")
        || lower.contains("syntax")
        || lower.contains("invalid identifier")
        || lower.contains("does not exist")
        || lower.contains("authentication")
        || lower.contains("auth ")
        || lower.contains("jwt")
        || lower.contains("private key")
        || lower.contains("unauthorized")
        || lower.contains("permission")
        || lower.contains("insufficient privileges")
        || lower.contains("access denied")
        || lower.contains("read-only guard");
    let retryable = !non_retryable
        && (lower.contains("connect")
            || lower.contains("timed out")
            || lower.contains("timeout")
            || lower.contains("broken pipe")
            || lower.contains("connection reset")
            || lower.contains("eof")
            || lower.contains("dns")
            || lower.contains("429")
            || lower.contains("too many requests")
            || lower.contains("500")
            || lower.contains("502")
            || lower.contains("503")
            || lower.contains("504")
            || lower.contains("service unavailable"));
    let kind = if retryable {
        "transport_error"
    } else {
        "snowflake_error"
    };
    snowflake_downstream_error(kind, message, retryable)
}

/// JSON Schema (draft 2020-12) for the fixed envelope wrapper
/// [`build_result_envelope`] produces. Describes the stable top-level
/// shape; per-query `response.rows` items are intentionally left untyped
/// (`{}`) so any row shape validates.
pub fn result_envelope_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "toolName": { "type": "string" },
            "profile": { "type": "string" },
            "request": {
                "type": "object",
                "properties": {
                    "account": { "type": "string" },
                    "database": { "type": ["string", "null"] },
                    "schema": { "type": ["string", "null"] }
                },
                "additionalProperties": true
            },
            "response": {
                "type": ["object", "null"],
                "properties": {
                    "rows": { "type": ["array", "null"], "items": {} },
                    "count": { "type": ["integer", "null"] },
                    "truncated": { "type": "boolean" },
                    "durationMs": { "type": "integer" }
                },
                "additionalProperties": true
            },
            "truncated": { "type": "boolean" },
            "downstreamError": { "type": ["object", "null"] },
            "downstreamErrors": { "type": "array", "items": {} },
            "error": { "type": ["string", "null"] }
        },
        "additionalProperties": true
    })
}

/// Build the Snowflake structured-content envelope returned as the
/// `BackendResponse.payload`.
#[allow(clippy::too_many_arguments)]
pub fn build_result_envelope(
    tool_name: &str,
    profile_name: &str,
    account: &str,
    database: Option<&str>,
    schema: Option<&str>,
    rows: Option<&[Value]>,
    row_count: Option<usize>,
    truncated: bool,
    duration_ms: u128,
    downstream_error: Option<&Value>,
    error: Option<&str>,
) -> Value {
    let response = if downstream_error.is_some() {
        Value::Null
    } else {
        json!({
            "rows": rows,
            "count": row_count,
            "truncated": truncated,
            "durationMs": duration_ms,
        })
    };
    json!({
        "toolName": tool_name,
        "profile": profile_name,
        "request": {
            "account": account,
            "database": database,
            "schema": schema,
        },
        "response": response,
        "truncated": truncated,
        "downstreamError": downstream_error,
        "downstreamErrors": downstream_error
            .map(|d| vec![d.clone()])
            .unwrap_or_default(),
        "error": error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_failure_is_retryable_transport_error() {
        let e = classify_error("Snowflake request failed: connection refused");
        assert_eq!(e["kind"], json!("transport_error"));
        assert_eq!(e["retryable"], json!(true));
    }

    #[test]
    fn rate_limit_is_retryable() {
        let e = classify_error("Snowflake API error. Code: 429. Message: too many requests");
        assert_eq!(e["kind"], json!("transport_error"));
        assert_eq!(e["retryable"], json!(true));
    }

    #[test]
    fn sql_compilation_is_not_retryable() {
        let e = classify_error(
            "Snowflake API error. Code: 000904. Message: SQL compilation error: invalid identifier 'BOGUS'",
        );
        assert_eq!(e["kind"], json!("snowflake_error"));
        assert_eq!(e["retryable"], json!(false));
    }

    #[test]
    fn auth_failure_is_not_retryable() {
        let e = classify_error("JWT token is invalid: authentication failed");
        assert_eq!(e["kind"], json!("snowflake_error"));
        assert_eq!(e["retryable"], json!(false));
    }

    #[test]
    fn query_envelope_has_rows_count_and_truncated() {
        let rows = vec![json!({ "ID": 1 })];
        let env = build_result_envelope(
            "u.get",
            "u.get",
            "xy12345.eu-central-1",
            Some("DB"),
            Some("PUBLIC"),
            Some(&rows),
            Some(1),
            false,
            7,
            None,
            None,
        );
        assert_eq!(env["response"]["count"], json!(1));
        assert_eq!(env["response"]["rows"][0]["ID"], json!(1));
        assert_eq!(env["response"]["truncated"], json!(false));
        assert_eq!(env["request"]["account"], json!("xy12345.eu-central-1"));
        assert_eq!(env["request"]["database"], json!("DB"));
        assert!(env["downstreamError"].is_null());
    }

    #[test]
    fn truncated_flag_propagates() {
        let rows = vec![json!({ "ID": 1 })];
        let env = build_result_envelope(
            "u.get",
            "u.get",
            "acct",
            None,
            None,
            Some(&rows),
            Some(1),
            true,
            7,
            None,
            None,
        );
        assert_eq!(env["truncated"], json!(true));
        assert_eq!(env["response"]["truncated"], json!(true));
    }

    #[test]
    fn error_envelope_nulls_response() {
        let d = classify_error("Snowflake API error: SQL compilation error");
        let env = build_result_envelope(
            "u.q",
            "u.q",
            "acct",
            None,
            None,
            None,
            None,
            false,
            2,
            Some(&d),
            Some("SQL compilation error"),
        );
        assert!(env["response"].is_null());
        assert_eq!(env["downstreamError"]["kind"], json!("snowflake_error"));
    }

    #[test]
    fn output_schema_matches_envelope_shape() {
        let schema = result_envelope_schema();
        assert_eq!(schema["type"], json!("object"));
        let rows = vec![json!({ "ID": 1 })];
        let env = build_result_envelope(
            "u.get",
            "u.get",
            "acct",
            Some("DB"),
            Some("PUBLIC"),
            Some(&rows),
            Some(1),
            false,
            7,
            None,
            None,
        );
        let props = schema["properties"].as_object().expect("properties object");
        for key in env.as_object().expect("envelope object").keys() {
            assert!(props.contains_key(key), "schema missing key `{key}`");
        }
        assert_eq!(
            schema["properties"]["response"]["properties"]["rows"]["items"],
            json!({})
        );
    }
}
