//! Snowflake REST driver glue: the lazily-built client, the async query
//! runner, and the Arrow→JSON marshaller.
//!
//! `snowflake-api` is async (reqwest-based) and authenticates on the first
//! request, so the client is built lazily on first `execute` (parsing the
//! private key only then) and cached per profile — `register_profile` stays
//! offline and the unit tests need no real key. The Arrow result-set decoder
//! is pure and is exercised by a synthetic-RecordBatch unit test.

use arrow::record_batch::RecordBatch;
use arrow_json::writer::{JsonArray, WriterBuilder};
use serde_json::Value;
use snowflake_api::QueryResult;

use crate::types::SnowflakeAuthMode;

/// Outcome of a completed query: the JSON rows (capped at `max_rows`) plus
/// whether more rows existed beyond the cap.
pub struct QueryOutcome {
    pub rows: Vec<Value>,
    pub truncated: bool,
    pub row_count: usize,
}

/// Reject a statement that is not read-only, delegating to the shared hardened
/// guard. Beyond the leading-keyword allowlist, that guard rejects write/DDL
/// keywords anywhere (write-CTEs), `EXPLAIN ANALYZE`, and stacked statements,
/// after blanking literals/comments. Fail-closed: an empty statement is
/// rejected. `result_scan` issues `SELECT * FROM TABLE(RESULT_SCAN('<id>'))`,
/// which is a SELECT with no write tokens and still passes.
pub fn enforce_read_only(statement: &str) -> Result<(), String> {
    mcpg_plugin_sdk::sql_guard::enforce_read_only(statement)
}

/// Build a `SnowflakeApi` client for a profile. Pure construction — auth
/// happens on the first `exec`, so this only fails on a malformed
/// account/key/builder, never on the network.
#[allow(clippy::too_many_arguments)]
pub fn build_client(
    account: &str,
    warehouse: Option<&str>,
    database: Option<&str>,
    schema: Option<&str>,
    role: Option<&str>,
    username: &str,
    mode: SnowflakeAuthMode,
    secret: &str,
) -> Result<snowflake_api::SnowflakeApi, String> {
    let api = match mode {
        SnowflakeAuthMode::KeyPair => snowflake_api::SnowflakeApi::with_certificate_auth(
            account, warehouse, database, schema, username, role, secret,
        ),
        SnowflakeAuthMode::Password => snowflake_api::SnowflakeApi::with_password_auth(
            account, warehouse, database, schema, username, role, secret,
        ),
    };
    api.map_err(|e| {
        mcpg_plugin_protocol::redact::redact_in_text(&format!("Snowflake client init failed: {e}"))
    })
}

/// Run the statement against an already-built client and marshal the result to
/// capped JSON rows.
pub async fn run_query(
    api: &snowflake_api::SnowflakeApi,
    statement: &str,
    max_rows: usize,
) -> Result<QueryOutcome, String> {
    let result = api
        .exec(statement)
        .await
        .map_err(|e| format!("Snowflake query failed: {e}"))?;
    marshal_result(result, max_rows)
}

/// Convert a `QueryResult` into capped JSON rows.
pub fn marshal_result(result: QueryResult, max_rows: usize) -> Result<QueryOutcome, String> {
    match result {
        QueryResult::Arrow(batches) => marshal_arrow(&batches, max_rows),
        QueryResult::Json(json) => Ok(marshal_json(json.value, max_rows)),
        QueryResult::Empty => Ok(QueryOutcome {
            rows: Vec::new(),
            truncated: false,
            row_count: 0,
        }),
    }
}

/// Marshal Arrow record batches to JSON row objects, capped at `max_rows`.
/// Uses `arrow-json`'s array writer with explicit nulls so NULL columns appear
/// as JSON `null` (rather than being omitted from the row object).
fn marshal_arrow(batches: &[RecordBatch], max_rows: usize) -> Result<QueryOutcome, String> {
    let total: usize = batches.iter().map(RecordBatch::num_rows).sum();

    // Slice batches so at most `max_rows` rows are serialized.
    let mut capped: Vec<RecordBatch> = Vec::new();
    let mut remaining = max_rows;
    for batch in batches {
        if remaining == 0 {
            break;
        }
        let n = batch.num_rows();
        if n <= remaining {
            capped.push(batch.clone());
            remaining -= n;
        } else {
            capped.push(batch.slice(0, remaining));
            remaining = 0;
        }
    }

    let mut buf = Vec::new();
    {
        let mut writer = WriterBuilder::new()
            .with_explicit_nulls(true)
            .build::<_, JsonArray>(&mut buf);
        let refs: Vec<&RecordBatch> = capped.iter().collect();
        writer
            .write_batches(&refs)
            .map_err(|e| format!("Snowflake Arrow→JSON write failed: {e}"))?;
        writer
            .finish()
            .map_err(|e| format!("Snowflake Arrow→JSON finish failed: {e}"))?;
    }

    let rows: Vec<Value> = if buf.is_empty() {
        Vec::new()
    } else {
        serde_json::from_slice(&buf)
            .map_err(|e| format!("Snowflake Arrow→JSON parse failed: {e}"))?
    };

    Ok(QueryOutcome {
        truncated: total > rows.len(),
        row_count: rows.len(),
        rows,
    })
}

/// Marshal a JSON `QueryResult` to rows, capped at `max_rows`. Snowflake
/// returns a JSON array of rows for non-SELECT statements; an array passes
/// through, anything else is wrapped as a single row.
fn marshal_json(value: Value, max_rows: usize) -> QueryOutcome {
    match value {
        Value::Array(mut arr) => {
            let total = arr.len();
            if arr.len() > max_rows {
                arr.truncate(max_rows);
            }
            QueryOutcome {
                truncated: total > arr.len(),
                row_count: arr.len(),
                rows: arr,
            }
        }
        Value::Null => QueryOutcome {
            rows: Vec::new(),
            truncated: false,
            row_count: 0,
        },
        other => {
            let rows = vec![other];
            let truncated = max_rows == 0;
            let kept = if truncated { Vec::new() } else { rows };
            QueryOutcome {
                row_count: kept.len(),
                rows: kept,
                truncated,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use arrow::array::{ArrayRef, BooleanArray, Int64Array, StringArray};
    use arrow::datatypes::{DataType, Field, Schema};
    use serde_json::json;

    #[test]
    fn read_only_allows_select_with_show() {
        for s in [
            "SELECT 1",
            "  select * from t",
            "WITH x AS (SELECT 1) SELECT * FROM x",
            "SHOW TABLES",
            "DESCRIBE TABLE t",
            "EXPLAIN SELECT 1",
            "-- a comment\nSELECT 1",
            "/* block */ SELECT 1",
            "(SELECT 1)",
        ] {
            assert!(enforce_read_only(s).is_ok(), "should allow: {s}");
        }
    }

    #[test]
    fn read_only_rejects_writes_and_ddl() {
        for s in [
            "INSERT INTO t VALUES (1)",
            "UPDATE t SET a = 1",
            "DELETE FROM t",
            "CREATE TABLE t (a INT)",
            "DROP TABLE t",
            "MERGE INTO t USING s ON t.id = s.id",
            "   ",
            "",
            "-- only a comment",
        ] {
            assert!(enforce_read_only(s).is_err(), "should reject: {s}");
        }
    }

    /// The guard delegates to the shared hardened helper, so the harder
    /// constructs (write-CTEs, `EXPLAIN ANALYZE`, stacked statements) are
    /// rejected while plain reads and the `result_scan` SELECT pass.
    #[test]
    fn read_only_delegates_to_hardened_guard() {
        for s in [
            "WITH x AS (INSERT INTO t SELECT 1) SELECT * FROM x",
            "EXPLAIN ANALYZE SELECT 1",
            "SELECT 1; DROP TABLE t",
        ] {
            assert!(enforce_read_only(s).is_err(), "should reject: {s}");
        }
        for s in ["SELECT 1", "SELECT * FROM TABLE(RESULT_SCAN('abc'))"] {
            assert!(enforce_read_only(s).is_ok(), "should accept: {s}");
        }
    }

    /// Build a synthetic RecordBatch (Int64 "id", Utf8 "name" with a null,
    /// Boolean "active") and assert the marshaller emits correct JSON rows
    /// including the explicit null.
    #[test]
    fn marshal_arrow_emits_rows_with_null() {
        let id = Arc::new(Int64Array::from(vec![1_i64, 2, 3])) as ArrayRef;
        let name =
            Arc::new(StringArray::from(vec![Some("alice"), None, Some("carol")])) as ArrayRef;
        let active = Arc::new(BooleanArray::from(vec![true, false, true])) as ArrayRef;
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("name", DataType::Utf8, true),
            Field::new("active", DataType::Boolean, false),
        ]));
        let batch = RecordBatch::try_new(schema, vec![id, name, active]).unwrap();

        let out = marshal_arrow(&[batch], 10_000).unwrap();
        assert_eq!(out.row_count, 3);
        assert!(!out.truncated);
        assert_eq!(
            out.rows[0],
            json!({ "id": 1, "name": "alice", "active": true })
        );
        // The null name must be present as an explicit JSON null.
        assert_eq!(out.rows[1]["id"], json!(2));
        assert!(out.rows[1].get("name").is_some(), "null name field present");
        assert_eq!(out.rows[1]["name"], Value::Null);
        assert_eq!(out.rows[1]["active"], json!(false));
        assert_eq!(
            out.rows[2],
            json!({ "id": 3, "name": "carol", "active": true })
        );
    }

    #[test]
    fn marshal_arrow_caps_and_flags_truncated() {
        let id = Arc::new(Int64Array::from(vec![1_i64, 2, 3, 4, 5])) as ArrayRef;
        let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, false)]));
        let batch = RecordBatch::try_new(schema, vec![id]).unwrap();

        let out = marshal_arrow(&[batch], 2).unwrap();
        assert_eq!(out.row_count, 2);
        assert!(out.truncated);
        assert_eq!(out.rows[0]["id"], json!(1));
        assert_eq!(out.rows[1]["id"], json!(2));
    }

    #[test]
    fn marshal_json_array_passes_through() {
        let out = marshal_json(json!([[1, "a"], [2, "b"]]), 10);
        assert_eq!(out.row_count, 2);
        assert!(!out.truncated);
        assert_eq!(out.rows[0], json!([1, "a"]));
    }

    #[test]
    fn marshal_json_array_caps() {
        let out = marshal_json(json!([1, 2, 3, 4]), 2);
        assert_eq!(out.row_count, 2);
        assert!(out.truncated);
    }

    #[test]
    fn marshal_empty_is_zero_rows() {
        let out = marshal_result(QueryResult::Empty, 100).unwrap();
        assert_eq!(out.row_count, 0);
        assert!(!out.truncated);
        assert!(out.rows.is_empty());
    }
}
