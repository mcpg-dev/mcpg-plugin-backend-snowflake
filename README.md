# `mcpg-plugin-backend-snowflake`

Snowflake cloud-warehouse backend binding plugin for mcpg (`kind: snowflake`).
Runs one **operator-fixed** analytical SQL statement against a Snowflake
warehouse over the REST API and returns the rows (Arrow result sets are decoded
to JSON; non-SELECT JSON results pass through).

The Snowflake complement to the `sql` (Postgres / MySQL / SQLite), `mssql`
(SQL Server) and `oracle` backends — none of those drivers speak the Snowflake
REST protocol.

## How it works

One binding = one statement = one MCP tool (or resource). Per call:

1. The cached REST client is built on first use (parsing the private key only
   then; auth happens on the first request), then reused.
2. The `statement` runs over the Snowflake REST API. SELECT results come back
   as Arrow record batches and are decoded to JSON row objects; non-SELECT
   statements return a JSON array of rows that passes through. Rows are capped
   at `query.max_rows` (extra rows set the `truncated` flag).
3. SQL compilation / auth / permission failures become a non-retryable
   `downstreamError` (the gateway's `isError` signal); connection / timeout /
   rate-limit (429) / 5xx failures are marked retryable.

## Driver / runtime

The driver is [`snowflake-api`](https://crates.io/crates/snowflake-api)
(mycelial/snowflake-rs) — pure-Rust REST + Arrow. TLS is **rustls** (reqwest →
hyper-rustls); there is **no openssl / native-tls / system library** (only
`openssl-probe`, which is allowed). The default `cert-auth` feature provides
key-pair JWT via `snowflake-jwt`.

It is **async** (reqwest-based), so — like the elasticsearch / LLM backends —
the cdylib bridge `block_on`s the async methods in a small 2-worker tokio
runtime (no `spawn_blocking`).

> The crate pulls a heavy transitive graph (Arrow 57 + `object_store`), so the
> first build is slow; that is expected.

## Auth

Two `auth.mode`s (default `key_pair`):

| Mode | Secret field | Notes |
|---|---|---|
| `key_pair` | `auth.private_key_pem` | PEM-encoded RSA private key → JWT. |
| `password` | `auth.password` | Plain password auth. |

The secret resolves through the gateway secret-resolver (`${env.X}` /
`vault://…` / `${cred://…}`) at config load — never plaintext in committed
config. A **bare** per-caller `cred://` is **rejected**: the connection is one
service identity (per-caller credentials are a deferred follow-on).

## Configuration

| Field | Type | Default | Notes |
|---|---|---|---|
| `account` | string (required) | — | Snowflake account identifier (e.g. `xy12345.eu-central-1`). Operator-configured (not caller-templated) → no SSRF vector; it determines the REST host. |
| `warehouse` | string | — | Session warehouse. |
| `database` | string | — | Session database. |
| `schema` | string | — | Session schema. |
| `role` | string | — | Session role. |
| `auth.mode` | `key_pair`\|`password` | `key_pair` | Auth mechanism. |
| `auth.username` | string (required) | — | Login user. |
| `auth.private_key_pem` | string | — | RSA private key (key-pair mode), secret-resolved. |
| `auth.password` | string | — | Password (password mode), secret-resolved. |
| `query.read_only` | bool | `true` | When true, rejects a statement that doesn't begin with SELECT / WITH / SHOW / DESCRIBE / EXPLAIN. |
| `query.statement_timeout_ms` | int | `60000` | Per-call ceiling on the whole REST round-trip. |
| `query.max_rows` | int | `10000` | Client-side cap on returned rows; extra rows set `truncated`. |
| `operation` | `query`\|`result_scan` | `query` | What the binding does. `query` runs `statement`; `result_scan` re-fetches a prior query's result by the `query_id` argument (see Operations). |
| `statement` | string | — | The operator-fixed SQL. Required for `operation: query`; ignored for `result_scan`. **Caller arguments are NOT templated into it** (see Scope). |

## Operations

### `query` (default)

Runs the operator-fixed `statement` verbatim and returns the rows (see the
examples above).

### `result_scan` — re-fetch a prior result by query id

`operation: result_scan` re-reads a previously-run query's result set by its
Snowflake **query id**, running `SELECT * FROM TABLE(RESULT_SCAN('<id>'))`. This
is a read-only re-fetch — useful for **pagination** over, or re-reading, a large
result without re-running the original (expensive) query. The query id arrives in
the `query_id` tool argument; `output_schema` is untyped rows (like `query`), and
`input_schema` surfaces the required `query_id` string argument. No `statement`
is needed.

> **Safety note (strict id validation, no bind).** `snowflake-api` 0.14 exposes
> **no server-side bind** primitive, so the query id is embedded into the SQL as
> a quoted literal. A query id is **not** free-form SQL — it is a
> server-generated UUID — so the binding validates it against a **strict charset
> allowlist** (ASCII hex digits and hyphens only, non-empty, length-bounded)
> before building the SQL. Anything carrying a quote, whitespace, parenthesis,
> semicolon, comment marker or any other SQL metacharacter is **rejected** (an
> error envelope, no network reached). This is the safe approach given there is
> no bind: an id is data, not SQL.

#### Pagination example

1. Run an expensive query (a `query`-operation binding) and note the Snowflake
   query id it returns (Snowflake surfaces the last query id via
   `last_query_id()`, or the REST response's statement handle).
2. Call the `result_scan` binding with that id to page over / re-read the cached
   result set without re-executing the original query.

```yaml
  capabilities:
    tools:
      # Step 1: the original (expensive) query.
      - name: analytics.run_report
        description: Run the daily report (note its query id from Snowflake).
        backend:
          kind: snowflake
          account: "xy12345.eu-central-1"
          warehouse: "ANALYTICS_WH"
          database: "PROD"
          schema: "PUBLIC"
          auth: { mode: key_pair, username: "svc_mcpg", private_key_pem: "${env.SNOWFLAKE_PRIVATE_KEY}" }
          query: { read_only: true, max_rows: 1000 }
          statement: "SELECT * FROM big_aggregation"

      # Step 2: re-fetch that result set by query id (re-read / pagination).
      - name: analytics.result_scan
        description: Re-fetch a prior query's result set by its Snowflake query id.
        backend:
          kind: snowflake
          account: "xy12345.eu-central-1"
          warehouse: "ANALYTICS_WH"
          database: "PROD"
          schema: "PUBLIC"
          auth: { mode: key_pair, username: "svc_mcpg", private_key_pem: "${env.SNOWFLAKE_PRIVATE_KEY}" }
          query: { read_only: true, max_rows: 1000 }
          operation: result_scan
          # No `statement` — the SQL is `SELECT * FROM TABLE(RESULT_SCAN('<query_id>'))`.
```

Calling `analytics.result_scan` with
`{ "query_id": "01b2c3d4-0000-0000-0000-0123456789ab" }` re-reads that query's
result set.

### As a tool

```yaml
mcp:
  capabilities:
    tools:
      - name: analytics.daily_signups
        description: Daily signup counts for the last 30 days.
        input_schema: { type: object, properties: {} }
        backend:
          kind: snowflake
          account: "xy12345.eu-central-1"
          warehouse: "ANALYTICS_WH"
          database: "PROD"
          schema: "PUBLIC"
          role: "REPORTER"
          auth:
            mode: key_pair
            username: "svc_mcpg"
            private_key_pem: "${env.SNOWFLAKE_PRIVATE_KEY}"
          query:
            read_only: true
            max_rows: 1000
          statement: >
            SELECT day, count(*) AS signups
            FROM events WHERE day >= dateadd(day, -30, current_date())
            GROUP BY day ORDER BY day
```

## MCP surfaces & composition

The same binding works on every MCP surface. The surface is selected by the
capability list the binding sits under plus a `surface:` knob; composition is via
`pipeline` steps and child tools.

### As a pipeline step

Inside a `kind: pipeline` binding, a Snowflake step uses the `snowflake` step
discriminator. The backend config fields are flattened next to `id` / `kind`;
`input_transform` shapes the step's arguments from prior steps.

```yaml
      backend:
        kind: pipeline
        pipeline_timeout_ms: 60000
        steps:
          - id: report
            kind: snowflake
            account: "xy12345.eu-central-1"
            warehouse: "ANALYTICS_WH"
            database: "PROD"
            schema: "PUBLIC"
            auth: { mode: key_pair, username: "svc_mcpg", private_key_pem: "${env.SNOWFLAKE_PRIVATE_KEY}" }
            query: { read_only: true, max_rows: 1000 }
            statement: "SELECT day, count(*) AS signups FROM events GROUP BY day"
            input_transform: "${arguments}"
          - id: summarize
            kind: transform
            expression: "{ 'first_day': steps.report.response.rows[0] }"
```

### As a resource

Place the binding under `mcp.capabilities.resources[]` with `surface: resource`.
Successful rows are reshaped into the `resources/read` `{contents:[…]}` body. Set
a static `uri:` or let the binding use the requested URI from the read call.

```yaml
  capabilities:
    resources:
      - name: analytics.signups
        uri: "snowflake://prod/daily_signups"
        backend:
          kind: snowflake
          account: "xy12345.eu-central-1"
          warehouse: "ANALYTICS_WH"
          database: "PROD"
          schema: "PUBLIC"
          auth: { mode: key_pair, username: "svc_mcpg", private_key_pem: "${env.SNOWFLAKE_PRIVATE_KEY}" }
          query: { read_only: true }
          surface: resource
          uri: "snowflake://prod/daily_signups"
          statement: "SELECT day, count(*) AS signups FROM events GROUP BY day"
```

### As a prompt

Under `mcp.capabilities.prompts[]` with `surface: prompt`, rows are reshaped into
the `prompts/get` `{messages:[…]}` body.

```yaml
  capabilities:
    prompts:
      - name: analytics.context
        backend:
          kind: snowflake
          account: "xy12345.eu-central-1"
          auth: { mode: key_pair, username: "svc_mcpg", private_key_pem: "${env.SNOWFLAKE_PRIVATE_KEY}" }
          surface: prompt
          statement: "SELECT day, count(*) AS signups FROM events GROUP BY day"
```

### As a child tool

An LLM / generator binding can list this binding in its child-tool set, letting
the model call it during a turn. Child dispatch is governed by
`governance.child_invoke.enforce_gates` (depth cap + self-call cycle refusal
apply), so a read-only warehouse query is a safe child.

### Schemas & annotations

`output_schema` for the envelope wrapper is advertised in `tools/list`, and
`input_schema` is advertised too. Operators should mark read-only warehouse
bindings explicitly so clients treat them as side-effect-free:

```yaml
        annotations: { read_only: true, open_world: false }
```

## Response envelope

```jsonc
{
  "toolName": "analytics.daily_signups",
  "profile":  "analytics.daily_signups",
  "request":  { "account": "xy12345.eu-central-1", "database": "PROD", "schema": "PUBLIC" },
  "response": {
    "rows": [ { "DAY": "2026-06-01", "SIGNUPS": 42 } ],
    "count": 1,
    "truncated": false,
    "durationMs": 312
  },
  "truncated": false,
  "downstreamError": null,    // non-null ⇒ isError:true (snowflake_error / transport_error)
  "downstreamErrors": [],
  "error": null
}
```

Snowflake upper-cases unquoted column / alias names — quote or alias them in
the `SELECT` for a specific JSON key case.

## Watching for changes (`snowflake_poll`)

The plugin ships a second `watch_strategy` entity (kind `snowflake_poll`) so a
resource can subscribe to Snowflake changes by **polling**. Snowflake has no
native change-push channel, so each watcher runs a cheap read-only scalar
"high-water" `tracking_query` on a cadence and emits
`notifications/resources/updated` whenever that scalar advances.

Each watcher is self-contained: it carries its own connection + auth (the same
shape as the backend binding) plus the tracking query and cadence.

| Field | Type | Default | Notes |
|---|---|---|---|
| `account` | string (required) | — | Snowflake account identifier; determines the REST host. |
| `warehouse` / `database` / `schema` / `role` | string | — | Session context (same as the backend binding). |
| `auth` | object (required) | — | Key-pair JWT or password block, identical to the backend binding. Bare `cred://` rejected. |
| `tracking_query` | string (required) | — | Read-only scalar high-water query (e.g. `SELECT max(updated_at) FROM events`); first row's first column is the cursor. Held to the read-only keyword guard. |
| `interval_ms` | int | `60000` | Poll cadence, floored at 250 ms by the SDK helper. |
| `timeout_ms` | int | `10000` | Per-tick wall-clock budget for the tracking query. |

The first successful poll establishes the baseline **without** emitting, so a
watcher never fires spuriously at startup. A non-null cursor that differs from
the previously-seen non-null cursor signals a change. Empty tables (zero rows)
or a NULL scalar are treated as "no change". An empty / non-read-only
`tracking_query`, an empty `account` / `auth.username`, or a bare `cred://`
secret is rejected at watch start.

```yaml
  capabilities:
    resources:
      - name: analytics.signups
        uri: "snowflake://prod/daily_signups"
        watch:
          kind: snowflake_poll
          account: "xy12345.eu-central-1"
          warehouse: "ANALYTICS_WH"
          database: "PROD"
          schema: "PUBLIC"
          role: "REPORTER"
          auth: { mode: key_pair, username: "svc_mcpg", private_key_pem: "${env.SNOWFLAKE_PRIVATE_KEY}" }
          tracking_query: "SELECT max(updated_at) FROM events"
          interval_ms: 30000
          timeout_ms: 5000
```

## Security

- **Operator-fixed statement.** The SQL is fixed in config; caller arguments
  are not interpolated into it in v1, so there is no caller-driven SQL surface.
- **No SSRF.** `account` (which selects the Snowflake host) is
  operator-configured, never caller-templated.
- **No plaintext secrets.** The key / password resolves through the gateway
  secret-resolver; it is never committed.
- **Bare `cred://` not supported.** The connection is one service identity, so
  a bare per-caller `cred://` secret is rejected at config validation.
- **Read-only guard.** With `query.read_only` (default on), a statement that
  doesn't begin with a read-only keyword is rejected fail-closed before
  anything is sent to Snowflake.
- **Strict query-id validation (`result_scan`).** Because the REST driver has
  no server-side bind, the `query_id` argument is embedded as a quoted literal.
  It is validated against a strict charset allowlist (hex digits + hyphens only,
  length-bounded) before the SQL is built — a query id is data, not SQL, so any
  quote / whitespace / semicolon / comment / metacharacter is rejected
  fail-closed (no network reached). `result_scan` is itself read-only (a
  result re-fetch).

## Build / test

```bash
nx build mcpg-plugin-backend-snowflake
nx test  mcpg-plugin-backend-snowflake                                       # unit tests (no network / credentials)
cargo test -p mcpg-plugin-backend-snowflake --features integration-tests     # live Snowflake (env-driven; skips when unset)
nx lint  mcpg-plugin-backend-snowflake
```

The integration test reads `SNOWFLAKE_TEST_ACCOUNT` / `_USER` /
`_PRIVATE_KEY_PEM` (or `_PASSWORD`) / `_WAREHOUSE` / `_DATABASE` / `_SCHEMA` /
`_ROLE`; with the required ones unset it prints a skip notice and passes as a
no-op (there is no Snowflake docker image).

## Scope / deferred

- **Per-caller credentials** (per-cred connections) — v1 is one service
  identity per binding.
- **CEL-bound parameters.** Unlike the `clickhouse` / `oracle` / `sql`
  backends, Snowflake has **no** CEL `params` surface. The `snowflake-api`
  REST driver exposes no server-side bind primitive: its `exec` takes only a
  SQL string, and the wire request body (`ExecRequest`) carries no `bindings`
  field, with the request-building path private (un-overridable). The
  operator-fixed `statement` therefore runs verbatim — caller arguments are
  never interpolated. Binding caller input would require string interpolation
  (an injection surface), so it is deliberately omitted rather than faked.
  `complete_template_variable` is likewise a no-op (the caller prefix has no
  safe bind target). A follow-on would require a Snowflake driver that exposes
  the SQL API `bindings` map.
- **PUT / GET (stage file transfer)** and multi-statement scripts are out of
  scope; v1 runs a single analytical statement.
- **Rich type fidelity.** Arrow result sets are decoded via `arrow-json` with
  explicit nulls; large decimals / temporal types follow `arrow-json`'s JSON
  rendering.
```
