# simplifi-mcp

**Unofficial, community-maintained Rust MCP server + client library for Quicken
Simplifi.** A security-hardened rewrite of
[krconv/quicken-simplifi-mcp](https://github.com/krconv/quicken-simplifi-mcp)
(TypeScript) built on the official
[MCP Rust SDK (`rmcp`)](https://github.com/modelcontextprotocol/rust-sdk).

> ## ⚠️ Use at your own risk
>
> Quicken Simplifi has **no official public API**. This project speaks to the
> Simplifi web app's internal REST endpoints (`services.quicken.com`) using your own
> account credentials. Quicken's Terms of Service prohibit interfacing with the
> service through unapproved means — running this may violate those terms, and
> automated access can trip Quicken's anti-fraud systems and **flag or lock your
> account**. It is intended strictly for single-user, own-account, personal use.
> This project is **not affiliated with or endorsed by Quicken Inc.** Endpoints may
> break without notice.

## Why this exists

The upstream TypeScript server proved the idea; this port keeps its MCP tool surface
(wire-compatible names) and adds the security work an always-on finance-adjacent
daemon deserves:

- **Encrypted-at-rest token cache** (XChaCha20-Poly1305, key in the macOS Keychain /
  env / 0600 key file) — no plaintext tokens, ever. `0600`/`0700` permissions enforced
  at every open.
- **Account-lockout protection as defaults, not options**: single-flight auth,
  exponential backoff, a hard rolling-24h credential-login budget, one persisted
  ThreatMetrix device identity, a global request pacing floor, and `Retry-After`
  honoring. (Upstream's failure mode was ~1,440 password logins/day on a stuck
  refresh.)
- **Read-only by default**; typed, allowlisted patches instead of a free-form deep
  merge; an **append-only audit journal** with before/after images for every
  mutation; a per-hour write quota.
- **SSRF-hardened** pagination (host allowlist, https-only, redirects disabled,
  cycle detection) and an error taxonomy that never leaks upstream response bodies.
- Decimal-exact money end-to-end (`rust_decimal`; amounts cross the MCP boundary as
  strings, never floats).

See [SECURITY.md](SECURITY.md) for the full threat model and mitigation table.

## Quick start

```sh
cargo build --release                 # stdio MCP server + CLI
./target/release/simplifi-mcp login   # one-time interactive login (MFA-aware)
./target/release/simplifi-mcp serve   # MCP server on stdio
```

### Credentials via 1Password (recommended)

Nothing secret goes in config files. Put the values in 1Password, reference them
from a `.env` file, and let `op run` inject them per-process:

```sh
# .env (values are op:// references, not secrets — see .env.example)
SIMPLIFI_EMAIL=op://Private/Simplifi/username
SIMPLIFI_PASSWORD=op://Private/Simplifi/password
SIMPLIFI_CLIENT_SECRET=op://Private/Simplifi/client-secret

op run --env-file=.env -- ./target/release/simplifi-mcp login
```

Claude Desktop / Claude Code MCP entry:

```json
{
  "mcpServers": {
    "simplifi": {
      "command": "op",
      "args": ["run", "--env-file=/path/to/.env", "--", "/path/to/simplifi-mcp", "serve"]
    }
  }
}
```

After the one-time `login`, the server runs on the encrypted refresh token alone —
the password does not need to be present in the environment again.

### About `SIMPLIFI_CLIENT_SECRET`

The Simplifi web app authenticates with an OAuth client id/secret embedded in its
own JavaScript bundle. This project deliberately does **not** bundle that secret.
Log in to Simplifi in your browser with DevTools open, find the `POST /oauth/token`
request, and copy the `clientSecret` value from its body into your own environment.

## Configuration

Everything is a `SIMPLIFI_*` environment variable (defaults shown; see
`.env.example` for the complete annotated list).

| Variable | Default | Purpose |
|---|---|---|
| `SIMPLIFI_EMAIL` / `SIMPLIFI_PASSWORD` | — | Login credentials; needed only for `login` |
| `SIMPLIFI_CLIENT_SECRET` | — | Quicken web-app OAuth secret (see above); required for token exchange/refresh |
| `SIMPLIFI_MCP_TOKEN_KEY` / `_FILE` | keychain | Token-cache key (base64, 32 bytes); macOS Keychain auto-creates one if unset |
| `SIMPLIFI_DATA_DIR` | `~/Library/Application Support/simplifi-mcp` (or `$XDG_DATA_HOME`) | Encrypted token cache + audit journal |
| `SIMPLIFI_DATASET_ID` | auto-discovered | Explicit dataset for multi-dataset accounts |
| `SIMPLIFI_TM_SESSION_ID` | generated once, persisted | ThreatMetrix device id override |
| `SIMPLIFI_MIN_REQUEST_INTERVAL_MS` | `250` | Global upstream pacing floor |
| `SIMPLIFI_MAX_CREDENTIAL_LOGINS_PER_24H` | `3` | Rolling login budget; excess ⇒ quarantine |
| `SIMPLIFI_AUTO_PASSWORD_LOGIN` | `false` | Allow refresh failure to fall back to a budgeted password login |
| `SIMPLIFI_ENABLE_UNVERIFIED_WRITES` | `false` | Enable the HAR-unverified create/bulk/delete endpoints |
| `SIMPLIFI_MCP_ALLOW_WRITES` | `false` | Enable mutating MCP tools (server is read-only otherwise) |
| `SIMPLIFI_MCP_MAX_STALE_SECS` | `120` | Mirror freshness window before a read triggers a sync |
| `SIMPLIFI_MCP_MIN_SYNC_INTERVAL_SECS` | `30` | Hard floor between upstream syncs (`refresh:true` cannot bypass) |
| `SIMPLIFI_MCP_MAX_WRITES_PER_HOUR` | `60` | Rolling mutation quota (bulk rows count individually) |
| `SIMPLIFI_MCP_HTTP_TOKEN` | — | Bearer token for `serve-http` (required, ≥ 32 chars) |
| `SIMPLIFI_MCP_HTTP_ALLOW_NONLOCAL` | `false` | Permit non-loopback bind for `serve-http` |

## MCP tools (21)

Read tools serve a freshness-gated in-memory mirror: the first call full-fetches
transactions + reference data, later calls sync incrementally (`modifiedAfter`).
`refresh: true` requests a sync but can never push upstream traffic past the sync
floor. Conventions: **amounts are decimal strings** (`"-12.34"`), dates are ISO
`YYYY-MM-DD`, every input schema is strict (`additionalProperties: false`), list
outputs are `{total, nextCursor?, items}`.

**Upstream-parity (wire-compatible names)**

| Tool | Purpose |
|---|---|
| `list_transactions` | Filtered, cursor-paginated transaction listing (account, date range, amount range, tombstones) |
| `search_transactions` | Case-insensitive text search over payee / renamedPayee / memo / mlInferredPayee + the same filters |
| `get_transaction` | One transaction by id (syncs once on cache miss) |
| `update_transaction` | Typed, allowlisted patch (payee, memo, category, tags, postedOn, amount, review flags) — **write-gated** |
| `categorize_transaction` | Assign `coa = {type: CATEGORY, id}` — **write-gated** |
| `list_uncategorized_transactions` | Transactions with no real category |
| `search_merchants` | Merchant-identity aggregation with counts |
| `list_categories` / `search_categories` | Category reference data |
| `list_tags` / `search_tags` | Tag reference data |
| `suggest_categories_for_merchant` | Historical categorization suggestions for a merchant |

**Additions in this port**

| Tool | Purpose |
|---|---|
| `create_transaction` | One manual transaction — **write-gated + unverified-endpoint-gated** |
| `bulk_import_transactions` | Simplifi import-template CSV (`Date,Payee,Amount[,Tags][,Memo]`, ≤ 1000 rows); `confirm:false` previews, `confirm:true` creates — same double gate |
| `list_accounts` | Raw Simplifi account objects |
| `account_balances` | Balance-ish fields per account, as decimal strings |
| `list_datasets` | Datasets visible to the logged-in user |
| `export_transactions` | `json`, `csv` (import-template), or `csv_full` (archival); oldest-first, 10k cap, formula-injection-sanitized |
| `recurring_detection` | Normalized-payee cadence detection (weekly → annual) with next-expected dates |
| `split_transaction` | Split a transaction across ≥ 2 categories; line amounts must total the transaction amount exactly (decimal-checked) — **write-gated**. Wire shape observed from live transactions and verified end-to-end (fresh-split and re-split PUTs, 2026-10-27): `split = {"items": [...]}`, no parent `coa`; re-splits preserve line ids. Setting a category directly on a split transaction clears its split, mirroring the web app |
| `bulk_update_transactions` | Apply one typed patch to every transaction matching the read-lane filters (+ optional text query); `confirm:false` previews matches, `confirm:true` applies sequentially — **write-gated** |

### Write gating (defense in depth)

1. `SIMPLIFI_MCP_ALLOW_WRITES=1` — otherwise every mutating tool returns
   `{"error":"writes_disabled"}`.
2. `create` / `bulk_import` additionally require `SIMPLIFI_ENABLE_UNVERIFIED_WRITES=1`
   because the creation endpoint's wire shape is inferred, not HAR-verified.
3. `bulk_import_transactions` requires an explicit `confirm: true` (default is a
   dry-run preview).
4. A rolling per-hour write quota applies (default 60).
5. Every accepted mutation is journaled to `data_dir/audit.jsonl` (append-only,
   `0600`): an `attempt` record with the before-image *before* any upstream call and
   a `result` record with the after-image/ack. If the journal can't be opened, the
   server forces itself read-only.

## Transports

- **stdio** (default, recommended): `simplifi-mcp serve`. Logs go to stderr.
- **Streamable HTTP** (optional, `--features http`): `simplifi-mcp serve-http
  [--bind 127.0.0.1:8787]`. Requires `SIMPLIFI_MCP_HTTP_TOKEN` (≥ 32 chars; e.g.
  `openssl rand -base64 33`). Loopback-only unless explicitly acknowledged;
  constant-time token check; no CORS; security headers on every response. The
  upstream project's multi-user OAuth authorization server is intentionally **not**
  reimplemented — this is a single-user server.

## CLI

```sh
simplifi-mcp login          # interactive credential login (prompts for MFA code)
simplifi-mcp import-session --from-auth-session f.json  # seed token cache from a browser session export
simplifi-mcp logout         # clear cached tokens
simplifi-mcp status         # redacted cache status (never prints secrets)
simplifi-mcp whoami         # GET /userprofiles/me sanity probe
simplifi-mcp datasets|accounts|categories|tags
simplifi-mcp transactions --all --date-on-after 2024-01-01
simplifi-mcp earliest-date-on
simplifi-mcp inspect-split <txn-id>   # raw split object + parsed lines (split-shape verification)
simplifi-mcp serve          # MCP over stdio
simplifi-mcp serve-http     # MCP over HTTP (feature `http`)
```

## Development — mock mode

The `mock` feature swaps the HTTP transport for a recorded-fixture transport so the
entire stack (auth flow, MFA challenge, pagination, tools) runs with **zero live
credentials and zero network**:

```sh
cargo test --features mock            # full suite: 85 tests, no network
cargo test --features "mock http"     # + HTTP transport tests
cargo clippy --all-targets --features "mock http" -- -D warnings
cargo audit
```

Fixtures live in `fixtures/` (JSON request/response pairs served by
`src/mock.rs`). To write a test against the mock stack, build a `Config` with
`KeySource::Static`, wrap `MockTransport::with_default_fixtures()` in
`Transport::Mock`, and drive `SimplifiClient`/`SimplifiMcpServer` directly — see
`tests/mcp_tools.rs` for the pattern. Unit tests cover auth parsing, models
(round-trip of unknown fields, patch allowlisting), decimal money, the CSV codec,
recurring detection, the encrypted cache format, and the audit journal.

Library layout: `config` · `secrets` · `token_cache` · `auth` · `transport` ·
`client` · `models` · `money` · `local` · `store` · `server` · `csvio` ·
`recurring` · `audit` · `http` (feature) · `mock` (feature).

## Credits & licensing

MIT — see [LICENSE](LICENSE). This is a from-scratch Rust implementation, but its
knowledge of the Simplifi wire protocol and parts of its design derive from three
MIT-licensed projects, whose notices are reproduced in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) as their licenses require:

- **[krconv/quicken-simplifi-mcp](https://github.com/krconv/quicken-simplifi-mcp)** —
  the primary upstream: endpoint constants, data models, sync strategy, and the MCP
  tool surface were ported from it.
- **[rijn/simplifiapi](https://github.com/rijn/simplifiapi)** — discovered the
  `GET /datasets`, `GET /accounts`, and `GET /userprofiles/me` endpoints used for
  dataset auto-discovery and health probes.
- **[apderosso/Quicken-Simplifi-API](https://github.com/apderosso/Quicken-Simplifi-API)** —
  reference for the web-UI CSV import format; no wire-protocol code derives from it.

Not affiliated with Quicken Inc. "Quicken" and "Simplifi" are trademarks of
Quicken Inc., used here only to identify the service this software interoperates
with.
