//! MCP server layer (rmcp, official Rust MCP SDK).
//!
//! Upstream-parity tool names/semantics (PORTING-SPEC section 6) plus the B2
//! feature additions: create_transaction, bulk_import_transactions,
//! list_accounts, account_balances, recurring_detection, export_transactions,
//! list_datasets.
//!
//! Conventions at the MCP boundary:
//! - amounts are DECIMAL STRINGS ("-12.34"), never JSON floats
//! - dates are ISO (YYYY-MM-DD)
//! - every input schema is strict (`deny_unknown_fields` -> additionalProperties:false)
//! - tool failures are tool-level results (`isError:true` with a JSON payload of
//!   `{error, message}`) so callers always see them; protocol errors are reserved
//!   for malformed requests
//!
//! Security posture (SECURITY-AUDIT):
//! - the server is READ-ONLY unless `SIMPLIFI_MCP_ALLOW_WRITES=1` (SA-09)
//! - creation endpoints stay additionally behind `SIMPLIFI_ENABLE_UNVERIFIED_WRITES=1`
//!   until HAR-verified (spec section 8)
//! - bulk import requires an explicit `confirm:true` argument (SA-09)
//! - `refresh:true` cannot bypass the upstream sync floor (SA-13, store layer)
//! - error payloads carry status+code only, never upstream bodies (SA-11)

use std::sync::{Arc, Mutex};

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use rust_decimal::Decimal;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use crate::audit::AuditLog;
use crate::client::SimplifiClient;
use crate::error::Error;
use crate::local;
use crate::models::{CoaRef, NewTransaction, Transaction, TransactionPatch};
use crate::money::parse_decimal;
use crate::recurring;
use crate::store::SyncStore;

const DEFAULT_PAGE: usize = 50;
const MAX_PAGE: usize = 200;
const MAX_EXPORT_ROWS: usize = 10_000;

// ==================================================================== inputs

/// Shared list/filter/pagination arguments (upstream `list_transactions` shape;
/// amounts are decimal strings here, unlike upstream's floats).
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListTransactionsInput {
    /// Page size, 1-200 (default 50).
    #[schemars(range(min = 1, max = 200))]
    pub limit: Option<u32>,
    /// Opaque pagination cursor returned as `nextCursor` by a previous call.
    pub cursor: Option<String>,
    /// Restrict to one account id.
    pub account_id: Option<String>,
    /// Inclusive lower bound on postedOn, ISO date YYYY-MM-DD.
    pub date_from: Option<String>,
    /// Inclusive upper bound on postedOn, ISO date YYYY-MM-DD.
    pub date_to: Option<String>,
    /// Inclusive lower bound on the signed amount, as a decimal string (e.g. "-50.00").
    pub min_amount: Option<String>,
    /// Inclusive upper bound on the signed amount, as a decimal string.
    pub max_amount: Option<String>,
    /// Include tombstoned (isDeleted) transactions. Default false.
    pub include_deleted: Option<bool>,
    /// Sync with Simplifi before answering (rate-limited server-side). Default false.
    pub refresh: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchTransactionsInput {
    /// Case-insensitive substring matched against payee, renamedPayee, memo and
    /// mlInferredPayee.
    #[schemars(length(min = 1))]
    pub query: String,
    #[schemars(range(min = 1, max = 200))]
    pub limit: Option<u32>,
    pub cursor: Option<String>,
    pub account_id: Option<String>,
    /// ISO date YYYY-MM-DD.
    pub date_from: Option<String>,
    /// ISO date YYYY-MM-DD.
    pub date_to: Option<String>,
    /// Decimal string.
    pub min_amount: Option<String>,
    /// Decimal string.
    pub max_amount: Option<String>,
    pub include_deleted: Option<bool>,
    pub refresh: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetTransactionInput {
    #[schemars(length(min = 1))]
    pub transaction_id: String,
    /// On cache miss, sync once and retry before failing. Default true.
    pub refresh_on_miss: Option<bool>,
}

/// Typed, allowlisted patch (SA-09/SA-14: no free-form merge; unknown fields are
/// rejected at the schema boundary).
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransactionPatchInput {
    pub payee: Option<String>,
    pub renamed_payee: Option<String>,
    pub memo: Option<String>,
    /// Category id — sets `coa = {type:"CATEGORY", id}`.
    pub category_id: Option<String>,
    /// Replaces the transaction's tag id list.
    pub tags: Option<Vec<String>>,
    pub is_reviewed: Option<bool>,
    pub is_excluded_from_reports: Option<bool>,
    /// ISO date YYYY-MM-DD.
    pub posted_on: Option<String>,
    /// Decimal string, e.g. "-12.34".
    pub amount: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateTransactionInput {
    #[schemars(length(min = 1))]
    pub transaction_id: String,
    pub patch: TransactionPatchInput,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CategorizeTransactionInput {
    #[schemars(length(min = 1))]
    pub transaction_id: String,
    #[schemars(length(min = 1))]
    pub category_id: String,
}

/// One line of a split: a category and a signed amount (decimal string). Line
/// amounts must total the transaction amount exactly.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplitLineInput {
    #[schemars(length(min = 1))]
    pub category_id: String,
    /// Signed decimal string, e.g. "-34.23".
    #[schemars(length(min = 1))]
    pub amount: String,
    pub memo: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplitTransactionInput {
    #[schemars(length(min = 1))]
    pub transaction_id: String,
    /// At least two lines; amounts must total the transaction amount exactly.
    #[schemars(length(min = 2))]
    pub lines: Vec<SplitLineInput>,
}

/// Bulk-apply one typed patch to every transaction matching the filters (the
/// read-lane filter set plus an optional text query). With `confirm` false
/// (default) this is a dry run: it reports how many transactions match and
/// changes nothing.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BulkUpdateTransactionsInput {
    /// Case-insensitive substring over payee / renamedPayee / memo /
    /// mlInferredPayee.
    pub query: Option<String>,
    pub account_id: Option<String>,
    /// ISO date YYYY-MM-DD.
    pub date_from: Option<String>,
    /// ISO date YYYY-MM-DD.
    pub date_to: Option<String>,
    /// Decimal string.
    pub min_amount: Option<String>,
    /// Decimal string.
    pub max_amount: Option<String>,
    pub include_deleted: Option<bool>,
    /// Sync with Simplifi before matching. Default false.
    pub refresh: Option<bool>,
    pub patch: TransactionPatchInput,
    /// False (default) = preview only. True = apply the patch to every match.
    pub confirm: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchMerchantsInput {
    /// Case-insensitive substring over the merchant identity
    /// (renamedPayee -> payee -> mlInferredPayee).
    #[schemars(length(min = 1))]
    pub query: String,
    #[schemars(range(min = 1, max = 200))]
    pub limit: Option<u32>,
    pub include_deleted: Option<bool>,
    pub refresh: Option<bool>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListReferenceInput {
    /// Re-fetch reference data from Simplifi first. Default false.
    pub refresh: Option<bool>,
    /// Max items returned, 1-5000.
    #[schemars(range(min = 1, max = 5000))]
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchReferenceInput {
    /// Case-insensitive name substring.
    #[schemars(length(min = 1))]
    pub query: String,
    pub refresh: Option<bool>,
    #[schemars(range(min = 1, max = 5000))]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum MatchModeInput {
    Exact,
    Contains,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SuggestCategoriesInput {
    /// Merchant identity to look up historical categorizations for.
    #[schemars(length(min = 1))]
    pub merchant: String,
    /// 1-20, default 5.
    #[schemars(range(min = 1, max = 20))]
    pub limit: Option<u32>,
    /// "exact" or "contains" (default "contains").
    pub match_mode: Option<MatchModeInput>,
    pub refresh_categories: Option<bool>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RefreshOnlyInput {
    /// Re-fetch from Simplifi first. Default false.
    pub refresh: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateTransactionInput {
    #[schemars(length(min = 1))]
    pub account_id: String,
    /// ISO date YYYY-MM-DD.
    #[schemars(length(min = 1))]
    pub posted_on: String,
    #[schemars(length(min = 1))]
    pub payee: String,
    /// Signed decimal string, e.g. "-4.50" for a purchase.
    #[schemars(length(min = 1))]
    pub amount: String,
    pub memo: Option<String>,
    /// Category id — sets `coa = {type:"CATEGORY", id}`.
    pub category_id: Option<String>,
    /// Tag id list.
    pub tags: Option<Vec<String>>,
    /// Idempotency key; a UUIDv4 is generated when omitted.
    pub client_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BulkImportInput {
    /// Account the rows are created in.
    #[schemars(length(min = 1))]
    pub account_id: String,
    /// CSV text, Simplifi import template: `Date,Payee,Amount[,Tags][,Memo]`.
    /// Dates M/D/YYYY or YYYY-MM-DD; amounts plain decimals ($ , () accepted).
    /// Header row optional. Max 1000 rows.
    #[schemars(length(min = 1))]
    pub csv: String,
    /// False (default) = parse-and-preview only. True = actually create.
    pub confirm: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    /// JSON array of transactions (amounts as decimal strings, ISO dates).
    #[default]
    Json,
    /// Simplifi-import-template CSV (`Date,Payee,Amount,Tags`, M/D/YYYY dates).
    Csv,
    /// Archival CSV with the full column set (ISO dates).
    CsvFull,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportTransactionsInput {
    /// "json" (default), "csv" (Simplifi import template) or "csv_full" (archival).
    pub format: Option<ExportFormat>,
    pub account_id: Option<String>,
    /// ISO date YYYY-MM-DD.
    pub date_from: Option<String>,
    /// ISO date YYYY-MM-DD.
    pub date_to: Option<String>,
    /// Case-insensitive payee/memo substring filter.
    pub query: Option<String>,
    pub include_deleted: Option<bool>,
    /// Row cap, 1-10000 (default 10000).
    #[schemars(range(min = 1, max = 10000))]
    pub max_rows: Option<u32>,
    pub refresh: Option<bool>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecurringDetectionInput {
    /// Restrict to one account id.
    pub account_id: Option<String>,
    /// Ignore transactions before this ISO date.
    pub date_from: Option<String>,
    /// Minimum occurrences to call something recurring, 2-12 (default 3).
    #[schemars(range(min = 2, max = 12))]
    pub min_occurrences: Option<u32>,
    pub refresh: Option<bool>,
}

// ================================================================ conversions

struct TxnQuery {
    account_id: Option<String>,
    date_from: Option<String>,
    date_to: Option<String>,
    min_amount: Option<Decimal>,
    max_amount: Option<Decimal>,
    include_deleted: bool,
}

impl TxnQuery {
    #[allow(clippy::too_many_arguments)]
    fn build(
        account_id: Option<String>,
        date_from: Option<String>,
        date_to: Option<String>,
        min_amount: Option<String>,
        max_amount: Option<String>,
        include_deleted: Option<bool>,
    ) -> Result<TxnQuery, String> {
        for d in [&date_from, &date_to].into_iter().flatten() {
            validate_iso_date(d)?;
        }
        Ok(TxnQuery {
            account_id,
            date_from,
            date_to,
            min_amount: min_amount.as_deref().map(parse_decimal).transpose()?,
            max_amount: max_amount.as_deref().map(parse_decimal).transpose()?,
            include_deleted: include_deleted.unwrap_or(false),
        })
    }

    fn matches(&self, t: &Transaction) -> bool {
        if !self.include_deleted && t.is_deleted.unwrap_or(false) {
            return false;
        }
        if let Some(acc) = &self.account_id {
            if t.account_id.as_deref() != Some(acc.as_str()) {
                return false;
            }
        }
        // ISO dates compare lexicographically.
        if let Some(from) = &self.date_from {
            match t.posted_on.as_deref() {
                Some(p) if p >= from.as_str() => {}
                _ => return false,
            }
        }
        if let Some(to) = &self.date_to {
            match t.posted_on.as_deref() {
                Some(p) if p <= to.as_str() => {}
                _ => return false,
            }
        }
        if let Some(min) = self.min_amount {
            match t.amount {
                Some(a) if a >= min => {}
                _ => return false,
            }
        }
        if let Some(max) = self.max_amount {
            match t.amount {
                Some(a) if a <= max => {}
                _ => return false,
            }
        }
        true
    }
}

fn validate_iso_date(s: &str) -> Result<(), String> {
    chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .map(|_| ())
        .map_err(|_| format!("invalid date {s:?}: expected YYYY-MM-DD"))
}

fn text_matches(t: &Transaction, q_lower: &str) -> bool {
    [&t.payee, &t.renamed_payee, &t.memo, &t.ml_inferred_payee]
        .into_iter()
        .flatten()
        .any(|s| s.to_lowercase().contains(q_lower))
}

/// Transaction as MCP output JSON: wire shape, but `amount` promoted to a
/// decimal string (money never crosses the MCP boundary as a float).
fn txn_out(t: &Transaction) -> serde_json::Value {
    let mut v = serde_json::to_value(t).unwrap_or_else(|_| json!({}));
    if let (Some(amount), Some(obj)) = (t.amount, v.as_object_mut()) {
        obj.insert("amount".to_string(), json!(amount.to_string()));
    }
    // Parsed split lines alongside the raw `split` object, amounts as decimal
    // strings like the parent amount.
    if let (Some(lines), Some(obj)) = (t.split_lines(), v.as_object_mut()) {
        let parsed: Vec<serde_json::Value> = lines
            .iter()
            .map(|l| {
                json!({
                    "categoryId": l.coa.as_ref().and_then(|c| c.id.clone()),
                    "amount": l.amount.map(|a| a.to_string()),
                    "memo": l.memo,
                })
            })
            .collect();
        obj.insert("splits".to_string(), json!(parsed));
    }
    v
}

fn paginate(
    items: Vec<serde_json::Value>,
    limit: Option<u32>,
    cursor: Option<&str>,
) -> Result<serde_json::Value, String> {
    let limit = (limit.map(|l| l as usize).unwrap_or(DEFAULT_PAGE)).clamp(1, MAX_PAGE);
    let offset: usize = match cursor {
        None => 0,
        Some(c) => c
            .parse()
            .map_err(|_| format!("invalid cursor {c:?} (use the returned nextCursor)"))?,
    };
    let total = items.len();
    let page: Vec<serde_json::Value> = items.into_iter().skip(offset).take(limit).collect();
    let consumed = offset.saturating_add(page.len());
    let mut out = json!({ "total": total, "items": page });
    if consumed < total {
        out["nextCursor"] = json!(consumed.to_string());
    }
    Ok(out)
}

fn ok_json(v: serde_json::Value) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![ContentBlock::text(
        v.to_string(),
    )]))
}

fn err_json(
    code: &'static str,
    message: impl std::fmt::Display,
) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::error(vec![ContentBlock::text(
        json!({ "error": code, "message": message.to_string() }).to_string(),
    )]))
}

fn err_code(e: &Error) -> &'static str {
    match e {
        Error::AuthRequired(_) => "auth_required",
        Error::MfaRequired(_) => "mfa_required",
        Error::LoginQuarantined { .. } | Error::RefreshBackoff { .. } => "rate_limited",
        Error::UnverifiedEndpointDisabled(_) => "unverified_endpoint_disabled",
        Error::MissingFields(_) => "missing_fields",
        Error::InvalidArgument(_) => "invalid_argument",
        Error::Api { .. } => "simplifi_api_error",
        _ => "simplifi_error",
    }
}

fn upstream_err(e: Error) -> Result<CallToolResult, McpError> {
    err_json(err_code(&e), e)
}

// ==================================================================== server

#[derive(Clone)]
pub struct SimplifiMcpServer {
    store: Arc<SyncStore>,
    allow_writes: bool,
    /// Append-only mutation journal (SA-09). `Some` exactly when writes are enabled;
    /// if it cannot be opened the server falls back to read-only (fail closed).
    audit: Option<Arc<AuditLog>>,
    /// Rolling-hour mutation timestamps for the write quota (SA-09).
    write_times: Arc<Mutex<Vec<i64>>>,
    max_writes_per_hour: u32,
}

impl SimplifiMcpServer {
    pub fn new(client: SimplifiClient) -> Self {
        let cfg = client.config();
        let mut allow_writes = cfg.mcp_allow_writes;
        let max_writes_per_hour = cfg.mcp_max_writes_per_hour;
        let audit = if allow_writes {
            match AuditLog::open(&cfg.data_dir) {
                Ok(log) => Some(Arc::new(log)),
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "audit journal unavailable; forcing read-only mode (SA-09 fail-closed)"
                    );
                    allow_writes = false;
                    None
                }
            }
        } else {
            None
        };
        SimplifiMcpServer {
            store: Arc::new(SyncStore::new(Arc::new(client))),
            allow_writes,
            audit,
            write_times: Arc::new(Mutex::new(Vec::new())),
            max_writes_per_hour,
        }
    }

    pub fn store(&self) -> &SyncStore {
        &self.store
    }

    fn write_gate(&self) -> Result<(), &'static str> {
        if self.allow_writes {
            Ok(())
        } else {
            Err("this server is read-only; start it with SIMPLIFI_MCP_ALLOW_WRITES=1 \
                 to enable mutating tools (SA-09 default)")
        }
    }

    /// Rolling per-hour write quota (SA-09). `cost` is the number of mutations this
    /// call will perform (bulk import: one per row). Reserves the slots on success.
    fn write_quota(&self, cost: usize) -> Result<(), String> {
        if self.max_writes_per_hour == 0 {
            return Ok(());
        }
        let now = crate::token_cache::now_unix();
        let mut times = self.write_times.lock().expect("write quota lock");
        times.retain(|t| now - *t < 3600);
        if times.len() + cost > self.max_writes_per_hour as usize {
            let oldest = times.iter().min().copied().unwrap_or(now);
            return Err(format!(
                "write quota exceeded: {} of {} mutations used this hour (cost {}); retry \
                 in {}s or raise SIMPLIFI_MCP_MAX_WRITES_PER_HOUR",
                times.len(),
                self.max_writes_per_hour,
                cost,
                ((oldest + 3600) - now).max(0)
            ));
        }
        times.extend(std::iter::repeat_n(now, cost));
        Ok(())
    }

    /// The audit journal; present whenever writes are enabled (see [`Self::new`]).
    fn audit(&self) -> Result<&AuditLog, &'static str> {
        self.audit
            .as_deref()
            .ok_or("audit journal unavailable; writes are disabled (SA-09 fail-closed)")
    }

    /// Load-or-sync a transaction by id (one forced retry on miss when allowed).
    async fn fetch_txn(
        &self,
        id: &str,
        refresh_on_miss: bool,
    ) -> Result<Option<Transaction>, Error> {
        self.store.ensure_transactions(false).await?;
        if let Some(t) = self.store.get_transaction(id).await {
            return Ok(Some(t));
        }
        if refresh_on_miss {
            self.store.ensure_transactions(true).await?;
            return Ok(self.store.get_transaction(id).await);
        }
        Ok(None)
    }

    async fn filtered_snapshot(
        &self,
        q: &TxnQuery,
        text_query: Option<&str>,
    ) -> Vec<Transaction> {
        let q_lower = text_query.map(str::to_lowercase);
        let mut snapshot = self.store.transactions_snapshot().await;
        snapshot.retain(|t| {
            q.matches(t)
                && q_lower
                    .as_deref()
                    .map(|ql| text_matches(t, ql))
                    .unwrap_or(true)
        });
        snapshot
    }
}

#[tool_router(vis = "pub")]
impl SimplifiMcpServer {
    // ------------------------------------------------------------- read lane

    #[tool(
        description = "List transactions from the local Simplifi mirror with filters and \
                       cursor pagination. Amounts are decimal strings; dates ISO YYYY-MM-DD."
    )]
    pub async fn list_transactions(
        &self,
        Parameters(input): Parameters<ListTransactionsInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self
            .store
            .ensure_transactions(input.refresh.unwrap_or(false))
            .await
        {
            return upstream_err(e);
        }
        let q = match TxnQuery::build(
            input.account_id,
            input.date_from,
            input.date_to,
            input.min_amount,
            input.max_amount,
            input.include_deleted,
        ) {
            Ok(q) => q,
            Err(e) => return err_json("invalid_argument", e),
        };
        let items: Vec<_> = self
            .filtered_snapshot(&q, None)
            .await
            .iter()
            .map(txn_out)
            .collect();
        match paginate(items, input.limit, input.cursor.as_deref()) {
            Ok(v) => ok_json(v),
            Err(e) => err_json("invalid_argument", e),
        }
    }

    #[tool(
        description = "Case-insensitive text search across payee, renamedPayee, memo and \
                       mlInferredPayee, with the same filters/pagination as list_transactions."
    )]
    pub async fn search_transactions(
        &self,
        Parameters(input): Parameters<SearchTransactionsInput>,
    ) -> Result<CallToolResult, McpError> {
        if input.query.trim().is_empty() {
            return err_json("invalid_argument", "query must be non-empty");
        }
        if let Err(e) = self
            .store
            .ensure_transactions(input.refresh.unwrap_or(false))
            .await
        {
            return upstream_err(e);
        }
        let q = match TxnQuery::build(
            input.account_id,
            input.date_from,
            input.date_to,
            input.min_amount,
            input.max_amount,
            input.include_deleted,
        ) {
            Ok(q) => q,
            Err(e) => return err_json("invalid_argument", e),
        };
        let items: Vec<_> = self
            .filtered_snapshot(&q, Some(&input.query))
            .await
            .iter()
            .map(txn_out)
            .collect();
        match paginate(items, input.limit, input.cursor.as_deref()) {
            Ok(v) => ok_json(v),
            Err(e) => err_json("invalid_argument", e),
        }
    }

    #[tool(
        description = "Fetch one transaction by id (syncs once on cache miss unless \
                       refreshOnMiss=false)."
    )]
    pub async fn get_transaction(
        &self,
        Parameters(input): Parameters<GetTransactionInput>,
    ) -> Result<CallToolResult, McpError> {
        match self
            .fetch_txn(&input.transaction_id, input.refresh_on_miss.unwrap_or(true))
            .await
        {
            Ok(Some(t)) => ok_json(json!({ "transaction": txn_out(&t) })),
            Ok(None) => err_json(
                "not_found",
                format!("transaction {:?} not found", input.transaction_id),
            ),
            Err(e) => upstream_err(e),
        }
    }

    #[tool(
        description = "List transactions with no category assigned (uncategorized lane); \
                       same filters/pagination as list_transactions."
    )]
    pub async fn list_uncategorized_transactions(
        &self,
        Parameters(input): Parameters<ListTransactionsInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self
            .store
            .ensure_transactions(input.refresh.unwrap_or(false))
            .await
        {
            return upstream_err(e);
        }
        let q = match TxnQuery::build(
            input.account_id,
            input.date_from,
            input.date_to,
            input.min_amount,
            input.max_amount,
            input.include_deleted,
        ) {
            Ok(q) => q,
            Err(e) => return err_json("invalid_argument", e),
        };
        let mut txns = self.filtered_snapshot(&q, None).await;
        txns.retain(|t| CoaRef::is_uncategorized(t.coa.as_ref()));
        let items: Vec<_> = txns.iter().map(txn_out).collect();
        match paginate(items, input.limit, input.cursor.as_deref()) {
            Ok(v) => ok_json(v),
            Err(e) => err_json("invalid_argument", e),
        }
    }

    #[tool(
        description = "Search distinct merchants (renamedPayee -> payee -> mlInferredPayee \
                       identity) with transaction counts, ordered by frequency."
    )]
    pub async fn search_merchants(
        &self,
        Parameters(input): Parameters<SearchMerchantsInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self
            .store
            .ensure_transactions(input.refresh.unwrap_or(false))
            .await
        {
            return upstream_err(e);
        }
        let snapshot = self.store.transactions_snapshot().await;
        let limit = input.limit.map(|l| l as usize).unwrap_or(DEFAULT_PAGE);
        let merchants = local::aggregate_merchants(
            &snapshot,
            Some(input.query.as_str()),
            limit.clamp(1, MAX_PAGE),
            input.include_deleted.unwrap_or(false),
        );
        ok_json(json!({ "merchants": merchants }))
    }

    #[tool(description = "List categories (id, name, type, parent) from Simplifi.")]
    pub async fn list_categories(
        &self,
        Parameters(input): Parameters<ListReferenceInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self
            .store
            .ensure_reference(input.refresh.unwrap_or(false))
            .await
        {
            return upstream_err(e);
        }
        let mut cats = self.store.categories().await;
        cats.truncate(input.limit.map(|l| l as usize).unwrap_or(5000));
        ok_json(json!({ "categories": cats }))
    }

    #[tool(description = "Search categories by case-insensitive name substring.")]
    pub async fn search_categories(
        &self,
        Parameters(input): Parameters<SearchReferenceInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self
            .store
            .ensure_reference(input.refresh.unwrap_or(false))
            .await
        {
            return upstream_err(e);
        }
        let ql = input.query.to_lowercase();
        let mut cats = self.store.categories().await;
        cats.retain(|c| {
            c.name
                .as_deref()
                .map(|n| n.to_lowercase().contains(&ql))
                .unwrap_or(false)
        });
        cats.truncate(input.limit.map(|l| l as usize).unwrap_or(5000));
        ok_json(json!({ "categories": cats }))
    }

    #[tool(description = "List tags (id, name, usage count) from Simplifi.")]
    pub async fn list_tags(
        &self,
        Parameters(input): Parameters<ListReferenceInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self
            .store
            .ensure_reference(input.refresh.unwrap_or(false))
            .await
        {
            return upstream_err(e);
        }
        let mut tags = self.store.tags().await;
        tags.truncate(input.limit.map(|l| l as usize).unwrap_or(5000));
        ok_json(json!({ "tags": tags }))
    }

    #[tool(description = "Search tags by case-insensitive name substring.")]
    pub async fn search_tags(
        &self,
        Parameters(input): Parameters<SearchReferenceInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self
            .store
            .ensure_reference(input.refresh.unwrap_or(false))
            .await
        {
            return upstream_err(e);
        }
        let ql = input.query.to_lowercase();
        let mut tags = self.store.tags().await;
        tags.retain(|t| {
            t.name
                .as_deref()
                .map(|n| n.to_lowercase().contains(&ql))
                .unwrap_or(false)
        });
        tags.truncate(input.limit.map(|l| l as usize).unwrap_or(5000));
        ok_json(json!({ "tags": tags }))
    }

    #[tool(
        description = "Suggest categories for a merchant from its historical \
                       categorizations (count-ranked)."
    )]
    pub async fn suggest_categories_for_merchant(
        &self,
        Parameters(input): Parameters<SuggestCategoriesInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self.store.ensure_transactions(false).await {
            return upstream_err(e);
        }
        if let Err(e) = self
            .store
            .ensure_reference(input.refresh_categories.unwrap_or(false))
            .await
        {
            return upstream_err(e);
        }
        let snapshot = self.store.transactions_snapshot().await;
        let cats = self.store.categories().await;
        let mode = match input.match_mode.unwrap_or(MatchModeInput::Contains) {
            MatchModeInput::Exact => local::MatchMode::Exact,
            MatchModeInput::Contains => local::MatchMode::Contains,
        };
        let suggestions = local::suggest_categories_for_merchant(
            &snapshot,
            &cats,
            &input.merchant,
            mode,
            input.limit.map(|l| l as usize).unwrap_or(5).clamp(1, 20),
        );
        ok_json(json!({ "suggestions": suggestions }))
    }

    // ------------------------------------------------- accounts / datasets

    #[tool(description = "List accounts (raw Simplifi account objects).")]
    pub async fn list_accounts(
        &self,
        Parameters(input): Parameters<RefreshOnlyInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self
            .store
            .ensure_reference(input.refresh.unwrap_or(false))
            .await
        {
            return upstream_err(e);
        }
        ok_json(json!({ "accounts": self.store.accounts().await }))
    }

    #[tool(
        description = "Account balances: id, name and every balance-like field \
                       (currentBalance, availableBalance, creditLimit, ...) as decimal strings."
    )]
    pub async fn account_balances(
        &self,
        Parameters(input): Parameters<RefreshOnlyInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self
            .store
            .ensure_reference(input.refresh.unwrap_or(false))
            .await
        {
            return upstream_err(e);
        }
        const BALANCE_KEYS: [&str; 7] = [
            "currentBalance",
            "availableBalance",
            "balance",
            "displayBalance",
            "clearedBalance",
            "onlineBalance",
            "creditLimit",
        ];
        let accounts = self.store.accounts().await;
        let rows: Vec<serde_json::Value> = accounts
            .iter()
            .map(|a| {
                let mut balances = serde_json::Map::new();
                for k in BALANCE_KEYS {
                    match a.extra.get(k) {
                        Some(serde_json::Value::Number(n)) => {
                            balances.insert(k.to_string(), json!(n.to_string()));
                        }
                        Some(serde_json::Value::String(s)) => {
                            balances.insert(k.to_string(), json!(s));
                        }
                        _ => {}
                    }
                }
                let mut row = serde_json::Map::new();
                row.insert("id".to_string(), json!(a.id_string()));
                row.insert("name".to_string(), json!(a.name));
                for k in ["type", "accountType", "currency"] {
                    if let Some(v) = a.extra.get(k) {
                        row.insert(k.to_string(), v.clone());
                    }
                }
                row.insert("balances".to_string(), serde_json::Value::Object(balances));
                serde_json::Value::Object(row)
            })
            .collect();
        ok_json(json!({ "accounts": rows }))
    }

    #[tool(description = "List Simplifi datasets visible to the logged-in user.")]
    pub async fn list_datasets(&self) -> Result<CallToolResult, McpError> {
        match self.store.client().list_datasets().await {
            Ok(ds) => {
                let rows: Vec<serde_json::Value> = ds
                    .iter()
                    .map(|d| json!({ "id": d.id_string(), "name": d.name }))
                    .collect();
                ok_json(json!({ "datasets": rows }))
            }
            Err(e) => upstream_err(e),
        }
    }

    // ------------------------------------------------------------ write lane

    #[tool(
        description = "Update editable fields of a transaction (payee, memo, category, tags, \
                       postedOn, amount, review flags). Requires SIMPLIFI_MCP_ALLOW_WRITES=1."
    )]
    pub async fn update_transaction(
        &self,
        Parameters(input): Parameters<UpdateTransactionInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(msg) = self.write_gate() {
            return err_json("writes_disabled", msg);
        }
        let patch = match build_patch(&input.patch) {
            Ok(p) => p,
            Err(e) => return err_json("invalid_argument", e),
        };
        let base = match self.fetch_txn(&input.transaction_id, true).await {
            Ok(Some(t)) => t,
            Ok(None) => {
                return err_json(
                    "not_found",
                    format!("transaction {:?} not found", input.transaction_id),
                )
            }
            Err(e) => return upstream_err(e),
        };
        if let Err(msg) = self.write_quota(1) {
            return err_json("write_quota_exceeded", msg);
        }
        let audit = match self.audit() {
            Ok(a) => a,
            Err(msg) => return err_json("writes_disabled", msg),
        };
        let op = match audit.begin(
            "update_transaction",
            Some(&input.transaction_id),
            json!({ "patch": serde_json::to_value(&patch).unwrap_or_default() }),
            serde_json::to_value(&base).ok(),
        ) {
            Ok(op) => op,
            Err(e) => return err_json("audit_unavailable", e),
        };
        match self.store.client().patch_transaction(&base, &patch).await {
            Ok((updated, ack)) => {
                audit.finish(
                    &op,
                    "update_transaction",
                    "ok",
                    serde_json::to_value(&updated).ok(),
                    serde_json::to_value(&ack).ok(),
                );
                self.store.upsert_local(updated.clone()).await;
                ok_json(json!({ "mutation": ack, "transaction": txn_out(&updated) }))
            }
            Err(e) => {
                audit.finish(&op, "update_transaction", &format!("error:{}", err_code(&e)), None, None);
                upstream_err(e)
            }
        }
    }

    #[tool(
        description = "Assign a category to a transaction (coa = {type:CATEGORY, id}). \
                       Requires SIMPLIFI_MCP_ALLOW_WRITES=1."
    )]
    pub async fn categorize_transaction(
        &self,
        Parameters(input): Parameters<CategorizeTransactionInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(msg) = self.write_gate() {
            return err_json("writes_disabled", msg);
        }
        let base = match self.fetch_txn(&input.transaction_id, true).await {
            Ok(Some(t)) => t,
            Ok(None) => {
                return err_json(
                    "not_found",
                    format!("transaction {:?} not found", input.transaction_id),
                )
            }
            Err(e) => return upstream_err(e),
        };
        if let Err(msg) = self.write_quota(1) {
            return err_json("write_quota_exceeded", msg);
        }
        let audit = match self.audit() {
            Ok(a) => a,
            Err(msg) => return err_json("writes_disabled", msg),
        };
        let op = match audit.begin(
            "categorize_transaction",
            Some(&input.transaction_id),
            json!({ "categoryId": input.category_id }),
            serde_json::to_value(&base).ok(),
        ) {
            Ok(op) => op,
            Err(e) => return err_json("audit_unavailable", e),
        };
        match self
            .store
            .client()
            .categorize_transaction(&base, &input.category_id)
            .await
        {
            Ok((updated, ack)) => {
                audit.finish(
                    &op,
                    "categorize_transaction",
                    "ok",
                    serde_json::to_value(&updated).ok(),
                    serde_json::to_value(&ack).ok(),
                );
                self.store.upsert_local(updated.clone()).await;
                ok_json(json!({ "mutation": ack, "transaction": txn_out(&updated) }))
            }
            Err(e) => {
                audit.finish(
                    &op,
                    "categorize_transaction",
                    &format!("error:{}", err_code(&e)),
                    None,
                    None,
                );
                upstream_err(e)
            }
        }
    }

    #[tool(
        description = "Split a transaction across two or more categories. Line amounts \
                       (decimal strings, signed like the transaction) must total the \
                       transaction amount exactly. Requires SIMPLIFI_MCP_ALLOW_WRITES=1."
    )]
    pub async fn split_transaction(
        &self,
        Parameters(input): Parameters<SplitTransactionInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(msg) = self.write_gate() {
            return err_json("writes_disabled", msg);
        }
        let mut lines = Vec::with_capacity(input.lines.len());
        for l in &input.lines {
            let amount = match parse_decimal(&l.amount) {
                Ok(a) => a,
                Err(e) => return err_json("invalid_argument", e),
            };
            lines.push(crate::models::SplitLine::new(
                l.category_id.clone(),
                amount,
                l.memo.clone(),
            ));
        }
        let base = match self.fetch_txn(&input.transaction_id, true).await {
            Ok(Some(t)) => t,
            Ok(None) => {
                return err_json(
                    "not_found",
                    format!("transaction {:?} not found", input.transaction_id),
                )
            }
            Err(e) => return upstream_err(e),
        };
        if let Err(msg) = crate::models::validate_split(&base, &lines) {
            return err_json("invalid_argument", msg);
        }
        if let Err(msg) = self.write_quota(1) {
            return err_json("write_quota_exceeded", msg);
        }
        let audit = match self.audit() {
            Ok(a) => a,
            Err(msg) => return err_json("writes_disabled", msg),
        };
        let op = match audit.begin(
            "split_transaction",
            Some(&input.transaction_id),
            json!({ "lines": serde_json::to_value(&lines).unwrap_or_default() }),
            serde_json::to_value(&base).ok(),
        ) {
            Ok(op) => op,
            Err(e) => return err_json("audit_unavailable", e),
        };
        match self.store.client().split_transaction(&base, &lines).await {
            Ok((updated, ack)) => {
                audit.finish(
                    &op,
                    "split_transaction",
                    "ok",
                    serde_json::to_value(&updated).ok(),
                    serde_json::to_value(&ack).ok(),
                );
                self.store.upsert_local(updated.clone()).await;
                ok_json(json!({ "mutation": ack, "transaction": txn_out(&updated) }))
            }
            Err(e) => {
                audit.finish(
                    &op,
                    "split_transaction",
                    &format!("error:{}", err_code(&e)),
                    None,
                    None,
                );
                upstream_err(e)
            }
        }
    }

    #[tool(
        description = "Apply the same typed patch (category, tags, review flags, memo, ...) \
                       to every transaction matching the filters. Dry run by default: with \
                       confirm:false it only reports the match count and a sample. With \
                       confirm:true it applies sequentially and reports per-transaction \
                       results. Requires SIMPLIFI_MCP_ALLOW_WRITES=1 when confirming."
    )]
    pub async fn bulk_update_transactions(
        &self,
        Parameters(input): Parameters<BulkUpdateTransactionsInput>,
    ) -> Result<CallToolResult, McpError> {
        let patch = match build_patch(&input.patch) {
            Ok(p) => p,
            Err(e) => return err_json("invalid_argument", e),
        };
        if let Err(e) = self
            .store
            .ensure_transactions(input.refresh.unwrap_or(false))
            .await
        {
            return upstream_err(e);
        }
        let q = match TxnQuery::build(
            input.account_id.clone(),
            input.date_from.clone(),
            input.date_to.clone(),
            input.min_amount.clone(),
            input.max_amount.clone(),
            input.include_deleted,
        ) {
            Ok(q) => q,
            Err(e) => return err_json("invalid_argument", e),
        };
        let matched = self.filtered_snapshot(&q, input.query.as_deref()).await;
        if !input.confirm.unwrap_or(false) {
            let sample: Vec<serde_json::Value> = matched
                .iter()
                .take(10)
                .map(|t| {
                    json!({
                        "id": t.id,
                        "postedOn": t.posted_on,
                        "payee": t.renamed_payee.clone().or_else(|| t.payee.clone()),
                        "amount": t.amount.map(|a| a.to_string()),
                    })
                })
                .collect();
            return ok_json(json!({
                "preview": true,
                "wouldUpdate": matched.len(),
                "sample": sample,
                "note": "re-run with confirm:true to apply the patch to every match",
            }));
        }
        if let Err(msg) = self.write_gate() {
            return err_json("writes_disabled", msg);
        }
        if matched.is_empty() {
            return err_json("invalid_argument", "no transactions match the filters");
        }
        if let Err(msg) = self.write_quota(matched.len()) {
            return err_json("write_quota_exceeded", msg);
        }
        let audit = match self.audit() {
            Ok(a) => a,
            Err(msg) => return err_json("writes_disabled", msg),
        };
        let ids: Vec<&str> = matched.iter().map(|t| t.id.as_str()).collect();
        let op = match audit.begin(
            "bulk_update_transactions",
            None,
            json!({
                "patch": serde_json::to_value(&patch).unwrap_or_default(),
                "transactionIds": ids,
            }),
            None,
        ) {
            Ok(op) => op,
            Err(e) => return err_json("audit_unavailable", e),
        };
        let outcome = self
            .store
            .client()
            .patch_transactions_bulk(&matched, &patch)
            .await;
        let mut results: Vec<serde_json::Value> = Vec::with_capacity(outcome.results.len());
        let mut updated_count = 0usize;
        for (base, r) in matched.iter().zip(outcome.results.iter()) {
            match r {
                Ok((updated, _ack)) => {
                    updated_count += 1;
                    self.store.upsert_local(updated.clone()).await;
                    results.push(json!({ "id": base.id, "status": "updated" }));
                }
                Err(e) => {
                    results.push(json!({
                        "id": base.id,
                        "status": "error",
                        "message": e.to_string(),
                    }));
                }
            }
        }
        audit.finish(
            &op,
            "bulk_update_transactions",
            "ok",
            None,
            Some(json!({
                "updated": updated_count,
                "attempted": outcome.results.len(),
                "aborted": outcome.aborted,
                "results": &results,
            })),
        );
        ok_json(json!({
            "preview": false,
            "updated": updated_count,
            "attempted": outcome.results.len(),
            "matched": matched.len(),
            "aborted": outcome.aborted,
            "results": results,
        }))
    }

    #[tool(
        description = "Create one manual transaction. Requires SIMPLIFI_MCP_ALLOW_WRITES=1 \
                       AND SIMPLIFI_ENABLE_UNVERIFIED_WRITES=1 (the create endpoint is \
                       inferred, not HAR-verified)."
    )]
    pub async fn create_transaction(
        &self,
        Parameters(input): Parameters<CreateTransactionInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(msg) = self.write_gate() {
            return err_json("writes_disabled", msg);
        }
        if let Err(e) = validate_iso_date(&input.posted_on) {
            return err_json("invalid_argument", e);
        }
        let amount = match parse_decimal(&input.amount) {
            Ok(a) => a,
            Err(e) => return err_json("invalid_argument", e),
        };
        let new = NewTransaction {
            account_id: input.account_id,
            posted_on: input.posted_on,
            payee: input.payee,
            amount: Some(amount),
            memo: input.memo,
            coa: input.category_id.map(CoaRef::category),
            tags: input.tags,
            state: None,
            match_state: None,
            source: None,
            txn_type: None,
            client_id: input.client_id,
        };
        if let Err(msg) = self.write_quota(1) {
            return err_json("write_quota_exceeded", msg);
        }
        let audit = match self.audit() {
            Ok(a) => a,
            Err(msg) => return err_json("writes_disabled", msg),
        };
        let op = match audit.begin(
            "create_transaction",
            None,
            serde_json::to_value(&new).unwrap_or_default(),
            None,
        ) {
            Ok(op) => op,
            Err(e) => return err_json("audit_unavailable", e),
        };
        match self.store.client().create_transaction(&new).await {
            Ok(ack) => {
                audit.finish(
                    &op,
                    "create_transaction",
                    "ok",
                    None,
                    serde_json::to_value(&ack).ok(),
                );
                ok_json(json!({ "created": ack }))
            }
            Err(e) => {
                audit.finish(&op, "create_transaction", &format!("error:{}", err_code(&e)), None, None);
                upstream_err(e)
            }
        }
    }

    #[tool(
        description = "Bulk-create transactions from Simplifi-template CSV \
                       (Date,Payee,Amount[,Tags][,Memo]; max 1000 rows). confirm:false \
                       returns a parse preview; confirm:true creates (requires \
                       SIMPLIFI_MCP_ALLOW_WRITES=1 and SIMPLIFI_ENABLE_UNVERIFIED_WRITES=1)."
    )]
    pub async fn bulk_import_transactions(
        &self,
        Parameters(input): Parameters<BulkImportInput>,
    ) -> Result<CallToolResult, McpError> {
        let parsed = match crate::csvio::parse_import_csv(&input.csv, &input.account_id) {
            Ok(p) => p,
            Err(e) => return err_json("invalid_argument", e),
        };
        let preview: Vec<serde_json::Value> = parsed
            .rows
            .iter()
            .map(|r| {
                json!({
                    "postedOn": r.posted_on,
                    "payee": r.payee,
                    "amount": r.amount.map(|a| a.to_string()),
                    "tags": r.tags,
                    "memo": r.memo,
                })
            })
            .collect();
        if !input.confirm.unwrap_or(false) {
            return ok_json(json!({
                "preview": true,
                "wouldCreate": parsed.rows.len(),
                "rows": preview,
                "errors": parsed.errors,
                "note": "re-run with confirm:true to create these transactions",
            }));
        }
        if let Err(msg) = self.write_gate() {
            return err_json("writes_disabled", msg);
        }
        if parsed.rows.is_empty() {
            return err_json("invalid_argument", "no valid rows to import");
        }
        if let Err(msg) = self.write_quota(parsed.rows.len()) {
            return err_json("write_quota_exceeded", msg);
        }
        let audit = match self.audit() {
            Ok(a) => a,
            Err(msg) => return err_json("writes_disabled", msg),
        };
        let op = match audit.begin(
            "bulk_import_transactions",
            None,
            json!({ "accountId": input.account_id, "rows": preview, "parseErrors": &parsed.errors }),
            None,
        ) {
            Ok(op) => op,
            Err(e) => return err_json("audit_unavailable", e),
        };
        match self
            .store
            .client()
            .create_transactions_bulk(&parsed.rows)
            .await
        {
            Ok(outcome) => {
                let results: Vec<serde_json::Value> = outcome
                    .results
                    .iter()
                    .enumerate()
                    .map(|(i, r)| match r {
                        Ok(ack) => json!({
                            "row": i + 1,
                            "status": "created",
                            "id": ack.id,
                            "clientId": ack.client_id,
                        }),
                        Err(e) => json!({
                            "row": i + 1,
                            "status": "error",
                            "message": e.to_string(),
                        }),
                    })
                    .collect();
                let created = outcome.results.iter().filter(|r| r.is_ok()).count();
                audit.finish(
                    &op,
                    "bulk_import_transactions",
                    "ok",
                    None,
                    Some(json!({
                        "created": created,
                        "attempted": outcome.results.len(),
                        "aborted": outcome.aborted,
                        "results": &results,
                    })),
                );
                ok_json(json!({
                    "preview": false,
                    "created": created,
                    "attempted": outcome.results.len(),
                    "aborted": outcome.aborted,
                    "parseErrors": parsed.errors,
                    "results": results,
                }))
            }
            Err(e) => {
                audit.finish(
                    &op,
                    "bulk_import_transactions",
                    &format!("error:{}", err_code(&e)),
                    None,
                    None,
                );
                upstream_err(e)
            }
        }
    }

    // --------------------------------------------------------- analysis lane

    #[tool(
        description = "Export filtered transactions as JSON, Simplifi-import-template CSV \
                       ('csv') or archival CSV ('csv_full'). Amounts are decimal strings."
    )]
    pub async fn export_transactions(
        &self,
        Parameters(input): Parameters<ExportTransactionsInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self
            .store
            .ensure_transactions(input.refresh.unwrap_or(false))
            .await
        {
            return upstream_err(e);
        }
        if let Err(e) = self.store.ensure_reference(false).await {
            return upstream_err(e);
        }
        let q = match TxnQuery::build(
            input.account_id,
            input.date_from,
            input.date_to,
            None,
            None,
            input.include_deleted,
        ) {
            Ok(q) => q,
            Err(e) => return err_json("invalid_argument", e),
        };
        let mut txns = self.filtered_snapshot(&q, input.query.as_deref()).await;
        let cap = input
            .max_rows
            .map(|m| m as usize)
            .unwrap_or(MAX_EXPORT_ROWS)
            .min(MAX_EXPORT_ROWS);
        let truncated = txns.len() > cap;
        txns.truncate(cap);
        // Export oldest-first for stable, appendable files.
        txns.reverse();
        let refs: Vec<&Transaction> = txns.iter().collect();
        match input.format.unwrap_or_default() {
            ExportFormat::Json => {
                let items: Vec<_> = refs.iter().map(|t| txn_out(t)).collect();
                ok_json(json!({
                    "format": "json",
                    "count": items.len(),
                    "truncated": truncated,
                    "items": items,
                }))
            }
            ExportFormat::Csv => {
                let tags = self.store.tag_names().await;
                match crate::csvio::export_import_template_csv(&refs, &tags) {
                    Ok(csv) => ok_json(json!({
                        "format": "csv",
                        "count": refs.len(),
                        "truncated": truncated,
                        "csv": csv,
                    })),
                    Err(e) => err_json("export_failed", e),
                }
            }
            ExportFormat::CsvFull => {
                let tags = self.store.tag_names().await;
                let cats = self.store.category_names().await;
                match crate::csvio::export_full_csv(&refs, &tags, &cats) {
                    Ok(csv) => ok_json(json!({
                        "format": "csv_full",
                        "count": refs.len(),
                        "truncated": truncated,
                        "csv": csv,
                    })),
                    Err(e) => err_json("export_failed", e),
                }
            }
        }
    }

    #[tool(
        description = "Detect recurring merchants (subscriptions, bills, payroll) by \
                       normalized payee + cadence (weekly/monthly/annual/...). Reports \
                       average amount, regularity, and next expected date."
    )]
    pub async fn recurring_detection(
        &self,
        Parameters(input): Parameters<RecurringDetectionInput>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(e) = self
            .store
            .ensure_transactions(input.refresh.unwrap_or(false))
            .await
        {
            return upstream_err(e);
        }
        if let Some(d) = &input.date_from {
            if let Err(e) = validate_iso_date(d) {
                return err_json("invalid_argument", e);
            }
        }
        let snapshot = self.store.transactions_snapshot().await;
        let groups = recurring::detect_recurring(
            &snapshot,
            input.min_occurrences.map(|m| m as usize).unwrap_or(3),
            input.account_id.as_deref(),
            input.date_from.as_deref(),
        );
        ok_json(json!({ "count": groups.len(), "groups": groups }))
    }
}

fn build_patch(input: &TransactionPatchInput) -> Result<TransactionPatch, String> {
    if let Some(d) = &input.posted_on {
        validate_iso_date(d)?;
    }
    let amount = input.amount.as_deref().map(parse_decimal).transpose()?;
    let patch = TransactionPatch {
        payee: input.payee.clone(),
        renamed_payee: input.renamed_payee.clone(),
        memo: input.memo.clone(),
        coa: input.category_id.as_deref().map(CoaRef::category),
        tags: input.tags.clone(),
        is_reviewed: input.is_reviewed,
        is_excluded_from_reports: input.is_excluded_from_reports,
        posted_on: input.posted_on.clone(),
        amount,
        check: None,
    };
    // An all-None patch would PUT the object unchanged — reject early.
    if serde_json::to_value(&patch)
        .map(|v| v.as_object().map(|o| o.is_empty()).unwrap_or(true))
        .unwrap_or(true)
    {
        return Err("patch has no fields to change".to_string());
    }
    Ok(patch)
}

#[tool_handler(
    name = "quicken-simplifi-mcp",
    instructions = "Unofficial Quicken Simplifi bridge (community project; not affiliated \
                    with Quicken). Read tools query a freshness-gated local mirror of the \
                    Simplifi ledger; pass refresh:true to sync first (rate-limited). \
                    Amounts are decimal strings; dates are ISO YYYY-MM-DD. Mutating tools \
                    are disabled unless the server was started with \
                    SIMPLIFI_MCP_ALLOW_WRITES=1."
)]
impl ServerHandler for SimplifiMcpServer {}
