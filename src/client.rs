//! Simplifi data-plane client (PORTING-SPEC section 3).
//!
//! Endpoints: transactions (list / nextLink paging / earliest-date-on / PUT upsert),
//! categories, tags, datasets (auto-discovery), accounts, userprofiles/me — plus the
//! config-gated, HAR-unverified transaction CREATE / bulk-create / tombstone-delete
//! (spec section 8).
//!
//! Safety properties (SECURITY-AUDIT):
//! - every followed `nextLink` is re-validated against the base host (SA-05), with
//!   bounded page counts and cycle detection
//! - one global pacing floor between upstream requests + 429/503 Retry-After honoring
//!   (SA-03/SA-13)
//! - error bodies are never propagated (SA-11)

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::{Method, Url};
use serde::de::DeserializeOwned;

use crate::auth::{api_error, AuthManager};
use crate::config::Config;
use crate::error::{Error, Result};
use crate::models::{
    Account, Category, Dataset, EarliestDateOn, NewTransaction, Page, Tag, Transaction,
    TransactionPatch, UpsertAck, UserProfile,
};
use crate::token_cache::TokenCache;
use crate::transport::{validate_upstream_url, ApiRequest, ApiResponse, HttpTransport, Transport};

const MAX_RETRIES: u32 = 2;
const RETRY_AFTER_CAP_SECS: u64 = 60;
/// Consecutive-failure abort threshold for bulk creation.
const BULK_ABORT_AFTER: usize = 3;

#[derive(Debug, Clone, Default)]
pub struct ListTransactionsParams {
    pub limit: Option<u32>,
    /// `YYYY-MM-DD`
    pub date_on_after: Option<String>,
    /// ISO datetime — incremental sync watermark.
    pub modified_after: Option<String>,
    /// Opaque cursor, observed format `dateOn;{date};{refId}`.
    pub after: Option<String>,
    pub current_page: Option<u32>,
}

/// Outcome of a bulk create: per-item results in input order; `aborted` set when the
/// consecutive-failure threshold stopped the run early.
pub struct BulkCreateOutcome {
    pub results: Vec<Result<UpsertAck>>,
    pub aborted: bool,
}

/// Outcome of a bulk patch: per-item updated transactions (or errors) in input
/// order; `aborted` set when the consecutive-failure threshold stopped the run.
pub struct BulkPatchOutcome {
    pub results: Vec<Result<(Transaction, UpsertAck)>>,
    pub aborted: bool,
}

pub struct SimplifiClient {
    cfg: Arc<Config>,
    transport: Arc<Transport>,
    cache: Arc<TokenCache>,
    auth: AuthManager,
    pace: tokio::sync::Mutex<Option<Instant>>,
}

impl SimplifiClient {
    /// Production constructor: hardened HTTPS transport + encrypted token cache.
    pub fn new(cfg: Config) -> Result<Self> {
        let transport = Transport::Http(HttpTransport::new(cfg.http_timeout_ms, &cfg.user_agent)?);
        Self::with_transport(cfg, transport)
    }

    /// Constructor with an explicit transport (mock transport in tests/demos).
    pub fn with_transport(cfg: Config, transport: Transport) -> Result<Self> {
        let key = cfg.key_source.resolve()?;
        let cache = Arc::new(TokenCache::open(&cfg.data_dir, key)?);
        let cfg = Arc::new(cfg);
        let transport = Arc::new(transport);
        let auth = AuthManager::new(cfg.clone(), transport.clone(), cache.clone());
        Ok(SimplifiClient {
            cfg,
            transport,
            cache,
            auth,
            pace: tokio::sync::Mutex::new(None),
        })
    }

    pub fn auth(&self) -> &AuthManager {
        &self.auth
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    // ---------------------------------------------------------------- datasets / whoami

    /// `GET /userprofiles/me` — token sanity probe (rijn client.py:66-82).
    pub async fn whoami(&self) -> Result<UserProfile> {
        let url = self.endpoint(&["userprofiles", "me"], &[])?;
        self.request_json(Method::GET, url, None, false).await
    }

    /// `GET /datasets` (rijn client.py:96-100).
    pub async fn list_datasets(&self) -> Result<Vec<Dataset>> {
        let url = self.endpoint(&["datasets"], &[("limit", "100")])?;
        let page: Page<Dataset> = self.request_json(Method::GET, url, None, false).await?;
        Ok(page.resources)
    }

    /// Resolve the dataset id: config/env override -> cached -> auto-discover via
    /// `GET /datasets` (feature addition — upstream required SIMPLIFI_DATASET_ID).
    pub async fn ensure_dataset_id(&self) -> Result<String> {
        if let Some(d) = &self.cfg.dataset_id {
            return Ok(d.clone());
        }
        if let Some(d) = self.cache.dataset_id() {
            return Ok(d);
        }
        let datasets = self.list_datasets().await?;
        let id = datasets
            .iter()
            .filter_map(|d| d.id_string())
            .next()
            .ok_or(Error::InvalidResponse("no datasets visible to this user"))?;
        self.cache.set_dataset_id(&id)?;
        tracing::info!("auto-discovered simplifi dataset id");
        Ok(id)
    }

    // ---------------------------------------------------------------- accounts

    /// `GET /accounts` (rijn client.py:102-109).
    pub async fn list_accounts(&self) -> Result<Vec<Account>> {
        let url = self.endpoint(&["accounts"], &[("limit", "1000")])?;
        let page: Page<Account> = self.request_json(Method::GET, url, None, true).await?;
        Ok(page.resources)
    }

    // ---------------------------------------------------------------- transactions

    /// Single page of `GET /transactions`.
    pub async fn list_transactions(
        &self,
        params: &ListTransactionsParams,
    ) -> Result<Page<Transaction>> {
        let limit = params.limit.unwrap_or(self.cfg.page_limit).to_string();
        let mut q: Vec<(&str, String)> = vec![("limit", limit)];
        if let Some(v) = &params.date_on_after {
            q.push(("dateOnAfter", v.clone()));
        }
        if let Some(v) = &params.modified_after {
            q.push(("modifiedAfter", v.clone()));
        }
        if let Some(v) = &params.after {
            q.push(("after", v.clone()));
        }
        if let Some(v) = params.current_page {
            q.push(("currentPage", v.to_string()));
        }
        let q_ref: Vec<(&str, &str)> = q.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let url = self.endpoint(&["transactions"], &q_ref)?;
        self.request_json(Method::GET, url, None, true).await
    }

    /// All pages of `GET /transactions`, following `metaData.nextLink` with host
    /// validation, page bound, and cycle detection. Returns (transactions, last asOf).
    pub async fn list_transactions_all(
        &self,
        params: &ListTransactionsParams,
    ) -> Result<(Vec<Transaction>, Option<String>)> {
        let mut out = Vec::new();
        let mut page = self.list_transactions(params).await?;
        let mut as_of = page.meta_data.as_of.clone();
        out.append(&mut page.resources);
        let mut visited: HashSet<String> = HashSet::new();
        let mut pages = 1usize;
        let mut next = page.meta_data.next_link.clone();
        while let Some(link) = next.filter(|l| !l.is_empty()) {
            pages += 1;
            if pages > self.cfg.max_pages {
                return Err(Error::PaginationLimit { pages });
            }
            let url = self.resolve_next_link(&link)?;
            if !visited.insert(url.to_string()) {
                return Err(Error::InvalidResponse("nextLink cycle detected"));
            }
            let mut p: Page<Transaction> = self.request_json(Method::GET, url, None, true).await?;
            if p.meta_data.as_of.is_some() {
                as_of = p.meta_data.as_of.clone();
            }
            out.append(&mut p.resources);
            next = p.meta_data.next_link.clone();
        }
        Ok((out, as_of))
    }

    /// `POST /transactions/earliest-date-on` (`accountIds: []` = all accounts).
    pub async fn earliest_date_on(&self, account_ids: &[String]) -> Result<EarliestDateOn> {
        let url = self.endpoint(&["transactions", "earliest-date-on"], &[])?;
        let body = serde_json::json!({ "accountIds": account_ids });
        self.request_json(Method::POST, url, Some(body), true).await
    }

    /// Scan pages for a transaction by id. There is no documented GET-by-id endpoint;
    /// bound the scan with `date_on_after` where possible. (The SQLite cache layer is
    /// the right place for point lookups — this is the wire-only fallback.)
    pub async fn find_transaction(
        &self,
        id: &str,
        date_on_after: Option<&str>,
    ) -> Result<Option<Transaction>> {
        let params = ListTransactionsParams {
            date_on_after: date_on_after.map(str::to_string),
            ..Default::default()
        };
        let (txns, _) = self.list_transactions_all(&params).await?;
        Ok(txns.into_iter().find(|t| t.id == id))
    }

    /// `PUT /transactions/{id}` — full-object upsert. Validates the required
    /// field set (see `UPSERT_REQUIRED_FIELDS` — the spec's list is trimmed
    /// to the fields live transactions actually carry) before sending.
    pub async fn update_transaction(&self, txn: &Transaction) -> Result<UpsertAck> {
        txn.validate_upsert_required().map_err(Error::MissingFields)?;
        let url = self.endpoint(&["transactions", &txn.id], &[])?;
        let body = serde_json::to_value(txn)?;
        self.request_json(Method::PUT, url, Some(body), true).await
    }

    /// Apply a typed, allowlisted patch to a fetched transaction and PUT it (replaces
    /// upstream's free-form deep-merge; SA-09/SA-14).
    pub async fn patch_transaction(
        &self,
        base: &Transaction,
        patch: &TransactionPatch,
    ) -> Result<(Transaction, UpsertAck)> {
        let updated = patch.apply(base);
        let ack = self.update_transaction(&updated).await?;
        Ok((updated, ack))
    }

    /// Sugar: assign `coa = { type: "CATEGORY", id: category_id }` and PUT.
    pub async fn categorize_transaction(
        &self,
        base: &Transaction,
        category_id: &str,
    ) -> Result<(Transaction, UpsertAck)> {
        let patch = TransactionPatch {
            coa: Some(crate::models::CoaRef::category(category_id)),
            ..Default::default()
        };
        self.patch_transaction(base, &patch).await
    }

    /// Split a transaction across categories: validate the lines (see
    /// [`crate::models::validate_split`]), set the `split` object on a clone of
    /// `base`, and PUT it like any other update.
    ///
    /// The wire shape was observed from live split transactions and verified
    /// end-to-end (fresh-split and re-split PUTs accepted, 2026-10-27):
    /// `split = { "items": [ { amount, clientId, coa, id?, memo, position,
    /// rate, type: "NORMAL", is* flags } ] }`, with no parent `coa` on the
    /// transaction. Lines are normalized before the PUT: a re-split inherits
    /// the existing line at the same position (keeping its server
    /// `id`/`clientId` stable, as the web app does); fresh lines get a
    /// generated clientId and the web app's defaults. `rate` always mirrors
    /// `amount`; `position` is the line index.
    pub async fn split_transaction(
        &self,
        base: &Transaction,
        lines: &[crate::models::SplitLine],
    ) -> Result<(Transaction, UpsertAck)> {
        crate::models::validate_split(base, lines).map_err(Error::InvalidArgument)?;
        let existing = base.split_lines().unwrap_or_default();
        let wire: Vec<crate::models::SplitLine> = lines
            .iter()
            .enumerate()
            .map(|(i, l)| {
                let mut w = existing.get(i).cloned().unwrap_or_else(|| {
                    crate::models::SplitLine {
                        coa: None,
                        amount: None,
                        memo: None,
                        extra: crate::models::Extra::new(),
                    }
                });
                w.coa = l.coa.clone();
                w.amount = l.amount;
                if l.memo.is_some() {
                    w.memo = l.memo.clone();
                }
                if w.memo.is_none() {
                    w.memo = Some(String::new());
                }
                if !w.extra.contains_key("clientId") {
                    w.extra.insert(
                        "clientId".to_string(),
                        serde_json::Value::String(
                            uuid::Uuid::new_v4().to_string().to_uppercase(),
                        ),
                    );
                }
                for flag in [
                    "isBillable",
                    "isExcludedFromF2S",
                    "isExcludedFromReports",
                    "isOverflow",
                    "isRatePercentage",
                    "isTaxable",
                ] {
                    if !w.extra.contains_key(flag) {
                        w.extra
                            .insert(flag.to_string(), serde_json::Value::Bool(false));
                    }
                }
                if !w.extra.contains_key("type") {
                    w.extra.insert(
                        "type".to_string(),
                        serde_json::Value::String("NORMAL".to_string()),
                    );
                }
                w.extra.insert(
                    "position".to_string(),
                    serde_json::Value::Number(i.into()),
                );
                if let Some(a) = l.amount {
                    use rust_decimal::prelude::ToPrimitive;
                    if let Some(f) = a.to_f64() {
                        if let Some(n) = serde_json::Number::from_f64(f) {
                            w.extra.insert("rate".to_string(), serde_json::Value::Number(n));
                        }
                    }
                }
                w
            })
            .collect();
        let mut updated = base.clone();
        updated.apply_split(&wire);
        let ack = self.update_transaction(&updated).await?;
        Ok((updated, ack))
    }

    /// Apply the same typed patch to many transactions, sequentially (paced by
    /// the global request floor), aborting after `BULK_ABORT_AFTER` consecutive
    /// failures so a systemic rejection can't turn into a hammer.
    pub async fn patch_transactions_bulk(
        &self,
        bases: &[Transaction],
        patch: &TransactionPatch,
    ) -> BulkPatchOutcome {
        let mut results = Vec::with_capacity(bases.len());
        let mut consecutive_failures = 0usize;
        let mut aborted = false;
        for base in bases {
            match self.patch_transaction(base, patch).await {
                Ok(pair) => {
                    consecutive_failures = 0;
                    results.push(Ok(pair));
                }
                Err(e) => {
                    consecutive_failures += 1;
                    results.push(Err(e));
                    if consecutive_failures >= BULK_ABORT_AFTER {
                        aborted = true;
                        break;
                    }
                }
            }
        }
        BulkPatchOutcome { results, aborted }
    }

    // ------------------------------------------------ transaction creation (UNVERIFIED)

    /// `POST /transactions` — **inferred, HAR-unverified** creation endpoint
    /// (PORTING-SPEC section 8). Body = upsert shape without `id`, with a
    /// client-generated `clientId`. Disabled unless
    /// `SIMPLIFI_ENABLE_UNVERIFIED_WRITES=1`.
    pub async fn create_transaction(&self, new: &NewTransaction) -> Result<UpsertAck> {
        if !self.cfg.enable_unverified_writes {
            return Err(Error::UnverifiedEndpointDisabled("POST /transactions"));
        }
        let client_id = new
            .client_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let body = new.to_create_body(&client_id);
        let url = self.endpoint(&["transactions"], &[])?;
        self.request_json(Method::POST, url, Some(body), true).await
    }

    /// Bulk creation for history backfill: sequential (paced by the global request
    /// floor), aborting after `BULK_ABORT_AFTER` consecutive failures so a rejected
    /// wire-shape can't turn into a 500-request hammer. Same gate as
    /// [`Self::create_transaction`].
    pub async fn create_transactions_bulk(
        &self,
        items: &[NewTransaction],
    ) -> Result<BulkCreateOutcome> {
        if !self.cfg.enable_unverified_writes {
            return Err(Error::UnverifiedEndpointDisabled("POST /transactions (bulk)"));
        }
        let mut results = Vec::with_capacity(items.len());
        let mut consecutive_failures = 0usize;
        let mut aborted = false;
        for item in items {
            match self.create_transaction(item).await {
                Ok(ack) => {
                    consecutive_failures = 0;
                    results.push(Ok(ack));
                }
                Err(e) => {
                    consecutive_failures += 1;
                    results.push(Err(e));
                    if consecutive_failures >= BULK_ABORT_AFTER {
                        aborted = true;
                        break;
                    }
                }
            }
        }
        Ok(BulkCreateOutcome { results, aborted })
    }

    /// Tombstone delete — **unverified** (spec section 8: "likely PUT isDeleted:true").
    /// Same gate as creation.
    pub async fn delete_transaction(&self, txn: &Transaction) -> Result<UpsertAck> {
        if !self.cfg.enable_unverified_writes {
            return Err(Error::UnverifiedEndpointDisabled(
                "PUT /transactions/{id} isDeleted tombstone",
            ));
        }
        let mut t = txn.clone();
        t.is_deleted = Some(true);
        t.validate_upsert_required().map_err(Error::MissingFields)?;
        let url = self.endpoint(&["transactions", &t.id], &[])?;
        let body = serde_json::to_value(&t)?;
        self.request_json(Method::PUT, url, Some(body), true).await
    }

    // ---------------------------------------------------------------- reference data

    /// Single page of `GET /categories`.
    pub async fn list_categories(
        &self,
        limit: Option<u32>,
        modified_after: Option<&str>,
    ) -> Result<Page<Category>> {
        self.list_reference("categories", limit, modified_after).await
    }

    /// All pages of `GET /categories`.
    pub async fn list_categories_all(&self) -> Result<Vec<Category>> {
        self.list_reference_all("categories").await
    }

    /// Single page of `GET /tags`.
    pub async fn list_tags(
        &self,
        limit: Option<u32>,
        modified_after: Option<&str>,
    ) -> Result<Page<Tag>> {
        self.list_reference("tags", limit, modified_after).await
    }

    /// All pages of `GET /tags`.
    pub async fn list_tags_all(&self) -> Result<Vec<Tag>> {
        self.list_reference_all("tags").await
    }

    async fn list_reference<T: DeserializeOwned>(
        &self,
        kind: &str,
        limit: Option<u32>,
        modified_after: Option<&str>,
    ) -> Result<Page<T>> {
        let limit = limit.unwrap_or(5000).to_string();
        let mut q: Vec<(&str, &str)> = vec![("limit", limit.as_str())];
        if let Some(m) = modified_after {
            q.push(("modifiedAfter", m));
        }
        let url = self.endpoint(&[kind], &q)?;
        self.request_json(Method::GET, url, None, true).await
    }

    async fn list_reference_all<T: DeserializeOwned>(&self, kind: &str) -> Result<Vec<T>> {
        let mut page: Page<T> = self.list_reference(kind, None, None).await?;
        let mut out = Vec::new();
        out.append(&mut page.resources);
        let mut visited: HashSet<String> = HashSet::new();
        let mut pages = 1usize;
        let mut next = page.meta_data.next_link.clone();
        while let Some(link) = next.filter(|l| !l.is_empty()) {
            pages += 1;
            if pages > self.cfg.max_pages {
                return Err(Error::PaginationLimit { pages });
            }
            let url = self.resolve_next_link(&link)?;
            if !visited.insert(url.to_string()) {
                return Err(Error::InvalidResponse("nextLink cycle detected"));
            }
            let mut p: Page<T> = self.request_json(Method::GET, url, None, true).await?;
            out.append(&mut p.resources);
            next = p.meta_data.next_link.clone();
        }
        Ok(out)
    }

    // ---------------------------------------------------------------- plumbing

    fn endpoint(&self, segments: &[&str], query: &[(&str, &str)]) -> Result<Url> {
        let mut url = self.cfg.base_url.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| Error::Config("base_url cannot be a base".to_string()))?;
            path.clear();
            for s in segments {
                path.push(s);
            }
        }
        if !query.is_empty() {
            let mut qp = url.query_pairs_mut();
            for (k, v) in query {
                qp.append_pair(k, v);
            }
        }
        Ok(url)
    }

    /// Resolve a `metaData.nextLink` relative to the base URL, then validate it against
    /// the host allowlist (SA-05).
    fn resolve_next_link(&self, link: &str) -> Result<Url> {
        let url = self
            .cfg
            .base_url
            .join(link)
            .map_err(|_| Error::UnsafeUrl(format!("unparseable nextLink: {link}")))?;
        validate_upstream_url(&url, self.cfg.allowed_host()?)?;
        Ok(url)
    }

    async fn request_json<T: DeserializeOwned>(
        &self,
        method: Method,
        url: Url,
        body: Option<serde_json::Value>,
        with_dataset: bool,
    ) -> Result<T> {
        let resp = self.request_raw(method, url, body, with_dataset).await?;
        resp.json()
    }

    pub(crate) async fn request_raw(
        &self,
        method: Method,
        url: Url,
        body: Option<serde_json::Value>,
        with_dataset: bool,
    ) -> Result<ApiResponse> {
        let token = self.auth.access_token().await?;
        // Resolving the dataset may itself issue a (dataset-less) /datasets request.
        let dataset = if with_dataset {
            Some(Box::pin(self.ensure_dataset_id()).await?)
        } else {
            None
        };

        // Exact upstream data-call header set (client.ts:117-130).
        let mut headers: Vec<(&'static str, String)> = vec![
            ("content-type", "application/json".to_string()),
            ("accept", "application/json".to_string()),
            ("authorization", format!("Bearer {token}")),
            ("app-client-id", self.cfg.client_id.clone()),
            ("app-release", self.cfg.app_release.clone()),
            ("app-build", self.cfg.app_build.clone()),
        ];
        if let Some(d) = &dataset {
            headers.push(("qcs-dataset-id", d.clone()));
        }

        let req = ApiRequest {
            method,
            url,
            headers,
            body,
        };

        let mut attempt = 0u32;
        loop {
            self.pace().await;
            let resp = self.transport.execute(req.clone()).await?;
            match resp.status {
                429 | 503 if attempt < MAX_RETRIES => {
                    attempt += 1;
                    let delay = resp
                        .retry_after
                        .unwrap_or(2u64.saturating_pow(attempt))
                        .min(RETRY_AFTER_CAP_SECS);
                    tracing::warn!(
                        status = resp.status,
                        delay_secs = delay,
                        "upstream throttling; honoring retry-after"
                    );
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                }
                s if s >= 400 => return Err(api_error(s, &resp)),
                _ => return Ok(resp),
            }
        }
    }

    /// Global pacing floor between upstream requests (SA-03/SA-13). Holding the lock
    /// across the sleep intentionally serializes all upstream traffic.
    async fn pace(&self) {
        let interval = Duration::from_millis(self.cfg.min_request_interval_ms);
        if interval.is_zero() {
            return;
        }
        let mut last = self.pace.lock().await;
        if let Some(prev) = *last {
            let elapsed = prev.elapsed();
            if elapsed < interval {
                tokio::time::sleep(interval - elapsed).await;
            }
        }
        *last = Some(Instant::now());
    }
}
