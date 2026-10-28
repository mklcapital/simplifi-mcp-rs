//! # simplifi-mcp
//!
//! Unofficial Rust client library **and MCP server** for Quicken Simplifi's
//! **internal, undocumented** web API. Security-hardened rewrite of
//! [krconv/quicken-simplifi-mcp](https://github.com/krconv/quicken-simplifi-mcp);
//! see SECURITY.md for the threat model and mitigation table, and
//! THIRD-PARTY-NOTICES.md for upstream MIT attributions.
//!
//! **Use at your own risk**: this speaks to endpoints Quicken does not document or
//! support; automated access may violate Quicken's terms and can flag or lock your
//! account. The SA-03 mitigations (single-flight auth, login budget, persisted
//! ThreatMetrix session id, pacing, Retry-After honoring) are defaults, not options.
//!
//! Layout:
//! - [`config`] — env-driven configuration (`op run` friendly; no bundled secrets)
//! - [`secrets`] — credential/env + token-cache key sourcing (keychain/env/file)
//! - [`token_cache`] — XChaCha20-Poly1305-encrypted at-rest token/state cache
//! - [`auth`] — OAuth login (MFA-aware), refresh, dual-encoding parsing
//! - [`client`] — typed endpoint wrappers incl. gated create/bulk-create
//! - [`models`] — serde models (decimal-safe money, unknown-field round-trip)
//! - [`local`] — client-side merchant/search/uncategorized helpers
//! - [`store`] — freshness-gated in-memory sync mirror behind the MCP tools
//! - [`server`] — the rmcp tool layer (19 tools, read-only by default)
//! - [`audit`] — append-only JSONL mutation journal (SA-09)
//! - [`csvio`] / [`recurring`] — CSV import/export codec, recurring detection
//! - [`http`] (feature `http`) — Streamable-HTTP transport w/ mandatory bearer auth
//! - [`mock`] (feature `mock`) — recorded-fixture transport for cred-free tests

pub mod audit;
pub mod auth;
pub mod client;
pub mod config;
pub mod csvio;
pub mod error;
#[cfg(feature = "http")]
pub mod http;
pub mod local;
#[cfg(feature = "mock")]
pub mod mock;
pub mod models;
pub mod money;
pub mod recurring;
pub mod secrets;
pub mod server;
pub mod store;
pub mod token_cache;
pub mod transport;

pub use auth::{parse_auth_session_export, AuthManager, LoginFlow};
pub use client::{BulkCreateOutcome, BulkPatchOutcome, ListTransactionsParams, SimplifiClient};
pub use config::Config;
pub use error::{Error, Result};
pub use models::{
    validate_split, Account, Category, CoaRef, Dataset, EarliestDateOn, MetaData, MfaChallenge,
    NewTransaction, Page, SplitLine, Tag, Transaction, TransactionPatch, UpsertAck, UserProfile,
};
pub use secrets::{Credentials, KeySource};
pub use server::SimplifiMcpServer;
pub use store::SyncStore;
