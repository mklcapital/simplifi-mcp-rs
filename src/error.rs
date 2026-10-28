//! Error taxonomy.
//!
//! Security requirement (SECURITY-AUDIT SA-11): upstream response *bodies* are never
//! interpolated into error text. API failures carry only the HTTP status and, when the
//! upstream error envelope had one, a short machine `code` (the `error` field, truncated).

use std::path::PathBuf;

use crate::models::MfaChallenge;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Configuration / environment problem, detected before any network traffic.
    #[error("configuration error: {0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Transport-level failure (DNS, TLS, timeout, mock route miss). URL-scrubbed.
    #[error("transport error: {0}")]
    Transport(String),

    /// Upstream API returned >= 400. Body is intentionally NOT included (SA-11).
    #[error("simplifi api error: status={status}{}", code.as_deref().map(|c| format!(" code={c}")).unwrap_or_default())]
    Api { status: u16, code: Option<String> },

    /// No usable token and no permitted automatic path to obtain one.
    #[error("authentication required ({0}); run `simplifi-mcp login`")]
    AuthRequired(&'static str),

    /// Simplifi answered the credential login with a 202 MFA challenge.
    #[error("simplifi MFA required via {}", .0.mfa_channel)]
    MfaRequired(MfaChallenge),

    /// Credential-login budget for the rolling 24h window is exhausted (SA-03 mitigation).
    #[error("credential-login budget exhausted; quarantined for {retry_after_secs}s — re-run `simplifi-mcp login` manually after the window passes")]
    LoginQuarantined { retry_after_secs: u64 },

    /// Refresh recently failed; we refuse to hammer upstream (SA-03 mitigation).
    #[error("token refresh backing off; retry in {retry_after_secs}s")]
    RefreshBackoff { retry_after_secs: u64 },

    #[error("invalid upstream response: {0}")]
    InvalidResponse(&'static str),

    /// Token cache could not be decrypted (wrong key or tampered file). Fails closed.
    #[error("token cache decryption failed: {0}")]
    Crypto(&'static str),

    /// Cache file/dir permissions are too loose. Fails closed (SA-01 mitigation).
    #[error("insecure permissions on {path} (mode {mode:o}); expected 0600 file / 0700 dir")]
    InsecurePermissions { path: PathBuf, mode: u32 },

    /// A write endpoint whose wire shape has not been HAR-verified is disabled by default
    /// (PORTING-SPEC section 8). Enable explicitly with SIMPLIFI_ENABLE_UNVERIFIED_WRITES=1.
    #[error("unverified write endpoint disabled: {0} (set SIMPLIFI_ENABLE_UNVERIFIED_WRITES=1 after HAR-verifying the endpoint)")]
    UnverifiedEndpointDisabled(&'static str),

    /// A followed URL (e.g. metaData.nextLink) failed the host/scheme allowlist (SA-05).
    #[error("refusing to follow unsafe url: {0}")]
    UnsafeUrl(String),

    #[error("pagination limit exceeded after {pages} pages")]
    PaginationLimit { pages: usize },

    /// Transaction failed upsert-required-fields validation (PORTING-SPEC section 4.2).
    #[error("transaction missing required upsert fields: {}", .0.join(", "))]
    MissingFields(Vec<&'static str>),

    /// Caller supplied an invalid argument, detected before any network traffic
    /// (e.g. split lines that do not total the transaction amount).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

pub type Result<T> = std::result::Result<T, Error>;
