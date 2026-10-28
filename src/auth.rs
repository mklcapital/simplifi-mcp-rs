//! Simplifi upstream auth: OAuth ROPC-ish flow against services.quicken.com.
//!
//! Wire protocol per PORTING-SPEC section 2 (verified against upstream
//! auth-service.ts). SA-03 mitigations baked in:
//! - single-flight token acquisition (no parallel logins / token stampede)
//! - refresh failures back off exponentially and NEVER auto-escalate to a password
//!   login unless `auto_password_login` is explicitly enabled
//! - credential logins are budgeted (rolling 24 h, persisted) and quarantine on excess
//! - ONE ThreatMetrix session id, generated once and persisted (stable device identity)
//! - MFA is surfaced to the caller (interactive), never brute-looped

use std::sync::{Arc, Mutex};

use chrono::DateTime;
use reqwest::Method;
use secrecy::ExposeSecret;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::models::{ErrorBody, MfaChallenge};
use crate::secrets::Credentials;
use crate::token_cache::{now_unix, TokenCache, TokenSet};
use crate::transport::{ApiRequest, ApiResponse, Transport};

/// Match upstream AUTHORIZATION_SKEW_MS (60 s).
const ACCESS_TOKEN_SKEW_SECS: i64 = 60;
const REFRESH_BACKOFF_BASE_SECS: u64 = 30;
const REFRESH_BACKOFF_MAX_SECS: u64 = 900;

#[derive(Debug)]
pub enum LoginFlow {
    Complete,
    MfaRequired(MfaChallenge),
}

pub struct MfaSubmission<'a> {
    pub challenge: &'a MfaChallenge,
    pub code: &'a str,
}

#[derive(Default)]
struct BackoffState {
    failures: u32,
    next_allowed_unix: i64,
}

pub struct AuthManager {
    cfg: Arc<Config>,
    transport: Arc<Transport>,
    cache: Arc<TokenCache>,
    /// Single-flight guard: at most one token acquisition in flight (SA-03).
    flight: tokio::sync::Mutex<()>,
    refresh_backoff: Mutex<BackoffState>,
}

impl AuthManager {
    pub fn new(cfg: Arc<Config>, transport: Arc<Transport>, cache: Arc<TokenCache>) -> Self {
        AuthManager {
            cfg,
            transport,
            cache,
            flight: tokio::sync::Mutex::new(()),
            refresh_backoff: Mutex::new(BackoffState::default()),
        }
    }

    pub fn cache(&self) -> &TokenCache {
        &self.cache
    }

    /// Get a valid access token: cached -> refresh -> (optionally, budgeted) credential
    /// login -> error. Never launches parallel logins.
    pub async fn access_token(&self) -> Result<String> {
        if let Some(tok) = self.cache.valid_access_token(ACCESS_TOKEN_SKEW_SECS) {
            return Ok(tok);
        }
        let _guard = self.flight.lock().await;
        // Re-check under the lock — another caller may have refreshed already.
        if let Some(tok) = self.cache.valid_access_token(ACCESS_TOKEN_SKEW_SECS) {
            return Ok(tok);
        }

        if let Some(refresh) = self.cache.refresh_token() {
            // Backoff window check (SA-03): don't hammer a failing refresh endpoint.
            {
                let b = self.refresh_backoff.lock().expect("backoff lock");
                let now = now_unix();
                if b.failures > 0 && now < b.next_allowed_unix {
                    return Err(Error::RefreshBackoff {
                        retry_after_secs: (b.next_allowed_unix - now).max(0) as u64,
                    });
                }
            }
            match self.refresh(&refresh).await {
                Ok(ts) => {
                    self.cache.store_tokens(&ts)?;
                    let mut b = self.refresh_backoff.lock().expect("backoff lock");
                    *b = BackoffState::default();
                    return Ok(ts.access_token);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "simplifi token refresh failed");
                    let mut b = self.refresh_backoff.lock().expect("backoff lock");
                    b.failures += 1;
                    let delay = (REFRESH_BACKOFF_BASE_SECS << (b.failures.min(6) - 1))
                        .min(REFRESH_BACKOFF_MAX_SECS);
                    b.next_allowed_unix = now_unix() + delay as i64;
                }
            }
        }

        // Refresh unavailable or failed. Only fall back to a credential login when the
        // operator explicitly opted in (upstream auto-escalated unconditionally: SA-03).
        if self.cfg.auto_password_login {
            if let Some(creds) = &self.cfg.credentials {
                return match self.login_attempt(creds, None).await {
                    Ok(ts) => Ok(ts.access_token),
                    Err(Error::MfaRequired(_)) => Err(Error::AuthRequired(
                        "MFA challenge received; interactive login needed",
                    )),
                    Err(e) => Err(e),
                };
            }
        }
        Err(Error::AuthRequired("no valid token and refresh unavailable"))
    }

    /// Interactive credential login (CLI/embedder driven). Returns `MfaRequired` with the
    /// challenge when Simplifi answers 202; complete with [`AuthManager::complete_mfa`].
    pub async fn login(&self, creds: &Credentials) -> Result<LoginFlow> {
        let _guard = self.flight.lock().await;
        match self.login_attempt(creds, None).await {
            Ok(_) => Ok(LoginFlow::Complete),
            Err(Error::MfaRequired(ch)) => Ok(LoginFlow::MfaRequired(ch)),
            Err(e) => Err(e),
        }
    }

    /// Complete a pending MFA challenge (same ThreatMetrix session id is reused
    /// automatically because it is persisted).
    pub async fn complete_mfa(
        &self,
        creds: &Credentials,
        challenge: &MfaChallenge,
        code: &str,
    ) -> Result<()> {
        let _guard = self.flight.lock().await;
        self.login_attempt(creds, Some(MfaSubmission { challenge, code }))
            .await
            .map(|_| ())
    }

    pub fn logout(&self) -> Result<()> {
        self.cache.clear_tokens()
    }

    async fn login_attempt(
        &self,
        creds: &Credentials,
        mfa: Option<MfaSubmission<'_>>,
    ) -> Result<TokenSet> {
        // Budget only NEW attempts; an MFA completion belongs to the attempt that
        // triggered the challenge.
        if mfa.is_none() {
            self.cache
                .check_and_record_credential_login(self.cfg.max_credential_logins_per_24h)?;
        }

        let tm = self
            .cache
            .tm_session_id(self.cfg.tm_session_id.as_deref())?;

        let body = serde_json::json!({
            "clientId": self.cfg.client_id,
            "username": creds.username,
            "password": creds.password.expose_secret(),
            "redirectUri": self.cfg.redirect_uri,
            "responseType": "code",
            "mfaChannel": mfa.as_ref().map(|m| m.challenge.mfa_channel.clone()),
            "mfaCode": mfa.as_ref().map(|m| m.code.to_string()),
            "mfaId": mfa.as_ref().map(|m| m.challenge.mfa_id.clone()),
            "threatMetrixRequestId": serde_json::Value::Null,
            "threatMetrixSessionId": tm,
        });

        let url = self
            .cfg
            .base_url
            .join("/oauth/authorize")
            .map_err(|_| Error::InvalidResponse("bad authorize url"))?;
        let mut headers = self.auth_headers();
        headers.push(("tm-session-id", tm.clone()));

        let resp = self
            .transport
            .execute(ApiRequest {
                method: Method::POST,
                url,
                headers,
                body: Some(body),
            })
            .await?;

        match resp.status {
            202 => {
                let v = resp.json_value().unwrap_or(serde_json::Value::Null);
                let challenge = MfaChallenge::from_body(&v);
                if challenge.mfa_id.is_empty() {
                    return Err(Error::InvalidResponse("202 without mfaId"));
                }
                Err(Error::MfaRequired(challenge))
            }
            200 | 201 => {
                let code = extract_auth_code(&resp, &self.cfg.base_url)?;
                let ts = self.exchange_code(&code).await?;
                self.cache.store_tokens(&ts)?;
                {
                    let mut b = self.refresh_backoff.lock().expect("backoff lock");
                    *b = BackoffState::default();
                }
                tracing::info!("simplifi credential login completed");
                Ok(ts)
            }
            status => Err(api_error(status, &resp)),
        }
    }

    async fn exchange_code(&self, code: &str) -> Result<TokenSet> {
        let secret = self.client_secret()?;
        let body = serde_json::json!({
            "grantType": "authorization_code",
            "clientId": self.cfg.client_id,
            "clientSecret": secret,
            "code": code,
            "redirectUri": self.cfg.redirect_uri,
        });
        self.token_request(body).await
    }

    async fn refresh(&self, refresh_token: &str) -> Result<TokenSet> {
        let secret = self.client_secret()?;
        let body = serde_json::json!({
            "grantType": "refreshToken",
            "responseType": "token",
            "redirectUri": self.cfg.redirect_uri,
            "clientId": self.cfg.client_id,
            "clientSecret": secret,
            "refreshToken": refresh_token,
        });
        self.token_request(body).await
    }

    async fn token_request(&self, body: serde_json::Value) -> Result<TokenSet> {
        let url = self
            .cfg
            .base_url
            .join("/oauth/token")
            .map_err(|_| Error::InvalidResponse("bad token url"))?;
        let resp = self
            .transport
            .execute(ApiRequest {
                method: Method::POST,
                url,
                headers: self.auth_headers(),
                body: Some(body),
            })
            .await?;
        if resp.status != 200 {
            return Err(api_error(resp.status, &resp));
        }
        parse_token_payload(&resp.json_value()?)
    }

    fn client_secret(&self) -> Result<&str> {
        self.cfg.client_secret.as_deref().ok_or_else(|| {
            Error::Config(
                "SIMPLIFI_CLIENT_SECRET is required for token exchange/refresh; it is \
                 Quicken's web-app client secret and is deliberately not bundled — see \
                 the README for how to read it from your own browser session"
                    .to_string(),
            )
        })
    }

    /// Exact upstream auth-call header set (auth-service.ts:318-335).
    fn auth_headers(&self) -> Vec<(&'static str, String)> {
        vec![
            ("content-type", "application/json;charset=UTF-8".to_string()),
            ("accept", "application/json, text/plain, */*".to_string()),
            ("app-client-id", self.cfg.client_id.clone()),
            ("app-release", self.cfg.app_release.clone()),
            ("app-build", self.cfg.app_build.clone()),
        ]
    }
}

/// Auth code arrives in TWO observed encodings — implement both (spec section 2.2):
/// 1. 2026: `Location` header containing `?code=...`
/// 2. 2023: JSON body `{ "code": "...", ... }`
fn extract_auth_code(resp: &ApiResponse, base: &reqwest::Url) -> Result<String> {
    if let Some(loc) = &resp.location {
        let parsed = reqwest::Url::parse(loc).or_else(|_| base.join(loc));
        if let Ok(u) = parsed {
            if let Some((_, code)) = u.query_pairs().find(|(k, _)| k == "code") {
                if !code.is_empty() {
                    return Ok(code.into_owned());
                }
            }
        }
        return Err(Error::InvalidResponse(
            "authorize Location header missing authorization code",
        ));
    }
    if let Ok(v) = resp.json_value() {
        if let Some(code) = v.get("code").and_then(|c| c.as_str()) {
            if !code.is_empty() {
                return Ok(code.to_string());
            }
        }
    }
    Err(Error::InvalidResponse(
        "authorize response had neither Location code nor JSON code",
    ))
}

/// Parse both token payload key styles (auth-service.ts:283-304):
/// `accessToken`/`access_token`, `accessTokenExpired` (ISO) / `expires_in` (secs),
/// fallback 55 min.
pub fn parse_token_payload(v: &serde_json::Value) -> Result<TokenSet> {
    let pick = |a: &str, b: &str| -> Option<String> {
        v.get(a)
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| v.get(b).and_then(|x| x.as_str()).filter(|s| !s.is_empty()))
            .map(str::to_string)
    };
    let access_token = pick("accessToken", "access_token")
        .ok_or(Error::InvalidResponse("token payload missing access token"))?;
    let refresh_token = pick("refreshToken", "refresh_token")
        .ok_or(Error::InvalidResponse("token payload missing refresh token"))?;

    let access_expires_at_unix = v
        .get("accessTokenExpired")
        .and_then(|x| x.as_str())
        .and_then(parse_iso_to_unix)
        .or_else(|| {
            v.get("expires_in")
                .and_then(|x| x.as_f64())
                .map(|secs| now_unix() + secs as i64)
        })
        .unwrap_or_else(|| now_unix() + 55 * 60);

    let refresh_expires_at_unix = v
        .get("refreshTokenExpired")
        .and_then(|x| x.as_str())
        .and_then(parse_iso_to_unix);

    Ok(TokenSet {
        access_token,
        access_expires_at_unix,
        refresh_token,
        refresh_expires_at_unix,
    })
}

fn parse_iso_to_unix(s: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(s).ok().map(|dt| dt.timestamp())
}

/// Parse a web-app session export — the value of `localStorage["authSession"]`
/// from a signed-in browser — into a [`TokenSet`], so a user who cannot hand
/// their password to the CLI can seed the token cache from their existing
/// browser session instead (the TS client's `auth import` path). Accepts the
/// bare session object, the object wrapped as `{ "authSession": ... }`, or
/// either as a JSON string. The session object uses the same key styles as a
/// token payload, so parsing delegates to [`parse_token_payload`]. Token
/// values are never logged or echoed by callers — only redacted status.
pub fn parse_auth_session_export(text: &str) -> Result<TokenSet> {
    let mut v: serde_json::Value = serde_json::from_str(text)
        .map_err(|_| Error::InvalidResponse("authSession export is not valid JSON"))?;
    // The localStorage value is itself a JSON string.
    if let Some(s) = v.as_str() {
        v = serde_json::from_str(s)
            .map_err(|_| Error::InvalidResponse("authSession export is not valid JSON"))?;
    }
    if let Some(inner) = v.get("authSession") {
        v = match inner {
            serde_json::Value::String(s) => serde_json::from_str(s).map_err(|_| {
                Error::InvalidResponse("authSession export is not valid JSON")
            })?,
            other => other.clone(),
        };
    }
    if !v.is_object() {
        return Err(Error::InvalidResponse(
            "authSession export is not a session object",
        ));
    }
    parse_token_payload(&v)
}

/// Build an SA-11-safe API error: status + short upstream `error` code only, never the body.
pub fn api_error(status: u16, resp: &ApiResponse) -> Error {
    let code = resp
        .json::<ErrorBody>()
        .ok()
        .and_then(|b| b.error)
        .map(|mut c| {
            c.truncate(64);
            c
        });
    Error::Api { status, code }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, location: Option<&str>, body: &str) -> ApiResponse {
        ApiResponse {
            status,
            location: location.map(str::to_string),
            retry_after: None,
            body: body.as_bytes().to_vec(),
        }
    }

    // ---- parse_token_payload: both observed key styles (spec section 2.3) ----

    #[test]
    fn token_payload_camel_case_with_iso_expiry() {
        let v = serde_json::json!({
            "accessToken": "at-1",
            "refreshToken": "rt-1",
            "accessTokenExpired": "2030-01-01T00:00:00Z",
            "refreshTokenExpired": "2030-02-01T00:00:00Z",
        });
        let ts = parse_token_payload(&v).unwrap();
        assert_eq!(ts.access_token, "at-1");
        assert_eq!(ts.refresh_token, "rt-1");
        assert_eq!(ts.access_expires_at_unix, 1_893_456_000);
        assert_eq!(ts.refresh_expires_at_unix, Some(1_896_134_400));
    }

    #[test]
    fn token_payload_snake_case_with_expires_in() {
        let v = serde_json::json!({
            "access_token": "at-2",
            "refresh_token": "rt-2",
            "expires_in": 3600,
        });
        let before = now_unix();
        let ts = parse_token_payload(&v).unwrap();
        assert_eq!(ts.access_token, "at-2");
        assert!(ts.access_expires_at_unix >= before + 3600);
        assert!(ts.access_expires_at_unix <= now_unix() + 3600 + 2);
        assert_eq!(ts.refresh_expires_at_unix, None);
    }

    #[test]
    fn token_payload_defaults_to_55_minutes_and_requires_both_tokens() {
        let v = serde_json::json!({ "accessToken": "at", "refreshToken": "rt" });
        let ts = parse_token_payload(&v).unwrap();
        assert!(ts.access_expires_at_unix > now_unix() + 54 * 60);

        let missing = serde_json::json!({ "accessToken": "at" });
        assert!(matches!(
            parse_token_payload(&missing),
            Err(Error::InvalidResponse(_))
        ));
        // empty strings are rejected, not accepted as tokens
        let empty = serde_json::json!({ "accessToken": "", "refreshToken": "rt" });
        assert!(parse_token_payload(&empty).is_err());
    }

    // ---- extract_auth_code: both observed encodings (spec section 2.2) ----

    #[test]
    fn auth_code_from_location_header() {
        let base = reqwest::Url::parse("https://services.quicken.com").unwrap();
        let r = resp(
            200,
            Some("https://simplifi.quicken.com/login?code=abc123&state=x"),
            "",
        );
        assert_eq!(extract_auth_code(&r, &base).unwrap(), "abc123");
        // relative Location resolves against the base
        let r = resp(200, Some("/login?code=rel456"), "");
        assert_eq!(extract_auth_code(&r, &base).unwrap(), "rel456");
    }

    #[test]
    fn auth_code_from_json_body() {
        let base = reqwest::Url::parse("https://services.quicken.com").unwrap();
        let r = resp(201, None, r#"{"code":"json789"}"#);
        assert_eq!(extract_auth_code(&r, &base).unwrap(), "json789");
    }

    #[test]
    fn auth_code_missing_fails() {
        let base = reqwest::Url::parse("https://services.quicken.com").unwrap();
        // Location present but no code param: does NOT fall through to the body
        let r = resp(200, Some("https://simplifi.quicken.com/login"), r#"{"code":"x"}"#);
        assert!(extract_auth_code(&r, &base).is_err());
        let r = resp(200, None, r#"{"nope":true}"#);
        assert!(extract_auth_code(&r, &base).is_err());
    }

    // ---- api_error: SA-11 (no body leakage, code truncated) ----

    #[test]
    fn api_error_carries_status_and_short_code_never_the_body() {
        let secret_body = r#"{"error":"invalid_grant","maskedEmail":"m***@example.com"}"#;
        let e = api_error(400, &resp(400, None, secret_body));
        let msg = e.to_string();
        assert!(msg.contains("status=400"), "{msg}");
        assert!(msg.contains("invalid_grant"), "{msg}");
        assert!(!msg.contains("maskedEmail"), "body leaked: {msg}");
        assert!(!msg.contains("example.com"), "body leaked: {msg}");
    }

    #[test]
    fn api_error_truncates_long_codes_and_tolerates_non_json() {
        let long = "x".repeat(500);
        let body = format!(r#"{{"error":"{long}"}}"#);
        match api_error(500, &resp(500, None, &body)) {
            Error::Api { status, code } => {
                assert_eq!(status, 500);
                assert_eq!(code.unwrap().len(), 64);
            }
            other => panic!("unexpected {other:?}"),
        }
        match api_error(502, &resp(502, None, "<html>gateway</html>")) {
            Error::Api { status, code } => {
                assert_eq!(status, 502);
                assert!(code.is_none());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    // ---- parse_auth_session_export: web-app session import ----

    const SESSION_JSON: &str = r#"{
        "accessToken": "acc-123",
        "refreshToken": "ref-456",
        "accessTokenExpired": "2099-01-01T00:00:00Z",
        "refreshTokenExpired": "2099-06-01T00:00:00Z"
    }"#;

    #[test]
    fn auth_session_export_parses_all_wrappings() {
        // bare object
        let ts = parse_auth_session_export(SESSION_JSON).unwrap();
        assert_eq!(ts.access_token, "acc-123");
        assert_eq!(ts.refresh_token, "ref-456");
        assert!(ts.access_expires_at_unix > now_unix());
        assert!(ts.refresh_expires_at_unix.is_some());
        // { "authSession": {...} }
        let wrapped = format!(r#"{{ "authSession": {SESSION_JSON} }}"#);
        assert_eq!(
            parse_auth_session_export(&wrapped).unwrap().access_token,
            "acc-123"
        );
        // the localStorage value itself is a JSON string
        let as_string = serde_json::to_string(SESSION_JSON).unwrap();
        assert_eq!(
            parse_auth_session_export(&as_string).unwrap().refresh_token,
            "ref-456"
        );
        // { "authSession": "<json string>" }
        let wrapped_string = serde_json::json!({ "authSession": SESSION_JSON }).to_string();
        assert_eq!(
            parse_auth_session_export(&wrapped_string)
                .unwrap()
                .access_token,
            "acc-123"
        );
    }

    #[test]
    fn auth_session_export_rejects_garbage() {
        assert!(parse_auth_session_export("not json").is_err());
        assert!(parse_auth_session_export("[1,2]").is_err());
        assert!(parse_auth_session_export("{}").is_err());
        // missing refresh token -> parse_token_payload's requirement applies
        assert!(parse_auth_session_export(r#"{ "accessToken": "x" }"#).is_err());
    }
}
