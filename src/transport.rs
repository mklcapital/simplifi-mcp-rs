//! HTTP transport abstraction.
//!
//! `Transport::Http` is a hardened reqwest client: rustls, `https_only`, redirects
//! disabled (`Policy::none()` — SA-05; upstream auth calls already required
//! `redirect: manual`), explicit timeouts. When `HTTPS_PROXY`/`https_proxy` is
//! set in the environment it is honored (with reqwest's default features off,
//! env proxies are not picked up automatically) — sandboxed and corporate
//! egress often requires a CONNECT proxy, and every other tool on such a
//! system (curl, git) already follows these variables. Likewise, when
//! `SSL_CERT_FILE` names a PEM bundle it is loaded as additional roots: the
//! intercepting proxies in those same environments present certificates
//! issued by a local CA that the bundled webpki roots cannot verify, while
//! curl/Python/OpenSSL all defer to `SSL_CERT_FILE`. `Transport::Mock`
//! (feature `mock`) serves recorded fixtures so tests and demos run with zero
//! live credentials.

use std::time::Duration;

use reqwest::{Method, Url};
use serde::de::DeserializeOwned;

use crate::error::{Error, Result};

#[derive(Clone, Debug)]
pub struct ApiRequest {
    pub method: Method,
    pub url: Url,
    /// (header-name, value) pairs; callers build exact upstream header sets.
    pub headers: Vec<(&'static str, String)>,
    pub body: Option<serde_json::Value>,
}

#[derive(Clone, Debug)]
pub struct ApiResponse {
    pub status: u16,
    pub location: Option<String>,
    pub retry_after: Option<u64>,
    pub body: Vec<u8>,
}

impl ApiResponse {
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        Ok(serde_json::from_slice(&self.body)?)
    }

    pub fn json_value(&self) -> Result<serde_json::Value> {
        Ok(serde_json::from_slice(&self.body)?)
    }
}

pub enum Transport {
    Http(HttpTransport),
    #[cfg(feature = "mock")]
    Mock(crate::mock::MockTransport),
}

impl Transport {
    pub async fn execute(&self, req: ApiRequest) -> Result<ApiResponse> {
        match self {
            Transport::Http(t) => t.execute(req).await,
            #[cfg(feature = "mock")]
            Transport::Mock(t) => t.execute(req).await,
        }
    }
}

pub struct HttpTransport {
    client: reqwest::Client,
}

/// The egress proxy from the standard environment variables, if set and
/// parseable. All upstream traffic is https, so only the https variant is
/// consulted.
fn env_https_proxy() -> Option<reqwest::Proxy> {
    let raw = std::env::var("HTTPS_PROXY")
        .or_else(|_| std::env::var("https_proxy"))
        .ok()
        .filter(|s| !s.trim().is_empty())?;
    reqwest::Proxy::https(&raw).ok()
}

/// Certificates from the `SSL_CERT_FILE` PEM bundle, if the variable is set.
/// An unreadable or unparseable bundle is an error, not a silent skip: the
/// variable expresses explicit intent about which roots to trust.
fn env_extra_roots() -> Result<Vec<reqwest::Certificate>> {
    let Some(path) = std::env::var_os("SSL_CERT_FILE") else {
        return Ok(Vec::new());
    };
    let pem = std::fs::read(&path)
        .map_err(|e| Error::Transport(format!("SSL_CERT_FILE unreadable: {e}")))?;
    let mut certs = Vec::new();
    let text = String::from_utf8_lossy(&pem);
    for chunk in text.split("-----END CERTIFICATE-----") {
        let Some(start) = chunk.find("-----BEGIN CERTIFICATE-----") else {
            continue;
        };
        let one = format!("{}-----END CERTIFICATE-----", &chunk[start..]);
        let cert = reqwest::Certificate::from_pem(one.as_bytes())
            .map_err(|e| Error::Transport(format!("SSL_CERT_FILE bad certificate: {e}")))?;
        certs.push(cert);
    }
    Ok(certs)
}

impl HttpTransport {
    pub fn new(timeout_ms: u64, user_agent: &str) -> Result<Self> {
        let mut builder = reqwest::Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(timeout_ms))
            .connect_timeout(Duration::from_secs(10))
            .user_agent(user_agent);
        if let Some(proxy) = env_https_proxy() {
            builder = builder.proxy(proxy);
        }
        for cert in env_extra_roots()? {
            builder = builder.add_root_certificate(cert);
        }
        let client = builder
            .build()
            .map_err(|e| Error::Transport(scrub_reqwest(e)))?;
        Ok(HttpTransport { client })
    }

    pub async fn execute(&self, req: ApiRequest) -> Result<ApiResponse> {
        let mut r = self.client.request(req.method, req.url);
        for (k, v) in &req.headers {
            r = r.header(*k, v);
        }
        if let Some(b) = &req.body {
            r = r.body(serde_json::to_vec(b)?);
        }
        let resp = r.send().await.map_err(|e| Error::Transport(scrub_reqwest(e)))?;
        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok());
        let body = resp
            .bytes()
            .await
            .map_err(|e| Error::Transport(scrub_reqwest(e)))?
            .to_vec();
        Ok(ApiResponse {
            status,
            location,
            retry_after,
            body,
        })
    }
}

/// Strip the URL (which may embed query material) from reqwest error text.
fn scrub_reqwest(e: reqwest::Error) -> String {
    e.without_url().to_string()
}

/// Validate an upstream-influenced URL before following it (SA-05): https only, host must
/// equal the allowlisted API host, no userinfo, no port override.
pub fn validate_upstream_url(url: &Url, allowed_host: &str) -> Result<()> {
    if url.scheme() != "https" {
        return Err(Error::UnsafeUrl(format!("non-https scheme: {}", url.scheme())));
    }
    match url.host_str() {
        Some(h) if h.eq_ignore_ascii_case(allowed_host) => {}
        other => {
            return Err(Error::UnsafeUrl(format!(
                "host {:?} not in allowlist [{allowed_host}]",
                other.unwrap_or("<none>")
            )))
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::UnsafeUrl("userinfo present".to_string()));
    }
    if url.port().is_some() {
        return Err(Error::UnsafeUrl("explicit port override".to_string()));
    }
    Ok(())
}
