//! A thin GitHub REST client over reqwest.
//!
//! Only what the adapter uses: build a URL from path segments (so a name can
//! never smuggle in `/`, `?` or `..`), send with the pinned API version and a
//! bearer credential, and map failures onto [`ForgeError`]. Redirects are not
//! followed: a 301 from GitHub means a repository was renamed or transferred,
//! which the core must learn about rather than have papered over, and not
//! following one also means a credential never travels to a URL nobody
//! configured.

use std::time::Duration;

use reqwest::{Method, Response, StatusCode, header};
use serde::de::DeserializeOwned;
use serde_json::Value;
use url::Url;
use vgi_forge::{ForgeError, Result};

use crate::secret::Secret;

/// GitHub REST API version this adapter is written against.
pub const API_VERSION: &str = "2022-11-28";

/// Ceiling on pages followed for one listing (100 per page).
const MAX_PAGES: usize = 50;

/// How a request authenticates.
#[derive(Clone, Copy)]
pub(crate) enum Auth<'a> {
    /// Unauthenticated (manifest conversion, device flow).
    None,
    /// `Authorization: Bearer …` — an App JWT, an installation token or a
    /// user token.
    Bearer(&'a Secret),
}

#[derive(Debug, Clone)]
pub(crate) struct Api {
    client: reqwest::Client,
    pub(crate) api_base: Url,
    pub(crate) web_base: Url,
}

impl Api {
    pub(crate) fn new(api_base: Url, web_base: Url, timeout: Duration) -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent(concat!("vgi-forge-github/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|e| ForgeError::Config(format!("HTTP client: {e}")))?;
        Ok(Api {
            client,
            api_base,
            web_base,
        })
    }

    /// `api_base` + segments, each percent-encoded as a single segment.
    pub(crate) fn url(&self, segments: &[&str]) -> Url {
        join(&self.api_base, segments)
    }

    /// `web_base` + segments.
    pub(crate) fn web_url(&self, segments: &[&str]) -> Url {
        join(&self.web_base, segments)
    }

    /// Send a request and map any non-2xx status to an error. `what` names
    /// the target in error messages.
    pub(crate) async fn send(
        &self,
        method: Method,
        url: Url,
        auth: Auth<'_>,
        body: Option<&Value>,
        what: &str,
    ) -> Result<Response> {
        let mut req = self
            .client
            .request(method, url)
            .header(header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", API_VERSION);
        if let Auth::Bearer(token) = auth {
            let mut value = header::HeaderValue::try_from(format!("Bearer {}", token.expose()))
                .map_err(|_| ForgeError::Config("credential is not a valid header value".into()))?;
            // Keeps the value out of reqwest/hyper debug output.
            value.set_sensitive(true);
            req = req.header(header::AUTHORIZATION, value);
        }
        if let Some(body) = body {
            req = req.json(body);
        }
        let resp = req.send().await.map_err(|e| {
            // Strip the URL: it is ours, but errors travel to the VTC's log.
            ForgeError::Unavailable(e.without_url().to_string())
        })?;
        check(resp, what).await
    }

    /// Send and decode a JSON body.
    pub(crate) async fn json<T: DeserializeOwned>(
        &self,
        method: Method,
        url: Url,
        auth: Auth<'_>,
        body: Option<&Value>,
        what: &str,
    ) -> Result<T> {
        let resp = self.send(method, url, auth, body, what).await?;
        decode(resp, what).await
    }

    /// POST a JSON body to a github.com OAuth endpoint (`/login/...`) and
    /// decode the answer. These live on the web host, speak plain
    /// `application/json`, and report most failures as a 200 with an
    /// `error` field, which the caller inspects.
    pub(crate) async fn oauth<T: DeserializeOwned>(&self, url: Url, body: &Value) -> Result<T> {
        let resp = self
            .client
            .post(url)
            .header(header::ACCEPT, "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| ForgeError::Unavailable(e.without_url().to_string()))?;
        let resp = check(resp, "OAuth device flow").await?;
        decode(resp, "OAuth device flow").await
    }

    /// `GET` that maps 404 to `None`.
    pub(crate) async fn get_opt<T: DeserializeOwned>(
        &self,
        url: Url,
        auth: Auth<'_>,
        what: &str,
    ) -> Result<Option<T>> {
        match self.json(Method::GET, url, auth, None, what).await {
            Ok(v) => Ok(Some(v)),
            Err(ForgeError::NotFound { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `GET` a list, following `Link: rel="next"` — but only to the same
    /// origin as the API base.
    pub(crate) async fn get_all<T: DeserializeOwned>(
        &self,
        mut url: Url,
        auth: Auth<'_>,
        what: &str,
    ) -> Result<Vec<T>> {
        url.query_pairs_mut().append_pair("per_page", "100");
        let mut out = Vec::new();
        for _ in 0..MAX_PAGES {
            let resp = self
                .send(Method::GET, url.clone(), auth, None, what)
                .await?;
            let next = next_link(&resp).filter(|n| n.origin() == self.api_base.origin());
            let page: Vec<T> = decode(resp, what).await?;
            out.extend(page);
            match next {
                Some(n) => url = n,
                None => return Ok(out),
            }
        }
        Err(ForgeError::Protocol(format!(
            "{what}: more than {MAX_PAGES} pages"
        )))
    }
}

/// Callers pass only validated segments — resource names (the vgi-core
/// grammar has no `.`/`..`/empty segments), checked repo paths, numeric ids,
/// `[A-Z0-9_]` variable names, the configured App slug. `url` treats a `..`
/// segment as navigation rather than data, so that validation is what keeps
/// every request inside the path it was built for; the test below pins that
/// even an unvalidated `..` cannot climb above its parent.
fn join(base: &Url, segments: &[&str]) -> Url {
    let mut url = base.clone();
    {
        let mut path = url
            .path_segments_mut()
            .expect("API base URLs are http(s), which have paths");
        path.pop_if_empty();
        for s in segments {
            path.push(s);
        }
    }
    url
}

async fn decode<T: DeserializeOwned>(resp: Response, what: &str) -> Result<T> {
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| ForgeError::Unavailable(e.without_url().to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| ForgeError::Protocol(format!("{what}: {e}")))
}

async fn check(resp: Response, what: &str) -> Result<Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    if status.is_redirection() {
        let location = resp
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("(no location)")
            .to_string();
        return Err(ForgeError::Moved {
            what: what.to_string(),
            location,
        });
    }

    let headers = resp.headers().clone();
    let message = error_message(resp).await;
    let header_u64 = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
    };
    let rate_limited = status == StatusCode::TOO_MANY_REQUESTS
        || (status == StatusCode::FORBIDDEN
            && (header_u64("x-ratelimit-remaining") == Some(0)
                || headers.contains_key(header::RETRY_AFTER)));

    Err(match status {
        _ if rate_limited => ForgeError::RateLimited {
            retry_after_secs: header_u64(header::RETRY_AFTER.as_str()),
        },
        StatusCode::UNAUTHORIZED => ForgeError::Unauthorized(format!("{what}: {message}")),
        StatusCode::FORBIDDEN => ForgeError::Forbidden(format!("{what}: {message}")),
        StatusCode::NOT_FOUND => ForgeError::NotFound {
            what: what.to_string(),
        },
        StatusCode::CONFLICT | StatusCode::UNPROCESSABLE_ENTITY | StatusCode::BAD_REQUEST => {
            ForgeError::Rejected {
                status: status.as_u16(),
                message: format!("{what}: {message}"),
            }
        }
        s if s.is_server_error() => ForgeError::Unavailable(format!("{what}: {s} {message}")),
        s => ForgeError::Protocol(format!("{what}: unexpected {s} {message}")),
    })
}

/// GitHub's `message` (and first validation error), truncated. Never the raw
/// body: it is shown to people and logged.
async fn error_message(resp: Response) -> String {
    let Ok(body) = resp.json::<Value>().await else {
        return "(no message)".into();
    };
    let mut msg = body
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("(no message)")
        .to_string();
    if let Some(detail) = body
        .get("errors")
        .and_then(Value::as_array)
        .and_then(|e| e.first())
    {
        let detail = detail
            .get("message")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| detail.as_str().map(str::to_string))
            .unwrap_or_else(|| detail.to_string());
        msg = format!("{msg} ({detail})");
    }
    if msg.len() > 300 {
        let mut end = 300;
        while !msg.is_char_boundary(end) {
            end -= 1;
        }
        msg.truncate(end);
        msg.push('…');
    }
    msg
}

fn next_link(resp: &Response) -> Option<Url> {
    let link = resp.headers().get(header::LINK)?.to_str().ok()?;
    link.split(',').find_map(|part| {
        let (target, params) = part.split_once(';')?;
        if !params.split(';').any(|p| p.trim() == r#"rel="next""#) {
            return None;
        }
        Url::parse(target.trim().trim_start_matches('<').trim_end_matches('>')).ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_segments_are_encoded_one_by_one() {
        let base = Url::parse("https://ghe.example/api/v3").unwrap();
        let url = join(&base, &["repos", "acme", "a/b?c", "contents"]);
        assert_eq!(
            url.as_str(),
            "https://ghe.example/api/v3/repos/acme/a%2Fb%3Fc/contents"
        );
        let url = join(&base, &["repos", "acme", "..", "..", "..", "x"]);
        assert!(url.path().starts_with("/api/v3/repos"), "{url}");
        let root = Url::parse("https://api.github.com").unwrap();
        assert_eq!(
            join(&root, &["user"]).as_str(),
            "https://api.github.com/user"
        );
    }
}
