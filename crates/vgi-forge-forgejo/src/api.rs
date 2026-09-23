//! A thin Forgejo REST client over reqwest.
//!
//! The same discipline as the GitHub adapter's client: URLs are built from
//! path segments (a name can never smuggle in `/`, `?` or `..`), every
//! request names its credential explicitly, and redirects are never
//! followed — Forgejo answers a renamed repository with a redirect, which
//! the core must learn about, and not following one also means the bot
//! token never travels to a URL nobody configured.

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::{Method, Response, StatusCode, header};
use serde::de::DeserializeOwned;
use serde_json::Value;
use url::Url;
use vgi_forge::{ForgeError, Result};
use zeroize::Zeroizing;

use crate::secret::Secret;

/// Items per page asked for. Forgejo caps it at `MAX_RESPONSE_ITEMS` (50 by
/// default); a smaller cap only means more pages.
const PAGE_LIMIT: usize = 50;

/// Ceiling on pages followed for one listing.
const MAX_PAGES: usize = 100;

/// How a request authenticates.
#[derive(Clone, Copy)]
pub(crate) enum Auth<'a> {
    /// `Authorization: token …` — the bot's personal access token.
    Token(&'a Secret),
    /// `Authorization: Bearer …` — an OAuth access token (the one-time
    /// admin token at bind, a member's token at link).
    Bearer(&'a Secret),
    /// `Authorization: Basic …` — the bot's password, which Forgejo requires
    /// for minting and deleting access tokens.
    Basic {
        /// The login.
        user: &'a str,
        /// The password.
        password: &'a Secret,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct Api {
    client: reqwest::Client,
    /// `<instance>/api/v1`.
    pub(crate) api_base: Url,
    /// `<instance>/`.
    pub(crate) web_base: Url,
}

impl Api {
    pub(crate) fn new(api_base: Url, web_base: Url, timeout: Duration) -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent(concat!("vgi-forge-forgejo/", env!("CARGO_PKG_VERSION")))
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
        let resp = self.raw(method, url, auth, body).await?;
        check(resp, what).await
    }

    async fn raw(
        &self,
        method: Method,
        url: Url,
        auth: Auth<'_>,
        body: Option<&Value>,
    ) -> Result<Response> {
        let bodyless_write =
            body.is_none() && matches!(method, Method::POST | Method::PUT | Method::PATCH);
        let mut req = self
            .client
            .request(method, url)
            .header(header::ACCEPT, "application/json");
        req = req.header(header::AUTHORIZATION, auth_header(auth)?);
        if let Some(body) = body {
            req = req.json(body);
        } else if bodyless_write {
            // hyper sends no length for an empty body, and a write with no
            // length at all is refused (411) by some proxies in front of
            // Forgejo.
            req = req
                .header(header::CONTENT_LENGTH, "0")
                .body(Vec::<u8>::new());
        }
        req.send().await.map_err(|e| {
            // Strip the URL: it is ours, but errors travel to the VTC's log.
            ForgeError::Unavailable(e.without_url().to_string())
        })
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

    /// Send and decode a JSON body whose bytes hold a credential (a new
    /// access token): the raw buffer is wiped once decoded.
    pub(crate) async fn json_secret<T: DeserializeOwned>(
        &self,
        method: Method,
        url: Url,
        auth: Auth<'_>,
        body: Option<&Value>,
        what: &str,
    ) -> Result<T> {
        let resp = self.send(method, url, auth, body, what).await?;
        let bytes = Zeroizing::new(
            resp.bytes()
                .await
                .map_err(|e| ForgeError::Unavailable(e.without_url().to_string()))?
                .to_vec(),
        );
        serde_json::from_slice(&bytes).map_err(|e| ForgeError::Protocol(format!("{what}: {e}")))
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

    /// `GET` whose answer is a bare status: 2xx is `true`, 404 is `false`.
    pub(crate) async fn exists(&self, url: Url, auth: Auth<'_>, what: &str) -> Result<bool> {
        match self.send(Method::GET, url, auth, None, what).await {
            Ok(_) => Ok(true),
            Err(ForgeError::NotFound { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// `GET` a list, page by page (`page`, `limit`), until the total the
    /// instance reported (`X-Total-Count`) is reached, a page comes back
    /// empty, or a page repeats the one before (an endpoint that does not
    /// paginate — Forgejo's org hook list — answers every page with the
    /// whole list). Page numbers rather than `Link` headers: Forgejo builds
    /// those from its configured `ROOT_URL`, which need not be the URL the
    /// bridge reaches it by.
    pub(crate) async fn get_all<T: DeserializeOwned>(
        &self,
        url: Url,
        auth: Auth<'_>,
        what: &str,
    ) -> Result<Vec<T>> {
        let mut out: Vec<Value> = Vec::new();
        let mut previous: Option<Vec<Value>> = None;
        let mut done = false;
        for page in 1..=MAX_PAGES {
            let mut u = url.clone();
            u.query_pairs_mut()
                .append_pair("page", &page.to_string())
                .append_pair("limit", &PAGE_LIMIT.to_string());
            let resp = self.send(Method::GET, u, auth, None, what).await?;
            let total = resp
                .headers()
                .get("x-total-count")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<usize>().ok());
            let items: Vec<Value> = decode(resp, what).await?;
            if items.is_empty() || previous.as_ref() == Some(&items) {
                done = true;
                break;
            }
            out.extend(items.iter().cloned());
            if total.is_some_and(|t| out.len() >= t) {
                done = true;
                break;
            }
            previous = Some(items);
        }
        if !done {
            return Err(ForgeError::Protocol(format!(
                "{what}: more than {MAX_PAGES} pages"
            )));
        }
        out.into_iter()
            .map(|v| {
                serde_json::from_value(v).map_err(|e| ForgeError::Protocol(format!("{what}: {e}")))
            })
            .collect()
    }

    /// POST a form to the instance's OAuth token endpoint and decode the
    /// answer. Errors there are a 400 (or 401) with an RFC 6749 `error`
    /// body, which the caller inspects, so those are decoded rather than
    /// mapped. The raw body holds the tokens and is wiped once decoded.
    pub(crate) async fn oauth_token<T: DeserializeOwned>(
        &self,
        url: Url,
        form: &[(&str, &str)],
    ) -> Result<T> {
        let body = Zeroizing::new(
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(form)
                .finish(),
        );
        let resp = self
            .client
            .post(url)
            .header(header::ACCEPT, "application/json")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body.as_bytes().to_vec())
            .send()
            .await
            .map_err(|e| ForgeError::Unavailable(e.without_url().to_string()))?;
        let resp = match resp.status() {
            StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED => resp,
            _ => check(resp, "OAuth token exchange").await?,
        };
        let bytes = Zeroizing::new(
            resp.bytes()
                .await
                .map_err(|e| ForgeError::Unavailable(e.without_url().to_string()))?
                .to_vec(),
        );
        serde_json::from_slice(&bytes)
            .map_err(|e| ForgeError::Protocol(format!("OAuth token exchange: {e}")))
    }
}

fn auth_header(auth: Auth<'_>) -> Result<header::HeaderValue> {
    let text = match auth {
        Auth::Token(t) => Zeroizing::new(format!("token {}", t.expose())),
        Auth::Bearer(t) => Zeroizing::new(format!("Bearer {}", t.expose())),
        Auth::Basic { user, password } => {
            let pair = Zeroizing::new(format!("{user}:{}", password.expose()));
            Zeroizing::new(format!("Basic {}", STANDARD.encode(pair.as_bytes())))
        }
    };
    let mut value = header::HeaderValue::try_from(text.as_str())
        .map_err(|_| ForgeError::Config("credential is not a valid header value".into()))?;
    // Keeps the value out of reqwest/hyper debug output.
    value.set_sensitive(true);
    Ok(value)
}

/// Callers pass only validated segments — resource names (the vgi-core
/// grammar has no `.`/`..`/empty segments), checked logins and repo paths,
/// numeric ids, `[A-Z0-9_]` variable names. `url` treats a `..` segment as
/// navigation rather than data, so that validation is what keeps every
/// request inside the path it was built for; the test below pins that even
/// an unvalidated `..` cannot climb above its parent.
fn join(base: &Url, segments: &[&str]) -> Url {
    let mut url = base.clone();
    {
        let mut path = url
            .path_segments_mut()
            .expect("instance URLs are http(s), which have paths");
        path.pop_if_empty();
        for s in segments {
            path.push(s);
        }
    }
    url
}

pub(crate) async fn decode<T: DeserializeOwned>(resp: Response, what: &str) -> Result<T> {
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

    let retry_after = resp
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let message = error_message(resp).await;
    Err(match status {
        StatusCode::TOO_MANY_REQUESTS => ForgeError::RateLimited {
            retry_after_secs: retry_after,
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

/// Forgejo's `message` (and first validation error), truncated. Never the
/// raw body: it is shown to people and logged.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_segments_are_encoded_one_by_one() {
        let base = Url::parse("https://git.example/sub/api/v1").unwrap();
        let url = join(&base, &["repos", "acme", "a/b?c", "contents"]);
        assert_eq!(
            url.as_str(),
            "https://git.example/sub/api/v1/repos/acme/a%2Fb%3Fc/contents"
        );
        let url = join(&base, &["repos", "acme", "..", "..", "..", "x"]);
        assert!(url.path().starts_with("/sub/api/v1/repos"), "{url}");
    }

    #[test]
    fn credentials_become_sensitive_headers() {
        let t = Secret::new("abc");
        let h = auth_header(Auth::Token(&t)).unwrap();
        assert!(h.is_sensitive());
        assert_eq!(h.to_str().unwrap(), "token abc");
        let h = auth_header(Auth::Basic {
            user: "bot",
            password: &Secret::new("pw"),
        })
        .unwrap();
        assert_eq!(h.to_str().unwrap(), "Basic Ym90OnB3");
        let h = auth_header(Auth::Bearer(&t)).unwrap();
        assert_eq!(h.to_str().unwrap(), "Bearer abc");
    }
}
