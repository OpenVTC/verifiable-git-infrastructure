//! The HTTP surface the forges (and admins' browsers) reach.
//!
//! | Route | Who calls it |
//! |---|---|
//! | `GET  /healthz` | the orchestrator |
//! | `GET  /github/{host}/register?state=` | the admin, from the URL the bridge logs (manifest flow) |
//! | `GET  /github/{host}/registered?code=&state=` | GitHub, after the App is registered |
//! | `GET  /github/{host}/setup?installation_id=&setup_action=&state=` | GitHub, after the App is installed (bind) |
//! | `POST /github/{host}/webhook` | GitHub |
//! | `GET  /forgejo/{host}/bind?code=&state=` | Forgejo's OAuth redirect (bind) |
//! | `GET  /forgejo/{host}/link?code=&state=` | Forgejo's OAuth redirect (account link) |
//! | `POST /forgejo/{host}/webhook` | Forgejo |
//!
//! Plain HTTP/1: TLS is terminated by the proxy in front (the operator guide
//! says so, and the config refuses a non-`https` public URL). Request bodies
//! are capped at `max_body_bytes`, and a webhook body is handed to the
//! adapter as the exact bytes received — the signature is checked over them
//! before anything parses them. A `{host}` the config does not name is a 404.
//! No handler reflects request input into a page.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};

use crate::bridge::Bridge;
use crate::flows;

/// The router, over `bridge`.
pub fn router(bridge: Arc<Bridge>) -> Router {
    let limit = bridge.cfg.max_body_bytes;
    let r = Router::new().route("/healthz", get(healthz));
    #[cfg(feature = "forge-github")]
    let r = r
        .route("/github/{host}/register", get(github_register))
        .route("/github/{host}/registered", get(github_registered))
        .route("/github/{host}/setup", get(github_setup))
        .route("/github/{host}/webhook", post(webhook));
    #[cfg(feature = "forge-forgejo")]
    let r = r
        .route("/forgejo/{host}/bind", get(forgejo_bind))
        .route("/forgejo/{host}/link", get(forgejo_link))
        .route("/forgejo/{host}/webhook", post(webhook));
    r.layer(DefaultBodyLimit::max(limit)).with_state(bridge)
}

async fn healthz() -> &'static str {
    "ok"
}

fn page(status: StatusCode, text: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Html(format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>VGI bridge</title></head>\
             <body><p>{}</p></body></html>",
            flows::html_escape(text)
        )),
    )
        .into_response()
}

fn known_host(bridge: &Bridge, host: &str) -> bool {
    bridge.adapters.get(host).is_some()
        || bridge.cfg.github.iter().any(|g| g.host == host)
        || bridge
            .cfg
            .forgejo
            .iter()
            .any(|f| f.host().is_ok_and(|h| h == host))
}

async fn webhook(
    State(bridge): State<Arc<Bridge>>,
    Path(host): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    if !known_host(&bridge, &host) {
        return StatusCode::NOT_FOUND;
    }
    crate::events::on_webhook(&bridge, &host, &headers, &body).await
}

#[cfg(feature = "forge-github")]
async fn github_register(
    State(bridge): State<Arc<Bridge>>,
    Path(host): Path<String>,
    Query(q): Query<BTreeMap<String, String>>,
) -> Response {
    if !known_host(&bridge, &host) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let state = q.get("state").map(String::as_str).unwrap_or("");
    match flows::manifest_page(&bridge, &host, state) {
        Ok(html) => (
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::REFERRER_POLICY, "no-referrer"),
            ],
            Html(html),
        )
            .into_response(),
        Err(e) => {
            tracing::warn!(%host, error = %e, "refused a registration page");
            page(
                StatusCode::NOT_FOUND,
                "This registration link is unknown or expired.",
            )
        }
    }
}

#[cfg(feature = "forge-github")]
async fn github_registered(
    State(bridge): State<Arc<Bridge>>,
    Path(host): Path<String>,
    Query(q): Query<BTreeMap<String, String>>,
) -> Response {
    if !known_host(&bridge, &host) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let (Some(code), Some(state)) = (q.get("code"), q.get("state")) else {
        return page(
            StatusCode::BAD_REQUEST,
            "The redirect is missing its code or state.",
        );
    };
    match flows::manifest_callback(&bridge, &host, code, state).await {
        Ok(msg) => page(StatusCode::OK, &msg),
        Err(e) => {
            tracing::warn!(%host, error = %e, "App registration failed");
            page(
                StatusCode::BAD_REQUEST,
                "The App could not be registered; the bridge's log says why.",
            )
        }
    }
}

async fn bind(bridge: Arc<Bridge>, host: String, q: BTreeMap<String, String>) -> Response {
    if !known_host(&bridge, &host) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match flows::bind_callback(&bridge, &host, q).await {
        Ok(msg) => page(StatusCode::OK, &msg),
        Err(e) => {
            tracing::warn!(%host, error = %e, "bind callback refused");
            page(
                StatusCode::BAD_REQUEST,
                "The namespace could not be bound; ask the VTC admin to start again.",
            )
        }
    }
}

#[cfg(feature = "forge-github")]
async fn github_setup(
    State(bridge): State<Arc<Bridge>>,
    Path(host): Path<String>,
    Query(q): Query<BTreeMap<String, String>>,
) -> Response {
    bind(bridge, host, q).await
}

#[cfg(feature = "forge-forgejo")]
async fn forgejo_bind(
    State(bridge): State<Arc<Bridge>>,
    Path(host): Path<String>,
    Query(q): Query<BTreeMap<String, String>>,
) -> Response {
    bind(bridge, host, q).await
}

#[cfg(feature = "forge-forgejo")]
async fn forgejo_link(
    State(bridge): State<Arc<Bridge>>,
    Path(host): Path<String>,
    Query(q): Query<BTreeMap<String, String>>,
) -> Response {
    if !known_host(&bridge, &host) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match flows::link_callback(&bridge, &host, q).await {
        Ok(msg) => page(StatusCode::OK, &msg),
        Err(e) => {
            tracing::warn!(%host, error = %e, "link callback refused");
            page(
                StatusCode::BAD_REQUEST,
                "Your account could not be linked; start again from your community app.",
            )
        }
    }
}
