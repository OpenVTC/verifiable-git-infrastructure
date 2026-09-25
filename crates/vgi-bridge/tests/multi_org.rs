//! Several GitHub organisations on one bridge: one private App per
//! organisation, keyed by (host, owner), each with its own secrets, routes
//! and webhook secret; the bridge picks the App from a resource's owner.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::*;
use serde_json::json;
use tower::ServiceExt;
use vgi_bridge::registry::{StoredApp, github_app_secret, legacy_github_app_secret};
use vgi_forge::Resource;
use vgi_forge_github::Secret;
use vgi_forge_github::webhook::sign_body;

const GLOBEX_APP: u64 = 2002;
const GLOBEX_SECRET: &str = "whsec-globex";

fn two_orgs() -> Options {
    Options {
        github_extra: r#"
[[github]]
app_name = "globex-vgi-bridge"
app_owner = "globex"
api_base = "{MOCK}"
web_base = "{MOCK}"
"#
        .into(),
        extra_apps: vec![("globex", GLOBEX_APP, GLOBEX_SECRET)],
        ..Options::default()
    }
}

async fn post(w: &World, uri: &str, secret: &str, headers: &[(&str, &str)]) -> StatusCode {
    let body = serde_json::to_vec(&json!({ "zen": "hi", "hook_id": 1 })).unwrap();
    let mut req = Request::post(uri)
        .header("x-github-event", "ping")
        .header("x-github-delivery", vgi_bridge::wire::new_id())
        .header(
            "x-hub-signature-256",
            sign_body(&Secret::new(secret), &body),
        );
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    vgi_bridge::http::router(w.bridge.clone())
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap()
        .status()
}

async fn get(w: &World, uri: &str) -> (StatusCode, String) {
    let resp = vgi_bridge::http::router(w.bridge.clone())
        .oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

fn app_id_for(w: &World, owner: &str) -> Option<u64> {
    let r = Resource::namespace_of("github.com", owner).unwrap();
    w.bridge
        .adapters()
        .for_resource(&r)
        .and_then(|a| a.github().map(|g| g.config().app_id))
}

#[tokio::test]
async fn each_organisation_is_served_by_its_own_app() {
    let w = world(two_orgs()).await;
    assert_eq!(app_id_for(&w, "acme"), Some(APP_ID));
    assert_eq!(
        app_id_for(&w, "Globex"),
        Some(GLOBEX_APP),
        "logins are case-insensitive"
    );
    // With several Apps on the host, an owner without one has none: its
    // namespaces cannot be bound through another organisation's App.
    assert_eq!(app_id_for(&w, "initech"), None);
    assert_eq!(w.bridge.adapters().count_on("github.com"), 2);
}

#[tokio::test]
async fn webhooks_are_routed_to_their_app_and_verified_with_its_secret() {
    let w = world(two_orgs()).await;
    // Each App's own route, its own secret.
    assert_eq!(
        post(&w, "/github/github.com/globex/webhook", GLOBEX_SECRET, &[]).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post(&w, "/github/github.com/acme/webhook", WEBHOOK_SECRET, &[]).await,
        StatusCode::NO_CONTENT
    );
    // Another App's secret does not verify.
    assert_eq!(
        post(&w, "/github/github.com/globex/webhook", WEBHOOK_SECRET, &[]).await,
        StatusCode::UNAUTHORIZED
    );
    // An owner the config does not name: nothing there.
    assert_eq!(
        post(
            &w,
            "/github/github.com/initech/webhook",
            WEBHOOK_SECRET,
            &[]
        )
        .await,
        StatusCode::NOT_FOUND
    );
    // There is no owner-less route: every App has its own.
    assert_eq!(
        post(&w, "/github/github.com/webhook", WEBHOOK_SECRET, &[]).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn each_organisation_registers_its_own_app_with_its_own_routes() {
    let w = world(Options {
        seed_app: false,
        extra_apps: vec![],
        ..two_orgs()
    })
    .await;
    let urls = vgi_bridge::flows::offer_registrations(&w.bridge).unwrap();
    assert_eq!(urls.len(), 2, "{urls:?}");
    let globex = urls
        .iter()
        .find(|u| u.contains("/github/github.com/globex/register?state="))
        .expect("globex's own link");
    assert!(
        urls.iter()
            .any(|u| u.contains("/github/github.com/acme/register?state="))
    );
    // Offering again reuses the open links rather than minting more.
    assert_eq!(
        vgi_bridge::flows::offer_registrations(&w.bridge)
            .unwrap()
            .len(),
        2
    );

    let path = globex.split("bridge.acme.example").nth(1).unwrap();
    let (status, page) = get(&w, path).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(
        page.contains("organizations/globex/settings/apps/new"),
        "{page}"
    );
    assert!(page.contains("globex-vgi-bridge"));
    assert!(
        page.contains("github/github.com/globex/webhook"),
        "its own webhook URL"
    );
    assert!(page.contains("github/github.com/globex/setup"));
    // One organisation's link on another's route is refused.
    let state = globex.split("state=").nth(1).unwrap();
    let (status, _) = get(
        &w,
        &format!("/github/github.com/acme/register?state={state}"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A store in the single-App layout (`github/<host>/app`) is refused at
/// start, with the way out: re-register the App.
#[tokio::test]
async fn a_single_app_store_is_refused_with_re_register_guidance() {
    let w = world(Options {
        seed_app: false,
        ..Options::default()
    })
    .await;
    let store = w.bridge.store();
    let legacy = serde_json::json!({
        "appId": APP_ID, "slug": "acme-vgi-bridge", "clientId": "Iv1.testclient",
        "clientSecret": "cs", "webhookSecret": WEBHOOK_SECRET, "pem": app_pem(),
    });
    store
        .put_secret(
            &legacy_github_app_secret("github.com"),
            &serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
    let err = vgi_bridge::build_adapters(w.bridge.config(), store)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Re-register the App"), "{err}");
    // Nothing was moved or read.
    assert!(
        store
            .get_secret(&github_app_secret("github.com", "acme"))
            .unwrap()
            .is_none()
    );
}

/// A lone App serves its own owner only: GitHub installs a private App only
/// on its owner, and the bridge does not pretend otherwise.
#[tokio::test]
async fn a_lone_app_serves_only_its_own_owner() {
    let w = world(Options::default()).await;
    assert_eq!(app_id_for(&w, "acme"), Some(APP_ID));
    assert_eq!(app_id_for(&w, "initech"), None);
    let r = Resource::namespace_of("github.com", "initech").unwrap();
    assert!(
        w.bridge
            .config()
            .github_for("github.com", "initech")
            .is_none()
    );
    assert!(w.bridge.adapters().vgi_for(&r).is_none());
}

#[tokio::test]
async fn an_app_stored_for_another_owner_is_refused() {
    let w = world(Options {
        seed_app: false,
        ..Options::default()
    })
    .await;
    // globex's App filed under acme.
    let wrong = StoredApp {
        app_id: GLOBEX_APP,
        owner: "globex".into(),
        slug: "globex-vgi-bridge".into(),
        client_id: "Iv1.g".into(),
        client_secret: "cs".into(),
        webhook_secret: GLOBEX_SECRET.into(),
        pem: app_pem().into(),
    };
    w.bridge
        .store()
        .put_secret(
            &github_app_secret("github.com", "acme"),
            &serde_json::to_vec(&wrong).unwrap(),
        )
        .unwrap();
    assert!(
        vgi_bridge::build_adapters(w.bridge.config(), w.bridge.store())
            .await
            .is_err()
    );
}
