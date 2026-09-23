//! What the bridge's Dependabot re-sign needs from GitHub (§9): verified
//! `push` deliveries for its provenance ledger, who opened a pull request
//! and where its head is, and a push token for one repository.

mod common;

use common::*;
use http::HeaderMap;
use serde_json::json;
use vgi_forge_github::manifest::{APP_EVENTS, RESIGN_EVENTS};
use vgi_forge_github::resign::ZERO_SHA;
use vgi_forge_github::{Secret, webhook};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const AFTER: &str = "1111111111111111111111111111111111111111";
const BASE: &str = "2222222222222222222222222222222222222222";

fn signed(event: &str, body: &serde_json::Value, secret: &str) -> (HeaderMap, Vec<u8>) {
    let body = serde_json::to_vec(body).unwrap();
    let mut h = HeaderMap::new();
    h.insert("x-github-event", event.parse().unwrap());
    h.insert("x-github-delivery", "d-9".parse().unwrap());
    h.insert(
        "x-hub-signature-256",
        webhook::sign_body(&Secret::new(secret), &body)
            .parse()
            .unwrap(),
    );
    (h, body)
}

/// The shape of GitHub's `push` payload for a new branch (as in GitHub's
/// published examples: `before` all zeros, `created: true`), sent by
/// Dependabot.
fn created_by_dependabot() -> serde_json::Value {
    json!({
        "ref": "refs/heads/dependabot/cargo/serde-1.0.200",
        "before": ZERO_SHA,
        "after": AFTER,
        "created": true, "deleted": false, "forced": false,
        "base_ref": null,
        "repository": { "id": 812, "full_name": "Acme/Widgets" },
        "pusher": { "name": "dependabot[bot]" },
        "sender": { "login": "dependabot[bot]", "id": 49699333, "type": "Bot" },
        "commits": [],
    })
}

#[test]
fn the_app_subscribes_to_push_for_the_re_sign() {
    assert!(APP_EVENTS.contains(&"push"));
    for e in RESIGN_EVENTS {
        assert!(APP_EVENTS.contains(&e), "{e}");
    }
    assert!(APP_EVENTS.is_sorted());
}

#[tokio::test]
async fn a_verified_push_is_read_with_its_sender() {
    let server = MockServer::start().await;
    let forge = forge_for(&server);
    let (h, b) = signed("push", &created_by_dependabot(), WEBHOOK_SECRET);
    let p = forge.parse_push(&h, &b).unwrap().expect("a push");
    assert_eq!(p.repo, repo("widgets"), "lowercased, qualified");
    assert_eq!(p.repo_id, 812);
    assert_eq!(p.branch(), Some("dependabot/cargo/serde-1.0.200"));
    assert_eq!((p.before.as_str(), p.after.as_str()), (ZERO_SHA, AFTER));
    assert!(p.created && !p.deleted && !p.forced);
    assert_eq!(
        (p.sender_login.as_str(), p.sender_id),
        ("dependabot[bot]", 49699333)
    );
    assert_eq!(p.delivery_id.as_deref(), Some("d-9"));

    // Another event is not a push, but is still verified first.
    let (h, b) = signed(
        "pull_request",
        &json!({ "action": "opened" }),
        WEBHOOK_SECRET,
    );
    assert!(forge.parse_push(&h, &b).unwrap().is_none());
    let (h, b) = signed("pull_request", &json!({}), "wrong-secret");
    assert!(forge.parse_push(&h, &b).is_err());
}

#[tokio::test]
async fn a_forged_or_malformed_push_is_refused() {
    let server = MockServer::start().await;
    let forge = forge_for(&server);
    let (h, b) = signed("push", &created_by_dependabot(), "wrong-secret");
    assert!(forge.parse_push(&h, &b).is_err(), "bad signature");
    for (key, value) in [
        ("after", json!("--upload-pack=x")),
        ("before", json!("abc")),
        ("sender", json!({ "login": "dependabot[bot]" })),
        ("ref", json!("")),
    ] {
        let mut p = created_by_dependabot();
        p[key] = value;
        let (h, b) = signed("push", &p, WEBHOOK_SECRET);
        assert!(forge.parse_push(&h, &b).is_err(), "{key}");
    }
}

#[tokio::test]
async fn a_pull_request_says_who_opened_it_and_where_its_head_is() {
    let server = MockServer::start().await;
    let forge = forge_for(&server);
    mount_token(
        &server,
        INSTALLATION,
        Some("widgets"),
        json!({ "metadata": "read", "pull_requests": "read" }),
        1,
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/pulls/17"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "state": "open",
            "user": { "login": "dependabot[bot]", "id": 49699333, "type": "Bot" },
            "head": { "sha": AFTER, "ref": "dependabot/cargo/serde-1.0.200",
                      "repo": { "id": 812 } },
            "base": { "ref": "main", "sha": BASE, "repo": { "id": 812 } },
        })))
        .mount(&server)
        .await;
    let pr = forge.pull_request(&repo("widgets"), 17).await.unwrap();
    assert_eq!(pr.head_ref, "dependabot/cargo/serde-1.0.200");
    assert_eq!((pr.head_repo_id, pr.base_repo_id), (Some(812), Some(812)));
    assert_eq!(pr.author_login.as_deref(), Some("dependabot[bot]"));
    assert_eq!(pr.author_id, Some(49699333));
}

#[tokio::test]
async fn the_push_token_is_contents_write_on_one_repository() {
    let server = MockServer::start().await;
    let forge = forge_for(&server);
    // Exactly these permissions on exactly this repository.
    mount_token(
        &server,
        INSTALLATION,
        Some("widgets"),
        json!({ "contents": "write", "metadata": "read" }),
        1,
    )
    .await;
    let t = forge.contents_write_token(&repo("widgets")).await.unwrap();
    assert_eq!(t.expose(), TOKEN);
}
