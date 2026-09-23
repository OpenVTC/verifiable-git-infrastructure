//! Webhook signature verification and translation into forge events.

mod common;

use common::*;
use http::{HeaderMap, HeaderValue};
use serde_json::{Value, json};
use vgi_forge::{Forge, ForgeError, ForgeEventKind, Resource};
use vgi_forge_forgejo::Secret;
use vgi_forge_forgejo::webhook::{HOOK_EVENTS, sign_body, verify_signature};

/// Headers as Forgejo sends them: both the Forgejo and Gitea names.
fn headers(event: &str, body: &[u8], secret: &str) -> HeaderMap {
    let sig = sign_body(&Secret::new(secret), body);
    let mut h = HeaderMap::new();
    for (name, value) in [
        ("x-forgejo-event", event),
        ("x-forgejo-delivery", "d-1"),
        ("x-forgejo-signature", &sig),
        ("x-gitea-event", event),
        ("x-gitea-delivery", "d-1"),
        ("x-gitea-signature", &sig),
    ] {
        h.insert(name, HeaderValue::from_str(value).unwrap());
    }
    h
}

fn repository(id: u64, full_name: &str) -> Value {
    json!({ "id": id, "full_name": full_name, "name": full_name.rsplit('/').next() })
}

#[test]
fn the_signature_is_bare_hex_hmac_sha256_of_the_raw_body() {
    // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
    let secret = Secret::new("Jefe");
    let body = b"what do ya want for nothing?";
    let tag = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    assert_eq!(sign_body(&secret, body), tag);
    for name in ["x-forgejo-signature", "x-gitea-signature"] {
        let mut h = HeaderMap::new();
        h.insert(name, HeaderValue::from_static(tag));
        verify_signature(&secret, &h, body).unwrap();
    }
}

#[tokio::test]
async fn unverified_deliveries_are_rejected_before_parsing() {
    let (_server, forge) = server_and_forge().await;
    let body =
        serde_json::to_vec(&json!({ "action": "deleted", "repository": repository(1, "acme/w") }))
            .unwrap();

    let wrong = headers("repository", &body, "not-the-secret");
    assert!(matches!(
        forge.parse_event(&wrong, &body),
        Err(ForgeError::Webhook(_))
    ));

    let good = headers("repository", &body, WEBHOOK_SECRET);
    let mut tampered = body.clone();
    tampered[5] ^= 1;
    assert!(matches!(
        forge.parse_event(&good, &tampered),
        Err(ForgeError::Webhook(_))
    ));

    let mut none = good.clone();
    none.remove("x-forgejo-signature");
    none.remove("x-gitea-signature");
    let e = forge.parse_event(&none, &body).unwrap_err();
    assert!(e.to_string().contains("missing X-Forgejo-Signature"), "{e}");

    let mut not_hex = good.clone();
    not_hex.insert("x-forgejo-signature", HeaderValue::from_static("zz"));
    assert!(forge.parse_event(&not_hex, &body).is_err());

    // A bad X-Forgejo-Signature is not rescued by a good X-Gitea-Signature.
    let mut mixed = good.clone();
    mixed.insert(
        "x-forgejo-signature",
        HeaderValue::from_str(&sign_body(&Secret::new("other"), &body)).unwrap(),
    );
    assert!(forge.parse_event(&mixed, &body).is_err());

    // A Gitea instance sends only the Gitea names.
    let mut gitea = good.clone();
    gitea.remove("x-forgejo-signature");
    gitea.remove("x-forgejo-event");
    gitea.remove("x-forgejo-delivery");
    let event = forge.parse_event(&gitea, &body).unwrap().unwrap();
    assert_eq!(event.delivery_id.as_deref(), Some("d-1"));
}

#[tokio::test]
async fn repository_events_become_forge_events() {
    let (_server, forge) = server_and_forge().await;
    for (action, created) in [("created", true), ("deleted", false)] {
        let body = serde_json::to_vec(&json!({
            "action": action,
            "repository": repository(812, "Acme/Widgets"),
            "organization": { "id": 100, "username": "acme" },
            "sender": { "id": 1, "login": "alice" },
        }))
        .unwrap();
        let event = forge
            .parse_event(&headers("repository", &body, WEBHOOK_SECRET), &body)
            .unwrap()
            .unwrap();
        assert_eq!(event.delivery_id.as_deref(), Some("d-1"));
        let repo = Resource::parse("codeberg.org/acme/widgets").unwrap();
        let expected = if created {
            ForgeEventKind::RepoCreated {
                repo,
                forge_id: 812,
            }
        } else {
            ForgeEventKind::RepoDeleted {
                repo,
                forge_id: 812,
            }
        };
        assert_eq!(event.kind, expected);
    }
}

#[tokio::test]
async fn other_verified_deliveries_are_ignored_and_bad_payloads_refused() {
    let (_server, forge) = server_and_forge().await;
    let push = serde_json::to_vec(&json!({ "ref": "refs/heads/main" })).unwrap();
    assert_eq!(
        forge
            .parse_event(&headers("push", &push, WEBHOOK_SECRET), &push)
            .unwrap(),
        None
    );
    let odd =
        serde_json::to_vec(&json!({ "action": "edited", "repository": repository(1, "acme/w") }))
            .unwrap();
    assert_eq!(
        forge
            .parse_event(&headers("repository", &odd, WEBHOOK_SECRET), &odd)
            .unwrap(),
        None
    );
    for bad in [
        json!({ "action": "created", "repository": { "full_name": "acme/w" } }),
        json!({ "action": "created", "repository": repository(1, "acme/evil/w") }),
        json!({ "action": "created", "repository": repository(1, "../w") }),
    ] {
        let body = serde_json::to_vec(&bad).unwrap();
        assert!(
            forge
                .parse_event(&headers("repository", &body, WEBHOOK_SECRET), &body)
                .is_err(),
            "{bad}"
        );
    }
    let not_json = b"not json";
    assert!(
        forge
            .parse_event(&headers("repository", not_json, WEBHOOK_SECRET), not_json)
            .is_err()
    );
    assert_eq!(HOOK_EVENTS, ["repository"]);
}
