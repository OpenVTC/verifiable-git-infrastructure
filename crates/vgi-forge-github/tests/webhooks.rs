//! Webhook signature verification and translation into forge events.

mod common;

use common::*;
use http::{HeaderMap, HeaderValue};
use serde_json::{Value, json};
use vgi_forge::{
    Forge, ForgeAccount, ForgeError, ForgeEventKind, InstallationChange, MemberChange, Resource,
    Visibility,
};
use vgi_forge_github::Secret;
use vgi_forge_github::webhook::{sign_body, verify_signature};

fn headers(event: &str, body: &[u8], secret: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("x-github-event", HeaderValue::from_str(event).unwrap());
    h.insert("x-github-delivery", HeaderValue::from_static("d-1"));
    h.insert(
        "x-hub-signature-256",
        HeaderValue::from_str(&sign_body(&Secret::new(secret), body)).unwrap(),
    );
    h
}

async fn parse(event: &str, payload: Value) -> vgi_forge::Result<Option<vgi_forge::ForgeEvent>> {
    let (_server, forge) = server_and_forge().await;
    let body = serde_json::to_vec(&payload).unwrap();
    forge.parse_event(&headers(event, &body, WEBHOOK_SECRET), &body)
}

fn repository(id: u64, full_name: &str) -> Value {
    json!({ "id": id, "full_name": full_name, "archived": false, "visibility": "public" })
}

#[test]
fn signature_is_hmac_sha256_over_the_raw_body() {
    // GitHub's documented example: secret "It's a Secret to Everybody",
    // payload "Hello, World!".
    let secret = Secret::new("It's a Secret to Everybody");
    let body = b"Hello, World!";
    assert_eq!(
        sign_body(&secret, body),
        "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
    );
    let mut h = HeaderMap::new();
    h.insert(
        "x-hub-signature-256",
        HeaderValue::from_static(
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
        ),
    );
    verify_signature(&secret, &h, body).unwrap();
}

#[tokio::test]
async fn unverified_deliveries_are_rejected_before_parsing() {
    let (_server, forge) = server_and_forge().await;
    let body =
        serde_json::to_vec(&json!({ "action": "deleted", "repository": repository(1, "acme/w") }))
            .unwrap();

    let wrong_secret = headers("repository", &body, "not-the-secret");
    assert!(matches!(
        forge.parse_event(&wrong_secret, &body),
        Err(ForgeError::Webhook(_))
    ));

    let good = headers("repository", &body, WEBHOOK_SECRET);
    let mut tampered = body.clone();
    tampered[5] ^= 1;
    assert!(matches!(
        forge.parse_event(&good, &tampered),
        Err(ForgeError::Webhook(_))
    ));

    let mut missing = good.clone();
    missing.remove("x-hub-signature-256");
    let e = forge.parse_event(&missing, &body).unwrap_err();
    assert!(e.to_string().contains("missing X-Hub-Signature-256"), "{e}");

    let mut sha1 = good.clone();
    sha1.insert("x-hub-signature-256", HeaderValue::from_static("sha1=abcd"));
    assert!(forge.parse_event(&sha1, &body).is_err());

    let mut not_hex = good.clone();
    not_hex.insert("x-hub-signature-256", HeaderValue::from_static("sha256=zz"));
    assert!(forge.parse_event(&not_hex, &body).is_err());

    // Garbage that is correctly signed is still refused, just later.
    let junk = b"not json";
    assert!(
        forge
            .parse_event(&headers("repository", junk, WEBHOOK_SECRET), junk)
            .is_err()
    );
}

#[tokio::test]
async fn repository_events_translate() {
    let ev = parse(
        "repository",
        json!({ "action": "created", "repository": repository(7, "Acme/New") }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(ev.delivery_id.as_deref(), Some("d-1"));
    assert_eq!(
        ev.kind,
        ForgeEventKind::RepoCreated {
            repo: repo("new"),
            forge_id: 7
        }
    );

    let ev = parse(
        "repository",
        json!({
            "action": "renamed",
            "repository": repository(7, "acme/gizmos"),
            "changes": { "repository": { "name": { "from": "Gadgets" } } },
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        ev.kind,
        ForgeEventKind::RepoRenamed {
            forge_id: 7,
            from: repo("gadgets"),
            to: repo("gizmos")
        }
    );

    let ev = parse(
        "repository",
        json!({
            "action": "transferred",
            "repository": repository(7, "newco/gadgets"),
            "changes": { "owner": { "from": { "organization": { "login": "Acme" } } } },
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        ev.kind,
        ForgeEventKind::RepoTransferred {
            forge_id: 7,
            from_namespace: Some(acme()),
            to: Resource::parse("github.com/newco/gadgets").unwrap(),
        }
    );

    let ev = parse(
        "repository",
        json!({ "action": "archived", "repository": repository(7, "acme/w") }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        ev.kind,
        ForgeEventKind::RepoArchived {
            repo: repo("w"),
            forge_id: 7,
            archived: true
        }
    );

    let ev = parse(
        "repository",
        json!({ "action": "privatized", "repository": repository(7, "acme/w") }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        ev.kind,
        ForgeEventKind::RepoVisibilityChanged {
            repo: repo("w"),
            forge_id: 7,
            visibility: Visibility::Private
        }
    );

    // A description edit is verified but not interesting.
    assert!(
        parse(
            "repository",
            json!({ "action": "edited", "repository": repository(7, "acme/w") })
        )
        .await
        .unwrap()
        .is_none()
    );
}

#[tokio::test]
async fn member_ruleset_and_installation_events_translate() {
    let ev = parse(
        "member",
        json!({
            "action": "added",
            "member": { "id": 3, "login": "mallory" },
            "repository": repository(9, "acme/w"),
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        ev.kind,
        ForgeEventKind::CollaboratorChanged {
            repo: repo("w"),
            forge_id: 9,
            account: ForgeAccount::new(3, "mallory"),
            change: MemberChange::Added,
        }
    );

    let ev = parse(
        "membership",
        json!({
            "action": "removed",
            "member": { "id": 4, "login": "dave" },
            "organization": { "login": "acme" },
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        ev.kind,
        ForgeEventKind::OrgMembershipChanged {
            namespace: acme(),
            account: ForgeAccount::new(4, "dave"),
            change: MemberChange::Removed,
        }
    );

    let ev = parse(
        "repository_ruleset",
        json!({
            "action": "edited",
            "repository_ruleset": { "id": 9, "name": "VGI commit trust" },
            "repository": repository(9, "acme/w"),
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        ev.kind,
        ForgeEventKind::ProtectionChanged {
            repo: Some(repo("w")),
            namespace: acme(),
            action: "edited".into()
        }
    );

    // An org-level ruleset has no repository.
    let ev = parse(
        "repository_ruleset",
        json!({ "action": "deleted", "organization": { "login": "acme" } }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        ev.kind,
        ForgeEventKind::ProtectionChanged {
            repo: None,
            namespace: acme(),
            action: "deleted".into()
        }
    );

    let ev = parse(
        "branch_protection_rule",
        json!({ "action": "created", "repository": repository(9, "acme/w") }),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(ev.kind, ForgeEventKind::ProtectionChanged { .. }));

    let ev = parse(
        "installation",
        json!({
            "action": "deleted",
            "installation": { "id": INSTALLATION, "account": { "id": 500, "login": "acme" } },
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        ev.kind,
        ForgeEventKind::InstallationChanged {
            namespace: acme(),
            installation_id: INSTALLATION,
            change: InstallationChange::Deleted,
        }
    );

    assert!(
        parse("ping", json!({ "zen": "Keep it logically awesome." }))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        parse("push", json!({ "ref": "refs/heads/main" }))
            .await
            .unwrap()
            .is_none()
    );
}
