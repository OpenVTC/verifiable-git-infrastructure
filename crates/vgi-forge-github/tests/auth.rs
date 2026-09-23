//! App JWT, manifest registration, namespace binding and device-flow
//! account linking, against a mock GitHub.

mod common;

use std::collections::BTreeMap;

use common::*;
use serde_json::json;
use url::Url;
use vgi_forge::{
    BindCallback, BindRequest, BindStep, Forge, ForgeError, LinkCallback, LinkStep, NamespaceKind,
    Resource,
};
use vgi_forge_github::jwt::{AppClaims, app_jwt, app_jwt_at};
use vgi_forge_github::manifest::{
    APP_EVENTS, APP_PERMISSIONS, ManifestParams, app_manifest, exchange_code, registration_url,
};
use vgi_forge_github::{GitHubForge, InProcessKey};
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, ResponseTemplate};

// ── JWT ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn app_jwt_is_rs256_backdated_and_short_lived() {
    let signer = InProcessKey::from_pem(&key().pkcs1_pem).unwrap();
    let now = 1_700_000_000;
    let jwt = app_jwt_at(&signer, CLIENT_ID, now).await.unwrap();
    let claims = verify_jwt(jwt.expose()).expect("signature verifies with the App's public key");
    assert_eq!(
        claims,
        serde_json::to_value(AppClaims::at(now, CLIENT_ID)).unwrap()
    );
    assert_eq!(claims["iat"], now - 60, "iat is backdated for clock drift");
    assert_eq!(claims["exp"], now + 540, "exp is nine minutes out");
    assert!(
        claims["exp"].as_u64().unwrap() - now <= 600,
        "GitHub caps exp at ten minutes"
    );
    assert_eq!(claims["iss"], CLIENT_ID);
}

#[tokio::test]
async fn both_pem_shapes_sign_verifiably() {
    for pem in [&key().pkcs1_pem, &key().pkcs8_pem] {
        let signer = InProcessKey::from_pem(pem).unwrap();
        let jwt = app_jwt(&signer, CLIENT_ID).await.unwrap();
        assert!(verify_jwt(jwt.expose()).is_some());
        assert_eq!(format!("{signer:?}"), "InProcessKey(<redacted>)");
        assert_eq!(format!("{jwt:?}"), "Secret(<redacted>)");
    }
}

// ── manifest ─────────────────────────────────────────────────────────────

fn params() -> ManifestParams {
    ManifestParams::new(
        "acme-vgi-bridge",
        "https://vtc.acme.example",
        "https://bridge.acme.example/webhook",
        "https://bridge.acme.example/manifest/callback",
    )
    .with_setup_url("https://bridge.acme.example/bind/callback")
}

#[test]
fn manifest_asks_for_exactly_the_reviewed_permissions() {
    let m = app_manifest(&params());
    assert_eq!(
        m["default_permissions"],
        json!({
            "administration": "write",
            "contents": "write",
            "actions_variables": "write",
            "metadata": "read",
            "members": "read",
            // §9: the org ruleset that makes verify-trust a required workflow.
            "organization_administration": "write",
            // §9: the check the bridge posts itself where there is none, and
            // the reads its trigger events need.
            "checks": "write",
            "pull_requests": "read",
            "merge_queues": "read",
        })
    );
    assert_eq!(m["public"], false);
    assert_eq!(
        m["hook_attributes"],
        json!({ "url": "https://bridge.acme.example/webhook", "active": true })
    );
    assert_eq!(
        m["redirect_url"],
        "https://bridge.acme.example/manifest/callback"
    );
    assert_eq!(
        m["callback_urls"],
        json!(["https://bridge.acme.example/manifest/callback"])
    );
    assert_eq!(m["setup_url"], "https://bridge.acme.example/bind/callback");
    assert_eq!(m["default_events"], json!(APP_EVENTS));
    for event in [
        "repository",
        "member",
        "membership",
        "organization",
        "repository_ruleset",
        "branch_protection_rule",
    ] {
        assert!(APP_EVENTS.contains(&event), "{event} feeds drift detection");
    }
    for event in ["pull_request", "merge_group", "check_run", "check_suite"] {
        assert!(
            APP_EVENTS.contains(&event),
            "{event} triggers the bridge's check"
        );
    }
    assert!(
        APP_EVENTS.is_sorted(),
        "exchange_code compares a sorted list"
    );
    assert_eq!(APP_PERMISSIONS.len(), 9, "no permission beyond §5.7's set");
}

#[test]
fn registration_url_targets_the_org_or_the_user() {
    let web = Url::parse("https://github.com").unwrap();
    assert_eq!(
        registration_url(&web, Some("acme"), "s1").as_str(),
        "https://github.com/organizations/acme/settings/apps/new?state=s1"
    );
    assert_eq!(
        registration_url(&web, None, "s1").as_str(),
        "https://github.com/settings/apps/new?state=s1"
    );
}

fn conversion(permissions: serde_json::Value) -> serde_json::Value {
    json!({
        "id": 1001,
        "slug": "acme-vgi-bridge",
        "owner": { "login": "acme" },
        "client_id": CLIENT_ID,
        "client_secret": "cs-secret-value",
        "webhook_secret": "wh-secret-value",
        "pem": key().pkcs1_pem,
        "permissions": permissions,
        "events": APP_EVENTS,
    })
}

#[tokio::test]
async fn manifest_code_exchange_returns_credentials_that_never_print() {
    let server = wiremock::MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/app-manifests/abc123/conversions"))
        // Bodyless, but it must still say so: GitHub answers 411 otherwise.
        .and(header("content-length", "0"))
        .respond_with(ResponseTemplate::new(201).set_body_json(conversion(json!({
            "administration": "write", "contents": "write", "actions_variables": "write",
            "checks": "write",
            "metadata": "read", "members": "read", "organization_administration": "write",
        }))))
        .expect(1)
        .mount(&server)
        .await;
    let base = Url::parse(&server.uri()).unwrap();
    let creds = exchange_code(&base, "abc123", "acme").await.unwrap();
    assert_eq!(creds.app_id, 1001);
    assert_eq!(creds.slug, "acme-vgi-bridge");
    assert_eq!(creds.client_id, CLIENT_ID);
    assert_eq!(creds.webhook_secret.expose(), "wh-secret-value");
    assert_eq!(creds.owner_login.as_deref(), Some("acme"));
    // The returned key is usable as the App's signer.
    InProcessKey::from_secret(&creds.pem).unwrap();

    let printed = format!("{creds:?}");
    for secret in ["cs-secret-value", "wh-secret-value", "PRIVATE KEY"] {
        assert!(
            !printed.contains(secret),
            "Debug leaked {secret}: {printed}"
        );
    }
}

#[tokio::test]
async fn manifest_exchange_refuses_an_app_with_more_than_the_reviewed_permissions() {
    let server = wiremock::MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/app-manifests/abc123/conversions"))
        .respond_with(ResponseTemplate::new(201).set_body_json(conversion(json!({
            "administration": "write", "contents": "write", "actions_variables": "write",
            "checks": "write",
            "metadata": "read", "members": "write", "secrets": "write",
            "organization_administration": "write", "organization_secrets": "write",
        }))))
        .mount(&server)
        .await;
    let base = Url::parse(&server.uri()).unwrap();
    let err = exchange_code(&base, "abc123", "acme")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("members:write")
            && err.contains("secrets:write")
            && err.contains("organization_secrets:write")
            && !err.contains("organization_administration"),
        "{err}"
    );
    assert!(
        exchange_code(&base, "../x", "acme").await.is_err(),
        "code must be alphanumeric"
    );
}

// ── bind ─────────────────────────────────────────────────────────────────

fn callback(state: &str, installation: &str, setup: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("state".to_string(), state.to_string()),
        ("installation_id".to_string(), installation.to_string()),
        ("setup_action".to_string(), setup.to_string()),
    ])
}

async fn mount_installation(server: &wiremock::MockServer, id: u64, login: &str, kind: &str) {
    Mock::given(method("GET"))
        .and(path(format!("/app/installations/{id}")))
        .and(ValidAppJwt)
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": id,
            "account": { "id": 500, "login": login, "type": kind },
            "permissions": {
                "administration": "write", "contents": "write", "actions_variables": "write",
            "checks": "write",
                "metadata": "read",
            },
            "suspended_at": null,
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn bind_sends_the_admin_to_the_install_page_with_state() {
    let (_server, forge) = server_and_forge().await;
    let state = GitHubForge::new_state().unwrap();
    assert!(state.len() >= 43);
    let BindStep::Redirect { url } = forge
        .begin_bind(BindRequest::new(
            Resource::parse("github.com/newco").unwrap(),
            state.clone(),
        ))
        .await
        .unwrap()
    else {
        panic!("expected a redirect");
    };
    assert!(
        url.contains("/apps/acme-vgi/installations/new?state="),
        "{url}"
    );
    assert!(url.ends_with(&state));

    // A short or guessable state is refused before anyone is redirected.
    assert!(
        forge
            .begin_bind(BindRequest::new(
                Resource::parse("github.com/newco").unwrap(),
                "abc"
            ))
            .await
            .is_err()
    );
    // A resource on another forge is refused.
    assert!(
        forge
            .begin_bind(BindRequest::new(
                Resource::parse("codeberg.org/newco").unwrap(),
                state
            ))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn complete_bind_records_installation_owner_and_kind() {
    let (server, forge) = server_and_forge().await;
    mount_installation(&server, 77, "NewCo", "Organization").await;
    // The bind also asks whether the org has org rulesets (§9): a token
    // with organization Administration only, and no repository.
    mount_token(
        &server,
        77,
        None,
        json!({ "organization_administration": "write" }),
        1,
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/orgs/newco/rulesets"))
        .and(InstallationToken)
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&server)
        .await;
    let state = GitHubForge::new_state().unwrap();
    let ns = Resource::parse("github.com/newco").unwrap();
    let binding = forge
        .complete_bind(BindCallback::new(
            callback(&state, "77", "install"),
            state.clone(),
            ns.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(binding.namespace.resource, ns);
    assert_eq!(binding.namespace.installation_id, Some(77));
    assert_eq!(binding.namespace.owner_id, Some(500));
    assert_eq!(binding.namespace.kind, NamespaceKind::Organization);
    // The mock installation lacks the members and org administration
    // permissions.
    // and everything the bridge-posted check needs, events included.
    assert_eq!(
        binding.missing_permissions,
        vec![
            "members:read".to_string(),
            "merge_queues:read".to_string(),
            "organization_administration:write".to_string(),
            "pull_requests:read".to_string(),
            "event:merge_group".to_string(),
            "event:pull_request".to_string(),
        ]
    );
    assert_eq!(forge.bridge_checks_ready(&ns), Some(false));
    forge.register_namespace(binding.namespace.clone()).unwrap();
    assert!(forge.capabilities(&binding.namespace).required_workflow);
    // Handed back as data for the bridge to persist, too.
    assert!(
        binding
            .capabilities
            .as_ref()
            .is_some_and(|c| c.required_workflow)
    );
}

#[tokio::test]
async fn complete_bind_rejects_wrong_state_owner_or_unapproved_installs() {
    let (server, forge) = server_and_forge().await;
    mount_installation(&server, 77, "someone-else", "User").await;
    Mock::given(method("GET"))
        .and(path("/app/installations/78"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "message": "Not Found" })))
        .mount(&server)
        .await;
    let state = GitHubForge::new_state().unwrap();
    let ns = Resource::parse("github.com/newco").unwrap();
    let bind = |params, expected: &str| {
        forge.complete_bind(BindCallback::new(params, expected.to_string(), ns.clone()))
    };

    let other = GitHubForge::new_state().unwrap();
    let e = bind(callback(&other, "77", "install"), &state)
        .await
        .unwrap_err();
    assert!(
        matches!(e, ForgeError::BindRejected(ref m) if m.contains("state")),
        "{e}"
    );

    let e = bind(callback(&state, "77", "install"), &state)
        .await
        .unwrap_err();
    assert!(
        matches!(e, ForgeError::BindRejected(ref m) if m.contains("someone-else")),
        "{e}"
    );

    let e = bind(callback(&state, "78", "install"), &state)
        .await
        .unwrap_err();
    assert!(
        matches!(e, ForgeError::BindRejected(ref m) if m.contains("not an installation")),
        "{e}"
    );

    let e = bind(callback(&state, "77", "request"), &state)
        .await
        .unwrap_err();
    assert!(
        matches!(e, ForgeError::BindRejected(ref m) if m.contains("approved")),
        "{e}"
    );

    let e = bind(callback(&state, "x", "install"), &state)
        .await
        .unwrap_err();
    assert!(matches!(e, ForgeError::BindRejected(_)), "{e}");
}

// ── device flow ──────────────────────────────────────────────────────────

async fn mount_device_code(server: &wiremock::MockServer) {
    Mock::given(method("POST"))
        .and(path("/login/device/code"))
        .and(header("accept", "application/json"))
        .and(body_json(json!({ "client_id": CLIENT_ID })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "device_code": "dev-code-1",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://github.com/login/device",
            "expires_in": 900,
            "interval": 5,
        })))
        .expect(1)
        .mount(server)
        .await;
}

fn poll_reply(body: serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(body)
}

#[tokio::test]
async fn device_flow_polls_through_pending_and_slow_down_then_reads_the_user() {
    let (server, forge) = server_and_forge().await;
    mount_device_code(&server).await;
    let token_path = || path("/login/oauth/access_token");
    let grant = || {
        body_json(json!({
            "client_id": CLIENT_ID,
            "device_code": "dev-code-1",
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        }))
    };
    // Wiremock answers with the first matching mock that still has uses
    // left, so these play in order.
    Mock::given(method("POST"))
        .and(token_path())
        .and(grant())
        .respond_with(poll_reply(json!({ "error": "authorization_pending" })))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(token_path())
        .and(grant())
        .respond_with(poll_reply(json!({ "error": "slow_down", "interval": 10 })))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(token_path())
        .and(grant())
        .respond_with(poll_reply(
            json!({ "access_token": "ghu_user_token", "token_type": "bearer" }),
        ))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/user"))
        .and(header("authorization", "Bearer ghu_user_token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "id": 583231, "login": "Octocat" })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let step = forge.begin_account_link("did:webvh:alice").await.unwrap();
    let LinkStep::DeviceCode {
        user_code,
        verification_uri,
        ..
    } = &step
    else {
        panic!("expected a device code");
    };
    assert_eq!(user_code, "WDJB-MJHT");
    assert_eq!(verification_uri, "https://github.com/login/device");

    let account = forge
        .complete_account_link(LinkCallback::from_device_step(&step).unwrap())
        .await
        .unwrap();
    assert_eq!(account.id, 583231);
    assert_eq!(account.login, "Octocat");
}

#[tokio::test]
async fn device_flow_stops_on_expiry_denial_or_deadline() {
    let (server, forge) = server_and_forge().await;
    let cb = |expires_in| LinkCallback::DeviceCode {
        device_code: "dev-code-1".into(),
        interval: 5,
        expires_in,
    };

    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .respond_with(poll_reply(json!({ "error": "expired_token" })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    let e = forge.complete_account_link(cb(900)).await.unwrap_err();
    assert!(
        matches!(e, ForgeError::LinkFailed(ref m) if m.contains("expired")),
        "{e}"
    );

    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .respond_with(poll_reply(json!({ "error": "access_denied" })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    let e = forge.complete_account_link(cb(900)).await.unwrap_err();
    assert!(
        matches!(e, ForgeError::LinkFailed(ref m) if m.contains("declined")),
        "{e}"
    );

    // Pending forever: the local deadline (expires_in) ends it.
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .respond_with(poll_reply(json!({ "error": "authorization_pending" })))
        .mount(&server)
        .await;
    let e = forge.complete_account_link(cb(12)).await.unwrap_err();
    assert!(
        matches!(e, ForgeError::LinkFailed(ref m) if m.contains("expired")),
        "{e}"
    );
}

// ── review follow-ups ────────────────────────────────────────────────────

fn good_permissions() -> serde_json::Value {
    json!({
        "administration": "write", "contents": "write", "actions_variables": "write",
        "checks": "write", "pull_requests": "read", "merge_queues": "read",
        "metadata": "read", "members": "read", "organization_administration": "write",
    })
}

async fn exchange_with(
    reply: serde_json::Value,
    expected_owner: &str,
) -> vgi_forge::Result<String> {
    let server = wiremock::MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/app-manifests/abc123/conversions"))
        .respond_with(ResponseTemplate::new(201).set_body_json(reply))
        .mount(&server)
        .await;
    let base = Url::parse(&server.uri()).unwrap();
    exchange_code(&base, "abc123", expected_owner)
        .await
        .map(|c| c.slug)
}

#[tokio::test]
async fn manifest_exchange_checks_owner_events_visibility_and_requires_permissions() {
    assert!(
        exchange_with(conversion(good_permissions()), "ACME")
            .await
            .is_ok()
    );

    let e = exchange_with(conversion(good_permissions()), "newco")
        .await
        .unwrap_err();
    assert!(
        e.to_string()
            .contains("registered under `acme`, not `newco`"),
        "{e}"
    );

    let mut no_perms = conversion(good_permissions());
    no_perms.as_object_mut().unwrap().remove("permissions");
    assert!(
        exchange_with(no_perms, "acme").await.is_err(),
        "absent permissions fail closed"
    );

    let mut no_owner = conversion(good_permissions());
    no_owner.as_object_mut().unwrap().remove("owner");
    assert!(exchange_with(no_owner, "acme").await.is_err());

    let mut fewer_events = conversion(good_permissions());
    fewer_events["events"] = json!(["repository"]);
    let e = exchange_with(fewer_events, "acme").await.unwrap_err();
    assert!(e.to_string().contains("events"), "{e}");

    let mut public = conversion(good_permissions());
    public["public"] = json!(true);
    let e = exchange_with(public, "acme").await.unwrap_err();
    assert!(e.to_string().contains("public"), "{e}");
}

#[tokio::test]
async fn jwt_issuer_can_be_the_numeric_app_id() {
    let server = wiremock::MockServer::start().await;
    let forge = forge_with(&server, |cfg| cfg.with_app_id_issuer());
    Mock::given(method("GET"))
        .and(path("/app/installations/77"))
        .and(ValidAppJwtFor("1001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 77,
            "account": { "id": 500, "login": "newco", "type": "Organization" },
            "permissions": good_permissions(),
            "events": APP_EVENTS,
        })))
        .expect(1)
        .mount(&server)
        .await;
    let state = GitHubForge::new_state().unwrap();
    let ns = Resource::parse("github.com/newco").unwrap();
    let binding = forge
        .complete_bind(BindCallback::new(
            callback(&state, "77", "install"),
            state.clone(),
            ns,
        ))
        .await
        .unwrap();
    assert!(binding.missing_permissions.is_empty());
}

#[tokio::test]
async fn device_code_never_prints_and_the_user_token_is_revoked() {
    let server = wiremock::MockServer::start().await;
    let forge = forge_for(&server).with_client_secret(vgi_forge_github::Secret::new("cs-secret"));
    mount_device_code(&server).await;
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .respond_with(poll_reply(
            json!({ "access_token": "ghu_user_token", "token_type": "bearer" }),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 7, "login": "bob" })))
        .mount(&server)
        .await;
    use base64::Engine;
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("{CLIENT_ID}:cs-secret"));
    Mock::given(method("DELETE"))
        .and(path(format!("/applications/{CLIENT_ID}/token")))
        .and(header("authorization", format!("Basic {basic}").as_str()))
        .and(body_json(json!({ "access_token": "ghu_user_token" })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let step = forge.begin_account_link("did:webvh:bob").await.unwrap();
    let cb = LinkCallback::from_device_step(&step).unwrap();
    for printed in [format!("{step:?}"), format!("{cb:?}")] {
        assert!(!printed.contains("dev-code-1"), "{printed}");
        assert!(printed.contains("<redacted>"), "{printed}");
    }
    let account = forge.complete_account_link(cb).await.unwrap();
    assert_eq!(account.id, 7);
}

#[tokio::test]
async fn a_caller_cannot_stretch_polling_past_the_device_code_lifetime() {
    let (server, forge) = server_and_forge().await;
    // 900 s / 5 s per poll: at most 180 polls, however long the caller asks.
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .respond_with(poll_reply(json!({ "error": "authorization_pending" })))
        .expect(1..=180)
        .mount(&server)
        .await;
    let e = forge
        .complete_account_link(LinkCallback::DeviceCode {
            device_code: "dev-code-1".into(),
            interval: 5,
            expires_in: u64::MAX,
        })
        .await
        .unwrap_err();
    assert!(
        matches!(e, ForgeError::LinkFailed(ref m) if m.contains("expired")),
        "{e}"
    );
}

#[tokio::test]
async fn a_member_bound_redirect_link_is_refused_by_the_device_flow_adapter() {
    let (server, forge) = server_and_forge().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    // GitHub links through the device flow; a redirect callback (which now
    // names the member it was started for) is not something it issues.
    let cb = LinkCallback::redirect(
        BTreeMap::from([("code".to_string(), "abc".to_string())]),
        "did:webvh:member.example",
    );
    let e = forge.complete_account_link(cb).await.unwrap_err();
    assert!(matches!(e, ForgeError::Unsupported { .. }), "{e:?}");
}
