//! Instance probing, namespace binding (OAuth2 + PKCE, owner check, team
//! and bot setup, webhook), account linking and bot-token rotation, against
//! a mock Forgejo.

mod common;

use std::collections::BTreeMap;

use common::*;
use serde_json::json;
use vgi_forge::{
    BindCallback, BindRequest, BindStep, Forge, ForgeError, LinkCallback, LinkStep, NamespaceKind,
};
use vgi_forge_forgejo::{
    BOT_TOKEN_SCOPES, Credentials, Flavor, ForgejoForge, MergeFallback, Secret, TOKEN_NAME_PREFIX,
};
use wiremock::matchers::{body_json, method, path};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

// ── probing ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn connect_probes_the_version_and_the_bot() {
    for (version, flavor, ff, vars) in [
        (
            "9.0.0+gitea-1.22.0",
            Flavor::Forgejo { major: 9, minor: 0 },
            true,
            true,
        ),
        (
            "7.0.4+gitea-1.21.0",
            Flavor::Forgejo { major: 7, minor: 0 },
            true,
            false,
        ),
        (
            "1.22.3",
            Flavor::Gitea {
                major: 1,
                minor: 22,
            },
            true,
            true,
        ),
        (
            "1.21.11",
            Flavor::Gitea {
                major: 1,
                minor: 21,
            },
            false,
            false,
        ),
    ] {
        let (_server, forge) = server_and_forge_at(version, MergeFallback::Fail).await;
        let info = forge.instance();
        assert_eq!(info.version, version);
        assert_eq!(info.flavor, flavor, "{version}");
        assert_eq!(info.features.fast_forward_only, ff, "{version}");
        assert_eq!(info.features.actions_variables, vars, "{version}");
        assert_eq!(forge.bot().id, BOT_ID);
    }
}

#[tokio::test]
async fn a_token_that_is_not_the_bots_is_refused() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "version": VERSION })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(user(5, "someone-else")))
        .mount(&server)
        .await;
    let e = ForgejoForge::connect(config(&server), credentials())
        .await
        .unwrap_err();
    assert!(e.to_string().contains("not the configured bot"), "{e}");

    let e = ForgejoForge::connect(
        config(&server),
        Credentials::new(Secret::new(""), Secret::new("x"), Secret::new("y")),
    )
    .await
    .unwrap_err();
    assert!(matches!(e, ForgeError::Config(_)));
}

#[tokio::test]
async fn the_signing_key_is_fetched_only_for_the_fallback_on_old_instances() {
    let server = MockServer::start().await;
    mount_probe(&server, "1.21.11").await;
    Mock::given(method("GET"))
        .and(path("/api/v1/signing-key.gpg"))
        .and(BotToken)
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nk\n-----END PGP PUBLIC KEY BLOCK-----\n",
        ))
        .expect(1)
        .mount(&server)
        .await;
    ForgejoForge::connect(
        config(&server).with_merge_fallback(MergeFallback::InstanceSigningKey),
        credentials(),
    )
    .await
    .unwrap();
    // Neither the default fallback nor a modern instance fetches it.
    ForgejoForge::connect(config(&server), credentials())
        .await
        .unwrap();
}

#[tokio::test]
async fn the_adapter_never_prints_a_secret() {
    let (_server, forge) = server_and_forge().await;
    let shown = format!("{forge:?}");
    for secret in [TOKEN, CLIENT_SECRET, WEBHOOK_SECRET] {
        assert!(!shown.contains(secret), "{shown}");
    }
}

// ── binding ──────────────────────────────────────────────────────────────

const STATE: &str = "Zm9yZ2Vqby1iaW5kLXN0YXRlLW5vbmNlLTAxMjM0NTY3";
const ADMIN_TOKEN: &str = "gto_admin_oauth_token";

async fn begin(forge: &ForgejoForge) -> BTreeMap<String, String> {
    let step = forge
        .begin_bind(BindRequest::new(acme(), STATE))
        .await
        .unwrap();
    let BindStep::Redirect { url } = step else {
        panic!("expected a redirect")
    };
    assert!(url.contains("/login/oauth/authorize?"), "{url}");
    query(&url)
}

fn callback(params: &[(&str, &str)]) -> BindCallback {
    BindCallback::new(
        params
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        STATE,
        acme(),
    )
}

async fn mount_exchange(server: &MockServer, challenge: String, redirect: &'static str) {
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .and(TokenExchange {
            code: "the-code",
            redirect_uri: redirect,
            challenge,
        })
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": ADMIN_TOKEN,
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": "gto_refresh_never_kept",
        })))
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_admin(server: &MockServer, is_owner: bool) {
    Mock::given(method("GET"))
        .and(path("/api/v1/user"))
        .and(BearerToken(ADMIN_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(user(50, "root-admin")))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/orgs/acme"))
        .and(BearerToken(ADMIN_TOKEN))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "id": ORG_ID, "name": "acme" })),
        )
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/users/root-admin/orgs/acme/permissions"))
        .and(BearerToken(ADMIN_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "is_owner": is_owner, "is_admin": is_owner, "can_write": true, "can_read": true,
            "can_create_repository": is_owner,
        })))
        .mount(server)
        .await;
}

fn team_body() -> serde_json::Value {
    json!({
        "name": "vgi-bridge",
        "description": "VGI bridge bot: creates repositories and enforces the VTC's roles and \
                        commit-trust protection. Managed by the bridge.",
        "permission": "admin",
        "can_create_org_repo": true,
        "includes_all_repositories": true,
        "units": ["repo.code", "repo.pulls", "repo.actions"],
    })
}

fn team(permission: &str, create: bool) -> serde_json::Value {
    json!({
        "id": TEAM_ID, "name": "vgi-bridge", "permission": permission,
        "can_create_org_repo": create, "includes_all_repositories": true,
    })
}

async fn mount_bot_side(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/api/v1/users/acme-vgi-bot/orgs/acme/permissions"))
        .and(BotToken)
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "is_owner": false, "is_admin": true, "can_write": true, "can_read": true,
            "can_create_repository": true,
        })))
        .mount(server)
        .await;
}

fn hook_body(with_type: bool) -> serde_json::Value {
    let mut b = json!({
        "config": { "url": HOOK_URL, "content_type": "json", "secret": WEBHOOK_SECRET },
        "events": ["repository"],
        "active": true,
    });
    if with_type {
        b["type"] = json!("forgejo");
    }
    b
}

#[tokio::test]
async fn begin_bind_sends_the_admin_to_oauth_with_pkce() {
    let (_server, forge) = server_and_forge().await;
    let q = begin(&forge).await;
    assert_eq!(q["client_id"], CLIENT_ID);
    assert_eq!(q["redirect_uri"], BIND_REDIRECT);
    assert_eq!(q["response_type"], "code");
    assert_eq!(q["state"], STATE);
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["code_challenge"].len(), 43);
    assert!(!q.contains_key("scope"), "no scope unless configured");
    // The verifier is derived, so a second start agrees with the first.
    assert_eq!(begin(&forge).await["code_challenge"], q["code_challenge"]);

    for bad in ["short", "has space in it and is long enough..."] {
        assert!(matches!(
            forge.begin_bind(BindRequest::new(acme(), bad)).await,
            Err(ForgeError::Config(_))
        ));
    }
    assert!(matches!(
        forge.begin_bind(BindRequest::new(repo("w"), STATE)).await,
        Err(ForgeError::WrongResource { .. })
    ));
    let github = vgi_forge::Resource::parse("github.com/acme").unwrap();
    assert!(
        forge
            .begin_bind(BindRequest::new(github, STATE))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn bind_an_org_sets_up_the_team_bot_and_webhook() {
    let (server, forge) = server_and_forge().await;
    let q = begin(&forge).await;
    mount_exchange(&server, q["code_challenge"].clone(), BIND_REDIRECT).await;
    mount_admin(&server, true).await;
    Mock::given(method("GET"))
        .and(path("/api/v1/orgs/acme/teams"))
        .and(BearerToken(ADMIN_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "id": 1, "name": "Owners", "permission": "owner",
              "can_create_org_repo": true, "includes_all_repositories": true }
        ])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/orgs/acme/teams"))
        .and(BearerToken(ADMIN_TOKEN))
        .and(body_json(team_body()))
        .respond_with(ResponseTemplate::new(201).set_body_json(team("admin", true)))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/teams/7/members/acme-vgi-bot"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "message": "nope" })))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/v1/teams/7/members/acme-vgi-bot"))
        .and(BearerToken(ADMIN_TOKEN))
        .and(EmptyBody)
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    mount_bot_side(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/v1/orgs/acme/hooks"))
        .and(BearerToken(ADMIN_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/orgs/acme/hooks"))
        .and(BearerToken(ADMIN_TOKEN))
        .and(body_json(hook_body(true)))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 3 })))
        .expect(1)
        .mount(&server)
        .await;

    let binding = forge
        .complete_bind(callback(&[("code", "the-code"), ("state", STATE)]))
        .await
        .unwrap();
    assert_eq!(binding.namespace.resource, acme());
    assert_eq!(binding.namespace.kind, NamespaceKind::Organization);
    assert_eq!(binding.namespace.owner_id, Some(ORG_ID));
    assert_eq!(binding.namespace.installation_id, Some(TEAM_ID));
    assert!(binding.missing_permissions.is_empty());
}

#[tokio::test]
async fn a_rebind_is_idempotent_and_repairs_the_team_and_hook() {
    let (server, forge) = server_and_forge().await;
    let q = begin(&forge).await;
    mount_exchange(&server, q["code_challenge"].clone(), BIND_REDIRECT).await;
    mount_admin(&server, true).await;
    // The team exists but was weakened: it is edited back, not duplicated.
    Mock::given(method("GET"))
        .and(path("/api/v1/orgs/acme/teams"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([team("write", false)])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/orgs/acme/teams"))
        .respond_with(ResponseTemplate::new(201))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/teams/7"))
        .and(body_json(team_body()))
        .respond_with(ResponseTemplate::new(200).set_body_json(team("admin", true)))
        .expect(1)
        .mount(&server)
        .await;
    // The bot is already in it.
    Mock::given(method("GET"))
        .and(path("/api/v1/teams/7/members/acme-vgi-bot"))
        .respond_with(ResponseTemplate::new(200).set_body_json(user(BOT_ID, BOT)))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/v1/teams/7/members/acme-vgi-bot"))
        .respond_with(ResponseTemplate::new(204))
        .expect(0)
        .mount(&server)
        .await;
    mount_bot_side(&server).await;
    // The hook exists: rewritten in place (its secret cannot be read back).
    Mock::given(method("GET"))
        .and(path("/api/v1/orgs/acme/hooks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "id": 12, "type": "forgejo", "config": { "url": "https://elsewhere/x" } },
            { "id": 13, "type": "forgejo", "config": { "url": HOOK_URL, "content_type": "json" } }
        ])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/orgs/acme/hooks"))
        .respond_with(ResponseTemplate::new(201))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/orgs/acme/hooks/13"))
        .and(body_json(hook_body(false)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 13 })))
        .expect(1)
        .mount(&server)
        .await;

    forge
        .complete_bind(callback(&[("code", "the-code"), ("state", STATE)]))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_non_owner_cannot_bind() {
    let (server, forge) = server_and_forge().await;
    let q = begin(&forge).await;
    mount_exchange(&server, q["code_challenge"].clone(), BIND_REDIRECT).await;
    mount_admin(&server, false).await;
    for m in ["GET", "POST", "PUT", "PATCH"] {
        Mock::given(method(m))
            .and(path("/api/v1/orgs/acme/teams"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
    }
    let e = forge
        .complete_bind(callback(&[("code", "the-code"), ("state", STATE)]))
        .await
        .unwrap_err();
    assert!(
        matches!(&e, ForgeError::BindRejected(m) if m.contains("not an owner of `acme`")),
        "{e}"
    );
}

#[tokio::test]
async fn a_bad_state_or_a_denial_never_reaches_the_token_endpoint() {
    let (server, forge) = server_and_forge().await;
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    for params in [
        vec![
            ("code", "the-code"),
            ("state", "Zm9yZ2Vqby1iaW5kLXN0YXRlLW5vbmNlLTAxMjM0NTY4"),
        ],
        vec![("code", "the-code")],
        vec![("error", "access_denied"), ("state", STATE)],
        vec![("state", STATE)],
    ] {
        let e = forge.complete_bind(callback(&params)).await.unwrap_err();
        assert!(matches!(e, ForgeError::BindRejected(_)), "{params:?}: {e}");
    }
    // A namespace on another forge is refused even with the right state.
    let cb = BindCallback::new(
        [("code", "c"), ("state", STATE)]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        STATE,
        vgi_forge::Resource::parse("github.com/acme").unwrap(),
    );
    assert!(matches!(
        forge.complete_bind(cb).await,
        Err(ForgeError::BindRejected(_))
    ));
}

#[tokio::test]
async fn a_refused_code_is_a_bind_rejection() {
    let (server, forge) = server_and_forge().await;
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant", "error_description": "code expired"
        })))
        .mount(&server)
        .await;
    let e = forge
        .complete_bind(callback(&[("code", "old"), ("state", STATE)]))
        .await
        .unwrap_err();
    assert!(
        matches!(&e, ForgeError::BindRejected(m) if m.contains("invalid_grant")),
        "{e}"
    );
}

#[tokio::test]
async fn a_personal_namespace_is_bound_by_its_holder_only() {
    let (server, forge) = server_and_forge().await;
    let state = "cGVyc29uYWwtbmFtZXNwYWNlLWJpbmQtc3RhdGUtMDE";
    let step = forge
        .begin_bind(BindRequest::new(alice_ns(), state))
        .await
        .unwrap();
    let BindStep::Redirect { url } = step else {
        panic!()
    };
    mount_exchange(
        &server,
        query(&url)["code_challenge"].clone(),
        BIND_REDIRECT,
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/user"))
        .and(BearerToken(ADMIN_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(user(ALICE_ID, "Alice")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/orgs/alice"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "message": "" })))
        .mount(&server)
        .await;
    let params = [("code", "the-code"), ("state", state)]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let binding = forge
        .complete_bind(BindCallback::new(params, state, alice_ns()))
        .await
        .unwrap();
    assert_eq!(binding.namespace.kind, NamespaceKind::User);
    assert_eq!(binding.namespace.owner_id, Some(ALICE_ID));
    assert_eq!(binding.namespace.installation_id, Some(BOT_ID));
    let caps = forge.capabilities(&binding.namespace);
    assert!(caps.automation && !caps.bot_can_create_repos);
}

#[tokio::test]
async fn the_bot_cannot_bind_on_its_own() {
    let (server, forge) = server_and_forge().await;
    let q = begin(&forge).await;
    mount_exchange(&server, q["code_challenge"].clone(), BIND_REDIRECT).await;
    Mock::given(method("GET"))
        .and(path("/api/v1/user"))
        .and(BearerToken(ADMIN_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(user(BOT_ID, BOT)))
        .mount(&server)
        .await;
    let e = forge
        .complete_bind(callback(&[("code", "the-code"), ("state", STATE)]))
        .await
        .unwrap_err();
    assert!(matches!(e, ForgeError::BindRejected(_)), "{e}");
}

#[tokio::test]
async fn a_disabled_webhook_is_reported_not_fatal() {
    let (server, forge) = server_and_forge().await;
    let q = begin(&forge).await;
    mount_exchange(&server, q["code_challenge"].clone(), BIND_REDIRECT).await;
    mount_admin(&server, true).await;
    Mock::given(method("GET"))
        .and(path("/api/v1/orgs/acme/teams"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([team("admin", true)])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/teams/7/members/acme-vgi-bot"))
        .respond_with(ResponseTemplate::new(200).set_body_json(user(BOT_ID, BOT)))
        .mount(&server)
        .await;
    mount_bot_side(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/v1/orgs/acme/hooks"))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(json!({ "message": "webhooks disabled" })),
        )
        .mount(&server)
        .await;
    let binding = forge
        .complete_bind(callback(&[("code", "the-code"), ("state", STATE)]))
        .await
        .unwrap();
    assert_eq!(binding.missing_permissions.len(), 1);
    assert!(binding.missing_permissions[0].contains("org webhook"));
}

// ── account link ─────────────────────────────────────────────────────────

const MEMBER_TOKEN: &str = "gto_member_oauth_token";

#[tokio::test]
async fn members_link_through_the_browser_with_pkce() {
    let (server, forge) = server_and_forge().await;
    let step = forge.begin_account_link("did:example:alice").await.unwrap();
    let LinkStep::Redirect { url } = step else {
        panic!("Forgejo has no device flow")
    };
    let q = query(&url);
    assert_eq!(q["redirect_uri"], LINK_REDIRECT);
    assert_eq!(q["code_challenge_method"], "S256");
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .and(TokenExchange {
            code: "member-code",
            redirect_uri: LINK_REDIRECT,
            challenge: q["code_challenge"].clone(),
        })
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "access_token": MEMBER_TOKEN })),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/user"))
        .and(BearerToken(MEMBER_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(user(ALICE_ID, "alice")))
        .expect(1)
        .mount(&server)
        .await;

    let params: BTreeMap<_, _> = [
        ("code".to_string(), "member-code".to_string()),
        ("state".to_string(), q["state"].clone()),
    ]
    .into();
    let account = forge
        .complete_account_link(LinkCallback::Redirect { params })
        .await
        .unwrap();
    assert_eq!(account.id, ALICE_ID);
    assert_eq!(account.login, "alice");
}

#[tokio::test]
async fn a_link_with_a_forged_state_or_a_device_code_is_refused() {
    let (server, forge) = server_and_forge().await;
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    for state in ["", "bm90LWEtc3RhdGUtdGhpcy1icmlkZ2UtaXNzdWVk"] {
        let params: BTreeMap<_, _> = [
            ("code".to_string(), "c".to_string()),
            ("state".to_string(), state.to_string()),
        ]
        .into();
        assert!(matches!(
            forge
                .complete_account_link(LinkCallback::Redirect { params })
                .await,
            Err(ForgeError::LinkFailed(_))
        ));
    }
    let LinkStep::Redirect { url } = forge.begin_account_link("did:x").await.unwrap() else {
        panic!()
    };
    let params: BTreeMap<_, _> = [
        ("error".to_string(), "access_denied".to_string()),
        ("state".to_string(), query(&url)["state"].clone()),
    ]
    .into();
    assert!(matches!(
        forge
            .complete_account_link(LinkCallback::Redirect { params })
            .await,
        Err(ForgeError::LinkFailed(_))
    ));
    let device = LinkCallback::DeviceCode {
        device_code: "d".into(),
        interval: 5,
        expires_in: 900,
    };
    assert!(matches!(
        forge.complete_account_link(device).await,
        Err(ForgeError::Unsupported { .. })
    ));
}

// ── token rotation ───────────────────────────────────────────────────────

const NEW_TOKEN: &str = "new-token-1111111111111111111111111111wxyz";

/// The token request body, exactly: a `vgi-bridge-` name and the three
/// scopes, nothing else.
struct NewTokenRequest;

impl Match for NewTokenRequest {
    fn matches(&self, req: &Request) -> bool {
        let Ok(body) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
            return false;
        };
        let Some(obj) = body.as_object() else {
            return false;
        };
        let mut keys: Vec<_> = obj.keys().map(String::as_str).collect();
        keys.sort();
        keys == ["name", "scopes"]
            && obj["name"]
                .as_str()
                .is_some_and(|n| n.starts_with(TOKEN_NAME_PREFIX))
            && obj["scopes"] == json!(BOT_TOKEN_SCOPES)
    }
}

async fn rotating_forge() -> (MockServer, ForgejoForge) {
    let server = MockServer::start().await;
    mount_probe(&server, VERSION).await;
    let forge = ForgejoForge::connect(
        config(&server),
        credentials().with_bot_password(Secret::new(BOT_PASSWORD)),
    )
    .await
    .unwrap();
    register(&forge);
    (server, forge)
}

#[tokio::test]
async fn rotation_mints_verifies_swaps_and_cleans_up() {
    let (server, forge) = rotating_forge().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/users/acme-vgi-bot/tokens"))
        .and(BotBasic)
        .and(NewTokenRequest)
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": 44, "name": "vgi-bridge-new", "sha1": NEW_TOKEN, "token_last_eight": "1111wxyz",
            "scopes": BOT_TOKEN_SCOPES,
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/user"))
        .and(TokenOf(NEW_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(user(BOT_ID, BOT)))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/users/acme-vgi-bot/tokens"))
        .and(BotBasic)
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-total-count", "4")
                .set_body_json(json!([
                    { "id": 40, "name": "setup", "token_last_eight": "0000abcd" },
                    { "id": 41, "name": "vgi-bridge-1700000000-aa", "token_last_eight": "zzzzzzzz" },
                    { "id": 42, "name": "someone's laptop", "token_last_eight": "yyyyyyyy" },
                    { "id": 44, "name": "vgi-bridge-new", "token_last_eight": "1111wxyz" },
                ])),
        )
        .mount(&server)
        .await;
    for id in [40, 41] {
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/users/acme-vgi-bot/tokens/{id}")))
            .and(BotBasic)
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
    }
    for id in [42, 44] {
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/users/acme-vgi-bot/tokens/{id}")))
            .respond_with(ResponseTemplate::new(204))
            .expect(0)
            .mount(&server)
            .await;
    }
    let report = forge.rotate_token().await.unwrap();
    assert!(report.new_token.starts_with(TOKEN_NAME_PREFIX));
    assert_eq!(report.deleted, ["setup", "vgi-bridge-1700000000-aa"]);

    // Later requests carry the new token.
    Mock::given(method("GET"))
        .and(path("/api/v1/version"))
        .and(TokenOf(NEW_TOKEN))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "version": "10.0.0+gitea-1.22.0" })),
        )
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        forge.refresh().await.unwrap().version,
        "10.0.0+gitea-1.22.0"
    );
}

/// `Authorization: token <t>`.
struct TokenOf(&'static str);

impl Match for TokenOf {
    fn matches(&self, req: &Request) -> bool {
        req.headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            == Some(&format!("token {}", self.0))
    }
}

#[tokio::test]
async fn a_new_token_that_fails_verification_is_deleted_and_the_old_one_kept() {
    let (server, forge) = rotating_forge().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/users/acme-vgi-bot/tokens"))
        .and(BotBasic)
        .and(NewTokenRequest)
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": 44, "name": "vgi-bridge-new", "sha1": NEW_TOKEN,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/user"))
        .and(TokenOf(NEW_TOKEN))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({ "message": "bad" })))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/users/acme-vgi-bot/tokens/44"))
        .and(BotBasic)
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    assert!(matches!(
        forge.rotate_token().await,
        Err(ForgeError::Unauthorized(_))
    ));
    // Still the old token.
    forge.refresh().await.unwrap();
}

#[tokio::test]
async fn manual_rotation_verifies_the_replacement() {
    let (server, forge) = server_and_forge().await;
    let e = forge.rotate_token().await.unwrap_err();
    assert!(
        matches!(&e, ForgeError::Unsupported { hint, .. } if hint.contains("replace_token")),
        "{e}"
    );
    Mock::given(method("GET"))
        .and(path("/api/v1/user"))
        .and(TokenOf("not-the-bots"))
        .respond_with(ResponseTemplate::new(200).set_body_json(user(5, "mallory")))
        .mount(&server)
        .await;
    assert!(
        forge
            .replace_token(Secret::new("not-the-bots"))
            .await
            .is_err()
    );
    Mock::given(method("GET"))
        .and(path("/api/v1/user"))
        .and(TokenOf(NEW_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(user(BOT_ID, BOT)))
        .mount(&server)
        .await;
    forge.replace_token(Secret::new(NEW_TOKEN)).await.unwrap();
    Mock::given(method("GET"))
        .and(path("/api/v1/version"))
        .and(TokenOf(NEW_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "version": VERSION })))
        .expect(1)
        .mount(&server)
        .await;
    forge.refresh().await.unwrap();
}

#[test]
fn scopes_are_the_reviewed_three() {
    assert_eq!(
        BOT_TOKEN_SCOPES,
        ["write:organization", "write:repository", "read:user"]
    );
}
