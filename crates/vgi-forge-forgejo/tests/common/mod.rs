//! Shared fixtures: a mock Forgejo, the adapter pointed at it, and matchers
//! for the credentials each request must carry.

#![allow(dead_code)]

use serde_json::{Value, json};
use url::Url;
use vgi_forge::{Namespace, NamespaceKind, Resource};
use vgi_forge_forgejo::{Credentials, ForgejoConfig, ForgejoForge, MergeFallback, Secret};
use wiremock::matchers::{method, path};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

pub const HOST: &str = "codeberg.org";
pub const VERSION: &str = "9.0.0+gitea-1.22.0";
pub const BOT: &str = "acme-vgi-bot";
pub const BOT_ID: u64 = 900;
pub const TOKEN: &str = "bot-token-0000000000000000000000000000abcd";
pub const CLIENT_ID: &str = "5f0c1d2e-client";
pub const CLIENT_SECRET: &str = "gto_client_secret";
pub const WEBHOOK_SECRET: &str = "whsec-test";
pub const BOT_PASSWORD: &str = "bot-password";
pub const ORG_ID: u64 = 100;
pub const TEAM_ID: u64 = 7;
pub const ALICE_ID: u64 = 1;

pub const BIND_REDIRECT: &str = "https://bridge.acme.example/bind/callback";
pub const LINK_REDIRECT: &str = "https://bridge.acme.example/link/callback";
pub const HOOK_URL: &str = "https://bridge.acme.example/webhook";

/// Matches requests authenticated as the bot (`Authorization: token …`).
pub struct BotToken;

impl Match for BotToken {
    fn matches(&self, req: &Request) -> bool {
        auth(req) == Some(format!("token {TOKEN}"))
    }
}

/// Matches `Authorization: Bearer <token>` (an OAuth token).
pub struct BearerToken(pub &'static str);

impl Match for BearerToken {
    fn matches(&self, req: &Request) -> bool {
        auth(req) == Some(format!("Bearer {}", self.0))
    }
}

/// Matches the bot's basic auth.
pub struct BotBasic;

impl Match for BotBasic {
    fn matches(&self, req: &Request) -> bool {
        use base64::Engine;
        let expected =
            base64::engine::general_purpose::STANDARD.encode(format!("{BOT}:{BOT_PASSWORD}"));
        auth(req) == Some(format!("Basic {expected}"))
    }
}

/// Matches a bodyless write that still says `Content-Length: 0`.
pub struct EmptyBody;

impl Match for EmptyBody {
    fn matches(&self, req: &Request) -> bool {
        req.body.is_empty()
            && req
                .headers
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                == Some("0")
    }
}

fn auth(req: &Request) -> Option<String> {
    req.headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

pub fn acme() -> Resource {
    Resource::parse("codeberg.org/acme").unwrap()
}

pub fn repo(name: &str) -> Resource {
    acme().join(name).unwrap()
}

pub fn alice_ns() -> Resource {
    Resource::parse("codeberg.org/alice").unwrap()
}

pub fn config(server: &MockServer) -> ForgejoConfig {
    ForgejoConfig::new(
        Url::parse(&server.uri()).unwrap(),
        BOT,
        CLIENT_ID,
        Url::parse(BIND_REDIRECT).unwrap(),
        Url::parse(LINK_REDIRECT).unwrap(),
    )
    .unwrap()
    .with_host(HOST)
    .with_webhook_url(Url::parse(HOOK_URL).unwrap())
}

pub fn credentials() -> Credentials {
    Credentials::new(
        Secret::new(TOKEN),
        Secret::new(CLIENT_SECRET),
        Secret::new(WEBHOOK_SECRET),
    )
}

/// `GET /version` and the bot's `GET /user`, as `connect` makes them.
pub async fn mount_probe(server: &MockServer, version: &str) {
    Mock::given(method("GET"))
        .and(path("/api/v1/version"))
        .and(BotToken)
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "version": version })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/user"))
        .and(BotToken)
        .respond_with(ResponseTemplate::new(200).set_body_json(user(BOT_ID, BOT)))
        .mount(server)
        .await;
}

pub fn register(forge: &ForgejoForge) {
    forge
        .register_namespace(
            Namespace::new(acme(), NamespaceKind::Organization)
                .with_owner_id(ORG_ID)
                .with_installation(TEAM_ID),
        )
        .unwrap();
    forge
        .register_namespace(
            Namespace::new(alice_ns(), NamespaceKind::User)
                .with_owner_id(ALICE_ID)
                .with_installation(BOT_ID),
        )
        .unwrap();
}

/// A mock Forgejo at [`VERSION`] and an adapter connected to it, with
/// `codeberg.org/acme` (org) and `codeberg.org/alice` (personal) bound.
pub async fn server_and_forge() -> (MockServer, ForgejoForge) {
    server_and_forge_at(VERSION, MergeFallback::Fail).await
}

pub async fn server_and_forge_at(
    version: &str,
    fallback: MergeFallback,
) -> (MockServer, ForgejoForge) {
    let server = MockServer::start().await;
    mount_probe(&server, version).await;
    let forge = ForgejoForge::connect(config(&server).with_merge_fallback(fallback), credentials())
        .await
        .unwrap();
    register(&forge);
    (server, forge)
}

pub fn user(id: u64, login: &str) -> Value {
    json!({ "id": id, "login": login, "full_name": "", "email": "" })
}

/// A repository as Forgejo returns it, fast-forward only and Actions on.
pub fn repo_json(id: u64, full_name: &str, archived: bool) -> Value {
    json!({
        "id": id,
        "full_name": full_name,
        "name": full_name.rsplit('/').next().unwrap(),
        "private": false,
        "archived": archived,
        "empty": false,
        "default_branch": "main",
        "has_pull_requests": true,
        "has_actions": true,
        "allow_fast_forward_only_merge": true,
        "allow_merge_commits": false,
        "allow_rebase": false,
        "allow_rebase_explicit": false,
        "allow_squash_merge": false,
        "default_merge_style": "fast-forward-only",
    })
}

pub const CONTEXT: &str = "Verify commit trust / Verify commit trust (pull_request)";

/// The protection rule the bootstrap writes, with `mergers` on the
/// allow-list.
pub fn good_rule(mergers: &[&str]) -> Value {
    json!({
        "rule_name": "main",
        "branch_name": "main",
        "enable_push": false,
        "enable_push_whitelist": false,
        "push_whitelist_usernames": null,
        "push_whitelist_teams": null,
        "push_whitelist_deploy_keys": false,
        "enable_merge_whitelist": true,
        "merge_whitelist_usernames": mergers,
        "merge_whitelist_teams": null,
        "enable_status_check": true,
        "status_check_contexts": [CONTEXT],
        "protected_file_patterns":
            ".forgejo/workflows/**;.gitea/workflows/**;.github/workflows/**;.forgejo/trusted-platform-keys.asc",
        "unprotected_file_patterns": "",
        "apply_to_admins": true,
        "require_signed_commits": false,
    })
}

/// Matches the OAuth token exchange exactly: a form with precisely these
/// fields, the client's own credentials, and a `code_verifier` whose S256
/// hash is `challenge` (taken from the authorize URL the adapter built).
pub struct TokenExchange {
    pub code: &'static str,
    pub redirect_uri: &'static str,
    pub challenge: String,
}

impl Match for TokenExchange {
    fn matches(&self, req: &Request) -> bool {
        use base64::Engine;
        if req
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            != Some("application/x-www-form-urlencoded")
        {
            return false;
        }
        let form: std::collections::BTreeMap<String, String> =
            url::form_urlencoded::parse(&req.body)
                .into_owned()
                .collect();
        let keys: Vec<&str> = form.keys().map(String::as_str).collect();
        if keys
            != [
                "client_id",
                "client_secret",
                "code",
                "code_verifier",
                "grant_type",
                "redirect_uri",
            ]
        {
            return false;
        }
        let verifier = &form["code_verifier"];
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, verifier.as_bytes()),
        );
        form["grant_type"] == "authorization_code"
            && form["code"] == self.code
            && form["redirect_uri"] == self.redirect_uri
            && form["client_id"] == CLIENT_ID
            && form["client_secret"] == CLIENT_SECRET
            && (43..=128).contains(&verifier.len())
            && challenge == self.challenge
    }
}

/// The query parameters of a URL.
pub fn query(url: &str) -> std::collections::BTreeMap<String, String> {
    Url::parse(url)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}
