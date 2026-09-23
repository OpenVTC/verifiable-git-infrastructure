//! Shared fixtures: a throwaway App key, a mock GitHub, and a matcher that
//! only accepts correctly signed App JWTs.

#![allow(dead_code)]

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{KeyPair, KeySize};
use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use url::Url;
use vgi_forge::{Namespace, NamespaceKind, Resource};
use vgi_forge_github::{GitHubConfig, GitHubForge, InProcessKey, Secret};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

pub const CLIENT_ID: &str = "Iv1.testclient";
pub const INSTALLATION: u64 = 42;
pub const USER_INSTALLATION: u64 = 43;
pub const WEBHOOK_SECRET: &str = "whsec-test";
pub const ACTIONS_APP_ID: u64 = 15368;
pub const TOKEN: &str = "ghs_installation_token";

/// One generated App key per test binary (RSA generation is the slow part).
pub struct TestKey {
    /// PKCS#8 PEM (`PRIVATE KEY`).
    pub pkcs8_pem: String,
    /// PKCS#1 PEM (`RSA PRIVATE KEY`) — the shape GitHub issues.
    pub pkcs1_pem: String,
    /// PKCS#1 `RSAPublicKey` DER.
    pub public: Vec<u8>,
}

pub fn key() -> &'static TestKey {
    static KEY: OnceLock<TestKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let kp = KeyPair::generate(KeySize::Rsa2048).expect("generate RSA key");
        let pkcs8 = kp.as_der().expect("export PKCS#8").as_ref().to_vec();
        let pkcs1 = pkcs1_from_pkcs8(&pkcs8);
        TestKey {
            pkcs8_pem: pem("PRIVATE KEY", &pkcs8),
            pkcs1_pem: pem("RSA PRIVATE KEY", &pkcs1),
            public: kp.public_key().as_ref().to_vec(),
        }
    })
}

fn pem(label: &str, der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// PKCS#8 `PrivateKeyInfo` → the PKCS#1 `RSAPrivateKey` inside its OCTET
/// STRING. Just enough DER to unwrap a key we generated ourselves.
fn pkcs1_from_pkcs8(der: &[u8]) -> Vec<u8> {
    fn header(buf: &[u8]) -> (u8, usize, usize) {
        let tag = buf[0];
        let first = buf[1] as usize;
        if first < 0x80 {
            (tag, first, 2)
        } else {
            let n = first & 0x7f;
            let len = buf[2..2 + n]
                .iter()
                .fold(0usize, |a, b| (a << 8) | *b as usize);
            (tag, len, 2 + n)
        }
    }
    let (tag, _, hl) = header(der);
    assert_eq!(tag, 0x30);
    let mut rest = &der[hl..];
    for expected in [0x02u8, 0x30] {
        let (tag, len, hl) = header(rest);
        assert_eq!(tag, expected);
        rest = &rest[hl + len..];
    }
    let (tag, len, hl) = header(rest);
    assert_eq!(tag, 0x04);
    rest[hl..hl + len].to_vec()
}

/// Verify an App JWT's signature against the test key and return its claims.
pub fn verify_jwt(jwt: &str) -> Option<Value> {
    let (signing_input, sig) = jwt.rsplit_once('.')?;
    let (header, claims) = signing_input.split_once('.')?;
    let sig = URL_SAFE_NO_PAD.decode(sig).ok()?;
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &key().public)
        .verify(signing_input.as_bytes(), &sig)
        .ok()?;
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).ok()?).ok()?;
    if header != json!({ "alg": "RS256", "typ": "JWT" }) {
        return None;
    }
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims).ok()?).ok()
}

/// Matches only requests bearing a valid App JWT from the test key, issued
/// by [`CLIENT_ID`], with `exp - iat` at most ten minutes.
pub struct ValidAppJwt;

impl Match for ValidAppJwt {
    fn matches(&self, req: &Request) -> bool {
        let Some(auth) = req
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
        else {
            return false;
        };
        let Some(claims) = auth.strip_prefix("Bearer ").and_then(verify_jwt) else {
            return false;
        };
        let (iat, exp) = (
            claims["iat"].as_u64().unwrap(),
            claims["exp"].as_u64().unwrap(),
        );
        claims["iss"] == CLIENT_ID && exp > iat && exp - iat <= 600
    }
}

/// Matches requests authenticated with the installation token.
pub struct InstallationToken;

impl Match for InstallationToken {
    fn matches(&self, req: &Request) -> bool {
        req.headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            == Some(&format!("Bearer {TOKEN}"))
    }
}

pub fn acme() -> Resource {
    Resource::parse("github.com/acme").unwrap()
}

pub fn repo(name: &str) -> Resource {
    acme().join(name).unwrap()
}

pub async fn server_and_forge() -> (MockServer, GitHubForge) {
    let server = MockServer::start().await;
    let forge = forge_for(&server);
    (server, forge)
}

pub fn forge_for(server: &MockServer) -> GitHubForge {
    let base = Url::parse(&server.uri()).unwrap();
    let mut cfg = GitHubConfig::github_com(1001, CLIENT_ID, "acme-vgi")
        .with_endpoints(base.clone(), base)
        .with_actions_integration_id(ACTIONS_APP_ID);
    cfg.device_poll_unit = Duration::from_millis(1);
    let signer = Arc::new(InProcessKey::from_pem(&key().pkcs1_pem).unwrap());
    let forge = GitHubForge::new(cfg, signer, Secret::new(WEBHOOK_SECRET)).unwrap();
    forge
        .register_namespace(
            Namespace::new(acme(), NamespaceKind::Organization)
                .with_owner_id(500)
                .with_installation(INSTALLATION),
        )
        .unwrap();
    forge
        .register_namespace(
            Namespace::new(
                Resource::parse("github.com/alice").unwrap(),
                NamespaceKind::User,
            )
            .with_owner_id(1)
            .with_installation(USER_INSTALLATION),
        )
        .unwrap();
    forge
}

/// Mount the installation-token endpoint for `installation`, expecting the
/// request to name `repo` (when given) and include `perms`, `times` times.
pub async fn mount_token(
    server: &MockServer,
    installation: u64,
    repo: Option<&str>,
    perms: Value,
    times: u64,
) {
    let mut body = json!({ "permissions": perms });
    if let Some(r) = repo {
        body["repositories"] = json!([r]);
    }
    Mock::given(method("POST"))
        .and(path(format!(
            "/app/installations/{installation}/access_tokens"
        )))
        .and(ValidAppJwt)
        .and(body_partial_json(body))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "token": TOKEN,
            "expires_at": "2099-01-01T00:00:00Z",
        })))
        .expect(times)
        .named(format!("installation token {perms}"))
        .mount(server)
        .await;
}

pub fn repo_json(id: u64, full_name: &str, archived: bool) -> Value {
    json!({
        "id": id,
        "full_name": full_name,
        "private": false,
        "visibility": "public",
        "archived": archived,
        "default_branch": "main",
    })
}

/// A ruleset exactly as the adapter creates it.
pub fn good_ruleset(id: u64) -> Value {
    json!({
        "id": id,
        "name": "VGI commit trust",
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "current_user_can_bypass": "never",
        "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
        "rules": [
            { "type": "deletion" },
            { "type": "non_fast_forward" },
            { "type": "pull_request", "parameters": { "required_approving_review_count": 0 } },
            { "type": "required_status_checks", "parameters": {
                "strict_required_status_checks_policy": false,
                "required_status_checks": [
                    { "context": "Verify commit trust", "integration_id": ACTIONS_APP_ID }
                ]
            } }
        ]
    })
}
