//! The Forgejo side: the adapter built from sealed credentials, and the bot
//! token rotated in two phases — mint, persist, and only then retire.

use std::sync::Arc;

use serde_json::json;
use trust_tasks_proof::affinidi::Verifier;
use vgi_bridge::registry::forgejo_secret;
use vgi_bridge::seal::MasterKey;
use vgi_bridge::store::Table;
use vgi_bridge::transport::memory::ChannelLink;
use vgi_bridge::{Bridge, BridgeConfig, BridgeIdentity, BridgeParts, Store};
use wiremock::matchers::{header, method, path};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

const BOT: &str = "acme-vgi-bot";
const OLD: &str = "old-token-00000000000000000000000000000abcd";
const NEW: &str = "new-token-11111111111111111111111111111wxyz";

fn basic() -> String {
    use base64::Engine;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{BOT}:bot-password"))
    )
}

/// Matches only once the new token is sealed in the store: the old token
/// may be deleted only after the new one is persisted.
struct NewTokenPersisted(Store, String);

impl Match for NewTokenPersisted {
    fn matches(&self, _req: &Request) -> bool {
        self.0
            .get_secret_string(&self.1)
            .ok()
            .flatten()
            .is_some_and(|t| t.as_str() == NEW)
    }
}

#[tokio::test]
async fn the_bot_token_is_minted_persisted_then_retired() {
    let server = MockServer::start().await;
    let host = "127.0.0.1";
    Mock::given(method("GET"))
        .and(path("/api/v1/version"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "version": "9.0.0+gitea-1.22.0" })),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 900, "login": BOT })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/users/{BOT}/tokens")))
        .and(header("authorization", basic().as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "id": 40, "name": "setup", "token_last_eight": &OLD[OLD.len() - 8..] },
        ])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/users/{BOT}/tokens")))
        .and(header("authorization", basic().as_str()))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": 44, "name": "vgi-bridge-1", "sha1": NEW, "token_last_eight": &NEW[NEW.len() - 8..],
        })))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let (vtc, _) = BridgeIdentity::generate_did_key().unwrap();
    let cfg = BridgeConfig::parse(&format!(
        r#"
vtc_did = "{}"
trust_registry_did = "did:webvh:QmReg:registry.acme.example"
mediator_did = "did:web:mediator.acme.example"
public_url = "https://bridge.acme.example/"
data_dir = "{}"

[verify_trust]
action = "https://code.example/vgi/verify-trust@0123456789abcdef0123456789abcdef01234567"
version = "v0.5.0"
sha256 = "{}"

[[forgejo]]
base_url = "{}"
bot_login = "{BOT}"
oauth_client_id = "cid"
rotate_token_days = 30
"#,
        vtc.did(),
        dir.path().display(),
        "a".repeat(64),
        server.uri(),
    ))
    .unwrap();
    let store = Store::in_memory(MasterKey::generate().unwrap()).unwrap();
    for (what, v) in [
        ("bot-token", OLD),
        ("oauth-client-secret", "cs"),
        ("webhook-secret", "wh"),
        ("bot-password", "bot-password"),
    ] {
        store
            .put_secret(&forgejo_secret(host, what), v.as_bytes())
            .unwrap();
    }
    // The old token is deleted only once the new one is sealed.
    Mock::given(method("DELETE"))
        .and(path(format!("/api/v1/users/{BOT}/tokens/40")))
        .and(NewTokenPersisted(
            store.clone(),
            forgejo_secret(host, "bot-token"),
        ))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let adapters = vgi_bridge::build_adapters(&cfg, &store).await.unwrap();
    assert!(
        adapters.get(host).is_some(),
        "the Forgejo adapter is in service"
    );
    let identity = BridgeIdentity::store_did_key(&store, &[5u8; 32]).unwrap();
    let (link, _inbox) = ChannelLink::new();
    let bridge = Bridge::new(BridgeParts::new(
        cfg,
        identity,
        store.clone(),
        adapters,
        Arc::new(link),
        Arc::new(Verifier::for_did_key()),
    ));

    // The first maintenance run starts the clock rather than rotating a
    // token the operator has just stored.
    bridge.maintenance().await;
    assert_eq!(
        store
            .get_secret_string(&forgejo_secret(host, "bot-token"))
            .unwrap()
            .unwrap()
            .as_str(),
        OLD
    );
    // Thirty-one days later.
    store
        .put(Table::Meta, &format!("forgejo/{host}/rotated-at"), &1_i64)
        .unwrap();
    bridge.maintenance().await;
    assert_eq!(
        store
            .get_secret_string(&forgejo_secret(host, "bot-token"))
            .unwrap()
            .unwrap()
            .as_str(),
        NEW,
        "the new token is what a restart comes back with"
    );
    // `server` checks on drop that the old token was deleted exactly once,
    // and only after the new one was persisted.
}
