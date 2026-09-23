//! A bridge wired to a mock GitHub (wiremock) and an in-process fake VTC.
//!
//! The fake VTC holds a real `did:key` and signs every document it sends;
//! the bridge's own documents arrive on a channel (its "inbox") and are
//! verified the way the VTC would.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{KeyPair, KeySize};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::Utc;
use serde_json::{Value, json};
use tokio::sync::mpsc::UnboundedReceiver;
use trust_tasks_proof::affinidi::Verifier;
use vgi_bridge::checks::{CommitLine, CommitVerifier, GitFetcher};
use vgi_bridge::registry::{StoredApp, github_app_secret};
use vgi_bridge::seal::MasterKey;
use vgi_bridge::store::{NamespaceRecord, NamespaceState, RepoRecord, Table};
use vgi_bridge::transport::InboundDoc;
use vgi_bridge::transport::memory::ChannelLink;
use vgi_bridge::wire::new_id;
use vgi_bridge::{Bridge, BridgeConfig, BridgeIdentity, BridgeParts, Store};
use vgi_forge::{Namespace, NamespaceBinding, NamespaceKind, Resource};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub const APP_ID: u64 = 1001;
pub const INSTALLATION: u64 = 42;
pub const WEBHOOK_SECRET: &str = "whsec-test";
pub const TOKEN: &str = "ghs_installation_token";
pub const NS: &str = "ns_acme";
pub const KEYRING: &str =
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nweb-flow\n-----END PGP PUBLIC KEY BLOCK-----\n";

pub const JOB: &str = "https://trusttasks.org/spec/git-ns/bridge/job/0.1";
pub const RESULT: &str = "https://trusttasks.org/spec/git-ns/bridge/result/0.1";
pub const EVENT: &str = "https://trusttasks.org/spec/git-ns/bridge/event/0.1";

/// One App key per test binary.
pub fn app_pem() -> &'static str {
    static PEM: OnceLock<String> = OnceLock::new();
    PEM.get_or_init(|| {
        let kp = KeyPair::generate(KeySize::Rsa2048).unwrap();
        let der = kp.as_der().unwrap().as_ref().to_vec();
        let b64 = STANDARD.encode(der);
        let mut out = "-----BEGIN PRIVATE KEY-----\n".to_string();
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str("-----END PRIVATE KEY-----\n");
        out
    })
}

pub fn acme() -> Resource {
    Resource::parse("github.com/acme").unwrap()
}

pub fn repo(name: &str) -> Resource {
    acme().join(name).unwrap()
}

/// A commit verifier that passes every commit whose id is in `trusted`.
pub struct FakeVerifier {
    pub trusted: Vec<String>,
    pub seen: std::sync::Mutex<Vec<(Vec<String>, String, String)>>,
}

#[async_trait]
impl CommitVerifier for FakeVerifier {
    async fn verify(
        &self,
        repo_dir: &std::path::Path,
        commits: &[String],
        resource: &str,
        fallback: &str,
    ) -> anyhow::Result<Vec<CommitLine>> {
        self.seen.lock().unwrap().push((
            commits.to_vec(),
            resource.to_string(),
            fallback.to_string(),
        ));
        commits
            .iter()
            .map(|c| {
                // The object really is in the fetched repository.
                verify_trust::read_commit_raw(repo_dir, c)?;
                let ok = self.trusted.contains(c);
                Ok(CommitLine::new(
                    c.clone(),
                    ok,
                    if ok { "trusted" } else { "unauthorized" },
                ))
            })
            .collect()
    }
}

/// The world a test runs in.
pub struct World {
    pub server: MockServer,
    pub bridge: Arc<Bridge>,
    pub vtc: BridgeIdentity,
    pub inbox: UnboundedReceiver<(String, Value)>,
    pub dir: tempfile::TempDir,
    pub verifier: Arc<FakeVerifier>,
}

pub struct Options {
    pub kind: NamespaceKind,
    pub required_workflow: bool,
    pub bridge_checks: bool,
    pub trusted: Vec<String>,
    pub local_remote: Option<url::Url>,
    pub store_path: Option<PathBuf>,
    pub key: Option<[u8; 32]>,
    pub vtc_seed: Option<[u8; 32]>,
    pub bridge_seed: Option<[u8; 32]>,
    pub seed_namespace: bool,
    pub max_body: usize,
    /// The GitHub web base, when it must differ from the mock (an `https`
    /// URL for flows whose `next` the schema requires to be https).
    pub web_base: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            kind: NamespaceKind::Organization,
            required_workflow: false,
            bridge_checks: true,
            trusted: Vec::new(),
            local_remote: None,
            store_path: None,
            key: None,
            vtc_seed: None,
            bridge_seed: None,
            seed_namespace: true,
            max_body: 2 * 1024 * 1024,
            web_base: None,
        }
    }
}

pub fn config(server: &MockServer, dir: &std::path::Path, vtc: &str, o: &Options) -> BridgeConfig {
    let keyring = dir.join("web-flow.asc");
    std::fs::write(&keyring, KEYRING).unwrap();
    BridgeConfig::parse(&format!(
        r#"
vtc_did = "{vtc}"
trust_registry_did = "did:webvh:QmReg:registry.acme.example"
mediator_did = "did:web:mediator.acme.example"
public_url = "https://bridge.acme.example/"
max_body_bytes = {max_body}
resend_secs = 3600

[verify_trust]
action = "OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@0123456789abcdef0123456789abcdef01234567"
version = "v0.5.0"

[[github]]
app_name = "acme-vgi-bridge"
app_owner = "acme"
platform_keyring_file = "{keyring}"
bridge_checks = {checks}
api_base = "{uri}"
web_base = "{web}"
"#,
        vtc = vtc,
        keyring = keyring.display(),
        checks = o.bridge_checks,
        uri = server.uri(),
        web = o.web_base.clone().unwrap_or_else(|| server.uri()),
        max_body = o.max_body,
    ))
    .unwrap()
}

pub fn seed_app(store: &Store) {
    let app = StoredApp {
        app_id: APP_ID,
        slug: "acme-vgi-bridge".into(),
        client_id: "Iv1.testclient".into(),
        client_secret: "client-secret".into(),
        webhook_secret: WEBHOOK_SECRET.into(),
        pem: app_pem().into(),
    };
    store
        .put_secret(
            &github_app_secret("github.com"),
            &serde_json::to_vec(&app).unwrap(),
        )
        .unwrap();
}

pub fn seed_namespace(store: &Store, kind: NamespaceKind, required_workflow: bool) {
    let ns_resource = match kind {
        NamespaceKind::User => Resource::parse("github.com/alice").unwrap(),
        _ => acme(),
    };
    let namespace = Namespace::new(ns_resource.clone(), kind)
        .with_owner_id(500)
        .with_installation(INSTALLATION);
    let mut rec = NamespaceRecord::pending(NS, ns_resource);
    rec.state = NamespaceState::Bound;
    rec.binding = Some(NamespaceBinding::new(namespace, vec![]));
    rec.required_workflow = Some(required_workflow);
    store.put(Table::Namespaces, NS, &rec).unwrap();
}

pub fn seed_repo(store: &Store, r: &Resource, id: u64) {
    let mut rec = RepoRecord::new(NS, r.clone(), id);
    rec.required_check = Some("Verify commit trust".into());
    rec.roles_known = true;
    store
        .put(Table::Repos, &format!("github.com#{id}"), &rec)
        .unwrap();
    store
        .update::<NamespaceRecord, _>(Table::Namespaces, NS, |n| {
            Ok((
                n.map(|mut n| {
                    n.managed.insert(id);
                    n
                }),
                (),
            ))
        })
        .unwrap();
}

/// Any installation token request succeeds.
pub async fn mount_any_token(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path_regex(r"^/app/installations/\d+/access_tokens$"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "token": TOKEN, "expires_at": "2099-01-01T00:00:00Z",
        })))
        .mount(server)
        .await;
}

pub async fn world(o: Options) -> World {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let vtc = match o.vtc_seed {
        Some(s) => BridgeIdentity::from_seed(&s).unwrap(),
        None => BridgeIdentity::generate_did_key().unwrap().0,
    };
    let cfg = config(&server, dir.path(), vtc.did(), &o);
    let key = MasterKey::from_bytes(o.key.unwrap_or([7u8; 32]));
    let store = match &o.store_path {
        Some(p) => Store::open(p, key).unwrap(),
        None => Store::in_memory(key).unwrap(),
    };
    seed_app(&store);
    if o.seed_namespace {
        seed_namespace(&store, o.kind, o.required_workflow);
    }
    let identity = match BridgeIdentity::load(&store).unwrap() {
        Some(id) => id,
        None => {
            let seed = o.bridge_seed.unwrap_or([9u8; 32]);
            BridgeIdentity::store_did_key(&store, &seed).unwrap()
        }
    };
    let adapters = vgi_bridge::build_adapters(&cfg, &store).await.unwrap();
    let (link, inbox) = ChannelLink::new();
    let verifier = Arc::new(FakeVerifier {
        trusted: o.trusted.clone(),
        seen: Default::default(),
    });
    let mut fetcher = GitFetcher::new(&cfg.checks);
    if let Some(remote) = &o.local_remote {
        fetcher = fetcher.with_local_remote(remote.clone());
    }
    let parts = BridgeParts::new(
        cfg,
        identity,
        store,
        adapters,
        Arc::new(link),
        Arc::new(Verifier::for_did_key()),
    )
    .with_commit_verifier(verifier.clone())
    .with_fetcher(fetcher);
    let bridge = Bridge::new(parts);
    bridge.restore().await.unwrap();
    World {
        server,
        bridge,
        vtc,
        inbox,
        dir,
        verifier,
    }
}

impl World {
    /// A document from the fake VTC to the bridge, signed.
    pub async fn doc(&self, type_uri: &str, payload: Value, thread: Option<&str>) -> Value {
        let id = new_id();
        let mut doc = json!({
            "id": id,
            "type": type_uri,
            "threadId": thread.unwrap_or(&id),
            "issuer": self.vtc.did(),
            "recipient": self.bridge.did(),
            "issuedAt": Utc::now().to_rfc3339(),
            "payload": payload,
        });
        doc = self.vtc.sign(&doc).await.unwrap();
        doc
    }

    /// Send a job; returns the job document.
    pub async fn send_job(&self, payload: Value) -> Value {
        let doc = self.doc(JOB, payload, None).await;
        self.deliver(doc.clone()).await;
        doc
    }

    pub async fn deliver(&self, doc: Value) {
        self.bridge
            .handle_inbound(InboundDoc {
                doc,
                authenticated_sender: Some(self.vtc.did().to_string()),
            })
            .await;
    }

    /// The next document the bridge sent, checked as the VTC checks it:
    /// addressed to the VTC, from the bridge, with a proof that verifies.
    pub async fn next(&mut self) -> Value {
        let (to, doc) = tokio::time::timeout(Duration::from_secs(20), self.inbox.recv())
            .await
            .expect("the bridge sent nothing in time")
            .expect("channel open");
        assert_eq!(to, self.vtc.did());
        assert_eq!(doc["issuer"], self.bridge.did());
        assert_eq!(doc["recipient"], self.vtc.did());
        Verifier::for_did_key()
            .verify_raw(&doc)
            .await
            .expect("the bridge's proof verifies");
        doc
    }

    /// The next document of type `ty` (skipping others), with the ones
    /// skipped.
    pub async fn next_of(&mut self, ty: &str) -> Value {
        loop {
            let d = self.next().await;
            if d["type"] == ty {
                return d;
            }
        }
    }

    /// Nothing more arrives within a short while.
    pub async fn quiet(&mut self) {
        assert!(
            tokio::time::timeout(Duration::from_millis(300), self.inbox.recv())
                .await
                .is_err(),
            "the bridge sent something unexpected"
        );
    }

    /// Acknowledge a result as the VTC does.
    pub async fn ack_result(&self, result_doc: &Value) {
        let job = result_doc["payload"]["jobId"].as_str().unwrap();
        let ack = self
            .doc(
                &format!("{RESULT}#response"),
                json!({ "jobId": job }),
                result_doc["threadId"].as_str(),
            )
            .await;
        self.deliver(ack).await;
    }
}

impl World {
    /// Acknowledge an event as the VTC does.
    pub async fn ack_event(&self, event_doc: &Value) {
        let ack = self
            .doc(
                &format!("{EVENT}#response"),
                json!({}),
                event_doc["threadId"].as_str(),
            )
            .await;
        self.deliver(ack).await;
    }
}

/// Wait until `server` has received a request matching `pred`.
pub async fn wait_for_request(
    server: &MockServer,
    what: &str,
    pred: impl Fn(&wiremock::Request) -> bool,
) -> wiremock::Request {
    for _ in 0..200 {
        if let Some(r) = server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|r| pred(r))
        {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no request: {what}");
}
