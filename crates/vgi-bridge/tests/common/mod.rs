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
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::Utc;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::UnboundedReceiver;
use tower::ServiceExt;
use trust_tasks_proof::affinidi::Verifier;
use vgi_bridge::checks::{CommitLine, CommitVerifier, GitFetcher};
use vgi_bridge::registry::{StoredApp, forgejo_secret, github_app_secret};
use vgi_bridge::seal::MasterKey;
use vgi_bridge::store::{NamespaceRecord, NamespaceState, RepoRecord, Table};
use vgi_bridge::transport::InboundDoc;
use vgi_bridge::transport::memory::ChannelLink;
use vgi_bridge::wire::new_id;
use vgi_bridge::{Bridge, BridgeConfig, BridgeIdentity, BridgeParts, Store};
use vgi_forge::{Namespace, NamespaceBinding, NamespaceKind, Resource};
use vgi_forge_github::Secret;
use vgi_forge_github::webhook::sign_body;
use wiremock::matchers::{method, path, path_regex, query_param};
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
/// `git-ns/bridge/event` 0.2, what the bridge sends unless configured
/// otherwise.
pub const EVENT: &str = "https://trusttasks.org/spec/git-ns/bridge/event/0.2";
/// `git-ns/bridge/event` 0.1, for a VTC configured `event_version = "0.1"`.
pub const EVENT_0_1: &str = "https://trusttasks.org/spec/git-ns/bridge/event/0.1";
/// `git-ns/bridge/job` 0.2: `projectRoles` may carry `removeAccounts`.
pub const JOB_0_2: &str = "https://trusttasks.org/spec/git-ns/bridge/job/0.2";

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
        commits: &[verify_trust::RangeCommit],
        resource: &str,
        fallback: &str,
    ) -> anyhow::Result<Vec<CommitLine>> {
        self.seen.lock().unwrap().push((
            commits.iter().map(|c| c.sha.clone()).collect(),
            resource.to_string(),
            fallback.to_string(),
        ));
        Ok(commits
            .iter()
            .map(|c| {
                // The fetcher handed over the real commit object.
                assert!(c.raw.starts_with(b"tree "), "a raw commit object");
                let ok = self.trusted.contains(&c.sha);
                CommitLine::new(
                    c.sha.clone(),
                    ok,
                    if ok { "trusted" } else { "unauthorized" },
                )
            })
            .collect())
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
    /// VTA mode: stops the mirror task when dropped.
    pub _mirror_stop: Option<tokio::sync::watch::Sender<bool>>,
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
    /// Seal a registered App before start.
    pub seed_app: bool,
    /// Configure the `web-flow` keyring.
    pub keyring: bool,
    /// Appended to the `[[github]]` table (e.g. per-namespace settings).
    pub github_extra: String,
    /// `event_version`, when set.
    pub event_version: Option<&'static str>,
    /// VTA mode: the store is a cache of this app-state (seeds go through
    /// it, and the mirror task runs).
    pub vta: Option<Arc<vgi_bridge::appstate::MemoryAppState>>,
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
            seed_app: true,
            keyring: true,
            github_extra: String::new(),
            event_version: None,
            vta: None,
        }
    }
}

pub fn config(server: &MockServer, dir: &std::path::Path, vtc: &str, o: &Options) -> BridgeConfig {
    let keyring_path = dir.join("web-flow.asc");
    std::fs::write(&keyring_path, KEYRING).unwrap();
    let keyring = if o.keyring {
        format!("platform_keyring_file = \"{}\"", keyring_path.display())
    } else {
        String::new()
    };
    BridgeConfig::parse(&format!(
        r#"
vtc_did = "{vtc}"
trust_registry_did = "did:webvh:QmReg:registry.acme.example"
mediator_did = "did:web:mediator.acme.example"
public_url = "https://bridge.acme.example/"
max_body_bytes = {max_body}
resend_secs = 3600
{event_version}

[verify_trust]
action = "OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@0123456789abcdef0123456789abcdef01234567"
version = "v0.5.0"

[[github]]
app_name = "acme-vgi-bridge"
app_owner = "acme"
{keyring}
bridge_checks = {checks}
api_base = "{uri}"
web_base = "{web}"
{extra}
"#,
        vtc = vtc,
        keyring = keyring,
        checks = o.bridge_checks,
        uri = server.uri(),
        web = o.web_base.clone().unwrap_or_else(|| server.uri()),
        max_body = o.max_body,
        extra = o.github_extra,
        event_version = o
            .event_version
            .map(|v| format!("event_version = \"{v}\""))
            .unwrap_or_default(),
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
    seed_namespace_ready(store, kind, required_workflow, Some(true));
}

/// A bound namespace whose installation's readiness for the bridge-posted
/// check is `ready` (`None`: never probed).
pub fn seed_namespace_ready(
    store: &Store,
    kind: NamespaceKind,
    required_workflow: bool,
    ready: Option<bool>,
) {
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
    rec.bridge_checks = ready;
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

/// The GitHub reads `inspect` makes for `acme/widgets` (forge id 812) in a
/// bridge-posted-check namespace, with a healthy ruleset pinned to the App.
pub async fn mount_inspect(server: &MockServer) {
    mount_inspect_as(server, 812, "acme/widgets").await;
}

/// As [`mount_inspect`], but GitHub answers for `acme/widgets` with
/// repository `id` named `full_name` (a transfer or a rename GitHub
/// redirects, or a new repository at the name).
pub async fn mount_inspect_as(server: &MockServer, id: u64, full_name: &str) {
    mount_any_token(server).await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": id, "full_name": full_name, "private": false,
            "visibility": "public", "archived": false, "default_branch": "main",
        })))
        .with_priority(1)
        .mount(server)
        .await;
    for p in ["collaborators", "invitations"] {
        Mock::given(method("GET"))
            .and(path(format!("/repos/acme/widgets/{p}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/rulesets"))
        .and(query_param("includes_parents", "false"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([{ "id": 9, "name": "VGI commit trust" }])),
        )
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/rulesets/9"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 9, "name": "VGI commit trust", "target": "branch", "enforcement": "active",
            "bypass_actors": [], "current_user_can_bypass": "never",
            "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
            "rules": [
                { "type": "deletion" }, { "type": "non_fast_forward" },
                { "type": "pull_request", "parameters": {
                    "required_approving_review_count": 0, "dismiss_stale_reviews_on_push": false,
                    "require_code_owner_review": false, "require_last_push_approval": false,
                    "required_review_thread_resolution": false } },
                { "type": "required_status_checks", "parameters": {
                    "strict_required_status_checks_policy": false,
                    "required_status_checks": [
                        { "context": "Verify commit trust", "integration_id": APP_ID } ] } }
            ],
        })))
        .mount(server)
        .await;
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
    let mut mirror_stop = None;
    let store = match &o.vta {
        Some(remote) => {
            let m = vgi_bridge::appstate::Mirror::new(MasterKey::from_bytes([11u8; 32]));
            let store = store.with_mirror(m.clone());
            m.pull(remote.as_ref(), &store).await.unwrap();
            let (tx, rx) = tokio::sync::watch::channel(false);
            let remote: Arc<dyn vgi_bridge::appstate::AppState> = remote.clone();
            tokio::spawn(m.run(remote, store.clone(), rx));
            mirror_stop = Some(tx);
            store
        }
        None => store,
    };
    if o.seed_app {
        seed_app(&store);
    }
    if o.seed_namespace {
        seed_namespace(&store, o.kind, o.required_workflow);
    }
    // VTA mode: the identity comes from the VTA, never from the store.
    let identity = match BridgeIdentity::load(&store).unwrap() {
        _ if o.vta.is_some() => {
            BridgeIdentity::from_seed(&o.bridge_seed.unwrap_or([9u8; 32])).unwrap()
        }
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
        _mirror_stop: mirror_stop,
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

    /// Send a `git-ns/bridge/job` 0.2 job; returns the job document.
    pub async fn send_job_0_2(&self, payload: Value) -> Value {
        let doc = self.doc(JOB_0_2, payload, None).await;
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
                &format!("{}#response", event_doc["type"].as_str().unwrap()),
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

/// Wait until delivery `id` on github.com is recorded as handled — every
/// check it called for has ended (posted or deliberately skipped).
pub async fn wait_delivery(w: &World, id: &str) {
    for _ in 0..400 {
        if w.bridge
            .store()
            .get::<i64>(Table::Deliveries, &format!("github.com#{id}"))
            .unwrap()
            .is_some()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("delivery {id} never completed");
}

/// Every check run the bridge posted (the POST bodies), in order.
pub async fn posted_checks(server: &MockServer) -> Vec<Value> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.method == http::Method::POST && r.url.path().ends_with("/check-runs"))
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect()
}

/// Every check-run completion the bridge sent (the PATCH bodies), in order.
pub async fn completed_checks(server: &MockServer) -> Vec<Value> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.method == http::Method::PATCH && r.url.path().contains("/check-runs/"))
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect()
}

/// Deliver a signed GitHub webhook to the bridge's router.
pub async fn post_webhook(w: &World, event: &str, delivery: &str, body: &Value) -> StatusCode {
    let bytes = serde_json::to_vec(body).unwrap();
    let sig = sign_body(&Secret::new(WEBHOOK_SECRET), &bytes);
    let req = Request::post("/github/github.com/webhook")
        .header("x-github-event", event)
        .header("x-github-delivery", delivery)
        .header("x-hub-signature-256", sig)
        .body(Body::from(bytes))
        .unwrap();
    vgi_bridge::http::router(w.bridge.clone())
        .oneshot(req)
        .await
        .unwrap()
        .status()
}

/// Serve the registry's `POST /trust-tasks`: `authorized` exactly for the
/// `(entity, resource)` grants.
pub async fn stub_registry(grants: Vec<(String, String)>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let grants = grants.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let header_end = loop {
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break p + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
                let len: usize = headers
                    .lines()
                    .find_map(|l| {
                        l.strip_prefix("content-length:")
                            .map(|v| v.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                while buf.len() < header_end + len {
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let req: Value = serde_json::from_slice(&buf[header_end..]).unwrap();
                let entity = req["payload"]["entity_id"].as_str().unwrap_or_default();
                let resource = req["payload"]["resource"].as_str().unwrap_or_default();
                let granted = grants.iter().any(|(e, r)| e == entity && r == resource);
                let body = json!({
                    "id": "urn:uuid:stub", "threadId": req["id"],
                    "type": "https://trusttasks.org/spec/registry/authorization/0.1#response",
                    "payload": {
                        "entity_id": entity, "authority_id": req["payload"]["authority_id"],
                        "action": req["payload"]["action"], "resource": resource,
                        "authorized": granted, "time_evaluated": "2026-09-23T00:00:00Z",
                    }
                })
                .to_string();
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(reply.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    format!("http://{addr}")
}

// ── Forgejo ─────────────────────────────────────────────────────────────

pub const FJ: &str = "127.0.0.1";
pub const BOT: &str = "acme-vgi-bot";
pub const BOT_ID: u64 = 900;

/// A bridge serving one bound Forgejo organisation, `acme`, on a mock
/// instance, with `acme/widgets` (forge id 812) managed. `extra` is appended
/// to the `[[forgejo]]` table. Collaborators and rules are the caller's to
/// mount.
pub async fn forgejo_world(extra: &str) -> World {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/version"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "version": "9.0.0+gitea-1.22.0" })),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/user"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "id": BOT_ID, "login": BOT })),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/repos/acme/widgets"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "id": 812, "full_name": "acme/widgets" })),
        )
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
resend_secs = 3600

[verify_trust]
action = "https://code.example/vgi/verify-trust@0123456789abcdef0123456789abcdef01234567"
version = "v0.5.0"
sha256 = "{}"

[[forgejo]]
base_url = "{}"
bot_login = "{BOT}"
oauth_client_id = "cid"
{extra}
"#,
        vtc.did(),
        dir.path().display(),
        "a".repeat(64),
        server.uri(),
    ))
    .unwrap();
    let store = Store::in_memory(MasterKey::generate().unwrap()).unwrap();
    for (what, v) in [
        ("bot-token", "bot-token-0000000000000000000000000000abcd"),
        ("oauth-client-secret", "cs"),
        ("webhook-secret", "wh"),
    ] {
        store
            .put_secret(&forgejo_secret(FJ, what), v.as_bytes())
            .unwrap();
    }
    let ns_resource = Resource::parse(&format!("{FJ}/acme")).unwrap();
    let namespace = Namespace::new(ns_resource.clone(), NamespaceKind::Organization)
        .with_owner_id(600)
        .with_installation(1);
    let mut ns = NamespaceRecord::pending(NS, ns_resource.clone());
    ns.state = NamespaceState::Bound;
    ns.binding = Some(NamespaceBinding::new(namespace, vec![]));
    ns.managed.insert(812);
    store.put(Table::Namespaces, NS, &ns).unwrap();
    let mut rec = RepoRecord::new(NS, ns_resource.join("widgets").unwrap(), 812);
    rec.roles_known = true;
    store.put(Table::Repos, &rec.key(), &rec).unwrap();

    let adapters = vgi_bridge::build_adapters(&cfg, &store).await.unwrap();
    let identity = BridgeIdentity::store_did_key(&store, &[5u8; 32]).unwrap();
    let (link, inbox) = ChannelLink::new();
    let bridge = Bridge::new(BridgeParts::new(
        cfg,
        identity,
        store,
        adapters,
        Arc::new(link),
        Arc::new(Verifier::for_did_key()),
    ));
    bridge.restore().await.unwrap();
    World {
        server,
        bridge,
        vtc,
        inbox,
        dir,
        verifier: Arc::new(FakeVerifier {
            trusted: vec![],
            seen: Default::default(),
        }),
        _mirror_stop: None,
    }
}
