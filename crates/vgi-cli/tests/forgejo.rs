//! `vgi repo init` on Forgejo, against a mock instance.

use std::process::{Command, Output};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use url::Url;
use vgi_forge::{ProtectionSpec, RepoSpec, Resource, StepAction, VgiConfig};
use vgi_forge_forgejo::plan::{
    MergePlan, PROTECTED_PATHS, PlanOptions, WORKFLOW_PATH, default_status_context, forgejo_plan,
};
use vgi_forge_forgejo::{
    DEFAULT_ACTIONS_BASE, DEFAULT_CHECKOUT_ACTION, DEFAULT_RUNS_ON, protection_body,
};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const VTC: &str = "did:webvh:QmVtc:vtc.acme.example";
const REGISTRY: &str = "did:webvh:QmReg:registry.acme.example";
const ACTION: &str = "OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@0123456789abcdef0123456789abcdef01234567";
const VERSION: &str = "v0.4.14";
const SHA256: &str = "3f1c2b7e9d8a6f5e4d3c2b1a0f9e8d7c6b5a49382716f5e4d3c2b1a0f9e8d7c6";
const TOKEN: &str = "not-a-real-token-0123";
const REPO: &str = "/api/v1/repos/alice/widgets";

fn repo_json(converged: bool) -> Value {
    json!({
        "id": 42,
        "full_name": "alice/widgets",
        "default_branch": "main",
        "empty": false,
        "private": false,
        "permissions": { "admin": true },
        "has_pull_requests": true,
        "has_actions": converged,
        "allow_fast_forward_only_merge": converged,
        "allow_merge_commits": !converged,
        "allow_rebase": !converged,
        "allow_rebase_explicit": !converged,
        "allow_squash_merge": !converged,
        "default_merge_style": if converged { "fast-forward-only" } else { "merge" },
    })
}

async fn instance(converged: Option<(&[u8], &Value)>) -> MockServer {
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
        .and(header("authorization", format!("token {TOKEN}").as_str()))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "id": 7, "login": "alice" })),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(REPO))
        .respond_with(ResponseTemplate::new(200).set_body_json(repo_json(converged.is_some())))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path(REPO))
        .respond_with(ResponseTemplate::new(200).set_body_json(repo_json(true)))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{REPO}/collaborators")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("{REPO}/contents/{WORKFLOW_PATH}")))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .mount(&server)
        .await;
    // The instance reads back what it was sent.
    Mock::given(method("POST"))
        .and(path(format!("{REPO}/branch_protections")))
        .respond_with(|req: &Request| {
            ResponseTemplate::new(201)
                .set_body_json(serde_json::from_slice::<Value>(&req.body).unwrap())
        })
        .mount(&server)
        .await;
    let rules = match converged {
        Some((workflow, rule)) => {
            Mock::given(method("GET"))
                .and(path(format!("{REPO}/contents/{WORKFLOW_PATH}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "type": "file",
                    "sha": "b10b",
                    "encoding": "base64",
                    "content": STANDARD.encode(workflow),
                })))
                .mount(&server)
                .await;
            json!([rule])
        }
        None => json!([]),
    };
    Mock::given(method("GET"))
        .and(path(format!("{REPO}/branch_protections")))
        .respond_with(ResponseTemplate::new(200).set_body_json(rules))
        .mount(&server)
        .await;
    server
}

async fn vgi(server: &MockServer, extra: &[&str], token: Option<&str>) -> Output {
    let mut args: Vec<String> = [
        "repo",
        "init",
        "--vtc",
        VTC,
        "--resource",
        "codeberg.org/alice/widgets",
        "--registry",
        REGISTRY,
        "--verify-trust-action",
        ACTION,
        "--verify-trust-version",
        VERSION,
        "--verify-trust-sha256",
        SHA256,
        "--forgejo-url",
        &server.uri(),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    args.extend(extra.iter().map(|s| s.to_string()));
    let token = token.map(str::to_string);
    tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_vgi"));
        cmd.args(&args).env_remove("FORGEJO_TOKEN");
        if let Some(t) = token {
            cmd.env("FORGEJO_TOKEN", t);
        }
        cmd.output().unwrap()
    })
    .await
    .unwrap()
}

fn ok(o: &Output) -> String {
    assert!(
        o.status.success(),
        "vgi failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8(o.stdout.clone()).unwrap()
}

async fn changes(server: &MockServer) -> Vec<Request> {
    server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.method.as_str() != "GET")
        .collect()
}

fn adapter_plan() -> Vec<vgi_forge::BootstrapStep> {
    let cfg = VgiConfig::new(REGISTRY, VTC, ACTION, VERSION).with_verify_trust_sha256(SHA256);
    let base = Url::parse(DEFAULT_ACTIONS_BASE).unwrap();
    forgejo_plan(
        &RepoSpec::new(Resource::parse("codeberg.org/alice/widgets").unwrap()),
        &cfg,
        &PlanOptions {
            checkout_action: DEFAULT_CHECKOUT_ACTION,
            actions_base: &base,
            runs_on: DEFAULT_RUNS_ON,
            status_context: default_status_context(&cfg.required_check),
            inline_variables: true,
            merges: MergePlan::FastForwardOnly,
        },
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_adapters_plan_lands_and_a_rerun_changes_nothing() {
    let server = instance(None).await;
    let out = ok(&vgi(&server, &["--owner", "did:web:alice.example"], Some(TOKEN)).await);
    let sent = changes(&server).await;
    let summary: Vec<(String, String)> = sent
        .iter()
        .map(|r| (r.method.to_string(), r.url.path().to_string()))
        .collect();
    assert_eq!(
        summary,
        vec![
            ("PATCH".into(), REPO.to_string()),
            ("POST".into(), format!("{REPO}/contents/{WORKFLOW_PATH}")),
            ("POST".into(), format!("{REPO}/branch_protections")),
        ]
    );
    for r in &sent {
        assert_eq!(
            r.headers.get("authorization").unwrap().to_str().unwrap(),
            format!("token {TOKEN}")
        );
    }

    let plan = adapter_plan();
    // Merge settings: fast-forward only, Actions on.
    let patch: Value = serde_json::from_slice(&sent[0].body).unwrap();
    assert_eq!(patch["allow_fast_forward_only_merge"], json!(true));
    assert_eq!(patch["default_merge_style"], json!("fast-forward-only"));
    assert_eq!(patch["has_actions"], json!(true));
    // The workflow, byte for byte.
    let StepAction::WriteFile { contents, .. } = &plan[1].action else {
        panic!("{:?}", plan[1])
    };
    let body: Value = serde_json::from_slice(&sent[1].body).unwrap();
    let written = STANDARD.decode(body["content"].as_str().unwrap()).unwrap();
    assert_eq!(&written, contents);
    // The protection: the adapter's body, the account holder on the merge
    // allow-list, the workflow paths protected.
    let spec = ProtectionSpec::standard(default_status_context("Verify commit trust"))
        .with_protected_paths(PROTECTED_PATHS);
    let mut want = protection_body(None, &["alice".to_string()], &spec).unwrap();
    want["rule_name"] = json!("main");
    want["branch_name"] = json!("main");
    let rule: Value = serde_json::from_slice(&sent[2].body).unwrap();
    assert_eq!(rule, want);
    assert!(out.contains("cnm git adopt codeberg.org/alice/widgets --owner did:web:alice.example"));

    // Against the instance as it now is: reads only.
    let converged = instance(Some((&written, &rule))).await;
    let out = ok(&vgi(&converged, &[], Some(TOKEN)).await);
    assert!(changes(&converged).await.is_empty());
    assert!(out.contains("Nothing to change"), "{out}");
}

#[tokio::test(flavor = "multi_thread")]
async fn dry_run_sends_nothing_but_reads() {
    let server = instance(None).await;
    let out = ok(&vgi(&server, &["--dry-run"], Some(TOKEN)).await);
    assert!(changes(&server).await.is_empty());
    assert!(out.contains("[would update] merge-styles"), "{out}");
    assert!(out.contains("[would create] workflow"), "{out}");
    assert!(out.contains("[would create] protection"), "{out}");
    assert!(out.contains(&format!("sha256: {SHA256}")), "{out}");
    assert!(out.contains(".forgejo/workflows/**"), "{out}");
}

#[tokio::test(flavor = "multi_thread")]
async fn no_token_no_requests() {
    let server = instance(None).await;
    let out = vgi(&server, &[], None).await;
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("FORGEJO_TOKEN"));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_instance_without_fast_forward_only_merges_is_refused_before_any_write() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "version": "1.21.0" })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/user"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "id": 7, "login": "alice" })),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(REPO))
        .respond_with(ResponseTemplate::new(200).set_body_json(repo_json(false)))
        .mount(&server)
        .await;
    let out = vgi(&server, &[], Some(TOKEN)).await;
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("fast-forward only"));
    assert!(changes(&server).await.is_empty());
}
