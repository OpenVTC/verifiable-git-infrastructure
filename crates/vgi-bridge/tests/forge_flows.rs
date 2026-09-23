//! Forge-facing flows: create, bind, link, webhooks, the bridge-posted
//! check, and what survives a restart.

mod common;

use std::collections::BTreeSet;
use std::process::Command;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::*;
use serde_json::{Value, json};
use tower::ServiceExt;
use vgi_bridge::store::{
    JobRecord, JobState, NamespaceRecord, NamespaceState, PendingFlow, PinRecord, RepoRecord, Table,
};
use vgi_forge_github::Secret;
use vgi_forge_github::webhook::sign_body;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, ResponseTemplate};

async fn post_webhook(
    w: &World,
    event: &str,
    delivery: &str,
    body: &Value,
    secret: &str,
) -> StatusCode {
    let bytes = serde_json::to_vec(body).unwrap();
    let sig = sign_body(&Secret::new(secret), &bytes);
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

async fn get(w: &World, uri: &str) -> (StatusCode, String) {
    let resp = vgi_bridge::http::router(w.bridge.clone())
        .oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

// ── webhooks ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn webhooks_are_verified_before_anything_is_reported() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    let renamed = json!({
        "action": "renamed",
        "repository": { "id": 812, "full_name": "acme/widgets-core" },
        "changes": { "repository": { "name": { "from": "widgets" } } },
    });

    // Wrong secret: refused, nothing reported.
    let s = post_webhook(&w, "repository", "d-1", &renamed, "not-the-secret").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    w.quiet().await;

    // Signed: the rename is reported by forge id, and the record follows.
    let s = post_webhook(&w, "repository", "d-2", &renamed, WEBHOOK_SECRET).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let ev = w.next_of(EVENT).await;
    assert_eq!(
        ev["payload"]["event"],
        json!({ "type": "repoRenamed", "forgeId": "812",
                "from": "github.com/acme/widgets", "to": "github.com/acme/widgets-core" })
    );
    let rec: RepoRecord = w
        .bridge
        .store()
        .get(Table::Repos, "github.com#812")
        .unwrap()
        .unwrap();
    assert_eq!(rec.resource.as_str(), "github.com/acme/widgets-core");

    // The same delivery again is dropped.
    let s = post_webhook(&w, "repository", "d-2", &renamed, WEBHOOK_SECRET).await;
    assert_eq!(s, StatusCode::OK);
    w.quiet().await;

    // The bridge's own `.vgi` is part of the binding, never "unmanaged".
    let created =
        json!({ "action": "created", "repository": { "id": 5, "full_name": "acme/.vgi" } });
    post_webhook(&w, "repository", "d-3", &created, WEBHOOK_SECRET).await;
    w.quiet().await;

    // A host the bridge does not serve.
    let resp = vgi_bridge::http::router(w.bridge.clone())
        .oneshot(
            Request::post("/github/evil.example/webhook")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_oversized_body_is_refused_before_it_is_read() {
    let w = world(Options {
        max_body: 64 * 1024,
        ..Options::default()
    })
    .await;
    let big = json!({ "pad": "x".repeat(100 * 1024) });
    let s = post_webhook(&w, "repository", "d-big", &big, WEBHOOK_SECRET).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
}

// ── create ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_repo_creates_bootstraps_projects_and_reports_each_step() {
    let mut w = world(Options::default()).await;
    let s = &w.server;
    mount_any_token(s).await;
    let repo_json = json!({
        "id": 9001, "full_name": "acme/gadgets", "private": false, "visibility": "public",
        "archived": false, "default_branch": "main",
    });
    // Not there before the create; there after.
    Mock::given(method("GET"))
        .and(path("/repos/acme/gadgets"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "message": "Not Found" })))
        .up_to_n_times(1)
        .mount(s)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/gadgets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(repo_json.clone()))
        .mount(s)
        .await;
    Mock::given(method("POST"))
        .and(path("/orgs/acme/repos"))
        .and(body_partial_json(
            json!({ "name": "gadgets", "visibility": "public", "auto_init": true }),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(repo_json))
        .expect(1)
        .mount(s)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/gadgets/rulesets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(s)
        .await;
    // The ruleset requires the check from this App (bridge-posted mode).
    Mock::given(method("POST"))
        .and(path("/repos/acme/gadgets/rulesets"))
        .and(body_partial_json(json!({ "rules": [
            { "type": "deletion" }, { "type": "non_fast_forward" }, { "type": "pull_request" },
            { "type": "required_status_checks", "parameters": { "required_status_checks": [
                { "context": "Verify commit trust", "integration_id": APP_ID } ] } } ] })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 3 })))
        .expect(1)
        .mount(s)
        .await;
    for p in ["collaborators", "invitations"] {
        Mock::given(method("GET"))
            .and(path(format!("/repos/acme/gadgets/{p}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(s)
            .await;
    }
    // Nothing is committed to the repository in this mode.
    Mock::given(method("PUT"))
        .and(path(
            "/repos/acme/gadgets/contents/.github/workflows/verify-trust.yml",
        ))
        .respond_with(ResponseTemplate::new(201))
        .expect(0)
        .mount(s)
        .await;

    w.send_job(json!({
        "jobId": "job_c", "namespace": NS, "kind": "createRepo", "repo": "github.com/acme/gadgets",
        "spec": { "visibility": "public", "description": "Small tools" }, "desiredRoles": [],
    }))
    .await;
    assert_eq!(w.next().await["payload"]["accepted"], true);
    let result = w.next_of(RESULT).await;
    let p = &result["payload"];
    assert_eq!(p["outcome"], "succeeded", "{p}");
    assert_eq!(
        p["repo"],
        json!({ "resource": "github.com/acme/gadgets", "forgeId": "9001" })
    );
    let steps: Vec<(String, String)> = p["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["step"].as_str().unwrap().to_string(),
                s["outcome"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(steps[0], ("create".into(), "applied".into()));
    assert!(
        steps.contains(&("requiredCheck".into(), "applied".into())),
        "{steps:?}"
    );
    assert!(
        steps.contains(&("variables".into(), "unchanged".into())),
        "{steps:?}"
    );
    assert_eq!(steps.last().unwrap(), &("roles".into(), "unchanged".into()));

    // Managed from now on — in the store and in the adapter.
    let ns: NamespaceRecord = w
        .bridge
        .store()
        .get(Table::Namespaces, NS)
        .unwrap()
        .unwrap();
    assert!(ns.managed.contains(&9001));
    let rec: RepoRecord = w
        .bridge
        .store()
        .get(Table::Repos, "github.com#9001")
        .unwrap()
        .unwrap();
    assert_eq!(rec.required_check.as_deref(), Some("Verify commit trust"));
}

// ── bind and link ────────────────────────────────────────────────────────

fn state_of(url: &str) -> String {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned()
}

#[tokio::test]
async fn a_bind_completes_through_the_setup_callback_once() {
    let mut w = world(Options {
        web_base: Some("https://github.example".into()),
        ..Options::default()
    })
    .await;
    let s = &w.server;
    mount_any_token(s).await;
    Mock::given(method("GET"))
        .and(path("/app/installations/77"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 77,
            "account": { "id": 600, "login": "NewCo", "type": "Organization" },
            "permissions": {
                "administration": "write", "contents": "write", "actions_variables": "write",
                "checks": "write", "metadata": "read", "members": "read",
                "organization_administration": "write",
            },
            "suspended_at": null,
        })))
        .mount(s)
        .await;
    Mock::given(method("GET"))
        .and(path("/orgs/newco/rulesets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(s)
        .await;

    w.send_job(json!({
        "jobId": "job_b", "namespace": "ns_new", "kind": "beginBind",
        "target": { "forge": "github.com", "owner": "newco" },
    }))
    .await;
    let resp = w.next().await;
    assert_eq!(resp["payload"]["accepted"], true);
    let url = resp["payload"]["next"]["url"].as_str().unwrap().to_string();
    assert!(
        url.contains("/apps/acme-vgi-bridge/installations/new"),
        "{url}"
    );
    assert!(resp["payload"]["next"]["expiresAt"].is_string());
    // `next` URLs are https by schema; this one is the mock's, so only check
    // the state it carries.
    let state = state_of(&url);

    let (status, _) = get(
        &w,
        &format!("/github/github.com/setup?installation_id=77&setup_action=install&state={state}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let ev = w.next_of(EVENT).await;
    assert_eq!(
        ev["payload"]["event"],
        json!({ "type": "bindCompleted", "jobId": "job_b", "ownerId": "600", "kind": "organization" })
    );
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["outcome"], "succeeded");
    let ns: NamespaceRecord = w
        .bridge
        .store()
        .get(Table::Namespaces, "ns_new")
        .unwrap()
        .unwrap();
    assert_eq!(ns.state, NamespaceState::Bound);
    assert_eq!(
        ns.required_workflow,
        Some(true),
        "org rulesets probed at bind"
    );

    // The state is single use.
    let (status, _) = get(
        &w,
        &format!("/github/github.com/setup?installation_id=77&setup_action=install&state={state}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    w.quiet().await;
}

#[tokio::test]
async fn a_bind_nobody_completes_ends_expired() {
    let mut w = world(Options {
        web_base: Some("https://github.example".into()),
        ..Options::default()
    })
    .await;
    w.send_job(json!({
        "jobId": "job_e", "namespace": "ns_new", "kind": "beginBind",
        "target": { "forge": "github.com", "owner": "newco" },
    }))
    .await;
    let resp = w.next().await;
    let state = state_of(resp["payload"]["next"]["url"].as_str().unwrap());
    w.bridge
        .store()
        .update::<PendingFlow, _>(Table::Pending, &state, |f| {
            let f = match f.unwrap() {
                PendingFlow::Bind {
                    job_id,
                    namespace,
                    resource,
                    ..
                } => PendingFlow::Bind {
                    job_id,
                    namespace,
                    resource,
                    expires_at: 1,
                },
                other => other,
            };
            Ok((Some(f), ()))
        })
        .unwrap();
    vgi_bridge::flows::expire(&w.bridge).await;
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["outcome"], "failed");
    assert_eq!(result["payload"]["error"]["code"], "expired");
}

#[tokio::test]
async fn an_account_link_runs_the_device_flow_and_reports_the_account() {
    let mut w = world(Options::default()).await;
    let s = &w.server;
    Mock::given(method("POST"))
        .and(path("/login/device/code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "device_code": "dc-secret", "user_code": "WDJB-MJHT",
            "verification_uri": "https://github.com/login/device",
            "expires_in": 900, "interval": 1,
        })))
        .mount(s)
        .await;
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .and(body_partial_json(json!({ "device_code": "dc-secret" })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "access_token": "ghu_member" })),
        )
        .mount(s)
        .await;
    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "id": 9120045, "login": "bob-builds" })),
        )
        .mount(s)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/applications/Iv1.testclient/token"))
        .respond_with(ResponseTemplate::new(204))
        .mount(s)
        .await;

    w.send_job(json!({
        "jobId": "job_l", "namespace": NS, "kind": "beginAccountLink",
        "subject": "did:webvh:QmBob:acme-vtc.example:bob",
    }))
    .await;
    let resp = w.next().await;
    assert_eq!(resp["payload"]["accepted"], true);
    assert_eq!(
        resp["payload"]["next"]["url"],
        "https://github.com/login/device"
    );
    assert_eq!(resp["payload"]["next"]["userCode"], "WDJB-MJHT");
    assert!(
        !resp.to_string().contains("dc-secret"),
        "the device code never leaves the bridge"
    );

    let ev = w.next_of(EVENT).await;
    assert_eq!(
        ev["payload"]["event"],
        json!({ "type": "accountLinked", "jobId": "job_l",
                "account": { "forge": "github.com", "id": "9120045", "login": "bob-builds" } })
    );
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["outcome"], "succeeded");
    assert!(
        w.bridge
            .store()
            .secret_names()
            .unwrap()
            .iter()
            .all(|n| !n.starts_with("pending/")),
        "the sealed device code is gone once used"
    );
}

// ── the bridge-posted check ──────────────────────────────────────────────

fn sh(dir: &std::path::Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// A repository with a base commit and two pull-request commits.
fn pr_repo() -> (tempfile::TempDir, String, Vec<String>) {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    sh(p, &["init", "-q", "-b", "main"]);
    let mut shas = Vec::new();
    for (i, msg) in ["base", "one", "two"].iter().enumerate() {
        std::fs::write(p.join("f.txt"), format!("{i}")).unwrap();
        sh(p, &["add", "f.txt"]);
        sh(
            p,
            &[
                "-c",
                "user.name=T",
                "-c",
                "user.email=t@example.org",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "-m",
                msg,
            ],
        );
        shas.push(sh(p, &["rev-parse", "HEAD"]));
    }
    // A hook that would betray any execution of repository content.
    std::fs::write(
        p.join(".git/hooks/post-checkout"),
        "#!/bin/sh\ntouch /tmp/vgi-bridge-pwned\n",
    )
    .unwrap();
    let base = shas.remove(0);
    (dir, base, shas)
}

async fn check_world(
    trust_all: bool,
    required_workflow: bool,
) -> (World, tempfile::TempDir, Vec<String>) {
    let (repo_dir, base, pr) = pr_repo();
    let remote = url::Url::from_directory_path(repo_dir.path()).unwrap();
    let trusted = if trust_all {
        pr.clone()
    } else {
        vec![pr[0].clone()]
    };
    let w = world(Options {
        trusted,
        local_remote: Some(remote),
        required_workflow,
        ..Options::default()
    })
    .await;
    let s = &w.server;
    mount_any_token(s).await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/repos/acme/widgets/compare/{base}...{}",
            pr[1]
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total_commits": 2,
            "merge_base_commit": { "sha": base },
            "commits": [ { "sha": pr[0] }, { "sha": pr[1] } ],
        })))
        .mount(s)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/widgets/check-runs"))
        .and(body_partial_json(
            json!({ "name": "Verify commit trust", "head_sha": pr[1], "status": "in_progress" }),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 77 })))
        .mount(s)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/repos/acme/widgets/check-runs/77"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 77 })))
        .mount(s)
        .await;
    let mut pr_and_base = pr.clone();
    pr_and_base.push(base);
    (w, repo_dir, pr_and_base)
}

fn pr_event(head: &str, base: &str) -> Value {
    json!({
        "action": "synchronize",
        "repository": { "id": 812, "full_name": "acme/widgets" },
        "pull_request": { "number": 5, "commits": 2,
            "head": { "sha": head }, "base": { "sha": base } },
    })
}

#[tokio::test]
async fn the_bridge_posts_a_passing_check_for_trusted_commits() {
    let (w, _repo, shas) = check_world(true, false).await;
    let (head, base) = (shas[1].clone(), shas[2].clone());
    let s = post_webhook(
        &w,
        "pull_request",
        "pr-1",
        &pr_event(&head, &base),
        WEBHOOK_SECRET,
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let done = wait_for_request(&w.server, "the check run completes", |r| {
        r.method == http::Method::PATCH && r.url.path() == "/repos/acme/widgets/check-runs/77"
    })
    .await;
    let body: Value = serde_json::from_slice(&done.body).unwrap();
    assert_eq!(body["status"], "completed");
    assert_eq!(body["conclusion"], "success", "{body}");
    assert_eq!(
        body["output"]["title"],
        "All 2 commits are signed by trusted DIDs"
    );
    // Qualified resource, namespace as the fallback (spec PR #623).
    let seen = w.verifier.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].0,
        shas[..2].to_vec(),
        "exactly the pull request's commits"
    );
    assert_eq!(seen[0].1, "github.com/acme/widgets");
    assert_eq!(seen[0].2, "github.com/acme");
    assert!(
        !std::path::Path::new("/tmp/vgi-bridge-pwned").exists(),
        "nothing from the repository ran"
    );
}

#[tokio::test]
async fn the_bridge_posts_a_failing_check_when_a_commit_is_not_trusted() {
    let (w, _repo, shas) = check_world(false, false).await;
    let (head, base) = (shas[1].clone(), shas[2].clone());
    post_webhook(
        &w,
        "pull_request",
        "pr-2",
        &pr_event(&head, &base),
        WEBHOOK_SECRET,
    )
    .await;
    let done = wait_for_request(&w.server, "the check run completes", |r| {
        r.method == http::Method::PATCH
    })
    .await;
    let body: Value = serde_json::from_slice(&done.body).unwrap();
    assert_eq!(body["conclusion"], "failure");
    assert_eq!(body["output"]["title"], "1 of 2 commits are not trusted");
    assert!(
        body["output"]["summary"]
            .as_str()
            .unwrap()
            .contains("unauthorized")
    );
}

#[tokio::test]
async fn a_check_that_cannot_complete_fails_closed() {
    let (w, _repo, shas) = check_world(true, false).await;
    // A head the comparison does not know: the fetch or the comparison
    // fails, and the check says so rather than staying pending or passing.
    let bogus = "f".repeat(40);
    Mock::given(method("GET"))
        .and(path(format!(
            "/repos/acme/widgets/compare/{}...{bogus}",
            shas[2]
        )))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "message": "Not Found" })))
        .mount(&w.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/widgets/check-runs"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 78 })))
        .mount(&w.server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/repos/acme/widgets/check-runs/78"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 78 })))
        .mount(&w.server)
        .await;
    post_webhook(
        &w,
        "pull_request",
        "pr-3",
        &pr_event(&bogus, &shas[2]),
        WEBHOOK_SECRET,
    )
    .await;
    let done = wait_for_request(&w.server, "the check run completes", |r| {
        r.method == http::Method::PATCH && r.url.path().ends_with("/78")
    })
    .await;
    let body: Value = serde_json::from_slice(&done.body).unwrap();
    assert_eq!(body["conclusion"], "failure");
    assert_eq!(body["output"]["title"], "The commits could not be verified");
}

#[tokio::test]
async fn a_required_workflow_namespace_gets_no_bridge_check() {
    let (w, _repo, shas) = check_world(true, true).await;
    let s = post_webhook(
        &w,
        "pull_request",
        "pr-4",
        &pr_event(&shas[1], &shas[2]),
        WEBHOOK_SECRET,
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let posted = w
        .server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .any(|r| r.url.path().contains("check-runs"));
    assert!(!posted, "Actions runs the required workflow there");
}

// ── restart ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_restart_restores_pins_managed_sets_and_unfinished_jobs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");
    let vtc_seed = [3u8; 32];
    {
        let w = world(Options {
            store_path: Some(path.clone()),
            required_workflow: true,
            vtc_seed: Some(vtc_seed),
            ..Options::default()
        })
        .await;
        w.bridge
            .store()
            .update::<NamespaceRecord, _>(Table::Namespaces, NS, |n| {
                let mut n = n.unwrap();
                n.managed = BTreeSet::from([812, 813]);
                n.pin = Some(PinRecord {
                    repository_id: 5,
                    sha: "a".repeat(40),
                    check: "Verify commit trust".into(),
                });
                Ok((Some(n), ()))
            })
            .unwrap();
        // A job the process died holding.
        let mut job = JobRecord::queued(
            "job_q",
            "x",
            NS,
            "archive",
            json!({ "jobId": "job_q", "namespace": NS, "kind": "archive", "repo": "github.com/acme/old" }),
            0,
        );
        job.state = JobState::Running;
        w.bridge.store().put(Table::Jobs, "job_q", &job).unwrap();
    }

    // The same store, a new process.
    let mut w = world(Options {
        store_path: Some(path),
        required_workflow: true,
        vtc_seed: Some(vtc_seed),
        seed_namespace: false,
        ..Options::default()
    })
    .await;
    let adapter = w.bridge.adapters().get("github.com").unwrap();
    let g = adapter.github().unwrap();
    assert_eq!(
        g.managed_repositories(&acme()),
        Some(BTreeSet::from([812, 813])),
        "the managed set is back before any org step runs"
    );
    let pin = g.required_workflow_pin(&acme()).expect("the pin is back");
    assert_eq!(pin.repository_id, 5);
    let ns: NamespaceRecord = w
        .bridge
        .store()
        .get(Table::Namespaces, NS)
        .unwrap()
        .unwrap();
    let caps = adapter.forge().capabilities(&ns.binding.unwrap().namespace);
    assert!(
        caps.required_workflow,
        "required-workflow availability is back"
    );

    // The interrupted job ran again and closed with one result (the repo
    // does not exist on the mock: a failed archive, still one result).
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["jobId"], "job_q");
    let rec: JobRecord = w.bridge.store().get(Table::Jobs, "job_q").unwrap().unwrap();
    assert_eq!(rec.state, JobState::Finished);
}
