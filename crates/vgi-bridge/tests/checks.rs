//! The check the bridge posts itself: only against the protected base,
//! re-checked when the base moves or someone asks, re-processed when a post
//! failed, fetched as commit objects only — and verified by the real
//! verify-trust path.

mod common;

use std::path::Path;
use std::process::{Command, Stdio};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::*;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;
use vgi_bridge::checks::{CommitVerifier, GitFetcher, VerifyTrustVerifier};
use vgi_bridge::config::CheckConfig;
use vgi_forge_github::Secret;
use vgi_forge_github::webhook::sign_body;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── fixtures ─────────────────────────────────────────────────────────────

fn git(dir: &Path, args: &[&str]) -> String {
    git_as(dir, "t@example.org", args)
}

fn git_as(dir: &Path, committer: &str, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "T")
        .env("GIT_AUTHOR_EMAIL", "t@example.org")
        .env("GIT_COMMITTER_NAME", "T")
        .env("GIT_COMMITTER_EMAIL", committer)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// A repository with a base commit and two pull-request commits on `main`.
/// Serves partial clones (`uploadpack.allowFilter`), like GitHub.
struct PrRepo {
    dir: tempfile::TempDir,
    base: String,
    pr: Vec<String>,
}

fn pr_repo() -> PrRepo {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    git(p, &["init", "-q", "-b", "main"]);
    git(p, &["config", "uploadpack.allowFilter", "true"]);
    git(p, &["config", "uploadpack.allowAnySHA1InWant", "true"]);
    let mut shas = Vec::new();
    for (i, msg) in ["base", "one", "two"].iter().enumerate() {
        std::fs::write(p.join("f.txt"), format!("{i}")).unwrap();
        git(p, &["add", "f.txt"]);
        git(
            p,
            &["-c", "commit.gpgsign=false", "commit", "-q", "-m", msg],
        );
        shas.push(git(p, &["rev-parse", "HEAD"]));
    }
    let base = shas.remove(0);
    PrRepo {
        dir,
        base,
        pr: shas,
    }
}

impl PrRepo {
    fn head(&self) -> &str {
        &self.pr[1]
    }
    fn remote(&self) -> url::Url {
        url::Url::from_directory_path(self.dir.path()).unwrap()
    }
}

async fn post_webhook(w: &World, event: &str, delivery: &str, body: &Value) -> StatusCode {
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

fn pr_event(action: &str, head: &str, base_ref: &str, base_sha: &str) -> Value {
    json!({
        "action": action,
        "repository": { "id": 812, "full_name": "acme/widgets" },
        "pull_request": { "number": 5, "head": { "sha": head },
                          "base": { "ref": base_ref, "sha": base_sha } },
    })
}

/// A bridge that posts checks on `acme/widgets` (default branch `main`),
/// fetching from `repo`. The pull request API answers per `pr` (head, base
/// ref, base sha); the comparison per the repository's own history.
async fn check_world(repo: &PrRepo, trusted: Vec<String>) -> World {
    let w = world(Options {
        trusted,
        local_remote: Some(repo.remote()),
        ..Options::default()
    })
    .await;
    let s = &w.server;
    mount_any_token(s).await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 812, "full_name": "acme/widgets", "default_branch": "main",
        })))
        .mount(s)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/repos/acme/widgets/compare/{}...{}",
            repo.base,
            repo.head()
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total_commits": 2,
            "merge_base_commit": { "sha": repo.base },
            "commits": [ { "sha": repo.pr[0] }, { "sha": repo.pr[1] } ],
        })))
        .mount(s)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/widgets/check-runs"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 77 })))
        .mount(s)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/repos/acme/widgets/check-runs/77"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 77 })))
        .mount(s)
        .await;
    w
}

/// The pull request API's answer for PR 5, the next `times` reads.
async fn mount_pr(w: &World, head: &str, base_ref: &str, base_sha: &str, times: u64) {
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/pulls/5"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "state": "open", "head": { "sha": head },
            "base": { "ref": base_ref, "sha": base_sha },
        })))
        .up_to_n_times(times)
        .mount(&w.server)
        .await;
}

// ── only against the protected base ──────────────────────────────────────

#[tokio::test]
async fn trusted_commits_into_the_default_branch_get_a_success() {
    let repo = pr_repo();
    let w = check_world(&repo, repo.pr.clone()).await;
    mount_pr(&w, repo.head(), "main", &repo.base, 10).await;
    let s = post_webhook(
        &w,
        "pull_request",
        "d-1",
        &pr_event("synchronize", repo.head(), "main", &repo.base),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    wait_delivery(&w, "d-1").await;
    let started = posted_checks(&w.server).await;
    assert_eq!(started.len(), 1);
    assert_eq!(started[0]["name"], "Verify commit trust", "the fixed name");
    assert_eq!(
        started[0]["external_id"],
        format!("main@{}", repo.head()),
        "keyed by base and head"
    );
    let done = completed_checks(&w.server).await;
    assert_eq!(done[0]["conclusion"], "success", "{}", done[0]);
    // Qualified resource, namespace as the fallback (spec PR #623).
    let seen = w.verifier.seen.lock().unwrap().clone();
    assert_eq!(seen[0].0, repo.pr);
    assert_eq!(seen[0].1, "github.com/acme/widgets");
    assert_eq!(seen[0].2, "github.com/acme");
}

#[tokio::test]
async fn an_untrusted_commit_fails_the_check() {
    let repo = pr_repo();
    let w = check_world(&repo, vec![repo.pr[0].clone()]).await;
    mount_pr(&w, repo.head(), "main", &repo.base, 10).await;
    post_webhook(
        &w,
        "pull_request",
        "d-1",
        &pr_event("opened", repo.head(), "main", &repo.base),
    )
    .await;
    wait_delivery(&w, "d-1").await;
    let done = completed_checks(&w.server).await;
    assert_eq!(done[0]["conclusion"], "failure");
    assert_eq!(done[0]["output"]["title"], "1 of 2 commits are not trusted");
}

/// The carry-over attack: `b → a` where `a` is not protected. A success on
/// the head would count for `b → main` too, so nothing is posted at all —
/// and when the base later moves to `main`, the check runs against `main`.
#[tokio::test]
async fn an_unprotected_base_gets_nothing_and_a_move_to_main_is_checked() {
    let repo = pr_repo();
    let w = check_world(&repo, repo.pr.clone()).await;
    // The delivery says `main`, but GitHub says the PR targets `feature`:
    // GitHub wins.
    mount_pr(&w, repo.head(), "feature", repo.head(), 1).await;
    post_webhook(
        &w,
        "pull_request",
        "d-1",
        &pr_event("opened", repo.head(), "main", &repo.base),
    )
    .await;
    wait_delivery(&w, "d-1").await;
    assert!(
        posted_checks(&w.server).await.is_empty(),
        "no check run for an unprotected base"
    );

    // A title edit is nothing; a base edit is a new check against the new
    // base — not dropped as "the same head already handled".
    let mut title = pr_event("edited", repo.head(), "main", &repo.base);
    title["changes"] = json!({ "title": { "from": "x" } });
    assert_eq!(
        post_webhook(&w, "pull_request", "d-2", &title).await,
        StatusCode::NO_CONTENT
    );
    mount_pr(&w, repo.head(), "main", &repo.base, 10).await;
    let mut moved = pr_event("edited", repo.head(), "main", &repo.base);
    moved["changes"] = json!({ "base": { "ref": { "from": "feature" } } });
    post_webhook(&w, "pull_request", "d-3", &moved).await;
    wait_delivery(&w, "d-3").await;
    let started = posted_checks(&w.server).await;
    assert_eq!(started.len(), 1);
    assert_eq!(started[0]["external_id"], format!("main@{}", repo.head()));
    assert_eq!(
        completed_checks(&w.server).await[0]["conclusion"],
        "success"
    );
}

#[tokio::test]
async fn a_merge_group_into_another_branch_gets_nothing() {
    let repo = pr_repo();
    let w = check_world(&repo, repo.pr.clone()).await;
    let group = |base_ref: &str| {
        json!({
            "action": "checks_requested",
            "repository": { "id": 812, "full_name": "acme/widgets" },
            "merge_group": { "head_sha": repo.head(), "base_sha": repo.base, "base_ref": base_ref },
        })
    };
    post_webhook(&w, "merge_group", "g-1", &group("refs/heads/release")).await;
    wait_delivery(&w, "g-1").await;
    assert!(posted_checks(&w.server).await.is_empty());
    post_webhook(&w, "merge_group", "g-2", &group("refs/heads/main")).await;
    wait_delivery(&w, "g-2").await;
    assert_eq!(posted_checks(&w.server).await.len(), 1);
}

#[tokio::test]
async fn a_pull_request_that_moved_on_is_left_to_its_newer_delivery() {
    let repo = pr_repo();
    let w = check_world(&repo, repo.pr.clone()).await;
    // GitHub's head is newer than the delivery's.
    mount_pr(&w, &repo.pr[0], "main", &repo.base, 10).await;
    post_webhook(
        &w,
        "pull_request",
        "d-1",
        &pr_event("synchronize", repo.head(), "main", &repo.base),
    )
    .await;
    wait_delivery(&w, "d-1").await;
    assert!(posted_checks(&w.server).await.is_empty());
}

/// An empty comparison against `main`: the head is already in `main`. Only
/// the tip itself is a success; a commit strictly inside `main` is not.
#[tokio::test]
async fn an_empty_range_is_a_success_only_at_the_base_tip() {
    let repo = pr_repo();
    let w = check_world(&repo, vec![]).await;
    let tip = repo.head().to_string();
    let inside = repo.pr[0].clone();
    for (head, base_sha) in [(&tip, &tip), (&inside, &tip)] {
        Mock::given(method("GET"))
            .and(path(format!(
                "/repos/acme/widgets/compare/{base_sha}...{head}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total_commits": 0, "merge_base_commit": { "sha": head }, "commits": [],
            })))
            .mount(&w.server)
            .await;
    }
    let group = |head: &str, base: &str| {
        json!({
            "action": "checks_requested",
            "repository": { "id": 812, "full_name": "acme/widgets" },
            "merge_group": { "head_sha": head, "base_sha": base, "base_ref": "refs/heads/main" },
        })
    };
    post_webhook(&w, "merge_group", "e-1", &group(&tip, &tip)).await;
    wait_delivery(&w, "e-1").await;
    post_webhook(&w, "merge_group", "e-2", &group(&inside, &tip)).await;
    wait_delivery(&w, "e-2").await;
    let done = completed_checks(&w.server).await;
    assert_eq!(done[0]["conclusion"], "success", "{}", done[0]);
    assert_eq!(done[1]["conclusion"], "failure", "{}", done[1]);
    assert!(
        w.verifier.seen.lock().unwrap().is_empty(),
        "nothing to verify"
    );
}

// ── re-running and redelivery ────────────────────────────────────────────

#[tokio::test]
async fn a_rerequest_runs_the_check_again() {
    let repo = pr_repo();
    let w = check_world(&repo, repo.pr.clone()).await;
    mount_pr(&w, repo.head(), "main", &repo.base, 10).await;
    let rerun = json!({
        "action": "rerequested",
        "repository": { "id": 812, "full_name": "acme/widgets" },
        "check_run": { "head_sha": repo.head(), "app": { "id": APP_ID },
            "pull_requests": [ { "number": 5,
                "base": { "ref": "main", "sha": repo.base }, "head": { "sha": repo.head() } } ] },
    });
    post_webhook(&w, "check_run", "r-1", &rerun).await;
    wait_delivery(&w, "r-1").await;
    assert_eq!(posted_checks(&w.server).await.len(), 1);
    let suite = json!({
        "action": "rerequested",
        "repository": { "id": 812, "full_name": "acme/widgets" },
        "check_suite": { "head_sha": repo.head(), "app": { "id": APP_ID },
            "pull_requests": [ { "number": 5,
                "base": { "ref": "main", "sha": repo.base }, "head": { "sha": repo.head() } } ] },
    });
    post_webhook(&w, "check_suite", "r-2", &suite).await;
    wait_delivery(&w, "r-2").await;
    assert_eq!(posted_checks(&w.server).await.len(), 2);
}

#[tokio::test]
async fn a_delivery_whose_check_failed_to_post_is_processed_again() {
    let repo = pr_repo();
    let w = world(Options {
        trusted: repo.pr.clone(),
        local_remote: Some(repo.remote()),
        ..Options::default()
    })
    .await;
    mount_any_token(&w.server).await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 812, "full_name": "acme/widgets", "default_branch": "main" })))
        .mount(&w.server)
        .await;
    mount_pr(&w, repo.head(), "main", &repo.base, 10).await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/repos/acme/widgets/compare/{}...{}",
            repo.base,
            repo.head()
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total_commits": 2, "merge_base_commit": { "sha": repo.base },
            "commits": [ { "sha": repo.pr[0] }, { "sha": repo.pr[1] } ] })))
        .mount(&w.server)
        .await;
    // GitHub fails the first post.
    Mock::given(method("POST"))
        .and(path("/repos/acme/widgets/check-runs"))
        .respond_with(ResponseTemplate::new(502))
        .up_to_n_times(1)
        .mount(&w.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/widgets/check-runs"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 77 })))
        .mount(&w.server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/repos/acme/widgets/check-runs/77"))
        .and(body_partial_json(json!({ "conclusion": "success" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 77 })))
        .expect(1)
        .mount(&w.server)
        .await;
    let ev = pr_event("opened", repo.head(), "main", &repo.base);
    post_webhook(&w, "pull_request", "d-1", &ev).await;
    // The failed attempt is not recorded as handled…
    for _ in 0..100 {
        if !posted_checks(&w.server).await.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        w.bridge
            .store()
            .get::<i64>(vgi_bridge::store::Table::Deliveries, "github.com#d-1")
            .unwrap()
            .is_none()
    );
    // …so GitHub's redelivery runs it, and then it is.
    assert_eq!(
        post_webhook(&w, "pull_request", "d-1", &ev).await,
        StatusCode::ACCEPTED
    );
    wait_delivery(&w, "d-1").await;
    assert_eq!(
        post_webhook(&w, "pull_request", "d-1", &ev).await,
        StatusCode::OK,
        "handled once it succeeded"
    );
}

#[tokio::test]
async fn a_required_workflow_namespace_or_an_unready_installation_gets_no_bridge_check() {
    let repo = pr_repo();
    for (required_workflow, ready) in [(true, Some(true)), (false, Some(false)), (false, None)] {
        let w = world(Options {
            required_workflow,
            local_remote: Some(repo.remote()),
            seed_namespace: false,
            ..Options::default()
        })
        .await;
        seed_namespace_ready(
            w.bridge.store(),
            vgi_forge::NamespaceKind::Organization,
            required_workflow,
            ready,
        );
        // The world restored before this seed; restore again with it.
        let adapter = w.bridge.adapters().get("github.com").unwrap();
        let rec = w
            .bridge
            .store()
            .get::<vgi_bridge::store::NamespaceRecord>(vgi_bridge::store::Table::Namespaces, NS)
            .unwrap()
            .unwrap();
        adapter.restore(&rec).unwrap();
        mount_any_token(&w.server).await;
        post_webhook(
            &w,
            "pull_request",
            "d-1",
            &pr_event("opened", repo.head(), "main", &repo.base),
        )
        .await;
        wait_delivery(&w, "d-1").await;
        assert!(
            posted_checks(&w.server).await.is_empty(),
            "{required_workflow} {ready:?}"
        );
    }
}

// ── the fetch ────────────────────────────────────────────────────────────

/// The fetch brings commit objects and nothing else: no working tree and no
/// tree objects, so there is nothing that could be checked out or run.
/// Falsifiable: a fetcher that cloned, checked out, or fetched without the
/// filter leaves the head's tree in the repository.
#[tokio::test]
async fn the_fetch_brings_commits_only() {
    let repo = pr_repo();
    let f = GitFetcher::new(&CheckConfig::default()).with_local_remote(repo.remote());
    let fetched = f
        .fetch(&repo.remote(), None, repo.head(), &repo.pr)
        .await
        .unwrap();
    assert_eq!(
        fetched
            .commits
            .iter()
            .map(|c| c.sha.clone())
            .collect::<Vec<_>>(),
        repo.pr
    );
    let tree = git(
        repo.dir.path(),
        &["rev-parse", &format!("{}^{{tree}}", repo.head())],
    );
    let has_tree = Command::new("git")
        .arg("-C")
        .arg(fetched.dir.path())
        .args(["cat-file", "-e", &tree])
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success();
    assert!(!has_tree, "the head's tree was fetched");
    assert!(
        !fetched.dir.path().join("f.txt").exists(),
        "nothing was checked out"
    );
    assert!(
        fetched.dir.path().join("objects").is_dir(),
        "a bare repository"
    );
}

#[tokio::test]
async fn a_fetch_past_the_byte_bound_is_stopped() {
    let repo = pr_repo();
    let mut cfg = CheckConfig::default();
    cfg.max_fetch_bytes = 1;
    let f = GitFetcher::new(&cfg).with_local_remote(repo.remote());
    let e = f
        .fetch(&repo.remote(), None, repo.head(), &repo.pr)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("bytes"), "{e}");
}

// ── the real verify-trust path ───────────────────────────────────────────

/// Serve the registry's `POST /trust-tasks`: `authorized` exactly for the
/// `(entity, resource)` grants.
async fn stub_registry(grants: Vec<(String, String)>) -> String {
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

/// A did:key and a commit it signed (sshsig, committer = the DID's key).
fn signed_commit(repo: &Path, key: &SigningKey, msg: &str) -> (String, String) {
    let public = key.verifying_key().to_bytes();
    let mb = vta_sdk::did_key::ed25519_multibase_pubkey(&public);
    let did = format!("did:key:{mb}");
    let vm = format!("{did}#{mb}");
    std::fs::write(repo.join("f.txt"), msg).unwrap();
    git_as(repo, &vm, &["add", "f.txt"]);
    git_as(
        repo,
        &vm,
        &["-c", "commit.gpgsign=false", "commit", "-q", "-m", msg],
    );
    let unsigned = git(repo, &["rev-parse", "HEAD"]);
    let payload = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["cat-file", "commit", &unsigned])
        .output()
        .unwrap()
        .stdout;
    let armored = vgi_core::create_ssh_signature(
        key,
        &key.verifying_key(),
        vgi_core::GIT_SSHSIG_NAMESPACE,
        &payload,
    )
    .unwrap();
    let text = String::from_utf8(payload).unwrap();
    let (headers, body) = text.split_once("\n\n").unwrap();
    let mut sig = String::from("gpgsig ");
    let mut lines = armored.trim_end().split('\n');
    sig.push_str(lines.next().unwrap());
    for l in lines {
        sig.push_str("\n ");
        sig.push_str(l);
    }
    let signed = format!("{headers}\n{sig}\n\n{body}");
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["hash-object", "-t", "commit", "-w", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(signed.as_bytes())
            .unwrap();
    }
    let sha = String::from_utf8(child.wait_with_output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_string();
    git(repo, &["update-ref", "refs/heads/main", &sha]);
    (did, sha)
}

/// The verifier the bridge runs in production — DID resolution (did:key),
/// signature checks, the registry query with the namespace as fallback —
/// against real signed commits fetched by the real fetcher; only the
/// registry is a local stub.
#[tokio::test]
async fn the_real_verifier_trusts_a_namespace_grant_and_refuses_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    git(p, &["init", "-q", "-b", "main"]);
    git(p, &["config", "uploadpack.allowFilter", "true"]);
    git(p, &["config", "uploadpack.allowAnySHA1InWant", "true"]);
    std::fs::write(p.join("f.txt"), "base").unwrap();
    git(p, &["add", "f.txt"]);
    git(
        p,
        &["-c", "commit.gpgsign=false", "commit", "-q", "-m", "base"],
    );
    let alice = SigningKey::from_bytes(&[1u8; 32]);
    let mallory = SigningKey::from_bytes(&[2u8; 32]);
    let (alice_did, c1) = signed_commit(p, &alice, "one");
    let (_, c2) = signed_commit(p, &mallory, "two");

    // Alice holds git.commit.sign on the namespace only (git.ns.admin's
    // implied grant, spec PR #623); Mallory holds nothing.
    let registry = stub_registry(vec![(alice_did.clone(), "github.com/acme".into())]).await;
    let server = MockServer::start().await;
    let cfg = config(
        &server,
        dir.path(),
        "did:webvh:QmVtc:acme-vtc.example",
        // No web-flow keyring: optional, and not needed for DID-signed commits.
        &Options {
            keyring: false,
            ..Options::default()
        },
    );
    let verifier = VerifyTrustVerifier::new(&cfg).with_registry_url(registry);
    let remote = url::Url::from_directory_path(p).unwrap();
    let fetched = GitFetcher::new(&cfg.checks)
        .with_local_remote(remote.clone())
        .fetch(&remote, None, &c2, &[c1.clone(), c2.clone()])
        .await
        .unwrap();
    let lines = verifier
        .verify(
            &fetched.commits,
            "github.com/acme/widgets",
            "github.com/acme",
        )
        .await
        .unwrap();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].passes, "{:?}", lines[0]);
    assert_eq!(lines[0].verdict, "trusted");
    assert!(!lines[1].passes);
    assert_eq!(lines[1].verdict, "unauthorized");

    // Without the fallback, Alice's namespace grant does not count.
    let lines = verifier
        .verify(
            &fetched.commits[..1],
            "github.com/acme/widgets",
            "github.com/acme/widgets",
        )
        .await
        .unwrap();
    assert!(!lines[0].passes);
}
