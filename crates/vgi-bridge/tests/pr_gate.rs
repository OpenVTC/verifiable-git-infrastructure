//! The pull-request gate against the fake VTC and a mock GitHub:
//! `pull_request` webhooks reported as `pullRequestOpened`
//! (`git-ns/bridge/event` 0.4), and `closePullRequest` jobs
//! (`git-ns/bridge/job` 0.5) carried out idempotently.

mod common;

use axum::http::StatusCode;
use chrono::Utc;
use common::*;
use serde_json::{Value, json};
use vgi_bridge::store::{NamespaceRecord, OutboxEntry, Table};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const EVENT_0_4: &str = "https://trusttasks.org/spec/git-ns/bridge/event/0.4";
const WIDGETS_ID: u64 = 812;
const OWN_BOT: &str = "acme-vgi-bridge[bot]";

/// A world that sends event 0.4, with `acme/widgets` managed. The
/// bridge-posted check is off: these tests watch the gate, not the check.
async fn gate_world(event_version: Option<&'static str>) -> World {
    let w = world(Options {
        event_version,
        bridge_checks: false,
        ..Options::default()
    })
    .await;
    seed_repo(w.bridge.store(), &repo("widgets"), WIDGETS_ID);
    w
}

fn pr_delivery(action: &str, head_repo: Value, draft: bool, sender: (u64, &str)) -> Value {
    json!({
        "action": action,
        "number": 42,
        "pull_request": {
            "number": 42,
            "state": "open",
            "draft": draft,
            "title": "a title that must never leave the bridge",
            "body": "a body that must never leave the bridge",
            "user": { "id": 5550123, "login": "eve-dev" },
            "head": { "ref": "secret-branch-name", "sha": "a".repeat(40), "repo": head_repo },
            "base": { "ref": "main", "sha": "b".repeat(40),
                      "repo": { "id": WIDGETS_ID, "full_name": "acme/widgets" } },
        },
        "repository": { "id": WIDGETS_ID, "full_name": "acme/widgets" },
        "sender": { "id": sender.0, "login": sender.1 },
    })
}

fn same_repo() -> Value {
    json!({ "id": WIDGETS_ID, "full_name": "acme/widgets" })
}

fn fork() -> Value {
    json!({ "id": 7001, "full_name": "eve-dev/widgets" })
}

/// Events not yet acknowledged.
fn open_events(w: &World) -> usize {
    w.bridge
        .store()
        .list::<OutboxEntry>(Table::Outbox)
        .unwrap()
        .into_iter()
        .filter(|(k, _)| k.starts_with("event:"))
        .count()
}

// ── events ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_opened_pull_request_is_reported_as_pull_request_opened() {
    let mut w = gate_world(Some("0.4")).await;
    let s = post_webhook(
        &w,
        "pull_request",
        "pr-1",
        &pr_delivery("opened", fork(), false, (5550123, "eve-dev")),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let ev = w.next_of(EVENT_0_4).await;
    assert_eq!(ev["payload"]["namespace"], NS);
    assert_eq!(
        ev["payload"]["event"],
        json!({
            "type": "pullRequestOpened",
            "forgeId": "812",
            "resource": "github.com/acme/widgets",
            "number": 42,
            "action": "opened",
            "author": { "forge": "github.com", "id": "5550123", "login": "eve-dev" },
            "actor": { "forge": "github.com", "id": "5550123", "login": "eve-dev" },
            "draft": false,
            "fromFork": true,
        })
    );
    // A valid 0.4 payload, and nothing of what the pull request contains.
    serde_json::from_value::<vgi_bridge::wire::event::Payload>(ev["payload"].clone())
        .expect("a 0.4 payload");
    let text = ev.to_string();
    for secret in ["a title", "a body", "secret-branch-name"] {
        assert!(!text.contains(secret), "{secret} leaked: {text}");
    }
    w.ack_event(&ev).await;
    assert_eq!(open_events(&w), 0);

    // GitHub redelivers: reported once.
    post_webhook(
        &w,
        "pull_request",
        "pr-1",
        &pr_delivery("opened", fork(), false, (5550123, "eve-dev")),
    )
    .await;
    w.quiet().await;
}

#[tokio::test]
async fn a_reopen_reports_who_reopened_it_and_a_draft_from_the_same_repository() {
    let mut w = gate_world(Some("0.4")).await;
    post_webhook(
        &w,
        "pull_request",
        "pr-2",
        &pr_delivery("reopened", same_repo(), true, (4410987, "alice-acme")),
    )
    .await;
    let ev = w.next_of(EVENT_0_4).await;
    let e = &ev["payload"]["event"];
    assert_eq!(e["action"], "reopened");
    assert_eq!(e["author"]["login"], "eve-dev");
    // The actor is GitHub's record of who reopened it, not the author.
    assert_eq!(
        e["actor"],
        json!({ "forge": "github.com", "id": "4410987", "login": "alice-acme" })
    );
    assert_eq!(e["draft"], true);
    assert_eq!(e["fromFork"], false);
}

#[tokio::test]
async fn other_actions_and_unmanaged_or_foreign_repositories_are_not_reported() {
    let mut w = gate_world(Some("0.4")).await;
    for (i, action) in ["synchronize", "edited", "closed", "labeled"]
        .iter()
        .enumerate()
    {
        post_webhook(
            &w,
            "pull_request",
            &format!("other-{i}"),
            &pr_delivery(action, fork(), false, (5550123, "eve-dev")),
        )
        .await;
    }
    // A repository the namespace does not manage.
    let mut unmanaged = pr_delivery("opened", fork(), false, (5550123, "eve-dev"));
    unmanaged["repository"] = json!({ "id": 999, "full_name": "acme/gadgets" });
    post_webhook(&w, "pull_request", "unmanaged", &unmanaged).await;
    // Another organisation's repository, on this App's route.
    let mut elsewhere = pr_delivery("opened", fork(), false, (5550123, "eve-dev"));
    elsewhere["repository"] = json!({ "id": WIDGETS_ID, "full_name": "evil/widgets" });
    post_webhook(&w, "pull_request", "elsewhere", &elsewhere).await;
    w.quiet().await;
}

#[tokio::test]
async fn the_same_delivery_still_prompts_the_bridge_posted_check() {
    // With the bridge-posted check on, an opening is both reported and
    // checked: the report takes nothing from the check's handling.
    let mut w = world(Options {
        event_version: Some("0.4"),
        ..Options::default()
    })
    .await;
    seed_repo(w.bridge.store(), &repo("widgets"), WIDGETS_ID);
    mount_any_token(&w.server).await;
    post_webhook(
        &w,
        "pull_request",
        "pr-check",
        &pr_delivery("opened", fork(), false, (5550123, "eve-dev")),
    )
    .await;
    let ev = w.next_of(EVENT_0_4).await;
    assert_eq!(ev["payload"]["event"]["type"], "pullRequestOpened");
    // The check runner reads the pull request back from GitHub.
    wait_for_request(&w.server, "the check reads the pull request", |r| {
        r.url.path().starts_with("/repos/acme/widgets")
    })
    .await;
}

#[tokio::test]
async fn below_event_0_4_no_pull_request_is_reported() {
    // The default (0.3): a VTC that has not listed 0.4 is told of no pull
    // requests, under any type.
    let mut w = gate_world(None).await;
    let s = post_webhook(
        &w,
        "pull_request",
        "pr-3",
        &pr_delivery("opened", fork(), false, (5550123, "eve-dev")),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    w.quiet().await;
    assert_eq!(open_events(&w), 0);
}

// ── jobs ─────────────────────────────────────────────────────────────────

fn close_job(job_id: &str) -> Value {
    json!({
        "jobId": job_id,
        "namespace": NS,
        "kind": "closePullRequest",
        "repo": "github.com/acme/widgets",
        "number": 42,
        "message": "Pull requests here are open to the community's committers only.",
    })
}

async fn send_close(w: &World, job_id: &str) -> Value {
    let doc = w.doc(JOB_0_5, close_job(job_id), None).await;
    w.deliver(doc.clone()).await;
    doc
}

/// `GET /repos/acme/widgets/pulls/42` answers `state` (merged when `merged`).
async fn mount_pull(server: &MockServer, state: &str, merged: bool) {
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/pulls/42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "number": 42, "state": state, "merged": merged,
            "merged_at": if merged { json!("2026-10-07T15:00:00Z") } else { Value::Null },
        })))
        .mount(server)
        .await;
}

async fn mount_events(server: &MockServer, events: Value) {
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/issues/42/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(events))
        .mount(server)
        .await;
}

async fn mount_comments(server: &MockServer, comments: Value) {
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/issues/42/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(comments))
        .mount(server)
        .await;
}

async fn mount_writes(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/repos/acme/widgets/issues/42/comments"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 1 })))
        .mount(server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/repos/acme/widgets/pulls/42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "state": "closed" })))
        .mount(server)
        .await;
}

async fn requests(server: &MockServer, m: http::Method, p: &str) -> Vec<Value> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.method == m && r.url.path() == p)
        .map(|r| serde_json::from_slice(&r.body).unwrap_or(Value::Null))
        .collect()
}

async fn comments_posted(server: &MockServer) -> Vec<Value> {
    requests(
        server,
        http::Method::POST,
        "/repos/acme/widgets/issues/42/comments",
    )
    .await
}

async fn closes(server: &MockServer) -> Vec<Value> {
    requests(server, http::Method::PATCH, "/repos/acme/widgets/pulls/42").await
}

fn steps(result: &Value) -> Vec<(String, String)> {
    result["payload"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["step"].as_str().unwrap().to_string(),
                s["outcome"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn pair(a: &str, b: &str) -> (String, String) {
    (a.to_string(), b.to_string())
}

#[tokio::test]
async fn an_open_pull_request_is_commented_on_then_closed() {
    let mut w = gate_world(None).await;
    mount_any_token(&w.server).await;
    mount_pull(&w.server, "open", false).await;
    mount_events(&w.server, json!([])).await;
    mount_comments(&w.server, json!([])).await;
    mount_writes(&w.server).await;

    send_close(&w, "job_close_1").await;
    let ack = w.next().await;
    assert_eq!(ack["type"], format!("{JOB_0_5}#response"));
    assert_eq!(ack["payload"]["accepted"], true);
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["outcome"], "succeeded", "{result}");
    assert_eq!(
        steps(&result),
        vec![pair("comment", "applied"), pair("close", "applied")]
    );
    assert_eq!(
        result["payload"]["repo"],
        json!({ "resource": "github.com/acme/widgets", "forgeId": "812" })
    );

    // The message verbatim, with the hidden marker naming the job.
    let posted = comments_posted(&w.server).await;
    assert_eq!(posted.len(), 1);
    assert_eq!(
        posted[0]["body"],
        "Pull requests here are open to the community's committers only.\n\n\
         <!-- vgi-bridge job:job_close_1 -->"
    );
    assert_eq!(closes(&w.server).await, vec![json!({ "state": "closed" })]);
}

#[tokio::test]
async fn an_already_closed_or_merged_pull_request_is_left_alone() {
    for (state, merged) in [("closed", false), ("closed", true)] {
        let mut w = gate_world(None).await;
        mount_any_token(&w.server).await;
        mount_pull(&w.server, state, merged).await;
        mount_writes(&w.server).await;

        send_close(&w, "job_close_2").await;
        let result = w.next_of(RESULT).await;
        assert_eq!(result["payload"]["outcome"], "succeeded", "{result}");
        assert_eq!(
            steps(&result),
            vec![pair("comment", "unchanged"), pair("close", "unchanged")]
        );
        assert!(comments_posted(&w.server).await.is_empty(), "no comment");
        assert!(closes(&w.server).await.is_empty());
    }
}

#[tokio::test]
async fn a_rerun_finds_its_own_comment_and_does_not_comment_twice() {
    // An earlier run of this job (before a restart) posted the comment and
    // did not get to close: the re-run reports `comment` unchanged and
    // closes. A comment by someone else carrying the marker does not count.
    let mut w = gate_world(None).await;
    mount_any_token(&w.server).await;
    mount_pull(&w.server, "open", false).await;
    mount_events(&w.server, json!([])).await;
    mount_comments(
        &w.server,
        json!([
            { "id": 1, "user": { "id": 5550123, "login": "eve-dev" },
              "body": "spoofed <!-- vgi-bridge job:job_close_3 -->" },
            { "id": 2, "user": { "id": 90001, "login": OWN_BOT },
              "performed_via_github_app": { "id": APP_ID },
              "body": "Pull requests here are … only.\n\n<!-- vgi-bridge job:job_close_3 -->" },
        ]),
    )
    .await;
    mount_writes(&w.server).await;

    send_close(&w, "job_close_3").await;
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["outcome"], "succeeded", "{result}");
    assert_eq!(
        steps(&result),
        vec![pair("comment", "unchanged"), pair("close", "applied")]
    );
    assert!(comments_posted(&w.server).await.is_empty());
    assert_eq!(closes(&w.server).await.len(), 1);
}

#[tokio::test]
async fn only_the_bridges_own_comment_for_this_job_counts() {
    // Someone else's comment with the marker, and the bridge's own comment
    // for another job: neither stops the comment.
    let mut w = gate_world(None).await;
    mount_any_token(&w.server).await;
    mount_pull(&w.server, "open", false).await;
    mount_events(&w.server, json!([])).await;
    mount_comments(
        &w.server,
        json!([
            { "id": 1, "user": { "id": 5550123, "login": "eve-dev" },
              "body": "<!-- vgi-bridge job:job_close_4 -->" },
            { "id": 2, "user": { "id": 90001, "login": OWN_BOT },
              "body": "<!-- vgi-bridge job:job_other -->" },
        ]),
    )
    .await;
    mount_writes(&w.server).await;
    send_close(&w, "job_close_4").await;
    let result = w.next_of(RESULT).await;
    assert_eq!(
        steps(&result),
        vec![pair("comment", "applied"), pair("close", "applied")]
    );
    assert_eq!(comments_posted(&w.server).await.len(), 1);
}

#[tokio::test]
async fn a_reopen_by_someone_else_after_the_job_was_issued_wins() {
    let mut w = gate_world(None).await;
    mount_any_token(&w.server).await;
    mount_pull(&w.server, "open", false).await;
    let later = (Utc::now() + chrono::TimeDelta::seconds(60)).to_rfc3339();
    let earlier = (Utc::now() - chrono::TimeDelta::seconds(600)).to_rfc3339();
    mount_events(
        &w.server,
        json!([
            { "event": "closed", "actor": { "id": 90001, "login": OWN_BOT },
              "created_at": earlier },
            // The owner's override, after the VTC issued the job.
            { "event": "reopened", "actor": { "id": 4410987, "login": "alice-acme" },
              "created_at": later },
        ]),
    )
    .await;
    mount_comments(&w.server, json!([])).await;
    mount_writes(&w.server).await;

    send_close(&w, "job_close_5").await;
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["outcome"], "succeeded", "{result}");
    assert_eq!(
        steps(&result),
        vec![pair("comment", "unchanged"), pair("close", "unchanged")]
    );
    let detail = result["payload"]["steps"][1]["detail"].as_str().unwrap();
    assert!(detail.contains("alice-acme"), "{detail}");
    assert!(comments_posted(&w.server).await.is_empty());
    assert!(closes(&w.server).await.is_empty());
}

#[tokio::test]
async fn a_reopen_before_the_job_or_by_the_bridge_itself_does_not_stop_it() {
    let mut w = gate_world(None).await;
    mount_any_token(&w.server).await;
    mount_pull(&w.server, "open", false).await;
    let later = (Utc::now() + chrono::TimeDelta::seconds(60)).to_rfc3339();
    let earlier = (Utc::now() - chrono::TimeDelta::seconds(600)).to_rfc3339();
    mount_events(
        &w.server,
        json!([
            { "event": "reopened", "actor": { "id": 4410987, "login": "alice-acme" },
              "created_at": earlier },
            { "event": "reopened", "actor": { "id": 90001, "login": OWN_BOT },
              "performed_via_github_app": { "id": APP_ID }, "created_at": later },
        ]),
    )
    .await;
    mount_comments(&w.server, json!([])).await;
    mount_writes(&w.server).await;
    send_close(&w, "job_close_6").await;
    let result = w.next_of(RESULT).await;
    assert_eq!(
        steps(&result),
        vec![pair("comment", "applied"), pair("close", "applied")]
    );
}

#[tokio::test]
async fn without_pull_requests_write_the_job_is_forbidden_and_the_permission_missing() {
    let mut w = gate_world(None).await;
    // The installation approved Pull requests at read only: GitHub refuses a
    // token that asks for write.
    Mock::given(method("POST"))
        .and(path(format!(
            "/app/installations/{INSTALLATION}/access_tokens"
        )))
        .and(body_partial_json(
            json!({ "permissions": { "pull_requests": "write" } }),
        ))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "message": "The permissions requested are not granted to this installation.",
        })))
        .with_priority(1)
        .mount(&w.server)
        .await;
    mount_any_token(&w.server).await;
    Mock::given(method("GET"))
        .and(path(format!("/app/installations/{INSTALLATION}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": INSTALLATION,
            "account": { "id": 500, "login": "acme", "type": "Organization" },
            "permissions": {
                "administration": "write", "contents": "write", "actions_variables": "write",
                "checks": "write", "pull_requests": "read", "merge_queues": "read",
                "metadata": "read", "members": "read", "organization_administration": "write",
            },
            "events": vgi_forge_github::manifest::APP_EVENTS,
        })))
        .mount(&w.server)
        .await;
    mount_pull(&w.server, "open", false).await;
    mount_events(&w.server, json!([])).await;
    mount_comments(&w.server, json!([])).await;
    mount_writes(&w.server).await;

    send_close(&w, "job_close_7").await;
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["outcome"], "failed", "{result}");
    assert_eq!(
        steps(&result),
        vec![pair("comment", "failed"), pair("close", "skipped")]
    );
    assert_eq!(result["payload"]["error"]["code"], "forbidden");
    assert!(comments_posted(&w.server).await.is_empty());
    // The installation was read again, and says what it lacks.
    let ns: NamespaceRecord = w
        .bridge
        .store()
        .get(Table::Namespaces, NS)
        .unwrap()
        .unwrap();
    assert_eq!(
        ns.binding.unwrap().missing_permissions,
        vec!["pull_requests:write".to_string()]
    );
    let status = &result["payload"]["ext"]["org.openvtc.git-ns"]["namespace"];
    assert_eq!(status["missingPermissions"], json!(["pull_requests:write"]));
}

#[tokio::test]
async fn a_pull_request_that_does_not_exist_is_not_found() {
    let mut w = gate_world(None).await;
    mount_any_token(&w.server).await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/pulls/42"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "message": "Not Found" })))
        .mount(&w.server)
        .await;
    send_close(&w, "job_close_8").await;
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["outcome"], "failed");
    assert_eq!(result["payload"]["error"]["code"], "notFound");
}

#[tokio::test]
async fn a_close_that_fails_after_the_comment_is_partial() {
    let mut w = gate_world(None).await;
    mount_any_token(&w.server).await;
    mount_pull(&w.server, "open", false).await;
    mount_events(&w.server, json!([])).await;
    mount_comments(&w.server, json!([])).await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/widgets/issues/42/comments"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 1 })))
        .mount(&w.server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/repos/acme/widgets/pulls/42"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "message": "Resource not accessible by integration",
        })))
        .mount(&w.server)
        .await;
    send_close(&w, "job_close_9").await;
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["outcome"], "partial", "{result}");
    assert_eq!(
        steps(&result),
        vec![pair("comment", "applied"), pair("close", "failed")]
    );
    assert_eq!(result["payload"]["error"]["code"], "forbidden");
}

#[tokio::test]
async fn close_pull_request_is_a_job_0_5_kind() {
    let mut w = gate_world(None).await;
    // Under 0.4 the kind does not exist: malformed, never run.
    let doc = w.doc(JOB, close_job("job_close_10"), None).await;
    w.deliver(doc).await;
    let err = w.next().await;
    assert_eq!(err["payload"]["code"], "malformedRequest", "{err}");
    // 0.5 without its members is malformed too.
    let mut bare = close_job("job_close_11");
    bare.as_object_mut().unwrap().remove("message");
    let doc = w.doc(JOB_0_5, bare, None).await;
    w.deliver(doc).await;
    let err = w.next().await;
    assert_eq!(err["payload"]["code"], "malformedRequest", "{err}");
    w.quiet().await;
}

#[tokio::test]
async fn a_job_0_4_is_still_taken() {
    let mut w = gate_world(None).await;
    w.send_job(
        json!({ "jobId": "job_inspect", "namespace": NS, "kind": "inspect",
                       "repo": "github.com/acme/widgets" }),
    )
    .await;
    let ack = w.next().await;
    assert_eq!(ack["type"], format!("{JOB}#response"));
    assert_eq!(ack["payload"]["accepted"], true);
    // Run, and answered with a result (every other test here sends 0.4 jobs
    // too: `JOB` is 0.4).
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["jobId"], "job_inspect");
}

#[tokio::test]
async fn forgejo_has_no_pull_request_gate_yet() {
    let mut w = forgejo_world("").await;
    let doc = w
        .doc(
            JOB_0_5,
            json!({
                "jobId": "job_fj", "namespace": NS, "kind": "closePullRequest",
                "repo": format!("{FJ}/acme/widgets"), "number": 3, "message": "m",
            }),
            None,
        )
        .await;
    w.deliver(doc).await;
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["outcome"], "failed", "{result}");
    assert_eq!(result["payload"]["error"]["code"], "notCapable");
}
