//! Orphaned namespaces (`git-ns/bridge/event` 0.6) and binding an owner
//! again (`git-ns/bridge/job` 0.7), against the fake VTC.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::*;
use serde_json::{Value, json};
use tower::ServiceExt;
use vgi_bridge::BridgeIdentity;
use vgi_bridge::store::{
    NamespaceRecord, NamespaceState, OutboxEntry, PinRecord, RepoRecord, RetiredNamespace, Table,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const ERROR: &str = "https://trusttasks.org/spec/trust-task-error/0.6";
const DAY: i64 = 86_400;

fn ns(w: &World, id: &str) -> Option<NamespaceRecord> {
    w.bridge.store().get(Table::Namespaces, id).unwrap()
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// The VTC's refusal of document `thread` with `code`, signed by the VTC.
async fn refusal(w: &World, code: &str, thread: &str) -> Value {
    w.doc(
        ERROR,
        json!({ "code": code, "message": "refused" }),
        Some(thread),
    )
    .await
}

/// Have the bridge send an event for `NS` (its role map), and the VTC answer
/// it with `git-ns:unknownNamespace`. Returns the event.
async fn orphan(w: &mut World) -> Value {
    w.bridge.report_role_map(NS).await;
    let ev = w.next_of(EVENT).await;
    let err = refusal(w, "git-ns:unknownNamespace", ev["id"].as_str().unwrap()).await;
    w.deliver(err).await;
    assert_eq!(ns(w, NS).unwrap().state, NamespaceState::Orphaned);
    ev
}

/// Requests the bridge made of the forge other than reads.
async fn writes(w: &World) -> Vec<String> {
    w.server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.method != http::Method::GET)
        .filter(|r| !r.url.path().ends_with("/access_tokens"))
        .map(|r| format!("{} {}", r.method, r.url.path()))
        .collect()
}

async fn get(w: &World, uri: &str) -> StatusCode {
    vgi_bridge::http::router(w.bridge.clone())
        .oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

fn state_of(url: &str) -> String {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned()
}

// ── orphaning ────────────────────────────────────────────────────────────

#[tokio::test]
async fn only_a_verified_unknown_namespace_answer_to_its_event_orphans_a_namespace() {
    let mut w = world(Options::default()).await;
    w.bridge.report_role_map(NS).await;
    let ev = w.next_of(EVENT).await;
    let thread = ev["id"].as_str().unwrap().to_string();

    // Threaded to nothing the bridge sent: not attributable.
    let stray = refusal(&w, "git-ns:unknownNamespace", "urn:uuid:not-ours").await;
    w.deliver(stray).await;
    // Another code, threaded to the event: not this answer.
    let other = refusal(&w, "permissionDenied", &thread).await;
    w.deliver(other).await;
    // The right answer, from someone other than the VTC: refused unread.
    let stranger = BridgeIdentity::generate_did_key().unwrap().0;
    let mut forged = json!({
        "id": vgi_bridge::wire::new_id(),
        "type": ERROR,
        "threadId": thread,
        "issuer": stranger.did(),
        "recipient": w.bridge.did(),
        "issuedAt": chrono::Utc::now().to_rfc3339(),
        "payload": { "code": "git-ns:unknownNamespace" },
    });
    forged = stranger.sign(&forged).await.unwrap();
    w.bridge
        .handle_inbound(vgi_bridge::transport::InboundDoc {
            doc: forged,
            authenticated_sender: Some(stranger.did().to_string()),
            via: vgi_bridge::transport::Via::Tsp,
        })
        .await;
    let rec = ns(&w, NS).unwrap();
    assert_eq!(rec.state, NamespaceState::Bound);
    assert!(rec.orphaned_at.is_none());

    // The VTC's own answer to the event: orphaned, and the event dropped.
    let before = now();
    let err = refusal(&w, "git-ns:unknownNamespace", &thread).await;
    w.deliver(err).await;
    let rec = ns(&w, NS).unwrap();
    assert_eq!(rec.state, NamespaceState::Orphaned);
    assert!(rec.orphaned_at.unwrap() >= before);
    assert!(
        w.bridge
            .store()
            .list::<OutboxEntry>(Table::Outbox)
            .unwrap()
            .is_empty(),
        "nothing for it waits to be resent"
    );
    w.quiet().await;
}

#[tokio::test]
async fn an_orphaned_namespace_gets_no_report_and_no_forge_change_and_keeps_its_state() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    orphan(&mut w).await;
    let before = writes(&w).await;

    // No role-map report, whether asked for or at a link-up.
    w.bridge.report_role_map(NS).await;
    w.bridge.link_up().await;
    // A repository deleted on the forge: not reported, and its record kept.
    let s = post_webhook(
        &w,
        "repository",
        "o-1",
        &json!({ "action": "deleted", "repository": { "id": 812, "full_name": "acme/widgets" } }),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    // A pull request opened: not reported.
    post_webhook(
        &w,
        "pull_request",
        "o-2",
        &json!({
            "action": "opened",
            "repository": { "id": 812, "full_name": "acme/widgets" },
            "sender": { "id": 7, "login": "eve" },
            "pull_request": { "number": 3, "user": { "id": 7, "login": "eve" },
                "head": { "sha": "a".repeat(40) }, "base": { "ref": "main", "sha": "b".repeat(40) } },
        }),
    )
    .await;
    w.bridge.maintenance().await;
    w.quiet().await;

    assert_eq!(writes(&w).await, before, "nothing changed on the forge");
    let rec = ns(&w, NS).unwrap();
    assert_eq!(rec.state, NamespaceState::Orphaned);
    assert!(rec.managed.contains(&812), "its forge-side state is kept");
    assert!(
        w.bridge
            .store()
            .get::<RepoRecord>(Table::Repos, "github.com#812")
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn a_job_for_an_orphaned_namespace_binds_it_again_and_reports_its_role_map() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    mount_inspect(&w.server).await;
    orphan(&mut w).await;

    w.send_job(json!({
        "jobId": "job_back", "namespace": NS, "kind": "inspect",
        "repo": "github.com/acme/widgets",
    }))
    .await;
    assert_eq!(w.next().await["payload"]["accepted"], true);
    let mut types = Vec::new();
    loop {
        let d = w.next().await;
        if d["type"] == RESULT {
            assert_eq!(d["payload"]["outcome"], "succeeded", "{d}");
            break;
        }
        assert_eq!(d["payload"]["namespace"], NS);
        types.push(d["payload"]["event"]["type"].as_str().unwrap().to_string());
    }
    assert!(types.contains(&"roleMapReported".to_string()), "{types:?}");
    let rec = ns(&w, NS).unwrap();
    assert_eq!(rec.state, NamespaceState::Bound);
    assert!(rec.orphaned_at.is_none());
}

// ── removal ──────────────────────────────────────────────────────────────

fn seed_ns(w: &World, id: &str, owner: &str, state: NamespaceState, orphaned_at: Option<i64>) {
    let r = vgi_forge::Resource::parse(&format!("github.com/{owner}")).unwrap();
    let mut n = NamespaceRecord::pending(id, r.clone());
    n.state = state;
    n.orphaned_at = orphaned_at;
    n.binding = Some(vgi_forge::NamespaceBinding::new(
        vgi_forge::Namespace::new(r, vgi_forge::NamespaceKind::Organization),
        vec![],
    ));
    w.bridge.store().put(Table::Namespaces, id, &n).unwrap();
}

#[tokio::test]
async fn the_retention_sweep_removes_only_namespaces_orphaned_past_it() {
    let mut w = world(Options::default()).await;
    let t = now();
    seed_ns(
        &w,
        "ns_old",
        "old",
        NamespaceState::Orphaned,
        Some(t - 31 * DAY),
    );
    seed_ns(
        &w,
        "ns_soon",
        "soon",
        NamespaceState::Orphaned,
        Some(t - 25 * DAY),
    );
    seed_ns(&w, "ns_new", "new", NamespaceState::Orphaned, Some(t - DAY));
    w.bridge
        .store()
        .put(
            Table::Repos,
            "github.com#901",
            &RepoRecord::new(
                "ns_old",
                vgi_forge::Resource::parse("github.com/old/x").unwrap(),
                901,
            ),
        )
        .unwrap();

    w.bridge.maintenance().await;

    assert!(ns(&w, "ns_old").is_none(), "past its retention");
    assert!(
        w.bridge
            .store()
            .get::<RepoRecord>(Table::Repos, "github.com#901")
            .unwrap()
            .is_none()
    );
    let soon = ns(&w, "ns_soon").unwrap();
    assert_eq!(soon.state, NamespaceState::Orphaned);
    assert!(
        soon.removal_warned_at.is_some(),
        "warned within a week of it"
    );
    let fresh = ns(&w, "ns_new").unwrap();
    assert!(fresh.removal_warned_at.is_none());
    // A bound namespace is never removed, however quiet.
    assert_eq!(ns(&w, NS).unwrap().state, NamespaceState::Bound);
    assert!(writes(&w).await.is_empty(), "nothing on the forge");
    w.quiet().await;
}

// ── binding the owner again ──────────────────────────────────────────────

/// A world whose `acme` namespace (`NS`, owner 500, installation 42) has
/// `acme/widgets` managed and a workflow pin, with GitHub answering for the
/// installation the update redirect names.
async fn rebind_world() -> World {
    let w = world(Options {
        web_base: Some("https://github.example".into()),
        ..Options::default()
    })
    .await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    w.bridge
        .store()
        .update::<NamespaceRecord, _>(Table::Namespaces, NS, |n| {
            let mut n = n.unwrap();
            n.pin = Some(PinRecord {
                repository_id: 777,
                sha: "c".repeat(40),
                check: "Verify commit trust".into(),
            });
            Ok((Some(n), ()))
        })
        .unwrap();
    let s = &w.server;
    mount_any_token(s).await;
    for (id, login, owner_id) in [(42, "acme", 500), (43, "someone-else", 501)] {
        Mock::given(method("GET"))
            .and(path(format!("/app/installations/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": id,
                "account": { "id": owner_id, "login": login, "type": "Organization" },
                "permissions": { "administration": "write", "contents": "write",
                    "checks": "write", "metadata": "read", "members": "read" },
                "suspended_at": null,
            })))
            .mount(s)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/orgs/acme/rulesets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(s)
        .await;
    w
}

async fn begin_rebind(w: &mut World, job: &str) -> String {
    w.send_job(json!({
        "jobId": job, "namespace": "ns_again", "kind": "beginBind",
        "target": { "forge": "github.com", "owner": "acme" },
    }))
    .await;
    let resp = w.next().await;
    assert_eq!(resp["payload"]["accepted"], true, "{resp}");
    state_of(resp["payload"]["next"]["url"].as_str().unwrap())
}

#[tokio::test]
async fn binding_an_owner_again_supersedes_the_earlier_namespace() {
    let mut w = rebind_world().await;
    let state = begin_rebind(&mut w, "job_again").await;

    // Until the proof arrives, the earlier namespace is as it was.
    let earlier = ns(&w, NS).unwrap();
    assert_eq!(earlier.state, NamespaceState::Bound);
    assert_eq!(ns(&w, "ns_again").unwrap().state, NamespaceState::Pending);

    // The App is already installed: the proof is the installation settings
    // saved from the job's link — GitHub's `update` redirect, carrying this
    // job's state and naming the owner.
    let status = get(
        &w,
        &format!(
            "/github/github.com/acme/setup?installation_id=42&setup_action=update&state={state}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let bound = w.next_of(EVENT).await;
    assert_eq!(bound["payload"]["namespace"], "ns_again");
    assert_eq!(
        bound["payload"]["event"],
        json!({ "type": "bindCompleted", "jobId": "job_again", "ownerId": "500",
                "kind": "organization", "supersedes": [NS] })
    );
    serde_json::from_value::<vgi_bridge::wire::event::Payload>(bound["payload"].clone())
        .expect("a 0.6 payload");
    let mut events = Vec::new();
    loop {
        let d = w.next().await;
        if d["type"] == RESULT {
            assert_eq!(d["payload"]["outcome"], "succeeded", "{d}");
            break;
        }
        assert_eq!(d["payload"]["namespace"], "ns_again");
        events.push(d["payload"]["event"].clone());
    }
    assert_eq!(events[0]["type"], "roleMapReported");
    // The repository the earlier namespace governed starts this one
    // unmanaged, for its admins to adopt.
    assert!(
        events.contains(&json!({ "type": "repoCreatedUnmanaged", "forgeId": "812",
                                 "resource": "github.com/acme/widgets" })),
        "{events:?}"
    );

    // The forge-side state moved; one record serves the owner.
    assert!(ns(&w, NS).is_none());
    let now_ns = ns(&w, "ns_again").unwrap();
    assert_eq!(now_ns.state, NamespaceState::Bound);
    assert!(now_ns.managed.contains(&812));
    assert_eq!(now_ns.pin, earlier.pin);
    let owners: Vec<_> = w
        .bridge
        .store()
        .list::<NamespaceRecord>(Table::Namespaces)
        .unwrap()
        .into_iter()
        .filter(|(_, n)| n.resource == acme())
        .collect();
    assert_eq!(owners.len(), 1, "one record for the owner");
    let rec: RepoRecord = w
        .bridge
        .store()
        .get(Table::Repos, "github.com#812")
        .unwrap()
        .unwrap();
    assert_eq!(rec.namespace, "ns_again");
    assert!(rec.owners.is_empty(), "no governance carried over");
    let retired: RetiredNamespace = w
        .bridge
        .store()
        .get(Table::Meta, &format!("retired-namespace/{NS}"))
        .unwrap()
        .unwrap();
    assert_eq!(retired.superseded_by, "ns_again");

    // The retired id is answered for as one the bridge never served…
    w.send_job(json!({
        "jobId": "job_old", "namespace": NS, "kind": "inspect",
        "repo": "github.com/acme/widgets",
    }))
    .await;
    let err = w.next().await;
    assert_eq!(err["payload"]["code"], "git-ns:unknownNamespace", "{err}");
    // …and never taken again.
    w.send_job(json!({
        "jobId": "job_reuse", "namespace": NS, "kind": "beginBind",
        "target": { "forge": "github.com", "owner": "acme" },
    }))
    .await;
    let err = w.next().await;
    assert_eq!(err["payload"]["code"], "malformedRequest", "{err}");
    w.quiet().await;
}

#[tokio::test]
async fn a_rebind_whose_proof_names_another_owner_changes_nothing() {
    let mut w = rebind_world().await;
    orphan(&mut w).await;
    let state = begin_rebind(&mut w, "job_wrong").await;
    // Saved for another account's installation: not this owner's proof.
    let status = get(
        &w,
        &format!(
            "/github/github.com/acme/setup?installation_id=43&setup_action=update&state={state}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["outcome"], "failed");
    // A redirect without this job's state completes nothing either.
    let status = get(
        &w,
        "/github/github.com/acme/setup?installation_id=42&setup_action=update&state=forged",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let earlier = ns(&w, NS).unwrap();
    assert_eq!(earlier.state, NamespaceState::Orphaned, "left as it was");
    assert!(earlier.managed.contains(&812));
    assert!(!w.bridge.store().is_retired(NS).unwrap());
    w.quiet().await;
}
