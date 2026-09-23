//! The VTC ↔ bridge protocol against an in-process fake VTC: job → response
//! → events → result, idempotency, refusals, acknowledgement and resend.

mod common;

use common::*;
use serde_json::{Value, json};
use vgi_bridge::store::{JobRecord, JobState, OutboxEntry, Table};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The GitHub reads `inspect` makes for `acme/widgets` (forge id 812) in a
/// bridge-posted-check namespace, with a healthy ruleset pinned to the App.
async fn mount_inspect(server: &MockServer) {
    mount_any_token(server).await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 812, "full_name": "acme/widgets", "private": false,
            "visibility": "public", "archived": false, "default_branch": "main",
        })))
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

fn inspect_job(id: &str) -> Value {
    json!({ "jobId": id, "namespace": NS, "kind": "inspect", "repo": "github.com/acme/widgets" })
}

#[tokio::test]
async fn a_job_is_answered_then_reported_then_closed_by_one_result() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    mount_inspect(&w.server).await;

    let job = w.send_job(inspect_job("job_1")).await;
    let resp = w.next().await;
    assert_eq!(resp["type"], format!("{JOB}#response"));
    assert_eq!(resp["threadId"], job["id"], "the response answers the job");
    assert_eq!(
        resp["payload"],
        json!({ "jobId": "job_1", "accepted": true })
    );

    let event = w.next().await;
    assert_eq!(event["type"], EVENT);
    assert_eq!(event["payload"]["namespace"], NS);
    assert_eq!(
        event["payload"]["event"],
        json!({ "type": "protectionChanged", "forgeId": "812",
                "resource": "github.com/acme/widgets", "requiredCheck": true })
    );
    assert!(event["payload"].get("drift").is_none(), "in sync");

    let result = w.next().await;
    assert_eq!(result["type"], RESULT);
    assert_eq!(result["payload"]["jobId"], "job_1");
    assert_eq!(result["payload"]["outcome"], "succeeded");
    assert_eq!(
        result["payload"]["repo"],
        json!({ "resource": "github.com/acme/widgets", "forgeId": "812" })
    );
    w.quiet().await;

    // The ledger holds the result, and not the desired state.
    let rec: JobRecord = w.bridge.store().get(Table::Jobs, "job_1").unwrap().unwrap();
    assert_eq!(rec.state, JobState::Finished);
    assert!(rec.payload.is_none());

    // Until the VTC acknowledges it, the result waits in the outbox; the
    // acknowledgement clears it.
    assert!(
        w.bridge
            .store()
            .get::<OutboxEntry>(Table::Outbox, "result:job_1")
            .unwrap()
            .is_some()
    );
    w.ack_result(&result).await;
    assert!(
        w.bridge
            .store()
            .get::<OutboxEntry>(Table::Outbox, "result:job_1")
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_finished_job_repeated_is_not_run_again_and_its_result_is_resent() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    mount_inspect(&w.server).await;
    w.send_job(inspect_job("job_1")).await;
    w.next_of(RESULT).await;
    let reads = w.server.received_requests().await.unwrap().len();

    w.send_job(inspect_job("job_1")).await;
    let resp = w.next().await;
    assert_eq!(
        resp["payload"],
        json!({ "jobId": "job_1", "accepted": false })
    );
    let again = w.next().await;
    assert_eq!(again["type"], RESULT);
    assert_eq!(again["payload"]["jobId"], "job_1");
    assert_eq!(again["payload"]["outcome"], "succeeded");
    w.quiet().await;
    assert_eq!(
        w.server.received_requests().await.unwrap().len(),
        reads,
        "nothing touched the forge again"
    );

    // Even after the VTC acknowledged it, a repeat has its result sent
    // again, rebuilt from the ledger (spec, request rule 4).
    w.ack_result(&again).await;
    w.send_job(inspect_job("job_1")).await;
    assert_eq!(w.next().await["payload"]["accepted"], false);
    let rebuilt = w.next().await;
    assert_eq!(rebuilt["type"], RESULT);
    assert_eq!(rebuilt["payload"], again["payload"]);

    // Same id, other content: jobIdReused.
    let mut other = inspect_job("job_1");
    other["repo"] = json!("github.com/acme/gadgets");
    w.send_job(other).await;
    let err = w.next().await;
    assert!(err["type"].as_str().unwrap().contains("trust-task-error"));
    assert_eq!(err["payload"]["code"], "git-ns/bridge/job:jobIdReused");
}

#[tokio::test]
async fn jobs_from_anyone_but_the_configured_vtc_are_refused_and_not_recorded() {
    let mut w = world(Options::default()).await;
    mount_inspect(&w.server).await;
    let (stranger, _) = vgi_bridge::BridgeIdentity::generate_did_key().unwrap();
    let mut doc = json!({
        "id": vgi_bridge::wire::new_id(), "type": JOB,
        "issuer": stranger.did(), "recipient": w.bridge.did(),
        "issuedAt": chrono::Utc::now().to_rfc3339(), "payload": inspect_job("job_x"),
    });
    doc = stranger.sign(&doc).await.unwrap();
    w.bridge
        .handle_inbound(vgi_bridge::transport::InboundDoc {
            doc,
            authenticated_sender: Some(stranger.did().to_string()),
        })
        .await;
    // Not even an error goes back: the bridge answers only its VTC.
    w.quiet().await;
    assert!(
        w.bridge
            .store()
            .get::<JobRecord>(Table::Jobs, "job_x")
            .unwrap()
            .is_none()
    );

    // The VTC's own job, arriving over a transport that proved someone
    // else: identityMismatch.
    let doc = w.doc(JOB, inspect_job("job_y"), None).await;
    w.bridge
        .handle_inbound(vgi_bridge::transport::InboundDoc {
            doc,
            authenticated_sender: Some(stranger.did().to_string()),
        })
        .await;
    let err = w.next().await;
    assert_eq!(err["payload"]["code"], "identityMismatch");

    // Tampered after the VTC signed it.
    let mut doc = w.doc(JOB, inspect_job("job_z"), None).await;
    doc["payload"]["repo"] = json!("github.com/acme/gadgets");
    w.deliver(doc).await;
    assert_eq!(w.next().await["payload"]["code"], "proofInvalid");
    assert!(
        w.bridge
            .store()
            .get::<JobRecord>(Table::Jobs, "job_z")
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn request_time_refusals_follow_the_spec() {
    let mut w = world(Options {
        kind: vgi_forge::NamespaceKind::User,
        ..Options::default()
    })
    .await;
    // Unknown namespace.
    w.send_job(json!({ "jobId": "j1", "namespace": "ns_other", "kind": "inspect" }))
        .await;
    assert_eq!(w.next().await["payload"]["code"], "git-ns:unknownNamespace");
    // A repository outside the namespace.
    w.send_job(
        json!({ "jobId": "j2", "namespace": NS, "kind": "inspect", "repo": "github.com/acme/x" }),
    )
    .await;
    assert_eq!(w.next().await["payload"]["code"], "git-ns:unknownNamespace");
    // createRepo on a personal account.
    w.send_job(json!({
        "jobId": "j3", "namespace": NS, "kind": "createRepo", "repo": "github.com/alice/x",
        "spec": { "visibility": "public" }, "desiredRoles": [],
    }))
    .await;
    assert_eq!(
        w.next().await["payload"]["code"],
        "git-ns/bridge/job:notCapable"
    );
    // A member its kind does not use.
    w.send_job(json!({ "jobId": "j4", "namespace": NS, "kind": "archive" }))
        .await;
    assert_eq!(w.next().await["payload"]["code"], "malformedRequest");
    for j in ["j1", "j2", "j3", "j4"] {
        assert!(
            w.bridge
                .store()
                .get::<JobRecord>(Table::Jobs, j)
                .unwrap()
                .is_none(),
            "{j} was refused, not recorded"
        );
    }
}

#[tokio::test]
async fn an_unacknowledged_result_is_sent_again_with_a_fresh_proof() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    mount_inspect(&w.server).await;
    w.send_job(inspect_job("job_1")).await;
    let event = w.next_of(EVENT).await;
    let first = w.next_of(RESULT).await;
    w.bridge.resend_unacknowledged(true).await;
    // Both go again, each as a new document.
    let (mut result2, mut event2) = (None, None);
    for _ in 0..2 {
        let d = w.next().await;
        if d["type"] == RESULT {
            result2 = Some(d);
        } else {
            event2 = Some(d);
        }
    }
    let (second, event2) = (result2.unwrap(), event2.unwrap());
    assert_eq!(second["payload"], first["payload"]);
    assert_ne!(second["id"], first["id"], "a new document, freshly issued");
    assert_eq!(event2["payload"], event["payload"]);
    // Acknowledging the resent documents (by the ids they went out under)
    // clears both.
    w.ack_result(&second).await;
    w.ack_event(&event2).await;
    w.bridge.resend_unacknowledged(true).await;
    w.quiet().await;
}

#[tokio::test]
async fn a_redirect_from_the_forge_is_not_followed() {
    let mut w = world(Options::default()).await;
    mount_any_token(&w.server).await;
    let elsewhere = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&elsewhere)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets"))
        .respond_with(
            ResponseTemplate::new(301)
                .insert_header("location", format!("{}/repositories/1", elsewhere.uri())),
        )
        .mount(&w.server)
        .await;
    w.send_job(inspect_job("job_r")).await;
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["outcome"], "failed");
    assert_eq!(result["payload"]["error"]["code"], "notFound");
    // `elsewhere` verifies on drop that it saw nothing.
}
