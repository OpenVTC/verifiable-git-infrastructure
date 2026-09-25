//! `git-ns/bridge/event` 0.2 against the fake VTC: a transfer detaches and
//! carries nothing into another namespace, a reused name detaches the old
//! repository, every resource lies inside its event's namespace — and the
//! 0.1 fallback for a VTC that has not moved.

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::{Value, json};
use vgi_bridge::store::{
    BranchLedger, NamespaceRecord, NamespaceState, OutboxEntry, RepoRecord, Table,
};
use vgi_forge::{Namespace, NamespaceBinding, NamespaceKind, Resource};

/// A second namespace this bridge serves on the same forge.
const LABS: &str = "ns_labs";

fn seed_labs(w: &World) {
    let resource = Resource::parse("github.com/acme-labs").unwrap();
    let namespace = Namespace::new(resource.clone(), NamespaceKind::Organization)
        .with_owner_id(600)
        .with_installation(43);
    let mut rec = NamespaceRecord::pending(LABS, resource);
    rec.state = NamespaceState::Bound;
    rec.binding = Some(NamespaceBinding::new(namespace, vec![]));
    rec.required_workflow = Some(false);
    rec.bridge_checks = Some(true);
    w.bridge.store().put(Table::Namespaces, LABS, &rec).unwrap();
    // Handed to its App, as a restart would (when acme-labs has one).
    if let Some(a) = w.bridge.adapters().for_resource(&rec.resource) {
        a.restore(&rec).unwrap();
    }
}

fn ns(w: &World, id: &str) -> NamespaceRecord {
    w.bridge
        .store()
        .get(Table::Namespaces, id)
        .unwrap()
        .unwrap()
}

fn record(w: &World, id: u64) -> Option<RepoRecord> {
    w.bridge
        .store()
        .get(Table::Repos, &format!("github.com#{id}"))
        .unwrap()
}

fn transferred(id: u64, to: &str) -> Value {
    json!({
        "action": "transferred",
        "repository": { "id": id, "full_name": to },
        "changes": { "owner": { "from": { "organization": { "id": 500, "login": "acme" } } } },
    })
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

/// A managed repository transferred to another organisation this same
/// bridge serves (through that organisation's own App): the old
/// organisation's App reports it to its namespace as `repoTransferred`, and
/// the new one's App reports it to its namespace as `repoCreatedUnmanaged` —
/// each App speaks for its own organisation only, and the record, the place
/// in the managed set and the Dependabot provenance never follow it. Same
/// handling on either event version; only the type differs.
async fn a_transfer_between_served_namespaces(version: Option<&'static str>, ty: &str) {
    let mut w = world(
        Options {
            event_version: version,
            ..Options::default()
        }
        .with_org("acme-labs", 3004),
    )
    .await;
    seed_labs(&w);
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    let ledger = "github.com#812#dependabot/cargo/serde-1.0.200";
    w.bridge
        .store()
        .put(Table::Branches, ledger, &BranchLedger::default())
        .unwrap();

    let s = post_webhook(
        &w,
        "repository",
        "t-1",
        &transferred(812, "acme-labs/widgets"),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);

    let out = w.next_of(ty).await;
    assert_eq!(out["payload"]["namespace"], NS);
    assert_eq!(
        out["payload"]["event"],
        json!({ "type": "repoTransferred", "forgeId": "812",
                "from": "github.com/acme/widgets", "to": "github.com/acme-labs/widgets" })
    );
    // acme's App says nothing for acme-labs: its own App does.
    w.quiet().await;
    let s = post_webhook_as(
        &w,
        "acme-labs",
        "repository",
        "t-1-labs",
        &transferred(812, "acme-labs/widgets"),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let arrived = w.next_of(ty).await;
    assert_eq!(arrived["payload"]["namespace"], LABS);
    assert_eq!(
        arrived["payload"]["event"],
        json!({ "type": "repoCreatedUnmanaged", "forgeId": "812",
                "resource": "github.com/acme-labs/widgets" })
    );
    w.quiet().await;

    assert!(record(&w, 812).is_none(), "no record, here or there");
    assert!(!ns(&w, NS).managed.contains(&812));
    assert!(!ns(&w, LABS).managed.contains(&812));
    assert!(
        w.bridge
            .store()
            .get::<BranchLedger>(Table::Branches, ledger)
            .unwrap()
            .is_none(),
        "the provenance ledger is not carried across"
    );

    // Acknowledged in the version it was sent, each clears.
    w.ack_event(&out).await;
    w.ack_event(&arrived).await;
    assert_eq!(open_events(&w), 0);

    // The same delivery again (the other installation's copy): harmless.
    let s = post_webhook(
        &w,
        "repository",
        "t-2",
        &transferred(812, "acme-labs/widgets"),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let again = w.next_of(ty).await;
    assert_eq!(again["payload"]["event"]["type"], "repoTransferred");
    let s = post_webhook_as(
        &w,
        "acme-labs",
        "repository",
        "t-2-labs",
        &transferred(812, "acme-labs/widgets"),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let again = w.next_of(ty).await;
    assert_eq!(again["payload"]["event"]["type"], "repoCreatedUnmanaged");
    assert!(record(&w, 812).is_none());
}

#[tokio::test]
async fn a_transfer_into_another_served_namespace_detaches_and_carries_nothing() {
    a_transfer_between_served_namespaces(None, EVENT).await;
}

#[tokio::test]
async fn under_0_1_a_transfer_is_handled_the_same_and_typed_0_1() {
    a_transfer_between_served_namespaces(Some("0.1"), EVENT_0_1).await;
}

/// Two events, in either order, keyed by namespace.
async fn two_events(w: &mut World) -> std::collections::BTreeMap<String, Value> {
    let mut out = std::collections::BTreeMap::new();
    for _ in 0..2 {
        let ev = w.next_of(EVENT).await;
        out.insert(
            ev["payload"]["namespace"].as_str().unwrap().to_string(),
            ev["payload"]["event"].clone(),
        );
    }
    out
}

/// A world with acme's `widgets` (812) managed, and acme-labs served by its
/// own App.
async fn two_org_world() -> World {
    let w = world(Options::default().with_org("acme-labs", 3004)).await;
    seed_labs(&w);
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    w
}

/// Probe (re-review of #90): only the NEW owner's App reports the transfer
/// (the old owner's delivery never comes, or comes later). The new side
/// reports it unmanaged; the old side is detached and told only once GitHub
/// itself confirms the move — never on the other organisation's word.
#[tokio::test]
async fn a_transfer_only_the_new_owner_reports_is_confirmed_before_the_old_side_detaches() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    let mut w = two_org_world().await;
    mount_any_token(&w.server).await;
    Mock::given(method("GET"))
        .and(path("/repositories/812"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "id": 812, "full_name": "acme-labs/widgets" })),
        )
        .mount(&w.server)
        .await;
    let s = post_webhook_as(
        &w,
        "acme-labs",
        "repository",
        "n-1",
        &transferred(812, "acme-labs/widgets"),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let evs = two_events(&mut w).await;
    assert_eq!(
        evs[NS],
        json!({ "type": "repoTransferred", "forgeId": "812",
                "from": "github.com/acme/widgets", "to": "github.com/acme-labs/widgets" })
    );
    assert_eq!(
        evs[LABS],
        json!({ "type": "repoCreatedUnmanaged", "forgeId": "812",
                "resource": "github.com/acme-labs/widgets" })
    );
    assert!(
        record(&w, 812).is_none(),
        "the old side's record is detached"
    );
    assert!(!ns(&w, NS).managed.contains(&812));

    // The old owner's delivery arrives late: nothing of it is left to
    // detach; nothing breaks.
    post_webhook(
        &w,
        "repository",
        "o-1",
        &transferred(812, "acme-labs/widgets"),
    )
    .await;
    let late = w.next_of(EVENT).await;
    assert_eq!(late["payload"]["event"]["type"], "repoTransferred");
    assert!(record(&w, 812).is_none());
}

/// The same transfer, the old owner's App first (the existing path) — the
/// new owner's delivery after it has nothing to confirm.
#[tokio::test]
async fn a_transfer_the_old_owner_reports_first_needs_no_confirmation() {
    let mut w = two_org_world().await;
    post_webhook(
        &w,
        "repository",
        "o-1",
        &transferred(812, "acme-labs/widgets"),
    )
    .await;
    let out = w.next_of(EVENT).await;
    assert_eq!(out["payload"]["namespace"], NS);
    assert_eq!(out["payload"]["event"]["type"], "repoTransferred");
    assert!(record(&w, 812).is_none());
    post_webhook_as(
        &w,
        "acme-labs",
        "repository",
        "n-1",
        &transferred(812, "acme-labs/widgets"),
    )
    .await;
    let arrived = w.next_of(EVENT).await;
    assert_eq!(arrived["payload"]["namespace"], LABS);
    assert_eq!(arrived["payload"]["event"]["type"], "repoCreatedUnmanaged");
    w.quiet().await;
    assert!(
        !w.server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.url.path() == "/repositories/812"),
        "nothing to confirm"
    );
}

/// The new owner's App claims a repository GitHub says is still the old
/// owner's: the old side is left alone.
#[tokio::test]
async fn an_unconfirmed_transfer_leaves_the_other_organisation_alone() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    let mut w = two_org_world().await;
    mount_any_token(&w.server).await;
    Mock::given(method("GET"))
        .and(path("/repositories/812"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "id": 812, "full_name": "acme/widgets" })),
        )
        .mount(&w.server)
        .await;
    post_webhook_as(
        &w,
        "acme-labs",
        "repository",
        "n-1",
        &transferred(812, "acme-labs/widgets"),
    )
    .await;
    let ev = w.next_of(EVENT).await;
    assert_eq!(
        ev["payload"]["namespace"], LABS,
        "only its own namespace hears of it"
    );
    w.quiet().await;
    assert!(record(&w, 812).is_some(), "acme's record is untouched");
    assert!(ns(&w, NS).managed.contains(&812));
}

#[tokio::test]
async fn a_transfer_out_of_every_served_namespace_detaches() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    let s = post_webhook(
        &w,
        "repository",
        "t-1",
        &transferred(812, "elsewhere/widgets"),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    // `to` lies outside the namespace, and may: it says where it went.
    let ev = w.next_of(EVENT).await;
    assert_eq!(
        ev["payload"]["event"],
        json!({ "type": "repoTransferred", "forgeId": "812",
                "from": "github.com/acme/widgets", "to": "github.com/elsewhere/widgets" })
    );
    w.quiet().await;
    assert!(record(&w, 812).is_none());
    assert!(!ns(&w, NS).managed.contains(&812));
}

#[tokio::test]
async fn a_transfer_the_forge_never_announced_is_reported_as_one_not_as_a_rename() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    // GitHub answers for the old name with the repository's new home.
    mount_inspect_as(&w.server, 812, "elsewhere/widgets").await;
    w.send_job(
        json!({ "jobId": "job_t", "namespace": NS, "kind": "inspect",
                       "repo": "github.com/acme/widgets" }),
    )
    .await;
    let ev = w.next_of(EVENT).await;
    assert_eq!(
        ev["payload"]["event"],
        json!({ "type": "repoTransferred", "forgeId": "812",
                "from": "github.com/acme/widgets", "to": "github.com/elsewhere/widgets" }),
        "never a repoRenamed whose `to` lies outside the namespace"
    );
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["jobId"], "job_t");
    w.quiet().await;
    assert!(record(&w, 812).is_none());
    assert!(!ns(&w, NS).managed.contains(&812));
}

#[tokio::test]
async fn a_new_repository_at_a_governed_name_detaches_the_old_one() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    // 812 went without an event; 990 now has its name.
    let created = json!({
        "action": "created",
        "repository": { "id": 990, "full_name": "acme/widgets" },
    });
    let s = post_webhook(&w, "repository", "c-1", &created).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let ev = w.next_of(EVENT).await;
    assert_eq!(
        ev["payload"]["event"],
        json!({ "type": "repoCreatedUnmanaged", "forgeId": "990",
                "resource": "github.com/acme/widgets" })
    );
    w.quiet().await;
    assert!(record(&w, 812).is_none(), "the old one is detached");
    assert!(record(&w, 990).is_none(), "the newcomer inherits nothing");
    assert!(ns(&w, NS).managed.is_empty());
}

#[tokio::test]
async fn an_inspection_that_finds_a_reused_name_reports_the_newcomer_unmanaged() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    mount_inspect_as(&w.server, 990, "acme/widgets").await;
    w.send_job(
        json!({ "jobId": "job_r", "namespace": NS, "kind": "inspect",
                       "repo": "github.com/acme/widgets" }),
    )
    .await;
    let ev = w.next_of(EVENT).await;
    assert_eq!(
        ev["payload"]["event"],
        json!({ "type": "repoCreatedUnmanaged", "forgeId": "990",
                "resource": "github.com/acme/widgets" })
    );
    let result = w.next_of(RESULT).await;
    assert_eq!(
        result["payload"]["repo"],
        json!({ "resource": "github.com/acme/widgets", "forgeId": "990" })
    );
    w.quiet().await;
    assert!(record(&w, 812).is_none());
    assert!(!ns(&w, NS).managed.contains(&812));
}

#[tokio::test]
async fn a_transfer_in_to_a_governed_name_detaches_the_old_one_too() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    let incoming = json!({
        "action": "transferred",
        "repository": { "id": 950, "full_name": "acme/widgets" },
        "changes": { "owner": { "from": { "user": { "id": 31, "login": "outsider" } } } },
    });
    let s = post_webhook(&w, "repository", "t-in", &incoming).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let ev = w.next_of(EVENT).await;
    assert_eq!(
        ev["payload"]["event"],
        json!({ "type": "repoCreatedUnmanaged", "forgeId": "950",
                "resource": "github.com/acme/widgets" })
    );
    w.quiet().await;
    assert!(record(&w, 812).is_none());
}

#[tokio::test]
async fn under_0_1_events_are_typed_0_1_and_either_acknowledgement_clears_them() {
    let mut w = world(Options {
        event_version: Some("0.1"),
        ..Options::default()
    })
    .await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    mount_inspect(&w.server).await;
    w.send_job(
        json!({ "jobId": "job_1", "namespace": NS, "kind": "inspect",
                       "repo": "github.com/acme/widgets" }),
    )
    .await;
    let ev = w.next_of(EVENT_0_1).await;
    assert_eq!(ev["payload"]["event"]["type"], "protectionChanged");
    // The payload is a valid 0.1 payload.
    serde_json::from_value::<vgi_bridge::wire::event_v0_1::Payload>(ev["payload"].clone())
        .expect("a 0.1 payload");
    assert_eq!(open_events(&w), 1);
    w.ack_event(&ev).await;
    assert_eq!(open_events(&w), 0);
}

#[tokio::test]
async fn by_default_events_are_typed_0_2() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    mount_inspect(&w.server).await;
    w.send_job(
        json!({ "jobId": "job_1", "namespace": NS, "kind": "inspect",
                       "repo": "github.com/acme/widgets" }),
    )
    .await;
    let ev = w.next_of(EVENT).await;
    serde_json::from_value::<vgi_bridge::wire::event::Payload>(ev["payload"].clone())
        .expect("a 0.2 payload");
    // A VTC that answers in 0.1 (the configured version changed while this
    // was out) still clears it.
    let ack = w
        .doc(
            &format!("{EVENT_0_1}#response"),
            json!({}),
            ev["threadId"].as_str(),
        )
        .await;
    w.deliver(ack).await;
    assert_eq!(open_events(&w), 0);
}
