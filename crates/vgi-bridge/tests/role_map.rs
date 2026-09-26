//! The configurable role map (§5.8 layer 3) on a `projectRoles` job, and the
//! 2026-09-25 decision that a namespace admin gets no forge role whatever
//! the map says.

mod common;

use common::*;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const BOB: u64 = 6600001;
const CAROL: u64 = 6600002;
const DAVE: u64 = 6600003;

fn role(id: u64, login: &str, right: &str) -> Value {
    json!({
        "subject": format!("did:webvh:QmScid:acme-vtc.example:{login}"),
        "account": { "forge": "github.com", "id": id.to_string(), "login": login },
        "right": right,
    })
}

/// `acme/<name>` with no collaborators yet; every user lookup answers.
async fn mount_empty_repo(server: &MockServer, name: &str) {
    mount_repo_with(server, name, json!([])).await;
}

/// `acme/<name>` with `collaborators`; every user lookup answers, and
/// every collaborator PUT and DELETE succeeds.
async fn mount_repo_with(server: &MockServer, name: &str, collaborators: Value) {
    mount_any_token(server).await;
    Mock::given(method("DELETE"))
        .and(wiremock::matchers::path_regex(format!(
            r"^/repos/acme/{name}/collaborators/"
        )))
        .respond_with(ResponseTemplate::new(204))
        .mount(server)
        .await;
    for (endpoint, body) in [("collaborators", collaborators), ("invitations", json!([]))] {
        Mock::given(method("GET"))
            .and(path(format!("/repos/acme/{name}/{endpoint}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }
    for (id, login) in [(BOB, "bob"), (CAROL, "carol"), (DAVE, "dave")] {
        Mock::given(method("GET"))
            .and(path(format!("/user/{id}")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "id": id, "login": login })),
            )
            .mount(server)
            .await;
    }
    Mock::given(method("PUT"))
        .and(wiremock::matchers::path_regex(format!(
            r"^/repos/acme/{name}/collaborators/"
        )))
        .respond_with(ResponseTemplate::new(204))
        .mount(server)
        .await;
}

/// `login → permission` for every collaborator PUT the bridge sent.
async fn puts(server: &MockServer) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r: &Request| r.method == http::Method::PUT)
        .map(|r| {
            let login = r.url.path().rsplit('/').next().unwrap().to_string();
            let body: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
            (login, body["permission"].as_str().unwrap_or("").to_string())
        })
        .collect();
    out.sort();
    out
}

async fn project(w: &mut World, name: &str, roles: Vec<Value>) -> Value {
    project_on(w, "github.com", name, roles).await
}

async fn project_on(w: &mut World, host: &str, name: &str, roles: Vec<Value>) -> Value {
    w.send_job_0_2(json!({
        "jobId": format!("job_{name}"), "namespace": NS, "kind": "projectRoles",
        "repo": format!("{host}/acme/{name}"), "desiredRoles": roles,
    }))
    .await;
    assert_eq!(w.next().await["payload"]["accepted"], true);
    w.next_of(RESULT).await
}

#[tokio::test]
async fn the_default_map_and_no_role_for_a_namespace_admin() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    mount_empty_repo(&w.server, "widgets").await;
    let result = project(
        &mut w,
        "widgets",
        vec![
            role(BOB, "bob", "git.repo.maintain"),
            role(CAROL, "carol", "git.ns.admin"),
            role(DAVE, "dave", "git.commit.sign"),
        ],
    )
    .await;
    assert_eq!(result["payload"]["outcome"], "succeeded", "{result}");
    // Maintainer → maintain; committer → nothing (fork PRs); the namespace
    // admin → nothing at all.
    assert_eq!(
        puts(&w.server).await,
        vec![("bob".into(), "maintain".into())]
    );
}

#[tokio::test]
async fn namespace_and_repository_overrides_apply_and_still_give_an_admin_nothing() {
    let mut w = world(Options {
        github_extra: r#"
[github.role_map]
maintain = "write"

[github.namespaces.acme.role_map]
maintain = "admin"

[github.namespaces.acme.repos.gadgets.role_map]
commit = "write"
"#
        .into(),
        ..Options::default()
    })
    .await;
    seed_repo(w.bridge.store(), &repo("gadgets"), 813);
    mount_empty_repo(&w.server, "gadgets").await;
    let result = project(
        &mut w,
        "gadgets",
        vec![
            role(BOB, "bob", "git.repo.maintain"),
            role(CAROL, "carol", "git.ns.admin"),
            role(DAVE, "dave", "git.commit.sign"),
        ],
    )
    .await;
    assert_eq!(result["payload"]["outcome"], "succeeded", "{result}");
    assert_eq!(
        puts(&w.server).await,
        vec![
            ("bob".into(), "admin".into()),
            ("dave".into(), "push".into()),
        ]
    );
}

/// Every DELETE path the bridge sent.
async fn deletes(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.method == http::Method::DELETE)
        .map(|r| r.url.path().to_string())
        .collect()
}

#[tokio::test]
async fn a_namespace_admins_direct_role_given_by_hand_is_removed() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    // Carol was made a repository admin on GitHub by hand; the bridge never
    // projected it. She is a namespace admin: the job lists her with
    // `git.ns.admin`, which asks for no role, so her direct role goes.
    mount_repo_with(
        &w.server,
        "widgets",
        json!([{ "id": CAROL, "login": "carol", "role_name": "admin" }]),
    )
    .await;
    let result = project(
        &mut w,
        "widgets",
        vec![role(CAROL, "carol", "git.ns.admin")],
    )
    .await;
    assert_eq!(result["payload"]["outcome"], "succeeded", "{result}");
    assert_eq!(
        deletes(&w.server).await,
        vec!["/repos/acme/widgets/collaborators/carol"]
    );
    assert!(puts(&w.server).await.is_empty());
}

// ── Forgejo: the merge allow-list under a role-map override ─────────────

fn fj_role(id: u64, login: &str, right: &str) -> Value {
    json!({
        "subject": format!("did:webvh:QmScid:acme-vtc.example:{login}"),
        "account": { "forge": FJ, "id": id.to_string(), "login": login },
        "right": right,
    })
}

/// `acme/widgets` on the mock Forgejo, bootstrapped (a `main` rule whose
/// merge allow-list holds only the bot), with the bot its only
/// collaborator; Bob's id resolves to `bob`, and collaborator PUTs and
/// allow-list PATCHes succeed.
async fn mount_forgejo_bootstrapped(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/api/v1/repos/acme/widgets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 812, "full_name": "acme/widgets", "default_branch": "main",
        })))
        .with_priority(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/repos/acme/widgets/collaborators"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-total-count", "1")
                .set_body_json(json!([{ "id": BOT_ID, "login": BOT }])),
        )
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/api/v1/repos/acme/widgets/collaborators/{BOT}/permission"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "permission": "admin" })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/repos/acme/widgets/branch_protections"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "rule_name": "main",
            "branch_name": "main",
            "enable_push": false,
            "enable_merge_whitelist": true,
            "merge_whitelist_usernames": [BOT],
            "merge_whitelist_teams": null,
            "enable_status_check": true,
            "status_check_contexts": ["Verify commit trust / Verify commit trust (pull_request)"],
            "apply_to_admins": true,
        }])))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/users/search"))
        .and(wiremock::matchers::query_param("uid", BOB.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true, "data": [{ "id": BOB, "login": "bob" }],
        })))
        .mount(server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/v1/repos/acme/widgets/collaborators/bob"))
        .respond_with(ResponseTemplate::new(204))
        .mount(server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/repos/acme/widgets/branch_protections/main"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(server)
        .await;
}

/// What the bridge asked Forgejo for: Bob's collaborator permission, and
/// every allow-list the bridge wrote.
async fn forgejo_writes(server: &MockServer) -> (Vec<String>, Vec<Value>) {
    let reqs = server.received_requests().await.unwrap_or_default();
    let body = |r: &Request| serde_json::from_slice::<Value>(&r.body).unwrap_or(Value::Null);
    let perms = reqs
        .iter()
        .filter(|r| r.method == http::Method::PUT)
        .map(|r| body(r)["permission"].as_str().unwrap_or("").to_string())
        .collect();
    let lists = reqs
        .iter()
        .filter(|r| r.method == http::Method::PATCH)
        .map(|r| body(r)["merge_whitelist_usernames"].clone())
        .collect();
    (perms, lists)
}

#[tokio::test]
async fn forgejo_maintainers_as_admins_are_on_the_merge_allow_list() {
    let mut w = forgejo_world("[forgejo.role_map]\nmaintain = \"admin\"").await;
    mount_forgejo_bootstrapped(&w.server).await;
    let result = project_on(
        &mut w,
        FJ,
        "widgets",
        vec![fj_role(BOB, "bob", "git.repo.maintain")],
    )
    .await;
    assert_eq!(result["payload"]["outcome"], "succeeded", "{result}");
    let (perms, lists) = forgejo_writes(&w.server).await;
    assert_eq!(perms, ["admin"]);
    assert_eq!(lists, [json!([BOT, "bob"])]);
}

#[tokio::test]
async fn forgejo_maintainers_as_writers_stay_off_the_merge_allow_list() {
    let mut w = forgejo_world("[forgejo.role_map]\nmaintain = \"write\"").await;
    mount_forgejo_bootstrapped(&w.server).await;
    let result = project_on(
        &mut w,
        FJ,
        "widgets",
        vec![fj_role(BOB, "bob", "git.repo.maintain")],
    )
    .await;
    assert_eq!(result["payload"]["outcome"], "succeeded", "{result}");
    let (perms, lists) = forgejo_writes(&w.server).await;
    assert_eq!(perms, ["write"]);
    assert!(lists.is_empty(), "the allow-list is not touched: {lists:?}");
}

#[tokio::test]
async fn forgejo_default_maintainers_get_write_and_the_allow_list() {
    let mut w = forgejo_world("").await;
    mount_forgejo_bootstrapped(&w.server).await;
    let result = project_on(
        &mut w,
        FJ,
        "widgets",
        vec![fj_role(BOB, "bob", "git.repo.maintain")],
    )
    .await;
    assert_eq!(result["payload"]["outcome"], "succeeded", "{result}");
    let (perms, lists) = forgejo_writes(&w.server).await;
    assert_eq!(perms, ["write"]);
    assert_eq!(lists, [json!([BOT, "bob"])]);
}

// ── the role-map report (`git-ns/bridge/event` 0.3, `roleMapReported`) ──────

use vgi_bridge::store::{OutboxEntry, RepoRecord, Table};
use vgi_forge::{NamespaceKind, Resource};

/// The next role-map report for namespace `NS`, as its event body.
async fn report(w: &mut World) -> Value {
    w.bridge.report_role_map(NS).await;
    let ev = w.next_of(EVENT).await;
    assert_eq!(ev["payload"]["namespace"], NS);
    // Fits the 0.3 payload type.
    serde_json::from_value::<vgi_bridge::wire::event::Payload>(ev["payload"].clone())
        .expect("a 0.3 payload");
    ev["payload"]["event"].clone()
}

fn map(own: &str, maintain: &str, commit: &str) -> Value {
    json!({ "own": own, "maintain": maintain, "commit": commit })
}

#[tokio::test]
async fn a_github_organisation_with_the_default_map_reports_just_the_map() {
    let mut w = world(Options::default()).await;
    // Projected before the bridge kept the map: taken as the default, which
    // is what applies, so not stale.
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    assert_eq!(
        report(&mut w).await,
        json!({
            "type": "roleMapReported",
            "roleMap": map("admin", "maintain", "none"),
            "ladder": ["read", "triage", "write", "maintain", "admin"],
        })
    );
}

#[tokio::test]
async fn a_github_personal_account_reports_the_one_collaborator_level() {
    let mut w = world(Options {
        kind: NamespaceKind::User,
        ..Options::default()
    })
    .await;
    seed_repo(
        w.bridge.store(),
        &Resource::parse("github.com/alice/widgets").unwrap(),
        812,
    );
    assert_eq!(
        report(&mut w).await,
        json!({ "type": "roleMapReported", "roleMap": map("write", "write", "none"), "ladder": ["write"] })
    );
}

#[tokio::test]
async fn repository_overrides_are_listed_and_repositories_projected_under_another_map_are_stale() {
    let mut w = world(Options {
        github_extra: r#"
[github.namespaces.acme.repos.widgets.role_map]
commit = "write"

[github.namespaces.acme.repos.same.role_map]
commit = "none"
"#
        .into(),
        ..Options::default()
    })
    .await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    seed_repo(w.bridge.store(), &repo("gadgets"), 813);
    let ev = report(&mut w).await;
    assert_eq!(ev["roleMap"], map("admin", "maintain", "none"));
    // `same` overrides nothing in effect, so it is not listed.
    assert_eq!(
        ev["repos"],
        json!([{ "resource": "github.com/acme/widgets", "roleMap": map("admin", "maintain", "write") }])
    );
    // `widgets` was projected under the default map (no record of one);
    // `gadgets` still gets the default.
    assert_eq!(ev["stale"], json!(["github.com/acme/widgets"]));

    // A successful projection records the map it applied: no longer stale.
    mount_empty_repo(&w.server, "widgets").await;
    let result = project(
        &mut w,
        "widgets",
        vec![role(DAVE, "dave", "git.commit.sign")],
    )
    .await;
    assert_eq!(result["payload"]["outcome"], "succeeded", "{result}");
    let rec: RepoRecord = w
        .bridge
        .store()
        .get(Table::Repos, "github.com#812")
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_value(rec.role_map).unwrap(),
        map("admin", "maintain", "write")
    );
    assert!(report(&mut w).await.get("stale").is_none());
}

#[tokio::test]
async fn a_newer_report_replaces_an_unacknowledged_one() {
    let mut w = world(Options::default()).await;
    let reports = |w: &World| {
        w.bridge
            .store()
            .list::<OutboxEntry>(Table::Outbox)
            .unwrap()
            .into_iter()
            .filter(|(_, e)| e.payload["event"]["type"] == "roleMapReported")
            .map(|(k, _)| k)
            .collect::<Vec<_>>()
    };
    report(&mut w).await;
    report(&mut w).await;
    assert_eq!(
        reports(&w),
        vec![vgi_bridge::rolemap::outbox_key(NS)],
        "one per namespace"
    );
}

#[tokio::test]
async fn a_bridge_on_event_0_2_never_reports_its_role_map() {
    let mut w = world(Options {
        event_version: Some("0.2"),
        ..Options::default()
    })
    .await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    w.bridge.report_role_maps().await;
    w.quiet().await;
    assert!(
        w.bridge
            .store()
            .list::<OutboxEntry>(Table::Outbox)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_bridge_reports_its_role_map_at_start_up() {
    let dir = tempfile::tempdir().unwrap();
    let store_path = dir.path().join("bridge.redb");
    // Start once to create the store, then again: every start reports.
    for _ in 0..2 {
        let w = world(Options {
            store_path: Some(store_path.clone()),
            seed_namespace: !store_path.exists(),
            ..Options::default()
        })
        .await;
        assert_eq!(w.startup_reports.len(), 1, "one bound namespace");
        let doc = &w.startup_reports[0];
        assert_eq!(doc["type"], EVENT);
        assert_eq!(
            doc["payload"]["event"]["roleMap"],
            map("admin", "maintain", "none")
        );
        // Acknowledged, so nothing is left to resend.
        assert!(
            w.bridge
                .store()
                .list::<OutboxEntry>(Table::Outbox)
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn forgejo_reports_its_ladder_and_a_changed_map_makes_repositories_stale() {
    let w = forgejo_world("").await;
    let doc = &w.startup_reports[0];
    // The adapter's own `maintain` rung (`write` plus the default branch's
    // merge allow-list) is reported as `maintain`, the level drift uses.
    assert_eq!(
        doc["payload"]["event"],
        json!({
            "type": "roleMapReported",
            "roleMap": map("admin", "maintain", "none"),
            "ladder": ["read", "write", "maintain", "admin"],
        })
    );

    let w = forgejo_world("[forgejo.role_map]\nmaintain = \"admin\"").await;
    let doc = &w.startup_reports[0];
    assert_eq!(
        doc["payload"]["event"],
        json!({
            "type": "roleMapReported",
            "roleMap": map("admin", "admin", "none"),
            "ladder": ["read", "write", "maintain", "admin"],
            "stale": [format!("{FJ}/acme/widgets")],
        })
    );
}

/// Role-map reports taken off the inbox until it is quiet, and the count of
/// everything else.
async fn drain(w: &mut World) -> (Vec<Value>, usize) {
    let (mut maps, mut other) = (Vec::new(), 0);
    while let Ok(Some((_, doc))) =
        tokio::time::timeout(std::time::Duration::from_millis(300), w.inbox.recv()).await
    {
        if doc["payload"]["event"]["type"] == "roleMapReported" {
            maps.push(doc);
        } else {
            other += 1;
        }
    }
    (maps, other)
}

#[tokio::test]
async fn a_link_that_comes_back_reports_the_role_map_once_per_namespace() {
    use std::sync::atomic::Ordering;
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);

    // The link drops: a result goes unsent, and nothing is flagged yet.
    w.link_down.store(true, Ordering::Release);
    mount_empty_repo(&w.server, "widgets").await;
    w.send_job_0_2(json!({
        "jobId": "job_down", "namespace": NS, "kind": "projectRoles",
        "repo": "github.com/acme/widgets", "desiredRoles": [],
    }))
    .await;
    // Give the job time to finish and its result to fail to send.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // The link comes back by itself: the first send that succeeds (the
    // outbox's retry) is the link-up.
    w.link_down.store(false, Ordering::Release);
    w.bridge.resend_unacknowledged(true).await;
    tokio::time::timeout(std::time::Duration::from_secs(2), w.bridge.link_recovered())
        .await
        .expect("a send succeeding after failures raises a link-up");
    w.bridge.link_up().await;
    let (maps, _) = drain(&mut w).await;
    assert_eq!(maps.len(), 1, "one report per namespace per link-up");
    assert_eq!(maps[0]["payload"]["namespace"], NS);

    // A link-up the transport signalled (a new mediator session) reports
    // once, and its own sends do not count as a second one.
    w.bridge.link_up().await;
    let (maps, _) = drain(&mut w).await;
    assert_eq!(maps.len(), 1);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(200),
            w.bridge.link_recovered()
        )
        .await
        .is_err(),
        "no second link-up"
    );
    // One outbox entry for the report, whatever was sent.
    let reports = w
        .bridge
        .store()
        .list::<OutboxEntry>(Table::Outbox)
        .unwrap()
        .into_iter()
        .filter(|(k, _)| k.starts_with(vgi_bridge::rolemap::OUTBOX_PREFIX))
        .count();
    assert_eq!(reports, 1);
}

#[tokio::test]
async fn a_namespace_the_bridge_starts_serving_is_reported() {
    let mut w = world(Options::default()).await;
    w.bridge.started_serving(NS).await;
    let (maps, other) = drain(&mut w).await;
    assert_eq!((maps.len(), other), (1, 0));
    // A namespace that is not bound (or unknown) is not reported.
    w.bridge.started_serving("ns_unknown").await;
    w.quiet().await;
}

#[tokio::test]
async fn a_resent_report_carries_the_map_applied_now_not_the_one_first_queued() {
    use std::sync::atomic::Ordering;
    let mut w = world(Options::default()).await;
    // Queued while the link is down: no stale repository yet.
    w.link_down.store(true, Ordering::Release);
    w.bridge.report_role_map(NS).await;
    let key = vgi_bridge::rolemap::outbox_key(NS);
    let queued: OutboxEntry = w.bridge.store().get(Table::Outbox, &key).unwrap().unwrap();
    assert!(queued.payload["event"].get("stale").is_none());
    // Before the resend, a repository comes to be projected under another
    // map than the one applied now.
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    w.bridge
        .store()
        .update::<RepoRecord, _>(Table::Repos, "github.com#812", |r| {
            Ok((
                r.map(|mut r| {
                    r.role_map = serde_json::from_value(map("admin", "admin", "none")).ok();
                    r
                }),
                (),
            ))
        })
        .unwrap();
    // The resend is built afresh: a later issuedAt carries the later map.
    w.link_down.store(false, Ordering::Release);
    w.bridge.resend_unacknowledged(true).await;
    let (maps, _) = drain(&mut w).await;
    let last = maps.last().expect("the report is sent again");
    assert_eq!(
        last["payload"]["event"]["stale"],
        json!(["github.com/acme/widgets"])
    );
}

#[tokio::test]
async fn a_pending_report_is_dropped_once_the_vtc_takes_an_event_version_below_0_3() {
    let mut w = world(Options {
        event_version: Some("0.2"),
        ..Options::default()
    })
    .await;
    // A report queued under 0.3, before the version was lowered.
    let key = vgi_bridge::rolemap::outbox_key(NS);
    w.bridge
        .store()
        .put(
            Table::Outbox,
            &key,
            &OutboxEntry::result(json!({
                "namespace": NS,
                "event": { "type": "roleMapReported", "roleMap": map("admin", "maintain", "none") },
            })),
        )
        .unwrap();
    w.bridge.resend_unacknowledged(true).await;
    w.quiet().await;
    assert!(
        w.bridge
            .store()
            .get::<OutboxEntry>(Table::Outbox, &key)
            .unwrap()
            .is_none(),
        "dropped, not sent under 0.2"
    );
}
