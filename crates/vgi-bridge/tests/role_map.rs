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
    w.send_job(json!({
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
maintain = "maintain"

[github.namespaces.acme.role_map]
maintain = "write"

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
            ("bob".into(), "push".into()),
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
