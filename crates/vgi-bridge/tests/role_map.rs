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
    mount_any_token(server).await;
    for (endpoint, body) in [("collaborators", json!([])), ("invitations", json!([]))] {
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
    w.send_job_0_2(json!({
        "jobId": format!("job_{name}"), "namespace": NS, "kind": "projectRoles",
        "repo": format!("github.com/acme/{name}"), "desiredRoles": roles,
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
