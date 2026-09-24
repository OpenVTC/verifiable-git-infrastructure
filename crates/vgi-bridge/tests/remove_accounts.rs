//! `git-ns/bridge/job` 0.2: `projectRoles` with `removeAccounts` — the job a
//! VTC sends to revert a `roleAdded` drift (`git-ns/drift/resolve`). The
//! bridge takes exactly the named accounts' direct roles off the
//! repository, though it never projected them; refuses the job shapes the
//! specification refuses; never removes the namespace's owner or its own
//! App or bot; and still takes 0.1 jobs.

mod common;

use std::sync::Arc;

use common::*;
use serde_json::{Value, json};
use trust_tasks_proof::affinidi::Verifier;
use vgi_bridge::registry::forgejo_secret;
use vgi_bridge::seal::MasterKey;
use vgi_bridge::store::{JobRecord, NamespaceRecord, NamespaceState, RepoRecord, Table};
use vgi_bridge::transport::memory::ChannelLink;
use vgi_bridge::{Bridge, BridgeConfig, BridgeIdentity, BridgeParts, Store};
use vgi_forge::{Namespace, NamespaceBinding, NamespaceKind, Resource};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ALICE: u64 = 4410987;
const EVE: u64 = 5550123;

fn alice_owns(host: &str) -> Value {
    json!({
        "subject": "did:webvh:QmAliceScid1:acme-vtc.example:alice",
        "account": { "forge": host, "id": ALICE.to_string(), "login": "alice-acme" },
        "right": "git.repo.own",
    })
}

fn account(host: &str, id: u64, login: &str) -> Value {
    json!({ "forge": host, "id": id.to_string(), "login": login })
}

fn revert_job(id: &str, repo: &str, remove: Value) -> Value {
    let host = repo.split('/').next().unwrap();
    json!({
        "jobId": id, "namespace": NS, "kind": "projectRoles", "repo": repo,
        "desiredRoles": [alice_owns(host)],
        "removeAccounts": remove,
    })
}

/// `acme/widgets` on the mock GitHub: Alice holds `admin` (her projected
/// role), and whoever `extra` lists holds what it says.
async fn mount_github_roles(server: &MockServer, owner: &str, extra: Vec<Value>) {
    mount_any_token(server).await;
    let mut collaborators =
        vec![json!({ "id": ALICE, "login": "alice-acme", "role_name": "admin" })];
    collaborators.extend(extra);
    Mock::given(method("GET"))
        .and(path(format!("/repos/{owner}/widgets/collaborators")))
        .respond_with(ResponseTemplate::new(200).set_body_json(Value::Array(collaborators)))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/repos/{owner}/widgets/invitations")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(server)
        .await;
}

/// Every collaborator DELETE the bridge sent.
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

fn roles_step(result: &Value) -> Value {
    result["payload"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["step"] == "roles")
        .cloned()
        .unwrap_or_else(|| panic!("no roles step: {result}"))
}

fn not_recorded(w: &World, job: &str) {
    assert!(
        w.bridge
            .store()
            .get::<JobRecord>(Table::Jobs, job)
            .unwrap()
            .is_none(),
        "{job} was refused, not recorded"
    );
}

#[tokio::test]
async fn a_0_2_job_removes_a_collaborator_added_on_github_by_id() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    // Eve was given `write` on GitHub, outside the bridge, and has since
    // renamed her account: the job still carries the login the VTC saw.
    mount_github_roles(
        &w.server,
        "acme",
        vec![json!({ "id": EVE, "login": "eve-renamed", "role_name": "write" })],
    )
    .await;
    Mock::given(method("DELETE"))
        .and(path("/repos/acme/widgets/collaborators/eve-renamed"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&w.server)
        .await;

    let job = w
        .send_job_0_2(revert_job(
            "job_rv",
            "github.com/acme/widgets",
            json!([account("github.com", EVE, "eve-dev")]),
        ))
        .await;
    let resp = w.next().await;
    assert_eq!(resp["type"], format!("{JOB_0_2}#response"));
    assert_eq!(resp["threadId"], job["id"]);
    assert_eq!(
        resp["payload"],
        json!({ "jobId": "job_rv", "accepted": true })
    );
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["outcome"], "succeeded", "{result}");
    assert_eq!(roles_step(&result)["outcome"], "applied");
    // Removed under the login GitHub reports for the id now, never the
    // job's display login; Alice's role untouched.
    assert_eq!(
        deletes(&w.server).await,
        vec!["/repos/acme/widgets/collaborators/eve-renamed"]
    );
    // Eve never becomes part of the projection.
    let rec: RepoRecord = w
        .bridge
        .store()
        .get(Table::Repos, "github.com#812")
        .unwrap()
        .unwrap();
    assert_eq!(
        rec.roles.iter().map(|r| r.account.id).collect::<Vec<_>>(),
        vec![ALICE]
    );
}

#[tokio::test]
async fn removing_an_account_that_holds_no_role_is_already_converged() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    mount_github_roles(&w.server, "acme", vec![]).await;
    w.send_job_0_2(revert_job(
        "job_nr",
        "github.com/acme/widgets",
        json!([account("github.com", EVE, "eve-dev")]),
    ))
    .await;
    assert_eq!(w.next().await["payload"]["accepted"], true);
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["outcome"], "succeeded", "{result}");
    assert_eq!(roles_step(&result)["outcome"], "unchanged");
    assert!(deletes(&w.server).await.is_empty());
}

#[tokio::test]
async fn remove_accounts_shapes_the_spec_refuses_are_malformed_and_not_recorded() {
    let mut w = world(Options::default()).await;
    let gh = "github.com";

    // An account in both desiredRoles and removeAccounts (by forge and id;
    // the login differing changes nothing).
    w.send_job_0_2(revert_job(
        "j_overlap",
        "github.com/acme/widgets",
        json!([account(gh, ALICE, "someone-else")]),
    ))
    .await;
    let err = w.next().await;
    assert!(err["type"].as_str().unwrap().contains("trust-task-error"));
    assert_eq!(err["payload"]["code"], "malformedRequest");
    assert!(
        err["payload"]["message"]
            .as_str()
            .unwrap()
            .contains("both `desiredRoles` and `removeAccounts`"),
        "{err}"
    );

    // Namespace-level projectRoles (no `repo`): removeAccounts never
    // touches the namespace itself.
    w.send_job_0_2(json!({
        "jobId": "j_ns", "namespace": NS, "kind": "projectRoles", "desiredRoles": [],
        "removeAccounts": [account(gh, EVE, "eve-dev")],
    }))
    .await;
    let err = w.next().await;
    assert_eq!(err["payload"]["code"], "malformedRequest", "{err}");
    assert!(
        err["payload"]["message"]
            .as_str()
            .unwrap()
            .contains("`repo`")
    );

    // An account on another forge than the namespace's.
    w.send_job_0_2(revert_job(
        "j_forge",
        "github.com/acme/widgets",
        json!([account("codeberg.org", EVE, "eve-dev")]),
    ))
    .await;
    assert_eq!(w.next().await["payload"]["code"], "malformedRequest");

    // Another kind carrying it.
    w.send_job_0_2(json!({
        "jobId": "j_kind", "namespace": NS, "kind": "inspect", "repo": "github.com/acme/widgets",
        "removeAccounts": [account(gh, EVE, "eve-dev")],
    }))
    .await;
    assert_eq!(w.next().await["payload"]["code"], "malformedRequest");

    // Empty, or one account twice.
    w.send_job_0_2(revert_job("j_empty", "github.com/acme/widgets", json!([])))
        .await;
    assert_eq!(w.next().await["payload"]["code"], "malformedRequest");
    w.send_job_0_2(revert_job(
        "j_twice",
        "github.com/acme/widgets",
        json!([account(gh, EVE, "eve-dev"), account(gh, EVE, "eve-renamed")]),
    ))
    .await;
    assert_eq!(w.next().await["payload"]["code"], "malformedRequest");

    // A 0.1 job has no `removeAccounts` member at all.
    let doc = w
        .doc(
            JOB,
            revert_job(
                "j_v01",
                "github.com/acme/widgets",
                json!([account(gh, EVE, "eve-dev")]),
            ),
            None,
        )
        .await;
    w.deliver(doc).await;
    assert_eq!(w.next().await["payload"]["code"], "malformedRequest");

    for j in [
        "j_overlap",
        "j_ns",
        "j_forge",
        "j_kind",
        "j_empty",
        "j_twice",
        "j_v01",
    ] {
        not_recorded(&w, j);
    }
    assert!(deletes(&w.server).await.is_empty());
}

#[tokio::test]
async fn a_0_1_project_roles_job_is_still_taken_and_answered_as_0_1() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    mount_github_roles(
        &w.server,
        "acme",
        vec![json!({ "id": EVE, "login": "eve-dev", "role_name": "write" })],
    )
    .await;
    w.send_job(json!({
        "jobId": "job_01", "namespace": NS, "kind": "projectRoles",
        "repo": "github.com/acme/widgets", "desiredRoles": [alice_owns("github.com")],
    }))
    .await;
    let resp = w.next().await;
    assert_eq!(resp["type"], format!("{JOB}#response"));
    assert_eq!(resp["payload"]["accepted"], true);
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["outcome"], "succeeded", "{result}");
    // 0.1 semantics unchanged: a role the bridge never projected stays.
    assert!(deletes(&w.server).await.is_empty());
}

#[tokio::test]
async fn the_personal_accounts_owner_is_never_removed() {
    let mut w = world(Options {
        kind: NamespaceKind::User,
        ..Options::default()
    })
    .await;
    let r = Resource::parse("github.com/alice/widgets").unwrap();
    seed_repo(w.bridge.store(), &r, 812);
    mount_github_roles(&w.server, "alice", vec![]).await;
    // Owner id 500 (the seeded namespace's), and Eve beside it: Eve holds
    // nothing, the owner is refused.
    w.send_job_0_2(json!({
        "jobId": "job_own", "namespace": NS, "kind": "projectRoles",
        "repo": "github.com/alice/widgets", "desiredRoles": [],
        "removeAccounts": [account("github.com", 500, "alice"), account("github.com", EVE, "eve-dev")],
    }))
    .await;
    assert_eq!(w.next().await["payload"]["accepted"], true);
    let result = w.next_of(RESULT).await;
    assert_ne!(result["payload"]["outcome"], "succeeded", "{result}");
    let step = roles_step(&result);
    assert_eq!(step["outcome"], "failed");
    assert!(
        step["detail"].as_str().unwrap().contains("never removed"),
        "{step}"
    );
    assert!(deletes(&w.server).await.is_empty());
}

#[tokio::test]
async fn the_bridges_own_github_app_is_never_removed() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    mount_github_roles(
        &w.server,
        "acme",
        vec![json!({ "id": 777, "login": "acme-vgi-bridge[bot]", "role_name": "admin" })],
    )
    .await;
    Mock::given(method("DELETE"))
        .and(path_regex(r"^/repos/acme/widgets/collaborators/"))
        .respond_with(ResponseTemplate::new(204))
        .expect(0)
        .mount(&w.server)
        .await;
    w.send_job_0_2(revert_job(
        "job_bot",
        "github.com/acme/widgets",
        json!([account("github.com", 777, "acme-vgi-bridge[bot]")]),
    ))
    .await;
    assert_eq!(w.next().await["payload"]["accepted"], true);
    let result = w.next_of(RESULT).await;
    let step = roles_step(&result);
    assert_eq!(step["outcome"], "failed", "{result}");
    assert!(step["detail"].as_str().unwrap().contains("never removed"));
}

// ── access that is not a direct role (GitHub) ───────────────────────────

/// Eve holds `write` directly; the job removes it. After that GitHub
/// answers her effective permission with `permission` (`role_name`), and
/// the organisation membership and the repository's teams as given (a
/// team whose membership is not mounted is one she is not in).
async fn mount_github_eve_after_removal(
    server: &MockServer,
    role_name: &str,
    org_role: Option<&str>,
    teams: &[(&str, &str, bool)],
    private: bool,
) {
    mount_github_roles(
        server,
        "acme",
        vec![json!({ "id": EVE, "login": "eve-renamed", "role_name": "write" })],
    )
    .await;
    Mock::given(method("DELETE"))
        .and(path("/repos/acme/widgets/collaborators/eve-renamed"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/user/{EVE}")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "id": EVE, "login": "eve-renamed" })),
        )
        .mount(server)
        .await;
    let permission = match role_name {
        "maintain" => "write",
        "triage" => "read",
        p => p,
    };
    Mock::given(method("GET"))
        .and(path(
            "/repos/acme/widgets/collaborators/eve-renamed/permission",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "permission": permission, "role_name": role_name,
            "user": { "id": EVE, "login": "eve-renamed" },
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 812, "full_name": "acme/widgets", "private": private,
            "visibility": if private { "private" } else { "public" },
        })))
        .mount(server)
        .await;
    if let Some(role) = org_role {
        Mock::given(method("GET"))
            .and(path("/orgs/acme/memberships/eve-renamed"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "state": "active", "role": role })),
            )
            .mount(server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/teams"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(Value::Array(
                teams
                    .iter()
                    .map(|(name, slug, _)| json!({ "name": name, "slug": slug }))
                    .collect(),
            )),
        )
        .mount(server)
        .await;
    for (_, slug, member) in teams {
        if *member {
            Mock::given(method("GET"))
                .and(path(format!(
                    "/orgs/acme/teams/{slug}/memberships/eve-renamed"
                )))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({ "state": "active", "role": "member" })),
                )
                .mount(server)
                .await;
        }
    }
}

/// Every request that could change something, other than minting tokens.
async fn writes(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.method != http::Method::GET && !r.url.path().ends_with("/access_tokens"))
        .map(|r| format!("{} {}", r.method, r.url.path()))
        .collect()
}

async fn run_revert(w: &mut World, job: &str, repo: &str, host: &str) -> Value {
    w.send_job_0_2(revert_job(
        job,
        repo,
        json!([account(host, EVE, "eve-dev")]),
    ))
    .await;
    assert_eq!(w.next().await["payload"]["accepted"], true);
    w.next_of(RESULT).await
}

/// Job 0.2: access through a team is not a role on the repository. The
/// direct role goes, the team stays untouched, and the `roles` step fails
/// naming the team — only the one she is in.
#[tokio::test]
async fn access_through_a_github_team_fails_the_roles_step_and_names_the_team() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    mount_github_eve_after_removal(
        &w.server,
        "maintain",
        Some("member"),
        &[("Core", "core", true), ("Docs", "docs", false)],
        false,
    )
    .await;
    let result = run_revert(&mut w, "job_team", "github.com/acme/widgets", "github.com").await;
    assert_eq!(result["payload"]["outcome"], "failed", "{result}");
    let step = roles_step(&result);
    assert_eq!(step["outcome"], "failed", "{result}");
    let detail = step["detail"].as_str().unwrap();
    assert!(detail.contains("eve-dev"), "{detail}");
    assert!(
        detail.contains("`maintain` access through team `Core`"),
        "{detail}"
    );
    assert!(!detail.contains("Docs"), "{detail}");
    assert!(!detail.contains("member of"), "{detail}");
    // The direct role is gone; nothing about the team or the organisation
    // was changed.
    assert_eq!(
        writes(&w.server).await,
        vec!["DELETE /repos/acme/widgets/collaborators/eve-renamed"]
    );
    // Membership was read with a token that may read it.
    let asked_members = w
        .server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path().ends_with("/access_tokens"))
        .any(|r| {
            serde_json::from_slice::<Value>(&r.body).unwrap()["permissions"]["members"] == "read"
        });
    assert!(asked_members);
}

/// An organisation owner is the repository's admin whatever its
/// collaborators say: reported, and the organisation left as it is.
#[tokio::test]
async fn a_github_organisation_owner_fails_the_roles_step() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    mount_github_eve_after_removal(&w.server, "admin", Some("admin"), &[], false).await;
    let result = run_revert(&mut w, "job_owner", "github.com/acme/widgets", "github.com").await;
    let step = roles_step(&result);
    assert_eq!(step["outcome"], "failed", "{result}");
    let detail = step["detail"].as_str().unwrap();
    assert!(
        detail.contains("`admin` access as an owner of `acme`"),
        "{detail}"
    );
    assert!(detail.contains("does not change teams or the organisation"));
    assert_eq!(
        writes(&w.server).await,
        vec!["DELETE /repos/acme/widgets/collaborators/eve-renamed"]
    );
}

/// On a private repository, `read` left from the organisation's base
/// permission is access too.
#[tokio::test]
async fn a_github_base_permission_on_a_private_repository_is_reported() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    mount_github_eve_after_removal(&w.server, "read", Some("member"), &[], true).await;
    let result = run_revert(&mut w, "job_base", "github.com/acme/widgets", "github.com").await;
    let step = roles_step(&result);
    assert_eq!(step["outcome"], "failed", "{result}");
    assert!(
        step["detail"]
            .as_str()
            .unwrap()
            .contains("`read` access as a member of `acme` (its base permission)"),
        "{step}"
    );
}

/// `read` on a public repository is what everyone has: the removal
/// succeeded.
#[tokio::test]
async fn read_on_a_public_github_repository_is_no_access_left() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    mount_github_eve_after_removal(&w.server, "read", None, &[], false).await;
    let result = run_revert(
        &mut w,
        "job_public",
        "github.com/acme/widgets",
        "github.com",
    )
    .await;
    assert_eq!(result["payload"]["outcome"], "succeeded", "{result}");
    assert_eq!(roles_step(&result)["outcome"], "applied");
}

// ── Forgejo ─────────────────────────────────────────────────────────────

const FJ: &str = "127.0.0.1";
const BOT: &str = "acme-vgi-bot";
const BOT_ID: u64 = 900;

/// A bridge serving one bound Forgejo organisation, `acme`, with
/// `acme/widgets` (forge id 812) managed and Alice its projected owner.
async fn forgejo_world() -> World {
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
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "id": BOT_ID, "login": BOT })),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/repos/acme/widgets"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "id": 812, "full_name": "acme/widgets" })),
        )
        .mount(&server)
        .await;
    let collaborators = [
        (ALICE, "alice-acme", "admin"),
        (EVE, "eve-renamed", "write"),
        (BOT_ID, BOT, "admin"),
    ];
    Mock::given(method("GET"))
        .and(path("/api/v1/repos/acme/widgets/collaborators"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-total-count", "3")
                .set_body_json(Value::Array(
                    collaborators
                        .iter()
                        .map(|(id, login, _)| json!({ "id": id, "login": login }))
                        .collect(),
                )),
        )
        .mount(&server)
        .await;
    for (_, login, perm) in collaborators {
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/repos/acme/widgets/collaborators/{login}/permission"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "permission": perm })))
            .mount(&server)
            .await;
    }

    let dir = tempfile::tempdir().unwrap();
    let (vtc, _) = BridgeIdentity::generate_did_key().unwrap();
    let cfg = BridgeConfig::parse(&format!(
        r#"
vtc_did = "{}"
trust_registry_did = "did:webvh:QmReg:registry.acme.example"
mediator_did = "did:web:mediator.acme.example"
public_url = "https://bridge.acme.example/"
data_dir = "{}"
resend_secs = 3600

[verify_trust]
action = "https://code.example/vgi/verify-trust@0123456789abcdef0123456789abcdef01234567"
version = "v0.5.0"
sha256 = "{}"

[[forgejo]]
base_url = "{}"
bot_login = "{BOT}"
oauth_client_id = "cid"
"#,
        vtc.did(),
        dir.path().display(),
        "a".repeat(64),
        server.uri(),
    ))
    .unwrap();
    let store = Store::in_memory(MasterKey::generate().unwrap()).unwrap();
    for (what, v) in [
        ("bot-token", "bot-token-0000000000000000000000000000abcd"),
        ("oauth-client-secret", "cs"),
        ("webhook-secret", "wh"),
    ] {
        store
            .put_secret(&forgejo_secret(FJ, what), v.as_bytes())
            .unwrap();
    }
    let ns_resource = Resource::parse(&format!("{FJ}/acme")).unwrap();
    let namespace = Namespace::new(ns_resource.clone(), NamespaceKind::Organization)
        .with_owner_id(600)
        .with_installation(1);
    let mut ns = NamespaceRecord::pending(NS, ns_resource.clone());
    ns.state = NamespaceState::Bound;
    ns.binding = Some(NamespaceBinding::new(namespace, vec![]));
    ns.managed.insert(812);
    store.put(Table::Namespaces, NS, &ns).unwrap();
    let mut rec = RepoRecord::new(NS, ns_resource.join("widgets").unwrap(), 812);
    rec.roles_known = true;
    store.put(Table::Repos, &rec.key(), &rec).unwrap();

    let adapters = vgi_bridge::build_adapters(&cfg, &store).await.unwrap();
    let identity = BridgeIdentity::store_did_key(&store, &[5u8; 32]).unwrap();
    let (link, inbox) = ChannelLink::new();
    let bridge = Bridge::new(BridgeParts::new(
        cfg,
        identity,
        store,
        adapters,
        Arc::new(link),
        Arc::new(Verifier::for_did_key()),
    ));
    bridge.restore().await.unwrap();
    World {
        server,
        bridge,
        vtc,
        inbox,
        dir,
        verifier: Arc::new(FakeVerifier {
            trusted: vec![],
            seen: Default::default(),
        }),
    }
}

#[tokio::test]
async fn a_0_2_job_removes_a_collaborator_added_on_forgejo_by_id() {
    let mut w = forgejo_world().await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/repos/acme/widgets/collaborators/eve-renamed"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&w.server)
        .await;
    w.send_job_0_2(revert_job(
        "job_fj",
        &format!("{FJ}/acme/widgets"),
        json!([account(FJ, EVE, "eve-dev")]),
    ))
    .await;
    let resp = w.next().await;
    assert_eq!(resp["type"], format!("{JOB_0_2}#response"));
    assert_eq!(resp["payload"]["accepted"], true, "{resp}");
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["outcome"], "succeeded", "{result}");
    assert_eq!(roles_step(&result)["outcome"], "applied");
    assert_eq!(
        deletes(&w.server).await,
        vec!["/api/v1/repos/acme/widgets/collaborators/eve-renamed"]
    );
}

#[tokio::test]
async fn the_bridges_own_forgejo_bot_is_never_removed() {
    let mut w = forgejo_world().await;
    w.send_job_0_2(revert_job(
        "job_fjbot",
        &format!("{FJ}/acme/widgets"),
        json!([account(FJ, BOT_ID, BOT)]),
    ))
    .await;
    assert_eq!(w.next().await["payload"]["accepted"], true);
    let result = w.next_of(RESULT).await;
    let step = roles_step(&result);
    assert_eq!(step["outcome"], "failed", "{result}");
    assert!(step["detail"].as_str().unwrap().contains("never removed"));
    assert!(deletes(&w.server).await.is_empty());
}

/// After Eve's direct role goes, Forgejo answers her effective permission
/// with `permission`, whether she owns the organisation with `owner`, and
/// the repository's teams as given (id, name, whether she is in it).
async fn mount_forgejo_eve_after_removal(
    server: &MockServer,
    permission: &str,
    owner: bool,
    teams: &[(u64, &str, bool)],
) {
    Mock::given(method("DELETE"))
        .and(path("/api/v1/repos/acme/widgets/collaborators/eve-renamed"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/users/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true, "data": [{ "id": EVE, "login": "eve-renamed" }],
        })))
        .mount(server)
        .await;
    // Ahead of the world's answer (her direct `write`).
    Mock::given(method("GET"))
        .and(path(
            "/api/v1/repos/acme/widgets/collaborators/eve-renamed/permission",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "permission": permission })))
        .with_priority(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/users/eve-renamed/orgs/acme/permissions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "is_owner": owner, "is_admin": owner, "can_write": true, "can_read": true,
            "can_create_repository": owner,
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/repos/acme/widgets/teams"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-total-count", teams.len().to_string())
                .set_body_json(Value::Array(
                    teams
                        .iter()
                        .map(|(id, name, _)| json!({ "id": id, "name": name, "permission": "write" }))
                        .collect(),
                )),
        )
        .mount(server)
        .await;
    for (id, _, member) in teams {
        if *member {
            Mock::given(method("GET"))
                .and(path(format!("/api/v1/teams/{id}/members/eve-renamed")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({ "id": EVE, "login": "eve-renamed" })),
                )
                .mount(server)
                .await;
        }
    }
}

/// Job 0.2 on Forgejo: write access through a team is reported, and only
/// the direct role is removed.
#[tokio::test]
async fn access_through_a_forgejo_team_fails_the_roles_step_and_names_the_team() {
    let mut w = forgejo_world().await;
    mount_forgejo_eve_after_removal(
        &w.server,
        "write",
        false,
        &[(3, "Developers", true), (4, "Docs", false)],
    )
    .await;
    let result = run_revert(&mut w, "job_fjteam", &format!("{FJ}/acme/widgets"), FJ).await;
    let step = roles_step(&result);
    assert_eq!(step["outcome"], "failed", "{result}");
    let detail = step["detail"].as_str().unwrap();
    assert!(
        detail.contains("`write` access through team `Developers`"),
        "{detail}"
    );
    assert!(!detail.contains("Docs"), "{detail}");
    assert!(!detail.contains("owner"), "{detail}");
    assert_eq!(
        writes(&w.server).await,
        vec!["DELETE /api/v1/repos/acme/widgets/collaborators/eve-renamed"]
    );
}

/// A Forgejo organisation owner (the Owners team) keeps `owner` access:
/// reported, never changed.
#[tokio::test]
async fn a_forgejo_organisation_owner_fails_the_roles_step() {
    let mut w = forgejo_world().await;
    mount_forgejo_eve_after_removal(&w.server, "owner", true, &[(1, "Owners", true)]).await;
    let result = run_revert(&mut w, "job_fjowner", &format!("{FJ}/acme/widgets"), FJ).await;
    let step = roles_step(&result);
    assert_eq!(step["outcome"], "failed", "{result}");
    let detail = step["detail"].as_str().unwrap();
    assert!(
        detail.contains("`admin` access as an owner of `acme` and through team `Owners`"),
        "{detail}"
    );
    assert_eq!(
        writes(&w.server).await,
        vec!["DELETE /api/v1/repos/acme/widgets/collaborators/eve-renamed"]
    );
}

/// `read` on a public Forgejo repository is what everyone has.
#[tokio::test]
async fn read_on_a_public_forgejo_repository_is_no_access_left() {
    let mut w = forgejo_world().await;
    mount_forgejo_eve_after_removal(&w.server, "read", false, &[]).await;
    let result = run_revert(&mut w, "job_fjread", &format!("{FJ}/acme/widgets"), FJ).await;
    assert_eq!(result["payload"]["outcome"], "succeeded", "{result}");
    assert_eq!(roles_step(&result)["outcome"], "applied");
}
