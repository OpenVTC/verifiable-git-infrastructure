//! Capabilities, repository operations, role projection (with the merge
//! allow-list) and the bootstrap, against a mock Forgejo.

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use serde_json::{Value, json};
use vgi_forge::{
    Drift, EffectiveRights, Forge, ForgeAccount, ForgeError, ForgeHooks, ForgeRole, HookDecision,
    LinkMethod, MergeMethod, Namespace, NamespaceKind, Projection, ProtectionGap, RepoSpec,
    RequiredCheckKind, Resource, Right, RoleAssignment, RoleMap, RoleOutcome, StepAction,
    StepOutcome, Unlisted, VgiConfig, Visibility, run_plan,
};
use vgi_forge_forgejo::MergeFallback;
use vgi_forge_forgejo::plan::{KEYRING_PATH, WORKFLOW_PATH};
use wiremock::matchers::{body_json, body_partial_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const SUM: &str = "4f1c0a5e9d0b8b1f3c5f8a0d2e7b6c9a1d3e5f7a9b0c2d4e6f8a1b3c5d7e9f0a";
const PATTERNS: &str = ".forgejo/workflows/**;.gitea/workflows/**;.github/workflows/**;.forgejo/trusted-platform-keys.asc";

fn vgi_config() -> VgiConfig {
    VgiConfig::new(
        "did:webvh:registry",
        "did:webvh:acme-vtc",
        format!("OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@{SHA}"),
        "v0.5.0",
    )
    .with_verify_trust_sha256(SUM)
}

async fn mount_repo(server: &MockServer, name: &str, body: Value) {
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/repos/acme/{name}")))
        .and(BotToken)
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

/// Collaborators and each one's permission.
async fn mount_people(server: &MockServer, name: &str, people: &[(u64, &str, &str)]) {
    let list: Vec<Value> = people.iter().map(|(id, l, _)| user(*id, l)).collect();
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/repos/acme/{name}/collaborators")))
        .and(BotToken)
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-total-count", people.len().to_string())
                .set_body_json(list),
        )
        .mount(server)
        .await;
    for (id, login, perm) in people {
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/repos/acme/{name}/collaborators/{login}/permission"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "permission": perm, "role_name": perm, "user": user(*id, login)
            })))
            .mount(server)
            .await;
    }
}

async fn mount_rules(server: &MockServer, name: &str, rules: Value) {
    Mock::given(method("GET"))
        .and(path(format!(
            "/api/v1/repos/acme/{name}/branch_protections"
        )))
        .and(BotToken)
        .respond_with(ResponseTemplate::new(200).set_body_json(rules))
        .mount(server)
        .await;
}

async fn mount_lookup(server: &MockServer, id: u64, login: &str) {
    Mock::given(method("GET"))
        .and(path("/api/v1/users/search"))
        .and(query_param("uid", id.to_string()))
        .and(BotToken)
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "ok": true, "data": [user(id, login)] })),
        )
        .mount(server)
        .await;
}

/// Fails the test if any write reaches the server.
async fn forbid_writes(server: &MockServer) {
    for m in ["POST", "PUT", "PATCH", "DELETE"] {
        Mock::given(method(m))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(server)
            .await;
    }
}

// ── capabilities ─────────────────────────────────────────────────────────

#[tokio::test]
async fn capabilities_follow_the_namespace() {
    let (_server, forge) = server_and_forge().await;
    let org = Namespace::new(acme(), NamespaceKind::Organization).with_installation(TEAM_ID);
    let user_ns = Namespace::new(alice_ns(), NamespaceKind::User).with_installation(BOT_ID);
    let manual = Namespace::new(acme(), NamespaceKind::Organization);

    let c = forge.capabilities(&org);
    assert!(c.automation && c.bot_can_create_repos);
    assert!(!c.webhooks, "role and protection drift are swept for");
    assert!(!c.per_repo_tokens);
    assert_eq!(c.required_checks, RequiredCheckKind::BranchProtection);
    assert_eq!(c.account_link, LinkMethod::AuthorizationCodePkce);
    assert_eq!(
        c.role_levels,
        [
            ForgeRole::Read,
            ForgeRole::Write,
            ForgeRole::Maintain,
            ForgeRole::Admin
        ]
    );
    let c = forge.capabilities(&user_ns);
    assert!(c.automation && !c.bot_can_create_repos);
    let c = forge.capabilities(&manual);
    assert!(!c.automation && !c.bot_can_create_repos);

    let map = RoleMap::default();
    let r = |x| EffectiveRights::from_granted([x]);
    assert_eq!(
        forge.map_role(&org, r(Right::RepoOwn), &map),
        ForgeRole::Admin
    );
    assert_eq!(
        forge.map_role(&org, r(Right::RepoMaintain), &map),
        ForgeRole::Maintain,
        "write plus the merge allow-list"
    );
    assert_eq!(
        forge.map_role(&org, r(Right::CommitSign), &map),
        ForgeRole::None
    );
    assert_eq!(
        forge.map_role(&org, r(Right::CommitSign), &RoleMap::with_committer_write()),
        ForgeRole::Write
    );
}

#[tokio::test]
async fn resources_are_checked_before_any_request() {
    let (server, forge) = server_and_forge().await;
    forbid_writes(&server).await;
    assert_eq!(
        forge.normalize("Codeberg.org/Acme/Widgets").unwrap(),
        repo("widgets")
    );
    assert!(matches!(
        forge.normalize("github.com/acme/widgets"),
        Err(ForgeError::WrongResource { .. })
    ));
    let e = forge
        .inspect(&Resource::parse("codeberg.org/unbound/x").unwrap())
        .await
        .unwrap_err();
    assert!(matches!(e, ForgeError::NotBound { .. }));
    assert!(matches!(
        forge.inspect(&acme()).await,
        Err(ForgeError::WrongResource { .. })
    ));
    // A deserialised resource can be deeper than owner/repo; it is refused,
    // not truncated to `acme/widgets`.
    let deep: Resource = serde_json::from_str("\"codeberg.org/acme/evil/widgets\"").unwrap();
    assert!(forge.inspect(&deep).await.is_err());
    assert!(forge.archive_repo(&deep).await.is_err());
    assert!(
        forge
            .bootstrap_plan(&RepoSpec::new(deep), &vgi_config())
            .is_err()
    );
}

// ── create / archive ─────────────────────────────────────────────────────

#[tokio::test]
async fn create_repo_in_an_org() {
    let (server, forge) = server_and_forge().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/repos/acme/gadgets"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "message": "" })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/orgs/acme/repos"))
        .and(BotToken)
        .and(body_json(json!({
            "name": "gadgets",
            "private": true,
            "auto_init": true,
            "readme": "Default",
            "default_branch": "main",
            "description": "Gadgets",
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": 9001, "full_name": "acme/gadgets", "private": true, "default_branch": "main"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let spec = RepoSpec::new(repo("gadgets"))
        .with_visibility(Visibility::Private)
        .with_description("Gadgets");
    let state = forge.create_repo(&spec).await.unwrap();
    assert_eq!(state.forge_id, 9001);
    assert_eq!(state.resource, repo("gadgets"));
    assert_eq!(state.visibility, Visibility::Private);
    assert_eq!(state.default_branch.as_deref(), Some("main"));
}

#[tokio::test]
async fn create_repo_refuses_an_existing_name() {
    let (server, forge) = server_and_forge().await;
    mount_repo(&server, "gadgets", repo_json(77, "acme/gadgets", false)).await;
    Mock::given(method("POST"))
        .and(path("/api/v1/orgs/acme/repos"))
        .and(body_partial_json(json!({ "name": "gadgets" })))
        .respond_with(ResponseTemplate::new(201))
        .expect(0)
        .mount(&server)
        .await;
    assert_eq!(
        forge
            .create_repo(&RepoSpec::new(repo("gadgets")))
            .await
            .unwrap_err(),
        ForgeError::AlreadyExists {
            resource: "codeberg.org/acme/gadgets".into(),
            forge_id: Some(77)
        }
    );

    // Created by someone else between the check and the create.
    Mock::given(method("GET"))
        .and(path("/api/v1/repos/acme/racy"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/orgs/acme/repos"))
        .and(body_json(json!({
            "name": "racy", "private": false, "auto_init": true, "readme": "Default",
            "default_branch": "main",
        })))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "message": "The repository with the same name already exists."
        })))
        .mount(&server)
        .await;
    assert!(matches!(
        forge.create_repo(&RepoSpec::new(repo("racy"))).await,
        Err(ForgeError::AlreadyExists { forge_id: None, .. })
    ));
}

#[tokio::test]
async fn create_repo_outside_an_org_or_internal_is_refused() {
    let (server, forge) = server_and_forge().await;
    forbid_writes(&server).await;
    let spec = RepoSpec::new(alice_ns().join("gadgets").unwrap());
    let e = forge.create_repo(&spec).await.unwrap_err();
    let ForgeError::Unsupported { hint, .. } = e else {
        panic!("expected Unsupported, got {e:?}")
    };
    assert!(
        hint.contains("acme-vgi-bot") && hint.contains("vgi repo init"),
        "{hint}"
    );
    let internal = RepoSpec::new(repo("x")).with_visibility(Visibility::Internal);
    assert!(matches!(
        forge.create_repo(&internal).await,
        Err(ForgeError::Unsupported { .. })
    ));
}

#[tokio::test]
async fn archive_is_idempotent() {
    let (server, forge) = server_and_forge().await;
    mount_repo(&server, "old", repo_json(1, "acme/old", true)).await;
    mount_repo(&server, "live", repo_json(2, "acme/live", false)).await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/repos/acme/old"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/repos/acme/live"))
        .and(BotToken)
        .and(body_json(json!({ "archived": true })))
        .respond_with(ResponseTemplate::new(200).set_body_json(repo_json(2, "acme/live", true)))
        .expect(1)
        .mount(&server)
        .await;
    forge.archive_repo(&repo("old")).await.unwrap();
    forge.archive_repo(&repo("live")).await.unwrap();
}

// ── inspect / diff ───────────────────────────────────────────────────────

fn projection() -> Projection {
    let mut p = Projection::new(repo("widgets"));
    p.forge_id = Some(812);
    p.required_check = Some("Verify commit trust".into());
    p.roles = vec![
        RoleAssignment::new(ForgeAccount::new(1, "alice"), ForgeRole::Admin),
        RoleAssignment::new(ForgeAccount::new(2, "bob"), ForgeRole::Maintain),
    ];
    p
}

#[tokio::test]
async fn inspect_reads_repo_people_protection_and_settings() {
    let (server, forge) = server_and_forge().await;
    mount_repo(&server, "widgets", repo_json(812, "Acme/Widgets", false)).await;
    mount_people(
        &server,
        "widgets",
        &[
            (1, "alice", "admin"),
            (2, "Bob", "write"),
            (3, "mallory", "write"),
        ],
    )
    .await;
    mount_rules(
        &server,
        "widgets",
        json!([
            // A glob rule that also matches `main` is not the managed rule.
            { "rule_name": "*", "enable_push": true },
            good_rule(&["alice", "bob"]),
        ]),
    )
    .await;
    let state = forge.inspect(&repo("widgets")).await.unwrap();
    assert_eq!(state.resource, repo("widgets"), "owner/name case is folded");
    assert_eq!(state.forge_id, 812);
    let roles: Vec<_> = state
        .collaborators
        .iter()
        .map(|c| (c.account.login.as_str(), c.role))
        .collect();
    assert_eq!(
        roles,
        [
            ("alice", ForgeRole::Admin),
            ("Bob", ForgeRole::Maintain),
            ("mallory", ForgeRole::Write),
        ]
    );
    let p = &state.protection;
    assert!(p.present && p.enforced && p.covers_default_branch && p.requires_pull_request);
    assert!(p.blocks_force_push && p.blocks_deletion && p.bypass_actors.is_empty());
    assert_eq!(p.required_checks, [CONTEXT]);
    assert_eq!(
        p.merge_methods.as_deref(),
        Some(&[MergeMethod::FastForward][..])
    );
    assert_eq!(p.ci_enabled, Some(true));
    assert_eq!(p.protected_paths.len(), 4);

    // The projection names the check by its job name; the adapter matches
    // it to the context Forgejo reports. Only mallory is drift.
    let drift = forge.diff(&state, &projection());
    assert_eq!(drift.len(), 1, "{drift:?}");
    assert!(matches!(&drift[0], Drift::UnexpectedRole { account, .. } if account.id == 3));
}

#[tokio::test]
async fn inspect_fails_closed_on_every_weakening() {
    let (server, forge) = server_and_forge().await;
    let mut r = repo_json(812, "acme/widgets", false);
    r["allow_squash_merge"] = json!(true);
    r["has_actions"] = json!(false);
    mount_repo(&server, "widgets", r).await;
    mount_people(&server, "widgets", &[(1, "alice", "admin")]).await;
    let mut rule = good_rule(&["alice"]);
    rule["enable_push"] = json!(true);
    rule["enable_push_whitelist"] = json!(true);
    rule["push_whitelist_usernames"] = json!(["dave"]);
    rule["apply_to_admins"] = json!(false);
    rule["status_check_contexts"] = json!(["something else"]);
    rule["protected_file_patterns"] = json!(".forgejo/workflows/*");
    rule["unprotected_file_patterns"] = json!("docs/**");
    rule["merge_whitelist_teams"] = json!(["Owners"]);
    mount_rules(&server, "widgets", json!([rule])).await;

    let state = forge.inspect(&repo("widgets")).await.unwrap();
    let drift = forge.diff(&state, &projection());
    let gaps = drift
        .iter()
        .find_map(|d| match d {
            Drift::ProtectionWeakened { gaps } => Some(gaps.clone()),
            _ => None,
        })
        .expect("protection drift");
    assert!(gaps.contains(&ProtectionGap::PullRequestNotRequired));
    assert!(gaps.contains(&ProtectionGap::CheckNotRequired {
        check: CONTEXT.into()
    }));
    let ProtectionGap::BypassActors { actors } = gaps
        .iter()
        .find(|g| matches!(g, ProtectionGap::BypassActors { .. }))
        .unwrap()
    else {
        unreachable!()
    };
    assert_eq!(
        actors,
        &[
            "repository admins (the rule does not apply to admins)",
            "push:dave",
            "unprotected-files:docs/**",
            "merge-team:Owners",
        ]
    );
    assert!(gaps.contains(&ProtectionGap::UnprotectedPaths {
        paths: vec![
            ".forgejo/workflows/**".into(),
            ".gitea/workflows/**".into(),
            ".github/workflows/**".into(),
            KEYRING_PATH.into(),
        ]
    }));
    assert!(gaps.contains(&ProtectionGap::MergeMethodAllowed {
        method: MergeMethod::Squash
    }));
    assert!(gaps.contains(&ProtectionGap::CiDisabled));
    assert!(drift.iter().any(Drift::is_critical));
}

#[tokio::test]
async fn a_missing_rule_is_one_gap_plus_the_settings() {
    let (server, forge) = server_and_forge().await;
    mount_repo(&server, "widgets", repo_json(812, "acme/widgets", false)).await;
    mount_people(&server, "widgets", &[]).await;
    mount_rules(&server, "widgets", json!([])).await;
    let state = forge.inspect(&repo("widgets")).await.unwrap();
    let mut want = projection();
    want.roles.clear();
    assert_eq!(
        forge.diff(&state, &want),
        [Drift::ProtectionWeakened {
            gaps: vec![ProtectionGap::Missing]
        }]
    );
}

// ── roles ────────────────────────────────────────────────────────────────

/// alice: write → admin (renamed since the VTC saw her); bob: new →
/// maintain; carol: maintain → write; dave: an admin nobody granted; erin:
/// on the allow-list but no collaborator.
async fn mount_roles_repo(server: &MockServer) {
    mount_repo(server, "widgets", repo_json(812, "acme/widgets", false)).await;
    mount_people(
        server,
        "widgets",
        &[
            (1, "alice", "write"),
            (3, "carol", "write"),
            (4, "dave", "admin"),
        ],
    )
    .await;
    mount_rules(
        server,
        "widgets",
        json!([good_rule(&["carol", "dave", "erin"])]),
    )
    .await;
    mount_lookup(server, 1, "alice-renamed").await;
    mount_lookup(server, 2, "bob").await;
    Mock::given(method("PUT"))
        .and(path(
            "/api/v1/repos/acme/widgets/collaborators/alice-renamed",
        ))
        .and(body_json(json!({ "permission": "admin" })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/v1/repos/acme/widgets/collaborators/bob"))
        .and(body_json(json!({ "permission": "write" })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(server)
        .await;
    // carol keeps `write`: no collaborator call, only the allow-list.
    Mock::given(method("PUT"))
        .and(path("/api/v1/repos/acme/widgets/collaborators/carol"))
        .respond_with(ResponseTemplate::new(204))
        .expect(0)
        .mount(server)
        .await;
}

fn desired() -> Vec<RoleAssignment> {
    vec![
        RoleAssignment::new(ForgeAccount::new(1, "alice"), ForgeRole::Admin),
        RoleAssignment::new(ForgeAccount::new(2, "bob"), ForgeRole::Maintain),
        RoleAssignment::new(ForgeAccount::new(3, "carol"), ForgeRole::Write),
    ]
}

#[tokio::test]
async fn apply_roles_converges_people_and_the_allow_list_in_report_mode() {
    let (server, forge) = server_and_forge().await;
    mount_roles_repo(&server).await;
    Mock::given(method("DELETE"))
        .respond_with(ResponseTemplate::new(204))
        .expect(0)
        .mount(&server)
        .await;
    // dave (unlisted, kept) and erin stay; carol goes; alice and bob join.
    Mock::given(method("PATCH"))
        .and(path("/api/v1/repos/acme/widgets/branch_protections/main"))
        .and(body_json(json!({
            "enable_merge_whitelist": true,
            "merge_whitelist_usernames": ["dave", "erin", "alice-renamed", "bob"],
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(good_rule(&[])))
        .expect(1)
        .mount(&server)
        .await;
    let report = forge
        .apply_roles(&repo("widgets"), &desired(), Unlisted::Keep)
        .await
        .unwrap();
    assert!(report.is_complete(), "{report:?}");
    let changes: Vec<_> = report
        .changes
        .iter()
        .map(|c| (c.account.id, c.from, c.to))
        .collect();
    assert_eq!(
        changes,
        [
            (1, ForgeRole::Write, ForgeRole::Admin),
            (2, ForgeRole::None, ForgeRole::Maintain),
            (3, ForgeRole::Maintain, ForgeRole::Write),
        ]
    );
    assert_eq!(report.kept_unlisted.len(), 1);
    assert_eq!(report.kept_unlisted[0].account.login, "dave");
    assert_eq!(report.kept_unlisted[0].role, ForgeRole::Admin);
}

#[tokio::test]
async fn apply_roles_in_enforce_mode_removes_the_unlisted() {
    let (server, forge) = server_and_forge().await;
    mount_roles_repo(&server).await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/repos/acme/widgets/collaborators/dave"))
        .and(BotToken)
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/repos/acme/widgets/branch_protections/main"))
        .and(body_json(json!({
            "enable_merge_whitelist": true,
            "merge_whitelist_usernames": ["alice-renamed", "bob"],
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(good_rule(&[])))
        .expect(1)
        .mount(&server)
        .await;
    let report = forge
        .apply_roles(&repo("widgets"), &desired(), Unlisted::Remove)
        .await
        .unwrap();
    assert!(report.is_complete(), "{report:?}");
    assert_eq!(report.changes.len(), 4);
    assert_eq!(report.changes[3].to, ForgeRole::None);
    assert!(report.kept_unlisted.is_empty());
}

#[tokio::test]
async fn a_converged_repo_needs_no_writes() {
    let (server, forge) = server_and_forge().await;
    mount_repo(&server, "widgets", repo_json(812, "acme/widgets", false)).await;
    mount_people(
        &server,
        "widgets",
        &[
            (1, "alice", "admin"),
            (2, "bob", "write"),
            (3, "carol", "write"),
        ],
    )
    .await;
    mount_rules(&server, "widgets", json!([good_rule(&["Alice", "bob"])])).await;
    forbid_writes(&server).await;
    let report = forge
        .apply_roles(&repo("widgets"), &desired(), Unlisted::Keep)
        .await
        .unwrap();
    assert!(report.changes.is_empty(), "{report:?}");
    assert_eq!(report.unchanged.len(), 3);
}

#[tokio::test]
async fn maintain_before_bootstrap_grants_write_and_says_what_is_missing() {
    let (server, forge) = server_and_forge().await;
    mount_repo(&server, "widgets", repo_json(812, "acme/widgets", false)).await;
    mount_people(&server, "widgets", &[]).await;
    mount_rules(&server, "widgets", json!([])).await;
    mount_lookup(&server, 2, "bob").await;
    Mock::given(method("PUT"))
        .and(path("/api/v1/repos/acme/widgets/collaborators/bob"))
        .and(body_json(json!({ "permission": "write" })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let report = forge
        .apply_roles(
            &repo("widgets"),
            &[RoleAssignment::new(
                ForgeAccount::new(2, "bob"),
                ForgeRole::Maintain,
            )],
            Unlisted::Keep,
        )
        .await
        .unwrap();
    assert!(!report.is_complete());
    assert!(
        matches!(&report.changes[0].outcome, RoleOutcome::Failed(m) if m.contains("merge allow-list")),
        "{report:?}"
    );
}

#[tokio::test]
async fn a_personal_namespace_owner_is_never_a_collaborator() {
    let (_server, forge) = server_and_forge().await;
    let r = alice_ns().join("gadgets").unwrap();
    let desired = vec![
        RoleAssignment::new(ForgeAccount::new(ALICE_ID, "alice"), ForgeRole::Admin),
        RoleAssignment::new(ForgeAccount::new(2, "bob"), ForgeRole::Write),
    ];
    let HookDecision::Modify(kept) = forge.before_apply_roles(&r, &desired) else {
        panic!("the owner should be dropped")
    };
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].account.id, 2);
    assert_eq!(
        forge.before_apply_roles(&repo("w"), &desired),
        HookDecision::Continue
    );
}

// ── bootstrap ────────────────────────────────────────────────────────────

fn step_contents(forge: &vgi_forge_forgejo::ForgejoForge, id: &str) -> Vec<u8> {
    let plan = forge
        .bootstrap_plan(&RepoSpec::new(repo("gadgets")), &vgi_config())
        .unwrap();
    plan.into_iter()
        .find_map(|s| match (s.id == id, s.action) {
            (true, StepAction::WriteFile { contents, .. }) => Some(contents),
            _ => None,
        })
        .unwrap()
}

fn protection_body(mergers: &[&str]) -> Value {
    json!({
        "enable_push": false,
        "enable_push_whitelist": false,
        "push_whitelist_usernames": [],
        "push_whitelist_teams": [],
        "push_whitelist_deploy_keys": false,
        "enable_merge_whitelist": true,
        "merge_whitelist_usernames": mergers,
        "merge_whitelist_teams": [],
        "enable_status_check": true,
        "status_check_contexts": [CONTEXT],
        "protected_file_patterns": PATTERNS,
        "unprotected_file_patterns": "",
        "apply_to_admins": true,
    })
}

#[tokio::test]
async fn bootstrap_runs_every_step_on_a_fresh_repo() {
    let (server, forge) = server_and_forge().await;
    let plan = forge
        .bootstrap_plan(&RepoSpec::new(repo("gadgets")), &vgi_config())
        .unwrap();
    let ids: Vec<_> = plan.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "merge-styles",
            "workflow",
            "variable:TRUST_REGISTRY_DID",
            "variable:VTC_DID",
            "protection"
        ]
    );

    // merge-styles: a fresh repo allows merge commits and has Actions off.
    let mut fresh = repo_json(9001, "acme/gadgets", false);
    fresh["allow_fast_forward_only_merge"] = json!(false);
    fresh["allow_merge_commits"] = json!(true);
    fresh["allow_squash_merge"] = json!(true);
    fresh["default_merge_style"] = json!("merge");
    fresh["has_actions"] = json!(false);
    mount_repo(&server, "gadgets", fresh).await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/repos/acme/gadgets"))
        .and(body_json(json!({
            "has_pull_requests": true,
            "allow_fast_forward_only_merge": true,
            "allow_merge_commits": false,
            "allow_rebase": false,
            "allow_rebase_explicit": false,
            "allow_squash_merge": false,
            "default_merge_style": "fast-forward-only",
            "has_actions": true,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(repo_json(
            9001,
            "acme/gadgets",
            false,
        )))
        .expect(1)
        .mount(&server)
        .await;
    // workflow: absent, created.
    Mock::given(method("GET"))
        .and(path(
            "/api/v1/repos/acme/gadgets/contents/.forgejo/workflows/verify-trust.yml",
        ))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "message": "" })))
        .mount(&server)
        .await;
    let workflow = step_contents(&forge, "workflow");
    let wf = String::from_utf8(workflow.clone()).unwrap();
    assert!(wf.contains(&format!("sha256: {SUM}")) && !wf.contains("if:"));
    Mock::given(method("POST"))
        .and(path(
            "/api/v1/repos/acme/gadgets/contents/.forgejo/workflows/verify-trust.yml",
        ))
        .and(BotToken)
        .and(body_json(json!({
            "message": "ci: add the VGI commit-trust check",
            "content": STANDARD.encode(&workflow),
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;
    // variables: absent, created.
    for (name, value) in [
        ("TRUST_REGISTRY_DID", "did:webvh:registry"),
        ("VTC_DID", "did:webvh:acme-vtc"),
    ] {
        let p = format!("/api/v1/repos/acme/gadgets/actions/variables/{name}");
        Mock::given(method("GET"))
            .and(path(p.clone()))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "message": "" })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(p))
            .and(body_json(json!({ "value": value })))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&server)
            .await;
    }
    // protection: absent, created — the repo's admin seeded on the
    // allow-list.
    mount_rules(&server, "gadgets", json!([])).await;
    mount_people(
        &server,
        "gadgets",
        &[(1, "alice", "admin"), (3, "carol", "write")],
    )
    .await;
    let mut create = protection_body(&["alice"]);
    create["rule_name"] = json!("main");
    create["branch_name"] = json!("main");
    Mock::given(method("POST"))
        .and(path("/api/v1/repos/acme/gadgets/branch_protections"))
        .and(BotToken)
        .and(body_json(create))
        .respond_with(ResponseTemplate::new(201).set_body_json(good_rule(&["alice"])))
        .expect(1)
        .mount(&server)
        .await;

    let report = run_plan(&forge, &repo("gadgets"), &plan).await;
    assert!(report.is_complete(), "{report:?}");
    let outcomes: Vec<_> = report.completed.iter().map(|(_, o)| *o).collect();
    assert_eq!(
        outcomes,
        [
            StepOutcome::Updated,
            StepOutcome::Created,
            StepOutcome::Created,
            StepOutcome::Created,
            StepOutcome::Created
        ]
    );
}

#[tokio::test]
async fn a_bootstrapped_repo_reruns_without_writing() {
    let (server, forge) = server_and_forge().await;
    mount_repo(&server, "gadgets", repo_json(9001, "acme/gadgets", false)).await;
    let workflow = step_contents(&forge, "workflow");
    Mock::given(method("GET"))
        .and(path(
            "/api/v1/repos/acme/gadgets/contents/.forgejo/workflows/verify-trust.yml",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "type": "file", "sha": "abc", "encoding": "base64",
            // Forgejo wraps base64 like git does; whitespace is ignored.
            "content": STANDARD.encode(&workflow).as_bytes().chunks(60)
                .map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("\n"),
        })))
        .mount(&server)
        .await;
    for (name, value) in [
        ("TRUST_REGISTRY_DID", "did:webvh:registry"),
        ("VTC_DID", "did:webvh:acme-vtc"),
    ] {
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/repos/acme/gadgets/actions/variables/{name}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "name": name, "data": value, "owner_id": 0, "repo_id": 9001
            })))
            .mount(&server)
            .await;
    }
    mount_rules(&server, "gadgets", json!([good_rule(&["alice"])])).await;
    mount_people(&server, "gadgets", &[(1, "alice", "admin")]).await;
    forbid_writes(&server).await;

    let plan = forge
        .bootstrap_plan(&RepoSpec::new(repo("gadgets")), &vgi_config())
        .unwrap();
    let report = run_plan(&forge, &repo("gadgets"), &plan).await;
    assert!(report.is_complete(), "{report:?}");
    assert!(
        report
            .completed
            .iter()
            .all(|(_, o)| *o == StepOutcome::Unchanged),
        "{report:?}"
    );
}

#[tokio::test]
async fn a_weakened_rule_is_repaired_keeping_what_others_added() {
    let (server, forge) = server_and_forge().await;
    mount_repo(&server, "gadgets", repo_json(9001, "acme/gadgets", false)).await;
    let mut weak = good_rule(&["bob"]);
    weak["enable_push"] = json!(true);
    weak["status_check_contexts"] = json!(["ci / build (pull_request)"]);
    weak["protected_file_patterns"] = json!("LICENSE");
    mount_rules(&server, "gadgets", json!([weak])).await;
    mount_people(
        &server,
        "gadgets",
        &[(1, "alice", "admin"), (2, "bob", "write")],
    )
    .await;
    let mut body = protection_body(&["bob", "alice"]);
    body["status_check_contexts"] = json!(["ci / build (pull_request)", CONTEXT]);
    body["protected_file_patterns"] = json!(format!("license;{PATTERNS}"));
    let mut back = good_rule(&["bob", "alice"]);
    back["status_check_contexts"] = json!(["ci / build (pull_request)", CONTEXT]);
    back["protected_file_patterns"] = json!(format!("license;{PATTERNS}"));
    Mock::given(method("PATCH"))
        .and(path("/api/v1/repos/acme/gadgets/branch_protections/main"))
        .and(body_json(body))
        .respond_with(ResponseTemplate::new(200).set_body_json(back))
        .expect(1)
        .mount(&server)
        .await;
    let plan = forge
        .bootstrap_plan(&RepoSpec::new(repo("gadgets")), &vgi_config())
        .unwrap();
    let step = plan.iter().find(|s| s.id == "protection").unwrap();
    assert_eq!(
        forge.run_step(&repo("gadgets"), step).await.unwrap(),
        StepOutcome::Updated
    );
}

#[tokio::test]
async fn a_rule_that_does_not_read_back_is_an_error() {
    let (server, forge) = server_and_forge().await;
    mount_repo(&server, "gadgets", repo_json(9001, "acme/gadgets", false)).await;
    mount_rules(&server, "gadgets", json!([])).await;
    mount_people(&server, "gadgets", &[]).await;
    let mut ignored = good_rule(&[]);
    ignored["protected_file_patterns"] = json!("");
    Mock::given(method("POST"))
        .and(path("/api/v1/repos/acme/gadgets/branch_protections"))
        .respond_with(ResponseTemplate::new(201).set_body_json(ignored))
        .mount(&server)
        .await;
    let plan = forge
        .bootstrap_plan(&RepoSpec::new(repo("gadgets")), &vgi_config())
        .unwrap();
    let step = plan.iter().find(|s| s.id == "protection").unwrap();
    assert!(matches!(
        forge.run_step(&repo("gadgets"), step).await,
        Err(ForgeError::Rejected { .. })
    ));
}

#[tokio::test]
async fn settings_that_do_not_stick_are_an_error() {
    let (server, forge) = server_and_forge().await;
    let mut off = repo_json(9001, "acme/gadgets", false);
    off["has_actions"] = json!(false);
    mount_repo(&server, "gadgets", off.clone()).await;
    // Actions disabled instance-wide: the PATCH is accepted, nothing changes.
    Mock::given(method("PATCH"))
        .and(path("/api/v1/repos/acme/gadgets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(off))
        .mount(&server)
        .await;
    let plan = forge
        .bootstrap_plan(&RepoSpec::new(repo("gadgets")), &vgi_config())
        .unwrap();
    let e = forge
        .run_step(&repo("gadgets"), &plan[0])
        .await
        .unwrap_err();
    assert!(e.to_string().contains("did not apply"), "{e}");
}

#[tokio::test]
async fn without_fast_forward_only_the_plan_fails_first_by_default() {
    let (server, forge) = server_and_forge_at("1.21.11", MergeFallback::Fail).await;
    let mut old = repo_json(9001, "acme/gadgets", false);
    old.as_object_mut()
        .unwrap()
        .remove("allow_fast_forward_only_merge");
    mount_repo(&server, "gadgets", old).await;
    forbid_writes(&server).await;
    let plan = forge
        .bootstrap_plan(&RepoSpec::new(repo("gadgets")), &vgi_config())
        .unwrap();
    // No variables API on 1.21: the DIDs are in the workflow instead.
    let ids: Vec<_> = plan.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids, ["merge-styles", "workflow", "protection"]);
    let report = run_plan(&forge, &repo("gadgets"), &plan).await;
    let (id, e) = report.failed.expect("the merge step fails");
    assert_eq!(id, "merge-styles");
    let ForgeError::Unsupported { hint, .. } = e else {
        panic!("{e:?}")
    };
    assert!(
        hint.contains("Forgejo 7") && hint.contains("1.21.11"),
        "{hint}"
    );
    assert_eq!(
        report.not_run,
        ["workflow", "protection"],
        "nothing was written"
    );
}

#[tokio::test]
async fn the_signing_key_fallback_allows_signed_merge_commits_only() {
    const KEY: &str =
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\ninstance\n-----END PGP PUBLIC KEY BLOCK-----\n";
    let server = MockServer::start().await;
    mount_probe(&server, "1.21.11").await;
    Mock::given(method("GET"))
        .and(path("/api/v1/signing-key.gpg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(KEY))
        .expect(1)
        .mount(&server)
        .await;
    let forge = vgi_forge_forgejo::ForgejoForge::connect(
        config(&server).with_merge_fallback(MergeFallback::InstanceSigningKey),
        credentials(),
    )
    .await
    .unwrap();
    register(&forge);

    let plan = forge
        .bootstrap_plan(&RepoSpec::new(repo("gadgets")), &vgi_config())
        .unwrap();
    let ids: Vec<_> = plan.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids, ["merge-styles", "workflow", "keyring", "protection"]);
    let wf = String::from_utf8(step_contents(&forge, "workflow")).unwrap();
    assert!(wf.contains(&format!("exempt-keyring: {KEYRING_PATH}")));
    assert!(wf.contains("vtc-did: 'did:webvh:acme-vtc'"));
    assert_eq!(step_contents(&forge, "keyring"), KEY.as_bytes());
    let StepAction::ProtectDefaultBranch(p) = &plan[3].action else {
        panic!()
    };
    assert!(p.protected_paths.iter().any(|x| x == KEYRING_PATH));

    let mut old = repo_json(9001, "acme/gadgets", false);
    old.as_object_mut()
        .unwrap()
        .remove("allow_fast_forward_only_merge");
    old["allow_squash_merge"] = json!(true);
    mount_repo(&server, "gadgets", old.clone()).await;
    let mut merged = old;
    merged["allow_merge_commits"] = json!(true);
    merged["allow_squash_merge"] = json!(false);
    merged["default_merge_style"] = json!("merge");
    Mock::given(method("PATCH"))
        .and(path("/api/v1/repos/acme/gadgets"))
        .and(body_json(json!({
            "has_pull_requests": true,
            "allow_merge_commits": true,
            "allow_rebase": false,
            "allow_rebase_explicit": false,
            "allow_squash_merge": false,
            "default_merge_style": "merge",
            "has_actions": true,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(merged))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        forge.run_step(&repo("gadgets"), &plan[0]).await.unwrap(),
        StepOutcome::Updated
    );
}

#[tokio::test]
async fn forgejo_7_writes_the_dids_into_the_workflow() {
    let (_server, forge) = server_and_forge_at("7.0.4+gitea-1.21.0", MergeFallback::Fail).await;
    let plan = forge
        .bootstrap_plan(&RepoSpec::new(repo("gadgets")), &vgi_config())
        .unwrap();
    assert!(
        !plan
            .iter()
            .any(|s| matches!(s.action, StepAction::SetVariable { .. }))
    );
    let wf = String::from_utf8(step_contents(&forge, "workflow")).unwrap();
    assert!(wf.contains("registry-did: 'did:webvh:registry'"));
}

#[tokio::test]
async fn bootstrap_refuses_what_it_cannot_see_or_did_not_write() {
    let (server, forge) = server_and_forge().await;
    let p = "/api/v1/repos/acme/gadgets/contents/.forgejo/workflows/verify-trust.yml";
    Mock::given(method("GET"))
        .and(path(p))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{ "type": "file" }])))
        .mount(&server)
        .await;
    forbid_writes(&server).await;
    let step = forge
        .bootstrap_plan(&RepoSpec::new(repo("gadgets")), &vgi_config())
        .unwrap()
        .into_iter()
        .find(|s| s.id == "workflow")
        .unwrap();
    let e = forge.run_step(&repo("gadgets"), &step).await.unwrap_err();
    assert!(e.to_string().contains("directory"), "{e}");

    let (server, forge) = server_and_forge().await;
    Mock::given(method("GET"))
        .and(path(p))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "type": "file", "sha": "abc", "encoding": null, "content": null
        })))
        .mount(&server)
        .await;
    forbid_writes(&server).await;
    let e = forge.run_step(&repo("gadgets"), &step).await.unwrap_err();
    assert!(e.to_string().contains("too large"), "{e}");
    let _ = WORKFLOW_PATH;
}
