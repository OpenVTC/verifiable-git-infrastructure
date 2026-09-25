//! Capabilities, repository operations, role projection and the bootstrap,
//! against a mock GitHub.

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use serde_json::json;
use vgi_forge::{
    EffectiveRights, Forge, ForgeAccount, ForgeError, ForgeHooks, ForgeRole, HookDecision,
    LinkMethod, Namespace, NamespaceKind, Projection, ProtectionGap, RepoSpec, RequiredCheckKind,
    Resource, Right, RoleAssignment, RoleMap, RoleOutcome, StepAction, StepOutcome, Unlisted,
    VgiConfig, run_plan,
};
use wiremock::matchers::{body_json, body_partial_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const KEYRING: &str =
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nweb-flow\n-----END PGP PUBLIC KEY BLOCK-----\n";

fn admin_perms() -> serde_json::Value {
    json!({ "administration": "write", "metadata": "read" })
}

/// A repository whose owner has a linked account (id 7, `bob`): who the
/// owner-review fallback names in `CODEOWNERS`.
fn owned(name: &str) -> RepoSpec {
    RepoSpec::new(repo(name)).with_owner(ForgeAccount::new(7, "bob"))
}

// ── capabilities ─────────────────────────────────────────────────────────

#[tokio::test]
async fn personal_accounts_get_the_reduced_capability_set() {
    let (_server, forge) = server_and_forge().await;
    let org = Namespace::new(acme(), NamespaceKind::Organization).with_installation(1);
    let user = Namespace::new(
        Resource::parse("github.com/alice").unwrap(),
        NamespaceKind::User,
    )
    .with_installation(2);
    let manual = Namespace::new(acme(), NamespaceKind::Organization);

    let c = forge.capabilities(&org);
    assert!(c.automation && c.bot_can_create_repos && c.webhooks && c.per_repo_tokens);
    assert_eq!(c.role_levels.len(), 5);
    assert_eq!(c.required_checks, RequiredCheckKind::Ruleset);
    assert_eq!(c.account_link, LinkMethod::DeviceFlow);

    let c = forge.capabilities(&user);
    assert!(c.automation, "the App can still manage existing repos");
    assert!(
        !c.bot_can_create_repos,
        "§8: creation is the account holder's"
    );
    assert_eq!(
        c.role_levels,
        vec![ForgeRole::Write],
        "collaborators are always write"
    );

    let c = forge.capabilities(&manual);
    assert!(!c.automation && !c.bot_can_create_repos && !c.webhooks);

    // Roles collapse onto the ladder, never up.
    let map = RoleMap::default();
    let r = |x| EffectiveRights::from_granted([x]);
    assert_eq!(
        forge.map_role(&org, r(Right::RepoOwn), &map),
        ForgeRole::Admin
    );
    assert_eq!(
        forge.map_role(&org, r(Right::RepoMaintain), &map),
        ForgeRole::Maintain
    );
    assert_eq!(
        forge.map_role(&org, r(Right::CommitSign), &map),
        ForgeRole::None
    );
    assert_eq!(
        forge.map_role(&org, r(Right::CommitSign), &RoleMap::with_committer_write()),
        ForgeRole::Write
    );
    assert_eq!(
        forge.map_role(&user, r(Right::RepoOwn), &map),
        ForgeRole::Write
    );
    assert_eq!(
        forge.map_role(&user, r(Right::RepoMaintain), &map),
        ForgeRole::Write
    );
    assert_eq!(
        forge.map_role(&user, r(Right::CommitSign), &map),
        ForgeRole::None
    );
}

#[tokio::test]
async fn resources_are_checked_before_any_request() {
    let (server, forge) = server_and_forge().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    assert_eq!(
        forge.normalize("GitHub.com/Acme/Widgets").unwrap(),
        repo("widgets")
    );
    assert!(matches!(
        forge.normalize("codeberg.org/acme/widgets"),
        Err(ForgeError::WrongResource { .. })
    ));
    let e = forge
        .inspect(&Resource::parse("github.com/unbound/x").unwrap())
        .await
        .unwrap_err();
    assert!(
        matches!(e, ForgeError::NotBound { ref namespace } if namespace == "github.com/unbound")
    );
    let e = forge.inspect(&acme()).await.unwrap_err();
    assert!(matches!(e, ForgeError::WrongResource { .. }));
}

// ── create / archive ─────────────────────────────────────────────────────

#[tokio::test]
async fn create_repo_in_an_org() {
    let (server, forge) = server_and_forge().await;
    // Org-wide (no repo exists to scope to), administration only.
    mount_token(&server, INSTALLATION, None, admin_perms(), 1).await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/gadgets"))
        .and(InstallationToken)
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "message": "Not Found" })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/orgs/acme/repos"))
        .and(InstallationToken)
        .and(body_json(json!({
            "name": "gadgets",
            "visibility": "private",
            "auto_init": true,
            "description": "Gadgets",
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(repo_json(
            9001,
            "acme/gadgets",
            false,
        )))
        .expect(1)
        .mount(&server)
        .await;

    let spec = RepoSpec::new(repo("gadgets"))
        .with_visibility(vgi_forge::Visibility::Private)
        .with_description("Gadgets");
    let state = forge.create_repo(&spec).await.unwrap();
    assert_eq!(state.forge_id, 9001);
    assert_eq!(state.resource, repo("gadgets"));
    assert_eq!(state.default_branch.as_deref(), Some("main"));
}

#[tokio::test]
async fn create_repo_refuses_an_existing_name_with_its_id() {
    let (server, forge) = server_and_forge().await;
    mount_token(&server, INSTALLATION, None, admin_perms(), 1).await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/gadgets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(repo_json(
            77,
            "acme/gadgets",
            false,
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/orgs/acme/repos"))
        .respond_with(ResponseTemplate::new(201))
        .expect(0)
        .mount(&server)
        .await;
    let e = forge
        .create_repo(&RepoSpec::new(repo("gadgets")))
        .await
        .unwrap_err();
    assert_eq!(
        e,
        ForgeError::AlreadyExists {
            resource: "github.com/acme/gadgets".into(),
            forge_id: Some(77)
        }
    );
}

#[tokio::test]
async fn create_repo_in_a_personal_account_is_manual() {
    let (server, forge) = server_and_forge().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let spec = RepoSpec::new(Resource::parse("github.com/alice/gadgets").unwrap());
    let e = forge.create_repo(&spec).await.unwrap_err();
    let ForgeError::Unsupported { hint, .. } = e else {
        panic!("expected Unsupported, got {e:?}");
    };
    assert!(
        hint.contains("gh repo create alice/gadgets") && hint.contains("vgi repo init"),
        "{hint}"
    );
}

#[tokio::test]
async fn archive_is_idempotent() {
    let (server, forge) = server_and_forge().await;
    mount_token(&server, INSTALLATION, Some("old"), admin_perms(), 1).await;
    mount_token(&server, INSTALLATION, Some("live"), admin_perms(), 1).await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/old"))
        .respond_with(ResponseTemplate::new(200).set_body_json(repo_json(1, "acme/old", true)))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/live"))
        .respond_with(ResponseTemplate::new(200).set_body_json(repo_json(2, "acme/live", false)))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/repos/acme/old"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/repos/acme/live"))
        .and(body_json(json!({ "archived": true })))
        .respond_with(ResponseTemplate::new(200).set_body_json(repo_json(2, "acme/live", true)))
        .expect(1)
        .mount(&server)
        .await;
    forge.archive_repo(&repo("old")).await.unwrap();
    forge.archive_repo(&repo("live")).await.unwrap();
}

// ── inspect / diff ───────────────────────────────────────────────────────

async fn mount_inspect(server: &MockServer, ruleset: serde_json::Value) {
    mount_token(server, INSTALLATION, Some("widgets"), admin_perms(), 1).await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets"))
        .and(InstallationToken)
        .respond_with(ResponseTemplate::new(200).set_body_json(repo_json(
            812,
            "Acme/Widgets",
            false,
        )))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/collaborators"))
        .and(query_param("affiliation", "direct"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "id": 1, "login": "alice", "role_name": "admin" },
            { "id": 3, "login": "mallory", "role_name": "custom-role",
              "permissions": { "admin": false, "maintain": false, "push": true, "triage": true, "pull": true } }
        ])))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/invitations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "id": 55, "invitee": { "id": 2, "login": "bob" }, "permissions": "maintain" }
        ])))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/rulesets"))
        .and(query_param("includes_parents", "false"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "id": 7, "name": "someone else's" },
            { "id": 9, "name": "VGI commit trust" }
        ])))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/rulesets/9"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ruleset))
        .mount(server)
        .await;
    // A solo-shaped repository: no CODEOWNERS (unmatched reads are 404s),
    // Actions on.
    mount_token(
        server,
        INSTALLATION,
        Some("widgets"),
        json!({ "contents": "read", "metadata": "read" }),
        1,
    )
    .await;
    mount_actions_allowed(server, "acme/widgets").await;
}

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
async fn inspect_reads_repo_people_and_protection() {
    let (server, forge) = server_and_forge().await;
    mount_inspect(&server, good_ruleset(9)).await;
    let state = forge.inspect(&repo("widgets")).await.unwrap();
    assert_eq!(state.resource, repo("widgets"), "owner/name case is folded");
    assert_eq!(state.forge_id, 812);
    let roles: Vec<_> = state
        .collaborators
        .iter()
        .map(|c| (c.account.login.as_str(), c.role, c.pending))
        .collect();
    assert_eq!(
        roles,
        [
            ("alice", ForgeRole::Admin, false),
            ("mallory", ForgeRole::Write, false),
            ("bob", ForgeRole::Maintain, true),
        ]
    );
    assert!(state.protection.enforced && state.protection.covers_default_branch);
    assert_eq!(state.protection.required_checks, ["Verify commit trust"]);

    // Only mallory, added in the GitHub UI, is drift.
    let drift = forge.diff(&state, &projection());
    assert_eq!(drift.len(), 1, "{drift:?}");
    assert!(
        matches!(&drift[0], vgi_forge::Drift::UnexpectedRole { account, .. } if account.id == 3)
    );
}

#[tokio::test]
async fn inspect_fails_closed_on_hidden_bypass_and_unpinned_checks() {
    let (server, forge) = server_and_forge().await;
    let mut weak = good_ruleset(9);
    weak.as_object_mut().unwrap().remove("bypass_actors");
    weak["rules"][3]["parameters"]["required_status_checks"][0]
        .as_object_mut()
        .unwrap()
        .remove("integration_id");
    weak["enforcement"] = json!("evaluate");
    mount_inspect(&server, weak).await;

    let state = forge.inspect(&repo("widgets")).await.unwrap();
    let drift = forge.diff(&state, &projection());
    let gaps = drift
        .iter()
        .find_map(|d| match d {
            vgi_forge::Drift::ProtectionWeakened { gaps } => Some(gaps.clone()),
            _ => None,
        })
        .expect("protection drift");
    assert!(gaps.contains(&ProtectionGap::NotEnforced));
    assert!(gaps.contains(&ProtectionGap::CheckNotRequired {
        check: "Verify commit trust".into()
    }));
    assert!(
        gaps.iter()
            .any(|g| matches!(g, ProtectionGap::BypassActors { .. }))
    );
    assert!(drift.iter().any(vgi_forge::Drift::is_critical));
}

// ── roles ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn apply_roles_converges_by_numeric_id() {
    let (server, forge) = server_and_forge().await;
    // Two runs below (report mode, then enforce mode) against the same
    // unchanged GitHub state, so the shared calls are expected twice.
    mount_token(&server, INSTALLATION, Some("widgets"), admin_perms(), 2).await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/collaborators"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "id": 1, "login": "alice", "role_name": "write" },
            { "id": 3, "login": "mallory", "role_name": "admin" },
            { "id": 4, "login": "dave", "role_name": "maintain" }
        ])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/invitations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    // alice: write → admin. Her login is looked up fresh by id, so the PUT
    // goes to her current login, not the one the VTC last saw.
    Mock::given(method("GET"))
        .and(path("/user/1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "id": 1, "login": "alice-renamed" })),
        )
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/repos/acme/widgets/collaborators/alice-renamed"))
        .and(body_json(json!({ "permission": "admin" })))
        .respond_with(ResponseTemplate::new(204))
        .expect(2)
        .mount(&server)
        .await;
    // bob: new → maintain, as an invitation.
    Mock::given(method("GET"))
        .and(path("/user/2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 2, "login": "bob" })))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/repos/acme/widgets/collaborators/bob"))
        .and(body_json(json!({ "permission": "maintain" })))
        .respond_with(ResponseTemplate::new(201))
        .expect(2)
        .mount(&server)
        .await;
    // dave: desired `none` → removed in both modes.
    Mock::given(method("DELETE"))
        .and(path("/repos/acme/widgets/collaborators/dave"))
        .respond_with(ResponseTemplate::new(204))
        .expect(2)
        .mount(&server)
        .await;
    // mallory: unlisted → removed only in enforce mode.
    Mock::given(method("DELETE"))
        .and(path("/repos/acme/widgets/collaborators/mallory"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let desired = [
        RoleAssignment::new(ForgeAccount::new(1, "alice"), ForgeRole::Admin),
        RoleAssignment::new(ForgeAccount::new(2, "bob"), ForgeRole::Maintain),
        RoleAssignment::new(ForgeAccount::new(4, "dave"), ForgeRole::None),
    ];

    // Report mode: mallory is kept and reported, not removed.
    let report = forge
        .apply_roles(&repo("widgets"), &desired, Unlisted::Keep)
        .await
        .unwrap();
    assert!(report.is_complete());
    assert_eq!(report.kept_unlisted.len(), 1);
    assert_eq!(report.kept_unlisted[0].account.id, 3);
    let outcomes: Vec<_> = report
        .changes
        .iter()
        .map(|c| (c.account.id, c.from, c.to, c.outcome.clone()))
        .collect();
    assert_eq!(
        outcomes,
        [
            (1, ForgeRole::Write, ForgeRole::Admin, RoleOutcome::Applied),
            (
                2,
                ForgeRole::None,
                ForgeRole::Maintain,
                RoleOutcome::Invited
            ),
            (
                4,
                ForgeRole::Maintain,
                ForgeRole::None,
                RoleOutcome::Applied
            ),
        ]
    );

    // Enforce mode removes mallory too.
    let report = forge
        .apply_roles(&repo("widgets"), &desired, Unlisted::Remove)
        .await
        .unwrap();
    assert!(report.kept_unlisted.is_empty());
    assert!(
        report
            .changes
            .iter()
            .any(|c| c.account.id == 3 && c.to == ForgeRole::None)
    );
}

#[tokio::test]
async fn apply_roles_in_a_personal_account_collapses_to_write_and_skips_the_owner() {
    let (server, forge) = server_and_forge().await;
    mount_token(
        &server,
        USER_INSTALLATION,
        Some("gadgets"),
        admin_perms(),
        1,
    )
    .await;
    // The listing includes the account holder herself (id 1).
    Mock::given(method("GET"))
        .and(path("/repos/alice/gadgets/collaborators"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "id": 1, "login": "alice", "role_name": "admin" }
        ])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/alice/gadgets/invitations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/repos/alice/gadgets/collaborators/alice"))
        .respond_with(ResponseTemplate::new(204))
        .expect(0)
        .named("the owner is never removed")
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/user/2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 2, "login": "bob" })))
        .mount(&server)
        .await;
    // No permission body: personal-account collaborators are always write.
    Mock::given(method("PUT"))
        .and(path("/repos/alice/gadgets/collaborators/bob"))
        .and(|req: &wiremock::Request| req.body.is_empty())
        // hyper sends no length for an empty body; GitHub would answer 411.
        .and(header("content-length", "0"))
        .respond_with(ResponseTemplate::new(201))
        .expect(1)
        .mount(&server)
        .await;

    let gadgets = Resource::parse("github.com/alice/gadgets").unwrap();
    let desired = vec![
        // The account holder (owner id 1): implicit admin, never a collaborator.
        RoleAssignment::new(ForgeAccount::new(1, "alice"), ForgeRole::Admin),
        RoleAssignment::new(ForgeAccount::new(2, "bob"), ForgeRole::Maintain),
    ];
    let HookDecision::Modify(filtered) = forge.before_apply_roles(&gadgets, &desired) else {
        panic!("the hook drops the owner");
    };
    assert_eq!(filtered, desired[1..]);

    // Enforce mode: even removing unlisted people leaves the owner alone.
    let report = forge
        .apply_roles(&gadgets, &desired, Unlisted::Remove)
        .await
        .unwrap();
    assert!(
        report.kept_unlisted.is_empty(),
        "the owner is not reported either"
    );
    assert_eq!(report.changes.len(), 1);
    assert_eq!(
        report.changes[0].to,
        ForgeRole::Write,
        "maintain collapses to write"
    );
    assert_eq!(report.changes[0].outcome, RoleOutcome::Invited);
}

// ── bootstrap ────────────────────────────────────────────────────────────

fn vgi_config() -> VgiConfig {
    VgiConfig::new(
        "did:webvh:registry.example",
        "did:webvh:vtc.acme.example",
        format!("OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@{SHA}"),
        "v0.5.0",
    )
    .with_platform_keyring(KEYRING)
}

fn file_contents(plan: &[vgi_forge::BootstrapStep], id: &str) -> Vec<u8> {
    plan.iter()
        .find_map(|s| match (&s.action, s.id == id) {
            (StepAction::WriteFile { contents, .. }, true) => Some(contents.clone()),
            _ => None,
        })
        .unwrap()
}

/// Token requests for one bootstrap run: each step gets its own token,
/// scoped to the repo and to that step's permissions.
async fn mount_bootstrap_tokens(server: &MockServer) {
    let contents = json!({ "contents": "write", "metadata": "read" });
    let variables = json!({ "actions_variables": "write", "metadata": "read" });
    mount_token(server, INSTALLATION, Some("gadgets"), contents, 2).await;
    mount_token(server, INSTALLATION, Some("gadgets"), admin_perms(), 1).await;
    mount_token(server, INSTALLATION, Some("gadgets"), variables, 2).await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/gadgets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(repo_json(
            9001,
            "acme/gadgets",
            false,
        )))
        .mount(server)
        .await;
}

/// A solo repository (one linked owner): workflow, keyring, the ruleset
/// with the check and no review requirement, and the legacy variables
/// removed — the DIDs are literals in the workflow now.
#[tokio::test]
async fn bootstrap_creates_everything_then_reruns_as_a_no_op() {
    let (server, forge) = server_and_forge().await;
    let spec = owned("gadgets");
    let plan = forge.bootstrap_plan(&spec, &vgi_config()).unwrap();
    let ids: Vec<_> = plan.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "workflow",
            "keyring",
            "ruleset",
            "cleanup:variable:TRUST_REGISTRY_DID",
            "cleanup:variable:VTC_DID"
        ]
    );
    let workflow = String::from_utf8(file_contents(&plan, "workflow")).unwrap();
    assert!(workflow.contains("resource-format: qualified"));
    assert!(workflow.contains("fallback-resource: github.com/${{ github.repository_owner }}\n"));
    assert!(workflow.contains("vtc-did: 'did:webvh:vtc.acme.example'"));
    assert!(!workflow.contains("${{ vars"));

    // ── first run: nothing exists but the legacy variables ──
    mount_bootstrap_tokens(&server).await;
    for (file, contents) in [
        (
            "workflows/verify-trust.yml",
            file_contents(&plan, "workflow"),
        ),
        ("trusted-platform-keys.asc", file_contents(&plan, "keyring")),
    ] {
        let p = format!("/repos/acme/gadgets/contents/.github/{file}");
        Mock::given(method("GET"))
            .and(path(p.clone()))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(json!({ "message": "Not Found" })),
            )
            .mount(&server)
            .await;
        // A create carries no `sha` and exactly the planned bytes.
        Mock::given(method("PUT"))
            .and(path(p))
            .and(InstallationToken)
            .and(body_partial_json(json!({
                "content": STANDARD.encode(&contents),
            })))
            .and(|req: &wiremock::Request| {
                serde_json::from_slice::<serde_json::Value>(&req.body)
                    .is_ok_and(|b| b.get("sha").is_none())
            })
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
            .expect(1)
            .mount(&server)
            .await;
    }
    for var in ["TRUST_REGISTRY_DID", "VTC_DID"] {
        let p = format!("/repos/acme/gadgets/actions/variables/{var}");
        Mock::given(method("GET"))
            .and(path(p.clone()))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "name": var, "value": "x" })),
            )
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(p))
            .and(InstallationToken)
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/repos/acme/gadgets/rulesets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/gadgets/rulesets"))
        .and(body_json(json!({
            "name": "VGI commit trust",
            "target": "branch",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
            "rules": [
                { "type": "deletion" },
                { "type": "non_fast_forward" },
                // One owner: no review requirement (the user's decision).
                { "type": "pull_request", "parameters": {
                    "required_approving_review_count": 0,
                    "dismiss_stale_reviews_on_push": false,
                    "require_code_owner_review": false,
                    "require_last_push_approval": false,
                    "required_review_thread_resolution": false
                } },
                { "type": "required_status_checks", "parameters": {
                    "strict_required_status_checks_policy": false,
                    "required_status_checks": [
                        { "context": "Verify commit trust", "integration_id": ACTIONS_APP_ID }
                    ]
                } }
            ]
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(good_ruleset(9)))
        .expect(1)
        .mount(&server)
        .await;

    let report = run_plan(&forge, &repo("gadgets"), &plan).await;
    assert!(report.is_complete(), "{:?}", report.failed);
    let outcomes: Vec<_> = report.completed.iter().map(|(_, o)| *o).collect();
    assert_eq!(
        outcomes,
        [
            StepOutcome::Created,
            StepOutcome::Created,
            StepOutcome::Created,
            StepOutcome::Updated,
            StepOutcome::Updated
        ]
    );
    server.verify().await;
    server.reset().await;

    // ── second run: everything already there, nothing is written ──
    mount_bootstrap_tokens(&server).await;
    for (file, contents) in [
        (
            "workflows/verify-trust.yml",
            file_contents(&plan, "workflow"),
        ),
        ("trusted-platform-keys.asc", file_contents(&plan, "keyring")),
    ] {
        // GitHub wraps base64 content at 60 columns; the adapter must not
        // mistake that for a difference.
        let b64 = STANDARD.encode(&contents);
        let wrapped: Vec<_> = b64
            .as_bytes()
            .chunks(60)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        Mock::given(method("GET"))
            .and(path(format!("/repos/acme/gadgets/contents/.github/{file}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "type": "file", "sha": "abc", "encoding": "base64", "content": wrapped.join("\n"),
            })))
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/repos/acme/gadgets/rulesets"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([{ "id": 9, "name": "VGI commit trust" }])),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/gadgets/rulesets/9"))
        .respond_with(ResponseTemplate::new(200).set_body_json(good_ruleset(9)))
        .mount(&server)
        .await;
    for verb in ["PUT", "POST", "PATCH", "DELETE"] {
        Mock::given(method(verb))
            .and(wiremock::matchers::path_regex("^/repos/"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .named(format!("no {verb} on a re-run"))
            .mount(&server)
            .await;
    }

    let report = run_plan(&forge, &repo("gadgets"), &plan).await;
    assert!(report.is_complete(), "{:?}", report.failed);
    assert!(
        report
            .completed
            .iter()
            .all(|(_, o)| *o == StepOutcome::Unchanged),
        "{report:?}"
    );
}

#[tokio::test]
async fn bootstrap_repairs_drifted_state_in_place() {
    let (server, forge) = server_and_forge().await;
    let plan = forge
        .bootstrap_plan(&owned("gadgets"), &vgi_config())
        .unwrap();
    let only = |id: &str| plan.iter().find(|s| s.id == id).unwrap().clone();

    // A changed workflow is rewritten with the existing blob's sha.
    mount_token(
        &server,
        INSTALLATION,
        Some("gadgets"),
        json!({ "contents": "write", "metadata": "read" }),
        1,
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/gadgets/contents/.github/workflows/verify-trust.yml"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "type": "file", "sha": "oldsha", "encoding": "base64", "content": STANDARD.encode("tampered"),
        })))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(
            "/repos/acme/gadgets/contents/.github/workflows/verify-trust.yml",
        ))
        .and(body_partial_json(json!({ "sha": "oldsha" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        forge
            .run_step(&repo("gadgets"), &only("workflow"))
            .await
            .unwrap(),
        StepOutcome::Updated
    );

    // A legacy variable is removed.
    mount_token(
        &server,
        INSTALLATION,
        Some("gadgets"),
        json!({ "actions_variables": "write", "metadata": "read" }),
        1,
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/gadgets/actions/variables/VTC_DID"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "name": "VTC_DID", "value": "did:web:evil" })),
        )
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/repos/acme/gadgets/actions/variables/VTC_DID"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        forge
            .run_step(&repo("gadgets"), &only("cleanup:variable:VTC_DID"))
            .await
            .unwrap(),
        StepOutcome::Updated
    );

    // A weakened ruleset (bypass actor added) is replaced.
    mount_token(&server, INSTALLATION, Some("gadgets"), admin_perms(), 1).await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/gadgets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(repo_json(
            9001,
            "acme/gadgets",
            false,
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/gadgets/rulesets"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([{ "id": 9, "name": "VGI commit trust" }])),
        )
        .mount(&server)
        .await;
    let mut weakened = good_ruleset(9);
    weakened["bypass_actors"] =
        json!([{ "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" }]);
    Mock::given(method("GET"))
        .and(path("/repos/acme/gadgets/rulesets/9"))
        .respond_with(ResponseTemplate::new(200).set_body_json(weakened))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/repos/acme/gadgets/rulesets/9"))
        .and(body_partial_json(
            json!({ "bypass_actors": [], "enforcement": "active" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(good_ruleset(9)))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        forge
            .run_step(&repo("gadgets"), &only("ruleset"))
            .await
            .unwrap(),
        StepOutcome::Updated
    );
}

#[tokio::test]
async fn a_protected_branch_explains_why_a_file_write_was_refused() {
    let (server, forge) = server_and_forge().await;
    mount_token(
        &server,
        INSTALLATION,
        Some("gadgets"),
        json!({ "contents": "write", "metadata": "read" }),
        1,
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/gadgets/contents/LICENSE"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "message": "Not Found" })))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/repos/acme/gadgets/contents/LICENSE"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "message": "Repository rule violations found",
            "errors": [{ "message": "Changes must be made through a pull request." }]
        })))
        .mount(&server)
        .await;
    let plan = forge
        .bootstrap_plan(
            &owned("gadgets"),
            &vgi_config().with_extra_file("LICENSE", "MIT\n"),
        )
        .unwrap();
    let step = plan.iter().find(|s| s.id == "file:LICENSE").unwrap();
    let e = forge.run_step(&repo("gadgets"), step).await.unwrap_err();
    let msg = e.to_string();
    assert!(matches!(e, ForgeError::Rejected { status: 409, .. }));
    assert!(
        msg.contains("pull request") && msg.contains("no bypass"),
        "{msg}"
    );
}

// ── HTTP error mapping ───────────────────────────────────────────────────

#[tokio::test]
async fn http_failures_map_to_decisions_the_core_can_make() {
    let (server, forge) = server_and_forge().await;
    let token =
        |repo: &'static str, status: u16, headers: &'static [(&'static str, &'static str)]| {
            let mut t = ResponseTemplate::new(status).set_body_json(json!({ "message": "nope" }));
            for (k, v) in headers {
                t = t.insert_header(*k, *v);
            }
            Mock::given(method("POST"))
                .and(path(format!(
                    "/app/installations/{INSTALLATION}/access_tokens"
                )))
                .and(body_partial_json(json!({ "repositories": [repo] })))
                .respond_with(t)
        };
    token("a", 401, &[]).mount(&server).await;
    token(
        "b",
        403,
        &[("x-ratelimit-remaining", "0"), ("retry-after", "30")],
    )
    .mount(&server)
    .await;
    token("c", 422, &[]).mount(&server).await;
    token("d", 502, &[]).mount(&server).await;

    assert!(matches!(
        forge.inspect(&repo("a")).await,
        Err(ForgeError::Unauthorized(_))
    ));
    let e = forge.inspect(&repo("b")).await.unwrap_err();
    assert_eq!(
        e,
        ForgeError::RateLimited {
            retry_after_secs: Some(30)
        }
    );
    assert!(e.is_retryable());
    // 422 on a repo-scoped token means the repo is not in the installation.
    assert!(matches!(
        forge.inspect(&repo("c")).await,
        Err(ForgeError::NotFound { .. })
    ));
    let e = forge.inspect(&repo("d")).await.unwrap_err();
    assert!(matches!(e, ForgeError::Unavailable(_)) && e.is_retryable());

    // A renamed repo answers 301; the adapter does not follow it.
    mount_token(&server, INSTALLATION, Some("renamed"), admin_perms(), 1).await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/renamed"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .respond_with(
            ResponseTemplate::new(301)
                .insert_header("location", "https://api.github.com/repositories/812"),
        )
        .mount(&server)
        .await;
    let e = forge.inspect(&repo("renamed")).await.unwrap_err();
    assert!(
        matches!(e, ForgeError::Moved { ref location, .. } if location.ends_with("/repositories/812")),
        "{e:?}"
    );
}

// ── review follow-ups ────────────────────────────────────────────────────

#[tokio::test]
async fn a_deserialized_deep_resource_never_reaches_github() {
    let (server, forge) = server_and_forge().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    // Valid under the general grammar, so it deserialises — but it is not
    // `acme/widgets`, and must not be acted on as if it were.
    let deep: Resource = serde_json::from_str("\"github.com/acme/evil/widgets\"").unwrap();
    for e in [
        forge.inspect(&deep).await.unwrap_err(),
        forge.archive_repo(&deep).await.unwrap_err(),
        forge
            .apply_roles(&deep, &[], Unlisted::Keep)
            .await
            .unwrap_err(),
        forge
            .create_repo(&RepoSpec::new(deep.clone()))
            .await
            .unwrap_err(),
        forge
            .bootstrap_plan(&RepoSpec::new(deep.clone()), &vgi_config())
            .unwrap_err(),
    ] {
        assert!(matches!(e, ForgeError::InvalidResource(_)), "{e:?}");
    }
}

#[tokio::test]
async fn a_ruleset_with_any_exclusion_does_not_cover_the_default_branch() {
    let (server, forge) = server_and_forge().await;
    let mut excluded = good_ruleset(9);
    excluded["conditions"]["ref_name"]["exclude"] = json!(["refs/heads/*"]);
    mount_inspect(&server, excluded.clone()).await;
    let state = forge.inspect(&repo("widgets")).await.unwrap();
    assert!(!state.protection.covers_default_branch);
    let drift = forge.diff(&state, &projection());
    assert!(drift.iter().any(|d| matches!(d,
        vgi_forge::Drift::ProtectionWeakened { gaps } if gaps.contains(&ProtectionGap::DefaultBranchNotCovered))));

    // …and the ruleset step puts the managed one back.
    let server = MockServer::start().await;
    let forge = forge_for(&server);
    mount_token(&server, INSTALLATION, Some("widgets"), admin_perms(), 1).await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(repo_json(
            812,
            "acme/widgets",
            false,
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/rulesets"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([{ "id": 9, "name": "VGI commit trust" }])),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/rulesets/9"))
        .respond_with(ResponseTemplate::new(200).set_body_json(excluded))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/repos/acme/widgets/rulesets/9"))
        .and(body_partial_json(json!({
            "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(good_ruleset(9)))
        .expect(1)
        .mount(&server)
        .await;
    let step = forge
        .bootstrap_plan(&owned("widgets"), &vgi_config())
        .unwrap()
        .into_iter()
        .find(|s| s.id == "ruleset")
        .unwrap();
    assert_eq!(
        forge.run_step(&repo("widgets"), &step).await.unwrap(),
        StepOutcome::Updated
    );
}

#[tokio::test]
async fn the_actions_app_id_is_looked_up_when_not_configured() {
    let server = MockServer::start().await;
    let forge = forge_with(&server, |cfg| cfg);
    mount_token(&server, INSTALLATION, Some("gadgets"), admin_perms(), 1).await;
    Mock::given(method("GET"))
        .and(path("/apps/github-actions"))
        .and(InstallationToken)
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "id": 424242, "slug": "github-actions" })),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/gadgets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(repo_json(
            9001,
            "acme/gadgets",
            false,
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/gadgets/rulesets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/gadgets/rulesets"))
        .and(|req: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
            body["rules"][3]["parameters"]["required_status_checks"][0]
                == json!({ "context": "Verify commit trust", "integration_id": 424242 })
        })
        .respond_with(ResponseTemplate::new(201).set_body_json(good_ruleset(9)))
        .expect(1)
        .mount(&server)
        .await;
    let step = forge
        .bootstrap_plan(&owned("gadgets"), &vgi_config())
        .unwrap()
        .into_iter()
        .find(|s| s.id == "ruleset")
        .unwrap();
    assert_eq!(
        forge.run_step(&repo("gadgets"), &step).await.unwrap(),
        StepOutcome::Created
    );
}

async fn write_file_against(content_reply: serde_json::Value) -> ForgeError {
    let (server, forge) = server_and_forge().await;
    mount_token(
        &server,
        INSTALLATION,
        Some("gadgets"),
        json!({ "contents": "write", "metadata": "read" }),
        1,
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/gadgets/contents/LICENSE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(content_reply))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(201))
        .expect(0)
        .mount(&server)
        .await;
    let step = forge
        .bootstrap_plan(
            &owned("gadgets"),
            &vgi_config().with_extra_file("LICENSE", "MIT\n"),
        )
        .unwrap()
        .into_iter()
        .find(|s| s.id == "file:LICENSE")
        .unwrap();
    forge.run_step(&repo("gadgets"), &step).await.unwrap_err()
}

#[tokio::test]
async fn a_directory_or_an_oversized_file_at_the_path_is_refused_not_overwritten() {
    let e = write_file_against(json!([{ "type": "file", "name": "a", "sha": "x" }])).await;
    assert!(
        matches!(e, ForgeError::Rejected { status: 409, ref message } if message.contains("directory")),
        "{e:?}"
    );

    let e = write_file_against(
        json!({ "type": "file", "sha": "big", "encoding": "none", "content": "" }),
    )
    .await;
    assert!(
        matches!(e, ForgeError::Rejected { status: 409, ref message } if message.contains("too large")),
        "{e:?}"
    );
}
