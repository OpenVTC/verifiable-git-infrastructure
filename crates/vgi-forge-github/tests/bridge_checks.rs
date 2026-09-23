//! The bridge-posted check (§9, "forged check runs"): with
//! `GitHubConfig::bridge_checks`, a namespace without an org required
//! workflow commits no workflow, and its ruleset requires the check from the
//! App itself — which only the bridge can post as.

mod common;

use common::*;
use http::HeaderMap;
use serde_json::json;
use vgi_forge::{
    CheckSourceGuard, Forge, ForgeAccount, ForgeError, Namespace, NamespaceKind, Projection,
    ProtectionGap, RepoSpec, StepAction, StepOutcome, VgiConfig,
};
use vgi_forge_github::{CheckConclusion, CheckTriggerKind, GitHubForge, Secret, webhook};
use wiremock::matchers::{body_json, body_partial_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const HEAD: &str = "1111111111111111111111111111111111111111";
const BASE: &str = "2222222222222222222222222222222222222222";
const KEYRING: &str =
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nweb-flow\n-----END PGP PUBLIC KEY BLOCK-----\n";
/// The App id `forge_with` configures.
const APP_ID: u64 = 1001;

fn bridge_forge(server: &MockServer) -> GitHubForge {
    forge_with(server, |cfg| {
        cfg.with_actions_integration_id(ACTIONS_APP_ID)
            .with_bridge_checks()
    })
}

fn vgi_config() -> VgiConfig {
    VgiConfig::new(
        "did:webvh:registry.example",
        "did:webvh:vtc.acme.example",
        format!("OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@{SHA}"),
        "v0.5.0",
    )
    .with_platform_keyring(KEYRING)
}

fn admin_perms() -> serde_json::Value {
    json!({ "administration": "write", "metadata": "read" })
}

#[tokio::test]
async fn capabilities_say_the_bridge_posts_the_check_outside_a_required_workflow() {
    let server = MockServer::start().await;
    let plain = forge_for(&server);
    let bridge = bridge_forge(&server);
    let org = Namespace::new(acme(), NamespaceKind::Organization)
        .with_owner_id(500)
        .with_installation(INSTALLATION);
    let user = Namespace::new(
        vgi_forge::Resource::parse("github.com/alice").unwrap(),
        NamespaceKind::User,
    )
    .with_owner_id(1)
    .with_installation(USER_INSTALLATION);
    for ns in [org.clone(), user] {
        assert!(!plain.capabilities(&ns).bridge_posted_check);
        let caps = bridge.capabilities(&ns);
        assert!(caps.bridge_posted_check, "{ns:?}");
        assert!(
            !caps.single_owner_repos_unreviewed,
            "no repository workflow is left to weaken"
        );
    }
    // Where the org has a required workflow, that is what runs.
    bridge.set_required_workflow(&acme(), true);
    let caps = bridge.capabilities(&org);
    assert!(caps.required_workflow && !caps.bridge_posted_check);
}

#[tokio::test]
async fn the_plan_commits_no_workflow_and_removes_an_old_one() {
    let server = MockServer::start().await;
    let forge = bridge_forge(&server);
    // Two owners: the owner-review guard would apply without bridge checks.
    let spec = RepoSpec::new(repo("gadgets"))
        .with_owner(ForgeAccount::new(7, "bob"))
        .with_owner(ForgeAccount::new(8, "carol"));
    let plan = forge.bootstrap_plan(&spec, &vgi_config()).unwrap();
    let ids: Vec<_> = plan.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "ruleset",
            "cleanup:variable:TRUST_REGISTRY_DID",
            "cleanup:variable:VTC_DID",
            "cleanup:workflow",
        ]
    );
    assert!(
        !plan
            .iter()
            .any(|s| matches!(s.action, StepAction::WriteFile { .. })),
        "nothing in the repository is on the check's path"
    );
    match &plan[0].action {
        StepAction::ProtectDefaultBranch(spec) => {
            assert!(spec.require_status_check && !spec.require_code_owner_review);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn the_ruleset_pins_the_check_to_the_app_itself() {
    let server = MockServer::start().await;
    let forge = bridge_forge(&server);
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
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    // Never asks for the Actions App: nothing Actions posts may count.
    Mock::given(method("GET"))
        .and(path("/apps/github-actions"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/gadgets/rulesets"))
        .and(body_partial_json(json!({
            "bypass_actors": [],
            "rules": [
                { "type": "deletion" },
                { "type": "non_fast_forward" },
                { "type": "pull_request" },
                { "type": "required_status_checks", "parameters": {
                    "required_status_checks": [
                        { "context": "Verify commit trust", "integration_id": APP_ID }
                    ]
                } }
            ]
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 5 })))
        .expect(1)
        .mount(&server)
        .await;

    let spec = RepoSpec::new(repo("gadgets")).with_owner(ForgeAccount::new(7, "bob"));
    let plan = forge.bootstrap_plan(&spec, &vgi_config()).unwrap();
    let outcome = forge.run_step(&repo("gadgets"), &plan[0]).await.unwrap();
    assert_eq!(outcome, StepOutcome::Created);
}

/// `good_ruleset` with the check pinned to `integration`.
fn ruleset_pinned_to(integration: u64) -> serde_json::Value {
    let mut rs = good_ruleset(9);
    rs["rules"][3]["parameters"]["required_status_checks"][0]["integration_id"] =
        json!(integration);
    rs
}

async fn mount_inspect(server: &MockServer, ruleset: serde_json::Value) {
    mount_token(server, INSTALLATION, Some("widgets"), admin_perms(), 1).await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(repo_json(
            812,
            "acme/widgets",
            false,
        )))
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
        .respond_with(ResponseTemplate::new(200).set_body_json(ruleset))
        .mount(server)
        .await;
}

fn projection() -> Projection {
    let mut p = Projection::new(repo("widgets"));
    p.forge_id = Some(812);
    p.required_check = Some("Verify commit trust".into());
    p.owners = vec![ForgeAccount::new(7, "bob"), ForgeAccount::new(8, "carol")];
    p
}

#[tokio::test]
async fn inspect_counts_only_a_check_pinned_to_the_app() {
    let server = MockServer::start().await;
    let forge = bridge_forge(&server);
    mount_inspect(&server, ruleset_pinned_to(APP_ID)).await;
    let state = forge.inspect(&repo("widgets")).await.unwrap();
    assert_eq!(state.protection.required_checks, ["Verify commit trust"]);
    assert_eq!(
        state.protection.check_source_guard,
        CheckSourceGuard::BridgePosted
    );
    assert!(
        forge.diff(&state, &projection()).is_empty(),
        "two owners need no review guard when the bridge posts the check"
    );

    // The same ruleset pinned to Actions is forgeable: it does not count.
    let server = MockServer::start().await;
    let forge = bridge_forge(&server);
    mount_inspect(&server, ruleset_pinned_to(ACTIONS_APP_ID)).await;
    let state = forge.inspect(&repo("widgets")).await.unwrap();
    let drift = forge.diff(&state, &projection());
    assert!(
        drift.iter().any(|d| matches!(d,
            vgi_forge::Drift::ProtectionWeakened { gaps }
                if gaps.contains(&ProtectionGap::CheckNotRequired { check: "Verify commit trust".into() }))),
        "{drift:?}"
    );
}

fn signed(event: &str, body: &serde_json::Value) -> (HeaderMap, Vec<u8>) {
    let body = serde_json::to_vec(body).unwrap();
    let mut h = HeaderMap::new();
    h.insert("x-github-event", event.parse().unwrap());
    h.insert("x-github-delivery", "d-1".parse().unwrap());
    h.insert(
        "x-hub-signature-256",
        webhook::sign_body(&Secret::new(WEBHOOK_SECRET), &body)
            .parse()
            .unwrap(),
    );
    (h, body)
}

fn pr_event(action: &str) -> serde_json::Value {
    json!({
        "action": action,
        "repository": { "id": 812, "full_name": "Acme/Widgets" },
        "pull_request": {
            "number": 17,
            "commits": 2,
            "head": { "sha": HEAD, "repo": { "full_name": "mallory/widgets" } },
            "base": { "sha": BASE },
        },
    })
}

#[tokio::test]
async fn pull_request_and_merge_group_deliveries_trigger_the_check() {
    let server = MockServer::start().await;
    let forge = bridge_forge(&server);

    for action in ["opened", "synchronize", "reopened"] {
        let (h, b) = signed("pull_request", &pr_event(action));
        let t = forge.parse_check_trigger(&h, &b).unwrap().unwrap();
        assert_eq!(t.repo, repo("widgets"), "the base repository, lowercased");
        assert_eq!((t.head_sha.as_str(), t.base_sha.as_str()), (HEAD, BASE));
        assert_eq!(
            t.kind,
            CheckTriggerKind::PullRequest {
                number: 17,
                commits: Some(2)
            }
        );
    }
    for action in ["closed", "labeled", "edited"] {
        let (h, b) = signed("pull_request", &pr_event(action));
        assert!(forge.parse_check_trigger(&h, &b).unwrap().is_none());
    }
    let (h, b) = signed(
        "merge_group",
        &json!({
            "action": "checks_requested",
            "repository": { "id": 812, "full_name": "acme/widgets" },
            "merge_group": { "head_sha": HEAD, "base_sha": BASE, "head_ref": "refs/heads/gh-readonly-queue/main/pr-17" },
        }),
    );
    let t = forge.parse_check_trigger(&h, &b).unwrap().unwrap();
    assert_eq!(t.kind, CheckTriggerKind::MergeGroup);

    // Other events are someone else's.
    let (h, b) = signed("repository", &json!({ "action": "created" }));
    assert!(forge.parse_check_trigger(&h, &b).unwrap().is_none());
}

#[tokio::test]
async fn a_delivery_is_verified_before_it_is_read() {
    let server = MockServer::start().await;
    let forge = bridge_forge(&server);
    let (mut h, b) = signed("pull_request", &pr_event("opened"));
    let mut tampered = b.clone();
    tampered.extend_from_slice(b" ");
    assert!(matches!(
        forge.parse_check_trigger(&h, &tampered),
        Err(ForgeError::Webhook(_))
    ));
    h.remove("x-hub-signature-256");
    assert!(matches!(
        forge.parse_check_trigger(&h, &b),
        Err(ForgeError::Webhook(_))
    ));
    // A signed body with a head that is not a commit id is refused too: it
    // would go into a git command line.
    let mut evil = pr_event("opened");
    evil["pull_request"]["head"]["sha"] = json!("--upload-pack=touch /tmp/x");
    let (h, b) = signed("pull_request", &evil);
    assert!(forge.parse_check_trigger(&h, &b).is_err());
}

#[tokio::test]
async fn check_runs_are_posted_with_a_checks_only_token_for_the_one_repository() {
    let server = MockServer::start().await;
    let forge = bridge_forge(&server);
    let checks = json!({ "checks": "write", "metadata": "read" });
    mount_token(&server, INSTALLATION, Some("widgets"), checks, 2).await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/widgets/check-runs"))
        .and(InstallationToken)
        .and(body_partial_json(json!({
            "name": "Verify commit trust", "head_sha": HEAD, "status": "in_progress",
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 77 })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/repos/acme/widgets/check-runs/77"))
        .and(body_json(json!({
            "status": "completed",
            "conclusion": "failure",
            "output": { "title": "1 of 2 commits not trusted", "summary": "details" },
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 77 })))
        .expect(1)
        .mount(&server)
        .await;

    let id = forge
        .start_check_run(&repo("widgets"), HEAD, "Verify commit trust", "d-1")
        .await
        .unwrap();
    assert_eq!(id, 77);
    forge
        .finish_check_run(
            &repo("widgets"),
            id,
            CheckConclusion::Failure,
            "1 of 2 commits not trusted",
            "details",
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn commits_are_compared_with_a_read_only_token() {
    let server = MockServer::start().await;
    let forge = bridge_forge(&server);
    let read = json!({ "contents": "read", "metadata": "read" });
    mount_token(&server, INSTALLATION, Some("widgets"), read, 2).await;
    Mock::given(method("GET"))
        .and(path(format!("/repos/acme/widgets/compare/{BASE}...{HEAD}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total_commits": 2,
            "merge_base_commit": { "sha": BASE },
            "commits": [ { "sha": SHA }, { "sha": HEAD } ],
        })))
        .expect(1)
        .mount(&server)
        .await;
    let c = forge
        .compare_commits(&repo("widgets"), BASE, HEAD)
        .await
        .unwrap();
    assert_eq!(c.commits, [SHA, HEAD]);
    assert_eq!(c.total, 2);
    let token = forge.contents_read_token(&repo("widgets")).await.unwrap();
    assert_eq!(token.expose(), TOKEN);
    assert_eq!(
        forge.clone_url(&repo("widgets")).unwrap().path(),
        "/acme/widgets.git"
    );
    // A bad id never reaches a URL.
    assert!(
        forge
            .compare_commits(&repo("widgets"), "main", HEAD)
            .await
            .is_err()
    );
}
