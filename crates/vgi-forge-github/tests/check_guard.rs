//! §9: the pull request must not be able to satisfy its own check.
//!
//! Organisations with org rulesets get a required workflow held in
//! `<org>/.vgi` at a pinned commit; elsewhere a repository with two or more
//! owners gets `CODEOWNERS` plus code-owner review, and a solo repository
//! gets the check alone (the user's decision). Driven against a mock GitHub
//! with exact request bodies.

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use serde_json::{Value, json};
use vgi_forge::{
    BootstrapStep, CheckSourceGuard, Drift, Forge, ForgeAccount, ForgeError, Namespace,
    NamespaceKind, Projection, ProtectionGap, RepoSpec, Resource, StepAction, StepOutcome,
    VgiConfig, run_plan,
};
use vgi_forge_github::plan::{WORKFLOW_PATH, render_codeowners};
use vgi_forge_github::{GitHubForge, RequiredWorkflowPin};
use wiremock::matchers::{body_json, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const KEYRING: &str =
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nweb-flow\n-----END PGP PUBLIC KEY BLOCK-----\n";
/// `.vgi`'s numeric id.
const CENTRAL_ID: u64 = 555;
/// `.vgi`'s head before the bridge writes.
const HEAD: &str = "1111111111111111111111111111111111111111";
/// The commit the bridge's workflow write produced, and pins.
const PIN: &str = "2222222222222222222222222222222222222222";
/// A commit somebody else pushed to `.vgi`.
const OTHER: &str = "3333333333333333333333333333333333333333";
/// `acme/gadgets`'s id.
const GADGETS_ID: u64 = 9001;

fn vgi_config() -> VgiConfig {
    VgiConfig::new(
        "did:webvh:registry.example",
        "did:webvh:vtc.acme.example",
        format!("OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@{SHA}"),
        "v0.5.0",
    )
    .with_platform_keyring(KEYRING)
}

fn admin() -> Value {
    json!({ "administration": "write", "metadata": "read" })
}

fn bob() -> ForgeAccount {
    ForgeAccount::new(7, "bob")
}

fn carol() -> ForgeAccount {
    ForgeAccount::new(9, "carol")
}

/// An org forge with org rulesets and `managed` as its managed set.
fn org_forge(server: &MockServer, managed: &[u64]) -> GitHubForge {
    let forge = forge_for(server);
    forge.set_required_workflow(&acme(), true);
    forge.set_managed_repositories(&acme(), managed.iter().copied());
    forge
}

fn step(plan: &[BootstrapStep], id: &str) -> BootstrapStep {
    plan.iter().find(|s| s.id == id).unwrap().clone()
}

fn org_plan(forge: &GitHubForge) -> Vec<BootstrapStep> {
    forge
        .bootstrap_plan(&RepoSpec::new(repo("gadgets")), &vgi_config())
        .unwrap()
}

fn central_workflow(forge: &GitHubForge) -> Vec<u8> {
    match step(&org_plan(forge), "required-workflow").action {
        StepAction::RequireNamespaceWorkflow { contents, .. } => contents,
        other => panic!("{other:?}"),
    }
}

fn central_repo_json() -> Value {
    json!({
        "id": CENTRAL_ID, "full_name": "acme/.vgi", "private": false,
        "visibility": "public", "archived": false, "default_branch": "main",
    })
}

/// The org ruleset exactly as the adapter asks for it.
fn org_ruleset_body(sha: &str, repo_ids: &[u64]) -> Value {
    json!({
        "name": "VGI required workflow",
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {
            "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] },
            "repository_id": { "repository_ids": repo_ids },
        },
        "rules": [{
            "type": "workflows",
            "parameters": {
                "do_not_enforce_on_create": false,
                "workflows": [{
                    "repository_id": CENTRAL_ID,
                    "path": ".github/workflows/verify-trust.yml",
                    "ref": "refs/heads/main",
                    "sha": sha,
                }],
            },
        }],
    })
}

/// The org ruleset as GitHub returns it.
fn org_ruleset(sha: &str, repo_ids: &[u64]) -> Value {
    let mut rs = org_ruleset_body(sha, repo_ids);
    rs["id"] = json!(31);
    rs["source_type"] = json!("Organization");
    rs["current_user_can_bypass"] = json!("never");
    rs
}

/// The repository ruleset without a status check or review: the
/// per-repository ruleset under a required workflow, and `.vgi`'s own.
fn plain_ruleset_body() -> Value {
    json!({
        "name": "VGI commit trust",
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
        "rules": [
            { "type": "deletion" },
            { "type": "non_fast_forward" },
            { "type": "pull_request", "parameters": {
                "required_approving_review_count": 0,
                "dismiss_stale_reviews_on_push": false,
                "require_code_owner_review": false,
                "require_last_push_approval": false,
                "required_review_thread_resolution": false
            } }
        ]
    })
}

fn plain_ruleset(id: u64) -> Value {
    let mut rs = plain_ruleset_body();
    rs["id"] = json!(id);
    rs["current_user_can_bypass"] = json!("never");
    rs
}

async fn mount_get(server: &MockServer, p: &str, reply: Value) {
    Mock::given(method("GET"))
        .and(path(p))
        .and(InstallationToken)
        .respond_with(ResponseTemplate::new(200).set_body_json(reply))
        .mount(server)
        .await;
}

async fn forbid_writes(server: &MockServer) {
    for verb in ["PUT", "POST", "PATCH", "DELETE"] {
        Mock::given(method(verb))
            .and(path_regex("^/(repos|orgs)/"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .named(format!("no {verb}"))
            .mount(server)
            .await;
    }
}

/// The org ruleset as the first read finds it (`before`) and as the read
/// after a write finds it (`after`).
async fn mount_org_ruleset(server: &MockServer, before: Option<Value>, after: Option<Value>) {
    mount_token(
        server,
        INSTALLATION,
        None,
        json!({ "organization_administration": "write" }),
        1,
    )
    .await;
    let list = match &before {
        Some(_) => {
            json!([{ "id": 31, "name": "VGI required workflow" }, { "id": 4, "name": "other" }])
        }
        None => json!([{ "id": 4, "name": "other" }]),
    };
    mount_get(server, "/orgs/acme/rulesets", list).await;
    if let Some(b) = before {
        let mut m = Mock::given(method("GET")).and(path("/orgs/acme/rulesets/31"));
        if after.is_some() {
            m = m.and(InstallationToken);
            m.respond_with(ResponseTemplate::new(200).set_body_json(b))
                .up_to_n_times(1)
                .with_priority(1)
                .mount(server)
                .await;
        } else {
            m.respond_with(ResponseTemplate::new(200).set_body_json(b))
                .mount(server)
                .await;
        }
    }
    if let Some(a) = after {
        mount_get(server, "/orgs/acme/rulesets/31", a).await;
    }
}

/// `.vgi`'s own ruleset: `existing` (`None`: to be created, exactly).
async fn mount_central_protection(server: &MockServer, existing: Option<Value>) {
    mount_token(server, INSTALLATION, Some(".vgi"), admin(), 1).await;
    match existing {
        Some(rs) => {
            mount_get(
                server,
                "/repos/acme/.vgi/rulesets",
                json!([{ "id": 5, "name": "VGI commit trust" }]),
            )
            .await;
            mount_get(server, "/repos/acme/.vgi/rulesets/5", rs).await;
        }
        None => {
            mount_get(server, "/repos/acme/.vgi/rulesets", json!([])).await;
            Mock::given(method("POST"))
                .and(path("/repos/acme/.vgi/rulesets"))
                .and(body_json(plain_ruleset_body()))
                .respond_with(ResponseTemplate::new(201).set_body_json(plain_ruleset(5)))
                .expect(1)
                .mount(server)
                .await;
        }
    }
}

/// The `required-workflow` step's reads once `.vgi` exists and is
/// protected.
async fn mount_step_reads(server: &MockServer, before: Option<Value>, after: Option<Value>) {
    mount_token(
        server,
        INSTALLATION,
        Some("gadgets"),
        json!({ "metadata": "read" }),
        1,
    )
    .await;
    mount_get(
        server,
        "/repos/acme/gadgets",
        repo_json(GADGETS_ID, "acme/gadgets", false),
    )
    .await;
    mount_token(
        server,
        INSTALLATION,
        Some(".vgi"),
        json!({ "contents": "write", "metadata": "read" }),
        1,
    )
    .await;
    mount_get(server, "/repos/acme/.vgi", central_repo_json()).await;
    mount_org_ruleset(server, before, after).await;
    mount_central_protection(server, Some(plain_ruleset(5))).await;
}

async fn mount_central_file(server: &MockServer, at: &str, contents: Option<&[u8]>) {
    let reply = match contents {
        Some(c) => ResponseTemplate::new(200).set_body_json(file_reply(c, "blob-at-ref")),
        None => ResponseTemplate::new(404).set_body_json(json!({ "message": "Not Found" })),
    };
    Mock::given(method("GET"))
        .and(path(
            "/repos/acme/.vgi/contents/.github/workflows/verify-trust.yml",
        ))
        .and(query_param("ref", at))
        .respond_with(reply)
        .mount(server)
        .await;
}

async fn run(forge: &GitHubForge, id: &str) -> vgi_forge::Result<StepOutcome> {
    forge
        .run_step(&repo("gadgets"), &step(&org_plan(forge), id))
        .await
}

// ── org mode ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn org_mode_creates_and_protects_vgi_and_pins_the_org_ruleset_then_reruns_as_a_no_op() {
    let server = MockServer::start().await;
    let forge = org_forge(&server, &[]);
    let org = Namespace::new(acme(), NamespaceKind::Organization).with_installation(INSTALLATION);
    let caps = forge.capabilities(&org);
    assert!(caps.required_workflow && !caps.single_owner_repos_unreviewed);

    let plan = org_plan(&forge);
    let ids: Vec<_> = plan.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "required-workflow",
            "ruleset",
            "cleanup:variable:TRUST_REGISTRY_DID",
            "cleanup:variable:VTC_DID",
            "cleanup:workflow",
            "cleanup:keyring"
        ],
        "no per-repo workflow, keyring, variables or CODEOWNERS; leftovers cleaned up"
    );
    let workflow = central_workflow(&forge);

    // ── first run: no `.vgi`, no org ruleset, no repo ruleset ──
    mount_token(
        &server,
        INSTALLATION,
        Some("gadgets"),
        json!({ "metadata": "read" }),
        1,
    )
    .await;
    mount_get(
        &server,
        "/repos/acme/gadgets",
        repo_json(GADGETS_ID, "acme/gadgets", false),
    )
    .await;
    // `.vgi` is not in the installation yet: the scoped token is refused…
    Mock::given(method("POST"))
        .and(path(format!(
            "/app/installations/{INSTALLATION}/access_tokens"
        )))
        .and(body_json(json!({
            "permissions": { "contents": "write", "metadata": "read" },
            "repositories": [".vgi"],
        })))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "message": "There is at least one repository that does not exist or is not accessible to the parent installation."
        })))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    // …then granted once the bridge has created it.
    mount_token(
        &server,
        INSTALLATION,
        Some(".vgi"),
        json!({ "contents": "write", "metadata": "read" }),
        1,
    )
    .await;
    mount_token(&server, INSTALLATION, None, admin(), 1).await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/.vgi"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "message": "Not Found" })))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/orgs/acme/repos"))
        .and(body_json(json!({
            "name": ".vgi",
            "visibility": "public",
            "description": "VGI: the commit-trust workflow this community's repositories are required to pass. Managed by the VGI bridge.",
            "auto_init": true,
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(central_repo_json()))
        .expect(1)
        .mount(&server)
        .await;
    mount_get(&server, "/repos/acme/.vgi", central_repo_json()).await;
    mount_org_ruleset(&server, None, Some(org_ruleset(PIN, &[GADGETS_ID]))).await;
    mount_get(
        &server,
        "/repos/acme/.vgi/commits/main",
        json!({ "sha": HEAD }),
    )
    .await;
    mount_central_file(&server, HEAD, None).await;
    Mock::given(method("PUT"))
        .and(path(
            "/repos/acme/.vgi/contents/.github/workflows/verify-trust.yml",
        ))
        .and(body_json(json!({
            "message": "ci: pin the VGI commit-trust check",
            "content": STANDARD.encode(&workflow),
            "branch": "main",
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "content": { "sha": "blob" }, "commit": { "sha": PIN },
        })))
        .expect(1)
        .mount(&server)
        .await;
    // `.vgi` itself gets a ruleset: PRs only, no force-push, no deletion.
    mount_central_protection(&server, None).await;
    Mock::given(method("POST"))
        .and(path("/orgs/acme/rulesets"))
        .and(body_json(org_ruleset_body(PIN, &[GADGETS_ID])))
        .respond_with(ResponseTemplate::new(201).set_body_json(org_ruleset(PIN, &[GADGETS_ID])))
        .expect(1)
        .mount(&server)
        .await;
    // The repo ruleset: no required status check (the org ruleset has it),
    // so no Actions App lookup either.
    mount_token(&server, INSTALLATION, Some("gadgets"), admin(), 1).await;
    mount_get(&server, "/repos/acme/gadgets/rulesets", json!([])).await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/gadgets/rulesets"))
        .and(body_json(plain_ruleset_body()))
        .respond_with(ResponseTemplate::new(201).set_body_json(plain_ruleset(9)))
        .expect(1)
        .mount(&server)
        .await;
    // Clean-up finds nothing to remove (unmatched reads are 404s).
    mount_token(
        &server,
        INSTALLATION,
        Some("gadgets"),
        json!({ "actions_variables": "write", "metadata": "read" }),
        2,
    )
    .await;
    mount_token(
        &server,
        INSTALLATION,
        Some("gadgets"),
        json!({ "contents": "write", "metadata": "read" }),
        2,
    )
    .await;

    let report = run_plan(&forge, &repo("gadgets"), &plan).await;
    assert!(report.is_complete(), "{:?}", report.failed);
    let outcomes: Vec<_> = report.completed.iter().map(|(_, o)| *o).collect();
    assert_eq!(
        outcomes,
        [
            StepOutcome::Created,
            StepOutcome::Created,
            StepOutcome::Unchanged,
            StepOutcome::Unchanged,
            StepOutcome::Unchanged,
            StepOutcome::Unchanged
        ]
    );
    assert_eq!(
        forge.required_workflow_pin(&acme()),
        Some(RequiredWorkflowPin::new(
            CENTRAL_ID,
            PIN,
            "Verify commit trust"
        ))
    );
    assert_eq!(
        forge.managed_repositories(&acme()),
        Some([GADGETS_ID].into())
    );
    server.verify().await;
    server.reset().await;

    // ── second run: all in place — even with someone's unrelated commit on
    // `.vgi`'s head, nothing is written and the pin does not move ──
    mount_step_reads(&server, Some(org_ruleset(PIN, &[GADGETS_ID])), None).await;
    mount_central_file(&server, PIN, Some(&workflow)).await;
    mount_get(
        &server,
        "/repos/acme/.vgi/commits/main",
        json!({ "sha": OTHER }),
    )
    .await;
    forbid_writes(&server).await;
    let r = run(&forge, "required-workflow").await.unwrap();
    assert_eq!(r, StepOutcome::Unchanged);
    server.verify().await;
}

/// The required workflow as bridges before the namespace fallback wrote it.
fn workflow_without_fallback(current: &[u8]) -> Vec<u8> {
    let current = std::str::from_utf8(current).unwrap();
    let fallback = "          # The namespace: where the VTC publishes namespace-wide commit rights.\n          \
                    fallback-resource: github.com/${{ github.repository_owner }}\n";
    assert!(current.contains(fallback), "{current}");
    current.replace(fallback, "").into_bytes()
}

/// An existing organisation, pinned to the workflow without the namespace
/// fallback, converges on the next bootstrap: `.vgi` is protected, so the
/// bridge cannot write the new workflow itself and the pin stays where it
/// is; once the new workflow is merged there (byte for byte what the
/// bridge renders), the pin moves to it — and only to it.
#[tokio::test]
async fn an_upgraded_workflow_is_pinned_once_merged_in_vgi_and_not_before() {
    let server = MockServer::start().await;
    let forge = org_forge(&server, &[]);
    let workflow = central_workflow(&forge);
    let old = workflow_without_fallback(&workflow);
    assert_ne!(old, workflow);

    // ── not merged yet: the head still holds the old workflow ──
    // (`mount_step_reads` without `.vgi`'s protection: the step stops
    // before it.)
    mount_token(
        &server,
        INSTALLATION,
        Some("gadgets"),
        json!({ "metadata": "read" }),
        1,
    )
    .await;
    mount_get(
        &server,
        "/repos/acme/gadgets",
        repo_json(GADGETS_ID, "acme/gadgets", false),
    )
    .await;
    mount_token(
        &server,
        INSTALLATION,
        Some(".vgi"),
        json!({ "contents": "write", "metadata": "read" }),
        1,
    )
    .await;
    mount_get(&server, "/repos/acme/.vgi", central_repo_json()).await;
    mount_org_ruleset(&server, Some(org_ruleset(PIN, &[GADGETS_ID])), None).await;
    mount_central_file(&server, PIN, Some(&old)).await;
    mount_get(
        &server,
        "/repos/acme/.vgi/commits/main",
        json!({ "sha": OTHER }),
    )
    .await;
    mount_central_file(&server, OTHER, Some(&old)).await;
    Mock::given(method("PUT"))
        .and(path(
            "/repos/acme/.vgi/contents/.github/workflows/verify-trust.yml",
        ))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "message": "Repository rule violations found"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/orgs/acme/rulesets/31"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let e = run(&forge, "required-workflow").await.unwrap_err();
    assert!(
        e.to_string().contains("lands through a pull request"),
        "{e}"
    );
    assert_eq!(
        forge.required_workflow_pin(&acme()),
        None,
        "the pin did not move"
    );
    server.verify().await;

    // ── merged: the head holds exactly the new workflow; it is pinned ──
    let server = MockServer::start().await;
    let forge = org_forge(&server, &[]);
    mount_step_reads(
        &server,
        Some(org_ruleset(PIN, &[GADGETS_ID])),
        Some(org_ruleset(OTHER, &[GADGETS_ID])),
    )
    .await;
    mount_central_file(&server, PIN, Some(&old)).await;
    mount_get(
        &server,
        "/repos/acme/.vgi/commits/main",
        json!({ "sha": OTHER }),
    )
    .await;
    mount_central_file(&server, OTHER, Some(&workflow)).await;
    Mock::given(method("PUT"))
        .and(path(
            "/repos/acme/.vgi/contents/.github/workflows/verify-trust.yml",
        ))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/orgs/acme/rulesets/31"))
        .and(body_json(org_ruleset_body(OTHER, &[GADGETS_ID])))
        .respond_with(ResponseTemplate::new(200).set_body_json(org_ruleset(OTHER, &[GADGETS_ID])))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        run(&forge, "required-workflow").await.unwrap(),
        StepOutcome::Updated
    );
    assert_eq!(
        forge.required_workflow_pin(&acme()),
        Some(RequiredWorkflowPin::new(
            CENTRAL_ID,
            OTHER,
            "Verify commit trust"
        ))
    );
    server.verify().await;
}

#[tokio::test]
async fn the_org_ruleset_lists_exactly_the_managed_set() {
    // Managed {77} plus the repository being bootstrapped; GitHub's 1234
    // (archived, or never managed) is dropped.
    let server = MockServer::start().await;
    let forge = org_forge(&server, &[77]);
    let workflow = central_workflow(&forge);
    mount_step_reads(
        &server,
        Some(org_ruleset(PIN, &[77, 1234])),
        Some(org_ruleset(PIN, &[77, GADGETS_ID])),
    )
    .await;
    mount_central_file(&server, PIN, Some(&workflow)).await;
    Mock::given(method("PUT"))
        .and(path("/orgs/acme/rulesets/31"))
        .and(body_json(org_ruleset_body(PIN, &[77, GADGETS_ID])))
        .respond_with(ResponseTemplate::new(200).set_body_json(org_ruleset(PIN, &[77, GADGETS_ID])))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        run(&forge, "required-workflow").await.unwrap(),
        StepOutcome::Updated
    );

    // Without the bridge's managed set, the step refuses to guess it.
    let server = MockServer::start().await;
    let forge = forge_for(&server);
    forge.set_required_workflow(&acme(), true);
    forbid_writes(&server).await;
    let e = run(&forge, "required-workflow").await.unwrap_err();
    assert!(e.to_string().contains("set_managed_repositories"), "{e}");
}

#[tokio::test]
async fn an_archived_repository_leaves_the_managed_set() {
    let server = MockServer::start().await;
    let forge = org_forge(&server, &[77, GADGETS_ID]);
    mount_token(&server, INSTALLATION, Some("gadgets"), admin(), 1).await;
    mount_get(
        &server,
        "/repos/acme/gadgets",
        repo_json(GADGETS_ID, "acme/gadgets", true),
    )
    .await;
    forge.archive_repo(&repo("gadgets")).await.unwrap();
    assert_eq!(forge.managed_repositories(&acme()), Some([77].into()));
}

#[tokio::test]
async fn a_concurrent_edit_that_loses_the_repository_is_an_error_to_retry() {
    let server = MockServer::start().await;
    let forge = org_forge(&server, &[77]);
    let workflow = central_workflow(&forge);
    // Written with 9001, but read back without it: someone else's write
    // landed in between.
    mount_step_reads(
        &server,
        Some(org_ruleset(PIN, &[77])),
        Some(org_ruleset(PIN, &[77])),
    )
    .await;
    mount_central_file(&server, PIN, Some(&workflow)).await;
    Mock::given(method("PUT"))
        .and(path("/orgs/acme/rulesets/31"))
        .and(body_json(org_ruleset_body(PIN, &[77, GADGETS_ID])))
        .respond_with(ResponseTemplate::new(200).set_body_json(org_ruleset(PIN, &[77, GADGETS_ID])))
        .expect(1)
        .mount(&server)
        .await;
    let e = run(&forge, "required-workflow").await.unwrap_err();
    assert!(e.is_retryable(), "{e:?}");
    assert!(e.to_string().contains("concurrent"), "{e}");
}

#[tokio::test]
async fn a_ruleset_switched_to_name_conditions_is_drift_and_rewritten_by_id() {
    let mut by_name = org_ruleset(PIN, &[]);
    by_name["conditions"] = json!({
        "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] },
        "repository_name": { "include": ["gadg*"], "exclude": [] },
    });

    // Inspect reports it…
    let server = MockServer::start().await;
    let forge = org_forge(&server, &[77, GADGETS_ID]);
    forge.set_required_workflow_pin(
        &acme(),
        RequiredWorkflowPin::new(CENTRAL_ID, PIN, "Verify commit trust"),
    );
    mount_org_inspect(&server, Some(by_name.clone())).await;
    let state = forge.inspect(&repo("gadgets")).await.unwrap();
    let gaps = source_gaps(&forge.diff(&state, &projection()));
    assert!(
        gaps.iter()
            .any(|g| g.contains("selects repositories by `repository_name`")),
        "{gaps:?}"
    );

    // …and the step rewrites the conditions to ids, with the whole managed
    // set — not just this repository.
    let server = MockServer::start().await;
    let forge = org_forge(&server, &[77, GADGETS_ID]);
    let workflow = central_workflow(&forge);
    mount_step_reads(
        &server,
        Some(by_name),
        Some(org_ruleset(PIN, &[77, GADGETS_ID])),
    )
    .await;
    mount_central_file(&server, PIN, Some(&workflow)).await;
    Mock::given(method("PUT"))
        .and(path("/orgs/acme/rulesets/31"))
        .and(body_json(org_ruleset_body(PIN, &[77, GADGETS_ID])))
        .respond_with(ResponseTemplate::new(200).set_body_json(org_ruleset(PIN, &[77, GADGETS_ID])))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        run(&forge, "required-workflow").await.unwrap(),
        StepOutcome::Updated
    );
}

/// Inspect of `acme/gadgets` under a required workflow, with the org
/// ruleset as `org` and a healthy `.vgi`.
async fn mount_org_inspect(server: &MockServer, org: Option<Value>) {
    mount_org_inspect_with(
        server,
        org,
        central_repo_json(),
        Some(plain_ruleset(5)),
        true,
    )
    .await;
}

async fn mount_org_inspect_with(
    server: &MockServer,
    org: Option<Value>,
    central: Value,
    central_ruleset: Option<Value>,
    pin_reachable: bool,
) {
    mount_token(server, INSTALLATION, Some("gadgets"), admin(), 1).await;
    mount_get(
        server,
        "/repos/acme/gadgets",
        repo_json(GADGETS_ID, "acme/gadgets", false),
    )
    .await;
    mount_get(server, "/repos/acme/gadgets/collaborators", json!([])).await;
    mount_get(server, "/repos/acme/gadgets/invitations", json!([])).await;
    mount_get(
        server,
        "/repos/acme/gadgets/rulesets",
        json!([{ "id": 9, "name": "VGI commit trust" }]),
    )
    .await;
    mount_get(server, "/repos/acme/gadgets/rulesets/9", plain_ruleset(9)).await;
    mount_actions_allowed(server, "acme/gadgets").await;
    mount_org_ruleset(server, org, None).await;
    mount_token(
        server,
        INSTALLATION,
        Some(".vgi"),
        json!({ "administration": "write", "contents": "read", "metadata": "read" }),
        1,
    )
    .await;
    mount_get(server, "/repos/acme/.vgi", central).await;
    match central_ruleset {
        Some(rs) => {
            mount_get(
                server,
                "/repos/acme/.vgi/rulesets",
                json!([{ "id": 5, "name": "VGI commit trust" }]),
            )
            .await;
            mount_get(server, "/repos/acme/.vgi/rulesets/5", rs).await;
        }
        None => mount_get(server, "/repos/acme/.vgi/rulesets", json!([])).await,
    }
    if pin_reachable {
        mount_get(
            server,
            &format!("/repos/acme/.vgi/commits/{PIN}"),
            json!({ "sha": PIN }),
        )
        .await;
    }
}

fn projection() -> Projection {
    let mut p = Projection::new(repo("gadgets"));
    p.forge_id = Some(GADGETS_ID);
    p.required_check = Some("Verify commit trust".into());
    p
}

fn source_gaps(drift: &[Drift]) -> Vec<String> {
    drift
        .iter()
        .filter_map(|d| match d {
            Drift::ProtectionWeakened { gaps } => Some(gaps.clone()),
            _ => None,
        })
        .flatten()
        .filter_map(|g| match g {
            ProtectionGap::CheckSourceUnprotected { detail } => Some(detail),
            _ => None,
        })
        .collect()
}

fn pinned(forge: &GitHubForge) {
    forge.set_required_workflow_pin(
        &acme(),
        RequiredWorkflowPin::new(CENTRAL_ID, PIN, "Verify commit trust"),
    );
}

#[tokio::test]
async fn a_healthy_org_ruleset_makes_the_check_required() {
    let server = MockServer::start().await;
    let forge = org_forge(&server, &[GADGETS_ID]);
    pinned(&forge);
    mount_org_inspect(&server, Some(org_ruleset(PIN, &[GADGETS_ID]))).await;
    let state = forge.inspect(&repo("gadgets")).await.unwrap();
    assert_eq!(state.protection.required_checks, ["Verify commit trust"]);
    assert_eq!(
        state.protection.check_source_guard,
        CheckSourceGuard::RequiredWorkflow
    );
    assert!(
        state.protection.other_gaps.is_empty(),
        "{:?}",
        state.protection.other_gaps
    );
    assert_eq!(forge.diff(&state, &projection()), vec![]);
}

#[tokio::test]
async fn every_weakening_of_the_org_ruleset_is_critical_drift_and_is_reapplied() {
    let with = |f: &dyn Fn(&mut Value)| {
        let mut rs = org_ruleset(PIN, &[GADGETS_ID]);
        f(&mut rs);
        Some(rs)
    };
    let cases: Vec<(&str, Option<Value>, &str)> = vec![
        ("missing", None, "is missing"),
        (
            "bypass actor added",
            with(
                &|rs| rs["bypass_actors"] = json!([{ "actor_id": 1, "actor_type": "OrganizationAdmin", "bypass_mode": "always" }]),
            ),
            "bypass actors: OrganizationAdmin:1",
        ),
        (
            "not enforced",
            with(&|rs| rs["enforcement"] = json!("evaluate")),
            "`evaluate`, not enforced",
        ),
        (
            "workflow re-pinned",
            with(&|rs| rs["rules"][0]["parameters"]["workflows"][0]["sha"] = json!(OTHER)),
            "pins workflow commit 3333",
        ),
        (
            "repository dropped",
            with(&|rs| rs["conditions"]["repository_id"]["repository_ids"] = json!([77])),
            "does not include this repository",
        ),
        (
            "workflow rule removed",
            with(&|rs| rs["rules"] = json!([])),
            "no longer requires",
        ),
        (
            "not enforced on creation",
            with(&|rs| rs["rules"][0]["parameters"]["do_not_enforce_on_create"] = json!(true)),
            "not enforced on branch creation",
        ),
    ];
    for (name, org, expect) in cases {
        let server = MockServer::start().await;
        let forge = org_forge(&server, &[GADGETS_ID]);
        pinned(&forge);
        let workflow = central_workflow(&forge);

        // Found by inspect…
        mount_org_inspect(&server, org.clone()).await;
        let state = forge.inspect(&repo("gadgets")).await.unwrap();
        let drift = forge.diff(&state, &projection());
        let gaps = source_gaps(&drift);
        assert!(gaps.iter().any(|g| g.contains(expect)), "{name}: {gaps:?}");
        assert!(
            drift.iter().any(Drift::is_critical),
            "{name}: enforce-mode drift"
        );
        assert!(state.protection.required_checks.is_empty(), "{name}");
        server.reset().await;

        // …and put back by the step. A re-pinned commit is never adopted:
        // the bridge pins what it read back as its own workflow.
        let fixed = org_ruleset(PIN, &[GADGETS_ID]);
        mount_step_reads(&server, org.clone(), Some(fixed.clone())).await;
        mount_central_file(&server, PIN, Some(&workflow)).await;
        if name == "workflow re-pinned" {
            mount_central_file(&server, OTHER, Some(b"tampered")).await;
        }
        if matches!(
            name,
            "workflow re-pinned" | "missing" | "workflow rule removed"
        ) {
            mount_get(
                &server,
                "/repos/acme/.vgi/commits/main",
                json!({ "sha": PIN }),
            )
            .await;
        }
        let (verb, p, outcome) = if org.is_some() {
            ("PUT", "/orgs/acme/rulesets/31", StepOutcome::Updated)
        } else {
            ("POST", "/orgs/acme/rulesets", StepOutcome::Created)
        };
        Mock::given(method(verb))
            .and(path(p))
            .and(body_json(org_ruleset_body(PIN, &[GADGETS_ID])))
            .respond_with(ResponseTemplate::new(200).set_body_json(fixed))
            .expect(1)
            .named(name)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path_regex("^/repos/acme/.vgi/contents/"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        assert_eq!(
            run(&forge, "required-workflow").await.unwrap(),
            outcome,
            "{name}"
        );
        server.verify().await;
    }
}

#[tokio::test]
async fn vgi_itself_is_inspected() {
    let mut private = central_repo_json();
    private["private"] = json!(true);
    private["visibility"] = json!("private");
    let mut weak = plain_ruleset(5);
    weak["rules"] = json!([{ "type": "deletion" }]);
    let cases: Vec<(&str, Value, Option<Value>, bool, &str)> = vec![
        (
            "not public",
            private,
            Some(plain_ruleset(5)),
            true,
            "no longer public",
        ),
        (
            "unprotected",
            central_repo_json(),
            None,
            true,
            "ruleset (pull requests only",
        ),
        (
            "protection weakened",
            central_repo_json(),
            Some(weak),
            true,
            "missing or weakened",
        ),
        (
            "pinned commit gone",
            central_repo_json(),
            Some(plain_ruleset(5)),
            false,
            "no longer in `.vgi`",
        ),
    ];
    for (name, central, rs, reachable, expect) in cases {
        let server = MockServer::start().await;
        let forge = org_forge(&server, &[GADGETS_ID]);
        pinned(&forge);
        mount_org_inspect_with(
            &server,
            Some(org_ruleset(PIN, &[GADGETS_ID])),
            central,
            rs,
            reachable,
        )
        .await;
        let state = forge.inspect(&repo("gadgets")).await.unwrap();
        let drift = forge.diff(&state, &projection());
        let gaps = source_gaps(&drift);
        assert!(gaps.iter().any(|g| g.contains(expect)), "{name}: {gaps:?}");
        assert!(drift.iter().any(Drift::is_critical), "{name}");
    }

    // `.vgi` gone altogether (the scoped token is refused).
    let server = MockServer::start().await;
    let forge = org_forge(&server, &[GADGETS_ID]);
    pinned(&forge);
    mount_token(&server, INSTALLATION, Some("gadgets"), admin(), 1).await;
    mount_get(
        &server,
        "/repos/acme/gadgets",
        repo_json(GADGETS_ID, "acme/gadgets", false),
    )
    .await;
    mount_get(&server, "/repos/acme/gadgets/collaborators", json!([])).await;
    mount_get(&server, "/repos/acme/gadgets/invitations", json!([])).await;
    mount_get(&server, "/repos/acme/gadgets/rulesets", json!([])).await;
    mount_actions_allowed(&server, "acme/gadgets").await;
    mount_org_ruleset(&server, Some(org_ruleset(PIN, &[GADGETS_ID])), None).await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/app/installations/{INSTALLATION}/access_tokens"
        )))
        .and(body_json(json!({
            "permissions": { "administration": "write", "contents": "read", "metadata": "read" },
            "repositories": [".vgi"],
        })))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({ "message": "nope" })))
        .mount(&server)
        .await;
    let state = forge.inspect(&repo("gadgets")).await.unwrap();
    let gaps = source_gaps(&forge.diff(&state, &projection()));
    assert!(
        gaps.iter().any(|g| g.contains("missing or not visible")),
        "{gaps:?}"
    );
}

#[tokio::test]
async fn actions_being_off_or_restricted_is_critical_drift() {
    let cases: Vec<(&str, Value, Option<Value>, Option<&str>)> = vec![
        (
            "disabled",
            json!({ "enabled": false }),
            None,
            Some("Actions is disabled"),
        ),
        (
            "local only",
            json!({ "enabled": true, "allowed_actions": "local_only" }),
            None,
            Some("only use actions from"),
        ),
        (
            "selected without verify-trust",
            json!({ "enabled": true, "allowed_actions": "selected" }),
            Some(json!({ "github_owned_allowed": true, "patterns_allowed": ["acme/*"] })),
            Some("does not allow `OpenVTC/verifiable-git-infrastructure"),
        ),
        (
            "selected without GitHub-owned",
            json!({ "enabled": true, "allowed_actions": "selected" }),
            Some(json!({ "github_owned_allowed": false, "patterns_allowed": ["OpenVTC/*"] })),
            Some("does not allow actions/checkout"),
        ),
        (
            "selected, both allowed",
            json!({ "enabled": true, "allowed_actions": "selected" }),
            Some(
                json!({ "github_owned_allowed": true, "patterns_allowed": ["OpenVTC/verifiable-git-infrastructure/*"] }),
            ),
            None,
        ),
    ];
    for (name, perms, selected, expect) in cases {
        let server = MockServer::start().await;
        let forge = org_forge(&server, &[GADGETS_ID]);
        pinned(&forge);
        let _ = org_plan(&forge); // records the verify-trust action
        Mock::given(method("GET"))
            .and(path("/repos/acme/gadgets/actions/permissions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(perms))
            .with_priority(1)
            .mount(&server)
            .await;
        if let Some(sel) = selected {
            mount_get(
                &server,
                "/repos/acme/gadgets/actions/permissions/selected-actions",
                sel,
            )
            .await;
        }
        // Priority 1 above; the helper's "all allowed" mock is shadowed.
        mount_org_inspect(&server, Some(org_ruleset(PIN, &[GADGETS_ID]))).await;
        let state = forge.inspect(&repo("gadgets")).await.unwrap();
        let drift = forge.diff(&state, &projection());
        let gaps = source_gaps(&drift);
        match expect {
            Some(e) => {
                assert!(gaps.iter().any(|g| g.contains(e)), "{name}: {gaps:?}");
                assert!(drift.iter().any(Drift::is_critical), "{name}");
            }
            None => assert_eq!(drift, vec![], "{name}"),
        }
    }
}

#[tokio::test]
async fn an_unknown_pin_fails_closed() {
    let server = MockServer::start().await;
    let forge = org_forge(&server, &[GADGETS_ID]);
    mount_org_inspect_with(
        &server,
        Some(org_ruleset(PIN, &[GADGETS_ID])),
        central_repo_json(),
        Some(plain_ruleset(5)),
        false,
    )
    .await;
    let state = forge.inspect(&repo("gadgets")).await.unwrap();
    let gaps = source_gaps(&forge.diff(&state, &projection()));
    assert!(gaps.iter().any(|g| g.contains("no record")), "{gaps:?}");
}

#[tokio::test]
async fn a_private_vgi_is_refused() {
    let server = MockServer::start().await;
    let forge = org_forge(&server, &[]);
    mount_token(
        &server,
        INSTALLATION,
        Some("gadgets"),
        json!({ "metadata": "read" }),
        1,
    )
    .await;
    mount_get(
        &server,
        "/repos/acme/gadgets",
        repo_json(GADGETS_ID, "acme/gadgets", false),
    )
    .await;
    mount_token(
        &server,
        INSTALLATION,
        Some(".vgi"),
        json!({ "contents": "write", "metadata": "read" }),
        1,
    )
    .await;
    let mut private = central_repo_json();
    private["private"] = json!(true);
    private["visibility"] = json!("private");
    mount_get(&server, "/repos/acme/.vgi", private).await;
    forbid_writes(&server).await;
    let e = run(&forge, "required-workflow").await.unwrap_err();
    assert!(e.to_string().contains("not public"), "{e}");
}

#[tokio::test]
async fn moving_to_org_mode_cleans_up_the_old_guard() {
    let server = MockServer::start().await;
    let forge = org_forge(&server, &[GADGETS_ID]);
    let plan = org_plan(&forge);

    // The repo ruleset loses its status-check rule and review requirement…
    mount_token(&server, INSTALLATION, Some("gadgets"), admin(), 1).await;
    mount_get(
        &server,
        "/repos/acme/gadgets",
        repo_json(GADGETS_ID, "acme/gadgets", false),
    )
    .await;
    mount_get(
        &server,
        "/repos/acme/gadgets/rulesets",
        json!([{ "id": 9, "name": "VGI commit trust" }]),
    )
    .await;
    mount_get(&server, "/repos/acme/gadgets/rulesets/9", review_ruleset(9)).await;
    Mock::given(method("PUT"))
        .and(path("/repos/acme/gadgets/rulesets/9"))
        .and(body_json(plain_ruleset_body()))
        .respond_with(ResponseTemplate::new(200).set_body_json(plain_ruleset(9)))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        forge
            .run_step(&repo("gadgets"), &step(&plan, "ruleset"))
            .await
            .unwrap(),
        StepOutcome::Updated
    );

    // …and the in-repo workflow and variables are removed.
    mount_token(
        &server,
        INSTALLATION,
        Some("gadgets"),
        json!({ "contents": "write", "metadata": "read" }),
        1,
    )
    .await;
    mount_get(
        &server,
        "/repos/acme/gadgets/contents/.github/workflows/verify-trust.yml",
        file_reply(b"old workflow", "wfblob"),
    )
    .await;
    Mock::given(method("DELETE"))
        .and(path(
            "/repos/acme/gadgets/contents/.github/workflows/verify-trust.yml",
        ))
        .and(body_json(json!({
            "message": "ci: the VGI check now runs as the org's required workflow",
            "sha": "wfblob",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        forge
            .run_step(&repo("gadgets"), &step(&plan, "cleanup:workflow"))
            .await
            .unwrap(),
        StepOutcome::Updated
    );
    mount_token(
        &server,
        INSTALLATION,
        Some("gadgets"),
        json!({ "actions_variables": "write", "metadata": "read" }),
        1,
    )
    .await;
    mount_get(
        &server,
        "/repos/acme/gadgets/actions/variables/VTC_DID",
        json!({ "name": "VTC_DID", "value": "did:x" }),
    )
    .await;
    Mock::given(method("DELETE"))
        .and(path("/repos/acme/gadgets/actions/variables/VTC_DID"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        forge
            .run_step(&repo("gadgets"), &step(&plan, "cleanup:variable:VTC_DID"))
            .await
            .unwrap(),
        StepOutcome::Updated
    );
}

// ── availability ─────────────────────────────────────────────────────────

#[tokio::test]
async fn availability_is_probed_and_falls_back() {
    let org = Namespace::new(acme(), NamespaceKind::Organization).with_installation(INSTALLATION);
    let org_token = json!({ "organization_administration": "write" });

    // Available: the org lists rulesets.
    let server = MockServer::start().await;
    let forge = forge_for(&server);
    assert!(
        !forge.capabilities(&org).required_workflow,
        "unknown ⇒ fallback"
    );
    mount_token(&server, INSTALLATION, None, org_token.clone(), 1).await;
    mount_get(&server, "/orgs/acme/rulesets", json!([])).await;
    assert!(forge.detect_required_workflow(&acme()).await.unwrap());
    assert!(forge.capabilities(&org).required_workflow);

    // A Free organisation: GitHub refuses the org rulesets API.
    let server = MockServer::start().await;
    let forge = forge_for(&server);
    forge.set_required_workflow(&acme(), true);
    mount_token(&server, INSTALLATION, None, org_token.clone(), 1).await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/rulesets"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "message": "Upgrade to GitHub Team to enable this feature."
        })))
        .mount(&server)
        .await;
    assert!(!forge.detect_required_workflow(&acme()).await.unwrap());
    let caps = forge.capabilities(&org);
    assert!(!caps.required_workflow && caps.single_owner_repos_unreviewed);
    let plan = forge
        .bootstrap_plan(
            &RepoSpec::new(repo("gadgets"))
                .with_owner(bob())
                .with_owner(carol()),
            &vgi_config(),
        )
        .unwrap();
    assert!(plan.iter().any(|s| s.id == "codeowners"));
    assert!(!plan.iter().any(|s| s.id == "required-workflow"));

    // The owner declined organization Administration: the token is refused.
    let server = MockServer::start().await;
    let forge = forge_for(&server);
    Mock::given(method("POST"))
        .and(path(format!(
            "/app/installations/{INSTALLATION}/access_tokens"
        )))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "message": "The permissions requested are not granted to this installation."
        })))
        .mount(&server)
        .await;
    assert!(!forge.detect_required_workflow(&acme()).await.unwrap());

    // A personal account never has one, and is not asked.
    let server = MockServer::start().await;
    let forge = forge_for(&server);
    forbid_writes(&server).await;
    assert!(
        !forge
            .detect_required_workflow(&Resource::parse("github.com/alice").unwrap())
            .await
            .unwrap()
    );
    server.verify().await;

    // A transient failure is an error, not a guess.
    let server = MockServer::start().await;
    let forge = forge_for(&server);
    mount_token(&server, INSTALLATION, None, org_token, 1).await;
    Mock::given(method("GET"))
        .and(path("/orgs/acme/rulesets"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    assert!(matches!(
        forge.detect_required_workflow(&acme()).await,
        Err(ForgeError::Unavailable(_))
    ));
}

/// The `required-workflow` step up to the org ruleset write, which GitHub
/// answers with `status` and `reply`.
async fn refused_org_ruleset(status: u16, reply: Value) -> (GitHubForge, ForgeError) {
    let server = MockServer::start().await;
    let forge = org_forge(&server, &[]);
    let workflow = central_workflow(&forge);
    mount_step_reads(&server, None, None).await;
    mount_get(
        &server,
        "/repos/acme/.vgi/commits/main",
        json!({ "sha": PIN }),
    )
    .await;
    mount_central_file(&server, PIN, Some(&workflow)).await;
    Mock::given(method("POST"))
        .and(path("/orgs/acme/rulesets"))
        .respond_with(ResponseTemplate::new(status).set_body_json(reply))
        .expect(1)
        .mount(&server)
        .await;
    let e = run(&forge, "required-workflow").await.unwrap_err();
    (forge, e)
}

#[tokio::test]
async fn only_a_plan_refusal_flips_the_namespace_to_the_fallback() {
    let org = Namespace::new(acme(), NamespaceKind::Organization).with_installation(INSTALLATION);

    // GitHub documents the workflows rule for Enterprise Cloud: a Team org
    // lists rulesets but is refused this rule.
    let (forge, e) = refused_org_ruleset(
        403,
        json!({
            "message": "Upgrade to GitHub Enterprise to enable this feature.",
            "documentation_url": "https://docs.github.com/get-started/learning-about-github/githubs-plans"
        }),
    )
    .await;
    assert!(
        matches!(
            &e,
            ForgeError::CapabilityChanged { capability, available: false, namespace, .. }
                if capability == "requiredWorkflow" && namespace == "github.com/acme"
        ),
        "{e:?}"
    );
    assert!(!forge.capabilities(&org).required_workflow);
    let plan = forge
        .bootstrap_plan(
            &RepoSpec::new(repo("gadgets"))
                .with_owner(bob())
                .with_owner(carol()),
            &vgi_config(),
        )
        .unwrap();
    assert!(plan.iter().any(|s| s.id == "codeowners"));

    // Any other 422 is an error, and changes nothing.
    let (forge, e) = refused_org_ruleset(
        422,
        json!({
            "message": "Validation Failed",
            "errors": ["Invalid property /rules/0: data matches no possible input"],
            "documentation_url": "https://docs.github.com/rest/orgs/rules#create-an-organization-repository-ruleset"
        }),
    )
    .await;
    assert!(
        matches!(e, ForgeError::Rejected { status: 422, .. }),
        "{e:?}"
    );
    assert!(forge.capabilities(&org).required_workflow);
}

// ── outside a required workflow ──────────────────────────────────────────

fn alice_repo() -> Resource {
    Resource::parse("github.com/alice/tools").unwrap()
}

#[tokio::test]
async fn a_solo_personal_repository_gets_the_check_without_review() {
    let server = MockServer::start().await;
    let forge = forge_for(&server);
    let user = Namespace::new(
        Resource::parse("github.com/alice").unwrap(),
        NamespaceKind::User,
    )
    .with_installation(USER_INSTALLATION);
    let caps = forge.capabilities(&user);
    assert!(!caps.required_workflow);
    assert!(
        caps.single_owner_repos_unreviewed,
        "the UI shows: solo, workflow edits not review-protected"
    );

    // No owners in the spec: the account holder alone — a solo repository.
    let plan = forge
        .bootstrap_plan(&RepoSpec::new(alice_repo()), &vgi_config())
        .unwrap();
    assert!(!plan.iter().any(|s| s.id == "codeowners"));
    let StepAction::ProtectDefaultBranch(spec) = &step(&plan, "ruleset").action else {
        panic!()
    };
    assert!(spec.require_status_check && !spec.require_code_owner_review);

    // …and a second owner makes it an owner-review repository.
    let plan = forge
        .bootstrap_plan(
            &RepoSpec::new(alice_repo()).with_owner(carol()),
            &vgi_config(),
        )
        .unwrap();
    let StepAction::RequireOwnerReview { owners, .. } = &step(&plan, "codeowners").action else {
        panic!()
    };
    assert_eq!(owners.iter().map(|o| o.id).collect::<Vec<_>>(), [1, 9]);
}

#[tokio::test]
async fn two_owners_get_codeowners_and_the_full_review_rule() {
    let server = MockServer::start().await;
    let forge = forge_for(&server);
    let plan = forge
        .bootstrap_plan(
            &RepoSpec::new(alice_repo()).with_owner(carol()),
            &vgi_config(),
        )
        .unwrap();

    // Logins are looked up from the ids now — alice renamed since binding.
    mount_token(
        &server,
        USER_INSTALLATION,
        Some("tools"),
        json!({ "metadata": "read" }),
        1,
    )
    .await;
    mount_get(
        &server,
        "/user/1",
        json!({ "id": 1, "login": "alice-renamed" }),
    )
    .await;
    mount_get(&server, "/user/9", json!({ "id": 9, "login": "carol" })).await;
    mount_token(
        &server,
        USER_INSTALLATION,
        Some("tools"),
        json!({ "contents": "write", "metadata": "read" }),
        1,
    )
    .await;
    let expected = render_codeowners(
        "",
        &["/.github/".into()],
        &["alice-renamed".into(), "carol".into()],
    );
    assert!(expected.contains("\n/.github/ @alice-renamed @carol\n"));
    Mock::given(method("PUT"))
        .and(path("/repos/alice/tools/contents/.github/CODEOWNERS"))
        .and(body_json(json!({
            "message": "ci: require an owner's review for workflow changes",
            "content": STANDARD.encode(&expected),
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        forge
            .run_step(&alice_repo(), &step(&plan, "codeowners"))
            .await
            .unwrap(),
        StepOutcome::Created
    );

    mount_token(&server, USER_INSTALLATION, Some("tools"), admin(), 1).await;
    mount_get(
        &server,
        "/repos/alice/tools",
        repo_json(4, "alice/tools", false),
    )
    .await;
    mount_get(&server, "/repos/alice/tools/rulesets", json!([])).await;
    let mut body = review_ruleset(0);
    for k in ["id", "current_user_can_bypass"] {
        body.as_object_mut().unwrap().remove(k);
    }
    Mock::given(method("POST"))
        .and(path("/repos/alice/tools/rulesets"))
        .and(body_json(body))
        .respond_with(ResponseTemplate::new(201).set_body_json(review_ruleset(9)))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        forge
            .run_step(&alice_repo(), &step(&plan, "ruleset"))
            .await
            .unwrap(),
        StepOutcome::Created
    );
}

#[tokio::test]
async fn an_existing_root_codeowners_is_kept_and_extended_where_it_is() {
    // Adopted repository with `CODEOWNERS` at the root: GitHub reads it
    // only because `.github/CODEOWNERS` does not exist — writing one there
    // would shadow it. The managed rules go into the root file, after its
    // own, and also guard the file itself.
    let server = MockServer::start().await;
    let forge = forge_for(&server);
    let plan = forge
        .bootstrap_plan(
            &RepoSpec::new(repo("gadgets"))
                .with_owner(bob())
                .with_owner(carol()),
            &vgi_config(),
        )
        .unwrap();
    mount_token(
        &server,
        INSTALLATION,
        Some("gadgets"),
        json!({ "metadata": "read" }),
        1,
    )
    .await;
    mount_get(&server, "/user/7", json!({ "id": 7, "login": "bob" })).await;
    mount_get(&server, "/user/9", json!({ "id": 9, "login": "carol" })).await;
    mount_token(
        &server,
        INSTALLATION,
        Some("gadgets"),
        json!({ "contents": "write", "metadata": "read" }),
        1,
    )
    .await;
    let theirs = "# ours\n*.rs @acme/rustaceans\n";
    mount_get(
        &server,
        "/repos/acme/gadgets/contents/CODEOWNERS",
        file_reply(theirs.as_bytes(), "rootblob"),
    )
    .await;
    let expected = render_codeowners(
        theirs,
        &["/.github/".into(), "/CODEOWNERS".into()],
        &["bob".into(), "carol".into()],
    );
    assert!(expected.starts_with(theirs));
    Mock::given(method("PUT"))
        .and(path("/repos/acme/gadgets/contents/CODEOWNERS"))
        .and(body_json(json!({
            "message": "ci: require an owner's review for workflow changes",
            "content": STANDARD.encode(&expected),
            "sha": "rootblob",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/repos/acme/gadgets/contents/.github/CODEOWNERS"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    assert_eq!(
        forge
            .run_step(&repo("gadgets"), &step(&plan, "codeowners"))
            .await
            .unwrap(),
        StepOutcome::Updated
    );
}

/// Owner-review inspect of `acme/gadgets`: repo ruleset `rs`, CODEOWNERS
/// `codeowners` at `.github/` (`None`: absent), GitHub's CODEOWNERS
/// `errors`.
async fn mount_owner_review_inspect(
    server: &MockServer,
    rs: Value,
    codeowners: Option<String>,
    errors: Value,
) {
    mount_token(server, INSTALLATION, Some("gadgets"), admin(), 1).await;
    mount_get(
        server,
        "/repos/acme/gadgets",
        repo_json(GADGETS_ID, "acme/gadgets", false),
    )
    .await;
    mount_get(server, "/repos/acme/gadgets/collaborators", json!([])).await;
    mount_get(server, "/repos/acme/gadgets/invitations", json!([])).await;
    mount_get(
        server,
        "/repos/acme/gadgets/rulesets",
        json!([{ "id": 9, "name": "VGI commit trust" }]),
    )
    .await;
    mount_get(server, "/repos/acme/gadgets/rulesets/9", rs).await;
    mount_actions_allowed(server, "acme/gadgets").await;
    mount_token(
        server,
        INSTALLATION,
        Some("gadgets"),
        json!({ "contents": "read", "metadata": "read" }),
        1,
    )
    .await;
    if let Some(c) = codeowners {
        Mock::given(method("GET"))
            .and(path("/repos/acme/gadgets/contents/.github/CODEOWNERS"))
            .and(query_param("ref", "main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(file_reply(c.as_bytes(), "co")))
            .mount(server)
            .await;
    }
    mount_get(server, "/users/bob", json!({ "id": 7, "login": "bob" })).await;
    mount_get(server, "/users/carol", json!({ "id": 9, "login": "carol" })).await;
    mount_get(
        server,
        "/users/mallory",
        json!({ "id": 66, "login": "mallory" }),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/gadgets/codeowners/errors"))
        .and(query_param("ref", "main"))
        .respond_with(ResponseTemplate::new(200).set_body_json(errors))
        .mount(server)
        .await;
}

fn owners_projection(owners: &[ForgeAccount]) -> Projection {
    let mut p = projection();
    p.owners = owners.to_vec();
    p
}

#[tokio::test]
async fn owner_review_drift_follows_the_owner_count() {
    let good = managed_codeowners("* @acme/devs\n", &["bob", "carol"]);
    let managed_line = good
        .lines()
        .position(|l| l.starts_with("/.github/"))
        .unwrap()
        + 1;
    let no_errors = json!({ "errors": [] });
    let with_rule = |f: &dyn Fn(&mut Value)| {
        let mut rs = review_ruleset(9);
        f(&mut rs);
        rs
    };
    let two = [bob(), carol()];
    type Case<'a> = (
        &'a str,
        Value,
        Option<String>,
        Value,
        Vec<ForgeAccount>,
        Option<&'a str>,
    );
    let cases: Vec<Case> = vec![
        (
            "healthy",
            review_ruleset(9),
            Some(good.clone()),
            no_errors.clone(),
            two.to_vec(),
            None,
        ),
        (
            "codeowners removed",
            review_ruleset(9),
            None,
            no_errors.clone(),
            two.to_vec(),
            Some("no CODEOWNERS"),
        ),
        (
            "rule appended after the managed block",
            review_ruleset(9),
            Some(format!("{good}/.github/workflows/ @mallory\n")),
            no_errors.clone(),
            two.to_vec(),
            Some("no longer ends with"),
        ),
        (
            "managed rule emptied",
            review_ruleset(9),
            Some(good.replace("/.github/ @bob @carol", "/.github/")),
            no_errors.clone(),
            two.to_vec(),
            Some("no longer give `/.github/` an owner"),
        ),
        (
            "code-owner review off",
            with_rule(&|rs| {
                rs["rules"][2]["parameters"]["require_code_owner_review"] = json!(false)
            }),
            Some(good.clone()),
            no_errors.clone(),
            two.to_vec(),
            Some("code owner"),
        ),
        (
            "stale reviews kept",
            with_rule(&|rs| {
                rs["rules"][2]["parameters"]["dismiss_stale_reviews_on_push"] = json!(false)
            }),
            Some(good.clone()),
            no_errors.clone(),
            two.to_vec(),
            Some("dismissed by later pushes"),
        ),
        (
            "last pusher may approve",
            with_rule(&|rs| {
                rs["rules"][2]["parameters"]["require_last_push_approval"] = json!(false)
            }),
            Some(good.clone()),
            no_errors.clone(),
            two.to_vec(),
            Some("not given by the last pusher"),
        ),
        (
            "reviewer swapped",
            review_ruleset(9),
            Some(good.replace("@carol", "@mallory")),
            no_errors.clone(),
            two.to_vec(),
            Some("names accounts"),
        ),
        (
            "GitHub rejects the managed line",
            review_ruleset(9),
            Some(good.clone()),
            json!({ "errors": [{
                "line": managed_line, "column": 11, "kind": "Unknown owner",
                "message": "Unknown owner on line 5: make sure @carol exists and has write access",
                "path": ".github/CODEOWNERS"
            }] }),
            two.to_vec(),
            Some("Unknown owner"),
        ),
    ];
    for (name, rs, codeowners, errors, owners, expect) in cases {
        let server = MockServer::start().await;
        let forge = forge_for(&server);
        mount_owner_review_inspect(&server, rs, codeowners, errors).await;
        let state = forge.inspect(&repo("gadgets")).await.unwrap();
        assert!(
            matches!(
                state.protection.check_source_guard,
                CheckSourceGuard::OwnerReview { .. }
            ),
            "{name}: {:?}",
            state.protection.check_source_guard
        );
        let drift = forge.diff(&state, &owners_projection(&owners));
        let gaps = source_gaps(&drift);
        match expect {
            None => assert_eq!(drift, vec![], "{name}"),
            Some(e) => {
                assert!(gaps.iter().any(|g| g.contains(e)), "{name}: {gaps:?}");
                assert!(drift.iter().any(Drift::is_critical), "{name}");
            }
        }
    }

    // Solo, and unreviewed: accepted.
    let server = MockServer::start().await;
    let forge = forge_for(&server);
    mount_owner_review_inspect(&server, good_ruleset(9), None, no_errors.clone()).await;
    let state = forge.inspect(&repo("gadgets")).await.unwrap();
    assert_eq!(
        state.protection.check_source_guard,
        CheckSourceGuard::Unreviewed
    );
    assert_eq!(forge.diff(&state, &owners_projection(&[bob()])), vec![]);
    // A second owner arrives: now it is a weakening, and a re-plan.
    let drift = forge.diff(&state, &owners_projection(&two));
    assert!(drift.iter().any(Drift::is_critical), "{drift:?}");
    assert!(
        drift
            .iter()
            .any(|d| matches!(d, Drift::ReplanNeeded { .. })),
        "{drift:?}"
    );

    // Down to one owner with review still on: a re-plan, not a weakening.
    let server = MockServer::start().await;
    let forge = forge_for(&server);
    mount_owner_review_inspect(&server, review_ruleset(9), Some(good), no_errors).await;
    let state = forge.inspect(&repo("gadgets")).await.unwrap();
    let drift = forge.diff(&state, &owners_projection(&[bob()]));
    assert!(
        matches!(drift.as_slice(), [Drift::ReplanNeeded { .. }]),
        "{drift:?}"
    );
    assert!(!drift.iter().any(Drift::is_critical));
}

#[tokio::test]
async fn weakened_owner_review_is_reapplied() {
    let server = MockServer::start().await;
    let forge = forge_for(&server);
    let plan = forge
        .bootstrap_plan(
            &RepoSpec::new(repo("gadgets"))
                .with_owner(bob())
                .with_owner(carol()),
            &vgi_config(),
        )
        .unwrap();
    let good = managed_codeowners("", &["bob", "carol"]);

    // A CODEOWNERS with a rule after the managed block is rewritten over its
    // blob; the stray rule is the community's now, kept ahead of the block.
    mount_token(
        &server,
        INSTALLATION,
        Some("gadgets"),
        json!({ "metadata": "read" }),
        1,
    )
    .await;
    mount_get(&server, "/user/7", json!({ "id": 7, "login": "bob" })).await;
    mount_get(&server, "/user/9", json!({ "id": 9, "login": "carol" })).await;
    mount_token(
        &server,
        INSTALLATION,
        Some("gadgets"),
        json!({ "contents": "write", "metadata": "read" }),
        1,
    )
    .await;
    let tampered = format!("{good}/.github/workflows/ @mallory\n");
    mount_get(
        &server,
        "/repos/acme/gadgets/contents/.github/CODEOWNERS",
        file_reply(tampered.as_bytes(), "oldblob"),
    )
    .await;
    let fixed = render_codeowners(
        "/.github/workflows/ @mallory\n",
        &["/.github/".into()],
        &["bob".into(), "carol".into()],
    );
    assert!(fixed.trim_end().ends_with("# END VGI managed owner rules"));
    Mock::given(method("PUT"))
        .and(path("/repos/acme/gadgets/contents/.github/CODEOWNERS"))
        .and(body_json(json!({
            "message": "ci: require an owner's review for workflow changes",
            "content": STANDARD.encode(&fixed),
            "sha": "oldblob",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        forge
            .run_step(&repo("gadgets"), &step(&plan, "codeowners"))
            .await
            .unwrap(),
        StepOutcome::Updated
    );

    // A ruleset with stale reviews kept is put back.
    let mut weak = review_ruleset(9);
    weak["rules"][2]["parameters"]["dismiss_stale_reviews_on_push"] = json!(false);
    mount_token(&server, INSTALLATION, Some("gadgets"), admin(), 1).await;
    mount_get(
        &server,
        "/repos/acme/gadgets",
        repo_json(GADGETS_ID, "acme/gadgets", false),
    )
    .await;
    mount_get(
        &server,
        "/repos/acme/gadgets/rulesets",
        json!([{ "id": 9, "name": "VGI commit trust" }]),
    )
    .await;
    mount_get(&server, "/repos/acme/gadgets/rulesets/9", weak).await;
    let mut body = review_ruleset(0);
    for k in ["id", "current_user_can_bypass"] {
        body.as_object_mut().unwrap().remove(k);
    }
    Mock::given(method("PUT"))
        .and(path("/repos/acme/gadgets/rulesets/9"))
        .and(body_json(body))
        .respond_with(ResponseTemplate::new(200).set_body_json(review_ruleset(9)))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        forge
            .run_step(&repo("gadgets"), &step(&plan, "ruleset"))
            .await
            .unwrap(),
        StepOutcome::Updated
    );
}

#[test]
fn the_required_workflow_lives_at_the_standard_path() {
    // Required workflows must sit under `.github/workflows/` in the source
    // repository.
    assert!(WORKFLOW_PATH.starts_with(".github/workflows/"));
}
