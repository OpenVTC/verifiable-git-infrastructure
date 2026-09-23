//! Forge-facing flows: create, bind, link, webhooks, the bridge-posted
//! check, and what survives a restart.

mod common;

use std::collections::BTreeSet;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::*;
use serde_json::{Value, json};
use tower::ServiceExt;
use vgi_bridge::store::{
    JobRecord, JobState, NamespaceRecord, NamespaceState, PendingFlow, PinRecord, RepoRecord, Table,
};
use vgi_forge_github::Secret;
use vgi_forge_github::webhook::sign_body;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, ResponseTemplate};

async fn post_webhook(
    w: &World,
    event: &str,
    delivery: &str,
    body: &Value,
    secret: &str,
) -> StatusCode {
    let bytes = serde_json::to_vec(body).unwrap();
    let sig = sign_body(&Secret::new(secret), &bytes);
    let req = Request::post("/github/github.com/webhook")
        .header("x-github-event", event)
        .header("x-github-delivery", delivery)
        .header("x-hub-signature-256", sig)
        .body(Body::from(bytes))
        .unwrap();
    vgi_bridge::http::router(w.bridge.clone())
        .oneshot(req)
        .await
        .unwrap()
        .status()
}

async fn get(w: &World, uri: &str) -> (StatusCode, String) {
    let resp = vgi_bridge::http::router(w.bridge.clone())
        .oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

// ── webhooks ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn webhooks_are_verified_before_anything_is_reported() {
    let mut w = world(Options::default()).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    let renamed = json!({
        "action": "renamed",
        "repository": { "id": 812, "full_name": "acme/widgets-core" },
        "changes": { "repository": { "name": { "from": "widgets" } } },
    });

    // Wrong secret: refused, nothing reported.
    let s = post_webhook(&w, "repository", "d-1", &renamed, "not-the-secret").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    w.quiet().await;

    // Signed: the rename is reported by forge id, and the record follows.
    let s = post_webhook(&w, "repository", "d-2", &renamed, WEBHOOK_SECRET).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let ev = w.next_of(EVENT).await;
    assert_eq!(
        ev["payload"]["event"],
        json!({ "type": "repoRenamed", "forgeId": "812",
                "from": "github.com/acme/widgets", "to": "github.com/acme/widgets-core" })
    );
    let rec: RepoRecord = w
        .bridge
        .store()
        .get(Table::Repos, "github.com#812")
        .unwrap()
        .unwrap();
    assert_eq!(rec.resource.as_str(), "github.com/acme/widgets-core");

    // The same delivery again is dropped.
    let s = post_webhook(&w, "repository", "d-2", &renamed, WEBHOOK_SECRET).await;
    assert_eq!(s, StatusCode::OK);
    w.quiet().await;

    // The bridge's own `.vgi` is part of the binding, never "unmanaged".
    let created =
        json!({ "action": "created", "repository": { "id": 5, "full_name": "acme/.vgi" } });
    post_webhook(&w, "repository", "d-3", &created, WEBHOOK_SECRET).await;
    w.quiet().await;

    // A host the bridge does not serve.
    let resp = vgi_bridge::http::router(w.bridge.clone())
        .oneshot(
            Request::post("/github/evil.example/webhook")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_oversized_body_is_refused_before_it_is_read() {
    let w = world(Options {
        max_body: 64 * 1024,
        ..Options::default()
    })
    .await;
    let big = json!({ "pad": "x".repeat(100 * 1024) });
    let s = post_webhook(&w, "repository", "d-big", &big, WEBHOOK_SECRET).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
}

// ── create ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_repo_creates_bootstraps_projects_and_reports_each_step() {
    let mut w = world(Options::default()).await;
    let s = &w.server;
    mount_any_token(s).await;
    let repo_json = json!({
        "id": 9001, "full_name": "acme/gadgets", "private": false, "visibility": "public",
        "archived": false, "default_branch": "main",
    });
    // Not there before the create; there after.
    Mock::given(method("GET"))
        .and(path("/repos/acme/gadgets"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "message": "Not Found" })))
        .up_to_n_times(1)
        .mount(s)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/gadgets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(repo_json.clone()))
        .mount(s)
        .await;
    Mock::given(method("POST"))
        .and(path("/orgs/acme/repos"))
        .and(body_partial_json(
            json!({ "name": "gadgets", "visibility": "public", "auto_init": true }),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(repo_json))
        .expect(1)
        .mount(s)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/gadgets/rulesets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(s)
        .await;
    // The ruleset requires the check from this App (bridge-posted mode).
    Mock::given(method("POST"))
        .and(path("/repos/acme/gadgets/rulesets"))
        .and(body_partial_json(json!({ "rules": [
            { "type": "deletion" }, { "type": "non_fast_forward" }, { "type": "pull_request" },
            { "type": "required_status_checks", "parameters": { "required_status_checks": [
                { "context": "Verify commit trust", "integration_id": APP_ID } ] } } ] })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 3 })))
        .expect(1)
        .mount(s)
        .await;
    for p in ["collaborators", "invitations"] {
        Mock::given(method("GET"))
            .and(path(format!("/repos/acme/gadgets/{p}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(s)
            .await;
    }
    // Nothing is committed to the repository in this mode.
    Mock::given(method("PUT"))
        .and(path(
            "/repos/acme/gadgets/contents/.github/workflows/verify-trust.yml",
        ))
        .respond_with(ResponseTemplate::new(201))
        .expect(0)
        .mount(s)
        .await;

    w.send_job(json!({
        "jobId": "job_c", "namespace": NS, "kind": "createRepo", "repo": "github.com/acme/gadgets",
        "spec": { "visibility": "public", "description": "Small tools" }, "desiredRoles": [],
    }))
    .await;
    assert_eq!(w.next().await["payload"]["accepted"], true);
    let result = w.next_of(RESULT).await;
    let p = &result["payload"];
    assert_eq!(p["outcome"], "succeeded", "{p}");
    assert_eq!(
        p["repo"],
        json!({ "resource": "github.com/acme/gadgets", "forgeId": "9001" })
    );
    let steps: Vec<(String, String)> = p["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["step"].as_str().unwrap().to_string(),
                s["outcome"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(steps[0], ("create".into(), "applied".into()));
    assert!(
        steps.contains(&("requiredCheck".into(), "applied".into())),
        "{steps:?}"
    );
    assert!(
        steps.contains(&("variables".into(), "unchanged".into())),
        "{steps:?}"
    );
    assert_eq!(steps.last().unwrap(), &("roles".into(), "unchanged".into()));
    // The guard the repository ended up with, read back after the
    // bootstrap, and the namespace's standing, in the result's `ext`.
    let ext = &p["ext"]["org.openvtc.git-ns"];
    assert_eq!(ext["repo"], json!({ "guard": "bridgePostedCheck" }), "{p}");
    assert_eq!(ext["namespace"]["installationId"], "42");
    assert_eq!(ext["namespace"]["bridgePostedCheck"], true);

    // Managed from now on — in the store and in the adapter.
    let ns: NamespaceRecord = w
        .bridge
        .store()
        .get(Table::Namespaces, NS)
        .unwrap()
        .unwrap();
    assert!(ns.managed.contains(&9001));
    let rec: RepoRecord = w
        .bridge
        .store()
        .get(Table::Repos, "github.com#9001")
        .unwrap()
        .unwrap();
    assert_eq!(rec.required_check.as_deref(), Some("Verify commit trust"));
}

// ── bind and link ────────────────────────────────────────────────────────

fn state_of(url: &str) -> String {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned()
}

#[tokio::test]
async fn a_bind_completes_through_the_setup_callback_once() {
    let mut w = world(Options {
        web_base: Some("https://github.example".into()),
        ..Options::default()
    })
    .await;
    let s = &w.server;
    mount_any_token(s).await;
    Mock::given(method("GET"))
        .and(path("/app/installations/77"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 77,
            "account": { "id": 600, "login": "NewCo", "type": "Organization" },
            "permissions": {
                "administration": "write", "contents": "write", "actions_variables": "write",
                "checks": "write", "metadata": "read", "members": "read",
                "organization_administration": "write",
            },
            "suspended_at": null,
        })))
        .mount(s)
        .await;
    Mock::given(method("GET"))
        .and(path("/orgs/newco/rulesets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(s)
        .await;

    w.send_job(json!({
        "jobId": "job_b", "namespace": "ns_new", "kind": "beginBind",
        "target": { "forge": "github.com", "owner": "newco" },
    }))
    .await;
    let resp = w.next().await;
    assert_eq!(resp["payload"]["accepted"], true);
    let url = resp["payload"]["next"]["url"].as_str().unwrap().to_string();
    assert!(
        url.contains("/apps/acme-vgi-bridge/installations/new"),
        "{url}"
    );
    assert!(resp["payload"]["next"]["expiresAt"].is_string());
    // `next` URLs are https by schema; this one is the mock's, so only check
    // the state it carries.
    let state = state_of(&url);

    let (status, _) = get(
        &w,
        &format!("/github/github.com/setup?installation_id=77&setup_action=install&state={state}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let ev = w.next_of(EVENT).await;
    assert_eq!(
        ev["payload"]["event"],
        json!({ "type": "bindCompleted", "jobId": "job_b", "ownerId": "600", "kind": "organization" })
    );
    // What the bind found, for the VTC's console: the installation, what it
    // lacks (the check's events), org rulesets on the plan.
    let ns_report = ev["payload"]["ext"]["org.openvtc.git-ns"]["namespace"].clone();
    assert_eq!(ns_report["installationId"], "77", "{ev}");
    assert_eq!(ns_report["appName"], "acme-vgi-bridge");
    assert_eq!(ns_report["appSlug"], "acme-vgi-bridge");
    assert_eq!(ns_report["appRegistration"], "registered");
    assert_eq!(ns_report["orgRulesets"], true);
    assert_eq!(ns_report["requiredWorkflow"], true);
    assert_eq!(ns_report["bridgePostedCheck"], false);
    assert_eq!(ns_report["permissionUpgradePending"], true);
    let missing = ns_report["missingPermissions"].as_array().unwrap();
    assert!(
        missing.contains(&json!("event:pull_request")),
        "{missing:?}"
    );
    assert!(
        ev["payload"]["ext"]["org.openvtc.git-ns"]
            .get("repo")
            .is_none(),
        "no repository to report on"
    );
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["outcome"], "succeeded");
    assert_eq!(
        result["payload"]["ext"]["org.openvtc.git-ns"]["namespace"],
        ns_report
    );
    let ns: NamespaceRecord = w
        .bridge
        .store()
        .get(Table::Namespaces, "ns_new")
        .unwrap()
        .unwrap();
    assert_eq!(ns.state, NamespaceState::Bound);
    assert_eq!(
        ns.required_workflow,
        Some(true),
        "org rulesets probed at bind"
    );
    // The installation predates the check's events: recorded as not ready,
    // so its repositories keep the in-repo workflow.
    assert_eq!(ns.bridge_checks, Some(false));

    // The state is single use.
    let (status, _) = get(
        &w,
        &format!("/github/github.com/setup?installation_id=77&setup_action=install&state={state}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    w.quiet().await;
}

#[tokio::test]
async fn a_bind_nobody_completes_ends_expired() {
    let mut w = world(Options {
        web_base: Some("https://github.example".into()),
        ..Options::default()
    })
    .await;
    w.send_job(json!({
        "jobId": "job_e", "namespace": "ns_new", "kind": "beginBind",
        "target": { "forge": "github.com", "owner": "newco" },
    }))
    .await;
    let resp = w.next().await;
    let state = state_of(resp["payload"]["next"]["url"].as_str().unwrap());
    w.bridge
        .store()
        .update::<PendingFlow, _>(Table::Pending, &state, |f| {
            let f = match f.unwrap() {
                PendingFlow::Bind {
                    job_id,
                    namespace,
                    resource,
                    ..
                } => PendingFlow::Bind {
                    job_id,
                    namespace,
                    resource,
                    expires_at: 1,
                },
                other => other,
            };
            Ok((Some(f), ()))
        })
        .unwrap();
    vgi_bridge::flows::expire(&w.bridge).await;
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["outcome"], "failed");
    assert_eq!(result["payload"]["error"]["code"], "expired");
}

#[tokio::test]
async fn an_account_link_runs_the_device_flow_and_reports_the_account() {
    let mut w = world(Options::default()).await;
    let s = &w.server;
    Mock::given(method("POST"))
        .and(path("/login/device/code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "device_code": "dc-secret", "user_code": "WDJB-MJHT",
            "verification_uri": "https://github.com/login/device",
            "expires_in": 900, "interval": 1,
        })))
        .mount(s)
        .await;
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .and(body_partial_json(json!({ "device_code": "dc-secret" })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "access_token": "ghu_member" })),
        )
        .mount(s)
        .await;
    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "id": 9120045, "login": "bob-builds" })),
        )
        .mount(s)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/applications/Iv1.testclient/token"))
        .respond_with(ResponseTemplate::new(204))
        .mount(s)
        .await;

    w.send_job(json!({
        "jobId": "job_l", "namespace": NS, "kind": "beginAccountLink",
        "subject": "did:webvh:QmBob:acme-vtc.example:bob",
    }))
    .await;
    let resp = w.next().await;
    assert_eq!(resp["payload"]["accepted"], true);
    assert_eq!(
        resp["payload"]["next"]["url"],
        "https://github.com/login/device"
    );
    assert_eq!(resp["payload"]["next"]["userCode"], "WDJB-MJHT");
    assert!(
        !resp.to_string().contains("dc-secret"),
        "the device code never leaves the bridge"
    );

    let ev = w.next_of(EVENT).await;
    assert_eq!(
        ev["payload"]["event"],
        json!({ "type": "accountLinked", "jobId": "job_l",
                "account": { "forge": "github.com", "id": "9120045", "login": "bob-builds" } })
    );
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["outcome"], "succeeded");
    assert!(
        w.bridge
            .store()
            .secret_names()
            .unwrap()
            .iter()
            .all(|n| !n.starts_with("pending/")),
        "the sealed device code is gone once used"
    );
}

#[tokio::test]
async fn an_installation_that_accepts_the_new_permissions_turns_the_bridge_check_on() {
    let w = world(Options {
        seed_namespace: false,
        ..Options::default()
    })
    .await;
    common::seed_namespace_ready(
        w.bridge.store(),
        vgi_forge::NamespaceKind::Organization,
        false,
        Some(false),
    );
    let adapter = w.bridge.adapters().get("github.com").unwrap();
    let rec: NamespaceRecord = w
        .bridge
        .store()
        .get(Table::Namespaces, NS)
        .unwrap()
        .unwrap();
    adapter.restore(&rec).unwrap();
    let namespace = rec.binding.clone().unwrap().namespace;
    assert!(!adapter.forge().capabilities(&namespace).bridge_posted_check);

    // The owner approved the updated App: permissions and events are there.
    Mock::given(method("GET"))
        .and(path(format!("/app/installations/{INSTALLATION}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": INSTALLATION,
            "account": { "id": 500, "login": "acme", "type": "Organization" },
            "permissions": { "checks": "write", "pull_requests": "read",
                             "merge_queues": "read", "metadata": "read" },
            "events": ["pull_request", "merge_group", "repository"],
        })))
        .mount(&w.server)
        .await;
    let accepted = json!({
        "action": "new_permissions_accepted",
        "installation": { "id": INSTALLATION, "account": { "id": 500, "login": "acme" } },
    });
    assert_eq!(
        post_webhook(&w, "installation", "i-1", &accepted, WEBHOOK_SECRET).await,
        StatusCode::ACCEPTED
    );
    for _ in 0..200 {
        let rec: NamespaceRecord = w
            .bridge
            .store()
            .get(Table::Namespaces, NS)
            .unwrap()
            .unwrap();
        if rec.bridge_checks == Some(true) {
            assert!(adapter.forge().capabilities(&namespace).bridge_posted_check);
            // What the installation lacks was read again with it: the
            // check's events are no longer missing.
            let missing = rec.binding.unwrap().missing_permissions;
            assert!(!missing.is_empty(), "this installation lacks others");
            assert!(
                missing.iter().all(|m| !m.starts_with("event:")),
                "{missing:?}"
            );
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("the readiness was never re-probed");
}

/// A failed code exchange leaves the registration link usable, so the admin
/// can retry; the link is spent once the App is registered.
#[tokio::test]
async fn a_failed_app_registration_can_be_retried_from_the_same_link() {
    let w = world(Options {
        seed_app: false,
        ..Options::default()
    })
    .await;
    assert!(w.bridge.adapters().get("github.com").is_none());
    let urls = vgi_bridge::flows::offer_registrations(&w.bridge).unwrap();
    let state = state_of(&urls[0]);
    Mock::given(method("POST"))
        .and(path("/app-manifests/abc123/conversions"))
        .respond_with(ResponseTemplate::new(502))
        .up_to_n_times(1)
        .mount(&w.server)
        .await;
    let mut perms = serde_json::Map::new();
    for (k, v) in vgi_forge_github::manifest::APP_PERMISSIONS {
        perms.insert(k.into(), json!(v));
    }
    Mock::given(method("POST"))
        .and(path("/app-manifests/abc123/conversions"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": APP_ID, "slug": "acme-vgi-bridge", "client_id": "Iv1.testclient",
            "client_secret": "cs", "webhook_secret": WEBHOOK_SECRET, "pem": common::app_pem(),
            "owner": { "login": "acme" }, "permissions": perms,
            "events": vgi_forge_github::manifest::APP_EVENTS,
        })))
        .mount(&w.server)
        .await;
    let uri = format!("/github/github.com/registered?code=abc123&state={state}");
    let (status, _) = get(&w, &uri).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "GitHub failed the exchange"
    );
    assert!(w.bridge.adapters().get("github.com").is_none());
    let (status, page) = get(&w, &uri).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(
        w.bridge.adapters().get("github.com").is_some(),
        "in service"
    );
    let (status, _) = get(&w, &uri).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "the link is spent");
}

// ── restart ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_restart_restores_pins_managed_sets_and_unfinished_jobs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");
    let vtc_seed = [3u8; 32];
    {
        let w = world(Options {
            store_path: Some(path.clone()),
            required_workflow: true,
            vtc_seed: Some(vtc_seed),
            ..Options::default()
        })
        .await;
        w.bridge
            .store()
            .update::<NamespaceRecord, _>(Table::Namespaces, NS, |n| {
                let mut n = n.unwrap();
                n.managed = BTreeSet::from([812, 813]);
                n.pin = Some(PinRecord {
                    repository_id: 5,
                    sha: "a".repeat(40),
                    check: "Verify commit trust".into(),
                });
                Ok((Some(n), ()))
            })
            .unwrap();
        // A job the process died holding.
        let mut job = JobRecord::queued(
            "job_q",
            "x",
            NS,
            "archive",
            json!({ "jobId": "job_q", "namespace": NS, "kind": "archive", "repo": "github.com/acme/old" }),
            0,
        );
        job.state = JobState::Running;
        w.bridge.store().put(Table::Jobs, "job_q", &job).unwrap();
    }

    // The same store, a new process.
    let mut w = world(Options {
        store_path: Some(path),
        required_workflow: true,
        vtc_seed: Some(vtc_seed),
        seed_namespace: false,
        ..Options::default()
    })
    .await;
    let adapter = w.bridge.adapters().get("github.com").unwrap();
    let g = adapter.github().unwrap();
    assert_eq!(
        g.managed_repositories(&acme()),
        Some(BTreeSet::from([812, 813])),
        "the managed set is back before any org step runs"
    );
    let pin = g.required_workflow_pin(&acme()).expect("the pin is back");
    assert_eq!(pin.repository_id, 5);
    let ns: NamespaceRecord = w
        .bridge
        .store()
        .get(Table::Namespaces, NS)
        .unwrap()
        .unwrap();
    let caps = adapter.forge().capabilities(&ns.binding.unwrap().namespace);
    assert!(
        caps.required_workflow,
        "required-workflow availability is back"
    );

    // The interrupted job ran again and closed with one result (the repo
    // does not exist on the mock: a failed archive, still one result).
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["jobId"], "job_q");
    let rec: JobRecord = w.bridge.store().get(Table::Jobs, "job_q").unwrap().unwrap();
    assert_eq!(rec.state, JobState::Finished);
}
