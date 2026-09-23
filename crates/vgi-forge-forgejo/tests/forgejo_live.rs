//! The adapter against a real Forgejo, in Docker.
//!
//! `#[ignore]`d, and a no-op unless `VGI_FORGEJO_IT=1`, since it needs a
//! Docker daemon and pulls an image:
//!
//! ```sh
//! VGI_FORGEJO_IT=1 cargo test -p vgi-forge-forgejo --test forgejo_live -- --ignored
//! ```
//!
//! It starts `codeberg.org/forgejo/forgejo:<FORGEJO_MAJOR>` (override with
//! `VGI_FORGEJO_IMAGE`), creates an admin, the bot and two members with the
//! container's CLI, an org and the bridge's OAuth app through the API, and
//! then drives the whole lifecycle as a bridge would: bind (through the real
//! OAuth consent pages) → create → bootstrap (twice: the re-run writes
//! nothing) → account links → roles → inspect/diff → the protected-workflow
//! guarantee → archive → token rotation. It also checks every endpoint and
//! field the adapter uses against the instance's own swagger.
//!
//! No Actions runner is registered, so the verify-trust job never runs; the
//! test posts the check's status itself where a merge needs one. That any
//! writer can post such a status is a real limitation of Forgejo's required
//! checks (it cannot pin a context to Actions), and is documented.

use std::collections::BTreeMap;
use std::process::Command;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::{Method, StatusCode, header};
use serde_json::{Value, json};
use url::Url;
use vgi_forge::{
    BindCallback, BindRequest, BindStep, Drift, Forge, ForgeRole, LinkCallback, LinkStep,
    MergeMethod, Projection, RepoSpec, Resource, RoleAssignment, StepOutcome, Unlisted, VgiConfig,
    run_plan,
};
use vgi_forge_forgejo::{
    BOT_TOKEN_SCOPES, Credentials, ForgejoConfig, ForgejoForge, Secret, plan::PROTECTED_PATHS,
};

/// The Forgejo major the test pins (the current LTS line).
const FORGEJO_MAJOR: &str = "15";

const ROOT: (&str, &str) = ("root", "root-Passw0rd-1");
const BOT: (&str, &str) = ("acme-vgi-bot", "bot-Passw0rd-1");
const ALICE: (&str, &str) = ("alice", "alice-Passw0rd-1");
const BOB: (&str, &str) = ("bob", "bob-Passw0rd-1");
const CONTEXT: &str = "Verify commit trust / Verify commit trust (pull_request)";

fn enabled() -> bool {
    std::env::var("VGI_FORGEJO_IT").as_deref() == Ok("1")
}

// ── the container ────────────────────────────────────────────────────────

/// A running Forgejo container, removed on drop.
struct Forgejo {
    id: String,
    base: Url,
}

impl Drop for Forgejo {
    fn drop(&mut self) {
        if std::env::var("VGI_FORGEJO_KEEP").as_deref() != Ok("1") {
            let _ = Command::new("docker").args(["rm", "-f", &self.id]).output();
        }
    }
}

fn docker(args: &[&str]) -> String {
    let out = Command::new("docker")
        .args(args)
        .output()
        .expect("the docker CLI is installed");
    assert!(
        out.status.success(),
        "docker {args:?} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start() -> Forgejo {
    let image = std::env::var("VGI_FORGEJO_IMAGE")
        .unwrap_or_else(|_| format!("codeberg.org/forgejo/forgejo:{FORGEJO_MAJOR}"));
    let port = free_port();
    let root_url = format!("http://localhost:{port}/");
    let publish = format!("127.0.0.1:{port}:3000");
    let env = [
        "FORGEJO__security__INSTALL_LOCK=true".to_string(),
        "FORGEJO__database__DB_TYPE=sqlite3".into(),
        format!("FORGEJO__server__ROOT_URL={root_url}"),
        "FORGEJO__server__HTTP_PORT=3000".into(),
        "FORGEJO__server__OFFLINE_MODE=true".into(),
        "FORGEJO__service__DISABLE_REGISTRATION=true".into(),
        "FORGEJO__actions__ENABLED=true".into(),
        "FORGEJO__webhook__ALLOWED_HOST_LIST=*".into(),
        "FORGEJO__log__LEVEL=Warn".into(),
    ];
    let mut args = vec!["run", "-d", "-p", &publish];
    for e in &env {
        args.extend(["-e", e]);
    }
    args.push(&image);
    let id = docker(&args);
    let forgejo = Forgejo {
        id,
        base: Url::parse(&root_url).unwrap(),
    };

    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let up = client
            .get(forgejo.base.join("api/v1/version").unwrap())
            .send()
            .await
            .is_ok_and(|r| r.status().is_success());
        if up {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Forgejo did not come up: {}",
            docker(&["logs", "--tail", "50", &forgejo.id])
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    forgejo
}

impl Forgejo {
    fn create_user(&self, (name, password): (&str, &str), admin: bool) {
        let email = format!("{name}@example.com");
        let mut args = vec![
            "exec",
            "-u",
            "git",
            &self.id,
            "forgejo",
            "admin",
            "user",
            "create",
            "--username",
            name,
            "--password",
            password,
            "--email",
            &email,
            "--must-change-password=false",
        ];
        if admin {
            args.push("--admin");
        }
        docker(&args);
    }

    /// An API call as `who` with basic auth.
    async fn api(
        &self,
        who: (&str, &str),
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut req = reqwest::Client::new()
            .request(
                method,
                self.base.join("api/v1/").unwrap().join(path).unwrap(),
            )
            .basic_auth(who.0, Some(who.1));
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status();
        let text = resp.text().await.unwrap();
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }

    async fn ok(
        &self,
        who: (&str, &str),
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Value {
        let (status, v) = self.api(who, method.clone(), path, body).await;
        assert!(status.is_success(), "{method} {path}: {status} {v}");
        v
    }
}

// ── a scripted browser for the OAuth consent pages ───────────────────────

/// Just enough of a browser to sign in and click "Authorize": a cookie jar,
/// no redirects followed.
struct Browser {
    client: reqwest::Client,
    base: Url,
    cookies: BTreeMap<String, String>,
}

impl Browser {
    async fn sign_in(base: &Url, (user, password): (&str, &str)) -> Browser {
        let mut b = Browser {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            base: base.clone(),
            cookies: BTreeMap::new(),
        };
        let login = base.join("user/login").unwrap();
        let (_, html) = b.get(login.clone()).await;
        let mut form = hidden_inputs(&html);
        form.insert("user_name".into(), user.into());
        form.insert("password".into(), password.into());
        let (status, _, location) = b.post(login, &form).await;
        assert!(
            status.is_redirection() && !location.contains("/user/login"),
            "sign-in as {user} failed: {status} → {location}"
        );
        b
    }

    fn keep_cookies(&mut self, resp: &reqwest::Response) {
        for v in resp.headers().get_all(header::SET_COOKIE) {
            let pair = v.to_str().unwrap().split(';').next().unwrap();
            if let Some((k, v)) = pair.split_once('=') {
                self.cookies.insert(k.trim().into(), v.trim().into());
            }
        }
    }

    fn cookie_header(&self) -> String {
        self.cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    async fn get(&mut self, url: Url) -> (StatusCode, String) {
        let resp = self
            .client
            .get(url)
            .header(header::COOKIE, self.cookie_header())
            .send()
            .await
            .unwrap();
        self.keep_cookies(&resp);
        let status = resp.status();
        let location = location(&resp);
        let body = resp.text().await.unwrap();
        (
            status,
            if status.is_redirection() {
                location
            } else {
                body
            },
        )
    }

    async fn post(
        &mut self,
        url: Url,
        form: &BTreeMap<String, String>,
    ) -> (StatusCode, String, String) {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        let resp = self
            .client
            .post(url)
            .header(header::COOKIE, self.cookie_header())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .unwrap();
        self.keep_cookies(&resp);
        let status = resp.status();
        let location = location(&resp);
        (status, resp.text().await.unwrap(), location)
    }

    /// Follow an authorize URL as the signed-in user, granting access, and
    /// return the query of the redirect back to the bridge.
    async fn authorize(&mut self, url: &str) -> BTreeMap<String, String> {
        let (status, page) = self.get(Url::parse(url).unwrap()).await;
        let location = if status.is_redirection() {
            // Already granted: straight back with a code.
            page
        } else {
            assert_eq!(status, StatusCode::OK, "authorize page: {page}");
            let mut form = hidden_inputs(&page);
            form.insert("granted".into(), "true".into());
            let grant = self.base.join("login/oauth/grant").unwrap();
            let (status, body, location) = self.post(grant, &form).await;
            assert!(status.is_redirection(), "grant: {status} {body}");
            location
        };
        Url::parse(&location)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect()
    }
}

fn location(resp: &reqwest::Response) -> String {
    resp.headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// `<input type="hidden" name="…" value="…">` fields of a page.
fn hidden_inputs(html: &str) -> BTreeMap<String, String> {
    let attr = |tag: &str, name: &str| {
        let key = format!("{name}=\"");
        tag.find(&key).map(|i| {
            let rest = &tag[i + key.len()..];
            unescape(&rest[..rest.find('"').unwrap_or(rest.len())])
        })
    };
    html.split("<input")
        .skip(1)
        .filter_map(|chunk| {
            let tag = &chunk[..chunk.find('>').unwrap_or(chunk.len())];
            (attr(tag, "type").as_deref() == Some("hidden"))
                .then(|| Some((attr(tag, "name")?, attr(tag, "value").unwrap_or_default())))
                .flatten()
        })
        .collect()
}

fn unescape(s: &str) -> String {
    s.replace("&#34;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

// ── the test ─────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "needs Docker; run with VGI_FORGEJO_IT=1 and --ignored"]
async fn the_adapter_against_a_real_forgejo() {
    if !enabled() {
        eprintln!("skipped: set VGI_FORGEJO_IT=1 to run against a Forgejo container");
        return;
    }
    let fj = start().await;
    fj.create_user(ROOT, true);
    for u in [BOT, ALICE, BOB] {
        fj.create_user(u, false);
    }
    swagger_covers_the_adapter(&fj).await;

    // The org, and the bridge's OAuth app (as the instance admin would).
    fj.ok(
        ROOT,
        Method::POST,
        "orgs",
        Some(json!({ "username": "acme" })),
    )
    .await;
    let bind_redirect = "http://127.0.0.1:9/bind";
    let link_redirect = "http://127.0.0.1:9/link";
    let app = fj
        .ok(
            ROOT,
            Method::POST,
            "user/applications/oauth2",
            Some(json!({
                "name": "acme VGI bridge",
                "redirect_uris": [bind_redirect, link_redirect],
                "confidential_client": true,
            })),
        )
        .await;
    // The bot's first token, minted the way the operator would.
    let token = fj
        .ok(
            BOT,
            Method::POST,
            &format!("users/{}/tokens", BOT.0),
            Some(json!({ "name": "setup", "scopes": BOT_TOKEN_SCOPES })),
        )
        .await;

    let config = ForgejoConfig::new(
        fj.base.clone(),
        BOT.0,
        app["client_id"].as_str().unwrap(),
        Url::parse(bind_redirect).unwrap(),
        Url::parse(link_redirect).unwrap(),
    )
    .unwrap()
    .with_webhook_url(Url::parse("http://127.0.0.1:9/webhook").unwrap());
    let creds = Credentials::new(
        Secret::new(token["sha1"].as_str().unwrap()),
        Secret::new(app["client_secret"].as_str().unwrap()),
        Secret::new("live-webhook-secret"),
    )
    .with_bot_password(Secret::new(BOT.1));
    let forge = ForgejoForge::connect(config, creds).await.unwrap();
    let info = forge.instance();
    eprintln!("instance: {} ({:?})", info.version, info.flavor);
    assert!(info.features.fast_forward_only && info.features.actions_variables);

    // ── bind, as the org's owner, through the real consent page ──────────
    let ns = Resource::parse("localhost/acme").unwrap();
    let state = ForgejoForge::new_state().unwrap();
    let BindStep::Redirect { url } = forge
        .begin_bind(BindRequest::new(ns.clone(), state.clone()))
        .await
        .unwrap()
    else {
        panic!()
    };
    let mut root = Browser::sign_in(&fj.base, ROOT).await;
    let params = root.authorize(&url).await;
    assert_eq!(params.get("state"), Some(&state));
    let binding = forge
        .complete_bind(BindCallback::new(params, state.clone(), ns.clone()))
        .await
        .unwrap();
    assert!(
        binding.missing_permissions.is_empty(),
        "{:?}",
        binding.missing_permissions
    );
    forge.register_namespace(binding.namespace.clone()).unwrap();
    let teams = fj.ok(ROOT, Method::GET, "orgs/acme/teams", None).await;
    let team = teams
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "vgi-bridge")
        .expect("the bridge team");
    assert_eq!(team["permission"], "admin");
    assert_eq!(team["can_create_org_repo"], true);
    let hooks = fj.ok(ROOT, Method::GET, "orgs/acme/hooks", None).await;
    assert_eq!(hooks.as_array().unwrap().len(), 1);
    assert_eq!(hooks[0]["events"], json!(["repository"]));

    // A re-bind is idempotent: still one team, one hook.
    let state2 = ForgejoForge::new_state().unwrap();
    let BindStep::Redirect { url } = forge
        .begin_bind(BindRequest::new(ns.clone(), state2.clone()))
        .await
        .unwrap()
    else {
        panic!()
    };
    let params = root.authorize(&url).await;
    forge
        .complete_bind(BindCallback::new(params, state2, ns.clone()))
        .await
        .unwrap();
    let teams = fj.ok(ROOT, Method::GET, "orgs/acme/teams", None).await;
    assert_eq!(
        teams
            .as_array()
            .unwrap()
            .iter()
            .filter(|t| t["name"] == "vgi-bridge")
            .count(),
        1
    );
    assert_eq!(
        fj.ok(ROOT, Method::GET, "orgs/acme/hooks", None)
            .await
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // A member who does not own the org cannot bind it.
    let state3 = ForgejoForge::new_state().unwrap();
    let BindStep::Redirect { url } = forge
        .begin_bind(BindRequest::new(ns.clone(), state3.clone()))
        .await
        .unwrap()
    else {
        panic!()
    };
    let mut bob_browser = Browser::sign_in(&fj.base, BOB).await;
    let params = bob_browser.authorize(&url).await;
    let e = forge
        .complete_bind(BindCallback::new(params, state3, ns.clone()))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("not an owner"), "{e}");

    // ── create, bootstrap ────────────────────────────────────────────────
    let widgets = ns.join("widgets").unwrap();
    let created = forge
        .create_repo(&RepoSpec::new(widgets.clone()))
        .await
        .unwrap();
    assert_eq!(created.default_branch.as_deref(), Some("main"));
    assert!(matches!(
        forge.create_repo(&RepoSpec::new(widgets.clone())).await,
        Err(vgi_forge::ForgeError::AlreadyExists { forge_id: Some(id), .. }) if id == created.forge_id
    ));

    let vgi = VgiConfig::new(
        "did:webvh:registry.example",
        "did:webvh:vtc.example",
        "OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@0123456789abcdef0123456789abcdef01234567",
        "v0.4.12",
    )
    .with_verify_trust_sha256("4f1c0a5e9d0b8b1f3c5f8a0d2e7b6c9a1d3e5f7a9b0c2d4e6f8a1b3c5d7e9f0a");
    let plan = forge
        .bootstrap_plan(&RepoSpec::new(widgets.clone()), &vgi)
        .unwrap();
    let report = run_plan(&forge, &widgets, &plan).await;
    assert!(report.is_complete(), "{report:?}");
    let report = run_plan(&forge, &widgets, &plan).await;
    assert!(report.is_complete(), "{report:?}");
    assert!(
        report
            .completed
            .iter()
            .all(|(_, o)| *o == StepOutcome::Unchanged),
        "a re-run writes nothing: {report:?}"
    );

    let state = forge.inspect(&widgets).await.unwrap();
    let p = &state.protection;
    assert!(
        p.present && p.requires_pull_request && p.bypass_actors.is_empty(),
        "{p:?}"
    );
    assert_eq!(p.required_checks, [CONTEXT]);
    assert_eq!(
        p.merge_methods.as_deref(),
        Some(&[MergeMethod::FastForward][..])
    );
    assert_eq!(p.ci_enabled, Some(true));
    for path in PROTECTED_PATHS {
        assert!(
            p.protected_paths.iter().any(|x| x == path),
            "{path} in {p:?}"
        );
    }
    // The DIDs are in the (protected) workflow, not in variables: Forgejo
    // lets only an owner manage those, and the bot is an admin.
    let wf = fj
        .ok(
            ROOT,
            Method::GET,
            "repos/acme/widgets/contents/.forgejo/workflows/verify-trust.yml",
            None,
        )
        .await;
    let wf = String::from_utf8(
        STANDARD
            .decode(wf["content"].as_str().unwrap().replace('\n', ""))
            .unwrap(),
    )
    .unwrap();
    assert!(wf.contains("vtc-did: 'did:webvh:vtc.example'"), "{wf}");
    assert!(wf.contains("uses: https://github.com/OpenVTC/"), "{wf}");

    // ── members link their accounts; roles are projected ────────────────
    let link = |who: (&'static str, &'static str)| {
        let forge = &forge;
        let base = fj.base.clone();
        async move {
            let LinkStep::Redirect { url } =
                forge.begin_account_link("did:example:m").await.unwrap()
            else {
                panic!()
            };
            let mut b = Browser::sign_in(&base, who).await;
            let params = b.authorize(&url).await;
            forge
                .complete_account_link(LinkCallback::Redirect { params })
                .await
                .unwrap()
        }
    };
    let alice = link(ALICE).await;
    let bob = link(BOB).await;
    assert_eq!(alice.login, "alice");
    assert_ne!(alice.id, bob.id);

    let desired = vec![
        RoleAssignment::new(alice.clone(), ForgeRole::Admin),
        RoleAssignment::new(bob.clone(), ForgeRole::Maintain),
    ];
    let report = forge
        .apply_roles(&widgets, &desired, Unlisted::Keep)
        .await
        .unwrap();
    assert!(report.is_complete(), "{report:?}");
    assert_eq!(report.changes.len(), 2);
    let again = forge
        .apply_roles(&widgets, &desired, Unlisted::Keep)
        .await
        .unwrap();
    assert!(again.changes.is_empty(), "{again:?}");

    let state = forge.inspect(&widgets).await.unwrap();
    let mut projection = Projection::new(widgets.clone());
    projection.forge_id = Some(created.forge_id);
    projection.required_check = Some("Verify commit trust".into());
    projection.roles = desired.clone();
    let drift = forge.diff(&state, &projection);
    assert!(drift.is_empty(), "{drift:?}");

    // Weakening the rule in the UI (as the org owner) is drift.
    fj.ok(
        ROOT,
        Method::PATCH,
        "repos/acme/widgets/branch_protections/main",
        Some(json!({ "protected_file_patterns": "", "apply_to_admins": false })),
    )
    .await;
    let drift = forge.diff(&forge.inspect(&widgets).await.unwrap(), &projection);
    assert!(
        matches!(drift.as_slice(), [Drift::ProtectionWeakened { gaps }] if gaps.len() == 2),
        "{drift:?}"
    );
    let step = plan.iter().find(|s| s.id == "protection").unwrap();
    assert_eq!(
        forge.run_step(&widgets, step).await.unwrap(),
        StepOutcome::Updated
    );
    let drift = forge.diff(&forge.inspect(&widgets).await.unwrap(), &projection);
    assert!(drift.is_empty(), "{drift:?}");

    // ── no PR can rewrite the check it is judged by ─────────────────────
    let evil = open_pr(&fj, BOB, "evil", ".forgejo/workflows/verify-trust.yml").await;
    let harmless = open_pr(&fj, BOB, "docs", "docs/README.md").await;
    for (_, sha) in [&evil, &harmless] {
        // No runner here: report the check's context by hand, as a PR that
        // rewrote the workflow would get its own job to.
        fj.ok(
            BOB,
            Method::POST,
            &format!("repos/acme/widgets/statuses/{sha}"),
            Some(json!({ "state": "success", "context": CONTEXT })),
        )
        .await;
    }
    // Forgejo works out a PR's mergeability — including which protected
    // files it changes — in the background; wait for it, so the refusals
    // below are about the rule and not about a check still running.
    for (index, _) in [&evil, &harmless] {
        wait_until_checked(&fj, *index).await;
    }
    for who in [BOB, ALICE] {
        let (status, body) = fj
            .api(
                who,
                Method::POST,
                &format!("repos/acme/widgets/pulls/{}/merge", evil.0),
                Some(json!({ "Do": "fast-forward-only" })),
            )
            .await;
        eprintln!("{} merging the workflow change: {status} {body}", who.0);
        assert!(
            !status.is_success(),
            "{} merged a PR that changes the workflow: {status} {body}",
            who.0
        );
        assert!(
            body.to_string().to_ascii_lowercase().contains("protected"),
            "refused, but not for the protected files: {status} {body}"
        );
    }
    // The same maintainer can merge a PR that leaves the workflow alone —
    // fast-forward, so the commit lands unchanged.
    let (status, body) = fj
        .api(
            BOB,
            Method::POST,
            &format!("repos/acme/widgets/pulls/{}/merge", harmless.0),
            Some(json!({ "Do": "fast-forward-only" })),
        )
        .await;
    assert!(status.is_success(), "harmless merge: {status} {body}");
    let main = fj
        .ok(ROOT, Method::GET, "repos/acme/widgets/branches/main", None)
        .await;
    assert_eq!(main["commit"]["id"], harmless.1);
    // Nobody pushes to main directly, not even through the contents API.
    let (status, _) = fj
        .api(
            ALICE,
            Method::POST,
            "repos/acme/widgets/contents/direct.txt",
            Some(json!({ "content": STANDARD.encode("x"), "message": "direct" })),
        )
        .await;
    assert!(!status.is_success(), "a direct write to main went through");

    // ── archive, rotate ──────────────────────────────────────────────────
    forge.archive_repo(&widgets).await.unwrap();
    forge.archive_repo(&widgets).await.unwrap();
    assert!(forge.inspect(&widgets).await.unwrap().archived);

    let rotated = forge.rotate_token().await.unwrap();
    assert_eq!(rotated.deleted, ["setup"]);
    let tokens = fj
        .ok(BOT, Method::GET, &format!("users/{}/tokens", BOT.0), None)
        .await;
    let names: Vec<_> = tokens
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, std::slice::from_ref(&rotated.new_token));
    forge.inspect(&widgets).await.unwrap();
    let rotated_again = forge.rotate_token().await.unwrap();
    assert_eq!(rotated_again.deleted, [rotated.new_token]);
    forge.inspect(&widgets).await.unwrap();
}

/// Wait for Forgejo's background mergeability check on PR `index`.
async fn wait_until_checked(fj: &Forgejo, index: u64) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let pr = fj
            .ok(
                ROOT,
                Method::GET,
                &format!("repos/acme/widgets/pulls/{index}"),
                None,
            )
            .await;
        if pr["mergeable"] == true {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "PR {index} never became mergeable: {pr}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// A branch off `main` changing `path`, as `who`, and a PR for it:
/// `(index, head sha)`.
async fn open_pr(fj: &Forgejo, who: (&str, &str), branch: &str, path: &str) -> (u64, String) {
    let file = fj
        .ok(
            who,
            Method::POST,
            &format!("repos/acme/widgets/contents/{path}"),
            Some(json!({
                "content": STANDARD.encode(format!("changed on {branch}\n")),
                "message": format!("change {path}"),
                "branch": "main",
                "new_branch": branch,
            })),
        )
        .await;
    let sha = file["commit"]["sha"].as_str().unwrap().to_string();
    let pr = fj
        .ok(
            who,
            Method::POST,
            "repos/acme/widgets/pulls",
            Some(json!({ "head": branch, "base": "main", "title": format!("change {path}") })),
        )
        .await;
    (pr["number"].as_u64().unwrap(), sha)
}

/// Every endpoint and field the adapter uses, against the instance's own
/// swagger. (The same table was checked against Codeberg's and against
/// Forgejo 7, 8, 11 and 15 when the adapter was written.)
async fn swagger_covers_the_adapter(fj: &Forgejo) {
    let s: Value = reqwest::get(fj.base.join("swagger.v1.json").unwrap())
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let defs = &s["definitions"];
    let responses = &s["responses"];
    let def_of = |schema: &Value| -> String {
        let schema = if schema["type"] == "array" {
            &schema["items"]
        } else {
            schema
        };
        schema["$ref"]
            .as_str()
            .unwrap_or("")
            .rsplit('/')
            .next()
            .unwrap()
            .to_string()
    };
    let mut problems = Vec::new();
    for (m, path, body, resp) in USED {
        let op = &s["paths"][path][m.to_ascii_lowercase()];
        if op.is_null() {
            problems.push(format!("missing {m} {path}"));
            continue;
        }
        if !body.is_empty() {
            let schema = op["parameters"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["in"] == "body")
                .map(|p| def_of(&p["schema"]))
                .unwrap_or_default();
            for f in *body {
                if defs[&schema]["properties"][f].is_null() {
                    problems.push(format!("{m} {path}: {schema} has no `{f}`"));
                }
            }
        }
        if !resp.is_empty() {
            let r = ["200", "201"]
                .iter()
                .map(|c| &op["responses"][c])
                .find(|r| !r.is_null())
                .unwrap();
            let schema = match r["$ref"].as_str() {
                Some(re) => def_of(&responses[re.rsplit('/').next().unwrap()]["schema"]),
                None => def_of(&r["schema"]),
            };
            for f in *resp {
                if defs[&schema]["properties"][f].is_null() {
                    problems.push(format!("{m} {path}: response {schema} has no `{f}`"));
                }
            }
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

type Used = (
    &'static str,
    &'static str,
    &'static [&'static str],
    &'static [&'static str],
);

const PROTECTION_FIELDS: &[&str] = &[
    "enable_push",
    "enable_push_whitelist",
    "push_whitelist_usernames",
    "push_whitelist_teams",
    "push_whitelist_deploy_keys",
    "enable_merge_whitelist",
    "merge_whitelist_usernames",
    "merge_whitelist_teams",
    "enable_status_check",
    "status_check_contexts",
    "protected_file_patterns",
    "unprotected_file_patterns",
    "apply_to_admins",
];

const REPO_SETTINGS: &[&str] = &[
    "archived",
    "has_pull_requests",
    "has_actions",
    "allow_fast_forward_only_merge",
    "allow_merge_commits",
    "allow_rebase",
    "allow_rebase_explicit",
    "allow_squash_merge",
    "default_merge_style",
];

const TEAM_FIELDS: &[&str] = &[
    "name",
    "description",
    "permission",
    "can_create_org_repo",
    "includes_all_repositories",
    "units",
];

const USED: &[Used] = &[
    ("GET", "/version", &[], &["version"]),
    ("GET", "/user", &[], &["id", "login"]),
    ("GET", "/signing-key.gpg", &[], &[]),
    ("GET", "/users/search", &[], &[]),
    (
        "POST",
        "/users/{username}/tokens",
        &["name", "scopes"],
        &["id", "sha1"],
    ),
    (
        "GET",
        "/users/{username}/tokens",
        &[],
        &["id", "name", "token_last_eight"],
    ),
    ("DELETE", "/users/{username}/tokens/{token}", &[], &[]),
    ("GET", "/orgs/{org}", &[], &["id"]),
    (
        "GET",
        "/users/{username}/orgs/{org}/permissions",
        &[],
        &["is_owner", "can_create_repository"],
    ),
    (
        "GET",
        "/orgs/{org}/teams",
        &[],
        &["id", "name", "permission"],
    ),
    ("POST", "/orgs/{org}/teams", TEAM_FIELDS, &["id"]),
    ("PATCH", "/teams/{id}", TEAM_FIELDS, &["id"]),
    ("GET", "/teams/{id}/members/{username}", &[], &[]),
    ("PUT", "/teams/{id}/members/{username}", &[], &[]),
    ("GET", "/orgs/{org}/hooks", &[], &["id", "url", "config"]),
    (
        "POST",
        "/orgs/{org}/hooks",
        &["type", "config", "events", "active"],
        &[],
    ),
    (
        "PATCH",
        "/orgs/{org}/hooks/{id}",
        &["config", "events", "active"],
        &[],
    ),
    (
        "POST",
        "/orgs/{org}/repos",
        &[
            "name",
            "private",
            "auto_init",
            "readme",
            "default_branch",
            "description",
        ],
        &["id", "full_name", "default_branch"],
    ),
    ("GET", "/repos/{owner}/{repo}", &[], REPO_SETTINGS),
    ("PATCH", "/repos/{owner}/{repo}", REPO_SETTINGS, &["id"]),
    (
        "GET",
        "/repos/{owner}/{repo}/collaborators",
        &[],
        &["id", "login"],
    ),
    (
        "GET",
        "/repos/{owner}/{repo}/collaborators/{collaborator}/permission",
        &[],
        &["permission"],
    ),
    (
        "PUT",
        "/repos/{owner}/{repo}/collaborators/{collaborator}",
        &["permission"],
        &[],
    ),
    (
        "DELETE",
        "/repos/{owner}/{repo}/collaborators/{collaborator}",
        &[],
        &[],
    ),
    (
        "GET",
        "/repos/{owner}/{repo}/branch_protections",
        &[],
        PROTECTION_FIELDS,
    ),
    (
        "POST",
        "/repos/{owner}/{repo}/branch_protections",
        PROTECTION_FIELDS,
        &["rule_name"],
    ),
    (
        "PATCH",
        "/repos/{owner}/{repo}/branch_protections/{name}",
        PROTECTION_FIELDS,
        &["rule_name"],
    ),
    (
        "GET",
        "/repos/{owner}/{repo}/contents/{filepath}",
        &[],
        &["type", "sha", "content", "encoding"],
    ),
    (
        "POST",
        "/repos/{owner}/{repo}/contents/{filepath}",
        &["content", "message"],
        &[],
    ),
    (
        "PUT",
        "/repos/{owner}/{repo}/contents/{filepath}",
        &["content", "message", "sha"],
        &[],
    ),
    (
        "GET",
        "/repos/{owner}/{repo}/actions/variables/{variablename}",
        &[],
        &["data"],
    ),
    (
        "POST",
        "/repos/{owner}/{repo}/actions/variables/{variablename}",
        &["value"],
        &[],
    ),
    (
        "PUT",
        "/repos/{owner}/{repo}/actions/variables/{variablename}",
        &["value", "name"],
        &[],
    ),
];
