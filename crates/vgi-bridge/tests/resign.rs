//! The Dependabot re-sign, end to end: signed push webhooks build the
//! provenance ledger, a mock GitHub answers the API, and a local repository
//! stands in for the one on GitHub — fetched from and force-pushed to. The
//! re-signed commits are then checked by the real verify-trust path.

mod common;

use std::path::Path;
use std::process::{Command, Stdio};

use axum::http::StatusCode;
use common::*;
use pgp::composed::{
    ArmorOptions, DetachedSignature, KeyType, SecretKeyParamsBuilder, SignedPublicKey,
    SignedSecretKey,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::types::Password;
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde_json::{Value, json};
use vgi_bridge::checks::{CommitVerifier, GitFetcher, VerifyTrustVerifier};
use vgi_bridge::resign::{ResignOutcome, run};
use vgi_bridge::store::{BranchLedger, Table};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const BRANCH: &str = "dependabot/cargo/foo-2.0.0";
const PR: u64 = 7;
const REPO_ID: u64 = 812;
const DEPENDABOT: (&str, u64) = ("dependabot[bot]", 49_699_333);
const ZERO: &str = "0000000000000000000000000000000000000000";
const DEPENDABOT_AUTHOR: &str =
    "dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>";

/// A Dependabot commit message: a `---` line, then its YAML, then a
/// sign-off — the shape that trips `interpret-trailers`' divider.
fn message(n: usize) -> String {
    format!(
        "Bump foo from 1.0.{n} to 2.0.{n}\n\nBumps [foo](https://github.com/x/foo) from 1.0.{n} \
         to 2.0.{n}.\n- [Commits](https://github.com/x/foo/compare/v1...v2)\n\n---\n\
         updated-dependencies:\n- dependency-name: foo\n  dependency-type: direct:production\n  \
         update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] \
         <support@github.com>\n"
    )
}

// ── fixtures ─────────────────────────────────────────────────────────────

fn git(dir: &Path, args: &[&str]) -> String {
    git_in(dir, args, None)
}

fn git_in(dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> String {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "dependabot[bot]")
        .env(
            "GIT_AUTHOR_EMAIL",
            "49699333+dependabot[bot]@users.noreply.github.com",
        )
        .env("GIT_AUTHOR_DATE", "1700000000 +0000")
        .env("GIT_COMMITTER_NAME", "GitHub")
        .env("GIT_COMMITTER_EMAIL", "noreply@github.com")
        .env("GIT_COMMITTER_DATE", "1700000000 +0000")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(input) = stdin {
        use std::io::Write;
        child.stdin.take().unwrap().write_all(input).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// GitHub's `web-flow` key, as a test stands it in.
fn platform_key() -> SignedSecretKey {
    let mut rng = StdRng::seed_from_u64(7);
    SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519)
        .can_sign(true)
        .primary_user_id("GitHub <noreply@github.com>".to_string())
        .build()
        .unwrap()
        .generate(&mut rng)
        .unwrap()
}

/// `unsigned` rewritten as a commit GitHub signed with `key`.
fn pgp_sign(repo: &Path, unsigned: &str, key: &SignedSecretKey) -> String {
    let payload = git(repo, &["cat-file", "commit", unsigned]);
    let payload = format!("{payload}\n");
    let mut rng = StdRng::seed_from_u64(11);
    let armored = DetachedSignature::sign_binary_data(
        &mut rng,
        &key.primary_key,
        &Password::empty(),
        HashAlgorithm::Sha256,
        payload.as_bytes(),
    )
    .unwrap()
    .to_armored_string(ArmorOptions::default())
    .unwrap();
    let (headers, body) = payload.split_once("\n\n").unwrap();
    let mut sig = String::from("gpgsig");
    for (i, line) in armored.trim_end().split('\n').enumerate() {
        sig.push_str(if i == 0 { " " } else { "\n " });
        sig.push_str(line);
    }
    let signed = format!("{headers}\n{sig}\n\n{body}");
    git_in(
        repo,
        &["hash-object", "-t", "commit", "-w", "--stdin"],
        Some(signed.as_bytes()),
    )
}

/// The repository on "GitHub": `main` with one commit, and a Dependabot
/// branch of `n` web-flow-signed commits on it. Serves partial clones and
/// takes pushes to the branch (it is not checked out).
struct Remote {
    dir: tempfile::TempDir,
    base: String,
    commits: Vec<String>,
    key: SignedSecretKey,
}

impl Remote {
    fn new(n: usize) -> Remote {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        git(p, &["init", "-q", "-b", "main"]);
        git(p, &["config", "uploadpack.allowFilter", "true"]);
        git(p, &["config", "uploadpack.allowAnySHA1InWant", "true"]);
        std::fs::write(p.join("Cargo.lock"), "foo 1.0\n").unwrap();
        git(p, &["add", "Cargo.lock"]);
        git(
            p,
            &["-c", "commit.gpgsign=false", "commit", "-q", "-m", "base"],
        );
        let base = git(p, &["rev-parse", "HEAD"]);
        let key = platform_key();
        let mut parent = base.clone();
        let mut commits = Vec::new();
        for i in 0..n {
            std::fs::write(p.join("Cargo.lock"), format!("foo 2.0.{i}\n")).unwrap();
            git(p, &["add", "Cargo.lock"]);
            let tree = git(p, &["write-tree"]);
            let unsigned = git_in(
                p,
                &["commit-tree", &tree, "-p", &parent, "-F", "-"],
                Some(message(i).as_bytes()),
            );
            let signed = pgp_sign(p, &unsigned, &key);
            commits.push(signed.clone());
            parent = signed;
        }
        git(p, &["update-ref", &format!("refs/heads/{BRANCH}"), &parent]);
        Remote {
            dir,
            base,
            commits,
            key,
        }
    }

    fn head(&self) -> &str {
        self.commits.last().unwrap()
    }

    fn url(&self) -> url::Url {
        url::Url::from_directory_path(self.dir.path()).unwrap()
    }

    fn branch_head(&self) -> String {
        git(
            self.dir.path(),
            &["rev-parse", &format!("refs/heads/{BRANCH}")],
        )
    }

    fn keyring(&self) -> String {
        SignedPublicKey::from(self.key.clone())
            .to_armored_string(ArmorOptions::default())
            .unwrap()
    }

    /// `base..head`, oldest first.
    fn range(&self, head: &str) -> Vec<String> {
        let out = git(
            self.dir.path(),
            &["rev-list", "--reverse", &format!("{}..{head}", self.base)],
        );
        out.lines().map(str::to_string).collect()
    }
}

/// A bridge over `remote`, its web-flow key configured (unless `keyring`
/// is off), with GitHub answering for pull request 7.
async fn resign_world(remote: &Remote, keyring: bool) -> World {
    let w = world(Options {
        local_remote: Some(remote.url()),
        keyring,
        ..Options::default()
    })
    .await;
    if keyring {
        // The config names this file; put the real (test) web-flow key in.
        std::fs::write(w.dir.path().join("web-flow.asc"), remote.keyring()).unwrap();
    }
    w
}

/// Mount GitHub's answers: pull request 7 with `head`, opened by `author`,
/// and the comparison `base...head`.
async fn mount_github(w: &World, remote: &Remote, head: &str, author: (&str, u64)) {
    w.server.reset().await;
    let s = &w.server;
    mount_any_token(s).await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": REPO_ID, "full_name": "acme/widgets", "default_branch": "main",
        })))
        .mount(s)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/repos/acme/widgets/pulls/{PR}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "number": PR, "state": "open",
            "user": { "login": author.0, "id": author.1, "type": "Bot" },
            "head": { "sha": head, "ref": BRANCH,
                      "repo": { "id": REPO_ID, "full_name": "acme/widgets" } },
            "base": { "ref": "main", "sha": remote.base,
                      "repo": { "id": REPO_ID, "full_name": "acme/widgets" } },
        })))
        .mount(s)
        .await;
    let commits = remote.range(head);
    Mock::given(method("GET"))
        .and(path(format!(
            "/repos/acme/widgets/compare/{}...{head}",
            remote.base
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total_commits": commits.len(),
            "merge_base_commit": { "sha": remote.base },
            "commits": commits.iter().map(|c| json!({ "sha": c })).collect::<Vec<_>>(),
        })))
        .mount(s)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/widgets/check-runs"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 77 })))
        .mount(s)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/repos/acme/widgets/check-runs/77"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 77 })))
        .mount(s)
        .await;
}

fn push_event(before: &str, after: &str, sender: (&str, u64)) -> Value {
    json!({
        "ref": format!("refs/heads/{BRANCH}"),
        "before": before, "after": after,
        "created": before == ZERO, "deleted": false, "forced": false,
        "repository": { "id": REPO_ID, "full_name": "acme/widgets" },
        "pusher": { "name": sender.0 },
        "sender": { "login": sender.0, "id": sender.1, "type": "Bot" },
    })
}

/// Dependabot's own history of the branch: created at the first commit,
/// then pushed to the head.
async fn dependabot_pushes(w: &World, remote: &Remote) {
    let mut before = ZERO.to_string();
    for (i, c) in remote.commits.iter().enumerate() {
        let s = post_webhook(
            w,
            "push",
            &format!("p-{i}"),
            &push_event(&before, c, DEPENDABOT),
        )
        .await;
        assert_eq!(s, StatusCode::ACCEPTED);
        before = c.clone();
    }
}

async fn resign(w: &World) -> ResignOutcome {
    run(
        &w.bridge,
        &vgi_forge::Resource::parse("github.com/acme/widgets").unwrap(),
        REPO_ID,
        PR,
    )
    .await
    .unwrap()
}

fn skipped(o: &ResignOutcome) -> &str {
    match o {
        ResignOutcome::Skipped(why) => why,
        other => panic!("expected a skip, got {other:?}"),
    }
}

/// Header `name`'s line of a raw commit.
fn header(raw: &str, name: &str) -> String {
    raw.split("\n\n")
        .next()
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{name} ")))
        .unwrap()
        .to_string()
}

// ── re-signing ───────────────────────────────────────────────────────────

/// Two web-flow-signed Dependabot commits on a branch only Dependabot
/// pushed to are re-signed by the bridge: same trees, same authors, the
/// bridge as committer and signer — and the real verify-trust path trusts
/// them on the bridge's namespace grant. A second run does nothing.
#[tokio::test]
async fn a_clean_dependabot_pull_request_is_re_signed_and_then_trusted() {
    let remote = Remote::new(2);
    let w = resign_world(&remote, true).await;
    mount_github(&w, &remote, remote.head(), DEPENDABOT).await;
    dependabot_pushes(&w, &remote).await;

    let ResignOutcome::Resigned {
        old_head,
        new_head,
        commits,
    } = resign(&w).await
    else {
        panic!("not re-signed")
    };
    assert_eq!(old_head, remote.head());
    assert_eq!(commits, 2);
    assert_eq!(remote.branch_head(), new_head, "force-pushed to the branch");

    let new = remote.range(&new_head);
    assert_eq!(new.len(), 2);
    let did = w.bridge.did().to_string();
    for (old, new) in remote.commits.iter().zip(&new) {
        let o = git(remote.dir.path(), &["cat-file", "commit", old]);
        let n = git(remote.dir.path(), &["cat-file", "commit", new]);
        assert_eq!(header(&o, "tree"), header(&n, "tree"), "same tree");
        assert_eq!(header(&o, "author"), header(&n, "author"), "same author");
        assert!(header(&o, "author").starts_with(DEPENDABOT_AUTHOR));
        assert!(
            header(&n, "committer").starts_with("VGI bridge <vgi-bridge@noreply.invalid> "),
            "{n}"
        );
        assert!(n.contains("-----BEGIN SSH SIGNATURE-----"));
        assert!(!n.contains("PGP SIGNATURE"));
        // The trailer is the last line, below the `---` block and the
        // sign-off, where git's trailer parser finds it.
        let trailers = git_in(
            remote.dir.path(),
            &["interpret-trailers", "--parse", "--no-divider"],
            Some(n.split_once("\n\n").unwrap().1.as_bytes()),
        );
        assert!(
            trailers
                .lines()
                .last()
                .unwrap()
                .starts_with(&format!("Signed-by-DID: {did}#")),
            "{trailers}"
        );
    }
    let first = git(remote.dir.path(), &["cat-file", "commit", &new[0]]);
    assert_eq!(
        header(&first, "parent"),
        remote.base,
        "keeps the base parent"
    );
    let second = git(remote.dir.path(), &["cat-file", "commit", &new[1]]);
    assert_eq!(header(&second, "parent"), new[0]);

    // The real verifier, against the registry granting the bridge's DID
    // git.commit.sign on the namespace (what the VTC grants at bind).
    let registry = stub_registry(vec![(did.clone(), "github.com/acme".into())]).await;
    let verifier = VerifyTrustVerifier::new(w.bridge.config()).with_registry_url(registry);
    let fetched = GitFetcher::new(&w.bridge.config().checks)
        .with_local_remote(remote.url())
        .fetch(&remote.url(), None, &new_head, &new)
        .await
        .unwrap();
    let lines = verifier
        .verify(
            &fetched.commits,
            "github.com/acme/widgets",
            "github.com/acme",
        )
        .await
        .unwrap();
    assert_eq!(lines.len(), 2);
    for l in &lines {
        assert!(l.passes, "{l:?}");
        assert_eq!(l.verdict, "trusted");
    }
    // …and the originals fail it: nothing was trusted before the re-sign.
    let before = GitFetcher::new(&w.bridge.config().checks)
        .with_local_remote(remote.url())
        .fetch(&remote.url(), None, remote.head(), &remote.commits)
        .await
        .unwrap();
    let lines = verifier
        .verify(
            &before.commits,
            "github.com/acme/widgets",
            "github.com/acme",
        )
        .await
        .unwrap();
    assert!(lines.iter().all(|l| !l.passes), "{lines:?}");

    // The bridge's own push arrives as a webhook; the pull request moves to
    // the re-signed head. Nothing more is done.
    let s = post_webhook(
        &w,
        "push",
        "p-own",
        &push_event(remote.head(), &new_head, ("acme-vgi-bridge[bot]", 5000)),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    mount_github(&w, &remote, &new_head, DEPENDABOT).await;
    let o = resign(&w).await;
    assert_eq!(skipped(&o), "already re-signed by the bridge");
    assert_eq!(remote.branch_head(), new_head);
}

/// GitHub delivers `pull_request` before the pushes: nothing is recorded
/// yet, so nothing happens — until the pushes arrive, and the re-sign runs.
#[tokio::test]
async fn a_push_delivered_after_the_pull_request_resumes_the_re_sign() {
    let remote = Remote::new(2);
    let w = resign_world(&remote, true).await;
    mount_github(&w, &remote, remote.head(), DEPENDABOT).await;
    let opened = json!({
        "action": "opened",
        "repository": { "id": REPO_ID, "full_name": "acme/widgets" },
        "pull_request": { "number": PR,
            "user": { "login": DEPENDABOT.0, "id": DEPENDABOT.1 },
            "head": { "sha": remote.head(), "ref": BRANCH },
            "base": { "ref": "main", "sha": remote.base } },
    });
    assert_eq!(
        post_webhook(&w, "pull_request", "d-1", &opened).await,
        StatusCode::ACCEPTED
    );
    wait_delivery(&w, "d-1").await;
    // The check fails, and says why the bridge is not re-signing (yet).
    let done = completed_checks(&w.server).await;
    assert_eq!(done[0]["conclusion"], "failure");
    let summary = done[0]["output"]["summary"].as_str().unwrap();
    assert!(
        summary.contains("will not re-sign") && summary.contains("no record of the push"),
        "{summary}"
    );
    assert_eq!(remote.branch_head(), remote.head());

    dependabot_pushes(&w, &remote).await;
    for _ in 0..200 {
        if remote.branch_head() != remote.head() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let head = remote.branch_head();
    assert_ne!(
        head,
        remote.head(),
        "re-signed once the pushes were recorded"
    );
    let raw = git(remote.dir.path(), &["cat-file", "commit", &head]);
    assert!(raw.contains(&format!("Signed-by-DID: {}#", w.bridge.did())));
}

/// The lease: if the branch moved after GitHub named its head, the push is
/// refused and the branch keeps what landed.
#[tokio::test]
async fn the_force_push_is_refused_when_the_head_moved() {
    let remote = Remote::new(2);
    let w = resign_world(&remote, true).await;
    mount_github(&w, &remote, remote.head(), DEPENDABOT).await;
    dependabot_pushes(&w, &remote).await;
    // Someone moves the branch between GitHub's answer and the push.
    git(
        remote.dir.path(),
        &[
            "update-ref",
            &format!("refs/heads/{BRANCH}"),
            &remote.commits[0],
        ],
    );
    let e = run(
        &w.bridge,
        &vgi_forge::Resource::parse("github.com/acme/widgets").unwrap(),
        REPO_ID,
        PR,
    )
    .await
    .unwrap_err();
    assert!(format!("{e:#}").contains("stale info"), "{e:#}");
    assert_eq!(remote.branch_head(), remote.commits[0], "not overwritten");
}

// ── not re-signing ───────────────────────────────────────────────────────

#[tokio::test]
async fn a_pull_request_not_opened_by_dependabot_is_left_alone() {
    let remote = Remote::new(2);
    let w = resign_world(&remote, true).await;
    dependabot_pushes(&w, &remote).await;
    // The login alone is not enough: the id must be Dependabot's too.
    for author in [("mallory", 7), ("dependabot[bot]", 7)] {
        mount_github(&w, &remote, remote.head(), author).await;
        let o = resign(&w).await;
        assert!(skipped(&o).contains("not opened by Dependabot"), "{o:?}");
    }
    assert_eq!(remote.branch_head(), remote.head());
}

#[tokio::test]
async fn a_branch_someone_else_pushed_to_is_left_alone() {
    let remote = Remote::new(2);
    let w = resign_world(&remote, true).await;
    mount_github(&w, &remote, remote.head(), DEPENDABOT).await;
    // Dependabot created the branch at the first commit; a writer pushed
    // the second (web-flow-signed and Dependabot-authored all the same —
    // which is exactly what authorship cannot prove).
    post_webhook(
        &w,
        "push",
        "p-0",
        &push_event(ZERO, &remote.commits[0], DEPENDABOT),
    )
    .await;
    post_webhook(
        &w,
        "push",
        "p-1",
        &push_event(&remote.commits[0], &remote.commits[1], ("mallory", 7)),
    )
    .await;
    let o = resign(&w).await;
    assert!(skipped(&o).contains("mallory"), "{o:?}");
    assert_eq!(remote.branch_head(), remote.head());
}

#[tokio::test]
async fn a_push_the_bridge_missed_is_left_alone() {
    let remote = Remote::new(2);
    let w = resign_world(&remote, true).await;
    mount_github(&w, &remote, remote.head(), DEPENDABOT).await;
    // Only the second push was seen (the bridge was down for the first).
    post_webhook(
        &w,
        "push",
        "p-1",
        &push_event(&remote.commits[0], &remote.commits[1], DEPENDABOT),
    )
    .await;
    let o = resign(&w).await;
    assert!(skipped(&o).contains("no record"), "{o:?}");
    assert_eq!(remote.branch_head(), remote.head());
}

#[tokio::test]
async fn without_a_platform_keyring_nothing_is_re_signed() {
    let remote = Remote::new(2);
    let w = resign_world(&remote, false).await;
    mount_github(&w, &remote, remote.head(), DEPENDABOT).await;
    dependabot_pushes(&w, &remote).await;
    let o = resign(&w).await;
    assert!(skipped(&o).contains("keyring"), "{o:?}");
    assert_eq!(remote.branch_head(), remote.head());
}

/// A commit GitHub did not sign (here: signed by another PGP key) stops the
/// whole re-sign, even on a clean branch.
#[tokio::test]
async fn a_commit_the_platform_did_not_sign_stops_the_re_sign() {
    let remote = Remote::new(2);
    let w = resign_world(&remote, true).await;
    // Configure a different web-flow key than the one that signed.
    let mut rng = StdRng::seed_from_u64(99);
    let other = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519)
        .can_sign(true)
        .primary_user_id("Not GitHub <x@example.org>".to_string())
        .build()
        .unwrap()
        .generate(&mut rng)
        .unwrap();
    std::fs::write(
        w.dir.path().join("web-flow.asc"),
        SignedPublicKey::from(other)
            .to_armored_string(ArmorOptions::default())
            .unwrap(),
    )
    .unwrap();
    mount_github(&w, &remote, remote.head(), DEPENDABOT).await;
    dependabot_pushes(&w, &remote).await;
    let o = resign(&w).await;
    assert!(skipped(&o).contains("does not verify"), "{o:?}");
    assert_eq!(remote.branch_head(), remote.head());
}

#[tokio::test]
async fn a_namespace_can_turn_the_re_sign_off() {
    let remote = Remote::new(1);
    let w = world(Options {
        local_remote: Some(remote.url()),
        github_extra: "[github.namespaces.acme]\nresign_dependabot = false\n".into(),
        ..Options::default()
    })
    .await;
    std::fs::write(w.dir.path().join("web-flow.asc"), remote.keyring()).unwrap();
    mount_github(&w, &remote, remote.head(), DEPENDABOT).await;
    dependabot_pushes(&w, &remote).await;
    let o = resign(&w).await;
    assert!(skipped(&o).contains("turned off"), "{o:?}");
    assert_eq!(remote.branch_head(), remote.head());
}

// ── the ledger, through webhooks ─────────────────────────────────────────

/// Pushes to other branches are not recorded, a repeat delivery changes
/// nothing, and a deletion clears the branch's record.
#[tokio::test]
async fn only_dependabot_branches_are_recorded_and_a_deletion_clears_one() {
    let remote = Remote::new(1);
    let w = resign_world(&remote, true).await;
    let mut other = push_event(ZERO, &remote.commits[0], DEPENDABOT);
    other["ref"] = json!("refs/heads/feature");
    assert_eq!(
        post_webhook(&w, "push", "p-x", &other).await,
        StatusCode::NO_CONTENT
    );
    dependabot_pushes(&w, &remote).await;
    let key = vgi_bridge::resign::ledger_key("github.com", REPO_ID, BRANCH);
    let store = w.bridge.store();
    let l: BranchLedger = store.get(Table::Branches, &key).unwrap().unwrap();
    assert_eq!(l.pushes.len(), 1);
    assert!(l.pushes[0].created);
    assert_eq!(l.pushes[0].sender_id, DEPENDABOT.1);
    assert_eq!(
        post_webhook(
            &w,
            "push",
            "p-0",
            &push_event(ZERO, &remote.commits[0], DEPENDABOT)
        )
        .await,
        StatusCode::OK,
        "a repeat delivery"
    );
    let mut deleted = push_event(&remote.commits[0], ZERO, ("maintainer", 3));
    deleted["deleted"] = json!(true);
    post_webhook(&w, "push", "p-del", &deleted).await;
    assert!(
        store
            .get::<BranchLedger>(Table::Branches, &key)
            .unwrap()
            .is_none()
    );
}

/// A push whose signature does not verify is refused and never recorded.
#[tokio::test]
async fn an_unsigned_push_is_refused() {
    let remote = Remote::new(1);
    let w = resign_world(&remote, true).await;
    let body = serde_json::to_vec(&push_event(ZERO, &remote.commits[0], DEPENDABOT)).unwrap();
    let req = axum::http::Request::post("/github/github.com/webhook")
        .header("x-github-event", "push")
        .header("x-github-delivery", "p-forged")
        .header("x-hub-signature-256", format!("sha256={}", "0".repeat(64)))
        .body(axum::body::Body::from(body))
        .unwrap();
    use tower::ServiceExt;
    let s = vgi_bridge::http::router(w.bridge.clone())
        .oneshot(req)
        .await
        .unwrap()
        .status();
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let key = vgi_bridge::resign::ledger_key("github.com", REPO_ID, BRANCH);
    assert!(
        w.bridge
            .store()
            .get::<BranchLedger>(Table::Branches, &key)
            .unwrap()
            .is_none()
    );
}
