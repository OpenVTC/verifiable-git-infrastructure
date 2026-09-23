//! Differential test: is the claim did-git-sign's commit-msg hook writes the
//! claim verify-trust reads?
//!
//! The hook places the `Signed-by-DID:` trailer with `git interpret-trailers`;
//! verify-trust reads it with `vgi_core::signer_did`, which follows git's
//! commit trailer view (`git log --format=%(trailers)`). Those are two
//! different parsers and two different questions — "where does the trailer
//! go" and "which trailer is the claim" — so they can drift apart. Version 1
//! of the hook did: `interpret-trailers` in its default mode takes a `---`
//! line for a patch divider and wrote the trailer above it, in a paragraph a
//! commit's trailer view never reads.
//!
//! This runs the real hook script, [`did_git_sign::init::COMMIT_MSG_HOOK`],
//! over generated messages — `---` lines included — and requires:
//!
//! - vgi-core and git's commit view name the same DID after the hook ran; and
//! - when the message held no `Signed-by-DID` trailer to keep, that DID is the
//!   one the hook was told to write.
//!
//! The reader side on its own (vgi-core against git) is covered in depth by
//! `crates/vgi-core/tests/trailer_differential.rs`.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};

use proptest::prelude::*;
use tempfile::TempDir;

const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
const KEY: &str = "Signed-by-DID";
const HOOK_DID: &str = "did:webvh:QmHook:example.com";

/// A throwaway repository holding the hook, with no user git configuration.
struct HookRepo {
    dir: TempDir,
    hook: PathBuf,
    msg: PathBuf,
}

impl HookRepo {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("create a temp dir");
        let hook = dir.path().join("commit-msg-hook");
        let msg = dir.path().join("MSG");
        let repo = Self { dir, hook, msg };
        repo.git(&["init", "--quiet"], b"");
        repo.git(&["hash-object", "-t", "tree", "-w", "--stdin"], b"");
        std::fs::write(&repo.hook, did_git_sign::init::COMMIT_MSG_HOOK).unwrap();
        repo
    }

    /// Apply the isolation the vgi-core differential uses: git's defaults for
    /// the comment character, separators and trailer configuration — the
    /// defaults vgi-core follows.
    fn isolate<'a>(&self, command: &'a mut Command) -> &'a mut Command {
        let no_config = self.dir.path().join("absent-gitconfig");
        command
            .current_dir(self.dir.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", &no_config)
            .env("GIT_CONFIG_SYSTEM", &no_config)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("HOME", self.dir.path())
            .env_remove("DID_GIT_SIGN_KEY")
    }

    fn git(&self, args: &[&str], stdin: &[u8]) -> String {
        let mut child = self
            .isolate(&mut Command::new("git"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("this test needs git on PATH");
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "`git {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("git output is UTF-8")
    }

    /// The message as the hook receives it: `git commit`'s default cleanup
    /// (`git stripspace --strip-comments`) runs first.
    fn cleaned(&self, message: &str) -> String {
        self.git(&["stripspace", "--strip-comments"], message.as_bytes())
    }

    /// Run the hook over `message` and return the rewritten message.
    fn run_hook(&self, message: &str) -> String {
        std::fs::write(&self.msg, message).unwrap();
        let output = self
            .isolate(&mut Command::new("sh"))
            .arg(&self.hook)
            .arg(&self.msg)
            .env("DID_GIT_SIGN_KEY", format!("{HOOK_DID}#key-0"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "hook failed on {message:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::read_to_string(&self.msg).unwrap()
    }

    fn commit_object(message: &str) -> String {
        format!(
            "tree {EMPTY_TREE}\n\
             author A U Thor <a@example.com> 1700000000 +0000\n\
             committer Alice <alice@example.com> 1700000000 +0000\n\
             \n\
             {message}"
        )
    }

    /// Every `Signed-by-DID` value in git's commit trailer view.
    fn logged_values(&self, message: &str) -> Vec<String> {
        let sha = self.git(
            &["hash-object", "-t", "commit", "-w", "--stdin"],
            Self::commit_object(message).as_bytes(),
        );
        let format = format!("--format=%(trailers:key={KEY},valueonly,unfold,separator=%x00)");
        let output = self.git(&["log", "-1", &format, sha.trim()], b"");
        let output = output.strip_suffix('\n').unwrap_or(&output);
        if output.is_empty() && !self.has_key(sha.trim()) {
            return Vec::new();
        }
        output.split('\0').map(str::to_string).collect()
    }

    /// Whether git's commit view holds a `Signed-by-DID` trailer, even an
    /// empty one (which `valueonly` output cannot tell from none).
    fn has_key(&self, sha: &str) -> bool {
        let format = format!("--format=%(trailers:key={KEY})");
        !self
            .git(&["log", "-1", &format, sha], b"")
            .trim()
            .is_empty()
    }
}

fn did_from_value(value: &str) -> Option<String> {
    let value = value.trim_ascii();
    value.starts_with("did:").then(|| {
        value
            .split(['#', '?', '/'])
            .next()
            .unwrap_or(value)
            .to_string()
    })
}

/// One repository per test binary; the hook tests share it, so they take
/// turns (the hook rewrites one message file).
fn shared_repo() -> std::sync::MutexGuard<'static, HookRepo> {
    static REPO: OnceLock<Mutex<HookRepo>> = OnceLock::new();
    REPO.get_or_init(|| Mutex::new(HookRepo::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn assert_hook_claim_is_read(repo: &HookRepo, message: &str) {
    let message = repo.cleaned(message);
    // git refuses an empty message before the hook runs.
    if message.trim_ascii().is_empty() {
        return;
    }
    let had_claim = !repo.logged_values(&message).is_empty();
    let hooked = repo.run_hook(&message);

    let logged = repo
        .logged_values(&hooked)
        .last()
        .and_then(|value| did_from_value(value));
    let verified = vgi_core::signer_did(HookRepo::commit_object(&hooked).as_bytes());
    assert_eq!(
        verified, logged,
        "verify-trust would check {verified:?} while git shows {logged:?}; hooked: {hooked:?}"
    );
    if !had_claim {
        assert_eq!(
            verified.as_deref(),
            Some(HOOK_DID),
            "the hook's claim is not the one verify-trust reads; hooked: {hooked:?}"
        );
    }
}

const FIXED_CASES: &[&str] = &[
    "subject\n",
    "subject\n\nbody\n",
    // Dependabot's shape: a `---` line, then YAML.
    "chore(deps): bump x from 1 to 2\n\nBumps x from 1 to 2.\n---\n\
     updated-dependencies:\n- dependency-name: x\n  dependency-version: 2\n",
    // A divider followed by a diff-like body.
    "subject\n\nexplanation\n\n---\ndiff --git a/f b/f\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-a\n+b\n",
    "subject\n\nbody\n---\n",
    "subject\n---\n",
    // A claim above the divider is not a claim anyone reads.
    "subject\n\nSigned-by-DID: did:webvh:QmOld:example.com\n---\nbelow\n",
    // A claim below one is, and is kept.
    "subject\n\nbody\n---\n\nSigned-by-DID: did:webvh:QmOld:example.com\n",
    // Keys that prefix, or are prefixed by, the claim's key.
    "subject\n\nSigned-by: someone\n",
    "subject\n\nS: x\n",
    "subject\n\nSigned-by-DIDX: x\n",
    // A mixed final paragraph, with and without git's own trailers.
    "subject\n\nprose\nFixes: #1\n",
    "subject\n\nprose\nSigned-off-by: A <a@example.com>\n",
    // A trailer-shaped subject.
    "Signed-by-DID: did:webvh:QmTitle:example.com\n",
];

#[test]
fn the_hook_claim_is_read_for_fixed_shapes() {
    let repo = shared_repo();
    for message in FIXED_CASES {
        assert_hook_claim_is_read(&repo, message);
    }
}

fn select(options: &'static [&'static str]) -> impl Strategy<Value = &'static str> {
    proptest::sample::select(options)
}

const LINES: &[&str] = &[
    "Signed-by-DID: did:webvh:QmOld:example.com#key-0",
    "signed-by-did : did:webvh:QmOld:example.com",
    "Signed-by-DID: not-a-did",
    "Signed-by-DID:",
    "Signed-by: someone",
    "Signed-by-DIDX: x",
    "Signed-off-by: A U Thor <a@example.com>",
    "(cherry picked from commit 0123456789abcdef0123456789abcdef01234567)",
    "Reviewed-by: R <r@example.com>",
    "Fixes: #12",
    ": separator at offset zero",
    "a plain line of prose",
    "updated-dependencies:",
    "- dependency-name: x",
    " continued value",
    "\tcontinued with a tab",
    "",
    "   ",
    "# a comment",
    "---",
    "--- ",
    "--- a/file",
    "+++ b/file",
    "----",
];

const SUBJECTS: &[&str] = &[
    "subject",
    "chore(deps): bump x",
    "Signed-by-DID: did:webvh:QmTitle:example.com",
    "---",
    "",
];

fn arb_message() -> impl Strategy<Value = String> {
    (
        select(SUBJECTS),
        prop::collection::vec(select(LINES), 0..10),
        select(&["", "\n", "\n\n"]),
    )
        .prop_map(|(subject, lines, tail)| {
            let mut message = String::from(subject);
            for line in lines {
                message.push('\n');
                message.push_str(line);
            }
            message.push_str(tail);
            message
        })
}

proptest! {
    #![proptest_config(ProptestConfig {
        // Each case spawns several git processes and a shell; the shapes that
        // must always run are in FIXED_CASES.
        cases: 64,
        max_shrink_iters: 64,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn the_hook_claim_is_read_for_generated_shapes(message in arb_message()) {
        assert_hook_claim_is_read(&shared_repo(), &message);
    }
}
