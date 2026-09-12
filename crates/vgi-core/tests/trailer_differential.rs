//! Differential test: does vgi-core read the same `Signed-by-DID:` trailer
//! that git reads?
//!
//! Every trust decision in verify-trust already fails closed on a parser
//! difference — the identity comes out of the signed payload, the DID has to
//! publish the key that signed, and the registry has to authorize it. What is
//! left is a **display** differential: a reviewer reads the DID that git
//! reports for a commit, so if vgi-core reads a different trailer, the DID that
//! was verified is not the DID that was shown.
//!
//! This generates commit messages full of awkward trailer shapes and holds
//! vgi-core to *both* commands review tooling uses:
//!
//! - `git interpret-trailers --parse`
//! - `git log -1 --format='%(trailers:key=Signed-by-DID,valueonly,…)'`
//!
//! git is the oracle here: no expected DID is hard-coded. The specific rules
//! these cases pin down are asserted without git, and much faster, in the unit
//! tests beside `trailer_did` in `src/commit.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use proptest::prelude::*;
use tempfile::TempDir;

/// The empty tree, so the generated commits point at an object that exists.
const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
const KEY: &str = "Signed-by-DID";

/// A throwaway bare repository to write commit objects into.
struct GitRepo {
    dir: TempDir,
}

impl GitRepo {
    fn new() -> Self {
        let repo = Self {
            dir: tempfile::tempdir().expect("create a temp dir"),
        };
        repo.git(&["init", "--bare", "--quiet"], b"");
        // `git log` reads the commits below, which name the empty tree.
        repo.git(&["hash-object", "-t", "tree", "-w", "--stdin"], b"");
        repo
    }

    /// Run git with no system, global or user configuration, so that the
    /// comment character, the trailer separators and any `trailer.<token>.key`
    /// settings are git's defaults — the same defaults `commit.rs` follows. A
    /// path that does not exist reads as empty configuration, and unlike
    /// `/dev/null` it exists on every platform.
    fn git(&self, args: &[&str], stdin: &[u8]) -> String {
        let no_config = self.dir.path().join("absent-gitconfig");
        let mut child = Command::new("git")
            .arg("-C")
            .arg(self.dir.path())
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", &no_config)
            .env("GIT_CONFIG_SYSTEM", &no_config)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("HOME", self.dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| {
                panic!(
                    "`git {}` failed to start ({error}); this test needs git on PATH",
                    args.join(" ")
                )
            });
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(stdin)
            .expect("write git stdin");
        let output = child.wait_with_output().expect("wait for git");
        assert!(
            output.status.success(),
            "`git {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("git output is UTF-8")
    }
}

/// One repository for the whole test binary: `git init` per generated case
/// would cost more than the comparison it enables.
fn shared_repo() -> &'static GitRepo {
    static REPO: OnceLock<GitRepo> = OnceLock::new();
    REPO.get_or_init(GitRepo::new)
}

/// The commit object both sides read. The committer is a plain email, so
/// `signer_did` cannot fall back to a DID committer identity and what is
/// compared is trailer parsing alone.
fn commit_object(message: &str) -> String {
    format!(
        "tree {EMPTY_TREE}\n\
         author A U Thor <a@example.com> 1700000000 +0000\n\
         committer Alice <alice@example.com> 1700000000 +0000\n\
         \n\
         {message}"
    )
}

/// vgi-core's value rules, applied to git's own reported value.
///
/// Both sides reduce a trailer value to a bare DID the same way, and that
/// shared step is not what is under test: this keeps it out of the comparison
/// so a mismatch can only mean the two sides read a *different trailer*.
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

/// The DID `git log`'s trailer view reports: the last `Signed-by-DID` value.
///
/// `separator=%x00` keeps an empty value as its own entry, which a newline
/// separator would lose.
fn did_from_git_log(repo: &GitRepo, message: &str) -> Option<String> {
    let sha = repo.git(
        &["hash-object", "-t", "commit", "-w", "--stdin"],
        commit_object(message).as_bytes(),
    );
    let format = format!("--format=%(trailers:key={KEY},valueonly,unfold,separator=%x00)");
    let output = repo.git(&["log", "-1", &format, sha.trim()], b"");
    let output = output.strip_suffix('\n').unwrap_or(&output);
    // With no matching trailer this is one empty entry, which yields no DID —
    // the same answer an empty value gives.
    output.split('\0').next_back().and_then(did_from_value)
}

/// The DID `git interpret-trailers --parse` reports: the last `Signed-by-DID`
/// among the trailer lines it prints, which it has already unfolded.
fn did_from_interpret_trailers(repo: &GitRepo, message: &str) -> Option<String> {
    let parsed = repo.git(&["interpret-trailers", "--parse"], message.as_bytes());
    parsed
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim_ascii().eq_ignore_ascii_case(KEY).then_some(value)
        })
        .next_back()
        .and_then(did_from_value)
}

/// The message as git's *commit* view presents it.
///
/// `git log` reads trailers from the subject onward: pretty.c's
/// `parse_commit_message` runs `skip_blank_lines` first, so blank lines at the
/// start of a commit message are not part of it. `git interpret-trailers` reads
/// plain text on stdin and does no such thing, so it is handed the same
/// normalized message — otherwise the two views genuinely disagree for those
/// messages and neither could serve as the oracle. vgi-core reads the commit
/// object, so the commit view is the one it has to match.
fn as_git_presents_it(message: &str) -> &str {
    let mut rest = message;
    while let Some(line_end) = rest.find('\n') {
        if !rest[..line_end].trim_ascii().is_empty() {
            break;
        }
        rest = &rest[line_end + 1..];
    }
    if rest.trim_ascii().is_empty() {
        return "";
    }
    rest
}

/// Fail unless vgi-core and both of git's own views name the same DID.
fn assert_agrees_with_git(repo: &GitRepo, message: &str) {
    let logged = did_from_git_log(repo, message);
    let interpreted = did_from_interpret_trailers(repo, as_git_presents_it(message));
    assert_eq!(
        logged, interpreted,
        "git's two trailer views disagree with each other, so this test cannot \
         judge vgi-core; message: {message:?}"
    );
    let ours = vgi_core::signer_did(commit_object(message).as_bytes());
    assert_eq!(
        ours, logged,
        "vgi-core would verify {ours:?} while git shows {logged:?}; message: {message:?}"
    );
}

/// Trailer shapes that must always be checked, whatever the generator does.
/// The 25% boundary is here in both directions because a generated message
/// lands on it only by luck.
const FIXED_CASES: &[&str] = &[
    // The ordinary shape did-git-sign's hook writes.
    "subject\n\nbody\n\nSigned-by-DID: did:webvh:QmA:example.com#key-0\n",
    "subject\n\nSigned-by-DID: did:webvh:QmA:example.com\n",
    // The title paragraph is never trailers.
    "Signed-by-DID: did:webvh:QmA:example.com\n",
    "subject\nSigned-by-DID: did:webvh:QmA:example.com\n",
    // A trailer line appended to a prose paragraph.
    "subject\n\nprose about the change\nSigned-by-DID: did:webvh:QmA:example.com\n",
    // Whitespace between the key and the colon.
    "subject\n\nSigned-by-DID : did:webvh:QmA:example.com\n",
    "subject\n\nSigned-by-DID\t: did:webvh:QmA:example.com\n",
    "subject\n\nSigned-by-DID  : did:webvh:QmA:example.com#key-0\n",
    // Key case.
    "subject\n\nsigned-by-did: did:webvh:QmA:example.com\n",
    "subject\n\nSIGNED-BY-DID: did:webvh:QmA:example.com\n",
    // Continuation (folded) values.
    "subject\n\nSigned-by-DID: did:webvh:QmA:example.com\n and more\n",
    "subject\n\nSigned-by-DID: did:webvh:QmA:example.com\n c1\n\tc2\n",
    "subject\n\nSigned-by-DID:\n did:webvh:QmA:example.com\n",
    // More than one claim.
    "subject\n\nSigned-by-DID: did:webvh:QmA:example.com\nSigned-by-DID: did:webvh:QmB:example.com\n",
    "subject\n\nSigned-by-DID: did:webvh:QmA:example.com\nSigned-by-DID: not-a-did\n",
    "subject\n\nSigned-by-DID: did:webvh:QmA:example.com\nSigned-by-DID:\n",
    // Trailing whitespace and blank lines.
    "subject\n\nSigned-by-DID: did:webvh:QmA:example.com   \n",
    "subject\n\nSigned-by-DID: did:webvh:QmA:example.com\n\n",
    "subject\n\nSigned-by-DID: did:webvh:QmA:example.com\n   \n",
    // Blank lines before the subject. git's commit view skips them, which
    // makes the trailer-shaped line the subject rather than a trailer.
    "\nSigned-by-DID: did:webvh:QmA:example.com\n",
    "   \nSigned-by-DID: did:webvh:QmA:example.com\n",
    "\t\nSigned-by-DID: did:webvh:QmA:example.com\n",
    "\n\nsubject\n\nSigned-by-DID: did:webvh:QmA:example.com\n",
    // Trailing whitespace on a folded trailer: the spaces before the newline
    // survive into the value, and the fold adds one more.
    "subject\n\nSigned-by-DID: did:webvh:QmA:example.com   \n continued value\n",
    // A non-trailer paragraph after the trailer block.
    "subject\n\nSigned-by-DID: did:webvh:QmA:example.com\n\nfinal prose, not a trailer\n",
    // git's own trailers unlock the 25%-non-trailer allowance; one line more
    // of prose and the whole block stops being one.
    "subject\n\nn1\nn2\nn3\nSigned-off-by: A U Thor <a@example.com>\nSigned-by-DID: did:webvh:QmA:example.com\n",
    "subject\n\nn1\nn2\nn3\nn4\nn5\nn6\nn7\nSigned-off-by: A U Thor <a@example.com>\nSigned-by-DID: did:webvh:QmA:example.com\n",
    // A cherry-pick line counts as one of git's own trailers even though it
    // holds no separator at all.
    "subject\n\nprose\n(cherry picked from commit 0123456789abcdef0123456789abcdef01234567)\nSigned-by-DID: did:webvh:QmA:example.com\n",
    // A separator at offset 0 is not a trailer.
    "subject\n\n: did:webvh:QmEvil:attacker.example\nSigned-by-DID: did:webvh:QmA:example.com\n",
    // Comment lines.
    "subject\n\n# a comment\nSigned-by-DID: did:webvh:QmA:example.com\n",
    "subject\n\n# Signed-by-DID: did:webvh:QmEvil:attacker.example\nSigned-by-DID: did:webvh:QmA:example.com\n",
    // A DID value with junk after it, and a bare scheme.
    "subject\n\nSigned-by-DID: did:webvh:QmA:example.com extra words\n",
    "subject\n\nSigned-by-DID: did:\n",
    // No trailer at all.
    "subject\n\njust a body\n",
    "",
];

#[test]
fn fixed_trailer_shapes_agree_with_git() {
    let repo = shared_repo();
    for message in FIXED_CASES {
        assert_agrees_with_git(repo, message);
    }
}

fn select(options: &'static [&'static str]) -> impl Strategy<Value = &'static str> {
    proptest::sample::select(options)
}

const KEYS: &[&str] = &[
    "Signed-by-DID",
    "signed-by-did",
    "SIGNED-BY-DID",
    "Signed-By-Did",
    // Near misses, which must not be read as the claim.
    "Signed-by-DIDX",
    "Signed-by",
];

/// What can sit between the key and the colon.
const GAPS: &[&str] = &["", " ", "  ", "\t", " \t"];

const VALUES: &[&str] = &[
    " did:webvh:QmAbc:example.com#key-0",
    " did:webvh:QmAbc:example.com",
    "did:webvh:QmNoSpace:example.com",
    " did:webvh:QmTrailing:example.com   ",
    " did:key:z6MkExampleExampleExample",
    " did:webvh:QmJunk:example.com and then words",
    " not-a-did",
    " did:",
    "",
];

const OTHER_TRAILERS: &[&str] = &[
    "Signed-off-by: A U Thor <a@example.com>",
    "(cherry picked from commit 0123456789abcdef0123456789abcdef01234567)",
    "Reviewed-by: R Eviewer <r@example.com>",
    "Fixes: #12",
    "Co-authored-by: B <b@example.com>",
    ": a separator at offset zero",
];

const PROSE: &[&str] = &[
    "a plain line of prose",
    "see the notes below",
    "fixes the thing (no colon here)",
    "refactor and tidy up",
];

/// Lines that fold into whatever trailer precedes them.
const CONTINUATIONS: &[&str] = &[
    " continued value",
    "\tcontinued with a tab",
    "  did:webvh:QmContinuation:example.com",
];

const BLANKS: &[&str] = &["", "   "];

const COMMENTS: &[&str] = &[
    "# a comment",
    "# Signed-by-DID: did:webvh:QmComment:example.com",
];

const SUBJECTS: &[&str] = &[
    "subject",
    "fix the trailer parser",
    // A subject that is itself trailer-shaped, for the title rule.
    "Signed-by-DID: did:webvh:QmTitle:example.com",
    "",
];

fn arb_line() -> impl Strategy<Value = String> {
    prop_oneof![
        6 => (select(KEYS), select(GAPS), select(VALUES))
            .prop_map(|(key, gap, value)| format!("{key}{gap}:{value}")),
        2 => select(OTHER_TRAILERS).prop_map(str::to_string),
        3 => select(PROSE).prop_map(str::to_string),
        2 => select(CONTINUATIONS).prop_map(str::to_string),
        2 => select(BLANKS).prop_map(str::to_string),
        1 => select(COMMENTS).prop_map(str::to_string),
    ]
}

fn arb_message() -> impl Strategy<Value = String> {
    (
        select(SUBJECTS),
        prop::collection::vec(arb_line(), 0..8),
        select(&["", "\n", "\n\n"]),
    )
        .prop_map(|(subject, lines, tail)| {
            let mut message = String::from(subject);
            for line in lines {
                message.push('\n');
                message.push_str(&line);
            }
            message.push_str(tail);
            message
        })
}

proptest! {
    #![proptest_config(ProptestConfig {
        // Each case spawns three git processes, so the count is bounded to
        // keep `cargo test` quick. The shapes that must always run are in
        // FIXED_CASES above.
        cases: 64,
        max_shrink_iters: 64,
        // Write nothing into the tree on failure: the shrunken message is
        // printed, and a shape worth keeping belongs in FIXED_CASES.
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn generated_trailer_shapes_agree_with_git(message in arb_message()) {
        assert_agrees_with_git(shared_repo(), &message);
    }
}
