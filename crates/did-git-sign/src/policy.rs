//! Signing-policy gate for `did-git-sign`.
//!
//! # What the gate does
//!
//! 1. Signing is refused unless the parent process is git (`git`, or one of
//!    git's `git-*` subcommand binaries) or `ssh-keygen`. The name is matched
//!    whole; see [`parent_is_allowed`].
//! 2. Every signing attempt, allowed or refused, is appended to an audit log
//!    under the user's config directory.
//!
//! This stops **accidental and naive use**: the binary wired up as an SSH
//! signing program for something other than git, or a script that runs
//! `did-git-sign -Y sign` directly. The audit log gives an honest user a local
//! record of what was signed to review.
//!
//! # What the gate does not do
//!
//! It is **not a boundary against code running as your user**, and no check of
//! the parent process can be. Code with your uid can:
//!
//! - run real `git` with `did-git-sign` as its signing program. The parent is
//!   then genuinely git, so a check on its name, path or code signature passes,
//!   and git signs whatever commit object that code asks it to;
//! - read the VTA credential from the OS keyring and talk to the VTA itself,
//!   without running this binary at all;
//! - edit or truncate the audit log, which is an ordinary file the user owns.
//!
//! The signing key is protected by the VTA credential in your OS keyring and by
//! the access the VTA grants that credential, not by this module. Treat the
//! audit log as a convenience, not as tamper-evident evidence.
//!
//! Path-based heuristics on the buffer file aren't enforced because
//! git's buffer files live in `$TMPDIR` with random names; trying to
//! pattern-match them produces false positives without constraining
//! anyone who can spawn `git` themselves.
//!
//! # Test builds
//!
//! The non-default `insecure-policy-bypass` feature lets an environment
//! variable skip the parent check, for tests that cannot run under git. It is
//! compiled out of normal builds, and enabling it without `debug_assertions`
//! (for example in a release profile) is a compile error.

#[cfg(all(feature = "insecure-policy-bypass", not(debug_assertions)))]
compile_error!(
    "the did-git-sign `insecure-policy-bypass` feature is for debug test builds only \
     and must not be enabled in a release build"
);

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use sysinfo::{Pid, System};

/// Test-only switch that skips the parent-process check. It exists only when
/// the `insecure-policy-bypass` feature is enabled, so a normal build neither
/// reads nor contains it.
#[cfg(feature = "insecure-policy-bypass")]
const BYPASS_ENV: &str = "DID_GIT_SIGN_BYPASS_POLICY";

/// Names whose presence as the parent process causes the policy to
/// permit signing. See [`parent_is_allowed`] for how they are matched.
const ALLOWED_PARENTS: &[&str] = &["git", "ssh-keygen"];

/// Does this parent-process name identify a program we sign for?
///
/// Matched on the **whole name**, not as a prefix. The previous
/// `token.starts_with("git")` also admitted `gitleaks`, `github-desktop`, and
/// anything an attacker chose to call `gitfoo` — every one of which satisfied
/// the gate this check exists to be. A build script only had to name its
/// binary well.
///
/// `git-*` is accepted because git dispatches subcommands as separate
/// `git-<name>` binaries, and a `.exe` suffix is stripped so the rule holds on
/// Windows, where the parent reports as `git.exe`.
///
/// This is an accident guard, not a boundary: as the module docs note, code
/// running as the user can spawn real `git` and satisfy any parent check.
/// Tightening it removed a free pass, not the attack.
fn parent_is_allowed(name: &str) -> bool {
    let token = name.strip_suffix(".exe").unwrap_or(name);
    ALLOWED_PARENTS
        .iter()
        .any(|allowed| token == *allowed || (*allowed == "git" && token.starts_with("git-")))
}

/// The gate's decision, as a pure function of its inputs.
///
/// `parent` is the parent process name as the OS reports it. Its first
/// whitespace-separated word is compared, case-insensitively, by
/// [`parent_is_allowed`]. An unknown parent is refused.
fn decide(bypass: bool, parent: Option<&str>) -> bool {
    bypass
        || parent
            .and_then(|name| name.split_whitespace().next())
            .is_some_and(|token| parent_is_allowed(&token.to_lowercase()))
}

/// Whether this invocation asked to skip the parent check.
///
/// Always `false` unless the crate was built with the `insecure-policy-bypass`
/// feature. With it, a bypass is announced on stderr every time it is used, so
/// it cannot go unnoticed in a test log.
fn bypass_requested() -> bool {
    #[cfg(feature = "insecure-policy-bypass")]
    {
        let on =
            std::env::var(BYPASS_ENV).is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        if on {
            eprintln!(
                "did-git-sign: WARNING — {BYPASS_ENV} is set; the parent-process check was \
                 skipped (test build with the insecure-policy-bypass feature)."
            );
        }
        on
    }
    #[cfg(not(feature = "insecure-policy-bypass"))]
    {
        false
    }
}

/// One audit-log line.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub timestamp_utc: String,
    pub action: &'static str,
    pub allowed: bool,
    pub parent_pid: Option<u32>,
    pub parent_name: Option<String>,
    pub namespace: String,
    pub buffer_path: Option<String>,
    pub buffer_sha256: String,
    /// Whether the parent check was skipped. Only a test build with the
    /// `insecure-policy-bypass` feature can set this; the field is kept so the
    /// log format does not change.
    pub bypass: bool,
}

/// Inspect the parent process and decide whether this signing attempt
/// is permitted. The `AuditEntry` is returned regardless so the caller
/// can append it to the audit log even on denial.
pub fn evaluate(
    namespace: &str,
    buffer_path: Option<&std::path::Path>,
    buffer: &[u8],
) -> AuditEntry {
    let bypass = bypass_requested();
    let (parent_pid, parent_name) = parent_process_info();
    let allowed = decide(bypass, parent_name.as_deref());

    let mut hasher = Sha256::new();
    hasher.update(buffer);
    let buffer_sha256 = hex::encode(hasher.finalize());

    AuditEntry {
        timestamp_utc: chrono::Utc::now().to_rfc3339(),
        action: "sign",
        allowed,
        parent_pid,
        parent_name,
        namespace: namespace.to_string(),
        buffer_path: buffer_path.map(|p| p.display().to_string()),
        buffer_sha256,
        bypass,
    }
}

/// Append `entry` to the per-user audit log.
///
/// Signing is not blocked when this fails. A read-only or full home directory
/// would otherwise make the user unable to commit, and refusing to sign does
/// not make the missing record appear.
///
/// It is reported on **stderr** rather than through `tracing` alone. The
/// subscriber is built with `EnvFilter::from_default_env()`, which defaults to
/// `ERROR` when `RUST_LOG` is unset — so a `warn!` here reached nobody in
/// normal use. This log is the only surface on which a user can notice
/// signatures they did not ask for, and losing it silently is precisely the
/// state an attacker would want. git shows a signing program's stderr, so this
/// lands in front of the person committing.
pub fn write_audit(entry: &AuditEntry) {
    if let Err(e) = try_write_audit(entry) {
        let path = audit_log_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<audit log unavailable>".to_string());
        eprintln!(
            "did-git-sign: WARNING — could not record this signing attempt in {path}: {e}\n\
             did-git-sign: the signature was still produced; the audit trail is incomplete."
        );
        tracing::warn!("did-git-sign audit log write failed: {e}");
    }
}

fn try_write_audit(entry: &AuditEntry) -> Result<()> {
    let path = audit_log_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create audit dir {}", parent.display()))?;
    }
    let line = serde_json::to_string(entry)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write as _;
    let mut f = opts
        .open(&path)
        .with_context(|| format!("open audit log {}", path.display()))?;
    writeln!(f, "{line}").with_context(|| format!("write audit log {}", path.display()))?;
    Ok(())
}

/// `~/.config/did-git-sign/audit.log` (or platform equivalent).
pub fn audit_log_path() -> Result<PathBuf> {
    let dir = dirs::config_dir().context("could not determine config directory")?;
    Ok(dir.join("did-git-sign").join("audit.log"))
}

fn parent_process_info() -> (Option<u32>, Option<String>) {
    let mut sys = System::new();
    let self_pid = std::process::id();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, false);
    let parent_pid = sys
        .process(Pid::from_u32(self_pid))
        .and_then(|p| p.parent())
        .map(|p| p.as_u32());
    let parent_name = parent_pid.and_then(|pid| {
        sys.process(Pid::from_u32(pid))
            .map(|p| p.name().to_string_lossy().to_string())
    });
    (parent_pid, parent_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_and_its_subcommand_binaries_may_sign() {
        for name in ["git", "git-remote-https", "git-lfs", "ssh-keygen"] {
            assert!(parent_is_allowed(name), "must still sign for {name}");
        }
    }

    /// Windows reports the parent as `git.exe`; the rule must survive that
    /// without falling back to prefix matching.
    #[test]
    fn a_windows_exe_suffix_is_stripped() {
        assert!(parent_is_allowed("git.exe"));
        assert!(parent_is_allowed("ssh-keygen.exe"));
    }

    /// The free pass the old `starts_with("git")` handed out: any program
    /// whose name merely began with an allowed one satisfied the gate, so an
    /// attacker's build script only had to be named well.
    #[test]
    fn programs_that_merely_start_with_an_allowed_name_may_not_sign() {
        for name in [
            "gitleaks",
            "github-desktop",
            "gitfoo",
            "gitk-evil",
            "ssh-keygen-wrapper",
            "not-git",
            "",
        ] {
            assert!(
                !parent_is_allowed(name),
                "{name} must not satisfy the parent check"
            );
        }
    }

    #[test]
    fn audit_entry_is_json_serializable() {
        let entry = AuditEntry {
            timestamp_utc: "2026-05-05T00:00:00Z".to_string(),
            action: "sign",
            allowed: true,
            parent_pid: Some(123),
            parent_name: Some("git".to_string()),
            namespace: "git".to_string(),
            buffer_path: Some("/tmp/buffer".to_string()),
            buffer_sha256: "deadbeef".to_string(),
            bypass: false,
        };
        let s = serde_json::to_string(&entry).unwrap();
        assert!(s.contains("\"allowed\":true"));
        assert!(s.contains("\"parent_name\":\"git\""));
    }

    #[test]
    fn evaluate_records_buffer_hash() {
        let entry = evaluate("git", None, b"hello");
        // sha256("hello")
        assert_eq!(
            entry.buffer_sha256,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn git_parents_are_allowed_whatever_the_os_reports() {
        for parent in [
            "git",
            "Git.EXE",
            "git-remote-https",
            "ssh-keygen",
            "git --no-pager",
        ] {
            assert!(decide(false, Some(parent)), "{parent:?} must be allowed");
        }
    }

    #[test]
    fn other_or_unknown_parents_are_refused() {
        for parent in [Some("cargo"), Some("gitleaks"), Some(""), Some("  "), None] {
            assert!(!decide(false, parent), "{parent:?} must be refused");
        }
    }

    #[test]
    fn a_bypass_is_the_only_thing_that_admits_an_unknown_parent() {
        assert!(decide(true, Some("cargo")));
        assert!(decide(true, None));
    }

    /// Without the feature, the gate cannot be told to skip the parent check.
    /// `bypass_requested` does not read the environment at all, so this needs
    /// no env mutation; `tests/policy_bypass.rs` covers the set-variable case.
    #[test]
    #[cfg(not(feature = "insecure-policy-bypass"))]
    fn normal_builds_never_request_a_bypass() {
        assert!(!bypass_requested());
    }

    #[test]
    #[cfg(feature = "insecure-policy-bypass")]
    #[serial_test::serial]
    fn evaluate_bypass_env_allows_unknown_parent() {
        // unsafe is required because env mutation is not thread-safe; the
        // serial attribute keeps it apart from the other env-touching tests.
        unsafe { std::env::set_var(BYPASS_ENV, "1") };
        let entry = evaluate("git", None, b"x");
        unsafe { std::env::remove_var(BYPASS_ENV) };
        assert!(entry.allowed);
        assert!(entry.bypass);
    }
}
