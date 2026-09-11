//! The parent-process gate cannot be switched off from the environment in a
//! normal build.
//!
//! `DID_GIT_SIGN_BYPASS_POLICY` used to skip the gate in every build. It is now
//! honoured only by debug test builds with the `insecure-policy-bypass`
//! feature, and these tests pin both halves of that down against the real
//! `policy::evaluate`.
//!
//! They assume the test process's parent is not git (`git` or `git-*`), which
//! holds under `cargo test` and nextest.

use serial_test::serial;

const BYPASS_ENV: &str = "DID_GIT_SIGN_BYPASS_POLICY";
const PAYLOAD: &[u8] = b"bytes the caller chose";

/// Evaluate the gate with the bypass variable set, restoring it afterwards.
fn evaluate_with_bypass_env(value: &str) -> did_git_sign::policy::AuditEntry {
    // Env mutation is not thread-safe; every test here is `#[serial]`.
    unsafe { std::env::set_var(BYPASS_ENV, value) };
    let decision = did_git_sign::policy::evaluate("git", None, PAYLOAD);
    unsafe { std::env::remove_var(BYPASS_ENV) };
    decision
}

#[test]
#[serial]
#[cfg(not(feature = "insecure-policy-bypass"))]
fn normal_builds_ignore_the_bypass_env() {
    for value in ["1", "true", "TRUE"] {
        let decision = evaluate_with_bypass_env(value);
        assert!(
            !decision.bypass,
            "the bypass must be compiled out ({BYPASS_ENV}={value}): {decision:?}"
        );
        assert!(
            !decision.allowed,
            "a non-git parent must be refused even with {BYPASS_ENV}={value}: {decision:?}"
        );
    }
}

/// The feature exists so tests can run without git as the parent; with it on,
/// the bypass must still work and must be recorded in the audit entry.
#[test]
#[serial]
#[cfg(feature = "insecure-policy-bypass")]
fn test_builds_honour_the_bypass_env_and_record_it() {
    let decision = evaluate_with_bypass_env("1");
    assert!(decision.bypass, "{decision:?}");
    assert!(decision.allowed, "{decision:?}");
}

#[test]
#[serial]
fn the_default_gate_denies_a_non_git_parent() {
    unsafe { std::env::remove_var(BYPASS_ENV) };
    let decision = did_git_sign::policy::evaluate("git", None, PAYLOAD);
    assert!(!decision.bypass, "{decision:?}");
    assert!(
        !decision.allowed,
        "with no bypass and a non-git parent the gate must deny: {decision:?}"
    );
}
