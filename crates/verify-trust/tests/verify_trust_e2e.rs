//! End-to-end `verify-trust` test: a real git repository containing a real
//! sshsig-signed commit object, verified against a stub Trust Registry
//! speaking the `POST /trust-tasks` wire contract.
//!
//! Requires the `git` binary (present on all CI runners).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::{Command, Stdio};

use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use verify_trust::{
    CommitStatus, ResolvedSigners, TrustReport, VerifyTrustArgs, build_resolver, list_commits,
    pgp_exempt::ExemptKeyring,
    read_range, resolve_signer_keys,
    resource::{CiEnv, ResourceFormat, select_resources},
    verify_prepared,
};
use vgi_core::{GIT_SSHSIG_NAMESPACE, create_ssh_signature};

const SIGNER: &str = "did:webvh:QmSigner:example.com";

// --- git helpers -------------------------------------------------------------

fn git(repo: &Path, args: &[&str]) -> String {
    // The identity every commit claims: `did-git-sign` sets `user.email` to
    // the verification-method id it signs with, and that header is what the
    // verifier reads the signer DID from.
    git_as(repo, &format!("{SIGNER}#key-0"), args)
}

/// `git`, with the committer identity the caller wants on the commit object.
fn git_as(repo: &Path, committer: &str, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_AUTHOR_NAME", "A U Thor")
        .env("GIT_AUTHOR_EMAIL", "author@example.com")
        .env("GIT_COMMITTER_NAME", "A U Thor")
        .env("GIT_COMMITTER_EMAIL", committer)
        // Hermetic: the host's config may enable commit signing (this very
        // tool!), which would corrupt the fixtures.
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .trim_end()
        .to_string()
}

/// Rewrite `sha` as an sshsig-signed commit object and return the new sha.
fn sign_head_commit(repo: &Path, sha: &str, key: &SigningKey) -> String {
    let payload = {
        let out = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["cat-file", "commit", sha])
            .output()
            .expect("git cat-file runs");
        assert!(out.status.success());
        out.stdout
    };
    let armored =
        create_ssh_signature(key, &key.verifying_key(), GIT_SSHSIG_NAMESPACE, &payload).unwrap();

    // Insert the gpgsig header before the blank line, continuation-indented
    // exactly as git stores it.
    let text = String::from_utf8(payload).unwrap();
    let (headers, body) = text.split_once("\n\n").unwrap();
    let mut sig_header = String::from("gpgsig ");
    let mut lines = armored.trim_end().split('\n');
    sig_header.push_str(lines.next().unwrap());
    for line in lines {
        sig_header.push_str("\n ");
        sig_header.push_str(line);
    }
    let signed = format!("{headers}\n{sig_header}\n\n{body}");

    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["hash-object", "-t", "commit", "-w", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("git hash-object spawns");
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(signed.as_bytes())
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).trim_end().to_string()
}

/// Create a repo with one unsigned base commit, then one signed commit.
/// Returns (base_sha, signed_sha).
fn repo_with_signed_commit(repo: &Path, key: &SigningKey) -> (String, String) {
    git(repo, &["init", "-q", "-b", "main"]);
    std::fs::write(repo.join("a.txt"), "one\n").unwrap();
    git(repo, &["add", "a.txt"]);
    git(repo, &["commit", "-q", "-m", "base"]);
    let base = git(repo, &["rev-parse", "HEAD"]);

    std::fs::write(repo.join("a.txt"), "two\n").unwrap();
    git(repo, &["add", "a.txt"]);
    git(repo, &["commit", "-q", "-m", "change"]);
    let unsigned = git(repo, &["rev-parse", "HEAD"]);

    let signed = sign_head_commit(repo, &unsigned, key);
    git(repo, &["update-ref", "refs/heads/main", &signed]);
    (base, signed)
}

// --- stub registry ------------------------------------------------------------

/// Serve the `/trust-tasks` contract: `authorized: true` exactly for the
/// given `(entity, resource)` grants.
async fn stub_registry_with(grants: Vec<(String, String)>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let grants = grants.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                // Read headers.
                let header_end = loop {
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let content_length: usize = headers
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                while buf.len() < header_end + content_length {
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let request: Value = serde_json::from_slice(&buf[header_end..]).unwrap();
                let entity = request["payload"]["entity_id"].as_str().unwrap_or_default();
                let resource = request["payload"]["resource"].as_str().unwrap_or_default();
                let granted = grants.iter().any(|(e, r)| e == entity && r == resource);
                let response = json!({
                    "id": "urn:uuid:stub-reply",
                    "threadId": request["id"],
                    "type": "https://trusttasks.org/spec/registry/authorization/0.1#response",
                    "payload": {
                        "entity_id": entity,
                        "authority_id": request["payload"]["authority_id"],
                        "action": request["payload"]["action"],
                        "resource": request["payload"]["resource"],
                        "authorized": granted,
                        "time_evaluated": "2026-07-16T00:00:00Z",
                    }
                });
                let body = response.to_string();
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(reply.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    format!("http://{addr}")
}

/// Convenience: one repo-scoped grant for `authorized_did`.
async fn stub_registry(authorized_did: String) -> String {
    stub_registry_with(vec![(authorized_did, "example/repo".to_string())]).await
}

fn args_for(repo: &Path, range: String, registry_url: String) -> VerifyTrustArgs {
    VerifyTrustArgs {
        repo_dir: repo.to_path_buf(),
        range,
        max_signers: 32,
        exempt_keyring: None,
        registry_url: Some(registry_url),
        registry_did: "did:example:registry".into(),
        vtc_did: "did:example:vtc".into(),
        action: "git.commit.sign".into(),
        resource: "example/repo".into(),
        fallback_resource: None,
        resolve_agent_names: false,
        json: false,
    }
}

/// The signer set a resolver would produce for a repo whose commits claim
/// `SIGNER` and whose DID document publishes `key`.
fn signers_for(key: &SigningKey) -> ResolvedSigners {
    ResolvedSigners::from_keys([(SIGNER, vec![key.verifying_key().to_bytes()])])
}

/// Read the range and verify it, the two halves `handle_verify_trust` runs
/// either side of DID resolution.
async fn verify(
    args: &VerifyTrustArgs,
    signers: &ResolvedSigners,
    exempt: Option<&ExemptKeyring>,
) -> TrustReport {
    let commits = read_range(&args.repo_dir, &args.range).expect("range reads");
    verify_prepared(args, &commits, signers, exempt)
        .await
        .expect("verification runs")
}

// --- tests ---------------------------------------------------------------------

#[tokio::test]
async fn signed_and_authorized_commit_passes() {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let (base, signed) = repo_with_signed_commit(dir.path(), &key);
    let registry = stub_registry(SIGNER.to_string()).await;

    let args = args_for(dir.path(), format!("{base}..{signed}"), registry);
    let report = verify(&args, &signers_for(&key), None).await;

    assert_eq!(report.commits.len(), 1);
    assert_eq!(
        report.commits[0].status,
        CommitStatus::Trusted {
            signer_did: SIGNER.to_string(),
            resource: "example/repo".to_string()
        }
    );
    assert!(report.ok);
}

/// The report names the signers that actually signed the range, and only
/// those: a name for a signer absent from the range is noise on a PR check,
/// and a commit entry always keeps its full DID so a consumer that ignores
/// names is unaffected.
#[tokio::test]
async fn the_report_names_only_the_signers_present_in_the_range() {
    use vta_sdk::display_name::{DisplayName, NameSource};

    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let (base, signed) = repo_with_signed_commit(dir.path(), &key);
    let registry = stub_registry(SIGNER.to_string()).await;

    let mut signers = signers_for(&key);
    signers.names.insert(
        SIGNER,
        DisplayName::new(
            "example.com/@alice",
            NameSource::AgentName { verified: true },
        ),
    );
    // Resolved and named, but signed nothing here.
    signers.names.insert(
        "did:example:absent",
        DisplayName::new("example.com/@bob", NameSource::AgentName { verified: true }),
    );

    let args = args_for(dir.path(), format!("{base}..{signed}"), registry);
    let report = verify(&args, &signers, None).await;

    assert_eq!(
        report.signer_names.keys().collect::<Vec<_>>(),
        vec![SIGNER],
        "only signers that signed in the range are named"
    );
    assert_eq!(report.signer_names[SIGNER].name, "example.com/@alice");
    assert_eq!(
        report.commits[0].status,
        CommitStatus::Trusted {
            signer_did: SIGNER.to_string(),
            resource: "example/repo".to_string()
        },
        "the commit entry keeps the full DID; the name is reported alongside"
    );
}

/// The spoof the committer header invites, end to end: sign with a key you
/// hold while naming a DID you do not control. The claim only chooses whose
/// document to check the key against, and that document does not publish it.
#[tokio::test]
async fn a_commit_claiming_a_did_it_cannot_sign_for_fails() {
    const VICTIM: &str = "did:webvh:QmVictim:example.com";

    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git(repo, &["init", "-q", "-b", "main"]);
    std::fs::write(repo.join("a.txt"), "one\n").unwrap();
    git(repo, &["add", "a.txt"]);
    git(repo, &["commit", "-q", "-m", "base"]);
    let base = git(repo, &["rev-parse", "HEAD"]);

    // The attacker's own key, on a commit claiming the victim's DID.
    let attacker = SigningKey::from_bytes(&[13u8; 32]);
    std::fs::write(repo.join("a.txt"), "two\n").unwrap();
    git_as(repo, &format!("{VICTIM}#key-0"), &["add", "a.txt"]);
    git_as(
        repo,
        &format!("{VICTIM}#key-0"),
        &["commit", "-q", "-m", "impersonation"],
    );
    let unsigned = git(repo, &["rev-parse", "HEAD"]);
    let signed = sign_head_commit(repo, &unsigned, &attacker);
    git(repo, &["update-ref", "refs/heads/main", &signed]);

    // The victim's DID resolves, and publishes a key that is not the
    // attacker's. The registry would authorize the victim — it is never asked.
    let signers = ResolvedSigners::from_keys([(
        VICTIM,
        vec![
            SigningKey::from_bytes(&[9u8; 32])
                .verifying_key()
                .to_bytes(),
        ],
    )]);
    let registry = stub_registry(VICTIM.to_string()).await;
    let args = args_for(repo, format!("{base}..{signed}"), registry);
    let report = verify(&args, &signers, None).await;

    assert!(
        !report.ok,
        "a key the claimed DID does not publish must fail"
    );
    assert!(
        matches!(report.commits[0].status, CommitStatus::UnknownKey { ref did, .. } if did == VICTIM),
        "expected unknownKey against the claimed DID, got {:?}",
        report.commits[0].status
    );
}

/// A signed commit whose committer is an ordinary email asserts no identity,
/// so there is nothing to resolve or authorize.
#[tokio::test]
async fn a_commit_whose_committer_is_not_a_did_fails() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git(repo, &["init", "-q", "-b", "main"]);
    std::fs::write(repo.join("a.txt"), "one\n").unwrap();
    git(repo, &["add", "a.txt"]);
    git(repo, &["commit", "-q", "-m", "base"]);
    let base = git(repo, &["rev-parse", "HEAD"]);

    let key = SigningKey::from_bytes(&[9u8; 32]);
    std::fs::write(repo.join("a.txt"), "two\n").unwrap();
    git_as(repo, "alice@example.com", &["add", "a.txt"]);
    git_as(
        repo,
        "alice@example.com",
        &["commit", "-q", "-m", "no did here"],
    );
    let unsigned = git(repo, &["rev-parse", "HEAD"]);
    let signed = sign_head_commit(repo, &unsigned, &key);
    git(repo, &["update-ref", "refs/heads/main", &signed]);

    // Deliberately unreachable: a commit with no claimed DID never gets there.
    let args = args_for(
        repo,
        format!("{base}..{signed}"),
        "http://127.0.0.1:1".into(),
    );
    let report = verify(&args, &signers_for(&key), None).await;

    assert!(!report.ok);
    assert_eq!(
        report.commits[0].status,
        CommitStatus::NoSignerDid {
            committer: "alice@example.com".to_string()
        },
        "a valid signature is not an identity"
    );
}

#[tokio::test]
async fn signed_but_unauthorized_commit_fails() {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let (base, signed) = repo_with_signed_commit(dir.path(), &key);
    // The registry authorizes a different DID.
    let registry = stub_registry("did:example:someone-else".to_string()).await;

    let args = args_for(dir.path(), format!("{base}..{signed}"), registry);
    let report = verify(&args, &signers_for(&key), None).await;

    assert!(!report.ok);
    assert_eq!(
        report.commits[0].status,
        CommitStatus::Unauthorized {
            signer_did: SIGNER.to_string()
        }
    );
}

#[tokio::test]
async fn unsigned_commit_fails_without_touching_the_registry() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git(repo, &["init", "-q", "-b", "main"]);
    std::fs::write(repo.join("a.txt"), "one\n").unwrap();
    git(repo, &["add", "a.txt"]);
    git(repo, &["commit", "-q", "-m", "base"]);
    let base = git(repo, &["rev-parse", "HEAD"]);
    std::fs::write(repo.join("a.txt"), "two\n").unwrap();
    git(repo, &["add", "a.txt"]);
    git(repo, &["commit", "-q", "-m", "unsigned change"]);
    let head = git(repo, &["rev-parse", "HEAD"]);

    // Deliberately unreachable registry: no signed commits means no queries.
    let args = args_for(repo, format!("{base}..{head}"), "http://127.0.0.1:1".into());
    let report = verify(&args, &ResolvedSigners::default(), None).await;

    assert!(!report.ok);
    assert_eq!(report.commits[0].status, CommitStatus::Unsigned);
}

#[tokio::test]
async fn unreachable_registry_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let (base, signed) = repo_with_signed_commit(dir.path(), &key);

    let args = args_for(
        dir.path(),
        format!("{base}..{signed}"),
        "http://127.0.0.1:1".into(),
    );
    let report = verify(&args, &signers_for(&key), None).await;

    assert!(
        !report.ok,
        "a valid signature must not pass without a registry decision"
    );
    assert!(matches!(
        report.commits[0].status,
        CommitStatus::RegistryUnavailable { .. }
    ));
}

// --- PGP platform-commit exemption ------------------------------------------

mod pgp_platform {
    use super::*;
    use pgp::composed::{
        ArmorOptions, DetachedSignature, KeyType, SecretKeyParamsBuilder, SignedPublicKey,
        SignedSecretKey,
    };
    use pgp::crypto::hash::HashAlgorithm;
    use pgp::types::Password;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use verify_trust::pgp_exempt::ExemptKeyring;

    /// Generated once: the key's creation time is the wall clock, so two
    /// generations a second apart are two different keys.
    fn platform_key() -> SignedSecretKey {
        static KEY: std::sync::LazyLock<SignedSecretKey> =
            std::sync::LazyLock::new(generate_platform_key);
        KEY.clone()
    }

    fn generate_platform_key() -> SignedSecretKey {
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

    /// Rewrite `sha` as a PGP-signed commit (the shape GitHub's web-flow key
    /// produces for web-UI merge and Dependabot commits).
    fn pgp_sign_commit(repo: &Path, sha: &str, key: &SignedSecretKey) -> String {
        let payload = {
            let out = Command::new("git")
                .arg("-C")
                .arg(repo)
                .args(["cat-file", "commit", sha])
                .output()
                .unwrap();
            assert!(out.status.success());
            out.stdout
        };
        let mut rng = StdRng::seed_from_u64(11);
        let armored = DetachedSignature::sign_binary_data(
            &mut rng,
            &key.primary_key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            &payload[..],
        )
        .unwrap()
        .to_armored_string(ArmorOptions::default())
        .unwrap();

        let text = String::from_utf8(payload).unwrap();
        let (headers, body) = text.split_once("\n\n").unwrap();
        let mut sig_header = String::from("gpgsig ");
        let mut lines = armored.trim_end().split('\n');
        sig_header.push_str(lines.next().unwrap());
        for line in lines {
            sig_header.push_str("\n ");
            sig_header.push_str(line);
        }
        let signed = format!("{headers}\n{sig_header}\n\n{body}");

        let mut child = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["hash-object", "-t", "commit", "-w", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(signed.as_bytes())
                .unwrap();
        }
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).trim_end().to_string()
    }

    fn platform_keyring() -> ExemptKeyring {
        let armor = SignedPublicKey::from(platform_key())
            .to_armored_string(ArmorOptions::default())
            .unwrap();
        ExemptKeyring::from_armored(&armor).unwrap()
    }

    fn status_of<'a>(report: &'a TrustReport, sha: &str) -> &'a CommitStatus {
        &report
            .commits
            .iter()
            .find(|c| c.sha == sha)
            .unwrap_or_else(|| panic!("{sha} is not in the report"))
            .status
    }

    /// A pull request as GitHub merges it: `main` and a `feature` branch fork
    /// from a common root, each gains a commit, and the platform writes a
    /// merge of the two, PGP-signed. The feature commit is DID-signed only if
    /// `sign_feature`. Returns `(main_tip, feature_tip, platform_merge)`; the
    /// range a PR check verifies is `main_tip..platform_merge`.
    fn platform_merge_fixture(
        repo: &Path,
        did_key: &SigningKey,
        sign_feature: bool,
    ) -> (String, String, String) {
        git(repo, &["init", "-q", "-b", "main"]);
        std::fs::write(repo.join("a.txt"), "one\n").unwrap();
        git(repo, &["add", "a.txt"]);
        git(repo, &["commit", "-q", "-m", "root"]);

        git(repo, &["checkout", "-q", "-b", "feature"]);
        std::fs::write(repo.join("b.txt"), "feature\n").unwrap();
        git(repo, &["add", "b.txt"]);
        git(repo, &["commit", "-q", "-m", "feature work"]);
        let mut feature = git(repo, &["rev-parse", "HEAD"]);
        if sign_feature {
            feature = sign_head_commit(repo, &feature, did_key);
            git(repo, &["update-ref", "refs/heads/feature", &feature]);
        }

        // Base-branch history: already reviewed, outside the range.
        git(repo, &["checkout", "-q", "main"]);
        std::fs::write(repo.join("c.txt"), "main\n").unwrap();
        git(repo, &["add", "c.txt"]);
        git(repo, &["commit", "-q", "-m", "main moves on"]);
        let main_tip = git(repo, &["rev-parse", "HEAD"]);

        git(
            repo,
            &[
                "merge",
                "-q",
                "--no-ff",
                "-m",
                "Merge pull request #1",
                "feature",
            ],
        );
        let merge = git(repo, &["rev-parse", "HEAD"]);
        let merge = pgp_sign_commit(repo, &merge, &platform_key());
        git(repo, &["update-ref", "refs/heads/main", &merge]);
        (main_tip, feature, merge)
    }

    #[tokio::test]
    async fn a_platform_signed_merge_of_verified_parents_is_exempt() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let did_key = SigningKey::from_bytes(&[9u8; 32]);
        let (main_tip, feature, merge) = platform_merge_fixture(repo, &did_key, true);

        let registry = stub_registry(SIGNER.to_string()).await;
        let args = args_for(repo, format!("{main_tip}..{merge}"), registry);
        let report = verify(&args, &signers_for(&did_key), Some(&platform_keyring())).await;

        assert!(report.ok, "{:#?}", report.commits);
        assert_eq!(report.commits.len(), 2);
        assert!(status_of(&report, &feature).is_trusted());
        assert!(matches!(
            status_of(&report, &merge),
            CommitStatus::Exempt { .. }
        ));
    }

    #[tokio::test]
    async fn a_platform_signed_merge_does_not_launder_an_unverified_parent() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let did_key = SigningKey::from_bytes(&[9u8; 32]);
        let (main_tip, feature, merge) = platform_merge_fixture(repo, &did_key, false);

        let args = args_for(
            repo,
            format!("{main_tip}..{merge}"),
            "http://127.0.0.1:1".into(),
        );
        let report = verify(&args, &signers_for(&did_key), Some(&platform_keyring())).await;

        assert!(!report.ok);
        assert_eq!(status_of(&report, &feature), &CommitStatus::Unsigned);
        assert!(
            matches!(
                status_of(&report, &merge),
                CommitStatus::PlatformMergeUnverifiedParent { parent, .. } if *parent == feature
            ),
            "{:#?}",
            report.commits
        );
    }

    #[tokio::test]
    async fn a_platform_signed_merge_with_content_of_its_own_is_refused() {
        // The web conflict editor: a merge whose tree is not what its parents
        // merge to, carrying text no verified commit holds.
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let did_key = SigningKey::from_bytes(&[9u8; 32]);
        let (main_tip, feature, _) = platform_merge_fixture(repo, &did_key, true);
        git(repo, &["reset", "-q", "--hard", &main_tip]);
        git(
            repo,
            &[
                "merge",
                "-q",
                "--no-ff",
                "-m",
                "Merge pull request #1",
                &feature,
            ],
        );
        std::fs::write(repo.join("smuggled.txt"), "not in either parent\n").unwrap();
        git(repo, &["add", "smuggled.txt"]);
        git(repo, &["commit", "-q", "--amend", "--no-edit"]);
        let altered = git(repo, &["rev-parse", "HEAD"]);
        let altered = pgp_sign_commit(repo, &altered, &platform_key());

        let registry = stub_registry(SIGNER.to_string()).await;
        let args = args_for(repo, format!("{main_tip}..{altered}"), registry);
        let report = verify(&args, &signers_for(&did_key), Some(&platform_keyring())).await;

        assert!(!report.ok);
        assert!(status_of(&report, &feature).is_trusted());
        assert!(
            matches!(
                status_of(&report, &altered),
                CommitStatus::PlatformMergeAltered { .. }
            ),
            "{:#?}",
            report.commits
        );
    }

    #[tokio::test]
    async fn a_merge_whose_parent_is_an_exempt_merge_is_exempt() {
        // "Update branch" on a PR, then the PR check's own merge: the second
        // platform merge's parent is the first, which must itself settle.
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let did_key = SigningKey::from_bytes(&[9u8; 32]);
        let (_, feature, update) = platform_merge_fixture(repo, &did_key, true);
        // The PR branch now points at the update merge; main moves again.
        git(repo, &["update-ref", "refs/heads/feature", &update]);
        git(repo, &["reset", "-q", "--hard", "HEAD~1"]);
        std::fs::write(repo.join("d.txt"), "main again\n").unwrap();
        git(repo, &["add", "d.txt"]);
        git(repo, &["commit", "-q", "-m", "main moves again"]);
        let main_tip = git(repo, &["rev-parse", "HEAD"]);
        git(
            repo,
            &[
                "merge",
                "-q",
                "--no-ff",
                "-m",
                "Merge pull request #1",
                "feature",
            ],
        );
        let outer = git(repo, &["rev-parse", "HEAD"]);
        let outer = pgp_sign_commit(repo, &outer, &platform_key());

        let registry = stub_registry(SIGNER.to_string()).await;
        let args = args_for(repo, format!("{main_tip}..{outer}"), registry);
        let report = verify(&args, &signers_for(&did_key), Some(&platform_keyring())).await;

        assert!(report.ok, "{:#?}", report.commits);
        assert_eq!(report.commits.len(), 3);
        assert!(status_of(&report, &feature).is_trusted());
        assert!(matches!(
            status_of(&report, &update),
            CommitStatus::Exempt { .. }
        ));
        assert!(matches!(
            status_of(&report, &outer),
            CommitStatus::Exempt { .. }
        ));
    }

    /// A single-parent commit on top of a DID-signed one, PGP-signed by the
    /// platform, authored as `author`: a web-UI or Contents API edit.
    async fn single_parent_platform_commit(author: Option<&str>) -> (TrustReport, String) {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let did_key = SigningKey::from_bytes(&[9u8; 32]);
        let (base, did_signed) = repo_with_signed_commit(repo, &did_key);

        std::fs::write(repo.join("a.txt"), "three\n").unwrap();
        git(repo, &["add", "a.txt"]);
        let author_arg = author.map(|author| format!("--author={author}"));
        let mut commit = vec!["commit", "-q", "-m", "Update a.txt"];
        commit.extend(author_arg.as_deref());
        git_as(repo, "noreply@github.com", &commit);
        let unsigned = git(repo, &["rev-parse", "HEAD"]);
        let pgp_signed = pgp_sign_commit(repo, &unsigned, &platform_key());

        let registry = stub_registry(SIGNER.to_string()).await;
        let args = args_for(repo, format!("{base}..{pgp_signed}"), registry);
        let report = verify(&args, &signers_for(&did_key), Some(&platform_keyring())).await;
        assert!(status_of(&report, &did_signed).is_trusted());
        (report, pgp_signed)
    }

    #[tokio::test]
    async fn a_platform_signed_single_parent_edit_is_refused() {
        let (report, edit) = single_parent_platform_commit(None).await;
        assert!(
            !report.ok,
            "a web edit must not pass on the platform's word"
        );
        assert!(matches!(
            status_of(&report, &edit),
            CommitStatus::PlatformSignedEdit { .. }
        ));
    }

    #[tokio::test]
    async fn a_platform_signed_dependabot_commit_is_refused() {
        // The author header is the only thing marking a Dependabot commit,
        // and nothing binds it to Dependabot: it is not an exemption.
        let (report, edit) = single_parent_platform_commit(Some(
            "dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
        ))
        .await;
        assert!(!report.ok);
        assert!(matches!(
            status_of(&report, &edit),
            CommitStatus::PlatformSignedEdit { .. }
        ));
    }

    #[tokio::test]
    async fn platform_signed_commit_fails_without_keyring() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        git(repo, &["init", "-q", "-b", "main"]);
        std::fs::write(repo.join("a.txt"), "one\n").unwrap();
        git(repo, &["add", "a.txt"]);
        git(repo, &["commit", "-q", "-m", "base"]);
        let base = git(repo, &["rev-parse", "HEAD"]);
        std::fs::write(repo.join("a.txt"), "two\n").unwrap();
        git(repo, &["add", "a.txt"]);
        git(repo, &["commit", "-q", "-m", "change"]);
        let unsigned = git(repo, &["rev-parse", "HEAD"]);
        let pgp_signed = pgp_sign_commit(repo, &unsigned, &platform_key());
        git(repo, &["update-ref", "refs/heads/main", &pgp_signed]);

        // No registry needed: the commit never reaches the registry pass.
        let args = args_for(
            repo,
            format!("{base}..{pgp_signed}"),
            "http://127.0.0.1:1".into(),
        );
        let report = verify(&args, &ResolvedSigners::default(), None).await;

        assert!(!report.ok, "no keyring means no exemptions");
        assert!(matches!(
            report.commits[0].status,
            CommitStatus::PgpRejected { .. }
        ));
    }
}

// --- org-fallback grants -------------------------------------------------------

#[tokio::test]
async fn org_grant_authorizes_via_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let (base, signed) = repo_with_signed_commit(dir.path(), &key);
    // Grant exists only at org scope.
    let registry = stub_registry_with(vec![(SIGNER.to_string(), "example".to_string())]).await;

    let mut args = args_for(dir.path(), format!("{base}..{signed}"), registry);
    args.fallback_resource = Some("example".to_string());
    let report = verify(&args, &signers_for(&key), None).await;

    assert!(report.ok);
    assert_eq!(
        report.commits[0].status,
        CommitStatus::Trusted {
            signer_did: SIGNER.to_string(),
            resource: "example".to_string()
        }
    );
}

#[tokio::test]
async fn org_grant_is_ignored_without_fallback_configured() {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let (base, signed) = repo_with_signed_commit(dir.path(), &key);
    let registry = stub_registry_with(vec![(SIGNER.to_string(), "example".to_string())]).await;

    let args = args_for(dir.path(), format!("{base}..{signed}"), registry);
    let report = verify(&args, &signers_for(&key), None).await;

    assert!(
        !report.ok,
        "no fallback configured: org grant must not apply"
    );
    assert!(matches!(
        report.commits[0].status,
        CommitStatus::Unauthorized { .. }
    ));
}

#[tokio::test]
async fn repo_grant_wins_before_fallback_is_queried() {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let (base, signed) = repo_with_signed_commit(dir.path(), &key);
    let registry = stub_registry_with(vec![
        (SIGNER.to_string(), "example/repo".to_string()),
        (SIGNER.to_string(), "example".to_string()),
    ])
    .await;

    let mut args = args_for(dir.path(), format!("{base}..{signed}"), registry);
    args.fallback_resource = Some("example".to_string());
    let report = verify(&args, &signers_for(&key), None).await;

    assert_eq!(
        report.commits[0].status,
        CommitStatus::Trusted {
            signer_did: SIGNER.to_string(),
            resource: "example/repo".to_string()
        },
        "the repo-scoped grant is reported, not the fallback"
    );
}

#[tokio::test]
async fn denied_at_both_scopes_is_unauthorized() {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let (base, signed) = repo_with_signed_commit(dir.path(), &key);
    let registry = stub_registry_with(vec![]).await;

    let mut args = args_for(dir.path(), format!("{base}..{signed}"), registry);
    args.fallback_resource = Some("example".to_string());
    let report = verify(&args, &signers_for(&key), None).await;

    assert!(!report.ok);
    assert!(matches!(
        report.commits[0].status,
        CommitStatus::Unauthorized { .. }
    ));
}

// --- forge-qualified resources ----------------------------------------------------

/// A GitHub Actions environment for `Example/Repo`, as the runner sets it.
fn github_actions_env() -> CiEnv {
    CiEnv::from_lookup(|name| match name {
        "GITHUB_SERVER_URL" => Some("https://github.com".to_string()),
        "GITHUB_REPOSITORY" => Some("Example/Repo".to_string()),
        _ => None,
    })
}

/// `args_for`, with the resources chosen the way the binary chooses them.
fn args_in_format(
    repo: &Path,
    range: String,
    registry_url: String,
    format: ResourceFormat,
    fallback: Option<&str>,
) -> VerifyTrustArgs {
    let (resource, fallback_resource) = select_resources(
        format,
        None,
        fallback.map(str::to_string),
        &github_actions_env(),
    )
    .expect("resources select");
    VerifyTrustArgs {
        resource,
        fallback_resource,
        ..args_for(repo, range, registry_url)
    }
}

#[tokio::test]
async fn a_qualified_run_queries_the_forge_qualified_tuple() {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let (base, signed) = repo_with_signed_commit(dir.path(), &key);
    let registry = stub_registry_with(vec![(
        SIGNER.to_string(),
        "github.com/example/repo".to_string(),
    )])
    .await;

    let args = args_in_format(
        dir.path(),
        format!("{base}..{signed}"),
        registry,
        ResourceFormat::Qualified,
        None,
    );
    let report = verify(&args, &signers_for(&key), None).await;

    assert!(report.ok);
    assert_eq!(
        report.commits[0].status,
        CommitStatus::Trusted {
            signer_did: SIGNER.to_string(),
            resource: "github.com/example/repo".to_string()
        }
    );
}

#[tokio::test]
async fn a_qualified_org_fallback_authorizes() {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let (base, signed) = repo_with_signed_commit(dir.path(), &key);
    let registry =
        stub_registry_with(vec![(SIGNER.to_string(), "github.com/example".to_string())]).await;

    let args = args_in_format(
        dir.path(),
        format!("{base}..{signed}"),
        registry,
        ResourceFormat::Qualified,
        Some("GitHub.com/Example"),
    );
    let report = verify(&args, &signers_for(&key), None).await;

    assert_eq!(
        report.commits[0].status,
        CommitStatus::Trusted {
            signer_did: SIGNER.to_string(),
            resource: "github.com/example".to_string()
        }
    );
}

#[tokio::test]
async fn one_run_never_accepts_a_grant_in_the_other_form() {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let (base, signed) = repo_with_signed_commit(dir.path(), &key);
    let range = format!("{base}..{signed}");

    // Only a legacy grant: a qualified run must not fall back to it.
    let legacy_only =
        stub_registry_with(vec![(SIGNER.to_string(), "Example/Repo".to_string())]).await;
    let args = args_in_format(
        dir.path(),
        range.clone(),
        legacy_only,
        ResourceFormat::Qualified,
        None,
    );
    let report = verify(&args, &signers_for(&key), None).await;
    assert!(matches!(
        report.commits[0].status,
        CommitStatus::Unauthorized { .. }
    ));

    // Only a qualified grant: a legacy run queries `Example/Repo`, verbatim.
    let qualified_only = stub_registry_with(vec![(
        SIGNER.to_string(),
        "github.com/example/repo".to_string(),
    )])
    .await;
    let args = args_in_format(
        dir.path(),
        range,
        qualified_only,
        ResourceFormat::Legacy,
        None,
    );
    assert_eq!(args.resource, "Example/Repo");
    let report = verify(&args, &signers_for(&key), None).await;
    assert!(matches!(
        report.commits[0].status,
        CommitStatus::Unauthorized { .. }
    ));
}

// --- range handling ---------------------------------------------------------------

#[test]
fn a_range_that_is_a_git_option_is_rejected_before_git_runs() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    let key = SigningKey::from_bytes(&[42u8; 32]);
    let (base, signed) = repo_with_signed_commit(repo, &key);

    // `--range` is a CI input. Handed to `git rev-list` as an option it
    // would write (or truncate) a file of the caller's choosing.
    let target = repo.join("x");
    let err = list_commits(repo, &format!("--output={}", target.display()))
        .expect_err("an option-shaped range must be refused");
    assert!(
        err.to_string().contains("not an option"),
        "unexpected error: {err:#}"
    );
    assert!(!target.exists(), "git ran with the range as an option");
    assert!(read_range(repo, "-n1").is_err());

    // An ordinary range still lists its commits.
    assert_eq!(
        list_commits(repo, &format!("{base}..main")).unwrap(),
        vec![signed.clone()]
    );
    assert_eq!(list_commits(repo, "main").unwrap(), vec![base, signed]);
}

// --- resolution egress policy ----------------------------------------------------

/// A signer DID naming an internal host must not be fetched at all.
///
/// This is the one input to the verifier that a fork pull request fully
/// controls: the `Signed-by-DID` trailer (and the committer header it falls
/// back to) is whatever the commit says, and resolving `did:webvh:<scid>:<host>`
/// fetches `did.jsonl` from `<host>`. On a runner that can reach an internal
/// network, an author could previously have walked it one DID at a time and read
/// the answers off the per-signer resolution errors.
///
/// Asserted through the real path — `build_resolver` then `resolve_signer_keys`,
/// exactly as `handle_verify_trust` runs them — because the property being
/// pinned is that *this binary's* resolver is the guarded one, not that a
/// guarded resolver exists somewhere. The listener stands in for the internal
/// service and must never be connected to: a refusal after a connection has
/// already told the author that something is listening.
#[tokio::test]
async fn a_signer_did_on_an_internal_host_is_refused_without_being_fetched() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let internal = format!("did:webvh:QmStandInScidAAAAAAAAAAAAAAAAAAAA:localhost%3A{port}:agent");

    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git(repo, &["init", "-q", "-b", "main"]);
    std::fs::write(repo.join("a.txt"), "one\n").unwrap();
    git(repo, &["add", "a.txt"]);
    git(repo, &["commit", "-q", "-m", "base"]);
    let base = git(repo, &["rev-parse", "HEAD"]);

    // A real signature, over a commit claiming the internal DID. The signature
    // is valid; the DID is what must not be looked up.
    let key = SigningKey::from_bytes(&[21u8; 32]);
    let committer = format!("{internal}#key-0");
    std::fs::write(repo.join("a.txt"), "two\n").unwrap();
    git_as(repo, &committer, &["add", "a.txt"]);
    git_as(repo, &committer, &["commit", "-q", "-m", "internal signer"]);
    let unsigned = git(repo, &["rev-parse", "HEAD"]);
    let signed = sign_head_commit(repo, &unsigned, &key);
    git(repo, &["update-ref", "refs/heads/main", &signed]);

    let tdk = build_resolver(false).await.expect("the resolver builds");
    let signers = resolve_signer_keys(&tdk, std::slice::from_ref(&internal))
        .await
        .expect("resolution runs to a verdict per DID");

    // Deliberately unreachable: a signer that did not resolve is never queried.
    let args = args_for(
        repo,
        format!("{base}..{signed}"),
        "http://127.0.0.1:1".into(),
    );
    let report = verify(&args, &signers, None).await;

    assert!(
        !report.ok,
        "a commit whose claimed signer was never resolved cannot pass"
    );
    let reason = report
        .unresolved_signers
        .get(&internal)
        .expect("the refused DID is reported as an unresolved signer");
    assert!(
        reason.contains("BlockedHost"),
        "the reason must name the host refusal rather than a timeout: {reason}"
    );
    assert!(
        matches!(report.commits[0].status, CommitStatus::UnresolvedSigner { ref did, .. } if did == &internal),
        "expected unresolvedSigner against the claimed DID, got {:?}",
        report.commits[0].status
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), listener.accept())
            .await
            .is_err(),
        "something connected to the stand-in internal service"
    );
}

// --- committed platform keyring --------------------------------------------------

#[test]
fn committed_web_flow_keyring_parses() {
    // Drift tripwire: the keyring committed for the dogfood workflow must
    // stay parseable by the exemption verifier.
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.github/trusted-platform-keys.asc"
    );
    let text = std::fs::read_to_string(path).expect("committed keyring readable");
    verify_trust::pgp_exempt::ExemptKeyring::from_armored(&text).expect("keyring parses");
}
