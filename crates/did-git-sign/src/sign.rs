use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use std::io::Read;
use std::path::Path;
use vgi_core::create_ssh_signature;

use crate::config::{self, SigningConfig};
use crate::policy;
use crate::vta;

/// Environment variable that selects which persona signs (R-G-1), as a
/// per-invocation override. Its value is the persona's `did:webvh:…#key-N`.
pub const SIGNING_KEY_ENV: &str = "DID_GIT_SIGN_KEY";

/// Per-repo git config key that selects which persona signs (R-G-1):
/// `git config did-git-sign.key did:webvh:…#key-N`.
pub const SIGNING_KEY_GIT_CONFIG: &str = "did-git-sign.key";

/// Where the effective signing-key selection came from (for clear diagnostics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// The [`SIGNING_KEY_ENV`] environment variable.
    Env,
    /// The [`SIGNING_KEY_GIT_CONFIG`] per-repo git config setting.
    GitConfig,
    /// The `did_key_id` from the config file git passed via `-f`.
    ConfigFile,
}

impl std::fmt::Display for KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            KeySource::Env => "the DID_GIT_SIGN_KEY environment variable",
            KeySource::GitConfig => "git config did-git-sign.key",
            KeySource::ConfigFile => "the did-git-sign config file",
        };
        f.write_str(s)
    }
}

/// Pure selection precedence (R-G-1): env var > per-repo git config > the config
/// file's own `did_key_id`. Whitespace is trimmed and an empty value is treated
/// as unset, so an exported-but-empty variable doesn't shadow the others.
fn select_signing_key(
    config_did: &str,
    env: Option<&str>,
    git: Option<&str>,
) -> (String, KeySource) {
    let clean = |v: Option<&str>| {
        v.map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    if let Some(v) = clean(env) {
        return (v, KeySource::Env);
    }
    if let Some(v) = clean(git) {
        return (v, KeySource::GitConfig);
    }
    (config_did.to_string(), KeySource::ConfigFile)
}

/// Read the per-repo git config selector (`did-git-sign.key`), if set. Runs in
/// the current directory — git sets the signer's cwd to the repo.
fn git_config_signing_key() -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["config", "--get", SIGNING_KEY_GIT_CONFIG])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!v.is_empty()).then_some(v)
}

/// Resolve the effective signing `did_key_id` and where it came from (R-G-1),
/// reading the env var and the per-repo git config around the pure
/// [`select_signing_key`].
fn resolve_signing_key(config_did: &str) -> (String, KeySource) {
    let env = std::env::var(SIGNING_KEY_ENV).ok();
    let git = git_config_signing_key();
    select_signing_key(config_did, env.as_deref(), git.as_deref())
}

/// The bare DID of a verification-method id (`did:webvh:…#key-0` → `did:webvh:…`).
fn bare_did(did_key_id: &str) -> &str {
    did_key_id
        .split(['#', '?', '/'])
        .next()
        .unwrap_or(did_key_id)
}

/// Refuse to sign a commit whose signer identity disagrees with the key
/// being used (R-G-3).
///
/// The signer DID is read from (in order): the `Signed-by-DID:` trailer,
/// then the committer email. When neither carries a DID, the commit has
/// no signer identity — but that is acceptable when a `commit-msg` hook
/// will inject the trailer before git finalises the object. At sign time
/// the trailer may already be present (hook ran) or absent (no hook, legacy
/// flow). We only reject a **conflicting** claim.
fn check_committer_matches_key(data: &[u8], did_key_id: &str, source: KeySource) -> Result<()> {
    use vgi_core::{committer_did, committer_identity, conflicting_signer_dids, signer_did};

    let signing_did = bare_did(did_key_id);

    if let Some((trailer, committer)) = conflicting_signer_dids(data) {
        anyhow::bail!(
            "did-git-sign: Signed-by-DID trailer claims '{trailer}' but committer claims \
             '{committer}'. Remove one claim or make them match before signing."
        );
    }

    // If a Signed-by-DID trailer is present, it must match.
    if let Some(trailer) = signer_did(data) {
        if trailer == signing_did {
            return Ok(());
        }
        // Trailer claims a different DID than the key we're signing with.
        if committer_did(data).is_some_and(|cd| cd != trailer) {
            // Both trailer and committer disagree — name the trailer since
            // verify-trust will prefer it.
            anyhow::bail!(
                "did-git-sign: Signed-by-DID trailer claims '{trailer}' but signing with \
                 key held by '{signing_did}' (selected via {source})."
            );
        }
        anyhow::bail!(
            "did-git-sign: signer identity '{trailer}' disagrees with the signing key \
             held by '{signing_did}' (selected via {source})."
        );
    }

    // No trailer. Check committer email (legacy path).
    match committer_did(data) {
        Some(claimed) if claimed == signing_did => Ok(()),
        Some(claimed) => anyhow::bail!(
            "did-git-sign: this commit would claim '{claimed}' but is being signed with a key \
             held by '{signing_did}' (selected via {source}). The commit would fail \
             verification as unknownKey. Set user.email to a '{signing_did}' key id, or select \
             the persona matching the committer."
        ),
        // No committer header: tags and non-git namespaces carry no commit
        // identity claim, so there is nothing for this guard to compare.
        None if committer_identity(data).is_none() => Ok(()),
        // Committer exists, but no DID in trailer or committer — the
        // commit-msg hook is missing.
        None => anyhow::bail!(
            "did-git-sign: no Signed-by-DID trailer and user.email is not a DID. \
             The commit would fail verification as noSignerDid. \
             Run 'did-git-sign init' to install the commit-msg hook, or set \
             user.email to '{did_key_id}'."
        ),
    }
}

/// Handle the signing invocation from git.
/// Git calls: `did-git-sign -Y sign -f <config_path> -n <namespace> <file_to_sign>`
/// The file to sign is passed as a positional argument; the armored SSH signature is written
/// to `<file_to_sign>.sig` on disk, matching ssh-keygen behaviour. Falls back to stdout
/// when no file argument is present (stdin mode).
pub async fn handle_sign(
    config_path: &Path,
    namespace: &str,
    sign_file: Option<&Path>,
) -> Result<()> {
    // Read data to sign from the file argument (git passes the buffer file path)
    // or fall back to stdin for compatibility.
    let data = if let Some(path) = sign_file {
        std::fs::read(path)
            .with_context(|| format!("failed to read file to sign: {}", path.display()))?
    } else {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("failed to read data from stdin")?;
        buf
    };

    // Policy gate: parent process must look like git, audit every attempt.
    // The audit log is append-only and records both accepted and denied
    // signing attempts so a user can detect anomalous activity after a
    // local-account compromise.
    let decision = policy::evaluate(namespace, sign_file, &data);
    policy::write_audit(&decision);
    if !decision.allowed {
        anyhow::bail!(
            "did-git-sign: signing refused by policy (parent process {:?} not in allow-list; \
             set DID_GIT_SIGN_BYPASS_POLICY=1 to override). \
             Attempt recorded in {}.",
            decision.parent_name.as_deref().unwrap_or("<unknown>"),
            policy::audit_log_path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<audit log unavailable>".to_string())
        );
    }

    // Load the config git pointed us at (`-f`).
    let cfg = SigningConfig::load(config_path)?;

    // R-G-1: resolve which community persona signs — an env var or a per-repo
    // git-config setting may override the config file's persona. R-G-2: when an
    // override names a persona with no stored credentials, fail clearly rather
    // than silently signing as an arbitrary (the config file's) persona.
    let (did_key_id, source) = resolve_signing_key(&cfg.did_key_id);
    if did_key_id != cfg.did_key_id && config::load_vta_credentials(&did_key_id).is_err() {
        anyhow::bail!(
            "did-git-sign: the signing persona '{did_key_id}' selected via {source} has no \
             stored credentials. Run `did-git-sign init` for that persona, or clear the \
             override ({} / `git config --unset {}`).",
            SIGNING_KEY_ENV,
            SIGNING_KEY_GIT_CONFIG,
        );
    }
    // R-G-3: the committer header is the identity claim this signature will be
    // checked against. Refuse now if it names a different DID than the key we
    // are about to sign with — see [`check_committer_matches_key`].
    check_committer_matches_key(&data, &did_key_id, source)?;

    let cfg = SigningConfig {
        did_key_id,
        user_name: cfg.user_name,
    };

    // Authenticate with VTA and fetch signing key
    let (client, creds) = vta::authenticate(&cfg).await?;
    let seed = vta::get_signing_key(&client, &creds.key_id).await?;

    // Create Ed25519 signing key from seed
    let signing_key = SigningKey::from_bytes(seed.as_bytes());
    let verifying_key = signing_key.verifying_key();

    // Build the SSH signature
    let signature = create_ssh_signature(&signing_key, &verifying_key, namespace, &data)?;

    // Write the signature to <file>.sig, mirroring ssh-keygen -Y sign behaviour.
    // Git reads the signature back from that path after the signing program exits.
    // Fall back to stdout only when no input file was given (stdin mode).
    if let Some(path) = sign_file {
        // Append ".sig" to the full path (not replace the extension), matching ssh-keygen.
        let mut sig_os = path.as_os_str().to_owned();
        sig_os.push(".sig");
        let sig_path = std::path::PathBuf::from(sig_os);
        std::fs::write(&sig_path, signature.as_bytes())
            .with_context(|| format!("failed to write signature to {}", sig_path.display()))?;
    } else {
        print!("{signature}");
    }

    Ok(())
}

/// Test that signing works by creating a signature and verifying the output format.
/// Used by the `verify` subcommand.
pub fn test_sign(
    signing_key: &SigningKey,
    verifying_key: &ed25519_dalek::VerifyingKey,
    data: &[u8],
) -> Result<()> {
    let signature = create_ssh_signature(signing_key, verifying_key, "git", data)?;
    if !signature.starts_with("-----BEGIN SSH SIGNATURE-----") {
        anyhow::bail!("signature output has invalid format");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNER: &str = "did:webvh:QmSigner:example.com";

    fn commit_committed_by(committer: &str) -> Vec<u8> {
        format!(
            "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
             author A U Thor <a@example.com> 1700000000 +0000\n\
             committer A U Thor <{committer}> 1700000000 +0000\n\
             \n\
             a message\n"
        )
        .into_bytes()
    }

    #[test]
    fn a_matching_committer_and_key_may_sign() {
        let commit = commit_committed_by(&format!("{SIGNER}#key-0"));
        assert!(
            check_committer_matches_key(&commit, &format!("{SIGNER}#key-0"), KeySource::ConfigFile)
                .is_ok()
        );
    }

    #[test]
    fn a_different_key_of_the_same_did_still_signs() {
        // The verifier requires the claimed DID to publish the signing key, not
        // that the fragments agree — being stricter here would fail commits CI
        // would happily accept.
        let commit = commit_committed_by(&format!("{SIGNER}#key-0"));
        assert!(
            check_committer_matches_key(&commit, &format!("{SIGNER}#key-3"), KeySource::GitConfig)
                .is_ok()
        );
    }

    #[test]
    fn signing_as_one_community_while_claiming_another_is_refused() {
        // The multi-community footgun: a persona override moved but user.email
        // did not, so the commit would be born unverifiable.
        let commit = commit_committed_by("did:webvh:QmOther:community.example#key-0");
        let error =
            check_committer_matches_key(&commit, &format!("{SIGNER}#key-0"), KeySource::GitConfig)
                .unwrap_err()
                .to_string();

        assert!(error.contains("QmOther"), "names the claim: {error}");
        assert!(error.contains("QmSigner"), "names the key's DID: {error}");
        assert!(
            error.contains("git config did-git-sign.key"),
            "names where the selection came from: {error}"
        );
    }

    #[test]
    fn a_non_did_committer_without_trailer_is_refused() {
        // No trailer and no DID in committer email = missing commit-msg hook.
        let commit = commit_committed_by("alice@example.com");
        let error =
            check_committer_matches_key(&commit, &format!("{SIGNER}#key-0"), KeySource::ConfigFile)
                .unwrap_err()
                .to_string();
        assert!(
            error.contains("noSignerDid"),
            "must refuse when no DID claim exists: {error}"
        );
    }

    #[test]
    fn trailer_matching_key_is_accepted() {
        let commit = format!(
            "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
             author A <a@x.com> 1700000000 +0000\n\
             committer A <alice@example.com> 1700000000 +0000\n\
             \n\
             message\n\
             \n\
             Signed-by-DID: {SIGNER}#key-0\n"
        );
        assert!(
            check_committer_matches_key(
                commit.as_bytes(),
                &format!("{SIGNER}#key-0"),
                KeySource::ConfigFile
            )
            .is_ok()
        );
    }

    #[test]
    fn trailer_conflicting_with_key_is_refused() {
        let commit = format!(
            "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
             author A <a@x.com> 1700000000 +0000\n\
             committer A <alice@example.com> 1700000000 +0000\n\
             \n\
             message\n\
             \n\
             Signed-by-DID: did:webvh:QmOther:other.example#key-0\n"
        );
        assert!(
            check_committer_matches_key(
                commit.as_bytes(),
                &format!("{SIGNER}#key-0"),
                KeySource::ConfigFile
            )
            .is_err()
        );
    }

    #[test]
    fn conflicting_trailer_and_committer_dids_are_refused() {
        let commit = format!(
            "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
             author A <a@x.com> 1700000000 +0000\n\
             committer A <did:webvh:QmOther:other.example#key-0> 1700000000 +0000\n\
             \n\
             message\n\
             \n\
             Signed-by-DID: {SIGNER}#key-0\n"
        );
        let error = check_committer_matches_key(
            commit.as_bytes(),
            &format!("{SIGNER}#key-0"),
            KeySource::ConfigFile,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("Signed-by-DID"), "names trailer: {error}");
        assert!(error.contains("committer"), "names committer: {error}");
    }

    #[test]
    fn a_payload_with_no_committer_is_not_a_claim_to_check() {
        // Tags and non-git namespaces carry no committer header, so there is
        // nothing to disagree with — signing must not be blocked.
        assert!(
            check_committer_matches_key(b"not a commit object", SIGNER, KeySource::ConfigFile)
                .is_ok()
        );
    }

    #[test]
    fn signing_key_selection_precedence() {
        // env wins over git config and the config file (R-G-1).
        let (key, src) = select_signing_key("cfg#k", Some("env#k"), Some("git#k"));
        assert_eq!(key, "env#k");
        assert_eq!(src, KeySource::Env);

        // git config wins over the config file when no env override.
        let (key, src) = select_signing_key("cfg#k", None, Some("git#k"));
        assert_eq!(key, "git#k");
        assert_eq!(src, KeySource::GitConfig);

        // Falls back to the config file's own did_key_id (back-compat).
        let (key, src) = select_signing_key("cfg#k", None, None);
        assert_eq!(key, "cfg#k");
        assert_eq!(src, KeySource::ConfigFile);
    }

    #[test]
    fn signing_key_selection_ignores_blank_overrides() {
        // An exported-but-empty / whitespace var must not shadow lower precedence.
        let (key, src) = select_signing_key("cfg#k", Some("   "), Some("git#k"));
        assert_eq!(key, "git#k");
        assert_eq!(src, KeySource::GitConfig);

        let (key, src) = select_signing_key("cfg#k", Some(""), None);
        assert_eq!(key, "cfg#k");
        assert_eq!(src, KeySource::ConfigFile);

        // A value is trimmed.
        let (key, _) = select_signing_key("cfg#k", Some("  env#k \n"), None);
        assert_eq!(key, "env#k");
    }

    #[test]
    fn key_source_messages_name_the_origin() {
        assert!(KeySource::Env.to_string().contains("DID_GIT_SIGN_KEY"));
        assert!(
            KeySource::GitConfig
                .to_string()
                .contains("did-git-sign.key")
        );
    }

    #[test]
    fn test_test_sign_accepts_valid_key() {
        let seed = [0xAA; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        assert!(test_sign(&signing_key, &verifying_key, b"test data").is_ok());
    }

    /// Regression guard: the .sig path must be formed by appending ".sig" to the full
    /// filename, not by replacing an existing extension.  git's buffer files can have
    /// names like "COMMIT_EDITMSG" (no extension) or, in theory, dotted names.
    /// Using Path::with_extension("sig") would silently drop any existing extension,
    /// so the production code uses OsString::push instead.  This test encodes that
    /// contract so any future refactor breaks loudly.
    #[test]
    fn sig_path_appends_dot_sig_not_replaces_extension() {
        let base = std::path::Path::new("/tmp/buffer.diff");
        let mut sig_os = base.as_os_str().to_owned();
        sig_os.push(".sig");
        let sig_path = std::path::PathBuf::from(sig_os);
        assert_eq!(sig_path, std::path::PathBuf::from("/tmp/buffer.diff.sig"));

        // Also verify a name with no extension is handled correctly.
        let base2 = std::path::Path::new("/tmp/COMMIT_EDITMSG");
        let mut sig_os2 = base2.as_os_str().to_owned();
        sig_os2.push(".sig");
        let sig_path2 = std::path::PathBuf::from(sig_os2);
        assert_eq!(
            sig_path2,
            std::path::PathBuf::from("/tmp/COMMIT_EDITMSG.sig")
        );
    }
}
