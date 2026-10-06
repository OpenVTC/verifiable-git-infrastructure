use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::{self, SigningConfig, VtaCredentials};

/// Inputs to install did-git-sign for an already-provisioned persona.
///
/// All fields are values the caller already has — there is no VTA bootstrap
/// here. The function writes the config file, stores VTA credentials in the
/// OS keyring, runs the relevant `git config` invocations, and updates the
/// allowed_signers file.
///
/// The `verifying_key` is the Ed25519 public key (32 raw bytes) that signs
/// the persona's commits. It's used in the allowed_signers entry; the
/// caller is expected to have already derived it from the persona key
/// material.
pub struct InstallArgs<'a> {
    /// `true` writes config to the user's `~/.config/did-git-sign/`,
    /// `false` writes a repo-local `.did-git-sign.json`.
    pub global: bool,
    /// The verification method id, e.g. `did:webvh:.../persona#key-1`.
    pub did_key_id: String,
    /// VTA key UUID for the persona's signing key (stored in keyring so
    /// `did-git-sign -Y sign` can fetch the secret on demand).
    pub vta_key_id: String,
    /// DID this binary authenticates to the VTA as. The persona admin DID
    /// minted during VTA provisioning is the right value here.
    pub credential_did: String,
    /// Multibase-encoded private key paired with `credential_did`.
    pub credential_private_key_mb: String,
    /// VTA's own DID (e.g. `did:webvh:.../vta`).
    pub vta_did: String,
    /// VTA service URL, as resolved from the VTA's DID document. May be
    /// empty for DIDComm-only VTAs — `mediator_did` must be set in that
    /// case so the signer can reach the VTA over DIDComm.
    pub vta_url: String,
    /// DIDComm mediator DID advertised by the VTA. When `Some`, the signer
    /// uses DIDComm transport instead of REST. Required when `vta_url` is
    /// empty.
    pub mediator_did: Option<String>,
    /// Optional `git config user.name` to set during install.
    pub user_name: Option<String>,
    /// Persona signing key public bytes (Ed25519, 32 bytes).
    pub verifying_key: &'a [u8; 32],
}

/// Output of [`install`]. Mostly informational — used for the post-install
/// summary the caller prints.
pub struct InstallResult {
    /// Path the JSON config was written to.
    pub config_path: PathBuf,
    /// SSH public key string (`ssh-ed25519 …`) for the user to paste into
    /// their git host's signing-key settings.
    pub ssh_public_key: String,
    /// Set to the previous `--global user.signingKey` value if a non-global
    /// install just shadowed it. The caller can flag this to the operator
    /// so they aren't surprised when inspecting `git config --list`.
    pub overridden_global_signing_key: Option<String>,
    /// Set when a `--global` install just made a DID the committer email for
    /// **every** repository on the machine.
    ///
    /// Correct for a contributor in one community, and wrong the moment there
    /// are two: the identity a commit claims has to match the key that signs
    /// it, so a single global value silently claims the wrong community
    /// everywhere else. The caller surfaces this with the per-community
    /// alternative rather than refusing — the single-community case is real
    /// and `--global` is the right tool for it.
    pub global_committer_email: Option<String>,
}

/// Configure did-git-sign for an already-provisioned persona.
///
/// Idempotent against the file/keyring/git config state — re-running on a
/// host that already has did-git-sign installed updates the values without
/// erroring.
pub fn install(args: InstallArgs<'_>) -> Result<InstallResult> {
    let cfg = SigningConfig {
        did_key_id: args.did_key_id.clone(),
        user_name: args.user_name,
    };

    let vta_creds = VtaCredentials {
        vta_url: args.vta_url,
        vta_did: args.vta_did,
        credential_did: args.credential_did,
        private_key_multibase: args.credential_private_key_mb,
        key_id: args.vta_key_id,
        mediator_did: args.mediator_did,
    };

    // Since 0.14 this writes no git configuration and `args.global` is
    // ignored. The identity is kept in did-git-sign's own directory, and a
    // repository signs with it only once its settings are included there
    // (`did-git-sign enable`, [`crate::enable`]), so an existing signing
    // setup is never replaced.
    let config_path = SigningConfig::default_global_path()?;
    cfg.save(&config_path)?;
    config::store_vta_credentials(&args.did_key_id, &vta_creds)?;
    append_allowed_signer(&allowed_signers_entry(&cfg, args.verifying_key))?;
    install_hooks()?;

    Ok(InstallResult {
        config_path,
        ssh_public_key: ssh_public_key_string(args.verifying_key),
        overridden_global_signing_key: None,
        global_committer_email: None,
    })
}

/// Store one more identity without making it the default.
///
/// Its credentials go in the keyring, under its `did:…#key-N`, and its key
/// into did-git-sign's `allowed_signers` file, so `git log --show-signature`
/// recognises its commits. The config file, which names the default
/// identity, is left alone, and no git config is written: the identity signs
/// only in repositories that include its settings (`did-git-sign enable`).
/// Returns its SSH public key line.
pub fn add_identity(args: InstallArgs<'_>) -> Result<String> {
    let cfg = SigningConfig {
        did_key_id: args.did_key_id.clone(),
        user_name: None,
    };
    let vta_creds = VtaCredentials {
        vta_url: args.vta_url,
        vta_did: args.vta_did,
        credential_did: args.credential_did,
        private_key_multibase: args.credential_private_key_mb,
        key_id: args.vta_key_id,
        mediator_did: args.mediator_did,
    };
    config::store_vta_credentials(&args.did_key_id, &vta_creds)?;
    append_allowed_signer(&allowed_signers_entry(&cfg, args.verifying_key))?;
    install_hooks()?;
    Ok(ssh_public_key_string(args.verifying_key))
}

/// Tear down a did-git-sign install for `did_key_id`. Idempotent — every
/// step succeeds (best-effort) when its target is already gone, so the
/// function is safe to run repeatedly or against a partial install.
///
/// The caller decides scope: pass `global = true` to remove the user's
/// `~/.config/did-git-sign/config.json` install, `false` to remove a
/// repo-local `.did-git-sign.json` next to the current directory.
///
/// Returned [`UninstallResult`] is informational — it lists what was
/// touched so callers can render a summary, but never carries a hard
/// failure.
pub fn uninstall(global: bool, did_key_id: &str) -> Result<UninstallResult> {
    let mut summary = UninstallResult::default();
    let data_config = SigningConfig::default_global_path()?;
    let data_signers = crate::enable::allowed_signers_path()?;

    // 1. The config file, only when it names this identity: a profile being
    //    removed must not take the default with it. A repository-local file
    //    from before 0.14 (`.did-git-sign.json`) is removed the same way.
    let mut config_files = vec![data_config.clone()];
    if !global {
        config_files.push(SigningConfig::repo_local_path());
    }
    for path in config_files {
        let ours = SigningConfig::load(&path)
            .map(|c| c.did_key_id == did_key_id)
            .unwrap_or(false);
        if ours {
            match std::fs::remove_file(&path) {
                Ok(()) => summary.removed_config_file = Some(path),
                Err(e) => summary
                    .warnings
                    .push(format!("could not remove {}: {e}", path.display())),
            }
        }
    }

    // 2. The keyring entries keyed by this identity.
    for suffix in [":vta", ":token"] {
        let key = format!("{did_key_id}{suffix}");
        if let Ok(entry) = keyring_core::Entry::new(config::KEYRING_SERVICE, &key) {
            match entry.delete_credential() {
                Ok(()) => summary.removed_keyring_entries.push(key.clone()),
                Err(keyring_core::Error::NoEntry) => {}
                Err(e) => summary
                    .warnings
                    .push(format!("could not remove keyring entry '{key}': {e}")),
            }
        }
        // A copy an older did-git-sign left in the Linux kernel keyring.
        if crate::store::remove_legacy(config::KEYRING_SERVICE, &key)
            && !summary.removed_keyring_entries.contains(&key)
        {
            summary.removed_keyring_entries.push(key);
        }
    }

    // 3. Its line in allowed_signers. Other identities' lines stay.
    let mut signer_files = vec![data_signers.clone()];
    if !global {
        signer_files.push(PathBuf::from("allowed_signers"));
    }
    for signers_path in signer_files {
        match remove_allowed_signer(&signers_path, did_key_id) {
            Ok(true) => summary.allowed_signers_entry_removed = true,
            Ok(false) => {}
            Err(e) => summary.warnings.push(e.to_string()),
        }
    }

    // 4. Its include files, and the lines that include them: every global
    //    `include.path` / `includeIf.*.path`, and this repository's.
    if let Ok(dir) = crate::enable::include_dir()
        && let Ok(entries) = std::fs::read_dir(&dir)
    {
        for entry in entries.flatten() {
            let path = entry.path();
            if crate::enable::include_identity(&path).as_deref() != Some(did_key_id) {
                continue;
            }
            match crate::enable::remove_references(&path) {
                Ok(n) => summary.removed_include_lines += n,
                Err(e) => summary.warnings.push(e.to_string()),
            }
            match std::fs::remove_file(&path) {
                Ok(()) => summary.removed_include_files.push(path),
                Err(e) => summary
                    .warnings
                    .push(format!("could not remove {}: {e}", path.display())),
            }
        }
    }

    // 5. Settings an install before 0.14 wrote directly into git config.
    //    Each is unset only while it still holds the value did-git-sign
    //    wrote, so a signing setup the user has since restored is never
    //    touched. `gpg.format` and `commit.gpgsign` are never unset: they are
    //    as likely to be the user's own as ours.
    let scope = if global { "--global" } else { "--local" };
    let config_str = data_config.to_string_lossy().into_owned();
    let signers_str = data_signers.to_string_lossy().into_owned();
    let legacy_local_config = std::env::current_dir()
        .map(|d| d.join(SigningConfig::repo_local_path()))
        .ok();
    let is_ours = |key: &str, value: &str| -> bool {
        let v = value.trim();
        match key {
            "gpg.ssh.program" => v == "did-git-sign",
            "did-git-sign.key" => v == did_key_id,
            "user.signingKey" | "gpg.ssh.defaultKeyFile" => {
                v == config_str
                    || v == ".did-git-sign.json"
                    || legacy_local_config
                        .as_ref()
                        .is_some_and(|p| Path::new(v) == p.as_path())
            }
            "gpg.ssh.allowedSignersFile" => {
                v == signers_str || Path::new(v).ends_with("did-git-sign/allowed_signers")
            }
            _ => false,
        }
    };
    for key in [
        "user.signingKey",
        "gpg.ssh.program",
        "gpg.ssh.defaultKeyFile",
        "gpg.ssh.allowedSignersFile",
        "did-git-sign.key",
    ] {
        if let Ok(Some(value)) = git_config_get(scope, key)
            && is_ours(key, &value)
            && git_config_unset(scope, key)
        {
            summary.git_config_keys_unset.push(key.to_string());
        }
    }
    match unset_did_git_sign_hooks_path(scope, global) {
        Ok(true) => summary
            .git_config_keys_unset
            .push("core.hooksPath".to_string()),
        Ok(false) => {}
        Err(e) => summary
            .warnings
            .push(format!("could not inspect core.hooksPath: {e}")),
    }

    Ok(summary)
}

/// Remove `did_key_id`'s line from the allowed_signers file at `path`, if
/// there is one. Returns whether a line was removed.
fn remove_allowed_signer(path: &Path, did_key_id: &str) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("could not read {}", path.display()))?;
    let prefix = format!("{did_key_id} ");
    let kept: Vec<&str> = content
        .lines()
        .filter(|l| !l.trim_start().starts_with(&prefix))
        .collect();
    if kept.len() == content.lines().count() {
        return Ok(false);
    }
    let mut new_content = kept.join("\n");
    if !new_content.is_empty() {
        new_content.push('\n');
    }
    // Atomic: a reader must never catch this file mid-truncate and conclude
    // the remaining principals are not allowed to sign.
    write_file_atomic(path, &new_content)
        .with_context(|| format!("could not rewrite {}", path.display()))?;
    Ok(true)
}

/// Outcome of an [`uninstall`] call. None of the variants represent fatal
/// errors — the caller is expected to render `warnings` if it wants to
/// surface partial-state issues to the operator.
#[derive(Debug, Default)]
pub struct UninstallResult {
    /// Path of the SigningConfig file that was removed (if any).
    pub removed_config_file: Option<PathBuf>,
    /// Keyring keys that were deleted (under the `did-git-sign` service).
    pub removed_keyring_entries: Vec<String>,
    /// True when an allowed_signers line for this principal was removed.
    pub allowed_signers_entry_removed: bool,
    /// Git config keys an install before 0.14 had written, unset because
    /// they still held did-git-sign's values.
    pub git_config_keys_unset: Vec<String>,
    /// did-git-sign include files removed (`<config dir>/did-git-sign/gitconfig/`).
    pub removed_include_files: Vec<PathBuf>,
    /// `include.path` / `includeIf.*.path` lines removed that named them.
    pub removed_include_lines: usize,
    /// Best-effort warnings — used for display, not error propagation.
    pub warnings: Vec<String>,
}

/// Returns true if `git config <scope> --unset <key>` removed something.
/// Errors and "key not present" both map to false (best-effort cleanup).
fn git_config_unset(scope: &str, key: &str) -> bool {
    Command::new("git")
        .arg("config")
        .arg(scope)
        .arg("--unset")
        .arg(key)
        .output()
        .ok()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn unset_did_git_sign_hooks_path(scope: &str, global: bool) -> Result<bool> {
    let Some(expected) = expected_hooks_dir(global)? else {
        return Ok(false);
    };
    let Some(configured) = git_config_get(scope, "core.hooksPath")? else {
        return Ok(false);
    };
    if Path::new(configured.trim()) == expected {
        return Ok(git_config_unset(scope, "core.hooksPath"));
    }
    Ok(false)
}

fn expected_hooks_dir(global: bool) -> Result<Option<PathBuf>> {
    if global {
        return Ok(Some(
            dirs::config_dir()
                .context("cannot determine config directory")?
                .join("did-git-sign")
                .join("hooks"),
        ));
    }

    let output = Command::new("git")
        .args(["rev-parse", "--absolute-git-dir"])
        .output()
        .context("failed to find .git directory")?;
    if !output.status.success() {
        return Ok(None);
    }
    let git_dir = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    Ok(Some(git_dir.join("did-git-sign-hooks")))
}

/// Generate an allowed_signers file entry for verification.
pub fn allowed_signers_entry(cfg: &SigningConfig, public_key_bytes: &[u8; 32]) -> String {
    let pub_b64 = base64_encode_pubkey(public_key_bytes);
    format!("{} ssh-ed25519 {}", cfg.did_key_id, pub_b64)
}

/// Replace a file's contents in one step: write a sibling temp file, then
/// rename it over the target.
///
/// `std::fs::write` truncates and then writes, so a reader arriving in between
/// sees an empty or partial file, and two writers racing can interleave. For
/// `allowed_signers` that means a concurrent `git verify-commit` reading no
/// principals — a signature that verifies reported as one that does not — or
/// one `init` losing another's entry. `rename(2)` within a directory is atomic
/// on POSIX: a reader sees either the old file or the new one.
///
/// The temp file is created in the destination directory because rename cannot
/// cross filesystems, and carries the pid so two processes cannot collide on
/// it.
fn write_file_atomic(path: &Path, contents: &str) -> Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("allowed_signers");
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));

    std::fs::write(&tmp, contents).with_context(|| format!("failed to write {}", tmp.display()))?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Do not leave the temp file behind on a failed rename.
            let _ = std::fs::remove_file(&tmp);
            Err(e).with_context(|| format!("failed to replace {}", path.display()))
        }
    }
}

/// Set up the allowed_signers file for signature verification.
/// Add `entry` to did-git-sign's allowed_signers file, unless it is already
/// there. The file is named to git only by the include files, so this
/// changes no git configuration.
pub fn append_allowed_signer(entry: &str) -> Result<()> {
    let signers_path = crate::enable::allowed_signers_path()?;
    if let Some(dir) = signers_path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
    }
    // Read-modify-write is still a race against a *concurrent* init — two
    // personas provisioned at once can still lose one entry — but the write
    // itself never exposes a truncated file to a reader mid-update.
    let existing = std::fs::read_to_string(&signers_path).unwrap_or_default();
    if !existing.contains(entry) {
        let mut content = existing;
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content.push_str(entry);
        content.push('\n');
        write_file_atomic(&signers_path, &content)?;
    }
    Ok(())
}

/// Read one git config value. A missing key is not an error.
fn git_config_get(scope: &str, key: &str) -> Result<Option<String>> {
    let output = Command::new("git")
        .arg("config")
        .arg(scope)
        .arg("--get")
        .arg(key)
        .output()
        .context("failed to run git config")?;

    if output.status.success() {
        return Ok(Some(
            String::from_utf8_lossy(&output.stdout)
                .trim_end_matches(['\r', '\n'])
                .to_string(),
        ));
    }
    if output.status.code() == Some(1) {
        return Ok(None);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    anyhow::bail!("git config {scope} --get {key} failed: {stderr}");
}

/// Format an Ed25519 public key as an SSH public key string (e.g., `ssh-ed25519 AAAA...`).
pub fn ssh_public_key_string(public_key_bytes: &[u8; 32]) -> String {
    format!("ssh-ed25519 {}", base64_encode_pubkey(public_key_bytes))
}

/// Base64-encode a raw Ed25519 public key for SSH authorized_keys format.
fn base64_encode_pubkey(public_key_bytes: &[u8; 32]) -> String {
    use base64::Engine;
    // SSH public key blob: "ssh-ed25519" type string + key bytes
    let mut blob = Vec::new();
    let key_type = b"ssh-ed25519";
    blob.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
    blob.extend_from_slice(key_type);
    blob.extend_from_slice(&(public_key_bytes.len() as u32).to_be_bytes());
    blob.extend_from_slice(public_key_bytes);
    base64::engine::general_purpose::STANDARD.encode(&blob)
}

/// The commit-msg hook script. Reads the DID the same way the signer selects
/// its key — `DID_GIT_SIGN_KEY`, then `did-git-sign.key` git config — and adds
/// a `Signed-by-DID:` trailer if one is not already present. This is how
/// `verify-trust` discovers the signer DID without requiring `user.email` to
/// be a DID.
///
/// Placement is delegated to `git interpret-trailers` rather than done by
/// hand: it finds the final trailer block, inserts the blank line that
/// separates a trailer block from the body, and leaves an existing trailer
/// alone. Appending with `sed` instead was wrong twice over. `sed -i ''` is
/// BSD-only syntax — GNU sed reads the empty argument as a filename, fails,
/// and leaves the file unchanged, so the strip loop that re-tests the same
/// condition spins forever and `git commit` hangs on Linux. And on a
/// one-line message (`git commit -m fix`) the trailer landed glued to the
/// subject line, where git's own parser reads no trailers at all.
///
/// Every `interpret-trailers` call passes `--no-divider` (git ≥ 2.20, 2.19.2). In its
/// default mode `interpret-trailers` takes a `---` line for the start of a
/// patch and works on the paragraph above it, but a commit message has no
/// patch: `git log`'s `%(trailers)` and verify-trust read the message's final
/// paragraph, `---` lines included. Version 1 of this hook omitted the flag,
/// so on any message holding a `---` line — every Dependabot commit — the
/// claim landed where nothing reads it and the commit failed `noSignerDid`.
///
/// `Signed-off-by:` is added only when `did-git-sign.signoff` is true. A DCO
/// sign-off is an assertion the committer makes about their right to submit
/// the code, not one a signing tool may make on their behalf, so it is
/// opt-in.
///
/// Bump [`COMMIT_MSG_HOOK_VERSION`] whenever this script changes behaviour:
/// installed copies are only replaced when the user re-runs `init`, and
/// `did-git-sign health` compares the version it finds against this one.
pub const COMMIT_MSG_HOOK: &str = r#"#!/bin/sh
# Installed by did-git-sign — chains the repo commit-msg hook, then adds the Signed-by-DID trailer.
# did-git-sign-hook-version: 2
git_dir=$(git rev-parse --absolute-git-dir 2>/dev/null) || exit 0
repo_hook="$git_dir/hooks/commit-msg"
if [ -x "$repo_hook" ] && [ "$repo_hook" != "$0" ]; then
    "$repo_hook" "$@" || exit $?
fi

msg_file="$1"
[ -n "$msg_file" ] || exit 0

# Same precedence the signer uses (R-G-1): env var, then per-repo git config.
# They must agree — the hook writes the claim and the signer checks it against
# the key it actually uses, so reading a different selector here would make
# `DID_GIT_SIGN_KEY=… git commit` refuse to sign its own commit.
DID=$(printf '%s' "${DID_GIT_SIGN_KEY:-}" | tr -d '\r\n')
[ -z "$DID" ] && DID=$(git config did-git-sign.key 2>/dev/null)
[ -z "$DID" ] && exit 0
case "$DID" in
    did:*) ;;
    *) exit 0 ;;
esac
case "$DID" in
    *[[:space:]]*)
        echo "did-git-sign: the selected DID contains whitespace; refusing to write a trailer" >&2
        exit 1
        ;;
esac

# Opt-in: a DCO sign-off is the committer's assertion to make, not ours.
if [ "$(git config --bool did-git-sign.signoff 2>/dev/null)" = "true" ]; then
    NAME=$(git config user.name 2>/dev/null | tr -d '\r\n')
    EMAIL=$(git config user.email 2>/dev/null | tr -d '\r\n')
    git interpret-trailers --in-place --no-divider --if-exists doNothing \
        --trailer "Signed-off-by: $NAME <$EMAIL>" "$msg_file" || exit 1
fi

# --no-divider: a commit message has no patch after it, so a `---` line is
# text, and the final paragraph is the trailer block git log and verify-trust
# read. Without it the trailer lands above the first `---`, where nobody looks.
#
# An existing claim is kept (amend, rebase). Existence is tested on the exact
# key rather than with `--if-exists doNothing`, which matches keys by prefix:
# a `Signed-by:` or `S:` trailer would count as a claim and none would be
# written.
existing=$(git interpret-trailers --parse --no-divider "$msg_file") || exit 1
if ! printf '%s\n' "$existing" | grep -qi '^Signed-by-DID:'; then
    git interpret-trailers --in-place --no-divider --where end --if-exists add \
        --trailer "Signed-by-DID: $DID" "$msg_file" || exit 1
fi
"#;

/// The version [`COMMIT_MSG_HOOK`] declares in its
/// `# did-git-sign-hook-version:` line. A did-git-sign hook without that line
/// predates it, and is version 1.
pub const COMMIT_MSG_HOOK_VERSION: u32 = 2;

const HOOK_VERSION_MARKER: &str = "# did-git-sign-hook-version:";
const HOOK_OWNER_MARKER: &str = "Installed by did-git-sign";

/// What `did-git-sign health` found at the commit-msg hook git will run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitMsgHookStatus {
    /// The installed hook is this release's.
    Current { path: PathBuf },
    /// A did-git-sign hook from an older release; re-running `init` replaces
    /// it.
    Outdated {
        path: PathBuf,
        installed: u32,
        current: u32,
    },
    /// A hook from a newer did-git-sign than this binary.
    Newer {
        path: PathBuf,
        installed: u32,
        current: u32,
    },
    /// A commit-msg hook exists but did-git-sign did not write it, so nothing
    /// is known to add the `Signed-by-DID:` trailer.
    Foreign { path: PathBuf },
    /// No commit-msg hook where git will look.
    Missing { path: PathBuf },
    /// Not in a repository and no global `core.hooksPath`: nowhere to look.
    Unknown,
}

/// Classify the text of a commit-msg hook (`None` when there is no file).
fn classify_commit_msg_hook(path: PathBuf, content: Option<&str>) -> CommitMsgHookStatus {
    let Some(content) = content else {
        return CommitMsgHookStatus::Missing { path };
    };
    if !content.contains(HOOK_OWNER_MARKER) {
        return CommitMsgHookStatus::Foreign { path };
    }
    let installed = content
        .lines()
        .find_map(|line| line.trim().strip_prefix(HOOK_VERSION_MARKER))
        .map(|version| version.trim().parse::<u32>().unwrap_or(0))
        .unwrap_or(1);
    let current = COMMIT_MSG_HOOK_VERSION;
    match installed.cmp(&current) {
        std::cmp::Ordering::Equal => CommitMsgHookStatus::Current { path },
        std::cmp::Ordering::Less => CommitMsgHookStatus::Outdated {
            path,
            installed,
            current,
        },
        std::cmp::Ordering::Greater => CommitMsgHookStatus::Newer {
            path,
            installed,
            current,
        },
    }
}

/// Inspect the commit-msg hook git would run from the current directory.
///
/// Inside a repository that is `git rev-parse --git-path hooks/commit-msg`,
/// which honours `core.hooksPath` at every scope, included files too; outside
/// one, the global `core.hooksPath` or did-git-sign's own hook directory.
pub fn commit_msg_hook_status() -> Result<CommitMsgHookStatus> {
    let output = Command::new("git")
        .args(["rev-parse", "--git-path", "hooks/commit-msg"])
        .output()
        .context("failed to run git")?;
    let path = if output.status.success() {
        // Relative to the current directory unless `core.hooksPath` is
        // absolute; made absolute so health can print where it looked.
        let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
        std::env::current_dir()
            .map(|cwd| cwd.join(&path))
            .unwrap_or(path)
    } else {
        // Outside a repository: a global `core.hooksPath` (an install
        // before 0.14), else did-git-sign's own hook directory, which the
        // include files point repositories at.
        match git_config_get("--global", "core.hooksPath")? {
            Some(dir) => PathBuf::from(dir.trim()).join("commit-msg"),
            None => crate::enable::hooks_dir()?.join("commit-msg"),
        }
    };
    let content = std::fs::read_to_string(&path).ok();
    Ok(classify_commit_msg_hook(path, content.as_deref()))
}

const STANDARD_GIT_HOOKS: &[&str] = &[
    "applypatch-msg",
    "commit-msg",
    "fsmonitor-watchman",
    "post-applypatch",
    "post-checkout",
    "post-commit",
    "post-index-change",
    "post-merge",
    "post-receive",
    "post-rewrite",
    "post-update",
    "pre-applypatch",
    "pre-auto-gc",
    "pre-commit",
    "pre-merge-commit",
    "pre-push",
    "pre-rebase",
    "pre-receive",
    "prepare-commit-msg",
    "proc-receive",
    "push-to-checkout",
    "reference-transaction",
    "sendemail-validate",
    "update",
];

fn delegating_hook(hook_name: &str) -> String {
    format!(
        r#"#!/bin/sh
# Installed by did-git-sign — delegates to the repository's {hook_name} hook.
git_dir=$(git rev-parse --absolute-git-dir 2>/dev/null) || exit 0
repo_hook="$git_dir/hooks/{hook_name}"
[ -x "$repo_hook" ] || exit 0
[ "$repo_hook" != "$0" ] || exit 0
exec "$repo_hook" "$@"
"#
    )
}

/// Write the hook dispatcher into did-git-sign's hook directory: a
/// commit-msg hook that adds the `Signed-by-DID:` trailer, and for every
/// other standard hook a stub that runs the repository's own `.git/hooks`
/// one. Git uses it only in repositories whose included settings point
/// `core.hooksPath` here; no git configuration is written.
pub fn install_hooks() -> Result<()> {
    let hooks_dir = crate::enable::hooks_dir()?;
    std::fs::create_dir_all(&hooks_dir)
        .with_context(|| format!("failed to create {}", hooks_dir.display()))?;
    for hook_name in STANDARD_GIT_HOOKS {
        let content = if *hook_name == "commit-msg" {
            COMMIT_MSG_HOOK.to_string()
        } else {
            delegating_hook(hook_name)
        };
        write_executable_hook(&hooks_dir.join(hook_name), &content)?;
    }
    Ok(())
}

fn write_executable_hook(hook_path: &Path, content: &str) -> Result<()> {
    if hook_path.exists() {
        let existing = std::fs::read_to_string(hook_path).unwrap_or_default();
        if existing.contains("Installed by did-git-sign") {
            std::fs::write(hook_path, content)?;
        } else {
            anyhow::bail!(
                "hook already exists at {}; merge manually",
                hook_path.display()
            );
        }
    } else {
        std::fs::write(hook_path, content)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(hook_path, std::fs::Permissions::from_mode(0o755))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_pubkey_format() {
        let key = [0u8; 32];
        let encoded = base64_encode_pubkey(&key);
        // Should be a valid base64 string
        assert!(!encoded.is_empty());

        // Decode and verify structure
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .unwrap();
        // 4 + 11 + 4 + 32 = 51 bytes
        assert_eq!(decoded.len(), 51);
    }

    #[test]
    fn test_allowed_signers_entry_format() {
        let cfg = SigningConfig {
            did_key_id: "did:webvh:abc:example.com#key-0".to_string(),
            user_name: None,
        };
        let key = [0u8; 32];
        let entry = allowed_signers_entry(&cfg, &key);
        assert!(entry.starts_with("did:webvh:abc:example.com#key-0 ssh-ed25519 "));
    }

    #[test]
    fn test_ssh_public_key_string_format() {
        let key = [0u8; 32];
        let result = ssh_public_key_string(&key);
        assert!(result.starts_with("ssh-ed25519 "));
        // The base64 part should be decodable
        let b64_part = result.strip_prefix("ssh-ed25519 ").unwrap();
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64_part).unwrap();
        // 4 + 11 + 4 + 32 = 51 bytes
        assert_eq!(decoded.len(), 51);
    }

    #[test]
    fn test_allowed_signers_entry_contains_valid_ssh_key() {
        let cfg = SigningConfig {
            did_key_id: "did:webvh:test:host#key-0".to_string(),
            user_name: Some("Test User".to_string()),
        };
        let key = [0xFF; 32];
        let entry = allowed_signers_entry(&cfg, &key);

        // Entry should have format: <email> ssh-ed25519 <base64>
        let parts: Vec<&str> = entry.splitn(3, ' ').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "did:webvh:test:host#key-0");
        assert_eq!(parts[1], "ssh-ed25519");
        // Third part is valid base64
        assert!(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, parts[2],).is_ok()
        );
    }

    #[test]
    fn test_base64_pubkey_encodes_key_type_and_bytes() {
        let key = [0x42; 32];
        let encoded = base64_encode_pubkey(&key);
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &encoded).unwrap();

        // Verify SSH wire format: uint32 len + "ssh-ed25519" + uint32 len + key bytes
        assert_eq!(&decoded[0..4], &(11u32).to_be_bytes());
        assert_eq!(&decoded[4..15], b"ssh-ed25519");
        assert_eq!(&decoded[15..19], &(32u32).to_be_bytes());
        assert_eq!(&decoded[19..51], &[0x42; 32]);
    }

    #[test]
    fn remove_allowed_signer_keeps_the_other_principals() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowed_signers");
        std::fs::write(
            &path,
            "did:x:bob#key-0 ssh-ed25519 AAAA\ndid:x:carol#key-0 ssh-ed25519 BBBB\n",
        )
        .unwrap();
        assert!(remove_allowed_signer(&path, "did:x:bob#key-0").unwrap());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "did:x:carol#key-0 ssh-ed25519 BBBB\n"
        );
        assert!(!remove_allowed_signer(&path, "did:x:bob#key-0").unwrap());
        assert!(!remove_allowed_signer(&dir.path().join("absent"), "did:x:bob#key-0").unwrap());
    }

    #[test]
    fn atomic_write_replaces_contents_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowed_signers");

        write_file_atomic(&path, "first\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first\n");

        write_file_atomic(&path, "second\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "second\n",
            "the rename must replace, not append"
        );

        let strays: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n != "allowed_signers")
            .collect();
        assert!(strays.is_empty(), "temp files left behind: {strays:?}");
    }

    /// The property `std::fs::write` could not offer: a reader either sees the
    /// old file or the new one, never a truncated one. Asserted by observing
    /// that the target is never absent or empty across a replace — with
    /// truncate-then-write there is a window where it is both.
    #[test]
    fn atomic_write_never_exposes_a_truncated_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowed_signers");
        let long = "did:webvh:test:host#key-0 ssh-ed25519 AAAA\n".repeat(500);
        write_file_atomic(&path, &long).unwrap();

        for _ in 0..20 {
            write_file_atomic(&path, &long).unwrap();
            let seen = std::fs::read_to_string(&path).expect("target always exists");
            assert_eq!(seen.len(), long.len(), "a reader saw a partial file");
        }
    }

    #[test]
    fn delegating_hook_targets_default_repo_hook_dir() {
        let hook = delegating_hook("pre-push");
        assert!(hook.contains("git rev-parse --absolute-git-dir"));
        assert!(hook.contains("$git_dir/hooks/pre-push"));
        assert!(hook.contains("exec \"$repo_hook\" \"$@\""));
    }

    /// Write `COMMIT_MSG_HOOK` into a throwaway repo and return its path.
    ///
    /// The hook is a shell script, so string assertions about it prove very
    /// little — both bugs this suite now guards (a `sed -i ''` loop that spun
    /// forever under GNU sed, and a trailer appended straight onto a one-line
    /// subject) passed every `contains` check that existed. These tests run it.
    #[cfg(unix)]
    fn repo_with_commit_msg_hook(dir: &Path, did: &str) -> PathBuf {
        for args in [
            vec!["init", "-q"],
            vec!["config", "user.name", "T Ester"],
            vec!["config", "user.email", "t@example.com"],
            vec!["config", "commit.gpgsign", "false"],
            vec!["config", "did-git-sign.key", did],
        ] {
            let out = Command::new("git")
                .args(["-C", dir.to_str().unwrap()])
                .args(&args)
                .output()
                .unwrap();
            assert!(out.status.success(), "git {args:?} failed");
        }

        let hook = dir.join(".git").join("hooks").join("commit-msg");
        std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
        write_executable_hook(&hook, COMMIT_MSG_HOOK).unwrap();
        hook
    }

    /// Ask git — not our own parser — which trailers it can see in HEAD.
    #[cfg(unix)]
    fn git_trailer(dir: &Path, key: &str) -> String {
        let out = Command::new("git")
            .args([
                "-C",
                dir.to_str().unwrap(),
                "log",
                "-1",
                &format!("--format=%(trailers:key={key},valueonly)"),
            ])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// A one-line message is the common case (`git commit -m "fix thing"`),
    /// and it is the case a naive append gets wrong: with no blank line
    /// between subject and trailer, git's own trailer parser reads *nothing*,
    /// so the DID would be invisible to `git log`, to forges, and to every
    /// tool that asks git rather than re-implementing the format.
    // Serial for the same reason as the other hook tests: see the note on
    // `commit_msg_hook_terminates_on_a_message_with_trailing_blank_lines`.
    // Here it is `git commit` that execs the hook, but the race is identical.
    #[test]
    #[cfg(unix)]
    #[serial_test::serial]
    fn commit_msg_hook_trailer_is_readable_by_git_on_a_one_line_message() {
        let dir = tempfile::tempdir().unwrap();
        let did = "did:webvh:QmAbc:example.com#key-0";
        repo_with_commit_msg_hook(dir.path(), did);

        std::fs::write(dir.path().join("f.txt"), "hi").unwrap();
        for args in [vec!["add", "f.txt"], vec!["commit", "-q", "-m", "subject"]] {
            let out = Command::new("git")
                .args(["-C", dir.path().to_str().unwrap()])
                .args(&args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        assert_eq!(
            git_trailer(dir.path(), "Signed-by-DID"),
            did,
            "git itself must parse the trailer the hook wrote"
        );
    }

    /// A message ending in blank lines drove the old strip loop. `sed -i ''`
    /// is BSD syntax; GNU sed reads the empty argument as a filename, fails,
    /// and leaves the file untouched, so the loop re-tested the same condition
    /// forever and `git commit` hung. Termination is the assertion — and it is
    /// bounded, because a regression here hangs rather than fails, and a CI job
    /// that runs to its timeout says much less than one that fails.
    ///
    /// Note this only reproduces where sed is GNU sed: on a BSD userland (macOS)
    /// the old code worked and this test passes either way. CI runs Linux.
    // Serial because this test writes a hook and then execs it, and so do the
    // three below. Run in parallel they fail intermittently with `ETXTBSY`
    // ("Text file busy"), and the test that fails moves between runs.
    //
    // The write is not the problem — `write_executable_hook` closes its handle
    // before returning. The race is across threads: when one test forks a child
    // (any `Command::spawn`) while another still holds its hook open for
    // writing, the child inherits that descriptor for the moment before it
    // execs, and Linux refuses to exec a file any process holds open for
    // writing. Serialising the hook tests removes the overlap.
    //
    // Production is unaffected: there, git execs the hook long after install.
    #[test]
    #[cfg(unix)]
    #[serial_test::serial]
    fn commit_msg_hook_terminates_on_a_message_with_trailing_blank_lines() {
        let dir = tempfile::tempdir().unwrap();
        let did = "did:webvh:QmAbc:example.com#key-0";
        let hook = repo_with_commit_msg_hook(dir.path(), did);

        let msg = dir.path().join("MSG");
        std::fs::write(&msg, "a message\n\n\n\n").unwrap();

        let mut child = Command::new(&hook)
            .arg(&msg)
            .current_dir(dir.path())
            .spawn()
            .unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let status = loop {
            match child.try_wait().unwrap() {
                Some(status) => break status,
                None if std::time::Instant::now() >= deadline => {
                    let _ = child.kill();
                    panic!("commit-msg hook did not terminate — the trailing-blank-line loop spun");
                }
                None => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        };

        assert!(status.success(), "hook failed: {status}");
        assert!(
            std::fs::read_to_string(&msg).unwrap().contains(did),
            "hook must still write the trailer"
        );
    }

    /// Commit `message` through the installed hook and report the claim as
    /// both readers of a commit object see it: git's `%(trailers)` view and
    /// `vgi_core::signer_did`, which is what `verify-trust` checks.
    #[cfg(unix)]
    fn commit_through_hook(dir: &Path, message: &str) -> (String, Option<String>) {
        let msg = dir.join("MSG");
        std::fs::write(&msg, message).unwrap();
        let out = Command::new("git")
            .args(["-C", dir.to_str().unwrap()])
            .args(["commit", "-q", "--allow-empty", "-F", msg.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git commit failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let raw = Command::new("git")
            .args(["-C", dir.to_str().unwrap(), "cat-file", "commit", "HEAD"])
            .output()
            .unwrap()
            .stdout;
        (
            git_trailer(dir, "Signed-by-DID"),
            vgi_core::signer_did(&raw),
        )
    }

    /// A `---` line is a patch divider to `git interpret-trailers` in its
    /// default mode, so the trailer used to land *above* it — in a paragraph
    /// that is not the final one. A commit object has no divider: `git log`'s
    /// `%(trailers)` and verify-trust both read the final paragraph, found no
    /// claim, and the commit failed as `noSignerDid`. Dependabot writes a
    /// `---` line into every message it generates.
    // Serial: `git commit` execs the hook — see the note above.
    #[test]
    #[cfg(unix)]
    #[serial_test::serial]
    fn commit_msg_hook_trailer_lands_in_the_final_block_past_a_divider() {
        let dir = tempfile::tempdir().unwrap();
        let did = "did:webvh:QmAbc:example.com#key-0";
        repo_with_commit_msg_hook(dir.path(), did);

        let messages = [
            // Dependabot's shape.
            "chore(deps): bump yaml-rust2 from 0.11.1 to 0.13.0\n\n\
             Bumps yaml-rust2 from 0.11.1 to 0.13.0.\n\
             ---\n\
             updated-dependencies:\n\
             - dependency-name: yaml-rust2\n  dependency-version: 0.13.0\n",
            // A divider followed by a diff-like body.
            "fix the thing\n\nexplanation\n\n---\n\
             diff --git a/f b/f\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-a\n+b\n",
            // A divider as the last line.
            "subject\n\nbody\n---\n",
        ];
        for message in messages {
            let (logged, verified) = commit_through_hook(dir.path(), message);
            assert_eq!(
                logged, did,
                "git log must see the claim; message: {message:?}"
            );
            assert_eq!(
                verified.as_deref(),
                Some("did:webvh:QmAbc:example.com"),
                "verify-trust must see the claim; message: {message:?}"
            );
        }
    }

    /// When the final paragraph already names a DID, `--if-exists doNothing`
    /// keeps it — and it is the claim the verifier reads, so the signer's
    /// mismatch check (not a silent divergence) is what catches it. The old
    /// hook put its own trailer above the divider instead, where nothing reads
    /// it, and verify-trust checked the stale one below.
    // Serial: `git commit` execs the hook — see the note above.
    #[test]
    #[cfg(unix)]
    #[serial_test::serial]
    fn commit_msg_hook_and_verifier_agree_on_an_existing_claim_past_a_divider() {
        let dir = tempfile::tempdir().unwrap();
        repo_with_commit_msg_hook(dir.path(), "did:webvh:QmAbc:example.com#key-0");

        let (logged, verified) = commit_through_hook(
            dir.path(),
            "subject\n\nbody\n---\nquoted\n\nSigned-by-DID: did:webvh:QmOld:example.com\n",
        );
        assert_eq!(logged, "did:webvh:QmOld:example.com");
        assert_eq!(verified.as_deref(), Some("did:webvh:QmOld:example.com"));
        let out = Command::new("git")
            .args([
                "-C",
                dir.path().to_str().unwrap(),
                "log",
                "-1",
                "--format=%B",
            ])
            .output()
            .unwrap();
        let body = String::from_utf8_lossy(&out.stdout);
        assert!(
            !body.contains("QmAbc"),
            "doNothing must not add a second, unread claim: {body}"
        );
    }

    /// `--if-exists doNothing` matches trailer keys by prefix, so a final
    /// block holding `Signed-by:` (or `S:`) used to count as an existing claim
    /// and the hook wrote none.
    // Serial: `git commit` execs the hook — see the note above.
    #[test]
    #[cfg(unix)]
    #[serial_test::serial]
    fn commit_msg_hook_is_not_fooled_by_a_key_that_prefixes_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let did = "did:webvh:QmAbc:example.com#key-0";
        repo_with_commit_msg_hook(dir.path(), did);

        for message in [
            "subject\n\nSigned-by: someone\n",
            "subject\n\nS: x\n",
            "subject\n\nSigned-by-DIDX: x\n",
        ] {
            let (logged, verified) = commit_through_hook(dir.path(), message);
            assert_eq!(logged, did, "message: {message:?}");
            assert_eq!(
                verified.as_deref(),
                Some("did:webvh:QmAbc:example.com"),
                "message: {message:?}"
            );
        }
    }

    #[test]
    fn the_hook_declares_the_current_version() {
        assert!(COMMIT_MSG_HOOK.contains(&format!(
            "{HOOK_VERSION_MARKER} {COMMIT_MSG_HOOK_VERSION}\n"
        )));
        assert_eq!(
            classify_commit_msg_hook(PathBuf::from("h"), Some(COMMIT_MSG_HOOK)),
            CommitMsgHookStatus::Current {
                path: PathBuf::from("h")
            }
        );
    }

    /// The hook every release before the version marker installed.
    #[test]
    fn a_hook_without_a_version_marker_is_outdated() {
        let v1 = "#!/bin/sh\n# Installed by did-git-sign — chains the repo commit-msg hook, \
                  then adds the Signed-by-DID trailer.\n\
                  git interpret-trailers --in-place --if-exists doNothing \\\n";
        assert_eq!(
            classify_commit_msg_hook(PathBuf::from("h"), Some(v1)),
            CommitMsgHookStatus::Outdated {
                path: PathBuf::from("h"),
                installed: 1,
                current: COMMIT_MSG_HOOK_VERSION,
            }
        );
    }

    #[test]
    fn hook_classification_covers_missing_foreign_and_newer() {
        let path = PathBuf::from("h");
        assert_eq!(
            classify_commit_msg_hook(path.clone(), None),
            CommitMsgHookStatus::Missing { path: path.clone() }
        );
        assert_eq!(
            classify_commit_msg_hook(path.clone(), Some("#!/bin/sh\nnpx commitlint\n")),
            CommitMsgHookStatus::Foreign { path: path.clone() }
        );
        let newer = COMMIT_MSG_HOOK.replace(
            &format!("{HOOK_VERSION_MARKER} {COMMIT_MSG_HOOK_VERSION}"),
            &format!("{HOOK_VERSION_MARKER} {}", COMMIT_MSG_HOOK_VERSION + 1),
        );
        assert_eq!(
            classify_commit_msg_hook(path.clone(), Some(&newer)),
            CommitMsgHookStatus::Newer {
                path,
                installed: COMMIT_MSG_HOOK_VERSION + 1,
                current: COMMIT_MSG_HOOK_VERSION,
            }
        );
    }

    /// Health finds the hook through `core.hooksPath`, as git does.
    #[test]
    #[serial_test::serial]
    fn commit_msg_hook_status_follows_core_hooks_path() {
        let dir = tempfile::tempdir().unwrap();
        let hooks = dir.path().join("my-hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        for args in [
            vec!["init", "-q"],
            vec!["config", "core.hooksPath", hooks.to_str().unwrap()],
        ] {
            assert!(
                Command::new("git")
                    .args(["-C", dir.path().to_str().unwrap()])
                    .args(&args)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let _cwd = CwdGuard::change_to(dir.path());
        let status = commit_msg_hook_status().unwrap();
        let CommitMsgHookStatus::Missing { path } = status else {
            panic!("expected Missing, got {status:?}");
        };
        assert_eq!(
            path.parent().unwrap().canonicalize().unwrap(),
            hooks.canonicalize().unwrap()
        );

        std::fs::write(hooks.join("commit-msg"), COMMIT_MSG_HOOK).unwrap();
        assert!(matches!(
            commit_msg_hook_status().unwrap(),
            CommitMsgHookStatus::Current { .. }
        ));
    }

    /// Running twice must not stack duplicate trailers — amends and rebases
    /// re-run the hook over a message that already carries one.
    // Serial: writes a hook and execs it — see the note above.
    #[test]
    #[cfg(unix)]
    #[serial_test::serial]
    fn commit_msg_hook_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let did = "did:webvh:QmAbc:example.com#key-0";
        let hook = repo_with_commit_msg_hook(dir.path(), did);

        let msg = dir.path().join("MSG");
        std::fs::write(&msg, "subject\n").unwrap();
        for _ in 0..2 {
            assert!(
                Command::new(&hook)
                    .arg(&msg)
                    .current_dir(dir.path())
                    .status()
                    .unwrap()
                    .success()
            );
        }

        let body = std::fs::read_to_string(&msg).unwrap();
        assert_eq!(
            body.matches("Signed-by-DID:").count(),
            1,
            "trailer must not be duplicated: {body}"
        );
    }

    /// A DCO sign-off asserts something about the committer's right to submit
    /// the code. The signing tool must not assert it for them, so the trailer
    /// is opt-in via `did-git-sign.signoff`.
    // Serial: writes a hook and execs it twice — see the note above.
    #[test]
    #[cfg(unix)]
    #[serial_test::serial]
    fn commit_msg_hook_adds_signoff_only_when_opted_in() {
        let dir = tempfile::tempdir().unwrap();
        let did = "did:webvh:QmAbc:example.com#key-0";
        let hook = repo_with_commit_msg_hook(dir.path(), did);
        let msg = dir.path().join("MSG");

        std::fs::write(&msg, "subject\n").unwrap();
        Command::new(&hook)
            .arg(&msg)
            .current_dir(dir.path())
            .status()
            .unwrap();
        assert!(
            !std::fs::read_to_string(&msg)
                .unwrap()
                .contains("Signed-off-by:"),
            "sign-off must not be added by default"
        );

        assert!(
            Command::new("git")
                .args([
                    "-C",
                    dir.path().to_str().unwrap(),
                    "config",
                    "did-git-sign.signoff",
                    "true",
                ])
                .status()
                .unwrap()
                .success()
        );
        std::fs::write(&msg, "subject\n").unwrap();
        Command::new(&hook)
            .arg(&msg)
            .current_dir(dir.path())
            .status()
            .unwrap();
        assert!(
            std::fs::read_to_string(&msg)
                .unwrap()
                .contains("Signed-off-by:"),
            "sign-off must be added once opted in"
        );
    }

    /// `core.hooksPath` is a single slot that husky, lefthook and pre-commit
    /// also claim. The dispatcher's delegating hooks fall back to
    /// `$git_dir/hooks`, never to a previously configured path, so taking the
    /// slot would silently stop every hook that tool installed.
    #[test]
    #[serial_test::serial]
    fn enable_refuses_to_take_a_local_hooks_path_it_does_not_own() {
        let dir = tempfile::tempdir().unwrap();
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["-C", dir.path().to_str().unwrap()])
            .args(["config", "core.hooksPath", ".husky"])
            .output()
            .unwrap();

        let err = {
            let _cwd = CwdGuard::change_to(dir.path());
            let include = crate::enable::include_path("test").unwrap();
            crate::enable::enable_repo(&include)
                .unwrap_err()
                .to_string()
        };
        assert!(err.contains(".husky"), "names the path it refused: {err}");

        // It left that configuration alone, and added no include.
        let get = |key: &str| {
            let out = Command::new("git")
                .args(["-C", dir.path().to_str().unwrap()])
                .args(["config", "--local", "--get-all", key])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        assert_eq!(get("core.hooksPath"), ".husky");
        assert_eq!(get("include.path"), "");
    }

    /// Enabling a repository adds exactly one `include.path` line; enabling
    /// another identity replaces it; disabling removes it and leaves every
    /// other setting, other includes included, as it was.
    #[test]
    #[serial_test::serial]
    fn enable_and_disable_touch_only_their_own_include_line() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap().to_string();
        let git = |args: &[&str]| {
            Command::new("git")
                .args(["-C", &d])
                .args(args)
                .output()
                .unwrap()
        };
        git(&["init", "-q"]);
        git(&["config", "user.signingKey", "~/.ssh/id_ed25519.pub"]);
        git(&["config", "--add", "include.path", "/somewhere/else.inc"]);
        let local =
            || String::from_utf8_lossy(&git(&["config", "--local", "--list"]).stdout).to_string();
        let before = local();

        let bob = crate::enable::include_path("bob").unwrap();
        let carol = crate::enable::include_path("carol").unwrap();
        let _cwd = CwdGuard::change_to(dir.path());

        crate::enable::enable_repo(&bob).unwrap();
        assert_eq!(crate::enable::repo_include(), Some(bob.clone()));
        crate::enable::enable_repo(&carol).unwrap();
        assert_eq!(crate::enable::repo_include(), Some(carol.clone()));
        let includes = String::from_utf8_lossy(
            &git(&["config", "--local", "--get-all", "include.path"]).stdout,
        )
        .to_string();
        assert_eq!(
            includes.lines().collect::<Vec<_>>(),
            vec!["/somewhere/else.inc", carol.to_str().unwrap()],
            "one did-git-sign include, and the other include kept"
        );

        assert!(crate::enable::disable_repo().unwrap());
        assert_eq!(local(), before, "disable restores the config exactly");
        assert!(!crate::enable::disable_repo().unwrap());
    }

    #[test]
    fn commit_msg_hook_chains_before_adding_signed_by_did() {
        let chain_pos = COMMIT_MSG_HOOK.find("repo_hook=").unwrap();
        let did_pos = COMMIT_MSG_HOOK
            .find("DID=$(git config did-git-sign.key")
            .unwrap();
        assert!(chain_pos < did_pos);
        assert!(COMMIT_MSG_HOOK.contains("$git_dir/hooks/commit-msg"));
        assert!(COMMIT_MSG_HOOK.contains("Signed-by-DID: $DID"));
    }

    #[test]
    fn test_different_keys_produce_different_ssh_strings() {
        let key_a = [0x00; 32];
        let key_b = [0xFF; 32];
        assert_ne!(ssh_public_key_string(&key_a), ssh_public_key_string(&key_b));
    }

    /// Changes the process CWD on construction, restores it on drop (panic-safe).
    /// Requires `#[serial_test::serial]` — CWD is process-global.
    /// **Any future non-serial test that uses a relative path or calls
    /// `current_dir()` will silently resolve against the wrong directory.**
    struct CwdGuard {
        original: std::path::PathBuf,
    }

    impl CwdGuard {
        fn change_to(path: &std::path::Path) -> Self {
            let original = std::env::current_dir().unwrap();
            std::env::set_current_dir(path).unwrap();
            CwdGuard { original }
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            // Best-effort restore; ignore errors (e.g. if the temp dir was already removed).
            let _ = std::env::set_current_dir(&self.original);
        }
    }
}
