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

    let config_path = if args.global {
        SigningConfig::default_global_path()?
    } else {
        SigningConfig::repo_local_path()
    };

    cfg.save(&config_path)?;
    config::store_vta_credentials(&args.did_key_id, &vta_creds)?;

    setup_git(&config_path, &cfg, args.global)?;

    let entry = allowed_signers_entry(&cfg, args.verifying_key);
    let config_dir = config_path.parent().unwrap_or(Path::new("."));
    setup_allowed_signers(config_dir, &entry, args.global)?;

    // Install the hook dispatcher that injects the Signed-by-DID trailer while
    // preserving any repository hooks shadowed by core.hooksPath.
    //
    // Non-fatal, because the rest of the install is still worth keeping — but
    // loudly so. Without the hook, commits carry no DID claim, and `sign`
    // refuses them rather than writing something CI would reject as
    // `noSignerDid`. Saying only "no trailer" would understate that: signing
    // does not degrade here, it stops.
    if let Err(e) = install_hook_dispatcher(args.global) {
        eprintln!(
            "warning: could not install the git hook that writes the Signed-by-DID trailer:\n  \
             {e}\n  \
             Until this is resolved, `git commit` will refuse to sign in this repository: \
             a commit with no DID claim cannot be verified. Resolve the conflict above and \
             re-run `did-git-sign init`, or set user.email to '{}' as the legacy claim.",
            cfg.did_key_id
        );
    }

    // If we just shadowed a global user.signingKey with a local one, tell
    // the caller so they can surface it. Best-effort — failures here are
    // non-fatal.
    let overridden_global_signing_key = (!args.global)
        .then(|| {
            std::process::Command::new("git")
                .args(["config", "--global", "user.signingKey"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .flatten();

    Ok(InstallResult {
        config_path,
        ssh_public_key: ssh_public_key_string(args.verifying_key),
        overridden_global_signing_key,
        global_committer_email: args.global.then(|| cfg.did_key_id.clone()),
    })
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

    let config_path = if global {
        SigningConfig::default_global_path()?
    } else {
        SigningConfig::repo_local_path()
    };

    // 1. Remove SigningConfig JSON file (silently if absent).
    if config_path.exists() {
        match std::fs::remove_file(&config_path) {
            Ok(()) => {
                summary.removed_config_file = Some(config_path.clone());
            }
            Err(e) => {
                summary
                    .warnings
                    .push(format!("could not remove {}: {e}", config_path.display()));
            }
        }
    }

    // 2. Drop the keyring entries that are keyed by did_key_id. The
    //    `delete_credential` API errors when the entry doesn't exist —
    //    swallow that case.
    for suffix in [":vta", ":token"] {
        let key = format!("{did_key_id}{suffix}");
        if let Ok(entry) = keyring_core::Entry::new(config::KEYRING_SERVICE, &key) {
            match entry.delete_credential() {
                Ok(()) => summary.removed_keyring_entries.push(key),
                Err(keyring_core::Error::NoEntry) => {}
                Err(e) => {
                    summary
                        .warnings
                        .push(format!("could not remove keyring entry '{key}': {e}"));
                }
            }
        }
    }

    // 3. Strip the matching line out of allowed_signers (if the file
    //    exists and contains an entry for this principal). Other principals
    //    in the same file are preserved.
    let signers_path = config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("allowed_signers");
    if signers_path.exists() {
        match std::fs::read_to_string(&signers_path) {
            Ok(content) => {
                let prefix = format!("{did_key_id} ");
                let mut kept = Vec::new();
                let mut removed = false;
                for line in content.lines() {
                    if line.trim_start().starts_with(&prefix) {
                        removed = true;
                    } else {
                        kept.push(line);
                    }
                }
                if removed {
                    let mut new_content = kept.join("\n");
                    if !new_content.is_empty() {
                        new_content.push('\n');
                    }
                    // Atomic for the same reason as the install path: a reader
                    // must never catch this file mid-truncate and conclude the
                    // remaining principals are not allowed to sign.
                    if let Err(e) = write_file_atomic(&signers_path, &new_content) {
                        summary
                            .warnings
                            .push(format!("could not rewrite {}: {e}", signers_path.display()));
                    } else {
                        summary.allowed_signers_entry_removed = true;
                    }
                }
            }
            Err(e) => {
                summary
                    .warnings
                    .push(format!("could not read {}: {e}", signers_path.display()));
            }
        }
    }

    // 4. Unset the git config keys we own at the install scope. Best
    //    effort — `git config --unset` errors when the key isn't set,
    //    which we ignore.
    let scope = if global { "--global" } else { "--local" };
    for key in [
        "user.signingKey",
        "gpg.format",
        "gpg.ssh.program",
        "gpg.ssh.defaultKeyFile",
        "gpg.ssh.allowedSignersFile",
        "commit.gpgsign",
        "did-git-sign.key",
    ] {
        if git_config_unset(scope, key) {
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
    /// Git config keys that were unset at the install scope.
    pub git_config_keys_unset: Vec<String>,
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

/// Initialize git configuration for DID-based SSH signing.
pub fn setup_git(config_path: &Path, cfg: &SigningConfig, global: bool) -> Result<()> {
    let scope = if global { "--global" } else { "--local" };
    let config_path_str = config_path
        .to_str()
        .context("config path is not valid UTF-8")?;

    // Set gpg format to ssh
    git_config(scope, "gpg.format", "ssh")?;

    // Set our tool as the signing program
    // Git calls: <program> -Y sign -f <user.signingKey or defaultKeyFile> -n git
    git_config(scope, "gpg.ssh.program", "did-git-sign")?;

    // Point git to our config file as both the signing key and the fallback key file.
    // user.signingKey takes precedence over gpg.ssh.defaultKeyFile when set, so we
    // must set it here to override any global user.signingKey (e.g. an SSH public key)
    // that would otherwise be passed as -f and cause a config parse error.
    //
    // NOTE: user.signingKey is conventionally a .pub path; using a .json path here
    // is unconventional. Third-party tools inspecting this repo's git config will
    // see a non-.pub value. This is an accepted trade-off — the local override is
    // the only non-destructive way to win over a global user.signingKey without
    // modifying the user's global git configuration.
    git_config(scope, "user.signingKey", config_path_str)?;
    git_config(scope, "gpg.ssh.defaultKeyFile", config_path_str)?;

    // Enable commit signing by default
    git_config(scope, "commit.gpgsign", "true")?;

    // The committer identity IS the DID claim. With the Signed-by-DID trailer
    // flow, the DID is injected as a trailer by the commit-msg hook rather
    // than set as user.email. This lets user.email stay a normal email for
    // git-host attribution (GitLab/GitHub account linking).
    //
    // For backwards compatibility, also store the DID in did-git-sign.key
    // git config so the hook can read it.
    git_config(scope, "did-git-sign.key", &cfg.did_key_id)?;

    // Optionally set user.name
    if let Some(name) = &cfg.user_name {
        git_config(scope, "user.name", name)?;
    }

    Ok(())
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
pub fn setup_allowed_signers(config_dir: &Path, entry: &str, global: bool) -> Result<()> {
    let signers_path = config_dir.join("allowed_signers");
    let signers_path_str = signers_path
        .to_str()
        .context("signers path is not valid UTF-8")?;

    // Append or create the allowed_signers file. Read-modify-write is still a
    // race against a *concurrent* init — two personas provisioned at once can
    // still lose one entry — but the write itself no longer exposes a
    // truncated file to a reader mid-update.
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

    let scope = if global { "--global" } else { "--local" };
    git_config(scope, "gpg.ssh.allowedSignersFile", signers_path_str)?;

    Ok(())
}

/// Run `git config <scope> <key> <value>`.
fn git_config(scope: &str, key: &str, value: &str) -> Result<()> {
    let output = Command::new("git")
        .arg("config")
        .arg(scope)
        .arg(key)
        .arg(value)
        .output()
        .context("failed to run git config")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git config {scope} {key} failed: {stderr}");
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
/// `Signed-off-by:` is added only when `did-git-sign.signoff` is true. A DCO
/// sign-off is an assertion the committer makes about their right to submit
/// the code, not one a signing tool may make on their behalf, so it is
/// opt-in.
const COMMIT_MSG_HOOK: &str = r#"#!/bin/sh
# Installed by did-git-sign — chains the repo commit-msg hook, then adds the Signed-by-DID trailer.
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
    git interpret-trailers --in-place --if-exists doNothing \
        --trailer "Signed-off-by: $NAME <$EMAIL>" "$msg_file" || exit 1
fi

git interpret-trailers --in-place --if-exists doNothing \
    --trailer "Signed-by-DID: $DID" "$msg_file" || exit 1
"#;

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

/// Install the hook dispatcher that injects the `Signed-by-DID:` trailer while
/// delegating every other standard Git hook back to the repository's default
/// `.git/hooks` directory.
///
/// For a **local** install, writes to `.git/did-git-sign-hooks/` in the current
/// repo and sets repo-local `core.hooksPath`. For a **global** install, writes
/// to `~/.config/did-git-sign/hooks/` and sets global `core.hooksPath` (git
/// 2.9+). The original `.git/hooks` directory remains the source for repository
/// hooks, including hooks added after did-git-sign is installed.
fn install_hook_dispatcher(global: bool) -> Result<()> {
    let hooks_dir = expected_hooks_dir(global)?
        .context("not inside a git repository — cannot install hook dispatcher")?;
    let scope = if global { "--global" } else { "--local" };

    // `core.hooksPath` is a single slot, and husky, lefthook and pre-commit
    // all claim it. Taking it from one of them is silent breakage: the
    // delegating hooks below fall back to `$git_dir/hooks`, never to whatever
    // was configured here before, so every hook that tool installed simply
    // stops running. Refuse in both scopes — the local case is the common one.
    if let Some(existing) = git_config_get(scope, "core.hooksPath")?
        && Path::new(existing.trim()) != hooks_dir
    {
        anyhow::bail!(
            "{scope} core.hooksPath is already set to '{existing}'; refusing to overwrite it. \
             Unset it, or add the Signed-by-DID trailer logic to that directory's commit-msg \
             hook manually."
        );
    }

    let hooks_dir_str = hooks_dir
        .to_str()
        .context("hooks directory path is not valid UTF-8")?
        .to_string();

    // Populate the directory *before* pointing git at it. `write_executable_hook`
    // refuses to clobber a hook it did not write, so this loop can fail partway;
    // if `core.hooksPath` already named this directory by then, the hooks that
    // were never written would silently stop running instead of the install
    // failing cleanly with the old configuration still intact.
    std::fs::create_dir_all(&hooks_dir)?;
    for hook_name in STANDARD_GIT_HOOKS {
        let hook_path = hooks_dir.join(hook_name);
        let content = if *hook_name == "commit-msg" {
            COMMIT_MSG_HOOK.to_string()
        } else {
            delegating_hook(hook_name)
        };

        write_executable_hook(&hook_path, &content)?;
    }

    git_config(scope, "core.hooksPath", &hooks_dir_str)?;

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
    fn test_setup_allowed_signers_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let entry = "did:webvh:test:host#key-0 ssh-ed25519 AAAA";

        // We cannot test the git config part without a git repo, but we can test
        // the file-writing portion by calling the function in a git repo context.
        // Instead, verify the file-writing logic directly:
        let signers_path = dir.path().join("allowed_signers");
        let content = format!("{entry}\n");
        std::fs::write(&signers_path, &content).unwrap();

        let read_back = std::fs::read_to_string(&signers_path).unwrap();
        assert!(read_back.contains(entry));
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
    fn install_hook_dispatcher_refuses_to_take_a_local_hooks_path_it_does_not_own() {
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
            install_hook_dispatcher(false).unwrap_err().to_string()
        };
        assert!(err.contains(".husky"), "names the path it refused: {err}");

        // And it must have left that configuration alone.
        let out = Command::new("git")
            .args(["-C", dir.path().to_str().unwrap()])
            .args(["config", "--local", "core.hooksPath"])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), ".husky");
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

    /// `setup_git` must write the signing DID into `did-git-sign.key` git
    /// config so the commit-msg hook can read it and inject the
    /// `Signed-by-DID:` trailer. Previously the DID was written to
    /// `user.email`, but that broke git-host attribution (GitLab/GitHub
    /// account linking).
    #[test]
    #[serial_test::serial]
    fn setup_git_writes_did_to_git_config_key() {
        let dir = tempfile::tempdir().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .unwrap();

        let original_cwd = std::env::current_dir().unwrap();
        {
            let _cwd = CwdGuard::change_to(dir.path());
            let config_path = dir.path().join(".did-git-sign.json");
            let cfg = SigningConfig {
                did_key_id: "did:webvh:test#key-0".to_string(),
                user_name: None,
            };
            setup_git(&config_path, &cfg, false).unwrap();
        }
        assert_eq!(
            std::env::current_dir().unwrap(),
            original_cwd,
            "CwdGuard must restore the original directory on drop"
        );

        // did-git-sign.key must carry the signing DID for the commit-msg hook.
        let out = std::process::Command::new("git")
            .args([
                "-C",
                dir.path().to_str().unwrap(),
                "config",
                "--local",
                "did-git-sign.key",
            ])
            .output()
            .unwrap();

        assert!(
            out.status.success(),
            "did-git-sign.key must be set by setup_git"
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "did:webvh:test#key-0",
        );

        // user.email must NOT be overwritten to a DID.
        let email_out = std::process::Command::new("git")
            .args([
                "-C",
                dir.path().to_str().unwrap(),
                "config",
                "--local",
                "user.email",
            ])
            .output()
            .unwrap();

        if email_out.status.success() {
            let email = String::from_utf8_lossy(&email_out.stdout)
                .trim()
                .to_string();
            assert!(
                !email.starts_with("did:"),
                "user.email must not be set to a DID (got {email})"
            );
        }
    }
}
