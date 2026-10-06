//! Which credential store did-git-sign keeps its VTA credentials in.
//!
//! OpenVTC writes the signing credential through this crate's
//! [`crate::config`] into whatever store *it* registered, and the
//! `did-git-sign` binary then reads it back from the store *it* registered —
//! so the two must pick the same store, or signing reports "no credentials"
//! for a credential that is sitting one store over.
//!
//! The selection is therefore OpenVTC's, verbatim:
//!
//! - default: [`vta_sdk::keyring_init::install_default_store`] — macOS
//!   Keychain, Windows Credential Manager, and on Linux the DBus Secret
//!   Service (GNOME Keyring / KWallet / KeePassXC). This is what OpenVTC, pnm
//!   and cnm install.
//! - `OPENVTC_SECURE_STORE=keyutils` (Linux): the kernel keyring, which OpenVTC
//!   also offers as a migration-only mode. RAM-only: lost on reboot.
//! - `OPENVTC_SECURE_STORE=file`: refused. OpenVTC's encrypted file store lives
//!   in `openvtc-core`, which this crate cannot depend on, and that store only
//!   accepts passphrase-encrypted profile blobs — OpenVTC cannot keep the
//!   signing credential there either.
//!
//! did-git-sign 0.18.1 and earlier used the kernel keyring on Linux
//! unconditionally; [`recover_legacy`] reads a credential left there and
//! copies it into the platform store.

use std::sync::OnceLock;

/// The environment variable OpenVTC reads to override its store. Honoured
/// here so a user who set it for OpenVTC gets the same store in git signing.
pub const OVERRIDE_ENV: &str = "OPENVTC_SECURE_STORE";

/// The store a process selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// The platform store, per `vta_sdk::keyring_init::install_default_store`.
    Platform,
    /// The Linux kernel keyring (keyutils). Migration only.
    KernelKeyring,
}

static ACTIVE: OnceLock<Selection> = OnceLock::new();

/// Read an `OPENVTC_SECURE_STORE` value. Same accepted values as OpenVTC: an
/// empty value is the platform store; anything unrecognised is an error rather
/// than a silent default.
pub fn parse_override(raw: &str) -> Result<Selection, String> {
    match raw {
        "" => Ok(Selection::Platform),
        "keyutils" if cfg!(target_os = "linux") => Ok(Selection::KernelKeyring),
        "keyutils" => Err(format!(
            "{OVERRIDE_ENV}=keyutils selects the Linux kernel keyring, which this platform \
             does not have. Unset {OVERRIDE_ENV} to use the OS credential store."
        )),
        "file" => Err(format!(
            "{OVERRIDE_ENV}=file selects OpenVTC's encrypted file store, which did-git-sign \
             cannot read (it belongs to openvtc-core and holds only passphrase-encrypted \
             profile data, so OpenVTC does not keep the signing credential there either). \
             Unset {OVERRIDE_ENV} for did-git-sign to use the OS credential store, or set \
             {OVERRIDE_ENV}=keyutils on Linux for the kernel keyring (lost on reboot)."
        )),
        other => Err(format!(
            "unknown {OVERRIDE_ENV}={other}. Leave it unset to use the OS credential store \
             (the same one OpenVTC uses)."
        )),
    }
}

/// Human name for a store, for error text: a missing credential must say
/// *where* it was looked for, so a mismatch between two tools is diagnosable.
pub fn describe(selection: Selection) -> &'static str {
    match selection {
        Selection::KernelKeyring => "Linux kernel keyring (keyutils)",
        Selection::Platform => platform_name(),
    }
}

fn platform_name() -> &'static str {
    if cfg!(target_os = "linux") {
        "Secret Service (DBus)"
    } else if cfg!(target_os = "macos") {
        "macOS Keychain"
    } else if cfg!(target_os = "windows") {
        "Windows Credential Manager"
    } else {
        "OS credential store"
    }
}

/// The store this process reads and writes credentials in, by name.
///
/// When the host registered its own store (OpenVTC calls this crate as a
/// library after installing the store itself), names it from the store's
/// vendor string instead.
pub fn describe_active() -> String {
    if let Some(sel) = ACTIVE.get() {
        return describe(*sel).to_string();
    }
    match keyring_core::get_default_store() {
        Some(store) => store.vendor(),
        None => "OS credential store (none registered)".to_string(),
    }
}

/// The selection made by [`install`] in this process, if it ran.
pub fn active() -> Option<Selection> {
    ACTIVE.get().copied()
}

/// Register the credential store as keyring-core's default. Must run before
/// any `keyring_core::Entry::new`.
pub fn install() -> anyhow::Result<()> {
    let raw = match std::env::var(OVERRIDE_ENV) {
        Ok(v) => v,
        Err(std::env::VarError::NotPresent) => String::new(),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("{OVERRIDE_ENV} is not valid UTF-8")
        }
    };
    let selection = parse_override(&raw).map_err(anyhow::Error::msg)?;
    match selection {
        Selection::Platform => {
            vta_sdk::keyring_init::install_default_store().map_err(|e| {
                anyhow::anyhow!("could not open the {}: {e}", platform_name())
            })?;
        }
        Selection::KernelKeyring => install_kernel_keyring()?,
    }
    let _ = ACTIVE.set(selection);
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_kernel_keyring() -> anyhow::Result<()> {
    let store = linux_keyutils_keyring_store::Store::new()
        .map_err(|e| anyhow::anyhow!("could not open the Linux kernel keyring: {e}"))?;
    keyring_core::set_default_store(store);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn install_kernel_keyring() -> anyhow::Result<()> {
    unreachable!("parse_override refuses keyutils off Linux")
}
