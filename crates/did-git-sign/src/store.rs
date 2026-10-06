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
            vta_sdk::keyring_init::install_default_store()
                .map_err(|e| anyhow::anyhow!("could not open the {}: {e}", platform_name()))?;
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

/// What [`copy_from_legacy`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum LegacyLookup {
    /// The legacy store has no such entry.
    Absent,
    /// Found and copied into the primary store.
    Migrated(String),
    /// Found, but the copy into the primary store failed (reason attached).
    /// The value is still usable for this run.
    FoundNotCopied(String, String),
}

/// Look `service`/`user` up in `legacy` and, if present, copy it into
/// `primary`. The legacy entry is left in place: the kernel keyring forgets it
/// at reboot anyway, and leaving it means a failed copy loses nothing.
pub fn copy_from_legacy(
    primary: &keyring_core::api::CredentialStore,
    legacy: &keyring_core::api::CredentialStore,
    service: &str,
    user: &str,
) -> keyring_core::Result<LegacyLookup> {
    let value = match legacy.build(service, user, None)?.get_password() {
        Ok(v) => v,
        Err(keyring_core::Error::NoEntry) => return Ok(LegacyLookup::Absent),
        Err(e) => return Err(e),
    };
    let copied = primary
        .build(service, user, None)
        .and_then(|entry| entry.set_password(&value));
    Ok(match copied {
        Ok(()) => LegacyLookup::Migrated(value),
        Err(e) => LegacyLookup::FoundNotCopied(value, e.to_string()),
    })
}

/// On a miss in the platform store, look for a credential did-git-sign
/// 0.18.1 or earlier wrote to the Linux kernel keyring, and move it across.
///
/// Only when this process installed the platform store itself on Linux: a host
/// that registered its own store (OpenVTC) or a user who chose keyutils has
/// nothing to migrate from. Any failure reading the kernel keyring is a miss —
/// the caller then reports the credential missing from the platform store,
/// which is the store it belongs in.
pub fn recover_legacy(service: &str, user: &str) -> Option<String> {
    if active() != Some(Selection::Platform) {
        return None;
    }
    recover_from_kernel_keyring(service, user)
}

#[cfg(target_os = "linux")]
fn recover_from_kernel_keyring(service: &str, user: &str) -> Option<String> {
    let legacy = linux_keyutils_keyring_store::Store::new().ok()?;
    let primary = keyring_core::get_default_store()?;
    match copy_from_legacy(primary.as_ref(), legacy.as_ref(), service, user) {
        Ok(LegacyLookup::Absent) => None,
        Ok(LegacyLookup::Migrated(v)) => {
            eprintln!(
                "did-git-sign: moved the credential '{user}' from the Linux kernel keyring \
                 (where did-git-sign 0.18.1 and earlier kept it, lost on reboot) to the \
                 {}.",
                platform_name()
            );
            Some(v)
        }
        Ok(LegacyLookup::FoundNotCopied(v, why)) => {
            eprintln!(
                "did-git-sign: found the credential '{user}' in the Linux kernel keyring but \
                 could not copy it to the {}: {why}. Using it for now; it is lost at reboot.",
                platform_name()
            );
            Some(v)
        }
        Err(e) => {
            tracing::debug!("kernel keyring lookup for {user}: {e}");
            None
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn recover_from_kernel_keyring(_service: &str, _user: &str) -> Option<String> {
    None
}

/// Remove `service`/`user` from the kernel keyring as well, when this process
/// uses the platform store on Linux — so `uninstall` leaves nothing an older
/// did-git-sign wrote. Best effort; returns whether an entry was removed.
pub fn remove_legacy(service: &str, user: &str) -> bool {
    if active() != Some(Selection::Platform) {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        use keyring_core::api::CredentialStoreApi;
        if let Ok(store) = linux_keyutils_keyring_store::Store::new()
            && let Ok(entry) = store.build(service, user, None)
        {
            return entry.delete_credential().is_ok();
        }
    }
    let _ = (service, user);
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyring_core::api::CredentialStoreApi;
    use keyring_core::mock;

    #[test]
    fn unset_or_empty_selects_the_platform_store() {
        assert_eq!(parse_override(""), Ok(Selection::Platform));
    }

    #[test]
    fn keyutils_selects_the_kernel_keyring_only_on_linux() {
        let got = parse_override("keyutils");
        if cfg!(target_os = "linux") {
            assert_eq!(got, Ok(Selection::KernelKeyring));
        } else {
            assert!(got.unwrap_err().contains("does not have"));
        }
    }

    #[test]
    fn file_is_refused_with_the_reason() {
        let err = parse_override("file").unwrap_err();
        assert!(err.contains("openvtc-core"), "{err}");
        assert!(err.contains(OVERRIDE_ENV), "{err}");
    }

    #[test]
    fn unknown_values_are_errors_not_defaults() {
        // Matches OpenVTC, which matches the raw value exactly.
        for v in ["os", "KEYUTILS", " keyutils", "dbus"] {
            assert!(parse_override(v).is_err(), "{v} should be refused");
        }
    }

    #[test]
    fn store_names_say_where_the_lookup_went() {
        assert_eq!(
            describe(Selection::KernelKeyring),
            "Linux kernel keyring (keyutils)"
        );
        let platform = describe(Selection::Platform);
        if cfg!(target_os = "linux") {
            assert_eq!(platform, "Secret Service (DBus)");
        } else if cfg!(target_os = "macos") {
            assert_eq!(platform, "macOS Keychain");
        }
    }

    #[test]
    fn legacy_entry_is_copied_into_the_primary_store() {
        let primary = mock::Store::new().unwrap();
        let legacy = mock::Store::new().unwrap();
        legacy
            .build("did-git-sign", "did:x#key-0:vta", None)
            .unwrap()
            .set_password("creds")
            .unwrap();

        let got = copy_from_legacy(
            primary.as_ref(),
            legacy.as_ref(),
            "did-git-sign",
            "did:x#key-0:vta",
        )
        .unwrap();
        assert_eq!(got, LegacyLookup::Migrated("creds".into()));
        let copied = primary
            .build("did-git-sign", "did:x#key-0:vta", None)
            .unwrap()
            .get_password()
            .unwrap();
        assert_eq!(copied, "creds");
        // The legacy entry is left where it was.
        assert!(
            legacy
                .build("did-git-sign", "did:x#key-0:vta", None)
                .unwrap()
                .get_password()
                .is_ok()
        );
    }

    #[test]
    fn legacy_miss_is_absent_and_writes_nothing() {
        let primary = mock::Store::new().unwrap();
        let legacy = mock::Store::new().unwrap();
        let got = copy_from_legacy(primary.as_ref(), legacy.as_ref(), "did-git-sign", "u").unwrap();
        assert_eq!(got, LegacyLookup::Absent);
        assert!(matches!(
            primary
                .build("did-git-sign", "u", None)
                .unwrap()
                .get_password(),
            Err(keyring_core::Error::NoEntry)
        ));
    }

    #[test]
    fn a_failed_copy_still_returns_the_value() {
        let primary = mock::Store::new().unwrap();
        let legacy = mock::Store::new().unwrap();
        legacy
            .build("s", "u", None)
            .unwrap()
            .set_password("v")
            .unwrap();
        let entry = primary.build("s", "u", None).unwrap();
        let cred: &mock::Cred = entry.as_any().downcast_ref().unwrap();
        cred.set_error(keyring_core::Error::NoStorageAccess(
            "locked".to_string().into(),
        ));
        match copy_from_legacy(primary.as_ref(), legacy.as_ref(), "s", "u").unwrap() {
            LegacyLookup::FoundNotCopied(v, why) => {
                assert_eq!(v, "v");
                assert!(!why.is_empty());
            }
            other => panic!("expected FoundNotCopied, got {other:?}"),
        }
    }

    #[test]
    fn a_legacy_read_error_is_an_error_not_a_miss() {
        let primary = mock::Store::new().unwrap();
        let legacy = mock::Store::new().unwrap();
        let entry = legacy.build("s", "u", None).unwrap();
        let cred: &mock::Cred = entry.as_any().downcast_ref().unwrap();
        cred.set_error(keyring_core::Error::NoStorageAccess(
            "locked".to_string().into(),
        ));
        assert!(copy_from_legacy(primary.as_ref(), legacy.as_ref(), "s", "u").is_err());
    }
}
