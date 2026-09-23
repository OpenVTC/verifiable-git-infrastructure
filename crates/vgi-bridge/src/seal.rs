//! Sealing secrets at rest.
//!
//! Every secret the bridge holds — its own DID keys, the GitHub App private
//! key and webhook secret, a Forgejo bot token and password — is stored
//! AES-256-GCM encrypted under one 32-byte **master key**, with the secret's
//! name bound in as associated data so a sealed value cannot be moved to
//! another name and opened there. Only the ciphertext reaches the store, and
//! so the store's backups.
//!
//! The master key itself never touches the store. It comes from a file the
//! deployment mounts (a Kubernetes or Docker secret, owner-only) or from an
//! environment variable, and is held zeroized in memory. Losing it loses every
//! sealed secret: the operator guide says to back it up separately from the
//! store, never next to it.
//!
//! Why not `vti-secrets`: its backends (keyring, AWS, GCP, Azure, Vault,
//! Kubernetes) are the right long-term home for the master key, but it pulls
//! `vti-common`, which requires a vta-sdk line this workspace does not build
//! yet — two copies of vta-sdk in one binary. The seam here is one function
//! ([`MasterKey::load`]), so moving the key into a `vti-secrets` store is a
//! local change once the lines meet.

use std::fmt;
use std::path::Path;

use anyhow::{Context, Result, bail};
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

/// Domain separation for the associated data: a value sealed by anything
/// else under the same key never opens here.
const AAD_PREFIX: &[u8] = b"vgi-bridge/sealed/v1\0";
/// Format byte in front of every sealed value, so a later format can be
/// told apart.
const VERSION: u8 = 1;

/// The 32-byte key every sealed secret is encrypted under.
pub struct MasterKey(Zeroizing<[u8; 32]>);

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

impl MasterKey {
    /// A fresh key from the system CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut k = Zeroizing::new([0u8; 32]);
        aws_lc_rs::rand::fill(k.as_mut()).map_err(|_| anyhow::anyhow!("system RNG unavailable"))?;
        Ok(MasterKey(k))
    }

    /// From raw bytes (tests, and keys handed over by another component).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        MasterKey(Zeroizing::new(bytes))
    }

    /// Parse the text form: 32 bytes, base64.
    pub fn from_text(text: &str) -> Result<Self> {
        let raw = Zeroizing::new(
            STANDARD
                .decode(text.trim())
                .context("master key is not base64")?,
        );
        let bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("master key must be 32 bytes, base64-encoded"))?;
        Ok(MasterKey::from_bytes(bytes))
    }

    /// The text form, for writing the key file once at `init`.
    pub fn to_text(&self) -> Zeroizing<String> {
        Zeroizing::new(STANDARD.encode(self.0.as_ref()))
    }

    /// Load the key from `file` or, failing that, from the environment
    /// variable `env`. A file readable by anyone but its owner is refused:
    /// whoever reads it can open every sealed secret.
    pub fn load(file: Option<&Path>, env: Option<&str>) -> Result<Self> {
        if let Some(path) = file {
            check_owner_only(path)?;
            let text = Zeroizing::new(
                std::fs::read_to_string(path)
                    .with_context(|| format!("reading the master key from {}", path.display()))?,
            );
            return MasterKey::from_text(&text);
        }
        if let Some(var) = env {
            let text = Zeroizing::new(std::env::var(var).with_context(|| {
                format!("the master key variable `{var}` is not set (or not UTF-8)")
            })?);
            return MasterKey::from_text(&text);
        }
        bail!("no master key source: set `master_key_file` or `master_key_env` in the config")
    }

    fn aead(&self) -> LessSafeKey {
        LessSafeKey::new(UnboundKey::new(&AES_256_GCM, self.0.as_ref()).expect("32-byte key"))
    }

    /// Seal `plaintext` as the secret called `name`.
    pub fn seal(&self, name: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        aws_lc_rs::rand::fill(&mut nonce).map_err(|_| anyhow::anyhow!("system RNG unavailable"))?;
        let mut buf = plaintext.to_vec();
        self.aead()
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad(name)),
                &mut buf,
            )
            .map_err(|_| anyhow::anyhow!("sealing `{name}` failed"))?;
        let mut out = Vec::with_capacity(1 + NONCE_LEN + buf.len());
        out.push(VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&buf);
        Ok(out)
    }

    /// Open the secret called `name`. Fails on a wrong key, a tampered value
    /// or one sealed under another name.
    pub fn open(&self, name: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if sealed.len() < 1 + NONCE_LEN || sealed[0] != VERSION {
            bail!("sealed secret `{name}` is not in a format this bridge reads");
        }
        let nonce: [u8; NONCE_LEN] = sealed[1..1 + NONCE_LEN].try_into().expect("length checked");
        let mut buf = Zeroizing::new(sealed[1 + NONCE_LEN..].to_vec());
        let len = self
            .aead()
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad(name)),
                buf.as_mut_slice(),
            )
            .map_err(|_| {
                anyhow::anyhow!(
                    "sealed secret `{name}` does not open: wrong master key, or the value was \
                     altered"
                )
            })?
            .len();
        buf.truncate(len);
        Ok(buf)
    }
}

fn aad(name: &str) -> Vec<u8> {
    let mut a = AAD_PREFIX.to_vec();
    a.extend_from_slice(name.as_bytes());
    a
}

#[cfg(unix)]
fn check_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .with_context(|| format!("reading {}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        bail!(
            "{} is readable by others (mode {:o}); `chmod 600` it — it opens every sealed secret",
            path.display(),
            mode & 0o777
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_owner_only(_path: &Path) -> Result<()> {
    Ok(())
}

/// Write `key` to `path`, owner-only, refusing to overwrite an existing key
/// (which would orphan every secret sealed under it).
pub fn write_key_file(path: &Path, key: &MasterKey) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).with_context(|| {
        format!(
            "creating {} (an existing key is never overwritten)",
            path.display()
        )
    })?;
    f.write_all(key.to_text().as_bytes())?;
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_value_opens_only_under_its_own_name_and_key() {
        let k = MasterKey::generate().unwrap();
        let sealed = k.seal("github/app", b"-----BEGIN RSA").unwrap();
        assert!(!sealed.windows(5).any(|w| w == b"BEGIN"), "ciphertext only");
        assert_eq!(&*k.open("github/app", &sealed).unwrap(), b"-----BEGIN RSA");
        assert!(
            k.open("forgejo/token", &sealed).is_err(),
            "bound to its name"
        );
        let other = MasterKey::generate().unwrap();
        assert!(other.open("github/app", &sealed).is_err());
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(k.open("github/app", &tampered).is_err());
    }

    #[test]
    fn key_text_round_trips_and_rejects_the_wrong_size() {
        let k = MasterKey::generate().unwrap();
        let again = MasterKey::from_text(&k.to_text()).unwrap();
        let sealed = k.seal("x", b"y").unwrap();
        assert_eq!(&*again.open("x", &sealed).unwrap(), b"y");
        assert!(MasterKey::from_text("c2hvcnQ=").is_err());
        assert_eq!(format!("{k:?}"), "MasterKey(<redacted>)");
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_key_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master.key");
        let k = MasterKey::generate().unwrap();
        write_key_file(&path, &k).unwrap();
        assert!(MasterKey::load(Some(&path), None).is_ok());
        assert!(write_key_file(&path, &k).is_err(), "never overwritten");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(MasterKey::load(Some(&path), None).is_err());
    }
}
