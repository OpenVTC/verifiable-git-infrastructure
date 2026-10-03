//! Named signing profiles.
//!
//! Every identity `init` sets up already has its own credentials in the
//! keyring, under its `did:…#key-N`, and signing already signs as whichever
//! one `DID_GIT_SIGN_KEY` or `git config did-git-sign.key` selects. What was
//! missing is a name for each: switching meant copying a `did:webvh:…#key-N`
//! around. A profile is that name, recorded in `profiles.json` next to the
//! global config so `did-git-sign use <name>` works in any repository.
//!
//! The file holds public identifiers only (DIDs and a context id). Secrets
//! stay in the keyring, keyed by the DID as before.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::config::SigningConfig;

/// One named identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// The signing identity, `did:…#key-N`: what `did-git-sign.key` is set
    /// to, and the keyring key its credentials are stored under.
    pub did_key_id: String,
    /// The VTA that holds the signing key.
    pub vta_did: String,
    /// The VTA context the identity was provisioned into, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

/// Every profile on this machine, by name.
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profiles {
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

impl Profiles {
    /// `profiles.json` beside the global config.
    pub fn default_path() -> Result<PathBuf> {
        let global = SigningConfig::default_global_path()?;
        Ok(global
            .parent()
            .context("global config path has no parent directory")?
            .join("profiles.json"))
    }

    /// Load the profiles at `path`; a missing file is an empty set.
    pub fn load_from(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(data) => serde_json::from_str(&data)
                .with_context(|| format!("failed to parse {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
        }
    }

    /// Load the profiles at [`Self::default_path`].
    pub fn load() -> Result<Self> {
        Self::load_from(&Self::default_path()?)
    }

    /// Write the profiles to `path`, creating its directory.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))
    }

    /// Write the profiles to [`Self::default_path`].
    pub fn save(&self) -> Result<()> {
        self.save_to(&Self::default_path()?)
    }

    /// The profile called `name`, or an error that lists the ones there are.
    pub fn get(&self, name: &str) -> Result<&Profile> {
        self.profiles.get(name).with_context(|| {
            if self.profiles.is_empty() {
                format!(
                    "no profile '{name}': there are none yet. Create one with \
                     `did-git-sign init --profile {name} …`"
                )
            } else {
                let names: Vec<&str> = self.profiles.keys().map(String::as_str).collect();
                format!("no profile '{name}'. Known profiles: {}", names.join(", "))
            }
        })
    }

    /// The name of the profile whose identity is `did_key_id`, if any.
    pub fn name_of(&self, did_key_id: &str) -> Option<&str> {
        self.profiles
            .iter()
            .find(|(_, p)| p.did_key_id == did_key_id)
            .map(|(n, _)| n.as_str())
    }
}

/// A profile name is used on the command line and shown in listings: a
/// lowercase letter or digit, then up to 63 of those, `-`, `_` or `.`.
pub fn validate_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let ok_first = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let ok_rest =
        chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'));
    if !ok_first || !ok_rest || name.len() > 64 {
        bail!(
            "invalid profile name '{name}': use a lowercase letter or digit, then lowercase \
             letters, digits, '-', '_' or '.' (at most 64 characters)"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bob() -> Profile {
        Profile {
            did_key_id: "did:webvh:QmBob:example.com:bob#key-0".into(),
            vta_did: "did:webvh:QmVta:example.com:vta".into(),
            context: Some("bob".into()),
        }
    }

    #[test]
    fn names_are_lowercase_slugs() {
        for ok in ["bob", "carol-2", "a", "x.y_z", "0day"] {
            assert!(validate_name(ok).is_ok(), "{ok} should be valid");
        }
        for bad in [
            "",
            "Bob",
            "-bob",
            "bob carol",
            "bob/carol",
            "é",
            &"a".repeat(65),
        ] {
            assert!(validate_name(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn a_missing_file_is_an_empty_set() {
        let dir = tempfile::tempdir().unwrap();
        let p = Profiles::load_from(&dir.path().join("profiles.json")).unwrap();
        assert!(p.profiles.is_empty());
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("profiles.json");
        let mut p = Profiles::default();
        p.profiles.insert("bob".into(), bob());
        p.save_to(&path).unwrap();
        assert_eq!(Profiles::load_from(&path).unwrap(), p);
    }

    #[test]
    fn get_names_the_known_profiles_when_one_is_missing() {
        let mut p = Profiles::default();
        assert!(p.get("bob").unwrap_err().to_string().contains("none yet"));
        p.profiles.insert("bob".into(), bob());
        let err = p.get("carol").unwrap_err().to_string();
        assert!(err.contains("Known profiles: bob"), "{err}");
        assert_eq!(p.get("bob").unwrap(), &bob());
    }

    #[test]
    fn name_of_finds_a_profile_by_identity() {
        let mut p = Profiles::default();
        p.profiles.insert("bob".into(), bob());
        assert_eq!(p.name_of(&bob().did_key_id), Some("bob"));
        assert_eq!(p.name_of("did:webvh:other#key-0"), None);
    }

    #[test]
    fn context_is_optional_on_the_wire() {
        let json = r#"{"profiles":{"bob":{"did_key_id":"did:x#key-0","vta_did":"did:v"}}}"#;
        let p: Profiles = serde_json::from_str(json).unwrap();
        assert_eq!(p.profiles["bob"].context, None);
    }
}
