//! [`Resource`]: a normalised, forge-qualified path (§4.5).
//!
//! The grammar lives in [`vgi_core::resource`] so the verifier, the VTC's
//! registry projection and every adapter produce the same bytes for the same
//! repository; this module wraps it in a type that can only hold a valid
//! value, and adds the owner/repo shape GitHub and Forgejo share.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use vgi_core::{normalize_resource, normalize_resource_with_depth, resource_contains};

use crate::error::{ForgeError, Result};

/// Path depth on forges whose paths are exactly `owner[/repo]` — GitHub and
/// Forgejo (§4.5).
pub const OWNER_REPO_DEPTH: usize = 2;

/// A normalised forge-qualified resource: `github.com/acme` or
/// `github.com/acme/widgets`.
///
/// Construction always goes through the [`vgi_core`] grammar, so a
/// `Resource` in hand is lowercased, names its forge, and has no empty or
/// dot segments. It serialises as its string form and deserialisation
/// re-validates, so a bridge job cannot smuggle an unnormalised one in.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Resource(String);

impl Resource {
    /// Parse and normalise any forge-qualified resource (any depth the
    /// grammar allows). Use [`Resource::parse_owner_repo`] when the forge is
    /// GitHub or Forgejo.
    pub fn parse(raw: &str) -> Result<Self> {
        Ok(Self(normalize_resource(raw)?))
    }

    /// Parse a resource on an `owner[/repo]` forge (GitHub, Forgejo).
    ///
    /// On top of the shared grammar this refuses a `.git` suffix on the repo
    /// segment: neither forge lets a repository be named that way, so it can
    /// only be a clone URL pasted in the wrong place.
    pub fn parse_owner_repo(raw: &str) -> Result<Self> {
        let canonical = normalize_resource_with_depth(raw, OWNER_REPO_DEPTH)?;
        if let Some(stem) = canonical.strip_suffix(".git")
            && canonical.matches('/').count() == 2
        {
            return Err(ForgeError::WrongResource {
                resource: canonical.clone(),
                expected: format!("a repository name without `.git`: `{stem}`"),
            });
        }
        Ok(Self(canonical))
    }

    /// Check that this is exactly `host/owner/repo` under the owner/repo
    /// grammar. A `Resource` that arrived by deserialisation was validated
    /// against the general grammar only (any depth), so an adapter for an
    /// owner/repo forge must call this before splitting it into owner and
    /// name — `github.com/acme/evil/widgets` is not `acme/widgets`.
    pub fn require_owner_repo(&self) -> Result<()> {
        let reparsed = Resource::parse_owner_repo(&self.0)?;
        if reparsed.is_namespace() {
            return Err(ForgeError::WrongResource {
                resource: self.0.clone(),
                expected: "a repository (`<host>/<owner>/<repo>`), not a namespace".into(),
            });
        }
        Ok(())
    }

    /// Build `host/owner` from parts, validating the result.
    pub fn namespace_of(host: &str, owner: &str) -> Result<Self> {
        Self::parse_owner_repo(&format!("{host}/{owner}"))
    }

    /// The canonical string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The forge host, e.g. `github.com`.
    pub fn host(&self) -> &str {
        self.0.split('/').next().unwrap_or_default()
    }

    /// Path segments after the host.
    pub fn path_segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/').skip(1)
    }

    /// The first path segment: the owner (org or user).
    pub fn owner(&self) -> &str {
        self.path_segments().next().unwrap_or_default()
    }

    /// The last path segment when the resource names a repository (more
    /// than one path segment); `None` for a namespace.
    pub fn repo_name(&self) -> Option<&str> {
        if self.is_namespace() {
            None
        } else {
            self.0.rsplit('/').next()
        }
    }

    /// Whether this is a namespace (`host/owner`) rather than a repository.
    pub fn is_namespace(&self) -> bool {
        self.path_segments().count() == 1
    }

    /// The namespace this resource sits in (`host/owner`); itself when it is
    /// one.
    pub fn namespace(&self) -> Resource {
        Resource(format!("{}/{}", self.host(), self.owner()))
    }

    /// A repository under this namespace. Fails if `self` is not a namespace
    /// or `name` is not a valid repo segment.
    pub fn join(&self, name: &str) -> Result<Resource> {
        if !self.is_namespace() {
            return Err(ForgeError::WrongResource {
                resource: self.0.clone(),
                expected: "a namespace (`<forge-host>/<owner>`) to create a repository in".into(),
            });
        }
        if name.contains('/') {
            return Err(ForgeError::WrongResource {
                resource: format!("{}/{name}", self.0),
                expected: "a single repository name, without `/`".into(),
            });
        }
        Resource::parse_owner_repo(&format!("{}/{name}", self.0))
    }

    /// Segment-prefix containment (§4.2 scope check): a namespace contains
    /// its repositories, never another owner's, never another forge's.
    pub fn contains(&self, other: &Resource) -> bool {
        resource_contains(&self.0, &other.0)
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Resource {
    type Err = ForgeError;
    fn from_str(s: &str) -> Result<Self> {
        Resource::parse(s)
    }
}

impl AsRef<str> for Resource {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Serialize for Resource {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Resource {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        // Re-validate rather than trust the wire: a bridge job is input.
        let parsed = Resource::parse(&raw).map_err(serde::de::Error::custom)?;
        if parsed.0 != raw {
            return Err(serde::de::Error::custom(format!(
                "resource `{raw}` is not in canonical form (expected `{parsed}`)"
            )));
        }
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_repo_shape() {
        let r = Resource::parse_owner_repo("GitHub.com/Acme/Widgets").unwrap();
        assert_eq!(r.as_str(), "github.com/acme/widgets");
        assert_eq!(r.host(), "github.com");
        assert_eq!(r.owner(), "acme");
        assert_eq!(r.repo_name(), Some("widgets"));
        assert!(!r.is_namespace());
        assert_eq!(r.namespace().as_str(), "github.com/acme");
        assert_eq!(r.namespace().repo_name(), None);
    }

    #[test]
    fn owner_repo_refuses_depth_and_dot_git() {
        assert!(matches!(
            Resource::parse_owner_repo("github.com/a/b/c"),
            Err(ForgeError::InvalidResource(_))
        ));
        let err = Resource::parse_owner_repo("github.com/acme/widgets.git").unwrap_err();
        assert!(
            err.to_string().contains("`github.com/acme/widgets`"),
            "{err}"
        );
    }

    #[test]
    fn deep_resources_are_not_owner_repo() {
        let deep: Resource = serde_json::from_str("\"github.com/acme/evil/widgets\"").unwrap();
        assert!(deep.require_owner_repo().is_err());
        assert!(
            Resource::parse("github.com/acme")
                .unwrap()
                .require_owner_repo()
                .is_err()
        );
        assert!(
            Resource::parse("github.com/acme/w")
                .unwrap()
                .require_owner_repo()
                .is_ok()
        );
    }

    #[test]
    fn join_builds_a_repo_under_a_namespace_only() {
        let ns = Resource::parse_owner_repo("github.com/acme").unwrap();
        assert_eq!(
            ns.join("Gadgets").unwrap().as_str(),
            "github.com/acme/gadgets"
        );
        assert!(ns.join("a/b").is_err());
        assert!(ns.join("..").is_err());
        assert!(ns.join("gadgets").unwrap().join("x").is_err());
    }

    #[test]
    fn containment() {
        let ns = Resource::parse("github.com/acme").unwrap();
        assert!(ns.contains(&Resource::parse("github.com/acme/w").unwrap()));
        assert!(!ns.contains(&Resource::parse("github.com/acme-labs/w").unwrap()));
        assert!(!ns.contains(&Resource::parse("codeberg.org/acme/w").unwrap()));
    }

    #[test]
    fn serde_round_trips_and_refuses_non_canonical_input() {
        let r = Resource::parse("github.com/acme/widgets").unwrap();
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, "\"github.com/acme/widgets\"");
        assert_eq!(serde_json::from_str::<Resource>(&json).unwrap(), r);
        assert!(serde_json::from_str::<Resource>("\"GitHub.com/acme\"").is_err());
        assert!(serde_json::from_str::<Resource>("\"acme/widgets\"").is_err());
    }
}
