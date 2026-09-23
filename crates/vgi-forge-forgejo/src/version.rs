//! What an instance is, from `GET /api/v1/version`, and what it can do.
//!
//! Forgejo reports `<forgejo version>+gitea-<compatible gitea version>`
//! (`9.0.0+gitea-1.22.0`, `16.0.0-dev-753-6bcc6da0+gitea-1.22.0`); Gitea,
//! and Forgejo before v7, report a plain `1.x.y`. Features are switched on
//! by version so a plan never includes a step the instance cannot run —
//! and the steps re-check the answer they get, since a version string says
//! what should be there, not what is.

use serde::{Deserialize, Serialize};

/// Which software, at which version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
#[non_exhaustive]
pub enum Flavor {
    /// Forgejo 7 or later (`<major>.<minor>.<patch>+gitea-…`).
    Forgejo {
        /// Major version.
        major: u32,
        /// Minor version.
        minor: u32,
    },
    /// Gitea, or Forgejo before v7 (a Gitea-numbered `1.x`).
    Gitea {
        /// Major version (always 1 so far).
        major: u32,
        /// Minor version.
        minor: u32,
    },
    /// A version string the adapter could not read. Every optional feature
    /// is off.
    Unknown,
}

/// Optional features the adapter uses, as the version implies them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Features {
    /// The `fast-forward-only` merge style (Gitea 1.22, Forgejo 7).
    pub fast_forward_only: bool,
    /// The repository Actions variables API (Gitea 1.22; Forgejo 8 to be
    /// safe). Without it the plan writes the DIDs into the workflow.
    pub actions_variables: bool,
    /// Webhook `type: forgejo` (any Forgejo 7+); `gitea` otherwise.
    pub forgejo_webhooks: bool,
}

/// The probed instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct InstanceInfo {
    /// The version string as reported.
    pub version: String,
    /// What it parses as.
    pub flavor: Flavor,
    /// What that implies.
    pub features: Features,
}

impl InstanceInfo {
    /// Read a `/api/v1/version` string.
    pub fn from_version(version: &str) -> Self {
        let flavor = parse(version);
        let at_least = |maj: u32, min: u32, (a, b): (u32, u32)| (a, b) >= (maj, min);
        let features = match flavor {
            Flavor::Forgejo { major, minor } => Features {
                fast_forward_only: at_least(7, 0, (major, minor)),
                actions_variables: at_least(8, 0, (major, minor)),
                forgejo_webhooks: true,
            },
            Flavor::Gitea { major, minor } => Features {
                fast_forward_only: at_least(1, 22, (major, minor)),
                actions_variables: at_least(1, 22, (major, minor)),
                forgejo_webhooks: false,
            },
            Flavor::Unknown => Features::default(),
        };
        InstanceInfo {
            version: version.to_string(),
            flavor,
            features,
        }
    }
}

fn parse(version: &str) -> Flavor {
    let (own, gitea) = match version.split_once("+gitea-") {
        Some((own, gitea)) => (own, Some(gitea)),
        None => (version, None),
    };
    let Some((major, minor)) = major_minor(own) else {
        return Flavor::Unknown;
    };
    match gitea {
        Some(_) => Flavor::Forgejo { major, minor },
        // A plain `1.x` is Gitea's numbering (or Forgejo's before v7, which
        // tracked it). A plain `7+` is a Forgejo build without the suffix.
        None if major >= 7 => Flavor::Forgejo { major, minor },
        None if major == 1 => Flavor::Gitea { major, minor },
        None => Flavor::Unknown,
    }
}

fn major_minor(v: &str) -> Option<(u32, u32)> {
    let v = v.trim().trim_start_matches('v');
    let mut parts = v.split(['.', '-', '+']);
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse_and_gate_features() {
        let f = InstanceInfo::from_version("9.0.0+gitea-1.22.0");
        assert_eq!(f.flavor, Flavor::Forgejo { major: 9, minor: 0 });
        assert!(f.features.fast_forward_only && f.features.actions_variables);
        assert!(f.features.forgejo_webhooks);

        let dev = InstanceInfo::from_version("16.0.0-dev-753-6bcc6da0+gitea-1.22.0");
        assert_eq!(
            dev.flavor,
            Flavor::Forgejo {
                major: 16,
                minor: 0
            }
        );

        let seven = InstanceInfo::from_version("7.0.5+gitea-1.21.0");
        assert!(seven.features.fast_forward_only && !seven.features.actions_variables);

        let gitea = InstanceInfo::from_version("1.22.3");
        assert_eq!(
            gitea.flavor,
            Flavor::Gitea {
                major: 1,
                minor: 22
            }
        );
        assert!(gitea.features.fast_forward_only && !gitea.features.forgejo_webhooks);

        let old = InstanceInfo::from_version("1.21.11-1");
        assert_eq!(old.features, Features::default());

        for junk in ["", "dev", "x.y.z", "3.0.0"] {
            assert_eq!(InstanceInfo::from_version(junk).flavor, Flavor::Unknown);
        }
    }
}
