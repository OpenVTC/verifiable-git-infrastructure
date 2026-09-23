//! VTC rights (§4.2) and how they project onto forge roles.
//!
//! The VTC evaluates delegation and implication; an adapter only ever sees
//! the result for one person on one repository, as [`EffectiveRights`], and
//! turns it into one [`ForgeRole`]. The mapping never grants more than the
//! community asked for: a forge whose role ladder lacks the requested level
//! gets the next level *down*, never up (§5.8, "fewer `role_levels`").

use std::fmt;

use serde::{Deserialize, Serialize};

/// One of the five git rights a VTC grants (§4.2), by registry action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Right {
    /// `git.ns.admin` on a namespace.
    #[serde(rename = "git.ns.admin")]
    NsAdmin,
    /// `git.repo.create` on a namespace.
    #[serde(rename = "git.repo.create")]
    RepoCreate,
    /// `git.repo.own` on a repository.
    #[serde(rename = "git.repo.own")]
    RepoOwn,
    /// `git.repo.maintain` on a repository.
    #[serde(rename = "git.repo.maintain")]
    RepoMaintain,
    /// `git.commit.sign` on a repository or namespace — the tuple
    /// verify-trust checks.
    #[serde(rename = "git.commit.sign")]
    CommitSign,
}

impl Right {
    /// Every right, broadest first.
    pub const ALL: [Right; 5] = [
        Right::NsAdmin,
        Right::RepoCreate,
        Right::RepoOwn,
        Right::RepoMaintain,
        Right::CommitSign,
    ];

    /// The registry action string.
    pub fn action(self) -> &'static str {
        match self {
            Right::NsAdmin => "git.ns.admin",
            Right::RepoCreate => "git.repo.create",
            Right::RepoOwn => "git.repo.own",
            Right::RepoMaintain => "git.repo.maintain",
            Right::CommitSign => "git.commit.sign",
        }
    }

    /// Parse a registry action string. Unknown actions are `None`, not an
    /// error: the registry carries other capabilities' actions too.
    pub fn from_action(action: &str) -> Option<Right> {
        Right::ALL.into_iter().find(|r| r.action() == action)
    }

    fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

impl fmt::Display for Right {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.action())
    }
}

/// The rights one subject holds on one resource, closed under implication.
///
/// Implication (§4.2): `own ⇒ maintain ⇒ commit` on the same resource, and
/// `ns.admin ⇒ create` plus `own` on every repository in the namespace. The
/// VTC evaluates this before projecting; it is repeated here so an adapter
/// handed a partial set (say, `own` alone) still maps it correctly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct EffectiveRights(u8);

impl EffectiveRights {
    /// No rights at all.
    pub const NONE: EffectiveRights = EffectiveRights(0);

    /// The closure of `granted` under implication.
    pub fn from_granted(granted: impl IntoIterator<Item = Right>) -> Self {
        let mut rights = EffectiveRights::NONE;
        for right in granted {
            rights.insert(right);
        }
        rights
    }

    /// Add a right and everything it implies.
    pub fn insert(&mut self, right: Right) {
        self.0 |= right.bit();
        match right {
            Right::NsAdmin => {
                self.insert(Right::RepoCreate);
                self.insert(Right::RepoOwn);
            }
            Right::RepoOwn => self.insert(Right::RepoMaintain),
            Right::RepoMaintain => self.insert(Right::CommitSign),
            Right::RepoCreate | Right::CommitSign => {}
        }
    }

    /// Whether `right` is held (directly or by implication).
    pub fn holds(self, right: Right) -> bool {
        self.0 & right.bit() != 0
    }

    /// Whether nothing is held.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Held rights, broadest first.
    pub fn iter(self) -> impl Iterator<Item = Right> {
        Right::ALL.into_iter().filter(move |r| self.holds(*r))
    }

    /// The repository-level tier that decides the forge role: own, then
    /// maintain, then commit. `None` when none of those is held.
    pub fn repo_tier(self) -> Option<Right> {
        [Right::RepoOwn, Right::RepoMaintain, Right::CommitSign]
            .into_iter()
            .find(|r| self.holds(*r))
    }
}

impl Serialize for EffectiveRights {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(self.iter())
    }
}

impl<'de> Deserialize<'de> for EffectiveRights {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(EffectiveRights::from_granted(Vec::<Right>::deserialize(d)?))
    }
}

/// A person's role on a repository, on the forge's side, as a point on the
/// common ladder. Ordered: `None < Read < … < Admin`.
///
/// GitHub offers every level; Forgejo only `Read`, `Write` and `Admin`; a
/// GitHub personal account only `Write` collaborators. Each adapter declares
/// its ladder in [`crate::Capabilities::role_levels`].
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ForgeRole {
    /// No direct role (fork-based contribution).
    #[default]
    None,
    /// Read.
    Read,
    /// Triage (GitHub).
    Triage,
    /// Write / push.
    Write,
    /// Maintain (GitHub): merge and manage without admin settings.
    Maintain,
    /// Admin.
    Admin,
}

impl fmt::Display for ForgeRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ForgeRole::None => "none",
            ForgeRole::Read => "read",
            ForgeRole::Triage => "triage",
            ForgeRole::Write => "write",
            ForgeRole::Maintain => "maintain",
            ForgeRole::Admin => "admin",
        })
    }
}

/// Which forge role each repository tier asks for, before the forge's ladder
/// is applied (§4.2's "GitHub projection (org)" column is the default).
///
/// This is the community hook of §5.8 layer 3: a namespace may override the
/// map (`maintain → admin` on Forgejo, or committers get `write` on a repo
/// that opts in) without code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RoleMap {
    /// Role for `git.repo.own`.
    pub own: ForgeRole,
    /// Role for `git.repo.maintain`.
    pub maintain: ForgeRole,
    /// Role for `git.commit.sign`. `None` by default: committers contribute
    /// through fork PRs, and the required check — not a forge role — decides
    /// whether their commits land.
    pub commit: ForgeRole,
}

impl Default for RoleMap {
    fn default() -> Self {
        RoleMap {
            own: ForgeRole::Admin,
            maintain: ForgeRole::Maintain,
            commit: ForgeRole::None,
        }
    }
}

impl RoleMap {
    /// The default map with committers given `write` — for a repository that
    /// opts in to branch-based contribution.
    pub fn with_committer_write() -> Self {
        RoleMap {
            commit: ForgeRole::Write,
            ..RoleMap::default()
        }
    }

    /// The role the rights ask for, before any ladder is applied.
    pub fn requested(&self, rights: EffectiveRights) -> ForgeRole {
        match rights.repo_tier() {
            Some(Right::RepoOwn) => self.own,
            Some(Right::RepoMaintain) => self.maintain,
            Some(Right::CommitSign) => self.commit,
            _ => ForgeRole::None,
        }
    }
}

/// Fit `requested` onto a forge's ladder: the highest level on the ladder
/// that does not exceed it, or [`ForgeRole::None`] when every level does.
///
/// Rounding down is the security property: a forge with fewer levels gives
/// less than the community asked for, never more. `ladder` need not be
/// sorted.
pub fn collapse_to_ladder(requested: ForgeRole, ladder: &[ForgeRole]) -> ForgeRole {
    ladder
        .iter()
        .copied()
        .filter(|level| *level <= requested)
        .max()
        .unwrap_or(ForgeRole::None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn implication_closes_own_to_commit_and_admin_to_own() {
        let own = EffectiveRights::from_granted([Right::RepoOwn]);
        assert!(own.holds(Right::RepoMaintain) && own.holds(Right::CommitSign));
        assert!(!own.holds(Right::NsAdmin) && !own.holds(Right::RepoCreate));

        let admin = EffectiveRights::from_granted([Right::NsAdmin]);
        assert_eq!(admin.iter().count(), 5);

        let commit = EffectiveRights::from_granted([Right::CommitSign]);
        assert_eq!(commit.iter().collect::<Vec<_>>(), vec![Right::CommitSign]);
        assert_eq!(commit.repo_tier(), Some(Right::CommitSign));

        let create = EffectiveRights::from_granted([Right::RepoCreate]);
        assert_eq!(create.repo_tier(), None);
    }

    #[test]
    fn actions_round_trip() {
        for r in Right::ALL {
            assert_eq!(Right::from_action(r.action()), Some(r));
        }
        assert_eq!(Right::from_action("vtc.member"), None);
        let json =
            serde_json::to_string(&EffectiveRights::from_granted([Right::RepoMaintain])).unwrap();
        assert_eq!(json, r#"["git.repo.maintain","git.commit.sign"]"#);
    }

    #[test]
    fn default_map_matches_the_org_projection() {
        let map = RoleMap::default();
        let r = |x| EffectiveRights::from_granted([x]);
        assert_eq!(map.requested(r(Right::NsAdmin)), ForgeRole::Admin);
        assert_eq!(map.requested(r(Right::RepoOwn)), ForgeRole::Admin);
        assert_eq!(map.requested(r(Right::RepoMaintain)), ForgeRole::Maintain);
        assert_eq!(map.requested(r(Right::CommitSign)), ForgeRole::None);
        assert_eq!(
            RoleMap::with_committer_write().requested(r(Right::CommitSign)),
            ForgeRole::Write
        );
        assert_eq!(map.requested(EffectiveRights::NONE), ForgeRole::None);
    }

    #[test]
    fn collapsing_rounds_down_never_up() {
        let forgejo = [ForgeRole::Read, ForgeRole::Write, ForgeRole::Admin];
        assert_eq!(
            collapse_to_ladder(ForgeRole::Maintain, &forgejo),
            ForgeRole::Write
        );
        assert_eq!(
            collapse_to_ladder(ForgeRole::Admin, &forgejo),
            ForgeRole::Admin
        );
        assert_eq!(
            collapse_to_ladder(ForgeRole::Triage, &forgejo),
            ForgeRole::Read
        );

        let personal = [ForgeRole::Write];
        assert_eq!(
            collapse_to_ladder(ForgeRole::Admin, &personal),
            ForgeRole::Write
        );
        assert_eq!(
            collapse_to_ladder(ForgeRole::Read, &personal),
            ForgeRole::None
        );
        assert_eq!(
            collapse_to_ladder(ForgeRole::None, &personal),
            ForgeRole::None
        );
    }
}
