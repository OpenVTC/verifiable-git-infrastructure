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
///
/// **Implication decides what a person may do, not which forge role they
/// get.** A namespace admin gets no role on the forge (decided 2026-09-25):
/// `git.ns.admin` is exercised through the VTC and the bridge, never as an
/// organisation owner or a repository role. So the rights `ns.admin` implies
/// are [held](EffectiveRights::holds) but never
/// [projected](EffectiveRights::forge_tier); only a repository right granted
/// in its own name (`own`, `maintain`, `commit.sign`) reaches a forge role.
///
/// Two values are equal when they hold the same rights *and* project the
/// same ones — i.e. when their [canonical grants](EffectiveRights::granted)
/// are equal. `[ns.admin]` and `[ns.admin, own]` hold the same rights but
/// are different values: only the second projects `own`. Serialised as the
/// canonical grants, so a round trip is the identity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct EffectiveRights {
    /// Every right held, directly or by implication.
    held: u8,
    /// The rights that may become a forge role: the closure of the
    /// repository rights granted, without what `ns.admin` implies.
    projectable: u8,
}

impl EffectiveRights {
    /// No rights at all.
    pub const NONE: EffectiveRights = EffectiveRights {
        held: 0,
        projectable: 0,
    };

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
        let closure = Self::closure(right);
        self.held |= closure;
        match right {
            // Namespace rights never project: `ns.admin`'s implied `own`
            // lets its holder act through the VTC, not on the forge.
            Right::NsAdmin | Right::RepoCreate => {}
            Right::RepoOwn | Right::RepoMaintain | Right::CommitSign => {
                self.projectable |= closure;
            }
        }
    }

    /// `right` and everything it implies, as bits.
    fn closure(right: Right) -> u8 {
        right.bit()
            | match right {
                Right::NsAdmin => Self::closure(Right::RepoCreate) | Self::closure(Right::RepoOwn),
                Right::RepoOwn => Self::closure(Right::RepoMaintain),
                Right::RepoMaintain => Self::closure(Right::CommitSign),
                Right::RepoCreate | Right::CommitSign => 0,
            }
    }

    /// Whether `right` is held (directly or by implication).
    pub fn holds(self, right: Right) -> bool {
        self.held & right.bit() != 0
    }

    /// Whether nothing is held.
    pub fn is_empty(self) -> bool {
        self.held == 0
    }

    /// Held rights, broadest first.
    pub fn iter(self) -> impl Iterator<Item = Right> {
        Right::ALL.into_iter().filter(move |r| self.holds(*r))
    }

    /// The repository-level tier held, by any route (including `ns.admin`'s
    /// implied `own`): own, then maintain, then commit. `None` when none of
    /// those is held. For authorisation; the forge role comes from
    /// [`EffectiveRights::forge_tier`].
    pub fn repo_tier(self) -> Option<Right> {
        Self::tier(self.held)
    }

    /// The repository-level tier that decides the forge role: own, then
    /// maintain, then commit, from repository rights granted in their own
    /// name. `ns.admin` alone gives `None` — a namespace admin gets no forge
    /// role.
    pub fn forge_tier(self) -> Option<Right> {
        Self::tier(self.projectable)
    }

    /// The smallest set of grants this value is the closure of, broadest
    /// first: `ns.admin` if held; `repo.create` if held and not implied by
    /// `ns.admin`; and the highest repository right granted in its own name.
    /// `EffectiveRights::from_granted(x.granted()) == x` for every `x`.
    pub fn granted(self) -> Vec<Right> {
        let mut out = Vec::new();
        if self.holds(Right::NsAdmin) {
            out.push(Right::NsAdmin);
        } else if self.holds(Right::RepoCreate) {
            out.push(Right::RepoCreate);
        }
        out.extend(self.forge_tier());
        out
    }

    fn tier(bits: u8) -> Option<Right> {
        [Right::RepoOwn, Right::RepoMaintain, Right::CommitSign]
            .into_iter()
            .find(|r| bits & r.bit() != 0)
    }
}

/// As the [canonical grants](EffectiveRights::granted), not every held
/// right: writing the rights `ns.admin` implies would read back as
/// repository rights granted in their own name, and project.
impl Serialize for EffectiveRights {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(self.granted())
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
/// This is the community hook of §5.8 layer 3: a bridge, a namespace or a
/// repository may override the map (`maintain → write` on Forgejo instead of
/// `write` plus the merge allow-list, or committers get `write` on a
/// repository that opts in to branch-based contribution) without code.
///
/// **There is no entry for `git.ns.admin`, by design** (decided 2026-09-25):
/// a namespace admin gets no forge role, so no map can give them one. An
/// `nsAdmin` key is refused when a map is read.
///
/// A map is always ordered — `own ≥ maintain ≥ commit` — and **only `own`
/// may map to [`ForgeRole::Admin`]** (`git-ns/bridge/job` 0.4): `maintain`
/// and `commit` are rights their holder may grant themselves, so either at
/// `admin` would let someone make themselves an administrator of the
/// repository on the forge on their own authority. A committer gets at most
/// `write`: the check, not the forge role, decides whose commits land, and a
/// committer with merge rights would be a maintainer. [`RoleMap::new`] and
/// deserialisation both enforce this, and the fields are private so that no
/// map can be changed afterwards to one they would refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "RawRoleMap")]
pub struct RoleMap {
    own: ForgeRole,
    maintain: ForgeRole,
    commit: ForgeRole,
}

/// The unchecked wire form of [`RoleMap`].
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawRoleMap {
    own: ForgeRole,
    maintain: ForgeRole,
    commit: ForgeRole,
}

impl TryFrom<RawRoleMap> for RoleMap {
    type Error = String;
    fn try_from(r: RawRoleMap) -> Result<Self, String> {
        RoleMap::new(r.own, r.maintain, r.commit)
    }
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
    /// The highest role a committer may be given.
    pub const MAX_COMMIT: ForgeRole = ForgeRole::Write;

    /// A map giving `own`, `maintain` and `commit` to the three tiers.
    /// Refused unless `own ≥ maintain ≥ commit`, `maintain` is below
    /// `admin` and `commit ≤ write`.
    pub fn new(own: ForgeRole, maintain: ForgeRole, commit: ForgeRole) -> Result<Self, String> {
        for (tier, role) in [("a maintainer", maintain), ("a committer", commit)] {
            if role >= ForgeRole::Admin {
                return Err(format!(
                    "{tier} may not get `{role}`: only an owner (`own`) may map to the forge's \
                     administrator role, since maintain and commit are rights their holder may \
                     grant themselves"
                ));
            }
        }
        if maintain > own {
            return Err(format!(
                "a maintainer (`{maintain}`) may not get more than an owner (`{own}`)"
            ));
        }
        if commit > maintain {
            return Err(format!(
                "a committer (`{commit}`) may not get more than a maintainer (`{maintain}`)"
            ));
        }
        if commit > Self::MAX_COMMIT {
            return Err(format!(
                "a committer may get at most `{}`, not `{commit}`: the check decides whose \
                 commits land, and merging is a maintainer's",
                Self::MAX_COMMIT
            ));
        }
        Ok(RoleMap {
            own,
            maintain,
            commit,
        })
    }

    /// Role for `git.repo.own`.
    pub fn own(&self) -> ForgeRole {
        self.own
    }

    /// Role for `git.repo.maintain`. Never [`ForgeRole::Admin`].
    pub fn maintain(&self) -> ForgeRole {
        self.maintain
    }

    /// Role for `git.commit.sign`. `None` by default: committers contribute
    /// through fork PRs, and the required check — not a forge role — decides
    /// whether their commits land. At most [`RoleMap::MAX_COMMIT`].
    pub fn commit(&self) -> ForgeRole {
        self.commit
    }

    /// The default map with committers given `write` — for a repository that
    /// opts in to branch-based contribution.
    pub fn with_committer_write() -> Self {
        RoleMap {
            commit: ForgeRole::Write,
            ..RoleMap::default()
        }
    }

    /// The role the rights ask for, before any ladder is applied. Only
    /// repository rights granted in their own name count
    /// ([`EffectiveRights::forge_tier`]): `ns.admin` alone asks for
    /// [`ForgeRole::None`].
    pub fn requested(&self, rights: EffectiveRights) -> ForgeRole {
        match rights.forge_tier() {
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
        assert_eq!(admin.repo_tier(), Some(Right::RepoOwn));
        assert_eq!(admin.forge_tier(), None, "ns.admin never projects");

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
        assert_eq!(json, r#"["git.repo.maintain"]"#);
    }

    #[test]
    fn default_map_matches_the_org_projection() {
        let map = RoleMap::default();
        let r = |x| EffectiveRights::from_granted([x]);
        assert_eq!(map.requested(r(Right::NsAdmin)), ForgeRole::None);
        assert_eq!(map.requested(r(Right::RepoCreate)), ForgeRole::None);
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
    fn a_namespace_admin_gets_no_forge_role_under_any_map() {
        let admin = EffectiveRights::from_granted([Right::NsAdmin]);
        let everything =
            RoleMap::new(ForgeRole::Admin, ForgeRole::Maintain, ForgeRole::Write).unwrap();
        for map in [
            RoleMap::default(),
            RoleMap::with_committer_write(),
            everything,
        ] {
            assert_eq!(map.requested(admin), ForgeRole::None);
        }
        // A repository right granted in its own name still projects, whatever
        // the holder also has on the namespace.
        let both = EffectiveRights::from_granted([Right::NsAdmin, Right::RepoMaintain]);
        assert!(both.holds(Right::RepoOwn));
        assert_eq!(RoleMap::default().requested(both), ForgeRole::Maintain);
    }

    #[test]
    fn serde_round_trips_are_the_identity() {
        use Right::*;
        let cases: &[(&[Right], &str)] = &[
            (&[], "[]"),
            (&[NsAdmin], r#"["git.ns.admin"]"#),
            (&[NsAdmin, RepoOwn], r#"["git.ns.admin","git.repo.own"]"#),
            (
                &[NsAdmin, RepoMaintain],
                r#"["git.ns.admin","git.repo.maintain"]"#,
            ),
            (&[NsAdmin, RepoCreate], r#"["git.ns.admin"]"#),
            (
                &[RepoCreate, CommitSign],
                r#"["git.repo.create","git.commit.sign"]"#,
            ),
            (&[RepoOwn, RepoMaintain, CommitSign], r#"["git.repo.own"]"#),
        ];
        for (granted, want) in cases {
            let x = EffectiveRights::from_granted(granted.iter().copied());
            let json = serde_json::to_string(&x).unwrap();
            assert_eq!(json, *want, "{granted:?}");
            let back: EffectiveRights = serde_json::from_str(&json).unwrap();
            assert_eq!(back, x, "{granted:?}");
            assert_eq!(back.forge_tier(), x.forge_tier(), "{granted:?}");
            assert_eq!(EffectiveRights::from_granted(x.granted()), x);
        }
        // An ns.admin-only value stays one: it never reads back as an owner.
        let admin: EffectiveRights = serde_json::from_str(
            &serde_json::to_string(&EffectiveRights::from_granted([NsAdmin])).unwrap(),
        )
        .unwrap();
        assert_eq!(RoleMap::default().requested(admin), ForgeRole::None);
        // Same rights held, different projection: not equal.
        assert_ne!(
            EffectiveRights::from_granted([NsAdmin]),
            EffectiveRights::from_granted([NsAdmin, RepoOwn])
        );
        assert_eq!(
            EffectiveRights::from_granted([RepoOwn]),
            EffectiveRights::from_granted([RepoOwn, CommitSign])
        );
    }

    #[test]
    fn a_role_map_is_ordered_and_committers_stop_at_write() {
        use ForgeRole::*;
        assert!(RoleMap::new(Admin, Maintain, Write).is_ok());
        assert!(RoleMap::new(Admin, Write, Write).is_ok());
        assert!(RoleMap::new(Write, Write, None).is_ok());
        assert!(RoleMap::new(Maintain, Write, None).is_ok());
        assert!(RoleMap::new(Write, Maintain, None).is_err());
        assert!(RoleMap::new(Admin, Write, Maintain).is_err());
        let ok: RoleMap =
            serde_json::from_str(r#"{"own":"admin","maintain":"write","commit":"write"}"#).unwrap();
        assert_eq!(ok.maintain(), Write);
        for bad in [
            r#"{"own":"write","maintain":"maintain","commit":"none"}"#,
            r#"{"own":"admin","maintain":"write","commit":"maintain"}"#,
            r#"{"own":"admin","maintain":"maintain","commit":"none","nsAdmin":"admin"}"#,
        ] {
            assert!(serde_json::from_str::<RoleMap>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_an_owner_may_map_to_admin() {
        use ForgeRole::*;
        // Maintain or commit at admin is refused, whatever else the map says.
        for (own, maintain, commit) in [
            (Admin, Admin, None),
            (Admin, Admin, Write),
            (Admin, Admin, Admin),
            (Admin, Maintain, Admin),
            (Admin, Write, Admin),
        ] {
            let err = RoleMap::new(own, maintain, commit).unwrap_err();
            assert!(
                err.contains("only an owner"),
                "{own}/{maintain}/{commit}: {err}"
            );
        }
        // Deserialisation takes the same path.
        for bad in [
            r#"{"own":"admin","maintain":"admin","commit":"none"}"#,
            r#"{"own":"admin","maintain":"admin","commit":"write"}"#,
            r#"{"own":"admin","maintain":"maintain","commit":"admin"}"#,
        ] {
            let err = serde_json::from_str::<RoleMap>(bad)
                .unwrap_err()
                .to_string();
            assert!(err.contains("only an owner"), "{bad}: {err}");
        }
        // Every map that exists gives admin to nobody but an owner.
        for map in [RoleMap::default(), RoleMap::with_committer_write()] {
            assert!(map.maintain() < Admin && map.commit() < Admin);
        }
        assert_eq!(RoleMap::default().own(), Admin);
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
