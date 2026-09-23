//! Forge events and drift (§5.6).
//!
//! A [`ForgeEvent`] is a verified webhook translated into forge-neutral
//! terms: the core decides what to do about it. A [`Drift`] is one way the
//! forge's state differs from the VTC's projection, found by comparing an
//! [`crate::RepoState`] to a [`crate::Projection`] — whether an event
//! prompted the comparison or a scheduled sweep did.

use serde::{Deserialize, Serialize};

use crate::bootstrap::MergeMethod;
use crate::model::{
    ForgeAccount, Projection, ProtectionState, RepoState, RoleAssignment, Visibility,
};
use crate::resource::Resource;
use crate::rights::ForgeRole;

/// A verified, translated webhook delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ForgeEvent {
    /// The forge's delivery id, for de-duplication. Webhook signatures carry
    /// no timestamp, so a replayed delivery verifies; dropping repeats by id
    /// is the core's job.
    pub delivery_id: Option<String>,
    /// What happened.
    pub kind: ForgeEventKind,
}

impl ForgeEvent {
    /// An event.
    pub fn new(delivery_id: Option<String>, kind: ForgeEventKind) -> Self {
        ForgeEvent { delivery_id, kind }
    }
}

/// How a membership or collaborator changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum MemberChange {
    /// Added.
    Added,
    /// Removed.
    Removed,
    /// Role or permission edited.
    Edited,
}

/// How an automation installation changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum InstallationChange {
    /// Installed.
    Created,
    /// Uninstalled: the namespace can no longer be managed.
    Deleted,
    /// Suspended by the owner.
    Suspended,
    /// Unsuspended.
    Unsuspended,
    /// The owner accepted a permission change.
    PermissionsAccepted,
}

/// What a [`ForgeEvent`] reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
#[non_exhaustive]
pub enum ForgeEventKind {
    /// A repository appeared — through the bridge or not (§5.6 *unmanaged*).
    RepoCreated {
        /// The repository.
        repo: Resource,
        /// Its forge id.
        forge_id: u64,
    },
    /// A repository was deleted.
    RepoDeleted {
        /// The repository.
        repo: Resource,
        /// Its forge id.
        forge_id: u64,
    },
    /// A repository was renamed within its owner.
    RepoRenamed {
        /// Its forge id — what the VTC keys rights on.
        forge_id: u64,
        /// The old resource.
        from: Resource,
        /// The new resource.
        to: Resource,
    },
    /// A repository moved to another owner.
    RepoTransferred {
        /// Its forge id.
        forge_id: u64,
        /// The previous owner's namespace, when the forge says.
        from_namespace: Option<Resource>,
        /// The new resource.
        to: Resource,
    },
    /// Archived or unarchived.
    RepoArchived {
        /// The repository.
        repo: Resource,
        /// Its forge id.
        forge_id: u64,
        /// The new state.
        archived: bool,
    },
    /// Visibility changed.
    RepoVisibilityChanged {
        /// The repository.
        repo: Resource,
        /// Its forge id.
        forge_id: u64,
        /// The new visibility.
        visibility: Visibility,
    },
    /// A direct collaborator was added, removed or changed.
    CollaboratorChanged {
        /// The repository.
        repo: Resource,
        /// Its forge id.
        forge_id: u64,
        /// Who.
        account: ForgeAccount,
        /// How.
        change: MemberChange,
    },
    /// Someone joined or left the organisation.
    OrgMembershipChanged {
        /// The namespace.
        namespace: Resource,
        /// Who.
        account: ForgeAccount,
        /// How.
        change: MemberChange,
    },
    /// Someone joined or left a team in the organisation. Distinct from
    /// [`ForgeEventKind::OrgMembershipChanged`]: leaving a team does not mean
    /// leaving the organisation.
    TeamMembershipChanged {
        /// The namespace.
        namespace: Resource,
        /// The team's slug.
        team: String,
        /// Who.
        account: ForgeAccount,
        /// How.
        change: MemberChange,
    },
    /// Branch protection or a ruleset changed. Always worth an `inspect`:
    /// a weakened rule is the drift that silently removes the guarantee.
    ProtectionChanged {
        /// The repository, or `None` for an owner-level rule.
        repo: Option<Resource>,
        /// The namespace.
        namespace: Resource,
        /// The forge's action word (`created`, `edited`, `deleted`), for the
        /// audit log.
        action: String,
    },
    /// The automation installation on a namespace changed.
    InstallationChanged {
        /// The namespace.
        namespace: Resource,
        /// The installation id.
        installation_id: u64,
        /// How.
        change: InstallationChange,
    },
}

/// One way the protection falls short of §5.3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
#[non_exhaustive]
pub enum ProtectionGap {
    /// The managed rule is gone.
    Missing,
    /// It exists but is not enforced.
    NotEnforced,
    /// It does not cover the default branch.
    DefaultBranchNotCovered,
    /// Pull requests are not required.
    PullRequestNotRequired,
    /// The check is not among the required ones.
    CheckNotRequired {
        /// The check that should be required.
        check: String,
    },
    /// Force-pushes are allowed.
    ForcePushAllowed,
    /// Deletion is allowed.
    DeletionAllowed,
    /// Someone can bypass it.
    BypassActors {
        /// Who, as the forge describes them.
        actors: Vec<String>,
    },
    /// A pull request could change these paths — the workflow or the exempt
    /// keyring — and so rewrite the check it is judged by.
    UnprotectedPaths {
        /// The paths (forge glob syntax) that should be protected and are not.
        paths: Vec<String>,
    },
    /// A merge method is allowed that lands commits the check never saw
    /// (a forge-made merge, rebase or squash commit).
    MergeMethodAllowed {
        /// The method.
        method: MergeMethod,
    },
    /// CI is disabled on the repository: the required check can never report.
    CiDisabled,
}

/// A difference between forge state and the VTC projection (§5.6 table).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
#[non_exhaustive]
pub enum Drift {
    /// Someone holds a direct role the VTC did not grant (added in the forge
    /// UI). Default response: report; adopt or revert.
    UnexpectedRole {
        /// Who.
        account: ForgeAccount,
        /// Their forge role.
        observed: ForgeRole,
    },
    /// Someone the VTC granted has no role. Default response: re-apply.
    MissingRole {
        /// Who.
        account: ForgeAccount,
        /// The role they should have.
        expected: ForgeRole,
    },
    /// Someone's role differs from the projection.
    RoleMismatch {
        /// Who.
        account: ForgeAccount,
        /// The role they should have.
        expected: ForgeRole,
        /// The role they have.
        observed: ForgeRole,
    },
    /// The required-check protection is weaker than it must be. Default
    /// response: re-apply and alert (§5.6).
    ProtectionWeakened {
        /// Every shortfall found.
        gaps: Vec<ProtectionGap>,
    },
    /// The repository now lives at another resource (same forge id).
    /// Registry tuples must be rewritten (§9, rename attacks).
    Renamed {
        /// Where the VTC thinks it is.
        expected: Resource,
        /// Where it is.
        observed: Resource,
    },
    /// The forge id differs: this is a different repository under the same
    /// name — never inherit grants onto it.
    Replaced {
        /// The id the VTC recorded.
        expected: u64,
        /// The id there now.
        observed: u64,
    },
    /// Archived state differs.
    ArchiveMismatch {
        /// Desired.
        expected: bool,
        /// Observed.
        observed: bool,
    },
    /// Visibility differs.
    VisibilityMismatch {
        /// Desired.
        expected: Visibility,
        /// Observed.
        observed: Visibility,
    },
}

impl Drift {
    /// Whether this drift removes the commit-trust guarantee or points
    /// rights at the wrong repository. These are enforced by default rather
    /// than reported (§5.6): a weakened ruleset lets unverified commits
    /// merge, and a replaced repo must not inherit grants.
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            Drift::ProtectionWeakened { .. } | Drift::Replaced { .. } | Drift::Renamed { .. }
        )
    }
}

/// Protection shortfalls of `observed` against a required `check`.
pub fn protection_gaps(observed: &ProtectionState, check: &str) -> Vec<ProtectionGap> {
    if !observed.present {
        return vec![ProtectionGap::Missing];
    }
    let mut gaps = Vec::new();
    if !observed.enforced {
        gaps.push(ProtectionGap::NotEnforced);
    }
    if !observed.covers_default_branch {
        gaps.push(ProtectionGap::DefaultBranchNotCovered);
    }
    if !observed.requires_pull_request {
        gaps.push(ProtectionGap::PullRequestNotRequired);
    }
    if !observed.required_checks.iter().any(|c| c == check) {
        gaps.push(ProtectionGap::CheckNotRequired {
            check: check.to_string(),
        });
    }
    if !observed.blocks_force_push {
        gaps.push(ProtectionGap::ForcePushAllowed);
    }
    if !observed.blocks_deletion {
        gaps.push(ProtectionGap::DeletionAllowed);
    }
    if !observed.bypass_actors.is_empty() {
        gaps.push(ProtectionGap::BypassActors {
            actors: observed.bypass_actors.clone(),
        });
    }
    gaps
}

/// The default [`crate::Forge::diff`]: compare observed state with the
/// projection field by field. Roles are matched on the numeric account id,
/// never the login; a pending invitation counts as present.
pub fn default_diff(observed: &RepoState, desired: &Projection) -> Vec<Drift> {
    let mut drift = Vec::new();

    if let Some(expected) = desired.forge_id
        && expected != observed.forge_id
    {
        // A different repository: nothing else about it is comparable, and
        // reporting role drift on it would invite "fixing" a stranger's repo.
        return vec![Drift::Replaced {
            expected,
            observed: observed.forge_id,
        }];
    }
    if observed.resource != desired.resource {
        drift.push(Drift::Renamed {
            expected: desired.resource.clone(),
            observed: observed.resource.clone(),
        });
    }
    if observed.archived != desired.archived {
        drift.push(Drift::ArchiveMismatch {
            expected: desired.archived,
            observed: observed.archived,
        });
    }
    if let Some(expected) = desired.visibility
        && expected != observed.visibility
    {
        drift.push(Drift::VisibilityMismatch {
            expected,
            observed: observed.visibility,
        });
    }
    if let Some(check) = &desired.required_check {
        let gaps = protection_gaps(&observed.protection, check);
        if !gaps.is_empty() {
            drift.push(Drift::ProtectionWeakened { gaps });
        }
    }

    drift.extend(role_drift(observed, &desired.roles));
    drift
}

fn role_drift(observed: &RepoState, desired: &[RoleAssignment]) -> Vec<Drift> {
    let mut drift = Vec::new();
    for want in desired {
        let have = observed
            .collaborators
            .iter()
            .find(|c| c.account.id == want.account.id);
        match have {
            None if want.role != ForgeRole::None => drift.push(Drift::MissingRole {
                account: want.account.clone(),
                expected: want.role,
            }),
            Some(c) if want.role == ForgeRole::None => drift.push(Drift::UnexpectedRole {
                account: c.account.clone(),
                observed: c.role,
            }),
            Some(c) if c.role != want.role => drift.push(Drift::RoleMismatch {
                account: c.account.clone(),
                expected: want.role,
                observed: c.role,
            }),
            _ => {}
        }
    }
    for c in &observed.collaborators {
        if c.role != ForgeRole::None && !desired.iter().any(|d| d.account.id == c.account.id) {
            drift.push(Drift::UnexpectedRole {
                account: c.account.clone(),
                observed: c.role,
            });
        }
    }
    drift
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Collaborator;

    fn res(s: &str) -> Resource {
        Resource::parse(s).unwrap()
    }

    fn protected(check: &str) -> ProtectionState {
        ProtectionState {
            present: true,
            enforced: true,
            covers_default_branch: true,
            requires_pull_request: true,
            required_checks: vec![check.into()],
            blocks_force_push: true,
            blocks_deletion: true,
            bypass_actors: vec![],
            ..ProtectionState::default()
        }
    }

    fn alice() -> ForgeAccount {
        ForgeAccount::new(1, "alice")
    }
    fn bob() -> ForgeAccount {
        ForgeAccount::new(2, "bob")
    }

    #[test]
    fn a_matching_repo_has_no_drift() {
        let mut state = RepoState::new(res("github.com/acme/w"), 9);
        state.protection = protected("Verify commit trust");
        state.collaborators = vec![
            Collaborator::new(ForgeAccount::new(1, "alice-renamed"), ForgeRole::Admin),
            Collaborator::invited(bob(), ForgeRole::Maintain),
        ];
        let mut want = Projection::new(res("github.com/acme/w"));
        want.forge_id = Some(9);
        want.required_check = Some("Verify commit trust".into());
        want.roles = vec![
            RoleAssignment::new(alice(), ForgeRole::Admin),
            RoleAssignment::new(bob(), ForgeRole::Maintain),
        ];
        assert_eq!(default_diff(&state, &want), vec![]);
    }

    #[test]
    fn role_drift_is_matched_by_id() {
        let mut state = RepoState::new(res("github.com/acme/w"), 9);
        state.collaborators = vec![
            Collaborator::new(alice(), ForgeRole::Write),
            Collaborator::new(ForgeAccount::new(3, "mallory"), ForgeRole::Admin),
        ];
        let mut want = Projection::new(res("github.com/acme/w"));
        want.roles = vec![
            RoleAssignment::new(alice(), ForgeRole::Admin),
            RoleAssignment::new(bob(), ForgeRole::Maintain),
        ];
        let drift = default_diff(&state, &want);
        assert_eq!(
            drift,
            vec![
                Drift::RoleMismatch {
                    account: alice(),
                    expected: ForgeRole::Admin,
                    observed: ForgeRole::Write
                },
                Drift::MissingRole {
                    account: bob(),
                    expected: ForgeRole::Maintain
                },
                Drift::UnexpectedRole {
                    account: ForgeAccount::new(3, "mallory"),
                    observed: ForgeRole::Admin
                },
            ]
        );
        assert!(!drift.iter().any(Drift::is_critical));
    }

    #[test]
    fn weakened_protection_lists_every_gap() {
        let mut state = RepoState::new(res("github.com/acme/w"), 9);
        let mut p = protected("something else");
        p.enforced = false;
        p.blocks_force_push = false;
        p.bypass_actors = vec!["OrganizationAdmin".into()];
        state.protection = p;
        let mut want = Projection::new(res("github.com/acme/w"));
        want.required_check = Some("Verify commit trust".into());
        let drift = default_diff(&state, &want);
        assert_eq!(
            drift,
            vec![Drift::ProtectionWeakened {
                gaps: vec![
                    ProtectionGap::NotEnforced,
                    ProtectionGap::CheckNotRequired {
                        check: "Verify commit trust".into()
                    },
                    ProtectionGap::ForcePushAllowed,
                    ProtectionGap::BypassActors {
                        actors: vec!["OrganizationAdmin".into()]
                    },
                ]
            }]
        );
        assert!(drift[0].is_critical());

        state.protection = ProtectionState::default();
        assert_eq!(
            default_diff(&state, &want),
            vec![Drift::ProtectionWeakened {
                gaps: vec![ProtectionGap::Missing]
            }]
        );
    }

    #[test]
    fn rename_and_replacement_are_told_apart_by_forge_id() {
        let state = RepoState::new(res("github.com/acme/new-name"), 9);
        let mut want = Projection::new(res("github.com/acme/w"));
        want.forge_id = Some(9);
        assert_eq!(
            default_diff(&state, &want),
            vec![Drift::Renamed {
                expected: res("github.com/acme/w"),
                observed: res("github.com/acme/new-name")
            }]
        );

        let imposter = RepoState::new(res("github.com/acme/w"), 10);
        assert_eq!(
            default_diff(&imposter, &want),
            vec![Drift::Replaced {
                expected: 9,
                observed: 10
            }]
        );
    }
}
