//! Pull requests, as far as the pull-request gate needs them
//! (`git-ns/bridge/event` 0.4 `pullRequestOpened`, `git-ns/bridge/job` 0.5
//! `closePullRequest`).
//!
//! The gate is hygiene, not the merge gate: the required commit-trust check
//! is what keeps untrusted commits out. So this is deliberately small — the
//! state of one pull request, whether the adapter already commented on it,
//! a comment, a close — and it never reads what a pull request contains.

use serde::{Deserialize, Serialize};

use crate::model::ForgeAccount;

/// Where a pull request stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum PullRequestState {
    /// Open.
    Open,
    /// Closed without being merged.
    Closed,
    /// Merged (and so closed).
    Merged,
}

/// A reopen of a pull request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Reopen {
    /// Who reopened it, as the forge records it (not assumed to be the
    /// author).
    pub by: ForgeAccount,
    /// When, in Unix seconds.
    pub at: i64,
}

impl Reopen {
    /// A reopen by `by` at `at` (Unix seconds).
    pub fn new(by: ForgeAccount, at: i64) -> Self {
        Reopen { by, at }
    }
}

/// One pull request, as [`crate::Forge::pull_request`] reads it now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PullRequest {
    /// Open, closed or merged.
    pub state: PullRequestState,
    /// The most recent reopen by an account **other than the adapter's
    /// own** (its App or bot), if there was one. `closePullRequest` stands
    /// down when this is later than the job: an owner's or maintainer's
    /// reopen is a newer fact than the VTC's order to close.
    pub last_reopen_by_other: Option<Reopen>,
}

impl PullRequest {
    /// A pull request in `state`, never reopened by anyone else.
    pub fn new(state: PullRequestState) -> Self {
        PullRequest {
            state,
            last_reopen_by_other: None,
        }
    }

    /// With the most recent reopen by another account.
    pub fn with_reopen(mut self, reopen: Reopen) -> Self {
        self.last_reopen_by_other = Some(reopen);
        self
    }

    /// Whether it is open.
    pub fn is_open(&self) -> bool {
        self.state == PullRequestState::Open
    }
}
