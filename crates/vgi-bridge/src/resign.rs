//! The Dependabot re-sign (design §9, "Dependabot re-sign bot").
//!
//! verify-trust exempts a `web-flow`-signed commit only when it is a clean
//! merge, so a Dependabot pull request fails the check: its commits are
//! single-parent, signed by GitHub, and nothing in them proves Dependabot
//! wrote them — any writer can have GitHub write and sign a commit with any
//! `author` through the Contents API. So that Dependabot pull requests still
//! merge without a human step, the GitHub bridge re-signs them with **its
//! own DID**, which the VTC grants `git.commit.sign` on the namespace.
//!
//! **Provenance comes from signed `push` webhooks, never from authorship.**
//!
//! 1. **The ledger.** Every verified `push` to a `dependabot/*` branch is
//!    recorded ([`BranchLedger`]): before, after, the sender GitHub reports
//!    (login *and* numeric id), the `created` flag, the delivery. A deletion
//!    clears the branch's record; a creation starts it afresh — but only a
//!    delivery at least as new (GitHub's signed `repository.pushed_at`) as
//!    every one recorded may reset or clear it, and one older than six days
//!    is not recorded at all (a replay the delivery ids no longer catch). At
//!    most 64 branches per repository are tracked; the one untouched longest
//!    is forgotten, and a forgotten branch is never clean.
//! 2. **Clean.** A branch is Dependabot-clean up to a head `H` when, walking
//!    back from `H` through `after → before`, every link is a recorded push
//!    and the walk ends at a creation pushed by Dependabot; and every push
//!    recorded on the branch came from Dependabot or was the bridge's own
//!    re-sign (recorded, before it was sent, as exactly that
//!    `before → after` — which also bridges the walk when the webhook for
//!    the bridge's own push never arrived). A push the bridge never saw (it was down), a push by
//!    anyone else, or a record that does not lead back to the creation, and
//!    the branch is not clean: nothing is re-signed, the check fails as it
//!    would anyway, and its summary says why and what a maintainer can do.
//! 3. **When.** On `pull_request` `opened` / `synchronize` / `reopened`, and
//!    again when a push lands on a branch whose pull request was already
//!    seen (deliveries arrive in any order). GitHub's API — not the delivery
//!    — must say the pull request is open, was opened by Dependabot (login
//!    and id), has its head on a `dependabot/*` branch **in the same
//!    repository**, and targets the protected default branch; the namespace
//!    must have the re-sign on (per-namespace config, on by default) and a
//!    platform (`web-flow`) keyring configured.
//! 4. **Each commit** in `base...head`, oldest first, must have exactly one
//!    parent (the previous commit of the range, or for the first, any), be
//!    `web-flow`-signed with a signature that verifies against the configured
//!    keyring, carry only the standard headers, be authored by Dependabot's
//!    noreply identity, and change nothing under `.github/workflows/` (the
//!    changed paths are read from the trees; if they cannot be, nothing is
//!    re-signed). Workflow changes are left to a maintainer: the bridge
//!    does not vouch for what CI runs, and does not hold the `workflows`
//!    permission a push of them would need anyway.
//! 5. **Re-signed.** Each commit becomes a new commit with the **same tree**
//!    (so nothing but commit objects is written), the original author line
//!    unchanged, the bridge as committer (`[resign]`, dated now), the
//!    original message plus a `Signed-by-DID: <bridge DID>#<key>` trailer
//!    (placed by `git interpret-trailers`, as did-git-sign's hook does, and
//!    read back with verify-trust's own trailer reader before signing), and
//!    an sshsig (`git` namespace) by the bridge's Ed25519 DID key, made with
//!    vgi-core's encoder. The parent chain is rebuilt on the first commit's
//!    original parent.
//! 6. **Pushed** with a contents-write token for that one repository,
//!    `--force-with-lease` on the exact old head (a push that landed in
//!    between is never overwritten), over the same hardened git as the check
//!    (no hooks, no config, `https` only, the token in an `extraHeader` from
//!    the environment). The push is recorded in the ledger as the bridge's
//!    own **before** it is sent.
//!
//! Re-signs run a bounded number at a time (`checks.concurrency`) and one at
//! a time per branch. Holding the branch, a run reads where the branch
//! points on the forge itself (not the API, which can lag a push) and
//! re-signs only if it is still the pull request's head: a run that read
//! the pull request while another was re-signing the branch then stops
//! rather than pushing on a lease that can no longer hold. It never loops:
//! a head whose commits already carry the bridge's signature is left alone
//! (Ed25519 is deterministic, so "our signature over this payload" is
//! checked exactly), and any commit that is not `web-flow`-signed stops the
//! re-sign.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use http::StatusCode;
use verify_trust::pgp_exempt::ExemptKeyring;
use vgi_core::{
    GIT_SSHSIG_NAMESPACE, conflicting_signer_dids, create_ssh_signature, normalize_sshsig_armor,
    signer_did, split_signed_commit,
};
use vgi_forge::Resource;
use vgi_forge_github::resign::ZERO_SHA;
use vgi_forge_github::{CheckTrigger, CheckTriggerKind, PullRequestInfo, PushEvent};

use crate::bridge::{Bridge, now};
use crate::config::GitHubForgeConfig;
use crate::identity::GitSigningKey;
use crate::jobs::Ctx;
use crate::store::{BranchLedger, NamespaceRecord, NamespaceState, OwnPush, PushRecord, Table};

/// Pushes one branch's ledger keeps; past this the branch is never clean.
const MAX_PUSHES: usize = 256;
/// The bridge's own pushes one branch's ledger keeps.
const MAX_OWN: usize = 64;
/// Dependabot branches tracked per repository; past this the one untouched
/// longest is forgotten.
const MAX_BRANCHES_PER_REPO: usize = 64;
/// Push deliveries older than this (by GitHub's `repository.pushed_at`) are
/// not recorded: the bridge forgets delivery ids after 7 days, so an older
/// delivery could be a replay it can no longer recognise.
const REPLAY_WINDOW_SECS: i64 = 6 * 86_400;
/// The workflow directory. A change under it is never re-signed: the
/// bridge does not vouch for what CI runs.
const WORKFLOWS: &str = ".github/workflows";
/// Ledgers untouched this long are dropped by the hourly maintenance.
const LEDGER_TTL_SECS: i64 = 90 * 86_400;
/// The branch prefix Dependabot pushes to.
pub const DEPENDABOT_PREFIX: &str = "dependabot/";

/// What one re-sign attempt came to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResignOutcome {
    /// The commits were re-signed and pushed.
    Resigned {
        /// The head that was replaced.
        old_head: String,
        /// The re-signed head.
        new_head: String,
        /// How many commits were re-signed.
        commits: usize,
    },
    /// Nothing was done, and why.
    Skipped(String),
}

/// Re-signs run a bounded number at a time, and one at a time per branch.
pub struct ResignRunner {
    permits: tokio::sync::Semaphore,
    in_flight: Mutex<BTreeSet<(u64, String)>>,
}

impl ResignRunner {
    /// At most `concurrency` re-signs at once.
    pub fn new(concurrency: usize) -> Self {
        ResignRunner {
            permits: tokio::sync::Semaphore::new(concurrency.max(1)),
            in_flight: Mutex::new(BTreeSet::new()),
        }
    }
}

struct InFlight<'a> {
    set: &'a Mutex<BTreeSet<(u64, String)>>,
    key: (u64, String),
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.set.lock().expect("lock").remove(&self.key);
    }
}

/// The ledger key of `branch` in repository `repo_id` on `host`.
pub fn ledger_key(host: &str, repo_id: u64, branch: &str) -> String {
    format!("{host}#{repo_id}#{branch}")
}

/// A `dependabot/*` branch name safe to put on a git command line: git's
/// ref-name rules, over a conservative character set.
pub fn check_branch_name(branch: &str) -> Result<()> {
    let ok = branch.starts_with(DEPENDABOT_PREFIX)
        && branch.len() <= 255
        && branch
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/@+".contains(&b))
        && !branch.contains("..")
        && !branch.contains("@{")
        && !branch.contains("//")
        && !branch.ends_with('/')
        && branch
            .split('/')
            .all(|c| !c.is_empty() && !c.starts_with('.') && !c.ends_with(".lock"));
    if ok {
        Ok(())
    } else {
        bail!("`{branch}` is not a Dependabot branch name this bridge pushes to")
    }
}

// ── the ledger ───────────────────────────────────────────────────────────

/// Make room for a new ledger under `key`: past [`MAX_BRANCHES_PER_REPO`]
/// ledgers in the repository, the one untouched longest is dropped (its
/// branch is then unknown, so never clean — fail-safe).
fn make_room(bridge: &Bridge, key: &str) -> Result<()> {
    if bridge
        .store
        .get::<BranchLedger>(Table::Branches, key)?
        .is_some()
    {
        return Ok(());
    }
    // `<host>#<repo id>#`: every ledger of the same repository.
    let prefix: String = {
        let mut parts = key.splitn(3, '#');
        format!(
            "{}#{}#",
            parts.next().unwrap_or_default(),
            parts.next().unwrap_or_default()
        )
    };
    let mut same: Vec<(i64, String)> = bridge
        .store
        .list::<BranchLedger>(Table::Branches)?
        .into_iter()
        .filter(|(k, _)| k.starts_with(&prefix))
        .map(|(k, l)| (l.touched, k))
        .collect();
    same.sort();
    let excess = (same.len() + 1).saturating_sub(MAX_BRANCHES_PER_REPO);
    for (_, k) in same.into_iter().take(excess) {
        tracing::info!(ledger = %k, "dropping the oldest Dependabot branch record");
        bridge.store.delete(Table::Branches, &k)?;
    }
    Ok(())
}

/// Record a verified push in its branch's ledger. Returns the pull request
/// already seen for the branch, if any, so the re-sign can resume.
///
/// Replays are held off by GitHub's own clock, which the delivery's
/// signature covers (`repository.pushed_at`): a delivery older than
/// [`REPLAY_WINDOW_SECS`] — older than the delivery ids the bridge keeps —
/// is not recorded at all, and only a delivery at least as new as every one
/// recorded may reset the ledger (a creation) or clear it (a deletion). One
/// that is older, or carries no time, only adds its record, which can make
/// a branch unclean but never clean.
pub fn record_push(bridge: &Bridge, host: &str, push: &PushEvent) -> Result<Option<u64>> {
    let branch = push.branch().context("not a branch")?.to_string();
    let key = ledger_key(host, push.repo_id, &branch);
    let now = now();
    if let Some(t) = push.pushed_at
        && t < now - REPLAY_WINDOW_SECS
    {
        tracing::warn!(
            repo = %push.repo, %branch, pushed_at = t,
            "ignoring a push delivery older than the replay window"
        );
        return Ok(None);
    }
    if !push.deleted {
        make_room(bridge, &key)?;
    }
    bridge
        .store
        .update::<BranchLedger, _>(Table::Branches, &key, |current| {
            let existed = current.is_some();
            let mut l = current.unwrap_or_default();
            let pr = l.pull_request;
            let newest = match (push.pushed_at, l.last_pushed_at) {
                (Some(t), Some(last)) => t >= last,
                (Some(_), None) => true,
                (None, _) => !existed,
            };
            if push.deleted {
                if newest {
                    // The branch is gone (and with it any pull request):
                    // its record ends here.
                    return Ok((None, None));
                }
                tracing::info!(%branch, "ignoring a deletion older than the branch's record");
                return Ok((existed.then_some(l), None));
            }
            if push.created && newest {
                // A new branch under an old name: what happened to the
                // old one says nothing about this one. The pull request
                // number is kept — its delivery may have come first.
                l = BranchLedger {
                    pull_request: pr,
                    last_pushed_at: l.last_pushed_at,
                    ..BranchLedger::default()
                };
            }
            l.repo = Some(push.repo.clone());
            l.branch = branch.clone();
            l.touched = now;
            if let Some(t) = push.pushed_at {
                l.last_pushed_at = Some(l.last_pushed_at.map_or(t, |last| last.max(t)));
            }
            let rec = PushRecord {
                before: push.before.clone(),
                after: push.after.clone(),
                sender_login: push.sender_login.clone(),
                sender_id: push.sender_id,
                created: push.created,
                delivery_id: push.delivery_id.clone(),
                at: now,
            };
            let repeat = l.pushes.iter().any(|p| {
                p.before == rec.before && p.after == rec.after && p.sender_id == rec.sender_id
            });
            if !repeat {
                if l.pushes.len() >= MAX_PUSHES {
                    l.overflow = true;
                } else {
                    l.pushes.push(rec);
                }
            }
            Ok((Some(l), pr))
        })
}

/// Remember the pull request open from a branch.
fn remember_pull_request(bridge: &Bridge, key: &str, number: u64) -> Result<()> {
    make_room(bridge, key)?;
    bridge
        .store
        .update::<BranchLedger, _>(Table::Branches, key, |l| {
            let mut l = l.unwrap_or_default();
            l.pull_request = Some(number);
            l.touched = now();
            Ok((Some(l), ()))
        })
}

/// Record a push the bridge is about to make, so that its webhook is
/// recognised as the bridge's own.
fn record_own(bridge: &Bridge, key: &str, before: &str, after: &str) -> Result<()> {
    bridge
        .store
        .update::<BranchLedger, _>(Table::Branches, key, |l| {
            let mut l = l.context("the branch's ledger disappeared")?;
            if l.own.len() >= MAX_OWN {
                l.own.remove(0);
            }
            l.own.push(OwnPush {
                before: before.to_string(),
                after: after.to_string(),
                at: now(),
            });
            l.touched = now();
            Ok((Some(l), ()))
        })
}

/// Note why the re-sign of `head` stopped at its commits, for the check.
fn note_skip(bridge: &Bridge, key: &str, head: &str, why: &str) {
    let _ = bridge
        .store
        .update::<BranchLedger, _>(Table::Branches, key, |l| {
            Ok((
                l.map(|mut l| {
                    l.last_skip = Some((head.to_string(), why.to_string()));
                    l.touched = now();
                    l
                }),
                (),
            ))
        });
}

fn short(sha: &str) -> &str {
    &sha[..sha.len().min(12)]
}

/// Whether the branch `ledger` records is Dependabot-clean up to `head`:
/// `Ok`, or why not.
pub fn is_clean(ledger: &BranchLedger, head: &str, login: &str, id: u64) -> Result<(), String> {
    if ledger.overflow {
        return Err(format!(
            "more than {MAX_PUSHES} pushes were made to the branch"
        ));
    }
    let dependabot = |p: &PushRecord| p.sender_login == login && p.sender_id == id;
    let own = |p: &PushRecord| {
        ledger
            .own
            .iter()
            .any(|o| o.before == p.before && o.after == p.after)
    };
    if let Some(p) = ledger.pushes.iter().find(|p| !dependabot(p) && !own(p)) {
        return Err(format!(
            "`{}` (id {}) pushed to the branch ({} → {})",
            p.sender_login,
            p.sender_id,
            short(&p.before),
            short(&p.after)
        ));
    }
    let mut cur = head;
    for _ in 0..=(ledger.pushes.len() + ledger.own.len()) {
        let Some(p) = ledger.pushes.iter().find(|p| p.after == cur) else {
            // A push the bridge made itself, whose webhook it missed: its
            // own record says exactly what it replaced. (The head it names
            // only ever existed in the bridge until it pushed it, so no one
            // else can have put it there.)
            if let Some(o) = ledger.own.iter().find(|o| o.after == cur) {
                cur = &o.before;
                continue;
            }
            return Err(format!(
                "the bridge has no record of the push that made {} the head (it may have been \
                 down when it happened)",
                short(cur)
            ));
        };
        if p.created {
            return if dependabot(p) {
                Ok(())
            } else {
                Err("the branch was not created by Dependabot".into())
            };
        }
        if p.before == ZERO_SHA {
            return Err("a push with no previous head is not marked as the creation".into());
        }
        cur = &p.before;
    }
    Err("the recorded pushes do not lead back to the branch's creation".into())
}

// ── deciding ─────────────────────────────────────────────────────────────

/// The bound namespace containing `repo`, on a GitHub adapter.
fn github_ctx(bridge: &Bridge, repo: &Resource) -> Option<Ctx> {
    let ns = bridge
        .store
        .list::<NamespaceRecord>(Table::Namespaces)
        .ok()?
        .into_iter()
        .map(|(_, n)| n)
        .find(|n| n.state == NamespaceState::Bound && n.resource.contains(repo))?;
    let ctx = Ctx::load(bridge, &ns.id).ok()?;
    ctx.adapter.github()?;
    Some(ctx)
}

fn github_config<'a>(bridge: &'a Bridge, host: &str) -> Option<&'a GitHubForgeConfig> {
    bridge.cfg.github.iter().find(|g| g.host == host)
}

/// Whether `pr` was opened by Dependabot, by login and id.
fn opened_by_dependabot(gh: &GitHubForgeConfig, pr: &PullRequestInfo) -> bool {
    pr.author_login.as_deref() == Some(gh.dependabot_login.as_str())
        && pr.author_id == Some(gh.dependabot_id)
}

/// Everything short of the commits themselves: `Ok` with the keyring to
/// check them against, or why this pull request is not re-signed.
/// `protected` is the repository's default branch, when known.
fn eligibility(
    bridge: &Bridge,
    ctx: &Ctx,
    repo: &Resource,
    repo_id: u64,
    pr: &PullRequestInfo,
    protected: Option<&str>,
) -> Result<std::path::PathBuf, String> {
    let gh = github_config(bridge, repo.host()).ok_or("no GitHub is configured for this host")?;
    if !ctx.adapter.forge().capabilities(&ctx.namespace).automation {
        return Err("the namespace is in manual mode".into());
    }
    if !gh.resign_dependabot(ctx.ns.resource.owner()) {
        return Err("the re-sign is turned off for this namespace".into());
    }
    let keyring = gh.platform_keyring_file.clone().ok_or(
        "no platform (web-flow) keyring is configured, so GitHub's signatures cannot be checked",
    )?;
    if !pr.open {
        return Err("the pull request is closed".into());
    }
    if !opened_by_dependabot(gh, pr) {
        return Err("the pull request was not opened by Dependabot".into());
    }
    if pr.head_repo_id != Some(repo_id) || pr.base_repo_id != Some(repo_id) {
        return Err("the pull request's head is not a branch of this repository".into());
    }
    check_branch_name(&pr.head_ref).map_err(|e| e.to_string())?;
    if let Some(p) = protected
        && pr.base_ref != p
    {
        return Err(format!("it does not target the protected branch `{p}`"));
    }
    let key = ledger_key(repo.host(), repo_id, &pr.head_ref);
    let ledger = bridge
        .store
        .get::<BranchLedger>(Table::Branches, &key)
        .map_err(|e| format!("the ledger is unavailable: {e}"))?
        .ok_or("the bridge recorded no push to the branch (it may have been down)")?;
    is_clean(
        &ledger,
        &pr.head_sha,
        &gh.dependabot_login,
        gh.dependabot_id,
    )?;
    Ok(keyring)
}

/// For a failing check on a Dependabot pull request: what the bridge does
/// about it, as a paragraph for the check's summary. `None` for any other
/// pull request. `protected` is the branch the check was posted against.
pub(crate) fn check_hint(
    bridge: &Bridge,
    ctx: &Ctx,
    trigger: &CheckTrigger,
    pr: &PullRequestInfo,
    protected: &str,
) -> Option<String> {
    let gh = github_config(bridge, trigger.repo.host())?;
    if !opened_by_dependabot(gh, pr) {
        return None;
    }
    let by_hand = "A maintainer who is an enrolled signer must re-sign the commits by hand \
                   (runbook §5: `gh pr checkout <number>`, then `git rebase --exec 'git commit \
                   --amend --no-edit -S' origin/main` and `git push --force-with-lease`)";
    // What the last re-sign of this very head found in its commits.
    let noted = bridge
        .store
        .get::<BranchLedger>(
            Table::Branches,
            &ledger_key(trigger.repo.host(), trigger.repo_id, &pr.head_ref),
        )
        .ok()
        .flatten()
        .and_then(|l| l.last_skip)
        .filter(|(head, _)| *head == pr.head_sha)
        .map(|(_, why)| why);
    let verdict = eligibility(
        bridge,
        ctx,
        &trigger.repo,
        trigger.repo_id,
        pr,
        Some(protected),
    )
    .and_then(|_| noted.map_or(Ok(()), Err));
    Some(match verdict {
        Ok(()) => format!(
            "\n\n**Dependabot.** Only Dependabot has pushed to this branch, so the \
             community's bridge re-signs these commits with its own DID (`{}`) and the check \
             runs again on the re-signed head — unless they change `{WORKFLOWS}/`, which the \
             bridge never re-signs. If the re-signed commits fail too, the VTC has not granted \
             the bridge `git.commit.sign` on this namespace.",
            bridge.did()
        ),
        Err(why) if why.contains(WORKFLOWS) => format!(
            "\n\n**Dependabot.** This pull request changes `{WORKFLOWS}/`, and the bridge never \
             re-signs workflow changes. {by_hand}."
        ),
        Err(why) => format!(
            "\n\n**Dependabot.** The bridge will not re-sign this pull request: {why}. \
             {by_hand}, or Dependabot must start the branch over: close the pull request and \
             delete the branch, or comment `@dependabot recreate` (which is re-signed only if \
             Dependabot re-creates the branch rather than force-pushing it)."
        ),
    })
}

/// Whether a changed path is (or could stand for) a workflow file.
fn touches_workflows(path: &[u8]) -> bool {
    let p = String::from_utf8_lossy(path).to_ascii_lowercase();
    p == ".github" || p == WORKFLOWS || p.starts_with(&format!("{WORKFLOWS}/"))
}

/// Whether the change from `parent` to `commit` touches the workflow
/// directory, read from the two trees (`diff-tree`, names only — no blob is
/// needed). `Err` when the trees cannot be read: the caller then re-signs
/// nothing.
async fn changes_workflows(
    fetcher: &crate::checks::GitFetcher,
    dir: &std::path::Path,
    parent: &str,
    commit: &str,
) -> Result<bool> {
    let out = fetcher
        .git_with_input(
            dir,
            &[
                "diff-tree",
                "-r",
                "-z",
                "--no-renames",
                "--name-only",
                "--no-commit-id",
                parent,
                commit,
            ],
            b"",
        )
        .await?;
    Ok(out
        .split(|&b| b == 0)
        .filter(|p| !p.is_empty())
        .any(touches_workflows))
}

// ── acting ───────────────────────────────────────────────────────────────

/// A verified `push` delivery: record it, and resume the re-sign of the
/// branch's pull request if one was seen. Returns the status for GitHub.
pub(crate) fn on_push(bridge: &Arc<Bridge>, host: &str, push: PushEvent) -> StatusCode {
    let Some(branch) = push.branch() else {
        return StatusCode::NO_CONTENT;
    };
    if !branch.starts_with(DEPENDABOT_PREFIX) {
        return StatusCode::NO_CONTENT;
    }
    if let Err(e) = check_branch_name(branch) {
        tracing::info!(repo = %push.repo, error = %e, "ignoring a push");
        return StatusCode::NO_CONTENT;
    }
    if github_ctx(bridge, &push.repo).is_none() {
        return StatusCode::NO_CONTENT;
    }
    let seen_key = push.delivery_id.as_deref().map(|d| format!("{host}#{d}"));
    if let Some(k) = &seen_key
        && matches!(bridge.store.get::<i64>(Table::Deliveries, k), Ok(Some(_)))
    {
        return StatusCode::OK;
    }
    let pr = match record_push(bridge, host, &push) {
        Ok(pr) => pr,
        Err(e) => {
            tracing::error!(repo = %push.repo, %branch, error = %e, "could not record a push");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };
    tracing::info!(
        repo = %push.repo, %branch, sender = %push.sender_login,
        before = %short(&push.before), after = %short(&push.after),
        created = push.created, deleted = push.deleted, "recorded a push"
    );
    if let Some(k) = seen_key {
        let _ = bridge.store.put(Table::Deliveries, &k, &now());
    }
    if let Some(number) = pr
        && !push.deleted
    {
        spawn(bridge, push.repo.clone(), push.repo_id, number);
    }
    StatusCode::ACCEPTED
}

/// Pull request deliveries that may be Dependabot's: re-sign, in the
/// background. The delivery's own head branch and author are only a filter
/// here; [`run`] re-reads both from GitHub.
pub(crate) fn on_pull_request_triggers(bridge: &Arc<Bridge>, triggers: &[CheckTrigger]) {
    for t in triggers {
        let CheckTriggerKind::PullRequest { number } = t.kind else {
            continue;
        };
        let Some(gh) = github_config(bridge, t.repo.host()) else {
            continue;
        };
        let head = t.head_ref.as_deref().unwrap_or_default();
        if head.starts_with(DEPENDABOT_PREFIX)
            && t.author_login.as_deref() == Some(gh.dependabot_login.as_str())
        {
            spawn(bridge, t.repo.clone(), t.repo_id, number);
        }
    }
}

fn spawn(bridge: &Arc<Bridge>, repo: Resource, repo_id: u64, number: u64) {
    let bridge = Arc::clone(bridge);
    tokio::spawn(async move {
        match run(&bridge, &repo, repo_id, number).await {
            Ok(ResignOutcome::Resigned {
                old_head,
                new_head,
                commits,
            }) => tracing::info!(
                %repo, pr = number, commits, old = %short(&old_head), new = %short(&new_head),
                "re-signed a Dependabot pull request"
            ),
            Ok(ResignOutcome::Skipped(why)) => {
                tracing::info!(%repo, pr = number, %why, "not re-signing")
            }
            Err(e) => {
                tracing::warn!(%repo, pr = number, error = %e, "the re-sign did not complete")
            }
        }
    });
}

/// Re-sign pull request `number` of `repo` (forge id `repo_id`) if it
/// qualifies (see the module documentation).
pub async fn run(
    bridge: &Bridge,
    repo: &Resource,
    repo_id: u64,
    number: u64,
) -> Result<ResignOutcome> {
    let skip = |why: String| Ok(ResignOutcome::Skipped(why));
    let Some(ctx) = github_ctx(bridge, repo) else {
        return skip("the repository is in no bound GitHub namespace".into());
    };
    let g = ctx.adapter.github().context("a GitHub namespace")?.clone();
    let pr = g.pull_request(repo, number).await?;
    let key = ledger_key(repo.host(), repo_id, &pr.head_ref);
    if pr.open
        && pr.head_repo_id == Some(repo_id)
        && check_branch_name(&pr.head_ref).is_ok()
        && let Some(gh) = github_config(bridge, repo.host())
        && opened_by_dependabot(gh, &pr)
    {
        // So that a push delivered after this one can resume the re-sign.
        remember_pull_request(bridge, &key, number)?;
    }
    let protected = g.default_branch(repo).await?;
    let keyring = match eligibility(bridge, &ctx, repo, repo_id, &pr, Some(&protected)) {
        Ok(k) => k,
        Err(why) => return skip(why),
    };

    let _permit = bridge.resign.permits.acquire().await?;
    let flight = (repo_id, pr.head_ref.clone());
    if !bridge
        .resign
        .in_flight
        .lock()
        .expect("lock")
        .insert(flight.clone())
    {
        return skip("a re-sign of this branch is already running".into());
    }
    let _flight = InFlight {
        set: &bridge.resign.in_flight,
        key: flight,
    };

    let cmp = g.compare_commits(repo, &pr.base_sha, &pr.head_sha).await?;
    let max = bridge.cfg.checks.max_commits;
    if cmp.total as usize > max || (cmp.commits.len() as u64) < cmp.total {
        return skip(format!(
            "{} commits, more than this bridge re-signs at once ({max}) or than GitHub listed",
            cmp.total
        ));
    }
    if cmp.commits.last().map(String::as_str) != Some(pr.head_sha.as_str()) {
        return skip("nothing to re-sign: the head is already part of the base".into());
    }
    let token = g.contents_read_token(repo).await?;
    let remote = g.clone_url(repo)?;
    let fetcher = &bridge.checks.fetcher;
    let fetched = fetcher
        .fetch_for_rewrite(&remote, Some(token.expose()), &pr.head_sha, &cmp.commits)
        .await?;
    // The pull request was read before this run held the branch: another
    // run may have re-signed (and pushed) it since, and the forge's API can
    // still report the old head for a while after a push. The branch
    // itself, read under the guard, is what the lease must match — no other
    // re-sign of this branch can push until this one is done.
    let current = fetcher
        .branch_head(fetched.dir.path(), Some(token.expose()), &pr.head_ref)
        .await?;
    drop(token);
    if current.as_deref() != Some(pr.head_sha.as_str()) {
        let ours = current.as_deref().is_some_and(|c| {
            bridge
                .store
                .get::<BranchLedger>(Table::Branches, &key)
                .ok()
                .flatten()
                .is_some_and(|l| {
                    l.own
                        .iter()
                        .any(|o| o.before == pr.head_sha && o.after == c)
                })
        });
        return skip(if ours {
            "already re-signed by the bridge".into()
        } else {
            format!(
                "the branch is at {}, no longer the pull request's head {} (the push that moved \
                 it resumes the re-sign)",
                current.as_deref().map_or("nothing", short),
                short(&pr.head_sha)
            )
        });
    }

    let signing = bridge.identity().git_signing_key()?;
    if fetched
        .commits
        .iter()
        .all(|c| signed_by(&c.raw, &signing).unwrap_or(false))
    {
        return skip("already re-signed by the bridge".into());
    }
    let gh = github_config(bridge, repo.host()).context("GitHub config")?;
    let keyring = ExemptKeyring::load(&keyring)?;
    let author_email = format!(
        "{}+{}@users.noreply.{}",
        gh.dependabot_id,
        gh.dependabot_login,
        repo.host()
    );
    let committer = format!(
        "{} <{}> {} +0000",
        bridge.cfg.resign.committer_name,
        bridge.cfg.resign.committer_email,
        Utc::now().timestamp()
    );

    // A reason found in the commits themselves is noted for the check.
    let stop = |why: String| {
        note_skip(bridge, &key, &pr.head_sha, &why);
        Ok(ResignOutcome::Skipped(why))
    };
    let mut previous_original: Option<&str> = None;
    let mut previous_new: Option<String> = None;
    for c in &fetched.commits {
        let commit = match Commit::parse(&c.raw) {
            Ok(x) => x,
            Err(e) => return stop(format!("commit {}: {e}", short(&c.sha))),
        };
        if let Err(why) = commit.check_dependabot(
            &c.raw,
            previous_original,
            &keyring,
            &gh.dependabot_login,
            &author_email,
        ) {
            return stop(format!("commit {}: {why}", short(&c.sha)));
        }
        match changes_workflows(fetcher, fetched.dir.path(), &commit.parent, &c.sha).await {
            Ok(false) => {}
            Ok(true) => {
                return stop(format!(
                    "commit {} changes `{WORKFLOWS}/`, which the bridge never re-signs",
                    short(&c.sha)
                ));
            }
            Err(e) => {
                return stop(format!(
                    "the files commit {} changes could not be read ({e})",
                    short(&c.sha)
                ));
            }
        }
        let parent = previous_new.as_deref().unwrap_or(&commit.parent);
        let message = add_trailer(fetcher, fetched.dir.path(), &commit.message, &signing).await?;
        let raw = match resign_commit(&commit, parent, &committer, &message, &signing) {
            Ok(r) => r,
            Err(e) => return stop(format!("commit {}: {e}", short(&c.sha))),
        };
        let sha = String::from_utf8(
            fetcher
                .git_with_input(
                    fetched.dir.path(),
                    &["hash-object", "-t", "commit", "-w", "--stdin"],
                    &raw,
                )
                .await?,
        )?
        .trim()
        .to_string();
        vgi_forge_github::checks::check_sha(&sha).map_err(|e| anyhow!("{e}"))?;
        previous_original = Some(&c.sha);
        previous_new = Some(sha);
    }
    let new_head = previous_new.context("no commits")?;

    let token = g.contents_read_token(repo).await?;
    fetcher
        .complete_for_push(
            fetched.dir.path(),
            Some(token.expose()),
            &new_head,
            &pr.head_sha,
        )
        .await?;
    drop(token);

    // The bridge's own push, on record before it can be delivered.
    record_own(bridge, &key, &pr.head_sha, &new_head)?;
    let token = g.contents_write_token(repo).await?;
    fetcher
        .push(
            fetched.dir.path(),
            Some(token.expose()),
            &new_head,
            &pr.head_ref,
            &pr.head_sha,
        )
        .await
        .context("pushing the re-signed commits (with a lease on the old head)")?;
    Ok(ResignOutcome::Resigned {
        old_head: pr.head_sha,
        new_head,
        commits: fetched.commits.len(),
    })
}

/// Whether `raw` carries the bridge's own signature: the bridge's DID
/// claimed, and an sshsig equal to the one the bridge's key makes over the
/// payload (Ed25519 signatures are deterministic).
fn signed_by(raw: &[u8], signing: &GitSigningKey) -> Result<bool> {
    let Some((payload, pem)) = split_signed_commit(raw)? else {
        return Ok(false);
    };
    let did = signing
        .verification_method
        .split('#')
        .next()
        .unwrap_or_default();
    if signer_did(&payload).as_deref() != Some(did) {
        return Ok(false);
    }
    let ours = create_ssh_signature(
        &signing.key,
        &signing.key.verifying_key(),
        GIT_SSHSIG_NAMESPACE,
        &payload,
    )?;
    Ok(normalize_sshsig_armor(&pem) == normalize_sshsig_armor(&ours))
}

/// A commit object, split into what the re-sign keeps and replaces.
struct Commit {
    tree: String,
    parent: String,
    parents: usize,
    /// The `author` header's value, kept byte for byte.
    author: String,
    /// Header names other than tree, parent, author, committer and gpgsig.
    unexpected: Vec<String>,
    /// Everything after the blank line, as it is.
    message: String,
}

impl Commit {
    fn parse(raw: &[u8]) -> Result<Commit> {
        let text = std::str::from_utf8(raw).context("not UTF-8")?;
        let (headers, message) = text
            .split_once("\n\n")
            .context("no blank line after the headers")?;
        let (mut tree, mut parent, mut author) = (None, None, None);
        let mut parents = 0;
        let mut unexpected = Vec::new();
        for line in headers.split('\n') {
            if line.starts_with(' ') {
                // A continuation of the header before (gpgsig's armor).
                continue;
            }
            let (name, value) = line.split_once(' ').unwrap_or((line, ""));
            match name {
                "tree" => tree = Some(value.to_string()),
                "parent" => {
                    parents += 1;
                    parent = Some(value.to_string());
                }
                "author" => author = Some(value.to_string()),
                "committer" | "gpgsig" => {}
                other => unexpected.push(other.to_string()),
            }
        }
        let tree = tree.context("no tree")?;
        vgi_forge_github::checks::check_sha(&tree).map_err(|e| anyhow!("{e}"))?;
        let parent = parent.unwrap_or_default();
        if parents == 1 {
            vgi_forge_github::checks::check_sha(&parent).map_err(|e| anyhow!("{e}"))?;
        }
        Ok(Commit {
            tree,
            parent,
            parents,
            author: author.context("no author")?,
            unexpected,
            message: message.to_string(),
        })
    }

    /// The per-commit conditions: one parent, continuing the range; only
    /// the standard headers; a `web-flow` signature that verifies; authored
    /// by Dependabot. `Err` says which failed.
    fn check_dependabot(
        &self,
        raw: &[u8],
        previous: Option<&str>,
        keyring: &ExemptKeyring,
        login: &str,
        email: &str,
    ) -> Result<(), String> {
        if self.parents != 1 {
            return Err(format!("has {} parents, not one", self.parents));
        }
        if let Some(p) = previous
            && self.parent != p
        {
            return Err("does not follow the commit before it".into());
        }
        if !self.unexpected.is_empty() {
            return Err(format!("carries headers {:?}", self.unexpected));
        }
        let (payload, pem) = split_signed_commit(raw)
            .map_err(|e| e.to_string())?
            .ok_or("is not signed")?;
        if !pem.starts_with("-----BEGIN PGP SIGNATURE-----") {
            return Err("is not signed by the platform (web-flow)".into());
        }
        keyring
            .verify(&pem, &payload)
            .map_err(|e| format!("its platform signature does not verify: {e}"))?;
        let expected = format!("{login} <{email}> ");
        if !self.author.starts_with(&expected) {
            return Err(format!("is not authored by `{login} <{email}>`"));
        }
        Ok(())
    }
}

/// `message` with the bridge's `Signed-by-DID:` trailer, placed by `git
/// interpret-trailers` as did-git-sign's hook places it — but with
/// `--no-divider`: a Dependabot message holds a `---` line (its
/// `updated-dependencies` block), and without the flag git would put the
/// trailer above it, where the trailer reader verify-trust shares with `git
/// log` does not look. The result is read back with that reader before it
/// is used.
async fn add_trailer(
    fetcher: &crate::checks::GitFetcher,
    dir: &std::path::Path,
    message: &str,
    signing: &GitSigningKey,
) -> Result<String> {
    let vm = &signing.verification_method;
    if vm.chars().any(|c| c.is_whitespace() || c.is_control()) {
        bail!("the verification method id holds whitespace");
    }
    let trailer = format!("Signed-by-DID: {vm}");
    let out = fetcher
        .git_with_input(
            dir,
            &[
                "interpret-trailers",
                "--no-divider",
                "--if-exists",
                "doNothing",
                "--trailer",
                &trailer,
            ],
            message.as_bytes(),
        )
        .await?;
    String::from_utf8(out).context("interpret-trailers wrote non-UTF-8")
}

/// The re-signed commit object.
fn resign_commit(
    c: &Commit,
    parent: &str,
    committer: &str,
    message: &str,
    signing: &GitSigningKey,
) -> Result<Vec<u8>> {
    let headers = format!(
        "tree {}\nparent {parent}\nauthor {}\ncommitter {committer}",
        c.tree, c.author
    );
    let unsigned = format!("{headers}\n\n{message}");
    // What verify-trust will read: exactly the bridge's DID, and no second
    // claim beside it.
    let did = signing
        .verification_method
        .split('#')
        .next()
        .unwrap_or_default();
    if signer_did(unsigned.as_bytes()).as_deref() != Some(did)
        || conflicting_signer_dids(unsigned.as_bytes()).is_some()
    {
        bail!(
            "the message's trailers do not name the bridge's DID as the signer (the message \
             already carries a `Signed-by-DID:` trailer?)"
        );
    }
    let armored = create_ssh_signature(
        &signing.key,
        &signing.key.verifying_key(),
        GIT_SSHSIG_NAMESPACE,
        unsigned.as_bytes(),
    )?;
    let mut sig = String::from("gpgsig");
    for (i, line) in armored.trim_end().split('\n').enumerate() {
        sig.push_str(if i == 0 { " " } else { "\n " });
        sig.push_str(line);
    }
    let signed = format!("{headers}\n{sig}\n\n{message}");
    // The signature must cover exactly the unsigned object.
    let (payload, _) =
        split_signed_commit(signed.as_bytes())?.context("the signature did not attach")?;
    if payload != unsigned.as_bytes() {
        bail!("the signed commit does not split back into what was signed");
    }
    Ok(signed.into_bytes())
}

// ── the grant, and housekeeping ──────────────────────────────────────────

/// Warn when the registry shows that the bridge's DID lacks
/// `git.commit.sign` on namespace `ns_id` — without it every re-signed
/// commit fails the check as `unauthorized`. Advisory only.
pub(crate) async fn warn_if_ungranted(bridge: &Bridge, ns_id: &str) {
    let Ok(Some(ns)) = bridge
        .store
        .get::<NamespaceRecord>(Table::Namespaces, ns_id)
    else {
        return;
    };
    if ns.state != NamespaceState::Bound {
        return;
    }
    let Some(gh) = github_config(bridge, ns.resource.host()) else {
        return;
    };
    if !gh.resign_dependabot(ns.resource.owner()) {
        return;
    }
    match bridge
        .checks
        .verifier
        .commit_sign_granted(bridge.did(), ns.resource.as_str())
        .await
    {
        Ok(Some(false)) => tracing::warn!(
            namespace = %ns_id, resource = %ns.resource, did = %bridge.did(),
            "the registry does not grant this bridge's DID git.commit.sign on the namespace: \
             Dependabot pull requests it re-signs will fail the check until the VTC grants it"
        ),
        Ok(_) => {}
        Err(e) => tracing::info!(
            namespace = %ns_id, error = %e,
            "could not ask the registry whether the bridge may sign commits"
        ),
    }
}

/// Drop ledgers nothing has touched for 90 days.
pub(crate) fn prune(bridge: &Bridge) {
    let Ok(ledgers) = bridge.store.list::<BranchLedger>(Table::Branches) else {
        return;
    };
    let now = now();
    for (key, l) in ledgers {
        let last = l
            .pushes
            .iter()
            .map(|p| p.at)
            .chain(l.own.iter().map(|o| o.at))
            .chain(std::iter::once(l.touched))
            .max()
            .unwrap_or(0);
        if now - last > LEDGER_TTL_SECS {
            let _ = bridge.store.delete(Table::Branches, &key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEP: (&str, u64) = ("dependabot[bot]", 49_699_333);

    fn sha(c: char) -> String {
        c.to_string().repeat(40)
    }

    fn push(before: &str, after: &str, who: (&str, u64), created: bool) -> PushRecord {
        PushRecord {
            before: before.into(),
            after: after.into(),
            sender_login: who.0.into(),
            sender_id: who.1,
            created,
            delivery_id: None,
            at: 0,
        }
    }

    fn ledger(pushes: Vec<PushRecord>) -> BranchLedger {
        BranchLedger {
            pushes,
            ..BranchLedger::default()
        }
    }

    #[test]
    fn a_branch_only_dependabot_pushed_to_is_clean() {
        let l = ledger(vec![
            push(ZERO_SHA, &sha('a'), DEP, true),
            push(&sha('a'), &sha('b'), DEP, false),
        ]);
        assert_eq!(is_clean(&l, &sha('b'), DEP.0, DEP.1), Ok(()));
        // Up to an earlier head, too.
        assert_eq!(is_clean(&l, &sha('a'), DEP.0, DEP.1), Ok(()));
        // Out of arrival order: the chain is rebuilt from before/after.
        let mut r = l.clone();
        r.pushes.reverse();
        assert_eq!(is_clean(&r, &sha('b'), DEP.0, DEP.1), Ok(()));
    }

    #[test]
    fn a_foreign_push_makes_the_branch_unclean_even_when_overwritten() {
        let l = ledger(vec![
            push(ZERO_SHA, &sha('a'), DEP, true),
            push(&sha('a'), &sha('x'), ("mallory", 7), false),
            push(&sha('x'), &sha('b'), DEP, false),
        ]);
        let e = is_clean(&l, &sha('b'), DEP.0, DEP.1).unwrap_err();
        assert!(e.contains("mallory"), "{e}");
        // The login alone is not Dependabot: the id must match too.
        let l = ledger(vec![push(
            ZERO_SHA,
            &sha('a'),
            ("dependabot[bot]", 1),
            true,
        )]);
        assert!(is_clean(&l, &sha('a'), DEP.0, DEP.1).is_err());
    }

    #[test]
    fn a_gap_or_a_missing_creation_is_unclean() {
        // The push a → b was never recorded (the bridge was down).
        let l = ledger(vec![
            push(ZERO_SHA, &sha('a'), DEP, true),
            push(&sha('b'), &sha('c'), DEP, false),
        ]);
        let e = is_clean(&l, &sha('c'), DEP.0, DEP.1).unwrap_err();
        assert!(e.contains("no record"), "{e}");
        // No creation on record.
        let l = ledger(vec![push(&sha('a'), &sha('b'), DEP, false)]);
        assert!(is_clean(&l, &sha('b'), DEP.0, DEP.1).is_err());
        // Nothing recorded produced this head.
        let l = ledger(vec![push(ZERO_SHA, &sha('a'), DEP, true)]);
        assert!(is_clean(&l, &sha('f'), DEP.0, DEP.1).is_err());
        // Created by someone else.
        let l = ledger(vec![push(ZERO_SHA, &sha('a'), ("mallory", 7), true)]);
        assert!(is_clean(&l, &sha('a'), DEP.0, DEP.1).is_err());
        // Overflowed.
        let mut l = ledger(vec![push(ZERO_SHA, &sha('a'), DEP, true)]);
        l.overflow = true;
        assert!(is_clean(&l, &sha('a'), DEP.0, DEP.1).is_err());
    }

    #[test]
    fn the_bridges_own_push_is_accepted_only_exactly() {
        let bot = ("acme-vgi-bridge[bot]", 99);
        let mut l = ledger(vec![
            push(ZERO_SHA, &sha('a'), DEP, true),
            push(&sha('a'), &sha('b'), bot, false),
            push(&sha('b'), &sha('c'), DEP, false),
        ]);
        assert!(
            is_clean(&l, &sha('c'), DEP.0, DEP.1).is_err(),
            "not on record as ours"
        );
        l.own.push(OwnPush {
            before: sha('a'),
            after: sha('b'),
            at: 0,
        });
        assert_eq!(is_clean(&l, &sha('c'), DEP.0, DEP.1), Ok(()));
        // Our record for a → b does not cover another push by the same
        // account.
        l.pushes.push(push(&sha('c'), &sha('d'), bot, false));
        assert!(is_clean(&l, &sha('d'), DEP.0, DEP.1).is_err());
    }

    #[test]
    fn workflow_paths_are_recognised_in_any_case() {
        for p in [
            ".github/workflows/ci.yml",
            ".GitHub/Workflows/x.yaml",
            ".github/workflows",
            ".github",
        ] {
            assert!(touches_workflows(p.as_bytes()), "{p}");
        }
        for p in [
            ".github/dependabot.yml",
            "Cargo.lock",
            "src/.github/workflows/x",
        ] {
            assert!(!touches_workflows(p.as_bytes()), "{p}");
        }
    }

    #[test]
    fn a_missed_own_push_still_links_the_chain_exactly() {
        // Dependabot created a; the bridge re-signed a → b (its webhook
        // never arrived); Dependabot then force-pushed b → c.
        let mut l = ledger(vec![
            push(ZERO_SHA, &sha('a'), DEP, true),
            push(&sha('b'), &sha('c'), DEP, false),
        ]);
        assert!(is_clean(&l, &sha('c'), DEP.0, DEP.1).is_err(), "a gap");
        l.own.push(OwnPush {
            before: sha('a'),
            after: sha('b'),
            at: 0,
        });
        assert_eq!(is_clean(&l, &sha('c'), DEP.0, DEP.1), Ok(()));
        // Exact only: an own record for another head bridges nothing.
        let mut l2 = ledger(vec![
            push(ZERO_SHA, &sha('a'), DEP, true),
            push(&sha('b'), &sha('c'), DEP, false),
        ]);
        l2.own.push(OwnPush {
            before: sha('a'),
            after: sha('d'),
            at: 0,
        });
        assert!(is_clean(&l2, &sha('c'), DEP.0, DEP.1).is_err());
    }

    #[test]
    fn only_plain_dependabot_branch_names_are_pushed_to() {
        for ok in [
            "dependabot/cargo/serde-1.0.200",
            "dependabot/npm_and_yarn/@types/node-20.1.0",
            "dependabot/github_actions/actions/checkout-4",
        ] {
            assert!(check_branch_name(ok).is_ok(), "{ok}");
        }
        for bad in [
            "main",
            "dependabot/../main",
            "dependabot/x y",
            "dependabot/x:refs/heads/main",
            "dependabot/-x/.hidden",
            "dependabot/x.lock",
            "dependabot//x",
            "dependabot/x/",
            "dependabot/x@{1}",
        ] {
            assert!(check_branch_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_resigned_commit_names_the_bridge_and_its_signature_covers_it() {
        let id = crate::identity::BridgeIdentity::from_seed(&[3u8; 32]).unwrap();
        let signing = id.git_signing_key().unwrap();
        let c = Commit {
            tree: sha('1'),
            parent: sha('2'),
            parents: 1,
            author: "dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com> 1 +0000"
                .into(),
            unexpected: vec![],
            message: "Bump x\n\nSigned-off-by: dependabot[bot] <support@github.com>\n".into(),
        };
        let msg = format!(
            "{}Signed-by-DID: {}\n",
            c.message, signing.verification_method
        );
        let raw = resign_commit(&c, &sha('3'), "B <b@e> 5 +0000", &msg, &signing).unwrap();
        assert!(signed_by(&raw, &signing).unwrap());
        let text = String::from_utf8(raw.clone()).unwrap();
        assert!(text.starts_with(&format!(
            "tree {}\nparent {}\nauthor dependabot",
            sha('1'),
            sha('3')
        )));
        // Without the trailer it is refused before anything is signed.
        assert!(resign_commit(&c, &sha('3'), "B <b@e> 5 +0000", &c.message, &signing).is_err());
        // Another key's signature over the same object is not ours.
        let other = crate::identity::BridgeIdentity::from_seed(&[4u8; 32])
            .unwrap()
            .git_signing_key()
            .unwrap();
        assert!(!signed_by(&raw, &other).unwrap());
    }
}
