//! §9: the pull request must not be able to satisfy its own check.
//!
//! The steps and inspections behind [`crate::plan::CheckGuard`]: the org
//! ruleset that requires the `<org>/.vgi` workflow at a pinned commit, the
//! `CODEOWNERS` owner-review guard, and the checks `inspect` makes on both.

use std::collections::BTreeSet;

use serde::Deserialize;
use vgi_forge::{CheckSourceGuard, DEFAULT_REQUIRED_CHECK, Drift, ProtectionGap};

use super::*;
use crate::api::Refusal;
use crate::plan::{CODEOWNERS_LOCATIONS, managed_rules};

/// Token for reading and protecting `.vgi`.
const PERMS_CENTRAL_ADMIN: &[(&str, &str)] = &[
    ("administration", "write"),
    ("contents", "read"),
    ("metadata", "read"),
];

/// The ruleset on `.vgi` itself: no force-push (which could make the pinned
/// commit unreachable), no deletion, changes through pull requests, no
/// bypass. No status check: nothing checks `.vgi`'s own pull requests, and
/// the org ruleset pins a commit, not a branch.
fn central_spec() -> ProtectionSpec {
    ProtectionSpec::standard(DEFAULT_REQUIRED_CHECK).with_check_enforced_by_namespace()
}

#[derive(Deserialize)]
struct Commit {
    sha: String,
}

#[derive(Deserialize)]
struct Written {
    commit: Commit,
}

#[derive(Deserialize)]
struct IdOnly {
    id: u64,
}

#[derive(Deserialize)]
struct CodeownersErrors {
    #[serde(default)]
    errors: Vec<CodeownersError>,
}

#[derive(Deserialize)]
struct CodeownersError {
    line: usize,
    #[serde(default)]
    message: String,
    #[serde(default)]
    path: String,
}

#[derive(Deserialize)]
struct ActionsPermissions {
    enabled: bool,
    #[serde(default)]
    allowed_actions: Option<String>,
}

#[derive(Deserialize)]
struct SelectedActions {
    #[serde(default)]
    github_owned_allowed: bool,
    #[serde(default)]
    patterns_allowed: Vec<String>,
}

impl GitHubForge {
    /// The guard this namespace plans for `spec`: a required workflow where
    /// the org has one; otherwise owner review for two or more owners, and
    /// none for a solo repository (the user's decision).
    pub(super) fn check_guard(&self, ns: &Namespace, spec: &RepoSpec) -> CheckGuard {
        let caps = self.capabilities(ns);
        if caps.required_workflow {
            return CheckGuard::RequiredWorkflow;
        }
        if caps.bridge_posted_check {
            return CheckGuard::BridgePosted;
        }
        let mut owners: Vec<ForgeAccount> = Vec::new();
        if ns.kind == NamespaceKind::User
            && let Some(id) = ns.owner_id
        {
            // The account holder: the one admin a personal repo has.
            owners.push(ForgeAccount::new(id, ns.resource.owner()));
        }
        owners.extend(spec.owners.iter().cloned());
        CheckGuard::for_owners(&owners)
    }

    /// The contents of `path` in `owner/repo` at `git_ref`, and its blob sha;
    /// `None` when there is no such file.
    pub(super) async fn file_at(
        &self,
        token: &Secret,
        owner: &str,
        repo: &str,
        path: &str,
        git_ref: Option<&str>,
    ) -> Result<Option<(Vec<u8>, String)>> {
        let mut segments = vec!["repos", owner, repo, "contents"];
        segments.extend(path.split('/'));
        let mut url = self.api.url(&segments);
        if let Some(r) = git_ref {
            url.query_pairs_mut().append_pair("ref", r);
        }
        let Some(v) = self
            .api
            .get_opt::<Value>(url, Auth::Bearer(token), path)
            .await?
        else {
            return Ok(None);
        };
        let c: ContentJson = serde_json::from_value(v)
            .map_err(|e| ForgeError::Protocol(format!("{path}: not a file ({e})")))?;
        if c.kind != "file" {
            return Err(ForgeError::Rejected {
                status: 409,
                message: format!("`{path}` exists and is a {}, not a file", c.kind),
            });
        }
        Ok(Some((decode_content(&c)?, c.sha)))
    }

    /// The `CODEOWNERS` GitHub uses: the first of `.github/`, root, `docs/`
    /// that exists (GitHub's documented search order).
    async fn find_codeowners(
        &self,
        token: &Secret,
        owner: &str,
        name: &str,
        git_ref: Option<&str>,
    ) -> Result<Option<(String, String)>> {
        for path in CODEOWNERS_LOCATIONS {
            if let Some((bytes, _)) = self.file_at(token, owner, name, path, git_ref).await? {
                let text = String::from_utf8(bytes)
                    .map_err(|_| ForgeError::Protocol(format!("`{path}` is not UTF-8")))?;
                return Ok(Some((path.to_string(), text)));
            }
        }
        Ok(None)
    }

    /// The owner-review guard: the managed rules, naming every owner (logins
    /// looked up from numeric ids now, so a renamed-and-re-registered login
    /// is never named), last in the `CODEOWNERS` GitHub uses.
    ///
    /// An existing `CODEOWNERS` (adopted repository) keeps its rules ahead of
    /// the managed block, and stays where it is: a new `.github/CODEOWNERS`
    /// would shadow one at the root or in `docs/`. Written anywhere but
    /// `.github/`, the file also guards its own path.
    pub(super) async fn require_owner_review(
        &self,
        repo: &Resource,
        paths: &[String],
        owners: &[ForgeAccount],
        community_rules: &[u8],
        message: &str,
    ) -> Result<StepOutcome> {
        if owners.len() < 2 {
            return Err(ForgeError::Config(
                "owner review needs at least two owners (one owner is a solo repository)".into(),
            ));
        }
        for p in paths {
            validate_repo_path(p.trim_start_matches('/').trim_end_matches('/'))?;
        }
        let planned = std::str::from_utf8(community_rules)
            .map_err(|_| ForgeError::Config("community CODEOWNERS is not UTF-8".into()))?;
        let (token, _, _) = self.repo_token(repo, PERMS_METADATA).await?;
        let mut logins = Vec::new();
        for id in owners.iter().map(|o| o.id) {
            let login = self.login_for(&token, id).await?;
            if !logins.contains(&login) {
                logins.push(login);
            }
        }
        drop(token);

        let (token, owner, name) = self.repo_token(repo, PERMS_CONTENTS).await?;
        let (target, community) = match self.find_codeowners(&token, &owner, &name, None).await? {
            Some((path, text)) => (path, text),
            None => (CODEOWNERS_PATH.to_string(), planned.to_string()),
        };
        let mut managed = paths.to_vec();
        if !target.starts_with(".github/") {
            managed.push(format!("/{target}"));
        }
        let contents = render_codeowners(&community, &managed, &logins);
        self.write_file_with(&token, &owner, &name, &target, contents.as_bytes(), message)
            .await
    }

    /// `<org>/.vgi`, created (public, with a first commit) if it does not
    /// exist, and a contents token scoped to it.
    async fn central_repo(&self, ns: &Namespace) -> Result<(RepoJson, Secret)> {
        let org = ns.resource.owner();
        let url = self.api.url(&["repos", org, CENTRAL_REPO]);
        let token = match self
            .installation_token(ns, Some(CENTRAL_REPO), PERMS_CONTENTS)
            .await
        {
            Ok(t) => t,
            Err(ForgeError::NotFound { .. }) => {
                // Not in the installation: absent, or there but not granted.
                // Same org-wide administration token as `create_repo`, for
                // the same reason (nothing to scope to yet).
                let admin = self.installation_token(ns, None, PERMS_ADMIN).await?;
                if let Some(existing) = self
                    .api
                    .get_opt::<RepoJson>(url.clone(), Auth::Bearer(&admin), CENTRAL_REPO)
                    .await?
                {
                    return Err(ForgeError::Unsupported {
                        operation: "namespace required workflow".into(),
                        hint: format!(
                            "`{}` exists (id {}) but the App installation cannot see it; add it \
                             to the installation's repositories, or delete it so the bridge can \
                             create it",
                            existing.full_name, existing.id
                        ),
                    });
                }
                let body = json!({
                    "name": CENTRAL_REPO,
                    "visibility": "public",
                    "description": "VGI: the commit-trust workflow this community's repositories \
                                    are required to pass. Managed by the VGI bridge.",
                    "auto_init": true,
                });
                self.api
                    .send(
                        Method::POST,
                        self.api.url(&["orgs", org, "repos"]),
                        Auth::Bearer(&admin),
                        Some(&body),
                        CENTRAL_REPO,
                    )
                    .await?;
                drop(admin);
                self.installation_token(ns, Some(CENTRAL_REPO), PERMS_CONTENTS)
                    .await?
            }
            Err(e) => return Err(e),
        };
        let repo: RepoJson = self
            .api
            .json(Method::GET, url, Auth::Bearer(&token), None, CENTRAL_REPO)
            .await?;
        // A private source repository's workflow runs only on private
        // repositories, an internal one's only on internal and private ones;
        // a public one's on all of them.
        if !is_public(&repo) {
            return Err(ForgeError::Rejected {
                status: 409,
                message: format!(
                    "`{}` is not public, so its workflow cannot be required on public \
                     repositories; make it public (it holds nothing secret)",
                    repo.full_name
                ),
            });
        }
        Ok((repo, token))
    }

    async fn org_ruleset(&self, token: &Secret, org: &str) -> Result<Option<RulesetJson>> {
        let url = self.api.url(&["orgs", org, "rulesets"]);
        let list: Vec<RulesetSummary> = self
            .api
            .get_all(url, Auth::Bearer(token), "org rulesets")
            .await?;
        let Some(summary) = list.into_iter().find(|r| r.name == ORG_RULESET_NAME) else {
            return Ok(None);
        };
        self.org_ruleset_by_id(token, org, summary.id).await
    }

    async fn org_ruleset_by_id(
        &self,
        token: &Secret,
        org: &str,
        id: u64,
    ) -> Result<Option<RulesetJson>> {
        let url = self.api.url(&["orgs", org, "rulesets", &id.to_string()]);
        self.api
            .get_opt(url, Auth::Bearer(token), "org ruleset")
            .await
    }

    /// The §9 required workflow: make `<org>/.vgi` hold `contents` at a
    /// commit, protect `.vgi`, and make the org ruleset require that
    /// commit's workflow on every managed repository's default branch, with
    /// no bypass.
    ///
    /// The pin moves only to a commit whose workflow the bridge has just
    /// read back (or written) as exactly `contents`. A commit someone else
    /// pushed to `.vgi` is never pinned, and an unrelated one does not churn
    /// the pin.
    ///
    /// The org ruleset is read, changed and written under a per-namespace
    /// lock, lists exactly the bridge's managed set (plus `repo`), and is
    /// read back afterwards: a concurrent edit that lost `repo` is an error
    /// to retry, not a silent gap.
    pub(super) async fn require_namespace_workflow(
        &self,
        repo: &Resource,
        contents: &[u8],
        check: &str,
        message: &str,
    ) -> Result<StepOutcome> {
        let (ns, owner, name) = self.locate(repo)?;
        if ns.kind != NamespaceKind::Organization {
            return Err(ForgeError::Unsupported {
                operation: "namespace required workflow".into(),
                hint: "only organisations have org rulesets; this namespace uses owner review"
                    .into(),
            });
        }
        let lock = self.org_lock(&ns.resource);
        let _held = lock.lock().await;
        let managed = self.managed_repositories(&ns.resource).ok_or_else(|| {
            ForgeError::Config(format!(
                "the managed repositories of `{}` are not known; call \
                 GitHubForge::set_managed_repositories from the bridge's store first (the org \
                 ruleset lists exactly them)",
                ns.resource
            ))
        })?;
        let target_id = {
            let t = self
                .installation_token(&ns, Some(name), PERMS_METADATA)
                .await?;
            let r: RepoJson = self
                .api
                .json(
                    Method::GET,
                    self.api.url(&["repos", owner, name]),
                    Auth::Bearer(&t),
                    None,
                    repo.as_str(),
                )
                .await?;
            r.id
        };

        let (central, ctoken) = self.central_repo(&ns).await?;
        let otoken = self
            .installation_token(&ns, None, PERMS_ORG_RULESETS)
            .await?;
        let existing = self.org_ruleset(&otoken, owner).await?;
        let branch = central
            .default_branch
            .clone()
            .unwrap_or_else(|| "main".into());

        let mut wrote = false;
        let current = existing.as_ref().and_then(|rs| pinned_sha(rs, central.id));
        let kept = match &current {
            Some(sha) => self
                .file_at(&ctoken, owner, CENTRAL_REPO, WORKFLOW_PATH, Some(sha))
                .await?
                .is_some_and(|(have, _)| have == contents),
            None => false,
        };
        let sha = match current {
            Some(sha) if kept => sha,
            _ => {
                let head: Commit = self
                    .api
                    .json(
                        Method::GET,
                        self.api
                            .url(&["repos", owner, CENTRAL_REPO, "commits", &branch]),
                        Auth::Bearer(&ctoken),
                        None,
                        CENTRAL_REPO,
                    )
                    .await?;
                match self
                    .file_at(&ctoken, owner, CENTRAL_REPO, WORKFLOW_PATH, Some(&head.sha))
                    .await?
                {
                    Some((have, _)) if have == contents => head.sha,
                    blob => {
                        let mut body = json!({
                            "message": message,
                            "content": STANDARD.encode(contents),
                            "branch": branch,
                        });
                        if let Some((_, blob_sha)) = blob {
                            body["sha"] = json!(blob_sha);
                        }
                        let mut segments = vec!["repos", owner, CENTRAL_REPO, "contents"];
                        segments.extend(WORKFLOW_PATH.split('/'));
                        let w: Written = self
                            .api
                            .json(
                                Method::PUT,
                                self.api.url(&segments),
                                Auth::Bearer(&ctoken),
                                Some(&body),
                                WORKFLOW_PATH,
                            )
                            .await
                            .map_err(|e| match e {
                                ForgeError::Rejected { status, message } => ForgeError::Rejected {
                                    status,
                                    message: format!(
                                        "{message} — `{CENTRAL_REPO}` is protected, so a new \
                                             workflow lands through a pull request there; the \
                                             bridge pins it once it is merged"
                                    ),
                                },
                                e => e,
                            })?;
                        wrote = true;
                        w.commit.sha
                    }
                }
            }
        };
        drop(ctoken);
        if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ForgeError::Protocol(format!("`{sha}` is not a commit sha")));
        }

        // `.vgi` itself: without this, a force-push there could make the
        // pinned commit unreachable, or its deletion remove the workflow.
        let atoken = self
            .installation_token(&ns, Some(CENTRAL_REPO), PERMS_ADMIN)
            .await?;
        let central_outcome = self
            .protect_with(&atoken, owner, CENTRAL_REPO, &central_spec(), false)
            .await?;
        drop(atoken);

        let mut ids: BTreeSet<u64> = managed;
        ids.insert(target_id);
        let ids: Vec<u64> = ids.into_iter().collect();
        let in_place = existing.as_ref().is_some_and(|rs| {
            org_ruleset_gaps(rs, central.id, &sha, target_id).is_empty()
                && conditions_kind(rs) == "repository_id"
                && covered_repository_ids(rs) == ids
        });
        let outcome = if in_place {
            if wrote || central_outcome != StepOutcome::Unchanged {
                StepOutcome::Updated
            } else {
                StepOutcome::Unchanged
            }
        } else {
            // Always the full `repository_id` condition: a ruleset switched
            // to names or properties is rewritten, not merged into.
            let body = org_ruleset_body(central.id, &sha, &branch, &ids);
            let (method, url) = match &existing {
                Some(rs) => (
                    Method::PUT,
                    self.api
                        .url(&["orgs", owner, "rulesets", &rs.id.to_string()]),
                ),
                None => (Method::POST, self.api.url(&["orgs", owner, "rulesets"])),
            };
            let resp = match self
                .api
                .send_or_refusal(
                    method,
                    url,
                    Auth::Bearer(&otoken),
                    Some(&body),
                    "org ruleset",
                )
                .await?
            {
                Ok(resp) => resp,
                Err(refusal) if workflows_rule_unsupported(&refusal) => {
                    self.set_required_workflow(&ns.resource, false);
                    return Err(ForgeError::CapabilityChanged {
                        namespace: ns.resource.to_string(),
                        capability: "requiredWorkflow".into(),
                        available: false,
                        reason: format!(
                            "GitHub refused the org ruleset's workflows rule ({}); the namespace \
                             falls back to owner review",
                            refusal.message
                        ),
                    });
                }
                Err(refusal) => return Err(refusal.error),
            };
            let written: IdOnly = resp
                .json()
                .await
                .map_err(|e| ForgeError::Protocol(format!("org ruleset: {e}")))?;
            let after = self
                .org_ruleset_by_id(&otoken, owner, written.id)
                .await?
                .ok_or_else(|| {
                    ForgeError::Unavailable("the org ruleset vanished right after writing".into())
                })?;
            if !covered_repository_ids(&after).contains(&target_id)
                || pinned_sha(&after, central.id).as_deref() != Some(sha.as_str())
            {
                return Err(ForgeError::Unavailable(
                    "the org ruleset changed while the bridge was writing it (a concurrent \
                     edit?); run the step again"
                        .into(),
                ));
            }
            if existing.is_some() {
                StepOutcome::Updated
            } else {
                StepOutcome::Created
            }
        };
        self.managed
            .write()
            .expect("lock poisoned")
            .entry(ns.resource.clone())
            .or_default()
            .insert(target_id);
        self.set_required_workflow_pin(
            &ns.resource,
            RequiredWorkflowPin::new(central.id, sha, check),
        );
        Ok(outcome)
    }

    /// Under a required workflow: how the org ruleset and `.vgi` fall short
    /// for this repository. When nothing does, the check counts as
    /// required.
    pub(super) async fn inspect_required_workflow(
        &self,
        ns: &Namespace,
        repo_id: u64,
        p: &mut ProtectionState,
    ) -> Result<()> {
        p.check_source_guard = CheckSourceGuard::RequiredWorkflow;
        let token = self
            .installation_token(ns, None, PERMS_ORG_RULESETS)
            .await?;
        let rs = self.org_ruleset(&token, ns.resource.owner()).await?;
        drop(token);
        let pin = self.required_workflow_pin(&ns.resource);
        let mut details = match (&rs, &pin) {
            (None, _) => vec![format!("the org ruleset `{ORG_RULESET_NAME}` is missing")],
            (Some(_), None) => vec![
                "the bridge has no record of the workflow commit it pinned; run the bootstrap \
                 to re-pin"
                    .to_string(),
            ],
            (Some(rs), Some(pin)) => org_ruleset_gaps(rs, pin.repository_id, &pin.sha, repo_id),
        };
        details.extend(self.central_gaps(ns, pin.as_ref()).await?);
        if details.is_empty() {
            if let Some(pin) = pin
                && !p.required_checks.contains(&pin.check)
            {
                p.required_checks.push(pin.check);
            }
        } else {
            p.other_gaps.extend(
                details
                    .into_iter()
                    .map(|detail| ProtectionGap::CheckSourceUnprotected { detail }),
            );
        }
        Ok(())
    }

    /// `.vgi` must exist, be public, keep its ruleset, and still have the
    /// pinned commit.
    async fn central_gaps(
        &self,
        ns: &Namespace,
        pin: Option<&RequiredWorkflowPin>,
    ) -> Result<Vec<String>> {
        let org = ns.resource.owner();
        let token = match self
            .installation_token(ns, Some(CENTRAL_REPO), PERMS_CENTRAL_ADMIN)
            .await
        {
            Ok(t) => t,
            Err(ForgeError::NotFound { .. }) => {
                return Ok(vec![format!(
                    "`{CENTRAL_REPO}` is missing or not visible to the App"
                )]);
            }
            Err(e) => return Err(e),
        };
        let Some(central) = self
            .api
            .get_opt::<RepoJson>(
                self.api.url(&["repos", org, CENTRAL_REPO]),
                Auth::Bearer(&token),
                CENTRAL_REPO,
            )
            .await?
        else {
            return Ok(vec![format!("`{CENTRAL_REPO}` is missing")]);
        };
        let mut gaps = Vec::new();
        if pin.is_some_and(|p| p.repository_id != central.id) {
            gaps.push(format!(
                "`{CENTRAL_REPO}` is a different repository (id {}) from the one pinned",
                central.id
            ));
        }
        if !is_public(&central) {
            gaps.push(format!("`{CENTRAL_REPO}` is no longer public"));
        }
        let spec = central_spec();
        let protected = match self.managed_ruleset(&token, org, CENTRAL_REPO).await? {
            Some(rs) => {
                let observed = self.protection(&rs, central.default_branch.as_deref(), None);
                satisfies(&observed, &spec) && rules_match(&rs, &spec)
            }
            None => false,
        };
        if !protected {
            gaps.push(format!(
                "`{CENTRAL_REPO}`'s ruleset (pull requests only, no force-push, no deletion, no \
                 bypass) is missing or weakened"
            ));
        }
        if let Some(pin) = pin {
            let url = self
                .api
                .url(&["repos", org, CENTRAL_REPO, "commits", &pin.sha]);
            match self
                .api
                .json::<Commit>(
                    Method::GET,
                    url,
                    Auth::Bearer(&token),
                    None,
                    "pinned commit",
                )
                .await
            {
                Ok(c) if c.sha == pin.sha => {}
                Ok(_) | Err(ForgeError::NotFound { .. } | ForgeError::Rejected { .. }) => gaps
                    .push(format!(
                        "the pinned workflow commit {} is no longer in `{CENTRAL_REPO}`",
                        pin.sha
                    )),
                Err(e) => return Err(e),
            }
        }
        Ok(gaps)
    }

    /// Outside a required workflow: what guards the repository's own
    /// workflow. Whether that is enough depends on how many owners it has,
    /// which the projection knows — see [`owner_review_drift`].
    pub(super) async fn inspect_owner_review(
        &self,
        repo: &Resource,
        owner: &str,
        name: &str,
        rs: Option<&RulesetJson>,
        default_branch: Option<&str>,
        p: &mut ProtectionState,
    ) -> Result<()> {
        let review_on = rs.is_some_and(|rs| {
            rs.rules.iter().any(|r| {
                r.kind == "pull_request"
                    && r.parameters
                        .as_ref()
                        .and_then(|p| p.get("require_code_owner_review"))
                        .and_then(Value::as_bool)
                        == Some(true)
            })
        });
        let (token, _, _) = self.repo_token(repo, PERMS_READ_CONTENTS).await?;
        let found = self
            .find_codeowners(&token, owner, name, default_branch)
            .await?;
        let managed = found.as_ref().and_then(|(_, text)| managed_rules(text));
        if !review_on && managed.is_none() {
            p.check_source_guard = CheckSourceGuard::Unreviewed;
            return Ok(());
        }

        let mut issues = Vec::new();
        let mut reviewers = Vec::new();
        if !rs.is_some_and(code_owner_review) {
            issues.push(
                "the ruleset no longer requires one approving review from a code owner, \
                 dismissed by later pushes and not given by the last pusher"
                    .to_string(),
            );
        }
        match (&found, managed) {
            (None, _) => issues.push("there is no CODEOWNERS file".to_string()),
            (Some((path, _)), None) => issues.push(format!(
                "`{path}` no longer ends with the managed owner rules"
            )),
            (Some((path, _)), Some(rules)) => {
                let mut required = vec![GUARDED_PATH.to_string()];
                if !path.starts_with(".github/") {
                    required.push(format!("/{path}"));
                }
                for pattern in &required {
                    match rules.iter().find(|(p, _, _)| p == pattern) {
                        Some((_, owners, _)) if !owners.is_empty() => {}
                        _ => issues.push(format!(
                            "the managed rules no longer give `{pattern}` an owner"
                        )),
                    }
                }
                if let Some((_, owners, _)) = rules.iter().find(|(p, _, _)| p == GUARDED_PATH) {
                    for o in owners {
                        let login = o.strip_prefix('@').filter(|l| !l.contains('/'));
                        let Some(login) = login else {
                            issues.push(format!(
                                "the managed rule names `{o}`, not a person's account"
                            ));
                            continue;
                        };
                        match self
                            .api
                            .get_opt::<UserJson>(
                                self.api.url(&["users", login]),
                                Auth::Bearer(&token),
                                "user",
                            )
                            .await?
                        {
                            Some(u) => reviewers.push(ForgeAccount::new(u.id, u.login)),
                            None => {
                                issues.push(format!("the managed rule names unknown account {o}"))
                            }
                        }
                    }
                }
                let lines: Vec<usize> = rules.iter().map(|(_, _, l)| *l).collect();
                let mut url = self
                    .api
                    .url(&["repos", owner, name, "codeowners", "errors"]);
                if let Some(b) = default_branch {
                    url.query_pairs_mut().append_pair("ref", b);
                }
                let errors: CodeownersErrors = self
                    .api
                    .json(
                        Method::GET,
                        url,
                        Auth::Bearer(&token),
                        None,
                        "CODEOWNERS errors",
                    )
                    .await?;
                for e in errors.errors {
                    if e.path == *path && lines.contains(&e.line) {
                        issues.push(format!(
                            "GitHub reports an error on the managed rule (`{path}` line {}): {}",
                            e.line, e.message
                        ));
                    }
                }
            }
        }
        p.check_source_guard = CheckSourceGuard::OwnerReview { reviewers, issues };
        Ok(())
    }

    /// Actions must be on, and allowed to run the workflow's actions
    /// (`actions/checkout`, GitHub-owned; the verify-trust action). A
    /// repository admin who turns Actions off or narrows the allowed
    /// actions stops the check from running at all.
    pub(super) async fn inspect_actions_policy(
        &self,
        token: &Secret,
        owner: &str,
        name: &str,
        p: &mut ProtectionState,
    ) -> Result<()> {
        let url = self
            .api
            .url(&["repos", owner, name, "actions", "permissions"]);
        let mut gaps = Vec::new();
        match self
            .api
            .get_opt::<ActionsPermissions>(url, Auth::Bearer(token), "Actions permissions")
            .await?
        {
            None => gaps.push("the repository's Actions settings could not be read".to_string()),
            Some(a) if !a.enabled => gaps.push("GitHub Actions is disabled".to_string()),
            Some(a) => match a.allowed_actions.as_deref() {
                Some("local_only") => gaps.push(
                    "Actions may only use actions from this repository's owner; the check \
                     needs actions/checkout and the verify-trust action"
                        .to_string(),
                ),
                Some("selected") => {
                    let url = self.api.url(&[
                        "repos",
                        owner,
                        name,
                        "actions",
                        "permissions",
                        "selected-actions",
                    ]);
                    let sel: Option<SelectedActions> = self
                        .api
                        .get_opt(url, Auth::Bearer(token), "allowed actions")
                        .await?;
                    let action = self
                        .verify_trust_action
                        .lock()
                        .expect("lock poisoned")
                        .clone()
                        .unwrap_or_else(|| {
                            "OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@\
                             0000000000000000000000000000000000000000"
                                .into()
                        });
                    let allowed = |candidate: &str| {
                        sel.as_ref().is_some_and(|s| {
                            s.patterns_allowed
                                .iter()
                                .any(|pat| glob_match(pat, candidate))
                        })
                    };
                    let checkout_ok = sel.as_ref().is_some_and(|s| s.github_owned_allowed)
                        || allowed(&self.config.checkout_action);
                    if !checkout_ok {
                        gaps.push(
                            "the allowed-actions policy does not allow actions/checkout".into(),
                        );
                    }
                    if !allowed(&action) {
                        gaps.push(format!(
                            "the allowed-actions policy does not allow `{action}`"
                        ));
                    }
                }
                _ => {}
            },
        }
        p.other_gaps.extend(
            gaps.into_iter()
                .map(|detail| ProtectionGap::CheckSourceUnprotected { detail }),
        );
        Ok(())
    }
}

fn is_public(repo: &RepoJson) -> bool {
    repo.visibility.as_deref() == Some("public") && !repo.private
}

/// Whether GitHub refused the org ruleset because the organisation's plan
/// lacks org rulesets or the workflows rule — as opposed to any other 403
/// or 422, which is returned as an error and changes nothing. GitHub's
/// exact wording is not documented, so this matches the phrases its plan
/// refusals use ("Upgrade to GitHub …", "not available") and a plans or
/// billing documentation link.
pub(super) fn workflows_rule_unsupported(r: &Refusal) -> bool {
    if r.status != 403 && r.status != 422 {
        return false;
    }
    let m = r.message.to_ascii_lowercase();
    let d = r.documentation_url.to_ascii_lowercase();
    let plan_doc = d.contains("githubs-plans") || d.contains("/billing");
    let plan_msg = [
        "upgrade to github",
        "upgrade your plan",
        "not available for",
        "is not available",
        "only available",
        "not enabled for this organization",
    ]
    .iter()
    .any(|k| m.contains(k));
    plan_doc || plan_msg
}

/// `*` matches any run of characters (case-insensitive), as GitHub's
/// allowed-actions patterns do.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.trim().to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    let (mut pi, mut ti, mut star, mut mark) = (0, 0, None, 0);
    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// Whether the ruleset's pull-request rule is the full owner-review rule:
/// one approval, a code owner's, dismissed by later pushes, not the last
/// pusher's.
pub(super) fn code_owner_review(rs: &RulesetJson) -> bool {
    rs.rules.iter().any(|r| {
        let param = |k: &str| r.parameters.as_ref().and_then(|p| p.get(k)).cloned();
        let on = |k: &str| param(k).and_then(|v| v.as_bool()) == Some(true);
        r.kind == "pull_request"
            && on("require_code_owner_review")
            && on("dismiss_stale_reviews_on_push")
            && on("require_last_push_approval")
            && param("required_approving_review_count")
                .and_then(|v| v.as_u64())
                .is_some_and(|n| n >= 1)
    })
}

/// Owner-review drift against the projection's owners (plus a personal
/// account's holder).
pub(super) fn owner_review_drift(
    ns: Option<&Namespace>,
    observed: &RepoState,
    desired: &Projection,
) -> Vec<Drift> {
    let mut owners: BTreeSet<u64> = desired.owners.iter().map(|o| o.id).collect();
    if let Some(ns) = ns
        && ns.kind == NamespaceKind::User
        && let Some(id) = ns.owner_id
    {
        owners.insert(id);
    }
    let weakened = |details: Vec<String>| Drift::ProtectionWeakened {
        gaps: details
            .into_iter()
            .map(|detail| ProtectionGap::CheckSourceUnprotected { detail })
            .collect(),
    };
    match &observed.protection.check_source_guard {
        CheckSourceGuard::OwnerReview { .. } if owners.len() == 1 => vec![Drift::ReplanNeeded {
            reason: "the repository has one owner now; owner review would block their own \
                     workflow changes"
                .into(),
        }],
        CheckSourceGuard::OwnerReview { reviewers, issues } => {
            let mut details = issues.clone();
            let have: BTreeSet<u64> = reviewers.iter().map(|r| r.id).collect();
            if owners.len() >= 2 && have != owners {
                details.push(format!(
                    "the managed rule names accounts {have:?}, but the owners are {owners:?}"
                ));
            }
            if details.is_empty() {
                vec![]
            } else {
                vec![weakened(details)]
            }
        }
        CheckSourceGuard::Unreviewed if owners.len() >= 2 => vec![
            weakened(vec![format!(
                "{} owners, but workflow changes are not review-protected",
                owners.len()
            )]),
            Drift::ReplanNeeded {
                reason: "the repository has more than one owner now".into(),
            },
        ],
        _ => vec![],
    }
}

/// One `ProtectionWeakened` with every gap, where the default diff and the
/// owner-review check each found some.
pub(super) fn merge_protection_drift(drift: Vec<Drift>) -> Vec<Drift> {
    let mut gaps = Vec::new();
    let mut at = None;
    let mut out = Vec::new();
    for d in drift {
        match d {
            Drift::ProtectionWeakened { gaps: g } => {
                gaps.extend(g);
                if at.is_none() {
                    at = Some(out.len());
                    out.push(Drift::ProtectionWeakened { gaps: Vec::new() });
                }
            }
            other => out.push(other),
        }
    }
    if let Some(i) = at {
        out[i] = Drift::ProtectionWeakened { gaps };
    }
    out
}

/// The org ruleset for the required workflow: every listed repository's
/// default branch must pass `.vgi`'s workflow at `sha`, with no bypass.
///
/// Repositories are listed by numeric id (`conditions.repository_id`), not
/// by name: an id survives a rename, and a new repository squatting a
/// managed name is not covered until the bridge bootstraps it. The list is
/// the bridge's managed set; the unmanaged rest of the org — and `.vgi`
/// itself — are not covered.
fn org_ruleset_body(central_id: u64, sha: &str, branch: &str, repo_ids: &[u64]) -> Value {
    json!({
        "name": ORG_RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {
            "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] },
            "repository_id": { "repository_ids": repo_ids },
        },
        "rules": [{
            "type": "workflows",
            "parameters": {
                // Enforced on creation too: a first push that creates the
                // default branch is a way in like any other.
                "do_not_enforce_on_create": false,
                "workflows": [{
                    "repository_id": central_id,
                    "path": WORKFLOW_PATH,
                    "ref": format!("refs/heads/{branch}"),
                    "sha": sha,
                }],
            },
        }],
    })
}

/// The `.vgi` commit the org ruleset pins, if it pins one for our workflow.
fn pinned_sha(rs: &RulesetJson, central_id: u64) -> Option<String> {
    workflow_entries(rs)
        .find(|w| {
            w.get("repository_id").and_then(Value::as_u64) == Some(central_id)
                && w.get("path").and_then(Value::as_str) == Some(WORKFLOW_PATH)
        })
        .and_then(|w| w.get("sha").and_then(Value::as_str).map(str::to_string))
}

fn workflow_rules(rs: &RulesetJson) -> impl Iterator<Item = &RuleJson> {
    rs.rules.iter().filter(|r| r.kind == "workflows")
}

fn workflow_entries(rs: &RulesetJson) -> impl Iterator<Item = &Value> {
    workflow_rules(rs)
        .filter_map(|r| r.parameters.as_ref()?.get("workflows")?.as_array())
        .flatten()
}

fn covered_repository_ids(rs: &RulesetJson) -> Vec<u64> {
    let mut ids: Vec<u64> = rs
        .conditions
        .as_ref()
        .and_then(|c| c.get("repository_id"))
        .and_then(|r| r.get("repository_ids"))
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_u64).collect())
        .unwrap_or_default();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// How the ruleset selects repositories: `repository_id`,
/// `repository_name`, `repository_property`, or `none`.
fn conditions_kind(rs: &RulesetJson) -> &'static str {
    let c = rs.conditions.as_ref();
    let has = |k: &str| c.and_then(|c| c.get(k)).is_some_and(|v| !v.is_null());
    if has("repository_id") {
        "repository_id"
    } else if has("repository_name") {
        "repository_name"
    } else if has("repository_property") {
        "repository_property"
    } else {
        "none"
    }
}

/// How the org ruleset falls short of requiring `.vgi`'s workflow at `sha`
/// on repository `repo_id`, in words for the drift report. Empty when it
/// does not.
fn org_ruleset_gaps(rs: &RulesetJson, central_id: u64, sha: &str, repo_id: u64) -> Vec<String> {
    let mut gaps = Vec::new();
    if rs.enforcement != "active" {
        gaps.push(format!(
            "the org ruleset is `{}`, not enforced",
            rs.enforcement
        ));
    }
    if rs.target.as_deref().unwrap_or("branch") != "branch" {
        gaps.push("the org ruleset does not target branches".into());
    }
    let refs = |key: &str| -> Vec<String> {
        rs.conditions
            .as_ref()
            .and_then(|c| c.get("ref_name"))
            .and_then(|r| r.get(key))
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let covers = refs("include")
        .iter()
        .any(|r| r == "~DEFAULT_BRANCH" || r == "~ALL")
        && refs("exclude").is_empty();
    if !covers {
        gaps.push("the org ruleset does not cover the default branch".into());
    }
    match conditions_kind(rs) {
        "repository_id" => {}
        other => gaps.push(format!(
            "the org ruleset selects repositories by `{other}`, not by id"
        )),
    }
    if !covered_repository_ids(rs).contains(&repo_id) {
        gaps.push("the org ruleset does not include this repository".into());
    }
    match &rs.bypass_actors {
        None => gaps.push("the org ruleset's bypass actors are not visible to the bridge".into()),
        Some(a) if !a.is_empty() => gaps.push(format!(
            "the org ruleset has bypass actors: {}",
            a.iter()
                .map(|a| format!(
                    "{}:{}",
                    a.actor_type,
                    a.actor_id.map_or_else(|| "-".into(), |i| i.to_string())
                ))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        Some(_) => {}
    }
    if let Some(mode) = rs.current_user_can_bypass.as_deref()
        && mode != "never"
    {
        gaps.push(format!(
            "the bridge's App can bypass the org ruleset ({mode})"
        ));
    }
    if workflow_rules(rs).any(|r| {
        r.parameters
            .as_ref()
            .and_then(|p| p.get("do_not_enforce_on_create"))
            .and_then(Value::as_bool)
            == Some(true)
    }) {
        gaps.push("the org ruleset's workflows rule is not enforced on branch creation".into());
    }
    match pinned_sha(rs, central_id) {
        None => gaps.push(format!(
            "the org ruleset no longer requires `{CENTRAL_REPO}/{WORKFLOW_PATH}`"
        )),
        Some(s) if s != sha => gaps.push(format!(
            "the org ruleset pins workflow commit {s}, not {sha}"
        )),
        Some(_) => {}
    }
    gaps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_action_patterns_glob() {
        let action = "OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@abc";
        assert!(glob_match("openvtc/*", action));
        assert!(glob_match(
            "OpenVTC/verifiable-git-infrastructure/*",
            action
        ));
        assert!(glob_match("*", action));
        assert!(glob_match(action, action));
        assert!(!glob_match("OpenVTC/other/*", action));
        assert!(!glob_match("actions/*", action));
    }

    #[test]
    fn only_plan_refusals_count_as_unsupported() {
        let r = |status, message: &str, doc: &str| Refusal {
            status,
            message: message.into(),
            documentation_url: doc.into(),
            error: ForgeError::Forbidden(String::new()),
        };
        assert!(workflows_rule_unsupported(&r(
            403,
            "Upgrade to GitHub Enterprise to enable this feature.",
            ""
        )));
        assert!(workflows_rule_unsupported(&r(
            422,
            "Validation Failed",
            "https://docs.github.com/get-started/learning-about-github/githubs-plans"
        )));
        assert!(!workflows_rule_unsupported(&r(
            422,
            "Validation Failed (Invalid property /rules/0: data matches no possible input)",
            "https://docs.github.com/rest/orgs/rules#create-an-organization-repository-ruleset"
        )));
        assert!(!workflows_rule_unsupported(&r(
            403,
            "Resource not accessible by integration",
            "https://docs.github.com/rest/orgs/rules"
        )));
        assert!(!workflows_rule_unsupported(&r(
            409,
            "Upgrade to GitHub",
            ""
        )));
    }
}
