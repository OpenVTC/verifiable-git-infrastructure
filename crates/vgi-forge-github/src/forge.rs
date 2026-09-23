//! [`GitHubForge`]: the `Forge` implementation.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use http::HeaderMap;
use reqwest::Method;
use serde::Deserialize;
use serde_json::{Value, json};
use vgi_forge::{
    ApplyReport, BindCallback, BindRequest, BindStep, BootstrapStep, Capabilities, Collaborator,
    Forge, ForgeAccount, ForgeError, ForgeEvent, ForgeHooks, ForgeKind, ForgeRole, HookDecision,
    LinkCallback, LinkMethod, LinkStep, Namespace, NamespaceBinding, NamespaceKind, ProtectionSpec,
    ProtectionState, RepoSpec, RepoState, RequiredCheckKind, Resource, Result, RoleAssignment,
    RoleChange, RoleOutcome, StepAction, StepOutcome, Unlisted, VgiConfig, Visibility, async_trait,
    collapse_to_ladder, validate_repo_path,
};

use crate::api::{Api, Auth};
use crate::config::{GitHubConfig, JwtIssuer};
use crate::jwt::{AppKeySigner, app_jwt};
use crate::manifest::missing_permissions;
use crate::plan::{RULESET_NAME, github_plan};
use crate::secret::Secret;
use crate::webhook;

/// The role ladder of an organisation repository.
const ORG_LADDER: [ForgeRole; 5] = [
    ForgeRole::Read,
    ForgeRole::Triage,
    ForgeRole::Write,
    ForgeRole::Maintain,
    ForgeRole::Admin,
];

/// A personal account's repositories have collaborators, and collaborators
/// are always `write` (§3, §8).
const USER_LADDER: [ForgeRole; 1] = [ForgeRole::Write];

/// Installation-token permissions per kind of job. Each token also names
/// the one repository it is for wherever a repository exists yet.
///
/// `inspect` asks for administration *write* although it only reads: GitHub
/// shows a ruleset's bypass actors only to a caller who could edit it, and
/// an inspect that could not see them would report "no bypass" for a ruleset
/// that has one.
const PERMS_ADMIN: &[(&str, &str)] = &[("administration", "write"), ("metadata", "read")];
const PERMS_CONTENTS: &[(&str, &str)] = &[("contents", "write"), ("metadata", "read")];
const PERMS_VARIABLES: &[(&str, &str)] = &[("actions_variables", "write"), ("metadata", "read")];

/// How long GitHub lets a device code live (15 minutes). Polling never runs
/// longer, whatever the caller says.
const DEVICE_CODE_MAX_LIFETIME_SECS: u64 = 900;

/// Shortest bind `state` accepted: 128 bits of base64url.
const MIN_STATE_LEN: usize = 22;

/// The GitHub adapter: one community's App on one GitHub (github.com or a
/// GHES instance).
///
/// Holds the App's key (behind [`AppKeySigner`]), its webhook secret, and
/// the namespaces the core has bound. It holds no forge token between calls:
/// each operation mints an installation token scoped to the one repository
/// and the permissions that operation needs, and drops it on return.
pub struct GitHubForge {
    config: GitHubConfig,
    api: Api,
    signer: Arc<dyn AppKeySigner>,
    webhook_secret: Secret,
    namespaces: RwLock<BTreeMap<Resource, Namespace>>,
    actions_app_id: Mutex<Option<u64>>,
    client_secret: Option<Secret>,
}

impl std::fmt::Debug for GitHubForge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubForge")
            .field("host", &self.config.host)
            .field("app_id", &self.config.app_id)
            .field("signer", &"<redacted>")
            .field("webhook_secret", &self.webhook_secret)
            .finish_non_exhaustive()
    }
}

impl GitHubForge {
    /// An adapter for `config`'s App, signing with `signer` and verifying
    /// webhooks with `webhook_secret`.
    pub fn new(
        config: GitHubConfig,
        signer: Arc<dyn AppKeySigner>,
        webhook_secret: Secret,
    ) -> Result<Self> {
        if webhook_secret.expose().is_empty() {
            return Err(ForgeError::Config("empty webhook secret".into()));
        }
        let slug_ok = !config.app_slug.is_empty()
            && config
                .app_slug
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !slug_ok {
            return Err(ForgeError::Config(format!(
                "App slug `{}` must be lowercase letters, digits and `-`",
                config.app_slug
            )));
        }
        let api = Api::new(
            config.api_base.clone(),
            config.web_base.clone(),
            config.request_timeout,
        )?;
        let actions_app_id = Mutex::new(config.actions_integration_id);
        Ok(GitHubForge {
            config,
            api,
            signer,
            webhook_secret,
            namespaces: RwLock::new(BTreeMap::new()),
            actions_app_id,
            client_secret: None,
        })
    }

    /// Give the adapter the App's OAuth client secret (from the manifest
    /// exchange). With it, the member's user token from an account link is
    /// revoked as soon as their id is read; without it the token is only
    /// dropped and lapses on its own (eight hours for an expiring App user
    /// token), because revocation is authenticated with the client secret.
    pub fn with_client_secret(mut self, secret: Secret) -> Self {
        self.client_secret = Some(secret);
        self
    }

    /// The configuration.
    pub fn config(&self) -> &GitHubConfig {
        &self.config
    }

    /// Tell the adapter about a bound namespace (from the VTC's store, after
    /// the admin confirmed the bind). Operations on repositories in a
    /// namespace that was never registered are refused with
    /// [`ForgeError::NotBound`]: the binding, not whatever the App happens
    /// to be installed on, is what authorises the bridge to act.
    pub fn register_namespace(&self, ns: Namespace) -> Result<()> {
        if ns.resource.host() != self.config.host || !ns.resource.is_namespace() {
            return Err(ForgeError::WrongResource {
                resource: ns.resource.to_string(),
                expected: format!("a namespace on `{}`", self.config.host),
            });
        }
        self.namespaces
            .write()
            .expect("namespace lock poisoned")
            .insert(ns.resource.clone(), ns);
        Ok(())
    }

    /// Forget a namespace (unbind).
    pub fn unregister_namespace(&self, ns: &Resource) {
        self.namespaces
            .write()
            .expect("namespace lock poisoned")
            .remove(ns);
    }

    /// A fresh bind `state` nonce: 256 bits from the system CSPRNG,
    /// base64url. The caller stores it with its expiry and hands it back to
    /// [`Forge::complete_bind`].
    pub fn new_state() -> Result<String> {
        let mut bytes = [0u8; 32];
        aws_lc_rs::rand::fill(&mut bytes)
            .map_err(|_| ForgeError::Config("system RNG unavailable".into()))?;
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Download GitHub's `web-flow` public key (`<web>/web-flow.gpg`) for the
    /// platform keyring. Never called implicitly: the keyring is
    /// configuration, and fetching it is a choice the operator makes and
    /// can review.
    pub async fn fetch_web_flow_key(&self) -> Result<Vec<u8>> {
        let url = self.api.web_url(&["web-flow.gpg"]);
        let resp = self
            .api
            .send(Method::GET, url, Auth::None, None, "web-flow key")
            .await?;
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| ForgeError::Unavailable(e.without_url().to_string()))
    }

    // ── credentials ──────────────────────────────────────────────────────

    async fn jwt(&self) -> Result<Secret> {
        let issuer = match self.config.jwt_issuer {
            JwtIssuer::AppId => self.config.app_id.to_string(),
            _ => self.config.client_id.clone(),
        };
        app_jwt(self.signer.as_ref(), &issuer).await
    }

    /// Mint an installation token for `ns`, limited to `repo` (when given)
    /// and `perms`. Dropped by the caller when the operation returns.
    async fn installation_token(
        &self,
        ns: &Namespace,
        repo: Option<&str>,
        perms: &[(&str, &str)],
    ) -> Result<Secret> {
        let installation = ns.installation_id.ok_or_else(|| ForgeError::Unsupported {
            operation: "forge automation".into(),
            hint: format!(
                "namespace `{}` is in manual mode (no App installation); run the steps by hand \
                 with `vgi repo init`",
                ns.resource
            ),
        })?;
        let jwt = self.jwt().await?;
        let permissions: BTreeMap<_, _> = perms.iter().copied().collect();
        let mut body = json!({ "permissions": permissions });
        if let Some(repo) = repo {
            body["repositories"] = json!([repo]);
        }
        let url = self.api.url(&[
            "app",
            "installations",
            &installation.to_string(),
            "access_tokens",
        ]);
        #[derive(Deserialize)]
        struct Token {
            token: String,
        }
        let t: Token = self
            .api
            .json(
                Method::POST,
                url,
                Auth::Bearer(&jwt),
                Some(&body),
                "installation token",
            )
            .await
            .map_err(|e| match e {
                // GitHub answers 422 when a named repository is not in the
                // installation — for the caller that is "not found".
                ForgeError::Rejected { status: 422, .. } if repo.is_some() => {
                    ForgeError::NotFound {
                        what: format!(
                            "{}/{} (not visible to the App installation)",
                            ns.resource,
                            repo.unwrap_or_default()
                        ),
                    }
                }
                e => e,
            })?;
        Ok(Secret::new(t.token))
    }

    fn namespace(&self, ns: &Resource) -> Result<Namespace> {
        self.namespaces
            .read()
            .expect("namespace lock poisoned")
            .get(ns)
            .cloned()
            .ok_or_else(|| ForgeError::NotBound {
                namespace: ns.to_string(),
            })
    }

    /// Check `repo` is a repository on this forge and return its namespace,
    /// owner and name.
    fn locate<'r>(&self, repo: &'r Resource) -> Result<(Namespace, &'r str, &'r str)> {
        if repo.host() != self.config.host {
            return Err(ForgeError::WrongResource {
                resource: repo.to_string(),
                expected: format!("a repository on `{}`", self.config.host),
            });
        }
        // A `Resource` from a bridge job was validated against the general
        // grammar (any depth). Splitting `github.com/acme/evil/widgets` into
        // first and last segment would act on `acme/widgets`.
        repo.require_owner_repo()?;
        let name = repo.repo_name().ok_or_else(|| ForgeError::WrongResource {
            resource: repo.to_string(),
            expected: "a repository (`<host>/<owner>/<repo>`), not a namespace".into(),
        })?;
        Ok((self.namespace(&repo.namespace())?, repo.owner(), name))
    }

    async fn repo_token(
        &self,
        repo: &Resource,
        perms: &[(&str, &str)],
    ) -> Result<(Secret, String, String)> {
        let (ns, owner, name) = self.locate(repo)?;
        let token = self.installation_token(&ns, Some(name), perms).await?;
        Ok((token, owner.to_string(), name.to_string()))
    }

    /// The GitHub Actions App's id — what the required check is pinned to.
    async fn actions_app_id(&self, token: &Secret) -> Result<u64> {
        if let Some(id) = *self.actions_app_id.lock().expect("lock poisoned") {
            return Ok(id);
        }
        #[derive(Deserialize)]
        struct App {
            id: u64,
        }
        let app: App = self
            .api
            .json(
                Method::GET,
                self.api.url(&["apps", "github-actions"]),
                Auth::Bearer(token),
                None,
                "GitHub Actions app",
            )
            .await?;
        *self.actions_app_id.lock().expect("lock poisoned") = Some(app.id);
        Ok(app.id)
    }

    /// `DELETE /applications/{client_id}/token`, authenticated with the
    /// client id and secret. Best effort: the link already succeeded, and a
    /// token that could not be revoked still lapses on its own — so a
    /// failure is logged, not returned.
    async fn revoke_user_token(&self, token: &Secret) {
        let Some(secret) = &self.client_secret else {
            return;
        };
        let url = self
            .api
            .url(&["applications", &self.config.client_id, "token"]);
        let body = json!({ "access_token": token.expose() });
        if let Err(e) = self
            .api
            .basic_delete(url, &self.config.client_id, secret, &body)
            .await
        {
            tracing::warn!(error = %e, "could not revoke a member's user token after linking");
        }
    }

    // ── reads ────────────────────────────────────────────────────────────

    fn repo_state(&self, r: &RepoJson) -> Result<RepoState> {
        let resource =
            Resource::parse_owner_repo(&format!("{}/{}", self.config.host, r.full_name))?;
        let mut state = RepoState::new(resource, r.id);
        state.visibility = match r.visibility.as_deref() {
            Some("public") => Visibility::Public,
            Some("internal") => Visibility::Internal,
            Some("private") => Visibility::Private,
            _ if r.private => Visibility::Private,
            _ => Visibility::Public,
        };
        state.archived = r.archived;
        state.default_branch = r.default_branch.clone();
        Ok(state)
    }

    async fn collaborators(
        &self,
        token: &Secret,
        owner: &str,
        name: &str,
    ) -> Result<Vec<CollaboratorJson>> {
        let mut url = self.api.url(&["repos", owner, name, "collaborators"]);
        url.query_pairs_mut().append_pair("affiliation", "direct");
        self.api
            .get_all(url, Auth::Bearer(token), "collaborators")
            .await
    }

    async fn invitations(
        &self,
        token: &Secret,
        owner: &str,
        name: &str,
    ) -> Result<Vec<InvitationJson>> {
        let url = self.api.url(&["repos", owner, name, "invitations"]);
        self.api
            .get_all(url, Auth::Bearer(token), "invitations")
            .await
    }

    async fn managed_ruleset(
        &self,
        token: &Secret,
        owner: &str,
        name: &str,
    ) -> Result<Option<RulesetJson>> {
        let mut url = self.api.url(&["repos", owner, name, "rulesets"]);
        url.query_pairs_mut()
            .append_pair("includes_parents", "false");
        let list: Vec<RulesetSummary> = self
            .api
            .get_all(url, Auth::Bearer(token), "rulesets")
            .await?;
        let Some(summary) = list.into_iter().find(|r| r.name == RULESET_NAME) else {
            return Ok(None);
        };
        let url = self
            .api
            .url(&["repos", owner, name, "rulesets", &summary.id.to_string()]);
        self.api.get_opt(url, Auth::Bearer(token), "ruleset").await
    }

    fn protection(
        &self,
        rs: &RulesetJson,
        default_branch: Option<&str>,
        actions_id: u64,
    ) -> ProtectionState {
        let mut p = ProtectionState::default();
        p.present = true;
        p.enforced = rs.enforcement == "active";

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
        let mut default_names = vec!["~DEFAULT_BRANCH".to_string(), "~ALL".to_string()];
        if let Some(b) = default_branch {
            default_names.push(format!("refs/heads/{b}"));
        }
        let (include, exclude) = (refs("include"), refs("exclude"));
        // Any exclusion at all counts as not covering: `refs/heads/*` or a
        // pattern matching the default branch excludes it as surely as its
        // literal name, and the managed ruleset is created with none.
        p.covers_default_branch = rs.target.as_deref().unwrap_or("branch") == "branch"
            && include.iter().any(|r| default_names.contains(r))
            && exclude.is_empty();

        for rule in &rs.rules {
            match rule.kind.as_str() {
                "pull_request" => p.requires_pull_request = true,
                "non_fast_forward" => p.blocks_force_push = true,
                "deletion" => p.blocks_deletion = true,
                "required_status_checks" => {
                    let checks = rule
                        .parameters
                        .as_ref()
                        .and_then(|v| v.get("required_status_checks"))
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    // Only a check pinned to the Actions App counts: an
                    // unpinned one is satisfied by any status of that name,
                    // which anyone with write access can post.
                    p.required_checks.extend(checks.iter().filter_map(|c| {
                        let pinned =
                            c.get("integration_id").and_then(Value::as_u64) == Some(actions_id);
                        pinned
                            .then(|| c.get("context").and_then(Value::as_str))
                            .flatten()
                            .map(str::to_string)
                    }));
                }
                _ => {}
            }
        }

        match &rs.bypass_actors {
            Some(actors) => {
                p.bypass_actors = actors
                    .iter()
                    .map(|a| {
                        format!(
                            "{}:{}:{}",
                            a.actor_type,
                            a.actor_id.map_or_else(|| "-".into(), |i| i.to_string()),
                            a.bypass_mode.as_deref().unwrap_or("always")
                        )
                    })
                    .collect()
            }
            // Not visible to us is not the same as none: fail closed.
            None => p.bypass_actors = vec!["<bypass actors not visible to the bridge>".into()],
        }
        if let Some(mode) = rs.current_user_can_bypass.as_deref()
            && mode != "never"
        {
            p.bypass_actors.push(format!("bridge-app:{mode}"));
        }
        p
    }

    // ── bootstrap steps ──────────────────────────────────────────────────

    async fn write_file(
        &self,
        repo: &Resource,
        path: &str,
        contents: &[u8],
        message: &str,
    ) -> Result<StepOutcome> {
        validate_repo_path(path)?;
        let (token, owner, name) = self.repo_token(repo, PERMS_CONTENTS).await?;
        let mut segments = vec!["repos", owner.as_str(), name.as_str(), "contents"];
        segments.extend(path.split('/'));
        let url = self.api.url(&segments);

        // A directory at `path` answers with a JSON array, a file with an
        // object: read it untyped first so the conflict is reported as one.
        let existing: Option<Value> = self
            .api
            .get_opt(url.clone(), Auth::Bearer(&token), path)
            .await?;
        let existing = match existing {
            Some(Value::Array(_)) => {
                return Err(ForgeError::Rejected {
                    status: 409,
                    message: format!("`{path}` exists and is a directory, not a file"),
                });
            }
            Some(v) => Some(
                serde_json::from_value::<ContentJson>(v)
                    .map_err(|e| ForgeError::Protocol(format!("{path}: {e}")))?,
            ),
            None => None,
        };
        let sha = match existing {
            Some(c) if c.kind != "file" => {
                return Err(ForgeError::Rejected {
                    status: 409,
                    message: format!("`{path}` exists and is a {}, not a file", c.kind),
                });
            }
            Some(c) => {
                if decode_content(&c)? == contents {
                    return Ok(StepOutcome::Unchanged);
                }
                Some(c.sha)
            }
            None => None,
        };

        let mut body = json!({ "message": message, "content": STANDARD.encode(contents) });
        if let Some(sha) = &sha {
            body["sha"] = json!(sha);
        }
        self.api
            .send(Method::PUT, url, Auth::Bearer(&token), Some(&body), path)
            .await
            .map_err(|e| match e {
                ForgeError::Rejected { status, message } => ForgeError::Rejected {
                    status,
                    message: format!(
                        "{message} — if the default branch is already protected, this file can \
                         only change through a pull request (the ruleset has no bypass actors, \
                         by design)"
                    ),
                },
                e => e,
            })?;
        Ok(if sha.is_some() {
            StepOutcome::Updated
        } else {
            StepOutcome::Created
        })
    }

    async fn set_variable(&self, repo: &Resource, var: &str, value: &str) -> Result<StepOutcome> {
        if var.is_empty()
            || !var
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(ForgeError::Config(format!(
                "variable name `{var}` must be [A-Z0-9_]"
            )));
        }
        let (token, owner, name) = self.repo_token(repo, PERMS_VARIABLES).await?;
        let url = self
            .api
            .url(&["repos", &owner, &name, "actions", "variables", var]);
        #[derive(Deserialize)]
        struct Variable {
            value: String,
        }
        let body = json!({ "name": var, "value": value });
        match self
            .api
            .get_opt::<Variable>(url.clone(), Auth::Bearer(&token), var)
            .await?
        {
            Some(v) if v.value == value => Ok(StepOutcome::Unchanged),
            Some(_) => {
                self.api
                    .send(Method::PATCH, url, Auth::Bearer(&token), Some(&body), var)
                    .await?;
                Ok(StepOutcome::Updated)
            }
            None => {
                let url = self
                    .api
                    .url(&["repos", &owner, &name, "actions", "variables"]);
                self.api
                    .send(Method::POST, url, Auth::Bearer(&token), Some(&body), var)
                    .await?;
                Ok(StepOutcome::Created)
            }
        }
    }

    async fn protect(&self, repo: &Resource, spec: &ProtectionSpec) -> Result<StepOutcome> {
        let (token, owner, name) = self.repo_token(repo, PERMS_ADMIN).await?;
        let actions_id = self.actions_app_id(&token).await?;
        let repo_json: RepoJson = self
            .api
            .json(
                Method::GET,
                self.api.url(&["repos", &owner, &name]),
                Auth::Bearer(&token),
                None,
                repo.as_str(),
            )
            .await?;
        let body = ruleset_body(spec, actions_id);

        match self.managed_ruleset(&token, &owner, &name).await? {
            Some(rs) => {
                let observed =
                    self.protection(&rs, repo_json.default_branch.as_deref(), actions_id);
                if satisfies(&observed, spec) {
                    return Ok(StepOutcome::Unchanged);
                }
                let url = self
                    .api
                    .url(&["repos", &owner, &name, "rulesets", &rs.id.to_string()]);
                self.api
                    .send(
                        Method::PUT,
                        url,
                        Auth::Bearer(&token),
                        Some(&body),
                        "ruleset",
                    )
                    .await?;
                Ok(StepOutcome::Updated)
            }
            None => {
                let url = self.api.url(&["repos", &owner, &name, "rulesets"]);
                self.api
                    .send(
                        Method::POST,
                        url,
                        Auth::Bearer(&token),
                        Some(&body),
                        "ruleset",
                    )
                    .await?;
                Ok(StepOutcome::Created)
            }
        }
    }

    // ── roles ────────────────────────────────────────────────────────────

    /// Whether `id` is the account holder of a personal-account namespace:
    /// the repository's implicit admin, never a collaborator to add, report
    /// or remove.
    fn is_personal_owner(ns: &Namespace, id: u64) -> bool {
        ns.kind == NamespaceKind::User && Some(id) == ns.owner_id
    }

    /// Drop assignments GitHub cannot express: the owner of a personal
    /// account is its implicit admin and cannot be added as a collaborator.
    fn expressible(&self, ns: &Namespace, desired: &[RoleAssignment]) -> Vec<RoleAssignment> {
        desired
            .iter()
            .filter(|a| !Self::is_personal_owner(ns, a.account.id))
            .cloned()
            .collect()
    }

    async fn login_for(&self, token: &Secret, id: u64) -> Result<String> {
        // The numeric id is the binding; the login is looked up fresh so a
        // renamed-and-re-registered login never receives the role.
        let user: UserJson = self
            .api
            .json(
                Method::GET,
                self.api.url(&["user", &id.to_string()]),
                Auth::Bearer(token),
                None,
                "user",
            )
            .await?;
        if user.id != id {
            return Err(ForgeError::Protocol(format!(
                "asked for user {id}, GitHub answered with {}",
                user.id
            )));
        }
        Ok(user.login)
    }

    #[allow(clippy::too_many_arguments)]
    async fn change_role(
        &self,
        token: &Secret,
        ns: &Namespace,
        owner: &str,
        name: &str,
        account: &ForgeAccount,
        to: ForgeRole,
        current: Option<&Current>,
    ) -> Result<RoleOutcome> {
        let auth = Auth::Bearer(token);
        match (current, to) {
            (Some(Current::Invited { id, .. }), ForgeRole::None) => {
                let url = self
                    .api
                    .url(&["repos", owner, name, "invitations", &id.to_string()]);
                self.api
                    .send(Method::DELETE, url, auth, None, "invitation")
                    .await?;
                Ok(RoleOutcome::Applied)
            }
            (Some(Current::Member { login, .. }), ForgeRole::None) => {
                let url = self
                    .api
                    .url(&["repos", owner, name, "collaborators", login]);
                self.api
                    .send(Method::DELETE, url, auth, None, "collaborator")
                    .await?;
                Ok(RoleOutcome::Applied)
            }
            (None, ForgeRole::None) => Ok(RoleOutcome::Applied),
            (Some(Current::Invited { id, .. }), role) => {
                let url = self
                    .api
                    .url(&["repos", owner, name, "invitations", &id.to_string()]);
                let body = json!({ "permissions": invitation_permission(role) });
                self.api
                    .send(Method::PATCH, url, auth, Some(&body), "invitation")
                    .await?;
                Ok(RoleOutcome::Invited)
            }
            (_, role) => {
                let login = self.login_for(token, account.id).await?;
                let url = self
                    .api
                    .url(&["repos", owner, name, "collaborators", &login]);
                // Personal-account repos take no permission: collaborators
                // there are always `write`.
                let body = (ns.kind == NamespaceKind::Organization)
                    .then(|| json!({ "permission": put_permission(role) }));
                let resp = self
                    .api
                    .send(Method::PUT, url, auth, body.as_ref(), "collaborator")
                    .await?;
                Ok(if resp.status() == reqwest::StatusCode::CREATED {
                    RoleOutcome::Invited
                } else {
                    RoleOutcome::Applied
                })
            }
        }
    }
}

/// Where someone stands on a repository before a change.
enum Current {
    Member { login: String, role: ForgeRole },
    Invited { id: u64, role: ForgeRole },
}

impl Current {
    fn role(&self) -> ForgeRole {
        match self {
            Current::Member { role, .. } | Current::Invited { role, .. } => *role,
        }
    }
}

#[async_trait]
impl Forge for GitHubForge {
    fn kind(&self) -> ForgeKind {
        ForgeKind::GitHub
    }

    fn host(&self) -> &str {
        &self.config.host
    }

    fn capabilities(&self, ns: &Namespace) -> Capabilities {
        let automated = ns.installation_id.is_some();
        let mut c = Capabilities::default();
        c.automation = automated;
        c.required_checks = RequiredCheckKind::Ruleset;
        c.account_link = LinkMethod::DeviceFlow;
        c.webhooks = automated;
        c.per_repo_tokens = automated;
        match ns.kind {
            NamespaceKind::User => {
                // §8: only the account holder can create repositories, and
                // every collaborator is `write`.
                c.bot_can_create_repos = false;
                c.role_levels = USER_LADDER.to_vec();
            }
            _ => {
                c.bot_can_create_repos = automated;
                c.role_levels = ORG_LADDER.to_vec();
            }
        }
        c
    }

    async fn begin_bind(&self, req: BindRequest) -> Result<BindStep> {
        if req.namespace.host() != self.config.host || !req.namespace.is_namespace() {
            return Err(ForgeError::WrongResource {
                resource: req.namespace.to_string(),
                expected: format!("a namespace on `{}`", self.config.host),
            });
        }
        if req.state.len() < MIN_STATE_LEN
            || !req
                .state
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(ForgeError::Config(format!(
                "bind state must be at least {MIN_STATE_LEN} base64url characters from a CSPRNG \
                 (see GitHubForge::new_state)"
            )));
        }
        let mut url = self
            .api
            .web_url(&["apps", &self.config.app_slug, "installations", "new"]);
        url.query_pairs_mut().append_pair("state", &req.state);
        Ok(BindStep::Redirect {
            url: url.to_string(),
        })
    }

    async fn complete_bind(&self, cb: BindCallback) -> Result<NamespaceBinding> {
        let reject = |m: String| Err(ForgeError::BindRejected(m));
        let state = cb.params.get("state").map(String::as_str).unwrap_or("");
        if cb.expected_state.len() < MIN_STATE_LEN
            || aws_lc_rs::constant_time::verify_slices_are_equal(
                state.as_bytes(),
                cb.expected_state.as_bytes(),
            )
            .is_err()
        {
            return reject("the `state` does not match a bind this VTC started".into());
        }
        match cb.params.get("setup_action").map(String::as_str) {
            Some("install") | Some("update") | None => {}
            Some("request") => {
                return reject(
                    "the installation was requested but an owner has not approved it yet".into(),
                );
            }
            Some(other) => return reject(format!("unexpected setup_action `{other}`")),
        }
        if cb.expected_namespace.host() != self.config.host || !cb.expected_namespace.is_namespace()
        {
            return reject(format!(
                "`{}` is not a namespace on `{}`",
                cb.expected_namespace, self.config.host
            ));
        }
        let installation_id: u64 = match cb.params.get("installation_id").map(|s| s.parse()) {
            Some(Ok(id)) => id,
            _ => return reject("missing or malformed `installation_id`".into()),
        };

        // Authenticated as the App, this only finds installations of *this*
        // App — another App's id is a 404.
        let jwt = self.jwt().await?;
        let url = self
            .api
            .url(&["app", "installations", &installation_id.to_string()]);
        let inst: InstallationJson = match self
            .api
            .json(Method::GET, url, Auth::Bearer(&jwt), None, "installation")
            .await
        {
            Ok(i) => i,
            Err(ForgeError::NotFound { .. }) => {
                return reject(format!(
                    "installation {installation_id} is not an installation of this App"
                ));
            }
            Err(e) => return Err(e),
        };
        if inst.id != installation_id {
            return reject("GitHub returned a different installation".into());
        }
        if !inst
            .account
            .login
            .eq_ignore_ascii_case(cb.expected_namespace.owner())
        {
            return reject(format!(
                "the App was installed on `{}`, but the bind was for `{}`",
                inst.account.login, cb.expected_namespace
            ));
        }
        if inst.suspended_at.is_some() {
            return reject("the installation is suspended".into());
        }
        let kind = match inst.account.kind.as_str() {
            "Organization" => NamespaceKind::Organization,
            "User" => NamespaceKind::User,
            other => return reject(format!("unsupported account type `{other}`")),
        };
        let namespace = Namespace::new(cb.expected_namespace.clone(), kind)
            .with_owner_id(inst.account.id)
            .with_installation(installation_id);
        Ok(NamespaceBinding::new(
            namespace,
            missing_permissions(&inst.permissions),
        ))
    }

    async fn begin_account_link(&self, member: &str) -> Result<LinkStep> {
        tracing::debug!(member, "starting GitHub device flow");
        let url = self.api.web_url(&["login", "device", "code"]);
        let resp: DeviceCodeJson = self
            .api
            .oauth(url, &json!({ "client_id": self.config.client_id }))
            .await?;
        if let Some(err) = resp.error {
            return Err(ForgeError::LinkFailed(format!(
                "{err}: {}",
                resp.error_description.unwrap_or_default()
            )));
        }
        let missing = || ForgeError::Protocol("device code response is incomplete".into());
        Ok(LinkStep::DeviceCode {
            device_code: resp.device_code.ok_or_else(missing)?,
            user_code: resp.user_code.ok_or_else(missing)?,
            verification_uri: resp.verification_uri.ok_or_else(missing)?,
            expires_in: resp.expires_in.ok_or_else(missing)?,
            interval: resp.interval.unwrap_or(5),
        })
    }

    async fn complete_account_link(&self, cb: LinkCallback) -> Result<ForgeAccount> {
        let LinkCallback::DeviceCode {
            device_code,
            mut interval,
            expires_in,
        } = cb
        else {
            return Err(ForgeError::Unsupported {
                operation: "redirect account link".into(),
                hint: "GitHub links accounts through the device flow".into(),
            });
        };
        let url = self.api.web_url(&["login", "oauth", "access_token"]);
        let body = json!({
            "client_id": self.config.client_id,
            "device_code": device_code,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        });
        // `expires_in` comes back from the caller, not from GitHub; never
        // poll longer than GitHub lets a device code live.
        let expires_in = expires_in.min(DEVICE_CODE_MAX_LIFETIME_SECS);
        let mut waited = 0u64;
        let token = loop {
            if waited >= expires_in {
                return Err(ForgeError::LinkFailed(
                    "the device code expired before the member approved; start again".into(),
                ));
            }
            tokio::time::sleep(self.config.device_poll_unit * interval.max(1) as u32).await;
            waited += interval.max(1);
            let poll: TokenPollJson = self.api.oauth(url.clone(), &body).await?;
            if let Some(token) = poll.access_token {
                break Secret::new(token);
            }
            match next_poll(interval, &poll)? {
                Some(next) => interval = next,
                None => unreachable!("next_poll returns Some or Err when there is no token"),
            }
        };

        let user: UserJson = self
            .api
            .json(
                Method::GET,
                self.api.url(&["user"]),
                Auth::Bearer(&token),
                None,
                "authenticated user",
            )
            .await?;
        // The bridge needs the id, not a standing credential for the
        // member's account: revoke the token when we can, and drop (wipe) it
        // either way.
        self.revoke_user_token(&token).await;
        Ok(ForgeAccount::new(user.id, user.login))
    }

    async fn inspect(&self, repo: &Resource) -> Result<RepoState> {
        let (ns, _, _) = self.locate(repo)?;
        let (token, owner, name) = self.repo_token(repo, PERMS_ADMIN).await?;
        let auth = Auth::Bearer(&token);
        let r: RepoJson = self
            .api
            .json(
                Method::GET,
                self.api.url(&["repos", &owner, &name]),
                auth,
                None,
                repo.as_str(),
            )
            .await?;
        let mut state = self.repo_state(&r)?;

        for c in self.collaborators(&token, &owner, &name).await? {
            if Self::is_personal_owner(&ns, c.id) {
                continue;
            }
            let role = c.role();
            state
                .collaborators
                .push(Collaborator::new(ForgeAccount::new(c.id, c.login), role));
        }
        for i in self.invitations(&token, &owner, &name).await? {
            if let Some(user) = i.invitee {
                state.collaborators.push(Collaborator::invited(
                    ForgeAccount::new(user.id, user.login),
                    role_from_name(&i.permissions).unwrap_or(ForgeRole::Read),
                ));
            }
        }
        if let Some(rs) = self.managed_ruleset(&token, &owner, &name).await? {
            let actions_id = self.actions_app_id(&token).await?;
            state.protection = self.protection(&rs, r.default_branch.as_deref(), actions_id);
        }
        Ok(state)
    }

    async fn create_repo(&self, spec: &RepoSpec) -> Result<RepoState> {
        let (ns, owner, name) = self.locate(&spec.resource)?;
        if !self.capabilities(&ns).bot_can_create_repos {
            return Err(ForgeError::Unsupported {
                operation: "repository creation".into(),
                hint: format!(
                    "the bridge cannot create repositories in `{}`; the account holder runs \
                     `gh repo create {owner}/{name}` and `vgi repo init`, then the repo is adopted",
                    ns.resource
                ),
            });
        }
        // No repository to scope to yet: this token is org-wide, but only
        // for administration. Accepted residual (review F6): for the life of
        // this one call the token could administer every repository the
        // installation covers. GitHub offers no narrower grant for
        // `POST /orgs/{org}/repos`; the token is not reused and is dropped on
        // return.
        let token = self.installation_token(&ns, None, PERMS_ADMIN).await?;
        let auth = Auth::Bearer(&token);
        if let Some(existing) = self
            .api
            .get_opt::<RepoJson>(
                self.api.url(&["repos", owner, name]),
                auth,
                spec.resource.as_str(),
            )
            .await?
        {
            return Err(ForgeError::AlreadyExists {
                resource: spec.resource.to_string(),
                forge_id: Some(existing.id),
            });
        }
        let mut body = json!({
            "name": name,
            "visibility": match spec.visibility {
                Visibility::Private => "private",
                Visibility::Internal => "internal",
                _ => "public",
            },
            // A first commit gives the repo a default branch for the
            // bootstrap to commit to and the ruleset to cover.
            "auto_init": true,
        });
        if let Some(d) = &spec.description {
            body["description"] = json!(d);
        }
        let created: RepoJson = self
            .api
            .json(
                Method::POST,
                self.api.url(&["orgs", owner, "repos"]),
                auth,
                Some(&body),
                spec.resource.as_str(),
            )
            .await
            .map_err(|e| match e {
                ForgeError::Rejected {
                    status: 422,
                    message,
                } if message.contains("already exists") => ForgeError::AlreadyExists {
                    resource: spec.resource.to_string(),
                    forge_id: None,
                },
                e => e,
            })?;
        self.repo_state(&created)
    }

    async fn archive_repo(&self, repo: &Resource) -> Result<()> {
        let (token, owner, name) = self.repo_token(repo, PERMS_ADMIN).await?;
        let url = self.api.url(&["repos", &owner, &name]);
        let r: RepoJson = self
            .api
            .json(
                Method::GET,
                url.clone(),
                Auth::Bearer(&token),
                None,
                repo.as_str(),
            )
            .await?;
        if r.archived {
            return Ok(());
        }
        self.api
            .send(
                Method::PATCH,
                url,
                Auth::Bearer(&token),
                Some(&json!({ "archived": true })),
                repo.as_str(),
            )
            .await?;
        Ok(())
    }

    async fn apply_roles(
        &self,
        repo: &Resource,
        desired: &[RoleAssignment],
        unlisted: Unlisted,
    ) -> Result<ApplyReport> {
        let (ns, owner, name) = self.locate(repo)?;
        let ladder = self.capabilities(&ns).role_levels;
        let desired = self.expressible(&ns, desired);
        let mut wanted: BTreeMap<u64, (ForgeAccount, ForgeRole)> = BTreeMap::new();
        for a in &desired {
            // Round down onto the ladder again: never trust the caller to
            // have done it, and never ask GitHub for more than it offers.
            let role = collapse_to_ladder(a.role, &ladder);
            if let Some((_, prev)) = wanted.insert(a.account.id, (a.account.clone(), role))
                && prev != role
            {
                return Err(ForgeError::Config(format!(
                    "account {} is assigned two different roles",
                    a.account.id
                )));
            }
        }

        let token = self
            .installation_token(&ns, Some(name), PERMS_ADMIN)
            .await?;
        let mut current: BTreeMap<u64, (ForgeAccount, Current)> = BTreeMap::new();
        for c in self.collaborators(&token, owner, name).await? {
            if Self::is_personal_owner(&ns, c.id) {
                continue;
            }
            let role = c.role();
            current.insert(
                c.id,
                (
                    ForgeAccount::new(c.id, c.login.clone()),
                    Current::Member {
                        login: c.login,
                        role,
                    },
                ),
            );
        }
        for i in self.invitations(&token, owner, name).await? {
            if let Some(user) = i.invitee {
                let role = role_from_name(&i.permissions).unwrap_or(ForgeRole::Read);
                current.entry(user.id).or_insert((
                    ForgeAccount::new(user.id, user.login),
                    Current::Invited { id: i.id, role },
                ));
            }
        }

        let mut report = ApplyReport::default();
        let mut todo: Vec<(ForgeAccount, ForgeRole)> = Vec::new();
        for (id, (account, role)) in &wanted {
            let have = current.get(id).map_or(ForgeRole::None, |(_, c)| c.role());
            if have == *role {
                if *role != ForgeRole::None {
                    report.unchanged.push(account.clone());
                }
            } else {
                todo.push((account.clone(), *role));
            }
        }
        for (id, (account, c)) in &current {
            if wanted.contains_key(id) {
                continue;
            }
            match unlisted {
                Unlisted::Remove => todo.push((account.clone(), ForgeRole::None)),
                _ => {
                    let mut collab = Collaborator::new(account.clone(), c.role());
                    collab.pending = matches!(c, Current::Invited { .. });
                    report.kept_unlisted.push(collab);
                }
            }
        }

        for (account, to) in todo {
            let cur = current.get(&account.id).map(|(_, c)| c);
            let from = cur.map_or(ForgeRole::None, Current::role);
            let outcome = match self
                .change_role(&token, &ns, owner, name, &account, to, cur)
                .await
            {
                Ok(o) => o,
                // Credentials and rate limits fail the whole job; anything
                // else is this one person's problem.
                Err(e @ (ForgeError::Unauthorized(_) | ForgeError::RateLimited { .. })) => {
                    return Err(e);
                }
                Err(e) => RoleOutcome::Failed(e.to_string()),
            };
            report
                .changes
                .push(RoleChange::new(account, from, to, outcome));
        }
        Ok(report)
    }

    fn bootstrap_plan(&self, repo: &RepoSpec, cfg: &VgiConfig) -> Result<Vec<BootstrapStep>> {
        if repo.resource.host() != self.config.host {
            return Err(ForgeError::WrongResource {
                resource: repo.resource.to_string(),
                expected: format!("a repository on `{}`", self.config.host),
            });
        }
        repo.resource.require_owner_repo()?;
        github_plan(repo, cfg, &self.config.checkout_action)
    }

    async fn run_step(&self, repo: &Resource, step: &BootstrapStep) -> Result<StepOutcome> {
        match &step.action {
            StepAction::WriteFile {
                path,
                contents,
                message,
            } => self.write_file(repo, path, contents, message).await,
            StepAction::SetVariable { name, value } => self.set_variable(repo, name, value).await,
            StepAction::ProtectDefaultBranch(spec) => self.protect(repo, spec).await,
            other => Err(ForgeError::Unsupported {
                operation: format!("bootstrap step {other:?}"),
                hint: "this GitHub adapter does not know that step".into(),
            }),
        }
    }

    fn parse_event(&self, headers: &HeaderMap, body: &[u8]) -> Result<Option<ForgeEvent>> {
        webhook::parse(&self.webhook_secret, &self.config.host, headers, body)
    }
}

impl ForgeHooks for GitHubForge {
    /// In a personal-account namespace the owner is the repository's
    /// implicit admin and GitHub refuses to add them as a collaborator, so
    /// they are dropped from the desired set before it reaches GitHub (and
    /// before the core reports their "missing" role as drift).
    fn before_apply_roles(
        &self,
        repo: &Resource,
        desired: &[RoleAssignment],
    ) -> HookDecision<Vec<RoleAssignment>> {
        let Ok(ns) = self.namespace(&repo.namespace()) else {
            return HookDecision::Continue;
        };
        let kept = self.expressible(&ns, desired);
        if kept.len() == desired.len() {
            HookDecision::Continue
        } else {
            HookDecision::Modify(kept)
        }
    }
}

/// The ruleset GitHub is asked for: default branch, PR required, the check
/// required and pinned to the Actions App, no force-push, no deletion, and
/// an empty bypass list.
fn ruleset_body(spec: &ProtectionSpec, actions_id: u64) -> Value {
    let mut rules = Vec::new();
    if spec.block_deletion {
        rules.push(json!({ "type": "deletion" }));
    }
    if spec.block_force_push {
        rules.push(json!({ "type": "non_fast_forward" }));
    }
    if spec.require_pull_request {
        rules.push(json!({
            "type": "pull_request",
            "parameters": {
                "required_approving_review_count": 0,
                "dismiss_stale_reviews_on_push": false,
                "require_code_owner_review": false,
                "require_last_push_approval": false,
                "required_review_thread_resolution": false,
            }
        }));
    }
    rules.push(json!({
        "type": "required_status_checks",
        "parameters": {
            "strict_required_status_checks_policy": false,
            "required_status_checks": [
                { "context": spec.required_check, "integration_id": actions_id }
            ],
        }
    }));
    json!({
        "name": RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
        "rules": rules,
    })
}

fn satisfies(observed: &ProtectionState, spec: &ProtectionSpec) -> bool {
    observed.present
        && observed.enforced
        && observed.covers_default_branch
        && observed.bypass_actors.is_empty()
        && observed.required_checks.contains(&spec.required_check)
        && (!spec.require_pull_request || observed.requires_pull_request)
        && (!spec.block_force_push || observed.blocks_force_push)
        && (!spec.block_deletion || observed.blocks_deletion)
}

/// The next poll interval after a device-flow poll that returned no token:
/// `Some(interval)` to keep polling, `Err` to stop.
///
/// `slow_down` adds five seconds (RFC 8628 §3.5) unless GitHub names the new
/// interval itself.
pub(crate) fn next_poll(interval: u64, poll: &TokenPollJson) -> Result<Option<u64>> {
    match poll.error.as_deref() {
        Some("authorization_pending") => Ok(Some(interval)),
        Some("slow_down") => Ok(Some(
            poll.interval.unwrap_or(interval + 5).max(interval + 5),
        )),
        Some("expired_token") => Err(ForgeError::LinkFailed(
            "the device code expired before the member approved; start again".into(),
        )),
        Some("access_denied") => Err(ForgeError::LinkFailed(
            "the member declined the authorisation".into(),
        )),
        Some(other) => Err(ForgeError::LinkFailed(format!(
            "{other}: {}",
            poll.error_description.as_deref().unwrap_or("")
        ))),
        None => Err(ForgeError::Protocol(
            "token response has neither a token nor an error".into(),
        )),
    }
}

fn decode_content(c: &ContentJson) -> Result<Vec<u8>> {
    match c.encoding.as_deref() {
        Some("base64") => {
            let compact: String = c
                .content
                .as_deref()
                .unwrap_or("")
                .chars()
                .filter(|ch| !ch.is_whitespace())
                .collect();
            STANDARD
                .decode(compact)
                .map_err(|e| ForgeError::Protocol(format!("file content: {e}")))
        }
        // Over 1 MB GitHub returns `encoding: "none"` and no content. Nothing
        // the bootstrap writes is that large, so a file that is must have
        // been put there by someone else: refuse rather than overwrite what
        // we cannot see.
        Some("none") => Err(ForgeError::Rejected {
            status: 409,
            message: "the existing file is too large for GitHub to return inline (over 1 MB); \
                      it was not written by the bootstrap — remove or rename it"
                .into(),
        }),
        other => Err(ForgeError::Protocol(format!(
            "file content in unknown encoding {other:?}"
        ))),
    }
}

fn role_from_name(name: &str) -> Option<ForgeRole> {
    Some(match name {
        "admin" => ForgeRole::Admin,
        "maintain" => ForgeRole::Maintain,
        "write" | "push" => ForgeRole::Write,
        "triage" => ForgeRole::Triage,
        "read" | "pull" => ForgeRole::Read,
        _ => return None,
    })
}

fn put_permission(role: ForgeRole) -> &'static str {
    match role {
        ForgeRole::Admin => "admin",
        ForgeRole::Maintain => "maintain",
        ForgeRole::Write => "push",
        ForgeRole::Triage => "triage",
        _ => "pull",
    }
}

fn invitation_permission(role: ForgeRole) -> &'static str {
    match role {
        ForgeRole::Admin => "admin",
        ForgeRole::Maintain => "maintain",
        ForgeRole::Write => "write",
        ForgeRole::Triage => "triage",
        _ => "read",
    }
}

// ── wire shapes ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RepoJson {
    id: u64,
    full_name: String,
    #[serde(default)]
    visibility: Option<String>,
    #[serde(default)]
    private: bool,
    #[serde(default)]
    archived: bool,
    #[serde(default)]
    default_branch: Option<String>,
}

#[derive(Deserialize)]
struct UserJson {
    id: u64,
    login: String,
}

#[derive(Deserialize)]
struct CollaboratorJson {
    id: u64,
    login: String,
    #[serde(default)]
    role_name: Option<String>,
    #[serde(default)]
    permissions: Option<PermsJson>,
}

impl CollaboratorJson {
    /// `role_name`, or — for a custom role — the highest base permission.
    fn role(&self) -> ForgeRole {
        if let Some(role) = self.role_name.as_deref().and_then(role_from_name) {
            return role;
        }
        let p = self.permissions.as_ref();
        let has = |f: fn(&PermsJson) -> bool| p.is_some_and(f);
        if has(|p| p.admin) {
            ForgeRole::Admin
        } else if has(|p| p.maintain) {
            ForgeRole::Maintain
        } else if has(|p| p.push) {
            ForgeRole::Write
        } else if has(|p| p.triage) {
            ForgeRole::Triage
        } else {
            ForgeRole::Read
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PermsJson {
    admin: bool,
    maintain: bool,
    push: bool,
    triage: bool,
}

#[derive(Deserialize)]
struct InvitationJson {
    id: u64,
    #[serde(default)]
    invitee: Option<UserJson>,
    permissions: String,
}

#[derive(Deserialize)]
struct RulesetSummary {
    id: u64,
    name: String,
}

#[derive(Deserialize)]
struct RulesetJson {
    id: u64,
    #[serde(default)]
    target: Option<String>,
    enforcement: String,
    /// Absent when the caller may not edit the ruleset — which is exactly
    /// when it must not be read as "none".
    #[serde(default)]
    bypass_actors: Option<Vec<BypassJson>>,
    #[serde(default)]
    current_user_can_bypass: Option<String>,
    #[serde(default)]
    conditions: Option<Value>,
    #[serde(default)]
    rules: Vec<RuleJson>,
}

#[derive(Deserialize)]
struct BypassJson {
    #[serde(default)]
    actor_id: Option<u64>,
    actor_type: String,
    #[serde(default)]
    bypass_mode: Option<String>,
}

#[derive(Deserialize)]
struct RuleJson {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    parameters: Option<Value>,
}

#[derive(Deserialize)]
struct InstallationJson {
    id: u64,
    account: AccountJson,
    #[serde(default)]
    permissions: BTreeMap<String, String>,
    #[serde(default)]
    suspended_at: Option<String>,
}

#[derive(Deserialize)]
struct AccountJson {
    id: u64,
    login: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize)]
struct ContentJson {
    sha: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    encoding: Option<String>,
}

#[derive(Deserialize)]
struct DeviceCodeJson {
    device_code: Option<String>,
    user_code: Option<String>,
    verification_uri: Option<String>,
    expires_in: Option<u64>,
    interval: Option<u64>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Deserialize, Default)]
pub(crate) struct TokenPollJson {
    pub(crate) access_token: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) error_description: Option<String>,
    pub(crate) interval: Option<u64>,
}

impl std::fmt::Debug for TokenPollJson {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenPollJson")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "<redacted>"),
            )
            .field("error", &self.error)
            .field("interval", &self.interval)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn poll(error: &str, interval: Option<u64>) -> TokenPollJson {
        TokenPollJson {
            error: Some(error.into()),
            interval,
            ..TokenPollJson::default()
        }
    }

    #[test]
    fn device_polling_backs_off_on_slow_down() {
        assert_eq!(
            next_poll(5, &poll("authorization_pending", None)).unwrap(),
            Some(5)
        );
        assert_eq!(next_poll(5, &poll("slow_down", None)).unwrap(), Some(10));
        assert_eq!(
            next_poll(5, &poll("slow_down", Some(15))).unwrap(),
            Some(15)
        );
        // A smaller server-named interval never speeds us up past +5.
        assert_eq!(next_poll(5, &poll("slow_down", Some(1))).unwrap(), Some(10));
        assert!(matches!(
            next_poll(5, &poll("expired_token", None)),
            Err(ForgeError::LinkFailed(_))
        ));
        assert!(matches!(
            next_poll(5, &poll("access_denied", None)),
            Err(ForgeError::LinkFailed(_))
        ));
    }

    #[test]
    fn roles_map_both_ways() {
        for role in [
            ForgeRole::Read,
            ForgeRole::Triage,
            ForgeRole::Write,
            ForgeRole::Maintain,
            ForgeRole::Admin,
        ] {
            assert_eq!(role_from_name(invitation_permission(role)), Some(role));
            assert_eq!(role_from_name(put_permission(role)), Some(role));
        }
        let custom = CollaboratorJson {
            id: 1,
            login: "x".into(),
            role_name: Some("security-reviewer".into()),
            permissions: Some(PermsJson {
                triage: true,
                ..PermsJson::default()
            }),
        };
        assert_eq!(custom.role(), ForgeRole::Triage);
    }
}
