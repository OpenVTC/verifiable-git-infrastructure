//! [`ForgejoForge`]: the `Forge` implementation.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use http::HeaderMap;
use reqwest::Method;
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use vgi_forge::{
    ApplyReport, BindCallback, BindRequest, BindStep, BootstrapStep, Capabilities, Collaborator,
    Drift, Forge, ForgeAccount, ForgeError, ForgeEvent, ForgeHooks, ForgeKind, ForgeRole,
    HookDecision, LinkCallback, LinkMethod, LinkStep, MergeMethod, Namespace, NamespaceBinding,
    NamespaceKind, Projection, ProtectionGap, ProtectionSpec, ProtectionState, RepoSettings,
    RepoSpec, RepoState, RequiredCheckKind, Resource, Result, RoleAssignment, RoleChange,
    RoleOutcome, StepAction, StepOutcome, Unlisted, VgiConfig, Visibility, async_trait,
    collapse_to_ladder, default_diff, validate_repo_path,
};

use crate::api::{Api, Auth};
use crate::config::{Credentials, ForgejoConfig, MergeFallback, TokenRotation, check_login};
use crate::oauth::{OAuthKeys, Purpose, TokenJson, unix_now};
use crate::plan::{MergePlan, PROTECTED_PATHS, PlanOptions, forgejo_plan};
use crate::secret::Secret;
use crate::version::InstanceInfo;
use crate::webhook::{self, HOOK_EVENTS};

/// Scopes the bot's access token needs, and no more:
///
/// - `write:organization` — create repositories in the org (with
///   `write:repository`), read the bot's own org permissions;
/// - `write:repository` — contents, collaborators, branch protection,
///   Actions variables, archive;
/// - `read:user` — look a person's login up by numeric id before every role
///   change (`/users/search?uid=`), and confirm a token is the bot's
///   (`/user`) before trusting it. Without it the adapter would have to act
///   on logins the VTC recorded, which a rename can hand to someone else.
pub const BOT_TOKEN_SCOPES: [&str; 3] = ["write:organization", "write:repository", "read:user"];

/// Name prefix of the tokens [`ForgejoForge::rotate_token`] mints; older
/// ones with this prefix are deleted once the new one is verified.
pub const TOKEN_NAME_PREFIX: &str = "vgi-bridge-";

/// The role ladder. Forgejo has `read`, `write` and `admin` collaborators;
/// `Maintain` is the adapter's own rung — `write` **and** a place on the
/// default branch's merge allow-list (§5.9) — because `write` alone cannot
/// separate "may merge" from "may push a branch".
const LADDER: [ForgeRole; 4] = [
    ForgeRole::Read,
    ForgeRole::Write,
    ForgeRole::Maintain,
    ForgeRole::Admin,
];

/// Shortest bind `state` accepted: 128 bits of base64url.
const MIN_STATE_LEN: usize = 22;

/// Team units, for instances old enough to read them (an `admin` team gets
/// every unit regardless on current Forgejo).
const TEAM_UNITS: [&str; 3] = ["repo.code", "repo.pulls", "repo.actions"];

/// What the adapter learned about the instance and its bot.
#[derive(Debug, Clone)]
struct Probed {
    info: InstanceInfo,
    bot: ForgeAccount,
    signing_key: Option<Vec<u8>>,
}

/// What [`ForgejoForge::rotate_token`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TokenRotationReport {
    /// Name of the token now in use.
    pub new_token: String,
    /// Names of the tokens deleted: earlier rotations' and the one replaced.
    pub deleted: Vec<String>,
}

/// The Forgejo adapter: one bot user on one Forgejo (or Gitea) instance.
///
/// Holds the bot's token (swappable, for rotation), the OAuth client secret,
/// the webhook secret, and the namespaces the core has bound. Build it with
/// [`ForgejoForge::connect`], which probes the instance's version and
/// confirms the token is the bot's.
pub struct ForgejoForge {
    config: ForgejoConfig,
    api: Api,
    token: RwLock<Arc<Secret>>,
    rotation: TokenRotation,
    oauth_secret: Secret,
    oauth_keys: OAuthKeys,
    webhook_secret: Secret,
    namespaces: RwLock<BTreeMap<Resource, Namespace>>,
    probed: RwLock<Probed>,
}

impl std::fmt::Debug for ForgejoForge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForgejoForge")
            .field("host", &self.config.host)
            .field("bot", &self.config.bot_login)
            .field("token", &"<redacted>")
            .field("rotation", &self.rotation)
            .field("oauth_secret", &self.oauth_secret)
            .field("webhook_secret", &self.webhook_secret)
            .finish_non_exhaustive()
    }
}

impl ForgejoForge {
    /// Connect to `config`'s instance: probe `/api/v1/version` (switching off
    /// what the instance lacks), confirm `credentials.bot_token` belongs to
    /// `config.bot_login`, and — in the signing-key merge fallback on an
    /// instance without fast-forward-only merges — fetch the instance's
    /// signing key for the plan.
    pub async fn connect(config: ForgejoConfig, credentials: Credentials) -> Result<Self> {
        let Credentials {
            bot_token,
            rotation,
            oauth_client_secret,
            webhook_secret,
        } = credentials;
        for (what, s) in [
            ("bot token", &bot_token),
            ("OAuth client secret", &oauth_client_secret),
            ("webhook secret", &webhook_secret),
        ] {
            if s.expose().is_empty() {
                return Err(ForgeError::Config(format!("empty {what}")));
            }
        }
        if config.oauth_client_id.is_empty() {
            return Err(ForgeError::Config("empty OAuth client id".into()));
        }
        check_login(&config.team_name)
            .map_err(|_| ForgeError::Config(format!("bad team name `{}`", config.team_name)))?;
        vgi_forge::Resource::namespace_of(&config.host, "x").map_err(|e| {
            ForgeError::Config(format!("`{}` is not a forge host: {e}", config.host))
        })?;
        let api = Api::new(
            config.api_base(),
            config.base_url.clone(),
            config.request_timeout,
        )?;
        let probed = probe(&api, &config, &bot_token).await?;
        let oauth_keys = OAuthKeys::new(&oauth_client_secret);
        Ok(ForgejoForge {
            config,
            api,
            token: RwLock::new(Arc::new(bot_token)),
            rotation,
            oauth_secret: oauth_client_secret,
            oauth_keys,
            webhook_secret,
            namespaces: RwLock::new(BTreeMap::new()),
            probed: RwLock::new(probed),
        })
    }

    /// The configuration.
    pub fn config(&self) -> &ForgejoConfig {
        &self.config
    }

    /// What the last probe found.
    pub fn instance(&self) -> InstanceInfo {
        self.probed().info
    }

    /// The bot's account.
    pub fn bot(&self) -> ForgeAccount {
        self.probed().bot
    }

    /// Probe the instance again (after an upgrade, say).
    pub async fn refresh(&self) -> Result<InstanceInfo> {
        let token = self.token();
        let probed = probe(&self.api, &self.config, &token).await?;
        let info = probed.info.clone();
        *self.probed.write().expect("probe lock poisoned") = probed;
        Ok(info)
    }

    fn probed(&self) -> Probed {
        self.probed.read().expect("probe lock poisoned").clone()
    }

    /// Tell the adapter about a bound namespace (from the VTC's store).
    /// Operations on repositories in a namespace never registered are
    /// refused with [`ForgeError::NotBound`].
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

    /// The instance's merge-signing public key (`/api/v1/signing-key.gpg`).
    pub async fn fetch_signing_key(&self) -> Result<Vec<u8>> {
        fetch_signing_key(&self.api, &self.token()).await
    }

    // ── the bot token ────────────────────────────────────────────────────

    fn token(&self) -> Arc<Secret> {
        self.token.read().expect("token lock poisoned").clone()
    }

    /// Swap in a token an operator minted (manual rotation). It is checked
    /// to be the bot's before it replaces the current one; the old token is
    /// not deleted — that is the operator's to do.
    pub async fn replace_token(&self, new: Secret) -> Result<()> {
        let bot = self.bot();
        let who = whoami(&self.api, Auth::Token(&new)).await?;
        if who.id != bot.id {
            return Err(ForgeError::Config(format!(
                "the new token belongs to `{}`, not the bot `{}`",
                who.login, bot.login
            )));
        }
        *self.token.write().expect("token lock poisoned") = Arc::new(new);
        Ok(())
    }

    /// Rotate the bot token: mint a new one (basic auth with the bot's
    /// password), verify it is the bot's, swap it in, then delete every
    /// earlier `vgi-bridge-*` token and the one it replaced. Needs
    /// [`TokenRotation::WithPassword`]. On any failure before the swap the
    /// new token is deleted and the old one stays in use.
    pub async fn rotate_token(&self) -> Result<TokenRotationReport> {
        let TokenRotation::WithPassword(password) = &self.rotation else {
            return Err(ForgeError::Unsupported {
                operation: "bot token rotation".into(),
                hint: format!(
                    "Forgejo mints tokens only under basic auth and this bridge holds no bot \
                     password: create a token for `{}` with scopes {} and pass it to \
                     `replace_token`",
                    self.config.bot_login,
                    BOT_TOKEN_SCOPES.join(", ")
                ),
            });
        };
        let bot = self.bot();
        let basic = Auth::Basic {
            user: &bot.login,
            password,
        };
        let mut suffix = [0u8; 4];
        aws_lc_rs::rand::fill(&mut suffix)
            .map_err(|_| ForgeError::Config("system RNG unavailable".into()))?;
        let name = format!("{TOKEN_NAME_PREFIX}{}-{}", unix_now(), hex::encode(suffix));
        let tokens_url = self.api.url(&["users", &bot.login, "tokens"]);
        let created: NewTokenJson = self
            .api
            .json_secret(
                Method::POST,
                tokens_url.clone(),
                basic,
                Some(&json!({ "name": name, "scopes": BOT_TOKEN_SCOPES })),
                "bot access token",
            )
            .await?;
        let new_id = created.id;
        let new = Secret::new(created.sha1.clone());
        drop(created);

        let delete = |id: u64| {
            let url = self
                .api
                .url(&["users", &bot.login, "tokens", &id.to_string()]);
            self.api
                .send(Method::DELETE, url, basic, None, "bot access token")
        };
        match whoami(&self.api, Auth::Token(&new)).await {
            Ok(who) if who.id == bot.id => {}
            other => {
                // Best effort: the error that matters is the one below.
                let _ = delete(new_id).await;
                return Err(match other {
                    Ok(who) => ForgeError::Protocol(format!(
                        "the new token authenticates as `{}`, not the bot",
                        who.login
                    )),
                    Err(e) => e,
                });
            }
        }
        let old = std::mem::replace(
            &mut *self.token.write().expect("token lock poisoned"),
            Arc::new(new),
        );
        let old_tail = last_eight(old.expose());
        drop(old);

        let listed: Vec<TokenInfoJson> = self
            .api
            .get_all(tokens_url, basic, "bot access tokens")
            .await?;
        let mut deleted = Vec::new();
        for t in listed {
            let ours = t.name.starts_with(TOKEN_NAME_PREFIX)
                || old_tail
                    .as_deref()
                    .is_some_and(|tail| t.token_last_eight.as_deref() == Some(tail));
            if t.id != new_id && ours {
                delete(t.id).await?;
                deleted.push(t.name);
            }
        }
        Ok(TokenRotationReport {
            new_token: name,
            deleted,
        })
    }

    // ── locating ─────────────────────────────────────────────────────────

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

    /// Check `repo` is exactly `host/owner/repo` on this forge and return its
    /// namespace, owner and name. A deeper path — which a deserialised
    /// resource can carry — is refused, not truncated.
    fn locate<'r>(&self, repo: &'r Resource) -> Result<(Namespace, &'r str, &'r str)> {
        if repo.host() != self.config.host {
            return Err(ForgeError::WrongResource {
                resource: repo.to_string(),
                expected: format!("a repository on `{}`", self.config.host),
            });
        }
        // A `Resource` from a bridge job was validated against the general
        // grammar (any depth). Splitting `codeberg.org/acme/evil/widgets`
        // into first and last segment would act on `acme/widgets`.
        repo.require_owner_repo()?;
        let name = repo.repo_name().ok_or_else(|| ForgeError::WrongResource {
            resource: repo.to_string(),
            expected: "a repository (`<host>/<owner>/<repo>`), not a namespace".into(),
        })?;
        Ok((self.namespace(&repo.namespace())?, repo.owner(), name))
    }

    fn automated(&self, ns: &Namespace) -> Result<()> {
        if ns.installation_id.is_none() {
            return Err(ForgeError::Unsupported {
                operation: "forge automation".into(),
                hint: format!(
                    "namespace `{}` is in manual mode (no bot binding); run the steps by hand \
                     with `vgi repo init`",
                    ns.resource
                ),
            });
        }
        Ok(())
    }

    /// Locate `repo` and return the bot token for it.
    fn repo_token<'r>(&self, repo: &'r Resource) -> Result<(Arc<Secret>, &'r str, &'r str)> {
        let (ns, owner, name) = self.locate(repo)?;
        self.automated(&ns)?;
        Ok((self.token(), owner, name))
    }

    // ── reads ────────────────────────────────────────────────────────────

    async fn get_repo(&self, token: &Secret, owner: &str, name: &str) -> Result<RepoJson> {
        self.api
            .json(
                Method::GET,
                self.api.url(&["repos", owner, name]),
                Auth::Token(token),
                None,
                &format!("{}/{owner}/{name}", self.config.host),
            )
            .await
    }

    fn repo_state(&self, r: &RepoJson) -> Result<RepoState> {
        let resource =
            Resource::parse_owner_repo(&format!("{}/{}", self.config.host, r.full_name))?;
        resource.require_owner_repo()?;
        let mut state = RepoState::new(resource, r.id);
        state.visibility = if r.private {
            Visibility::Private
        } else {
            Visibility::Public
        };
        state.archived = r.archived;
        state.default_branch = r.default_branch();
        Ok(state)
    }

    /// Direct collaborators with their repository permission.
    async fn collaborators(
        &self,
        token: &Secret,
        owner: &str,
        name: &str,
    ) -> Result<Vec<(ForgeAccount, Perm)>> {
        let users: Vec<UserJson> = self
            .api
            .get_all(
                self.api.url(&["repos", owner, name, "collaborators"]),
                Auth::Token(token),
                "collaborators",
            )
            .await?;
        let mut out = Vec::with_capacity(users.len());
        for u in users {
            check_login(&u.login)?;
            let p: PermissionJson = self
                .api
                .json(
                    Method::GET,
                    self.api.url(&[
                        "repos",
                        owner,
                        name,
                        "collaborators",
                        &u.login,
                        "permission",
                    ]),
                    Auth::Token(token),
                    None,
                    "collaborator permission",
                )
                .await?;
            if let Some(perm) = Perm::parse(&p.permission) {
                out.push((ForgeAccount::new(u.id, u.login), perm));
            }
        }
        Ok(out)
    }

    /// The branch protection rule named exactly `branch`. A glob rule that
    /// happens to match is not the managed rule and never counts as it.
    async fn protection_rule(
        &self,
        token: &Secret,
        owner: &str,
        name: &str,
        branch: &str,
    ) -> Result<Option<ProtectionJson>> {
        let rules: Vec<ProtectionJson> = self
            .api
            .json(
                Method::GET,
                self.api.url(&["repos", owner, name, "branch_protections"]),
                Auth::Token(token),
                None,
                "branch protections",
            )
            .await?;
        Ok(rules.into_iter().find(|r| r.name() == Some(branch)))
    }

    fn protection_state(&self, rule: Option<&ProtectionJson>, repo: &RepoJson) -> ProtectionState {
        let mut p = ProtectionState::default();
        p.merge_methods = Some(repo.merge_methods());
        p.ci_enabled = repo.has_actions;
        let Some(rule) = rule else {
            return p;
        };
        p.present = true;
        // A Forgejo rule has no disabled state, and it is only ever looked
        // up by the default branch's exact name.
        p.enforced = true;
        p.covers_default_branch = true;
        p.requires_pull_request = !rule.enable_push;
        if rule.enable_status_check {
            p.required_checks = rule.status_check_contexts.clone();
        }
        // Forgejo refuses force-pushes to, and deletion of, any protected
        // branch outright; there is no setting to weaken. (Gitea 1.23 added
        // `enable_force_push`; honour it where an instance reports it.)
        p.blocks_force_push = rule.enable_force_push != Some(true);
        p.blocks_deletion = true;
        p.protected_paths = patterns(&rule.protected_file_patterns);
        p.bypass_actors = rule.bypass_actors();
        p
    }

    fn allowed_merge_methods(&self) -> Vec<MergeMethod> {
        let probed = self.probed();
        if !probed.info.features.fast_forward_only
            && self.config.merge_fallback == MergeFallback::InstanceSigningKey
        {
            vec![MergeMethod::MergeCommit]
        } else {
            vec![MergeMethod::FastForward]
        }
    }

    /// Gaps in what the protection and settings must add up to on Forgejo,
    /// beyond the neutral ones: protected workflow paths, merge methods, CI.
    fn forgejo_gaps(&self, p: &ProtectionState) -> Vec<ProtectionGap> {
        let mut gaps = Vec::new();
        if p.present {
            let missing: Vec<String> = PROTECTED_PATHS
                .iter()
                .filter(|want| !p.protected_paths.iter().any(|have| have == *want))
                .map(|s| s.to_string())
                .collect();
            if !missing.is_empty() {
                gaps.push(ProtectionGap::UnprotectedPaths { paths: missing });
            }
        }
        let allowed = self.allowed_merge_methods();
        if let Some(methods) = &p.merge_methods {
            for m in methods {
                if !allowed.contains(m) {
                    gaps.push(ProtectionGap::MergeMethodAllowed { method: *m });
                }
            }
        }
        if p.ci_enabled == Some(false) {
            gaps.push(ProtectionGap::CiDisabled);
        }
        gaps
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
        let (token, owner, name) = self.repo_token(repo)?;
        let mut segments = vec!["repos", owner, name, "contents"];
        segments.extend(path.split('/'));
        let url = self.api.url(&segments);

        let existing: Option<Value> = self
            .api
            .get_opt(url.clone(), Auth::Token(&token), path)
            .await?;
        let sha = match existing {
            Some(Value::Array(_)) => {
                return Err(ForgeError::Rejected {
                    status: 409,
                    message: format!("`{path}` exists and is a directory, not a file"),
                });
            }
            Some(v) => {
                let c: ContentJson = serde_json::from_value(v)
                    .map_err(|e| ForgeError::Protocol(format!("{path}: {e}")))?;
                if c.kind != "file" {
                    return Err(ForgeError::Rejected {
                        status: 409,
                        message: format!("`{path}` exists and is a {}, not a file", c.kind),
                    });
                }
                if decode_content(&c)? == contents {
                    return Ok(StepOutcome::Unchanged);
                }
                Some(c.sha)
            }
            None => None,
        };

        let mut body = json!({ "message": message, "content": STANDARD.encode(contents) });
        let method = match &sha {
            Some(sha) => {
                body["sha"] = json!(sha);
                Method::PUT
            }
            None => Method::POST,
        };
        self.api
            .send(method, url, Auth::Token(&token), Some(&body), path)
            .await
            .map_err(|e| match e {
                ForgeError::Rejected { status, message } => ForgeError::Rejected {
                    status,
                    message: format!("{message}{PROTECTED_HINT}"),
                },
                ForgeError::Forbidden(message) => {
                    ForgeError::Forbidden(format!("{message}{PROTECTED_HINT}"))
                }
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
        if !self.probed().info.features.actions_variables {
            return Err(ForgeError::Unsupported {
                operation: "Actions variables".into(),
                hint: "this instance has no variables API; the plan writes the DIDs into the \
                       workflow instead — rebuild the plan"
                    .into(),
            });
        }
        let (token, owner, name) = self.repo_token(repo)?;
        let url = self
            .api
            .url(&["repos", owner, name, "actions", "variables", var]);
        match self
            .api
            .get_opt::<VariableJson>(url.clone(), Auth::Token(&token), var)
            .await?
        {
            Some(v) if v.data == value => Ok(StepOutcome::Unchanged),
            Some(_) => {
                let body = json!({ "name": var, "value": value });
                self.api
                    .send(Method::PUT, url, Auth::Token(&token), Some(&body), var)
                    .await?;
                Ok(StepOutcome::Updated)
            }
            None => {
                let body = json!({ "value": value });
                self.api
                    .send(Method::POST, url, Auth::Token(&token), Some(&body), var)
                    .await?;
                Ok(StepOutcome::Created)
            }
        }
    }

    async fn configure_repo(&self, repo: &Resource, s: &RepoSettings) -> Result<StepOutcome> {
        let (token, owner, name) = self.repo_token(repo)?;
        let r = self.get_repo(&token, owner, name).await?;
        let ff_wanted = s.merge_methods.contains(&MergeMethod::FastForward);
        let ff_available = self.probed().info.features.fast_forward_only
            && r.allow_fast_forward_only_merge.is_some();
        if ff_wanted && !ff_available {
            return Err(ForgeError::Unsupported {
                operation: "fast-forward-only merges".into(),
                hint: match self.config.merge_fallback {
                    MergeFallback::Fail => format!(
                        "`{}` ({}) cannot restrict merges to fast-forward only, and every web \
                         merge would land a commit the check never saw. Upgrade to Forgejo 7 \
                         or Gitea 1.22, or configure the signing-key merge fallback \
                         (the instance must sign merges)",
                        self.config.host,
                        self.probed().info.version
                    ),
                    _ => "the plan was built for fast-forward-only merges but the instance \
                          does not offer them; rebuild the plan"
                        .into(),
                },
            });
        }
        if satisfies_settings(&r, s) {
            return Ok(StepOutcome::Unchanged);
        }

        let has = |m| s.merge_methods.contains(&m);
        let mut body = json!({});
        if !s.merge_methods.is_empty() {
            // Forgejo applies merge settings only alongside
            // `has_pull_requests`.
            body = json!({
                "has_pull_requests": true,
                "allow_merge_commits": has(MergeMethod::MergeCommit),
                "allow_rebase": has(MergeMethod::Rebase),
                "allow_rebase_explicit": has(MergeMethod::RebaseMerge),
                "allow_squash_merge": has(MergeMethod::Squash),
                "default_merge_style": merge_style(s.merge_methods[0]),
            });
            if r.allow_fast_forward_only_merge.is_some() {
                body["allow_fast_forward_only_merge"] = json!(ff_wanted);
            }
        }
        if s.enable_ci {
            body["has_actions"] = json!(true);
        }
        let after: RepoJson = self
            .api
            .json(
                Method::PATCH,
                self.api.url(&["repos", owner, name]),
                Auth::Token(&token),
                Some(&body),
                repo.as_str(),
            )
            .await?;
        if !satisfies_settings(&after, s) {
            return Err(ForgeError::Rejected {
                status: 200,
                message: format!(
                    "{repo}: the instance accepted the settings but did not apply them all \
                     (are Actions or pull requests disabled instance-wide?)"
                ),
            });
        }
        Ok(StepOutcome::Updated)
    }

    async fn protect(&self, repo: &Resource, spec: &ProtectionSpec) -> Result<StepOutcome> {
        let (token, owner, name) = self.repo_token(repo)?;
        let r = self.get_repo(&token, owner, name).await?;
        let branch = r.default_branch().ok_or_else(|| ForgeError::Rejected {
            status: 409,
            message: format!("{repo} is empty: there is no default branch to protect yet"),
        })?;
        let existing = self.protection_rule(&token, owner, name, &branch).await?;
        if let Some(rule) = &existing
            && satisfies_protection(rule, spec)
        {
            return Ok(StepOutcome::Unchanged);
        }

        // Seed the merge allow-list with the repository's admins: once it is
        // enabled, even an admin cannot merge without a place on it (and an
        // admin can edit the rule anyway, so this grants nothing new).
        // Maintainers are added by `apply_roles`.
        let mut allow: Vec<String> = existing
            .as_ref()
            .filter(|r| r.enable_merge_whitelist)
            .map(|r| r.merge_whitelist_usernames.clone())
            .unwrap_or_default();
        for (account, perm) in self.collaborators(&token, owner, name).await? {
            if perm == Perm::Admin && !contains_login(&allow, &account.login) {
                allow.push(account.login);
            }
        }
        let mut contexts = existing
            .as_ref()
            .map(|r| r.status_check_contexts.clone())
            .unwrap_or_default();
        if !contexts.contains(&spec.required_check) {
            contexts.push(spec.required_check.clone());
        }
        let mut paths = existing
            .as_ref()
            .map(|r| patterns(&r.protected_file_patterns))
            .unwrap_or_default();
        for p in &spec.protected_paths {
            let p = p.to_ascii_lowercase();
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
        let mut body = json!({
            "enable_push": !spec.require_pull_request,
            "enable_push_whitelist": false,
            "push_whitelist_usernames": [],
            "push_whitelist_teams": [],
            "push_whitelist_deploy_keys": false,
            "enable_merge_whitelist": true,
            "merge_whitelist_usernames": allow,
            "merge_whitelist_teams": [],
            "enable_status_check": true,
            "status_check_contexts": contexts,
            "protected_file_patterns": paths.join(";"),
            "unprotected_file_patterns": "",
            "apply_to_admins": true,
        });
        let (method, url, outcome) = match &existing {
            Some(rule) => (
                Method::PATCH,
                self.api.url(&[
                    "repos",
                    owner,
                    name,
                    "branch_protections",
                    rule.name().unwrap_or(&branch),
                ]),
                StepOutcome::Updated,
            ),
            None => {
                body["rule_name"] = json!(branch);
                // Pre-1.22 instances know only `branch_name`.
                body["branch_name"] = json!(branch);
                (
                    Method::POST,
                    self.api.url(&["repos", owner, name, "branch_protections"]),
                    StepOutcome::Created,
                )
            }
        };
        let after: ProtectionJson = self
            .api
            .json(
                method,
                url,
                Auth::Token(&token),
                Some(&body),
                "branch protection",
            )
            .await?;
        if !satisfies_protection(&after, spec) {
            return Err(ForgeError::Rejected {
                status: 200,
                message: format!(
                    "{repo}: the instance accepted the branch protection but it does not read \
                     back as requested"
                ),
            });
        }
        Ok(outcome)
    }

    // ── roles ────────────────────────────────────────────────────────────

    /// Drop assignments Forgejo cannot express: the owner of a personal
    /// namespace owns every repository in it and cannot be a collaborator.
    fn expressible(&self, ns: &Namespace, desired: &[RoleAssignment]) -> Vec<RoleAssignment> {
        desired
            .iter()
            .filter(|a| !is_personal_owner(ns, a.account.id))
            .cloned()
            .collect()
    }

    async fn login_for(&self, token: &Secret, id: u64) -> Result<String> {
        // The numeric id is the binding; the login is looked up fresh so a
        // renamed-and-re-registered login never receives the role. Forgejo
        // has no `/user/{id}`; search by `uid` is its lookup by id.
        let mut url = self.api.url(&["users", "search"]);
        url.query_pairs_mut().append_pair("uid", &id.to_string());
        let found: SearchJson = self
            .api
            .json(Method::GET, url, Auth::Token(token), None, "user")
            .await?;
        let user =
            found
                .data
                .into_iter()
                .find(|u| u.id == id)
                .ok_or_else(|| ForgeError::NotFound {
                    what: format!("user {id}"),
                })?;
        check_login(&user.login)?;
        Ok(user.login)
    }

    async fn set_collaborator(
        &self,
        token: &Secret,
        owner: &str,
        name: &str,
        login: &str,
        perm: Option<Perm>,
    ) -> Result<()> {
        let url = self
            .api
            .url(&["repos", owner, name, "collaborators", login]);
        match perm {
            Some(p) => {
                let body = json!({ "permission": p.as_str() });
                self.api
                    .send(
                        Method::PUT,
                        url,
                        Auth::Token(token),
                        Some(&body),
                        "collaborator",
                    )
                    .await?;
            }
            None => {
                self.api
                    .send(
                        Method::DELETE,
                        url,
                        Auth::Token(token),
                        None,
                        "collaborator",
                    )
                    .await?;
            }
        }
        Ok(())
    }
}

/// The instance's version, the bot's identity, and (when needed) its
/// signing key.
async fn probe(api: &Api, config: &ForgejoConfig, token: &Secret) -> Result<Probed> {
    #[derive(Deserialize)]
    struct Version {
        version: String,
    }
    let v: Version = api
        .json(
            Method::GET,
            api.url(&["version"]),
            Auth::Token(token),
            None,
            "instance version",
        )
        .await?;
    let info = InstanceInfo::from_version(&v.version);
    let bot = whoami(api, Auth::Token(token)).await?;
    if !bot.login.eq_ignore_ascii_case(&config.bot_login) {
        return Err(ForgeError::Config(format!(
            "the bot token belongs to `{}`, not the configured bot `{}`",
            bot.login, config.bot_login
        )));
    }
    let signing_key = if !info.features.fast_forward_only
        && config.merge_fallback == MergeFallback::InstanceSigningKey
    {
        Some(fetch_signing_key(api, token).await?)
    } else {
        None
    };
    Ok(Probed {
        info,
        bot,
        signing_key,
    })
}

async fn whoami(api: &Api, auth: Auth<'_>) -> Result<ForgeAccount> {
    let u: UserJson = api
        .json(
            Method::GET,
            api.url(&["user"]),
            auth,
            None,
            "authenticated user",
        )
        .await?;
    Ok(ForgeAccount::new(u.id, u.login))
}

async fn fetch_signing_key(api: &Api, token: &Secret) -> Result<Vec<u8>> {
    let resp = api
        .send(
            Method::GET,
            api.url(&["signing-key.gpg"]),
            Auth::Token(token),
            None,
            "instance signing key",
        )
        .await?;
    resp.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| ForgeError::Unavailable(e.without_url().to_string()))
}

const PROTECTED_HINT: &str = " — if the default branch is already protected, this file can only \
                              change through a pull request, and the workflow and keyring not \
                              even then (they are protected paths, by design)";

#[async_trait]
impl Forge for ForgejoForge {
    fn kind(&self) -> ForgeKind {
        ForgeKind::Forgejo
    }

    fn host(&self) -> &str {
        &self.config.host
    }

    fn capabilities(&self, ns: &Namespace) -> Capabilities {
        let automated = ns.installation_id.is_some();
        let mut c = Capabilities::default();
        c.automation = automated;
        c.required_checks = RequiredCheckKind::BranchProtection;
        c.account_link = LinkMethod::AuthorizationCodePkce;
        // The org webhook announces only repository creation and deletion;
        // role, protection, rename and archive drift must be swept for.
        c.webhooks = false;
        // One bot token for everything: it cannot be narrowed per job.
        c.per_repo_tokens = false;
        c.role_levels = LADDER.to_vec();
        c.bot_can_create_repos = automated && ns.kind == NamespaceKind::Organization;
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
                 (see ForgejoForge::new_state)"
            )));
        }
        let verifier = self.oauth_keys.verifier(Purpose::Bind, &req.state);
        Ok(BindStep::Redirect {
            url: self
                .authorize_url(&self.config.bind_redirect_uri, &req.state, &verifier)
                .to_string(),
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
        if let Some(err) = cb.params.get("error") {
            return reject(format!(
                "the admin did not authorise the bridge: {err} {}",
                cb.params
                    .get("error_description")
                    .map(String::as_str)
                    .unwrap_or("")
            ));
        }
        let ns = &cb.expected_namespace;
        if ns.host() != self.config.host || !ns.is_namespace() {
            return reject(format!(
                "`{ns}` is not a namespace on `{}`",
                self.config.host
            ));
        }
        let owner = ns.owner();
        let code = match cb.params.get("code") {
            Some(c) if !c.is_empty() => c,
            _ => return reject("missing authorisation `code`".into()),
        };

        let verifier = self.oauth_keys.verifier(Purpose::Bind, state);
        let admin_token = self
            .exchange_code(
                code,
                &self.config.bind_redirect_uri,
                &verifier,
                ForgeError::BindRejected,
            )
            .await?;
        let result = self.bind_as_admin(ns, owner, &admin_token).await;
        // The one-time admin token is wiped here, whatever happened: the
        // bridge never keeps an admin credential.
        drop(admin_token);
        result
    }

    async fn begin_account_link(&self, member: &str) -> Result<LinkStep> {
        tracing::debug!(member, "starting Forgejo account link");
        let state = self.oauth_keys.issue_link_state(unix_now())?;
        let verifier = self.oauth_keys.verifier(Purpose::Link, &state);
        Ok(LinkStep::Redirect {
            url: self
                .authorize_url(&self.config.link_redirect_uri, &state, &verifier)
                .to_string(),
        })
    }

    async fn complete_account_link(&self, cb: LinkCallback) -> Result<ForgeAccount> {
        let LinkCallback::Redirect { params } = cb else {
            return Err(ForgeError::Unsupported {
                operation: "device-flow account link".into(),
                hint: "Forgejo has no device flow; members link through the browser \
                       (authorisation code + PKCE)"
                    .into(),
            });
        };
        let state = params.get("state").map(String::as_str).unwrap_or("");
        self.oauth_keys
            .check_link_state(state, unix_now(), self.config.link_state_ttl)?;
        if let Some(err) = params.get("error") {
            return Err(ForgeError::LinkFailed(format!(
                "the member did not authorise the bridge: {err}"
            )));
        }
        let code = match params.get("code") {
            Some(c) if !c.is_empty() => c,
            _ => {
                return Err(ForgeError::LinkFailed(
                    "missing authorisation `code`".into(),
                ));
            }
        };
        let verifier = self.oauth_keys.verifier(Purpose::Link, state);
        let token = self
            .exchange_code(
                code,
                &self.config.link_redirect_uri,
                &verifier,
                ForgeError::LinkFailed,
            )
            .await?;
        let account = whoami(&self.api, Auth::Bearer(&token)).await;
        // `token` is dropped (and wiped) here: the bridge needs the id, not
        // a standing credential for the member's account.
        drop(token);
        account
    }

    async fn inspect(&self, repo: &Resource) -> Result<RepoState> {
        let (token, owner, name) = self.repo_token(repo)?;
        let ns = self.namespace(&repo.namespace())?;
        let r = self.get_repo(&token, owner, name).await?;
        let mut state = self.repo_state(&r)?;
        let rule = match r.default_branch() {
            Some(branch) => self.protection_rule(&token, owner, name, &branch).await?,
            None => None,
        };
        let allow = rule
            .as_ref()
            .filter(|r| r.enable_merge_whitelist)
            .map(|r| r.merge_whitelist_usernames.clone())
            .unwrap_or_default();
        for (account, perm) in self.collaborators(&token, owner, name).await? {
            if is_personal_owner(&ns, account.id) {
                continue;
            }
            let role = perm.observed(contains_login(&allow, &account.login));
            state.collaborators.push(Collaborator::new(account, role));
        }
        state.protection = self.protection_state(rule.as_ref(), &r);
        Ok(state)
    }

    async fn create_repo(&self, spec: &RepoSpec) -> Result<RepoState> {
        let (ns, owner, name) = self.locate(&spec.resource)?;
        if !self.capabilities(&ns).bot_can_create_repos {
            return Err(ForgeError::Unsupported {
                operation: "repository creation".into(),
                hint: format!(
                    "the bridge cannot create repositories in `{}`; the account holder creates \
                     `{owner}/{name}`, adds `{}` as an admin collaborator, runs `vgi repo init`, \
                     and the repo is adopted",
                    ns.resource, self.config.bot_login
                ),
            });
        }
        let private = match spec.visibility {
            Visibility::Public => false,
            Visibility::Private => true,
            _ => {
                return Err(ForgeError::Unsupported {
                    operation: "internal visibility".into(),
                    hint: "Forgejo repositories are public or private".into(),
                });
            }
        };
        let token = self.token();
        if let Some(existing) = self
            .api
            .get_opt::<RepoJson>(
                self.api.url(&["repos", owner, name]),
                Auth::Token(&token),
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
            "private": private,
            // A first commit gives the repo a default branch for the
            // bootstrap to commit to and the protection to cover.
            "auto_init": true,
            "readme": "Default",
            "default_branch": "main",
        });
        if let Some(d) = &spec.description {
            body["description"] = json!(d);
        }
        let created: RepoJson = self
            .api
            .json(
                Method::POST,
                self.api.url(&["orgs", owner, "repos"]),
                Auth::Token(&token),
                Some(&body),
                spec.resource.as_str(),
            )
            .await
            .map_err(|e| match e {
                ForgeError::Rejected { status: 409, .. } => ForgeError::AlreadyExists {
                    resource: spec.resource.to_string(),
                    forge_id: None,
                },
                e => e,
            })?;
        self.repo_state(&created)
    }

    async fn archive_repo(&self, repo: &Resource) -> Result<()> {
        let (token, owner, name) = self.repo_token(repo)?;
        let r = self.get_repo(&token, owner, name).await?;
        if r.archived {
            return Ok(());
        }
        self.api
            .send(
                Method::PATCH,
                self.api.url(&["repos", owner, name]),
                Auth::Token(&token),
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
        self.automated(&ns)?;
        let desired = self.expressible(&ns, desired);
        let mut wanted: BTreeMap<u64, (ForgeAccount, ForgeRole)> = BTreeMap::new();
        for a in &desired {
            // Round down onto the ladder again: never trust the caller to
            // have done it.
            let role = collapse_to_ladder(a.role, &LADDER);
            if let Some((_, prev)) = wanted.insert(a.account.id, (a.account.clone(), role))
                && prev != role
            {
                return Err(ForgeError::Config(format!(
                    "account {} is assigned two different roles",
                    a.account.id
                )));
            }
        }

        let token = self.token();
        let r = self.get_repo(&token, owner, name).await?;
        let rule = match r.default_branch() {
            Some(branch) => self.protection_rule(&token, owner, name, &branch).await?,
            None => None,
        };
        let allow: Vec<String> = rule
            .as_ref()
            .filter(|r| r.enable_merge_whitelist)
            .map(|r| r.merge_whitelist_usernames.clone())
            .unwrap_or_default();
        let mut current: BTreeMap<u64, Have> = BTreeMap::new();
        for (account, perm) in self.collaborators(&token, owner, name).await? {
            if is_personal_owner(&ns, account.id) {
                // Never reported as unlisted, never removed.
                continue;
            }
            let listed = contains_login(&allow, &account.login);
            current.insert(
                account.id,
                Have {
                    account,
                    perm,
                    listed,
                },
            );
        }

        let fatal = |e: &ForgeError| {
            matches!(
                e,
                ForgeError::Unauthorized(_) | ForgeError::RateLimited { .. }
            )
        };
        let mut report = ApplyReport::default();
        // Allow-list edits, applied in one write at the end: logins to add
        // (fresh), ids whose entries go, and the changes that depend on it.
        let mut list_add: Vec<String> = Vec::new();
        let mut list_drop: BTreeSet<u64> = BTreeSet::new();
        let mut list_dependent: Vec<usize> = Vec::new();
        let mut keep_listed: BTreeSet<u64> = BTreeSet::new();

        for (id, (account, role)) in &wanted {
            let have = current.get(id);
            let need_perm = Perm::for_role(*role);
            let need_listed = rule.is_some() && *role >= ForgeRole::Maintain;
            let have_perm = have.map(|h| h.perm);
            let have_listed = have.is_some_and(|h| h.listed);
            // `Maintain` is write *plus* the allow-list; before the bootstrap
            // there is no rule to put anyone on.
            let unexpressible = *role == ForgeRole::Maintain && rule.is_none();
            if need_listed {
                keep_listed.insert(*id);
            }
            if have_perm == need_perm && have_listed == need_listed && !unexpressible {
                if *role != ForgeRole::None {
                    report.unchanged.push(account.clone());
                }
                continue;
            }
            let from = have.map_or(ForgeRole::None, |h| h.perm.observed(h.listed));
            let mut outcome = RoleOutcome::Applied;
            let mut fresh_login = None;
            if have_perm != need_perm {
                let result = match need_perm {
                    Some(p) => match self.login_for(&token, *id).await {
                        Ok(login) => {
                            let r = self
                                .set_collaborator(&token, owner, name, &login, Some(p))
                                .await;
                            fresh_login = Some(login);
                            r
                        }
                        Err(e) => Err(e),
                    },
                    None => {
                        let login = &have.expect("have_perm differs from None").account.login;
                        self.set_collaborator(&token, owner, name, login, None)
                            .await
                    }
                };
                if let Err(e) = result {
                    if fatal(&e) {
                        return Err(e);
                    }
                    report.changes.push(RoleChange::new(
                        account.clone(),
                        from,
                        *role,
                        RoleOutcome::Failed(e.to_string()),
                    ));
                    continue;
                }
            }
            if need_listed && !have_listed {
                let login = match fresh_login {
                    Some(l) => Ok(l),
                    None => self.login_for(&token, *id).await,
                };
                match login {
                    Ok(l) => {
                        list_add.push(l);
                        list_dependent.push(report.changes.len());
                    }
                    Err(e) if fatal(&e) => return Err(e),
                    Err(e) => outcome = RoleOutcome::Failed(e.to_string()),
                }
            } else if !need_listed && have_listed {
                list_drop.insert(*id);
                list_dependent.push(report.changes.len());
            }
            if unexpressible {
                outcome = RoleOutcome::Failed(
                    "granted `write`; `maintain` also needs a place on the default branch's merge \
                     allow-list, which exists once the repository is bootstrapped"
                        .into(),
                );
            }
            report
                .changes
                .push(RoleChange::new(account.clone(), from, *role, outcome));
        }

        for (id, have) in &current {
            if wanted.contains_key(id) {
                continue;
            }
            let observed = have.perm.observed(have.listed);
            match unlisted {
                Unlisted::Remove => {
                    let outcome = match self
                        .set_collaborator(&token, owner, name, &have.account.login, None)
                        .await
                    {
                        Ok(()) => RoleOutcome::Applied,
                        Err(e) if fatal(&e) => return Err(e),
                        Err(e) => RoleOutcome::Failed(e.to_string()),
                    };
                    if have.listed {
                        list_drop.insert(*id);
                    }
                    report.changes.push(RoleChange::new(
                        have.account.clone(),
                        observed,
                        ForgeRole::None,
                        outcome,
                    ));
                }
                _ => {
                    if have.listed {
                        keep_listed.insert(*id);
                    }
                    report
                        .kept_unlisted
                        .push(Collaborator::new(have.account.clone(), observed));
                }
            }
        }

        if let Some(rule) = &rule {
            let id_of = |login: &str| {
                current
                    .values()
                    .find(|h| h.account.login.eq_ignore_ascii_case(login))
                    .map(|h| h.account.id)
            };
            let mut next: Vec<String> = allow
                .iter()
                .filter(|login| match id_of(login) {
                    Some(id) => !list_drop.contains(&id) && keep_listed.contains(&id),
                    // Someone on the list who is not a collaborator: kept in
                    // report mode, removed in enforce mode.
                    None => unlisted != Unlisted::Remove,
                })
                .cloned()
                .collect();
            for login in list_add {
                if !contains_login(&next, &login) {
                    next.push(login);
                }
            }
            let same = next.len() == allow.len()
                && next.iter().all(|l| contains_login(&allow, l))
                && rule.enable_merge_whitelist;
            if !same {
                let branch = rule.name().unwrap_or_default().to_string();
                let body = json!({
                    "enable_merge_whitelist": true,
                    "merge_whitelist_usernames": next,
                });
                let result = self
                    .api
                    .send(
                        Method::PATCH,
                        self.api
                            .url(&["repos", owner, name, "branch_protections", &branch]),
                        Auth::Token(&token),
                        Some(&body),
                        "merge allow-list",
                    )
                    .await;
                if let Err(e) = result {
                    if fatal(&e) {
                        return Err(e);
                    }
                    for i in list_dependent {
                        if let Some(c) = report.changes.get_mut(i)
                            && c.outcome == RoleOutcome::Applied
                        {
                            c.outcome = RoleOutcome::Failed(format!("merge allow-list: {e}"));
                        }
                    }
                }
            }
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
        let probed = self.probed();
        let key: Option<Vec<u8>> = if probed.info.features.fast_forward_only {
            None
        } else {
            match self.config.merge_fallback {
                // The step will fail, naming the upgrade; the plan still
                // asks for fast-forward only.
                MergeFallback::Fail => None,
                _ => Some(
                    cfg.platform_keyring
                        .clone()
                        .or(probed.signing_key.clone())
                        .ok_or_else(|| {
                            ForgeError::Config(
                                "the signing-key merge fallback needs the instance's signing \
                                 key; refresh the adapter or supply it as the platform keyring"
                                    .into(),
                            )
                        })?,
                ),
            }
        };
        let opts = PlanOptions {
            checkout_action: &self.config.checkout_action,
            actions_base: &self.config.actions_base,
            runs_on: &self.config.runs_on,
            status_context: self.config.status_context(&cfg.required_check),
            inline_variables: !probed.info.features.actions_variables,
            merges: match &key {
                Some(k) => MergePlan::SigningKey(k),
                None => MergePlan::FastForwardOnly,
            },
        };
        forgejo_plan(repo, cfg, &opts)
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
            StepAction::ConfigureRepo(settings) => self.configure_repo(repo, settings).await,
            other => Err(ForgeError::Unsupported {
                operation: format!("bootstrap step {other:?}"),
                hint: "this Forgejo adapter does not know that step".into(),
            }),
        }
    }

    fn parse_event(&self, headers: &HeaderMap, body: &[u8]) -> Result<Option<ForgeEvent>> {
        webhook::parse(&self.webhook_secret, &self.config.host, headers, body)
    }

    /// The neutral comparison, with the check named as Forgejo reports it
    /// (`<workflow> / <job> (pull_request)`), plus what makes the check mean
    /// something on Forgejo: the protected workflow paths, fast-forward-only
    /// merges, and Actions being on.
    fn diff(&self, observed: &RepoState, desired: &Projection) -> Vec<Drift> {
        let mut want = desired.clone();
        want.required_check = desired
            .required_check
            .as_deref()
            .map(|c| self.config.status_context(c));
        let mut drift = default_diff(observed, &want);
        if desired.required_check.is_none()
            || drift.iter().any(|d| matches!(d, Drift::Replaced { .. }))
        {
            return drift;
        }
        let extra = self.forgejo_gaps(&observed.protection);
        if extra.is_empty() {
            return drift;
        }
        match drift
            .iter_mut()
            .find(|d| matches!(d, Drift::ProtectionWeakened { .. }))
        {
            Some(Drift::ProtectionWeakened { gaps }) => {
                if !gaps.contains(&ProtectionGap::Missing) {
                    gaps.extend(extra);
                } else {
                    gaps.extend(
                        extra
                            .into_iter()
                            .filter(|g| !matches!(g, ProtectionGap::UnprotectedPaths { .. })),
                    );
                }
            }
            _ => drift.push(Drift::ProtectionWeakened { gaps: extra }),
        }
        drift
    }
}

impl ForgejoForge {
    fn authorize_url(&self, redirect: &url::Url, state: &str, verifier: &Secret) -> url::Url {
        let mut url = self.api.web_url(&["login", "oauth", "authorize"]);
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("client_id", &self.config.oauth_client_id)
                .append_pair("redirect_uri", redirect.as_str())
                .append_pair("response_type", "code")
                .append_pair("state", state)
                .append_pair("code_challenge", &OAuthKeys::challenge(verifier))
                .append_pair("code_challenge_method", "S256");
            if let Some(scope) = &self.config.oauth_scope {
                q.append_pair("scope", scope);
            }
        }
        url
    }

    async fn exchange_code(
        &self,
        code: &str,
        redirect: &url::Url,
        verifier: &Secret,
        fail: fn(String) -> ForgeError,
    ) -> Result<Secret> {
        let url = self.api.web_url(&["login", "oauth", "access_token"]);
        let t: TokenJson = self
            .api
            .oauth_token(
                url,
                &[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("redirect_uri", redirect.as_str()),
                    ("client_id", &self.config.oauth_client_id),
                    ("client_secret", self.oauth_secret.expose()),
                    ("code_verifier", verifier.expose()),
                ],
            )
            .await?;
        t.into_token(fail)
    }

    /// The bind, with the admin's one-time token: confirm ownership, set up
    /// the team and the bot, and the webhook.
    async fn bind_as_admin(
        &self,
        ns: &Resource,
        owner: &str,
        admin_token: &Secret,
    ) -> Result<NamespaceBinding> {
        let reject = |m: String| Err(ForgeError::BindRejected(m));
        let admin_auth = Auth::Bearer(admin_token);
        let admin = whoami(&self.api, admin_auth).await?;
        let bot = self.bot();
        if admin.id == bot.id {
            return reject(
                "the bot cannot bind a namespace: an owner must sign in as themselves".into(),
            );
        }
        check_login(owner)?;
        let org: Option<OrgJson> = self
            .api
            .get_opt(self.api.url(&["orgs", owner]), admin_auth, "organisation")
            .await?;
        let Some(org) = org else {
            // A personal namespace: only its holder can bind it.
            if !admin.login.eq_ignore_ascii_case(owner) {
                return reject(format!(
                    "`{owner}` is not an organisation, and `{}` signed in — only the account \
                     holder can bind a personal namespace",
                    admin.login
                ));
            }
            let namespace = Namespace::new(ns.clone(), NamespaceKind::User)
                .with_owner_id(admin.id)
                .with_installation(bot.id);
            return Ok(NamespaceBinding::new(namespace, Vec::new()));
        };

        // Owning the org is the binding proof.
        let perms: OrgPermsJson = self
            .api
            .json(
                Method::GET,
                self.api
                    .url(&["users", &admin.login, "orgs", owner, "permissions"]),
                admin_auth,
                None,
                "organisation permissions",
            )
            .await?;
        if !perms.is_owner {
            return reject(format!(
                "`{}` is not an owner of `{owner}`; an owner must bind the namespace",
                admin.login
            ));
        }

        let team = self.ensure_team(admin_token, owner).await?;
        let member = self
            .api
            .url(&["teams", &team.id.to_string(), "members", &bot.login]);
        if !self
            .api
            .exists(member.clone(), admin_auth, "team member")
            .await?
        {
            self.api
                .send(Method::PUT, member, admin_auth, None, "team member")
                .await?;
        }

        let mut missing = Vec::new();
        // Confirm from the bot's side that the team gives it what it needs.
        let bot_perms: OrgPermsJson = self
            .api
            .json(
                Method::GET,
                self.api
                    .url(&["users", &bot.login, "orgs", owner, "permissions"]),
                Auth::Token(&self.token()),
                None,
                "bot organisation permissions",
            )
            .await?;
        if !bot_perms.can_create_repository {
            missing.push(format!(
                "create repositories in `{owner}` (team `{}`)",
                self.config.team_name
            ));
        }
        if let Some(hook_url) = &self.config.webhook_url {
            match self.ensure_hook(admin_token, owner, hook_url).await {
                Ok(()) => {}
                Err(ForgeError::Forbidden(m) | ForgeError::Rejected { message: m, .. }) => {
                    missing.push(format!("org webhook: {m}"));
                }
                Err(ForgeError::NotFound { .. }) => {
                    missing.push("org webhook: webhooks are disabled on the instance".into());
                }
                Err(e) => return Err(e),
            }
        }
        let namespace = Namespace::new(ns.clone(), NamespaceKind::Organization)
            .with_owner_id(org.id)
            .with_installation(team.id);
        Ok(NamespaceBinding::new(namespace, missing))
    }

    async fn ensure_team(&self, admin_token: &Secret, org: &str) -> Result<TeamJson> {
        let auth = Auth::Bearer(admin_token);
        let teams: Vec<TeamJson> = self
            .api
            .get_all(self.api.url(&["orgs", org, "teams"]), auth, "teams")
            .await?;
        let body = json!({
            "name": self.config.team_name,
            "description": "VGI bridge bot: creates repositories and enforces the VTC's roles \
                            and commit-trust protection. Managed by the bridge.",
            "permission": "admin",
            "can_create_org_repo": true,
            "includes_all_repositories": true,
            "units": TEAM_UNITS,
        });
        match teams
            .into_iter()
            .find(|t| t.name.eq_ignore_ascii_case(&self.config.team_name))
        {
            Some(t)
                if t.permission == "admin"
                    && t.can_create_org_repo
                    && t.includes_all_repositories =>
            {
                Ok(t)
            }
            Some(t) => {
                self.api
                    .json(
                        Method::PATCH,
                        self.api.url(&["teams", &t.id.to_string()]),
                        auth,
                        Some(&body),
                        "team",
                    )
                    .await
            }
            None => {
                self.api
                    .json(
                        Method::POST,
                        self.api.url(&["orgs", org, "teams"]),
                        auth,
                        Some(&body),
                        "team",
                    )
                    .await
            }
        }
    }

    async fn ensure_hook(&self, admin_token: &Secret, org: &str, url: &url::Url) -> Result<()> {
        let auth = Auth::Bearer(admin_token);
        let hooks: Vec<HookJson> = self
            .api
            .get_all(self.api.url(&["orgs", org, "hooks"]), auth, "org webhooks")
            .await?;
        let config = json!({
            "url": url.as_str(),
            "content_type": "json",
            "secret": self.webhook_secret.expose(),
        });
        let existing = hooks.into_iter().find(|h| {
            h.config.get("url").map(String::as_str) == Some(url.as_str())
                || h.url.as_deref() == Some(url.as_str())
        });
        match existing {
            // The secret cannot be read back, so an existing hook is always
            // rewritten: that is what makes a re-bind repair a changed one.
            Some(h) => {
                let body = json!({ "config": config, "events": HOOK_EVENTS, "active": true });
                self.api
                    .send(
                        Method::PATCH,
                        self.api.url(&["orgs", org, "hooks", &h.id.to_string()]),
                        auth,
                        Some(&body),
                        "org webhook",
                    )
                    .await?;
            }
            None => {
                let kind = if self.probed().info.features.forgejo_webhooks {
                    "forgejo"
                } else {
                    "gitea"
                };
                let body = json!({
                    "type": kind,
                    "config": config,
                    "events": HOOK_EVENTS,
                    "active": true,
                });
                self.api
                    .send(
                        Method::POST,
                        self.api.url(&["orgs", org, "hooks"]),
                        auth,
                        Some(&body),
                        "org webhook",
                    )
                    .await?;
            }
        }
        Ok(())
    }
}

impl ForgeHooks for ForgejoForge {
    /// The holder of a personal namespace owns every repository in it and
    /// cannot be added as a collaborator, so they are dropped from the
    /// desired set before it reaches Forgejo (and before the core reports
    /// their "missing" role as drift).
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

// ── helpers ──────────────────────────────────────────────────────────────

/// A collaborator's repository permission, as Forgejo reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Perm {
    Read,
    Write,
    Admin,
}

impl Perm {
    fn parse(s: &str) -> Option<Perm> {
        match s {
            "read" => Some(Perm::Read),
            "write" => Some(Perm::Write),
            "admin" | "owner" => Some(Perm::Admin),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Perm::Read => "read",
            Perm::Write => "write",
            Perm::Admin => "admin",
        }
    }

    /// The collaborator permission a role needs; `None` for no role.
    fn for_role(role: ForgeRole) -> Option<Perm> {
        match role {
            ForgeRole::Admin => Some(Perm::Admin),
            ForgeRole::Maintain | ForgeRole::Write => Some(Perm::Write),
            ForgeRole::None => None,
            _ => Some(Perm::Read),
        }
    }

    /// The role this permission (and allow-list place) amounts to.
    fn observed(self, listed: bool) -> ForgeRole {
        match self {
            Perm::Admin => ForgeRole::Admin,
            Perm::Write if listed => ForgeRole::Maintain,
            Perm::Write => ForgeRole::Write,
            Perm::Read => ForgeRole::Read,
        }
    }
}

/// Someone's standing on a repository before a change.
struct Have {
    account: ForgeAccount,
    perm: Perm,
    listed: bool,
}

/// The holder of a personal namespace: owns every repository in it, is
/// never a collaborator.
fn is_personal_owner(ns: &Namespace, id: u64) -> bool {
    ns.kind == NamespaceKind::User && ns.owner_id == Some(id)
}

fn contains_login(list: &[String], login: &str) -> bool {
    list.iter().any(|l| l.eq_ignore_ascii_case(login))
}

/// Forgejo's `;`-separated pattern list, as it compiles it: trimmed and
/// lowercased, empties dropped.
fn patterns(s: &str) -> Vec<String> {
    s.split(';')
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| !p.is_empty())
        .collect()
}

fn last_eight(token: &str) -> Option<String> {
    (token.len() >= 8).then(|| token[token.len() - 8..].to_string())
}

fn merge_style(m: MergeMethod) -> &'static str {
    match m {
        MergeMethod::FastForward => "fast-forward-only",
        MergeMethod::Rebase => "rebase",
        MergeMethod::RebaseMerge => "rebase-merge",
        MergeMethod::Squash => "squash",
        _ => "merge",
    }
}

fn satisfies_settings(r: &RepoJson, s: &RepoSettings) -> bool {
    if s.enable_ci && r.has_actions != Some(true) {
        return false;
    }
    if s.merge_methods.is_empty() {
        return true;
    }
    r.has_pull_requests != Some(false)
        && r.merge_methods() == {
            let mut want = s.merge_methods.clone();
            want.sort();
            want.dedup();
            want
        }
        && r.default_merge_style.as_deref() == Some(merge_style(s.merge_methods[0]))
}

/// Whether an existing rule already is what the protection step writes.
fn satisfies_protection(rule: &ProtectionJson, spec: &ProtectionSpec) -> bool {
    let paths = patterns(&rule.protected_file_patterns);
    (!spec.require_pull_request || !rule.enable_push)
        && rule.enable_status_check
        && rule.status_check_contexts.contains(&spec.required_check)
        && rule.enable_merge_whitelist
        && rule.merge_whitelist_teams.is_empty()
        && patterns(&rule.unprotected_file_patterns).is_empty()
        // `None`: an instance without the setting, where it cannot be had.
        && rule.apply_to_admins != Some(false)
        && rule.enable_force_push != Some(true)
        && spec
            .protected_paths
            .iter()
            .all(|p| paths.contains(&p.to_ascii_lowercase()))
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
        // Forgejo returns no inline content for a blob over its API size
        // limit. Nothing the bootstrap writes is that large, so a file that
        // is was put there by someone else: refuse rather than overwrite
        // what we cannot see.
        None => Err(ForgeError::Rejected {
            status: 409,
            message: "the existing file is too large for the instance to return inline; it was \
                      not written by the bootstrap — remove or rename it"
                .into(),
        }),
        other => Err(ForgeError::Protocol(format!(
            "file content in unknown encoding {other:?}"
        ))),
    }
}

/// `null` (which Forgejo sends for an empty list) as the default.
fn nullable<'de, D, T>(d: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

// ── wire shapes ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RepoJson {
    id: u64,
    full_name: String,
    #[serde(default)]
    private: bool,
    #[serde(default)]
    archived: bool,
    #[serde(default)]
    empty: bool,
    #[serde(default)]
    default_branch: Option<String>,
    #[serde(default)]
    has_pull_requests: Option<bool>,
    #[serde(default)]
    has_actions: Option<bool>,
    #[serde(default)]
    allow_fast_forward_only_merge: Option<bool>,
    #[serde(default)]
    allow_merge_commits: Option<bool>,
    #[serde(default)]
    allow_rebase: Option<bool>,
    #[serde(default)]
    allow_rebase_explicit: Option<bool>,
    #[serde(default)]
    allow_squash_merge: Option<bool>,
    #[serde(default)]
    default_merge_style: Option<String>,
}

impl RepoJson {
    fn default_branch(&self) -> Option<String> {
        self.default_branch
            .clone()
            .filter(|b| !b.is_empty() && !self.empty)
    }

    /// Allowed merge methods, sorted. None at all when pull requests are off.
    fn merge_methods(&self) -> Vec<MergeMethod> {
        if self.has_pull_requests == Some(false) {
            return Vec::new();
        }
        let mut m: Vec<MergeMethod> = [
            (self.allow_fast_forward_only_merge, MergeMethod::FastForward),
            (self.allow_merge_commits, MergeMethod::MergeCommit),
            (self.allow_rebase, MergeMethod::Rebase),
            (self.allow_rebase_explicit, MergeMethod::RebaseMerge),
            (self.allow_squash_merge, MergeMethod::Squash),
        ]
        .into_iter()
        .filter(|(on, _)| *on == Some(true))
        .map(|(_, m)| m)
        .collect();
        m.sort();
        m
    }
}

#[derive(Deserialize)]
struct UserJson {
    id: u64,
    login: String,
}

#[derive(Deserialize)]
struct SearchJson {
    #[serde(default, deserialize_with = "nullable")]
    data: Vec<UserJson>,
}

#[derive(Deserialize)]
struct PermissionJson {
    permission: String,
}

#[derive(Deserialize)]
struct OrgJson {
    id: u64,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct OrgPermsJson {
    is_owner: bool,
    can_create_repository: bool,
}

#[derive(Deserialize)]
struct TeamJson {
    id: u64,
    name: String,
    #[serde(default)]
    permission: String,
    #[serde(default)]
    can_create_org_repo: bool,
    #[serde(default)]
    includes_all_repositories: bool,
}

#[derive(Deserialize)]
struct HookJson {
    id: u64,
    #[serde(default)]
    url: Option<String>,
    #[serde(default, deserialize_with = "nullable")]
    config: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct VariableJson {
    #[serde(default)]
    data: String,
}

#[derive(Deserialize)]
struct ContentJson {
    #[serde(default)]
    sha: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    encoding: Option<String>,
}

#[derive(Deserialize)]
struct NewTokenJson {
    id: u64,
    sha1: String,
}

impl Drop for NewTokenJson {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.sha1.zeroize();
    }
}

#[derive(Deserialize)]
struct TokenInfoJson {
    id: u64,
    name: String,
    #[serde(default)]
    token_last_eight: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ProtectionJson {
    rule_name: Option<String>,
    branch_name: Option<String>,
    enable_push: bool,
    enable_push_whitelist: bool,
    #[serde(deserialize_with = "nullable")]
    push_whitelist_usernames: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    push_whitelist_teams: Vec<String>,
    push_whitelist_deploy_keys: bool,
    enable_merge_whitelist: bool,
    #[serde(deserialize_with = "nullable")]
    merge_whitelist_usernames: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    merge_whitelist_teams: Vec<String>,
    enable_status_check: bool,
    #[serde(deserialize_with = "nullable")]
    status_check_contexts: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    protected_file_patterns: String,
    #[serde(deserialize_with = "nullable")]
    unprotected_file_patterns: String,
    /// Absent on instances without the setting — where repository admins
    /// can always merge past the check.
    apply_to_admins: Option<bool>,
    /// Gitea 1.23+; Forgejo refuses force-pushes to protected branches
    /// without a setting.
    enable_force_push: Option<bool>,
}

impl ProtectionJson {
    fn name(&self) -> Option<&str> {
        self.rule_name
            .as_deref()
            .filter(|n| !n.is_empty())
            .or(self.branch_name.as_deref())
    }

    /// Everyone who can land a change on the branch without the check.
    fn bypass_actors(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.apply_to_admins != Some(true) {
            out.push("repository admins (the rule does not apply to admins)".into());
        }
        if self.enable_push {
            if !self.enable_push_whitelist {
                out.push("push: everyone with write access".into());
            } else {
                out.extend(
                    self.push_whitelist_usernames
                        .iter()
                        .map(|u| format!("push:{u}")),
                );
                out.extend(
                    self.push_whitelist_teams
                        .iter()
                        .map(|t| format!("push-team:{t}")),
                );
                if self.push_whitelist_deploy_keys {
                    out.push("push:deploy-keys".into());
                }
            }
        }
        let unprotected = patterns(&self.unprotected_file_patterns);
        if !unprotected.is_empty() {
            // Pushes touching only these files skip the protection.
            out.push(format!("unprotected-files:{}", unprotected.join(";")));
        }
        // A team on the merge allow-list lets people the VTC never made
        // maintainers merge.
        out.extend(
            self.merge_whitelist_teams
                .iter()
                .map(|t| format!("merge-team:{t}")),
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_map_both_ways() {
        for role in LADDER {
            let perm = Perm::for_role(role).unwrap();
            assert_eq!(perm.observed(role >= ForgeRole::Maintain), role);
            assert_eq!(Perm::parse(perm.as_str()), Some(perm));
        }
        assert_eq!(Perm::for_role(ForgeRole::None), None);
        assert_eq!(Perm::parse("owner"), Some(Perm::Admin));
        assert_eq!(Perm::parse("none"), None);
        assert_eq!(
            collapse_to_ladder(ForgeRole::Triage, &LADDER),
            ForgeRole::Read
        );
    }

    #[test]
    fn patterns_are_read_as_forgejo_compiles_them() {
        assert_eq!(
            patterns(" .Forgejo/workflows/** ;;x.asc; "),
            [".forgejo/workflows/**", "x.asc"]
        );
        assert!(patterns("").is_empty());
    }

    #[test]
    fn null_lists_deserialise_as_empty() {
        let p: ProtectionJson = serde_json::from_value(json!({
            "rule_name": "main",
            "merge_whitelist_usernames": null,
            "status_check_contexts": null,
            "protected_file_patterns": null,
        }))
        .unwrap();
        assert!(p.merge_whitelist_usernames.is_empty() && p.status_check_contexts.is_empty());
        assert_eq!(p.apply_to_admins, None);
        assert_eq!(
            p.bypass_actors(),
            ["repository admins (the rule does not apply to admins)"]
        );
    }
}
