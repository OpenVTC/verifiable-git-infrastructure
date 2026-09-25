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
    AccessSource, ApplyReport, BindCallback, BindRequest, BindStep, BootstrapStep, Capabilities,
    Collaborator, Drift, Forge, ForgeAccount, ForgeError, ForgeEvent, ForgeHooks, ForgeKind,
    ForgeRole, HookDecision, IndirectAccess, LinkCallback, LinkMethod, LinkStep, MergeMethod,
    Namespace, NamespaceBinding, NamespaceKind, Projection, ProtectionGap, ProtectionSpec,
    ProtectionState, RepoSettings, RepoSpec, RepoState, RequiredCheckKind, Resource, Result,
    RoleAssignment, RoleChange, RoleOutcome, StepAction, StepOutcome, Unlisted, VgiConfig,
    Visibility, async_trait, collapse_to_ladder, default_diff, validate_repo_path,
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

/// Name prefix of the tokens [`ForgejoForge::mint_token`] mints. Only for
/// recognising them in the bot's token list; nothing is deleted by prefix.
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

/// What [`ForgejoForge::refresh_managed_files`] did, for the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RefreshReport {
    /// The step's outcome: `Updated` if any file was written.
    pub outcome: StepOutcome,
    /// Each file and what happened to it.
    pub files: Vec<(String, StepOutcome)>,
    /// Whether the protection was opened for the bridge at all.
    pub opened: bool,
    /// One line for the audit log: what was opened, written and restored.
    pub detail: String,
}

/// One of the bot's access tokens, by the id and name Forgejo lists it
/// under. Holds no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TokenRef {
    /// Forgejo's id for the token.
    pub id: u64,
    /// Its name.
    pub name: String,
}

/// What [`ForgejoForge::mint_token`] minted, now in use.
#[derive(Debug)]
#[non_exhaustive]
pub struct MintedToken {
    /// The new token.
    pub token: TokenRef,
    /// Its secret, for the caller to persist (sealed) before retiring the
    /// old one. Never printed.
    pub secret: Secret,
    /// The token it replaced, when it could be identified — what to pass to
    /// [`ForgejoForge::retire_token`] once the new one is persisted
    /// everywhere it is used. `None`: find and delete it by hand.
    pub previous: Option<TokenRef>,
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
    /// The token in use, when this adapter minted it.
    current_token: RwLock<Option<TokenRef>>,
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
        if let Some(context) = &config.status_check_context {
            crate::plan::check_check_name(context)?;
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
            current_token: RwLock::new(None),
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
        *self.current_token.write().expect("token lock poisoned") = None;
        Ok(())
    }

    /// Rotation, phase 1: mint a new bot token (basic auth with the bot's
    /// password), verify it is the bot's, and put it in use. Needs
    /// [`TokenRotation::WithPassword`].
    ///
    /// The new secret is returned: **persist it (sealed) before calling
    /// [`ForgejoForge::retire_token`]**, or a restart after the old token is
    /// deleted comes back with a dead credential. Nothing is deleted here —
    /// other bridge replicas using the old token keep working until the
    /// caller has distributed the new one and retires the old. The token it
    /// replaced is identified before anything is minted (by the id this
    /// adapter recorded when it minted it, or else by its last eight
    /// characters in the bot's token list), so once the new token is in use
    /// nothing is left that can fail.
    pub async fn mint_token(&self) -> Result<MintedToken> {
        let password = self.bot_password()?;
        let bot = self.bot();
        let basic = Auth::Basic {
            user: &bot.login,
            password,
        };
        let tokens_url = self.api.url(&["users", &bot.login, "tokens"]);
        let tracked = self
            .current_token
            .read()
            .expect("token lock poisoned")
            .clone();
        let previous = match tracked {
            Some(t) => Some(t),
            None => {
                let tail = last_eight(self.token().expose());
                let listed: Vec<TokenInfoJson> = self
                    .api
                    .get_all(tokens_url.clone(), basic, "bot access tokens")
                    .await?;
                let mut matching = listed
                    .into_iter()
                    .filter(|t| tail.is_some() && t.token_last_eight.as_deref() == tail.as_deref());
                // Only an unambiguous match is named; two tokens sharing
                // their last eight characters are left for a human.
                match (matching.next(), matching.next()) {
                    (Some(t), None) => Some(TokenRef {
                        id: t.id,
                        name: t.name,
                    }),
                    _ => None,
                }
            }
        };

        let mut suffix = [0u8; 4];
        aws_lc_rs::rand::fill(&mut suffix)
            .map_err(|_| ForgeError::Config("system RNG unavailable".into()))?;
        let name = format!("{TOKEN_NAME_PREFIX}{}-{}", unix_now(), hex::encode(suffix));
        let created: NewTokenJson = self
            .api
            .json_secret(
                Method::POST,
                tokens_url,
                basic,
                Some(&json!({ "name": name, "scopes": BOT_TOKEN_SCOPES })),
                "bot access token",
            )
            .await?;
        let minted = TokenRef {
            id: created.id,
            name: name.clone(),
        };
        let for_caller = Secret::new(created.sha1.clone());
        let in_use = Secret::new(created.sha1.clone());
        drop(created);

        match whoami(&self.api, Auth::Token(&in_use)).await {
            Ok(who) if who.id == bot.id => {}
            other => {
                // Best effort: the error that matters is the one below.
                let _ = self.delete_token(&bot.login, password, minted.id).await;
                return Err(match other {
                    Ok(who) => ForgeError::Protocol(format!(
                        "the new token authenticates as `{}`, not the bot",
                        who.login
                    )),
                    Err(e) => e,
                });
            }
        }
        *self.token.write().expect("token lock poisoned") = Arc::new(in_use);
        *self.current_token.write().expect("token lock poisoned") = Some(minted.clone());
        Ok(MintedToken {
            token: minted,
            secret: for_caller,
            previous,
        })
    }

    /// Rotation, phase 2: delete a token this bridge replaced — exactly the
    /// one named, never a pattern, so another bridge's (or a person's)
    /// tokens on the same bot are never touched. Refuses the token in use.
    /// A token already gone is not an error.
    pub async fn retire_token(&self, old: &TokenRef) -> Result<()> {
        let password = self.bot_password()?;
        if self
            .current_token
            .read()
            .expect("token lock poisoned")
            .as_ref()
            .is_some_and(|t| t.id == old.id)
        {
            return Err(ForgeError::Config(format!(
                "token `{}` is the one in use; mint a new one first",
                old.name
            )));
        }
        let bot = self.bot();
        match self.delete_token(&bot.login, password, old.id).await {
            Ok(()) | Err(ForgeError::NotFound { .. }) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn bot_password(&self) -> Result<&Secret> {
        match &self.rotation {
            TokenRotation::WithPassword(p) => Ok(p),
            _ => Err(ForgeError::Unsupported {
                operation: "bot token rotation".into(),
                hint: format!(
                    "Forgejo mints and deletes tokens only under basic auth and this bridge \
                     holds no bot password: create a token for `{}` with scopes {}, pass it to \
                     `replace_token`, and delete the old one yourself",
                    self.config.bot_login,
                    BOT_TOKEN_SCOPES.join(", ")
                ),
            }),
        }
    }

    async fn delete_token(&self, login: &str, password: &Secret, id: u64) -> Result<()> {
        let url = self.api.url(&["users", login, "tokens", &id.to_string()]);
        self.api
            .send(
                Method::DELETE,
                url,
                Auth::Basic {
                    user: login,
                    password,
                },
                None,
                "bot access token",
            )
            .await?;
        Ok(())
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

    /// The branch protection rule named exactly `branch` — the managed rule
    /// — and the names of any other rules that could apply to the branch
    /// in its place.
    ///
    /// Forgejo applies the *first* matching rule: plain-name rules before
    /// glob rules, and among those the oldest, with a plain name matching
    /// the branch case-insensitively. So another plain rule whose name
    /// equals the branch ignoring case (`Main` for `main`) may win over the
    /// managed one and is reported; a glob rule never outranks a plain one
    /// and is not.
    async fn protection_rule(
        &self,
        token: &Secret,
        owner: &str,
        name: &str,
        branch: &str,
    ) -> Result<(Option<ProtectionJson>, Vec<String>)> {
        let mut rules: Vec<ProtectionJson> = self
            .api
            .json(
                Method::GET,
                self.api.url(&["repos", owner, name, "branch_protections"]),
                Auth::Token(token),
                None,
                "branch protections",
            )
            .await?;
        let (managed, shadowing) = select_rule(&rules, branch);
        Ok((managed.map(|i| rules.swap_remove(i)), shadowing))
    }

    fn protection_state(
        &self,
        rule: Option<&ProtectionJson>,
        shadowing: &[String],
        repo: &RepoJson,
    ) -> ProtectionState {
        let mut p = ProtectionState::default();
        p.merge_methods = Some(repo.merge_methods());
        p.ci_enabled = repo.has_actions;
        let Some(rule) = rule else {
            return p;
        };
        p.present = true;
        // A Forgejo rule has no disabled state, and it is only ever looked
        // up by the default branch's exact name — but another rule that
        // Forgejo may apply first means it cannot be relied on to cover it.
        p.enforced = true;
        p.covers_default_branch = shadowing.is_empty();
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
        p.bypass_actors
            .extend(shadowing.iter().map(|n| format!("shadowing-rule:{n}")));
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

        let sha = match self.current_file(&token, owner, name, path).await? {
            Some((_, current)) if current == contents => return Ok(StepOutcome::Unchanged),
            Some((sha, _)) => Some(sha),
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

    /// The file at `path` on the default branch: `None` when absent, its
    /// blob sha and contents otherwise. A directory, or a file too large to
    /// return inline, is refused.
    async fn current_file(
        &self,
        token: &Secret,
        owner: &str,
        name: &str,
        path: &str,
    ) -> Result<Option<(String, Vec<u8>)>> {
        let mut segments = vec!["repos", owner, name, "contents"];
        segments.extend(path.split('/'));
        let existing: Option<Value> = self
            .api
            .get_opt(self.api.url(&segments), Auth::Token(token), path)
            .await?;
        match existing {
            Some(Value::Array(_)) => Err(ForgeError::Rejected {
                status: 409,
                message: format!("`{path}` exists and is a directory, not a file"),
            }),
            Some(v) => {
                let c: ContentJson = serde_json::from_value(v)
                    .map_err(|e| ForgeError::Protocol(format!("{path}: {e}")))?;
                if c.kind != "file" {
                    return Err(ForgeError::Rejected {
                        status: 409,
                        message: format!("`{path}` exists and is a {}, not a file", c.kind),
                    });
                }
                let contents = decode_content(&c)?;
                Ok(Some((c.sha, contents)))
            }
            None => Ok(None),
        }
    }

    /// The Forgejo job for [`StepAction::RefreshProtectedFiles`]: the one
    /// sanctioned way the bridge changes a protected path (the managed
    /// workflow, the keyring) after bootstrap.
    ///
    /// If every file already matches, nothing is touched. Otherwise the
    /// managed rule is opened for the bot alone — pushes enabled with a push
    /// allow-list of just the bot, the protected-file patterns cleared,
    /// since Forgejo refuses protected files even to an allowed pusher —
    /// the files are written, and the rule's exact prior push and
    /// protected-file settings are restored and read back. The restore is
    /// attempted (twice) whatever happened to the writes. While open, an
    /// `inspect` reports the bot as a bypass actor and the paths as
    /// unprotected: critical drift, so a restore that failed is re-applied
    /// by the next sweep's protection step.
    pub async fn refresh_managed_files(
        &self,
        repo: &Resource,
        files: &[vgi_forge::ExtraFile],
        message: &str,
    ) -> Result<RefreshReport> {
        let (token, owner, name) = self.repo_token(repo)?;
        let r = self.get_repo(&token, owner, name).await?;
        let branch = r.default_branch().ok_or_else(|| ForgeError::Rejected {
            status: 409,
            message: format!("{repo} is empty: nothing to refresh"),
        })?;
        self.refresh_on_branch(repo, &branch, files, message).await
    }

    /// [`ForgejoForge::refresh_managed_files`] on `branch`, the repository's
    /// default branch, already read.
    async fn refresh_on_branch(
        &self,
        repo: &Resource,
        branch: &str,
        files: &[vgi_forge::ExtraFile],
        message: &str,
    ) -> Result<RefreshReport> {
        for f in files {
            validate_repo_path(&f.path)?;
        }
        let (token, owner, name) = self.repo_token(repo)?;
        let mut stale = Vec::new();
        for f in files {
            let current = self.current_file(&token, owner, name, &f.path).await?;
            if current.map(|(_, c)| c) != Some(f.contents.clone()) {
                stale.push(f);
            }
        }
        let mut report = RefreshReport {
            outcome: StepOutcome::Unchanged,
            files: files
                .iter()
                .map(|f| (f.path.clone(), StepOutcome::Unchanged))
                .collect(),
            opened: false,
            detail: format!("{repo}: managed files already current"),
        };
        if stale.is_empty() {
            return Ok(report);
        }

        let (rule, shadowing) = self.protection_rule(&token, owner, name, branch).await?;
        if !shadowing.is_empty() {
            return Err(ForgeError::Rejected {
                status: 409,
                message: format!(
                    "{repo}: rule(s) {} shadow the managed protection; resolve that first",
                    shadowing.join(", ")
                ),
            });
        }
        let bot = self.bot();
        let rule_url = |rule_name: &str| {
            self.api
                .url(&["repos", owner, name, "branch_protections", rule_name])
        };
        let prior = rule.as_ref().map(|r| {
            (
                r.name().unwrap_or(branch).to_string(),
                json!({
                    "enable_push": r.enable_push,
                    "enable_push_whitelist": r.enable_push_whitelist,
                    "push_whitelist_usernames": r.push_whitelist_usernames,
                    "push_whitelist_teams": r.push_whitelist_teams,
                    "push_whitelist_deploy_keys": r.push_whitelist_deploy_keys,
                    "protected_file_patterns": r.protected_file_patterns,
                }),
                r.clone(),
            )
        });
        let mut open_error = None;
        if let Some((rule_name, _, _)) = &prior {
            tracing::warn!(
                repo = %repo,
                bot = %bot.login,
                files = ?stale.iter().map(|f| &f.path).collect::<Vec<_>>(),
                "opening the default-branch protection to the bridge alone to refresh managed files"
            );
            let open = json!({
                "enable_push": true,
                "enable_push_whitelist": true,
                "push_whitelist_usernames": [bot.login],
                "push_whitelist_teams": [],
                "push_whitelist_deploy_keys": false,
                "protected_file_patterns": "",
            });
            // A failed open may still have applied on the server (a timeout
            // after the write, a 5xx from a proxy): nothing is written then,
            // but the restore below is attempted all the same.
            match self
                .api
                .send(
                    Method::PATCH,
                    rule_url(rule_name),
                    Auth::Token(&token),
                    Some(&open),
                    "branch protection (open for refresh)",
                )
                .await
            {
                Ok(_) => report.opened = true,
                Err(e) => open_error = Some(e),
            }
        }

        let mut write_error = None;
        for (i, f) in files.iter().enumerate() {
            if open_error.is_some() {
                break;
            }
            if !stale.iter().any(|s| s.path == f.path) {
                continue;
            }
            match self.write_file(repo, &f.path, &f.contents, message).await {
                Ok(o) => report.files[i].1 = o,
                Err(e) => {
                    write_error = Some((f.path.clone(), e));
                    break;
                }
            }
        }

        let mut restore_error = None;
        if let Some((rule_name, body, before)) = &prior {
            for _ in 0..2 {
                let result: Result<ProtectionJson> = self
                    .api
                    .json(
                        Method::PATCH,
                        rule_url(rule_name),
                        Auth::Token(&token),
                        Some(body),
                        "branch protection (restore after refresh)",
                    )
                    .await;
                restore_error = match result {
                    Ok(after) if same_push_settings(&after, before) => None,
                    Ok(_) => Some(ForgeError::Rejected {
                        status: 200,
                        message: "the restored protection does not read back as it was".into(),
                    }),
                    Err(e) => Some(e),
                };
                if restore_error.is_none() {
                    break;
                }
            }
        }

        let written: Vec<&str> = report
            .files
            .iter()
            .filter(|(_, o)| *o != StepOutcome::Unchanged)
            .map(|(p, _)| p.as_str())
            .collect();
        report.detail = format!(
            "{repo}: protection {} for `{}`; wrote {:?}; {}",
            match (&prior, &open_error) {
                (None, _) => "absent, not opened".to_string(),
                (Some(_), None) => "opened".to_string(),
                (Some(_), Some(e)) => format!("open failed ({e})"),
            },
            bot.login,
            written,
            match (&restore_error, prior.is_some()) {
                (None, true) => "protection restored and verified".to_string(),
                (None, false) => "nothing to restore".to_string(),
                (Some(e), _) => format!("PROTECTION LEFT OPEN: {e}"),
            }
        );
        if let Some(e) = &restore_error {
            tracing::error!(repo = %repo, error = %e, "refresh could not restore the protection");
            return Err(ForgeError::Rejected {
                status: 500,
                message: report.detail,
            });
        }
        if let Some(e) = open_error {
            tracing::warn!(repo = %repo, detail = %report.detail, "refresh could not open the protection");
            return Err(match e {
                ForgeError::Rejected { status, message } => ForgeError::Rejected {
                    status,
                    message: format!("{message} (nothing written; protection restored)"),
                },
                other => other,
            });
        }
        tracing::info!(repo = %repo, detail = %report.detail, "managed files refreshed");
        if let Some((path, e)) = write_error {
            return Err(match e {
                ForgeError::Rejected { status, message } => ForgeError::Rejected {
                    status,
                    message: format!("{path}: {message} (protection restored)"),
                },
                other => other,
            });
        }
        report.outcome = if written.is_empty() {
            StepOutcome::Unchanged
        } else {
            StepOutcome::Updated
        };
        Ok(report)
    }

    /// The bootstrap's write of a managed file (the workflow, the keyring).
    ///
    /// On a repository that is not protected yet this is a plain write. On
    /// one bootstrapped before, the file is a protected path no pull request
    /// may change, so a rendering that moved on (a new verify-trust release,
    /// the namespace fallback) would otherwise fail every later bootstrap:
    /// it goes through the audited [`ForgejoForge::refresh_managed_files`]
    /// instead, which does nothing when the file is current. An empty
    /// repository has no branch to protect and is written directly.
    async fn write_managed_file(
        &self,
        repo: &Resource,
        path: &str,
        contents: &[u8],
        message: &str,
    ) -> Result<StepOutcome> {
        let (token, owner, name) = self.repo_token(repo)?;
        let Some(branch) = self.get_repo(&token, owner, name).await?.default_branch() else {
            return self.write_file(repo, path, contents, message).await;
        };
        let file = vgi_forge::ExtraFile {
            path: path.to_string(),
            contents: contents.to_vec(),
        };
        let report = self
            .refresh_on_branch(repo, &branch, std::slice::from_ref(&file), message)
            .await?;
        Ok(report
            .files
            .first()
            .map_or(report.outcome, |(_, outcome)| *outcome))
    }

    /// The single maintenance step that brings the managed workflow (and, in
    /// the signing-key fallback, the keyring) up to date on a bootstrapped
    /// repository — see [`ForgejoForge::refresh_managed_files`].
    pub fn refresh_plan(&self, repo: &RepoSpec, cfg: &VgiConfig) -> Result<Vec<BootstrapStep>> {
        let files: Vec<vgi_forge::ExtraFile> = self
            .bootstrap_plan(repo, cfg)?
            .into_iter()
            .filter_map(|s| match s.action {
                StepAction::WriteFile { path, contents, .. }
                    if path == crate::plan::WORKFLOW_PATH || path == crate::plan::KEYRING_PATH =>
                {
                    Some(vgi_forge::ExtraFile { path, contents })
                }
                _ => None,
            })
            .collect();
        Ok(vec![BootstrapStep::new(
            "refresh-managed-files",
            vgi_forge::BootstrapComponent::Workflow,
            StepAction::RefreshProtectedFiles {
                files,
                message: "ci: update the VGI commit-trust check".into(),
            },
        )])
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

        let body = settings_request(&r, s);
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
        if is_glob(&branch) {
            return Err(ForgeError::Unsupported {
                operation: "protecting the default branch".into(),
                hint: format!(
                    "the default branch `{branch}` contains glob characters, so Forgejo would \
                     read a rule for it as a pattern; rename the branch"
                ),
            });
        }
        let (existing, shadowing) = self.protection_rule(&token, owner, name, &branch).await?;
        if !shadowing.is_empty() {
            // Never adopt or rely on a rule Forgejo may not apply; deleting
            // someone else's rule is a human's decision.
            return Err(ForgeError::Rejected {
                status: 409,
                message: format!(
                    "{repo}: branch protection rule(s) {} also match `{branch}` (Forgejo compares \
                     rule names case-insensitively and applies the oldest), so the managed rule \
                     may never apply; remove them and re-run",
                    shadowing.join(", ")
                ),
            });
        }
        if let Some(rule) = &existing
            && satisfies_protection(rule, spec)
        {
            return Ok(StepOutcome::Unchanged);
        }

        // Seed the merge allow-list with the repository's admins: once it is
        // enabled, even an admin cannot merge without a place on it (and an
        // admin can edit the rule anyway, so this grants nothing new).
        // Maintainers are added by `apply_roles`.
        let admins: Vec<String> = self
            .collaborators(&token, owner, name)
            .await?
            .into_iter()
            .filter(|(_, perm)| *perm == Perm::Admin)
            .map(|(account, _)| account.login)
            .collect();
        let mut body = protection_request(existing.as_ref(), &admins, spec);
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

    /// Where `login`'s access to an organisation's repository comes from,
    /// other than a direct role: owning the organisation, and the teams
    /// with access to the repository that they are in. Best effort: a
    /// lookup Forgejo refuses leaves that source out, and the access is
    /// still reported.
    async fn access_sources(
        &self,
        token: &Secret,
        owner: &str,
        name: &str,
        login: &str,
    ) -> Vec<AccessSource> {
        let auth = Auth::Token(token);
        let mut via = Vec::new();
        let org: Option<OrgPermissionsJson> = self
            .api
            .get_opt(
                self.api
                    .url(&["users", login, "orgs", owner, "permissions"]),
                auth,
                "organisation permissions",
            )
            .await
            .ok()
            .flatten();
        if org.is_some_and(|o| o.is_owner) {
            via.push(AccessSource::OrgOwner(owner.to_string()));
        }
        let teams: Vec<TeamJson> = self
            .api
            .get_all(
                self.api.url(&["repos", owner, name, "teams"]),
                auth,
                "repository teams",
            )
            .await
            .unwrap_or_default();
        for t in teams {
            let url = self
                .api
                .url(&["teams", &t.id.to_string(), "members", login]);
            if self
                .api
                .exists(url, auth, "team member")
                .await
                .unwrap_or(false)
            {
                via.push(AccessSource::Team(t.name));
            }
        }
        via
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
                              even then (they are protected paths, by design): update those \
                              with the audited refresh-managed-files step";

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

    /// The owner, and the bot every automated action goes through.
    fn is_protected_account(&self, ns: &Namespace, account: u64) -> bool {
        ns.owner_id == Some(account) || self.bot().id == account
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
        let state = self.oauth_keys.issue_link_state(member, unix_now())?;
        let verifier = self.oauth_keys.verifier(Purpose::Link, &state);
        Ok(LinkStep::Redirect {
            url: self
                .authorize_url(&self.config.link_redirect_uri, &state, &verifier)
                .to_string(),
        })
    }

    async fn complete_account_link(&self, cb: LinkCallback) -> Result<ForgeAccount> {
        let LinkCallback::Redirect { params, member, .. } = cb else {
            return Err(ForgeError::Unsupported {
                operation: "device-flow account link".into(),
                hint: "Forgejo has no device flow; members link through the browser \
                       (authorisation code + PKCE)"
                    .into(),
            });
        };
        let state = params.get("state").map(String::as_str).unwrap_or("");
        let member = member.ok_or_else(|| {
            ForgeError::LinkFailed(
                "the callback does not say which member started this link (build it with \
                 LinkCallback::redirect and the member from the caller's session)"
                    .into(),
            )
        })?;
        self.oauth_keys
            .check_link_state(state, &member, unix_now(), self.config.link_state_ttl)?;
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
        let (rule, shadowing) = match r.default_branch() {
            Some(branch) => self.protection_rule(&token, owner, name, &branch).await?,
            None => (None, Vec::new()),
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
        state.protection = self.protection_state(rule.as_ref(), &shadowing, &r);
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
            Some(branch) => self.protection_rule(&token, owner, name, &branch).await?.0,
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

        let bot = self.bot().id;
        for (id, (account, role)) in &wanted {
            let have = current.get(id);
            if *id == bot
                && *role == ForgeRole::None
                && let Some(h) = have
            {
                // Whatever the caller asked: the bot losing its role would
                // end every automated action here.
                report.changes.push(RoleChange::new(
                    account.clone(),
                    h.perm.observed(h.listed),
                    ForgeRole::None,
                    RoleOutcome::Failed("the bridge's own bot is never removed".into()),
                ));
                continue;
            }
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

    /// Forgejo's effective permission for the account
    /// (`/collaborators/{collaborator}/permission` counts teams and
    /// organisation ownership), then where it comes from. Forgejo has no
    /// organisation-wide base permission: an organisation's members reach
    /// its repositories through teams (the owners through the Owners team).
    async fn indirect_access(
        &self,
        repo: &Resource,
        account: &ForgeAccount,
    ) -> Result<Option<IndirectAccess>> {
        let (ns, owner, name) = self.locate(repo)?;
        self.automated(&ns)?;
        let token = self.token();
        let login = match self.login_for(&token, account.id).await {
            Ok(l) => l,
            // No such account any more: it has no access.
            Err(ForgeError::NotFound { .. }) => return Ok(None),
            Err(e) => return Err(e),
        };
        let url = self
            .api
            .url(&["repos", owner, name, "collaborators", &login, "permission"]);
        let Some(p) = self
            .api
            .get_opt::<PermissionJson>(url, Auth::Token(&token), "collaborator permission")
            .await?
        else {
            return Ok(None);
        };
        let Some(perm) = Perm::parse(&p.permission) else {
            // `none`.
            return Ok(None);
        };
        // Everyone reads a public repository: that is no access to report.
        if perm == Perm::Read && !self.get_repo(&token, owner, name).await?.private {
            return Ok(None);
        }
        let via = if ns.kind == NamespaceKind::Organization {
            self.access_sources(&token, owner, name, &login).await
        } else {
            Vec::new()
        };
        Ok(Some(IndirectAccess::new(perm.observed(false), via)))
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
            inline_variables: !(self.config.use_actions_variables
                && probed.info.features.actions_variables),
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
            } if path == crate::plan::WORKFLOW_PATH || path == crate::plan::KEYRING_PATH => {
                self.write_managed_file(repo, path, contents, message).await
            }
            StepAction::WriteFile {
                path,
                contents,
                message,
            } => self.write_file(repo, path, contents, message).await,
            StepAction::SetVariable { name, value } => self.set_variable(repo, name, value).await,
            StepAction::ProtectDefaultBranch(spec) => self.protect(repo, spec).await,
            StepAction::ConfigureRepo(settings) => self.configure_repo(repo, settings).await,
            StepAction::RefreshProtectedFiles { files, message } => self
                .refresh_managed_files(repo, files, message)
                .await
                .map(|r| r.outcome),
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
        let existing = teams
            .into_iter()
            .find(|t| t.name.eq_ignore_ascii_case(&self.config.team_name));
        if let Some(t) = &existing {
            // The team is granted admin on every repository. Adopting one
            // someone else already uses would hand that to its members, so
            // only a team that is empty or holds just the bot is taken over.
            let bot = self.bot();
            let members: Vec<UserJson> = self
                .api
                .get_all(
                    self.api.url(&["teams", &t.id.to_string(), "members"]),
                    auth,
                    "team members",
                )
                .await?;
            let others: Vec<String> = members
                .into_iter()
                .filter(|m| m.id != bot.id)
                .map(|m| m.login)
                .collect();
            if !others.is_empty() {
                return Err(ForgeError::BindRejected(format!(
                    "`{org}` already has a team named `{}` with other members ({}); the bridge \
                     will not adopt it and grant them admin on every repository. Rename that \
                     team or configure another team name",
                    t.name,
                    others.join(", ")
                )));
            }
        }
        match existing {
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

/// Whether Forgejo reads `name` as a glob pattern rather than a plain name
/// (gobwas `syntax.Special`). The same characters in a required status
/// context make it a pattern too — and an invalid pattern there matches as
/// if nothing were required, so the plan refuses them.
pub(crate) fn is_glob(name: &str) -> bool {
    name.contains(['*', '?', '[', ']', '{', '}', '\\'])
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

/// The managed rule among `rules` — the one named exactly `branch` — and
/// the names of any other plain rules Forgejo may apply to the branch in its
/// place (a case-insensitive name match; see `protection_rule`).
fn select_rule(rules: &[ProtectionJson], branch: &str) -> (Option<usize>, Vec<String>) {
    let folded = branch.to_lowercase();
    let mut managed = None;
    let mut shadowing = Vec::new();
    for (i, rule) in rules.iter().enumerate() {
        match rule.name() {
            Some(n) if n == branch => managed = Some(i),
            Some(n) if !is_glob(n) && n.to_lowercase() == folded => shadowing.push(n.to_string()),
            _ => {}
        }
    }
    (managed, shadowing)
}

/// The `PATCH /repos/{owner}/{repo}` body that makes the repository's merge
/// and CI settings `s`.
fn settings_request(r: &RepoJson, s: &RepoSettings) -> Value {
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
            body["allow_fast_forward_only_merge"] = json!(has(MergeMethod::FastForward));
        }
    }
    if s.enable_ci {
        body["has_actions"] = json!(true);
    }
    body
}

/// The branch-protection body for `spec`, keeping what an `existing` rule
/// already has (its merge allow-list, contexts and protected paths) and
/// seeding the allow-list with `admins`. A new rule also needs its
/// `rule_name` / `branch_name`, which the caller adds.
fn protection_request(
    existing: Option<&ProtectionJson>,
    admins: &[String],
    spec: &ProtectionSpec,
) -> Value {
    let mut allow: Vec<String> = existing
        .filter(|r| r.enable_merge_whitelist)
        .map(|r| r.merge_whitelist_usernames.clone())
        .unwrap_or_default();
    for login in admins {
        if !contains_login(&allow, login) {
            allow.push(login.clone());
        }
    }
    let mut contexts = existing
        .map(|r| r.status_check_contexts.clone())
        .unwrap_or_default();
    if !contexts.contains(&spec.required_check) {
        contexts.push(spec.required_check.clone());
    }
    let mut paths = existing
        .map(|r| patterns(&r.protected_file_patterns))
        .unwrap_or_default();
    for p in &spec.protected_paths {
        let p = p.to_ascii_lowercase();
        if !paths.contains(&p) {
            paths.push(p);
        }
    }
    json!({
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
    })
}

// ── the same shapes, for a client acting as the repository's admin ───────
//
// `vgi repo init` runs a bootstrap plan as the account holder, through their
// own token, where no bridge exists. These let it ask Forgejo for exactly
// what `run_step` asks for, and skip exactly what `run_step` would skip.

fn parse<T: serde::de::DeserializeOwned>(what: &str, v: &Value) -> Result<T> {
    serde_json::from_value(v.clone()).map_err(|e| ForgeError::Protocol(format!("{what}: {e}")))
}

/// From `GET /repos/{owner}/{repo}/branch_protections`: the managed rule for
/// `branch`, and the names of rules that could shadow it (a plan must refuse
/// to rely on the managed rule while any exist).
pub fn managed_protection_rule(
    rules: &Value,
    branch: &str,
) -> Result<(Option<Value>, Vec<String>)> {
    let mut list: Vec<Value> = parse("branch protections", rules)?;
    let typed = list
        .iter()
        .map(|v| parse::<ProtectionJson>("branch protection", v))
        .collect::<Result<Vec<_>>>()?;
    let (managed, shadowing) = select_rule(&typed, branch);
    Ok((managed.map(|i| list.swap_remove(i)), shadowing))
}

/// Whether a rule (as Forgejo returns it) already is what the protection
/// step would write for `spec`.
pub fn protection_satisfies(rule: &Value, spec: &ProtectionSpec) -> Result<bool> {
    Ok(satisfies_protection(
        &parse("branch protection", rule)?,
        spec,
    ))
}

/// The protection body for `spec` over an `existing` rule, the allow-list
/// seeded with `admins`. For a new rule, add `rule_name` and `branch_name`.
pub fn protection_body(
    existing: Option<&Value>,
    admins: &[String],
    spec: &ProtectionSpec,
) -> Result<Value> {
    let existing: Option<ProtectionJson> = existing
        .map(|v| parse("branch protection", v))
        .transpose()?;
    Ok(protection_request(existing.as_ref(), admins, spec))
}

/// Whether a repository (as `GET /repos/{owner}/{repo}` returns it) already
/// has the settings `s`.
pub fn settings_satisfied(repo: &Value, s: &RepoSettings) -> Result<bool> {
    Ok(satisfies_settings(&parse("repository", repo)?, s))
}

/// The `PATCH /repos/{owner}/{repo}` body for `s`.
pub fn settings_body(repo: &Value, s: &RepoSettings) -> Result<Value> {
    Ok(settings_request(&parse("repository", repo)?, s))
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

/// Whether two readings of a rule agree on everything a refresh opens.
fn same_push_settings(a: &ProtectionJson, b: &ProtectionJson) -> bool {
    let set = |v: &[String]| {
        let mut v: Vec<String> = v.iter().map(|s| s.to_lowercase()).collect();
        v.sort();
        v
    };
    a.enable_push == b.enable_push
        && (!a.enable_push
            || (a.enable_push_whitelist == b.enable_push_whitelist
                && set(&a.push_whitelist_usernames) == set(&b.push_whitelist_usernames)
                && set(&a.push_whitelist_teams) == set(&b.push_whitelist_teams)
                && a.push_whitelist_deploy_keys == b.push_whitelist_deploy_keys))
        && patterns(&a.protected_file_patterns) == patterns(&b.protected_file_patterns)
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
struct OrgPermissionsJson {
    #[serde(default)]
    is_owner: bool,
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

#[derive(Deserialize, Default, Clone)]
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
        // Without the allow-list, everyone with write access may merge.
        if !self.enable_merge_whitelist {
            out.push("merge: everyone with write access".into());
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
            [
                "repository admins (the rule does not apply to admins)",
                "merge: everyone with write access",
            ]
        );
    }

    #[test]
    fn glob_characters_are_forgejos() {
        for g in ["main*", "rel?", "[ab]", "{a,b}", "a\\b"] {
            assert!(is_glob(g), "{g}");
        }
        for plain in ["main", "release/1.0", "feature-x_y", "Verify commit trust"] {
            assert!(!is_glob(plain), "{plain}");
        }
    }
}
