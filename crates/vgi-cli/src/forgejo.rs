//! Forgejo (and Gitea), with the person's own token.
//!
//! The plan, the merge-settings body and the branch-protection body — and
//! the tests for "already done" — are the Forgejo adapter's own; this module
//! only carries them over HTTP as the repository's admin instead of the
//! community's bot.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::{Method, StatusCode, redirect};
use serde_json::{Value, json};
use url::Url;
use vgi_forge::{
    BootstrapStep, MergeMethod, ProtectionSpec, RepoSettings, RepoSpec, StepAction, VgiConfig,
};
use vgi_forge_forgejo::plan::{MergePlan, PlanOptions, default_status_context, forgejo_plan};
use vgi_forge_forgejo::{
    DEFAULT_ACTIONS_BASE, DEFAULT_CHECKOUT_ACTION, InstanceInfo, managed_protection_rule,
    protection_body, protection_satisfies, settings_body, settings_satisfied,
};

use crate::report::{Change, Report};

/// The environment variable holding the person's token.
pub const TOKEN_ENV: &str = "FORGEJO_TOKEN";

/// A Forgejo API client acting as the token's owner.
pub struct Client {
    http: reqwest::Client,
    api: Url,
    token: String,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("api", &self.api.as_str())
            .field("token", &"<redacted>")
            .finish()
    }
}

/// `https://<host>/`, or `base` checked the way the adapter checks its
/// instance URL: `https`, or `http` only on loopback (the token travels on
/// every request).
pub fn base_url(host: &str, base: Option<&Url>) -> Result<Url> {
    let mut url = match base {
        Some(u) => u.clone(),
        None => Url::parse(&format!("https://{host}/")).context("instance URL")?,
    };
    let h = url.host_str().unwrap_or("").to_ascii_lowercase();
    let loopback = matches!(h.as_str(), "localhost" | "127.0.0.1" | "[::1]");
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        s => bail!("instance URL `{url}`: `{s}` is not allowed (https, or http on loopback)"),
    }
    if !url.path().ends_with('/') {
        let p = format!("{}/", url.path());
        url.set_path(&p);
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

impl Client {
    /// A client for the instance at `base` (see [`base_url`]).
    pub fn new(base: &Url, token: String) -> Result<Self> {
        if token.trim().is_empty() {
            bail!("{TOKEN_ENV} is empty");
        }
        let http = reqwest::Client::builder()
            .user_agent(concat!("vgi/", env!("CARGO_PKG_VERSION")))
            .redirect(redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .context("HTTP client")?;
        Ok(Client {
            http,
            api: base.join("api/v1/").context("API URL")?,
            token,
        })
    }

    fn url(&self, segments: &[&str]) -> Url {
        let mut u = self.api.clone();
        u.path_segments_mut()
            .expect("an http(s) URL has path segments")
            .pop_if_empty()
            .extend(segments);
        u
    }

    async fn call(
        &self,
        method: Method,
        url: Url,
        body: Option<&Value>,
    ) -> Result<(StatusCode, Value)> {
        let mut req = self
            .http
            .request(method.clone(), url.clone())
            .header("Authorization", format!("token {}", self.token))
            .header("Accept", "application/json");
        if let Some(b) = body {
            req = req.json(b);
        }
        let what = format!("{method} {}", url.path());
        let resp = req
            .send()
            .await
            .map_err(|e| anyhow!("{what}: {}", e.without_url()))?;
        let status = resp.status();
        let bytes = resp.bytes().await.with_context(|| what.clone())?;
        let value = if bytes.iter().all(u8::is_ascii_whitespace) {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes)))
        };
        Ok((status, value))
    }

    async fn get(&self, segments: &[&str]) -> Result<Option<Value>> {
        let url = self.url(segments);
        let (status, v) = self.call(Method::GET, url.clone(), None).await?;
        match status.as_u16() {
            200..=299 => Ok(Some(v)),
            404 => Ok(None),
            _ => bail!("GET {}: HTTP {status}: {}", url.path(), message(&v)),
        }
    }

    async fn send(&self, method: Method, segments: &[&str], body: &Value) -> Result<Value> {
        let url = self.url(segments);
        let (status, v) = self.call(method.clone(), url.clone(), Some(body)).await?;
        if !status.is_success() {
            bail!("{method} {}: HTTP {status}: {}", url.path(), message(&v));
        }
        Ok(v)
    }
}

fn message(v: &Value) -> String {
    v.get("message")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| v.to_string())
}

/// The instance's version and the token owner's login.
pub async fn probe(c: &Client) -> Result<(InstanceInfo, String)> {
    let v = c
        .get(&["version"])
        .await?
        .ok_or_else(|| anyhow!("no /api/v1/version: is this a Forgejo or Gitea instance?"))?;
    let info = InstanceInfo::from_version(v.get("version").and_then(Value::as_str).unwrap_or(""));
    let me = c
        .get(&["user"])
        .await?
        .ok_or_else(|| anyhow!("{TOKEN_ENV} is not accepted (GET /user)"))?;
    let login = me
        .get("login")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("GET /user: no login"))?
        .to_string();
    Ok((info, login))
}

/// The adapter's plan, with the adapter's defaults: fast-forward-only
/// merges, DIDs written into the workflow.
pub fn plan(spec: &RepoSpec, cfg: &VgiConfig, runs_on: &str) -> Result<Vec<BootstrapStep>> {
    let actions_base = Url::parse(DEFAULT_ACTIONS_BASE).expect("static URL");
    let opts = PlanOptions {
        checkout_action: DEFAULT_CHECKOUT_ACTION,
        actions_base: &actions_base,
        runs_on,
        status_context: default_status_context(&cfg.required_check),
        inline_variables: true,
        merges: MergePlan::FastForwardOnly,
    };
    Ok(forgejo_plan(spec, cfg, &opts)?)
}

/// Run `steps` in order, check-then-apply, stopping at the first failure.
pub async fn apply(
    c: &Client,
    owner: &str,
    name: &str,
    me: &str,
    info: &InstanceInfo,
    steps: &[BootstrapStep],
    report: &mut Report<'_>,
) -> Result<()> {
    let repo = c.get(&["repos", owner, name]).await?.ok_or_else(|| {
        anyhow!("{owner}/{name} does not exist, or {TOKEN_ENV} cannot see it; create it first")
    })?;
    if repo.pointer("/permissions/admin").and_then(Value::as_bool) == Some(false) {
        bail!("{TOKEN_ENV} is not an admin of {owner}/{name}; branch protection needs admin");
    }
    for step in steps {
        let id = step.id.as_str();
        match &step.action {
            StepAction::ConfigureRepo(s) => {
                let (change, body) = configure(c, owner, name, info, s, report.dry_run()).await?;
                report.step(
                    id,
                    "merge settings",
                    change,
                    Some(&serde_json::to_string_pretty(&body)?),
                );
            }
            StepAction::WriteFile {
                path,
                contents,
                message,
            } => {
                let change =
                    write_file(c, owner, name, path, contents, message, report.dry_run()).await?;
                report.step(id, path, change, Some(&String::from_utf8_lossy(contents)));
            }
            StepAction::ProtectDefaultBranch(spec) => {
                let (change, body) = protect(c, owner, name, me, spec, report.dry_run()).await?;
                report.step(
                    id,
                    "default branch protection",
                    change,
                    Some(&serde_json::to_string_pretty(&body)?),
                );
            }
            other => bail!("step `{id}` ({other:?}) is not one `vgi repo init` runs on Forgejo"),
        }
    }
    Ok(())
}

async fn configure(
    c: &Client,
    owner: &str,
    name: &str,
    info: &InstanceInfo,
    s: &RepoSettings,
    dry_run: bool,
) -> Result<(Change, Value)> {
    let repo = c
        .get(&["repos", owner, name])
        .await?
        .ok_or_else(|| anyhow!("{owner}/{name} vanished"))?;
    let ff_wanted = s.merge_methods.contains(&MergeMethod::FastForward);
    let ff_available =
        info.features.fast_forward_only && repo.get("allow_fast_forward_only_merge").is_some();
    if ff_wanted && !ff_available {
        bail!(
            "this instance ({}) cannot restrict merges to fast-forward only, and every web merge \
             would land a commit the check never saw. Upgrade to Forgejo 7 or Gitea 1.22",
            info.version
        );
    }
    let body = settings_body(&repo, s)?;
    if settings_satisfied(&repo, s)? {
        return Ok((Change::Unchanged, body));
    }
    if !dry_run {
        let after = c
            .send(Method::PATCH, &["repos", owner, name], &body)
            .await?;
        if !settings_satisfied(&after, s)? {
            bail!(
                "{owner}/{name}: the instance accepted the settings but did not apply them all \
                 (are Actions or pull requests disabled instance-wide?)"
            );
        }
    }
    Ok((Change::Update, body))
}

async fn write_file(
    c: &Client,
    owner: &str,
    name: &str,
    file: &str,
    contents: &[u8],
    message: &str,
    dry_run: bool,
) -> Result<Change> {
    vgi_forge::validate_repo_path(file)?;
    let mut segs = vec!["repos", owner, name, "contents"];
    segs.extend(file.split('/'));
    let existing = match c.get(&segs).await? {
        None => None,
        Some(v) => {
            if v.is_array() || v.get("type").and_then(Value::as_str) != Some("file") {
                bail!("`{file}` exists in {owner}/{name} and is not a file");
            }
            let Some(b64) = v.get("content").and_then(Value::as_str) else {
                bail!(
                    "`{file}` in {owner}/{name} is too large for the instance to return inline; \
                     it was not written by the bootstrap — remove or rename it"
                );
            };
            let compact: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
            let bytes = STANDARD
                .decode(compact)
                .with_context(|| format!("`{file}`: content is not base64"))?;
            let sha = v
                .get("sha")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            Some((sha, bytes))
        }
    };
    let (change, method) = match &existing {
        Some((_, current)) if current == contents => return Ok(Change::Unchanged),
        Some(_) => (Change::Update, Method::PUT),
        None => (Change::Create, Method::POST),
    };
    if dry_run {
        return Ok(change);
    }
    let mut body = json!({ "message": message, "content": STANDARD.encode(contents) });
    if let Some((sha, _)) = &existing {
        body["sha"] = json!(sha);
    }
    c.send(method, &segs, &body).await.map_err(|e| {
        e.context(format!(
            "writing `{file}` — once the default branch is protected, the workflow is a \
             protected path and changes only through the community's bridge"
        ))
    })?;
    Ok(change)
}

/// Admin collaborators, plus the person running this: the rule applies to
/// admins, and its merge allow-list is who may merge at all, so the account
/// holder (never a collaborator of their own repository) must be on it or
/// they lock themselves out. The bridge seeds only collaborators, because
/// there a namespace's owner is not the one running the plan.
async fn admins(c: &Client, owner: &str, name: &str, me: &str) -> Result<Vec<String>> {
    let mut out = vec![me.to_string()];
    let mut page = 1u32;
    loop {
        let mut url = c.url(&["repos", owner, name, "collaborators"]);
        url.query_pairs_mut()
            .append_pair("page", &page.to_string())
            .append_pair("limit", "50");
        let (status, v) = c.call(Method::GET, url, None).await?;
        if !status.is_success() {
            bail!("listing collaborators: HTTP {status}: {}", message(&v));
        }
        let users = v.as_array().cloned().unwrap_or_default();
        if users.is_empty() {
            break;
        }
        for u in &users {
            let Some(login) = u.get("login").and_then(Value::as_str) else {
                continue;
            };
            let perm = c
                .get(&["repos", owner, name, "collaborators", login, "permission"])
                .await?;
            let is_admin = perm
                .as_ref()
                .and_then(|p| p.get("permission"))
                .and_then(Value::as_str)
                == Some("admin");
            if is_admin && !out.iter().any(|l| l.eq_ignore_ascii_case(login)) {
                out.push(login.to_string());
            }
        }
        if users.len() < 50 {
            break;
        }
        page += 1;
    }
    Ok(out)
}

async fn protect(
    c: &Client,
    owner: &str,
    name: &str,
    me: &str,
    spec: &ProtectionSpec,
    dry_run: bool,
) -> Result<(Change, Value)> {
    let repo = c
        .get(&["repos", owner, name])
        .await?
        .ok_or_else(|| anyhow!("{owner}/{name} vanished"))?;
    let empty = repo.get("empty").and_then(Value::as_bool) == Some(true);
    let branch = repo
        .get("default_branch")
        .and_then(Value::as_str)
        .filter(|b| !b.is_empty() && !empty)
        .map(str::to_string);
    let Some(branch) = branch else {
        if dry_run {
            // The workflow step would have made the first commit.
            let mut body = protection_body(None, &[me.to_string()], spec)?;
            body["rule_name"] = json!("<default branch>");
            return Ok((Change::Create, body));
        }
        bail!("{owner}/{name} is empty: there is no default branch to protect yet");
    };
    if branch.contains(['*', '?', '[', ']', '{', '}', '\\']) {
        bail!(
            "the default branch `{branch}` contains glob characters, so Forgejo would read a rule \
             for it as a pattern; rename the branch"
        );
    }
    let rules = c
        .get(&["repos", owner, name, "branch_protections"])
        .await?
        .unwrap_or(Value::Array(Vec::new()));
    let (existing, shadowing) = managed_protection_rule(&rules, &branch)?;
    if !shadowing.is_empty() {
        bail!(
            "{owner}/{name}: branch protection rule(s) {} also match `{branch}` (Forgejo compares \
             rule names case-insensitively and applies the oldest), so the managed rule may \
             never apply; remove them and re-run",
            shadowing.join(", ")
        );
    }
    if let Some(rule) = &existing
        && protection_satisfies(rule, spec)?
    {
        return Ok((Change::Unchanged, rule.clone()));
    }
    let admins = admins(c, owner, name, me).await?;
    let mut body = protection_body(existing.as_ref(), &admins, spec)?;
    let (change, method, segs): (Change, Method, Vec<String>) = match &existing {
        Some(rule) => {
            let rule_name = rule
                .get("rule_name")
                .and_then(Value::as_str)
                .filter(|n| !n.is_empty())
                .or_else(|| rule.get("branch_name").and_then(Value::as_str))
                .unwrap_or(&branch)
                .to_string();
            (
                Change::Update,
                Method::PATCH,
                vec![
                    "repos".into(),
                    owner.into(),
                    name.into(),
                    "branch_protections".into(),
                    rule_name,
                ],
            )
        }
        None => {
            body["rule_name"] = json!(branch);
            // Pre-1.22 instances know only `branch_name`.
            body["branch_name"] = json!(branch);
            (
                Change::Create,
                Method::POST,
                vec![
                    "repos".into(),
                    owner.into(),
                    name.into(),
                    "branch_protections".into(),
                ],
            )
        }
    };
    if !dry_run {
        let segs: Vec<&str> = segs.iter().map(String::as_str).collect();
        let after = c.send(method, &segs, &body).await?;
        if !protection_satisfies(&after, spec)? {
            bail!(
                "{owner}/{name}: the instance accepted the branch protection but it does not read \
                 back as requested"
            );
        }
    }
    Ok((change, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_urls_are_checked() {
        assert_eq!(
            base_url("codeberg.org", None).unwrap().as_str(),
            "https://codeberg.org/"
        );
        let sub = Url::parse("https://example.org/git").unwrap();
        assert_eq!(
            base_url("x", Some(&sub)).unwrap().as_str(),
            "https://example.org/git/"
        );
        let lo = Url::parse("http://127.0.0.1:3000").unwrap();
        assert!(base_url("x", Some(&lo)).is_ok());
        let plain = Url::parse("http://git.example.org/").unwrap();
        assert!(base_url("x", Some(&plain)).is_err());
    }

    #[test]
    fn path_segments_are_encoded() {
        let c = Client::new(&Url::parse("https://h.example/sub/").unwrap(), "t".into()).unwrap();
        assert_eq!(
            c.url(&["repos", "a", "b", "contents", ".forgejo", "x y?"])
                .as_str(),
            "https://h.example/sub/api/v1/repos/a/b/contents/.forgejo/x%20y%3F"
        );
    }
}
