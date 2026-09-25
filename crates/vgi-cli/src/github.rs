//! GitHub, through the person's own `gh` login.
//!
//! Every request is one `gh api` process with its arguments passed as an
//! argument vector — never a shell string — and any body on stdin
//! (`--input -`), so nothing from a repository name, a file or a DID is ever
//! parsed by a shell or read as a flag. Each path segment is percent-encoded
//! (including `{` and `}`, which `gh api` would otherwise fill in from the
//! current directory's repository).

use std::ffi::OsString;
use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use vgi_forge::{BootstrapStep, ForgeAccount, ProtectionSpec, RepoSpec, StepAction, VgiConfig};
use vgi_forge_github::plan::{
    CODEOWNERS_LOCATIONS, CODEOWNERS_PATH, CheckGuard, RULESET_NAME, github_plan, render_codeowners,
};
use vgi_forge_github::{API_VERSION, DEFAULT_CHECKOUT_ACTION, ruleset_body, ruleset_satisfies};

use crate::report::{Change, Report};

/// One `gh api` reply.
#[derive(Debug)]
pub struct Reply {
    /// HTTP status.
    pub status: u16,
    /// Body.
    pub body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Result<Value> {
        if self.body.iter().all(u8::is_ascii_whitespace) {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&self.body).context("GitHub's reply is not JSON")
    }

    fn message(&self) -> String {
        self.json()
            .ok()
            .and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_else(|| String::from_utf8_lossy(&self.body).trim().to_string())
    }
}

/// `gh api` against one host.
#[derive(Debug, Clone)]
pub struct Gh {
    program: OsString,
    host: String,
}

/// Percent-encode one path segment: everything but RFC 3986 unreserved.
pub fn segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `a/b/c` from segments, each encoded.
pub fn path(segments: &[&str]) -> String {
    segments
        .iter()
        .map(|s| segment(s))
        .collect::<Vec<_>>()
        .join("/")
}

impl Gh {
    /// `gh` from `PATH`, for `host` (`github.com`, or a GHES host).
    pub fn new(host: impl Into<String>) -> Self {
        Gh {
            program: "gh".into(),
            host: host.into(),
        }
    }

    /// The argument vector for one request (exposed for tests).
    pub fn argv(&self, method: &str, path: &str, with_body: bool) -> Vec<String> {
        let mut argv = vec![
            "api".to_string(),
            "--hostname".into(),
            self.host.clone(),
            "--include".into(),
            "--method".into(),
            method.into(),
            "-H".into(),
            "Accept: application/vnd.github+json".into(),
            "-H".into(),
            format!("X-GitHub-Api-Version: {API_VERSION}"),
        ];
        if with_body {
            argv.push("--input".into());
            argv.push("-".into());
        }
        // Last, and never flag-like: every path starts with a letter.
        argv.push(path.into());
        argv
    }

    /// One request. A non-2xx status is a [`Reply`], not an error; failing to
    /// run `gh`, or `gh` failing before any HTTP exchange (no login), is.
    pub fn request(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Reply> {
        debug_assert!(path.starts_with(|c: char| c.is_ascii_alphabetic()));
        let mut child = Command::new(&self.program)
            .args(self.argv(method, path, body.is_some()))
            .stdin(if body.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                anyhow!("could not run `gh` ({e}); install the GitHub CLI and run `gh auth login`")
            })?;
        if let Some(body) = body {
            let mut stdin = child.stdin.take().expect("piped stdin");
            stdin
                .write_all(&serde_json::to_vec(body)?)
                .context("writing the request body to gh")?;
        }
        let out = child.wait_with_output().context("waiting for gh")?;
        parse_include(&out.stdout).ok_or_else(|| {
            anyhow!(
                "`gh api {method} {path}` failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )
        })
    }

    /// `GET`, with 404 as `None`.
    pub fn get(&self, path: &str) -> Result<Option<Value>> {
        let r = self.request("GET", path, None)?;
        match r.status {
            200..=299 => Ok(Some(r.json()?)),
            404 => Ok(None),
            s => bail!("GET {path}: HTTP {s}: {}", r.message()),
        }
    }

    /// A change; any non-2xx is an error.
    pub fn send(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        let r = self.request(method, path, body)?;
        match r.status {
            200..=299 => r.json(),
            s => bail!("{method} {path}: HTTP {s}: {}", r.message()),
        }
    }
}

/// Split `gh api --include` output into status and body.
fn parse_include(out: &[u8]) -> Option<Reply> {
    if !out.starts_with(b"HTTP/") {
        return None;
    }
    let (head, body) = match find(out, b"\r\n\r\n") {
        Some(i) => (&out[..i], &out[i + 4..]),
        None => match find(out, b"\n\n") {
            Some(i) => (&out[..i], &out[i + 2..]),
            None => (out, &[][..]),
        },
    };
    let first = std::str::from_utf8(head).ok()?.lines().next()?;
    let status = first.split_whitespace().nth(1)?.parse().ok()?;
    Some(Reply {
        status,
        body: body.to_vec(),
    })
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// What the repository and its account say about who owns it.
#[derive(Debug)]
pub struct RepoFacts {
    /// The owning account's login as the resource names it (lowercased),
    /// used in API paths; GitHub matches it case-insensitively.
    pub owner: String,
    /// Repository name.
    pub name: String,
    /// The owning account is a user (a personal repository).
    pub personal: bool,
    /// The owning account.
    pub account: ForgeAccount,
}

/// Look the repository up and check the caller can administer it.
pub fn repo_facts(gh: &Gh, owner: &str, name: &str) -> Result<RepoFacts> {
    let repo = gh.get(&path(&["repos", owner, name]))?.ok_or_else(|| {
        anyhow!(
            "{owner}/{name} does not exist, or your gh login cannot see it. Create it first: \
             gh repo create {owner}/{name} --private (or --public)"
        )
    })?;
    if repo.pointer("/permissions/admin").and_then(Value::as_bool) != Some(true) {
        bail!(
            "your gh login is not an admin of {owner}/{name}; the ruleset needs admin (the \
             account holder, or an org owner, runs this)"
        );
    }
    let acct = repo
        .get("owner")
        .ok_or_else(|| anyhow!("repository has no owner"))?;
    let id = acct
        .get("id")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("repository owner has no id"))?;
    let login = acct
        .get("login")
        .and_then(Value::as_str)
        .unwrap_or(owner)
        .to_string();
    Ok(RepoFacts {
        owner: owner.into(),
        name: name.into(),
        personal: acct.get("type").and_then(Value::as_str) == Some("User"),
        account: ForgeAccount::new(id, login),
    })
}

fn account(v: &Value, what: &str) -> Result<ForgeAccount> {
    let id = v
        .get("id")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("{what}: no id"))?;
    let login = v
        .get("login")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{what}: no login"))?;
    Ok(ForgeAccount::new(id, login))
}

/// The owners the guard is chosen from: the person running this (on a
/// personal repository, the account holder — the only admin one can have)
/// plus each `--code-owner`, counted once per account id.
///
/// On an organisation repository fewer than two owners is refused unless
/// `solo`: with no owner review, any other member with write access could
/// edit the workflow in the pull request it judges.
pub fn owners(
    gh: &Gh,
    facts: &RepoFacts,
    code_owners: &[String],
    solo: bool,
) -> Result<Vec<ForgeAccount>> {
    let mut out: Vec<ForgeAccount> = Vec::new();
    let mut add = |a: ForgeAccount| {
        if !out.iter().any(|o| o.id == a.id) {
            out.push(a);
        }
    };
    if facts.personal {
        add(facts.account.clone());
    } else {
        let me = gh
            .get("user")?
            .ok_or_else(|| anyhow!("could not read your GitHub account"))?;
        add(account(&me, "your account")?);
    }
    for login in code_owners {
        let v = gh
            .get(&path(&["users", login]))?
            .ok_or_else(|| anyhow!("no GitHub account `{login}`"))?;
        add(account(&v, login)?);
    }
    if !facts.personal && out.len() < 2 && !solo {
        bail!(
            "{}/{} belongs to an organisation and you are its only owner here. With one owner \
             only the check is required and no one has to review workflow changes, so any other \
             member with write access could edit .github/workflows/verify-trust.yml in the very \
             pull request it judges. Name another owner with --code-owner <login> (two or more \
             owners require a code owner's review of .github/), or pass --solo to accept that",
            facts.owner,
            facts.name
        );
    }
    Ok(out)
}

/// The adapter's own plan for this repository under `guard`.
pub fn plan(spec: &RepoSpec, cfg: &VgiConfig, guard: &CheckGuard) -> Result<Vec<BootstrapStep>> {
    Ok(github_plan(spec, cfg, DEFAULT_CHECKOUT_ACTION, guard)?)
}

/// Run `steps` in order, check-then-apply, stopping at the first failure
/// (as the bridge does: the ruleset must never land before the workflow).
pub fn apply(
    gh: &Gh,
    facts: &RepoFacts,
    steps: &[BootstrapStep],
    report: &mut Report,
) -> Result<()> {
    let (o, n) = (facts.owner.as_str(), facts.name.as_str());
    for step in steps {
        let id = step.id.as_str();
        match &step.action {
            StepAction::WriteFile {
                path: p,
                contents,
                message,
            } => {
                let change = write_file(gh, o, n, p, contents, message, report.dry_run())?;
                report.step(id, p, change, Some(&String::from_utf8_lossy(contents)));
            }
            StepAction::RemoveFile { path: p, message } => {
                let change = remove_file(gh, o, n, p, message, report.dry_run())?;
                report.step(id, p, change, None);
            }
            StepAction::RemoveVariable { name } => {
                let url = path(&["repos", o, n, "actions", "variables", name]);
                let change = match gh.get(&url)? {
                    None => Change::Unchanged,
                    Some(_) => {
                        if !report.dry_run() {
                            gh.send("DELETE", &url, None)?;
                        }
                        Change::Remove
                    }
                };
                report.step(id, &format!("variable {name}"), change, None);
            }
            StepAction::RequireOwnerReview {
                paths,
                owners,
                community_rules,
                message,
            } => {
                let (target, contents) = codeowners(gh, o, n, paths, owners, community_rules)?;
                let change = write_file(
                    gh,
                    o,
                    n,
                    &target,
                    contents.as_bytes(),
                    message,
                    report.dry_run(),
                )?;
                report.step(id, &target, change, Some(&contents));
            }
            StepAction::ProtectDefaultBranch(spec) => {
                let (change, body) = protect(gh, o, n, spec, report.dry_run())?;
                report.step(
                    id,
                    &format!("ruleset \"{RULESET_NAME}\""),
                    change,
                    Some(&serde_json::to_string_pretty(&body)?),
                );
            }
            other => bail!(
                "step `{id}` ({other:?}) needs the community's bridge; `vgi repo init` runs the \
                 manual-mode plan only"
            ),
        }
    }
    Ok(())
}

fn contents_path(owner: &str, name: &str, file: &str) -> String {
    let mut segs = vec!["repos", owner, name, "contents"];
    segs.extend(file.split('/'));
    path(&segs)
}

/// The file at `file` on the default branch: its blob sha and bytes.
fn read_file(gh: &Gh, owner: &str, name: &str, file: &str) -> Result<Option<(String, Vec<u8>)>> {
    vgi_forge::validate_repo_path(file)?;
    let Some(v) = gh.get(&contents_path(owner, name, file))? else {
        return Ok(None);
    };
    if v.is_array() || v.get("type").and_then(Value::as_str) != Some("file") {
        bail!("`{file}` exists in {owner}/{name} and is not a file");
    }
    if v.get("encoding").and_then(Value::as_str) != Some("base64") {
        bail!(
            "`{file}` in {owner}/{name} is too large for GitHub to return inline; it was not \
             written by the bootstrap — remove or rename it"
        );
    }
    let compact: String = v
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let bytes = STANDARD
        .decode(compact)
        .with_context(|| format!("`{file}`: content is not base64"))?;
    let sha = v
        .get("sha")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("`{file}`: no blob sha"))?;
    Ok(Some((sha.to_string(), bytes)))
}

fn write_file(
    gh: &Gh,
    owner: &str,
    name: &str,
    file: &str,
    contents: &[u8],
    message: &str,
    dry_run: bool,
) -> Result<Change> {
    let existing = read_file(gh, owner, name, file)?;
    let change = match &existing {
        Some((_, current)) if current == contents => return Ok(Change::Unchanged),
        Some(_) => Change::Update,
        None => Change::Create,
    };
    if dry_run {
        return Ok(change);
    }
    let mut body = json!({ "message": message, "content": STANDARD.encode(contents) });
    if let Some((sha, _)) = &existing {
        body["sha"] = json!(sha);
    }
    gh.send("PUT", &contents_path(owner, name, file), Some(&body))
        .map_err(|e| {
            e.context(format!(
                "writing `{file}` — if the default branch is already protected, this file can \
                 only change through a pull request (the ruleset has no bypass actors, by design)"
            ))
        })?;
    Ok(change)
}

fn remove_file(
    gh: &Gh,
    owner: &str,
    name: &str,
    file: &str,
    message: &str,
    dry_run: bool,
) -> Result<Change> {
    let Some((sha, _)) = read_file(gh, owner, name, file)? else {
        return Ok(Change::Unchanged);
    };
    if !dry_run {
        let body = json!({ "message": message, "sha": sha });
        gh.send("DELETE", &contents_path(owner, name, file), Some(&body))?;
    }
    Ok(Change::Remove)
}

/// The `CODEOWNERS` to write and where, as the adapter's owner-review step
/// renders it: an existing file keeps its place and its own rules, the
/// managed block last, naming each owner by the login their numeric id has
/// now.
fn codeowners(
    gh: &Gh,
    owner: &str,
    name: &str,
    paths: &[String],
    owners: &[ForgeAccount],
    community_rules: &[u8],
) -> Result<(String, String)> {
    let mut logins: Vec<String> = Vec::new();
    for o in owners {
        let v = gh
            .get(&path(&["user", &o.id.to_string()]))?
            .ok_or_else(|| anyhow!("GitHub account {} ({}) no longer exists", o.id, o.login))?;
        let login = account(&v, &o.login)?.login;
        if !logins.contains(&login) {
            logins.push(login);
        }
    }
    let mut found = None;
    for loc in CODEOWNERS_LOCATIONS {
        if let Some((_, bytes)) = read_file(gh, owner, name, loc)? {
            let text = String::from_utf8(bytes).map_err(|_| anyhow!("`{loc}` is not UTF-8"))?;
            found = Some((loc.to_string(), text));
            break;
        }
    }
    let (target, community) = match found {
        Some(f) => f,
        None => (
            CODEOWNERS_PATH.to_string(),
            String::from_utf8(community_rules.to_vec())
                .map_err(|_| anyhow!("community CODEOWNERS is not UTF-8"))?,
        ),
    };
    let mut managed = paths.to_vec();
    if !target.starts_with(".github/") {
        managed.push(format!("/{target}"));
    }
    Ok((
        target.clone(),
        render_codeowners(&community, &managed, &logins),
    ))
}

/// Converge the managed ruleset to `spec`, the check pinned to GitHub
/// Actions. Returns the change and the body GitHub is (or would be) sent.
fn protect(
    gh: &Gh,
    owner: &str,
    name: &str,
    spec: &ProtectionSpec,
    dry_run: bool,
) -> Result<(Change, Value)> {
    let actions_id = if spec.require_status_check {
        let app = gh
            .get("apps/github-actions")?
            .ok_or_else(|| anyhow!("GitHub has no `github-actions` app on this host"))?;
        Some(
            app.get("id")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow!("the GitHub Actions app has no id"))?,
        )
    } else {
        None
    };
    let body = ruleset_body(spec, actions_id);
    let list_path = format!(
        "{}?includes_parents=false&per_page=100",
        path(&["repos", owner, name, "rulesets"])
    );
    let list = gh.get(&list_path)?.unwrap_or(Value::Array(Vec::new()));
    let existing = list
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r.get("name").and_then(Value::as_str) == Some(RULESET_NAME))
        .and_then(|r| r.get("id").and_then(Value::as_u64));
    match existing {
        Some(rid) => {
            let one = path(&["repos", owner, name, "rulesets", &rid.to_string()]);
            let rs = gh
                .get(&one)?
                .ok_or_else(|| anyhow!("ruleset {rid} vanished while being read"))?;
            if ruleset_satisfies(&rs, None, actions_id, spec)? {
                return Ok((Change::Unchanged, body));
            }
            if !dry_run {
                gh.send("PUT", &one, Some(&body))?;
            }
            Ok((Change::Update, body))
        }
        None => {
            if !dry_run {
                gh.send(
                    "POST",
                    &path(&["repos", owner, name, "rulesets"]),
                    Some(&body),
                )?;
            }
            Ok((Change::Create, body))
        }
    }
}

/// A one-line description of `guard` for the report. `personal`: the
/// repository belongs to a user account rather than an organisation.
pub fn describe(guard: &CheckGuard, personal: bool) -> String {
    match guard {
        CheckGuard::OwnerReview { owners } => format!(
            "owner review — changes under .github/ need an approving review from one of {}",
            owners
                .iter()
                .map(|o| format!("@{}", o.login))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        CheckGuard::SoloOwner if personal => {
            "solo owner — the ruleset requires the check; no review of workflow changes is \
             required, so a collaborator with write access could edit the workflow in a pull \
             request (add --code-owner <login> for a second owner)"
                .into()
        }
        CheckGuard::SoloOwner => "solo owner (--solo) — the ruleset requires the check; no review \
                                  of workflow changes is required, so any organisation member \
                                  with write access could edit the workflow in the pull request \
                                  it judges"
            .into(),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segments_cannot_become_placeholders_or_paths() {
        assert_eq!(segment("{owner}"), "%7Bowner%7D");
        assert_eq!(segment("a/b"), "a%2Fb");
        assert_eq!(segment("widgets.rs"), "widgets.rs");
        assert_eq!(
            path(&["repos", "acme", "w", "contents", ".github", "CODEOWNERS"]),
            "repos/acme/w/contents/.github/CODEOWNERS"
        );
    }

    #[test]
    fn include_output_is_split() {
        let r = parse_include(b"HTTP/2.0 404 Not Found\r\nA: b\r\n\r\n{\"message\":\"Not Found\"}")
            .unwrap();
        assert_eq!(r.status, 404);
        assert_eq!(r.message(), "Not Found");
        let r = parse_include(b"HTTP/2.0 204 No Content\n\n").unwrap();
        assert_eq!(r.status, 204);
        assert_eq!(r.json().unwrap(), Value::Null);
        assert!(
            parse_include(b"gh: To get started with GitHub CLI, please run: gh auth login")
                .is_none()
        );
    }

    #[test]
    fn the_body_goes_on_stdin_and_the_path_last() {
        let argv = Gh::new("github.com").argv("PUT", "repos/a/b/contents/x", true);
        assert_eq!(argv.last().unwrap(), "repos/a/b/contents/x");
        let i = argv.iter().position(|a| a == "--input").unwrap();
        assert_eq!(argv[i + 1], "-");
        assert!(
            !argv
                .iter()
                .any(|a| a.starts_with("-f") || a.starts_with("--raw-field"))
        );
    }
}
