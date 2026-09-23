//! GitHub's bootstrap plan (§5.3) and the files it commits.
//!
//! The order is load-bearing: files go in first, then the variables, then
//! the protection. The ruleset has no bypass actors — the bridge included —
//! so after it exists every change to the default branch goes through a pull
//! request and the check.
//!
//! **The pull request must not be able to satisfy its own check** (§9). A
//! `pull_request` workflow runs from the pull request's own files, so the
//! plan takes one of two guards, chosen per namespace ([`CheckGuard`]):
//!
//! - [`CheckGuard::RequiredWorkflow`] (organisations with org rulesets): the
//!   check is not committed to the repository at all. It lives in the
//!   bridge-managed `<org>/.vgi` repository and an org ruleset requires it
//!   at a **pinned commit**, so nothing in the pull request changes what
//!   runs. The DIDs and the exempt keyring are written into that workflow,
//!   not read from the repository under test.
//! - Elsewhere (personal accounts, organisations without org rulesets) the
//!   workflow is committed to the repository, with the DIDs as literals:
//!   - [`CheckGuard::OwnerReview`], two or more owners: `CODEOWNERS` makes
//!     every change under `.github/` — the workflow, the keyring,
//!     `CODEOWNERS` itself — need another owner's approving review, which
//!     the ruleset requires (dismissed by later pushes, never the last
//!     pusher's own).
//!   - [`CheckGuard::SoloOwner`], one owner: no review requirement, only the
//!     check. The owner could weaken their own workflow; accepted (the
//!     user's decision), since they control the repository anyway.
//!
//!   In both, repository writers are trusted not to forge a "Verify commit
//!   trust" check run from a workflow on another branch; only the required
//!   workflow closes that.

use vgi_forge::{
    BootstrapComponent, BootstrapStep, ForgeAccount, ForgeError, ProtectionSpec, RepoSpec, Result,
    StepAction, VgiConfig, validate_repo_path,
};

/// Where the workflow is committed (in the repository, or in `.vgi`).
pub const WORKFLOW_PATH: &str = ".github/workflows/verify-trust.yml";
/// Where the exempt platform keyring is committed.
pub const KEYRING_PATH: &str = ".github/trusted-platform-keys.asc";
/// Where the managed code-owner rules are committed. GitHub reads
/// `.github/CODEOWNERS` ahead of `CODEOWNERS` and `docs/CODEOWNERS`.
pub const CODEOWNERS_PATH: &str = ".github/CODEOWNERS";
/// Every place GitHub looks for a `CODEOWNERS` file; the first one found is
/// the only one used.
pub const CODEOWNERS_LOCATIONS: [&str; 3] = [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"];
/// The paths owner review guards: everything a workflow run reads from the
/// repository under test to decide how to check it.
pub const GUARDED_PATH: &str = "/.github/";
/// Name of the ruleset the adapter manages. Found by name on re-runs.
pub const RULESET_NAME: &str = "VGI commit trust";
/// Name of the org ruleset that requires the namespace workflow.
pub const ORG_RULESET_NAME: &str = "VGI required workflow";
/// The bridge-managed repository in an organisation that holds the required
/// workflow. Public, so the workflow may run on repositories of any
/// visibility (a private source repository's workflow may run only on
/// private repositories); it holds nothing secret.
pub const CENTRAL_REPO: &str = ".vgi";
/// Registry DID variable.
pub const VAR_REGISTRY: &str = "TRUST_REGISTRY_DID";
/// VTC DID variable.
pub const VAR_VTC: &str = "VTC_DID";

/// How the plan keeps the pull request away from its own check (§9).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckGuard {
    /// An org ruleset requires the workflow in `<org>/.vgi` at a pinned
    /// commit.
    RequiredWorkflow,
    /// Two or more owners: `CODEOWNERS` names them for `.github/`, and the
    /// ruleset requires one approval — a code owner's, not the last
    /// pusher's, dismissed by later pushes.
    OwnerReview {
        /// Who may approve workflow changes. At least two.
        owners: Vec<ForgeAccount>,
    },
    /// Exactly one owner: no review requirement, only the required check.
    /// The owner could weaken their own workflow — accepted, since they
    /// control the repository anyway (the user's decision). Re-plan when a
    /// second owner arrives.
    SoloOwner,
}

impl CheckGuard {
    /// The guard for a repository with these (linked) owners, outside a
    /// required-workflow namespace. Duplicate ids count once.
    pub fn for_owners(owners: &[ForgeAccount]) -> CheckGuard {
        let mut distinct: Vec<ForgeAccount> = Vec::new();
        for o in owners {
            if !distinct.iter().any(|d| d.id == o.id) {
                distinct.push(o.clone());
            }
        }
        if distinct.len() == 1 {
            CheckGuard::SoloOwner
        } else {
            CheckGuard::OwnerReview { owners: distinct }
        }
    }
}

/// Build the plan. Validates everything that ends up in a file or a
/// variable, so a bad config fails here rather than half-way through.
pub fn github_plan(
    repo: &RepoSpec,
    cfg: &VgiConfig,
    checkout_action: &str,
    guard: &CheckGuard,
) -> Result<Vec<BootstrapStep>> {
    if repo.resource.is_namespace() {
        return Err(ForgeError::WrongResource {
            resource: repo.resource.to_string(),
            expected: "a repository, not a namespace".into(),
        });
    }
    check_did("trust_registry_did", &cfg.trust_registry_did)?;
    check_did("vtc_did", &cfg.vtc_did)?;
    check_pinned("checkout action", checkout_action)?;
    check_pinned("verify-trust action", &cfg.verify_trust_action)?;
    check_version(&cfg.verify_trust_version)?;
    check_check_name(&cfg.required_check)?;
    let keyring = cfg.platform_keyring.as_deref().ok_or_else(|| {
        ForgeError::Config(
            "no platform keyring: GitHub web-UI merges are signed by `web-flow`, and without its \
             key in the exempt keyring every merge commit fails the check. Supply it in the \
             config (for github.com, the contents of https://github.com/web-flow.gpg)"
                .into(),
        )
    })?;
    check_keyring(keyring)?;

    let mut steps = Vec::new();
    if !matches!(guard, CheckGuard::RequiredWorkflow) {
        steps.push(BootstrapStep::new(
            "workflow",
            BootstrapComponent::Workflow,
            StepAction::WriteFile {
                path: WORKFLOW_PATH.into(),
                contents: render_workflow(cfg, checkout_action).into_bytes(),
                message: "ci: add the VGI commit-trust check".into(),
            },
        ));
        steps.push(BootstrapStep::new(
            "keyring",
            BootstrapComponent::Keyring,
            StepAction::WriteFile {
                path: KEYRING_PATH.into(),
                contents: keyring.to_vec(),
                message: "ci: add the exempt platform keyring for web-flow merges".into(),
            },
        ));
    }

    let mut community_owners: Option<&[u8]> = None;
    for file in &cfg.extra_files {
        validate_repo_path(&file.path)?;
        if file.path == WORKFLOW_PATH || file.path == KEYRING_PATH {
            return Err(ForgeError::Config(format!(
                "extra file `{}` would overwrite a file the bootstrap manages",
                file.path
            )));
        }
        if matches!(guard, CheckGuard::OwnerReview { .. })
            && CODEOWNERS_LOCATIONS.contains(&file.path.as_str())
        {
            // The managed `.github/CODEOWNERS` would shadow a community one
            // anywhere else (GitHub reads only the first it finds), so the
            // community's rules are folded into it instead, ahead of the
            // managed rule.
            if community_owners.replace(&file.contents).is_some() {
                return Err(ForgeError::Config(
                    "more than one CODEOWNERS among the extra files; GitHub would use only one"
                        .into(),
                ));
            }
            continue;
        }
        steps.push(BootstrapStep::new(
            format!("file:{}", file.path),
            BootstrapComponent::Extra,
            StepAction::WriteFile {
                path: file.path.clone(),
                contents: file.contents.clone(),
                message: format!("chore: add {}", file.path),
            },
        ));
    }

    match guard {
        CheckGuard::RequiredWorkflow => {
            check_embeddable_keyring(keyring)?;
            steps.push(BootstrapStep::new(
                "required-workflow",
                BootstrapComponent::Workflow,
                StepAction::RequireNamespaceWorkflow {
                    contents: render_required_workflow(cfg, checkout_action, keyring)?.into_bytes(),
                    check: cfg.required_check.clone(),
                    message: "ci: pin the VGI commit-trust check".into(),
                },
            ));
            steps.push(BootstrapStep::new(
                "ruleset",
                BootstrapComponent::RequiredCheck,
                StepAction::ProtectDefaultBranch(
                    ProtectionSpec::standard(cfg.required_check.clone())
                        .with_check_enforced_by_namespace(),
                ),
            ));
            // A repository that had the owner-review guard before its org
            // gained org rulesets: its own workflow, keyring and variables
            // are no longer what runs. The ruleset step above already drops
            // its status-check rule.
            steps.extend(cleanup_variables());
            for (id, path) in [
                ("cleanup:workflow", WORKFLOW_PATH),
                ("cleanup:keyring", KEYRING_PATH),
            ] {
                steps.push(BootstrapStep::new(
                    id,
                    BootstrapComponent::Extra,
                    StepAction::RemoveFile {
                        path: path.into(),
                        message: "ci: the VGI check now runs as the org's required workflow".into(),
                    },
                ));
            }
        }
        CheckGuard::OwnerReview { owners } => {
            if owners.len() < 2 {
                return Err(ForgeError::Config(format!(
                    "`{}`: owner review needs at least two owners with linked GitHub accounts \
                     (one owner is a solo repository, none cannot be planned)",
                    repo.resource
                )));
            }
            let community_rules = community_owners.map(<[u8]>::to_vec).unwrap_or_default();
            if std::str::from_utf8(&community_rules).is_err() {
                return Err(ForgeError::Config(
                    "community CODEOWNERS is not UTF-8".into(),
                ));
            }
            steps.push(BootstrapStep::new(
                "codeowners",
                BootstrapComponent::Workflow,
                StepAction::RequireOwnerReview {
                    paths: vec![GUARDED_PATH.into()],
                    owners: owners.clone(),
                    community_rules,
                    message: "ci: require an owner's review for workflow changes".into(),
                },
            ));
            steps.push(BootstrapStep::new(
                "ruleset",
                BootstrapComponent::RequiredCheck,
                StepAction::ProtectDefaultBranch(
                    ProtectionSpec::standard(cfg.required_check.clone()).with_code_owner_review(),
                ),
            ));
            steps.extend(cleanup_variables());
        }
        CheckGuard::SoloOwner => {
            steps.push(BootstrapStep::new(
                "ruleset",
                BootstrapComponent::RequiredCheck,
                StepAction::ProtectDefaultBranch(ProtectionSpec::standard(
                    cfg.required_check.clone(),
                )),
            ));
            steps.extend(cleanup_variables());
        }
    }
    Ok(steps)
}

/// The DIDs are literals in the workflow now (a repository variable could
/// be changed by any repository admin, and overrides an org one): the old
/// variables are removed so nothing suggests they still matter.
fn cleanup_variables() -> Vec<BootstrapStep> {
    [VAR_REGISTRY, VAR_VTC]
        .into_iter()
        .map(|name| {
            BootstrapStep::new(
                format!("cleanup:variable:{name}"),
                BootstrapComponent::Variables,
                StepAction::RemoveVariable { name: name.into() },
            )
        })
        .collect()
}

/// First line of the managed block in a `CODEOWNERS` file.
pub const MANAGED_BEGIN: &str = "# BEGIN VGI managed owner rules";
/// Last line of the managed block.
pub const MANAGED_END: &str = "# END VGI managed owner rules";

/// A `CODEOWNERS` file: `community_rules` (the file's own rules, the managed
/// block removed), then the managed block last, so it wins for `paths` (the
/// last matching pattern takes precedence). `logins` are resolved from
/// numeric ids at run time.
pub fn render_codeowners(community_rules: &str, paths: &[String], logins: &[String]) -> String {
    let mut out = String::new();
    let community = strip_managed(community_rules);
    if !community.trim().is_empty() {
        out.push_str(community.trim_end());
        out.push_str("\n\n");
    }
    out.push_str(MANAGED_BEGIN);
    out.push_str(
        "\n# Kept last by this community's VGI bridge: every change to the repository's\n\
         # workflows (and to this file) needs another owner's approving review, so the\n\
         # commit-trust check is not editable by the pull request it checks.\n",
    );
    let owners: Vec<String> = logins.iter().map(|l| format!("@{l}")).collect();
    for p in paths {
        out.push_str(&format!("{p} {}\n", owners.join(" ")));
    }
    out.push_str(MANAGED_END);
    out.push('\n');
    out
}

/// `text` without the managed block (so re-rendering keeps only the
/// community's own rules).
pub fn strip_managed(text: &str) -> String {
    let mut out = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        match line.trim() {
            l if l == MANAGED_BEGIN => inside = true,
            l if l == MANAGED_END && inside => inside = false,
            _ if inside => {}
            _ => out.push(line),
        }
    }
    let mut s = out.join("\n");
    if !s.is_empty() {
        s.push('\n');
    }
    s
}

/// The managed block of a `CODEOWNERS` file, if it is there and nothing but
/// comments follows it: `(pattern, owners, 1-based line)` per rule.
pub fn managed_rules(text: &str) -> Option<Vec<(String, Vec<String>, usize)>> {
    let lines: Vec<&str> = text.lines().collect();
    let begin = lines.iter().rposition(|l| l.trim() == MANAGED_BEGIN)?;
    let end = begin
        + lines[begin..]
            .iter()
            .position(|l| l.trim() == MANAGED_END)?;
    let is_rule = |l: &&str| {
        let t = l.trim();
        !t.is_empty() && !t.starts_with('#')
    };
    if lines[end + 1..].iter().any(is_rule) {
        return None;
    }
    let rules = lines[begin + 1..end]
        .iter()
        .enumerate()
        .filter(|(_, l)| is_rule(l))
        .map(|(i, l)| {
            let mut parts = l.split('#').next().unwrap_or("").split_whitespace();
            let pattern = parts.next().unwrap_or("").to_string();
            (pattern, parts.map(str::to_string).collect(), begin + 2 + i)
        })
        .collect();
    Some(rules)
}

/// The workflow committed to the repository (outside a required-workflow
/// namespace). Differs from the dormant one in the runbook: there is no
/// `if: vars.TRUST_REGISTRY_DID != ''` guard (a *skipped* required job
/// counts as passing), and the DIDs are literals rather than `vars.*`,
/// which any repository admin could change.
pub fn render_workflow(cfg: &VgiConfig, checkout_action: &str) -> String {
    format!(
        r#"# Managed by this community's VGI bridge. It is rewritten on bootstrap;
# propose changes to the VTC rather than editing it here.
name: verify-trust

on:
  pull_request:
  # A merge queue runs required checks on its own merge commits; without
  # this trigger the check never reports there and queued merges stall.
  merge_group:

# Reads the repository and downloads a public release; writes nothing.
permissions:
  contents: read

jobs:
  verify:
    name: {job_name}
    runs-on: ubuntu-latest
    steps:
      - uses: {checkout}
        with:
          # The base ref must be present so `origin/<base>..HEAD` resolves.
          fetch-depth: 0
          persist-credentials: false

      - name: verify-trust
        uses: {action}
        with:
          # merge_group events have no base_ref; the queue names its base
          # commit instead.
          range: ${{{{ github.event_name == 'merge_group' && github.event.merge_group.base_sha || format('origin/{{0}}', github.base_ref) }}}}..HEAD
          # Literals, not `vars.*`: repository variables are any
          # repository admin's to change.
          registry-did: {registry}
          vtc-did: {vtc}
          resource-format: qualified
          # GitHub web-UI merge/squash commits are PGP-signed by web-flow;
          # they pass only via this committed keyring.
          exempt-keyring: {keyring}
          version: {version}
"#,
        job_name = yaml_single_quoted(&cfg.required_check),
        checkout = checkout_action,
        action = cfg.verify_trust_action,
        registry = yaml_single_quoted(&cfg.trust_registry_did),
        vtc = yaml_single_quoted(&cfg.vtc_did),
        keyring = KEYRING_PATH,
        version = cfg.verify_trust_version,
    )
}

/// The required workflow held in `<org>/.vgi`. It runs in the context of
/// the repository under test (its `GITHUB_REPOSITORY`, its pull request),
/// but everything that decides *how* to check is fixed here, at the pinned
/// commit:
///
/// - the DIDs are literals, not `vars.*` — a repository variable overrides
///   an organisation one of the same name, and repository admins set those;
/// - the exempt keyring is written from this file to the runner's temp
///   directory, not read from the repository, where the pull request could
///   add its own key to it.
pub fn render_required_workflow(
    cfg: &VgiConfig,
    checkout_action: &str,
    keyring: &[u8],
) -> Result<String> {
    let keyring = std::str::from_utf8(keyring)
        .map_err(|_| ForgeError::Config("platform keyring is not ASCII armor".into()))?;
    let mut block = String::new();
    for line in keyring.lines() {
        if line.is_empty() {
            block.push('\n');
        } else {
            block.push_str("            ");
            block.push_str(line);
            block.push('\n');
        }
    }
    Ok(format!(
        r#"# Managed by this community's VGI bridge, and required on the community's
# repositories by the org ruleset "{ruleset}" at a pinned commit. A change
# here takes effect only when the bridge pins it; propose changes to the VTC.
name: verify-trust

on:
  pull_request:
  # A merge queue runs required workflows on its own merge commits; without
  # this trigger the check never reports there and queued merges stall.
  merge_group:

# Reads the repository and downloads a public release; writes nothing.
permissions:
  contents: read

jobs:
  verify:
    name: {job_name}
    runs-on: ubuntu-latest
    steps:
      - uses: {checkout}
        with:
          # The base ref must be present so `origin/<base>..HEAD` resolves.
          fetch-depth: 0
          persist-credentials: false

      # GitHub web-UI merge/squash commits are PGP-signed by web-flow and pass
      # only via this keyring. It is part of this pinned file, not of the
      # repository under test, which a pull request could edit.
      - name: exempt platform keyring
        env:
          VGI_PLATFORM_KEYRING: |
{keyring}        run: printf '%s' "$VGI_PLATFORM_KEYRING" > "$RUNNER_TEMP/vgi-platform-keys.asc"

      - name: verify-trust
        uses: {action}
        with:
          # merge_group events have no base_ref; the queue names its base
          # commit instead.
          range: ${{{{ github.event_name == 'merge_group' && github.event.merge_group.base_sha || format('origin/{{0}}', github.base_ref) }}}}..HEAD
          # Literals, not `vars.*`: a repository variable of the same name
          # would override an organisation one.
          registry-did: {registry}
          vtc-did: {vtc}
          resource-format: qualified
          exempt-keyring: ${{{{ runner.temp }}}}/vgi-platform-keys.asc
          version: {version}
"#,
        ruleset = ORG_RULESET_NAME,
        job_name = yaml_single_quoted(&cfg.required_check),
        checkout = checkout_action,
        keyring = block,
        action = cfg.verify_trust_action,
        registry = yaml_single_quoted(&cfg.trust_registry_did),
        vtc = yaml_single_quoted(&cfg.vtc_did),
        version = cfg.verify_trust_version,
    ))
}

fn yaml_single_quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn check_did(field: &str, did: &str) -> Result<()> {
    // `${{` would make the value an Actions expression where it is written
    // into a workflow as a literal.
    let ok = did.starts_with("did:")
        && !did.contains("${{")
        && did.len() <= 2048
        && did
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'\'' && b != b'"');
    if ok {
        Ok(())
    } else {
        Err(ForgeError::Config(format!(
            "{field} `{did}` is not a DID (expected `did:<method>:…`, no spaces or quotes)"
        )))
    }
}

/// `owner/repo[/path]@<40 hex>` — the only form the workflow will `uses:`.
fn check_pinned(what: &str, reference: &str) -> Result<()> {
    let pinned = reference.rsplit_once('@').is_some_and(|(path, sha)| {
        sha.len() == 40
            && sha.bytes().all(|b| b.is_ascii_hexdigit())
            && path.split('/').count() >= 2
            && path.split('/').all(|s| {
                !s.is_empty()
                    && s != ".."
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            })
    });
    if pinned {
        Ok(())
    } else {
        Err(ForgeError::Config(format!(
            "{what} `{reference}` must be pinned to a commit: `owner/repo[/path]@<40-hex sha>`"
        )))
    }
}

fn check_version(v: &str) -> Result<()> {
    let ok = !v.is_empty()
        && v.len() <= 64
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if ok {
        Ok(())
    } else {
        Err(ForgeError::Config(format!(
            "verify-trust version `{v}` must be a release tag like `v0.5.0` or `latest`"
        )))
    }
}

fn check_check_name(name: &str) -> Result<()> {
    // `${{` would make the job name an Actions expression.
    if name.trim().is_empty()
        || name.len() > 100
        || name.chars().any(char::is_control)
        || name.contains("${{")
    {
        return Err(ForgeError::Config(format!(
            "required check name `{name}` must be 1–100 printable characters"
        )));
    }
    Ok(())
}

fn check_keyring(bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ForgeError::Config("platform keyring is not ASCII armor".into()))?;
    if text.contains("PRIVATE KEY") {
        // Committing it would publish it.
        return Err(ForgeError::Config(
            "platform keyring contains a PRIVATE key block; supply the public key only".into(),
        ));
    }
    if !text.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----") {
        return Err(ForgeError::Config(
            "platform keyring is not an armored PGP public key block".into(),
        ));
    }
    Ok(())
}

/// The keyring is written into the required workflow as a YAML block
/// scalar inside `env:`, where Actions evaluates expressions: refuse
/// anything that could become one, or that is not plain armor text.
fn check_embeddable_keyring(bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ForgeError::Config("platform keyring is not ASCII armor".into()))?;
    // A lone `\r` is a line break to a YAML parser but not to `lines()`, so
    // it could end the block scalar early: only `\r\n` is allowed.
    let lone_cr = text
        .char_indices()
        .any(|(i, c)| c == '\r' && !text[i + 1..].starts_with('\n'));
    if text.contains("${{")
        || lone_cr
        || text
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\r')
    {
        return Err(ForgeError::Config(
            "platform keyring holds characters that cannot be embedded in the required workflow"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vgi_forge::Resource;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn cfg() -> VgiConfig {
        VgiConfig::new(
            "did:webvh:reg",
            "did:webvh:vtc",
            format!("OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@{SHA}"),
            "v0.5.0",
        )
        .with_platform_keyring(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nx\n-----END PGP PUBLIC KEY BLOCK-----\n",
        )
    }

    fn spec() -> RepoSpec {
        RepoSpec::new(Resource::parse("github.com/acme/gadgets").unwrap())
    }

    fn owner_review() -> CheckGuard {
        CheckGuard::OwnerReview {
            owners: vec![ForgeAccount::new(7, "bob"), ForgeAccount::new(9, "carol")],
        }
    }

    const CHECKOUT: &str = crate::config::DEFAULT_CHECKOUT_ACTION;

    fn ids(plan: &[BootstrapStep]) -> Vec<&str> {
        plan.iter().map(|s| s.id.as_str()).collect()
    }

    #[test]
    fn the_guard_follows_the_owner_count() {
        let bob = ForgeAccount::new(7, "bob");
        assert_eq!(
            CheckGuard::for_owners(std::slice::from_ref(&bob)),
            CheckGuard::SoloOwner
        );
        assert_eq!(
            CheckGuard::for_owners(&[bob.clone(), ForgeAccount::new(7, "bob-renamed")]),
            CheckGuard::SoloOwner,
            "one id, twice, is one owner"
        );
        assert!(matches!(
            CheckGuard::for_owners(&[bob, ForgeAccount::new(9, "carol")]),
            CheckGuard::OwnerReview { owners } if owners.len() == 2
        ));
    }

    #[test]
    fn owner_review_plans_files_then_codeowners_then_ruleset_then_cleanup() {
        let plan = github_plan(
            &spec(),
            &cfg()
                .with_extra_file("LICENSE", "MIT\n")
                .with_extra_file("CODEOWNERS", "* @acme/owners\n"),
            CHECKOUT,
            &owner_review(),
        )
        .unwrap();
        assert_eq!(
            ids(&plan),
            [
                "workflow",
                "keyring",
                "file:LICENSE",
                "codeowners",
                "ruleset",
                "cleanup:variable:TRUST_REGISTRY_DID",
                "cleanup:variable:VTC_DID",
            ]
        );
        // The community's CODEOWNERS is folded into the managed one, which
        // GitHub would otherwise read instead of it.
        let StepAction::RequireOwnerReview {
            paths,
            owners,
            community_rules,
            ..
        } = &plan[3].action
        else {
            panic!("{:?}", plan[3]);
        };
        assert_eq!(paths, &["/.github/"]);
        assert_eq!(owners.len(), 2);
        assert_eq!(community_rules, b"* @acme/owners\n");
        let StepAction::ProtectDefaultBranch(p) = &plan[4].action else {
            panic!()
        };
        assert!(p.require_code_owner_review && p.require_status_check);

        for owners in [vec![], vec![ForgeAccount::new(7, "bob")]] {
            let e = github_plan(
                &spec(),
                &cfg(),
                CHECKOUT,
                &CheckGuard::OwnerReview { owners },
            )
            .unwrap_err();
            assert!(e.to_string().contains("at least two owners"), "{e}");
        }
        let two = cfg()
            .with_extra_file("CODEOWNERS", "")
            .with_extra_file("docs/CODEOWNERS", "");
        assert!(github_plan(&spec(), &two, CHECKOUT, &owner_review()).is_err());
    }

    #[test]
    fn a_solo_repository_gets_the_check_and_no_review() {
        let plan = github_plan(
            &spec(),
            &cfg().with_extra_file("CODEOWNERS", "* @acme/owners\n"),
            CHECKOUT,
            &CheckGuard::SoloOwner,
        )
        .unwrap();
        assert_eq!(
            ids(&plan),
            [
                "workflow",
                "keyring",
                "file:CODEOWNERS",
                "ruleset",
                "cleanup:variable:TRUST_REGISTRY_DID",
                "cleanup:variable:VTC_DID",
            ]
        );
        let StepAction::ProtectDefaultBranch(p) = &plan[3].action else {
            panic!()
        };
        assert!(p.require_status_check && !p.require_code_owner_review);
    }

    #[test]
    fn required_workflow_plans_no_repo_workflow_keyring_or_variables() {
        let plan = github_plan(
            &spec(),
            &cfg().with_extra_file("CODEOWNERS", "* @acme/owners\n"),
            CHECKOUT,
            &CheckGuard::RequiredWorkflow,
        )
        .unwrap();
        assert_eq!(
            ids(&plan),
            [
                "file:CODEOWNERS",
                "required-workflow",
                "ruleset",
                "cleanup:variable:TRUST_REGISTRY_DID",
                "cleanup:variable:VTC_DID",
                "cleanup:workflow",
                "cleanup:keyring"
            ]
        );
        let StepAction::ProtectDefaultBranch(p) = &plan[2].action else {
            panic!()
        };
        assert!(!p.require_status_check && !p.require_code_owner_review);
    }

    #[test]
    fn the_required_workflow_fixes_everything_the_pr_could_touch() {
        let wf =
            render_required_workflow(&cfg(), CHECKOUT, cfg().platform_keyring.as_deref().unwrap())
                .unwrap();
        assert!(wf.contains("    name: 'Verify commit trust'\n"));
        assert!(wf.contains("  pull_request:\n") && wf.contains("  merge_group:\n"));
        assert!(wf.contains("registry-did: 'did:webvh:reg'\n"));
        assert!(wf.contains("vtc-did: 'did:webvh:vtc'\n"));
        assert!(
            !wf.contains("${{ vars"),
            "no repository-overridable variables"
        );
        assert!(wf.contains("exempt-keyring: ${{ runner.temp }}/vgi-platform-keys.asc\n"));
        assert!(
            !wf.contains(KEYRING_PATH),
            "the keyring is not read from the repo"
        );
        assert!(wf.contains(
            "          VGI_PLATFORM_KEYRING: |\n            -----BEGIN PGP PUBLIC KEY BLOCK-----\n\n            x\n            -----END PGP PUBLIC KEY BLOCK-----\n        run: "
        ));
        assert!(wf.contains("resource-format: qualified"));
        assert!(!wf.contains("if:"));

        let mut c = cfg();
        c.vtc_did = "did:x:${{github.token}}".into();
        assert!(github_plan(&spec(), &c, CHECKOUT, &CheckGuard::RequiredWorkflow).is_err());
        let c =
            cfg().with_platform_keyring("-----BEGIN PGP PUBLIC KEY BLOCK-----\n${{ secrets.X }}\n");
        assert!(github_plan(&spec(), &c, CHECKOUT, &CheckGuard::RequiredWorkflow).is_err());
        // A lone CR is a YAML line break: it could end the block scalar.
        let c = cfg().with_platform_keyring(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\rrun: evil\n-----END PGP PUBLIC KEY BLOCK-----\n",
        );
        assert!(github_plan(&spec(), &c, CHECKOUT, &CheckGuard::RequiredWorkflow).is_err());
        // CRLF armor is fine.
        let c = cfg().with_platform_keyring(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n\r\nx\r\n-----END PGP PUBLIC KEY BLOCK-----\r\n",
        );
        assert!(github_plan(&spec(), &c, CHECKOUT, &CheckGuard::RequiredWorkflow).is_ok());
    }

    #[test]
    fn codeowners_puts_the_managed_block_last_and_rerenders_stably() {
        let out = render_codeowners(
            "* @acme/owners\n",
            &["/.github/".into()],
            &["alice".into(), "bob".into()],
        );
        assert!(out.starts_with("* @acme/owners\n\n# BEGIN VGI managed owner rules\n"));
        assert!(
            out.ends_with("/.github/ @alice @bob\n# END VGI managed owner rules\n"),
            "{out}"
        );
        let rules = managed_rules(&out).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].0, "/.github/");
        assert_eq!(rules[0].1, ["@alice", "@bob"]);
        assert_eq!(
            out.lines().nth(rules[0].2 - 1),
            Some("/.github/ @alice @bob")
        );
        // Re-rendering over its own output keeps the community rules once.
        assert_eq!(
            render_codeowners(&out, &["/.github/".into()], &["alice".into(), "bob".into()]),
            out
        );
        // A rule after the block means the block no longer wins.
        assert!(managed_rules(&format!("{out}* @mallory\n")).is_none());
        assert!(managed_rules(&format!("{out}# just a comment\n")).is_some());
        assert!(managed_rules("* @acme/owners\n").is_none());
    }

    #[test]
    fn the_workflow_is_pinned_qualified_and_unguarded() {
        let wf = render_workflow(&cfg(), CHECKOUT);
        assert!(wf.contains("registry-did: 'did:webvh:reg'\n"));
        assert!(wf.contains("vtc-did: 'did:webvh:vtc'\n"));
        assert!(
            !wf.contains("${{ vars"),
            "no repository-overridable variables"
        );
        assert!(wf.contains("    name: 'Verify commit trust'\n"));
        assert!(wf.contains("resource-format: qualified"));
        assert!(wf.contains("  merge_group:\n"));
        assert!(wf.contains(
            "range: ${{ github.event_name == 'merge_group' && github.event.merge_group.base_sha \
             || format('origin/{0}', github.base_ref) }}..HEAD"
        ));
        assert!(wf.contains(&format!("verify-trust@{SHA}")));
        assert!(wf.contains("uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"));
        assert!(!wf.contains("if:"));
        let mut quoted = cfg();
        quoted.required_check = "it's".into();
        assert!(render_workflow(&quoted, "a/b@x").contains("name: 'it''s'"));
    }

    #[test]
    fn bad_config_fails_before_any_step_runs() {
        for guard in [
            owner_review(),
            CheckGuard::SoloOwner,
            CheckGuard::RequiredWorkflow,
        ] {
            let plan = |c: &VgiConfig| github_plan(&spec(), c, CHECKOUT, &guard);
            let mut c = cfg();
            c.verify_trust_action =
                "OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@v0.5.0".into();
            assert!(plan(&c).unwrap_err().to_string().contains("pinned"));

            let mut c = cfg();
            c.platform_keyring = None;
            assert!(plan(&c).unwrap_err().to_string().contains("web-flow"));

            let c = cfg().with_platform_keyring("-----BEGIN PGP PRIVATE KEY BLOCK-----");
            assert!(plan(&c).unwrap_err().to_string().contains("PRIVATE"));

            let mut c = cfg();
            c.vtc_did = "did:web:x\n  evil: true".into();
            assert!(plan(&c).is_err());

            let mut c = cfg();
            c.verify_trust_version = "v1\nx".into();
            assert!(plan(&c).is_err());

            assert!(plan(&cfg().with_extra_file("../x", "")).is_err());
            assert!(plan(&cfg().with_extra_file(WORKFLOW_PATH, "")).is_err());

            assert!(github_plan(&spec(), &cfg(), "actions/checkout@v4", &guard).is_err());
            let ns = RepoSpec::new(Resource::parse("github.com/acme").unwrap());
            assert!(github_plan(&ns, &cfg(), CHECKOUT, &guard).is_err());
        }
    }
}
