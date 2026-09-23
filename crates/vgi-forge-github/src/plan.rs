//! GitHub's bootstrap plan (§5.3) and the files it commits.
//!
//! The order is load-bearing: the workflow, keyring and community files go
//! in first, then the variables, then the ruleset. The ruleset has no bypass
//! actors — the bridge included — so after it exists every change to the
//! default branch goes through a pull request and the check.

use vgi_forge::{
    BootstrapComponent, BootstrapStep, ForgeError, ProtectionSpec, RepoSpec, Result, StepAction,
    VgiConfig, validate_repo_path,
};

/// Where the workflow is committed.
pub const WORKFLOW_PATH: &str = ".github/workflows/verify-trust.yml";
/// Where the exempt platform keyring is committed.
pub const KEYRING_PATH: &str = ".github/trusted-platform-keys.asc";
/// Name of the ruleset the adapter manages. Found by name on re-runs.
pub const RULESET_NAME: &str = "VGI commit trust";
/// Registry DID variable.
pub const VAR_REGISTRY: &str = "TRUST_REGISTRY_DID";
/// VTC DID variable.
pub const VAR_VTC: &str = "VTC_DID";

/// Build the plan. Validates everything that ends up in a file or a
/// variable, so a bad config fails here rather than half-way through.
pub fn github_plan(
    repo: &RepoSpec,
    cfg: &VgiConfig,
    checkout_action: &str,
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

    let mut steps = vec![
        BootstrapStep::new(
            "workflow",
            BootstrapComponent::Workflow,
            StepAction::WriteFile {
                path: WORKFLOW_PATH.into(),
                contents: render_workflow(cfg, checkout_action).into_bytes(),
                message: "ci: add the VGI commit-trust check".into(),
            },
        ),
        BootstrapStep::new(
            "keyring",
            BootstrapComponent::Keyring,
            StepAction::WriteFile {
                path: KEYRING_PATH.into(),
                contents: keyring.to_vec(),
                message: "ci: add the exempt platform keyring for web-flow merges".into(),
            },
        ),
    ];
    for file in &cfg.extra_files {
        validate_repo_path(&file.path)?;
        if file.path == WORKFLOW_PATH || file.path == KEYRING_PATH {
            return Err(ForgeError::Config(format!(
                "extra file `{}` would overwrite a file the bootstrap manages",
                file.path
            )));
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
    for (name, value) in [
        (VAR_REGISTRY, &cfg.trust_registry_did),
        (VAR_VTC, &cfg.vtc_did),
    ] {
        steps.push(BootstrapStep::new(
            format!("variable:{name}"),
            BootstrapComponent::Variables,
            StepAction::SetVariable {
                name: name.into(),
                value: value.clone(),
            },
        ));
    }
    steps.push(BootstrapStep::new(
        "ruleset",
        BootstrapComponent::RequiredCheck,
        StepAction::ProtectDefaultBranch(ProtectionSpec::standard(cfg.required_check.clone())),
    ));
    Ok(steps)
}

/// The workflow. Differs from the dormant one in the runbook in one way:
/// there is no `if: vars.TRUST_REGISTRY_DID != ''` guard. The bridge sets
/// the variables itself, and a *skipped* required job counts as passing —
/// so with the guard, deleting a variable would silently turn the check
/// off. Without it, a missing variable fails the check, closed.
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
          registry-did: ${{{{ vars.TRUST_REGISTRY_DID }}}}
          vtc-did: ${{{{ vars.VTC_DID }}}}
          resource-format: qualified
          # GitHub web-UI merge/squash commits are PGP-signed by web-flow;
          # they pass only via this committed keyring.
          exempt-keyring: {keyring}
          version: {version}
"#,
        job_name = yaml_single_quoted(&cfg.required_check),
        checkout = checkout_action,
        action = cfg.verify_trust_action,
        keyring = KEYRING_PATH,
        version = cfg.verify_trust_version,
    )
}

fn yaml_single_quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn check_did(field: &str, did: &str) -> Result<()> {
    let ok = did.starts_with("did:")
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
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----\n",
        )
    }

    fn spec() -> RepoSpec {
        RepoSpec::new(Resource::parse("github.com/acme/gadgets").unwrap())
    }

    #[test]
    fn the_plan_is_files_then_variables_then_ruleset() {
        let plan = github_plan(
            &spec(),
            &cfg().with_extra_file("CODEOWNERS", "* @acme/owners\n"),
            crate::config::DEFAULT_CHECKOUT_ACTION,
        )
        .unwrap();
        let ids: Vec<_> = plan.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "workflow",
                "keyring",
                "file:CODEOWNERS",
                "variable:TRUST_REGISTRY_DID",
                "variable:VTC_DID",
                "ruleset"
            ]
        );
    }

    #[test]
    fn the_workflow_is_pinned_qualified_and_unguarded() {
        let wf = render_workflow(&cfg(), crate::config::DEFAULT_CHECKOUT_ACTION);
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
        let checkout = crate::config::DEFAULT_CHECKOUT_ACTION;
        let mut c = cfg();
        c.verify_trust_action =
            "OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@v0.5.0".into();
        assert!(
            github_plan(&spec(), &c, checkout)
                .unwrap_err()
                .to_string()
                .contains("pinned")
        );

        let mut c = cfg();
        c.platform_keyring = None;
        assert!(
            github_plan(&spec(), &c, checkout)
                .unwrap_err()
                .to_string()
                .contains("web-flow")
        );

        let c = cfg().with_platform_keyring("-----BEGIN PGP PRIVATE KEY BLOCK-----");
        assert!(
            github_plan(&spec(), &c, checkout)
                .unwrap_err()
                .to_string()
                .contains("PRIVATE")
        );

        let mut c = cfg();
        c.vtc_did = "did:web:x\n  evil: true".into();
        assert!(github_plan(&spec(), &c, checkout).is_err());

        let mut c = cfg();
        c.verify_trust_version = "v1\nx".into();
        assert!(github_plan(&spec(), &c, checkout).is_err());

        let c = cfg().with_extra_file("../x", "");
        assert!(github_plan(&spec(), &c, checkout).is_err());
        let c = cfg().with_extra_file(WORKFLOW_PATH, "");
        assert!(github_plan(&spec(), &c, checkout).is_err());

        assert!(github_plan(&spec(), &cfg(), "actions/checkout@v4").is_err());
        let ns = RepoSpec::new(Resource::parse("github.com/acme").unwrap());
        assert!(github_plan(&ns, &cfg(), checkout).is_err());
    }
}
