//! Forgejo's bootstrap plan (§5.9) and the files it commits.
//!
//! Order: merge settings first — the one step an older instance may refuse,
//! so it fails before anything is written — then the workflow (and, in the
//! signing-key fallback, the keyring), community files, the variables, and
//! last the branch protection. The protection lets nobody push and applies
//! to admins, so after it exists every change goes through a pull request,
//! the check and the merge allow-list; and it protects the workflow paths,
//! so no pull request can rewrite the check it is judged by.

use url::Url;
use vgi_forge::{
    BootstrapComponent, BootstrapStep, ForgeError, MergeMethod, ProtectionSpec, RepoSettings,
    RepoSpec, Resource, Result, StepAction, VgiConfig, validate_repo_path,
};

/// Where the workflow is committed.
pub const WORKFLOW_PATH: &str = ".forgejo/workflows/verify-trust.yml";
/// Where the exempt keyring (the instance's signing key) is committed in
/// the signing-key fallback.
pub const KEYRING_PATH: &str = ".forgejo/trusted-platform-keys.asc";
/// Registry DID variable.
pub const VAR_REGISTRY: &str = "TRUST_REGISTRY_DID";
/// VTC DID variable.
pub const VAR_VTC: &str = "VTC_DID";

/// Paths no pull request may change and still merge (Forgejo's
/// `protected_file_patterns`: `;`-separated, lowercased globs in which `*`
/// stops at `/` and `.`, hence `**`). Every directory Forgejo runs workflows
/// from — a PR that *adds* a workflow whose job reports the required
/// context would otherwise pass itself — and the exempt keyring.
pub const PROTECTED_PATHS: [&str; 4] = [
    ".forgejo/workflows/**",
    ".gitea/workflows/**",
    ".github/workflows/**",
    KEYRING_PATH,
];

/// How merge commits pass the check on this instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergePlan<'a> {
    /// Fast-forward only: the DID-signed commits land unchanged.
    FastForwardOnly,
    /// Instance-made merge commits, exempted by the instance's signing key
    /// (armored), committed as the keyring.
    SigningKey(&'a [u8]),
}

impl MergePlan<'_> {
    /// The merge methods this plan allows, the default first.
    pub fn methods(&self) -> Vec<MergeMethod> {
        match self {
            MergePlan::FastForwardOnly => vec![MergeMethod::FastForward],
            MergePlan::SigningKey(_) => vec![MergeMethod::MergeCommit],
        }
    }
}

/// Instance-specific inputs to the plan.
#[derive(Debug, Clone)]
pub struct PlanOptions<'a> {
    /// `uses:` for checkout: a full URL pinned to a commit.
    pub checkout_action: &'a str,
    /// Where a bare verify-trust reference is resolved.
    pub actions_base: &'a Url,
    /// `runs-on:`.
    pub runs_on: &'a str,
    /// The status context the protection requires.
    pub status_context: String,
    /// Write the DIDs into the workflow rather than Actions variables (the
    /// instance has no variables API).
    pub inline_variables: bool,
    /// How merges pass.
    pub merges: MergePlan<'a>,
}

/// Build the plan. Validates everything that ends up in a file, a variable
/// or the protection, so a bad config fails here rather than half-way.
pub fn forgejo_plan(
    repo: &RepoSpec,
    cfg: &VgiConfig,
    opts: &PlanOptions<'_>,
) -> Result<Vec<BootstrapStep>> {
    repo.resource.require_owner_repo()?;
    check_did("trust_registry_did", &cfg.trust_registry_did)?;
    check_did("vtc_did", &cfg.vtc_did)?;
    check_full_url_pin("checkout action", opts.checkout_action)?;
    let action = resolve_action(&cfg.verify_trust_action, opts.actions_base)?;
    check_version(&cfg.verify_trust_version)?;
    let sha256 = cfg.verify_trust_sha256.as_deref().ok_or_else(|| {
        ForgeError::Config(
            "no verify_trust_sha256: a Forgejo runner cannot verify the release's build \
             attestation, so the tarball's SHA-256 must be pinned in the workflow (see the \
             runbook's Forgejo Actions runners section for how to take it)"
                .into(),
        )
    })?;
    check_sha256(sha256)?;
    check_check_name(&cfg.required_check)?;
    check_check_name(&opts.status_context)?;
    check_runs_on(opts.runs_on)?;
    if let MergePlan::SigningKey(key) = opts.merges {
        check_keyring(key)?;
    }

    let mut steps = vec![BootstrapStep::new(
        "merge-styles",
        // On Forgejo the merge setting is what the web-flow keyring is on
        // GitHub: the reason a web merge passes the check.
        BootstrapComponent::Keyring,
        StepAction::ConfigureRepo(RepoSettings::merge_methods(opts.merges.methods())),
    )];
    steps.push(BootstrapStep::new(
        "workflow",
        BootstrapComponent::Workflow,
        StepAction::WriteFile {
            path: WORKFLOW_PATH.into(),
            contents: render_workflow(cfg, opts, &repo.resource, &action, sha256).into_bytes(),
            message: "ci: add the VGI commit-trust check".into(),
        },
    ));
    if let MergePlan::SigningKey(key) = opts.merges {
        steps.push(BootstrapStep::new(
            "keyring",
            BootstrapComponent::Keyring,
            StepAction::WriteFile {
                path: KEYRING_PATH.into(),
                contents: key.to_vec(),
                message: "ci: add the instance signing key as the exempt keyring".into(),
            },
        ));
    }
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
    if !opts.inline_variables {
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
    }
    steps.push(BootstrapStep::new(
        "protection",
        BootstrapComponent::RequiredCheck,
        StepAction::ProtectDefaultBranch(
            ProtectionSpec::standard(opts.status_context.clone())
                .with_protected_paths(PROTECTED_PATHS),
        ),
    ));
    Ok(steps)
}

/// The workflow. Like the GitHub adapter's, it has no `if:
/// vars.TRUST_REGISTRY_DID != ''` guard: a *skipped* required job reports
/// success, so with the guard, deleting a variable would silently turn the
/// check off. Without it, a missing variable fails the check, closed.
///
/// The workflow and its job both carry the check name, so the status
/// context Forgejo reports is `<name> / <name> (pull_request)`.
///
/// The namespace is the fallback resource ([`fallback_resource`]): the VTC
/// publishes namespace-wide commit rights on it, not on each repository.
pub fn render_workflow(
    cfg: &VgiConfig,
    opts: &PlanOptions<'_>,
    repo: &Resource,
    action: &str,
    sha256: &str,
) -> String {
    let name = yaml_single_quoted(&cfg.required_check);
    let (registry, vtc) = if opts.inline_variables {
        (
            yaml_single_quoted(&cfg.trust_registry_did),
            yaml_single_quoted(&cfg.vtc_did),
        )
    } else {
        (
            "${{ vars.TRUST_REGISTRY_DID }}".to_string(),
            "${{ vars.VTC_DID }}".to_string(),
        )
    };
    let keyring = match opts.merges {
        MergePlan::SigningKey(_) => format!(
            "          # Web merges are signed by the instance; they pass only via its\n          \
             # key, committed here.\n          exempt-keyring: {KEYRING_PATH}\n"
        ),
        MergePlan::FastForwardOnly => String::new(),
    };
    format!(
        r#"# Managed by this community's VGI bridge. Branch protection refuses
# pull requests that change it; the bridge updates it only through its
# audited refresh-managed-files step. Propose changes to the VTC.
name: {name}

on:
  pull_request:

permissions:
  contents: read

jobs:
  verify:
    name: {name}
    runs-on: {runs_on}
    steps:
      - uses: {checkout}
        with:
          # The base ref must be present so `origin/<base>..HEAD` resolves.
          fetch-depth: 0
          persist-credentials: false

      - name: verify-trust
        uses: {action}
        with:
          range: origin/${{{{ github.base_ref }}}}..HEAD
          registry-did: {registry}
          vtc-did: {vtc}
          resource-format: qualified
          # The namespace: where the VTC publishes namespace-wide commit rights.
          fallback-resource: {fallback}
{keyring}          # A Forgejo runner cannot check the release's attestation; the
          # pinned version and checksum are what hold if a release is replaced.
          version: {version}
          sha256: {sha256}
"#,
        runs_on = opts.runs_on,
        checkout = opts.checkout_action,
        fallback = fallback_resource(repo),
        version = cfg.verify_trust_version,
    )
}

/// The `fallback-resource` the workflow passes:
/// `<forge-host>/${{ github.repository_owner }}`.
///
/// The VTC publishes a namespace's commit rights — every `git.ns.admin`'s
/// implied `git.commit.sign`, a namespace-wide grant, the bridge's service
/// grant — on the namespace resource (`codeberg.org/acme`), and a bridge that
/// sets up a repository's check must make the namespace its fallback (git-ns
/// `right/grant` 0.1).
///
/// Exactly the repository's own namespace, never broader: the owner is the
/// one the runner runs the job for, read at run time (Forgejo Actions fills
/// the `github` context), and the host is this instance's, fixed here. The
/// value reaches verify-trust through the action's environment, never a
/// script, and verify-trust refuses a fallback that does not contain the
/// repository's own resource. It is only ever written next to
/// `resource-format: qualified`.
pub fn fallback_resource(repo: &Resource) -> String {
    format!("{}/${{{{ github.repository_owner }}}}", repo.host())
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

/// `owner/repo[/path]@<40 hex>`.
fn is_pinned_path(reference: &str) -> bool {
    reference.rsplit_once('@').is_some_and(|(path, sha)| {
        sha.len() == 40
            && sha.bytes().all(|b| b.is_ascii_hexdigit())
            && path.split('/').count() >= 2
            && path.split('/').all(|s| {
                !s.is_empty()
                    && s != ".."
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            })
    })
}

/// `https://<host>/owner/repo[/path]@<40 hex>`.
fn check_full_url_pin(what: &str, reference: &str) -> Result<()> {
    let ok = reference.strip_prefix("https://").is_some_and(|rest| {
        rest.split_once('/').is_some_and(|(host, path)| {
            !host.is_empty()
                && host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
                && is_pinned_path(path)
        })
    });
    if ok {
        Ok(())
    } else {
        Err(ForgeError::Config(format!(
            "{what} `{reference}` must be a full URL pinned to a commit: \
             `https://<host>/owner/repo[/path]@<40-hex sha>`"
        )))
    }
}

/// The verify-trust reference as the workflow must write it: a full URL,
/// since a Forgejo runner resolves a bare `owner/repo` against the
/// instance's own default actions host. A bare pinned reference (the form
/// the GitHub adapter takes from the same config) is put under `base`.
pub fn resolve_action(reference: &str, base: &Url) -> Result<String> {
    if reference.starts_with("https://") {
        check_full_url_pin("verify-trust action", reference)?;
        return Ok(reference.to_string());
    }
    if !is_pinned_path(reference) {
        return Err(ForgeError::Config(format!(
            "verify-trust action `{reference}` must be pinned to a commit: \
             `[https://<host>/]owner/repo[/path]@<40-hex sha>`"
        )));
    }
    let full = format!("{}/{reference}", base.as_str().trim_end_matches('/'));
    check_full_url_pin("verify-trust action", &full)?;
    Ok(full)
}

fn check_version(v: &str) -> Result<()> {
    let ok = !v.is_empty()
        && v != "latest"
        && v.len() <= 64
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if ok {
        Ok(())
    } else {
        Err(ForgeError::Config(format!(
            "verify-trust version `{v}` must be a release tag like `v0.5.0` — pinned, not \
             `latest`, since the checksum is pinned with it"
        )))
    }
}

fn check_sha256(s: &str) -> Result<()> {
    if s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(ForgeError::Config(format!(
            "verify_trust_sha256 `{s}` must be 64 lowercase hex digits"
        )))
    }
}

pub(crate) fn check_check_name(name: &str) -> Result<()> {
    // Forgejo matches required status contexts as glob patterns, and one
    // that does not compile is skipped — the requirement silently falls
    // away. A literal name is the only safe one.
    if crate::forge::is_glob(name) {
        return Err(ForgeError::Config(format!(
            "check name `{name}` contains a glob character (`*?[]{{}}\\`); Forgejo would \
             read the required context as a pattern"
        )));
    }
    // `${{` would make the job name an Actions expression.
    if name.trim().is_empty()
        || name.len() > 200
        || name.chars().any(char::is_control)
        || name.contains("${{")
    {
        return Err(ForgeError::Config(format!(
            "check name `{name}` must be 1–200 printable characters"
        )));
    }
    Ok(())
}

fn check_runs_on(label: &str) -> Result<()> {
    let ok = !label.is_empty()
        && label.len() <= 100
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if ok {
        Ok(())
    } else {
        Err(ForgeError::Config(format!(
            "runner label `{label}` must be letters, digits, `-`, `_` or `.`"
        )))
    }
}

pub(crate) fn check_keyring(bytes: &[u8]) -> Result<()> {
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
            "the instance's signing key is not an armored PGP public key block — does the \
             instance sign merges (`[repository.signing]`)?"
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
    const SUM: &str = "4f1c0a5e9d0b8b1f3c5f8a0d2e7b6c9a1d3e5f7a9b0c2d4e6f8a1b3c5d7e9f0a";
    const KEY: &str =
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\ninstance\n-----END PGP PUBLIC KEY BLOCK-----\n";

    fn cfg() -> VgiConfig {
        VgiConfig::new(
            "did:webvh:reg",
            "did:webvh:vtc",
            format!("OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@{SHA}"),
            "v0.5.0",
        )
        .with_verify_trust_sha256(SUM)
    }

    fn base() -> Url {
        Url::parse(crate::config::DEFAULT_ACTIONS_BASE).unwrap()
    }

    fn opts<'a>(base: &'a Url, merges: MergePlan<'static>, inline: bool) -> PlanOptions<'a> {
        PlanOptions {
            checkout_action: crate::config::DEFAULT_CHECKOUT_ACTION,
            actions_base: base,
            runs_on: "docker",
            status_context: "Verify commit trust / Verify commit trust (pull_request)".into(),
            inline_variables: inline,
            merges,
        }
    }

    fn spec() -> RepoSpec {
        RepoSpec::new(Resource::parse("codeberg.org/acme/gadgets").unwrap())
    }

    fn ids(plan: &[BootstrapStep]) -> Vec<&str> {
        plan.iter().map(|s| s.id.as_str()).collect()
    }

    #[test]
    fn the_plan_is_merges_files_variables_protection() {
        let b = base();
        let plan = forgejo_plan(
            &spec(),
            &cfg().with_extra_file("CODEOWNERS", "* @acme/owners\n"),
            &opts(&b, MergePlan::FastForwardOnly, false),
        )
        .unwrap();
        assert_eq!(
            ids(&plan),
            [
                "merge-styles",
                "workflow",
                "file:CODEOWNERS",
                "variable:TRUST_REGISTRY_DID",
                "variable:VTC_DID",
                "protection"
            ]
        );
        let StepAction::ConfigureRepo(settings) = &plan[0].action else {
            panic!()
        };
        assert_eq!(settings.merge_methods, [MergeMethod::FastForward]);
        let StepAction::ProtectDefaultBranch(p) = &plan[5].action else {
            panic!()
        };
        assert_eq!(
            p.required_check,
            "Verify commit trust / Verify commit trust (pull_request)"
        );
        assert_eq!(p.protected_paths, PROTECTED_PATHS);

        // Fallback: the keyring goes in, merge commits come out; no
        // variables API means no variable steps.
        let plan = forgejo_plan(
            &spec(),
            &cfg(),
            &opts(&b, MergePlan::SigningKey(KEY.as_bytes()), true),
        )
        .unwrap();
        assert_eq!(
            ids(&plan),
            ["merge-styles", "workflow", "keyring", "protection"]
        );
        let StepAction::ConfigureRepo(settings) = &plan[0].action else {
            panic!()
        };
        assert_eq!(settings.merge_methods, [MergeMethod::MergeCommit]);
    }

    #[test]
    fn the_workflow_is_pinned_by_full_url_qualified_and_unguarded() {
        let b = base();
        let o = opts(&b, MergePlan::FastForwardOnly, false);
        let action = resolve_action(&cfg().verify_trust_action, &b).unwrap();
        let wf = render_workflow(&cfg(), &o, &spec().resource, &action, SUM);
        assert!(wf.contains("name: 'Verify commit trust'\n"));
        assert!(wf.contains("    name: 'Verify commit trust'\n"));
        assert!(wf.contains(&format!(
            "uses: https://github.com/OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@{SHA}"
        )));
        assert!(wf.contains(&format!("uses: {}", crate::config::DEFAULT_CHECKOUT_ACTION)));
        assert!(
            wf.contains(
                "          resource-format: qualified\n          \
                 # The namespace: where the VTC publishes namespace-wide commit rights.\n          \
                 fallback-resource: codeberg.org/${{ github.repository_owner }}\n"
            ),
            "{wf}"
        );
        assert_eq!(wf.matches("fallback-resource:").count(), 1);
        assert!(wf.contains("version: v0.5.0\n"));
        assert!(wf.contains(&format!("sha256: {SUM}\n")));
        assert!(wf.contains("registry-did: ${{ vars.TRUST_REGISTRY_DID }}"));
        assert!(wf.contains("range: origin/${{ github.base_ref }}..HEAD"));
        assert!(!wf.contains("if:"));
        assert!(!wf.contains("exempt-keyring"));

        let o = opts(&b, MergePlan::SigningKey(KEY.as_bytes()), true);
        let wf = render_workflow(&cfg(), &o, &spec().resource, &action, SUM);
        assert!(wf.contains("exempt-keyring: .forgejo/trusted-platform-keys.asc\n"));
        assert!(wf.contains("registry-did: 'did:webvh:reg'"));
        assert!(wf.contains("vtc-did: 'did:webvh:vtc'"));
        assert!(!wf.contains("vars."));
    }

    #[test]
    fn the_fallback_is_the_running_repositorys_own_namespace_on_this_instance() {
        let b = base();
        let o = opts(&b, MergePlan::FastForwardOnly, false);
        let action = resolve_action(&cfg().verify_trust_action, &b).unwrap();
        let here = Resource::parse("git.example.org/acme/gadgets").unwrap();
        assert_eq!(
            fallback_resource(&here),
            "git.example.org/${{ github.repository_owner }}"
        );
        let wf = render_workflow(&cfg(), &o, &here, &action, SUM);
        assert!(
            wf.contains("fallback-resource: git.example.org/${{ github.repository_owner }}\n"),
            "{wf}"
        );
        // The same file for every repository of the namespace: nothing in
        // it names the repository or its owner.
        let other = Resource::parse("git.example.org/acme/widgets").unwrap();
        assert_eq!(wf, render_workflow(&cfg(), &o, &other, &action, SUM));
        assert!(!wf.contains("acme"));
    }

    #[test]
    fn bad_config_fails_before_any_step_runs() {
        let b = base();
        let o = opts(&b, MergePlan::FastForwardOnly, false);
        let err = |c: &VgiConfig| forgejo_plan(&spec(), c, &o).unwrap_err().to_string();

        let mut c = cfg();
        c.verify_trust_sha256 = None;
        assert!(err(&c).contains("verify_trust_sha256"));
        assert!(err(&cfg().with_verify_trust_sha256("ABC")).contains("64 lowercase hex"));
        let mut c = cfg();
        c.verify_trust_version = "latest".into();
        assert!(err(&c).contains("not `latest`"));
        let mut c = cfg();
        c.verify_trust_action =
            "OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@v1".into();
        assert!(err(&c).contains("pinned"));
        let mut c = cfg();
        c.verify_trust_action = format!("http://github.com/o/r@{SHA}");
        assert!(err(&c).contains("pinned"));
        for bad in ["Verify [trust]", "Verify *", "a{b}", "a?b", "a\\b"] {
            let mut c = cfg();
            c.required_check = bad.into();
            assert!(err(&c).contains("glob"), "{bad}");
            let mut o2 = o.clone();
            o2.status_context = format!("{bad} / x (pull_request)");
            assert!(forgejo_plan(&spec(), &cfg(), &o2).is_err(), "{bad}");
        }
        let mut c = cfg();
        c.vtc_did = "did:web:x\n  evil: true".into();
        assert!(forgejo_plan(&spec(), &c, &o).is_err());
        assert!(forgejo_plan(&spec(), &cfg().with_extra_file(WORKFLOW_PATH, ""), &o).is_err());
        assert!(forgejo_plan(&spec(), &cfg().with_extra_file("../x", ""), &o).is_err());

        let mut bad = o.clone();
        bad.checkout_action = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262";
        assert!(
            forgejo_plan(&spec(), &cfg(), &bad).is_err(),
            "checkout must be a full URL"
        );
        let mut bad = o.clone();
        bad.runs_on = "docker\nevil: 1";
        assert!(forgejo_plan(&spec(), &cfg(), &bad).is_err());
        let bad = opts(
            &b,
            MergePlan::SigningKey(b"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
            false,
        );
        assert!(
            forgejo_plan(&spec(), &cfg(), &bad)
                .unwrap_err()
                .to_string()
                .contains("PRIVATE")
        );
        let bad = opts(&b, MergePlan::SigningKey(b""), false);
        assert!(
            forgejo_plan(&spec(), &cfg(), &bad)
                .unwrap_err()
                .to_string()
                .contains("sign merges")
        );

        let ns = RepoSpec::new(Resource::parse("codeberg.org/acme").unwrap());
        assert!(forgejo_plan(&ns, &cfg(), &o).is_err());
        let deep = RepoSpec::new(Resource::parse("codeberg.org/acme/a/b").unwrap());
        assert!(forgejo_plan(&deep, &cfg(), &o).is_err());
    }
}
