//! Structural regression gate for the two CI findings of SEC-4045: the
//! composite action interpolated `${{ inputs.* }}` straight into its `run:`
//! script, and the workflows referenced actions by mutable tag.
//!
//! Both were fixed by changing the *shape* of the YAML — values moved into
//! `env:`, refs replaced by commit SHAs — so the gate asks questions about the
//! YAML tree rather than about the file's text:
//!
//! 1. no `${{ }}` expression appears inside any `run:` scalar;
//! 2. every `uses:` names a 40-hex commit SHA.
//!
//! It is a parser, not a grep, for a concrete reason: the fix for the injection
//! left a comment in `.github/actions/verify-trust/action.yml` explaining that
//! `${{ }}` must not appear in a script body. A text search reports that
//! comment — and every input description that mentions an expression — as a
//! finding. A YAML comment is not part of any scalar, so anchoring on the tree
//! ignores prose and sees only what GitHub will actually substitute. The
//! reverse also holds: a `${{ }}` inside a *shell* comment in a `run:` block is
//! substituted before bash ever reads it, and the tree-walk catches it.
//!
//! [`the_checks_flag_a_reintroduced_injection_and_ignore_prose`] pins both
//! halves of that down against an inline fixture, so the gate cannot rot into
//! a check that passes because it looks at nothing.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use yaml_rust2::{Yaml, YamlLoader};

/// What the audit found, over every definition file it read.
#[derive(Default)]
struct Audit {
    /// Files parsed, by repo-relative path.
    files: Vec<String>,
    /// `run:` scalars examined. Zero means the walk stopped working.
    run_scalars: usize,
    /// `uses:` scalars examined. Zero means the walk stopped working.
    uses_scalars: usize,
    /// One entry per `${{ }}` found inside a `run:` scalar.
    injections: Vec<String>,
    /// One entry per `uses:` that is not pinned to a commit SHA.
    unpinned: Vec<String>,
}

impl Audit {
    fn report(findings: &[String]) -> String {
        let mut out = String::new();
        for finding in findings {
            let _ = write!(out, "\n  - {finding}");
        }
        out
    }
}

// --- locating the definitions ------------------------------------------------

/// The repository root: the first ancestor of this crate holding `.github`.
fn repo_root() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        if dir.join(".github").is_dir() {
            return dir;
        }
        assert!(
            dir.pop(),
            "no ancestor of {} contains a .github directory",
            env!("CARGO_MANIFEST_DIR")
        );
    }
}

/// Every YAML file under `dir`, recursively, sorted for a stable report.
fn yaml_files_under(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    if !dir.is_dir() {
        return found;
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| e.expect("directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            found.extend(yaml_files_under(&path));
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yml" | "yaml")
        ) {
            found.push(path);
        }
    }
    found
}

/// Read and audit every workflow and every composite action in the repository.
///
/// `.github/actions/` is covered as well as `.github/workflows/`: the injection
/// was in a composite action, which is where a `run:` script is most exposed
/// because its inputs come from whoever calls it.
fn audit_repository() -> Audit {
    let root = repo_root();
    let mut audit = Audit::default();
    let mut paths = yaml_files_under(&root.join(".github/workflows"));
    paths.extend(yaml_files_under(&root.join(".github/actions")));

    for path in paths {
        let label = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .display()
            .to_string();
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        audit_document(&label, &text, &mut audit);
    }
    audit
}

/// Parse one definition file and walk its tree into `audit`.
fn audit_document(label: &str, text: &str, audit: &mut Audit) {
    let docs = YamlLoader::load_from_str(text)
        .unwrap_or_else(|e| panic!("{label} is not parseable YAML: {e}"));
    audit.files.push(label.to_string());
    for doc in &docs {
        walk(doc, label, "", audit);
    }
}

// --- the tree walk -----------------------------------------------------------

/// Visit `node`, checking every `run:` and `uses:` scalar beneath it.
///
/// `trail` is the position in the tree, rendered the way a reader would address
/// it (`jobs.test.steps[5]`), so a failure names the file, the job and the step
/// without the walk needing to know what a job or a step is. That also means
/// the walk covers shapes the workflow schema grows later — reusable-workflow
/// `jobs.<id>.uses`, composite-action steps, anything nested — rather than only
/// the two it was written against.
fn walk(node: &Yaml, file: &str, trail: &str, audit: &mut Audit) {
    match node {
        Yaml::Hash(hash) => {
            // A step's `name:` is how a person refers to it in the run log, so
            // it goes in the message alongside the structural position.
            let step_name = hash
                .get(&Yaml::String("name".to_string()))
                .and_then(Yaml::as_str)
                .map(|n| format!(" (\"{n}\")"))
                .unwrap_or_default();

            for (key, value) in hash {
                let Some(key) = key.as_str() else {
                    continue;
                };
                let here = if trail.is_empty() {
                    key.to_string()
                } else {
                    format!("{trail}.{key}")
                };
                if let Some(scalar) = value.as_str() {
                    let at = format!("{file}: {here}{step_name}");
                    match key {
                        "run" => {
                            audit.run_scalars += 1;
                            check_run(scalar, &at, audit);
                        }
                        "uses" => {
                            audit.uses_scalars += 1;
                            check_uses(scalar, &at, audit);
                        }
                        _ => {}
                    }
                }
                walk(value, file, &here, audit);
            }
        }
        Yaml::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                walk(item, file, &format!("{trail}[{index}]"), audit);
            }
        }
        _ => {}
    }
}

/// A `run:` script must contain no `${{ }}`.
///
/// GitHub substitutes an expression into the script as text before any shell
/// parses it, so an input holding `$(…)` or a backtick becomes a command. The
/// fix is to bind the value in `env:` and reference it as a quoted variable,
/// which keeps it data whatever it contains.
fn check_run(script: &str, at: &str, audit: &mut Audit) {
    let mut rest = script;
    while let Some(start) = rest.find("${{") {
        let expression = match rest[start..].find("}}") {
            Some(end) => &rest[start..start + end + 2],
            // Unterminated: report what there is rather than dropping it.
            None => &rest[start..],
        };
        audit.injections.push(format!(
            "{at}: `run:` interpolates {expression} — bind it in `env:` and \
             reference it as a quoted shell variable instead"
        ));
        rest = &rest[start + 3..];
    }
}

/// A `uses:` must name a 40-hex commit SHA.
///
/// A tag or branch is whatever the action's owner points it at today, so a
/// workflow holding `contents: write` or an OIDC token would run code chosen
/// after review. Only a local path is exempt: `./…` resolves inside this
/// repository, at the commit being tested. Anything else — including a
/// `docker://` image without a digest — has to fail and be looked at.
fn check_uses(reference: &str, at: &str, audit: &mut Audit) {
    if reference.starts_with("./") || reference.starts_with("../") {
        return;
    }
    let pinned = reference.rsplit_once('@').is_some_and(|(_, git_ref)| {
        git_ref.len() == 40 && git_ref.bytes().all(|b| b.is_ascii_hexdigit())
    });
    if !pinned {
        audit.unpinned.push(format!(
            "{at}: `uses: {reference}` is not pinned — give it the 40-hex commit \
             SHA of the release, with the version in a trailing comment"
        ));
    }
}

// --- the gates ---------------------------------------------------------------

#[test]
fn no_expression_is_interpolated_into_a_run_script() {
    let audit = audit_repository();
    assert!(
        audit.injections.is_empty(),
        "{} `run:` script(s) interpolate a GitHub expression:{}",
        audit.injections.len(),
        Audit::report(&audit.injections)
    );
}

#[test]
fn every_action_reference_is_pinned_to_a_commit_sha() {
    let audit = audit_repository();
    assert!(
        audit.unpinned.is_empty(),
        "{} action reference(s) are not pinned to a commit SHA:{}",
        audit.unpinned.len(),
        Audit::report(&audit.unpinned)
    );
}

/// Both gates above pass when they find nothing, so this asserts they found
/// something: the definition files exist, both directories contribute, and the
/// walk reached real `run:` and `uses:` scalars. Without it, renaming
/// `.github/workflows` or breaking the walk would turn the gates green.
#[test]
fn the_audit_reads_every_workflow_and_action_definition() {
    let audit = audit_repository();

    let workflows = audit
        .files
        .iter()
        .filter(|f| f.starts_with(".github/workflows/"))
        .count();
    let actions = audit
        .files
        .iter()
        .filter(|f| f.starts_with(".github/actions/"))
        .count();

    assert!(
        workflows > 0,
        "no workflow was read; files seen: {:?}",
        audit.files
    );
    assert!(
        actions > 0,
        "no composite action was read; files seen: {:?}",
        audit.files
    );
    assert!(
        audit.run_scalars > 0,
        "the walk found no `run:` scalar in {} file(s), so the injection check \
         examined nothing",
        audit.files.len()
    );
    assert!(
        audit.uses_scalars > 0,
        "the walk found no `uses:` scalar in {} file(s), so the pinning check \
         examined nothing",
        audit.files.len()
    );
}

/// The gate must fire on a reintroduced injection and stay quiet on prose about
/// one. An earlier string-matching check in this programme reported the
/// explanatory comment below as a finding; the marker appears four times here
/// outside a script, and once inside one.
#[test]
fn the_checks_flag_a_reintroduced_injection_and_ignore_prose() {
    let fixture = r#"
name: fixture
inputs:
  range:
    # Never paste ${{ inputs.range }} into a script body.
    description: "A range. Do not interpolate ${{ inputs.range }} into run:."
    default: ${{ github.repository }}
runs:
  using: composite
  steps:
    - name: Safe
      env:
        VT_RANGE: ${{ inputs.range }}
      run: |
        # A shell comment, and a shell variable, are both fine.
        verify-trust --range "$VT_RANGE"
    - name: Unsafe
      run: verify-trust --range "${{ inputs.range }}"
    - name: Pinned
      uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
    - name: Local
      uses: ./.github/actions/verify-trust
    - name: Floating
      uses: actions/checkout@v7
"#;

    let mut audit = Audit::default();
    audit_document("fixture.yml", fixture, &mut audit);

    assert_eq!(
        audit.injections.len(),
        1,
        "exactly the one script-body expression must be reported:{}",
        Audit::report(&audit.injections)
    );
    let injection = &audit.injections[0];
    assert!(
        injection.contains("\"Unsafe\""),
        "the finding must name the offending step: {injection}"
    );
    assert!(
        injection.contains("${{ inputs.range }}"),
        "the finding must quote the expression: {injection}"
    );

    assert_eq!(
        audit.unpinned.len(),
        1,
        "exactly the floating tag must be reported:{}",
        Audit::report(&audit.unpinned)
    );
    assert!(
        audit.unpinned[0].contains("\"Floating\""),
        "the finding must name the offending step: {}",
        audit.unpinned[0]
    );

    // Two `run:` and three `uses:` were examined, so neither check passed by
    // looking at nothing.
    assert_eq!(audit.run_scalars, 2);
    assert_eq!(audit.uses_scalars, 3);
}
