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
//! A later change made the action portable to Forgejo runners, which have no
//! `gh` and whose job token belongs to the Forgejo instance (so it must never
//! be sent to GitHub). The install now downloads anonymously with `curl`, and
//! the gate also asks:
//!
//! 3. every `curl` in a composite action is HTTPS-only (`--proto '=https'`,
//!    `--tlsv1.2`), fails on an HTTP error (`--fail`) and is never `--insecure`;
//! 4. the action's install step needs no `gh` and exports no token: the only
//!    `gh` it runs is the optional `gh attestation verify`, and no step binds
//!    `GH_TOKEN` or `GITHUB_TOKEN` for every command in its script.
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
    /// One entry per `curl` invocation examined, naming where it is.
    curls: Vec<String>,
    /// One entry per `curl` invocation missing a transport safeguard.
    weak_curls: Vec<String>,
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
                            check_curl(scalar, &at, audit);
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

/// A script's commands, with backslash-continued lines joined, so a `curl`
/// whose flags span several lines is read as the one command it is.
fn logical_lines(script: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for line in script.lines() {
        if let Some(continued) = line.trim_end().strip_suffix('\\') {
            current.push_str(continued);
            current.push(' ');
        } else {
            current.push_str(line);
            lines.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// The shell words of `line`, comment dropped, with command substitutions and
/// separators split out so that `x=$(curl …)` yields `x=` then `curl`.
fn command_words(line: &str) -> Vec<String> {
    let code = line.split_once(" #").map_or(line, |(code, _)| code);
    let code = if code.trim_start().starts_with('#') {
        ""
    } else {
        code
    };
    code.replace("$(", " ")
        .replace(['`', '(', ')', ';', '{', '}'], " ")
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

/// Positions in [`command_words`] at which `line` runs `program`, as opposed
/// to naming it: `command -v gh`, a comment, or a word in a message do not
/// count. A command word is the first word, or follows an environment
/// assignment, `||`, `&&`, `!`, `then`, `do` or `else`.
fn invocations(line: &str, program: &str) -> Vec<usize> {
    let words = command_words(line);
    (0..words.len())
        .filter(|&i| words[i] == program)
        .filter(|&i| {
            i == 0
                || words[i - 1].ends_with('=')
                || (words[i - 1].contains('=') && !words[i - 1].starts_with('-'))
                || matches!(
                    words[i - 1].as_str(),
                    "then" | "do" | "else" | "||" | "&&" | "!" | "|"
                )
        })
        .collect()
}

/// Every `curl` a script runs must be HTTPS-only (redirects included), use
/// TLS 1.2 or later, fail on an HTTP error status rather than keep the error
/// page, and never skip certificate checks.
///
/// Recorded for every file; the gate holds composite actions to it, since they
/// run on whatever runner calls them.
fn check_curl(script: &str, at: &str, audit: &mut Audit) {
    for line in logical_lines(script) {
        for _ in invocations(&line, "curl") {
            audit.curls.push(at.to_string());
            let mut missing = Vec::new();
            if !(line.contains("--proto '=https'") || line.contains("--proto =https")) {
                missing.push("--proto '=https'");
            }
            if !line.contains("--tlsv1.2") && !line.contains("--tlsv1.3") {
                missing.push("--tlsv1.2");
            }
            if !line.contains("--fail") {
                missing.push("--fail");
            }
            let insecure = command_words(&line)
                .iter()
                .any(|w| *w == "-k" || *w == "--insecure");
            if !missing.is_empty() || insecure {
                audit.weak_curls.push(format!(
                    "{at}: `{}` — missing {missing:?}{}",
                    line.trim(),
                    if insecure {
                        ", and disables certificate verification"
                    } else {
                        ""
                    }
                ));
            }
        }
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

/// A composite action runs on whatever runner calls it — including Forgejo
/// runners, where it fetches its binary anonymously from github.com — so its
/// downloads must not fall back to plain HTTP, old TLS, or a saved error page.
#[test]
fn every_curl_in_a_composite_action_is_https_only() {
    let audit = audit_repository();
    let in_actions = |f: &&String| f.starts_with(".github/actions/");

    assert!(
        audit.curls.iter().filter(in_actions).count() > 0,
        "no `curl` was found in any composite action, so this check examined \
         nothing; the action's install step downloads with curl"
    );
    let weak: Vec<String> = audit
        .weak_curls
        .iter()
        .filter(in_actions)
        .cloned()
        .collect();
    assert!(
        weak.is_empty(),
        "{} `curl` invocation(s) in composite actions lack a transport safeguard:{}",
        weak.len(),
        Audit::report(&weak)
    );
}

/// The action's step named `name`, as a YAML hash.
fn action_step(name: &str) -> Yaml {
    action_steps()
        .into_iter()
        .find(|step| step["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("action.yml has no step named {name:?}"))
}

/// The install must work where there is no `gh` and no GitHub token — a
/// Forgejo runner, whose job token belongs to the Forgejo instance and must
/// never reach GitHub. So: no `gh` on the download path, the only `gh` run is
/// the optional attestation check, and the token is handed to that command
/// alone rather than exported to the whole script.
#[test]
fn the_action_installs_without_gh_or_an_exported_token() {
    let step = action_step("Install verify-trust");
    let script = step["run"].as_str().expect("install step has a run script");

    // Every input the install reads arrives through `env:`.
    assert!(
        !script.contains("${{"),
        "the install script interpolates a GitHub expression"
    );

    let lines = logical_lines(script);
    let mut gh_runs = 0;
    for line in &lines {
        let words = command_words(line);
        for i in invocations(line, "gh") {
            gh_runs += 1;
            assert_eq!(
                words.get(i + 1..i + 3),
                Some(&["attestation".to_string(), "verify".to_string()][..]),
                "the install step runs `gh` for something other than the \
                 optional attestation check: `{}`",
                line.trim()
            );
        }
    }
    assert_eq!(
        gh_runs, 1,
        "expected exactly one `gh attestation verify`, found {gh_runs} `gh` invocation(s)"
    );
    assert!(
        lines.iter().any(|l| !invocations(l, "curl").is_empty()),
        "the install step does not download with curl"
    );

    // No ambient token: neither well-known name is bound for the step, and the
    // job token reaches only the `gh attestation verify` command line.
    for step in action_steps() {
        let env = step["env"].as_hash().cloned().unwrap_or_default();
        for key in ["GH_TOKEN", "GITHUB_TOKEN"] {
            assert!(
                !env.contains_key(&Yaml::String(key.to_string())),
                "step {:?} exports {key} to its whole script",
                step["name"].as_str()
            );
        }
    }
    let env = step["env"].as_hash().expect("install step has env");
    let token_vars: Vec<&str> = env
        .iter()
        .filter(|(_, v)| v.as_str().is_some_and(|v| v.contains("github.token")))
        .filter_map(|(k, _)| k.as_str())
        .collect();
    assert_eq!(
        token_vars,
        ["VGI_GITHUB_TOKEN"],
        "the job token must be bound once, under a name no tool reads by default"
    );
    for line in lines.iter().filter(|l| l.contains("VGI_GITHUB_TOKEN")) {
        assert!(
            line.contains("gh attestation verify"),
            "the job token is used outside the attestation check: `{}`",
            line.trim()
        );
    }
}

/// Every step of the verify-trust action.
fn action_steps() -> Vec<Yaml> {
    let path = repo_root().join(".github/actions/verify-trust/action.yml");
    let text = std::fs::read_to_string(&path).expect("read action.yml");
    let doc = YamlLoader::load_from_str(&text)
        .expect("action.yml parses")
        .remove(0);
    doc["runs"]["steps"]
        .as_vec()
        .expect("runs.steps is a list")
        .clone()
}

/// The curl and `gh` checks must see through line continuations and command
/// substitutions, and not mistake a name for a command.
#[test]
fn the_curl_check_flags_weak_downloads_and_ignores_mentions() {
    let script = r#"
# curl http://example.com is only a comment
if ! command -v curl >/dev/null; then echo "curl is required"; fi
fetch() {
  curl --fail --silent --location --proto '=https' --tlsv1.2 \
    --retry 5 "$@"
}
landed="$(curl --fail --proto '=https' --tlsv1.2 -o /dev/null https://example.com)"
body=$(curl -sSf https://example.com)
curl --fail --proto '=https' --tlsv1.2 -k https://example.com
GH_TOKEN="$T" gh attestation verify x --repo o/r
command -v gh
"#;
    let mut audit = Audit::default();
    check_curl(script, "fixture", &mut audit);
    assert_eq!(
        audit.curls.len(),
        4,
        "four curl commands are run; mentions are not:{}",
        Audit::report(&audit.curls)
    );
    assert_eq!(
        audit.weak_curls.len(),
        2,
        "the bare one and the --insecure one must be reported:{}",
        Audit::report(&audit.weak_curls)
    );
    assert!(audit.weak_curls[0].contains("body=$(curl -sSf"));
    assert!(audit.weak_curls[1].contains("certificate verification"));

    let gh: usize = logical_lines(script)
        .iter()
        .map(|l| invocations(l, "gh").len())
        .sum();
    assert_eq!(gh, 1, "only the attestation command runs gh");
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
