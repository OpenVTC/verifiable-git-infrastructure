//! `vgi repo init` on GitHub, against a fake `gh` on `PATH` that records
//! every argument vector and request body and answers from canned replies.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use vgi_forge::{ForgeAccount, ProtectionSpec, RepoSpec, Resource, StepAction, VgiConfig};
use vgi_forge_github::plan::{
    CheckGuard, KEYRING_PATH, WORKFLOW_PATH, github_plan, render_workflow,
};
use vgi_forge_github::{DEFAULT_CHECKOUT_ACTION, ruleset_body};

const VTC: &str = "did:webvh:QmVtc:vtc.acme.example";
const REGISTRY: &str = "did:webvh:QmReg:registry.acme.example";
const ACTION: &str = "OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@0123456789abcdef0123456789abcdef01234567";
const VERSION: &str = "v0.4.14";
const KEYRING: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQENBFmUaEEBCACzXTDt\n-----END PGP PUBLIC KEY BLOCK-----\n";
const ACTIONS_APP: u64 = 15368;

/// The fake: `$FAKE_GH_STATE/calls/NNNN/{argv,stdin}` per call; a reply for
/// `<METHOD> <path>` is `responses/<key>` (first line the status, the rest
/// the body). Unknown GETs are 404, unknown changes 200 `{}`.
const FAKE_GH: &str = r#"#!/bin/sh
state="$FAKE_GH_STATE"
mkdir -p "$state/calls" "$state/responses"
n=$(ls "$state/calls" | wc -l | tr -d ' ')
dir="$state/calls/$(printf '%04d' $((n + 1)))"
mkdir -p "$dir"
: > "$dir/argv"
for a in "$@"; do printf '%s\n' "$a" >> "$dir/argv"; done
method=GET; input=0; prev=""; path=""
for a in "$@"; do
  [ "$prev" = "--method" ] && method="$a"
  [ "$prev" = "--input" ] && [ "$a" = "-" ] && input=1
  prev="$a"; path="$a"
done
[ $input = 1 ] && cat > "$dir/stdin"
key=$(printf '%s %s' "$method" "$path" | tr '/?&= ' '_____')
if [ -f "$state/responses/$key" ]; then
  status=$(head -n 1 "$state/responses/$key")
  printf 'HTTP/2.0 %s X\r\nContent-Type: application/json\r\n\r\n' "$status"
  tail -n +2 "$state/responses/$key"
  case "$status" in 2*) exit 0 ;; *) exit 1 ;; esac
fi
case "$method" in
  GET) printf 'HTTP/2.0 404 Not Found\r\n\r\n{"message":"Not Found"}'; exit 1 ;;
  *) printf 'HTTP/2.0 200 OK\r\n\r\n{}'; exit 0 ;;
esac
"#;

struct Fake {
    _tmp: tempfile::TempDir,
    bin: PathBuf,
    state: PathBuf,
    keyring: PathBuf,
}

#[derive(Debug)]
struct Call {
    argv: Vec<String>,
    stdin: Option<Value>,
}

impl Call {
    fn method(&self) -> &str {
        let i = self.argv.iter().position(|a| a == "--method").unwrap();
        &self.argv[i + 1]
    }
    fn path(&self) -> &str {
        self.argv.last().unwrap()
    }
}

impl Fake {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        let state = tmp.path().join("state");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(state.join("responses")).unwrap();
        let gh = bin.join("gh");
        std::fs::write(&gh, FAKE_GH).unwrap();
        std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).unwrap();
        let keyring = tmp.path().join("web-flow.asc");
        std::fs::write(&keyring, KEYRING).unwrap();
        Fake {
            _tmp: tmp,
            bin,
            state,
            keyring,
        }
    }

    fn respond(&self, method: &str, path: &str, status: u16, body: &Value) {
        let key: String = format!("{method} {path}")
            .chars()
            .map(|c| if "/?&= ".contains(c) { '_' } else { c })
            .collect();
        std::fs::write(
            self.state.join("responses").join(key),
            format!("{status}\n{body}"),
        )
        .unwrap();
    }

    fn reset_calls(&self) {
        let _ = std::fs::remove_dir_all(self.state.join("calls"));
    }

    fn calls(&self) -> Vec<Call> {
        let dir = self.state.join("calls");
        let mut names: Vec<_> = match std::fs::read_dir(&dir) {
            Ok(rd) => rd.map(|e| e.unwrap().path()).collect(),
            Err(_) => return Vec::new(),
        };
        names.sort();
        names
            .into_iter()
            .map(|d| Call {
                argv: std::fs::read_to_string(d.join("argv"))
                    .unwrap()
                    .lines()
                    .map(str::to_string)
                    .collect(),
                stdin: std::fs::read(d.join("stdin"))
                    .ok()
                    .map(|b| serde_json::from_slice(&b).unwrap()),
            })
            .collect()
    }

    fn changes(&self) -> Vec<Call> {
        self.calls()
            .into_iter()
            .filter(|c| c.method() != "GET")
            .collect()
    }

    fn vgi(&self, extra: &[&str]) -> Output {
        self.vgi_for("github.com/alice/gadgets", extra)
    }

    fn vgi_for(&self, resource: &str, extra: &[&str]) -> Output {
        let path = format!(
            "{}:{}",
            self.bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut args = vec![
            "repo",
            "init",
            "--vtc",
            VTC,
            "--resource",
            resource,
            "--registry",
            REGISTRY,
            "--verify-trust-action",
            ACTION,
            "--verify-trust-version",
            VERSION,
            "--platform-keyring",
            self.keyring.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        Command::new(env!("CARGO_BIN_EXE_vgi"))
            .args(&args)
            .env("PATH", path)
            .env("FAKE_GH_STATE", &self.state)
            .current_dir(self.state.parent().unwrap())
            .output()
            .unwrap()
    }
}

fn cfg() -> VgiConfig {
    VgiConfig::new(REGISTRY, VTC, ACTION, VERSION).with_platform_keyring(KEYRING)
}

fn personal_repo(fake: &Fake, owner: &str, kind: &str, id: u64) {
    fake.respond(
        "GET",
        &format!("repos/{owner}/gadgets"),
        200,
        &json!({
            "name": "gadgets",
            "default_branch": "main",
            "owner": { "login": owner, "id": id, "type": kind },
            "permissions": { "admin": true },
        }),
    );
    fake.respond(
        "GET",
        "apps/github-actions",
        200,
        &json!({ "id": ACTIONS_APP }),
    );
}

fn stdout(o: &Output) -> String {
    assert!(
        o.status.success(),
        "vgi failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8(o.stdout.clone()).unwrap()
}

fn content_of(call: &Call) -> Vec<u8> {
    let c = call.stdin.as_ref().unwrap()["content"].as_str().unwrap();
    STANDARD.decode(c).unwrap()
}

/// What GitHub would answer after `changes` landed: each written file
/// readable, the ruleset listed and readable.
fn converge(fake: &Fake, changes: &[Call], owner: &str) {
    for c in changes {
        let body = c.stdin.clone().unwrap_or(Value::Null);
        match c.method() {
            "PUT" if c.path().contains("/contents/") => fake.respond(
                "GET",
                c.path(),
                200,
                &json!({
                    "type": "file",
                    "sha": "b10b",
                    "encoding": "base64",
                    // GitHub wraps base64 at 60 columns.
                    "content": body["content"].as_str().unwrap().as_bytes()
                        .chunks(60).map(|l| String::from_utf8_lossy(l).into_owned())
                        .collect::<Vec<_>>().join("\n"),
                }),
            ),
            "POST" if c.path().ends_with("/rulesets") => {
                fake.respond(
                    "GET",
                    &format!("repos/{owner}/gadgets/rulesets?includes_parents=false&per_page=100"),
                    200,
                    &json!([{ "id": 7, "name": body["name"] }]),
                );
                let mut rs = body.clone();
                rs["id"] = json!(7);
                rs["current_user_can_bypass"] = json!("never");
                fake.respond(
                    "GET",
                    &format!("repos/{owner}/gadgets/rulesets/7"),
                    200,
                    &rs,
                );
            }
            other => panic!("unexpected change {other} {}", c.path()),
        }
    }
}

#[test]
fn a_personal_repository_gets_the_adapters_files_and_ruleset_then_nothing_changes() {
    let fake = Fake::new();
    personal_repo(&fake, "alice", "User", 1001);

    let out = stdout(&fake.vgi(&["--owner", "did:web:alice.example"]));
    let changes = fake.changes();
    let summary: Vec<(String, String)> = changes
        .iter()
        .map(|c| (c.method().to_string(), c.path().to_string()))
        .collect();
    assert_eq!(
        summary,
        vec![
            (
                "PUT".into(),
                format!("repos/alice/gadgets/contents/{WORKFLOW_PATH}")
            ),
            (
                "PUT".into(),
                format!("repos/alice/gadgets/contents/{KEYRING_PATH}")
            ),
            ("POST".into(), "repos/alice/gadgets/rulesets".into()),
        ]
    );

    // Byte-for-byte the adapter's output.
    let steps = github_plan(
        &RepoSpec::new(Resource::parse("github.com/alice/gadgets").unwrap()),
        &cfg(),
        DEFAULT_CHECKOUT_ACTION,
        &CheckGuard::SoloOwner,
    )
    .unwrap();
    let StepAction::WriteFile {
        contents, message, ..
    } = &steps[0].action
    else {
        panic!()
    };
    assert_eq!(&content_of(&changes[0]), contents);
    assert_eq!(
        content_of(&changes[0]),
        render_workflow(
            &cfg(),
            DEFAULT_CHECKOUT_ACTION,
            &Resource::parse("github.com/alice/gadgets").unwrap()
        )
        .into_bytes()
    );
    // Namespace-wide rights are published at the namespace.
    assert!(
        String::from_utf8(content_of(&changes[0]))
            .unwrap()
            .contains("fallback-resource: github.com/")
    );
    assert_eq!(
        changes[0].stdin.as_ref().unwrap()["message"],
        json!(message)
    );
    assert!(changes[0].stdin.as_ref().unwrap().get("sha").is_none());
    assert_eq!(content_of(&changes[1]), KEYRING.as_bytes());
    assert_eq!(
        changes[2].stdin.as_ref().unwrap(),
        &ruleset_body(
            &ProtectionSpec::standard("Verify commit trust"),
            Some(ACTIONS_APP)
        )
    );

    // Hardened argv: gh api, the host, the body on stdin, the path last.
    for c in fake.calls() {
        assert_eq!(&c.argv[..3], ["api", "--hostname", "github.com"]);
        assert!(c.argv.contains(&"--include".to_string()));
        if c.method() != "GET" {
            let i = c.argv.iter().position(|a| a == "--input").unwrap();
            assert_eq!(c.argv[i + 1], "-");
        }
        assert!(!c.path().contains('{') && !c.path().starts_with('-'));
    }

    assert!(out.contains("solo owner"), "{out}");
    assert!(out.contains("cnm git adopt github.com/alice/gadgets --owner did:web:alice.example"));
    assert!(out.contains("VTA session"), "{out}");

    // Re-run against the converged repository: reads only.
    converge(&fake, &changes, "alice");
    fake.reset_calls();
    let out = stdout(&fake.vgi(&[]));
    assert!(fake.changes().is_empty(), "{:?}", fake.changes());
    assert!(out.contains("Nothing to change"), "{out}");
    assert!(out.contains("--owner <owner-did>"), "{out}");
}

#[test]
fn dry_run_prints_every_change_and_makes_none() {
    let fake = Fake::new();
    personal_repo(&fake, "alice", "User", 1001);
    let out = stdout(&fake.vgi(&["--dry-run"]));
    assert!(fake.changes().is_empty(), "{:?}", fake.changes());
    assert!(out.contains("dry run"), "{out}");
    assert!(out.contains("[would create] workflow"), "{out}");
    assert!(out.contains("[would create] keyring"), "{out}");
    assert!(out.contains("[would create] ruleset"), "{out}");
    assert!(
        out.contains("[unchanged   ] cleanup:variable:VTC_DID"),
        "{out}"
    );
    // The workflow's own lines, and the ruleset body.
    assert!(
        out.contains(&format!("      |           vtc-did: '{VTC}'")),
        "{out}"
    );
    assert!(out.contains("\"integration_id\": 15368"), "{out}");
    assert!(out.contains("3 change(s) would be made"), "{out}");
}

#[test]
fn stale_variables_are_removed_and_a_drifted_ruleset_is_rewritten() {
    let fake = Fake::new();
    personal_repo(&fake, "alice", "User", 1001);
    let first = {
        stdout(&fake.vgi(&[]));
        fake.changes()
    };
    converge(&fake, &first, "alice");
    // Someone added a bypass actor and the old variables are still there.
    let mut rs = ruleset_body(
        &ProtectionSpec::standard("Verify commit trust"),
        Some(ACTIONS_APP),
    );
    rs["id"] = json!(7);
    rs["bypass_actors"] =
        json!([{ "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" }]);
    fake.respond("GET", "repos/alice/gadgets/rulesets/7", 200, &rs);
    fake.respond(
        "GET",
        "repos/alice/gadgets/actions/variables/VTC_DID",
        200,
        &json!({ "name": "VTC_DID", "value": "did:web:old" }),
    );
    fake.reset_calls();
    stdout(&fake.vgi(&[]));
    let summary: Vec<(String, String)> = fake
        .changes()
        .iter()
        .map(|c| (c.method().to_string(), c.path().to_string()))
        .collect();
    assert_eq!(
        summary,
        vec![
            ("PUT".into(), "repos/alice/gadgets/rulesets/7".into()),
            (
                "DELETE".into(),
                "repos/alice/gadgets/actions/variables/VTC_DID".into()
            ),
        ]
    );
}

#[test]
fn two_owners_get_the_managed_codeowners_and_a_code_owner_review() {
    let fake = Fake::new();
    personal_repo(&fake, "acme", "Organization", 9);
    // The person running this counts as an owner too.
    runner(&fake);
    fake.respond("GET", "users/bob", 200, &json!({ "id": 2, "login": "bob" }));
    fake.respond(
        "GET",
        "users/carol",
        200,
        &json!({ "id": 3, "login": "carol" }),
    );
    fake.respond("GET", "user/2", 200, &json!({ "id": 2, "login": "bob" }));
    fake.respond("GET", "user/3", 200, &json!({ "id": 3, "login": "Carol" }));
    let out = fake.vgi_for(
        "github.com/acme/gadgets",
        &["--code-owner", "bob", "--code-owner", "carol"],
    );
    let text = stdout(&out);
    assert!(text.contains("owner review"), "{text}");
    let changes = fake.changes();
    let codeowners = changes
        .iter()
        .find(|c| c.path() == "repos/acme/gadgets/contents/.github/CODEOWNERS")
        .expect("CODEOWNERS written");
    let expected = vgi_forge_github::plan::render_codeowners(
        "",
        &["/.github/".to_string()],
        &["root".to_string(), "bob".to_string(), "Carol".to_string()],
    );
    assert_eq!(content_of(codeowners), expected.as_bytes());
    let rules = changes
        .iter()
        .find(|c| c.path().ends_with("/rulesets"))
        .unwrap();
    let owners = vec![
        ForgeAccount::new(1, "root"),
        ForgeAccount::new(2, "bob"),
        ForgeAccount::new(3, "carol"),
    ];
    let steps = github_plan(
        &RepoSpec::new(Resource::parse("github.com/acme/gadgets").unwrap()),
        &cfg(),
        DEFAULT_CHECKOUT_ACTION,
        &CheckGuard::OwnerReview { owners },
    )
    .unwrap();
    let spec = steps
        .iter()
        .find_map(|s| match &s.action {
            StepAction::ProtectDefaultBranch(p) => Some(p.clone()),
            _ => None,
        })
        .unwrap();
    assert!(spec.require_code_owner_review);
    assert_eq!(
        rules.stdin.as_ref().unwrap(),
        &ruleset_body(&spec, Some(ACTIONS_APP))
    );
}

/// The person running `vgi`: `root`, id 1.
fn runner(fake: &Fake) {
    fake.respond("GET", "user", 200, &json!({ "id": 1, "login": "root" }));
    fake.respond("GET", "user/1", 200, &json!({ "id": 1, "login": "root" }));
}

#[test]
fn an_organisation_repository_with_one_owner_is_refused_without_solo() {
    let fake = Fake::new();
    personal_repo(&fake, "acme", "Organization", 9);
    runner(&fake);
    let out = fake.vgi_for("github.com/acme/gadgets", &[]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--solo"), "{err}");
    assert!(err.contains("--code-owner"), "{err}");
    assert!(err.contains("write access"), "{err}");
    assert!(fake.changes().is_empty(), "{:?}", fake.changes());

    // Naming yourself does not make a second owner.
    fake.respond(
        "GET",
        "users/root",
        200,
        &json!({ "id": 1, "login": "root" }),
    );
    let out = fake.vgi_for("github.com/acme/gadgets", &["--code-owner", "root"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--solo"));
    assert!(fake.changes().is_empty(), "{:?}", fake.changes());
}

#[test]
fn an_organisation_repository_with_solo_gets_the_check_only() {
    let fake = Fake::new();
    personal_repo(&fake, "acme", "Organization", 9);
    runner(&fake);
    let text = stdout(&fake.vgi_for("github.com/acme/gadgets", &["--solo"]));
    assert!(text.contains("solo owner (--solo)"), "{text}");
    assert!(text.contains("organisation member"), "{text}");
    assert!(!text.contains("no one else"), "{text}");
    let changes = fake.changes();
    assert!(
        !changes.iter().any(|c| c.path().ends_with("CODEOWNERS")),
        "{changes:?}"
    );
    let rules = changes
        .iter()
        .find(|c| c.path().ends_with("/rulesets"))
        .unwrap();
    assert_eq!(
        rules.stdin.as_ref().unwrap(),
        &ruleset_body(
            &ProtectionSpec::standard("Verify commit trust"),
            Some(ACTIONS_APP)
        )
    );
    // --solo and --code-owner contradict each other.
    let out = fake.vgi_for(
        "github.com/acme/gadgets",
        &["--solo", "--code-owner", "bob"],
    );
    assert!(!out.status.success());
}

#[test]
fn one_code_owner_and_the_runner_are_two_owners() {
    let fake = Fake::new();
    personal_repo(&fake, "acme", "Organization", 9);
    runner(&fake);
    fake.respond("GET", "users/bob", 200, &json!({ "id": 2, "login": "bob" }));
    fake.respond("GET", "user/2", 200, &json!({ "id": 2, "login": "bob" }));
    let text = stdout(&fake.vgi_for("github.com/acme/gadgets", &["--code-owner", "bob"]));
    assert!(text.contains("owner review"), "{text}");
    assert!(text.contains("@root, @bob"), "{text}");
}

#[test]
fn a_missing_repository_names_the_command_that_creates_it() {
    let fake = Fake::new();
    let out = fake.vgi(&[]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("gh repo create alice/gadgets"), "{err}");
    assert!(fake.changes().is_empty());
}

#[test]
fn bad_dids_are_refused_before_anything_runs() {
    let fake = Fake::new();
    let out = fake.vgi(&["--owner", "did:web:x;rm -rf ~"]);
    assert!(!out.status.success());
    assert!(fake.calls().is_empty());
}
