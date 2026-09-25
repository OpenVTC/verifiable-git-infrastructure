//! The identity commands, run as the operator runs them.

use std::path::Path;
use std::process::{Command, Output};

const MEDIATOR: &str = "did:web:mediator.acme.example";

fn config(dir: &Path, mediator: &str) -> std::path::PathBuf {
    let path = dir.join("bridge.toml");
    std::fs::write(
        &path,
        format!(
            r#"
vtc_did = "did:webvh:QmVtc:acme-vtc.example"
trust_registry_did = "did:webvh:QmReg:registry.acme.example"
mediator_did = "{mediator}"
public_url = "https://bridge.acme.example/"
master_key_file = "{key}"
data_dir = "{data}"

[verify_trust]
action = "OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@0123456789abcdef0123456789abcdef01234567"
version = "v0.5.0"
"#,
            key = dir.join("master.key").display(),
            data = dir.join("data").display(),
        ),
    )
    .unwrap();
    path
}

fn bridge(cfg: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vgi-bridge"))
        .arg("--config")
        .arg(cfg)
        .args(args)
        .env("RUST_LOG", "error")
        .output()
        .unwrap()
}

fn stdout(o: &Output) -> String {
    assert!(
        o.status.success(),
        "exit {:?}: {}",
        o.status,
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8(o.stdout.clone())
        .unwrap()
        .trim()
        .to_string()
}

#[test]
fn init_mints_a_did_peer_naming_the_mediator_and_an_export_restores_it() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), MEDIATOR);

    let did = stdout(&bridge(&cfg, &["init"]));
    assert!(did.starts_with("did:peer:2."), "{did}");
    assert_eq!(
        vgi_bridge::identity::advertised_mediator(&did)
            .unwrap()
            .as_deref(),
        Some(MEDIATOR),
        "the VTC finds the mediator in the DID itself"
    );
    // A second `init` keeps the identity.
    assert_eq!(stdout(&bridge(&cfg, &["init"])), did);

    // Export: a new owner-only file, never an overwrite.
    let out = dir.path().join("identity.json");
    assert_eq!(
        stdout(&bridge(
            &cfg,
            &["identity", "export", out.to_str().unwrap()]
        )),
        did
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&out).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert!(
        !bridge(&cfg, &["identity", "export", out.to_str().unwrap()])
            .status
            .success()
    );

    // The store is lost; the master key and the export survive. Importing
    // the export into a fresh store brings back the same DID.
    std::fs::remove_dir_all(dir.path().join("data")).unwrap();
    assert_eq!(
        stdout(&bridge(
            &cfg,
            &["identity", "import", out.to_str().unwrap()]
        )),
        did
    );
    assert_eq!(stdout(&bridge(&cfg, &["identity", "show"])), did);

    // `mint` does not replace an identity unless told to.
    assert!(!bridge(&cfg, &["identity", "mint"]).status.success());
    let fresh = stdout(&bridge(&cfg, &["identity", "mint", "--replace"]));
    assert_ne!(fresh, did);
    assert!(fresh.starts_with("did:peer:2."));
}

#[test]
fn a_did_peer_minted_for_another_mediator_is_not_imported() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), MEDIATOR);
    vgi_bridge::seal::write_key_file(
        &dir.path().join("master.key"),
        &vgi_bridge::seal::MasterKey::generate().unwrap(),
    )
    .unwrap();
    let (_, bundle) =
        vgi_bridge::BridgeIdentity::generate_did_peer("did:web:other-mediator.example").unwrap();
    let file = dir.path().join("bundle.json");
    std::fs::write(&file, serde_json::to_vec(&bundle).unwrap()).unwrap();

    let o = bridge(&cfg, &["identity", "import", file.to_str().unwrap()]);
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("other-mediator.example"), "{err}");
    // Nothing was stored in its place.
    assert!(!bridge(&cfg, &["identity", "show"]).status.success());
}
