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

    // `mint` does not replace an identity unless told to, and not without
    // somewhere to keep the one it replaces.
    assert!(!bridge(&cfg, &["identity", "mint"]).status.success());
    let o = bridge(&cfg, &["identity", "mint", "--replace"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("--backup"));
    assert_eq!(stdout(&bridge(&cfg, &["identity", "show"])), did);

    let backup = dir.path().join("old-identity.json");
    let o = bridge(
        &cfg,
        &[
            "identity",
            "mint",
            "--replace",
            "--backup",
            backup.to_str().unwrap(),
        ],
    );
    let fresh = stdout(&o);
    assert_ne!(fresh, did);
    assert!(fresh.starts_with("did:peer:2."));
    let err = String::from_utf8_lossy(&o.stderr);
    for consequence in ["[git_ns] bridges", "git.commit.sign", "unbind", &did] {
        assert!(err.contains(consequence), "{consequence}: {err}");
    }
    // The backup is the old identity, restorable.
    let old: vta_sdk::did_secrets::DidSecretsBundle =
        serde_json::from_slice(&std::fs::read(&backup).unwrap()).unwrap();
    assert_eq!(old.did, did);
    let back = dir.path().join("fresh-identity.json");
    let o = bridge(
        &cfg,
        &[
            "identity",
            "import",
            backup.to_str().unwrap(),
            "--backup",
            back.to_str().unwrap(),
        ],
    );
    assert_eq!(stdout(&o), did);
}

/// A key file and a store holding `mediator`'s did:peer, like `init` leaves.
fn initialised(dir: &Path) -> (std::path::PathBuf, String) {
    let cfg = config(dir, MEDIATOR);
    let did = stdout(&bridge(&cfg, &["init"]));
    (cfg, did)
}

fn open_store(dir: &Path) -> vgi_bridge::Store {
    let key = vgi_bridge::seal::MasterKey::load(Some(&dir.join("master.key")), None).unwrap();
    vgi_bridge::Store::open(&dir.join("data").join("state.redb"), key).unwrap()
}

#[test]
fn mint_replace_refuses_while_namespaces_are_bound_to_the_did() {
    use vgi_bridge::store::{NamespaceRecord, NamespaceState, Table};
    let dir = tempfile::tempdir().unwrap();
    let (cfg, did) = initialised(dir.path());
    {
        let store = open_store(dir.path());
        let mut ns = NamespaceRecord::pending(
            "ns_01",
            vgi_forge::Resource::parse("github.com/acme").unwrap(),
        );
        ns.state = NamespaceState::Bound;
        store.put(Table::Namespaces, "ns_01", &ns).unwrap();
    }
    let backup = dir.path().join("old.json");
    let args = [
        "identity",
        "mint",
        "--replace",
        "--backup",
        backup.to_str().unwrap(),
    ];
    let o = bridge(&cfg, &args);
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("ns_01") && err.contains("github.com/acme"),
        "{err}"
    );
    assert!(err.contains("--abandon-current-did"), "{err}");
    assert!(!backup.exists(), "nothing written for a refused replace");
    assert_eq!(stdout(&bridge(&cfg, &["identity", "show"])), did);

    // Told explicitly, it replaces — and keeps the old one.
    let mut forced = args.to_vec();
    forced.push("--abandon-current-did");
    assert_ne!(stdout(&bridge(&cfg, &forced)), did);
    let old: vta_sdk::did_secrets::DidSecretsBundle =
        serde_json::from_slice(&std::fs::read(&backup).unwrap()).unwrap();
    assert_eq!(old.did, did);
}

/// A VTA-provisioned-looking bundle: a did:webvh with an Ed25519, an X25519
/// and a P-256 key.
fn webvh_bundle() -> vta_sdk::did_secrets::DidSecretsBundle {
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use vta_sdk::did_secrets::{DidSecretsBundle, SecretEntry};
    use vta_sdk::keys::KeyType;
    let did = "did:webvh:QmBridgeScid:bridge.acme.example";
    let entry = |s: Secret, n: u8, key_type| SecretEntry {
        key_id: format!("{did}#key-{n}"),
        key_type,
        private_key_multibase: s.get_private_keymultibase().unwrap(),
    };
    DidSecretsBundle {
        did: did.into(),
        secrets: vec![
            entry(Secret::generate_ed25519(None, None), 0, KeyType::Ed25519),
            entry(
                Secret::generate_x25519(None, None).unwrap(),
                1,
                KeyType::X25519,
            ),
            entry(Secret::generate_p256(None, None).unwrap(), 2, KeyType::P256),
        ],
    }
}

#[test]
fn a_vta_provisioned_did_exports_verbatim_and_is_not_replaced_unasked() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, _) = initialised(dir.path());
    let bundle = webvh_bundle();
    let file = dir.path().join("bundle.json");
    std::fs::write(&file, serde_json::to_vec(&bundle).unwrap()).unwrap();
    let first = dir.path().join("peer.json");
    let o = bridge(
        &cfg,
        &[
            "identity",
            "import",
            file.to_str().unwrap(),
            "--backup",
            first.to_str().unwrap(),
        ],
    );
    assert_eq!(stdout(&o), bundle.did);

    // Every key, the P-256 one included, exactly as imported.
    let out = dir.path().join("export.json");
    stdout(&bridge(
        &cfg,
        &["identity", "export", out.to_str().unwrap()],
    ));
    let exported: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(exported, serde_json::to_value(&bundle).unwrap());

    // Not a DID this bridge minted: replacing it needs the explicit flag.
    let backup = dir.path().join("webvh.json");
    let args = [
        "identity",
        "mint",
        "--replace",
        "--backup",
        backup.to_str().unwrap(),
    ];
    let o = bridge(&cfg, &args);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("did not mint"));
    let mut forced = args.to_vec();
    forced.push("--abandon-current-did");
    assert!(stdout(&bridge(&cfg, &forced)).starts_with("did:peer:2."));
    let kept: serde_json::Value = serde_json::from_slice(&std::fs::read(&backup).unwrap()).unwrap();
    assert_eq!(kept, serde_json::to_value(&bundle).unwrap());
}

#[cfg(unix)]
#[test]
fn export_refuses_to_write_through_a_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, _) = initialised(dir.path());
    let target = dir.path().join("elsewhere.json");
    let link = dir.path().join("link.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(
        !bridge(&cfg, &["identity", "export", link.to_str().unwrap()])
            .status
            .success()
    );
    assert!(!target.exists(), "no key material written through the link");
}

#[test]
fn run_refuses_a_did_peer_that_names_another_mediator() {
    let dir = tempfile::tempdir().unwrap();
    let (_, did) = initialised(dir.path());
    let moved = config(dir.path(), "did:web:new-mediator.acme.example");
    let o = bridge(&moved, &["run"]);
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains(&did), "{err}");
    assert!(
        err.contains(&format!("mediator_did = \"{MEDIATOR}\"")),
        "{err}"
    );
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
