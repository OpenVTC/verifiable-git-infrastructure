//! VTA mode end to end: the bridge's state and secrets live in its context's
//! app-state (here an in-memory one), the local store is a cache, and a new
//! host with an empty data directory comes back with everything.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use serde_json::{Value, json};
use vgi_bridge::appstate::MemoryAppState;
use vgi_bridge::store::{NamespaceRecord, Table};

fn inspect_job(id: &str) -> Value {
    json!({ "jobId": id, "namespace": NS, "kind": "inspect", "repo": "github.com/acme/widgets" })
}

fn vta_options(remote: &Arc<MemoryAppState>) -> Options {
    Options {
        vta: Some(remote.clone()),
        ..Options::default()
    }
}

#[tokio::test]
async fn state_and_secrets_live_in_the_vta_and_a_new_host_rebuilds_from_it() {
    let remote = Arc::new(MemoryAppState::new());
    {
        let mut w = world(vta_options(&remote)).await;
        seed_repo(w.bridge.store(), &repo("widgets"), 812);
        mount_inspect(&w.server).await;
        w.send_job(inspect_job("job_1")).await;
        let result = w.next_of(RESULT).await;
        assert_eq!(result["payload"]["outcome"], "succeeded");
        assert!(w.bridge.store().flush(Duration::from_secs(5)).await);
        let snap = remote.snapshot();
        assert!(
            snap.contains_key("secret/github/github.com/acme/app"),
            "{:?}",
            snap.keys()
        );
        assert!(snap.contains_key(&format!("state/namespaces/{NS}")));
        assert!(snap.contains_key("state/repos/github.com#812"));
        assert!(
            !snap
                .keys()
                .any(|k| k.starts_with("state/jobs/") || k == "secret/identity"),
            "the job ledger and no identity go to the VTA: {:?}",
            snap.keys()
        );
    }

    // The host is lost. A new one: empty data directory, nothing seeded, the
    // same context.
    let mut w = world(Options {
        seed_app: false,
        seed_namespace: false,
        ..vta_options(&remote)
    })
    .await;
    let ns: NamespaceRecord = w
        .bridge
        .store()
        .get(Table::Namespaces, NS)
        .unwrap()
        .expect("the namespace came back from the VTA");
    assert!(ns.managed.contains(&812));
    assert!(
        w.bridge.adapters().get("github.com").is_some(),
        "the App came back from the VTA and is in service"
    );
    // And it serves the namespace as before.
    mount_inspect(&w.server).await;
    w.send_job(inspect_job("job_2")).await;
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["outcome"], "succeeded");
}

#[tokio::test]
async fn a_result_waits_for_the_vta_and_goes_out_once_its_state_is_written() {
    let remote = Arc::new(MemoryAppState::new());
    let mut w = world(vta_options(&remote)).await;
    seed_repo(w.bridge.store(), &repo("widgets"), 812);
    assert!(w.bridge.store().flush(Duration::from_secs(5)).await);
    mount_inspect(&w.server).await;

    remote.set_down(true);
    w.send_job(inspect_job("job_1")).await;
    // The job response is not state: it goes out at once.
    let resp = w.next().await;
    assert_eq!(resp["payload"]["accepted"], true);
    // What the job changed is not in the VTA, so neither its event nor its
    // result is sent.
    assert!(
        tokio::time::timeout(Duration::from_secs(12), w.inbox.recv())
            .await
            .is_err(),
        "nothing is reported while the VTA is unreachable"
    );
    assert!(
        w.bridge
            .store()
            .get::<vgi_bridge::store::OutboxEntry>(Table::Outbox, "result:job_1")
            .unwrap()
            .is_some(),
        "the result is held in the outbox"
    );

    remote.set_down(false);
    assert!(w.bridge.store().flush(Duration::from_secs(70)).await);
    w.bridge.resend_unacknowledged(true).await;
    let result = w.next_of(RESULT).await;
    assert_eq!(result["payload"]["jobId"], "job_1");
}
