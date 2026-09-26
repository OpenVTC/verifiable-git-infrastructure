//! The per-community VGI bridge (design §5.7): the one service that holds a
//! community's forge credentials — its own GitHub App key, its Forgejo bot's
//! token — and acts on the forges for its VTC.
//!
//! ```text
//!  VTC ──DIDComm (authcrypt, via mediator)──▶ bridge ──adapters──▶ GitHub / Forgejo
//!      ◀── git-ns/bridge/result, /event ────       ◀── webhooks, OAuth redirects (HTTPS)
//! ```
//!
//! - **Identity.** Its own DID ([`identity`]), keys sealed ([`seal`]). It
//!   serves exactly one VTC and refuses a document from any other DID,
//!   whatever its proof ([`wire`]).
//! - **Jobs.** `git-ns/bridge/job` in, exactly one `git-ns/bridge/result`
//!   out per job, with `jobId` idempotency from a durable ledger
//!   ([`store`]): a repeat is answered, never run twice, and a finished job
//!   repeated has its result sent again. Each job kind maps onto the
//!   forge-neutral adapter calls, with the adapter's hooks around each
//!   ([`jobs`]); binds and account links wait for the person under a
//!   single-use `state` ([`flows`]).
//! - **Events.** Verified webhooks, and a scheduled sweep where a forge has
//!   none, become `git-ns/bridge/event`s with the complete drift
//!   ([`events`]).
//! - **Checks.** Where no required workflow is available on GitHub, the
//!   bridge runs verify-trust itself on each pull request and posts the
//!   check as the App, which the ruleset pins ([`checks`]).
//! - **Dependabot re-sign.** On signed push provenance only, the bridge
//!   re-signs Dependabot pull requests with its own DID so they pass that
//!   check without a human step ([`resign`]).
//!
//! State is one redb file — in VTA mode ([`vta`]) a cache of the state the
//! bridge keeps in its trust context of the VTC's VTA ([`appstate`]), where
//! its identity and secrets live too. The operator guide (`docs/BRIDGE.md`)
//! covers deployment, VTA mode, the App registration, backups and networking.

pub mod appstate;
pub mod bridge;
#[cfg(feature = "forge-github")]
pub mod checks;
pub mod config;
mod events;
pub mod flows;
pub mod http;
pub mod identity;
mod jobs;
pub mod mapping;
pub mod registry;
#[cfg(feature = "forge-github")]
pub mod resign;
pub mod rolemap;
pub mod seal;
pub mod status;
pub mod store;
pub mod transport;
pub mod vta;
pub mod wire;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::StreamExt;

pub use bridge::{Bridge, BridgeParts};
pub use config::BridgeConfig;
pub use identity::BridgeIdentity;
pub use store::Store;

/// Build the adapters the config names from the sealed credentials. A forge
/// whose credentials are not stored yet is skipped with a warning (a GitHub
/// App is registered while the bridge runs).
pub async fn build_adapters(cfg: &BridgeConfig, store: &Store) -> Result<registry::Adapters> {
    let adapters = registry::Adapters::new();
    #[cfg(feature = "forge-github")]
    registry::refuse_single_app_layout(cfg, store)?;
    #[cfg(feature = "forge-github")]
    for g in &cfg.github {
        let keyring = match &g.platform_keyring_file {
            Some(p) => Some(registry::read_keyring(p)?),
            None => None,
        };
        match registry::build_github(store, g)? {
            Some(forge) => adapters.insert(
                registry::Adapter::GitHub(forge),
                Some(&g.app_owner),
                registry::vgi_config(cfg, keyring),
            ),
            None => {
                tracing::warn!(host = %g.host, owner = %g.app_owner, "no GitHub App registered yet")
            }
        }
    }
    #[cfg(feature = "forge-forgejo")]
    for f in &cfg.forgejo {
        match registry::build_forgejo(cfg, store, f).await {
            Ok(Some(forge)) => adapters.insert(
                registry::Adapter::Forgejo(forge),
                None,
                registry::vgi_config(cfg, None),
            ),
            Ok(None) => tracing::warn!(
                url = %f.base_url,
                "no Forgejo bot token stored yet (`vgi-bridge secret set forgejo/<host>/bot-token`)"
            ),
            Err(e) => {
                tracing::error!(url = %f.base_url, error = %e, "the Forgejo adapter did not start")
            }
        }
    }
    Ok(adapters)
}

/// The production proof checker: resolves the VTC's DID (`did:key`
/// locally, `did:webvh` / `did:web` over the network), caching a resolved
/// document for the default [`verify_trust::DEFAULT_DID_CACHE_TTL_SECS`].
/// Only the configured VTC DID is ever resolved — [`wire::DocChecker`]
/// refuses any other issuer before it looks at a proof.
pub async fn proof_checker() -> Result<Arc<dyn wire::ProofCheck>> {
    proof_checker_with_ttl(DEFAULT_DID_CACHE_TTL_SECS).await
}

/// How long a resolved DID document is cached unless the config says
/// otherwise (`did_cache_ttl_secs`).
pub const DEFAULT_DID_CACHE_TTL_SECS: u64 = 60;

/// [`proof_checker`] with a cache lifetime of `ttl_secs`, and one fresh
/// resolution after a proof fails against the cached document (the VTC
/// rotated its key since) before the document is refused
/// ([`wire::ReResolving`]).
pub async fn proof_checker_with_ttl(ttl_secs: u64) -> Result<Arc<dyn wire::ProofCheck>> {
    use affinidi_tdk::did_resolver::DIDCacheClient;
    use affinidi_tdk::did_resolver::config::DIDCacheConfigBuilder;
    use trust_tasks_proof::affinidi::{CachedDidResolver, Verifier};
    let ttl = u32::try_from(ttl_secs).unwrap_or(u32::MAX);
    let client = Arc::new(
        DIDCacheClient::new(DIDCacheConfigBuilder::default().with_cache_ttl(ttl).build())
            .await
            .context("building the DID resolver")?,
    );
    let verifier: Arc<dyn wire::ProofCheck> = Arc::new(Verifier::with_resolver(Arc::new(
        CachedDidResolver::new(Arc::clone(&client)),
    )));
    Ok(Arc::new(wire::ReResolving::new(verifier, client)))
}

/// What the bridge opens its identity and secrets with.
#[non_exhaustive]
pub enum Keys {
    /// The self-contained modes: the master key the sealed store opens with.
    Sealed(seal::MasterKey),
    /// VTA mode: the context-scoped VTA credential ([`vta`]).
    Vta(vta_sdk::credentials::CredentialBundle),
}

/// Run the bridge until SIGINT/SIGTERM, with the `keys` the caller loaded
/// (and, when they came from the environment, cleared from it — which only
/// the single-threaded `main` can do safely).
pub async fn run(cfg: BridgeConfig, keys: Keys) -> Result<()> {
    std::fs::create_dir_all(&cfg.data_dir)
        .with_context(|| format!("creating {}", cfg.data_dir.display()))?;
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let (store, identity, vta_parts) = match keys {
        Keys::Sealed(key) => {
            let store = Store::open(&cfg.store_path(), key)?;
            let identity = BridgeIdentity::load(&store)?.context(
                "the bridge has no identity yet: run `vgi-bridge init` (or `identity import`)",
            )?;
            (store, identity, None)
        }
        Keys::Vta(mut cred) => {
            let v = cfg
                .vta
                .as_ref()
                .context("a VTA credential without a `[vta]` section")?;
            let budget = Duration::from_secs(v.start_timeout_secs);
            let session = vta::Session::connect_retrying(v, &cred).await;
            let vta_did = cred.vta_did.clone();
            zeroize::Zeroize::zeroize(&mut cred.private_key_multibase);
            let session = session?;
            let docs: Arc<dyn vta::DidDocuments> = Arc::new(vta::Resolver::new().await?);
            let did = vta::with_retry(budget, "reading the bridge's context", || {
                session.context_did()
            })
            .await?
            .context(
                "the VTA context has no DID yet: provision one for the bridge (BRIDGE.md §2a)",
            )?;
            // Nothing is sealed into the file in VTA mode: the key only
            // satisfies the store's shape and dies with the process.
            let store = Store::open(&cfg.store_path(), seal::MasterKey::generate()?)?;
            vta::check_cache_binding(&store, &vta_did, &v.context, &did)?;
            // The state first: which signing key signs depends on when each
            // was first listed, which the VTA keeps.
            let (store, mirror, remote) = vta::attach(&session, store, budget).await?;
            let policy = vta::SigningPolicy::load(&store, v, chrono::Utc::now().timestamp())?;
            let (identity, policy) = vta::with_retry(budget, "fetching the bridge's keys", || {
                session.load_identity(v.did.as_deref(), docs.as_ref(), None, &policy)
            })
            .await?;
            if identity.did() != did {
                anyhow::bail!("the VTA context's DID changed while the bridge started");
            }
            policy.save(&store)?;
            tracing::info!(context = %v.context, "the bridge's state and secrets are in the VTA");
            let task = tokio::spawn(mirror.run(remote, store.clone(), stop_rx.clone()));
            (store, identity, Some((session, task, docs)))
        }
    };
    tracing::info!(did = %identity.did(), vtc = %cfg.vtc_did, "starting the VGI bridge");
    // The VTC finds where to send jobs in this DID's document. A did:peer
    // that names another mediator is refused (jobs would go where the bridge
    // does not listen); a did:key, which names none, is served with a
    // warning, since results and events still go out.
    if let Some(warning) = identity::check_reachable(identity.did(), &cfg.mediator_did)? {
        tracing::warn!("{warning}");
    }
    let adapters = build_adapters(&cfg, &store).await?;
    let link = Arc::new(transport::SupervisedLink::new());
    let parts = BridgeParts::new(
        cfg.clone(),
        identity.clone(),
        store,
        adapters,
        link.clone(),
        proof_checker_with_ttl(cfg.did_cache_ttl_secs).await?,
    );
    let bridge = Bridge::new(parts);
    bridge.restore().await?;
    #[cfg(feature = "forge-github")]
    flows::offer_registrations(&bridge)?;

    // DIDComm: connect, serve, reconnect with capped backoff.
    let messaging = {
        let bridge = Arc::clone(&bridge);
        let link = Arc::clone(&link);
        let mut stop = stop_rx.clone();
        let mut rotations = bridge.rotations();
        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            loop {
                // The current keys, read at every connect: a rotation ends
                // the session below and the next one uses the new ones.
                let current = bridge.identity();
                rotations.borrow_and_update();
                let connected =
                    transport::DidcommLink::connect(&current, &bridge.cfg.mediator_did).await;
                drop(current);
                match connected {
                    Ok((conn, mut inbound)) => {
                        let conn = Arc::new(conn);
                        link.set(Some(conn.clone())).await;
                        tracing::info!("connected to the mediator");
                        let started = std::time::Instant::now();
                        // Anything queued while disconnected goes out now,
                        // and the role maps are reported afresh.
                        bridge.link_up().await;
                        loop {
                            tokio::select! {
                                next = inbound.next() => match next {
                                    Some(doc) => bridge.handle_inbound(doc).await,
                                    None => break,
                                },
                                _ = stop.changed() => {
                                    link.set(None).await;
                                    conn.shutdown().await;
                                    return;
                                }
                                _ = rotations.changed() => {
                                    tracing::info!("the bridge's keys were rotated; reconnecting with the new ones");
                                    backoff = Duration::from_millis(100);
                                    break;
                                }
                            }
                        }
                        link.set(None).await;
                        conn.shutdown().await;
                        if backoff > Duration::from_millis(100) {
                            tracing::warn!("the mediator session ended; reconnecting");
                        }
                        if started.elapsed() > Duration::from_secs(60) {
                            backoff = Duration::from_secs(1);
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "could not reach the mediator"),
                }
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = stop.changed() => return,
                }
                backoff = (backoff * 2).min(Duration::from_secs(120));
            }
        })
    };

    let background = tokio::spawn(Arc::clone(&bridge).background(stop_rx.clone()));

    // VTA mode: pick up a rotation of the bridge's keys — on an interval,
    // and at once on SIGHUP.
    let refresh = vta_parts.as_ref().map(|(session, _, docs)| {
        let v = cfg.vta.clone().expect("VTA mode");
        tokio::spawn(vta::refresh_keys(
            Arc::clone(&bridge),
            session.clone(),
            v,
            Arc::clone(docs),
            stop_rx.clone(),
        ))
    });

    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("listening on {}", cfg.listen))?;
    tracing::info!(listen = %cfg.listen, public = %cfg.public_url, "HTTP server up");
    let mut stop_http = stop_rx.clone();
    let server = axum::serve(listener, http::router(Arc::clone(&bridge))).with_graceful_shutdown(
        async move {
            let _ = stop_http.changed().await;
        },
    );
    let server = tokio::spawn(async move { server.await });

    shutdown_signal().await;
    tracing::info!("shutting down");
    let _ = stop_tx.send(true);
    let _ = messaging.await;
    let _ = background.await;
    let _ = server.await;
    if let Some(r) = refresh {
        let _ = r.await;
    }
    if let Some((session, mirror, _)) = vta_parts {
        // The mirror's last pass has run; say what did not make it.
        let _ = mirror.await;
        if let Some(m) = bridge.store.mirror()
            && m.pending() > 0
        {
            tracing::error!(
                pending = m.pending(),
                "stopping with changes not yet written to the VTA (it was unreachable); they are in \
                 the local cache and go out at the next start on this host"
            );
        }
        session.shutdown().await;
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
