//! VTA mode: the bridge works off the VTC's VTA (design §5.7, decided
//! 2026-09-25).
//!
//! The bridge's identity and secrets live in **its own trust context** of the
//! VTC's VTA, and this host holds only an ephemeral, context-scoped VTA
//! credential (a `did:key`) that can be revoked and re-issued:
//!
//! - the bridge's DID (a `did:webvh` the VTA minted into the context) and its
//!   keys — Ed25519 for Trust Task proofs, job results and Dependabot
//!   re-signs, X25519 for DIDComm — are fetched into memory at start-up
//!   ([`Session::load_identity`]) and never written to disk or logs. Which
//!   keys it holds is what its current DID document lists, through every
//!   step of a rotation ([`refresh_keys`]). They are the
//!   bridge's own keys: nothing the bridge signs claims the VTC's authority;
//! - the GitHub App's credentials, webhook secrets and Forgejo tokens, and the
//!   bridge's own state (namespaces, managed repositories, pins, the
//!   provenance ledger), are records in the context's `vta/app-state`
//!   ([`VtaAppState`], [`crate::appstate`]). The local store is a cache.
//!
//! Recovery after a lost host is therefore: issue a new context credential,
//! start the bridge on an empty data directory. The DID does not change.
//!
//! **What the credential can reach.** Exporting a key's secret is gated on
//! the VTA's `key-export` capability, which only the `admin` role derives, so
//! the credential is an admin **scoped to the bridge's context**: it can read
//! and use that context's keys and app-state (and administer that context),
//! but every key, sign and app-state operation checks the key's or record's
//! own context, so it reaches no other context — the VTC's included — and no
//! unscoped key. `vgi-bridge vta setup` checks that it sees no other context.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use serde_json::{Value, json};
use vta_sdk::client::VtaClient;
use vta_sdk::credentials::CredentialBundle;
use vta_sdk::did_secrets::DidSecretsBundle;
use vta_sdk::error::VtaError;
use vta_sdk::protocols::app_state::{
    AppStateGetResponse, AppStateListResponse, AppStatePutResponse,
};
use zeroize::{Zeroize, Zeroizing};

use crate::appstate::{AppState, NAMESPACE, PutError, Record};
use crate::config::VtaConfig;
use crate::identity::BridgeIdentity;
use crate::seal::MasterKey;

/// Read the credential bundle from the file or environment variable the
/// config names. The caller clears the variable (only `main`, while it is
/// single-threaded, may).
pub fn load_credential(cfg: &VtaConfig) -> Result<CredentialBundle> {
    let text = if let Some(path) = &cfg.credential_file {
        crate::seal::check_owner_only(path)?;
        Zeroizing::new(
            std::fs::read_to_string(path)
                .with_context(|| format!("reading the VTA credential {}", path.display()))?,
        )
    } else if let Some(var) = &cfg.credential_env {
        Zeroizing::new(std::env::var(var).with_context(|| {
            format!("the VTA credential variable `{var}` is not set (or not UTF-8)")
        })?)
    } else {
        bail!("`[vta]` names no credential (`credential_file` or `credential_env`)");
    };
    parse_credential(&text)
}

/// A credential bundle: its JSON, or the JSON base64-encoded.
pub fn parse_credential(text: &str) -> Result<CredentialBundle> {
    use base64::Engine as _;
    let t = text.trim();
    if t.starts_with("-----BEGIN") {
        bail!(
            "this is a sealed bundle: open it first (`pnm bootstrap open --bundle <file> \
             --expect-digest <digest> --out <credential.json>`) and point the bridge at the \
             credential JSON"
        );
    }
    let json = if t.starts_with('{') {
        Zeroizing::new(t.to_string())
    } else {
        let bytes = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(t)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(t))
                .context("the VTA credential is neither JSON nor base64")?,
        );
        Zeroizing::new(
            String::from_utf8(bytes.to_vec()).context("the VTA credential is not UTF-8")?,
        )
    };
    let bundle: CredentialBundle =
        serde_json::from_str(&json).context("parsing the VTA credential bundle")?;
    if !bundle.did.starts_with("did:key:") {
        bail!(
            "the VTA credential's `did` must be a did:key, got `{}`",
            bundle.did
        );
    }
    Ok(bundle)
}

/// Whether credentials may travel to `url`: https, or cleartext to loopback
/// only (parsed, not prefix-matched).
fn url_is_secure(url: &str) -> bool {
    match url::Url::parse(url) {
        Ok(u) if u.scheme() == "https" => true,
        Ok(u) if u.scheme() == "http" => matches!(
            u.host(),
            Some(url::Host::Domain("localhost"))
                | Some(url::Host::Ipv4(std::net::Ipv4Addr::LOCALHOST))
                | Some(url::Host::Ipv6(std::net::Ipv6Addr::LOCALHOST))
        ),
        _ => false,
    }
}

/// An authenticated session with the VTA, in the bridge's context.
#[derive(Clone)]
pub struct Session {
    client: VtaClient,
    context: String,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("context", &self.context)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// A session over an already-authenticated client (tests drive a
    /// loopback one).
    pub fn from_client(client: VtaClient, context: impl Into<String>) -> Self {
        Session {
            client,
            context: context.into(),
        }
    }

    /// Authenticate once: DIDComm through `mediator_did` when configured,
    /// else REST at the bundle's (or the config's) URL.
    pub async fn connect(cfg: &VtaConfig, cred: &CredentialBundle) -> Result<Self> {
        let url = cfg
            .url
            .as_ref()
            .map(|u| u.as_str().trim_end_matches('/').to_string())
            .or_else(|| cred.vta_url.clone())
            .unwrap_or_default();
        if cfg.mediator_did.is_none() && url.is_empty() {
            bail!("the VTA credential carries no `vtaUrl`: set `vta.url` or `vta.mediator_did`");
        }
        if !url.is_empty() && !url_is_secure(&url) {
            bail!("the VTA URL must be https (cleartext only to loopback), got `{url}`");
        }
        let connected = VtaClient::connect_auto(vta_sdk::client::AutoConnect {
            vta_url: &url,
            vta_did: &cred.vta_did,
            credential_did: &cred.did,
            private_key_multibase: &cred.private_key_multibase,
            mediator_did: cfg.mediator_did.as_deref(),
        })
        .await
        .map_err(|e| anyhow!("authenticating to the VTA as `{}`: {e}", cred.did))?;
        Ok(Session::from_client(connected.client, cfg.context.clone()))
    }

    /// [`Session::connect`], retried with capped backoff for up to
    /// `cfg.start_timeout_secs` — the bridge cannot start without its keys,
    /// and a VTA restarting alongside it should not fail the start. A refusal
    /// (the credential revoked or wrong) is not retried.
    pub async fn connect_retrying(cfg: &VtaConfig, cred: &CredentialBundle) -> Result<Self> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(cfg.start_timeout_secs);
        let mut backoff = Duration::from_secs(1);
        loop {
            match Session::connect(cfg, cred).await {
                Ok(s) => return Ok(s),
                Err(e) if is_refusal(&e) => return Err(e),
                Err(e) if tokio::time::Instant::now() + backoff > deadline => {
                    return Err(e.context("the VTA did not answer in time"));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "the VTA is not reachable yet; retrying in {backoff:?}");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
    }

    /// The context id.
    pub fn context(&self) -> &str {
        &self.context
    }

    /// The client.
    pub fn client(&self) -> &VtaClient {
        &self.client
    }

    /// Close the session (a DIDComm session holds a mediator slot).
    pub async fn shutdown(&self) {
        self.client.shutdown().await;
    }

    /// The bridge's identity: its context's DID, and the keys of it the
    /// bridge holds — every signing (`assertionMethod`) and key-agreement
    /// key the DID's **current document** lists, with its private half from
    /// the VTA or, for a key the VTA no longer releases but the document
    /// still lists (a rotation's overlap), from `held`. A key the document
    /// does not list is not held, whatever the VTA exports; a key it stops
    /// listing is dropped. The newest signing key the VTA still exports
    /// signs. Fetched in one call and held in memory only. `want`: the DID
    /// the config names, which the context's must be.
    pub async fn load_identity(
        &self,
        want: Option<&str>,
        docs: &dyn DidDocuments,
        held: Option<&BridgeIdentity>,
    ) -> Result<BridgeIdentity> {
        let mut bundle = self
            .client
            .fetch_did_secrets_bundle(&self.context)
            .await
            .map_err(|e| explain(e, &self.context, "fetching the bridge's keys"))?;
        let out = async {
            check_did(&bundle.did, want)?;
            let created = key_ages(self, &bundle.did).await?;
            let doc = docs.current(&bundle.did).await?;
            reconcile(&bundle, held, &doc, &created)
        }
        .await;
        wipe(&mut bundle);
        out
    }

    /// The key the bridge seals its secrets with before they go to
    /// app-state: derived (HKDF-SHA256) from a dedicated key in the context,
    /// labelled [`SEAL_KEY_LABEL`], which only an admin of the context can
    /// export. Created on first use when `create`. Derived keys are in the
    /// VTA's backups and recoverable from its mnemonic, so a restored VTA
    /// still opens them.
    pub async fn sealing_key(&self, create: bool) -> Result<MasterKey> {
        let listed = self
            .client
            .list_keys(0, 1000, Some("active"), Some(&self.context))
            .await
            .map_err(|e| explain(e, &self.context, "listing the context's keys"))?;
        let found = listed
            .keys
            .iter()
            .find(|k| {
                k.label.as_deref() == Some(SEAL_KEY_LABEL)
                    && k.context_id.as_deref() == Some(self.context.as_str())
            })
            .map(|k| k.key_id.clone());
        let key_id = match found {
            Some(id) => id,
            None if create => {
                let mut req =
                    vta_sdk::client::CreateKeyRequest::new(vta_sdk::keys::KeyType::Ed25519);
                req.label = Some(SEAL_KEY_LABEL.into());
                req.context_id = Some(self.context.clone());
                let created =
                    self.client.create_key(req).await.map_err(|e| {
                        explain(e, &self.context, "creating the bridge's sealing key")
                    })?;
                tracing::info!(key = %created.key_id, "created the key the bridge seals its secrets in the VTA with");
                created.key_id
            }
            None => bail!(
                "the context `{}` has no sealing key (`{SEAL_KEY_LABEL}`) yet: run `vgi-bridge vta setup`",
                self.context
            ),
        };
        let mut secret = self
            .client
            .get_key_secret(&key_id)
            .await
            .map_err(|e| explain(e, &self.context, "fetching the bridge's sealing key"))?;
        let seed = Zeroizing::new(
            vta_sdk::did_key::decode_private_key_multibase(&secret.private_key_multibase)
                .map_err(|e| anyhow!("the sealing key does not decode: {e}"))?,
        );
        secret.private_key_multibase.zeroize();
        derive_seal(&seed)
    }

    /// The contexts this credential can see (setup's isolation check).
    pub async fn visible_contexts(&self) -> Result<Vec<String>> {
        let list = self
            .client
            .list_contexts()
            .await
            .map_err(|e| anyhow!("listing contexts: {e}"))?;
        Ok(list.contexts.into_iter().map(|c| c.id).collect())
    }

    /// The context's DID, as the VTA records it.
    pub async fn context_did(&self) -> Result<Option<String>> {
        let ctx = self
            .client
            .get_context(&self.context)
            .await
            .map_err(|e| explain(e, &self.context, "reading the context"))?;
        Ok(ctx.did)
    }
}

/// Where the bridge reads its own DID document: as published **now**,
/// never a cached copy — the document decides which keys the bridge holds.
#[async_trait]
pub trait DidDocuments: Send + Sync {
    /// `did`'s current document.
    async fn current(&self, did: &str) -> Result<Value>;
}

/// The production [`DidDocuments`]: the DID resolver, with the DID evicted
/// from its cache before every read.
pub struct Resolver(Arc<affinidi_tdk::did_resolver::DIDCacheClient>);

impl Resolver {
    /// A resolver of its own.
    pub async fn new() -> Result<Self> {
        use affinidi_tdk::did_resolver::DIDCacheClient;
        use affinidi_tdk::did_resolver::config::DIDCacheConfigBuilder;
        Ok(Resolver(Arc::new(
            DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
                .await
                .context("building the DID resolver")?,
        )))
    }
}

#[async_trait]
impl DidDocuments for Resolver {
    async fn current(&self, did: &str) -> Result<Value> {
        let _ = self.0.remove(did).await;
        let r = self
            .0
            .resolve(did)
            .await
            .map_err(|e| anyhow!("resolving the bridge's DID `{did}`: {e}"))?;
        Ok(serde_json::to_value(&r.doc)?)
    }
}

/// Check the VTA again and put the result in service
/// ([`crate::Bridge::replace_identity`]): keys the document now lists are
/// taken up, keys it stopped listing are dropped. `Ok(true)` if the keys in
/// service changed.
pub async fn refresh_once(
    bridge: &crate::Bridge,
    session: &Session,
    cfg: &VtaConfig,
    docs: &dyn DidDocuments,
) -> Result<bool> {
    let held = bridge.identity();
    let fresh = session
        .load_identity(cfg.did.as_deref(), docs, Some(&held))
        .await?;
    let changed = bridge.replace_identity(fresh)?;
    if changed {
        let now = bridge.identity();
        tracing::info!(
            did = %bridge.did(),
            keys = now.messaging_secrets().len(),
            signing = %now.signing_key_id(),
            "the bridge's keys changed (a rotation); the ones its DID document lists are in service"
        );
    }
    Ok(changed)
}

/// What a rotation changes, without exporting anything: the DID's keys as
/// the VTA lists them, and the keys its document lists.
async fn fingerprint(
    session: &Session,
    did: &str,
    docs: &dyn DidDocuments,
) -> Result<(Vec<(String, String)>, Listed)> {
    let listed = session
        .client
        .list_keys(0, 1000, Some("active"), Some(&session.context))
        .await
        .map_err(|e| explain(e, &session.context, "listing the context's keys"))?;
    let prefix = format!("{did}#");
    let mut keys: Vec<(String, String)> = listed
        .keys
        .into_iter()
        .filter(|k| k.key_id.starts_with(&prefix))
        .map(|k| (k.key_id, k.public_key))
        .collect();
    keys.sort();
    Ok((keys, listed_keys(did, &docs.current(did).await?)?))
}

/// When each of the DID's keys was created in the VTA (for "newest").
async fn key_ages(session: &Session, did: &str) -> Result<BTreeMap<String, i64>> {
    let listed = session
        .client
        .list_keys(0, 1000, Some("active"), Some(&session.context))
        .await
        .map_err(|e| explain(e, &session.context, "listing the context's keys"))?;
    let prefix = format!("{did}#");
    Ok(listed
        .keys
        .into_iter()
        .filter(|k| k.key_id.starts_with(&prefix))
        .map(|k| (k.key_id, k.created_at.timestamp_millis()))
        .collect())
}

/// Serve until `stop`: every `cfg.key_refresh_secs`, compare the DID's keys
/// as the VTA lists them and as its current document lists them (public
/// halves only), and re-fetch the secrets ([`refresh_once`]) only when
/// either changed — so the VTA's audit log shows an export per rotation
/// step, not per minute. SIGHUP re-fetches at once. A failed check keeps
/// the keys in service and tries again at the next tick.
pub async fn refresh_keys(
    bridge: Arc<crate::Bridge>,
    session: Session,
    cfg: VtaConfig,
    docs: Arc<dyn DidDocuments>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let every = Duration::from_secs(cfg.key_refresh_secs.max(30));
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    #[cfg(unix)]
    let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();
    let mut last = fingerprint(&session, bridge.did(), docs.as_ref())
        .await
        .ok();
    loop {
        #[cfg(unix)]
        let hangup = async {
            match hup.as_mut() {
                Some(h) => {
                    h.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        #[cfg(not(unix))]
        let hangup = std::future::pending::<()>();
        let forced = tokio::select! {
            _ = tick.tick() => false,
            _ = hangup => {
                tracing::info!("SIGHUP: checking the VTA and the DID document for rotated keys");
                true
            }
            _ = stop.changed() => return,
        };
        let now = match fingerprint(&session, bridge.did(), docs.as_ref()).await {
            Ok(k) => Some(k),
            Err(e) => {
                tracing::warn!(error = %e, "could not check for rotated keys; the current ones stay in service");
                continue;
            }
        };
        if !forced && now == last {
            continue;
        }
        match refresh_once(&bridge, &session, &cfg, docs.as_ref()).await {
            Ok(_) => last = now,
            Err(e) => {
                tracing::warn!(error = %e, "could not take up the rotated keys; the current ones stay in service")
            }
        }
    }
}

/// The label of the context key the bridge's secrets are sealed under.
pub const SEAL_KEY_LABEL: &str = "vgi-bridge/app-state-seal";

/// The AES-256-GCM key for app-state secrets, from the sealing key's seed.
fn derive_seal(seed: &[u8; 32]) -> Result<MasterKey> {
    use aws_lc_rs::hkdf;
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"vgi-bridge").extract(seed);
    let okm = prk
        .expand(&[b"app-state secrets v1"], hkdf::HKDF_SHA256)
        .map_err(|_| anyhow!("deriving the sealing key"))?;
    let mut out = Zeroizing::new([0u8; 32]);
    okm.fill(out.as_mut())
        .map_err(|_| anyhow!("deriving the sealing key"))?;
    Ok(MasterKey::from_bytes(*out))
}

/// The context's DID must be one, and the one the config names (if any).
fn check_did(did: &str, want: Option<&str>) -> Result<()> {
    if let Some(w) = want
        && w != did
    {
        bail!(
            "the VTA context's DID is `{did}`, but `vta.did` names `{w}`: point the bridge at the \
             right context, or correct `vta.did`"
        );
    }
    if !did.starts_with("did:") {
        bail!("the VTA context has no DID yet: provision one for the bridge (see BRIDGE.md)");
    }
    Ok(())
}

/// The keys a DID document lists, by verification-method id: its
/// `assertionMethod` (signing) and `keyAgreement` keys, each with its raw
/// public key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Listed {
    signing: BTreeMap<String, Vec<u8>>,
    agreement: BTreeMap<String, Vec<u8>>,
}

/// Read [`Listed`] from `doc` (ids made absolute against `did`; references
/// and embedded methods both; `publicKeyMultibase` keys only).
pub(crate) fn listed_keys(did: &str, doc: &Value) -> Result<Listed> {
    let abs = |id: &str| {
        if id.starts_with('#') {
            format!("{did}{id}")
        } else {
            id.to_string()
        }
    };
    let key_of = |vm: &Value| -> Option<(String, Vec<u8>)> {
        let id = abs(vm.get("id")?.as_str()?);
        let mb = vm.get("publicKeyMultibase")?.as_str()?;
        let (_, raw) = multibase::decode(mb).ok()?;
        // Multicodec-prefixed (ed25519-pub 0xed01, x25519-pub 0xec01) or bare.
        let bytes = match raw.as_slice() {
            [0xed, 0x01, rest @ ..] | [0xec, 0x01, rest @ ..] if rest.len() == 32 => rest.to_vec(),
            r if r.len() == 32 => r.to_vec(),
            _ => return None,
        };
        Some((id, bytes))
    };
    let methods: BTreeMap<String, Vec<u8>> = doc
        .get("verificationMethod")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(key_of).collect())
        .unwrap_or_default();
    let relation = |name: &str| -> BTreeMap<String, Vec<u8>> {
        doc.get(name)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|e| match e {
                        Value::String(r) => {
                            let id = abs(r);
                            methods.get(&id).map(|k| (id, k.clone()))
                        }
                        other => key_of(other),
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    Ok(Listed {
        signing: relation("assertionMethod"),
        agreement: relation("keyAgreement"),
    })
}

/// The keys to hold: of what the VTA exports now (`fetched`) and what the
/// bridge already holds (`held`), exactly those the document lists under
/// the right relationship **with the same public key**. The newest listed
/// signing key the VTA still exports signs (by its creation in the VTA,
/// then its `#key-N` number); if the VTA exports none, the newest one held.
fn reconcile(
    fetched: &DidSecretsBundle,
    held: Option<&BridgeIdentity>,
    doc: &Value,
    created: &BTreeMap<String, i64>,
) -> Result<BridgeIdentity> {
    use affinidi_tdk::affinidi_crypto::KeyType;
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    let did = fetched.did.as_str();
    let listed = listed_keys(did, doc)?;
    let prefix = format!("{did}#");
    let exported: Vec<Secret> = vta_sdk::did_key::secrets_from_bundle(fetched)
        .map_err(|e| anyhow!("DID secrets bundle: {e}"))?;
    let exported_ids: std::collections::BTreeSet<String> =
        exported.iter().map(|s| s.id.clone()).collect();
    let mut candidates: BTreeMap<String, Secret> = BTreeMap::new();
    if let Some(h) = held
        && h.did() == did
    {
        for s in h.secrets() {
            candidates.insert(s.id.clone(), s.clone());
        }
    }
    for s in exported {
        candidates.insert(s.id.clone(), s);
    }
    let keep: Vec<Secret> = candidates
        .into_values()
        .filter(|s| s.id.starts_with(&prefix))
        .filter(|s| {
            let want = match s.get_key_type() {
                KeyType::Ed25519 => listed.signing.get(&s.id),
                KeyType::X25519 => listed.agreement.get(&s.id),
                _ => None,
            };
            let ok = want.is_some_and(|p| p.as_slice() == s.get_public_bytes());
            if want.is_some() && !ok {
                tracing::warn!(key = %s.id, "the DID document lists another public key under this id; not using it");
            }
            ok
        })
        .collect();
    let number = |id: &str| {
        id.rsplit_once("#key-")
            .and_then(|(_, n)| n.parse::<i64>().ok())
            .unwrap_or(-1)
    };
    let age = |s: &Secret| {
        (
            created.get(&s.id).copied().unwrap_or(i64::MIN),
            number(&s.id),
        )
    };
    let signing_candidates: Vec<&Secret> = keep
        .iter()
        .filter(|s| s.get_key_type() == KeyType::Ed25519)
        .collect();
    let signing = signing_candidates
        .iter()
        .filter(|s| exported_ids.contains(&s.id))
        .max_by_key(|s| age(s))
        .or_else(|| signing_candidates.iter().max_by_key(|s| age(s)))
        .map(|s| (*s).clone())
        .with_context(|| {
            format!(
                "the DID document of `{did}` lists no signing (assertionMethod) key the bridge \
                 holds a private key for"
            )
        })?;
    if !keep.iter().any(|s| s.get_key_type() == KeyType::X25519) {
        bail!(
            "the DID document of `{did}` lists no key-agreement key the bridge holds a private \
             key for; DIDComm needs one"
        );
    }
    BridgeIdentity::from_secrets(did, signing, keep)
}

/// Overwrite a bundle's key material.
fn wipe(bundle: &mut DidSecretsBundle) {
    for s in &mut bundle.secrets {
        s.private_key_multibase.zeroize();
    }
}

/// Whether an error is the VTA saying no (not worth retrying).
fn is_refusal(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<VtaError>()
            .is_some_and(|v| matches!(v, VtaError::Auth(_) | VtaError::Forbidden(_)))
    }) || {
        let s = format!("{e:#}");
        s.contains("authentication failed") || s.contains("forbidden")
    }
}

/// A VTA error with the operator's next step.
fn explain(e: VtaError, context: &str, doing: &str) -> anyhow::Error {
    match e {
        VtaError::Forbidden(m) => anyhow!(
            "{doing}: the VTA refused ({m}). The bridge's credential must be an `admin` scoped to \
             the context `{context}` (exporting its own keys needs `key-export`, which only that \
             role carries): `pnm acl create --did <credential did:key> --role admin --contexts \
             {context}`"
        ),
        VtaError::NotFound(m) => anyhow!("{doing}: the VTA has no context `{context}` ({m})"),
        other => anyhow!("{doing}: {other}"),
    }
}

/// The context's `vta/app-state`, as the bridge's [`AppState`].
pub struct VtaAppState {
    client: VtaClient,
    context: String,
}

impl VtaAppState {
    /// Over `session`'s client and context.
    pub fn new(session: &Session) -> Self {
        VtaAppState {
            client: session.client.clone(),
            context: session.context.clone(),
        }
    }

    async fn current_version(&self, key: &str) -> Option<u64> {
        self.get(key).await.ok().flatten().map(|r| r.version)
    }
}

/// A precondition failure, however the transport reported it (sdk 0.51
/// folds the trust-task error into a message).
fn is_conflict(e: &VtaError) -> bool {
    matches!(e, VtaError::Conflict(_)) || e.to_string().contains("versionConflict")
}

#[async_trait]
impl AppState for VtaAppState {
    async fn list(&self) -> Result<Vec<Record>> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let v = self
                .client
                .app_state_list(
                    &self.context,
                    Some(NAMESPACE),
                    None,
                    true,
                    Some(500),
                    cursor.as_deref(),
                )
                .await
                .map_err(|e| explain(e, &self.context, "listing the bridge's app-state"))?;
            let page: AppStateListResponse =
                serde_json::from_value(v).context("decoding an app-state list")?;
            for r in page.records {
                if r.deleted {
                    continue;
                }
                out.push(Record {
                    key: r.key,
                    version: r.version,
                    value: r.value.unwrap_or(Value::Null),
                });
            }
            match (page.truncated, page.cursor) {
                (true, Some(c)) => cursor = Some(c),
                _ => return Ok(out),
            }
        }
    }

    async fn get(&self, key: &str) -> Result<Option<Record>> {
        match self
            .client
            .app_state_get(&self.context, NAMESPACE, key, false)
            .await
        {
            Ok(v) => {
                let r: AppStateGetResponse =
                    serde_json::from_value(v).context("decoding an app-state record")?;
                if r.record.deleted {
                    return Ok(None);
                }
                Ok(Some(Record {
                    key: r.record.key,
                    version: r.record.version,
                    value: r.record.value.unwrap_or(Value::Null),
                }))
            }
            Err(VtaError::NotFound(_)) => Ok(None),
            Err(e) => Err(explain(e, &self.context, "reading the bridge's app-state")),
        }
    }

    async fn put(
        &self,
        key: &str,
        value: Value,
        expected: Option<u64>,
    ) -> std::result::Result<u64, PutError> {
        match self
            .client
            .app_state_put(&self.context, NAMESPACE, key, value, expected)
            .await
        {
            Ok(v) => {
                let r: AppStatePutResponse = serde_json::from_value(v)
                    .map_err(|e| PutError::Other(anyhow!("decoding an app-state write: {e}")))?;
                Ok(r.version)
            }
            Err(e) if is_conflict(&e) => Err(PutError::Conflict(self.current_version(key).await)),
            Err(e) => Err(PutError::Other(explain(
                e,
                &self.context,
                "writing the bridge's app-state",
            ))),
        }
    }

    async fn delete(&self, key: &str, expected: Option<u64>) -> std::result::Result<(), PutError> {
        // `Some(0)` is never a valid delete precondition.
        let expected = expected.filter(|v| *v > 0);
        match self
            .client
            .app_state_delete(&self.context, NAMESPACE, key, expected)
            .await
        {
            Ok(_) => Ok(()),
            Err(VtaError::NotFound(_)) => Ok(()),
            Err(e) if is_conflict(&e) => Err(PutError::Conflict(self.current_version(key).await)),
            Err(e) => Err(PutError::Other(explain(
                e,
                &self.context,
                "deleting from the bridge's app-state",
            ))),
        }
    }
}

/// The bridge's app-state, retried: every call on `inner` is tried again
/// with backoff while the VTA is unreachable, up to `budget`.
pub async fn with_retry<T, F, Fut>(budget: Duration, what: &str, mut f: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let deadline = tokio::time::Instant::now() + budget;
    let mut backoff = Duration::from_millis(500);
    loop {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) if is_refusal(&e) || tokio::time::Instant::now() + backoff > deadline => {
                return Err(e.context(format!("{what} (the VTA did not answer in time)")));
            }
            Err(e) => {
                tracing::warn!(error = %e, "{what}: retrying in {backoff:?}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

/// What a data directory's cache was filled for: refuse to run a cache
/// built for another context or DID (or by a bridge not in VTA mode) against
/// this one, which would write that bridge's state into this context.
pub const BINDING_META: &str = "vta/binding";

/// Check (and on first use, record) that the local cache belongs to this
/// VTA context and DID.
pub fn check_cache_binding(
    store: &crate::store::Store,
    vta_did: &str,
    context: &str,
    did: &str,
) -> Result<()> {
    use crate::store::Table;
    let want = json!({ "vtaDid": vta_did, "context": context, "did": did });
    match store.get::<Value>(Table::Meta, BINDING_META)? {
        Some(have) if have == want => Ok(()),
        Some(have) => bail!(
            "the data directory is the cache of another VTA context or DID ({have}); this bridge \
             is `{did}` in `{context}`. Use an empty `data_dir` (the state comes back from the VTA)"
        ),
        None => {
            // Only the self-contained modes ever seal secrets into the file.
            if !store.is_empty(Table::Secrets)? || !store.is_empty(Table::Namespaces)? {
                bail!(
                    "the data directory holds the store of a bridge not in VTA mode; VTA mode starts \
                     from an empty `data_dir` (its state lives in the VTA). Keep the old store for \
                     the self-contained mode, or move it aside"
                );
            }
            // Written without marking it for the mirror: the binding is this
            // cache's, not the context's.
            store.put_cached(Table::Meta, BINDING_META, &want)
        }
    }
}

/// `vgi-bridge vta setup`: what was checked, for the operator.
#[derive(Debug, Default)]
pub struct SetupReport {
    /// The bridge's DID.
    pub did: String,
    /// Lines to print, in order (`ok …` / `warning …`).
    pub lines: Vec<String>,
    /// Anything that stops the bridge from working.
    pub failed: bool,
}

impl SetupReport {
    fn ok(&mut self, s: impl Into<String>) {
        self.lines.push(format!("ok       {}", s.into()));
    }
    fn warn(&mut self, s: impl Into<String>) {
        self.lines.push(format!("warning  {}", s.into()));
    }
    fn fail(&mut self, s: impl Into<String>) {
        self.failed = true;
        self.lines.push(format!("FAILED   {}", s.into()));
    }
}

/// Verify a VTA context is ready for the bridge: it exists and has a DID
/// with an Ed25519 and an X25519 key, the credential can fetch them and use
/// app-state, and it reaches no other context.
pub async fn setup(
    session: &Session,
    cfg: &VtaConfig,
    mediator_did: &str,
    docs: &dyn DidDocuments,
) -> SetupReport {
    let mut r = SetupReport::default();
    let ctx = session.context().to_string();
    match session.context_did().await {
        Ok(Some(did)) => r.ok(format!("context `{ctx}` exists, DID `{did}`")),
        Ok(None) => {
            r.fail(format!(
                "context `{ctx}` has no DID: provision a did:webvh for the bridge into it (an \
                 Ed25519 signing key and an X25519 key-agreement key, and a DIDCommMessaging \
                 service naming `{mediator_did}`)"
            ));
            return r;
        }
        Err(e) => {
            r.fail(format!("{e:#}"));
            return r;
        }
    }
    match session.load_identity(cfg.did.as_deref(), docs, None).await {
        Ok(id) => {
            r.did = id.did().to_string();
            r.ok(format!(
                "the credential fetches the DID's keys, and its current document lists {} of \
                 them (signing with `{}`); held in memory only",
                id.messaging_secrets().len(),
                id.signing_key_id()
            ));
            match crate::identity::check_reachable(id.did(), mediator_did) {
                Ok(None) => {}
                Ok(Some(w)) => r.warn(w),
                Err(e) => r.fail(format!("{e:#}")),
            }
        }
        Err(e) => r.fail(format!("{e:#}")),
    }
    match session.sealing_key(true).await {
        Ok(_) => r.ok(format!(
            "the key secrets are sealed under (`{SEAL_KEY_LABEL}`) is in the context and exports"
        )),
        Err(e) => r.fail(format!("{e:#}")),
    }
    let remote = VtaAppState::new(session);
    let probe = "setup/probe";
    let probed = async {
        let v = remote
            .put(probe, json!({ "at": chrono::Utc::now().timestamp() }), None)
            .await
            .map_err(|e| anyhow!("{e}"))?;
        let back = remote
            .get(probe)
            .await?
            .context("the probe did not read back")?;
        if back.version != v {
            bail!("the probe read back at another version");
        }
        remote
            .delete(probe, Some(v))
            .await
            .map_err(|e| anyhow!("{e}"))?;
        anyhow::Ok(())
    };
    match probed.await {
        Ok(()) => r.ok(format!(
            "the credential writes, reads and deletes app-state (`{NAMESPACE}`)"
        )),
        Err(e) => r.fail(format!("app-state: {e:#}")),
    }
    match remote.list().await {
        Ok(records) => {
            let secrets = records
                .iter()
                .filter(|x| x.key.starts_with("secret/"))
                .count();
            let state = records
                .iter()
                .filter(|x| x.key.starts_with("state/"))
                .count();
            r.ok(format!(
                "app-state holds {secrets} secrets and {state} state records"
            ));
        }
        Err(e) => r.fail(format!("{e:#}")),
    }
    match session.visible_contexts().await {
        Ok(ids) => {
            let prefix = format!("{ctx}/");
            let others: Vec<_> = ids
                .iter()
                .filter(|i| **i != ctx && !i.starts_with(&prefix))
                .cloned()
                .collect();
            if others.is_empty() {
                r.ok(format!("the credential reaches `{ctx}` only"));
            } else {
                r.warn(format!(
                    "the credential also reaches {others:?}: it should be an admin scoped to `{ctx}` \
                     alone (`pnm acl create --did <did:key> --role admin --contexts {ctx}`), so a \
                     compromised bridge host cannot touch the VTC's keys"
                ));
            }
        }
        Err(e) => r.warn(format!(
            "could not list the contexts the credential sees: {e:#}"
        )),
    }
    r
}

/// Build the in-memory half of VTA mode and pull the context's state into
/// `store`: returns the store (a cache now) and the mirror to run.
pub async fn attach(
    session: &Session,
    store: crate::store::Store,
    budget: Duration,
) -> Result<(
    crate::store::Store,
    Arc<crate::appstate::Mirror>,
    Arc<dyn AppState>,
)> {
    let seal = with_retry(budget, "fetching the bridge's sealing key", || {
        session.sealing_key(true)
    })
    .await?;
    let mirror = crate::appstate::Mirror::new(seal);
    let store = store.with_mirror(mirror.clone());
    let remote: Arc<dyn AppState> = Arc::new(VtaAppState::new(session));
    with_retry(budget, "pulling the bridge's state from the VTA", || {
        mirror.pull(remote.as_ref(), &store)
    })
    .await?;
    Ok((store, mirror, remote))
}

#[cfg(test)]
pub(crate) mod testing {
    #![allow(dead_code)]
    //! A scripted VTA behind the SDK's loopback transport: the context's
    //! DID bundle, contexts, and app-state with the VTA's versioning.

    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use vta_sdk::client::loopback::LoopbackSink;
    use vta_sdk::trust_tasks as tt;

    /// A namespace counter and its records, by key.
    type Versioned = (u64, BTreeMap<String, (u64, Value)>);

    pub struct FakeVta {
        pub context: String,
        pub bundle: Mutex<Value>,
        pub contexts: Vec<String>,
        state: Mutex<Versioned>,
        pub forbid_secrets: bool,
        /// Keys created in the context: id, label, private multibase.
        keys_made: Mutex<Vec<(String, String, String)>>,
        /// The DID's keys the VTA has ever held: id → (key type, created
        /// at, millis). Listed while the bundle carries them.
        did_keys: Mutex<BTreeMap<String, (String, i64)>>,
    }

    /// The bridge's DID document as published, set by the test.
    pub struct FakeDocs(pub Mutex<Value>);

    impl FakeDocs {
        pub fn listing(did: &str, bundles: &[&DidSecretsBundle]) -> Arc<Self> {
            Arc::new(FakeDocs(Mutex::new(doc_for(did, bundles))))
        }
        /// Publish a new document listing `bundles`' keys.
        pub fn publish(&self, did: &str, bundles: &[&DidSecretsBundle]) {
            *self.0.lock().unwrap() = doc_for(did, bundles);
        }
    }

    #[async_trait]
    impl DidDocuments for FakeDocs {
        async fn current(&self, _did: &str) -> Result<Value> {
            Ok(self.0.lock().unwrap().clone())
        }
    }

    /// A DID document listing every key of `bundles`: Ed25519 keys under
    /// `assertionMethod`, X25519 under `keyAgreement`.
    pub fn doc_for(did: &str, bundles: &[&DidSecretsBundle]) -> Value {
        use affinidi_tdk::secrets_resolver::secrets::Secret;
        let mut vms = Vec::new();
        let (mut sign, mut agree) = (Vec::new(), Vec::new());
        for b in bundles {
            for e in &b.secrets {
                let secret =
                    Secret::from_multibase(&e.private_key_multibase, Some(&e.key_id)).unwrap();
                let prefix: [u8; 2] = match e.key_type {
                    vta_sdk::keys::KeyType::Ed25519 => {
                        sign.push(json!(e.key_id));
                        [0xed, 0x01]
                    }
                    _ => {
                        agree.push(json!(e.key_id));
                        [0xec, 0x01]
                    }
                };
                let mut raw = prefix.to_vec();
                raw.extend_from_slice(secret.get_public_bytes());
                vms.push(json!({
                    "id": e.key_id, "type": "Multikey", "controller": did,
                    "publicKeyMultibase": multibase::encode(multibase::Base::Base58Btc, raw),
                }));
            }
        }
        json!({
            "id": did, "verificationMethod": vms,
            "assertionMethod": sign, "authentication": sign.clone(), "keyAgreement": agree,
        })
    }

    /// Two bundles' keys as one (the VTA holding both during a rotation).
    pub fn merged(a: &DidSecretsBundle, b: &DidSecretsBundle) -> DidSecretsBundle {
        let mut out = a.clone();
        out.secrets.extend(b.secrets.iter().cloned());
        out
    }

    /// The wire form of a DID secrets bundle.
    pub fn bundle_json(bundle: &DidSecretsBundle) -> Value {
        json!({
            "did": bundle.did,
            "secrets": bundle.secrets.iter().map(|e| json!({
                "keyId": e.key_id,
                "keyType": e.key_type,
                "privateKeyMultibase": e.private_key_multibase,
            })).collect::<Vec<_>>(),
        })
    }

    /// A fresh key pair for `did` (a `did:webvh` stand-in: `#key-0`
    /// Ed25519, `#key-1` X25519), as a secrets bundle.
    pub fn webvh_bundle(did: &str) -> DidSecretsBundle {
        webvh_bundle_from(did, 0)
    }

    /// As [`webvh_bundle`], numbered from `#key-{first}`.
    pub fn webvh_bundle_from(did: &str, first: usize) -> DidSecretsBundle {
        let (_, mut b) = BridgeIdentity::generate_did_peer("did:web:mediator.example").unwrap();
        for (i, e) in b.secrets.iter_mut().enumerate() {
            e.key_id = format!("{did}#key-{}", first + i);
        }
        b.did = did.to_string();
        b
    }

    impl FakeVta {
        pub fn new(context: &str, bundle: &DidSecretsBundle) -> Self {
            FakeVta {
                context: context.into(),
                // The wire's spelling (lowerCamelCase), not the bundle's.
                bundle: Mutex::new(bundle_json(bundle)),
                contexts: vec![context.into()],
                state: Mutex::new((0, BTreeMap::new())),
                forbid_secrets: false,
                keys_made: Mutex::new(Vec::new()),
                did_keys: Mutex::new(Self::ages(&BTreeMap::new(), bundle)),
            }
        }

        fn ages(
            known: &BTreeMap<String, (String, i64)>,
            bundle: &DidSecretsBundle,
        ) -> BTreeMap<String, (String, i64)> {
            let mut out = known.clone();
            let mut next = known.values().map(|(_, t)| *t).max().unwrap_or(0);
            for e in &bundle.secrets {
                out.entry(e.key_id.clone()).or_insert_with(|| {
                    next += 1000;
                    let ty = match e.key_type {
                        vta_sdk::keys::KeyType::Ed25519 => "ed25519",
                        _ => "x25519",
                    };
                    (ty.to_string(), next)
                });
            }
            out
        }

        pub fn session(self: &Arc<Self>) -> Session {
            let sink: Arc<dyn LoopbackSink> = self.clone();
            Session::from_client(VtaClient::loopback(sink), self.context.clone())
        }

        /// The VTA now holds (and releases) exactly `bundle`'s keys.
        pub fn rotate(&self, bundle: &DidSecretsBundle) {
            let mut ages = self.did_keys.lock().unwrap();
            *ages = Self::ages(&ages, bundle);
            *self.bundle.lock().unwrap() = bundle_json(bundle);
        }

        pub fn keys(&self) -> Vec<String> {
            self.state.lock().unwrap().1.keys().cloned().collect()
        }

        fn record(&self, key: &str, version: u64, value: Option<&Value>) -> Value {
            let mut r = json!({
                "contextId": self.context, "namespace": NAMESPACE, "key": key,
                "version": version, "deleted": false, "updatedAt": "2026-09-25T00:00:00Z",
            });
            if let Some(v) = value {
                r["value"] = v.clone();
            }
            r
        }
    }

    impl LoopbackSink for FakeVta {
        fn dispatch(&self, uri: &str, p: &Value) -> std::result::Result<Value, VtaError> {
            if let Some(c) = p.get("contextId").and_then(Value::as_str)
                && c != self.context
            {
                return Err(VtaError::Forbidden(format!("no access to context {c}")));
            }
            let key = p
                .get("key")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let mut st = self.state.lock().unwrap();
            let conflict = || {
                VtaError::Protocol(
                    "trust task failed [vta/app-state/put:versionConflict]: record is at another version"
                        .into(),
                )
            };
            match uri {
                u if u == tt::TASK_CONTEXTS_SECRETS_1_0 => {
                    if self.forbid_secrets {
                        return Err(VtaError::Forbidden("key-export required".into()));
                    }
                    Ok(self.bundle.lock().unwrap().clone())
                }
                u if u == tt::TASK_KEYS_LIST_0_1 => {
                    let keys = self.keys_made.lock().unwrap();
                    let mut out: Vec<Value> = keys.iter().map(|(id, label, _)| json!({
                        "keyId": id, "derivationPath": "m/1", "keyType": "ed25519",
                        "status": "active", "publicKey": "z", "label": label,
                        "contextId": self.context,
                        "createdAt": "2026-09-25T00:00:00Z", "updatedAt": "2026-09-25T00:00:00Z",
                    })).collect();
                    let bundle = self.bundle.lock().unwrap().clone();
                    let ages = self.did_keys.lock().unwrap();
                    for e in bundle["secrets"].as_array().unwrap() {
                        let id = e["keyId"].as_str().unwrap();
                        let (ty, at) = ages[id].clone();
                        let at = chrono::DateTime::from_timestamp_millis(1_790_000_000_000 + at)
                            .unwrap()
                            .to_rfc3339();
                        out.push(json!({
                            "keyId": id, "derivationPath": "m/2", "keyType": ty,
                            "status": "active", "publicKey": format!("z{id}"),
                            "contextId": self.context, "createdAt": at, "updatedAt": at,
                        }));
                    }
                    let total = out.len();
                    Ok(json!({ "keys": out, "total": total }))
                }
                u if u == tt::TASK_KEYS_CREATE_0_1 => {
                    let mut keys = self.keys_made.lock().unwrap();
                    let id = format!("key-{}", keys.len());
                    // Any Ed25519 private key in the VTA's multibase form.
                    let (_, b) = BridgeIdentity::generate_did_peer("did:web:m.example").unwrap();
                    let mb = b
                        .secrets
                        .iter()
                        .find(|e| e.key_type == vta_sdk::keys::KeyType::Ed25519)
                        .unwrap()
                        .private_key_multibase
                        .clone();
                    keys.push((
                        id.clone(),
                        p["label"].as_str().unwrap_or("").to_string(),
                        mb,
                    ));
                    Ok(json!({ "key": {
                        "keyId": id, "keyType": "ed25519", "derivationPath": "m/1",
                        "publicKey": "z", "status": "active", "label": p["label"],
                        "createdAt": "2026-09-25T00:00:00Z",
                    }}))
                }
                u if u == tt::TASK_KEYS_EXPORT_SECRET_0_1 => {
                    let keys = self.keys_made.lock().unwrap();
                    let id = p["keyId"].as_str().unwrap_or("");
                    let (_, _, mb) = keys
                        .iter()
                        .find(|(k, _, _)| k == id)
                        .ok_or_else(|| VtaError::NotFound(id.to_string()))?;
                    Ok(json!({ "keyId": id, "keyType": "ed25519",
                        "publicKeyMultibase": "z", "privateKeyMultibase": mb }))
                }
                u if u == tt::TASK_CONTEXTS_GET_1_0 => Ok(json!({
                    "id": self.context, "name": self.context,
                    "did": self.bundle.lock().unwrap()["did"].clone(), "basePath": "m/0", "index": 0,
                    "createdAt": "2026-09-25T00:00:00Z", "updatedAt": "2026-09-25T00:00:00Z",
                })),
                u if u == tt::TASK_CONTEXTS_LIST_1_0 => Ok(json!({
                    "contexts": self.contexts.iter().map(|c| json!({
                        "id": c, "name": c, "basePath": "m/0", "index": 0,
                        "createdAt": "2026-09-25T00:00:00Z", "updatedAt": "2026-09-25T00:00:00Z",
                    })).collect::<Vec<_>>()
                })),
                u if u == tt::TASK_VTA_APP_STATE_GET_1_0 => match st.1.get(&key) {
                    Some((v, value)) => Ok(json!({ "record": self.record(&key, *v, Some(value)) })),
                    None => Err(VtaError::NotFound(key)),
                },
                u if u == tt::TASK_VTA_APP_STATE_PUT_1_0 => {
                    let current = st.1.get(&key).map(|(v, _)| *v);
                    let expected = p.get("expectedVersion").and_then(Value::as_u64);
                    let ok = match (expected, current) {
                        (None, _) | (Some(0), None) => true,
                        (Some(e), Some(c)) => e == c,
                        _ => false,
                    };
                    if !ok {
                        return Err(conflict());
                    }
                    st.0 += 1;
                    let v = st.0;
                    st.1.insert(key.clone(), (v, p["value"].clone()));
                    Ok(json!({
                        "contextId": self.context, "namespace": NAMESPACE, "key": key,
                        "version": v, "created": current.is_none(), "updatedAt": "2026-09-25T00:00:00Z",
                    }))
                }
                u if u == tt::TASK_VTA_APP_STATE_DELETE_1_0 => {
                    let current = st.1.get(&key).map(|(v, _)| *v);
                    if let Some(e) = p.get("expectedVersion").and_then(Value::as_u64)
                        && Some(e) != current
                    {
                        return Err(conflict());
                    }
                    let existed = st.1.remove(&key).is_some();
                    st.0 += 1;
                    Ok(
                        json!({ "contextId": self.context, "namespace": NAMESPACE, "key": key,
                        "existed": existed, "version": st.0, "deletedAt": "2026-09-25T00:00:00Z" }),
                    )
                }
                u if u == tt::TASK_VTA_APP_STATE_LIST_1_0 => {
                    let records: Vec<Value> =
                        st.1.iter()
                            .map(|(k, (v, value))| self.record(k, *v, Some(value)))
                            .collect();
                    Ok(json!({ "records": records, "truncated": false, "highWatermark": st.0 }))
                }
                other => Err(VtaError::Validation(format!(
                    "the fake VTA does not do {other}"
                ))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::FakeVta;
    use super::*;
    use crate::seal::MasterKey;
    use crate::store::{Store, Table};

    const MEDIATOR: &str = "did:web:mediator.acme-vtc.example";

    fn fake() -> (Arc<FakeVta>, BridgeIdentity, Arc<super::testing::FakeDocs>) {
        let (id, bundle) = BridgeIdentity::generate_did_peer(MEDIATOR).unwrap();
        let docs = super::testing::FakeDocs::listing(id.did(), &[&bundle]);
        (Arc::new(FakeVta::new("vgi-bridge", &bundle)), id, docs)
    }

    #[test]
    fn credentials_parse_as_json_or_base64_and_must_be_did_key() {
        let json = r#"{"did":"did:key:z6MkX","privateKeyMultibase":"z1","vtaDid":"did:web:vta.example","vtaUrl":"https://vta.example"}"#;
        assert_eq!(parse_credential(json).unwrap().did, "did:key:z6MkX");
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json);
        assert_eq!(
            parse_credential(&b64).unwrap().vta_did,
            "did:web:vta.example"
        );
        assert!(parse_credential(&json.replace("did:key:z6MkX", "did:web:x")).is_err());
        assert!(parse_credential("-----BEGIN VTA SEALED BUNDLE-----").is_err());
        assert!(url_is_secure("https://vta.example"));
        assert!(url_is_secure("http://localhost:8100"));
        assert!(!url_is_secure("http://localhost.evil.example"));
        assert!(!url_is_secure("http://vta.example"));
    }

    #[tokio::test]
    async fn the_identity_comes_from_the_context_and_signs_as_before() {
        let (vta, minted, docs) = fake();
        let s = vta.session();
        let id = s.load_identity(None, docs.as_ref(), None).await.unwrap();
        assert_eq!(id.did(), minted.did());
        assert_eq!(id.messaging_secrets().len(), 2);
        assert_eq!(
            id.git_signing_key().unwrap().key.to_bytes(),
            minted.git_signing_key().unwrap().key.to_bytes()
        );
        // The config naming another DID is refused.
        let err = s
            .load_identity(Some("did:webvh:QmOther:x.example"), docs.as_ref(), None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("vta.did"), "{err}");
        // A document that lists none of the keys the VTA releases: refused.
        *docs.0.lock().unwrap() = json!({ "id": id.did() });
        let err = s
            .load_identity(None, docs.as_ref(), None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("lists no signing"), "{err}");
    }

    #[tokio::test]
    async fn a_credential_without_key_export_is_told_what_role_it_needs() {
        let (id, bundle) = BridgeIdentity::generate_did_peer(MEDIATOR).unwrap();
        let docs = super::testing::FakeDocs::listing(id.did(), &[&bundle]);
        let mut f = FakeVta::new("vgi-bridge", &bundle);
        f.forbid_secrets = true;
        let err = Arc::new(f)
            .session()
            .load_identity(None, docs.as_ref(), None)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("--role admin --contexts vgi-bridge"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn app_state_round_trips_with_versions_and_conflicts() {
        let (vta, _, _) = fake();
        let remote = VtaAppState::new(&vta.session());
        let v1 = remote.put("state/meta/a", json!(1), Some(0)).await.unwrap();
        assert!(matches!(
            remote.put("state/meta/a", json!(2), Some(0)).await,
            Err(PutError::Conflict(Some(v))) if v == v1
        ));
        let v2 = remote
            .put("state/meta/a", json!(2), Some(v1))
            .await
            .unwrap();
        assert_eq!(
            remote.get("state/meta/a").await.unwrap().unwrap().version,
            v2
        );
        assert_eq!(remote.list().await.unwrap().len(), 1);
        remote.delete("state/meta/a", Some(v2)).await.unwrap();
        assert!(remote.get("state/meta/a").await.unwrap().is_none());
        remote.delete("state/meta/a", None).await.unwrap();
    }

    #[tokio::test]
    async fn a_new_host_rebuilds_from_the_vta() {
        let (vta, _, _) = fake();
        let session = vta.session();
        let store = Store::in_memory(MasterKey::generate().unwrap()).unwrap();
        let (store, mirror, remote) = attach(&session, store, Duration::from_secs(1))
            .await
            .unwrap();
        store
            .put_secret("github/github.com/app", b"{\"pem\":\"k\"}")
            .unwrap();
        store
            .put(Table::Namespaces, "ns_1", &json!({ "id": "ns_1" }))
            .unwrap();
        mirror.sync_once(remote.as_ref(), &store).await.unwrap();
        assert!(
            store.raw_secret_rows().unwrap().is_empty(),
            "no secret on disk"
        );
        assert_eq!(
            vta.keys(),
            ["secret/github/github.com/app", "state/namespaces/ns_1"]
        );

        // The host is lost: a new one, an empty data directory.
        let fresh = Store::in_memory(MasterKey::generate().unwrap()).unwrap();
        let (fresh, m2, _) = attach(&session, fresh, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(m2.pending(), 0);
        assert_eq!(
            &*fresh.get_secret("github/github.com/app").unwrap().unwrap(),
            b"{\"pem\":\"k\"}"
        );
        assert!(
            fresh
                .get::<Value>(Table::Namespaces, "ns_1")
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn setup_checks_the_context_and_warns_about_a_wide_credential() {
        let (id, bundle) = BridgeIdentity::generate_did_peer(MEDIATOR).unwrap();
        let docs = super::testing::FakeDocs::listing(id.did(), &[&bundle]);
        let mut f = FakeVta::new("vgi-bridge", &bundle);
        let cfg: VtaConfig =
            toml::from_str("context = \"vgi-bridge\"\ncredential_file = \"/x\"").unwrap();
        let r = setup(
            &Arc::new(FakeVta::new("vgi-bridge", &bundle)).session(),
            &cfg,
            MEDIATOR,
            docs.as_ref(),
        )
        .await;
        assert!(!r.failed, "{:#?}", r.lines);
        assert_eq!(r.did, id.did());
        assert!(
            r.lines
                .iter()
                .any(|l| l.contains("reaches `vgi-bridge` only")),
            "{:#?}",
            r.lines
        );

        f.contexts.push("vtc".into());
        let r = setup(&Arc::new(f).session(), &cfg, MEDIATOR, docs.as_ref()).await;
        assert!(
            r.lines
                .iter()
                .any(|l| l.starts_with("warning") && l.contains("vtc")),
            "{:#?}",
            r.lines
        );
    }

    #[test]
    fn a_cache_is_bound_to_its_context_and_did() {
        let s = Store::in_memory(MasterKey::generate().unwrap()).unwrap();
        check_cache_binding(&s, "did:web:vta", "vgi-bridge", "did:webvh:Qm:b").unwrap();
        check_cache_binding(&s, "did:web:vta", "vgi-bridge", "did:webvh:Qm:b").unwrap();
        assert!(check_cache_binding(&s, "did:web:vta", "other", "did:webvh:Qm:b").is_err());
        // A sealed-mode store is not reused as a cache.
        let old = Store::in_memory(MasterKey::generate().unwrap()).unwrap();
        old.put_secret("identity", b"x").unwrap();
        assert!(check_cache_binding(&old, "did:web:vta", "vgi-bridge", "did:webvh:Qm:b").is_err());
    }

    /// A verification-method resolver that knows one set of keys — the
    /// DID document as the VTC would resolve it after the rotation.
    struct Published(std::collections::BTreeMap<String, Vec<u8>>);

    #[async_trait]
    impl affinidi_data_integrity::VerificationMethodResolver for Published {
        async fn resolve_vm(
            &self,
            vm: &str,
        ) -> std::result::Result<
            affinidi_data_integrity::did_vm::ResolvedKey,
            affinidi_data_integrity::DataIntegrityError,
        > {
            self.0
                .get(vm)
                .map(|k| {
                    affinidi_data_integrity::did_vm::ResolvedKey::new(
                        affinidi_tdk::affinidi_crypto::KeyType::Ed25519,
                        k.clone(),
                    )
                })
                .ok_or_else(|| {
                    affinidi_data_integrity::DataIntegrityError::Resolver(format!(
                        "{vm} is not published"
                    ))
                })
        }
    }

    fn published(id: &BridgeIdentity) -> trust_tasks_proof::affinidi::Verifier {
        let k = id.git_signing_key().unwrap();
        let map = [(
            k.verification_method.clone(),
            k.key.verifying_key().to_bytes().to_vec(),
        )]
        .into_iter()
        .collect();
        trust_tasks_proof::affinidi::Verifier::with_resolver(Arc::new(Published(map)))
    }

    /// A rotation, step by step: the bridge holds every key its current DID
    /// document lists, signs with the newest, keeps the old ones while the
    /// document still lists them (a message encrypted to either opens), and
    /// drops a key only when the document stops listing it. Jobs keep
    /// flowing throughout.
    #[tokio::test]
    async fn the_bridge_holds_what_its_did_document_lists_through_a_rotation() {
        use super::testing::{FakeDocs, merged, webvh_bundle_from};
        use crate::transport::InboundDoc;
        use crate::transport::memory::ChannelLink;
        const DID: &str = "did:webvh:QmBridge:bridge.acme.example";
        let old_keys = webvh_bundle_from(DID, 0);
        let new_keys = webvh_bundle_from(DID, 2);
        let vta = Arc::new(FakeVta::new("vgi-bridge", &old_keys));
        let docs = FakeDocs::listing(DID, &[&old_keys]);
        let session = vta.session();
        let cfg_vta: VtaConfig =
            toml::from_str("context = \"vgi-bridge\"\ncredential_file = \"/x\"").unwrap();

        let (vtc, _) = BridgeIdentity::generate_did_key().unwrap();
        let cfg = crate::config::BridgeConfig::parse(&format!(
            r#"
vtc_did = "{}"
trust_registry_did = "did:webvh:QmReg:registry.acme.example"
mediator_did = "did:web:mediator.acme.example"
public_url = "https://bridge.acme.example/"
[verify_trust]
action = "OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@0123456789abcdef0123456789abcdef01234567"
version = "v0.5.0"
"#,
            vtc.did()
        ))
        .unwrap();
        let identity = session
            .load_identity(None, docs.as_ref(), None)
            .await
            .unwrap();
        let old = identity.clone();
        let store = Store::in_memory(MasterKey::generate().unwrap()).unwrap();
        let (link, mut inbox) = ChannelLink::new();
        let bridge = crate::Bridge::new(crate::BridgeParts::new(
            cfg,
            identity,
            store,
            crate::registry::Adapters::new(),
            Arc::new(link),
            Arc::new(trust_tasks_proof::affinidi::Verifier::for_did_key()),
        ));
        let rotations = bridge.rotations();
        let ids = |b: &crate::Bridge| -> Vec<String> {
            let mut v: Vec<String> = b
                .identity()
                .messaging_secrets()
                .iter()
                .map(|s| s.id.rsplit('#').next().unwrap().to_string())
                .collect();
            v.sort();
            v
        };

        let mut n = 0;
        let mut answer = async |bridge: &Arc<crate::Bridge>| -> Value {
            n += 1;
            let id = crate::wire::new_id();
            let doc = json!({
                "id": id, "type": "https://trusttasks.org/spec/git-ns/bridge/job/0.1",
                "threadId": id, "issuer": vtc.did(), "recipient": DID,
                "issuedAt": chrono::Utc::now().to_rfc3339(),
                "payload": { "jobId": format!("job_{n}"), "namespace": "ns_unknown",
                             "kind": "inspect", "repo": "github.com/acme/widgets" },
            });
            let doc = vtc.sign(&doc).await.unwrap();
            let arc = bridge;
            arc.handle_inbound(InboundDoc {
                doc,
                authenticated_sender: Some(vtc.did().into()),
            })
            .await;
            inbox.try_recv().expect("the bridge answered").1
        };

        let a = answer(&bridge).await;
        published(&old)
            .verify_raw(&a)
            .await
            .expect("the key in service signs");
        assert!(
            !refresh_once(&bridge, &session, &cfg_vta, docs.as_ref())
                .await
                .unwrap()
        );

        // 1. The VTA mints the successor keys, not yet in the document: not
        //    held, not used.
        vta.rotate(&merged(&old_keys, &new_keys));
        assert!(
            !refresh_once(&bridge, &session, &cfg_vta, docs.as_ref())
                .await
                .unwrap()
        );
        assert_eq!(ids(&bridge), ["key-0", "key-1"]);

        // 2. The document lists both (the overlap): all four held, the
        //    newest signs.
        docs.publish(DID, &[&old_keys, &new_keys]);
        assert!(
            refresh_once(&bridge, &session, &cfg_vta, docs.as_ref())
                .await
                .unwrap()
        );
        assert!(
            rotations.has_changed().unwrap(),
            "DIDComm reconnects with every listed key"
        );
        assert_eq!(ids(&bridge), ["key-0", "key-1", "key-2", "key-3"]);
        let new = bridge.identity();
        assert!(
            new.signing_key_id().ends_with("#key-2"),
            "{}",
            new.signing_key_id()
        );
        let a = answer(&bridge).await;
        published(&new)
            .verify_raw(&a)
            .await
            .expect("the newest key signs");
        assert!(published(&old).verify_raw(&a).await.is_err());

        // 3. The VTA stops releasing the old keys, but the document still
        //    lists them: the bridge keeps its copies.
        vta.rotate(&new_keys);
        refresh_once(&bridge, &session, &cfg_vta, docs.as_ref())
            .await
            .unwrap();
        assert_eq!(ids(&bridge), ["key-0", "key-1", "key-2", "key-3"]);

        // 4. The document stops listing them (the end of the overlap): gone.
        docs.publish(DID, &[&new_keys]);
        assert!(
            refresh_once(&bridge, &session, &cfg_vta, docs.as_ref())
                .await
                .unwrap()
        );
        assert_eq!(ids(&bridge), ["key-2", "key-3"]);
        let a = answer(&bridge).await;
        published(&new)
            .verify_raw(&a)
            .await
            .expect("jobs keep flowing");
        assert_eq!(
            bridge.identity().git_signing_key().unwrap().key.to_bytes(),
            new.git_signing_key().unwrap().key.to_bytes(),
            "the re-sign key moved too"
        );

        // A document whose key id carries another public key is not trusted
        // with it, and a context that suddenly names another DID is refused;
        // the keys in service stay.
        let impostor = webvh_bundle_from(DID, 2);
        docs.publish(DID, &[&impostor]);
        assert!(
            refresh_once(&bridge, &session, &cfg_vta, docs.as_ref())
                .await
                .is_err()
        );
        let other = webvh_bundle_from("did:webvh:QmOther:elsewhere.example", 0);
        docs.publish(DID, &[&new_keys]);
        vta.rotate(&other);
        assert!(
            refresh_once(&bridge, &session, &cfg_vta, docs.as_ref())
                .await
                .is_err()
        );
        assert_eq!(ids(&bridge), ["key-2", "key-3"]);
    }
}
