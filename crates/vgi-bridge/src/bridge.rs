//! The bridge core: inbound documents, the job ledger, the outbox, restore.
//!
//! Everything the VTC sends arrives at [`Bridge::handle_inbound`] after the
//! transport; everything the bridge sends goes through
//! `Bridge::send_outbox`. The per-kind job logic is in [`crate::jobs`], the
//! person-facing flows in [`crate::flows`], webhooks in [`crate::events`].

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{Value, json};
use trust_tasks_rs::{ErrorPayload, Payload as _, StandardCode, TrustTask};
use vgi_forge::Resource;

use crate::config::BridgeConfig;
use crate::identity::BridgeIdentity;
use crate::mapping::{self, Report};
use crate::registry::Adapters;
use crate::store::{
    JobRecord, JobState, NamespaceRecord, NamespaceState, OutboxEntry, OutboxKind, Store, Table,
};
use crate::transport::{InboundDoc, VtcLink};
use crate::wire::{self, DocChecker, VerifiedDoc, event, job, result};

/// What [`Bridge::new`] is built from.
#[non_exhaustive]
pub struct BridgeParts {
    /// The configuration.
    pub config: BridgeConfig,
    /// The bridge's DID and keys.
    pub identity: BridgeIdentity,
    /// The state store.
    pub store: Store,
    /// The forge adapters.
    pub adapters: Adapters,
    /// The link to the VTC.
    pub link: Arc<dyn VtcLink>,
    /// How inbound proofs are checked.
    pub proof: Arc<dyn wire::ProofCheck>,
    /// How the bridge-posted check verifies commits.
    #[cfg(feature = "forge-github")]
    pub commits: Arc<dyn crate::checks::CommitVerifier>,
    /// How commits are fetched for the check.
    #[cfg(feature = "forge-github")]
    pub fetcher: crate::checks::GitFetcher,
}

impl BridgeParts {
    /// The parts, with the default commit verifier and fetcher.
    pub fn new(
        config: BridgeConfig,
        identity: BridgeIdentity,
        store: Store,
        adapters: Adapters,
        link: Arc<dyn VtcLink>,
        proof: Arc<dyn wire::ProofCheck>,
    ) -> Self {
        #[cfg(feature = "forge-github")]
        let (commits, fetcher) = {
            let c: Arc<dyn crate::checks::CommitVerifier> =
                Arc::new(crate::checks::VerifyTrustVerifier::new(&config));
            (c, crate::checks::GitFetcher::new(&config.checks))
        };
        BridgeParts {
            config,
            identity,
            store,
            adapters,
            link,
            proof,
            #[cfg(feature = "forge-github")]
            commits,
            #[cfg(feature = "forge-github")]
            fetcher,
        }
    }

    /// Replace the commit verifier (tests; a verifier with a pinned
    /// resolver).
    #[cfg(feature = "forge-github")]
    pub fn with_commit_verifier(mut self, v: Arc<dyn crate::checks::CommitVerifier>) -> Self {
        self.commits = v;
        self
    }

    /// Replace the fetcher (tests fetch from a local repository).
    #[cfg(feature = "forge-github")]
    pub fn with_fetcher(mut self, f: crate::checks::GitFetcher) -> Self {
        self.fetcher = f;
        self
    }
}

/// The bridge.
pub struct Bridge {
    pub(crate) cfg: BridgeConfig,
    /// The bridge's DID: fixed for the process (a key rotation keeps it).
    did: String,
    /// Its keys, replaced when the VTA rotates them ([`Bridge::replace_identity`]).
    identity: std::sync::RwLock<BridgeIdentity>,
    /// Bumped on every rotation, so the DIDComm link reconnects with the
    /// new key-agreement key.
    rotation: tokio::sync::watch::Sender<u64>,
    pub(crate) store: Store,
    pub(crate) adapters: Adapters,
    pub(crate) link: Arc<dyn VtcLink>,
    pub(crate) checker: DocChecker,
    ns_locks: Mutex<BTreeMap<String, Arc<tokio::sync::Mutex<()>>>>,
    #[cfg(feature = "forge-github")]
    pub(crate) checks: crate::checks::CheckRunner,
    #[cfg(feature = "forge-github")]
    pub(crate) resign: crate::resign::ResignRunner,
}

impl std::fmt::Debug for Bridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bridge")
            .field("did", &self.did)
            .field("vtc", &self.cfg.vtc_did)
            .field("adapters", &self.adapters)
            .finish_non_exhaustive()
    }
}

/// How long a result or event waits for the VTA mirror before it is held
/// for the next resend.
const OUTBOX_FLUSH: std::time::Duration = std::time::Duration::from_secs(10);

/// Unix seconds now.
pub(crate) fn now() -> i64 {
    Utc::now().timestamp()
}

/// A job refusal at request time.
pub(crate) struct JobRefusal(pub Box<ErrorPayload>);

impl JobRefusal {
    fn standard(code: StandardCode, msg: impl Into<String>) -> Self {
        JobRefusal(Box::new(ErrorPayload::new(code).with_message(msg)))
    }

    pub(crate) fn unknown_namespace(msg: impl Into<String>) -> Self {
        JobRefusal(Box::new(
            ErrorPayload::from(job::error_codes::UNKNOWN_NAMESPACE).with_message(msg),
        ))
    }

    pub(crate) fn not_capable(msg: impl Into<String>) -> Self {
        JobRefusal(Box::new(
            ErrorPayload::from(job::error_codes::NOT_CAPABLE).with_message(msg),
        ))
    }
}

impl Bridge {
    /// Assemble a bridge. Call [`Bridge::restore`] before taking traffic.
    pub fn new(parts: BridgeParts) -> Arc<Self> {
        let checker = DocChecker::new(
            parts.config.vtc_did.clone(),
            parts.identity.did().to_string(),
            parts.config.max_job_age_secs,
            parts.proof,
        );
        #[cfg(feature = "forge-github")]
        let checks =
            crate::checks::CheckRunner::new(&parts.config.checks, parts.commits, parts.fetcher);
        #[cfg(feature = "forge-github")]
        let resign = crate::resign::ResignRunner::new(parts.config.checks.concurrency);
        Arc::new(Bridge {
            cfg: parts.config,
            did: parts.identity.did().to_string(),
            identity: std::sync::RwLock::new(parts.identity),
            rotation: tokio::sync::watch::channel(0).0,
            store: parts.store,
            adapters: parts.adapters,
            link: parts.link,
            checker,
            ns_locks: Mutex::new(BTreeMap::new()),
            #[cfg(feature = "forge-github")]
            checks,
            #[cfg(feature = "forge-github")]
            resign,
        })
    }

    /// The bridge's DID.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The bridge's current keys.
    pub fn identity(&self) -> BridgeIdentity {
        self.identity.read().expect("lock").clone()
    }

    /// Put rotated keys in service: from now on every document and re-sign
    /// is signed with `new`, and the DIDComm link reconnects with its
    /// key-agreement key. The old keys are dropped. `Ok(false)`: the keys are
    /// the ones already in service. Refused for another DID — a rotation
    /// keeps the DID, and the VTC knows the bridge by it.
    pub fn replace_identity(&self, new: BridgeIdentity) -> Result<bool> {
        if new.did() != self.did {
            anyhow::bail!(
                "the VTA now names the DID `{}` for this bridge, not `{}`: refusing to switch DIDs \
                 at run time (the VTC knows the bridge by its DID); restart after fixing the context",
                new.did(),
                self.did
            );
        }
        let mut current = self.identity.write().expect("lock");
        if current.same_keys(&new) {
            return Ok(false);
        }
        *current = new;
        drop(current);
        self.rotation.send_modify(|g| *g += 1);
        Ok(true)
    }

    /// Changes on every key rotation.
    pub fn rotations(&self) -> tokio::sync::watch::Receiver<u64> {
        self.rotation.subscribe()
    }

    /// The configuration.
    pub fn config(&self) -> &BridgeConfig {
        &self.cfg
    }

    /// The state store.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// The adapters.
    pub fn adapters(&self) -> &Adapters {
        &self.adapters
    }

    /// Bring the adapters and the ledger back after a (re)start:
    ///
    /// 1. every bound namespace goes back to its adapter — on GitHub with
    ///    its required-workflow availability, managed set and pin, without
    ///    which org-mode steps refuse to run;
    /// 2. jobs that were queued or running are run again (every job is
    ///    convergent);
    /// 3. device-flow account links still inside their window are polled
    ///    again;
    /// 4. unacknowledged results and events are sent again.
    pub async fn restore(self: &Arc<Self>) -> Result<()> {
        for (_, ns) in self.store.list::<NamespaceRecord>(Table::Namespaces)? {
            if let Some(adapter) = self.adapters.for_resource(&ns.resource)
                && let Err(e) = adapter.restore(&ns)
            {
                tracing::error!(namespace = %ns.id, error = %e, "could not restore a namespace");
            }
            // A namespace bound before its readiness for the bridge-posted
            // check was recorded: find out, in the background.
            if ns.state == NamespaceState::Bound && ns.bridge_checks.is_none() {
                let me = Arc::clone(self);
                tokio::spawn(async move { me.probe_bridge_checks(&ns.id).await });
            }
        }
        for (id, job) in self.store.list::<JobRecord>(Table::Jobs)? {
            if matches!(job.state, JobState::Queued | JobState::Running) {
                tracing::info!(job = %id, "resuming a job interrupted by a restart");
                self.spawn_job(id);
            }
        }
        crate::flows::resume_device_polls(self)?;
        self.resend_unacknowledged(true).await;
        Ok(())
    }

    /// Ask GitHub whether namespace `ns_id`'s installation carries the
    /// bridge-posted check (checks, pull requests and merge queue
    /// permissions, `pull_request` and `merge_group` events), and record the
    /// answer. Called after a restart for a namespace never probed, and when
    /// an installation accepts new permissions (the upgrade path for an App
    /// registered before these were in its manifest).
    pub(crate) async fn probe_bridge_checks(&self, ns_id: &str) {
        #[cfg(feature = "forge-github")]
        {
            let Ok(Some(ns)) = self.store.get::<NamespaceRecord>(Table::Namespaces, ns_id) else {
                return;
            };
            let Some(adapter) = self.adapters.for_resource(&ns.resource) else {
                return;
            };
            let Some(g) = adapter.github() else {
                return;
            };
            match g.detect_installation(&ns.resource).await {
                Ok((ready, missing)) => {
                    // What the installation lacks, read again: an owner who
                    // approved an upgrade no longer shows it as missing.
                    let _ =
                        self.store
                            .update::<NamespaceRecord, _>(Table::Namespaces, ns_id, |n| {
                                Ok((
                                    n.map(|mut n| {
                                        n.bridge_checks = Some(ready);
                                        if let Some(b) = n.binding.as_mut() {
                                            b.missing_permissions = missing.clone();
                                        }
                                        n
                                    }),
                                    (),
                                ))
                            });
                    if !ready {
                        tracing::warn!(
                            namespace = %ns_id,
                            "the installation lacks what the bridge-posted check needs \
                             (checks: write, pull_requests: read, merge_queues: read, and the \
                             pull_request and merge_group events); its repositories keep the \
                             in-repo workflow until the App is updated and the change approved"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(namespace = %ns_id, error = %e, "could not read the installation")
                }
            }
        }
        #[cfg(not(feature = "forge-github"))]
        let _ = ns_id;
    }

    /// Put an adapter's namespaces back after it came into service later
    /// than start-up (a GitHub App registered at run time).
    pub(crate) fn restore_host(&self, host: &str) -> Result<()> {
        let Some(adapter) = self.adapters.get(host) else {
            return Ok(());
        };
        for (_, ns) in self.store.list::<NamespaceRecord>(Table::Namespaces)? {
            if ns.resource.host() == host {
                adapter.restore(&ns)?;
            }
        }
        Ok(())
    }

    /// One document in from the transport.
    pub async fn handle_inbound(self: &Arc<Self>, inbound: InboundDoc) {
        let verified = match self
            .checker
            .check(&inbound.doc, inbound.authenticated_sender.as_deref())
            .await
        {
            Ok(v) => v,
            Err(refusal) => {
                tracing::warn!(
                    code = %refusal.payload.code,
                    message = refusal.payload.message.as_deref().unwrap_or(""),
                    "refused an inbound document"
                );
                // Answer only a document that claims to be from our VTC:
                // an error sent to whoever a stranger names would make the
                // bridge a reflector.
                if let Some(doc) = &refusal.doc
                    && doc.issuer.as_deref() == Some(self.cfg.vtc_did.as_str())
                    && !doc.type_uri.is_response()
                {
                    self.send_error(doc, refusal.payload).await;
                }
                return;
            }
        };
        let ty = verified.doc.type_uri.to_string();
        if wire::is_job_type(&ty) {
            self.on_job(verified).await;
        } else if ty == result::Response::TYPE_URI {
            self.on_result_ack(&verified);
        } else if wire::is_event_response_type(&ty) {
            self.on_event_ack(&verified);
        } else if verified.doc.type_uri.slug() == "trust-task-error" {
            self.on_error_response(&verified);
        } else {
            tracing::info!(r#type = %ty, "ignoring a document type this bridge does not handle");
            if !verified.doc.type_uri.is_response() {
                self.send_error(
                    &verified.doc,
                    ErrorPayload::new(StandardCode::UnsupportedType)
                        .with_message("this bridge handles git-ns/bridge/job only"),
                )
                .await;
            }
        }
    }

    async fn send_error(&self, request: &TrustTask<Value>, payload: ErrorPayload) {
        match wire::signed_error(&self.identity(), request, payload).await {
            Ok(doc) => {
                if let Err(e) = self.link.send(&self.cfg.vtc_did, &doc).await {
                    tracing::warn!(error = %e, "could not send an error response");
                }
            }
            Err(e) => tracing::error!(error = %e, "could not build an error response"),
        }
    }

    async fn respond(&self, request: &TrustTask<Value>, payload: Value) {
        match wire::signed_response(&self.identity(), request, payload).await {
            Ok(doc) => {
                if let Err(e) = self.link.send(&self.cfg.vtc_did, &doc).await {
                    // The VTC repeats a job it got no answer to; the ledger
                    // answers the repeat.
                    tracing::warn!(error = %e, "could not send a job response");
                }
            }
            Err(e) => tracing::error!(error = %e, "could not build a job response"),
        }
    }

    async fn on_job(self: &Arc<Self>, v: VerifiedDoc) {
        let payload = match wire::parse_job(&v.type_uri(), &v.doc.payload) {
            Ok(p) => p,
            Err(e) => {
                self.send_error(
                    &v.doc,
                    ErrorPayload::new(StandardCode::MalformedRequest).with_message(e),
                )
                .await;
                return;
            }
        };
        if let Err(msg) = wire::check_kind_members(&payload) {
            self.send_error(
                &v.doc,
                ErrorPayload::new(StandardCode::MalformedRequest).with_message(msg),
            )
            .await;
            return;
        }
        let job_id = payload.job_id.to_string();
        // Over the canonical (JCS) form, so a repeat whose members arrive in
        // another order is still the same job.
        let digest =
            trust_tasks_rs::sha256_hex(trust_tasks_rs::canonical_json(&v.doc.payload).as_bytes());

        // A job we already hold: answer from the ledger, never run it again.
        match self.store.get::<JobRecord>(Table::Jobs, &job_id) {
            Ok(Some(existing)) => {
                if existing.digest != digest {
                    self.send_error(
                        &v.doc,
                        ErrorPayload::from(job::error_codes::JOB_ID_REUSED).with_message(
                            "this bridge already holds a job with this jobId and other content",
                        ),
                    )
                    .await;
                    return;
                }
                let finished = existing.state == JobState::Finished;
                let mut resp = json!({ "jobId": job_id, "accepted": !finished });
                if !finished && let Some(next) = existing.next {
                    resp["next"] = next;
                }
                self.respond(&v.doc, resp).await;
                if finished {
                    // How a VTC that lost the result recovers it (spec,
                    // request rule 4): the result is rebuilt from the
                    // ledger and sent again, even if an earlier copy was
                    // acknowledged.
                    let key = format!("result:{job_id}");
                    if let Some(result) = existing.result {
                        let _ =
                            self.store
                                .put_new(Table::Outbox, &key, &OutboxEntry::result(result));
                    }
                    self.send_outbox(&key).await;
                }
                return;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!(error = %e, "job ledger unavailable");
                self.send_error(
                    &v.doc,
                    ErrorPayload::new(StandardCode::Unavailable)
                        .with_message("the bridge's store is unavailable"),
                )
                .await;
                return;
            }
        }

        if let Err(JobRefusal(err)) = self.admit(&payload) {
            self.send_error(&v.doc, *err).await;
            return;
        }

        let record = JobRecord::queued(
            job_id.clone(),
            digest,
            payload.namespace.to_string(),
            payload.kind.to_string(),
            v.doc.payload.clone(),
            now(),
        );
        // Durable before `accepted: true` (spec, request rule 4).
        match self.store.put_new(Table::Jobs, &job_id, &record) {
            Ok(true) => {}
            Ok(false) => {
                // The same job raced in twice; the other copy answers.
                return;
            }
            Err(e) => {
                tracing::error!(error = %e, "could not record a job");
                self.send_error(
                    &v.doc,
                    ErrorPayload::new(StandardCode::Unavailable)
                        .with_message("the bridge could not record the job"),
                )
                .await;
                return;
            }
        }

        match payload.kind {
            job::PayloadKind::BeginBind | job::PayloadKind::BeginAccountLink => {
                let next = crate::flows::begin(self, &payload).await;
                let mut resp = json!({ "jobId": job_id, "accepted": true });
                match next {
                    Ok(next) => {
                        resp["next"] = next.clone();
                        let _ = self
                            .store
                            .update::<JobRecord, _>(Table::Jobs, &job_id, |r| {
                                Ok((
                                    r.map(|mut r| {
                                        r.state = JobState::Waiting;
                                        r.next = Some(next);
                                        r
                                    }),
                                    (),
                                ))
                            });
                        self.respond(&v.doc, resp).await;
                    }
                    Err(report) => {
                        self.respond(&v.doc, resp).await;
                        self.finish_job(&job_id, report).await;
                    }
                }
            }
            _ => {
                self.respond(&v.doc, json!({ "jobId": job_id, "accepted": true }))
                    .await;
                self.spawn_job(job_id);
            }
        }
    }

    /// The request-time refusals (spec, request rules 1 and 2).
    fn admit(&self, p: &job::Payload) -> Result<(), JobRefusal> {
        use job::PayloadKind as K;
        let ns_id = p.namespace.to_string();
        if p.kind == K::BeginBind {
            let target = p.target.as_ref().expect("checked by kind");
            let resource = Resource::namespace_of(&target.forge, &target.owner)
                .map_err(|e| JobRefusal::standard(StandardCode::MalformedRequest, e.to_string()))?;
            if self.adapters.for_resource(&resource).is_none() {
                return Err(JobRefusal::not_capable(format!(
                    "this bridge serves no forge at `{}`",
                    resource.host()
                )));
            }
            if let Ok(Some(existing)) = self.store.get::<NamespaceRecord>(Table::Namespaces, &ns_id)
                && existing.resource != resource
            {
                return Err(JobRefusal::standard(
                    StandardCode::MalformedRequest,
                    format!(
                        "namespace `{ns_id}` is already `{}`; a namespace id is never reused",
                        existing.resource
                    ),
                ));
            }
            return Ok(());
        }
        let ns = self.bound_namespace(&ns_id)?;
        let adapter = self.adapters.for_resource(&ns.resource).ok_or_else(|| {
            JobRefusal::not_capable(format!(
                "the adapter for `{}` is not in service",
                ns.resource.host()
            ))
        })?;
        if let Some(repo) = &p.repo {
            let repo = Resource::parse(repo)
                .map_err(|e| JobRefusal::standard(StandardCode::MalformedRequest, e.to_string()))?;
            if !ns.resource.contains(&repo) || repo.is_namespace() {
                return Err(JobRefusal::unknown_namespace(format!(
                    "`{repo}` is not in namespace `{ns_id}` (`{}`)",
                    ns.resource
                )));
            }
        }
        // An account to remove on another forge than the namespace's could
        // only be a mistake: nothing here could remove it (spec, request
        // rule 3).
        if let Some(a) = p
            .remove_accounts
            .iter()
            .flatten()
            .find(|a| *a.forge != *ns.resource.host())
        {
            return Err(JobRefusal::standard(
                StandardCode::MalformedRequest,
                format!(
                    "`removeAccounts` names account {} on `{}`; namespace `{ns_id}` is on `{}`",
                    *a.id,
                    *a.forge,
                    ns.resource.host()
                ),
            ));
        }
        let binding = ns.binding.as_ref().expect("bound");
        let caps = adapter.forge().capabilities(&binding.namespace);
        match p.kind {
            K::BeginAccountLink => {
                if caps.account_link == vgi_forge::LinkMethod::None {
                    return Err(JobRefusal::not_capable("this forge has no account link"));
                }
            }
            K::ProjectRoles if p.repo.is_none() => {
                return Err(JobRefusal::not_capable(
                    "namespace-level roles (organisation owners) are not projected by this \
                     bridge; project git.ns.admin by hand",
                ));
            }
            K::CreateRepo if !caps.bot_can_create_repos => {
                return Err(JobRefusal::not_capable(
                    "the bridge cannot create repositories in this namespace (a personal \
                     account, or manual mode); the account holder creates it and the VTC adopts it",
                ));
            }
            _ if !caps.automation => {
                return Err(JobRefusal::not_capable(
                    "this namespace is in manual mode: nothing acts on the forge",
                ));
            }
            _ => {}
        }
        Ok(())
    }

    /// The bound namespace `id`, or `unknownNamespace`.
    pub(crate) fn bound_namespace(&self, id: &str) -> Result<NamespaceRecord, JobRefusal> {
        match self.store.get::<NamespaceRecord>(Table::Namespaces, id) {
            Ok(Some(ns)) if ns.state == NamespaceState::Bound && ns.binding.is_some() => Ok(ns),
            Ok(_) => Err(JobRefusal::unknown_namespace(format!(
                "no namespace `{id}` is bound to this bridge"
            ))),
            Err(e) => Err(JobRefusal::standard(
                StandardCode::Unavailable,
                format!("store: {e}"),
            )),
        }
    }

    /// One lock per namespace: its jobs run one at a time.
    pub(crate) fn ns_lock(&self, ns: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.ns_locks
            .lock()
            .expect("lock")
            .entry(ns.to_string())
            .or_default()
            .clone()
    }

    fn spawn_job(self: &Arc<Self>, job_id: String) {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(e) = me.run_job(&job_id).await {
                tracing::error!(job = %job_id, error = %e, "job failed to run");
                let mut report = Report::default();
                report.fail_with(
                    "forgeError",
                    format!("the bridge could not run the job: {e}"),
                );
                me.finish_job(&job_id, report).await;
            }
        });
    }

    async fn run_job(self: &Arc<Self>, job_id: &str) -> Result<()> {
        let record: JobRecord = self
            .store
            .get(Table::Jobs, job_id)?
            .context("the job is not in the ledger")?;
        if record.state == JobState::Finished {
            return Ok(());
        }
        let payload: job::Payload = serde_json::from_value(
            record
                .payload
                .clone()
                .context("the job's payload is gone")?,
        )?;
        let lock = self.ns_lock(&record.namespace);
        let _guard = lock.lock().await;
        self.store
            .update::<JobRecord, _>(Table::Jobs, job_id, |r| {
                Ok((
                    r.map(|mut r| {
                        r.state = JobState::Running;
                        r
                    }),
                    (),
                ))
            })?;
        let report = crate::jobs::run(self, &payload).await;
        self.finish_job(job_id, report).await;
        Ok(())
    }

    /// Close a job: record its result (exactly one per job) and send it.
    pub(crate) async fn finish_job(&self, job_id: &str, report: Report) {
        let result = match report.to_result(job_id) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(job = %job_id, error = %e, "the result does not fit the schema");
                let mut r = Report::default();
                r.fail_with("forgeError", "the bridge produced an invalid result");
                r.to_result(job_id).expect("minimal result is valid")
            }
        };
        let mut payload = serde_json::to_value(&result).expect("serialisable");
        // The bridge's status report (`ext`), for the namespace and the
        // repository the job reached.
        let namespace = self
            .store
            .get::<JobRecord>(Table::Jobs, job_id)
            .ok()
            .flatten()
            .map(|j| j.namespace);
        if let Some(ns) = namespace {
            let repo = report.repo.as_ref().map(|(r, id)| (r.host(), *id));
            payload = crate::status::attach::<result::Payload>(
                payload,
                crate::status::ext(self, &ns, repo),
            );
        }
        match self.store.finish_job(job_id, &payload, now()) {
            Ok(true) => self.send_outbox(&format!("result:{job_id}")).await,
            Ok(false) => {}
            Err(e) => {
                // Nothing was written: the job is still open, and runs (or
                // expires) again.
                tracing::error!(job = %job_id, error = %e, "could not record a result");
            }
        }
    }

    /// Report an event in `namespace` (queued until the VTC acknowledges
    /// it).
    ///
    /// An event naming a repository outside `namespace` is never sent
    /// (event 0.2: a bridge's authority is per namespace, and the VTC
    /// refuses such an event whole): it is logged and dropped, whichever
    /// version the VTC takes.
    pub(crate) async fn send_event(
        &self,
        namespace: &str,
        event_json: Value,
        drift: Option<Vec<Value>>,
    ) -> Result<()> {
        // The repository an event is about, by forge id, for the status
        // report (`ext`).
        let repo = event_json
            .get("forgeId")
            .and_then(Value::as_str)
            .and_then(|id| id.parse::<u64>().ok());
        let ns_resource = self
            .store
            .get::<NamespaceRecord>(Table::Namespaces, namespace)
            .ok()
            .flatten()
            .map(|n| n.resource);
        // With no namespace record there is nothing to contain a repository:
        // only an event that names none may go.
        if let Some(resource) = mapping::outside_namespace(
            ns_resource.as_ref(),
            &event_json,
            drift.as_deref().unwrap_or_default(),
        ) {
            let ty = event_json.get("type").and_then(Value::as_str).unwrap_or("");
            tracing::error!(
                namespace,
                %resource,
                r#type = ty,
                "not reporting an event that names a repository outside its namespace"
            );
            return Ok(());
        }
        let payload = mapping::event_payload(namespace, event_json, drift)?;
        let host = ns_resource.map(|r| r.host().to_string());
        let ext = crate::status::ext(self, namespace, host.as_deref().zip(repo));
        let payload = crate::status::attach::<event::Payload>(serde_json::to_value(&payload)?, ext);
        let key = format!("event:{}", wire::new_id());
        let entry = OutboxEntry {
            kind: OutboxKind::Event,
            payload,
            doc_ids: Vec::new(),
            last_sent: 0,
            attempts: 0,
        };
        self.store.put(Table::Outbox, &key, &entry)?;
        self.send_outbox(&key).await;
        Ok(())
    }

    /// Send (again) the outbox entry `key`, as a freshly issued and signed
    /// document.
    pub(crate) async fn send_outbox(&self, key: &str) {
        let Ok(Some(entry)) = self.store.get::<OutboxEntry>(Table::Outbox, key) else {
            return;
        };
        // VTA mode: what a result or event reports (a binding, a managed
        // repository) must be in the VTA before the VTC hears of it, or a
        // host lost in between would come back without it. Held here, the
        // entry goes out on a later resend.
        if !self.store.flush(OUTBOX_FLUSH).await {
            tracing::warn!(
                key,
                "holding a result or event until the bridge's state is written to the VTA"
            );
            return;
        }
        let type_uri = match entry.kind {
            OutboxKind::Result => result::Payload::TYPE_URI,
            _ => wire::event_type_uri(self.cfg.event_version),
        };
        let (id, doc) = match wire::signed_request(
            &self.identity(),
            &self.cfg.vtc_did,
            type_uri,
            entry.payload.clone(),
        )
        .await
        {
            Ok(x) => x,
            Err(e) => {
                tracing::error!(key, error = %e, "could not sign an outbound document");
                return;
            }
        };
        let _ = self
            .store
            .update::<OutboxEntry, _>(Table::Outbox, key, |e| {
                Ok((
                    e.map(|mut e| {
                        e.doc_ids.push(id.clone());
                        if e.doc_ids.len() > 8 {
                            e.doc_ids.remove(0);
                        }
                        e.last_sent = now();
                        e.attempts += 1;
                        e
                    }),
                    (),
                ))
            });
        if let Err(e) = self.link.send(&self.cfg.vtc_did, &doc).await {
            tracing::warn!(key, error = %e, "send failed; the outbox will retry");
        }
    }

    /// Send every unacknowledged result and event that is due (all of them
    /// when `all`). Backs off per entry: the resend interval doubled per
    /// attempt, capped at an hour.
    pub async fn resend_unacknowledged(&self, all: bool) {
        let Ok(entries) = self.store.list::<OutboxEntry>(Table::Outbox) else {
            return;
        };
        let now = now();
        for (key, e) in entries {
            let backoff = (self.cfg.resend_secs as i64)
                .saturating_mul(1_i64 << e.attempts.min(6))
                .min(3600);
            if all || now >= e.last_sent + backoff {
                self.send_outbox(&key).await;
            }
        }
    }

    fn on_result_ack(&self, v: &VerifiedDoc) {
        let Ok(resp) = serde_json::from_value::<result::Response>(v.doc.payload.clone()) else {
            tracing::warn!("ignoring a malformed result response");
            return;
        };
        let key = format!("result:{}", *resp.job_id);
        match self.store.delete(Table::Outbox, &key) {
            Ok(true) => tracing::debug!(job = %*resp.job_id, "the VTC recorded the result"),
            Ok(false) => {}
            Err(e) => tracing::warn!(error = %e, "could not clear an acknowledged result"),
        }
    }

    fn on_event_ack(&self, v: &VerifiedDoc) {
        let Some(thread) = v.doc.thread_id.as_deref() else {
            return;
        };
        self.clear_outbox_thread(thread);
    }

    fn clear_outbox_thread(&self, thread: &str) -> Option<OutboxEntry> {
        let entries = self.store.list::<OutboxEntry>(Table::Outbox).ok()?;
        for (key, e) in entries {
            if e.doc_ids.iter().any(|d| d == thread) {
                let _ = self.store.delete(Table::Outbox, &key);
                return Some(e);
            }
        }
        None
    }

    fn on_error_response(&self, v: &VerifiedDoc) {
        let code = v
            .doc
            .payload
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let thread = v.doc.thread_id.clone().unwrap_or_default();
        tracing::warn!(code = %code, thread = %thread, "the VTC refused a document");
        // A result for a job the VTC never sent will never be accepted:
        // stop sending it. Anything else is retried.
        if code == result::error_codes::UNKNOWN_JOB.code || code == "git-ns:unknownNamespace" {
            self.clear_outbox_thread(&thread);
        }
    }

    /// Serve until `shutdown` resolves: the retry, expiry and sweep loops.
    /// The transport and HTTP server run beside it ([`crate::run`]).
    pub async fn background(self: Arc<Self>, shutdown: tokio::sync::watch::Receiver<bool>) {
        let resend = std::time::Duration::from_secs(self.cfg.resend_secs.max(5));
        let sweep = std::time::Duration::from_secs(self.cfg.drift_sweep_secs.max(60));
        let mut resend_tick = tokio::time::interval(resend);
        let mut expiry_tick = tokio::time::interval(std::time::Duration::from_secs(15));
        let mut sweep_tick = tokio::time::interval(sweep);
        let mut maint_tick = tokio::time::interval(std::time::Duration::from_secs(3600));
        let mut shutdown = shutdown;
        // The Dependabot re-sign needs the VTC to grant this bridge's DID
        // `git.commit.sign` on each namespace: say so at start if it has not.
        #[cfg(feature = "forge-github")]
        {
            let me = Arc::clone(&self);
            tokio::spawn(async move {
                if let Ok(all) = me.store.list::<NamespaceRecord>(Table::Namespaces) {
                    for (id, _) in all {
                        crate::resign::warn_if_ungranted(&me, &id).await;
                    }
                }
            });
        }
        loop {
            tokio::select! {
                _ = resend_tick.tick() => self.resend_unacknowledged(false).await,
                _ = expiry_tick.tick() => crate::flows::expire(&self).await,
                _ = sweep_tick.tick() => crate::jobs::sweep_without_webhooks(&self).await,
                _ = maint_tick.tick() => self.maintenance().await,
                _ = shutdown.changed() => return,
            }
        }
    }

    /// Hourly: prune old delivery ids and finished jobs whose results the
    /// VTC acknowledged long ago (kept 30 days, so a late repeat is still
    /// answered from the ledger), and rotate Forgejo bot tokens that are due.
    pub async fn maintenance(&self) {
        let now = now();
        if let Ok(ds) = self.store.list::<i64>(Table::Deliveries) {
            for (k, at) in ds {
                if now - at > 7 * 86_400 {
                    let _ = self.store.delete(Table::Deliveries, &k);
                }
            }
        }
        if let Ok(jobs) = self.store.list::<JobRecord>(Table::Jobs) {
            for (k, j) in jobs {
                let acked = !matches!(
                    self.store
                        .get::<OutboxEntry>(Table::Outbox, &format!("result:{k}")),
                    Ok(Some(_))
                );
                if j.state == JobState::Finished
                    && acked
                    && j.finished_at.is_some_and(|t| now - t > 30 * 86_400)
                {
                    let _ = self.store.delete(Table::Jobs, &k);
                }
            }
        }
        #[cfg(feature = "forge-github")]
        crate::resign::prune(self);
        #[cfg(feature = "forge-forgejo")]
        crate::flows::rotate_forgejo_tokens(self).await;
    }
}
