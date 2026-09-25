//! Durable state, in one redb file.
//!
//! What the bridge must remember across a restart, and why:
//!
//! - **The job ledger** ([`JobRecord`]): `jobId` idempotency (a repeated job
//!   is answered, never run twice), the result until the VTC acknowledges it,
//!   and jobs still to run.
//! - **Namespaces** ([`NamespaceRecord`]): the binding the VTC's namespace id
//!   maps to, the capabilities found while binding (and any later
//!   `CapabilityChanged`), and on GitHub the managed repository set and the
//!   required-workflow pin — which the adapter refuses to act without after a
//!   restart, so [`crate::Bridge::restore`] hands them back first.
//! - **Repositories** ([`RepoRecord`]): forge id, owners and the roles the
//!   bridge projected — the projection an `inspect` compares against, since a
//!   job carries none.
//! - **Pending flows** ([`PendingFlow`]): binds and account links waiting for
//!   the person, keyed by their single-use `state`.
//! - **The outbox** ([`OutboxEntry`]): results and events not yet
//!   acknowledged by the VTC.
//! - **Sealed secrets**: see [`crate::seal`]. Only ciphertext is written.
//! - **The provenance ledger** ([`BranchLedger`]): who pushed to each
//!   `dependabot/*` branch since it was created. The Dependabot re-sign acts
//!   only on an unbroken record, so losing it means Dependabot pull requests
//!   open before the loss are not re-signed (`@dependabot recreate` starts
//!   them over).
//!
//! Every value is JSON in a string-keyed table: small, inspectable in a
//! support session, and free of a schema migration story for records this
//! size. Writes are one transaction each, committed durably (fsync) before
//! the caller goes on — in particular a job is on disk before the bridge
//! answers `accepted: true`.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vgi_forge::{Capabilities, ForgeAccount, NamespaceBinding, Resource, RoleAssignment};
use zeroize::Zeroizing;

use crate::seal::MasterKey;

/// One logical collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Table {
    /// [`JobRecord`] by `jobId`.
    Jobs,
    /// [`NamespaceRecord`] by the VTC's namespace id.
    Namespaces,
    /// [`RepoRecord`] by `<host>#<forge id>`.
    Repos,
    /// [`PendingFlow`] by its `state`.
    Pending,
    /// [`OutboxEntry`] by `result:<jobId>` / `event:<id>`.
    Outbox,
    /// Webhook delivery ids already handled, with when.
    Deliveries,
    /// Sealed secrets by name.
    Secrets,
    /// Small bookkeeping values (last token rotation, …) by name.
    Meta,
    /// [`BranchLedger`] by `<host>#<repository id>#<branch>`: the Dependabot
    /// re-sign's provenance ledger.
    Branches,
}

impl Table {
    const ALL: [Table; 9] = [
        Table::Jobs,
        Table::Namespaces,
        Table::Repos,
        Table::Pending,
        Table::Outbox,
        Table::Deliveries,
        Table::Secrets,
        Table::Meta,
        Table::Branches,
    ];

    fn def(self) -> TableDefinition<'static, &'static str, &'static [u8]> {
        TableDefinition::new(match self {
            Table::Jobs => "jobs",
            Table::Namespaces => "namespaces",
            Table::Repos => "repos",
            Table::Pending => "pending",
            Table::Outbox => "outbox",
            Table::Deliveries => "deliveries",
            Table::Secrets => "secrets",
            Table::Meta => "meta",
            Table::Branches => "branches",
        })
    }
}

/// Where a job is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum JobState {
    /// Recorded, not started (or interrupted by a restart: run again — every
    /// job is convergent).
    Queued,
    /// Running now.
    Running,
    /// A `begin*` job waiting for the person.
    Waiting,
    /// Done; `result` holds the result payload.
    Finished,
}

/// One job, as the ledger holds it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct JobRecord {
    /// The VTC's id for it.
    pub job_id: String,
    /// SHA-256 of the payload's canonical JSON: a repeat with other content
    /// is `jobIdReused`.
    pub digest: String,
    /// The namespace it acts in.
    pub namespace: String,
    /// Its `kind`.
    pub kind: String,
    /// The payload, while the job may still run. Cleared once finished — the
    /// VTC is the source of truth and resends the full desired state (spec:
    /// the bridge SHOULD NOT keep `desiredRoles` beyond the result).
    pub payload: Option<Value>,
    /// Where it is.
    pub state: JobState,
    /// For `begin*` jobs: the `next` the job response carried.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<Value>,
    /// The result payload, once finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Unix seconds.
    pub received_at: i64,
    /// Unix seconds, once finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<i64>,
}

impl JobRecord {
    /// A job just received, queued to run.
    pub fn queued(
        job_id: impl Into<String>,
        digest: impl Into<String>,
        namespace: impl Into<String>,
        kind: impl Into<String>,
        payload: Value,
        received_at: i64,
    ) -> Self {
        JobRecord {
            job_id: job_id.into(),
            digest: digest.into(),
            namespace: namespace.into(),
            kind: kind.into(),
            payload: Some(payload),
            state: JobState::Queued,
            next: None,
            result: None,
            received_at,
            finished_at: None,
        }
    }
}

/// Whether a namespace's binding has completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum NamespaceState {
    /// A `beginBind` is waiting for the admin.
    Pending,
    /// Bound: the adapter acts on it.
    Bound,
}

/// The required-workflow pin, as GitHub's adapter hands it out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PinRecord {
    /// `<org>/.vgi`'s forge id.
    pub repository_id: u64,
    /// The pinned commit.
    pub sha: String,
    /// The check name.
    pub check: String,
}

/// One namespace the VTC bound through this bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct NamespaceRecord {
    /// The VTC's namespace id.
    pub id: String,
    /// `host/owner`.
    pub resource: Resource,
    /// Pending or bound.
    pub state: NamespaceState,
    /// The completed binding (owner id, kind, installation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<NamespaceBinding>,
    /// Capabilities found while binding, updated by `CapabilityChanged`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Capabilities>,
    /// GitHub: whether org rulesets (a required workflow) are available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_workflow: Option<bool>,
    /// GitHub: the required-workflow pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<PinRecord>,
    /// GitHub: whether the installation carries the bridge-posted check
    /// (its permissions and event subscriptions). `None`: not probed yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_checks: Option<bool>,
    /// Forge ids of the repositories the bridge manages here.
    #[serde(default)]
    pub managed: BTreeSet<u64>,
}

impl NamespaceRecord {
    /// A namespace whose bind has started.
    pub fn pending(id: impl Into<String>, resource: Resource) -> Self {
        NamespaceRecord {
            id: id.into(),
            resource,
            state: NamespaceState::Pending,
            binding: None,
            capabilities: None,
            required_workflow: None,
            pin: None,
            bridge_checks: None,
            managed: BTreeSet::new(),
        }
    }
}

/// One repository the bridge manages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RepoRecord {
    /// The VTC namespace id.
    pub namespace: String,
    /// Where it is now.
    pub resource: Resource,
    /// The forge's id — what everything is keyed on.
    pub forge_id: u64,
    /// Owners with linked accounts (for the owner-review guard and the
    /// projection).
    #[serde(default)]
    pub owners: Vec<ForgeAccount>,
    /// The forge roles the bridge last projected: the roles it manages.
    #[serde(default)]
    pub roles: Vec<RoleAssignment>,
    /// Whether roles have been projected at all (an empty set is a real
    /// projection; `false` means "unknown, do not report role drift").
    #[serde(default)]
    pub roles_known: bool,
    /// The required check, once bootstrapped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_check: Option<String>,
    /// Archived through the bridge.
    #[serde(default)]
    pub archived: bool,
    /// Digest of the drift last reported, so a sweep that finds the same
    /// drift again sends nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_drift: Option<String>,
    /// The check-source guard the last inspection found in force, in the
    /// VTC's words ([`crate::status::Guard`]). Reported, never acted on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard: Option<String>,
    /// The last check the bridge posted on the repository itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_check: Option<LastCheck>,
    /// The role map, as the forge applies it, under which `roles` were last
    /// projected. `None` on a record written before the bridge kept it,
    /// which is taken to be the default map (`crate::rolemap`): the only
    /// map a released bridge applied until then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_map: Option<vgi_forge::RoleMap>,
}

/// A check the bridge posted (GitHub fallback mode), as it reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LastCheck {
    /// The commit the check run is on.
    pub sha: String,
    /// `success` or `failure`.
    pub conclusion: String,
    /// Unix seconds, when it was completed.
    pub at: i64,
}

impl LastCheck {
    /// A check completed on `sha` at `at`.
    pub fn new(sha: impl Into<String>, conclusion: impl Into<String>, at: i64) -> Self {
        LastCheck {
            sha: sha.into(),
            conclusion: conclusion.into(),
            at,
        }
    }
}

impl RepoRecord {
    /// A record for a repository first seen now.
    pub fn new(namespace: impl Into<String>, resource: Resource, forge_id: u64) -> Self {
        RepoRecord {
            namespace: namespace.into(),
            resource,
            forge_id,
            owners: Vec::new(),
            roles: Vec::new(),
            roles_known: false,
            required_check: None,
            archived: false,
            last_drift: None,
            guard: None,
            last_check: None,
            role_map: None,
        }
    }

    /// The store key: `<host>#<forge id>`.
    pub fn key(&self) -> String {
        repo_key(self.resource.host(), self.forge_id)
    }
}

/// The key a repository is stored under.
pub fn repo_key(host: &str, forge_id: u64) -> String {
    format!("{host}#{forge_id}")
}

/// One verified `push` to a `dependabot/*` branch, as GitHub reported it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PushRecord {
    /// The branch's value before the push (all zeros when it was created).
    pub before: String,
    /// Its value after.
    pub after: String,
    /// Who GitHub says pushed: login…
    pub sender_login: String,
    /// …and numeric id.
    pub sender_id: u64,
    /// The push created the branch.
    pub created: bool,
    /// GitHub's delivery id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_id: Option<String>,
    /// Unix seconds, when the bridge recorded it.
    pub at: i64,
}

/// A push the bridge made itself (a re-sign), recorded before it was sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct OwnPush {
    /// The head it replaced (the force-push's lease).
    pub before: String,
    /// The re-signed head.
    pub after: String,
    /// Unix seconds.
    pub at: i64,
}

/// The provenance ledger of one `dependabot/*` branch (§9): every push the
/// bridge has seen to it since it was created, and the bridge's own pushes.
/// A branch's deletion clears it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct BranchLedger {
    /// `host/owner/repo`, as last seen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<Resource>,
    /// The branch.
    #[serde(default)]
    pub branch: String,
    /// Pushes, in the order they arrived (GitHub does not promise delivery
    /// order; the chain is rebuilt from `before`/`after`).
    #[serde(default)]
    pub pushes: Vec<PushRecord>,
    /// The bridge's own re-sign pushes.
    #[serde(default)]
    pub own: Vec<OwnPush>,
    /// More pushes arrived than the ledger keeps: the branch is never clean
    /// again (until deleted).
    #[serde(default)]
    pub overflow: bool,
    /// The open pull request from this branch, once one was seen — so a push
    /// that arrives after the pull request's delivery can resume the re-sign.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_request: Option<u64>,
    /// Unix seconds, when anything last changed here (the oldest untouched
    /// ledger of a repository is evicted first).
    #[serde(default)]
    pub touched: i64,
    /// The newest `repository.pushed_at` of a delivery recorded here: an
    /// older delivery may add a record but never resets or clears the
    /// ledger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_pushed_at: Option<i64>,
    /// Why the last re-sign of a head stopped at its commits (the head, and
    /// the reason), for the check's summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_skip: Option<(String, String)>,
}

/// A flow waiting for a person, by its `state`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
#[non_exhaustive]
pub enum PendingFlow {
    /// A namespace bind.
    Bind {
        /// The `beginBind` job.
        job_id: String,
        /// The VTC namespace id.
        namespace: String,
        /// `host/owner` being bound.
        resource: Resource,
        /// Unix seconds.
        expires_at: i64,
    },
    /// An account link.
    Link {
        /// The `beginAccountLink` job.
        job_id: String,
        /// The VTC namespace id.
        namespace: String,
        /// The forge host.
        host: String,
        /// The member's DID, for the adapter's member-bound `state`.
        member: String,
        /// Unix seconds.
        expires_at: i64,
        /// A device flow is being polled (the device code is a sealed
        /// secret, `pending/<state>/device`).
        #[serde(default)]
        device: Option<DevicePoll>,
    },
    /// A GitHub App registration through the manifest flow.
    Manifest {
        /// The forge host.
        host: String,
        /// The org the App is registered under, or `None` for the account
        /// of whoever registers it.
        owner: Option<String>,
        /// Unix seconds.
        expires_at: i64,
    },
}

impl PendingFlow {
    /// When it lapses.
    pub fn expires_at(&self) -> i64 {
        match self {
            PendingFlow::Bind { expires_at, .. }
            | PendingFlow::Link { expires_at, .. }
            | PendingFlow::Manifest { expires_at, .. } => *expires_at,
        }
    }

    /// The job it belongs to, if any.
    pub fn job_id(&self) -> Option<&str> {
        match self {
            PendingFlow::Bind { job_id, .. } | PendingFlow::Link { job_id, .. } => Some(job_id),
            PendingFlow::Manifest { .. } => None,
        }
    }
}

/// How a device-flow link is polled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePoll {
    /// Seconds between polls.
    pub interval: u64,
    /// Seconds the code lives.
    pub expires_in: u64,
}

/// A result or event the VTC has not acknowledged yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct OutboxEntry {
    /// `result` or `event`.
    pub kind: OutboxKind,
    /// The payload; a fresh, signed document is built around it on every
    /// send (a stale `issuedAt` would be refused).
    pub payload: Value,
    /// Ids of the documents sent so far (the most recent last), to match the
    /// VTC's response by `threadId`.
    #[serde(default)]
    pub doc_ids: Vec<String>,
    /// Unix seconds of the last send.
    pub last_sent: i64,
    /// Sends so far.
    pub attempts: u32,
}

impl OutboxEntry {
    /// A result not sent yet.
    pub fn result(payload: Value) -> Self {
        OutboxEntry {
            kind: OutboxKind::Result,
            payload,
            doc_ids: Vec::new(),
            last_sent: 0,
            attempts: 0,
        }
    }
}

/// What an [`OutboxEntry`] carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum OutboxKind {
    /// A `git-ns/bridge/result`.
    Result,
    /// A `git-ns/bridge/event`.
    Event,
}

/// The store.
#[derive(Clone)]
pub struct Store {
    db: Arc<Database>,
    key: Arc<MasterKey>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}

impl Store {
    /// Open (or create) the store at `path`, sealing secrets under `key`.
    /// redb takes an exclusive lock: one bridge process per store.
    pub fn open(path: &Path, key: MasterKey) -> Result<Self> {
        let db = Database::create(path).with_context(|| {
            format!(
                "opening the state store {} (is another bridge running on it?)",
                path.display()
            )
        })?;
        Self::with_db(db, key)
    }

    /// An in-memory store (tests).
    pub fn in_memory(key: MasterKey) -> Result<Self> {
        let db = Database::builder().create_with_backend(redb::backends::InMemoryBackend::new())?;
        Self::with_db(db, key)
    }

    fn with_db(db: Database, key: MasterKey) -> Result<Self> {
        let w = db.begin_write()?;
        for t in Table::ALL {
            w.open_table(t.def())?;
        }
        w.commit()?;
        Ok(Store {
            db: Arc::new(db),
            key: Arc::new(key),
        })
    }

    /// Read one record.
    pub fn get<T: DeserializeOwned>(&self, table: Table, key: &str) -> Result<Option<T>> {
        let r = self.db.begin_read()?;
        let t = r.open_table(table.def())?;
        match t.get(key)? {
            Some(v) => Ok(Some(
                serde_json::from_slice(v.value())
                    .with_context(|| format!("decoding {table:?}/{key}"))?,
            )),
            None => Ok(None),
        }
    }

    /// Write one record.
    pub fn put<T: Serialize>(&self, table: Table, key: &str, value: &T) -> Result<()> {
        let bytes = serde_json::to_vec(value)?;
        let w = self.db.begin_write()?;
        w.open_table(table.def())?.insert(key, bytes.as_slice())?;
        w.commit()?;
        Ok(())
    }

    /// Write one record only if the key is free. `false` if it was taken.
    pub fn put_new<T: Serialize>(&self, table: Table, key: &str, value: &T) -> Result<bool> {
        let bytes = serde_json::to_vec(value)?;
        let w = self.db.begin_write()?;
        {
            let mut t = w.open_table(table.def())?;
            if t.get(key)?.is_some() {
                return Ok(false);
            }
            t.insert(key, bytes.as_slice())?;
        }
        w.commit()?;
        Ok(true)
    }

    /// Read-modify-write one record in a single transaction. `f` returns the
    /// new value (`None` deletes) and what to hand back.
    pub fn update<T, R>(
        &self,
        table: Table,
        key: &str,
        f: impl FnOnce(Option<T>) -> Result<(Option<T>, R)>,
    ) -> Result<R>
    where
        T: Serialize + DeserializeOwned,
    {
        let w = self.db.begin_write()?;
        let out = {
            let mut t = w.open_table(table.def())?;
            let current = match t.get(key)? {
                Some(v) => Some(serde_json::from_slice(v.value())?),
                None => None,
            };
            let (next, out) = f(current)?;
            match next {
                Some(v) => {
                    let bytes = serde_json::to_vec(&v)?;
                    t.insert(key, bytes.as_slice())?;
                }
                None => {
                    t.remove(key)?;
                }
            }
            out
        };
        w.commit()?;
        Ok(out)
    }

    /// Close job `job_id` with `result` and queue it for sending, in **one**
    /// transaction: a crash can leave the job either running (it runs again)
    /// or finished with its result queued — never finished with the result
    /// lost. `false` (and nothing written) if the job is unknown or already
    /// finished.
    pub fn finish_job(&self, job_id: &str, result: &Value, finished_at: i64) -> Result<bool> {
        let w = self.db.begin_write()?;
        {
            let mut jobs = w.open_table(Table::Jobs.def())?;
            let Some(current) = jobs.get(job_id)? else {
                return Ok(false);
            };
            let mut rec: JobRecord = serde_json::from_slice(current.value())?;
            drop(current);
            if rec.state == JobState::Finished {
                return Ok(false);
            }
            rec.state = JobState::Finished;
            rec.result = Some(result.clone());
            rec.payload = None;
            rec.finished_at = Some(finished_at);
            let bytes = serde_json::to_vec(&rec)?;
            jobs.insert(job_id, bytes.as_slice())?;
            let entry = OutboxEntry::result(result.clone());
            let bytes = serde_json::to_vec(&entry)?;
            w.open_table(Table::Outbox.def())?
                .insert(format!("result:{job_id}").as_str(), bytes.as_slice())?;
        }
        w.commit()?;
        Ok(true)
    }

    /// Delete one record. `true` if it existed.
    pub fn delete(&self, table: Table, key: &str) -> Result<bool> {
        let w = self.db.begin_write()?;
        let existed = w.open_table(table.def())?.remove(key)?.is_some();
        w.commit()?;
        Ok(existed)
    }

    /// Every record in a table, by key.
    pub fn list<T: DeserializeOwned>(&self, table: Table) -> Result<Vec<(String, T)>> {
        let r = self.db.begin_read()?;
        let t = r.open_table(table.def())?;
        let mut out = Vec::new();
        for row in t.iter()? {
            let (k, v) = row?;
            let key = k.value().to_string();
            let value = serde_json::from_slice(v.value())
                .with_context(|| format!("decoding {table:?}/{key}"))?;
            out.push((key, value));
        }
        Ok(out)
    }

    /// Seal `value` under `name` and store it.
    pub fn put_secret(&self, name: &str, value: &[u8]) -> Result<()> {
        let sealed = self.key.seal(name, value)?;
        let w = self.db.begin_write()?;
        w.open_table(Table::Secrets.def())?
            .insert(name, sealed.as_slice())?;
        w.commit()?;
        Ok(())
    }

    /// Open the secret `name`, if stored.
    pub fn get_secret(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let r = self.db.begin_read()?;
        let t = r.open_table(Table::Secrets.def())?;
        match t.get(name)? {
            Some(v) => Ok(Some(self.key.open(name, v.value())?)),
            None => Ok(None),
        }
    }

    /// The secret `name` as UTF-8, if stored.
    pub fn get_secret_string(&self, name: &str) -> Result<Option<Zeroizing<String>>> {
        match self.get_secret(name)? {
            Some(bytes) => Ok(Some(Zeroizing::new(
                String::from_utf8(bytes.to_vec())
                    .map_err(|_| anyhow::anyhow!("secret `{name}` is not UTF-8"))?,
            ))),
            None => Ok(None),
        }
    }

    /// Remove the secret `name`.
    pub fn delete_secret(&self, name: &str) -> Result<()> {
        self.delete(Table::Secrets, name).map(|_| ())
    }

    /// Names of the stored secrets (never their values).
    pub fn secret_names(&self) -> Result<Vec<String>> {
        let r = self.db.begin_read()?;
        let t = r.open_table(Table::Secrets.def())?;
        let mut out = Vec::new();
        for row in t.iter()? {
            out.push(row?.0.value().to_string());
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        Store::in_memory(MasterKey::generate().unwrap()).unwrap()
    }

    #[test]
    fn records_round_trip_and_update_is_atomic() {
        let s = store();
        let ns = NamespaceRecord::pending("ns_1", Resource::parse("github.com/acme").unwrap());
        s.put(Table::Namespaces, "ns_1", &ns).unwrap();
        let back: NamespaceRecord = s.get(Table::Namespaces, "ns_1").unwrap().unwrap();
        assert_eq!(back.state, NamespaceState::Pending);
        let n = s
            .update::<NamespaceRecord, _>(Table::Namespaces, "ns_1", |r| {
                let mut r = r.unwrap();
                r.managed.insert(9);
                let n = r.managed.len();
                Ok((Some(r), n))
            })
            .unwrap();
        assert_eq!(n, 1);
        assert!(!s.put_new(Table::Namespaces, "ns_1", &back).unwrap());
        assert_eq!(
            s.list::<NamespaceRecord>(Table::Namespaces).unwrap().len(),
            1
        );
        assert!(s.delete(Table::Namespaces, "ns_1").unwrap());
        assert!(
            s.get::<NamespaceRecord>(Table::Namespaces, "ns_1")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn finishing_a_job_records_the_result_and_queues_it_together() {
        let s = store();
        let job = JobRecord::queued("j1", "d", "ns", "inspect", serde_json::json!({}), 0);
        s.put(Table::Jobs, "j1", &job).unwrap();
        let result = serde_json::json!({ "jobId": "j1", "outcome": "succeeded" });
        assert!(s.finish_job("j1", &result, 5).unwrap());
        let rec: JobRecord = s.get(Table::Jobs, "j1").unwrap().unwrap();
        assert_eq!(rec.state, JobState::Finished);
        assert_eq!(rec.result.as_ref(), Some(&result));
        assert!(rec.payload.is_none());
        let queued: OutboxEntry = s.get(Table::Outbox, "result:j1").unwrap().unwrap();
        assert_eq!(queued.payload, result);
        // Exactly once: a second close changes nothing, even after the
        // entry was acknowledged.
        s.delete(Table::Outbox, "result:j1").unwrap();
        assert!(!s.finish_job("j1", &serde_json::json!({}), 6).unwrap());
        assert!(
            s.get::<OutboxEntry>(Table::Outbox, "result:j1")
                .unwrap()
                .is_none()
        );
        assert!(!s.finish_job("unknown", &result, 6).unwrap());
    }

    #[test]
    fn secrets_are_stored_sealed() {
        let s = store();
        s.put_secret("github/github.com/app", b"pem-bytes").unwrap();
        assert_eq!(
            &*s.get_secret("github/github.com/app").unwrap().unwrap(),
            b"pem-bytes"
        );
        let raw =
            s.db.begin_read()
                .unwrap()
                .open_table(Table::Secrets.def())
                .unwrap()
                .get("github/github.com/app")
                .unwrap()
                .unwrap()
                .value()
                .to_vec();
        assert!(
            !raw.windows(9).any(|w| w == b"pem-bytes"),
            "ciphertext only"
        );
        assert_eq!(s.secret_names().unwrap(), ["github/github.com/app"]);
    }

    #[test]
    fn a_file_store_survives_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.redb");
        let key = MasterKey::generate().unwrap();
        let text = key.to_text();
        {
            let s = Store::open(&path, key).unwrap();
            s.put_secret("x", b"y").unwrap();
            s.put(Table::Deliveries, "d-1", &1_i64).unwrap();
        }
        let s = Store::open(&path, MasterKey::from_text(&text).unwrap()).unwrap();
        assert_eq!(&*s.get_secret("x").unwrap().unwrap(), b"y");
        assert_eq!(s.get::<i64>(Table::Deliveries, "d-1").unwrap(), Some(1));
    }
}
