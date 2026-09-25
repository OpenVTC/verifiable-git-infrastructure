//! The bridge's state and secrets in the VTA's `app-state` (VTA mode).
//!
//! In VTA mode ([`crate::vta`]) the durable copy of everything the bridge
//! cannot rebuild lives in its own trust context's `vta/app-state`, one
//! record per item, under the namespace [`NAMESPACE`]:
//!
//! | Key | What |
//! |---|---|
//! | `secret/<name>` | a secret — the GitHub App's credentials, webhook secrets, Forgejo tokens — **sealed** (AES-256-GCM, bound to its name) under a key only the context's admins can export (`{"sealed": …}`, see below) |
//! | `state/<table>/<key>` | a record of a mirrored [`Table`]: namespaces, repositories, the Dependabot provenance ledger, bookkeeping |
//!
//! The local redb file is then a **cache**: a new host with a new VTA
//! credential starts from an empty data directory and pulls everything back
//! ([`Mirror::pull`]). Secrets are never written to it at all — they are
//! held in memory ([`crate::store::Store`] routes them here), and in the
//! VTA.
//!
//! Writes reach the VTA from a background task ([`Mirror::run`]) a moment
//! after the local write, as conditional puts on the version last seen, so a
//! second host writing the same context is noticed (and logged) rather than
//! silently overwritten. What must not be lost waits for the mirror to drain
//! ([`crate::store::Store::flush`]): a result or event goes to the VTC only
//! once the state it reports is in the VTA, and a registered App is
//! persisted before its page says so.
//!
//! **Secrets are sealed before they leave the host.** The VTA documents
//! app-state as *not for secrets* (values are stored as given, readable by
//! any credential with access to the context, and in the VTA's backups), so
//! every secret is sealed with a key derived from a dedicated key in the
//! context ([`crate::vta::SEAL_KEY_LABEL`]), which only an `admin` of the
//! context can export. What app-state holds is ciphertext.
//!
//! **A second writer stops the mirror.** Every write is conditional on the
//! version this host last saw. A record someone else wrote means a second
//! bridge (or a stolen credential) is running on the same context: the
//! mirror writes nothing more, the change stays in the local cache, results
//! and events are held (they wait for the mirror), and `/healthz` fails, so
//! the operator finds out instead of two hosts overwriting each other.
//!
//! What is **not** mirrored, because a lost host can do without it: the job
//! ledger (the VTC repeats unfinished jobs, and every job is convergent),
//! the outbox (the same), pending binds and links (the person starts again),
//! webhook delivery ids, and device-flow codes (in memory only).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};
use tokio::sync::Notify;
use zeroize::Zeroizing;

use crate::seal::MasterKey;
use crate::store::Table;

/// A namespace counter and its records, by key.
type Versioned = (u64, BTreeMap<String, (u64, Value)>);

/// The app-state namespace the bridge writes under, in its own context.
pub const NAMESPACE: &str = "vgi-bridge";

/// The largest value the VTA stores in one record (its documented cap).
pub const MAX_VALUE_BYTES: usize = 65_536;

/// The tables whose records are mirrored: what a new host needs and cannot
/// rebuild from the forges or the VTC.
pub const MIRRORED: [Table; 4] = [
    Table::Namespaces,
    Table::Repos,
    Table::Branches,
    Table::Meta,
];

/// Records of a mirrored table that belong to this host's cache, not to the
/// context (the cache's binding, [`crate::vta::BINDING_META`]).
pub fn record_is_mirrored(table: Table, key: &str) -> bool {
    MIRRORED.contains(&table) && !(table == Table::Meta && key == crate::vta::BINDING_META)
}

/// Secrets that stay in memory only: short-lived device-flow codes.
pub fn secret_is_mirrored(name: &str) -> bool {
    !name.starts_with("pending/")
}

/// One record as the remote holds it.
#[derive(Debug, Clone)]
pub struct Record {
    /// The key.
    pub key: String,
    /// Its version (the namespace counter its last write took).
    pub version: u64,
    /// The value.
    pub value: Value,
}

/// Why a conditional write did not apply.
#[derive(Debug)]
pub enum PutError {
    /// The record is not at the version the write expected: someone else
    /// wrote it. Carries the version it is at now (`None`: no live record).
    Conflict(Option<u64>),
    /// Anything else (the VTA unreachable, refused, …).
    Other(anyhow::Error),
}

impl std::fmt::Display for PutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PutError::Conflict(v) => write!(f, "version conflict (the record is at {v:?})"),
            PutError::Other(e) => write!(f, "{e:#}"),
        }
    }
}

/// A key-value store with versioned, conditional writes: the VTA's
/// `app-state`, or an in-memory one for tests.
#[async_trait]
pub trait AppState: Send + Sync {
    /// Every live record in the bridge's namespace.
    async fn list(&self) -> Result<Vec<Record>>;
    /// One live record.
    async fn get(&self, key: &str) -> Result<Option<Record>>;
    /// Write `value` at `key`. `expected`: `Some(0)` only if no live record
    /// exists, `Some(n)` only at version `n`, `None` unconditionally.
    /// Returns the version the write took.
    async fn put(
        &self,
        key: &str,
        value: Value,
        expected: Option<u64>,
    ) -> std::result::Result<u64, PutError>;
    /// Remove `key` (a no-op if there is nothing there).
    async fn delete(&self, key: &str, expected: Option<u64>) -> std::result::Result<(), PutError>;
}

/// An in-memory [`AppState`], for tests and dry runs. Behaves as the VTA's
/// does: one counter for the namespace, conditional writes.
#[derive(Default)]
pub struct MemoryAppState {
    inner: Mutex<Versioned>,
    /// When set, every call fails (the VTA unreachable).
    down: std::sync::atomic::AtomicBool,
}

impl MemoryAppState {
    /// Empty.
    pub fn new() -> Self {
        MemoryAppState::default()
    }

    /// Make every call fail (`true`) or work again.
    pub fn set_down(&self, down: bool) {
        self.down.store(down, std::sync::atomic::Ordering::SeqCst);
    }

    /// A snapshot of every record, by key.
    pub fn snapshot(&self) -> BTreeMap<String, Value> {
        let g = self.inner.lock().expect("lock");
        g.1.iter()
            .map(|(k, (_, v))| (k.clone(), v.clone()))
            .collect()
    }

    fn check(&self) -> Result<()> {
        if self.down.load(std::sync::atomic::Ordering::SeqCst) {
            Err(anyhow!("the VTA is unreachable (test)"))
        } else {
            Ok(())
        }
    }

    fn precondition(
        current: Option<u64>,
        expected: Option<u64>,
    ) -> std::result::Result<(), PutError> {
        match (expected, current) {
            (None, _) => Ok(()),
            (Some(0), None) => Ok(()),
            (Some(e), Some(c)) if e == c => Ok(()),
            _ => Err(PutError::Conflict(current)),
        }
    }
}

#[async_trait]
impl AppState for MemoryAppState {
    async fn list(&self) -> Result<Vec<Record>> {
        self.check()?;
        let g = self.inner.lock().expect("lock");
        Ok(g.1
            .iter()
            .map(|(k, (v, value))| Record {
                key: k.clone(),
                version: *v,
                value: value.clone(),
            })
            .collect())
    }

    async fn get(&self, key: &str) -> Result<Option<Record>> {
        self.check()?;
        let g = self.inner.lock().expect("lock");
        Ok(g.1.get(key).map(|(v, value)| Record {
            key: key.to_string(),
            version: *v,
            value: value.clone(),
        }))
    }

    async fn put(
        &self,
        key: &str,
        value: Value,
        expected: Option<u64>,
    ) -> std::result::Result<u64, PutError> {
        self.check().map_err(PutError::Other)?;
        let mut g = self.inner.lock().expect("lock");
        let current = g.1.get(key).map(|(v, _)| *v);
        Self::precondition(current, expected)?;
        g.0 += 1;
        let v = g.0;
        g.1.insert(key.to_string(), (v, value));
        Ok(v)
    }

    async fn delete(&self, key: &str, expected: Option<u64>) -> std::result::Result<(), PutError> {
        self.check().map_err(PutError::Other)?;
        let mut g = self.inner.lock().expect("lock");
        let current = g.1.get(key).map(|(v, _)| *v);
        if current.is_some() {
            Self::precondition(current, expected)?;
            g.0 += 1;
            g.1.remove(key);
        }
        Ok(())
    }
}

/// The remote key of a mirrored record.
pub fn state_key(table: Table, key: &str) -> String {
    format!("state/{}/{key}", table.name())
}

/// The remote key of a secret.
pub fn secret_key(name: &str) -> String {
    format!("secret/{name}")
}

/// A secret as the remote holds it: sealed under `seal`, bound to its name.
pub fn secret_value(seal: &MasterKey, name: &str, bytes: &[u8]) -> Result<Value> {
    Ok(json!({ "sealed": B64.encode(seal.seal(&secret_key(name), bytes)?) }))
}

/// Open a secret record.
pub fn secret_bytes(seal: &MasterKey, name: &str, v: &Value) -> Result<Zeroizing<Vec<u8>>> {
    let s = v
        .get("sealed")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("not a sealed secret record"))?;
    seal.open(&secret_key(name), &B64.decode(s)?)
        .map_err(|_| anyhow!("the secret `{name}` does not open with this context's sealing key"))
}

/// One pending change: what the next mirror pass writes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Dirty {
    /// A record of a mirrored table.
    Record(Table, String),
    /// A secret.
    Secret(String),
}

impl Dirty {
    fn remote_key(&self) -> String {
        match self {
            Dirty::Record(t, k) => state_key(*t, k),
            Dirty::Secret(n) => secret_key(n),
        }
    }
}

/// The in-memory half of VTA mode: the secrets (never on disk), the set of
/// changes not yet in the VTA, and the version each remote record was last
/// seen at. Shared by the [`crate::store::Store`] (which marks changes) and
/// the task that writes them ([`Mirror::run`]).
pub struct Mirror {
    /// What secrets are sealed with before they go to the VTA.
    seal: MasterKey,
    pub(crate) secrets: Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>,
    dirty: Mutex<BTreeSet<Dirty>>,
    in_flight: Mutex<usize>,
    versions: Mutex<HashMap<String, u64>>,
    wake: Notify,
    idle: Notify,
    /// Conflicts seen: another host wrote this context. Once non-zero the
    /// mirror writes nothing more (fails closed).
    conflicts: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for Mirror {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mirror")
            .field("pending", &self.pending())
            .finish_non_exhaustive()
    }
}

impl Mirror {
    /// Empty: nothing pulled yet. Secrets are sealed with `seal`.
    pub fn new(seal: MasterKey) -> Arc<Self> {
        Arc::new(Mirror {
            seal,
            secrets: Mutex::default(),
            dirty: Mutex::default(),
            in_flight: Mutex::default(),
            versions: Mutex::default(),
            wake: Notify::new(),
            idle: Notify::new(),
            conflicts: Default::default(),
        })
    }

    /// Whether the mirror stopped because someone else wrote the context.
    pub fn stopped(&self) -> bool {
        self.conflicts() > 0
    }

    pub(crate) fn mark(&self, d: Dirty) {
        self.dirty.lock().expect("lock").insert(d);
        self.wake.notify_one();
    }

    /// Changes not yet written to the VTA.
    pub fn pending(&self) -> usize {
        self.dirty.lock().expect("lock").len() + *self.in_flight.lock().expect("lock")
    }

    /// Conditional writes that found someone else's version: a second host
    /// is running on this context.
    pub fn conflicts(&self) -> u64 {
        self.conflicts.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Load everything the remote holds: secrets into memory, records into
    /// the local cache (the remote wins over a cached copy), and mark every
    /// cached record the remote does not have for writing — what this host
    /// wrote and had not yet mirrored when it stopped.
    pub async fn pull(&self, remote: &dyn AppState, store: &crate::store::Store) -> Result<()> {
        let records = remote.list().await?;
        let mut remote_keys = BTreeSet::new();
        {
            let mut versions = self.versions.lock().expect("lock");
            versions.clear();
            for r in &records {
                versions.insert(r.key.clone(), r.version);
            }
        }
        for r in records {
            remote_keys.insert(r.key.clone());
            if let Some(name) = r.key.strip_prefix("secret/") {
                match secret_bytes(&self.seal, name, &r.value) {
                    Ok(b) => {
                        self.secrets
                            .lock()
                            .expect("lock")
                            .insert(name.to_string(), b);
                    }
                    Err(e) => {
                        // Refused rather than skipped: running without a
                        // secret the context holds would fail later and
                        // less clearly.
                        return Err(e.context(format!("reading `{}` from the VTA", r.key)));
                    }
                }
            } else if let Some(rest) = r.key.strip_prefix("state/") {
                let Some((table, key)) = rest.split_once('/') else {
                    continue;
                };
                let Some(table) = Table::from_name(table).filter(|t| record_is_mirrored(*t, key))
                else {
                    tracing::debug!(key = %r.key, "ignoring a record of a table this release does not mirror");
                    continue;
                };
                store.put_cached(table, key, &r.value)?;
            }
        }
        for table in MIRRORED {
            for key in store.keys(table)? {
                if record_is_mirrored(table, &key) && !remote_keys.contains(&state_key(table, &key))
                {
                    self.mark(Dirty::Record(table, key));
                }
            }
        }
        Ok(())
    }

    /// Write every pending change, once. `Err` when the VTA could not be
    /// reached: what was not written stays pending.
    pub async fn sync_once(
        &self,
        remote: &dyn AppState,
        store: &crate::store::Store,
    ) -> Result<()> {
        // Taken and counted in flight under one lock, so `pending` never
        // reads zero while a change is on its way.
        let batch: Vec<Dirty> = {
            let mut d = self.dirty.lock().expect("lock");
            let batch: Vec<Dirty> = std::mem::take(&mut *d).into_iter().collect();
            *self.in_flight.lock().expect("lock") += batch.len();
            batch
        };
        let mut failed: Option<anyhow::Error> = None;
        for item in batch {
            if failed.is_none()
                && let Err(e) = self.write(remote, store, &item).await
            {
                failed = Some(e);
            }
            if failed.is_some() {
                // Not written (this one failed, or a failure stopped the
                // pass before it): pending again, then no longer in flight.
                self.dirty.lock().expect("lock").insert(item);
            }
            *self.in_flight.lock().expect("lock") -= 1;
        }
        self.idle.notify_waiters();
        match failed {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Write one change: the value the local store holds now (a deletion if
    /// it holds none), conditional on the version last seen.
    async fn write(
        &self,
        remote: &dyn AppState,
        store: &crate::store::Store,
        item: &Dirty,
    ) -> Result<()> {
        let key = item.remote_key();
        let value: Option<Value> = match item {
            Dirty::Record(t, k) => store.get_raw(*t, k)?,
            Dirty::Secret(n) => {
                let bytes = self.secrets.lock().expect("lock").get(n).cloned();
                match bytes {
                    Some(b) => Some(secret_value(&self.seal, n, &b)?),
                    None => None,
                }
            }
        };
        if let Some(v) = &value {
            let size = serde_json::to_vec(v)?.len();
            if size > MAX_VALUE_BYTES {
                // Refused loudly and not retried: the VTA would refuse it too.
                tracing::error!(
                    key = %key,
                    size,
                    "a record is larger than the VTA stores ({MAX_VALUE_BYTES} bytes); it stays in \
                     the local cache only and a new host would not have it"
                );
                return Ok(());
            }
        }
        let seen = self.versions.lock().expect("lock").get(&key).copied();
        let res = match &value {
            // `Some(0)`: create only — the remote held nothing when this host
            // last looked.
            Some(v) => remote
                .put(&key, v.clone(), Some(seen.unwrap_or(0)))
                .await
                .map(Some),
            None => remote.delete(&key, seen).await.map(|_| None),
        };
        match res {
            Ok(Some(version)) => {
                self.versions
                    .lock()
                    .expect("lock")
                    .insert(key.clone(), version);
                Ok(())
            }
            Ok(None) => {
                self.versions.lock().expect("lock").remove(&key);
                Ok(())
            }
            Err(PutError::Conflict(_)) => {
                // Someone else wrote this record since this host last saw it:
                // a second bridge, or a stolen credential, on the same
                // context. Nothing more is written — the host cannot tell
                // whose state is right — and the operator is told.
                self.conflicts
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::error!(
                    key = %key,
                    "the VTA holds a version of the bridge's state this bridge did not write: \
                     another bridge (or someone holding its credential) is writing the same VTA \
                     context. The bridge stops writing its state and holds its results; stop the \
                     other bridge, revoke the credential if it is not yours, and restart this one"
                );
                Err(anyhow!("`{key}` was written by someone else"))
            }
            Err(PutError::Other(e)) => Err(e),
        }
    }

    /// Serve until `stop`: write changes as they come, retrying with capped
    /// backoff while the VTA is unreachable.
    pub async fn run(
        self: Arc<Self>,
        remote: Arc<dyn AppState>,
        store: crate::store::Store,
        mut stop: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut backoff = Duration::from_millis(500);
        loop {
            if self.stopped() {
                // Fail closed: wait for the stop, write nothing.
                let _ = stop.changed().await;
                return;
            }
            if self.dirty.lock().expect("lock").is_empty() {
                tokio::select! {
                    _ = self.wake.notified() => {}
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {}
                    _ = stop.changed() => {
                        // One last pass, so a clean stop leaves nothing behind.
                        if !self.stopped() {
                            let _ = self.sync_once(remote.as_ref(), &store).await;
                        }
                        return;
                    }
                }
            }
            match self.sync_once(remote.as_ref(), &store).await {
                Ok(()) => {
                    if backoff > Duration::from_millis(500) {
                        tracing::info!("the bridge's state was written to the VTA");
                    }
                    backoff = Duration::from_millis(500);
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        pending = self.pending(),
                        "could not write the bridge's state to the VTA; retrying in {backoff:?}"
                    );
                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => {}
                        _ = stop.changed() => return,
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
            }
        }
    }

    /// Wait until every change made so far is in the VTA, for at most
    /// `timeout`. `false` if it is not by then.
    pub async fn flush(&self, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.stopped() {
                return false;
            }
            let idle = self.idle.notified();
            if self.pending() == 0 {
                return true;
            }
            self.wake.notify_one();
            if tokio::time::timeout_at(deadline, idle).await.is_err() {
                return self.pending() == 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::MasterKey;
    use crate::store::Store;

    fn vta_store() -> (Store, Arc<Mirror>) {
        let m = Mirror::new(MasterKey::from_bytes([3u8; 32]));
        let s = Store::in_memory(MasterKey::generate().unwrap())
            .unwrap()
            .with_mirror(m.clone());
        (s, m)
    }

    #[tokio::test]
    async fn changes_reach_the_remote_and_a_new_host_pulls_them_back() {
        let remote = MemoryAppState::new();
        let (s, m) = vta_store();
        s.put(Table::Namespaces, "ns_1", &json!({"id": "ns_1"}))
            .unwrap();
        s.put(Table::Jobs, "j1", &json!({"not": "mirrored"}))
            .unwrap();
        s.put_secret("github/github.com/app", b"pem").unwrap();
        s.put_secret("pending/abc/device", b"code").unwrap();
        assert_eq!(m.pending(), 2);
        m.sync_once(&remote, &s).await.unwrap();
        assert_eq!(m.pending(), 0);
        let snap = remote.snapshot();
        assert_eq!(
            snap.keys().cloned().collect::<Vec<_>>(),
            ["secret/github/github.com/app", "state/namespaces/ns_1"]
        );
        // A new host: empty cache, same remote.
        let (s2, m2) = vta_store();
        m2.pull(&remote, &s2).await.unwrap();
        assert_eq!(
            s2.get::<Value>(Table::Namespaces, "ns_1").unwrap(),
            Some(json!({"id": "ns_1"}))
        );
        assert_eq!(
            &*s2.get_secret("github/github.com/app").unwrap().unwrap(),
            b"pem"
        );
        assert!(s2.get::<Value>(Table::Jobs, "j1").unwrap().is_none());
        assert_eq!(m2.pending(), 0);
        // A deletion is mirrored too.
        s2.delete(Table::Namespaces, "ns_1").unwrap();
        m2.sync_once(&remote, &s2).await.unwrap();
        assert!(!remote.snapshot().contains_key("state/namespaces/ns_1"));
    }

    #[tokio::test]
    async fn secrets_never_reach_the_local_file() {
        let (s, _m) = vta_store();
        s.put_secret("forgejo/codeberg.org/bot-token", b"tok")
            .unwrap();
        assert!(s.raw_secret_rows().unwrap().is_empty());
        assert_eq!(
            s.secret_names().unwrap(),
            ["forgejo/codeberg.org/bot-token"]
        );
    }

    #[tokio::test]
    async fn an_unreachable_vta_keeps_changes_pending_and_flush_says_so() {
        let remote = Arc::new(MemoryAppState::new());
        let (s, m) = vta_store();
        remote.set_down(true);
        s.put(Table::Repos, "github.com#1", &json!({"x": 1}))
            .unwrap();
        assert!(m.sync_once(remote.as_ref(), &s).await.is_err());
        assert_eq!(m.pending(), 1);
        assert!(!m.flush(Duration::from_millis(50)).await);
        remote.set_down(false);
        let (tx, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(m.clone().run(remote.clone(), s.clone(), rx));
        assert!(m.flush(Duration::from_secs(5)).await);
        assert!(remote.snapshot().contains_key("state/repos/github.com#1"));
        let _ = tx.send(true);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn a_second_writer_stops_the_mirror() {
        let remote = MemoryAppState::new();
        let (s, m) = vta_store();
        s.put(Table::Meta, "k", &json!(1)).unwrap();
        m.sync_once(&remote, &s).await.unwrap();
        // Another host writes the same record.
        remote.put("state/meta/k", json!(2), None).await.unwrap();
        s.put(Table::Meta, "k", &json!(3)).unwrap();
        assert!(m.sync_once(&remote, &s).await.is_err());
        assert!(m.stopped());
        // Nothing overwritten, nothing more written, and flush says so.
        assert_eq!(remote.snapshot()["state/meta/k"], json!(2));
        s.put(Table::Meta, "other", &json!(1)).unwrap();
        assert!(m.sync_once(&remote, &s).await.is_err());
        assert!(!remote.snapshot().contains_key("state/meta/other"));
        assert!(!m.flush(Duration::from_millis(10)).await);
    }

    #[tokio::test]
    async fn secrets_leave_the_host_sealed() {
        let remote = MemoryAppState::new();
        let (s, m) = vta_store();
        s.put_secret("github/github.com/app", b"-----BEGIN RSA PRIVATE KEY-----")
            .unwrap();
        m.sync_once(&remote, &s).await.unwrap();
        let stored = remote.snapshot()["secret/github/github.com/app"].to_string();
        assert!(!stored.contains("BEGIN RSA"), "{stored}");
        assert!(!stored.contains(&B64.encode(b"-----BEGIN RSA PRIVATE KEY-----")));
        // Another context's key does not open it.
        let other = Mirror::new(MasterKey::from_bytes([4u8; 32]));
        let s2 = Store::in_memory(MasterKey::generate().unwrap())
            .unwrap()
            .with_mirror(other.clone());
        assert!(other.pull(&remote, &s2).await.is_err());
        // Bound to its name: moved to another key, it does not open either.
        let v = remote.snapshot()["secret/github/github.com/app"].clone();
        assert!(
            secret_bytes(&MasterKey::from_bytes([3u8; 32]), "forgejo/x/bot-token", &v).is_err()
        );
    }

    #[tokio::test]
    async fn cached_records_the_remote_lacks_are_written_back() {
        let remote = MemoryAppState::new();
        let (s, m) = vta_store();
        s.put_cached(Table::Namespaces, "ns_9", &json!({"id": "ns_9"}))
            .unwrap();
        m.pull(&remote, &s).await.unwrap();
        assert_eq!(m.pending(), 1);
        m.sync_once(&remote, &s).await.unwrap();
        assert!(remote.snapshot().contains_key("state/namespaces/ns_9"));
    }
}
