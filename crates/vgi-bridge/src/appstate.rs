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

use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};
use tokio::sync::Notify;
use zeroize::Zeroizing;

use crate::seal::MasterKey;
use crate::store::Table;

/// A namespace counter and its records by key (`None`: a tombstone).
type Versioned = (u64, BTreeMap<String, (u64, Option<Value>)>);

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
    /// A tombstone: the record was deleted at `version`.
    pub deleted: bool,
    /// The value (`Null` on a tombstone).
    pub value: Value,
}

/// Everything the remote holds for the bridge: live records **and the
/// tombstones it still retains**, and the namespace counter.
#[derive(Debug, Clone, Default)]
pub struct Listing {
    /// Each key's latest record.
    pub records: Vec<Record>,
    /// The namespace counter (the version the latest write took).
    pub watermark: u64,
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
    /// Every record in the bridge's namespace, tombstones included, and
    /// the namespace counter.
    async fn list(&self) -> Result<Listing>;
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
    /// Remove `key` (a no-op if there is nothing there). Returns the
    /// version the tombstone took, if a record was removed.
    async fn delete(
        &self,
        key: &str,
        expected: Option<u64>,
    ) -> std::result::Result<Option<u64>, PutError>;
}

/// An in-memory [`AppState`], for tests and dry runs. Behaves as the VTA's
/// does: one counter for the namespace, conditional writes.
#[derive(Default)]
pub struct MemoryAppState {
    inner: Mutex<Versioned>,
    /// When set, every call fails (the VTA unreachable).
    down: std::sync::atomic::AtomicBool,
    /// Puts per key, for tests that count writes.
    puts: Mutex<BTreeMap<String, usize>>,
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

    /// A snapshot of every live record, by key.
    pub fn snapshot(&self) -> BTreeMap<String, Value> {
        let g = self.inner.lock().expect("lock");
        g.1.iter()
            .filter_map(|(k, (_, v))| v.as_ref().map(|v| (k.clone(), v.clone())))
            .collect()
    }

    /// How many puts `key` has had.
    pub fn puts(&self, key: &str) -> usize {
        self.puts
            .lock()
            .expect("lock")
            .get(key)
            .copied()
            .unwrap_or(0)
    }

    /// Put `value` at `key` as someone else would (no precondition).
    pub fn put_as_other(&self, key: &str, value: Value) -> u64 {
        let mut g = self.inner.lock().expect("lock");
        g.0 += 1;
        let v = g.0;
        g.1.insert(key.to_string(), (v, Some(value)));
        v
    }

    /// The live record at `key`, raw.
    pub fn raw(&self, key: &str) -> Option<(u64, Value)> {
        let g = self.inner.lock().expect("lock");
        g.1.get(key).and_then(|(v, x)| x.clone().map(|x| (*v, x)))
    }

    /// Forget the tombstones (the VTA's retention window passed).
    pub fn reap_tombstones(&self) {
        let mut g = self.inner.lock().expect("lock");
        g.1.retain(|_, (_, v)| v.is_some());
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
    async fn list(&self) -> Result<Listing> {
        self.check()?;
        let g = self.inner.lock().expect("lock");
        Ok(Listing {
            records: g
                .1
                .iter()
                .map(|(k, (v, value))| Record {
                    key: k.clone(),
                    version: *v,
                    deleted: value.is_none(),
                    value: value.clone().unwrap_or(Value::Null),
                })
                .collect(),
            watermark: g.0,
        })
    }

    async fn get(&self, key: &str) -> Result<Option<Record>> {
        self.check()?;
        let g = self.inner.lock().expect("lock");
        Ok(g.1.get(key).and_then(|(v, value)| {
            value.as_ref().map(|value| Record {
                key: key.to_string(),
                version: *v,
                deleted: false,
                value: value.clone(),
            })
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
        let current = g.1.get(key).and_then(|(v, x)| x.as_ref().map(|_| *v));
        Self::precondition(current, expected)?;
        g.0 += 1;
        let v = g.0;
        g.1.insert(key.to_string(), (v, Some(value)));
        *self
            .puts
            .lock()
            .expect("lock")
            .entry(key.to_string())
            .or_insert(0) += 1;
        Ok(v)
    }

    async fn delete(
        &self,
        key: &str,
        expected: Option<u64>,
    ) -> std::result::Result<Option<u64>, PutError> {
        self.check().map_err(PutError::Other)?;
        let mut g = self.inner.lock().expect("lock");
        let current = g.1.get(key).and_then(|(v, x)| x.as_ref().map(|_| *v));
        if current.is_none() {
            return Ok(None);
        }
        Self::precondition(current, expected)?;
        g.0 += 1;
        let v = g.0;
        g.1.insert(key.to_string(), (v, None));
        Ok(Some(v))
    }
}

/// The table and local key a remote `state/<table>/<key>` names, if it is
/// one this release mirrors.
fn parse_state_key(key: &str) -> Option<(Table, &str)> {
    let rest = key.strip_prefix("state/")?;
    let (table, local) = rest.split_once('/')?;
    let table = Table::from_name(table).filter(|t| record_is_mirrored(*t, local))?;
    Some((table, local))
}

/// The remote key of a mirrored record.
pub fn state_key(table: Table, key: &str) -> String {
    format!("state/{}/{key}", table.name())
}

/// The remote key of a secret.
pub fn secret_key(name: &str) -> String {
    format!("secret/{name}")
}

/// The associated data a secret is sealed under: its name **and the version
/// of the record that holds it**. A ciphertext put back later (a replay by
/// anyone with app-state access, or a rolled-back store) lands at another
/// version and does not open.
fn secret_aad(name: &str, version: u64) -> String {
    format!("{}@{version}", secret_key(name))
}

/// A secret as the remote holds it at record version `version`: sealed
/// under `seal`, bound to its name and that version.
pub fn secret_value(seal: &MasterKey, name: &str, version: u64, bytes: &[u8]) -> Result<Value> {
    Ok(json!({ "sealed": B64.encode(seal.seal(&secret_aad(name, version), bytes)?) }))
}

/// Open a secret record read at version `version`.
pub fn secret_bytes(
    seal: &MasterKey,
    name: &str,
    version: u64,
    v: &Value,
) -> Result<Zeroizing<Vec<u8>>> {
    let s = v
        .get("sealed")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("not a sealed secret record"))?;
    seal.open(&secret_aad(name, version), &B64.decode(s)?).map_err(|_| {
        anyhow!(
            "the secret `{name}` does not open with this context's sealing key at the version it \
             is stored at: it was written by someone other than this bridge (or put back from an \
             older copy). Re-set it (`vgi-bridge secret set`, or register the App again), and \
             revoke any credential that is not the bridge's"
        )
    })
}

/// The record every writer of the bridge's app-state holds while it writes
/// (the mirror for a pass, `secret set`, `vta setup`'s probe).
///
/// A secret is sealed to the version its record will take, which is the
/// namespace counter plus one — exact only while nobody else writes the
/// namespace. The lease makes that so: one writer at a time, each write's
/// version known before it is made, so a secret is sealed once and is never
/// left live and unopenable. It expires after [`LEASE_TTL_SECS`], so a
/// writer that crashed holding it holds nothing for long.
pub const LEASE_KEY: &str = "lease/writer";

/// How long a lease lasts unless renewed.
pub const LEASE_TTL_SECS: i64 = 120;

/// A held [`LEASE_KEY`], and the version the holder's next write takes.
#[derive(Debug)]
pub struct Lease {
    holder: String,
    version: u64,
    until: i64,
    next: u64,
}

impl Lease {
    /// Take the lease for `holder`, waiting up to `wait` for another holder
    /// to release it (or for it to expire).
    pub async fn acquire(remote: &dyn AppState, holder: &str, wait: Duration) -> Result<Lease> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let now = chrono::Utc::now().timestamp();
            let current = remote.get(LEASE_KEY).await?;
            let expected = match &current {
                None => Some(0),
                Some(r) => {
                    let until = r.value.get("until").and_then(Value::as_i64).unwrap_or(0);
                    let theirs = r.value.get("holder").and_then(Value::as_str).unwrap_or("");
                    (until < now || theirs == holder).then_some(r.version)
                }
            };
            if let Some(expected) = expected {
                let until = now + LEASE_TTL_SECS;
                match remote
                    .put(
                        LEASE_KEY,
                        json!({ "holder": holder, "until": until }),
                        Some(expected),
                    )
                    .await
                {
                    Ok(version) => {
                        return Ok(Lease {
                            holder: holder.to_string(),
                            version,
                            until,
                            next: version + 1,
                        });
                    }
                    Err(PutError::Conflict(_)) => {}
                    Err(PutError::Other(e)) => return Err(e),
                }
            }
            if tokio::time::Instant::now() >= deadline {
                bail!(
                    "another writer holds the bridge's app-state lease (`{LEASE_KEY}`); try again \
                     shortly"
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Note the version one of the holder's writes (or deletes) took.
    pub fn observe(&mut self, version: u64) {
        self.next = self.next.max(version + 1);
    }

    /// The version the holder's next write takes.
    pub fn next(&self) -> u64 {
        self.next
    }

    /// Extend the lease if less than half of it is left.
    pub async fn renew_if_due(&mut self, remote: &dyn AppState) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        if self.until - now > LEASE_TTL_SECS / 2 {
            return Ok(());
        }
        let until = now + LEASE_TTL_SECS;
        let v = remote
            .put(
                LEASE_KEY,
                json!({ "holder": self.holder, "until": until }),
                Some(self.version),
            )
            .await
            .map_err(|e| anyhow!("renewing the app-state lease: {e}"))?;
        self.version = v;
        self.until = until;
        self.observe(v);
        Ok(())
    }

    /// Give the lease up.
    pub async fn release(self, remote: &dyn AppState) {
        if let Err(e) = remote.delete(LEASE_KEY, Some(self.version)).await {
            tracing::debug!(error = %e, "could not release the app-state lease; it expires");
        }
    }
}

/// Write a sealed secret whose record is at `current` (`None`: absent),
/// holding `lease`: sealed to the version the write takes, so it is written
/// once. If a write outside the lease landed in between (only a writer that
/// ignores it — not the bridge's own tools), it is sealed again to the
/// version it did land at, before this returns. Returns the version it is
/// stored at.
pub async fn put_sealed(
    remote: &dyn AppState,
    seal: &MasterKey,
    name: &str,
    bytes: &[u8],
    current: Option<u64>,
    lease: &mut Lease,
) -> std::result::Result<u64, PutError> {
    let key = secret_key(name);
    let mut expected = current.unwrap_or(0);
    for _ in 0..4 {
        let predicted = lease.next();
        let value = secret_value(seal, name, predicted, bytes).map_err(PutError::Other)?;
        let v = remote.put(&key, value, Some(expected)).await?;
        lease.observe(v);
        if v == predicted {
            return Ok(v);
        }
        tracing::warn!(key = %key, "a write outside the app-state lease landed in between; sealing again");
        expected = v;
    }
    Err(PutError::Other(anyhow!(
        "`{key}` could not be written at a predictable version: something ignores the bridge's \
         app-state lease and keeps writing its VTA context"
    )))
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
    /// This mirror's name as a lease holder.
    holder: String,
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
            holder: format!("mirror-{}", crate::wire::new_id()),
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

    /// Load everything the remote holds, the remote being the authority:
    ///
    /// - secrets into memory, opened at the version they are stored at;
    /// - records into the local cache, over a cached copy;
    /// - a cached record this host **mirrored** that the remote no longer
    ///   has (deleted by another host — a tombstone, or one the VTA has
    ///   since reaped) is dropped here, never written back;
    /// - a cached record this host **never mirrored** (written while the VTA
    ///   was unreachable) is marked for writing, unless the remote holds a
    ///   tombstone for it (deleted since: dropped);
    /// - a remote record at an **older** version than this host mirrored
    ///   means the remote went back in time (restored from an older copy, or
    ///   written by someone replaying one): fail closed.
    pub async fn pull(&self, remote: &dyn AppState, store: &crate::store::Store) -> Result<()> {
        let listing = remote.list().await?;
        let mirrored: BTreeMap<String, u64> =
            store.list::<u64>(Table::Mirror)?.into_iter().collect();
        let mut latest: BTreeMap<String, Record> = BTreeMap::new();
        for r in listing.records {
            match latest.get(&r.key) {
                Some(have) if have.version >= r.version => {}
                _ => {
                    latest.insert(r.key.clone(), r);
                }
            }
        }
        // The VTA restored to a point before this host's last write: its
        // counter is behind what this host saw, and a record this host
        // mirrored after that point is simply missing — not deleted.
        if let Some((key, m)) = mirrored.iter().max_by_key(|(_, v)| **v)
            && listing.watermark < *m
        {
            self.conflicts
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            bail!(
                "the VTA's counter for the bridge's state is at {}, behind the {m} this bridge \
                 wrote `{key}` at: its state was rolled back. The bridge does not run on it (it \
                 would take what is missing for deleted); restore the VTA's current state (or \
                 recreate the context) and start again",
                listing.watermark
            );
        }
        for (key, m) in &mirrored {
            if !latest.contains_key(key) && *m > listing.watermark {
                self.conflicts
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                bail!("`{key}` vanished from the VTA above its counter: its state was rolled back");
            }
        }
        for (key, r) in &latest {
            if let Some(m) = mirrored.get(key)
                && r.version < *m
            {
                self.conflicts
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                bail!(
                    "the VTA holds `{key}` at version {}, older than the {m} this bridge wrote: \
                     its state was rolled back or replayed. The bridge does not run on it; restore \
                     the VTA's current state (or recreate the context) and start again",
                    r.version
                );
            }
        }
        {
            let mut versions = self.versions.lock().expect("lock");
            versions.clear();
            for (k, r) in &latest {
                if !r.deleted {
                    versions.insert(k.clone(), r.version);
                }
            }
        }
        for (key, r) in &latest {
            if let Some(name) = key.strip_prefix("secret/") {
                if r.deleted {
                    continue;
                }
                // Refused rather than skipped: running without a secret the
                // context holds would fail later and less clearly.
                let b = secret_bytes(&self.seal, name, r.version, &r.value)
                    .map_err(|e| e.context(format!("reading `{key}` from the VTA")))?;
                self.secrets
                    .lock()
                    .expect("lock")
                    .insert(name.to_string(), b);
                store.put_cached(Table::Mirror, key, &r.version)?;
            } else if let Some((table, local)) = parse_state_key(key) {
                if r.deleted {
                    if store.get_raw(table, local)?.is_some() {
                        tracing::info!(key = %key, "dropping a cached record deleted in the VTA");
                    }
                    store.delete_cached(table, local)?;
                    store.delete_cached(Table::Mirror, key)?;
                } else {
                    store.put_cached(table, local, &r.value)?;
                    store.put_cached(Table::Mirror, key, &r.version)?;
                }
            } else {
                tracing::debug!(key = %key, "ignoring a record this release does not mirror");
            }
        }
        for table in MIRRORED {
            for local in store.keys(table)? {
                if !record_is_mirrored(table, &local) {
                    continue;
                }
                let key = state_key(table, &local);
                if latest.contains_key(&key) {
                    continue;
                }
                if mirrored.contains_key(&key) {
                    // Mirrored once, gone from the VTA now (its tombstone
                    // reaped): another host deleted it.
                    tracing::info!(key = %key, "dropping a cached record the VTA no longer holds");
                    store.delete_cached(table, &local)?;
                    store.delete_cached(Table::Mirror, &key)?;
                } else {
                    self.mark(Dirty::Record(table, local));
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
        if self.dirty.lock().expect("lock").is_empty() {
            self.idle.notify_waiters();
            return Ok(());
        }
        // One writer at a time (see [`Lease`]). Taken before the batch, so a
        // pass given up while it waits loses nothing.
        let mut lease = Some(Lease::acquire(remote, &self.holder, Duration::from_secs(10)).await?);
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
            if failed.is_none() {
                let l = lease.as_mut().expect("held");
                let res = match l.renew_if_due(remote).await {
                    Ok(()) => self.write(remote, store, &item, l).await,
                    Err(e) => Err(e),
                };
                if let Err(e) = res {
                    failed = Some(e);
                }
            }
            if failed.is_some() {
                // Not written (this one failed, or a failure stopped the
                // pass before it): pending again, then no longer in flight.
                self.dirty.lock().expect("lock").insert(item);
            }
            *self.in_flight.lock().expect("lock") -= 1;
        }
        if let Some(l) = lease.take() {
            l.release(remote).await;
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
        lease: &mut Lease,
    ) -> Result<()> {
        let key = item.remote_key();
        let value: Option<Value> = match item {
            Dirty::Record(t, k) => store.get_raw(*t, k)?,
            // Sealed in `put_sealed`, bound to the version it lands at; the
            // size check below uses a stand-in of the same length.
            Dirty::Secret(n) => {
                let bytes = self.secrets.lock().expect("lock").get(n).cloned();
                match bytes {
                    Some(b) => Some(secret_value(&self.seal, n, u64::MAX, &b)?),
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
        let res = match (&value, item) {
            (Some(_), Dirty::Secret(n)) => {
                let bytes = self.secrets.lock().expect("lock").get(n).cloned();
                let Some(bytes) = bytes else { return Ok(()) };
                put_sealed(remote, &self.seal, n, &bytes, seen, lease)
                    .await
                    .map(Some)
            }
            // `Some(0)`: create only — the remote held nothing when this host
            // last looked.
            (Some(v), _) => remote
                .put(&key, v.clone(), Some(seen.unwrap_or(0)))
                .await
                .map(Some),
            // A deletion takes a version too (its tombstone's): the next
            // write's is one past it.
            (None, _) => remote.delete(&key, seen).await.map(|tombstone| {
                if let Some(t) = tombstone {
                    lease.observe(t);
                }
                None
            }),
        };
        match res {
            Ok(Some(version)) => {
                self.versions
                    .lock()
                    .expect("lock")
                    .insert(key.clone(), version);
                lease.observe(version);
                store.put_cached(Table::Mirror, &key, &version)?;
                Ok(())
            }
            Ok(None) => {
                self.versions.lock().expect("lock").remove(&key);
                store.delete_cached(Table::Mirror, &key)?;
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
        // Bound to its name and version: it opens where it is, and nowhere
        // else.
        let seal = MasterKey::from_bytes([3u8; 32]);
        let (ver, v) = remote.raw("secret/github/github.com/app").unwrap();
        assert!(secret_bytes(&seal, "github/github.com/app", ver, &v).is_ok());
        assert!(secret_bytes(&seal, "forgejo/x/bot-token", ver, &v).is_err());
        assert!(secret_bytes(&seal, "github/github.com/app", ver + 1, &v).is_err());
    }

    /// Probe (review of #89): a host restarted on its old cache must not
    /// bring back what a recovery host deleted in the meantime.
    #[tokio::test]
    async fn a_removed_record_is_not_resurrected_by_a_stale_host() {
        let remote = MemoryAppState::new();
        // Host A mirrors a namespace and a repository, then goes away.
        let (a, ma) = vta_store();
        a.put(Table::Namespaces, "ns_1", &json!({"id": "ns_1"}))
            .unwrap();
        a.put(Table::Repos, "github.com#812", &json!({"forgeId": 812}))
            .unwrap();
        ma.sync_once(&remote, &a).await.unwrap();
        // Host B (recovery) pulls and removes the repository.
        let (b, mb) = vta_store();
        mb.pull(&remote, &b).await.unwrap();
        b.delete(Table::Repos, "github.com#812").unwrap();
        mb.sync_once(&remote, &b).await.unwrap();
        assert!(!remote.snapshot().contains_key("state/repos/github.com#812"));
        // Host A comes back on its old cache: the record is dropped, not
        // written back — while the tombstone is retained, and after.
        for reaped in [false, true] {
            let (a2, ma2) = vta_store();
            a2.put_cached(Table::Repos, "github.com#812", &json!({"forgeId": 812}))
                .unwrap();
            // What A had mirrored, as its cache remembers it.
            for (k, v) in a.list::<u64>(Table::Mirror).unwrap() {
                a2.put_cached(Table::Mirror, &k, &v).unwrap();
            }
            if reaped {
                remote.reap_tombstones();
            }
            ma2.pull(&remote, &a2).await.unwrap();
            assert_eq!(ma2.pending(), 0, "nothing to push (reaped: {reaped})");
            assert!(
                a2.get::<Value>(Table::Repos, "github.com#812")
                    .unwrap()
                    .is_none()
            );
            ma2.sync_once(&remote, &a2).await.unwrap();
            assert!(!remote.snapshot().contains_key("state/repos/github.com#812"));
            assert!(remote.snapshot().contains_key("state/namespaces/ns_1"));
        }
    }

    /// A record the remote holds at an older version than this host wrote
    /// means the remote went back in time: fail closed.
    #[tokio::test]
    async fn a_rolled_back_remote_is_refused() {
        let remote = MemoryAppState::new();
        let (a, ma) = vta_store();
        a.put(Table::Meta, "k", &json!(1)).unwrap();
        ma.sync_once(&remote, &a).await.unwrap();
        let mirrored: Vec<(String, u64)> = a.list(Table::Mirror).unwrap();
        // The cache remembers a later version than the remote holds.
        let (b, mb) = vta_store();
        for (k, v) in mirrored {
            b.put_cached(Table::Mirror, &k, &(v + 5)).unwrap();
        }
        let err = mb.pull(&remote, &b).await.unwrap_err();
        assert!(err.to_string().contains("rolled back"), "{err}");
        assert!(mb.stopped());
    }

    /// A sealed secret put back later (a replay) lands at another version
    /// and does not open: the start is refused.
    #[tokio::test]
    async fn a_replayed_secret_does_not_open() {
        let remote = MemoryAppState::new();
        let (s, m) = vta_store();
        s.put_secret("forgejo/codeberg.org/bot-token", b"old-token")
            .unwrap();
        m.sync_once(&remote, &s).await.unwrap();
        let (_, old) = remote.raw("secret/forgejo/codeberg.org/bot-token").unwrap();
        s.put_secret("forgejo/codeberg.org/bot-token", b"new-token")
            .unwrap();
        m.sync_once(&remote, &s).await.unwrap();
        // Someone with app-state access puts the old ciphertext back.
        remote.put_as_other("secret/forgejo/codeberg.org/bot-token", old);
        let (s2, m2) = vta_store();
        let err = m2.pull(&remote, &s2).await.unwrap_err();
        assert!(format!("{err:#}").contains("does not open"), "{err:#}");
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

    /// Probe (re-review of #89): a VTA restored to a snapshot from before a
    /// record existed must not make the bridge take the missing record for
    /// deleted.
    #[tokio::test]
    async fn a_vta_rolled_back_to_before_a_record_existed_is_refused() {
        let remote = MemoryAppState::new();
        let (s, m) = vta_store();
        s.put(Table::Namespaces, "ns_1", &json!({"id": "ns_1"}))
            .unwrap();
        m.sync_once(&remote, &s).await.unwrap();
        s.put(Table::Namespaces, "ns_2", &json!({"id": "ns_2"}))
            .unwrap();
        m.sync_once(&remote, &s).await.unwrap();
        // The VTA is restored to a snapshot holding ns_1 only, its counter
        // back where it was then.
        let (_, ns1) = remote.raw("state/namespaces/ns_1").unwrap();
        let restored = MemoryAppState::new();
        restored.put_as_other("state/namespaces/ns_1", ns1);
        assert_eq!(restored.list().await.unwrap().watermark, 1);
        // The same host, its cache intact.
        let m2 = Mirror::new(MasterKey::from_bytes([3u8; 32]));
        let s2 = s.clone().with_mirror(m2.clone());
        let err = m2.pull(&restored, &s2).await.unwrap_err();
        assert!(err.to_string().contains("rolled back"), "{err}");
        assert!(m2.stopped(), "fails closed: 503, nothing written");
        assert!(
            s2.get::<Value>(Table::Namespaces, "ns_2")
                .unwrap()
                .is_some(),
            "ns_2 is kept, not taken for deleted"
        );
    }

    /// A deletion and a secret in one pass: the secret is sealed to the
    /// version it takes (the deletion's tombstone moved the counter), once.
    #[tokio::test]
    async fn a_secret_after_a_deletion_is_sealed_once() {
        let remote = MemoryAppState::new();
        let (s, m) = vta_store();
        s.put(Table::Meta, "a", &json!(1)).unwrap();
        m.sync_once(&remote, &s).await.unwrap();
        s.delete(Table::Meta, "a").unwrap();
        s.put_secret("github/github.com/acme/app", b"pem").unwrap();
        m.sync_once(&remote, &s).await.unwrap();
        assert_eq!(
            remote.puts("secret/github/github.com/acme/app"),
            1,
            "sealed once"
        );
        let (s2, m2) = vta_store();
        m2.pull(&remote, &s2).await.unwrap();
        assert_eq!(
            &*s2.get_secret("github/github.com/acme/app")
                .unwrap()
                .unwrap(),
            b"pem"
        );
    }

    /// An operator's `secret set` (or `vta setup`) while the bridge runs:
    /// the lease keeps their writes apart, and every secret opens.
    #[tokio::test]
    async fn writers_take_turns_under_the_lease_and_every_secret_opens() {
        let remote = Arc::new(MemoryAppState::new());
        let (s, m) = vta_store();
        let seal = MasterKey::from_bytes([3u8; 32]);
        // The operator holds the lease and writes a secret.
        let mut op = Lease::acquire(remote.as_ref(), "operator", Duration::from_secs(1))
            .await
            .unwrap();
        // The mirror cannot take it meanwhile: its pass waits for it.
        s.put_secret("forgejo/codeberg.org/bot-token", b"tok")
            .unwrap();
        let pass = {
            let (m, s, remote) = (m.clone(), s.clone(), remote.clone());
            tokio::spawn(async move { m.sync_once(remote.as_ref(), &s).await })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!pass.is_finished(), "the mirror waits for the lease");
        put_sealed(
            remote.as_ref(),
            &seal,
            "forgejo/codeberg.org/webhook-secret",
            b"wh",
            None,
            &mut op,
        )
        .await
        .unwrap();
        op.release(remote.as_ref()).await;
        pass.await.unwrap().unwrap();
        let (s2, m2) = vta_store();
        m2.pull(remote.as_ref(), &s2).await.unwrap();
        assert_eq!(
            &*s2.get_secret("forgejo/codeberg.org/bot-token")
                .unwrap()
                .unwrap(),
            b"tok"
        );
        assert_eq!(
            &*s2.get_secret("forgejo/codeberg.org/webhook-secret")
                .unwrap()
                .unwrap(),
            b"wh"
        );
    }

    /// A write that ignores the lease lands between: the secret is sealed
    /// again to the version it took before `put_sealed` returns — never left
    /// live and unopenable.
    #[tokio::test]
    async fn a_write_outside_the_lease_is_resealed_before_returning() {
        let remote = MemoryAppState::new();
        let seal = MasterKey::from_bytes([3u8; 32]);
        let mut lease = Lease::acquire(&remote, "me", Duration::from_secs(1))
            .await
            .unwrap();
        // Someone bumps the counter without the lease.
        remote.put_as_other("state/meta/x", json!(1));
        let v = put_sealed(&remote, &seal, "a/b", b"s", None, &mut lease)
            .await
            .unwrap();
        let (at, value) = remote.raw("secret/a/b").unwrap();
        assert_eq!(v, at);
        assert_eq!(&*secret_bytes(&seal, "a/b", at, &value).unwrap(), b"s");
        assert_eq!(
            remote.puts("secret/a/b"),
            2,
            "sealed again after the stray write"
        );
    }

    /// A lease its holder crashed with expires.
    #[tokio::test]
    async fn an_abandoned_lease_expires() {
        let remote = MemoryAppState::new();
        remote.put_as_other(LEASE_KEY, json!({ "holder": "crashed", "until": 0 }));
        Lease::acquire(&remote, "me", Duration::from_secs(1))
            .await
            .unwrap();
        remote.put_as_other(
            LEASE_KEY,
            json!({ "holder": "alive", "until": chrono::Utc::now().timestamp() + 60 }),
        );
        assert!(
            Lease::acquire(&remote, "me", Duration::from_millis(300))
                .await
                .is_err()
        );
    }
}
