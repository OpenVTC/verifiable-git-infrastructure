//! A namespace's life after its binding: orphaned namespaces
//! (`git-ns/bridge/event` 0.6), binding an owner again (`git-ns/bridge/job`
//! 0.7), and what the operator sees and removes.
//!
//! **Orphaned.** A VTC can lose a namespace the bridge still serves (its
//! records restored from an older backup, a test instance recreated). It
//! then answers every event for it with `git-ns:unknownNamespace`. A
//! verified answer of that code, threaded to an event the bridge sent naming
//! the namespace, orphans it ([`Bridge::orphan`]); nothing else does — no
//! other code, no refusal the bridge cannot attribute, and never quiet. While
//! orphaned the bridge changes nothing on the forge for it (only a bound
//! namespace loads a job context, a re-sign or a projection), fails the
//! check it posts there, and sends no event for it. It deletes nothing on
//! the forge and keeps its forge-side state — the installation, the
//! workflow repository and ruleset pin, the record of what it projected —
//! for a VTC that binds the owner again.
//!
//! **Back.** A job from the VTC naming the namespace shows the VTC has it
//! after all: the bridge makes it bound again before it admits the job, and
//! reports its role map as for any namespace it starts serving
//! ([`Bridge::unorphan`]).
//!
//! **Superseded.** A `beginBind` for an owner the bridge already holds under
//! another id needs the forge-side proof afresh; when it completes, the new
//! namespace takes the owner's forge-side state over and the earlier ids are
//! retired ([`Bridge::supersede`]) — answered for as ids the bridge never
//! served, never taken again, and named in `bindCompleted.supersedes`.
//! Nothing of the earlier namespace's governance passes on.
//!
//! **Removed.** The operator lists namespaces and forgets an orphaned one
//! (`vgi-bridge namespace list|forget`, [`forget`]); the maintenance tick
//! removes one past its retention ([`Bridge::sweep_orphaned`]). Removing
//! discards the bridge's record, never anything on the forge.

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use vgi_forge::Resource;

use crate::appstate::{AppState, Lease, state_key};

use crate::bridge::{Bridge, now};
use crate::store::{
    NamespaceRecord, NamespaceState, OutboxEntry, OutboxKind, RETIRED_PREFIX, RepoRecord,
    RetiredNamespace, Store, Table,
};

/// Seconds in a day.
const DAY: i64 = 86_400;

/// How long before its removal the operator is warned, daily.
const WARN_AHEAD: i64 = 7 * DAY;

/// When the retention sweep removes orphaned namespace `ns` (Unix seconds),
/// under a retention of `days`. `None` for a namespace that is not orphaned.
pub fn removal_due(ns: &NamespaceRecord, days: u64) -> Option<i64> {
    if !ns.is_orphaned() {
        return None;
    }
    Some(
        ns.orphaned_at
            .unwrap_or(0)
            .saturating_add((days as i64).saturating_mul(DAY)),
    )
}

/// What [`forget`] removed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Forgotten {
    /// The namespace's owner on the forge.
    pub resource: Resource,
    /// How many repository records went with it.
    pub repos: usize,
}

/// Remove orphaned namespace `id`'s record from `store`: the namespace, the
/// repository records the bridge kept for it, and events for it still
/// waiting to be sent. Nothing on the forge is touched. Refused for a
/// namespace that is not orphaned — a bound one is governed, and only the
/// VTC's answer says otherwise.
pub fn forget(store: &Store, id: &str) -> Result<Forgotten> {
    let Some(ns) = store.get::<NamespaceRecord>(Table::Namespaces, id)? else {
        bail!("this bridge holds no namespace `{id}`");
    };
    if !ns.is_orphaned() {
        bail!(
            "namespace `{id}` ({}) is {}, not orphaned: only a namespace its VTC no longer has is \
             forgotten",
            ns.resource,
            state_word(ns.state)
        );
    }
    let mut repos = 0;
    for (key, rec) in store.list::<RepoRecord>(Table::Repos)? {
        if rec.namespace == id && store.delete(Table::Repos, &key)? {
            repos += 1;
        }
    }
    drop_events(store, id);
    store.delete(Table::Namespaces, id)?;
    Ok(Forgotten {
        resource: ns.resource,
        repos,
    })
}

/// Every namespace record in the VTA's app-state (VTA mode, read by the
/// operator's commands without the local cache).
pub async fn list_remote(remote: &dyn AppState) -> Result<Vec<NamespaceRecord>> {
    let prefix = state_key(Table::Namespaces, "");
    let mut out = Vec::new();
    for r in remote.list().await?.records {
        if r.deleted || !r.key.starts_with(&prefix) {
            continue;
        }
        out.push(
            serde_json::from_value(r.value)
                .with_context(|| format!("decoding `{}` from the VTA", r.key))?,
        );
    }
    Ok(out)
}

/// [`forget`], on the VTA's app-state (VTA mode): the namespace's record
/// and its repository records are deleted there, under the bridge's
/// app-state lease, and a bridge drops them from its cache when it next
/// starts. Run it with the bridge stopped: a running one would find the
/// records it mirrored deleted under it and stop mirroring.
pub async fn forget_remote(remote: &dyn AppState, id: &str) -> Result<Forgotten> {
    let listing = remote.list().await?;
    let ns_key = state_key(Table::Namespaces, id);
    let Some(rec) = listing
        .records
        .iter()
        .find(|r| r.key == ns_key && !r.deleted)
    else {
        bail!("the bridge's VTA context holds no namespace `{id}`");
    };
    let ns: NamespaceRecord = serde_json::from_value(rec.value.clone())?;
    if !ns.is_orphaned() {
        bail!(
            "namespace `{id}` ({}) is {}, not orphaned: only a namespace its VTC no longer has is              forgotten",
            ns.resource,
            state_word(ns.state)
        );
    }
    let repo_prefix = state_key(Table::Repos, "");
    let mut doomed: Vec<(String, u64)> = listing
        .records
        .iter()
        .filter(|r| !r.deleted && r.key.starts_with(&repo_prefix))
        .filter(|r| r.value.get("namespace").and_then(Value::as_str) == Some(id))
        .map(|r| (r.key.clone(), r.version))
        .collect();
    let repos = doomed.len();
    // The namespace last: a pass cut short leaves it to be forgotten again.
    doomed.push((ns_key, rec.version));
    let mut lease = Lease::acquire(
        remote,
        &format!("namespace-forget-{}", crate::wire::new_id()),
        std::time::Duration::from_secs(60),
    )
    .await?;
    let done = async {
        for (key, version) in &doomed {
            lease.renew_if_due(remote).await?;
            if let Some(v) = remote
                .delete(key, Some(*version))
                .await
                .map_err(|e| anyhow!("deleting `{key}`: {e}"))?
            {
                lease.observe(v);
            }
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    lease.release(remote).await;
    done?;
    Ok(Forgotten {
        resource: ns.resource,
        repos,
    })
}

/// Delete every event for namespace `ns_id` waiting in the outbox.
fn drop_events(store: &Store, ns_id: &str) -> usize {
    let Ok(entries) = store.list::<OutboxEntry>(Table::Outbox) else {
        return 0;
    };
    let mut n = 0;
    for (key, e) in entries {
        if e.kind == OutboxKind::Event
            && e.payload.get("namespace").and_then(Value::as_str) == Some(ns_id)
            && store.delete(Table::Outbox, &key).unwrap_or(false)
        {
            n += 1;
        }
    }
    n
}

/// A state as the operator reads it.
pub fn state_word(s: NamespaceState) -> &'static str {
    match s {
        NamespaceState::Pending => "pending",
        NamespaceState::Bound => "bound",
        NamespaceState::Orphaned => "orphaned",
        #[allow(unreachable_patterns)]
        _ => "unknown",
    }
}

/// One line of `vgi-bridge namespace list`: id, state, owner, and for an
/// orphaned namespace when it was orphaned and when the retention sweep
/// removes it.
pub fn list_line(ns: &NamespaceRecord, retention_days: u64) -> String {
    let mut line = format!(
        "{}\t{}\t{}",
        ns.id,
        state_word(ns.state),
        ns.resource.as_str()
    );
    if ns.is_orphaned() {
        let at = ns.orphaned_at.unwrap_or(0);
        line.push_str(&format!("\torphaned {}", crate::flows::rfc3339(at)));
        if let Some(due) = removal_due(ns, retention_days) {
            line.push_str(&format!("\tremoved after {}", crate::flows::rfc3339(due)));
        }
    }
    line
}

impl Bridge {
    /// Orphan namespace `ns_id` (`git-ns/bridge/event` 0.6): its VTC answered
    /// an event for it with `git-ns:unknownNamespace`. Only a bound
    /// namespace is orphaned; when it is, every event for it still waiting
    /// is dropped. Returns whether it was orphaned now.
    pub(crate) fn orphan(&self, ns_id: &str) -> bool {
        let at = now();
        let orphaned = self
            .store
            .update::<NamespaceRecord, _>(Table::Namespaces, ns_id, |n| {
                let Some(mut n) = n else {
                    return Ok((None, false));
                };
                if n.state != NamespaceState::Bound {
                    return Ok((Some(n), false));
                }
                n.state = NamespaceState::Orphaned;
                n.orphaned_at = Some(at);
                n.removal_warned_at = None;
                Ok((Some(n), true))
            })
            .unwrap_or_else(|e| {
                tracing::error!(namespace = ns_id, error = %e, "could not orphan a namespace");
                false
            });
        if orphaned {
            let dropped = drop_events(&self.store, ns_id);
            tracing::warn!(
                namespace = ns_id,
                dropped_events = dropped,
                retention_days = self.cfg.orphan_retention_days,
                "the VTC no longer has this namespace: it is orphaned. The bridge changes \
                 nothing on the forge for it, fails the check it posts there, and reports \
                 nothing, until the VTC sends a job for it or binds its owner again. Its \
                 forge-side state is kept; `vgi-bridge namespace forget` removes the bridge's \
                 record of it sooner than the retention period"
            );
        }
        orphaned
    }

    /// A job from the VTC names namespace `ns_id`: if it is orphaned, the VTC
    /// has it after all, and it is bound again (`git-ns/bridge/job` 0.7,
    /// request rule 1). Returns whether it was orphaned.
    pub(crate) fn unorphan(&self, ns_id: &str) -> bool {
        let back = self
            .store
            .update::<NamespaceRecord, _>(Table::Namespaces, ns_id, |n| {
                let Some(mut n) = n else {
                    return Ok((None, false));
                };
                if !n.is_orphaned() {
                    return Ok((Some(n), false));
                }
                n.state = NamespaceState::Bound;
                n.orphaned_at = None;
                n.removal_warned_at = None;
                Ok((Some(n), true))
            })
            .unwrap_or_else(|e| {
                tracing::error!(namespace = ns_id, error = %e, "could not un-orphan a namespace");
                false
            });
        if back {
            tracing::info!(
                namespace = ns_id,
                "the VTC sent a job for an orphaned namespace: it has it after all, and the \
                 bridge serves it again"
            );
        }
        back
    }

    /// Whether namespace `ns_id` is orphaned.
    pub(crate) fn is_orphaned(&self, ns_id: &str) -> bool {
        matches!(
            self.store.get::<NamespaceRecord>(Table::Namespaces, ns_id),
            Ok(Some(n)) if n.is_orphaned()
        )
    }

    /// The retention sweep (from the maintenance tick): remove each orphaned
    /// namespace past `orphan_retention_days`, and warn the operator, once a
    /// day, of each due within a week. Never a bound namespace, however
    /// quiet it has been.
    pub async fn sweep_orphaned(&self) {
        let Ok(all) = self.store.list::<NamespaceRecord>(Table::Namespaces) else {
            return;
        };
        let now = now();
        let days = self.cfg.orphan_retention_days;
        for (id, ns) in all {
            let Some(due) = removal_due(&ns, days) else {
                continue;
            };
            if now >= due {
                // Under the namespace's lock: no job of it runs meanwhile.
                let lock = self.ns_lock(&id);
                let _g = lock.lock().await;
                match forget(&self.store, &id) {
                    Ok(f) => tracing::warn!(
                        namespace = %id,
                        owner = %f.resource,
                        repos = f.repos,
                        "removed the record of a namespace orphaned more than {days} days ago; \
                         nothing on the forge was changed"
                    ),
                    Err(e) => {
                        tracing::warn!(namespace = %id, error = %e, "could not remove an orphaned namespace")
                    }
                }
            } else if due - now <= WARN_AHEAD && ns.removal_warned_at.is_none_or(|w| now - w >= DAY)
            {
                tracing::warn!(
                    namespace = %id,
                    owner = %ns.resource,
                    removal_after = %crate::flows::rfc3339(due),
                    "an orphaned namespace's record will be removed after its retention period \
                     (nothing on the forge is changed); a job from the VTC for it, or its owner \
                     bound again, keeps it"
                );
                let _ = self
                    .store
                    .update::<NamespaceRecord, _>(Table::Namespaces, &id, |n| {
                        Ok((
                            n.map(|mut n| {
                                n.removal_warned_at = Some(now);
                                n
                            }),
                            (),
                        ))
                    });
            }
        }
    }

    /// Binding `new` (the record a completed bind is about to store as
    /// bound) supersedes every namespace this bridge holds — bound or
    /// orphaned — for the same owner under another id (`git-ns/bridge/job`
    /// 0.7, *Binding an owner again*). Their forge-side state passes to
    /// `new`: the managed repository set and the workflow pin (on `new`),
    /// and the repository records (re-keyed to `new`, with what was
    /// projected kept and the owners the earlier VTC named dropped). Each
    /// earlier id is retired. Returns the retired ids, and the repositories
    /// that came over (for `repoCreatedUnmanaged`: the new namespace governs
    /// none of them until its admins adopt them).
    pub(crate) fn supersede(
        &self,
        new: &mut NamespaceRecord,
    ) -> Result<(Vec<String>, Vec<RepoRecord>)> {
        let owner_id = new.binding.as_ref().and_then(|b| b.namespace.owner_id);
        let earlier: Vec<NamespaceRecord> = self
            .store
            .list::<NamespaceRecord>(Table::Namespaces)?
            .into_iter()
            .map(|(_, n)| n)
            .filter(|n| {
                n.id != new.id
                    && matches!(n.state, NamespaceState::Bound | NamespaceState::Orphaned)
                    && n.resource.host() == new.resource.host()
                    && (n.resource == new.resource
                        || (owner_id.is_some()
                            && n.binding.as_ref().and_then(|b| b.namespace.owner_id) == owner_id))
            })
            .collect();
        let at = now();
        let mut retired = Vec::new();
        let mut moved = Vec::new();
        for old in earlier {
            // Retired first: from here on the id is answered for as one the
            // bridge never served, whatever happens next.
            self.store.put(
                Table::Meta,
                &format!("{RETIRED_PREFIX}{}", old.id),
                &RetiredNamespace::new(old.resource.clone(), new.id.clone(), at),
            )?;
            for (key, rec) in self.store.list::<RepoRecord>(Table::Repos)? {
                if rec.namespace != old.id {
                    continue;
                }
                let moved_rec = self
                    .store
                    .update::<RepoRecord, _>(Table::Repos, &key, |r| {
                        let Some(mut r) = r else {
                            return Ok((None, None));
                        };
                        r.namespace = new.id.clone();
                        // Who the earlier VTC named owner is its governance, not
                        // forge-side state: gone with it.
                        r.owners.clear();
                        // The drift is reported afresh to the new namespace.
                        r.last_drift = None;
                        let out = r.clone();
                        Ok((Some(r), Some(out)))
                    })?;
                moved.extend(moved_rec);
            }
            new.managed.extend(old.managed.iter().copied());
            if new.pin.is_none() {
                new.pin = old.pin.clone();
            }
            if new.required_workflow.is_none() {
                new.required_workflow = old.required_workflow;
            }
            drop_events(&self.store, &old.id);
            self.store.delete(Table::Namespaces, &old.id)?;
            tracing::warn!(
                namespace = %new.id,
                retired = %old.id,
                owner = %new.resource,
                "the owner was bound again: the new namespace takes over the forge-side state \
                 the bridge held for it, and the earlier namespace id is retired"
            );
            retired.push(old.id);
        }
        retired.sort();
        Ok((retired, moved))
    }

    /// Whether namespace id `id` was retired by a re-binding.
    pub(crate) fn is_retired(&self, id: &str) -> bool {
        self.store.is_retired(id).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::MasterKey;

    fn rec(id: &str, state: NamespaceState, orphaned_at: Option<i64>) -> NamespaceRecord {
        let mut n = NamespaceRecord::pending(id, Resource::parse("github.com/acme").unwrap());
        n.state = state;
        n.orphaned_at = orphaned_at;
        n
    }

    #[test]
    fn only_an_orphaned_namespace_is_due_for_removal() {
        assert_eq!(
            removal_due(&rec("a", NamespaceState::Orphaned, Some(100)), 30),
            Some(100 + 30 * DAY)
        );
        assert_eq!(
            removal_due(&rec("a", NamespaceState::Bound, None), 30),
            None
        );
        assert_eq!(
            removal_due(&rec("a", NamespaceState::Pending, None), 30),
            None
        );
    }

    #[test]
    fn forget_refuses_a_namespace_that_is_not_orphaned_and_keeps_others() {
        let s = Store::in_memory(MasterKey::generate().unwrap()).unwrap();
        s.put(
            Table::Namespaces,
            "bound",
            &rec("bound", NamespaceState::Bound, None),
        )
        .unwrap();
        s.put(
            Table::Namespaces,
            "gone",
            &rec("gone", NamespaceState::Orphaned, Some(1)),
        )
        .unwrap();
        let r = Resource::parse("github.com/acme/widgets").unwrap();
        s.put(
            Table::Repos,
            "github.com#1",
            &RepoRecord::new("gone", r.clone(), 1),
        )
        .unwrap();
        s.put(
            Table::Repos,
            "github.com#2",
            &RepoRecord::new("bound", r, 2),
        )
        .unwrap();
        assert!(forget(&s, "bound").is_err());
        assert!(forget(&s, "nope").is_err());
        let f = forget(&s, "gone").unwrap();
        assert_eq!(f.repos, 1);
        assert!(
            s.get::<NamespaceRecord>(Table::Namespaces, "gone")
                .unwrap()
                .is_none()
        );
        assert!(
            s.get::<RepoRecord>(Table::Repos, "github.com#2")
                .unwrap()
                .is_some()
        );
    }
}
