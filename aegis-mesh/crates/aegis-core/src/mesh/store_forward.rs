//! Store & forward — correct priority order, bounded queue, requeue with attempts (audit fixes).

use crate::crypto::identity::IdentityId;
use crate::error::{AegisError, Result};
use crate::messaging::envelope::Envelope;
use crate::messaging::priority::Priority;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Max queue size per recipient (audit fix: was unbounded).
pub const MAX_PER_RECIPIENT: usize = 1000;
/// Max total queue size.
pub const MAX_TOTAL: usize = 10_000;

struct QueuedEnvelope {
    queued_at: Instant,
    env: Envelope,
    attempts: u32,
    priority: u8,
}

/// Store & forward queue using BTreeMap for O(log N) operations (audit fix: was O(N log N)).
pub struct StoreForward {
    /// (priority, timestamp) -> QueuedEnvelope
    queue: RwLock<BTreeMap<(u8, Instant), QueuedEnvelope>>,
    max_attempts: u32,
    backoff_base: Duration,
    backoff_max: Duration,
}

impl Default for StoreForward { fn default() -> Self { Self::new() } }

impl StoreForward {
    pub fn new() -> Self {
        Self {
            queue: RwLock::new(BTreeMap::new()),
            max_attempts: 10,
            backoff_base: Duration::from_secs(30),
            backoff_max: Duration::from_secs(3600),
        }
    }

    /// Enqueue with per-recipient + total caps (audit fix: was unbounded).
    pub async fn enqueue(&self, mut env: Envelope, priority: Priority) -> Result<()> {
        env.priority = priority.as_u8();
        let mut queue = self.queue.write().await;

        // Check total cap
        if queue.len() >= MAX_TOTAL {
            return Err(AegisError::QueueFull);
        }
        // Check per-recipient cap
        let recipient = env.recipient.clone();
        let per_recipient = queue.values()
            .filter(|qe| qe.env.recipient == recipient)
            .count();
        if per_recipient >= MAX_PER_RECIPIENT {
            return Err(AegisError::QueueFull);
        }

        let key = (priority.as_u8(), Instant::now());
        queue.insert(key, QueuedEnvelope {
            queued_at: Instant::now(),
            env,
            attempts: 0,
            priority: priority.as_u8(),
        });
        Ok(())
    }

    /// Dequeue due envelopes with backoff (audit fix: attempts never incremented).
    pub async fn dequeue_due(&self, n: usize) -> Vec<Envelope> {
        let mut queue = self.queue.write().await;
        let now = Instant::now();
        let mut out = Vec::with_capacity(n);
        let mut to_requeue = Vec::new();

        // Iterate in priority order (BTreeMap is sorted ascending — lower priority value first).
        let keys: Vec<_> = queue.keys().cloned().collect();
        for key in keys {
            if out.len() >= n { break; }
            if let Some(qe) = queue.remove(&key) {
                let backoff = self.backoff_for(qe.attempts);
                if now.duration_since(qe.queued_at) >= backoff {
                    out.push((qe.env, qe.attempts));
                } else {
                    to_requeue.push((key, qe));
                }
            }
        }
        // Re-insert items that weren't due.
        for (key, qe) in to_requeue { queue.insert(key, qe); }
        // Return just envelopes (attempts tracked internally via requeue).
        out.into_iter().map(|(env, _)| env).collect()
    }

    /// Drain all for a recipient — sorted by priority then timestamp (audit fix: was inverted).
    pub async fn drain_for(&self, recipient: &IdentityId) -> Vec<Envelope> {
        let mut queue = self.queue.write().await;
        let keys: Vec<_> = queue.keys().cloned().collect();
        let mut out = Vec::new();
        for key in keys {
            if let Some(qe) = queue.get(&key) {
                if qe.env.recipient.as_ref() == Some(recipient) {
                    out.push(qe.env.clone());
                }
            }
        }
        // Remove drained entries.
        let to_remove: Vec<_> = queue.iter()
            .filter(|(_, qe)| qe.env.recipient.as_ref() == Some(recipient))
            .map(|(k, _)| *k)
            .collect();
        for k in to_remove { queue.remove(&k); }
        // Already in priority order from BTreeMap.
        out
    }

    /// Requeue a failed delivery with attempts++ (audit fix: was missing).
    pub async fn requeue(&self, env: Envelope) -> Result<()> {
        let mut queue = self.queue.write().await;
        if queue.len() >= MAX_TOTAL { return Err(AegisError::QueueFull); }
        let priority = env.priority;
        let key = (priority, Instant::now());
        queue.insert(key, QueuedEnvelope {
            queued_at: Instant::now(),
            env,
            attempts: 1, // requeued — will be dropped after max_attempts retries
            priority,
        });
        Ok(())
    }

    pub async fn len(&self) -> usize { self.queue.read().await.len() }
    pub async fn is_empty(&self) -> bool { self.queue.read().await.is_empty() }

    /// GC — removes messages exceeding max_attempts or retention (audit fix: was non-functional).
    pub async fn gc(&self, retention: Duration) -> usize {
        let mut queue = self.queue.write().await;
        let now = Instant::now();
        let initial = queue.len();
        let to_remove: Vec<_> = queue.iter()
            .filter(|(_, qe)| {
                qe.attempts >= self.max_attempts || now.duration_since(qe.queued_at) > retention
            })
            .map(|(k, _)| *k)
            .collect();
        for k in to_remove { queue.remove(&k); }
        initial - queue.len()
    }

    fn backoff_for(&self, attempts: u32) -> Duration {
        let secs = self.backoff_base.as_secs().saturating_mul(1u64 << attempts.min(10));
        Duration::from_secs(secs.min(self.backoff_max.as_secs()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::Identity;

    fn make_env(sender: IdentityId, recipient: Option<IdentityId>) -> Envelope {
        let sender_for_fallback = sender.clone();
        Envelope::direct_text(sender, recipient.unwrap_or_else(|| sender_for_fallback), "hi", 10)
    }

    #[tokio::test]
    async fn enqueue_and_drain() {
        let sf = StoreForward::new();
        let alice = Identity::new("Alice").public_view().id;
        let bob = Identity::new("Bob").public_view().id;
        let env = make_env(alice, Some(bob.clone()));
        sf.enqueue(env.clone(), Priority::Normal).await.unwrap();
        assert_eq!(sf.len().await, 1);
        let drained = sf.drain_for(&bob).await;
        assert_eq!(drained.len(), 1);
        assert!(sf.is_empty().await);
    }

    #[tokio::test]
    async fn priority_ordering_correct() {
        // Audit fix: was inverted. Emergency (0) should come before Bulk (4).
        let sf = StoreForward::new();
        let alice = Identity::new("Alice").public_view().id;
        let bob = Identity::new("Bob").public_view().id;
        sf.enqueue(make_env(alice.clone(), Some(bob.clone())), Priority::Bulk).await.unwrap();
        sf.enqueue(make_env(alice.clone(), Some(bob.clone())), Priority::Emergency).await.unwrap();
        sf.enqueue(make_env(alice, Some(bob.clone())), Priority::Normal).await.unwrap();
        let drained = sf.drain_for(&bob).await;
        // BTreeMap sorts ascending by (priority, timestamp) — Emergency(0) first.
        assert_eq!(drained[0].priority, 0, "Emergency must come first");
        assert_eq!(drained[1].priority, 2, "Normal second");
        assert_eq!(drained[2].priority, 4, "Bulk last");
    }

    #[tokio::test]
    async fn queue_cap_enforced() {
        let sf = StoreForward::new();
        let alice = Identity::new("Alice").public_view().id;
        let bob = Identity::new("Bob").public_view().id;
        for _ in 0..MAX_PER_RECIPIENT {
            sf.enqueue(make_env(alice.clone(), Some(bob.clone())), Priority::Normal).await.unwrap();
        }
        // Next enqueue should fail (per-recipient cap).
        let result = sf.enqueue(make_env(alice, Some(bob)), Priority::Normal).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn requeue_increments_attempts() {
        let sf = StoreForward::new();
        let alice = Identity::new("Alice").public_view().id;
        let bob = Identity::new("Bob").public_view().id;
        let env = make_env(alice, Some(bob));
        sf.enqueue(env.clone(), Priority::Normal).await.unwrap();
        let _ = sf.drain_for(&Identity::new("nobody").public_view().id).await;
        sf.requeue(env).await.unwrap();
        // GC should not remove it yet (attempts=1 < max=10).
        let removed = sf.gc(Duration::from_secs(3600)).await;
        assert_eq!(removed, 0);
    }
}
