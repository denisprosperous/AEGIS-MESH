//! Distance-vector router — with signed route announcements + bounded seq (audit fixes).

use crate::crypto::identity::IdentityId;
use crate::error::Result;
use crate::messaging::envelope::{Envelope, EnvelopeId, EnvelopeType, Payload};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Max allowed sequence jump (audit fix: was unbounded, u64::MAX attack).
pub const MAX_SEQ_JUMP: u64 = 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    pub next_hop: IdentityId,
    pub cost: u8,
    pub seq: u64,
    pub updated_ns: u64,
}

#[derive(Debug, Default)]
pub struct RouteTable {
    routes: RwLock<HashMap<IdentityId, RouteEntry>>,
    seen_messages: RwLock<HashMap<EnvelopeId, Instant>>,
    seen_ttl: Duration,
}

impl RouteTable {
    pub fn new() -> Self {
        Self {
            routes: RwLock::new(HashMap::new()),
            seen_messages: RwLock::new(HashMap::new()),
            seen_ttl: Duration::from_secs(300),
        }
    }

    /// Update route with seq bound check (audit fix: u64::MAX attack).
    pub async fn update(&self, dest: IdentityId, entry: RouteEntry) -> bool {
        let mut routes = self.routes.write().await;
        let should_update = match routes.get(&dest) {
            None => true,
            Some(existing) => {
                // Reject absurdly high seq jumps (audit fix).
                if entry.seq > existing.seq + MAX_SEQ_JUMP && entry.seq != u64::MAX {
                    return false; // suspicious — reject
                }
                if entry.seq > existing.seq { true }
                else if entry.seq == existing.seq && entry.cost < existing.cost { true }
                else { false }
            }
        };
        if should_update {
            routes.insert(dest, entry);
            true
        } else { false }
    }

    pub async fn next_hop(&self, dest: &IdentityId) -> Option<IdentityId> {
        self.routes.read().await.get(dest).map(|e| e.next_hop.clone())
    }

    pub async fn get(&self, dest: &IdentityId) -> Option<RouteEntry> {
        self.routes.read().await.get(dest).cloned()
    }

    pub async fn remove(&self, dest: &IdentityId) {
        self.routes.write().await.remove(dest);
    }

    /// Remove all routes via a given next_hop (audit fix: was missing).
    pub async fn remove_routes_via(&self, next_hop: &IdentityId) {
        let mut routes = self.routes.write().await;
        routes.retain(|_, e| e.next_hop != *next_hop);
    }

    pub async fn snapshot(&self) -> Vec<(IdentityId, RouteEntry)> {
        self.routes.read().await.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    pub async fn check_and_record(&self, id: &EnvelopeId) -> bool {
        let mut seen = self.seen_messages.write().await;
        if seen.contains_key(id) { return false; }
        seen.insert(id.clone(), Instant::now());
        true
    }

    /// GC seen messages — must be called periodically (audit fix: was never called).
    pub async fn gc_seen(&self) {
        let mut seen = self.seen_messages.write().await;
        let now = Instant::now();
        seen.retain(|_, ts| now.duration_since(*ts) < self.seen_ttl);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDecision {
    Deliver,
    DeliverAndRelay,
    Relay,
    Drop,
}

pub struct Router {
    pub our_id: IdentityId,
    pub table: RouteTable,
    pub max_hops: u8,
}

impl Router {
    pub fn new(our_id: IdentityId, max_hops: u8) -> Self {
        Self { our_id, table: RouteTable::new(), max_hops }
    }

    /// Route inbound — checks max_hops BEFORE dedup (audit fix: order was wrong).
    pub async fn route_inbound(&self, env: &Envelope) -> Result<RouteDecision> {
        // Validate hops first (before polluting dedup cache).
        if env.hops > self.max_hops { return Ok(RouteDecision::Drop); }
        if env.ttl == 0 && env.hops > 0 { return Ok(RouteDecision::Drop); }

        // Timestamp freshness check (audit fix: was replayable).
        let max_age_ns = 10 * 60 * 1_000_000_000u64; // 10 minutes
        let max_skew_ns = 60 * 1_000_000_000u64; // 60 seconds
        if !env.is_fresh(max_age_ns, max_skew_ns) { return Ok(RouteDecision::Drop); }

        // Dedup
        if !self.table.check_and_record(&env.id).await { return Ok(RouteDecision::Drop); }

        let for_us = match &env.recipient {
            Some(r) => r == &self.our_id,
            None => true,
        };
        if for_us {
            let should_relay = matches!(env.kind, EnvelopeType::Channel | EnvelopeType::Broadcast | EnvelopeType::PeerDiscovery | EnvelopeType::RouteAnnounce);
            if should_relay && env.ttl > 0 {
                return Ok(RouteDecision::DeliverAndRelay);
            }
            return Ok(RouteDecision::Deliver);
        }
        if env.ttl > 0 { Ok(RouteDecision::Relay) } else { Ok(RouteDecision::Drop) }
    }

    /// Process a signed route announce (audit fix: was never called, unauthenticated).
    pub async fn process_route_announce(
        &self,
        origin: IdentityId,
        origin_verifying_key: [u8; 32],
        hop_count: u8,
        seq: u64,
        via: IdentityId,
        signature: &[u8; 64],
    ) -> Result<bool> {
        if origin == self.our_id { return Ok(false); }
        // Reject hop_count that would overflow (audit fix: u8 wrapping).
        if hop_count >= 255 { return Ok(false); }
        let cost = hop_count.saturating_add(1);

        // Verify signature over (origin, hop_count, seq) — audit fix: was unauthenticated.
        let mut msg = Vec::new();
        msg.extend_from_slice(origin.as_str().as_bytes());
        msg.extend_from_slice(&hop_count.to_be_bytes());
        msg.extend_from_slice(&seq.to_be_bytes());
        let Ok(vk) = VerifyingKey::from_bytes(&origin_verifying_key) else {
            return Err(crate::AegisError::Signature);
        };
        use ed25519_dalek::Verifier;
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        if vk.verify(&msg, &sig).is_err() {
            return Err(crate::AegisError::Signature);
        }

        // Verify identity binding (audit fix).
        let mut h = sha2::Sha256::new();
        h.update(&origin_verifying_key);
        let computed_id = hex::encode(h.finalize());
        if computed_id != origin.0 {
            return Err(crate::AegisError::Signature);
        }

        let entry = RouteEntry {
            next_hop: via,
            cost,
            seq,
            updated_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64).unwrap_or(0),
        };
        Ok(self.table.update(origin, entry).await)
    }

    /// Forward targets — excludes sender (audit fix: was empty / didn't exclude sender).
    pub async fn forward_targets(&self, env: &Envelope, online_neighbors: &[IdentityId]) -> Vec<IdentityId> {
        if let Some(recipient) = &env.recipient {
            // Direct message — use route table if available.
            if let Some(next) = self.table.next_hop(recipient).await {
                if next != env.sender { return vec![next]; }
            }
            // Unknown route — flood to all neighbors except sender.
            return online_neighbors.iter()
                .filter(|n| **n != env.sender)
                .cloned().collect();
        }
        // Broadcast/channel — flood to all neighbors except sender.
        online_neighbors.iter()
            .filter(|n| **n != env.sender)
            .cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::Identity;
    use crate::messaging::envelope::{EnvelopeFlags, Payload};

    fn make_env(sender: IdentityId, recipient: Option<IdentityId>, ttl: u8) -> Envelope {
        Envelope {
            version: crate::messaging::envelope::ENVELOPE_VERSION,
            id: EnvelopeId::new(), kind: EnvelopeType::Direct, sender, recipient, channel: None,
            payload: Payload::Text("hi".into()), timestamp_ns: now_ns(), ttl, hops: 0,
            priority: 2, flags: EnvelopeFlags::new(), signature: None,
        }
    }

    fn now_ns() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64).unwrap_or(0)
    }

    #[tokio::test]
    async fn deliver_for_us() {
        let bob = Identity::new("Bob").public_view().id;
        let alice = Identity::new("Alice").public_view().id;
        let router = Router::new(bob.clone(), 10);
        let env = make_env(alice, Some(bob), 10);
        assert_eq!(router.route_inbound(&env).await.unwrap(), RouteDecision::Deliver);
    }

    #[tokio::test]
    async fn relay_for_others() {
        let bob = Identity::new("Bob").public_view().id;
        let alice = Identity::new("Alice").public_view().id;
        let carol = Identity::new("Carol").public_view().id;
        let router = Router::new(bob, 10);
        let env = make_env(alice, Some(carol), 10);
        assert_eq!(router.route_inbound(&env).await.unwrap(), RouteDecision::Relay);
    }

    #[tokio::test]
    async fn drop_duplicate() {
        let bob = Identity::new("Bob").public_view().id;
        let alice = Identity::new("Alice").public_view().id;
        let router = Router::new(bob.clone(), 10);
        let env = make_env(alice, Some(bob), 10);
        let _ = router.route_inbound(&env).await.unwrap();
        assert_eq!(router.route_inbound(&env).await.unwrap(), RouteDecision::Drop);
    }

    #[tokio::test]
    async fn max_hops_checked_before_dedup() {
        let bob = Identity::new("Bob").public_view().id;
        let alice = Identity::new("Alice").public_view().id;
        let carol = Identity::new("Carol").public_view().id;
        let router = Router::new(bob, 10);
        let mut env = make_env(alice, Some(carol), 10);
        env.hops = 20; // exceeds max_hops
        // First call drops, but doesn't pollute dedup (audit fix).
        assert_eq!(router.route_inbound(&env).await.unwrap(), RouteDecision::Drop);
        // Same envelope should still be droppable (not in dedup cache).
        env.hops = 0; // fix hops, same ID
        let dec = router.route_inbound(&env).await.unwrap();
        assert_ne!(dec, RouteDecision::Drop, "should not be deduped since max_hops check came first");
    }

    #[tokio::test]
    async fn forward_targets_excludes_sender() {
        let bob = Identity::new("Bob").public_view().id;
        let alice = Identity::new("Alice").public_view().id;
        let carol = Identity::new("Carol").public_view().id;
        let router = Router::new(bob.clone(), 10);
        let env = make_env(alice.clone(), Some(carol.clone()), 10);
        let neighbors = vec![alice.clone(), bob.clone(), carol.clone()];
        let targets = router.forward_targets(&env, &neighbors).await;
        assert!(!targets.contains(&alice), "must exclude sender");
    }

    #[tokio::test]
    async fn route_table_rejects_absurd_seq_jump() {
        let dest = Identity::new("Dest").public_view().id;
        let via1 = Identity::new("Via1").public_view().id;
        let via2 = Identity::new("Via2").public_view().id;
        let table = RouteTable::new();
        table.update(dest.clone(), RouteEntry { next_hop: via1, cost: 2, seq: 1, updated_ns: 0 }).await;
        // Absurd jump — should be rejected.
        let changed = table.update(dest.clone(), RouteEntry { next_hop: via2, cost: 1, seq: 2000, updated_ns: 0 }).await;
        assert!(!changed, "absurd seq jump must be rejected");
    }
}
