//! Peer registry — respects Blocked state (audit fix: observe() unblocked blocked peers).

use crate::crypto::identity::{IdentityId, PublicIdentity};
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PeerState { Online, Stale, Offline, Blocked }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub identity: PublicIdentity,
    pub last_seen_ns: u64,
    pub state: PeerState,
    pub rssi: Option<i8>,
    pub last_transport: Option<String>,
    pub verified: bool,
}

impl Peer {
    pub fn age(&self) -> Duration {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64).unwrap_or(0);
        Duration::from_nanos(now.saturating_sub(self.last_seen_ns))
    }
}

/// Peer registry with rate limiting + Blocked-state protection (audit fixes).
pub struct PeerRegistry {
    peers: RwLock<HashMap<IdentityId, Peer>>,
    /// Per-peer observation timestamps for rate limiting.
    observe_times: RwLock<HashMap<IdentityId, Instant>>,
    stale_threshold: Duration,
    offline_threshold: Duration,
    max_peers: usize,
}

impl Default for PeerRegistry {
    fn default() -> Self { Self::new() }
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            observe_times: RwLock::new(HashMap::new()),
            stale_threshold: Duration::from_secs(300),
            offline_threshold: Duration::from_secs(1800),
            max_peers: 10_000, // audit fix: bounded
        }
    }

    /// Observe a peer — respects Blocked state + rate limit (audit fixes).
    pub async fn observe(
        &self,
        identity: PublicIdentity,
        rssi: Option<i8>,
        transport: impl Into<String>,
    ) -> Result<()> {
        let transport = transport.into();
        let now = Instant::now();

        // Rate limit: max 1 observe per peer per 5 seconds.
        {
            let mut times = self.observe_times.write().await;
            if let Some(last) = times.get(&identity.id) {
                if now.duration_since(*last) < Duration::from_secs(5) {
                    return Ok(()); // rate limited
                }
            }
            times.insert(identity.id.clone(), now);
        }

        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64).unwrap_or(0);

        let mut peers = self.peers.write().await;

        // Audit fix: don't unblock a blocked peer.
        if let Some(existing) = peers.get(&identity.id) {
            if existing.state == PeerState::Blocked {
                return Ok(());
            }
        }

        // Enforce max_peers cap (audit fix: was unbounded).
        if peers.len() >= self.max_peers && !peers.contains_key(&identity.id) {
            // Evict oldest offline peer.
            if let Some(oldest) = peers.iter()
                .filter(|(_, p)| p.state == PeerState::Offline)
                .min_by_key(|(_, p)| p.last_seen_ns)
                .map(|(k, _)| k.clone())
            {
                peers.remove(&oldest);
            } else {
                return Ok(()); // can't add more
            }
        }

        let entry = peers.entry(identity.id.clone()).or_insert_with(|| Peer {
            identity: identity.clone(),
            last_seen_ns: now_ns,
            state: PeerState::Online,
            rssi,
            last_transport: Some(transport.clone()),
            verified: false,
        });
        entry.last_seen_ns = now_ns;
        entry.rssi = rssi;
        entry.last_transport = Some(transport);
        entry.state = PeerState::Online;
        Ok(())
    }

    pub async fn mark_verified(&self, id: &IdentityId) {
        let mut peers = self.peers.write().await;
        if let Some(p) = peers.get_mut(id) { p.verified = true; }
    }

    pub async fn block(&self, id: &IdentityId) {
        let mut peers = self.peers.write().await;
        if let Some(p) = peers.get_mut(id) { p.state = PeerState::Blocked; }
    }

    pub async fn unblock(&self, id: &IdentityId) {
        let mut peers = self.peers.write().await;
        if let Some(p) = peers.get_mut(id) {
            if p.state == PeerState::Blocked { p.state = PeerState::Offline; }
        }
    }

    pub async fn get(&self, id: &IdentityId) -> Option<Peer> {
        self.peers.read().await.get(id).cloned()
    }

    pub async fn list(&self) -> Vec<Peer> {
        let peers = self.peers.read().await;
        let mut list: Vec<Peer> = peers.values().cloned().collect();
        list.sort_by(|a, b| b.last_seen_ns.cmp(&a.last_seen_ns));
        list
    }

    pub async fn list_online(&self) -> Vec<Peer> {
        self.list().await.into_iter().filter(|p| p.state == PeerState::Online).collect()
    }

    /// List all known peer IDs (for routing flood — audit fix: was missing).
    pub async fn neighbor_ids(&self) -> Vec<IdentityId> {
        let peers = self.peers.read().await;
        peers.iter()
            .filter(|(_, p)| p.state == PeerState::Online)
            .map(|(k, _)| k.clone())
            .collect()
    }

    pub async fn refresh_states(&self) {
        let mut peers = self.peers.write().await;
        for p in peers.values_mut() {
            if p.state == PeerState::Blocked { continue; }
            let age = p.age();
            p.state = if age > self.offline_threshold { PeerState::Offline }
                      else if age > self.stale_threshold { PeerState::Stale }
                      else { PeerState::Online };
        }
    }

    pub async fn counts(&self) -> (usize, usize, usize, usize) {
        let peers = self.peers.read().await;
        let (mut o, mut s, mut f, mut b) = (0, 0, 0, 0);
        for p in peers.values() {
            match p.state {
                PeerState::Online => o += 1, PeerState::Stale => s += 1,
                PeerState::Offline => f += 1, PeerState::Blocked => b += 1,
            }
        }
        (o, s, f, b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::Identity;

    #[tokio::test]
    async fn observe_respects_blocked() {
        let reg = PeerRegistry::new();
        let alice = Identity::new("Alice").public_view();
        reg.observe(alice.clone(), None, "ble").await.unwrap();
        reg.block(&alice.id).await;
        // Re-observe — should NOT unblock.
        reg.observe(alice.clone(), None, "ble").await.unwrap();
        let p = reg.get(&alice.id).await.unwrap();
        assert_eq!(p.state, PeerState::Blocked, "blocked peer must stay blocked");
    }

    #[tokio::test]
    async fn neighbor_ids_returns_online() {
        let reg = PeerRegistry::new();
        let alice = Identity::new("Alice").public_view();
        reg.observe(alice.clone(), None, "ble").await.unwrap();
        let ids = reg.neighbor_ids().await;
        assert!(ids.contains(&alice.id));
    }
}
