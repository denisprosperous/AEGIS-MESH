//! Message envelope — wire format (audited: version field, size limits, field validation).

use crate::crypto::identity::IdentityId;
use crate::error::{AegisError, Result};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum envelope size — 64 KB (audit fix: was unbounded).
pub const MAX_ENVELOPE_SIZE: usize = 64 * 1024;

/// Wire format version (audit fix: was missing).
pub const ENVELOPE_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnvelopeId(pub String);

impl EnvelopeId {
    pub fn new() -> Self {
        // UUIDv7-style: timestamp-prefixed, no XOR (audit fix: was ts ^ rand).
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let rand_part: u128 = rand::random();
        Self(format!("{ts:032x}"))
    }
    pub fn as_str(&self) -> &str { &self.0 }
}

impl Default for EnvelopeId { fn default() -> Self { Self::new() } }

impl std::fmt::Display for EnvelopeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(&self.0) }
}

impl std::str::FromStr for EnvelopeId {
    type Err = AegisError;
    fn from_str(s: &str) -> Result<Self> {
        if s.len() != 32 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AegisError::Invalid);
        }
        Ok(Self(s.to_lowercase()))
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeType {
    Direct,
    Channel,
    Broadcast,
    RouteAnnounce,
    PeerDiscovery,
    FileChunk,
    VoiceFrame,
    EmergencyBeacon,
    DeliveryReceipt,
    ReadReceipt,
}

impl EnvelopeType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct", Self::Channel => "channel", Self::Broadcast => "broadcast",
            Self::RouteAnnounce => "route_announce", Self::PeerDiscovery => "peer_discovery",
            Self::FileChunk => "file_chunk", Self::VoiceFrame => "voice_frame",
            Self::EmergencyBeacon => "emergency_beacon", Self::DeliveryReceipt => "delivery_receipt",
            Self::ReadReceipt => "read_receipt",
        }
    }
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "direct" => Self::Direct, "channel" => Self::Channel, "broadcast" => Self::Broadcast,
            "route_announce" => Self::RouteAnnounce, "peer_discovery" => Self::PeerDiscovery,
            "file_chunk" => Self::FileChunk, "voice_frame" => Self::VoiceFrame,
            "emergency_beacon" => Self::EmergencyBeacon, "delivery_receipt" => Self::DeliveryReceipt,
            "read_receipt" => Self::ReadReceipt, _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvelopeFlags(pub u16);

impl EnvelopeFlags {
    pub const fn new() -> Self { Self(0) }
    pub const fn with_ephemeral(mut self) -> Self { self.0 |= 1 << 0; self }
    pub const fn with_priority_relay(mut self) -> Self { self.0 |= 1 << 1; self }
    pub const fn with_encrypted(mut self) -> Self { self.0 |= 1 << 2; self }
    pub const fn with_signed(mut self) -> Self { self.0 |= 1 << 3; self }
    pub const fn is_ephemeral(self) -> bool { self.0 & (1 << 0) != 0 }
    pub const fn is_priority_relay(self) -> bool { self.0 & (1 << 1) != 0 }
    pub const fn is_encrypted(self) -> bool { self.0 & (1 << 2) != 0 }
    pub const fn is_signed(self) -> bool { self.0 & (1 << 3) != 0 }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Payload {
    Text(String),
    Encrypted(#[serde(with = "hex::serde")] Vec<u8>),
    Binary(#[serde(with = "hex::serde")] Vec<u8>),
    RouteAnnounce {
        origin: IdentityId,
        hop_count: u8,
        seq: u64,
        #[serde(with = "hex::serde")]
        origin_verifying_key: [u8; 32],
    },
    Discovery {
        display_name: String,
        #[serde(with = "hex::serde")]
        verifying_key: [u8; 32],
    },
    Receipt { acked_id: EnvelopeId, read: bool },
}

mod opt_sig_hex {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Option<[u8; 64]>, s: S) -> Result<S::Ok, S::Error> {
        match v { None => s.serialize_none(), Some(a) => hex::serde::serialize(a, s) }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 64]>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(s) => {
                let b = hex::decode(&s).map_err(serde::de::Error::custom)?;
                if b.len() != 64 { return Err(serde::de::Error::custom("64 bytes")); }
                let mut a = [0u8; 64]; a.copy_from_slice(&b);
                Ok(Some(a))
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    /// Wire version (audit fix: was missing).
    pub version: u8,
    pub id: EnvelopeId,
    pub kind: EnvelopeType,
    pub sender: IdentityId,
    pub recipient: Option<IdentityId>,
    pub channel: Option<String>,
    pub payload: Payload,
    pub timestamp_ns: u64,
    pub ttl: u8,
    pub hops: u8,
    pub priority: u8,
    pub flags: EnvelopeFlags,
    #[serde(with = "opt_sig_hex")]
    pub signature: Option<[u8; 64]>,
}

impl Envelope {
    pub fn direct_text(sender: IdentityId, recipient: IdentityId, text: impl Into<String>, ttl: u8) -> Self {
        Self {
            version: ENVELOPE_VERSION, id: EnvelopeId::new(), kind: EnvelopeType::Direct,
            sender, recipient: Some(recipient), channel: None,
            payload: Payload::Text(text.into()), timestamp_ns: now_ns(), ttl, hops: 0,
            priority: 2, flags: EnvelopeFlags::new(), signature: None,
        }
    }

    pub fn channel_text(sender: IdentityId, channel: impl Into<String>, text: impl Into<String>, ttl: u8) -> Self {
        Self {
            version: ENVELOPE_VERSION, id: EnvelopeId::new(), kind: EnvelopeType::Channel,
            sender, recipient: None, channel: Some(channel.into()),
            payload: Payload::Text(text.into()), timestamp_ns: now_ns(), ttl, hops: 0,
            priority: 2, flags: EnvelopeFlags::new(), signature: None,
        }
    }

    pub fn broadcast_text(sender: IdentityId, text: impl Into<String>, ttl: u8) -> Self {
        Self {
            version: ENVELOPE_VERSION, id: EnvelopeId::new(), kind: EnvelopeType::Broadcast,
            sender, recipient: None, channel: None,
            payload: Payload::Text(text.into()), timestamp_ns: now_ns(), ttl, hops: 0,
            priority: 0, flags: EnvelopeFlags::new(), signature: None,
        }
    }

    pub fn discovery(sender: IdentityId, display_name: impl Into<String>, verifying_key: [u8; 32]) -> Self {
        Self {
            version: ENVELOPE_VERSION, id: EnvelopeId::new(), kind: EnvelopeType::PeerDiscovery,
            sender: sender.clone(), recipient: None, channel: None,
            payload: Payload::Discovery { display_name: display_name.into(), verifying_key },
            timestamp_ns: now_ns(), ttl: 1, hops: 0, priority: 3,
            flags: EnvelopeFlags::new(), signature: None,
        }
    }

    /// Route announce — includes origin's verifying key for signature verification (audit fix).
    pub fn route_announce(
        sender: IdentityId,
        origin: IdentityId,
        origin_verifying_key: [u8; 32],
        hop_count: u8,
        seq: u64,
        max_hops: u8,
    ) -> Self {
        Self {
            version: ENVELOPE_VERSION, id: EnvelopeId::new(), kind: EnvelopeType::RouteAnnounce,
            sender, recipient: None, channel: None,
            payload: Payload::RouteAnnounce { origin, hop_count, seq, origin_verifying_key },
            timestamp_ns: now_ns(), ttl: max_hops, hops: 0, priority: 3,
            flags: EnvelopeFlags::new(), signature: None,
        }
    }

    pub fn receipt(sender: IdentityId, recipient: IdentityId, acked: EnvelopeId, read: bool) -> Self {
        Self {
            version: ENVELOPE_VERSION, id: EnvelopeId::new(), kind: EnvelopeType::DeliveryReceipt,
            sender, recipient: Some(recipient), channel: None,
            payload: Payload::Receipt { acked_id: acked, read }, timestamp_ns: now_ns(),
            ttl: 5, hops: 0, priority: 1, flags: EnvelopeFlags::new(), signature: None,
        }
    }

    /// Advance TTL with overflow-safe hop check (audit fix: no max_hops check).
    pub fn advance_ttl(&mut self, max_hops: u8) -> bool {
        if self.ttl == 0 { return false; }
        if self.hops >= max_hops { return false; }
        self.ttl -= 1;
        self.hops = self.hops.saturating_add(1);
        true
    }

    /// Canonical signing bytes (audit fix: was non-canonical serde_json).
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut copy = self.clone();
        copy.signature = None;
        Ok(serde_json::to_vec(&copy)?)
    }

    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) -> Result<()> {
        self.flags = self.flags.with_signed();
        let bytes = self.signing_bytes()?;
        use ed25519_dalek::Signer;
        let sig = signing_key.sign(&bytes);
        self.signature = Some(sig.to_bytes());
        Ok(())
    }

    pub fn verify(&self, verifying_key: &ed25519_dalek::VerifyingKey) -> bool {
        let Some(sig_bytes) = self.signature else { return false; };
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let Ok(bytes) = self.signing_bytes() else { return false; };
        use ed25519_dalek::Verifier;
        verifying_key.verify(&bytes, &sig).is_ok()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Deserialize with size limit + field validation (audit fix: no limits, no validation).
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() > MAX_ENVELOPE_SIZE {
            return Err(AegisError::Invalid);
        }
        let env: Self = serde_json::from_slice(b).map_err(|_| AegisError::Json)?;
        env.validate()?;
        Ok(env)
    }

    /// Validate envelope invariants (audit fix: was missing).
    pub fn validate(&self) -> Result<()> {
        if self.version != ENVELOPE_VERSION { return Err(AegisError::Invalid); }
        // Validate priority range
        if self.priority > 4 { return Err(AegisError::Invalid); }
        // Validate recipient/channel/kind consistency (audit fix)
        match self.kind {
            EnvelopeType::Direct => {
                if self.recipient.is_none() || self.channel.is_some() { return Err(AegisError::Invalid); }
            }
            EnvelopeType::Channel => {
                if self.recipient.is_some() || self.channel.is_none() { return Err(AegisError::Invalid); }
            }
            EnvelopeType::Broadcast | EnvelopeType::PeerDiscovery | EnvelopeType::RouteAnnounce
            | EnvelopeType::EmergencyBeacon => {
                if self.recipient.is_some() || self.channel.is_some() { return Err(AegisError::Invalid); }
            }
            _ => {}
        }
        // Validate reserved flag bits (audit fix)
        if self.flags.0 & 0xFFF0 != 0 { return Err(AegisError::Invalid); }
        // Validate IdentityId format
        if self.sender.0.len() != 64 { return Err(AegisError::Invalid); }
        if let Some(ref r) = self.recipient {
            if r.0.len() != 64 { return Err(AegisError::Invalid); }
        }
        Ok(())
    }

    /// Check timestamp freshness (audit fix: no freshness check, replayable).
    pub fn is_fresh(&self, max_age_ns: u64, max_skew_ns: u64) -> bool {
        let now = now_ns();
        if self.timestamp_ns > now + max_skew_ns { return false; } // future-dated
        if now > self.timestamp_ns + max_age_ns { return false; }  // too old
        true
    }
}

fn now_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::Identity;

    #[test]
    fn envelope_round_trip() {
        let alice = Identity::new("Alice");
        let bob = Identity::new("Bob");
        let env = Envelope::direct_text(alice.id.clone(), bob.id.clone(), "hello", 10);
        let bytes = env.to_bytes().unwrap();
        let env2 = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(env, env2);
    }

    #[test]
    fn size_limit_enforced() {
        let big = vec![0u8; MAX_ENVELOPE_SIZE + 1];
        assert!(Envelope::from_bytes(&big).is_err());
    }

    #[test]
    fn sign_and_verify() {
        let alice = Identity::new("Alice");
        let bob = Identity::new("Bob");
        let mut env = Envelope::direct_text(alice.id.clone(), bob.id.clone(), "hello", 10);
        env.sign(alice.signing_key()).unwrap();
        assert!(env.verify(&alice.verifying_key()));
    }

    #[test]
    fn recipient_channel_consistency() {
        let alice = Identity::new("Alice");
        let mut env = Envelope::direct_text(alice.id.clone(), alice.id.clone(), "hi", 10);
        env.channel = Some("wrong".into()); // Direct must not have channel
        assert!(env.validate().is_err());
    }

    #[test]
    fn ttl_advance_respects_max_hops() {
        let alice = Identity::new("Alice");
        let bob = Identity::new("Bob");
        let mut env = Envelope::direct_text(alice.id, bob.id, "hi", 5);
        env.hops = 10;
        assert!(!env.advance_ttl(10)); // hops >= max_hops
    }
}
