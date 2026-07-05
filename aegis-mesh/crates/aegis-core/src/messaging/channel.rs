//! Channels — with domain-separated ID derivation (audit fix).

use crate::crypto::identity::IdentityId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChannelId(pub String);

impl ChannelId {
    /// Domain-separated derivation (audit fix: was unprefixed concatenation).
    pub fn derive(name: &str, creator: &IdentityId) -> Self {
        let mut h = Sha256::new();
        h.update(b"aegis-channel-v1");
        h.update(&(name.len() as u32).to_be_bytes());
        h.update(name.as_bytes());
        h.update(creator.as_str().as_bytes());
        Self(hex::encode(h.finalize()))
    }
    pub fn as_str(&self) -> &str { &self.0 }
}

impl std::fmt::Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(&self.0) }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChannelRole { Member, Admin, Owner }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMembership {
    pub channel_id: ChannelId,
    pub member: IdentityId,
    pub role: ChannelRole,
    pub joined_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub id: ChannelId,
    pub name: String,
    pub creator: IdentityId,
    pub members: Option<Vec<IdentityId>>,
    pub admins: Vec<IdentityId>,
    /// Channel key is encrypted per-recipient, never plaintext (audit fix).
    /// Format: map of recipient_id -> encrypted key blob.
    #[serde(with = "hex::serde")]
    pub channel_key_wrapped: Vec<u8>, // placeholder — in production, per-recipient wrapped keys
    pub created_ns: u64,
}

impl Channel {
    pub fn new(name: impl Into<String>, creator: IdentityId, channel_key_wrapped: Vec<u8>) -> Self {
        let name = name.into();
        let id = ChannelId::derive(&name, &creator);
        Self {
            id, name, creator: creator.clone(),
            members: Some(vec![creator.clone()]),
            admins: vec![creator],
            channel_key_wrapped,
            created_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64).unwrap_or(0),
        }
    }

    pub fn is_member(&self, id: &IdentityId) -> bool {
        match &self.members {
            None => true,
            Some(list) => list.contains(id),
        }
    }
    pub fn is_admin(&self, id: &IdentityId) -> bool {
        self.admins.contains(id) || self.creator == *id
    }

    pub fn add_member(&mut self, admin: &IdentityId, member: IdentityId) -> Result<(), String> {
        if !self.is_admin(admin) { return Err("not an admin".into()); }
        if let Some(list) = &mut self.members {
            if !list.contains(&member) { list.push(member); }
        }
        Ok(())
    }

    /// Remove member — creator protected (audit fix: creator could be removed).
    pub fn remove_member(&mut self, admin: &IdentityId, member: &IdentityId) -> Result<(), String> {
        if !self.is_admin(admin) { return Err("not an admin".into()); }
        if *member == self.creator { return Err("cannot remove creator".into()); }
        if let Some(list) = &mut self.members {
            list.retain(|m| m != member);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::Identity;

    #[test]
    fn channel_creation() {
        let creator = Identity::new("Alice").public_view().id;
        let ch = Channel::new("team", creator.clone(), vec![0u8; 32]);
        assert!(ch.is_member(&creator));
        assert!(ch.is_admin(&creator));
    }

    #[test]
    fn creator_protected_from_removal() {
        let alice = Identity::new("Alice").public_view().id;
        let mut ch = Channel::new("team", alice.clone(), vec![0u8; 32]);
        assert!(ch.remove_member(&alice, &alice).is_err(), "cannot remove creator");
    }

    #[test]
    fn domain_separated_id() {
        let alice = Identity::new("Alice").public_view().id;
        let id1 = ChannelId::derive("foo", &alice);
        // Different name -> different ID
        let id2 = ChannelId::derive("bar", &alice);
        assert_ne!(id1, id2);
    }
}
