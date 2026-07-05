//! X25519 key agreement with low-order point validation (audit fix).

use crate::crypto::aead::{hkdf_derive, KEY_SIZE};
use crate::error::{AegisError, Result};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const X25519_SECRET_SIZE: usize = 32;
pub const X25519_PUBLIC_SIZE: usize = 32;

/// Ephemeral X25519 keypair — consumed by diffie_hellman (one-shot, forward secrecy).
pub struct EphemeralKeypair {
    secret: x25519_dalek::EphemeralSecret,
    public: PublicKey,
}

impl EphemeralKeypair {
    pub fn new() -> Self {
        let secret = x25519_dalek::EphemeralSecret::random_from_rng(&mut OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Derive shared key — consumes self (X25519 ephemeral is one-shot).
    /// Validates against low-order points (audit fix).
    pub fn derive_shared_key(self, peer_public: &[u8; 32], context: &[u8]) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
        let peer = PublicKey::from(*peer_public);
        let shared = self.secret.diffie_hellman(&peer);
        let shared_bytes = shared.to_bytes();
        // Reject all-zero output (low-order point attack)
        if shared_bytes.ct_eq(&[0u8; 32]).into() {
            return Err(AegisError::Crypto);
        }
        let okm = hkdf_derive(&shared_bytes, b"aegis-x25519-v1", context, KEY_SIZE);
        let mut out = Zeroizing::new([0u8; KEY_SIZE]);
        out.copy_from_slice(&okm);
        Ok(out)
    }
}

impl Default for EphemeralKeypair {
    fn default() -> Self { Self::new() }
}

/// Static (reusable) X25519 keypair — for X3DH signed prekeys.
#[derive(Serialize, Deserialize)]
pub struct StaticKeypair {
    #[serde(with = "hex::serde")]
    pub(crate) secret: [u8; 32],
    #[serde(with = "hex::serde")]
    public: [u8; 32],
}

impl StaticKeypair {
    pub fn new() -> Self {
        let secret = StaticSecret::random_from_rng(&mut OsRng);
        let public = PublicKey::from(&secret);
        Self { secret: secret.to_bytes(), public: public.to_bytes() }
    }

    pub fn from_secret_bytes(secret: [u8; 32]) -> Self {
        let s = StaticSecret::from(secret);
        let p = PublicKey::from(&s);
        Self { secret: s.to_bytes(), public: p.to_bytes() }
    }

    pub fn public_bytes(&self) -> [u8; 32] { self.public }
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> { Zeroizing::new(self.secret) }

    /// Derive shared key with low-order point validation.
    pub fn derive_shared_key(&self, peer_public: &[u8; 32], context: &[u8]) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
        let secret = StaticSecret::from(self.secret);
        let peer = PublicKey::from(*peer_public);
        let shared = secret.diffie_hellman(&peer);
        let shared_bytes = shared.to_bytes();
        if shared_bytes.ct_eq(&[0u8; 32]).into() {
            return Err(AegisError::Crypto);
        }
        let okm = hkdf_derive(&shared_bytes, b"aegis-x25519-v1", context, KEY_SIZE);
        let mut out = Zeroizing::new([0u8; KEY_SIZE]);
        out.copy_from_slice(&okm);
        Ok(out)
    }
}

impl Default for StaticKeypair { fn default() -> Self { Self::new() } }

impl std::fmt::Debug for StaticKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticKeypair")
            .field("public", &hex::encode(self.public))
            .finish_non_exhaustive()
    }
}

impl Drop for StaticKeypair {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_key_agreement() {
        let alice = EphemeralKeypair::new();
        let bob = EphemeralKeypair::new();
        let alice_pub = alice.public_bytes();
        let bob_pub = bob.public_bytes();
        let alice_key = alice.derive_shared_key(&bob_pub, b"test").unwrap();
        let bob_key = bob.derive_shared_key(&alice_pub, b"test").unwrap();
        assert_eq!(*alice_key, *bob_key);
    }

    #[test]
    fn static_key_agreement() {
        let alice = StaticKeypair::new();
        let bob = StaticKeypair::new();
        let alice_key = alice.derive_shared_key(&bob.public_bytes(), b"static").unwrap();
        let bob_key = bob.derive_shared_key(&alice.public_bytes(), b"static").unwrap();
        assert_eq!(*alice_key, *bob_key);
    }

    #[test]
    fn different_contexts_differ() {
        let alice = StaticKeypair::new();
        let bob = StaticKeypair::new();
        let k1 = alice.derive_shared_key(&bob.public_bytes(), b"ctx1").unwrap();
        let k2 = alice.derive_shared_key(&bob.public_bytes(), b"ctx2").unwrap();
        assert_ne!(*k1, *k2);
    }
}
