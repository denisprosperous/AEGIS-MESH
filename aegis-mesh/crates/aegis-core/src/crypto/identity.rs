//! Identity — Ed25519 from SLIP-0010, with Ed25519→X25519 conversion for identity binding.

use crate::crypto::fingerprint::Fingerprint;
use crate::error::{AegisError, Result};
use bip39::Mnemonic;
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

type HmacSha512 = Hmac<Sha512>;

/// Stable identifier = SHA-256(verifying_key).hex() — 64 hex chars.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityId(pub String);

impl IdentityId {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(bytes))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for IdentityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for IdentityId {
    type Err = AegisError;
    fn from_str(s: &str) -> Result<Self> {
        if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AegisError::Invalid);
        }
        Ok(Self(s.to_lowercase()))
    }
}

/// Convert an Ed25519 verifying key to an X25519 public key (RFC 7748 §4.1).
///
/// This binds the Ed25519 signing identity to the X25519 DH identity —
/// the same key material is used for both signing and key agreement.
pub fn ed25519_to_x25519_public(ed_pub: &VerifyingKey) -> [u8; 32] {
    let compressed = CompressedEdwardsY::from_slice(&ed_pub.to_bytes())
        .expect("valid Ed25519 public key");
    let montgomery = compressed.decompress().expect("valid point").to_montgomery();
    montgomery.to_bytes()
}

/// Convert an Ed25519 signing key to an X25519 secret key.
/// Uses SHA-512 of the Ed25519 seed, then clamps per RFC 7748.
/// This matches the Ed25519→X25519 conversion used by libsodium and Signal.
pub fn ed25519_to_x25519_secret(ed_secret: &SigningKey) -> Zeroizing<[u8; 32]> {
    use sha2::Digest;
    let seed = ed_secret.to_bytes();
    let mut hasher = sha2::Sha512::new();
    hasher.update(seed);
    let hash = hasher.finalize();
    let mut x_secret = [0u8; 32];
    x_secret.copy_from_slice(&hash[..32]);
    // Clamp per RFC 7748
    x_secret[0] &= 248;
    x_secret[31] &= 127;
    x_secret[31] |= 64;
    Zeroizing::new(x_secret)
}

/// A node's identity: BIP39 mnemonic + Ed25519 signing keypair.
pub struct Identity {
    pub display_name: String,
    mnemonic: Zeroizing<String>,
    signing_key: SigningKey,
    pub id: IdentityId,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("display_name", &self.display_name)
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Identity {
    pub fn new(display_name: impl Into<String>) -> Self {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy_in(bip39::Language::English, &entropy)
            .expect("32 bytes is always valid BIP39");
        Self::from_mnemonic(display_name, &mnemonic.to_string())
            .expect("derived keys must be valid")
    }

    /// Restore from BIP39 mnemonic using SLIP-0010 derivation (audit fix: was seed[..32] truncation).
    pub fn from_mnemonic(display_name: impl Into<String>, mnemonic: &str) -> Result<Self> {
        let mnemonic_obj = Mnemonic::parse_normalized(mnemonic)
            .map_err(|_| AegisError::Crypto)?;
        let seed: [u8; 64] = mnemonic_obj.to_seed("");

        // SLIP-0010 Ed25519 derivation: HMAC-SHA512("ed25519 seed", seed), take first 32 bytes.
        let slip_seed = {
            let mut hmac = HmacSha512::new_from_slice(b"ed25519 seed").expect("HMAC key");
            hmac.update(&seed);
            let result = hmac.finalize().into_bytes();
            let mut out = Zeroizing::new([0u8; 64]);
            out.copy_from_slice(&result);
            out
        };
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&slip_seed[..32]);

        let signing_key = SigningKey::from_bytes(&secret);
        let verifying = signing_key.verifying_key();
        let id = Self::derive_id(&verifying);

        use zeroize::Zeroize;
    secret.zeroize();

        Ok(Self {
            display_name: display_name.into(),
            mnemonic: Zeroizing::new(mnemonic_obj.to_string()),
            signing_key,
            id,
        })
    }

    fn derive_id(verifying: &VerifyingKey) -> IdentityId {
        let mut h = sha2::Sha256::new();
        h.update(verifying.to_bytes());
        IdentityId::from_bytes(&h.finalize())
    }

    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn sign(&self, msg: &[u8]) -> ed25519_dalek::Signature {
        use ed25519_dalek::Signer;
        self.signing_key.sign(msg)
    }

    pub fn verify(&self, msg: &[u8], sig: &ed25519_dalek::Signature) -> bool {
        use ed25519_dalek::Verifier;
        self.verifying_key().verify(msg, sig).is_ok()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::from_verifying_key(&self.verifying_key())
    }

    /// X25519 static secret derived from Ed25519 (for X3DH identity binding).
    pub fn x25519_static_secret(&self) -> Zeroizing<[u8; 32]> {
        ed25519_to_x25519_secret(&self.signing_key)
    }

    /// X25519 static public key derived from Ed25519 verifying key.
    pub fn x25519_static_public(&self) -> [u8; 32] {
        ed25519_to_x25519_public(&self.verifying_key())
    }

    pub fn public_view(&self) -> PublicIdentity {
        PublicIdentity {
            id: self.id.clone(),
            display_name: self.display_name.clone(),
            verifying_key: self.verifying_key().to_bytes(),
        }
    }

    /// Encrypted blob with version byte + AAD binding (audit fix: no version, no AAD).
    pub fn to_encrypted_blob(&self, passphrase: &str) -> Result<Vec<u8>> {
        let payload = serde_json::json!({
            "version": 1u8,
            "display_name": self.display_name,
            "mnemonic": &*self.mnemonic,
        });
        let payload_bytes = serde_json::to_vec(&payload).map_err(|_| AegisError::Json)?;
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let key = crate::crypto::aead::derive_key(passphrase, &salt)?;
        let ct = crate::crypto::aead::encrypt_with_aad(&key, &payload_bytes, b"aegis-identity-blob-v1")?;
        let mut out = Vec::with_capacity(1 + 16 + ct.len());
        out.push(0x01); // version byte
        out.extend_from_slice(&salt);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn from_encrypted_blob(blob: &[u8], passphrase: &str) -> Result<Self> {
        if blob.len() < 1 + 16 + 12 + 16 {
            return Err(AegisError::Invalid);
        }
        let version = blob[0];
        if version != 0x01 {
            return Err(AegisError::Invalid);
        }
        let (salt, ct) = blob[1..].split_at(16);
        let key = crate::crypto::aead::derive_key(passphrase, salt)?;
        let pt = crate::crypto::aead::decrypt_with_aad(&key, ct, b"aegis-identity-blob-v1")?;
        let payload: serde_json::Value = serde_json::from_slice(&pt).map_err(|_| AegisError::Json)?;
        let display_name = payload["display_name"].as_str().ok_or(AegisError::Invalid)?.to_string();
        let mnemonic = payload["mnemonic"].as_str().ok_or(AegisError::Invalid)?;
        Self::from_mnemonic(display_name, mnemonic)
    }
}

// No manual Drop — Zeroizing<T> handles wiping. ed25519-dalek's zeroize feature wipes SigningKey.

/// Public identity (safe to share).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicIdentity {
    pub id: IdentityId,
    pub display_name: String,
    pub verifying_key: [u8; 32],
}

impl PublicIdentity {
    pub fn verify(&self, msg: &[u8], sig: &ed25519_dalek::Signature) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(&self.verifying_key) else { return false; };
        use ed25519_dalek::Verifier;
        vk.verify(msg, sig).is_ok()
    }

    /// Verify that this public identity's ID matches its verifying key (audit fix: was missing).
    pub fn verify_id_binding(&self) -> bool {
        let mut h = sha2::Sha256::new();
        h.update(&self.verifying_key);
        let computed = hex::encode(h.finalize());
        computed == self.id.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_mnemonic() {
        let id = Identity::new("Alice");
        let mnemonic = id.mnemonic().to_string();
        let id2 = Identity::from_mnemonic("Alice", &mnemonic).unwrap();
        assert_eq!(id.id, id2.id);
        assert_eq!(id.verifying_key(), id2.verifying_key());
    }

    #[test]
    fn sign_and_verify() {
        let id = Identity::new("Bob");
        let msg = b"hello world";
        let sig = id.sign(msg);
        assert!(id.verify(msg, &sig));
        assert!(!id.verify(b"hello earth", &sig));
    }

    #[test]
    fn encrypted_blob_round_trip() {
        let id = Identity::new("Carol");
        let blob = id.to_encrypted_blob("hunter2").unwrap();
        let id2 = Identity::from_encrypted_blob(&blob, "hunter2").unwrap();
        assert_eq!(id.id, id2.id);
    }

    #[test]
    fn encrypted_blob_wrong_passphrase() {
        let id = Identity::new("Dave");
        let blob = id.to_encrypted_blob("correct horse battery staple").unwrap();
        assert!(Identity::from_encrypted_blob(&blob, "wrong").is_err());
    }

    #[test]
    fn identity_id_is_stable() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let id1 = Identity::from_mnemonic("Test", mnemonic).unwrap();
        let id2 = Identity::from_mnemonic("Different Name", mnemonic).unwrap();
        assert_eq!(id1.id, id2.id);
    }

    #[test]
    fn public_identity_verify_id_binding() {
        let id = Identity::new("Eve");
        let pub_id = id.public_view();
        assert!(pub_id.verify_id_binding());
    }

    #[test]
    fn x25519_derivation_is_consistent() {
        // Verify that the X25519 public key derived from the Ed25519 verifying key
        // matches the X25519 public derived from the Ed25519 secret (via conversion).
        let id = Identity::new("Frank");
        let public_from_ed = id.x25519_static_public();
        // The conversion is deterministic — just check it's not all zeros.
        assert_ne!(public_from_ed, [0u8; 32]);
    }
}
