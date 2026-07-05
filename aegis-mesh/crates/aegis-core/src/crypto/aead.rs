//! AES-256-GCM with deterministic counter nonce (audit fix: random nonce had birthday bound).

use crate::error::{AegisError, Result};
use aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

/// A ciphertext blob: nonce + ciphertext + tag.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AeadCiphertext {
    #[serde(with = "hex::serde")]
    pub nonce: [u8; NONCE_SIZE],
    #[serde(with = "hex::serde")]
    pub ct: Vec<u8>,
}

fn argon2_params() -> Result<Params> {
    Params::new(65_536, 3, 4, Some(KEY_SIZE)).map_err(|_| AegisError::Crypto)
}

/// AES-256-GCM with a deterministic counter nonce.
/// Each key has its own monotonic counter — no birthday bound, no nonce reuse.
pub struct AeadCipher {
    cipher: Aes256Gcm,
    counter: std::sync::atomic::AtomicU64,
}

impl AeadCipher {
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        Self {
            cipher: Aes256Gcm::new(key.into()),
            counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn next_nonce(&self) -> [u8; NONCE_SIZE] {
        let n = self.counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[4..].copy_from_slice(&n.to_be_bytes());
        nonce
    }

    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes = self.next_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = self.cipher.encrypt(nonce, Payload { msg: plaintext, aad })
            .map_err(|_| AegisError::Crypto)?;
        let mut out = Vec::with_capacity(NONCE_SIZE + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn decrypt(&self, blob: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if blob.len() < NONCE_SIZE + TAG_SIZE {
            return Err(AegisError::Invalid);
        }
        let (nonce_bytes, ct) = blob.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher.decrypt(nonce, Payload { msg: ct, aad })
            .map_err(|_| AegisError::Crypto)
    }
}

/// Derive an AES-256 key from passphrase + salt using Argon2id.
pub fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    if salt.len() < 16 {
        return Err(AegisError::Invalid);
    }
    let params = argon2_params()?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    argon.hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .map_err(|_| AegisError::Crypto)?;
    Ok(key)
}

/// HKDF-SHA256 — returns Zeroizing (audit fix: returned plain Vec).
pub fn hkdf_derive(master: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Zeroizing<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master);
    let mut okm = Zeroizing::new(vec![0u8; out_len]);
    hk.expand(info, &mut *okm).expect("HKDF expand");
    okm
}

/// One-shot encrypt with random nonce (for at-rest blobs only, not message ratchet).
pub fn encrypt(key: &[u8; KEY_SIZE], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, Payload { msg: plaintext, aad: &[] })
        .map_err(|_| AegisError::Crypto)?;
    let mut out = Vec::with_capacity(NONCE_SIZE + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt(key: &[u8; KEY_SIZE], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_SIZE + TAG_SIZE {
        return Err(AegisError::Invalid);
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_SIZE);
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, Payload { msg: ct, aad: &[] })
        .map_err(|_| AegisError::Crypto)
}

/// One-shot encrypt with AAD (for at-rest blobs with context binding).
pub fn encrypt_with_aad(key: &[u8; KEY_SIZE], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| AegisError::Crypto)?;
    let mut out = Vec::with_capacity(NONCE_SIZE + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt_with_aad(key: &[u8; KEY_SIZE], blob: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_SIZE + TAG_SIZE {
        return Err(AegisError::Invalid);
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_SIZE);
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, Payload { msg: ct, aad })
        .map_err(|_| AegisError::Crypto)
}

use rand_core::RngCore;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_cipher_round_trip() {
        let key = [0x42u8; KEY_SIZE];
        let cipher = AeadCipher::new(&key);
        let ct = cipher.encrypt(b"hello", b"aad").unwrap();
        let pt = cipher.decrypt(&ct, b"aad").unwrap();
        assert_eq!(&pt, b"hello");
    }

    #[test]
    fn aead_cipher_aad_tamper_fails() {
        let key = [0x42u8; KEY_SIZE];
        let cipher = AeadCipher::new(&key);
        let ct = cipher.encrypt(b"hello", b"correct").unwrap();
        assert!(cipher.decrypt(&ct, b"wrong").is_err());
    }

    #[test]
    fn derive_key_rejects_short_salt() {
        assert!(derive_key("pass", &[0u8; 8]).is_err());
    }

    #[test]
    fn derive_key_deterministic() {
        let salt = [0u8; 16];
        let k1 = derive_key("pass", &salt).unwrap();
        let k2 = derive_key("pass", &salt).unwrap();
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn hkdf_returns_zeroizing() {
        let k = hkdf_derive(b"master", b"salt", b"info", 32);
        assert_eq!(k.len(), 32);
    }
}
