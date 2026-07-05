//! Fingerprints — 60-digit safety numbers (audit fix: was 12 digits, brute-forceable).

use crate::error::Result;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// 160-bit fingerprint (PGP-style), displayed as 10 groups of 4 hex chars.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fingerprint(#[serde(with = "hex::serde")] [u8; 20]);

impl Fingerprint {
    pub fn from_public_key(pubkey: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(pubkey);
        let hash = h.finalize();
        let mut out = [0u8; 20];
        out.copy_from_slice(&hash[..20]);
        Self(out)
    }

    pub fn from_verifying_key(vk: &VerifyingKey) -> Self {
        Self::from_public_key(&vk.to_bytes())
    }

    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }

    pub fn as_bytes(&self) -> &[u8; 20] { &self.0 }

    pub fn to_hex(&self) -> String {
        hex::encode_upper(self.0)
    }

    pub fn to_display(&self) -> String {
        let h = self.to_hex();
        let mut out = String::with_capacity(49);
        for (i, c) in h.chars().enumerate() {
            if i > 0 && i % 4 == 0 { out.push(' '); }
            out.push(c);
        }
        out
    }

    /// 60-digit safety number (Signal-style, ~2^199 entropy).
    /// Two parties compute the same number from each other's fingerprints.
    pub fn safety_number(&self, other: &Self) -> String {
        let mut h = Sha256::new();
        let (a, b) = if self.0 <= other.0 {
            (self.0, other.0)
        } else {
            (other.0, self.0)
        };
        h.update(a);
        h.update(b);
        let hash1 = h.finalize();

        let mut h2 = Sha256::new();
        h2.update(&hash1);
        h2.update(a);
        h2.update(b);
        let hash2 = h2.finalize();

        // 30 digits from each half = 60 total
        let n1 = u128::from_be_bytes(hash1[..16].try_into().unwrap()) % 1_000_000_000_000_000_000_000_000_000_000u128;
        let n2 = u128::from_be_bytes(hash2[..16].try_into().unwrap()) % 1_000_000_000_000_000_000_000_000_000_000u128;
        format!("{n1:030}{n2:030}")
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        let bytes = hex::decode(&cleaned)?;
        if bytes.len() != 20 { return Err(crate::AegisError::Invalid); }
        let mut out = [0u8; 20];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }
}

/// Use ct_eq for PartialEq (audit fix: derived PartialEq leaked timing).
impl PartialEq for Fingerprint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}
impl Eq for Fingerprint {}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_format() {
        let fp = Fingerprint::from_public_key(b"test key");
        let display = fp.to_display();
        let groups: Vec<&str> = display.split(' ').collect();
        assert_eq!(groups.len(), 10);
        for g in &groups { assert_eq!(g.len(), 4); }
    }

    #[test]
    fn safety_number_is_60_digits() {
        let a = Fingerprint::from_public_key(b"alice");
        let b = Fingerprint::from_public_key(b"bob");
        let n = a.safety_number(&b);
        assert_eq!(n.len(), 60);
        assert!(n.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn safety_number_symmetric() {
        let a = Fingerprint::from_public_key(b"alice");
        let b = Fingerprint::from_public_key(b"bob");
        assert_eq!(a.safety_number(&b), b.safety_number(&a));
    }

    #[test]
    fn partial_eq_is_constant_time() {
        let a = Fingerprint::from_public_key(b"key1");
        let b = Fingerprint::from_public_key(b"key1");
        let c = Fingerprint::from_public_key(b"key2");
        assert!(a == b);
        assert!(a != c);
    }
}
