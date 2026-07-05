//! Cryptographic primitives for AEGIS-MESH v0.2 (audited).
//!
//! - Identity: Ed25519 from SLIP-0010 derivation of BIP39 seed
//! - Key agreement: X25519 with Ed25519→X25519 conversion for identity binding
//! - Symmetric: AES-256-GCM with deterministic counter nonce
//! - Forward secrecy: full Double Ratchet (KDF-chain + DH ratchet)
//! - Fingerprints: 60-digit safety numbers (~2^199 entropy)
//! - All secrets wrapped in Zeroizing<T>

pub mod aead;
pub mod fingerprint;
pub mod identity;
pub mod keystore;
pub mod signal;
pub mod x25519;

pub use aead::{decrypt, encrypt, AeadCiphertext, AeadCipher};
pub use fingerprint::Fingerprint;
pub use identity::{Identity, IdentityId};
pub use keystore::KeyStore;
pub use signal::{Session, SessionState, X3DHBundle, X3DHInitialMessage};
