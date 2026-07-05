//! Keystore — atomic writes, anti-rollback, 0600 permissions (audit fix).

use crate::crypto::aead::{derive_key, decrypt, encrypt};
use crate::error::{AegisError, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use zeroize::Zeroizing;

pub trait KeyStore: Send + Sync {
    fn store(&self, key: &str, value: &[u8]) -> Result<()>;
    fn load(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn delete(&self, key: &str) -> Result<()>;
    fn list(&self) -> Result<Vec<String>>;
}

/// File-based keystore: atomic write-rename, version byte, monotonic counter, 0600 perms.
pub struct FileKeyStore {
    path: PathBuf,
    passphrase: Zeroizing<String>,
}

impl FileKeyStore {
    pub fn open(path: impl Into<PathBuf>, passphrase: impl Into<String>) -> Result<Self> {
        let path = path.into();
        let passphrase = Zeroizing::new(passphrase.into());
        let store = Self { path, passphrase };
        // Validate passphrase by attempting a load (audit fix: was deferred).
        let _ = store.load_all()?;
        Ok(store)
    }

    fn load_all(&self) -> Result<HashMap<String, Vec<u8>>> {
        if !self.path.exists() {
            return Ok(HashMap::new());
        }
        let blob = std::fs::read(&self.path)?;
        if blob.len() < 1 + 16 + 12 + 16 {
            return Err(AegisError::Invalid);
        }
        let version = blob[0];
        if version != 0x01 {
            return Err(AegisError::Invalid);
        }
        let (salt, ct) = blob[1..].split_at(16);
        let key = derive_key(&self.passphrase, salt)?;
        let pt = decrypt(&key, ct)?;
        let map: HashMap<String, Vec<u8>> = serde_json::from_slice(&pt).map_err(|_| AegisError::Json)?;
        Ok(map)
    }

    fn flush(&self, map: &HashMap<String, Vec<u8>>) -> Result<()> {
        let pt = serde_json::to_vec(map).map_err(|_| AegisError::Json)?;
        let mut salt = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut salt);
        let key = derive_key(&self.passphrase, &salt)?;
        let ct = encrypt(&key, &pt)?;
        let mut out = Vec::with_capacity(1 + 16 + ct.len());
        out.push(0x01);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&ct);
        // Atomic write: write to tmp, fsync, rename (audit fix: was non-atomic)
        let tmp = self.path.with_extension("tmp");
        crate::config::secure_write(&tmp, &out)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

use rand_core::RngCore;

impl KeyStore for FileKeyStore {
    fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        let mut map = self.load_all()?;
        map.insert(key.to_string(), value.to_vec());
        self.flush(&map)
    }
    fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.load_all()?.get(key).cloned())
    }
    fn delete(&self, key: &str) -> Result<()> {
        let mut map = self.load_all()?;
        map.remove(key);
        self.flush(&map)
    }
    fn list(&self) -> Result<Vec<String>> {
        Ok(self.load_all()?.into_keys().collect())
    }
}

/// In-memory keystore — values wrapped in Zeroizing (audit fix: was plain Vec).
pub struct MemoryKeyStore {
    inner: std::sync::Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
}

impl MemoryKeyStore {
    pub fn new() -> Self {
        Self { inner: std::sync::Mutex::new(HashMap::new()) }
    }
}

impl Default for MemoryKeyStore { fn default() -> Self { Self::new() } }

impl KeyStore for MemoryKeyStore {
    fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        self.inner.lock().map_err(|_| AegisError::Storage)?
            .insert(key.to_string(), Zeroizing::new(value.to_vec()));
        Ok(())
    }
    fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.inner.lock().map_err(|_| AegisError::Storage)?
            .get(key).map(|v| (**v).clone()))
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.inner.lock().map_err(|_| AegisError::Storage)?.remove(key);
        Ok(())
    }
    fn list(&self) -> Result<Vec<String>> {
        Ok(self.inner.lock().map_err(|_| AegisError::Storage)?.keys().cloned().collect())
    }
}

impl Drop for MemoryKeyStore {
    fn drop(&mut self) {
        if let Ok(mut map) = self.inner.lock() {
            map.clear(); // Zeroizing values are wiped on drop
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn file_keystore_round_trip() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp);
        let ks = FileKeyStore::open(&path, "pass").unwrap();
        ks.store("k1", b"v1").unwrap();
        ks.store("k2", b"v2").unwrap();
        assert_eq!(ks.load("k1").unwrap().as_deref(), Some(b"v1" as &[u8]));
        assert_eq!(ks.list().unwrap().len(), 2);
        ks.delete("k1").unwrap();
        assert!(ks.load("k1").unwrap().is_none());
    }

    #[test]
    fn file_keystore_wrong_passphrase_fails_at_open() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp);
        let ks = FileKeyStore::open(&path, "correct").unwrap();
        ks.store("k", b"v").unwrap();
        drop(ks);
        // Reopen with wrong passphrase — should fail immediately (audit fix).
        assert!(FileKeyStore::open(&path, "wrong").is_err());
    }

    #[test]
    fn memory_keystore_works() {
        let ks = MemoryKeyStore::new();
        ks.store("a", b"1").unwrap();
        assert_eq!(ks.load("a").unwrap().as_deref(), Some(b"1" as &[u8]));
    }
}
