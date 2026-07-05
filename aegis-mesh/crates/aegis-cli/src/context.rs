use anyhow::Result;
use std::path::PathBuf;

pub struct CliContext {
    pub data_dir: PathBuf,
    pub config_path: PathBuf,
    pub identity_path: PathBuf,
    pub db_path: PathBuf,
    pub socket_path: PathBuf,
}

impl CliContext {
    pub fn new(data_dir: PathBuf) -> Result<Self> {
        Ok(Self {
            config_path: data_dir.join("config.toml"),
            identity_path: data_dir.join("identity.enc"),
            db_path: data_dir.join("aegis.db"),
            socket_path: data_dir.join("aegis.sock"),
            data_dir,
        })
    }

    pub fn read_identity_blob(&self) -> Result<Option<Vec<u8>>> {
        if self.identity_path.exists() {
            Ok(Some(std::fs::read(&self.identity_path)?))
        } else {
            Ok(None)
        }
    }

    /// Write identity blob with 0600 perms (audit fix: was default umask).
    pub fn write_identity_blob(&self, blob: &[u8]) -> Result<()> {
        aegis_core::config::secure_write(&self.identity_path, blob)?;
        Ok(())
    }

    pub fn open_store(&self) -> Result<aegis_core::storage::SqliteStore> {
        Ok(aegis_core::storage::SqliteStore::open(&self.db_path)?)
    }

    pub fn prompt_passphrase() -> Result<String> {
        // Allow AEGIS_PASSPHRASE env var for testing / automation.
        if let Ok(p) = std::env::var("AEGIS_PASSPHRASE") {
            return Ok(p);
        }
        Ok(rpassword::prompt_password("Passphrase: ")?)
    }
}
