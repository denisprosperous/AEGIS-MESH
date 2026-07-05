//! Configuration — with validation (audit fix: config.rs had zero validation).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub display_name: String,
    pub database_path: PathBuf,
    pub identity_path: PathBuf,
    pub max_hops: u8,
    pub message_retention: Duration,
    pub message_ttl: Duration,
    pub security: SecurityProfile,
    pub transports: TransportsConfig,
    #[serde(default)]
    pub paranoid_default: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SecurityProfile {
    #[default]
    Paranoid,
    Balanced,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TransportsConfig {
    pub ble_advertise_interval_ms: Option<u16>,
    pub ble_scan_window_ms: Option<u16>,
    pub lora_serial_path: Option<PathBuf>,
    pub lora_frequency_mhz: Option<u32>,
    pub enable_loopback: bool,
    pub loopback_socket_path: Option<PathBuf>,
}

impl NodeConfig {
    pub fn default_for(data_dir: PathBuf, display_name: impl Into<String>) -> Self {
        Self {
            display_name: display_name.into(),
            database_path: data_dir.join("aegis.db"),
            identity_path: data_dir.join("identity.enc"),
            max_hops: 10,
            message_retention: Duration::from_secs(60 * 60 * 24 * 7),
            message_ttl: Duration::from_secs(60 * 60 * 24),
            security: SecurityProfile::default(),
            transports: TransportsConfig::default(),
            paranoid_default: true,
        }
    }

    /// Validate config values (audit fix: no validation existed).
    pub fn validate(&self) -> crate::Result<()> {
        if self.display_name.is_empty() || self.display_name.len() > 64 {
            return Err(crate::AegisError::Invalid);
        }
        if self.display_name.chars().any(|c| c.is_control() || c == '\0') {
            return Err(crate::AegisError::Invalid);
        }
        if self.max_hops > 16 {
            return Err(crate::AegisError::Invalid);
        }
        if self.message_retention > Duration::from_secs(60 * 60 * 24 * 30) {
            return Err(crate::AegisError::Invalid);
        }
        Ok(())
    }

    pub fn load_or_default(path: &std::path::Path) -> crate::Result<Self> {
        if path.exists() {
            // Audit fix: cap config file size before reading.
            let meta = std::fs::metadata(path)?;
            if meta.len() > 1024 * 1024 {
                return Err(crate::AegisError::Invalid);
            }
            let s = std::fs::read_to_string(path)?;
            let cfg: Self = toml::from_str(&s).map_err(|_| crate::AegisError::Invalid)?;
            cfg.validate()?;
            Ok(cfg)
        } else {
            let data_dir = path.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
            Ok(Self::default_for(data_dir, "Anonymous"))
        }
    }

    /// Save config with 0600 permissions (audit fix: default umask was 0644).
    pub fn save(&self, path: &std::path::Path) -> crate::Result<()> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let s = toml::to_string_pretty(self).map_err(|_| crate::AegisError::Invalid)?;
        secure_write(path, s.as_bytes())?;
        Ok(())
    }
}

pub fn default_data_dir() -> crate::Result<PathBuf> {
    directories::ProjectDirs::from("network", "aegis", "aegis-mesh")
        .map(|d| d.data_dir().to_path_buf())
        .ok_or(crate::AegisError::Io)
}

/// Write a file with 0600 permissions on Unix (audit fix: world-readable files).
pub fn secure_write(path: &std::path::Path, data: &[u8]) -> crate::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)?;
    }
    Ok(())
}
