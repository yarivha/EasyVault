// =============================================================================
// config.rs — TOML configuration loading and the Config data model
//
// Reads config from the path in $EASYVAULT_CONFIG (default ./config.toml).
// All fields have defaults so a missing file still yields a usable config.
// =============================================================================

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Top-level application configuration, mirroring config.toml.example.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub init: InitConfig,
}

/// HTTP listener settings. TLS fields are parsed now but enforced later.
/// Every field defaults individually so a partial `[server]` table is valid.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub address: String,
    pub port: u16,
    pub tls: bool,
    pub tls_cert: String,
    pub tls_key: String,
}

/// Backing store selection. Only sqlite is wired up in this increment.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    #[serde(rename = "type")]
    pub kind: String,
    pub path: String,
    pub url: String,
}

/// GUI session / brute-force / proxy-trust knobs.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    pub session_ttl_hours: u64,
    pub max_login_attempts: u32,
    pub lockout_minutes: u64,
    pub trusted_proxies: Vec<String>,
}

/// Audit log behaviour and optional EasyLog sink.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    pub enabled: bool,
    pub log_raw_values: bool,
    pub easylog_url: String,
}

/// Defaults used by the /v1/sys/init ceremony.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct InitConfig {
    pub default_key_shares: u8,
    pub default_key_threshold: u8,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            address: "0.0.0.0".into(),
            port: 8200,
            tls: false,
            tls_cert: String::new(),
            tls_key: String::new(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            kind: "sqlite".into(),
            path: "easyvault.db".into(),
            url: String::new(),
        }
    }
}

impl StorageConfig {
    // ─────────────────────────────────────────────────────────────────────────
    // StorageConfig::resolved_path
    // Resolve the SQLite path to an absolute, CWD-independent location. Absolute
    // paths are used as-is; relative paths anchor to the EasyVault data dir so
    // the database survives no matter which directory the server is launched in.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn resolved_path(&self) -> PathBuf {
        let p = Path::new(&self.path);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            data_dir().join(p)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// data_dir
// Base directory for EasyVault state (DB, TLS material): $EASYVAULT_HOME, else
// $HOME/.easyvault, else the current directory as a last resort.
// ─────────────────────────────────────────────────────────────────────────────
pub fn data_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("EASYVAULT_HOME") {
        return PathBuf::from(home);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return Path::new(&home).join(".easyvault");
    }
    PathBuf::from(".")
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            session_ttl_hours: 8,
            max_login_attempts: 5,
            lockout_minutes: 15,
            trusted_proxies: vec!["127.0.0.1".into()],
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_raw_values: false,
            easylog_url: String::new(),
        }
    }
}

impl Default for InitConfig {
    fn default() -> Self {
        Self {
            default_key_shares: 5,
            default_key_threshold: 3,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            storage: StorageConfig::default(),
            security: SecurityConfig::default(),
            audit: AuditConfig::default(),
            init: InitConfig::default(),
        }
    }
}

impl Config {
    // ─────────────────────────────────────────────────────────────────────────
    // Config::load
    // Resolve the config path ($EASYVAULT_CONFIG or ./config.toml) and parse it.
    // A missing file is not an error — defaults are returned instead.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn load() -> anyhow::Result<Self> {
        let path = std::env::var("EASYVAULT_CONFIG").unwrap_or_else(|_| "config.toml".into());
        Self::load_from(&path)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Config::load_from
    // Parse a specific TOML file path, falling back to defaults if absent.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn load_from(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            tracing::warn!(?path, "config file not found; using defaults");
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&raw)?;
        Ok(cfg)
    }
}
