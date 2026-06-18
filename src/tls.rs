// =============================================================================
// tls.rs — TLS certificate material (configured or auto self-signed)
//
// When TLS is enabled, EasyVault uses the cert/key from config if both are set,
// otherwise it loads a self-signed pair from the data dir, generating it on
// first run. Self-signed certs cover localhost + 127.0.0.1 and are meant for
// development / behind a trusting reverse proxy — supply real certs in prod.
// =============================================================================

use std::fs;
use std::path::PathBuf;

use crate::config::{self, Config};

/// PEM-encoded certificate chain + private key.
pub struct TlsPem {
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// load_or_generate
// Resolve TLS material: explicit config paths if given, else a persisted
// self-signed pair under <data_dir>/tls (generated on first run).
// ─────────────────────────────────────────────────────────────────────────────
pub fn load_or_generate(cfg: &Config) -> anyhow::Result<TlsPem> {
    if !cfg.server.tls_cert.is_empty() && !cfg.server.tls_key.is_empty() {
        return Ok(TlsPem {
            cert: fs::read(&cfg.server.tls_cert)?,
            key: fs::read(&cfg.server.tls_key)?,
        });
    }

    let dir: PathBuf = config::data_dir().join("tls");
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");

    if cert_path.exists() && key_path.exists() {
        tracing::info!(path = %cert_path.display(), "using existing self-signed certificate");
        return Ok(TlsPem {
            cert: fs::read(&cert_path)?,
            key: fs::read(&key_path)?,
        });
    }

    // First run: generate and persist a self-signed certificate.
    let sans = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let certified = rcgen::generate_simple_self_signed(sans)?;
    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();

    fs::create_dir_all(&dir)?;
    fs::write(&cert_path, &cert_pem)?;
    fs::write(&key_path, &key_pem)?;
    restrict(&key_path);
    tracing::warn!(path = %cert_path.display(), "generated self-signed certificate (localhost, 127.0.0.1)");

    Ok(TlsPem {
        cert: cert_pem.into_bytes(),
        key: key_pem.into_bytes(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// restrict
// Best-effort tighten the private-key file to owner-only read/write (Unix).
// ─────────────────────────────────────────────────────────────────────────────
fn restrict(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}
