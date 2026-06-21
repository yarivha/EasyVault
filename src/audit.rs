// =============================================================================
// audit.rs — append-only audit log with per-row HMAC tamper detection
//
// Every secret-access operation is recorded with an HMAC-SHA256 over the row's
// canonical fields, keyed by a value derived from the master key. Because the
// key never leaves memory, rows cannot be forged or silently edited at rest.
// Secret values are never logged — only paths, actors, IPs and result codes.
// =============================================================================

use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::AppError;

/// Settings key for the audit-log retention window, in days (0 = keep forever).
const RETENTION_KEY: &str = "audit_retention_days";

type HmacSha256 = Hmac<Sha256>;

/// A single audit event to record (borrowed fields, no secret values).
pub struct AuditEntry<'a> {
    pub operation: &'a str,
    pub vault_id: Option<&'a str>,
    pub path: Option<&'a str>,
    pub actor_type: &'a str,
    pub actor_hash: Option<&'a str>,
    pub source_ip: Option<&'a str>,
    pub response_code: i64,
}

/// An audit row read back for the viewer (incl. its stored HMAC).
#[derive(Debug, sqlx::FromRow)]
pub struct AuditRow {
    pub request_id: String,
    pub timestamp: String,
    pub operation: String,
    pub vault_id: Option<String>,
    pub path: Option<String>,
    pub actor_type: String,
    pub actor_hash: Option<String>,
    pub source_ip: Option<String>,
    pub response_code: Option<i64>,
    pub hmac: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// audit_key
// Derive the audit HMAC key from the master key via a domain-separated SHA-256.
// ─────────────────────────────────────────────────────────────────────────────
fn audit_key(master_key: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"easyvault-audit-hmac-v1");
    h.update(master_key);
    h.finalize().into()
}

// ─────────────────────────────────────────────────────────────────────────────
// canonical
// Build the stable field string that the HMAC is computed over.
// ─────────────────────────────────────────────────────────────────────────────
fn canonical(
    request_id: &str,
    timestamp: &str,
    operation: &str,
    vault_id: Option<&str>,
    path: Option<&str>,
    actor_type: &str,
    actor_hash: Option<&str>,
    source_ip: Option<&str>,
    response_code: i64,
) -> String {
    format!(
        "{request_id}|{timestamp}|{operation}|{}|{}|{actor_type}|{}|{}|{response_code}",
        vault_id.unwrap_or(""),
        path.unwrap_or(""),
        actor_hash.unwrap_or(""),
        source_ip.unwrap_or(""),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// hmac_hex
// Compute the lowercase-hex HMAC-SHA256 of `data` under the audit key.
// ─────────────────────────────────────────────────────────────────────────────
fn hmac_hex(master_key: &[u8; 32], data: &str) -> String {
    let key = audit_key(master_key);
    let mut mac = HmacSha256::new_from_slice(&key).expect("hmac accepts any key length");
    mac.update(data.as_bytes());
    let tag = mac.finalize().into_bytes();
    let mut out = String::with_capacity(tag.len() * 2);
    for b in tag {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// record
// Insert an audit row with its computed HMAC. Best-effort: failures are logged,
// never propagated, so auditing cannot break the audited operation.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn record(db: &sqlx::SqlitePool, master_key: &[u8; 32], entry: AuditEntry<'_>) {
    let request_id = Uuid::new_v4().to_string();
    let timestamp = Utc::now().to_rfc3339();
    let canon = canonical(
        &request_id,
        &timestamp,
        entry.operation,
        entry.vault_id,
        entry.path,
        entry.actor_type,
        entry.actor_hash,
        entry.source_ip,
        entry.response_code,
    );
    let hmac = hmac_hex(master_key, &canon);

    let result = sqlx::query(
        "INSERT INTO audit_log \
         (request_id, timestamp, operation, vault_id, path, actor_type, actor_hash, source_ip, response_code, hmac) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&request_id)
    .bind(&timestamp)
    .bind(entry.operation)
    .bind(entry.vault_id)
    .bind(entry.path)
    .bind(entry.actor_type)
    .bind(entry.actor_hash)
    .bind(entry.source_ip)
    .bind(entry.response_code)
    .bind(&hmac)
    .execute(db)
    .await;
    if let Err(e) = result {
        tracing::warn!(error = %e, "failed to write audit row");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// list
// Most-recent audit rows (newest first), capped at `limit`.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn list(db: &sqlx::SqlitePool, limit: i64) -> Result<Vec<AuditRow>, AppError> {
    let rows = sqlx::query_as::<_, AuditRow>(
        "SELECT request_id, timestamp, operation, vault_id, path, actor_type, actor_hash, \
         source_ip, response_code, hmac FROM audit_log ORDER BY id DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

// ─────────────────────────────────────────────────────────────────────────────
// count
// Total number of rows currently in the audit log.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn count(db: &sqlx::SqlitePool) -> Result<i64, AppError> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM audit_log").fetch_one(db).await?)
}

// ─────────────────────────────────────────────────────────────────────────────
// retention_days / set_retention_days
// Read or set the retention window (days). 0 = keep forever (the default).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn retention_days(db: &sqlx::SqlitePool) -> Result<i64, AppError> {
    let v: Option<String> = sqlx::query_scalar("SELECT value FROM settings WHERE key = ?")
        .bind(RETENTION_KEY)
        .fetch_optional(db)
        .await?;
    Ok(v.and_then(|s| s.parse::<i64>().ok()).unwrap_or(0).max(0))
}

pub async fn set_retention_days(db: &sqlx::SqlitePool, days: i64) -> Result<(), AppError> {
    let days = days.max(0);
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES (?, ?) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(RETENTION_KEY)
    .bind(days.to_string())
    .execute(db)
    .await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// prune
// Delete audit rows older than the configured retention window. No-op when
// retention is 0 (keep forever). Returns how many rows were removed.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn prune(db: &sqlx::SqlitePool) -> Result<u64, AppError> {
    let days = retention_days(db).await?;
    if days <= 0 {
        return Ok(0);
    }
    // Both stored timestamps and this cutoff are RFC3339 (UTC, +00:00), so a
    // lexicographic comparison is chronologically correct.
    let cutoff = (Utc::now() - Duration::days(days)).to_rfc3339();
    let res = sqlx::query("DELETE FROM audit_log WHERE timestamp < ?")
        .bind(cutoff)
        .execute(db)
        .await?;
    let removed = res.rows_affected();
    if removed > 0 {
        tracing::info!(removed, days, "pruned audit log");
    }
    Ok(removed)
}

// ─────────────────────────────────────────────────────────────────────────────
// verify_row
// Recompute a row's HMAC and compare it to the stored value (tamper check).
// ─────────────────────────────────────────────────────────────────────────────
pub fn verify_row(master_key: &[u8; 32], row: &AuditRow) -> bool {
    let canon = canonical(
        &row.request_id,
        &row.timestamp,
        &row.operation,
        row.vault_id.as_deref(),
        row.path.as_deref(),
        &row.actor_type,
        row.actor_hash.as_deref(),
        row.source_ip.as_deref(),
        row.response_code.unwrap_or(0),
    );
    hmac_hex(master_key, &canon) == row.hmac
}
