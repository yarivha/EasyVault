// =============================================================================
// vault/mod.rs — vault lifecycle, per-vault roles, and key distribution
//
// Each vault has one random vault_key. It is escrowed under the master key
// (AES-GCM(vault_key, master_key)) so the unsealed server can re-wrap it for
// users that the blind master assigns. Per-user it is wrapped under an
// ephemeral X25519 ECDH secret (crypto Flows 3–5), stamped with a role.
//
// Roles (per vault): viewer (read) < editor (read+write+tokens) < admin
// (+assign users). The global master holds NO vault key and cannot read.
// =============================================================================

use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, aes, ecdh};
use crate::error::AppError;

pub mod acl;

/// A user's role within a single vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Viewer,
    Editor,
    Admin,
}

impl Role {
    /// Parse a stored role string; unknown values are rejected.
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "viewer" => Some(Role::Viewer),
            "editor" => Some(Role::Editor),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }
    /// Canonical lowercase storage/display string.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Editor => "editor",
            Role::Admin => "admin",
        }
    }
    /// May read secret values (any role).
    pub fn can_read(self) -> bool {
        true
    }
    /// May create/update secrets and create tokens (editor and admin).
    pub fn can_write(self) -> bool {
        matches!(self, Role::Editor | Role::Admin)
    }
    /// May assign users to the vault (admin only).
    pub fn can_assign(self) -> bool {
        matches!(self, Role::Admin)
    }
}

/// A vault row (metadata only — keys live escrowed/wrapped, never plaintext).
#[derive(Debug, sqlx::FromRow)]
pub struct VaultRow {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub locked: bool,
    pub created_by: Option<String>,
}

/// Summary of a vault for list views.
#[derive(Debug, sqlx::FromRow)]
pub struct VaultSummary {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}

/// A member of a vault: user + their role + grant time.
#[derive(Debug, sqlx::FromRow)]
pub struct VaultMember {
    pub user_id: String,
    pub username: String,
    pub role: String,
    pub granted_at: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// create_vault — crypto Flow 3, escrow variant
// Generate a vault_key, store it sealed under the master key, and persist the
// vault. The blind master gets NO membership row — an admin must be assigned.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn create_vault(
    db: &sqlx::SqlitePool,
    name: &str,
    description: &str,
    creator_id: &str,
    master_key: &[u8; 32],
) -> Result<String, AppError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest("vault name is required".into()));
    }
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM vaults WHERE name = ?")
        .bind(name)
        .fetch_optional(db)
        .await?;
    if exists.is_some() {
        return Err(AppError::BadRequest("a vault with that name already exists".into()));
    }

    let vault_key = Zeroizing::new(crypto::random_key());
    let (nonce, enc) = aes::encrypt(master_key, vault_key.as_ref())
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let vault_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO vaults (id, name, description, created_by, vault_key_enc_master, vault_key_nonce_master) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&vault_id)
    .bind(name)
    .bind(if description.trim().is_empty() { None } else { Some(description.trim()) })
    .bind(creator_id)
    .bind(enc)
    .bind(nonce.to_vec())
    .execute(db)
    .await?;

    tracing::info!(%name, vault_id = %vault_id, "vault created (master-escrowed)");
    Ok(vault_id)
}

// ─────────────────────────────────────────────────────────────────────────────
// list_all
// Every vault, for the master's blind management view.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn list_all(db: &sqlx::SqlitePool) -> Result<Vec<VaultSummary>, AppError> {
    let rows = sqlx::query_as::<_, VaultSummary>(
        "SELECT id, name, description FROM vaults ORDER BY name",
    )
    .fetch_all(db)
    .await?;
    Ok(rows)
}

// ─────────────────────────────────────────────────────────────────────────────
// list_for_user
// Vaults the given user has a wrapped key for, ordered by name.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn list_for_user(db: &sqlx::SqlitePool, user_id: &str) -> Result<Vec<VaultSummary>, AppError> {
    let rows = sqlx::query_as::<_, VaultSummary>(
        "SELECT v.id, v.name, v.description FROM vaults v \
         JOIN vault_user_keys k ON k.vault_id = v.id \
         WHERE k.user_id = ? ORDER BY v.name",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

// ─────────────────────────────────────────────────────────────────────────────
// get
// Fetch a vault's metadata by id.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn get(db: &sqlx::SqlitePool, vault_id: &str) -> Result<Option<VaultRow>, AppError> {
    let row = sqlx::query_as::<_, VaultRow>(
        "SELECT id, name, description, locked, created_by FROM vaults WHERE id = ?",
    )
    .bind(vault_id)
    .fetch_optional(db)
    .await?;
    Ok(row)
}

// ─────────────────────────────────────────────────────────────────────────────
// get_user_role
// The caller's role within a vault, or None if they are not a member.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn get_user_role(db: &sqlx::SqlitePool, vault_id: &str, user_id: &str) -> Result<Option<Role>, AppError> {
    let role: Option<String> =
        sqlx::query_scalar("SELECT role FROM vault_user_keys WHERE vault_id = ? AND user_id = ?")
            .bind(vault_id)
            .bind(user_id)
            .fetch_optional(db)
            .await?;
    Ok(role.and_then(|r| Role::parse(&r)))
}

// ─────────────────────────────────────────────────────────────────────────────
// members
// List users with access to a vault, with their roles.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn members(db: &sqlx::SqlitePool, vault_id: &str) -> Result<Vec<VaultMember>, AppError> {
    let rows = sqlx::query_as::<_, VaultMember>(
        "SELECT k.user_id, u.username, k.role, k.granted_at FROM vault_user_keys k \
         JOIN users u ON u.id = k.user_id WHERE k.vault_id = ? ORDER BY u.username",
    )
    .bind(vault_id)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

// ─────────────────────────────────────────────────────────────────────────────
// resolve_vault_key — crypto Flow 5 (member access)
// Recover the vault_key for a member by re-deriving their ECDH shared secret
// from the stored (ephemeral) granter public key and decrypting their copy.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn resolve_vault_key(
    db: &sqlx::SqlitePool,
    vault_id: &str,
    user_id: &str,
    user_private: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, AppError> {
    let row = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, Vec<u8>)>(
        "SELECT vault_key_enc, vault_key_nonce, granter_public_key \
         FROM vault_user_keys WHERE vault_id = ? AND user_id = ?",
    )
    .bind(vault_id)
    .bind(user_id)
    .fetch_optional(db)
    .await?
    .ok_or(AppError::Forbidden)?;

    let (vk_enc, nonce_vec, granter_public) = row;
    if nonce_vec.len() != crypto::NONCE_LEN || granter_public.len() != 32 {
        return Err(AppError::Internal("corrupt vault key material".into()));
    }
    let mut nonce = [0u8; crypto::NONCE_LEN];
    nonce.copy_from_slice(&nonce_vec);
    let mut granter = [0u8; 32];
    granter.copy_from_slice(&granter_public);

    let shared = ecdh::shared_secret(user_private, &granter);
    unwrap_key(&shared, &nonce, &vk_enc)
}

// ─────────────────────────────────────────────────────────────────────────────
// resolve_vault_key_via_master
// Recover a vault_key from its master-key escrow (server-side, when unsealed).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn resolve_vault_key_via_master(
    db: &sqlx::SqlitePool,
    vault_id: &str,
    master_key: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, AppError> {
    let row = sqlx::query_as::<_, (Option<Vec<u8>>, Option<Vec<u8>>)>(
        "SELECT vault_key_enc_master, vault_key_nonce_master FROM vaults WHERE id = ?",
    )
    .bind(vault_id)
    .fetch_optional(db)
    .await?
    .ok_or(AppError::NotFound)?;

    let (Some(enc), Some(nonce_vec)) = row else {
        return Err(AppError::Internal("vault has no master escrow".into()));
    };
    if nonce_vec.len() != crypto::NONCE_LEN {
        return Err(AppError::Internal("corrupt escrow nonce".into()));
    }
    let mut nonce = [0u8; crypto::NONCE_LEN];
    nonce.copy_from_slice(&nonce_vec);
    unwrap_key(master_key, &nonce, &enc)
}

// ─────────────────────────────────────────────────────────────────────────────
// assign
// Server-side assignment: recover the vault_key via master escrow, wrap it for
// `target_username` using a fresh ephemeral X25519 keypair, and upsert the
// membership with `role`. Used by both the master and vault admins.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn assign(
    db: &sqlx::SqlitePool,
    vault_id: &str,
    master_key: &[u8; 32],
    target_username: &str,
    role: Role,
    granted_by: &str,
) -> Result<(), AppError> {
    let target = crate::users::get_by_username(db, target_username.trim())
        .await?
        .ok_or_else(|| AppError::BadRequest("no such user".into()))?;
    if target.is_master {
        return Err(AppError::BadRequest("the master user cannot be a vault member".into()));
    }

    // If already a member, just change the role (key wrapping stays valid).
    let existing = get_user_role(db, vault_id, &target.id).await?;
    if existing.is_some() {
        sqlx::query("UPDATE vault_user_keys SET role = ? WHERE vault_id = ? AND user_id = ?")
            .bind(role.as_str())
            .bind(vault_id)
            .bind(&target.id)
            .execute(db)
            .await?;
        tracing::info!(%vault_id, user = %target.username, role = role.as_str(), "vault role updated");
        return Ok(());
    }

    let vault_key = resolve_vault_key_via_master(db, vault_id, master_key).await?;
    let mut target_public = [0u8; 32];
    if target.public_key.len() != 32 {
        return Err(AppError::Internal("corrupt target public key".into()));
    }
    target_public.copy_from_slice(&target.public_key);

    // Ephemeral-ECDH wrap: store the ephemeral public as granter_public_key;
    // the target recovers via ECDH(target_private, ephemeral_public) — Flow 5.
    let ephemeral = ecdh::generate_keypair();
    let shared = ecdh::shared_secret(&ephemeral.private, &target_public);
    let (nonce, vk_enc) = aes::encrypt(&shared, vault_key.as_ref())
        .map_err(|e| AppError::Internal(e.to_string()))?;

    sqlx::query(
        "INSERT INTO vault_user_keys \
         (vault_id, user_id, vault_key_enc, vault_key_nonce, granter_public_key, role, granted_by) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(vault_id)
    .bind(&target.id)
    .bind(vk_enc)
    .bind(nonce.to_vec())
    .bind(ephemeral.public.to_vec())
    .bind(role.as_str())
    .bind(granted_by)
    .execute(db)
    .await?;

    tracing::info!(%vault_id, user = %target.username, role = role.as_str(), "vault access assigned");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// get_acl
// Read a vault's network ACL as a combined list of IP/CIDR entries.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn get_acl(db: &sqlx::SqlitePool, vault_id: &str) -> Result<Vec<String>, AppError> {
    let row = sqlx::query_as::<_, (String, String)>(
        "SELECT acl_ips, acl_subnets FROM vaults WHERE id = ?",
    )
    .bind(vault_id)
    .fetch_optional(db)
    .await?
    .unwrap_or_else(|| ("[]".into(), "[]".into()));
    let mut entries: Vec<String> = serde_json::from_str(&row.0).unwrap_or_default();
    let subnets: Vec<String> = serde_json::from_str(&row.1).unwrap_or_default();
    entries.extend(subnets);
    Ok(entries)
}

// ─────────────────────────────────────────────────────────────────────────────
// set_acl
// Replace a vault's network ACL from a flat list of IP/CIDR entries, splitting
// bare IPs into acl_ips and CIDRs into acl_subnets.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn set_acl(db: &sqlx::SqlitePool, vault_id: &str, entries: &[String]) -> Result<(), AppError> {
    let mut ips = Vec::new();
    let mut subnets = Vec::new();
    for e in entries {
        let e = e.trim();
        if e.is_empty() {
            continue;
        }
        if e.contains('/') {
            if e.parse::<ipnet::IpNet>().is_err() {
                return Err(AppError::BadRequest(format!("invalid CIDR: {e}")));
            }
            subnets.push(e.to_string());
        } else {
            if e.parse::<std::net::IpAddr>().is_err() {
                return Err(AppError::BadRequest(format!("invalid IP: {e}")));
            }
            ips.push(e.to_string());
        }
    }
    sqlx::query("UPDATE vaults SET acl_ips = ?, acl_subnets = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
        .bind(serde_json::to_string(&ips).unwrap_or_else(|_| "[]".into()))
        .bind(serde_json::to_string(&subnets).unwrap_or_else(|_| "[]".into()))
        .bind(vault_id)
        .execute(db)
        .await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// revoke — crypto Flow 9 (Revoke + Key Rotation)
// Remove the user's wrapped key, then rotate the vault key so any secret
// material the revoked user already saw can no longer decrypt future reads.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn revoke(db: &sqlx::SqlitePool, vault_id: &str, user_id: &str, master_key: &[u8; 32]) -> Result<(), AppError> {
    sqlx::query("DELETE FROM vault_user_keys WHERE vault_id = ? AND user_id = ?")
        .bind(vault_id)
        .bind(user_id)
        .execute(db)
        .await?;
    rotate_vault(db, vault_id, master_key).await?;
    tracing::info!(%vault_id, %user_id, "vault access revoked + key rotated");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// rotate_vault — crypto Flow 9 (Key Rotation)
// Generate a new vault_key, re-encrypt every secret version, and re-wrap the
// key everywhere it lives: master escrow, each remaining member (ephemeral
// ECDH), and each live token (under its token_key). Done in one transaction.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn rotate_vault(db: &sqlx::SqlitePool, vault_id: &str, master_key: &[u8; 32]) -> Result<(), AppError> {
    let old_key = resolve_vault_key_via_master(db, vault_id, master_key).await?;
    let new_key = Zeroizing::new(crypto::random_key());

    let mut tx = db.begin().await?;

    // 1. Re-encrypt every stored secret version with the new vault key.
    let secret_rows = sqlx::query_as::<_, (String, Vec<u8>, Vec<u8>)>(
        "SELECT id, value_enc, value_nonce FROM secrets WHERE vault_id = ?",
    )
    .bind(vault_id)
    .fetch_all(&mut *tx)
    .await?;
    for (id, enc, nonce_vec) in secret_rows {
        let plain = decrypt_blob(&old_key, &nonce_vec, &enc)?;
        let (nonce, new_enc) = aes::encrypt(&new_key, &plain).map_err(|e| AppError::Internal(e.to_string()))?;
        sqlx::query("UPDATE secrets SET value_enc = ?, value_nonce = ? WHERE id = ?")
            .bind(new_enc)
            .bind(nonce.to_vec())
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }

    // 2. Re-wrap the master escrow.
    let (esc_nonce, esc_enc) = aes::encrypt(master_key, new_key.as_ref()).map_err(|e| AppError::Internal(e.to_string()))?;
    sqlx::query("UPDATE vaults SET vault_key_enc_master = ?, vault_key_nonce_master = ? WHERE id = ?")
        .bind(esc_enc)
        .bind(esc_nonce.to_vec())
        .bind(vault_id)
        .execute(&mut *tx)
        .await?;

    // 3. Re-wrap each remaining member via a fresh ephemeral ECDH.
    let member_rows = sqlx::query_as::<_, (String, Vec<u8>)>(
        "SELECT k.user_id, u.public_key FROM vault_user_keys k \
         JOIN users u ON u.id = k.user_id WHERE k.vault_id = ?",
    )
    .bind(vault_id)
    .fetch_all(&mut *tx)
    .await?;
    for (uid, public) in member_rows {
        let mut target = [0u8; 32];
        if public.len() != 32 {
            return Err(AppError::Internal("corrupt member public key".into()));
        }
        target.copy_from_slice(&public);
        let ephemeral = ecdh::generate_keypair();
        let shared = ecdh::shared_secret(&ephemeral.private, &target);
        let (nonce, enc) = aes::encrypt(&shared, new_key.as_ref()).map_err(|e| AppError::Internal(e.to_string()))?;
        sqlx::query(
            "UPDATE vault_user_keys SET vault_key_enc = ?, vault_key_nonce = ?, \
             granter_public_key = ?, key_version = key_version + 1 WHERE vault_id = ? AND user_id = ?",
        )
        .bind(enc)
        .bind(nonce.to_vec())
        .bind(ephemeral.public.to_vec())
        .bind(vault_id)
        .bind(uid)
        .execute(&mut *tx)
        .await?;
    }

    // 4. Re-wrap the vault key for each live token (under its token_key).
    let token_rows = sqlx::query_as::<_, (String, Vec<u8>, Vec<u8>)>(
        "SELECT id, token_key_enc, token_key_nonce FROM api_tokens WHERE vault_id = ? AND revoked = 0",
    )
    .bind(vault_id)
    .fetch_all(&mut *tx)
    .await?;
    for (id, tk_enc, tk_nonce) in token_rows {
        let token_key = decrypt_blob(master_key, &tk_nonce, &tk_enc)?;
        let mut tk = [0u8; 32];
        if token_key.len() != 32 {
            return Err(AppError::Internal("corrupt token key".into()));
        }
        tk.copy_from_slice(&token_key);
        let (nonce, enc) = aes::encrypt(&tk, new_key.as_ref()).map_err(|e| AppError::Internal(e.to_string()))?;
        sqlx::query("UPDATE api_tokens SET vault_key_enc = ?, vault_key_nonce = ? WHERE id = ?")
            .bind(enc)
            .bind(nonce.to_vec())
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;
    tracing::info!(%vault_id, "vault key rotated");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// decrypt_blob
// Decrypt a (nonce, ciphertext) blob with `key`, returning a zeroizing buffer.
// ─────────────────────────────────────────────────────────────────────────────
fn decrypt_blob(key: &[u8; 32], nonce_vec: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, AppError> {
    if nonce_vec.len() != crypto::NONCE_LEN {
        return Err(AppError::Internal("corrupt nonce".into()));
    }
    let mut nonce = [0u8; crypto::NONCE_LEN];
    nonce.copy_from_slice(nonce_vec);
    let plain = aes::decrypt(key, &nonce, ciphertext).map_err(|_| AppError::Internal("rotation decrypt failed".into()))?;
    Ok(Zeroizing::new(plain))
}

// ─────────────────────────────────────────────────────────────────────────────
// unwrap_key
// Decrypt a wrapped 32-byte key with `key`+`nonce`, returning a zeroizing copy.
// ─────────────────────────────────────────────────────────────────────────────
fn unwrap_key(key: &[u8; 32], nonce: &[u8; crypto::NONCE_LEN], ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>, AppError> {
    let mut plain = aes::decrypt(key, nonce, ciphertext)
        .map_err(|_| AppError::Internal("failed to unwrap vault key".into()))?;
    if plain.len() != 32 {
        plain.zeroize();
        return Err(AppError::Internal("corrupt vault key".into()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&plain);
    plain.zeroize();
    Ok(Zeroizing::new(out))
}
