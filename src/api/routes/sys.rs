// =============================================================================
// api/routes/sys.rs — /v1/sys/* system endpoints
//
// Implements the init / unseal lifecycle and status probes:
//   POST /v1/sys/init          — one-time master-key generation + Shamir split
//   POST /v1/sys/unseal        — submit shares to reconstruct the master key
//   GET  /v1/sys/seal-status   — initialized / sealed / share progress
//   GET  /v1/sys/health        — Vault-style health probe with status codes
//
// These endpoints are intentionally exempt from token auth.
// =============================================================================

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::crypto::{self, aes, shamir};
use crate::error::AppError;
use crate::state::{AppState, MasterKey};

/// Constant sealed under the master key at init; decrypting it back out at
/// unseal proves the reconstructed key is correct.
const UNSEAL_VERIFICATION: &[u8] = b"easyvault-unseal-verification-v1";

/// Snapshot of the system_init row relevant to sealing.
struct InitRow {
    initialized: bool,
    sealed: bool,
    master_key_enc: Option<Vec<u8>>,
    master_key_nonce: Option<Vec<u8>>,
    key_shares: Option<i64>,
    key_threshold: Option<i64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// load_init_row
// Read the single system_init row, returning a "never initialized" default
// when the row is absent.
// ─────────────────────────────────────────────────────────────────────────────
async fn load_init_row(db: &sqlx::SqlitePool) -> Result<InitRow, AppError> {
    let row = sqlx::query_as::<_, (bool, bool, Option<Vec<u8>>, Option<Vec<u8>>, Option<i64>, Option<i64>)>(
        "SELECT initialized, sealed, master_key_enc, master_key_nonce, key_shares, key_threshold \
         FROM system_init WHERE id = 1",
    )
    .fetch_optional(db)
    .await?;

    Ok(match row {
        Some((initialized, sealed, enc, nonce, shares, threshold)) => InitRow {
            initialized,
            sealed,
            master_key_enc: enc,
            master_key_nonce: nonce,
            key_shares: shares,
            key_threshold: threshold,
        },
        None => InitRow {
            initialized: false,
            sealed: true,
            master_key_enc: None,
            master_key_nonce: None,
            key_shares: None,
            key_threshold: None,
        },
    })
}

/// Request body for POST /v1/sys/init (all fields optional → config defaults).
#[derive(Debug, Default, Deserialize)]
pub struct InitRequest {
    pub secret_shares: Option<u8>,
    pub secret_threshold: Option<u8>,
}

/// Response body for POST /v1/sys/init — the shares are shown exactly once.
#[derive(Debug, Serialize)]
pub struct InitResponse {
    pub keys: Vec<String>,
    pub keys_base64: Vec<String>,
    pub shares: u8,
    pub threshold: u8,
}

/// Public snapshot of seal state, for the GUI and status handlers.
pub struct SealView {
    pub initialized: bool,
    pub sealed: bool,
    pub threshold: i64,
    pub shares: i64,
    pub progress: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// seal_view
// Current initialization / seal / unseal-progress snapshot.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn seal_view(state: &Arc<AppState>) -> Result<SealView, AppError> {
    let row = load_init_row(&state.db).await?;
    Ok(SealView {
        initialized: row.initialized,
        sealed: state.is_sealed().await,
        threshold: row.key_threshold.unwrap_or(0),
        shares: row.key_shares.unwrap_or(0),
        progress: state.unseal_progress.read().await.len(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// perform_init
// Core init: generate the master key, seal the verification constant, Shamir-
// split, persist. Returns the base64 shares (shown once). Shared by API + GUI.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn perform_init(state: &Arc<AppState>, shares: u8, threshold: u8) -> Result<Vec<String>, AppError> {
    if load_init_row(&state.db).await?.initialized {
        return Err(AppError::BadRequest("EasyVault is already initialized".into()));
    }
    if threshold == 0 || shares == 0 || threshold > shares {
        return Err(AppError::BadRequest("secret_threshold must be between 1 and secret_shares".into()));
    }

    let master = crypto::random_key();
    let (nonce, enc) = aes::encrypt(&master, UNSEAL_VERIFICATION).map_err(|e| AppError::Internal(e.to_string()))?;
    let share_bytes = shamir::split(&master, shares, threshold);
    let keys_base64: Vec<String> = share_bytes.iter().map(|s| B64.encode(s)).collect();

    sqlx::query(
        "INSERT INTO system_init (id, initialized, sealed, master_key_enc, master_key_nonce, key_shares, key_threshold) \
         VALUES (1, 1, 1, ?, ?, ?, ?)",
    )
    .bind(&enc)
    .bind(nonce.to_vec())
    .bind(shares as i64)
    .bind(threshold as i64)
    .execute(&state.db)
    .await?;

    tracing::info!(shares, threshold, "EasyVault initialized");
    Ok(keys_base64)
}

// ─────────────────────────────────────────────────────────────────────────────
// add_unseal_share
// Core unseal step: record one base64 share and, once the threshold is reached,
// reconstruct + verify the master key and mark the instance unsealed. Shared by
// API + GUI. No-op (Ok) when already unsealed.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn add_unseal_share(state: &Arc<AppState>, key_b64: &str) -> Result<(), AppError> {
    let row = load_init_row(&state.db).await?;
    if !row.initialized {
        return Err(AppError::Uninitialized);
    }
    if !state.is_sealed().await {
        return Ok(());
    }

    let share = B64
        .decode(key_b64.trim())
        .map_err(|_| AppError::BadRequest("share is not valid base64".into()))?;
    let threshold = row.key_threshold.unwrap_or(0) as usize;

    let collected = {
        let mut progress = state.unseal_progress.write().await;
        progress.push(share);
        progress.clone()
    };
    if collected.len() < threshold {
        return Ok(());
    }

    let recovered = match shamir::combine(threshold as u8, &collected) {
        Ok(r) if r.len() == crypto::KEY_LEN => r,
        _ => {
            state.unseal_progress.write().await.clear();
            return Err(AppError::BadRequest("unseal failed: invalid shares".into()));
        }
    };
    let mut master = [0u8; crypto::KEY_LEN];
    master.copy_from_slice(&recovered);

    let enc = row.master_key_enc.ok_or_else(|| AppError::Internal("missing verification ciphertext".into()))?;
    let nonce_vec = row.master_key_nonce.ok_or_else(|| AppError::Internal("missing verification nonce".into()))?;
    if nonce_vec.len() != crypto::NONCE_LEN {
        return Err(AppError::Internal("corrupt verification nonce".into()));
    }
    let mut nonce = [0u8; crypto::NONCE_LEN];
    nonce.copy_from_slice(&nonce_vec);

    match aes::decrypt(&master, &nonce, &enc) {
        Ok(plain) if plain == UNSEAL_VERIFICATION => {
            *state.master_key.write().await = Some(MasterKey::new(master));
            state.unseal_progress.write().await.clear();
            sqlx::query("UPDATE system_init SET sealed = 0 WHERE id = 1")
                .execute(&state.db)
                .await?;
            tracing::info!("EasyVault unsealed");
            Ok(())
        }
        _ => {
            state.unseal_progress.write().await.clear();
            Err(AppError::BadRequest("unseal failed: shares did not reconstruct the master key".into()))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// perform_seal
// Drop the master key from memory and mark the instance sealed — an immediate
// lockdown that blocks all secret operations until it is unsealed again.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn perform_seal(state: &Arc<AppState>) -> Result<(), AppError> {
    *state.master_key.write().await = None;
    state.unseal_progress.write().await.clear();
    sqlx::query("UPDATE system_init SET sealed = 1 WHERE id = 1")
        .execute(&state.db)
        .await?;
    tracing::warn!("EasyVault sealed");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /v1/sys/init
// Generate the master key, split it into Shamir shares, and store the
// verification ciphertext. Returns the shares once; instance stays sealed.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn init(
    State(state): State<Arc<AppState>>,
    body: Option<Json<InitRequest>>,
) -> Result<Json<InitResponse>, AppError> {
    let req = body.map(|Json(b)| b).unwrap_or_default();
    let shares = req.secret_shares.unwrap_or(state.config.init.default_key_shares);
    let threshold = req.secret_threshold.unwrap_or(state.config.init.default_key_threshold);
    let keys = perform_init(&state, shares, threshold).await?;
    Ok(Json(InitResponse {
        keys: keys.clone(),
        keys_base64: keys,
        shares,
        threshold,
    }))
}

/// Request body for POST /v1/sys/unseal.
#[derive(Debug, Default, Deserialize)]
pub struct UnsealRequest {
    /// A single base64-encoded Shamir share.
    pub key: Option<String>,
    /// When true, discard any accumulated shares and report status.
    #[serde(default)]
    pub reset: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /v1/sys/unseal
// Accumulate submitted shares; once the threshold is reached, reconstruct and
// verify the master key, then hold it in memory and mark the instance unsealed.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn unseal(
    State(state): State<Arc<AppState>>,
    body: Option<Json<UnsealRequest>>,
) -> Result<Response, AppError> {
    let req = body.map(|Json(b)| b).unwrap_or_default();

    let row = load_init_row(&state.db).await?;
    if !row.initialized {
        return Err(AppError::Uninitialized);
    }

    // Reset clears progress without touching the seal state.
    if req.reset {
        state.unseal_progress.write().await.clear();
        return Ok(seal_status_json(&state, &row).await.into_response());
    }

    // Already unsealed — nothing to do.
    if !state.is_sealed().await {
        return Ok(seal_status_json(&state, &row).await.into_response());
    }

    let key_b64 = req
        .key
        .ok_or_else(|| AppError::BadRequest("missing 'key' share".into()))?;
    add_unseal_share(&state, &key_b64).await?;

    let fresh = load_init_row(&state.db).await?;
    Ok(seal_status_json(&state, &fresh).await.into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/sys/seal-status
// Report initialization, seal state, share counts and unseal progress.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn seal_status(State(state): State<Arc<AppState>>) -> Result<Json<serde_json::Value>, AppError> {
    let row = load_init_row(&state.db).await?;
    Ok(seal_status_json(&state, &row).await)
}

// ─────────────────────────────────────────────────────────────────────────────
// seal_status_json
// Build the shared seal-status JSON body from current state + the init row.
// ─────────────────────────────────────────────────────────────────────────────
async fn seal_status_json(state: &Arc<AppState>, row: &InitRow) -> Json<serde_json::Value> {
    let sealed = state.is_sealed().await;
    let progress = state.unseal_progress.read().await.len();
    Json(json!({
        "type": "shamir",
        "initialized": row.initialized,
        "sealed": sealed,
        "t": row.key_threshold.unwrap_or(0),
        "n": row.key_shares.unwrap_or(0),
        "progress": progress,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/sys/health
// Vault-style health probe: 200 active, 503 sealed, 501 not initialized.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn health(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    let row = load_init_row(&state.db).await?;
    let sealed = state.is_sealed().await;

    let code = if !row.initialized {
        StatusCode::NOT_IMPLEMENTED // 501: not initialized
    } else if sealed {
        StatusCode::SERVICE_UNAVAILABLE // 503: sealed
    } else {
        StatusCode::OK
    };

    let body = Json(json!({
        "initialized": row.initialized,
        "sealed": sealed,
        "version": env!("CARGO_PKG_VERSION"),
    }));
    Ok((code, body).into_response())
}
