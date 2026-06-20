// =============================================================================
// api/routes/kv.rs — /v1/secret/* KV v2 API (token-authenticated)
//
// HashiCorp Vault–compatible KV v2 over the token path. The token determines
// the vault (one token = one vault); the URL path is the secret path within it.
//   GET    /v1/secret/data/{*path}        read latest version
//   POST   /v1/secret/data/{*path}        write a new version ({"data": {...}})
//   DELETE /v1/secret/data/{*path}        soft-delete latest version
//   GET    /v1/secret/metadata/{*path}    list paths under a prefix (?list=true)
//
// Auth: X-Vault-Token: ev.<base64url>. The instance must be unsealed. Path and
// IP/subnet ACLs (token + vault) are enforced; every attempt is audited.
// =============================================================================

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Json;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

use crate::api::response::VaultResponse;
use crate::audit::{self, AuditEntry};
use crate::error::AppError;
use crate::state::AppState;
use crate::tokens::{self, TokenAuth};
use crate::secrets;
use crate::vault::acl;

/// Query flags for the metadata endpoint (`?list=true`).
#[derive(Debug, Default, Deserialize)]
pub struct MetadataQuery {
    #[serde(default)]
    pub list: bool,
}

/// KV v2 write body: `{"data": {...}, "options": {"max_reads": N}}`.
#[derive(Debug, Deserialize)]
pub struct WriteBody {
    pub data: serde_json::Value,
    #[serde(default)]
    pub options: Option<WriteOptions>,
}

/// Write options. `max_reads` makes the version single/N-use (burn after read).
#[derive(Debug, Deserialize)]
pub struct WriteOptions {
    pub max_reads: Option<i64>,
}

/// Resolved request context after auth + ACL checks.
struct Ctx {
    auth: TokenAuth,
    ip: String,
    master: Zeroizing<[u8; 32]>,
}

// ─────────────────────────────────────────────────────────────────────────────
// begin
// Resolve the master key + client IP, authenticate the token, and enforce the
// path + token-IP + vault-IP ACLs. Denials are audited and returned as a 403
// (or 503 when sealed). On success returns the token context for the handler.
// ─────────────────────────────────────────────────────────────────────────────
async fn begin(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    peer: SocketAddr,
    path: &str,
    operation: &str,
) -> Result<Ctx, Response> {
    let master = match state.master_key_bytes().await {
        Some(m) => m,
        None => return Err(AppError::Sealed.into_response()),
    };
    let ip = acl::client_ip(peer, headers, &state.config.security.trusted_proxies);
    let ip_str = ip.to_string();

    let Some(raw) = headers
        .get("x-vault-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        record_deny(state, &master, operation, None, path, None, &ip_str).await;
        return Err(AppError::Forbidden.into_response());
    };

    let auth = match tokens::authenticate_token(&state.db, &master, raw).await {
        Ok(a) => a,
        Err(e) => {
            record_deny(state, &master, operation, None, path, None, &ip_str).await;
            return Err(e.into_response());
        }
    };

    // Path + per-token IP/CIDR ACL ("where this token may be used from").
    let allowed = tokens::path_allowed(&auth.allowed_paths, path)
        && acl::ip_allowed(ip, &auth.allowed_ips);
    if !allowed {
        record_deny(state, &master, operation, Some(&auth.vault_id), path, Some(&auth.token_id), &ip_str).await;
        return Err(AppError::Forbidden.into_response());
    }

    Ok(Ctx { auth, ip: ip_str, master })
}

// ─────────────────────────────────────────────────────────────────────────────
// record_deny
// Audit a denied request (403) with whatever token context is known.
// ─────────────────────────────────────────────────────────────────────────────
#[allow(clippy::too_many_arguments)]
async fn record_deny(
    state: &Arc<AppState>,
    master: &[u8; 32],
    operation: &str,
    vault_id: Option<&str>,
    path: &str,
    actor: Option<&str>,
    ip: &str,
) {
    audit::record(
        &state.db,
        master,
        AuditEntry {
            operation,
            vault_id,
            path: Some(path),
            actor_type: "api_token",
            actor_hash: actor,
            source_ip: Some(ip),
            response_code: 403,
        },
    )
    .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// audit_ok
// Record a successful (or not-found) operation against the token context.
// ─────────────────────────────────────────────────────────────────────────────
async fn audit_ok(state: &Arc<AppState>, ctx: &Ctx, operation: &str, path: &str, code: i64) {
    audit::record(
        &state.db,
        &ctx.master,
        AuditEntry {
            operation,
            vault_id: Some(&ctx.auth.vault_id),
            path: Some(path),
            actor_type: "api_token",
            actor_hash: Some(&ctx.auth.token_id),
            source_ip: Some(&ctx.ip),
            response_code: code,
        },
    )
    .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/secret/data/{*path}
// Read and decrypt the latest live version, in KV v2 envelope shape.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn read(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let ctx = match begin(&state, &headers, peer, &path, "READ").await {
        Ok(c) => c,
        Err(resp) => return Ok(resp),
    };
    // Consuming read — single/N-use secrets burn here.
    match secrets::read_and_consume(&state.db, &ctx.auth.vault_id, &path, &ctx.auth.vault_key).await? {
        Some((version, value, remaining)) => {
            audit_ok(&state, &ctx, "READ", &path, 200).await;
            Ok(Json(VaultResponse::new(json!({
                "data": value,
                "metadata": { "version": version, "destroyed": false, "reads_remaining": remaining }
            })))
            .into_response())
        }
        None => {
            audit_ok(&state, &ctx, "READ", &path, 404).await;
            Err(AppError::NotFound)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /v1/secret/data/{*path}
// Write a new version of the secret; returns the new version metadata.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn write(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(path): Path<String>,
    headers: HeaderMap,
    Json(body): Json<WriteBody>,
) -> Result<Response, AppError> {
    let ctx = match begin(&state, &headers, peer, &path, "WRITE").await {
        Ok(c) => c,
        Err(resp) => return Ok(resp),
    };
    let creator = ctx.auth.created_by.as_deref().ok_or_else(|| AppError::Internal("token has no owner".into()))?;
    let max_reads = body.options.and_then(|o| o.max_reads);
    let version = secrets::write(&state.db, &ctx.auth.vault_id, &path, &body.data, &ctx.auth.vault_key, creator, max_reads).await?;
    audit_ok(&state, &ctx, "WRITE", &path, 200).await;
    Ok(Json(VaultResponse::new(json!({ "version": version, "destroyed": false }))).into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// DELETE /v1/secret/data/{*path}
// Soft-delete the latest version (recoverable); 204 on success.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn delete(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let ctx = match begin(&state, &headers, peer, &path, "DELETE").await {
        Ok(c) => c,
        Err(resp) => return Ok(resp),
    };
    secrets::soft_delete(&state.db, &ctx.auth.vault_id, &path).await?;
    audit_ok(&state, &ctx, "DELETE", &path, 204).await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/secret/metadata/{*path}?list=true
// List secret paths under a prefix (Vault directory listing).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn metadata_list(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(path): Path<String>,
    headers: HeaderMap,
    Query(q): Query<MetadataQuery>,
) -> Result<Response, AppError> {
    metadata_list_inner(&state, &headers, peer, &path, q.list).await
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/secret/metadata (root prefix)
// Same as `metadata_list` but for the empty prefix the wildcard cannot capture.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn metadata_list_root(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<MetadataQuery>,
) -> Result<Response, AppError> {
    metadata_list_inner(&state, &headers, peer, "", q.list).await
}

// ─────────────────────────────────────────────────────────────────────────────
// metadata_list_inner
// Shared listing logic for both the prefixed and root metadata routes.
// ─────────────────────────────────────────────────────────────────────────────
async fn metadata_list_inner(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    peer: SocketAddr,
    path: &str,
    list: bool,
) -> Result<Response, AppError> {
    let ctx = match begin(state, headers, peer, path, "LIST").await {
        Ok(c) => c,
        Err(resp) => return Ok(resp),
    };
    if !list {
        return Err(AppError::BadRequest("only ?list=true is supported on metadata".into()));
    }
    let prefix = path.trim_end_matches('/');
    let keys: Vec<String> = secrets::list_paths(&state.db, &ctx.auth.vault_id)
        .await?
        .into_iter()
        .filter(|s| prefix.is_empty() || s.path == prefix || s.path.starts_with(&format!("{prefix}/")))
        .map(|s| s.path)
        .collect();
    audit_ok(state, &ctx, "LIST", path, 200).await;
    Ok(Json(VaultResponse::new(json!({ "keys": keys }))).into_response())
}
