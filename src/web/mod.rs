// =============================================================================
// web/mod.rs — management GUI routes (/gui/*)
//
// Server-rendered, cookie-session HTML for first-run setup, login/logout and
// the dashboard. Auth state is resolved per-request from the ev_session cookie;
// a dedicated middleware layer is introduced in a later increment.
// =============================================================================

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{ConnectInfo, Form, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use chrono::{Duration, Utc};
use serde::Deserialize;
use zeroize::Zeroize;

use crate::api::routes::sys;
use crate::audit::AuditEntry;
use crate::auth::session::{self, SessionIdentity, SessionKeys};
use crate::error::AppError;
use crate::state::AppState;
use crate::vault::{Role, acl};
use crate::{audit, secrets, tokens, users, vault};

// ─────────────────────────────────────────────────────────────────────────────
// audit_gui
// Best-effort audit of a GUI (session) operation. No-op while sealed (the audit
// HMAC key is derived from the master key, which isn't in memory then).
// ─────────────────────────────────────────────────────────────────────────────
#[allow(clippy::too_many_arguments)]
async fn audit_gui(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    peer: SocketAddr,
    operation: &str,
    vault_id: Option<&str>,
    path: Option<&str>,
    user_id: &str,
    code: i64,
) {
    let Some(master) = state.master_key_bytes().await else { return };
    let ip = acl::client_ip(peer, headers, &state.config.security.trusted_proxies).to_string();
    audit::record(
        &state.db,
        &master,
        AuditEntry {
            operation,
            vault_id,
            path,
            actor_type: "gui_session",
            actor_hash: Some(user_id),
            source_ip: Some(&ip),
            response_code: code,
        },
    )
    .await;
}

pub mod pages;

// ─────────────────────────────────────────────────────────────────────────────
// guard! — request preconditions for GUI handlers
//   auth:     resolve the session or redirect to /gui/login (yields SessionKeys)
//   unsealed: render a notice and return if the instance is sealed
//   master:   render a forbidden notice and return if the user is not master
// Each arm may early-`return` from the enclosing handler.
// ─────────────────────────────────────────────────────────────────────────────
macro_rules! guard {
    (auth $state:ident $headers:ident) => {
        match session_keys(&$state, &$headers).await {
            Some(k) => k,
            None => return Ok(Redirect::to("/gui/login").into_response()),
        }
    };
    (unsealed $state:ident, $keys:expr) => {
        if $state.is_sealed().await {
            return Ok(Html(pages::notice_page(
                Some(($keys).username.as_str()),
                "Instance sealed",
                "Unseal EasyVault via /v1/sys/unseal before accessing vaults and secrets.",
            ))
            .into_response());
        }
    };
    (master $keys:expr) => {
        if !($keys).is_master {
            return Ok((
                StatusCode::FORBIDDEN,
                Html(pages::notice_page(
                    Some(($keys).username.as_str()),
                    "Access denied",
                    "Only the master user can perform this action.",
                )),
            )
                .into_response());
        }
    };
}

/// Credentials submitted by the setup and login forms.
#[derive(Debug, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// routes
// The /gui/* router, returned without state so the caller attaches it once.
// ─────────────────────────────────────────────────────────────────────────────
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/gui", get(gui_root))
        .route("/gui/", get(gui_root))
        .route("/gui/unseal", get(unseal_form).post(unseal_submit))
        .route("/gui/unseal/init", post(unseal_init))
        .route("/gui/setup", get(setup_form).post(setup_submit))
        .route("/gui/login", get(login_form).post(login_submit))
        .route("/gui/logout", post(logout))
        .route("/gui/users", get(users_list).post(users_create))
        .route("/gui/audit", get(audit_view))
        .route("/gui/seal", post(seal_instance))
        .route("/gui/vaults/new", get(vault_new_form))
        .route("/gui/vaults", post(vault_create))
        .route("/gui/vaults/{id}", get(vault_detail))
        .route("/gui/vaults/{id}/assign", post(vault_assign))
        .route("/gui/vaults/{id}/revoke", post(vault_revoke))
        .route("/gui/vaults/{id}/acl", post(vault_acl_set))
        .route("/gui/vaults/{id}/rotate", post(vault_rotate))
        .route("/gui/vaults/{id}/secret", get(secret_view).post(secret_write))
        .route("/gui/vaults/{id}/secret/new", get(secret_new_form))
        .route("/gui/vaults/{id}/secret/delete", post(secret_delete))
        .route("/gui/vaults/{id}/tokens", get(tokens_list).post(tokens_create))
        .route("/gui/vaults/{id}/tokens/{tid}/revoke", post(tokens_revoke))
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /gui/ (and /gui)
// First-run → setup; unauthenticated → login; otherwise render the dashboard.
// ─────────────────────────────────────────────────────────────────────────────
async fn gui_root(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, AppError> {
    // Uninitialized or sealed instances are steered to the unseal flow first.
    let seal = sys::seal_view(&state).await?;
    if !seal.initialized || seal.sealed {
        return Ok(Redirect::to("/gui/unseal").into_response());
    }
    if users::count_users(&state.db).await? == 0 {
        return Ok(Redirect::to("/gui/setup").into_response());
    }
    let Some(id) = current_identity(&state, &headers).await else {
        return Ok(Redirect::to("/gui/login").into_response());
    };

    let sealed = state.is_sealed().await;
    // Master manages every vault (but is blind to contents); others see only theirs.
    let rows = if id.is_master {
        vault::list_all(&state.db).await?
    } else {
        vault::list_for_user(&state.db, &id.user_id).await?
    };
    let vaults: Vec<pages::VaultListItem> = rows
        .into_iter()
        .map(|v| pages::VaultListItem { id: v.id, name: v.name, description: v.description })
        .collect();
    Ok(Html(pages::dashboard_page(&id.username, id.is_master, sealed, &vaults)).into_response())
}

/// Initialize form fields (share / threshold counts).
#[derive(Debug, Deserialize)]
pub struct InitForm {
    #[serde(default)]
    pub shares: String,
    #[serde(default)]
    pub threshold: String,
}

/// Single unseal-share submission.
#[derive(Debug, Deserialize)]
pub struct ShareForm {
    pub key: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /gui/unseal
// Show the initialize form (uninitialized), the unseal form (sealed), or
// redirect to the app when already unsealed. Public (pre-auth).
// ─────────────────────────────────────────────────────────────────────────────
async fn unseal_form(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    let v = sys::seal_view(&state).await?;
    if !v.initialized {
        return Ok(Html(pages::unseal_init_page(None)).into_response());
    }
    if !v.sealed {
        return Ok(Redirect::to("/gui/").into_response());
    }
    Ok(Html(pages::unseal_page(v.progress, v.threshold, None)).into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /gui/unseal/init
// Initialize the instance and display the generated shares once.
// ─────────────────────────────────────────────────────────────────────────────
async fn unseal_init(
    State(state): State<Arc<AppState>>,
    Form(form): Form<InitForm>,
) -> Result<Response, AppError> {
    if sys::seal_view(&state).await?.initialized {
        return Ok(Redirect::to("/gui/unseal").into_response());
    }
    let shares = form.shares.trim().parse::<u8>().unwrap_or(state.config.init.default_key_shares);
    let threshold = form.threshold.trim().parse::<u8>().unwrap_or(state.config.init.default_key_threshold);
    match sys::perform_init(&state, shares, threshold).await {
        Ok(keys) => Ok(Html(pages::unseal_shares_page(&keys, threshold as usize)).into_response()),
        Err(AppError::BadRequest(msg)) => {
            Ok((StatusCode::BAD_REQUEST, Html(pages::unseal_init_page(Some(&msg)))).into_response())
        }
        Err(e) => Err(e),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /gui/unseal
// Submit one unseal share; redirect to the app once unsealed.
// ─────────────────────────────────────────────────────────────────────────────
async fn unseal_submit(
    State(state): State<Arc<AppState>>,
    Form(form): Form<ShareForm>,
) -> Result<Response, AppError> {
    let v = sys::seal_view(&state).await?;
    if !v.initialized {
        return Ok(Redirect::to("/gui/unseal").into_response());
    }
    if !v.sealed {
        return Ok(Redirect::to("/gui/").into_response());
    }
    match sys::add_unseal_share(&state, &form.key).await {
        Ok(()) => {
            let after = sys::seal_view(&state).await?;
            if after.sealed {
                Ok(Html(pages::unseal_page(after.progress, after.threshold, None)).into_response())
            } else {
                Ok(Redirect::to("/gui/").into_response())
            }
        }
        Err(AppError::BadRequest(msg)) => {
            let after = sys::seal_view(&state).await?;
            Ok((StatusCode::BAD_REQUEST, Html(pages::unseal_page(after.progress, after.threshold, Some(&msg)))).into_response())
        }
        Err(e) => Err(e),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /gui/setup
// Render the first-run master-account form; redirect to login if users exist.
// ─────────────────────────────────────────────────────────────────────────────
async fn setup_form(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    if users::count_users(&state.db).await? > 0 {
        return Ok(Redirect::to("/gui/login").into_response());
    }
    Ok(Html(pages::setup_page(None)).into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /gui/setup
// Create the master user (only when none exist), then auto-login.
// ─────────────────────────────────────────────────────────────────────────────
async fn setup_submit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<Credentials>,
) -> Result<Response, AppError> {
    if users::count_users(&state.db).await? > 0 {
        return Ok(Redirect::to("/gui/login").into_response());
    }
    if let Err(e) = users::create_user(&state.db, &form.username, &form.password, true).await {
        return match e {
            AppError::BadRequest(msg) => {
                Ok((StatusCode::BAD_REQUEST, Html(pages::setup_page(Some(&msg)))).into_response())
            }
            other => Err(other),
        };
    }
    issue_session(&state, &headers, &form).await
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /gui/login
// Render the login form.
// ─────────────────────────────────────────────────────────────────────────────
async fn login_form() -> Response {
    Html(pages::login_page(None)).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /gui/login
// Verify credentials with brute-force lockout, then issue a session.
// ─────────────────────────────────────────────────────────────────────────────
async fn login_submit(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<Credentials>,
) -> Result<Response, AppError> {
    let key = form.username.trim().to_lowercase();

    if let Some(msg) = locked_message(&state, &key).await {
        return Ok((StatusCode::TOO_MANY_REQUESTS, Html(pages::login_page(Some(&msg)))).into_response());
    }

    match session::authenticate(&state.db, form.username.trim(), &form.password).await? {
        Some(auth) => {
            reset_throttle(&state, &key).await;
            audit_gui(&state, &headers, peer, "LOGIN", None, None, &auth.user_id, 200).await;
            let token = session::create_session(&state, auth, client_ip(&headers)).await?;
            Ok(redirect_with_cookie(
                "/gui/",
                &session::build_cookie(&token, state.config.security.session_ttl_hours),
            ))
        }
        None => {
            record_failure(&state, &key).await;
            Ok((
                StatusCode::UNAUTHORIZED,
                Html(pages::login_page(Some("Invalid username or password."))),
            )
                .into_response())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /gui/logout
// Drop the current session and clear the cookie.
// ─────────────────────────────────────────────────────────────────────────────
async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(token) = cookie_token(&headers) {
        session::logout(&state, &token).await;
    }
    redirect_with_cookie("/gui/login", &session::clear_cookie())
}

/// Vault create form fields.
#[derive(Debug, Deserialize)]
pub struct VaultForm {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

/// Assign-access form fields (username + role).
#[derive(Debug, Deserialize)]
pub struct AssignForm {
    pub username: String,
    pub role: String,
}

/// Revoke-access form fields.
#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    pub user_id: String,
}

/// Secret write form fields.
#[derive(Debug, Deserialize)]
pub struct SecretForm {
    pub path: String,
    pub data: String,
}

/// Single-path form/query fields (view, delete, prefill).
#[derive(Debug, Default, Deserialize)]
pub struct PathParam {
    #[serde(default)]
    pub path: String,
}

/// Vault network-ACL form (newline-separated IP/CIDR entries).
#[derive(Debug, Deserialize)]
pub struct AclForm {
    #[serde(default)]
    pub entries: String,
}

/// Token create form fields.
#[derive(Debug, Deserialize)]
pub struct TokenForm {
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub allowed_paths: String,
    #[serde(default)]
    pub allowed_ips: String,
    #[serde(default)]
    pub ttl_hours: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /gui/users
// Master-only user listing + create form.
// ─────────────────────────────────────────────────────────────────────────────
async fn users_list(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, AppError> {
    let keys = guard!(auth state headers);
    guard!(master &keys);
    let users = users::list_all(&state.db).await?;
    Ok(Html(pages::users_page(&keys.username, &users, None)).into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /gui/users
// Master creates a standard (non-master) user.
// ─────────────────────────────────────────────────────────────────────────────
async fn users_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<Credentials>,
) -> Result<Response, AppError> {
    let keys = guard!(auth state headers);
    guard!(master &keys);

    match users::create_user(&state.db, &form.username, &form.password, false).await {
        Ok(_) => Ok(Redirect::to("/gui/users").into_response()),
        Err(AppError::BadRequest(msg)) => {
            let users = users::list_all(&state.db).await?;
            Ok((StatusCode::BAD_REQUEST, Html(pages::users_page(&keys.username, &users, Some(&msg)))).into_response())
        }
        Err(e) => Err(e),
    }
}

/// A user's effective capabilities for one vault (global master + per-vault role).
struct Access {
    is_master: bool,
    role: Option<Role>,
}
impl Access {
    /// May read secret values (a per-vault role; master is blind).
    fn can_read(&self) -> bool {
        self.role.map(Role::can_read).unwrap_or(false)
    }
    /// May create/update secrets and tokens (editor or admin).
    fn can_write(&self) -> bool {
        self.role.map(Role::can_write).unwrap_or(false)
    }
    /// May assign/revoke users (global master or vault admin).
    fn can_assign(&self) -> bool {
        self.is_master || self.role.map(Role::can_assign).unwrap_or(false)
    }
    /// May open the vault page at all (master for management, or any member).
    fn can_view(&self) -> bool {
        self.is_master || self.role.is_some()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// load_access
// Resolve the caller's capabilities for a vault from their global + per-vault role.
// ─────────────────────────────────────────────────────────────────────────────
async fn load_access(state: &Arc<AppState>, keys: &SessionKeys, vault_id: &str) -> Result<Access, AppError> {
    let role = vault::get_user_role(&state.db, vault_id, &keys.user_id).await?;
    Ok(Access { is_master: keys.is_master, role })
}

// ─────────────────────────────────────────────────────────────────────────────
// master_key
// Copy the in-memory master key, or fail with Sealed when locked.
// ─────────────────────────────────────────────────────────────────────────────
async fn master_key(state: &Arc<AppState>) -> Result<zeroize::Zeroizing<[u8; 32]>, AppError> {
    state.master_key_bytes().await.ok_or(AppError::Sealed)
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /gui/vaults/new
// Master-only form to create a vault.
// ─────────────────────────────────────────────────────────────────────────────
async fn vault_new_form(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, AppError> {
    let keys = guard!(auth state headers);
    guard!(unsealed state, &keys);
    guard!(master &keys);
    Ok(Html(pages::vault_create_page(&keys.username, None)).into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /gui/vaults
// Create a vault owned by the master user (crypto Flow 3).
// ─────────────────────────────────────────────────────────────────────────────
async fn vault_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<VaultForm>,
) -> Result<Response, AppError> {
    let keys = guard!(auth state headers);
    guard!(unsealed state, &keys);
    guard!(master &keys);

    let mk = master_key(&state).await?;
    match vault::create_vault(&state.db, &form.name, &form.description, &keys.user_id, &mk).await {
        Ok(id) => Ok(Redirect::to(&format!("/gui/vaults/{id}")).into_response()),
        Err(AppError::BadRequest(msg)) => {
            Ok((StatusCode::BAD_REQUEST, Html(pages::vault_create_page(&keys.username, Some(&msg)))).into_response())
        }
        Err(e) => Err(e),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /gui/vaults/{id}
// Vault detail: secret listing, members, and grant/revoke controls.
// ─────────────────────────────────────────────────────────────────────────────
async fn vault_detail(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let keys = guard!(auth state headers);
    guard!(unsealed state, &keys);
    render_vault_detail(&state, &keys, &vault_id, None).await
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /gui/vaults/{id}/assign
// Master or vault admin assigns a user a role; the server re-wraps the vault key
// via master escrow + ephemeral ECDH (crypto Flow 4, escrow variant).
// ─────────────────────────────────────────────────────────────────────────────
async fn vault_assign(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<AssignForm>,
) -> Result<Response, AppError> {
    let keys = guard!(auth state headers);
    guard!(unsealed state, &keys);
    let access = load_access(&state, &keys, &vault_id).await?;
    if !access.can_assign() {
        return Ok(access_denied(&keys));
    }
    let Some(role) = Role::parse(form.role.trim()) else {
        return render_vault_detail(&state, &keys, &vault_id, Some("Invalid role.")).await;
    };

    let mk = master_key(&state).await?;
    match vault::assign(&state.db, &vault_id, &mk, &form.username, role, &keys.user_id).await {
        Ok(()) => {
            audit_gui(&state, &headers, peer, "GRANT", Some(&vault_id), None, &keys.user_id, 200).await;
            Ok(Redirect::to(&format!("/gui/vaults/{vault_id}")).into_response())
        }
        Err(AppError::BadRequest(msg)) => render_vault_detail(&state, &keys, &vault_id, Some(&msg)).await,
        Err(e) => Err(e),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /gui/vaults/{id}/revoke
// Master or vault admin removes a user's access (key rotation pending — Flow 9).
// ─────────────────────────────────────────────────────────────────────────────
async fn vault_revoke(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<RevokeForm>,
) -> Result<Response, AppError> {
    let keys = guard!(auth state headers);
    guard!(unsealed state, &keys);
    let access = load_access(&state, &keys, &vault_id).await?;
    if !access.can_assign() {
        return Ok(access_denied(&keys));
    }
    let mk = master_key(&state).await?;
    vault::revoke(&state.db, &vault_id, &form.user_id, &mk).await?;
    audit_gui(&state, &headers, peer, "REVOKE", Some(&vault_id), None, &keys.user_id, 200).await;
    Ok(Redirect::to(&format!("/gui/vaults/{vault_id}")).into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /gui/vaults/{id}/acl
// Master or vault admin sets the vault's network ACL (IPs / CIDRs).
// ─────────────────────────────────────────────────────────────────────────────
async fn vault_acl_set(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<AclForm>,
) -> Result<Response, AppError> {
    let keys = guard!(auth state headers);
    guard!(unsealed state, &keys);
    if !load_access(&state, &keys, &vault_id).await?.can_assign() {
        return Ok(access_denied(&keys));
    }
    let entries = lines_to_vec(&form.entries);
    match vault::set_acl(&state.db, &vault_id, &entries).await {
        Ok(()) => Ok(Redirect::to(&format!("/gui/vaults/{vault_id}")).into_response()),
        Err(AppError::BadRequest(msg)) => render_vault_detail(&state, &keys, &vault_id, Some(&msg)).await,
        Err(e) => Err(e),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /gui/vaults/{id}/rotate
// Master or vault admin rotates the vault key (crypto Flow 9), re-encrypting
// secrets and re-wrapping the key for the escrow, members, and tokens.
// ─────────────────────────────────────────────────────────────────────────────
async fn vault_rotate(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let keys = guard!(auth state headers);
    guard!(unsealed state, &keys);
    if !load_access(&state, &keys, &vault_id).await?.can_assign() {
        return Ok(access_denied(&keys));
    }
    let mk = master_key(&state).await?;
    vault::rotate_vault(&state.db, &vault_id, &mk).await?;
    audit_gui(&state, &headers, peer, "ROTATE", Some(&vault_id), None, &keys.user_id, 200).await;
    render_vault_detail(&state, &keys, &vault_id, Some("Vault key rotated.")).await
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /gui/audit
// Master-only audit log viewer with per-row HMAC verification.
// ─────────────────────────────────────────────────────────────────────────────
async fn audit_view(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, AppError> {
    let keys = guard!(auth state headers);
    guard!(master &keys);
    let mk = master_key(&state).await?;
    let rows = audit::list(&state.db, 200).await?;
    let verified: Vec<bool> = rows.iter().map(|r| audit::verify_row(&mk, r)).collect();
    Ok(Html(pages::audit_page(&keys.username, &rows, &verified)).into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /gui/seal
// Master-only emergency lockdown: drop the master key and seal the instance.
// ─────────────────────────────────────────────────────────────────────────────
async fn seal_instance(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let keys = guard!(auth state headers);
    guard!(master &keys);
    // Audit before sealing — afterwards the HMAC key (master key) is gone.
    audit_gui(&state, &headers, peer, "SEAL", None, None, &keys.user_id, 200).await;
    sys::perform_seal(&state).await?;
    Ok(Redirect::to("/gui/unseal").into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /gui/vaults/{id}/secret/new
// Form to write a secret (path prefilled when adding a new version).
// ─────────────────────────────────────────────────────────────────────────────
async fn secret_new_form(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    Query(q): Query<PathParam>,
) -> Result<Response, AppError> {
    let keys = guard!(auth state headers);
    guard!(unsealed state, &keys);
    let Some(v) = vault::get(&state.db, &vault_id).await? else { return Ok(not_found(&keys)); };
    if !load_access(&state, &keys, &vault_id).await?.can_write() {
        return Ok(access_denied(&keys));
    }
    Ok(Html(pages::secret_new_page(&keys.username, &vault_id, &v.name, None, &q.path, "")).into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /gui/vaults/{id}/secret
// Write a new version of a secret, sealed with the vault key (crypto Flow 6).
// ─────────────────────────────────────────────────────────────────────────────
async fn secret_write(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<SecretForm>,
) -> Result<Response, AppError> {
    let keys = guard!(auth state headers);
    guard!(unsealed state, &keys);
    let Some(v) = vault::get(&state.db, &vault_id).await? else { return Ok(not_found(&keys)); };
    if !load_access(&state, &keys, &vault_id).await?.can_write() {
        return Ok(access_denied(&keys));
    }

    // Parse the submitted data as a JSON value.
    let value: serde_json::Value = match serde_json::from_str(form.data.trim()) {
        Ok(val) => val,
        Err(_) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Html(pages::secret_new_page(&keys.username, &vault_id, &v.name, Some("Data must be valid JSON (e.g. {\"password\":\"…\"})."), &form.path, &form.data)),
            )
                .into_response());
        }
    };

    let mut vault_key = match vault::resolve_vault_key(&state.db, &vault_id, &keys.user_id, &keys.private_key).await {
        Ok(k) => k,
        Err(AppError::Forbidden) => return Ok(access_denied(&keys)),
        Err(e) => return Err(e),
    };

    let result = secrets::write(&state.db, &vault_id, &form.path, &value, &vault_key, &keys.user_id).await;
    vault_key.zeroize();
    match result {
        Ok(_) => {
            audit_gui(&state, &headers, peer, "WRITE", Some(&vault_id), Some(form.path.trim()), &keys.user_id, 200).await;
            Ok(Redirect::to(&format!("/gui/vaults/{}/secret?path={}", vault_id, urlencode(form.path.trim()))).into_response())
        }
        Err(AppError::BadRequest(msg)) => Ok((
            StatusCode::BAD_REQUEST,
            Html(pages::secret_new_page(&keys.username, &vault_id, &v.name, Some(&msg), &form.path, &form.data)),
        )
            .into_response()),
        Err(e) => Err(e),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /gui/vaults/{id}/secret?path=…
// Decrypt and display a secret's current value plus its version history.
// ─────────────────────────────────────────────────────────────────────────────
async fn secret_view(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    Query(q): Query<PathParam>,
) -> Result<Response, AppError> {
    let keys = guard!(auth state headers);
    guard!(unsealed state, &keys);
    let Some(v) = vault::get(&state.db, &vault_id).await? else { return Ok(not_found(&keys)); };
    if !load_access(&state, &keys, &vault_id).await?.can_read() {
        return Ok(access_denied(&keys));
    }

    let mut vault_key = match vault::resolve_vault_key(&state.db, &vault_id, &keys.user_id, &keys.private_key).await {
        Ok(k) => k,
        Err(AppError::Forbidden) => return Ok(access_denied(&keys)),
        Err(e) => return Err(e),
    };
    let latest = secrets::read_latest(&state.db, &vault_id, &q.path, &vault_key).await;
    vault_key.zeroize();

    let (version, value) = match latest? {
        Some(pair) => pair,
        None => {
            audit_gui(&state, &headers, peer, "READ", Some(&vault_id), Some(&q.path), &keys.user_id, 404).await;
            return Ok(Html(pages::notice_page(Some(keys.username.as_str()), "Secret not found", "No live version exists for that path.")).into_response());
        }
    };
    audit_gui(&state, &headers, peer, "READ", Some(&vault_id), Some(&q.path), &keys.user_id, 200).await;
    let pretty = serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".into());
    let versions = secrets::versions(&state.db, &vault_id, &q.path).await?;
    Ok(Html(pages::secret_view_page(&keys.username, &vault_id, &v.name, &q.path, version, &pretty, &versions)).into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /gui/vaults/{id}/secret/delete
// Soft-delete the latest version of a secret path.
// ─────────────────────────────────────────────────────────────────────────────
async fn secret_delete(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<PathParam>,
) -> Result<Response, AppError> {
    let keys = guard!(auth state headers);
    guard!(unsealed state, &keys);
    if !load_access(&state, &keys, &vault_id).await?.can_write() {
        return Ok(access_denied(&keys));
    }
    secrets::soft_delete(&state.db, &vault_id, &form.path).await?;
    audit_gui(&state, &headers, peer, "DELETE", Some(&vault_id), Some(form.path.trim()), &keys.user_id, 200).await;
    Ok(Redirect::to(&format!("/gui/vaults/{vault_id}")).into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /gui/vaults/{id}/tokens
// List the vault's API tokens; editor+ may also create them.
// ─────────────────────────────────────────────────────────────────────────────
async fn tokens_list(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let keys = guard!(auth state headers);
    guard!(unsealed state, &keys);
    let Some(v) = vault::get(&state.db, &vault_id).await? else { return Ok(not_found(&keys)); };
    let access = load_access(&state, &keys, &vault_id).await?;
    if !access.can_write() {
        return Ok(access_denied(&keys));
    }
    let list = tokens::list_for_vault(&state.db, &vault_id).await?;
    Ok(Html(pages::tokens_page(&keys.username, &vault_id, &v.name, &list, true, None)).into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /gui/vaults/{id}/tokens
// Mint a per-vault API token (crypto Flow 7); shows the raw token once.
// ─────────────────────────────────────────────────────────────────────────────
async fn tokens_create(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Result<Response, AppError> {
    let keys = guard!(auth state headers);
    guard!(unsealed state, &keys);
    let Some(v) = vault::get(&state.db, &vault_id).await? else { return Ok(not_found(&keys)); };
    if !load_access(&state, &keys, &vault_id).await?.can_write() {
        return Ok(access_denied(&keys));
    }

    let paths = lines_to_vec(&form.allowed_paths);
    let ips = lines_to_vec(&form.allowed_ips);
    let ttl_seconds = match form.ttl_hours.trim() {
        "" => None,
        h => match h.parse::<i64>() {
            Ok(n) if n > 0 => Some(n * 3600),
            _ => {
                let list = tokens::list_for_vault(&state.db, &vault_id).await?;
                return Ok((StatusCode::BAD_REQUEST, Html(pages::tokens_page(&keys.username, &vault_id, &v.name, &list, true, Some("TTL must be a positive number of hours.")))).into_response());
            }
        },
    };

    let mk = master_key(&state).await?;
    match tokens::create_token(&state.db, &vault_id, &keys.user_id, &keys.private_key, &mk, &form.display_name, &paths, &ips, ttl_seconds).await {
        Ok(raw) => Ok(Html(pages::token_created_page(&keys.username, &vault_id, &v.name, &raw)).into_response()),
        Err(AppError::Forbidden) => Ok(access_denied(&keys)),
        Err(AppError::BadRequest(msg)) => {
            let list = tokens::list_for_vault(&state.db, &vault_id).await?;
            Ok((StatusCode::BAD_REQUEST, Html(pages::tokens_page(&keys.username, &vault_id, &v.name, &list, true, Some(&msg)))).into_response())
        }
        Err(e) => Err(e),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /gui/vaults/{id}/tokens/{tid}/revoke
// Revoke a token (effective immediately).
// ─────────────────────────────────────────────────────────────────────────────
async fn tokens_revoke(
    State(state): State<Arc<AppState>>,
    Path((vault_id, token_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let keys = guard!(auth state headers);
    guard!(unsealed state, &keys);
    if !load_access(&state, &keys, &vault_id).await?.can_write() {
        return Ok(access_denied(&keys));
    }
    tokens::revoke_token(&state.db, &vault_id, &token_id).await?;
    Ok(Redirect::to(&format!("/gui/vaults/{vault_id}/tokens")).into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// lines_to_vec
// Split a textarea into trimmed, non-empty lines.
// ─────────────────────────────────────────────────────────────────────────────
fn lines_to_vec(input: &str) -> Vec<String> {
    input.lines().map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// render_vault_detail
// Load a vault's secrets + members and render the detail page (or access pages).
// ─────────────────────────────────────────────────────────────────────────────
async fn render_vault_detail(
    state: &Arc<AppState>,
    keys: &SessionKeys,
    vault_id: &str,
    error: Option<&str>,
) -> Result<Response, AppError> {
    let Some(v) = vault::get(&state.db, vault_id).await? else { return Ok(not_found(keys)); };
    let access = load_access(state, keys, vault_id).await?;
    if !access.can_view() {
        return Ok(access_denied(keys));
    }
    // The blind master never sees secret paths — only members can read those.
    let secret_list = if access.can_read() {
        secrets::list_paths(&state.db, vault_id).await?
    } else {
        Vec::new()
    };
    let members = vault::members(&state.db, vault_id).await?;
    let acl_entries = if access.can_assign() {
        vault::get_acl(&state.db, vault_id).await?
    } else {
        Vec::new()
    };
    Ok(Html(pages::vault_detail_page(pages::VaultDetail {
        username: &keys.username,
        vault_id,
        vault_name: &v.name,
        description: v.description.as_deref().unwrap_or(""),
        secrets: &secret_list,
        members: &members,
        current_user_id: &keys.user_id,
        acl_entries: &acl_entries,
        can_read: access.can_read(),
        can_write: access.can_write(),
        can_assign: access.can_assign(),
        error,
    }))
    .into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// session_keys
// Resolve the request's session into key material, if logged in.
// ─────────────────────────────────────────────────────────────────────────────
async fn session_keys(state: &Arc<AppState>, headers: &HeaderMap) -> Option<SessionKeys> {
    let token = cookie_token(headers)?;
    session::keys(state, &token).await
}

// ─────────────────────────────────────────────────────────────────────────────
// not_found / access_denied
// Standard GUI notice responses for missing vaults and insufficient access.
// ─────────────────────────────────────────────────────────────────────────────
fn not_found(keys: &SessionKeys) -> Response {
    (StatusCode::NOT_FOUND, Html(pages::notice_page(Some(keys.username.as_str()), "Not found", "That vault does not exist."))).into_response()
}
fn access_denied(keys: &SessionKeys) -> Response {
    (StatusCode::FORBIDDEN, Html(pages::notice_page(Some(keys.username.as_str()), "Access denied", "You do not have access to this vault."))).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// urlencode
// Minimal percent-encoding for redirect targets containing secret paths.
// ─────────────────────────────────────────────────────────────────────────────
fn urlencode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// issue_session
// Authenticate the just-submitted credentials and set the session cookie.
// ─────────────────────────────────────────────────────────────────────────────
async fn issue_session(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    form: &Credentials,
) -> Result<Response, AppError> {
    let auth = session::authenticate(&state.db, form.username.trim(), &form.password)
        .await?
        .ok_or_else(|| AppError::Internal("post-setup authentication failed".into()))?;
    let token = session::create_session(state, auth, client_ip(headers)).await?;
    Ok(redirect_with_cookie(
        "/gui/",
        &session::build_cookie(&token, state.config.security.session_ttl_hours),
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// current_identity
// Resolve the ev_session cookie to a logged-in identity, if any.
// ─────────────────────────────────────────────────────────────────────────────
async fn current_identity(state: &Arc<AppState>, headers: &HeaderMap) -> Option<SessionIdentity> {
    let token = cookie_token(headers)?;
    session::lookup(state, &token).await
}

// ─────────────────────────────────────────────────────────────────────────────
// cookie_token
// Extract the raw session token from the request's Cookie header.
// ─────────────────────────────────────────────────────────────────────────────
fn cookie_token(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    session::token_from_cookie_header(cookie)
}

// ─────────────────────────────────────────────────────────────────────────────
// client_ip
// Best-effort client IP from X-Forwarded-For (first hop), else None.
// ─────────────────────────────────────────────────────────────────────────────
fn client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// ─────────────────────────────────────────────────────────────────────────────
// redirect_with_cookie
// Build a 303-style redirect response carrying a Set-Cookie header.
// ─────────────────────────────────────────────────────────────────────────────
fn redirect_with_cookie(location: &str, cookie: &str) -> Response {
    let mut resp = Redirect::to(location).into_response();
    if let Ok(value) = HeaderValue::from_str(cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, value);
    }
    resp
}

// ─────────────────────────────────────────────────────────────────────────────
// locked_message
// If the username is currently locked out, return a user-facing message.
// ─────────────────────────────────────────────────────────────────────────────
async fn locked_message(state: &Arc<AppState>, key: &str) -> Option<String> {
    let throttle = state.login_throttle.read().await;
    let entry = throttle.get(key)?;
    let until = entry.locked_until?;
    let remaining = until - Utc::now();
    if remaining > Duration::zero() {
        let mins = remaining.num_minutes() + 1;
        Some(format!("Too many failed attempts. Try again in about {mins} minute(s)."))
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// record_failure
// Increment the failure counter and lock the account at the configured limit.
// ─────────────────────────────────────────────────────────────────────────────
async fn record_failure(state: &Arc<AppState>, key: &str) {
    let max = state.config.security.max_login_attempts;
    let lockout = state.config.security.lockout_minutes as i64;
    let mut throttle = state.login_throttle.write().await;
    let entry = throttle.entry(key.to_string()).or_default();
    entry.failures += 1;
    if entry.failures >= max {
        entry.locked_until = Some(Utc::now() + Duration::minutes(lockout));
        entry.failures = 0;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// reset_throttle
// Clear any failure/lockout state for a username after a successful login.
// ─────────────────────────────────────────────────────────────────────────────
async fn reset_throttle(state: &Arc<AppState>, key: &str) {
    state.login_throttle.write().await.remove(key);
}
