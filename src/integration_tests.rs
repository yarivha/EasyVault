// =============================================================================
// integration_tests.rs — end-to-end tests of the trust-critical flows
//
// Exercises the real module functions against an in-memory database: user
// registration/login, vault creation + escrow + cross-user ECDH access,
// versioned secrets, API tokens (Flow 7/8), key rotation (Flow 9), password
// change (Flow 10), user disable, and audit-log HMAC + tamper detection.
// =============================================================================

use serde_json::json;

use crate::approle;
use crate::audit::{self, AuditEntry};
use crate::auth::session;
use crate::crypto;
use crate::secrets;
use crate::storage::sqlite::test_pool;
use crate::tokens;
use crate::users;
use crate::vault::{self, Role};

/// Log in and return the user's decrypted X25519 private key (32 bytes).
async fn private_key(db: &sqlx::SqlitePool, username: &str, password: &str) -> [u8; 32] {
    session::authenticate(db, username, password)
        .await
        .unwrap()
        .expect("login should succeed")
        .private_key
}

// ─────────────────────────────────────────────────────────────────────────────
// users: registration + login round trip, wrong password, duplicate
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn user_register_and_login() {
    let db = test_pool().await;
    users::create_user(&db, "alice", "password123", false).await.unwrap();

    assert!(session::authenticate(&db, "alice", "password123").await.unwrap().is_some());
    assert!(session::authenticate(&db, "alice", "wrong").await.unwrap().is_none());
    assert!(session::authenticate(&db, "ghost", "password123").await.unwrap().is_none());

    // Duplicate username and short password are rejected.
    assert!(users::create_user(&db, "alice", "password123", false).await.is_err());
    assert!(users::create_user(&db, "bob", "short", false).await.is_err());
}

// ─────────────────────────────────────────────────────────────────────────────
// vault + secrets: cross-user envelope encryption (Flows 3–6)
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn vault_assign_and_cross_user_secret_access() {
    let db = test_pool().await;
    let master_key = crypto::random_key();

    let master_id = users::create_user(&db, "master", "masterpass", true).await.unwrap();
    users::create_user(&db, "edith", "edithpass", false).await.unwrap();
    users::create_user(&db, "victor", "victorpass", false).await.unwrap();

    let vault_id = vault::create_vault(&db, "prod", "", &master_id, &master_key).await.unwrap();
    vault::assign(&db, &vault_id, &master_key, "edith", Role::Editor, &master_id).await.unwrap();
    vault::assign(&db, &vault_id, &master_key, "victor", Role::Viewer, &master_id).await.unwrap();

    let edith_id = users::get_by_username(&db, "edith").await.unwrap().unwrap().id;
    let edith_priv = private_key(&db, "edith", "edithpass").await;

    // Editor writes a secret with the resolved vault key.
    let vkey = vault::resolve_vault_key(&db, &vault_id, &edith_id, &edith_priv).await.unwrap();
    secrets::write(&db, &vault_id, "db/pg", &json!({"password": "hunter2"}), &vkey, &edith_id, None).await.unwrap();

    // Viewer recovers the SAME vault key via their own private key and decrypts.
    let victor_id = users::get_by_username(&db, "victor").await.unwrap().unwrap().id;
    let victor_priv = private_key(&db, "victor", "victorpass").await;
    let vkey_v = vault::resolve_vault_key(&db, &vault_id, &victor_id, &victor_priv).await.unwrap();
    let (ver, value) = secrets::read_latest(&db, &vault_id, "db/pg", &vkey_v).await.unwrap().unwrap();
    assert_eq!(ver, 1);
    assert_eq!(value["password"], "hunter2");

    // A non-member cannot resolve the vault key.
    users::create_user(&db, "mallory", "mallorypass", false).await.unwrap();
    let mallory_id = users::get_by_username(&db, "mallory").await.unwrap().unwrap().id;
    let mallory_priv = private_key(&db, "mallory", "mallorypass").await;
    assert!(vault::resolve_vault_key(&db, &vault_id, &mallory_id, &mallory_priv).await.is_err());
}

// ─────────────────────────────────────────────────────────────────────────────
// secret versioning: each write is a new version; read returns the latest
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn secret_versioning() {
    let db = test_pool().await;
    let master_key = crypto::random_key();
    let mid = users::create_user(&db, "m", "masterpass", true).await.unwrap();
    let vid = vault::create_vault(&db, "v", "", &mid, &master_key).await.unwrap();
    vault::assign(&db, &vid, &master_key, "m", Role::Editor, &mid).await.unwrap_err(); // master can't be a member
    let vkey = vault::resolve_vault_key_via_master(&db, &vid, &master_key).await.unwrap();

    secrets::write(&db, &vid, "k", &json!({"v": 1}), &vkey, &mid, None).await.unwrap();
    let v2 = secrets::write(&db, &vid, "k", &json!({"v": 2}), &vkey, &mid, None).await.unwrap();
    assert_eq!(v2, 2);
    let (ver, value) = secrets::read_latest(&db, &vid, "k", &vkey).await.unwrap().unwrap();
    assert_eq!(ver, 2);
    assert_eq!(value["v"], 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// tokens: create (Flow 7) + authenticate (Flow 8) + path ACL + revoke
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn token_create_authenticate_revoke() {
    let db = test_pool().await;
    let master_key = crypto::random_key();
    let mid = users::create_user(&db, "m", "masterpass", true).await.unwrap();
    users::create_user(&db, "ed", "edpassword", false).await.unwrap();
    let vid = vault::create_vault(&db, "v", "", &mid, &master_key).await.unwrap();
    vault::assign(&db, &vid, &master_key, "ed", Role::Editor, &mid).await.unwrap();
    let ed_id = users::get_by_username(&db, "ed").await.unwrap().unwrap().id;
    let ed_priv = private_key(&db, "ed", "edpassword").await;
    let vkey = vault::resolve_vault_key(&db, &vid, &ed_id, &ed_priv).await.unwrap();
    secrets::write(&db, &vid, "db/pg", &json!({"p": "s3cret"}), &vkey, &ed_id, None).await.unwrap();

    let raw = tokens::create_token(&db, &vid, &ed_id, &ed_priv, &master_key, "ci", &["db/*".into()], &[], None).await.unwrap();
    assert!(raw.starts_with("ev."));

    // Authenticate the token and read through master_key -> token_key -> vault_key.
    let auth = tokens::authenticate_token(&db, &master_key, &raw).await.unwrap();
    assert_eq!(auth.vault_id, vid);
    assert!(tokens::path_allowed(&auth.allowed_paths, "db/pg"));
    assert!(!tokens::path_allowed(&auth.allowed_paths, "api/key"));
    let (_, value) = secrets::read_latest(&db, &vid, "db/pg", &auth.vault_key).await.unwrap().unwrap();
    assert_eq!(value["p"], "s3cret");

    // A bad token and a revoked token both fail.
    assert!(tokens::authenticate_token(&db, &master_key, "ev.garbage").await.is_err());
    tokens::revoke_token(&db, &vid, &auth.token_id).await.unwrap();
    assert!(tokens::authenticate_token(&db, &master_key, &raw).await.is_err());
}

// ─────────────────────────────────────────────────────────────────────────────
// token self-management: lookup-self / renew-self / revoke-self
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn token_self_lookup_renew_revoke() {
    let db = test_pool().await;
    let master_key = crypto::random_key();
    let mid = users::create_user(&db, "m", "masterpass", true).await.unwrap();
    users::create_user(&db, "ed", "edpassword", false).await.unwrap();
    let vid = vault::create_vault(&db, "v", "", &mid, &master_key).await.unwrap();
    vault::assign(&db, &vid, &master_key, "ed", Role::Editor, &mid).await.unwrap();
    let ed_id = users::get_by_username(&db, "ed").await.unwrap().unwrap().id;
    let ed_priv = private_key(&db, "ed", "edpassword").await;

    // A token WITH a TTL is renewable.
    let raw = tokens::create_token(&db, &vid, &ed_id, &ed_priv, &master_key, "ci", &["*".into()], &[], Some(3600)).await.unwrap();
    let info = tokens::lookup(&db, &raw).await.unwrap();
    assert!(info.renewable);
    assert!(info.ttl_seconds() > 3500 && info.ttl_seconds() <= 3600);

    // Renew extends the lifetime.
    let renewed = tokens::renew(&db, &raw, Some(7200)).await.unwrap();
    assert!(renewed.ttl_seconds() > 7100);

    // Revoke-self invalidates it everywhere.
    tokens::revoke_self(&db, &raw).await.unwrap();
    assert!(tokens::lookup(&db, &raw).await.is_err());
    assert!(tokens::authenticate_token(&db, &master_key, &raw).await.is_err());

    // A token WITHOUT a TTL is not renewable.
    let perm = tokens::create_token(&db, &vid, &ed_id, &ed_priv, &master_key, "perm", &["*".into()], &[], None).await.unwrap();
    assert!(!tokens::lookup(&db, &perm).await.unwrap().renewable);
    assert!(tokens::renew(&db, &perm, None).await.is_err());
}

// ─────────────────────────────────────────────────────────────────────────────
// rotation (Flow 9): members and live tokens still decrypt after re-keying
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn rotation_preserves_access() {
    let db = test_pool().await;
    let master_key = crypto::random_key();
    let mid = users::create_user(&db, "m", "masterpass", true).await.unwrap();
    users::create_user(&db, "ed", "edpassword", false).await.unwrap();
    let vid = vault::create_vault(&db, "v", "", &mid, &master_key).await.unwrap();
    vault::assign(&db, &vid, &master_key, "ed", Role::Editor, &mid).await.unwrap();
    let ed_id = users::get_by_username(&db, "ed").await.unwrap().unwrap().id;
    let ed_priv = private_key(&db, "ed", "edpassword").await;
    let vkey = vault::resolve_vault_key(&db, &vid, &ed_id, &ed_priv).await.unwrap();
    secrets::write(&db, &vid, "k", &json!({"v": "x"}), &vkey, &ed_id, None).await.unwrap();
    let raw = tokens::create_token(&db, &vid, &ed_id, &ed_priv, &master_key, "t", &["*".into()], &[], None).await.unwrap();

    vault::rotate_vault(&db, &vid, &master_key).await.unwrap();

    // Member still decrypts (their wrapped key was re-issued).
    let vkey2 = vault::resolve_vault_key(&db, &vid, &ed_id, &ed_priv).await.unwrap();
    let (_, value) = secrets::read_latest(&db, &vid, "k", &vkey2).await.unwrap().unwrap();
    assert_eq!(value["v"], "x");

    // Live token still decrypts (its vault_key_enc was re-wrapped).
    let auth = tokens::authenticate_token(&db, &master_key, &raw).await.unwrap();
    let (_, tv) = secrets::read_latest(&db, &vid, "k", &auth.vault_key).await.unwrap().unwrap();
    assert_eq!(tv["v"], "x");
}

// ─────────────────────────────────────────────────────────────────────────────
// delete: a fully-deleted secret leaves the listing and can be recreated
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn delete_path_removes_from_listing_and_allows_recreate() {
    let db = test_pool().await;
    let master_key = crypto::random_key();
    let mid = users::create_user(&db, "m", "masterpass", true).await.unwrap();
    let vid = vault::create_vault(&db, "v", "", &mid, &master_key).await.unwrap();
    let vkey = vault::resolve_vault_key_via_master(&db, &vid, &master_key).await.unwrap();

    // Two versions, then delete the whole secret.
    secrets::write(&db, &vid, "db/pg", &json!({"v": 1}), &vkey, &mid, None).await.unwrap();
    secrets::write(&db, &vid, "db/pg", &json!({"v": 2}), &vkey, &mid, None).await.unwrap();
    assert_eq!(secrets::list_paths(&db, &vid).await.unwrap().len(), 1);

    secrets::delete_path(&db, &vid, "db/pg").await.unwrap();
    // Gone from the listing, and no live version to read.
    assert!(secrets::list_paths(&db, &vid).await.unwrap().is_empty());
    assert!(secrets::read_latest(&db, &vid, "db/pg", &vkey).await.unwrap().is_none());

    // Recreating the same path starts a new live version (v3).
    let v = secrets::write(&db, &vid, "db/pg", &json!({"v": 3}), &vkey, &mid, None).await.unwrap();
    assert_eq!(v, 3);
    let list = secrets::list_paths(&db, &vid).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].version, 3);
    let (_, value) = secrets::read_latest(&db, &vid, "db/pg", &vkey).await.unwrap().unwrap();
    assert_eq!(value["v"], 3);
}

// ─────────────────────────────────────────────────────────────────────────────
// burn-after-read: a single/N-use secret is destroyed once its reads run out
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn single_use_secret_burns_after_read() {
    let db = test_pool().await;
    let master_key = crypto::random_key();
    let mid = users::create_user(&db, "m", "masterpass", true).await.unwrap();
    let vid = vault::create_vault(&db, "v", "", &mid, &master_key).await.unwrap();
    let vkey = vault::resolve_vault_key_via_master(&db, &vid, &master_key).await.unwrap();

    // max_reads = 2: two consuming reads, then it's gone.
    secrets::write(&db, &vid, "otp", &json!({"code": "123456"}), &vkey, &mid, Some(2)).await.unwrap();

    let (_, v1, rem1) = secrets::read_and_consume(&db, &vid, "otp", &vkey).await.unwrap().unwrap();
    assert_eq!(v1["code"], "123456");
    assert_eq!(rem1, Some(1));

    let (_, v2, rem2) = secrets::read_and_consume(&db, &vid, "otp", &vkey).await.unwrap().unwrap();
    assert_eq!(v2["code"], "123456");
    assert_eq!(rem2, Some(0));

    // Burned: no more live version on either read path.
    assert!(secrets::read_and_consume(&db, &vid, "otp", &vkey).await.unwrap().is_none());
    assert!(secrets::read_latest(&db, &vid, "otp", &vkey).await.unwrap().is_none());

    // An unlimited secret never burns.
    secrets::write(&db, &vid, "static", &json!({"k": "v"}), &vkey, &mid, None).await.unwrap();
    for _ in 0..5 {
        let (_, _, rem) = secrets::read_and_consume(&db, &vid, "static", &vkey).await.unwrap().unwrap();
        assert_eq!(rem, None);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// audit retention: prune removes rows older than the window, keeps recent ones
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn audit_retention_prune() {
    let db = test_pool().await;
    let master_key = crypto::random_key();

    // One recent row (via record) + one back-dated row inserted directly.
    audit::record(
        &db,
        &master_key,
        AuditEntry { operation: "READ", vault_id: None, path: None, actor_type: "system", actor_hash: None, source_ip: None, response_code: 200 },
    )
    .await;
    sqlx::query("INSERT INTO audit_log (request_id, timestamp, operation, actor_type, hmac) VALUES (?, ?, ?, ?, ?)")
        .bind("old")
        .bind("2000-01-01T00:00:00+00:00")
        .bind("READ")
        .bind("system")
        .bind("x")
        .execute(&db)
        .await
        .unwrap();
    assert_eq!(audit::count(&db).await.unwrap(), 2);

    // Default retention = 0 (keep forever) → prune is a no-op.
    assert_eq!(audit::prune(&db).await.unwrap(), 0);
    assert_eq!(audit::count(&db).await.unwrap(), 2);

    // 30-day retention → the year-2000 row is removed, the recent one stays.
    audit::set_retention_days(&db, 30).await.unwrap();
    assert_eq!(audit::retention_days(&db).await.unwrap(), 30);
    assert_eq!(audit::prune(&db).await.unwrap(), 1);
    assert_eq!(audit::count(&db).await.unwrap(), 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// AppRole: role + secret-id → login mints a scoped, working per-vault token
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn approle_login_mints_scoped_token() {
    let db = test_pool().await;
    let master_key = crypto::random_key();
    let mid = users::create_user(&db, "m", "masterpass", true).await.unwrap();
    users::create_user(&db, "ed", "edpassword", false).await.unwrap();
    let vid = vault::create_vault(&db, "v", "", &mid, &master_key).await.unwrap();
    vault::assign(&db, &vid, &master_key, "ed", Role::Editor, &mid).await.unwrap();
    let ed_id = users::get_by_username(&db, "ed").await.unwrap().unwrap().id;
    let ed_priv = private_key(&db, "ed", "edpassword").await;
    let vkey = vault::resolve_vault_key(&db, &vid, &ed_id, &ed_priv).await.unwrap();
    secrets::write(&db, &vid, "db/pg", &json!({"password": "hunter2"}), &vkey, &ed_id, None).await.unwrap();

    let role_id = approle::create_role(&db, &vid, "ci", &["db/*".into()], &[], Some(3600), &ed_id).await.unwrap();
    let internal = approle::get_by_role_id(&db, &role_id).await.unwrap().unwrap().id;
    let secret_id = approle::generate_secret_id(&db, &internal).await.unwrap();

    // Login mints a token scoped to the role's vault + paths + ttl.
    let (token, policies, ttl) = approle::login(&db, &master_key, &role_id, &secret_id).await.unwrap();
    assert_eq!(policies, vec!["db/*".to_string()]);
    assert_eq!(ttl, Some(3600));

    // The minted token authenticates and reads within its path ACL.
    let auth = tokens::authenticate_token(&db, &master_key, &token).await.unwrap();
    assert_eq!(auth.vault_id, vid);
    assert!(tokens::path_allowed(&auth.allowed_paths, "db/pg"));
    assert!(!tokens::path_allowed(&auth.allowed_paths, "other/key"));
    let (_, value) = secrets::read_latest(&db, &vid, "db/pg", &auth.vault_key).await.unwrap().unwrap();
    assert_eq!(value["password"], "hunter2");

    // Wrong secret-id and wrong role-id both fail.
    assert!(approle::login(&db, &master_key, &role_id, "wrong").await.is_err());
    assert!(approle::login(&db, &master_key, "nope", &secret_id).await.is_err());
}

// ─────────────────────────────────────────────────────────────────────────────
// password change (Flow 10): new password works, old fails, access preserved
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn password_change_preserves_vault_access() {
    let db = test_pool().await;
    let master_key = crypto::random_key();
    let mid = users::create_user(&db, "m", "masterpass", true).await.unwrap();
    users::create_user(&db, "ed", "oldpassword", false).await.unwrap();
    let vid = vault::create_vault(&db, "v", "", &mid, &master_key).await.unwrap();
    vault::assign(&db, &vid, &master_key, "ed", Role::Editor, &mid).await.unwrap();
    let ed_id = users::get_by_username(&db, "ed").await.unwrap().unwrap().id;
    let vkey = vault::resolve_vault_key(&db, &vid, &ed_id, &private_key(&db, "ed", "oldpassword").await).await.unwrap();
    secrets::write(&db, &vid, "k", &json!({"v": "keep"}), &vkey, &ed_id, None).await.unwrap();

    // Wrong current password is rejected; correct one succeeds.
    assert!(users::change_password(&db, &ed_id, "WRONG", "newpassword1").await.is_err());
    users::change_password(&db, &ed_id, "oldpassword", "newpassword1").await.unwrap();

    assert!(session::authenticate(&db, "ed", "oldpassword").await.unwrap().is_none());
    assert!(session::authenticate(&db, "ed", "newpassword1").await.unwrap().is_some());

    // Vault access survives: resolve + decrypt with the key from the NEW login.
    let new_priv = private_key(&db, "ed", "newpassword1").await;
    let vkey2 = vault::resolve_vault_key(&db, &vid, &ed_id, &new_priv).await.unwrap();
    let (_, value) = secrets::read_latest(&db, &vid, "k", &vkey2).await.unwrap().unwrap();
    assert_eq!(value["v"], "keep");
}

// ─────────────────────────────────────────────────────────────────────────────
// disable: a deactivated user cannot authenticate
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn disabled_user_cannot_login() {
    let db = test_pool().await;
    let id = users::create_user(&db, "ed", "edpassword", false).await.unwrap();
    assert!(session::authenticate(&db, "ed", "edpassword").await.unwrap().is_some());
    users::set_active(&db, &id, false).await.unwrap();
    assert!(session::authenticate(&db, "ed", "edpassword").await.unwrap().is_none());
    users::set_active(&db, &id, true).await.unwrap();
    assert!(session::authenticate(&db, "ed", "edpassword").await.unwrap().is_some());
}

// ─────────────────────────────────────────────────────────────────────────────
// audit: HMAC verifies, and any tampering is detected
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn audit_hmac_detects_tampering() {
    let db = test_pool().await;
    let master_key = crypto::random_key();
    audit::record(
        &db,
        &master_key,
        AuditEntry {
            operation: "READ",
            vault_id: Some("v1"),
            path: Some("db/pg"),
            actor_type: "api_token",
            actor_hash: Some("tok1"),
            source_ip: Some("127.0.0.1"),
            response_code: 200,
        },
    )
    .await;

    let rows = audit::list(&db, 10).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert!(audit::verify_row(&master_key, &rows[0]));

    // Tamper with a field → verification fails.
    let mut tampered = audit::list(&db, 10).await.unwrap().pop().unwrap();
    tampered.path = Some("HACKED".into());
    assert!(!audit::verify_row(&master_key, &tampered));

    // A different (wrong) master key also fails verification.
    assert!(!audit::verify_row(&crypto::random_key(), &rows[0]));
}
