# Changelog

All notable changes to EasyVault are documented here.
The format is loosely based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Fixed
- **Database no longer depends on the launch directory.** The SQLite path was
  CWD-relative (`./easyvault.db`), so launching from a different directory opened
  a fresh, empty database — which looked like "the master account is gone, set
  up again" every run. Relative paths now anchor to the EasyVault data dir
  (`$EASYVAULT_HOME`, else `$HOME/.easyvault`); absolute paths are used as-is.
  The resolved path is logged on startup and its parent dir is auto-created.
  (Note: the instance still comes up sealed on every restart by design — that
  requires re-unsealing, not re-creating the account.)

### Added — Vault-key rotation (crypto Flow 9)
- **`vault::rotate_vault`** — generates a new vault key, re-encrypts every stored
  secret version, and re-wraps the key for the master escrow, each remaining
  member (fresh ephemeral ECDH, `key_version`++), and each live token (under its
  `token_key`) — all in one transaction.
- **`revoke` now rotates** — removing a user's access re-keys the vault so any
  secret material they already held can't decrypt future reads (closes the
  earlier revoke gap).
- **Manual rotate** — master/vault-admin can rotate proactively via a button on
  the vault page (`POST /gui/vaults/:id/rotate`).
- Verified: after revoke+rotation, remaining members and live tokens still
  decrypt secrets and `key_version` bumps; the revoked user gets 403.

### Added — Increment 3 (part 1): API tokens + Vault-compatible KV API
- **Per-vault API tokens** (`tokens.rs`):
  - `create_token` (crypto Flow 7) — `ev.<base64url>`; the vault key is sealed
    under a per-token `token_key`, which is sealed under the master key. Only
    `SHA-256(token)` is stored; the raw token is shown once. Created by editor+.
  - `authenticate_token` (crypto Flow 8) — unwraps master_key → token_key →
    vault_key; rejects revoked/expired; bumps `last_used_at`.
  - `path_allowed` — `*` / trailing-`*` glob / exact path matching.
  - `list_for_vault`, `revoke_token` (effective immediately).
- **KV v2 REST API** (`api/routes/kv.rs`), token-authenticated via
  `X-Vault-Token` (the token selects the vault):
  - `GET/POST/DELETE /v1/secret/data/{*path}` — read / write-new-version /
    soft-delete, in Vault's response envelope.
  - `GET /v1/secret/metadata[/{*path}]?list=true` — directory listing (incl. root).
- **Token GUI** — per-vault `/gui/vaults/:id/tokens` (list + create + revoke,
  editor+), with one-time raw-token display.
- Requires an unsealed instance (master_key reachable) for all token operations.
- Verified end-to-end: a REST client reads/writes a secret with a token; path
  ACL, missing/bad token, expiry, and revocation all enforced (403).

### Added — Increment 3 (part 2): IP/subnet ACL + HMAC audit log
- **IP/subnet ACL** (`vault/acl.rs`, `ipnet`) — client IP resolved from the TCP
  peer (or first `X-Forwarded-For` hop when the peer is a configured trusted
  proxy). KV requests are checked against both the **token** `allowed_ips` and
  the **vault** ACL (IPs + CIDRs); empty = no restriction. `ConnectInfo` is now
  enabled on the server. Vault ACL is editable in the GUI by master/vault-admin.
- **HMAC audit log** (`audit.rs`) — every KV operation (incl. denials) is
  recorded with `request_id`, timestamp, op, vault, path, actor, source IP, and
  result code, plus an **HMAC-SHA256 over the row** keyed by a master-key-derived
  secret. Secret values are never logged. Master-only viewer at `/gui/audit`
  shows each row's integrity (ok / TAMPERED via `verify_row`).
- 2 ACL unit tests added (13 total). Verified: token + vault IP ACL enforcement,
  editor-cannot-set-ACL (403), audit rows for 200s and 403 denials all verify
  ok, and a DB-tampered row is flagged TAMPERED in the viewer.
- **Known limitation:** only the token `/v1/secret/*` path is audited; GUI secret
  reads/writes are not yet audited (follow-up). Vault-key rotation on revoke
  (Flow 9) also still pending.

### Changed — Increment 2c (roles + master-key escrow)
- **Per-vault roles** — `vault_user_keys` gains a `role` column
  (`viewer` < `editor` < `admin`). Capabilities: viewer reads; editor reads +
  writes secrets + (later) creates tokens; admin additionally assigns users.
- **Blind master** — the global `master` manages vaults/users and assigns
  access but can **no longer read secrets**. Vault creation stores the vault key
  escrowed under the master key and gives master **no** membership row; the
  GUI hides secret contents/paths from master (separation of duties).
- **Server-side key distribution** (migration 002) — `vaults` gains
  `vault_key_enc_master` (= `AES-GCM(vault_key, master_key)`). Assignment
  (`vault::assign`) recovers the vault key from this escrow and re-wraps it for
  the target user via a fresh **ephemeral X25519 ECDH** keypair, stamped with a
  role. Replaces the old user-to-user `grant`. Works for both master and vault
  admins; re-assigning an existing member just changes their role.
- **Capability enforcement** — write/token = editor|admin; assign/revoke =
  master|vault-admin; vault/user creation = master. Verified end-to-end:
  blind-master 403s, editor write+read, viewer read-only, admin-can-assign,
  role-change upsert, per-vault admin ≠ global master.

### Added — Increment 2b (vaults, secrets, secret-browser GUI)
- **Vault layer** (`vault/mod.rs`) — `create_vault` (crypto Flow 3: random
  vault_key wrapped for the creator via self-ECDH), `list_for_user`, `get`,
  `members`, `user_has_access`, `resolve_vault_key` (Flow 5), `grant` (Flow 4:
  re-wrap the vault key under ECDH(granter→target)), and `revoke`.
- **Secrets layer** (`secrets.rs`) — append-only versioned KV (crypto Flow 6):
  `write` (new version per write, JSON sealed with the vault key), `read_latest`,
  `list_paths`, `versions`, `soft_delete`.
- **Secret-browser GUI** — dashboard vault list; vault create (master); vault
  detail with secret listing + member list; add-secret / view-secret (decrypted,
  with version history) / new-version / delete; grant + revoke (master).
- **User management** (`/gui/users`, master only) — list users and create
  standard (non-master) users; `users::list_all`.
- **Seal gating** — all vault/secret operations require an unsealed instance.
- **Key hygiene** — `SessionKeys` is `ZeroizeOnDrop`; resolved vault keys are
  `Zeroizing` and explicitly wiped after use.
- **Known gap:** `revoke` removes access but does not yet rotate the vault key
  (crypto Flow 9) — full re-encryption rotation is a planned follow-up.

### Added — Increment 2a (auth + GUI foundation)
- **First-run setup** (`/gui/setup`) — creates the initial master user
  (crypto Flow 1: X25519 keypair generated, private key sealed under the
  password-derived user_key). Locked once any user exists.
- **Login / logout** (`/gui/login`, `/gui/logout`) — crypto Flow 2 verifies the
  password, decrypts the private key, and opens a server-side session.
- **Server-side sessions** (`auth/session.rs`) — the decrypted X25519 private
  key lives only in `AppState.sessions` (in-memory, `ZeroizeOnDrop`); the
  `gui_sessions` row stores just the hashed token + expiry. Cookie `ev_session`
  (HttpOnly, SameSite=Lax), TTL from `security.session_ttl_hours`.
- **Brute-force lockout** — `max_login_attempts` failures lock a username for
  `lockout_minutes` (tracked in memory).
- **Dashboard** (`/gui/`) — identity + role, instance seal state, vault count.
- **Users module** (`users.rs`) — `create_user` / `get_by_username` /
  `count_users`.
- **Crypto helper** — `crypto::sha256_hex` for session/token lookup hashes.
- `GET /` now redirects to `/gui/` (replaces the placeholder landing page).

## [0.1.0] — 2026-06-17

First foundation increment: a Vault-compatible server that boots **sealed** and
can be initialized and unsealed.

### Added
- **Project skeleton** — Cargo (edition 2024), Axum 0.8, SQLite via sqlx 0.8.
- **Config** (`config.rs`) — TOML loading via `$EASYVAULT_CONFIG` (default
  `./config.toml`); all fields default so a missing file still works.
- **Crypto primitives** (`crypto/`) with unit tests:
  - `aes` — AES-256-GCM seal/open with per-call random nonces.
  - `argon2` — Argon2id password hashing **and** user-key derivation from the
    same salt, domain-separated so the two outputs differ.
  - `ecdh` — X25519 keypair generation + shared-secret derivation.
  - `shamir` — master-key split / threshold reconstruction (sharks).
- **Storage** (`storage/sqlite.rs`) — pool creation, foreign keys, embedded
  migrations.
- **Schema** (`migrations/001_initial.sql`) — `system_init`, `users`, `vaults`,
  `vault_user_keys`, `secrets`, `api_tokens`, `gui_sessions`, `policies`,
  `audit_log`.
- **AppState + MasterKey** (`state.rs`) — shared state holding the SQLite pool,
  config, and the in-memory master key (`ZeroizeOnDrop`, best-effort `mlock`).
- **Error envelope** (`error.rs`) — Vault-compatible `{"errors":[…]}` responses.
- **Response envelope** (`api/response.rs`) — `VaultResponse<T>`.
- **System endpoints** (`api/routes/sys.rs`):
  - `POST /v1/sys/init` — generate master key, Shamir-split, return shares once.
  - `POST /v1/sys/unseal` — accumulate shares, reconstruct + verify, unseal.
  - `GET  /v1/sys/seal-status` — initialized / sealed / share progress.
  - `GET  /v1/sys/health` — 200 active, 503 sealed, 501 uninitialized.

### Verified
- 11 crypto unit tests pass.
- End-to-end: pre-init `health` 501 → `init` (3-of-5) → sealed `health` 503 →
  three-share `unseal` → `health` 200; re-init rejected with 400.

[0.1.0]: https://github.com/yarivha/EasyVault/releases/tag/v0.1.0
