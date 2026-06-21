# Changelog

All notable changes to EasyVault are documented here.
The format is loosely based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added — audit-log retention (master only)
- The master can set an **audit-log retention window** (days; 0/blank = keep
  forever) on the audit page, with a **Prune now** button. A background task
  prunes on startup and every 6 hours. Prevents the audit log from growing
  unbounded. Settings live in a new `settings` table (migration 006).

### Fixed — deleting a secret
- A fully-deleted secret no longer lingers in the vault's secret list. The
  listing now excludes paths whose only versions are soft-deleted (it already
  excluded destroyed/burned ones) — previously such a path stayed visible but
  led to a "not found" dead end.
- The GUI **Delete** now deletes the **whole secret** (all versions) in one
  action — relabelled **"Delete secret"** with a confirm — instead of one
  version at a time. Re-creating the same path afterwards starts a fresh live
  version. (The Vault-compatible `DELETE /v1/secret/data/:path` still
  soft-deletes a single version.)

## [0.1.5] — 2026-06-20

### Added — single-use / N-use secrets (burn after read)
- A secret can cap how many times it may be fetched over the token API. Set
  **Max reads** when writing (GUI field, or `{"options":{"max_reads":N}}` on the
  KV write API). After the Nth read the version is **destroyed and its ciphertext
  wiped** — the next fetch returns 404. Read responses include
  `metadata.reads_remaining`. Useful for one-time credentials / OTP handoff.
- GUI viewing does **not** consume a use (it's management inspection); the secret
  view page shows a "single-use" badge with reads remaining. Migration 005 adds
  `secrets.max_reads` + `read_count`.

### Changed — network ACL is per-token, not per-vault
- Removed the vault-level network ACL. IP/CIDR restrictions now live **on each
  token and AppRole** (their `allowed_ips`) — you say where a credential may be
  used from when you issue it. KV requests are checked against the token's IPs
  only; the vault Settings page no longer has a Network ACL card and
  `POST /gui/vaults/:id/acl` is gone.

### Changed — vault Settings page
- Vault management (member access/assign/revoke, network ACL, key rotation) moved
  off the main vault page onto a dedicated **Settings** page
  (`/gui/vaults/:id/settings`, master / vault-admin only). The vault page now
  focuses on secrets, with a **Settings** button for managers.

## [0.1.4] — 2026-06-20

### Added — AppRole auth (`/v1/auth/approle/login`)
- **Machine login** — a service exchanges a `role_id` + `secret_id` for a
  per-vault API token (Vault's `auth` envelope). The token is minted via the
  master escrow (no human session), scoped to the role's vault + path/IP ACL +
  TTL. Only `SHA-256(secret_id)` is stored (migration 004 adds `approles` +
  `approle_secrets`).
- **Role management in the GUI** (editor+, per vault, `/gui/vaults/:id/approles`)
  — create roles (name, allowed paths/IPs, token TTL), issue secret-ids (shown
  once, with a ready-to-run login `curl`), and delete roles.
- Token minting refactored into a shared `mint` helper so both session-created
  tokens and AppRole logins go through one path. New integration test (23 total).

### Added — Vault token self-management (`/v1/auth/token/*`)
- **`GET/POST /v1/auth/token/lookup-self`** — metadata about the calling token
  (display name, policies/paths, ttl, renewable, expiry, vault) — what real
  Vault clients call to introspect their token.
- **`POST /v1/auth/token/revoke-self`** — the token revokes itself (204).
- **`POST /v1/auth/token/renew-self`** — extend a renewable token by an
  `increment` (seconds) or its stored renew period. Tokens created **with a TTL
  are now renewable**; the TTL is the default renew period (migration 003 adds
  `api_tokens.renew_period`). All authenticated by `X-Vault-Token`.
- New integration test (22 total).

### Added — Windows service
- The Windows installer now registers EasyVault as a **Windows service** (via
  the [WinSW](https://github.com/winsw/winsw) wrapper, fetched in CI), set to
  start automatically and restart on failure — mirroring the Linux systemd unit.
  Data (database, TLS certs, config, logs) lives under `%ProgramData%\EasyVault`
  so it survives upgrades; uninstall stops/removes the service but preserves the
  data. The Start-menu shortcut now opens the dashboard (`http://localhost:8200`)
  instead of launching the binary directly.

## [0.1.3] — 2026-06-20

### Added — UI
- A subtle **version label** in the lower-right corner of every page.

### Added — user lifecycle
- **Disable / enable users** (master only, on `/gui/users`) — a disabled user
  can't log in, and their active sessions are dropped immediately. You can't
  disable your own or another master account. Audited (`USER_DISABLE`/`ENABLE`).
- **Self-service password change** (`/gui/account/password`, crypto Flow 10) —
  verifies the current password, re-wraps the X25519 private key under a new
  salt + key; **vault access is preserved** (the `vault_user_keys` rows use ECDH
  shared secrets, not the password). Audited (`PASSWORD_CHANGE`). The header
  username now links here. (Note: master cannot reset another user's password —
  the key model makes that impossible by design.)

### Added — test coverage
- 8 integration tests against an in-memory database covering the trust-critical
  flows: registration/login, cross-user vault access (escrow + ECDH), secret
  versioning, API tokens (Flow 7/8 + path ACL + revoke), key rotation (Flow 9),
  password change (Flow 10), user disable, and audit HMAC + tamper detection.
  **21 tests total.**

## [0.1.2] — 2026-06-19

### Added — dark / light theme
- The GUI palette is now driven by CSS variables with a **light theme** in
  addition to the existing dark one. A **◐ toggle** in the header switches and
  persists the choice in `localStorage`; the default follows the OS
  `prefers-color-scheme`. A tiny inline head script applies the theme before
  first paint (no flash). No dependencies.

### Added — full audit coverage + emergency seal
- **GUI actions are now audited** too (not just the token API): secret `READ`
  (incl. 404), `WRITE`, `DELETE`, plus `LOGIN`, `GRANT`, `REVOKE`, `ROTATE` and
  `SEAL` — recorded with `actor_type = gui_session` and the acting user, the
  same HMAC-signed rows shown in `/gui/audit`.
- **Re-seal** (`POST /gui/seal`, master only) — an emergency lockdown that drops
  the master key from memory and seals the instance immediately (the `SEAL`
  event is audited just before the key is wiped). Surfaced as a "Seal instance"
  button on the dashboard; the API core is `sys::perform_seal`.

## [0.1.1] — 2026-06-19

### Added — Linux service
- **systemd service** — the `.deb`/`.rpm` packages now install
  `/lib/systemd/system/easyvault.service` and, via maintainer scripts, create a
  dedicated `easyvault` system user, the `/etc/easyvault`, `/var/lib/easyvault`
  and `/var/log/easyvault` directories, seed `/etc/easyvault/config.toml` from
  the example, then enable and start the service on install.
- The service runs as the `easyvault` user with `EASYVAULT_HOME=/var/lib/easyvault`
  (database + TLS certs) and `EASYVAULT_CONFIG=/etc/easyvault/config.toml`,
  systemd hardening (`ProtectSystem=strict`, `NoNewPrivileges`, …), `CAP_IPC_LOCK`
  so the master key can be `mlock`ed, and logs under `/var/log/easyvault`.
- Removal stops/disables the service; `purge` removes data, logs and config.
- Note: it starts **sealed** on every boot — initialize/unseal at the dashboard.

## [0.1.0] — 2026-06-18

First release: a self-hosted, HashiCorp Vault–compatible secrets manager with
envelope encryption, per-vault roles, per-vault API tokens, IP/subnet ACLs, an
HMAC audit log, vault-key rotation, TLS, and a fully browser-based bootstrap.

### Added — Browser init / unseal flow
- **`/gui/unseal`** — no more curl for the unseal lifecycle. A sealed or
  uninitialized instance now redirects the GUI here:
  - **Uninitialized** → an Initialize form (share/threshold counts) → a
    one-time **shares** screen to save, with a clear warning.
  - **Sealed** → submit unseal shares one at a time with a `progress / threshold`
    indicator; once the threshold is met you're dropped into the app.
- `gui_root` now steers to `/gui/unseal` before setup/login when the instance
  isn't usable yet, so the whole bootstrap (initialize → unseal → create master
  account → log in) is clickable.
- Refactored the init/unseal core out of the JSON handlers (`sys::perform_init`,
  `sys::add_unseal_share`, `sys::seal_view`) so the API and GUI share one path;
  the `/v1/sys/*` JSON endpoints are unchanged.

### Added — TLS (HTTPS)
- **HTTPS support** (`axum-server` + rustls, `tls.rs`). Set `server.tls = true`
  to serve over TLS. If `tls_cert`/`tls_key` are set they're loaded; otherwise a
  self-signed cert (localhost, 127.0.0.1) is generated on first run under
  `<data_dir>/tls`, persisted (key file `0600`), and reused on later runs.
  `ConnectInfo` (for IP ACL) works under TLS too.
- **Partial config tables now valid** — each config section uses
  `#[serde(default)]`, so a `[server]` block with only some keys no longer
  errors on missing fields.

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

### Added — Foundation (Increment 1)
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
- 13 unit tests pass (crypto primitives + ACL matching).
- End-to-end across the stack: init → unseal → setup → roles/assignment →
  secret read/write → API-token REST access → IP ACL → audit + tamper detection
  → key rotation, over both HTTP and TLS.

[0.1.5]: https://github.com/yarivha/EasyVault/releases/tag/v0.1.5
[0.1.4]: https://github.com/yarivha/EasyVault/releases/tag/v0.1.4
[0.1.3]: https://github.com/yarivha/EasyVault/releases/tag/v0.1.3
[0.1.2]: https://github.com/yarivha/EasyVault/releases/tag/v0.1.2
[0.1.1]: https://github.com/yarivha/EasyVault/releases/tag/v0.1.1
[0.1.0]: https://github.com/yarivha/EasyVault/releases/tag/v0.1.0
