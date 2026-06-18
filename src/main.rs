// =============================================================================
// main.rs — EasyVault entry point
//
// Loads config, opens the SQLite store (running migrations), constructs the
// shared AppState (starting sealed), builds the router, and serves HTTP.
// TLS termination is deferred to a later increment.
// =============================================================================

mod api;
mod audit;
mod auth;
mod config;
mod crypto;
mod error;
mod secrets;
mod state;
mod storage;
mod tokens;
mod users;
mod vault;
mod web;

use std::net::SocketAddr;

use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::state::AppState;

// ─────────────────────────────────────────────────────────────────────────────
// main
// Async runtime entry: initialize logging, wire dependencies, and serve.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cfg = Config::load()?;
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "starting EasyVault");

    if cfg.storage.kind != "sqlite" {
        anyhow::bail!("storage type '{}' is not supported yet (only sqlite)", cfg.storage.kind);
    }

    let db_path = cfg.storage.resolved_path();
    tracing::info!(path = %db_path.display(), "using database");
    let pool = storage::open_sqlite(&db_path).await?;
    let addr: SocketAddr = format!("{}:{}", cfg.server.address, cfg.server.port).parse()?;

    let state = AppState::new(pool, cfg);
    let app = api::build_router(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "EasyVault listening (sealed until /v1/sys/unseal)");
    // ConnectInfo exposes the TCP peer address for IP/subnet ACL enforcement.
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}
