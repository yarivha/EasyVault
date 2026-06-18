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
mod tls;
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

    // Resolve TLS material before `cfg` is moved into the shared state.
    let tls_pem = if cfg.server.tls { Some(tls::load_or_generate(&cfg)?) } else { None };

    let state = AppState::new(pool, cfg);
    let app = api::build_router(state);

    // ConnectInfo exposes the TCP peer address for IP/subnet ACL enforcement.
    let service = app.into_make_service_with_connect_info::<SocketAddr>();

    if let Some(pem) = tls_pem {
        // Install the ring crypto provider (we build rustls without a default one).
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem(pem.cert, pem.key).await?;
        tracing::info!(%addr, "EasyVault listening on HTTPS (sealed until /v1/sys/unseal)");
        axum_server::bind_rustls(addr, tls_config).serve(service).await?;
    } else {
        tracing::info!(%addr, "EasyVault listening on HTTP (sealed until /v1/sys/unseal)");
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, service).await?;
    }

    Ok(())
}
