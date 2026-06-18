// =============================================================================
// storage/sqlite.rs — SQLite pool creation and migration runner
//
// Opens (creating if absent) the SQLite database at the configured path,
// enables foreign keys, and applies the embedded migrations in ./migrations.
// =============================================================================

use std::path::Path;

use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

// ─────────────────────────────────────────────────────────────────────────────
// open_sqlite
// Ensure the parent directory exists, open/create the SQLite database at the
// given path, enable foreign keys, run migrations, and return a ready pool.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn open_sqlite(path: &Path) -> anyhow::Result<SqlitePool> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}
