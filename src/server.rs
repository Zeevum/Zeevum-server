use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::config::Config;
use crate::connection;
use crate::db;
use crate::hub::Hub;
use crate::ratelimit::RateLimiter;
use crate::tls;

/// Cheap to clone, the expensive parts are already shared behind an `Arc`
#[derive(Clone)]
pub struct AppContext {
    pub config: Arc<Config>,
    pub pool: sqlx::SqlitePool,
    pub hub: Hub,
    pub rate_limiter: Arc<Mutex<RateLimiter>>,
    /// Argon2 hash of a throwaway password. Verified when a login names a user
    /// that does not exist, so response time does not reveal whether it does
    pub fake_hash: Arc<String>,
}

impl AppContext {
    pub async fn new(config: Config) -> Result<Self> {
        let pool = db::init_database(&config.db_path)
            .await
            .with_context(|| format!("Failed to open database {:?}", config.db_path))?;
        db::migrate(&pool).await.context("Migration failed")?;

        let fake_hash = db::hash_password("fake_password_for_timing_attack")
            .context("Failed to generate fake hash")?;

        Ok(Self {
            config: Arc::new(config),
            pool,
            hub: Hub::new(),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new())),
            fake_hash: Arc::new(fake_hash),
        })
    }
}

/// Takes the listener from the caller so that tests can bind an ephemeral port
/// before the server starts accepting
pub async fn serve(ctx: AppContext, listener: TcpListener) -> Result<()> {
    let acceptor = TlsAcceptor::from(tls::load_tls_config(
        &ctx.config.tls_cert_path,
        &ctx.config.tls_key_path,
    )?);

    loop {
        let (stream, peer) = listener.accept().await?;

        let ctx = ctx.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            connection::handle_client(stream, peer, ctx, acceptor).await;
        });
    }
}
