use std::time::Duration;

use tokio::sync::oneshot;

use zeevum_server::{AppContext, Config, db, error, info, logger, serve, warning};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let config = Config::from_env();
    logger::init("Zeevum-server", config.log_level);

    info!(
        "Zeevum-server v{} starting (protocol v{})",
        env!("CARGO_PKG_VERSION"),
        zeevum_protocol::PROTOCOL_VERSION
    );

    let _ = ctrlc::set_handler(move || {
        info!("Program exit with CTRL+C");
        std::thread::sleep(Duration::from_millis(50));
        std::process::exit(0);
    });

    if let Err(e) = run(config).await {
        error!("Fatal error: {e:#}");
        std::process::exit(1);
    }
}

async fn run(config: Config) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(&config.server_address).await?;
    info!("Server listening on {}", config.server_address);

    let ctx = AppContext::new(config).await?;

    // The first tick fires immediately, which covers the cleanup on startup too.
    let _gc_stop = spawn_session_gc(ctx.pool.clone());

    serve(ctx, listener).await
}

/// Ends when the returned sender is dropped, so returning from `run` is enough.
fn spawn_session_gc(pool: sqlx::SqlitePool) -> oneshot::Sender<()> {
    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(60 * 60));
        loop {
            tokio::select! {
                _ = ticker.tick() => match db::delete_expired_sessions(&pool).await {
                    Ok(0) => {}
                    Ok(n) => info!("Deleted {n} expired sessions"),
                    Err(e) => warning!("Failed to delete expired sessions: {e}"),
                },
                _ = &mut stop_rx => break,
            }
        }
    });

    stop_tx
}
