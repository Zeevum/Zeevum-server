use std::time::Duration;

use tokio::sync::oneshot;

use zeevum_server::{AppContext, Config, db, error, info, logger, serve, warning};

#[tokio::main]
async fn main() {
    // Relative paths inside .env are relative to the file itself, so the
    // same value means the same database whether the binary was started by
    // `cargo run` from the project or by hand out of target/release.
    if let Some(dir) = dotenvy::dotenv()
        .ok()
        .and_then(|file| file.parent().map(|p| p.to_path_buf()))
    {
        zeevum_server::config::set_env_dir(dir);
    }
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Before the config, not after: building it demands the TLS material,
    // and `admin` will never use a certificate.
    logger::init("Zeevum-server", Config::log_level_from_env());

    let _ = ctrlc::set_handler(move || {
        info!("Program exit with CTRL+C");
        logger::shutdown();
        std::process::exit(0);
    });

    // `admin` never serves: it opens the same database and exits, so the two
    // never compete for the port.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(|s| s.as_str()) == Some("admin") {
        if let Err(e) = zeevum_server::admin::run(&args[1..]).await {
            error!("{e:#}");
            logger::shutdown();
            std::process::exit(1);
        }
        return;
    }

    let config = Config::from_env();

    info!(
        "Zeevum-server v{} starting (protocol v{})",
        env!("CARGO_PKG_VERSION"),
        zeevum_protocol::PROTOCOL_VERSION
    );

    // Resolved, because a relative DB_PATH means a different file depending
    // on where the server was started from, and that is worth one line at
    // startup rather than an afternoon.
    info!("database: {}", Config::absolute(&config.db_path).display());

    if let Err(e) = run(config).await {
        error!("Fatal error: {e:#}");
        logger::shutdown();
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
