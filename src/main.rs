//! Zeevum server binary
//!
//! All logic lives in the `zeevum_server` library so that integration tests can
//! start a real server without going through this entry point

use std::time::Duration;

use zeevum_server::{AppContext, Config, error, info, logger, serve};

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
    serve(ctx, listener).await
}
