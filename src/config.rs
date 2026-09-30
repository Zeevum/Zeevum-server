use crate::{db, logger};
use std::{
    env,
    path::{Path, PathBuf},
    time::Duration,
};
use zeevum_protocol::pow::Difficulty;

#[derive(Debug)]
pub struct Config {
    pub server_address: String,
    pub db_path: PathBuf,
    pub read_timeout: Duration,
    pub handshake_timeout: Duration,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    pub pow_difficulty: Difficulty,
    pub session_duration_hours: f64,
    pub log_level: logger::LogLevel,
}

impl Config {
    /// Where a path really points, resolved against the directory the
    /// process was started in. A relative `DB_PATH` is relative to that, and
    /// not to the directory the binary sits in, which is the whole difference
    /// between `cargo run` and running the .exe out of target/release.
    pub fn absolute(path: &Path) -> PathBuf {
        std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
    }

    /// Where the database is, decided once for every entry point. Kept apart
    /// from the rest, because `admin` needs the database and nothing else:
    /// it has no use for a TLS certificate, and it must not fail because one
    /// is missing.
    pub fn db_path_from_env() -> PathBuf {
        match env::var("DB_PATH") {
            Ok(val) if !val.trim().is_empty() => PathBuf::from(val),
            _ => db::get_db_path().expect("Failed to build default DB path"),
        }
    }

    /// Kept apart from the rest for the same reason as the database path:
    /// `admin` has to be able to start a log without first having everything
    /// a server needs.
    pub fn log_level_from_env() -> logger::LogLevel {
        match env::var("LOG_LEVEL")
            .unwrap_or_default()
            .to_uppercase()
            .as_str()
        {
            "TRACE" => logger::LogLevel::Trace,
            "DEBUG" => logger::LogLevel::Debug,
            "INFO" | "" => logger::LogLevel::Info,
            "WARN" | "WARNING" => logger::LogLevel::Warning,
            "ERROR" => logger::LogLevel::Error,
            unknown => {
                eprintln!("Unknown LOG_LEVEL value '{unknown}', falling back to INFO");
                logger::LogLevel::Info
            }
        }
    }

    pub fn from_env() -> Self {
        let server_address = env::var("SERVER_ADDRESS")
            .unwrap_or_else(|_| {
                trace!("Environment parameter 'SERVER_ADDRESS' not found. Default address and port are being used: 0.0.0.0:1990");
                "0.0.0.0:1990".to_string()
            });

        let read_timeout = env::var("READ_TIMEOUT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&t| t > 0)
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(300));

        let handshake_timeout = env::var("HANDSHAKE_TIMEOUT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&t| t > 0)
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(10));

        let tls_cert_path = env::var("TLS_CERT_PATH")
            .map(PathBuf::from)
            .expect("TLS_CERT_PATH variable is required");

        let tls_key_path = env::var("TLS_KEY_PATH")
            .map(PathBuf::from)
            .expect("TLS_KEY_PATH variable is required");

        let bot_secure_level = env::var("POW_DIFFICULTY")
            .unwrap_or_else(|_| {
                trace!("Environment parameter 'POW_DIFFICULTY' not found. Default value will be used: medium");
                "medium".to_string()
            });
        let pow_difficulty = Difficulty::parse_env(&bot_secure_level).unwrap_or_else(|| {
            eprintln!("Unknown POW_DIFFICULTY value '{bot_secure_level}', falling back to medium");
            Difficulty::Medium
        });

        let session_duration_hours = env::var("SESSION_DURATION_HOURS")
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .filter(|&t| t > 0.0)
            .unwrap_or(720.0);

        Self {
            server_address,
            db_path: Self::db_path_from_env(),
            read_timeout,
            handshake_timeout,
            tls_cert_path,
            tls_key_path,
            pow_difficulty,
            session_duration_hours,
            log_level: Self::log_level_from_env(),
        }
    }
}
