use crate::db;
use std::{
    env,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::Duration,
};
use tracing::level_filters::LevelFilter;
use tracing::trace;
use zeevum_protocol::pow::Difficulty;

/// Where the `.env` was found, when there was one. A relative path written
/// in it is relative to the file, not to the directory the binary happened
/// to start from.
static ENV_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Called once from `main`, before anything reads the environment.
pub fn set_env_dir(dir: PathBuf) {
    let _ = ENV_DIR.set(dir);
}

fn base_dir() -> PathBuf {
    ENV_DIR
        .get()
        .cloned()
        .unwrap_or_else(|| env::current_dir().expect("no .env and no working directory"))
}

/// Who may create an account. `Open` is the behaviour of a server before
/// invitations existed, and the default for the same reason: an upgrade
/// must not lock anybody out before the operator has chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationMode {
    Open,
    Invite,
    Closed,
}

impl RegistrationMode {
    fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "open" => Some(Self::Open),
            "invite" => Some(Self::Invite),
            "closed" => Some(Self::Closed),
            _ => None,
        }
    }
}

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
    /// Rate limits, see `ratelimit.rs`. Every one of them is a small
    /// number on purpose: this is a self-hosted server, the defaults are
    /// for a household, not a city.
    pub reg_per_ip_per_hour: u32,
    pub msg_burst: u32,
    pub msg_per_sec: u32,
    pub conn_per_ip_per_10s: u32,
    pub registration: RegistrationMode,
    pub log_level: LevelFilter,
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
            Ok(val) if !val.trim().is_empty() => {
                let path = PathBuf::from(val);
                if path.is_absolute() {
                    path
                } else {
                    base_dir().join(path)
                }
            }
            _ => db::get_db_path().expect("Failed to build default DB path"),
        }
    }

    /// Kept apart from the rest for the same reason as the database path:
    /// `admin` has to be able to start a log without first having everything
    /// a server needs.
    pub fn log_level_from_env() -> LevelFilter {
        match env::var("LOG_LEVEL")
            .unwrap_or_default()
            .to_uppercase()
            .as_str()
        {
            "TRACE" => LevelFilter::TRACE,
            "DEBUG" => LevelFilter::DEBUG,
            "INFO" | "" => LevelFilter::INFO,
            "WARN" | "WARNING" => LevelFilter::WARN,
            "ERROR" => LevelFilter::ERROR,
            unknown => {
                eprintln!("Unknown LOG_LEVEL value '{unknown}', falling back to INFO");
                LevelFilter::INFO
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

        let reg_per_ip_per_hour = positive_env_u32("REG_PER_IP_PER_HOUR", 3);
        let msg_burst = positive_env_u32("MSG_BURST", 30);
        let msg_per_sec = positive_env_u32("MSG_PER_SEC", 5);
        let conn_per_ip_per_10s = positive_env_u32("CONN_PER_IP_PER_10S", 5);

        let registration = match env::var("REGISTRATION") {
            Ok(value) => RegistrationMode::parse(&value).unwrap_or_else(|| {
                eprintln!("Unknown REGISTRATION value '{value}', falling back to open");
                RegistrationMode::Open
            }),
            Err(_) => RegistrationMode::Open,
        };

        Self {
            server_address,
            db_path: Self::db_path_from_env(),
            read_timeout,
            handshake_timeout,
            tls_cert_path,
            tls_key_path,
            pow_difficulty,
            session_duration_hours,
            reg_per_ip_per_hour,
            msg_burst,
            msg_per_sec,
            conn_per_ip_per_10s,
            registration,
            log_level: Self::log_level_from_env(),
        }
    }
}

/// A positive whole number from the environment, or the default. Zero is
/// refused rather than clamped: a limit of zero means "block everyone",
/// which nobody sets on purpose.
fn positive_env_u32(name: &str, default: u32) -> u32 {
    match env::var(name) {
        Ok(value) => match value.parse::<u32>() {
            Ok(n) if n > 0 => n,
            _ => {
                eprintln!("Unknown {name} value '{value}', falling back to {default}");
                default
            }
        },
        Err(_) => {
            trace!(
                "Environment parameter '{name}' not found. Default value will be used: {default}"
            );
            default
        }
    }
}
