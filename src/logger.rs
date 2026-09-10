use chrono::Local;
use colored::Colorize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{OnceLock, mpsc};
use std::thread;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Fatal,
}

impl LogLevel {
    fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warning => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Fatal => "FATAL",
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

struct LogEntry {
    level: LogLevel,
    content: String,
}

static LOG_SENDER: OnceLock<mpsc::Sender<LogEntry>> = OnceLock::new();
static LOG_LEVEL: OnceLock<LogLevel> = OnceLock::new();

/// Инициализирует логгер. Должна вызываться первой в main()
pub fn init(app_name: &str, min_level: LogLevel) {
    let app_lowercase = app_name.to_lowercase();
    LOG_LEVEL.set(min_level).ok();

    let (tx, rx) = mpsc::channel::<LogEntry>();
    LOG_SENDER.set(tx).ok();

    let log_dir = get_log_dir(app_name);
    if let Err(e) = std::fs::create_dir_all(&log_dir) {
        eprintln!("Failed to create log directory: {e}");
    }

    thread::Builder::new()
        .name("LoggerThread".into())
        .spawn(move || {
            let mut current_day = String::new();
            let mut file: Option<File> = None;

            for entry in rx {
                let now = Local::now();
                let day_str = now.format("%Y-%m-%d").to_string();

                if day_str != current_day {
                    current_day = day_str;
                    let path = log_dir.join(format!("{}_{}.log", app_lowercase, current_day));
                    file = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&path)
                        .ok();
                }

                let timestamp = now.format("%Y-%m-%d %H:%M:%S.%f");
                let file_line = format!("[{:<5}] {} - {}", entry.level, timestamp, entry.content);

                if let Some(f) = file.as_mut()
                    && let Err(e) = writeln!(f, "{}", file_line)
                {
                    eprintln!("Failed to write to log file: {e}");
                }

                let console_str = format!(
                    "[{:<5}] {} - {}",
                    entry.level.to_string().bold(),
                    timestamp,
                    entry.content
                );
                match entry.level {
                    LogLevel::Trace => println!("{}", console_str.bright_black()),
                    LogLevel::Debug => println!("{}", console_str.bright_green()),
                    LogLevel::Info => println!("{}", console_str.bright_blue()),
                    LogLevel::Warning => println!("{}", console_str.yellow()),
                    LogLevel::Error => println!("{}", console_str.bright_red()),
                    LogLevel::Fatal => println!("{}", console_str.red().bold().on_black()),
                }
            }
        })
        .expect("Failed to spawn logger thread");
}

fn get_log_dir(app_name: &str) -> PathBuf {
    let base_dir = if cfg!(target_os = "windows") {
        std::env::var("APPDATA")
            .map(|p| PathBuf::from(p.replace("Roaming", "LocalLow")))
            .unwrap_or_else(|_| PathBuf::from("."))
    } else {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            PathBuf::from(xdg)
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".local/share")
        } else {
            PathBuf::from(".")
        }
    };

    base_dir.join("Zeevum").join(app_name).join("logs")
}

pub fn log(content: String, level: LogLevel) {
    if let Some(min_level) = LOG_LEVEL.get()
        && level < *min_level
    {
        return;
    }

    if let Some(sender) = LOG_SENDER.get() {
        let _ = sender.send(LogEntry { level, content });
    } else {
        eprintln!("[{level}] (FALLBACK) {content}");
    }
}

#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        $crate::logger::log(format!($($arg)*), $crate::logger::LogLevel::Trace)
    };
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        $crate::logger::log(format!($($arg)*), $crate::logger::LogLevel::Info)
    };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        $crate::logger::log(format!($($arg)*), $crate::logger::LogLevel::Debug)
    };
}

#[macro_export]
macro_rules! warning {
    ($($arg:tt)*) => {
        $crate::logger::log(format!($($arg)*), $crate::logger::LogLevel::Warning)
    };
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::logger::log(format!($($arg)*), $crate::logger::LogLevel::Error)
    };
}

#[macro_export]
#[allow(dead_code)]
macro_rules! fatal {
    ($($arg:tt)*) => {
        $crate::logger::log(format!($($arg)*), $crate::logger::LogLevel::Fatal)
    };
}
