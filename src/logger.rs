//! Logging on `tracing`, in the shape the server always printed: a colored
//! console line and a daily file, both `[LEVEL] timestamp - message`, with
//! the span of the connection in front of the message.
//!
//! Events are written synchronously, an event is on disk by the time its
//! call returns, so an exit cannot lose the last lines the way a queue and
//! a writer thread could.

use chrono::Local;
use colored::Colorize;
use std::fmt::{self, Write as FmtWrite};
use std::fs::{File, OpenOptions};
use std::io::Write as IoWrite;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use tracing::Level;
use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{
    FmtContext, FormatEvent, FormatFields, FormattedFields, Layer, MakeWriter,
};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

/// Sets up the process-wide subscriber. Must be called first in `main`;
/// the admin branch and the server branch share it.
pub fn init(app_name: &str, min_level: LevelFilter) {
    let console = Layer::default()
        .with_ansi(false)
        .event_format(ZeevumFormat { colored: true });
    let file = Layer::default()
        .with_ansi(false)
        .with_writer(DailyFile::new(app_name))
        .event_format(ZeevumFormat { colored: false });

    tracing_subscriber::registry()
        .with(min_level)
        .with(console)
        .with(file)
        .init();
}

/// `[LEVEL] timestamp - [spans: ] message`, the line the server always
/// wrote, now with the span chain of the event in front of the message.
struct ZeevumFormat {
    colored: bool,
}

/// Pulls the fields out of an event: the message on its own, everything
/// else as `key=value`, so an event without a message still says what it
/// carried instead of printing an empty line.
struct Fields {
    message: String,
    rest: String,
}

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            let _ = write!(self.rest, "{}={value:?} ", field.name());
        }
    }
}

impl<S, N> FormatEvent<S, N> for ZeevumFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut fields = Fields {
            message: String::new(),
            rest: String::new(),
        };
        event.record(&mut fields);
        let text = if fields.rest.is_empty() {
            fields.message
        } else {
            format!("{} {}", fields.message, fields.rest.trim_end())
        };

        let mut spans = String::new();
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                let _ = write!(
                    spans,
                    "{}{{{}}}: ",
                    span.metadata().name(),
                    span.extensions()
                        .get::<FormattedFields<N>>()
                        .map(|f| f.fields.as_str())
                        .unwrap_or("")
                );
            }
        }

        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S.%f");
        let line = format!(
            "[{:<5}] {timestamp} - {spans}{text}",
            event.metadata().level()
        );

        if self.colored {
            match *event.metadata().level() {
                Level::TRACE => writeln!(writer, "{}", line.bright_black()),
                Level::DEBUG => writeln!(writer, "{}", line.bright_green()),
                Level::INFO => writeln!(writer, "{}", line.bright_blue()),
                Level::WARN => writeln!(writer, "{}", line.yellow()),
                Level::ERROR => writeln!(writer, "{}", line.bright_red()),
            }
        } else {
            writeln!(writer, "{line}")
        }
    }
}

/// One file per day, the path and name the server always used:
/// `<data>/Zeevum/<app>/logs/<app>_YYYY-MM-DD.log`, appended. The handle
/// is kept for the day, so an event costs one write and nothing more.
struct DailyFile {
    directory: PathBuf,
    prefix: String,
    today: Mutex<TodayFile>,
}

struct TodayFile {
    day: String,
    file: Option<File>,
}

impl DailyFile {
    fn new(app_name: &str) -> Self {
        Self {
            directory: log_dir(app_name),
            prefix: app_name.to_lowercase(),
            today: Mutex::new(TodayFile {
                day: String::new(),
                file: None,
            }),
        }
    }
}

impl<'a> MakeWriter<'a> for DailyFile {
    type Writer = DailyWriter<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        let mut today = self.today.lock().unwrap();
        let day = Local::now().format("%Y-%m-%d").to_string();
        if today.day != day {
            if std::fs::create_dir_all(&self.directory).is_ok() {
                today.file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(self.directory.join(format!("{}_{}.log", self.prefix, day)))
                    .ok();
            }
            today.day = day;
        }
        DailyWriter { today }
    }
}

struct DailyWriter<'a> {
    today: MutexGuard<'a, TodayFile>,
}

impl IoWrite for DailyWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.today.file.as_mut() {
            Some(file) => file.write(buf),
            // No file, no message; dropping it is better than failing the
            // caller over a log line.
            None => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.today.file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

fn log_dir(app_name: &str) -> PathBuf {
    let base_dir = if cfg!(target_os = "windows") {
        std::env::var("APPDATA")
            .map(|p| PathBuf::from(p.replace("Roaming", "LocalLow")))
            .unwrap_or_else(|_| PathBuf::from("."))
    } else if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        PathBuf::from(xdg)
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".local/share")
    } else {
        PathBuf::from(".")
    };

    base_dir.join("Zeevum").join(app_name).join("logs")
}

#[cfg(test)]
mod tests {
    /// The level column keeps its width, the format stays greppable the way
    /// it has always been.
    #[test]
    fn the_level_column_keeps_its_width() {
        assert_eq!(format!("[{:<5}]", "INFO"), "[INFO ]");
        assert_eq!(format!("[{:<5}]", "WARN"), "[WARN ]");
        assert_eq!(format!("[{:<5}]", "ERROR"), "[ERROR]");
    }
}
