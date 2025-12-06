#[cfg(feature = "qlog")]
use std::io;
use std::{io::BufWriter, net::SocketAddr, path::PathBuf, time::SystemTime};

use tracing::{trace, warn};

use crate::{ConnectionId, Instant, Side};

/// Constructs a [`QlogConfig`] for individual connections.
///
/// This is set via [`TransportConfig::qlog_factory`].
///
/// [`TransportConfig::qlog_factory]: crate::config::TransportConfig::qlog_factory
pub trait QlogFactory: Send + Sync + 'static {
    /// Returns a [`QlogConfig`] for a connection, if logging should be enabled.
    ///
    /// If `None` is returned, qlog capture is disabled for the connection.
    fn for_connection(
        &self,
        side: Side,
        remote: SocketAddr,
        initial_dst_cid: ConnectionId,
        now: Instant,
    ) -> Option<QlogConfig>;
}

/// Configuration for qlog trace logging.
///
/// This struct is returned from [`QlogFactory::for_connection`] if qlog logging should
/// be enabled for a connection. It allows to set metadata for the qlog trace.
///
/// The trace will be written to the provided writer in the [`JSON-SEQ format`] defined in the qlog spec.
///
/// [`JSON-SEQ format`](https://www.ietf.org/archive/id/draft-ietf-quic-qlog-main-schema-13.html#section-5)
#[cfg(feature = "qlog")]
pub struct QlogConfig {
    pub(crate) writer: Box<dyn io::Write + Send + Sync>,
    pub(crate) title: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) start_time: Option<Instant>,
}

#[cfg(feature = "qlog")]
impl QlogConfig {
    /// Creates a new [`QlogConfig`] that writes a qlog trace to the specified `writer`.
    pub fn new(writer: Box<dyn io::Write + Send + Sync>) -> Self {
        Self {
            writer,
            title: None,
            description: None,
            start_time: None,
        }
    }

    /// Title to record in the qlog capture
    pub fn title(&mut self, title: Option<String>) -> &mut Self {
        self.title = title;
        self
    }

    /// Description to record in the qlog capture
    pub fn description(&mut self, description: Option<String>) -> &mut Self {
        self.description = description;
        self
    }

    /// Epoch qlog event times are recorded relative to
    ///
    /// If unset, the start of the connection is used.
    pub fn start_time(&mut self, start_time: Instant) -> &mut Self {
        self.start_time = Some(start_time);
        self
    }
}

/// Enables writing qlog traces to a directory.
#[derive(Debug)]
pub struct QlogFileFactory {
    dir: Option<PathBuf>,
    prefix: Option<String>,
    start_instant: Option<Instant>,
}

impl QlogFileFactory {
    /// Creates a new qlog factory that writes files into the specified directory.
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir: Some(dir),
            prefix: None,
            start_instant: None,
        }
    }

    /// Creates a new qlog factory that writes files into `QLOGDIR`, if set.
    ///
    /// If the environment variable `QLOGDIR` is set, qlog traces for all connections handled
    /// by this endpoint will be written into that directory.
    /// If the directory doesn't exist it will be created.
    pub fn from_env() -> Self {
        let dir = match std::env::var("QLOGDIR") {
            Ok(dir) => {
                if let Err(err) = std::fs::create_dir_all(&dir) {
                    warn!("qlog not enabled: failed to create qlog directory at {dir}: {err}",);
                    None
                } else {
                    Some(PathBuf::from(dir))
                }
            }
            Err(_) => None,
        };
        Self {
            dir,
            prefix: None,
            start_instant: None,
        }
    }

    /// Sets a prefix to the filename of the generated files.
    pub fn with_prefix(mut self, prefix: impl ToString) -> Self {
        self.prefix = Some(prefix.to_string());
        self
    }

    /// Override the instant relative to which all events are recorded.
    ///
    /// If not set, events will be recorded relative to the start of the connection.
    pub fn with_start_instant(mut self, start: Instant) -> Self {
        self.start_instant = Some(start);
        self
    }
}

impl QlogFactory for QlogFileFactory {
    fn for_connection(
        &self,
        side: Side,
        _remote: SocketAddr,
        initial_dst_cid: ConnectionId,
        now: Instant,
    ) -> Option<QlogConfig> {
        let dir = self.dir.as_ref()?;

        let name = {
            let timestamp = SystemTime::now()
                .checked_sub(Instant::now().duration_since(now))?
                .duration_since(SystemTime::UNIX_EPOCH)
                .ok()?
                .as_millis();
            let prefix = self
                .prefix
                .as_ref()
                .filter(|prefix| !prefix.is_empty())
                .map(|prefix| format!("{prefix}-"))
                .unwrap_or_default();
            let side = format!("{side:?}").to_lowercase();
            format!("{prefix}{timestamp}-{initial_dst_cid}-{side}.qlog")
        };
        let path = dir.join(name);
        let file = std::fs::File::create(&path)
            .inspect_err(|err| warn!("Failed to create qlog file at {}: {err}", path.display()))
            .ok()?;
        trace!(
            "Initialized qlog file for connection {initial_dst_cid} at {}",
            path.display()
        );
        let writer = BufWriter::new(file);
        let mut config = QlogConfig::new(Box::new(writer));
        if let Some(instant) = self.start_instant {
            config.start_time(instant);
        }
        Some(config)
    }
}
