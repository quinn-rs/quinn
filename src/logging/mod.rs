// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

/// Comprehensive Logging System for ant-quic
///
/// This module provides structured logging capabilities for debugging,
/// monitoring, and analyzing QUIC connections, NAT traversal, and
/// protocol-level events.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tracing::{Level, Span, debug, error, info, trace, warn};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    ConnectionId, Duration, Instant, Side, connection::nat_traversal::NatTraversalRole,
    frame::FrameType, transport_parameters::TransportParameterId,
};

#[cfg(test)]
mod tests;

mod components;
mod filters;
mod formatters;
mod lifecycle;
/// Metrics collection and reporting utilities
pub mod metrics;
mod structured;

pub use components::*;
pub use filters::*;
pub use formatters::*;
pub use lifecycle::*;
pub use metrics::*;
pub use structured::*;

/// Global logger instance
static LOGGER: once_cell::sync::OnceCell<Arc<Logger>> = once_cell::sync::OnceCell::new();

/// Initialize the logging system
pub fn init_logging(config: LoggingConfig) -> Result<(), LoggingError> {
    let logger = Arc::new(Logger::new(config)?);

    LOGGER
        .set(logger.clone())
        .map_err(|_| LoggingError::AlreadyInitialized)?;

    // Initialize tracing subscriber
    let env_filter = EnvFilter::from_default_env().add_directive("ant_quic=debug".parse().unwrap());

    if logger.use_json() {
        let fmt_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_target(true)
            .with_thread_ids(true)
            .with_level(true);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();
    } else {
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_thread_ids(true)
            .with_level(true);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();
    }

    info!("ant-quic logging system initialized");
    Ok(())
}

/// Get the global logger instance
pub fn logger() -> Arc<Logger> {
    LOGGER.get().cloned().unwrap_or_else(|| {
        // Create default logger if not initialized
        let config = LoggingConfig::default();
        let logger = Arc::new(Logger::new(config).expect("Failed to create default logger"));
        let _ = LOGGER.set(logger.clone());
        logger
    })
}

/// Main logger struct
pub struct Logger {
    config: LoggingConfig,
    metrics_collector: Arc<MetricsCollector>,
    event_buffer: Arc<Mutex<Vec<LogEvent>>>,
    rate_limiter: Arc<RateLimiter>,
}

impl Logger {
    /// Create a new logger with the given configuration
    pub fn new(config: LoggingConfig) -> Result<Self, LoggingError> {
        let rate_limit = config.rate_limit_per_second;
        let buffer_size = config.event_buffer_size;
        Ok(Self {
            config,
            metrics_collector: Arc::new(MetricsCollector::new()),
            event_buffer: Arc::new(Mutex::new(Vec::with_capacity(buffer_size))),
            rate_limiter: Arc::new(RateLimiter::new(rate_limit, Duration::from_secs(1))),
        })
    }

    /// Check if JSON output is enabled
    fn use_json(&self) -> bool {
        self.config.json_output
    }

    /// Log a structured event
    pub fn log_event(&self, event: LogEvent) {
        if !self.rate_limiter.should_log(event.level) {
            return;
        }

        // Add to buffer for analysis
        if let Ok(mut buffer) = self.event_buffer.lock() {
            if buffer.len() < 10000 {
                buffer.push(event.clone());
            }
        }

        // Log using tracing
        match event.level {
            Level::ERROR => error!("{} - {}", event.target, event.message),
            Level::WARN => warn!("{} - {}", event.target, event.message),
            Level::INFO => info!("{} - {}", event.target, event.message),
            Level::DEBUG => debug!("{} - {}", event.target, event.message),
            Level::TRACE => trace!("{} - {}", event.target, event.message),
        }

        // Update metrics
        self.metrics_collector.record_event(&event);
    }

    /// Get recent events for analysis
    pub fn recent_events(&self, count: usize) -> Vec<LogEvent> {
        match self.event_buffer.lock() {
            Ok(buffer) => buffer.iter().rev().take(count).cloned().collect(),
            _ => Vec::new(),
        }
    }

    /// Get metrics summary
    pub fn metrics_summary(&self) -> MetricsSummary {
        self.metrics_collector.summary()
    }
}

/// Logging configuration
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// Enable JSON output format
    pub json_output: bool,
    /// Rate limit per second
    pub rate_limit_per_second: u64,
    /// Component-specific log levels
    pub component_levels: HashMap<String, Level>,
    /// Enable performance metrics collection
    pub collect_metrics: bool,
    /// Buffer size for event storage
    pub event_buffer_size: usize,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            json_output: false,
            rate_limit_per_second: 1000,
            component_levels: HashMap::new(),
            collect_metrics: true,
            event_buffer_size: 10000,
        }
    }
}

/// Structured log event
#[derive(Debug, Clone)]
pub struct LogEvent {
    /// Time the log was recorded
    pub timestamp: Instant,
    /// Severity level of the log
    pub level: Level,
    /// Target component/module of the log
    pub target: String,
    /// Primary message content
    pub message: String,
    /// Arbitrary structured fields
    pub fields: HashMap<String, String>,
    /// Optional span identifier for tracing correlation
    pub span_id: Option<String>,
}

/// Connection role for logging
#[derive(Debug, Clone, Copy)]
pub enum ConnectionRole {
    /// Client-side role
    Client,
    /// Server-side role
    Server,
}

/// Connection information for logging
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Connection identifier
    pub id: ConnectionId,
    /// Remote socket address
    pub remote_addr: SocketAddr,
    /// Role of the connection
    pub role: ConnectionRole,
}

/// Frame information for logging
#[derive(Debug)]
pub struct FrameInfo {
    /// QUIC frame type
    pub frame_type: FrameType,
    /// Encoded frame size in bytes
    pub size: usize,
    /// Optional packet number the frame was carried in
    pub packet_number: Option<u64>,
}

/// Transport parameter information
#[derive(Debug)]
pub struct TransportParamInfo {
    pub(crate) param_id: TransportParameterId,
    /// Raw value bytes, if present
    pub value: Option<Vec<u8>>,
    /// Which side (client/server) provided the parameter
    pub side: Side,
}

/// NAT traversal information
#[derive(Debug)]
pub struct NatTraversalInfo {
    /// NAT traversal role of this endpoint
    pub role: NatTraversalRole,
    /// Remote peer address involved in NAT traversal
    pub remote_addr: SocketAddr,
    /// Number of candidate addresses considered
    pub candidate_count: usize,
}

/// Error context for detailed logging
#[derive(Debug, Default)]
pub struct ErrorContext {
    /// Component name related to the error
    pub component: &'static str,
    /// Operation being performed when the error occurred
    pub operation: &'static str,
    /// Optional connection identifier involved
    pub connection_id: Option<ConnectionId>,
    /// Additional static key/value fields for context
    pub additional_fields: Vec<(&'static str, &'static str)>,
}

/// Warning context
#[derive(Debug, Default)]
pub struct WarningContext {
    /// Component name related to the warning
    pub component: &'static str,
    /// Additional static key/value fields for context
    pub details: Vec<(&'static str, &'static str)>,
}

/// Info context
#[derive(Debug, Default)]
pub struct InfoContext {
    /// Component name related to the information
    pub component: &'static str,
    /// Additional static key/value fields for context
    pub details: Vec<(&'static str, &'static str)>,
}

/// Debug context
#[derive(Debug, Default)]
pub struct DebugContext {
    /// Component name related to the debug message
    pub component: &'static str,
    /// Additional static key/value fields for context
    pub details: Vec<(&'static str, &'static str)>,
}

/// Trace context
#[derive(Debug, Default)]
pub struct TraceContext {
    /// Component name related to the trace message
    pub component: &'static str,
    /// Additional static key/value fields for context
    pub details: Vec<(&'static str, &'static str)>,
}

/// Logging errors
#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    /// Attempted to initialize the logging system more than once
    #[error("Logging system already initialized")]
    AlreadyInitialized,
    /// Error returned from tracing subscriber initialization
    #[error("Failed to initialize tracing subscriber: {0}")]
    SubscriberError(String),
}

/// Rate limiter for preventing log spam
pub struct RateLimiter {
    /// Maximum events allowed per window
    max_events: u64,
    /// Length of the rate-limiting window
    window: Duration,
    /// Number of events counted in the current window
    events_in_window: AtomicU64,
    /// Start time of the current window
    window_start: Mutex<Instant>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(max_events: u64, window: Duration) -> Self {
        Self {
            max_events,
            window,
            events_in_window: AtomicU64::new(0),
            window_start: Mutex::new(Instant::now()),
        }
    }

    /// Determine whether an event at the given level should be logged
    pub fn should_log(&self, level: Level) -> bool {
        // Always allow ERROR level
        if level == Level::ERROR {
            return true;
        }

        let now = Instant::now();
        let mut window_start = self.window_start.lock().unwrap();

        // Reset window if expired
        if now.duration_since(*window_start) > self.window {
            *window_start = now;
            self.events_in_window.store(0, Ordering::Relaxed);
        }

        // Check rate limit
        let current = self.events_in_window.fetch_add(1, Ordering::Relaxed);
        current < self.max_events
    }
}

// Convenience logging functions

/// Log an error with context
pub fn log_error(message: &str, context: ErrorContext) {
    let mut fields = HashMap::new();
    fields.insert("component".to_string(), context.component.to_string());
    fields.insert("operation".to_string(), context.operation.to_string());

    if let Some(conn_id) = context.connection_id {
        fields.insert("conn_id".to_string(), format!("{conn_id:?}"));
    }

    for (key, value) in context.additional_fields {
        fields.insert(key.to_string(), value.to_string());
    }

    logger().log_event(LogEvent {
        timestamp: Instant::now(),
        level: Level::ERROR,
        target: format!("ant_quic::{}", context.component),
        message: message.to_string(),
        fields,
        span_id: None,
    });
}

/// Log a warning
pub fn log_warning(message: &str, context: WarningContext) {
    let mut fields = HashMap::new();
    fields.insert("component".to_string(), context.component.to_string());

    for (key, value) in context.details {
        fields.insert(key.to_string(), value.to_string());
    }

    logger().log_event(LogEvent {
        timestamp: Instant::now(),
        level: Level::WARN,
        target: format!("ant_quic::{}", context.component),
        message: message.to_string(),
        fields,
        span_id: None,
    });
}

/// Log info message
pub fn log_info(message: &str, context: InfoContext) {
    let mut fields = HashMap::new();
    fields.insert("component".to_string(), context.component.to_string());

    for (key, value) in context.details {
        fields.insert(key.to_string(), value.to_string());
    }

    logger().log_event(LogEvent {
        timestamp: Instant::now(),
        level: Level::INFO,
        target: format!("ant_quic::{}", context.component),
        message: message.to_string(),
        fields,
        span_id: None,
    });
}

/// Log debug message
pub fn log_debug(message: &str, context: DebugContext) {
    let mut fields = HashMap::new();
    fields.insert("component".to_string(), context.component.to_string());

    for (key, value) in context.details {
        fields.insert(key.to_string(), value.to_string());
    }

    logger().log_event(LogEvent {
        timestamp: Instant::now(),
        level: Level::DEBUG,
        target: format!("ant_quic::{}", context.component),
        message: message.to_string(),
        fields,
        span_id: None,
    });
}

/// Log trace message
pub fn log_trace(message: &str, context: TraceContext) {
    let mut fields = HashMap::new();
    fields.insert("component".to_string(), context.component.to_string());

    for (key, value) in context.details {
        fields.insert(key.to_string(), value.to_string());
    }

    logger().log_event(LogEvent {
        timestamp: Instant::now(),
        level: Level::TRACE,
        target: format!("ant_quic::{}", context.component),
        message: message.to_string(),
        fields,
        span_id: None,
    });
}

/// Create a span for connection operations
pub fn create_connection_span(conn_id: &ConnectionId) -> Span {
    tracing::span!(
        Level::DEBUG,
        "connection",
        conn_id = %format!("{:?}", conn_id),
    )
}

/// Create a span for frame processing
pub fn create_frame_span(frame_type: FrameType) -> Span {
    tracing::span!(
        Level::TRACE,
        "frame",
        frame_type = ?frame_type,
    )
}
