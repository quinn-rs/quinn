/// Performance metrics collection and logging
///
/// Tracks and logs performance metrics for monitoring and optimization
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::{LogEvent, logger};
use crate::{Duration, Instant};

/// Metrics collector for performance tracking
#[derive(Debug)]
pub struct MetricsCollector {
    /// Event counts by level and component
    event_counts: Arc<Mutex<HashMap<(tracing::Level, String), u64>>>,
    /// Throughput metrics
    throughput: Arc<ThroughputTracker>,
    /// Latency metrics
    latency: Arc<LatencyTracker>,
    /// Connection metrics
    connections: Arc<ConnectionMetrics>,
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            event_counts: Arc::new(Mutex::new(HashMap::new())),
            throughput: Arc::new(ThroughputTracker::new()),
            latency: Arc::new(LatencyTracker::new()),
            connections: Arc::new(ConnectionMetrics::new()),
        }
    }

    /// Record a log event for metrics
    pub fn record_event(&self, event: &LogEvent) {
        if let Ok(mut counts) = self.event_counts.lock() {
            let key = (event.level, event.target.clone());
            *counts.entry(key).or_insert(0) += 1;
        }
    }

    /// Get a summary of collected metrics
    pub fn summary(&self) -> MetricsSummary {
        let event_counts = self
            .event_counts
            .lock()
            .map(|counts| counts.clone())
            .unwrap_or_default();

        MetricsSummary {
            event_counts,
            throughput: self.throughput.summary(),
            latency: self.latency.summary(),
            connections: self.connections.summary(),
        }
    }
}

/// Throughput tracking
#[derive(Debug)]
pub struct ThroughputTracker {
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
    start_time: Instant,
}

impl Default for ThroughputTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ThroughputTracker {
    pub fn new() -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    pub fn record_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        self.packets_received.fetch_add(1, Ordering::Relaxed);
    }

    pub fn summary(&self) -> ThroughputSummary {
        let duration = self.start_time.elapsed();
        let duration_secs = duration.as_secs_f64();

        let bytes_sent = self.bytes_sent.load(Ordering::Relaxed);
        let bytes_received = self.bytes_received.load(Ordering::Relaxed);

        ThroughputSummary {
            bytes_sent,
            bytes_received,
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            duration,
            send_rate_mbps: (bytes_sent as f64 * 8.0) / (duration_secs * 1_000_000.0),
            recv_rate_mbps: (bytes_received as f64 * 8.0) / (duration_secs * 1_000_000.0),
        }
    }
}

/// Latency tracking
#[derive(Debug)]
pub struct LatencyTracker {
    samples: Arc<Mutex<Vec<Duration>>>,
    min_rtt: AtomicU64, // microseconds
    max_rtt: AtomicU64, // microseconds
    sum_rtt: AtomicU64, // microseconds
    count: AtomicU64,
}

impl Default for LatencyTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl LatencyTracker {
    pub fn new() -> Self {
        Self {
            samples: Arc::new(Mutex::new(Vec::with_capacity(1000))),
            min_rtt: AtomicU64::new(u64::MAX),
            max_rtt: AtomicU64::new(0),
            sum_rtt: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    pub fn record_rtt(&self, rtt: Duration) {
        let micros = rtt.as_micros() as u64;

        // Update min
        let mut current_min = self.min_rtt.load(Ordering::Relaxed);
        while micros < current_min {
            match self.min_rtt.compare_exchange_weak(
                current_min,
                micros,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => current_min = x,
            }
        }

        // Update max
        let mut current_max = self.max_rtt.load(Ordering::Relaxed);
        while micros > current_max {
            match self.max_rtt.compare_exchange_weak(
                current_max,
                micros,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => current_max = x,
            }
        }

        // Update sum and count
        self.sum_rtt.fetch_add(micros, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        // Store sample
        if let Ok(mut samples) = self.samples.lock() {
            if samples.len() < 1000 {
                samples.push(rtt);
            }
        }
    }

    pub fn summary(&self) -> LatencySummary {
        let count = self.count.load(Ordering::Relaxed);
        let min_rtt = self.min_rtt.load(Ordering::Relaxed);

        LatencySummary {
            min_rtt: if min_rtt == u64::MAX {
                Duration::from_micros(0)
            } else {
                Duration::from_micros(min_rtt)
            },
            max_rtt: Duration::from_micros(self.max_rtt.load(Ordering::Relaxed)),
            avg_rtt: if count > 0 {
                Duration::from_micros(self.sum_rtt.load(Ordering::Relaxed) / count)
            } else {
                Duration::from_micros(0)
            },
            sample_count: count,
        }
    }
}

/// Connection metrics
#[derive(Debug)]
pub struct ConnectionMetrics {
    active_connections: AtomicUsize,
    total_connections: AtomicU64,
    failed_connections: AtomicU64,
    migrated_connections: AtomicU64,
}

impl Default for ConnectionMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionMetrics {
    pub fn new() -> Self {
        Self {
            active_connections: AtomicUsize::new(0),
            total_connections: AtomicU64::new(0),
            failed_connections: AtomicU64::new(0),
            migrated_connections: AtomicU64::new(0),
        }
    }

    pub fn connection_opened(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn connection_closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn connection_failed(&self) {
        self.failed_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn connection_migrated(&self) {
        self.migrated_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn summary(&self) -> ConnectionMetricsSummary {
        ConnectionMetricsSummary {
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            failed_connections: self.failed_connections.load(Ordering::Relaxed),
            migrated_connections: self.migrated_connections.load(Ordering::Relaxed),
        }
    }
}

/// Metrics summary
#[derive(Debug, Clone)]
pub struct MetricsSummary {
    pub event_counts: HashMap<(tracing::Level, String), u64>,
    pub throughput: ThroughputSummary,
    pub latency: LatencySummary,
    pub connections: ConnectionMetricsSummary,
}

/// Throughput metrics
#[derive(Debug, Clone)]
pub struct ThroughputMetrics {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub duration: Duration,
    pub packets_sent: u64,
    pub packets_received: u64,
}

/// Throughput summary
#[derive(Debug, Clone)]
pub struct ThroughputSummary {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub duration: Duration,
    pub send_rate_mbps: f64,
    pub recv_rate_mbps: f64,
}

/// Latency metrics
#[derive(Debug, Clone)]
pub struct LatencyMetrics {
    pub rtt: Duration,
    pub min_rtt: Duration,
    pub max_rtt: Duration,
    pub smoothed_rtt: Duration,
}

/// Latency summary
#[derive(Debug, Clone)]
pub struct LatencySummary {
    pub min_rtt: Duration,
    pub max_rtt: Duration,
    pub avg_rtt: Duration,
    pub sample_count: u64,
}

/// Connection metrics summary
#[derive(Debug, Clone)]
pub struct ConnectionMetricsSummary {
    pub active_connections: usize,
    pub total_connections: u64,
    pub failed_connections: u64,
    pub migrated_connections: u64,
}

/// Log throughput metrics
pub fn log_throughput_metrics(metrics: &ThroughputMetrics) {
    let duration_secs = metrics.duration.as_secs_f64();
    let send_rate_mbps = (metrics.bytes_sent as f64 * 8.0) / (duration_secs * 1_000_000.0);
    let recv_rate_mbps = (metrics.bytes_received as f64 * 8.0) / (duration_secs * 1_000_000.0);

    let mut fields = HashMap::new();
    fields.insert("bytes_sent".to_string(), metrics.bytes_sent.to_string());
    fields.insert(
        "bytes_received".to_string(),
        metrics.bytes_received.to_string(),
    );
    fields.insert("packets_sent".to_string(), metrics.packets_sent.to_string());
    fields.insert(
        "packets_received".to_string(),
        metrics.packets_received.to_string(),
    );
    fields.insert(
        "duration_ms".to_string(),
        metrics.duration.as_millis().to_string(),
    );
    fields.insert("send_rate_mbps".to_string(), format!("{send_rate_mbps:.2}"));
    fields.insert("recv_rate_mbps".to_string(), format!("{recv_rate_mbps:.2}"));

    logger().log_event(LogEvent {
        timestamp: Instant::now(),
        level: tracing::Level::INFO,
        target: "ant_quic::metrics::throughput".to_string(),
        message: "throughput_metrics".to_string(),
        fields,
        span_id: None,
    });
}

/// Log latency metrics
pub fn log_latency_metrics(metrics: &LatencyMetrics) {
    let mut fields = HashMap::new();
    fields.insert("rtt_ms".to_string(), metrics.rtt.as_millis().to_string());
    fields.insert(
        "min_rtt_ms".to_string(),
        metrics.min_rtt.as_millis().to_string(),
    );
    fields.insert(
        "max_rtt_ms".to_string(),
        metrics.max_rtt.as_millis().to_string(),
    );
    fields.insert(
        "smoothed_rtt_ms".to_string(),
        metrics.smoothed_rtt.as_millis().to_string(),
    );

    logger().log_event(LogEvent {
        timestamp: Instant::now(),
        level: tracing::Level::INFO,
        target: "ant_quic::metrics::latency".to_string(),
        message: "latency_metrics".to_string(),
        fields,
        span_id: None,
    });
}
