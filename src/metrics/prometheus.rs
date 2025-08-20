// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


//! Prometheus metrics exporter
//!
//! This module provides functionality to export ant-quic metrics in Prometheus format.

use prometheus::{
    Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec, Opts, Registry,
};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::logging::metrics::MetricsCollector;

/// Prometheus metrics exporter
#[derive(Debug)]
pub struct PrometheusExporter {
    /// Prometheus registry
    registry: Registry,
    /// Metrics collector reference
    collector: Arc<MetricsCollector>,

    // Connection metrics
    active_connections: Gauge,
    total_connections: Counter,
    failed_connections: Counter,
    migrated_connections: Counter,

    // Throughput metrics
    bytes_sent_total: Counter,
    bytes_received_total: Counter,
    packets_sent_total: Counter,
    packets_received_total: Counter,

    // Latency metrics
    rtt_histogram: Histogram,

    // NAT traversal metrics
    nat_sessions_active: Gauge,
    nat_coordinations_total: Counter,
    nat_coordination_duration: Histogram,
    nat_bootstrap_nodes: Gauge,

    // Event counters by level and component
    log_events_total: CounterVec,
}

impl PrometheusExporter {
    /// Create a new Prometheus exporter
    pub fn new(collector: Arc<MetricsCollector>) -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        // Connection metrics
        let active_connections = Gauge::with_opts(Opts::new(
            "ant_quic_connections_active",
            "Number of active QUIC connections",
        ))?;
        registry.register(Box::new(active_connections.clone()))?;

        let total_connections = Counter::with_opts(Opts::new(
            "ant_quic_connections_total",
            "Total number of QUIC connections created",
        ))?;
        registry.register(Box::new(total_connections.clone()))?;

        let failed_connections = Counter::with_opts(Opts::new(
            "ant_quic_connections_failed_total",
            "Total number of failed QUIC connections",
        ))?;
        registry.register(Box::new(failed_connections.clone()))?;

        let migrated_connections = Counter::with_opts(Opts::new(
            "ant_quic_connections_migrated_total",
            "Total number of migrated QUIC connections",
        ))?;
        registry.register(Box::new(migrated_connections.clone()))?;

        // Throughput metrics
        let bytes_sent_total = Counter::with_opts(Opts::new(
            "ant_quic_bytes_sent_total",
            "Total bytes sent over QUIC connections",
        ))?;
        registry.register(Box::new(bytes_sent_total.clone()))?;

        let bytes_received_total = Counter::with_opts(Opts::new(
            "ant_quic_bytes_received_total",
            "Total bytes received over QUIC connections",
        ))?;
        registry.register(Box::new(bytes_received_total.clone()))?;

        let packets_sent_total = Counter::with_opts(Opts::new(
            "ant_quic_packets_sent_total",
            "Total packets sent over QUIC connections",
        ))?;
        registry.register(Box::new(packets_sent_total.clone()))?;

        let packets_received_total = Counter::with_opts(Opts::new(
            "ant_quic_packets_received_total",
            "Total packets received over QUIC connections",
        ))?;
        registry.register(Box::new(packets_received_total.clone()))?;

        // Latency metrics
        let rtt_histogram = Histogram::with_opts(
            HistogramOpts::new("ant_quic_rtt_seconds", "Round-trip time in seconds").buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
        )?;
        registry.register(Box::new(rtt_histogram.clone()))?;

        // NAT traversal metrics
        let nat_sessions_active = Gauge::with_opts(Opts::new(
            "ant_quic_nat_sessions_active",
            "Number of active NAT traversal sessions",
        ))?;
        registry.register(Box::new(nat_sessions_active.clone()))?;

        let nat_coordinations_total = Counter::with_opts(Opts::new(
            "ant_quic_nat_coordinations_total",
            "Total number of NAT coordination attempts",
        ))?;
        registry.register(Box::new(nat_coordinations_total.clone()))?;

        let nat_coordination_duration = Histogram::with_opts(
            HistogramOpts::new(
                "ant_quic_nat_coordination_duration_seconds",
                "NAT coordination duration in seconds",
            )
            .buckets(vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0]),
        )?;
        registry.register(Box::new(nat_coordination_duration.clone()))?;

        let nat_bootstrap_nodes = Gauge::with_opts(Opts::new(
            "ant_quic_nat_bootstrap_nodes",
            "Number of known bootstrap nodes",
        ))?;
        registry.register(Box::new(nat_bootstrap_nodes.clone()))?;

        // Log event metrics
        let log_events_total = CounterVec::new(
            Opts::new("ant_quic_log_events_total", "Total number of log events"),
            &["level", "target"],
        )?;
        registry.register(Box::new(log_events_total.clone()))?;

        Ok(Self {
            registry,
            collector,
            active_connections,
            total_connections,
            failed_connections,
            migrated_connections,
            bytes_sent_total,
            bytes_received_total,
            packets_sent_total,
            packets_received_total,
            rtt_histogram,
            nat_sessions_active,
            nat_coordinations_total,
            nat_coordination_duration,
            nat_bootstrap_nodes,
            log_events_total,
        })
    }

    /// Update all Prometheus metrics from the internal metrics collector
    pub fn update_metrics(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let summary = self.collector.summary();

        // Update connection metrics
        let conn_metrics = &summary.connections;
        self.active_connections
            .set(conn_metrics.active_connections as f64);

        // For counters, we need to track the difference since last update
        // For now, we'll set to the total values (this could be improved with state tracking)
        self.total_connections.reset();
        self.total_connections
            .inc_by(conn_metrics.total_connections as f64);

        self.failed_connections.reset();
        self.failed_connections
            .inc_by(conn_metrics.failed_connections as f64);

        self.migrated_connections.reset();
        self.migrated_connections
            .inc_by(conn_metrics.migrated_connections as f64);

        // Update throughput metrics
        let throughput = &summary.throughput;
        self.bytes_sent_total.reset();
        self.bytes_sent_total.inc_by(throughput.bytes_sent as f64);

        self.bytes_received_total.reset();
        self.bytes_received_total
            .inc_by(throughput.bytes_received as f64);

        self.packets_sent_total.reset();
        self.packets_sent_total
            .inc_by(throughput.packets_sent as f64);

        self.packets_received_total.reset();
        self.packets_received_total
            .inc_by(throughput.packets_received as f64);

        // Update latency metrics
        let latency = &summary.latency;
        if latency.sample_count > 0 {
            // Observe the average RTT for the histogram
            let avg_rtt_seconds = latency.avg_rtt.as_secs_f64();
            self.rtt_histogram.observe(avg_rtt_seconds);
        }

        // Update log event metrics
        for ((level, target), count) in &summary.event_counts {
            let level_str = match *level {
                tracing::Level::ERROR => "error",
                tracing::Level::WARN => "warn",
                tracing::Level::INFO => "info",
                tracing::Level::DEBUG => "debug",
                tracing::Level::TRACE => "trace",
            };

            let counter = self
                .log_events_total
                .with_label_values(&[level_str, target]);
            counter.reset();
            counter.inc_by(*count as f64);
        }

        debug!("Updated Prometheus metrics from internal collector");
        Ok(())
    }

    /// Update NAT traversal specific metrics
    pub fn update_nat_metrics(
        &self,
        active_sessions: usize,
        total_coordinations: u64,
        bootstrap_nodes: usize,
    ) {
        self.nat_sessions_active.set(active_sessions as f64);

        self.nat_coordinations_total.reset();
        self.nat_coordinations_total
            .inc_by(total_coordinations as f64);

        self.nat_bootstrap_nodes.set(bootstrap_nodes as f64);

        debug!(
            "Updated NAT traversal metrics: sessions={}, coordinations={}, bootstrap_nodes={}",
            active_sessions, total_coordinations, bootstrap_nodes
        );
    }

    /// Record a NAT coordination duration
    pub fn record_nat_coordination_duration(&self, duration: std::time::Duration) {
        self.nat_coordination_duration
            .observe(duration.as_secs_f64());
    }

    /// Record an RTT measurement
    pub fn record_rtt(&self, rtt: std::time::Duration) {
        self.rtt_histogram.observe(rtt.as_secs_f64());
    }

    /// Get the Prometheus registry
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Gather all metrics in Prometheus text format
    pub fn gather(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        use prometheus::Encoder;

        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();

        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;

        Ok(String::from_utf8(buffer)?)
    }
}

impl Drop for PrometheusExporter {
    fn drop(&mut self) {
        info!("Prometheus exporter shutting down");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_prometheus_exporter_creation() {
        let collector = Arc::new(MetricsCollector::new());
        let exporter = PrometheusExporter::new(collector);
        assert!(exporter.is_ok());
    }

    #[test]
    fn test_metrics_update() {
        let collector = Arc::new(MetricsCollector::new());

        // Add some test data to the collector
        // Note: In a real test, we would need public methods to populate test data
        // For now, we'll just test that the exporter can be created and updated

        let exporter = PrometheusExporter::new(collector).expect("Failed to create exporter");

        // Update metrics should not fail
        assert!(exporter.update_metrics().is_ok());

        // Should be able to gather metrics
        let metrics_text = exporter.gather().expect("Failed to gather metrics");
        assert!(!metrics_text.is_empty());
        assert!(metrics_text.contains("ant_quic_"));
    }

    #[test]
    fn test_nat_metrics_update() {
        let collector = Arc::new(MetricsCollector::new());
        let exporter = PrometheusExporter::new(collector).expect("Failed to create exporter");

        exporter.update_nat_metrics(5, 42, 3);
        exporter.record_nat_coordination_duration(Duration::from_millis(1500));

        let metrics_text = exporter.gather().expect("Failed to gather metrics");
        assert!(metrics_text.contains("ant_quic_nat_"));
    }

    #[test]
    fn test_rtt_recording() {
        let collector = Arc::new(MetricsCollector::new());
        let exporter = PrometheusExporter::new(collector).expect("Failed to create exporter");

        exporter.record_rtt(Duration::from_millis(50));
        exporter.record_rtt(Duration::from_millis(100));

        let metrics_text = exporter.gather().expect("Failed to gather metrics");
        assert!(metrics_text.contains("ant_quic_rtt_seconds"));
    }
}
