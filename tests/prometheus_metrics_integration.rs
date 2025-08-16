//! Integration tests for Prometheus metrics functionality
//!
//! These tests verify that the metrics system works correctly with the prometheus feature.

#![cfg(feature = "prometheus")]

use ant_quic::{
    logging::metrics::MetricsCollector,
    metrics::{MetricsConfig, MetricsServer, PrometheusExporter},
    logging::LogEvent,
};
use std::{net::IpAddr, sync::Arc, time::Duration};

#[tokio::test]
async fn test_prometheus_exporter_basic_functionality() {
    // Create a metrics collector
    let collector = Arc::new(MetricsCollector::new());
    
    // Simulate some log events to populate the metrics
    let log_event = LogEvent {
        timestamp: std::time::Instant::now(),
        level: tracing::Level::INFO,
        target: "ant_quic::test".to_string(),
        message: "Test message".to_string(),
        fields: std::collections::HashMap::new(),
        span_id: None,
    };
    
    collector.record_event(&log_event);
    
    // Create Prometheus exporter
    let exporter = PrometheusExporter::new(collector)
        .expect("Failed to create Prometheus exporter");
    
    // Update metrics from collector
    exporter.update_metrics()
        .expect("Failed to update metrics");
    
    // Gather metrics
    let metrics_text = exporter.gather()
        .expect("Failed to gather metrics");
    
    // Verify metrics are present
    assert!(!metrics_text.is_empty());
    assert!(metrics_text.contains("ant_quic_"));
    assert!(metrics_text.contains("ant_quic_log_events_total"));
}

#[tokio::test]
async fn test_metrics_server_disabled() {
    let config = MetricsConfig {
        enabled: false,
        port: 9090,
        bind_address: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        update_interval: Duration::from_secs(30),
    };
    
    let mut server = MetricsServer::new(config);
    
    // Should succeed without starting actual server
    assert!(server.start().await.is_ok());
    
    // Stop should also succeed
    server.stop().await;
}

#[tokio::test]
async fn test_metrics_config_default() {
    let config = MetricsConfig::default();
    
    assert!(!config.enabled);
    assert_eq!(config.port, 9090);
    assert_eq!(config.bind_address, IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));
    assert_eq!(config.update_interval, Duration::from_secs(30));
}

#[tokio::test]
async fn test_prometheus_exporter_nat_metrics() {
    let collector = Arc::new(MetricsCollector::new());
    let exporter = PrometheusExporter::new(collector)
        .expect("Failed to create Prometheus exporter");
    
    // Update NAT metrics directly (these are public methods)
    exporter.update_nat_metrics(3, 42, 2);
    exporter.record_nat_coordination_duration(Duration::from_millis(1500));
    
    // Gather metrics
    let metrics_text = exporter.gather()
        .expect("Failed to gather metrics");
    
    // Verify NAT metrics
    assert!(metrics_text.contains("ant_quic_nat_sessions_active"));
    assert!(metrics_text.contains("ant_quic_nat_coordinations_total"));
    assert!(metrics_text.contains("ant_quic_nat_coordination_duration_seconds"));
    assert!(metrics_text.contains("ant_quic_nat_bootstrap_nodes"));
    
    // Check values
    assert!(metrics_text.contains("ant_quic_nat_sessions_active 3"));
    assert!(metrics_text.contains("ant_quic_nat_coordinations_total 42"));
    assert!(metrics_text.contains("ant_quic_nat_bootstrap_nodes 2"));
}

#[tokio::test]
async fn test_prometheus_exporter_rtt_recording() {
    let collector = Arc::new(MetricsCollector::new());
    let exporter = PrometheusExporter::new(collector)
        .expect("Failed to create Prometheus exporter");
    
    // Record multiple RTT measurements directly
    exporter.record_rtt(Duration::from_millis(50));
    exporter.record_rtt(Duration::from_millis(100));
    exporter.record_rtt(Duration::from_millis(75));
    
    // Gather metrics
    let metrics_text = exporter.gather()
        .expect("Failed to gather metrics");
    
    // Verify RTT histogram is present
    assert!(metrics_text.contains("ant_quic_rtt_seconds_bucket"));
    assert!(metrics_text.contains("ant_quic_rtt_seconds_count"));
    assert!(metrics_text.contains("ant_quic_rtt_seconds_sum"));
    
    // Should have recorded 3 measurements
    assert!(metrics_text.contains("ant_quic_rtt_seconds_count 3"));
}

#[tokio::test]
async fn test_metrics_server_creation_and_shutdown() {
    let config = MetricsConfig {
        enabled: true,
        port: 0, // Use any available port
        bind_address: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        update_interval: Duration::from_secs(30),
    };
    
    let collector = Arc::new(MetricsCollector::new());
    let exporter = Arc::new(
        PrometheusExporter::new(collector)
            .expect("Failed to create Prometheus exporter")
    );
    
    let mut server = MetricsServer::new(config);
    server.set_exporter(exporter).await;
    
    // Since we can't easily test the actual HTTP server without complex setup,
    // we'll just verify that the server can be created and configured
    assert!(server.config().enabled);
    
    // Test graceful shutdown
    server.stop().await;
}

/// Test that compilation works without prometheus feature
#[cfg(not(feature = "prometheus"))]
#[tokio::test]
async fn test_compilation_without_prometheus_feature() {
    // This test just verifies that the code compiles without the prometheus feature
    // The metrics module should still be available but without Prometheus functionality
    use ant_quic::metrics::MetricsConfig;
    
    let _config = MetricsConfig::default();
    // This should compile but MetricsServer and PrometheusExporter won't be available
}

#[tokio::test] 
async fn test_metrics_exporter_with_log_events() {
    let collector = Arc::new(MetricsCollector::new());
    
    // Simulate some log events by directly calling the collector
    let log_event = LogEvent {
        timestamp: std::time::Instant::now(),
        level: tracing::Level::INFO,
        target: "ant_quic::test".to_string(),
        message: "Test message".to_string(),
        fields: std::collections::HashMap::new(),
        span_id: None,
    };
    
    collector.record_event(&log_event);
    
    let exporter = PrometheusExporter::new(collector)
        .expect("Failed to create Prometheus exporter");
    
    exporter.update_metrics()
        .expect("Failed to update metrics");
    
    let metrics_text = exporter.gather()
        .expect("Failed to gather metrics");
    
    // Verify log event metrics
    assert!(metrics_text.contains("ant_quic_log_events_total"));
    assert!(metrics_text.contains("level=\"info\""));
    assert!(metrics_text.contains("target=\"ant_quic::test\""));
}

#[tokio::test]
async fn test_metrics_persistence_across_updates() {
    let collector = Arc::new(MetricsCollector::new());
    let exporter = PrometheusExporter::new(collector.clone())
        .expect("Failed to create Prometheus exporter");
    
    // Add initial log events
    let log_event1 = LogEvent {
        timestamp: std::time::Instant::now(),
        level: tracing::Level::INFO,
        target: "ant_quic::test".to_string(),
        message: "First message".to_string(),
        fields: std::collections::HashMap::new(),
        span_id: None,
    };
    
    collector.record_event(&log_event1);
    exporter.update_metrics().expect("Failed to update metrics");
    
    let first_metrics = exporter.gather().expect("Failed to gather metrics");
    assert!(first_metrics.contains("ant_quic_log_events_total"));
    
    // Add more log events
    let log_event2 = LogEvent {
        timestamp: std::time::Instant::now(),
        level: tracing::Level::WARN,
        target: "ant_quic::test".to_string(),
        message: "Second message".to_string(),
        fields: std::collections::HashMap::new(),
        span_id: None,
    };
    
    collector.record_event(&log_event2);
    exporter.update_metrics().expect("Failed to update metrics");
    
    let second_metrics = exporter.gather().expect("Failed to gather metrics");
    assert!(second_metrics.contains("ant_quic_log_events_total"));
    assert!(second_metrics.contains("level=\"warn\""));
}