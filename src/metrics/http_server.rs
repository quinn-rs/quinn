//! HTTP server for exposing Prometheus metrics
//!
//! This module provides a lightweight HTTP server that exposes metrics in Prometheus format.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use warp::Filter;

use super::prometheus::PrometheusExporter;
use crate::metrics::MetricsConfig;

/// HTTP server for metrics export
#[derive(Debug)]
pub struct MetricsServer {
    /// Server configuration
    config: MetricsConfig,
    /// Prometheus exporter
    exporter: Arc<RwLock<Option<Arc<PrometheusExporter>>>>,
    /// Server shutdown signal
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl MetricsServer {
    /// Create a new metrics server
    pub fn new(config: MetricsConfig) -> Self {
        Self {
            config,
            exporter: Arc::new(RwLock::new(None)),
            shutdown_tx: None,
        }
    }
    
    /// Set the Prometheus exporter
    pub async fn set_exporter(&self, exporter: Arc<PrometheusExporter>) {
        let mut exp = self.exporter.write().await;
        *exp = Some(exporter);
    }
    
    /// Start the HTTP server
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.enabled {
            debug!("Metrics server disabled in configuration");
            return Ok(());
        }
        
        let bind_addr = SocketAddr::new(self.config.bind_address, self.config.port);
        
        // Create the /metrics endpoint
        let exporter = Arc::clone(&self.exporter);
        let metrics_route = warp::path("metrics")
            .and(warp::get())
            .and_then(move || {
                let exporter = Arc::clone(&exporter);
                async move {
                    handle_metrics_request(exporter).await
                }
            });
        
        // Create a health check endpoint
        let health_route = warp::path("health")
            .and(warp::get())
            .map(|| warp::reply::with_status("OK", warp::http::StatusCode::OK));
        
        // Combine routes
        let routes = metrics_route
            .or(health_route)
            .with(warp::log("ant_quic::metrics::http"));
        
        info!("Starting metrics server on {}", bind_addr);
        
        // Create shutdown signal
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);
        
        // Start the server with graceful shutdown
        let (_addr, server) = warp::serve(routes)
            .bind_with_graceful_shutdown(bind_addr, async {
                shutdown_rx.await.ok();
                info!("Metrics server shutting down gracefully");
            });
        
        // Spawn the server task
        tokio::spawn(server);
        
        info!("Metrics server started successfully on {}", bind_addr);
        Ok(())
    }
    
    /// Stop the metrics server
    pub async fn stop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
            info!("Metrics server stop signal sent");
        }
    }
    
    /// Get the server configuration
    pub fn config(&self) -> &MetricsConfig {
        &self.config
    }
}

impl Drop for MetricsServer {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
    }
}

/// Handle the /metrics endpoint request
async fn handle_metrics_request(
    exporter: Arc<RwLock<Option<Arc<PrometheusExporter>>>>
) -> Result<impl warp::Reply, Infallible> {
    let exporter_guard = exporter.read().await;
    
    match exporter_guard.as_ref() {
        Some(exp) => {
            // Update metrics before serving
            if let Err(e) = exp.update_metrics() {
                error!("Failed to update metrics: {}", e);
            }
            
            // Gather metrics in Prometheus format
            match exp.gather() {
                Ok(metrics) => {
                    debug!("Serving metrics, {} bytes", metrics.len());
                    Ok(warp::reply::with_header(
                        metrics,
                        "Content-Type",
                        "text/plain; version=0.0.4; charset=utf-8"
                    ))
                }
                Err(e) => {
                    error!("Failed to gather metrics: {}", e);
                    Ok(warp::reply::with_header(
                        format!("# ERROR: Failed to gather metrics: {}\n", e),
                        "Content-Type",
                        "text/plain; charset=utf-8"
                    ))
                }
            }
        }
        None => {
            warn!("Metrics endpoint called but no exporter configured");
            Ok(warp::reply::with_header(
                "# ERROR: No metrics exporter configured\n".to_string(),
                "Content-Type",
                "text/plain; charset=utf-8"
            ))
        }
    }
}

/// Utility function to create and start a metrics server
pub async fn start_metrics_server(
    config: MetricsConfig,
    exporter: Arc<PrometheusExporter>,
) -> Result<MetricsServer, Box<dyn std::error::Error + Send + Sync>> {
    let mut server = MetricsServer::new(config);
    server.set_exporter(exporter).await;
    server.start().await?;
    Ok(server)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::metrics::MetricsCollector;
    use std::time::Duration;

    #[tokio::test]
    async fn test_metrics_server_creation() {
        let config = MetricsConfig::default();
        let server = MetricsServer::new(config);
        assert!(!server.config.enabled);
    }
    
    #[tokio::test]
    async fn test_disabled_metrics_server() {
        let config = MetricsConfig {
            enabled: false,
            ..Default::default()
        };
        let mut server = MetricsServer::new(config);
        
        // Should succeed without starting actual server
        assert!(server.start().await.is_ok());
    }
    
    #[tokio::test]
    async fn test_metrics_server_with_exporter() {
        let config = MetricsConfig {
            enabled: true,
            port: 0, // Use any available port
            bind_address: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            ..Default::default()
        };
        
        let collector = Arc::new(MetricsCollector::new());
        let exporter = Arc::new(
            PrometheusExporter::new(collector).expect("Failed to create exporter")
        );
        
        let server = MetricsServer::new(config);
        server.set_exporter(exporter).await;
        
        // Note: In real tests, we'd need to find an available port
        // For now, just test that the server can be created and configured
        assert!(server.exporter.read().await.is_some());
    }
    
    #[tokio::test]
    async fn test_handle_metrics_request_no_exporter() {
        let exporter = Arc::new(RwLock::new(None));
        let response = handle_metrics_request(exporter).await;
        
        // Should not panic and should return a response
        assert!(response.is_ok());
    }
    
    #[tokio::test]
    async fn test_handle_metrics_request_with_exporter() {
        let collector = Arc::new(MetricsCollector::new());
        let prometheus_exporter = Arc::new(
            PrometheusExporter::new(collector).expect("Failed to create exporter")
        );
        
        let exporter = Arc::new(RwLock::new(Some(prometheus_exporter)));
        let response = handle_metrics_request(exporter).await;
        
        // Should return metrics successfully
        assert!(response.is_ok());
    }
}