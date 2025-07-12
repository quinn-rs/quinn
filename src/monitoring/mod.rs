//! Production Monitoring and Diagnostics
//!
//! This module provides comprehensive observability for NAT traversal operations
//! in production environments, including metrics collection, alerting, tracing,
//! and diagnostic capabilities.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, error};

// Import from NAT traversal API for configuration types
use crate::nat_traversal_api::NatTraversalConfig;

pub mod metrics;
pub mod alerting;
pub mod distributed_tracing;
pub mod diagnostics;
pub mod health;
pub mod export;
pub mod dashboards;

// Selective imports to avoid conflicts
pub use metrics::{ProductionMetricsCollector, MetricsConfig};
pub use alerting::{ProductionAlertManager, AlertingConfig};
pub use distributed_tracing::{DistributedTraceCollector, TracingConfig};
pub use diagnostics::{DiagnosticEngine, DiagnosticsConfig};
pub use health::{HealthMonitor, HealthConfig};
pub use export::{ExportManager, ExportConfig as MonitoringExportConfig};
pub use dashboards::{DashboardManager, DashboardConfig};

/// Central monitoring system for NAT traversal operations
pub struct MonitoringSystem {
    /// Metrics collection subsystem
    metrics_collector: Arc<ProductionMetricsCollector>,
    /// Alerting subsystem
    alert_manager: Arc<ProductionAlertManager>,
    /// Distributed tracing subsystem
    trace_collector: Arc<DistributedTraceCollector>,
    /// Health monitoring subsystem
    health_monitor: Arc<HealthMonitor>,
    /// Diagnostic engine
    diagnostic_engine: Arc<DiagnosticEngine>,
    /// Export manager
    export_manager: Arc<ExportManager>,
    /// Dashboard manager
    dashboard_manager: Arc<DashboardManager>,
    /// System configuration
    config: MonitoringConfig,
    /// System state
    state: Arc<RwLock<MonitoringState>>,
}

impl MonitoringSystem {
    /// Create new monitoring system
    pub async fn new(config: MonitoringConfig) -> Result<Self, MonitoringError> {
        info!("Initializing production monitoring system");
        
        // Initialize subsystems
        let metrics_collector = Arc::new(
            ProductionMetricsCollector::new(config.metrics.clone()).await?
        );
        
        let alert_manager = Arc::new(
            ProductionAlertManager::new(config.alerting.clone()).await?
        );
        
        let trace_collector = Arc::new(
            DistributedTraceCollector::new(config.tracing.clone()).await?
        );
        
        let health_monitor = Arc::new(
            HealthMonitor::new(config.health.clone()).await?
        );
        
        let diagnostic_engine = Arc::new(
            DiagnosticEngine::new(config.diagnostics.clone()).await?
        );
        
        let export_manager = Arc::new(
            ExportManager::new(config.export.clone()).await?
        );
        
        let dashboard_manager = Arc::new(
            DashboardManager::new(config.dashboards.clone()).await?
        );
        
        let state = Arc::new(RwLock::new(MonitoringState::new()));
        
        Ok(Self {
            metrics_collector,
            alert_manager,
            trace_collector,
            health_monitor,
            diagnostic_engine,
            export_manager,
            dashboard_manager,
            config,
            state,
        })
    }
    
    /// Start monitoring system
    pub async fn start(&self) -> Result<(), MonitoringError> {
        info!("Starting production monitoring system");
        
        // Update state
        {
            let mut state = self.state.write().await;
            state.start_time = Some(SystemTime::now());
            state.status = MonitoringStatus::Starting;
        }
        
        // Start subsystems in dependency order
        self.metrics_collector.start().await?;
        self.trace_collector.start().await?;
        self.health_monitor.start().await?;
        self.diagnostic_engine.start().await?;
        self.alert_manager.start().await?;
        self.export_manager.start().await?;
        self.dashboard_manager.start().await?;
        
        // Update state to running
        {
            let mut state = self.state.write().await;
            state.status = MonitoringStatus::Running;
        }
        
        info!("Production monitoring system started successfully");
        Ok(())
    }
    
    /// Stop monitoring system
    pub async fn stop(&self) -> Result<(), MonitoringError> {
        info!("Stopping production monitoring system");
        
        // Update state
        {
            let mut state = self.state.write().await;
            state.status = MonitoringStatus::Stopping;
        }
        
        // Stop subsystems in reverse order
        self.dashboard_manager.stop().await?;
        self.export_manager.stop().await?;
        self.alert_manager.stop().await?;
        self.diagnostic_engine.stop().await?;
        self.health_monitor.stop().await?;
        self.trace_collector.stop().await?;
        self.metrics_collector.stop().await?;
        
        // Update state to stopped
        {
            let mut state = self.state.write().await;
            state.status = MonitoringStatus::Stopped;
            state.stop_time = Some(SystemTime::now());
        }
        
        info!("Production monitoring system stopped");
        Ok(())
    }
    
    /// Record NAT traversal attempt
    pub async fn record_nat_attempt(&self, attempt: NatTraversalAttempt) -> Result<(), MonitoringError> {
        // Record metrics
        self.metrics_collector.record_nat_attempt(&attempt).await?;
        
        // Start trace if configured
        if self.config.tracing.enabled {
            self.trace_collector.start_nat_trace(&attempt).await?;
        }
        
        // Check for alerts
        self.alert_manager.evaluate_nat_attempt(&attempt).await?;
        
        Ok(())
    }
    
    /// Record NAT traversal result
    pub async fn record_nat_result(&self, result: NatTraversalResult) -> Result<(), MonitoringError> {
        // Record metrics
        self.metrics_collector.record_nat_result(&result).await?;
        
        // Complete trace
        if self.config.tracing.enabled {
            self.trace_collector.complete_nat_trace(&result).await?;
        }
        
        // Update health status
        self.health_monitor.update_nat_health(&result).await?;
        
        // Check for alerts
        self.alert_manager.evaluate_nat_result(&result).await?;
        
        // Trigger diagnostics if needed
        if !result.success {
            self.diagnostic_engine.analyze_failure(&result).await?;
        }
        
        Ok(())
    }
    
    /// Get system status
    pub async fn get_status(&self) -> MonitoringSystemStatus {
        let state = self.state.read().await;
        let uptime = state.start_time.map(|start| start.elapsed().unwrap_or_default());
        
        MonitoringSystemStatus {
            status: state.status.clone(),
            uptime,
            subsystems: SubsystemStatus {
                metrics: self.metrics_collector.get_status().await,
                alerting: self.alert_manager.get_status().await,
                tracing: self.trace_collector.get_status().await,
                health: self.health_monitor.get_status().await,
                diagnostics: self.diagnostic_engine.get_status().await,
                export: self.export_manager.get_status().await,
                dashboards: self.dashboard_manager.get_status().await,
            },
            metrics_summary: self.get_metrics_summary().await,
        }
    }
    
    /// Get metrics summary
    async fn get_metrics_summary(&self) -> MetricsSummary {
        self.metrics_collector.get_summary().await
    }
    
    /// Trigger manual diagnostic
    pub async fn trigger_diagnostic(&self, diagnostic_type: DiagnosticType) -> Result<DiagnosticReport, MonitoringError> {
        self.diagnostic_engine.run_diagnostic(diagnostic_type).await
    }
    
    /// Get health check
    pub async fn health_check(&self) -> HealthCheckResult {
        self.health_monitor.comprehensive_health_check().await
    }
}

/// Health check result
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthCheckResult {
    /// Overall health status
    pub status: HealthStatus,
    /// Individual component health
    pub components: HashMap<String, ComponentHealth>,
    /// Health check timestamp
    pub timestamp: SystemTime,
    /// Overall score (0-100)
    pub score: u8,
}

/// Health status enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// Component health information
#[derive(Debug, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component status
    pub status: HealthStatus,
    /// Status message
    pub message: String,
    /// Response time
    pub response_time_ms: u64,
    /// Error count
    pub error_count: u64,
}

/// Diagnostic type enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiagnosticType {
    NatTraversalFailure,
    ConnectionPerformance,
    NetworkConnectivity,
    SystemHealth,
    SecurityAudit,
}

/// Diagnostic report
#[derive(Debug, Serialize, Deserialize)]
pub struct DiagnosticReport {
    /// Report identifier
    pub id: String,
    /// Diagnostic type
    pub diagnostic_type: DiagnosticType,
    /// Report timestamp
    pub timestamp: SystemTime,
    /// Overall severity
    pub severity: DiagnosticSeverity,
    /// Findings
    pub findings: Vec<DiagnosticFinding>,
    /// Recommended actions
    pub recommendations: Vec<DiagnosticRecommendation>,
    /// Report metadata
    pub metadata: HashMap<String, String>,
}

/// Diagnostic severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Individual diagnostic finding
#[derive(Debug, Serialize, Deserialize)]
pub struct DiagnosticFinding {
    /// Finding identifier
    pub id: String,
    /// Finding title
    pub title: String,
    /// Finding description
    pub description: String,
    /// Severity level
    pub severity: DiagnosticSeverity,
    /// Evidence
    pub evidence: Vec<String>,
    /// Confidence score (0-100)
    pub confidence: u8,
}

/// Diagnostic recommendation
#[derive(Debug, Serialize, Deserialize)]
pub struct DiagnosticRecommendation {
    /// Recommendation identifier
    pub id: String,
    /// Action title
    pub title: String,
    /// Action description
    pub description: String,
    /// Priority level
    pub priority: RecommendationPriority,
    /// Implementation steps
    pub steps: Vec<String>,
    /// Expected impact
    pub impact: String,
}

/// Recommendation priority levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendationPriority {
    Low,
    Medium,
    High,
    Critical,
}

/// Monitoring system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Metrics collection configuration
    pub metrics: MetricsConfig,
    /// Alerting configuration
    pub alerting: AlertingConfig,
    /// Tracing configuration
    pub tracing: TracingConfig,
    /// Health monitoring configuration
    pub health: HealthConfig,
    /// Diagnostics configuration
    pub diagnostics: DiagnosticsConfig,
    /// Export configuration
    pub export: MonitoringExportConfig,
    /// Dashboard configuration
    pub dashboards: DashboardConfig,
    /// Global settings
    pub global: GlobalConfig,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            metrics: MetricsConfig::default(),
            alerting: AlertingConfig::default(),
            tracing: TracingConfig::default(),
            health: HealthConfig::default(),
            diagnostics: DiagnosticsConfig::default(),
            export: MonitoringExportConfig::default(),
            dashboards: DashboardConfig::default(),
            global: GlobalConfig::default(),
        }
    }
}

/// Global monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// Service name for identification
    pub service_name: String,
    /// Service version
    pub service_version: String,
    /// Environment (dev, staging, prod)
    pub environment: String,
    /// Region identifier
    pub region: String,
    /// Instance identifier
    pub instance_id: String,
    /// Maximum overhead budget (percentage)
    pub max_overhead_percent: f32,
    /// Security settings
    pub security: SecurityConfig,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            service_name: "ant-quic".to_string(),
            service_version: "0.2.1".to_string(),
            environment: "dev".to_string(),
            region: "local".to_string(),
            instance_id: "default".to_string(),
            max_overhead_percent: 1.0,
            security: SecurityConfig::default(),
        }
    }
}

/// Security configuration for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable data anonymization
    pub anonymize_data: bool,
    /// Enable audit logging
    pub audit_logging: bool,
    /// Access control settings
    pub access_control: AccessControlConfig,
    /// Encryption settings
    pub encryption: EncryptionConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            anonymize_data: true,
            audit_logging: true,
            access_control: AccessControlConfig::default(),
            encryption: EncryptionConfig::default(),
        }
    }
}

/// Access control configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlConfig {
    /// Enable authentication
    pub enabled: bool,
    /// Authentication provider
    pub provider: AuthProvider,
    /// Required permissions
    pub required_permissions: Vec<String>,
}

impl Default for AccessControlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            provider: AuthProvider::OAuth2,
            required_permissions: vec!["monitoring:read".to_string()],
        }
    }
}

/// Authentication providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthProvider {
    OAuth2,
    OIDC,
    ApiKey,
    Certificate,
}

/// Encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Enable TLS for metrics export
    pub tls_enabled: bool,
    /// Encrypt data at rest
    pub at_rest_encryption: bool,
    /// Encryption key rotation period
    pub key_rotation_period: Duration,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            tls_enabled: true,
            at_rest_encryption: true,
            key_rotation_period: Duration::from_secs(86400 * 30), // 30 days
        }
    }
}

/// NAT traversal attempt information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatTraversalAttempt {
    /// Unique attempt identifier
    pub attempt_id: String,
    /// Timestamp of attempt start
    pub timestamp: SystemTime,
    /// Client endpoint information
    pub client_info: EndpointInfo,
    /// Server endpoint information
    pub server_info: EndpointInfo,
    /// NAT traversal configuration
    pub nat_config: NatTraversalConfig,
    /// Bootstrap nodes involved
    pub bootstrap_nodes: Vec<String>,
    /// Network conditions
    pub network_conditions: NetworkConditions,
}

/// NAT traversal result information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatTraversalResult {
    /// Attempt identifier
    pub attempt_id: String,
    /// Whether traversal was successful
    pub success: bool,
    /// Duration of traversal attempt
    pub duration: Duration,
    /// Final connection information
    pub connection_info: Option<ConnectionInfo>,
    /// Error information if failed
    pub error_info: Option<ErrorInfo>,
    /// Performance metrics
    pub performance_metrics: PerformanceMetrics,
    /// Candidate information
    pub candidates_used: Vec<CandidateInfo>,
}

/// Endpoint information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointInfo {
    /// Endpoint identifier
    pub id: String,
    /// Endpoint role
    pub role: EndpointRole,
    /// Network address (anonymized)
    pub address_hash: String,
    /// NAT type detected
    pub nat_type: Option<NatType>,
    /// Geographic region
    pub region: Option<String>,
}

/// Connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    /// Established connection path
    pub path: ConnectionPath,
    /// Connection quality metrics
    pub quality: ConnectionQuality,
    /// Protocol information
    pub protocol_info: ProtocolInfo,
}

/// Error information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorInfo {
    /// Error code
    pub error_code: String,
    /// Error category
    pub error_category: ErrorCategory,
    /// Human-readable error message
    pub error_message: String,
    /// Detailed error context
    pub error_context: HashMap<String, String>,
    /// Recovery suggestions
    pub recovery_suggestions: Vec<String>,
}

/// Performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Total connection establishment time
    pub connection_time_ms: u64,
    /// Time to first candidate
    pub first_candidate_time_ms: u64,
    /// Time to successful connection
    pub success_time_ms: Option<u64>,
    /// Number of candidates tried
    pub candidates_tried: u32,
    /// Number of round trips required
    pub round_trips: u32,
    /// Bytes transferred during setup
    pub setup_bytes: u64,
}

/// Network conditions during attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConditions {
    /// Estimated round-trip time
    pub rtt_ms: Option<u32>,
    /// Packet loss rate
    pub packet_loss_rate: Option<f32>,
    /// Available bandwidth
    pub bandwidth_mbps: Option<u32>,
    /// Network congestion indicator
    pub congestion_level: CongestionLevel,
}

/// Connection path information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionPath {
    /// Path type (direct, relayed, etc.)
    pub path_type: PathType,
    /// Intermediate hops
    pub hops: Vec<HopInfo>,
    /// Path quality score
    pub quality_score: f32,
}

/// Connection quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionQuality {
    /// Latency in milliseconds
    pub latency_ms: u32,
    /// Jitter in milliseconds
    pub jitter_ms: u32,
    /// Throughput in Mbps
    pub throughput_mbps: f32,
    /// Stability score (0-1)
    pub stability_score: f32,
}

/// Protocol information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolInfo {
    /// QUIC version used
    pub quic_version: String,
    /// Encryption cipher
    pub cipher: String,
    /// Extensions used
    pub extensions: Vec<String>,
}

/// Candidate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateInfo {
    /// Candidate type
    pub candidate_type: CandidateType,
    /// Priority assigned
    pub priority: u32,
    /// Whether candidate was successful
    pub success: bool,
    /// Time to test candidate
    pub test_time_ms: u64,
}

/// Hop information for connection path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopInfo {
    /// Hop identifier (anonymized)
    pub hop_id: String,
    /// Hop type
    pub hop_type: HopType,
    /// Latency to this hop
    pub latency_ms: u32,
}

/// Endpoint roles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EndpointRole {
    Client,
    Server,
    Bootstrap,
    Relay,
}

/// NAT types for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NatType {
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric,
    CarrierGrade,
    DoubleNat,
    None,
}

/// Error categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ErrorCategory {
    NetworkConnectivity,
    NatTraversal,
    Authentication,
    Protocol,
    Timeout,
    ResourceExhaustion,
    Configuration,
    Unknown,
}

/// Congestion levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CongestionLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Path types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PathType {
    Direct,
    NatTraversed,
    Relayed,
    TurnRelayed,
}

/// Candidate types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CandidateType {
    Host,
    ServerReflexive,
    PeerReflexive,
    Relay,
}

/// Hop types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HopType {
    Router,
    Nat,
    Firewall,
    Proxy,
    Relay,
}

/// Monitoring system state
#[derive(Debug)]
struct MonitoringState {
    /// Current status
    status: MonitoringStatus,
    /// Start time
    start_time: Option<SystemTime>,
    /// Stop time
    stop_time: Option<SystemTime>,
    /// Error count
    error_count: u64,
    /// Last error
    last_error: Option<String>,
}

impl MonitoringState {
    fn new() -> Self {
        Self {
            status: MonitoringStatus::Stopped,
            start_time: None,
            stop_time: None,
            error_count: 0,
            last_error: None,
        }
    }
}

/// Monitoring system status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MonitoringStatus {
    Stopped,
    Starting,
    Running,
    Stopping,
    Error,
}

/// Overall system status
#[derive(Debug, Serialize, Deserialize)]
pub struct MonitoringSystemStatus {
    /// Current status
    pub status: MonitoringStatus,
    /// System uptime
    pub uptime: Option<Duration>,
    /// Subsystem statuses
    pub subsystems: SubsystemStatus,
    /// Metrics summary
    pub metrics_summary: MetricsSummary,
}

/// Subsystem statuses
#[derive(Debug, Serialize, Deserialize)]
pub struct SubsystemStatus {
    /// Metrics subsystem status
    pub metrics: String,
    /// Alerting subsystem status  
    pub alerting: String,
    /// Tracing subsystem status
    pub tracing: String,
    /// Health subsystem status
    pub health: String,
    /// Diagnostics subsystem status
    pub diagnostics: String,
    /// Export subsystem status
    pub export: String,
    /// Dashboard subsystem status
    pub dashboards: String,
}

/// Metrics summary
#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsSummary {
    /// Total NAT attempts in last hour
    pub nat_attempts_last_hour: u64,
    /// Success rate in last hour
    pub success_rate_last_hour: f32,
    /// Average connection time in last hour
    pub avg_connection_time_ms: u64,
    /// Active connections
    pub active_connections: u64,
    /// Error rate in last hour
    pub error_rate_last_hour: f32,
}

/// Monitoring errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum MonitoringError {
    #[error("Metrics collection error: {0}")]
    MetricsError(String),
    
    #[error("Alerting error: {0}")]
    AlertingError(String),
    
    #[error("Tracing error: {0}")]
    TracingError(String),
    
    #[error("Health monitoring error: {0}")]
    HealthError(String),
    
    #[error("Diagnostics error: {0}")]
    DiagnosticsError(String),
    
    #[error("Export error: {0}")]
    ExportError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("System error: {0}")]
    SystemError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_monitoring_system_creation() {
        let config = MonitoringConfig::default();
        let monitoring = MonitoringSystem::new(config).await.unwrap();
        
        let status = monitoring.get_status().await;
        assert!(matches!(status.status, MonitoringStatus::Stopped));
    }
    
    #[test]
    fn test_config_serialization() {
        let config = MonitoringConfig::default();
        let json = serde_json::to_string_pretty(&config).unwrap();
        let _deserialized: MonitoringConfig = serde_json::from_str(&json).unwrap();
    }
}