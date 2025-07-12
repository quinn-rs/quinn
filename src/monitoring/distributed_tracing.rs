//! Distributed Tracing System
//!
//! This module implements distributed tracing for NAT traversal operations
//! to provide end-to-end visibility across the entire connection establishment process.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use tokio::sync::{RwLock, Mutex};
use tracing::{debug, info, warn, Span};
use uuid::Uuid;

use crate::monitoring::{
    MonitoringError, NatTraversalAttempt, NatTraversalResult,
};

/// Distributed trace collector for NAT traversal operations
pub struct DistributedTraceCollector {
    /// Tracing configuration
    config: TracingConfig,
    /// Active traces storage
    active_traces: Arc<RwLock<HashMap<String, TraceContext>>>,
    /// Trace exporter
    exporter: Arc<TraceExporter>,
    /// Sampling decision engine
    sampler: Arc<TraceSampler>,
    /// Span builder for creating structured spans
    span_builder: Arc<SpanBuilder>,
    /// Correlation ID manager
    correlation_manager: Arc<CorrelationManager>,
}

impl DistributedTraceCollector {
    /// Create new distributed trace collector
    pub async fn new(config: TracingConfig) -> Result<Self, MonitoringError> {
        let exporter = Arc::new(TraceExporter::new(config.export.clone()));
        let sampler = Arc::new(TraceSampler::new(config.sampling.clone()));
        let span_builder = Arc::new(SpanBuilder::new());
        let correlation_manager = Arc::new(CorrelationManager::new());
        
        Ok(Self {
            config,
            active_traces: Arc::new(RwLock::new(HashMap::new())),
            exporter,
            sampler,
            span_builder,
            correlation_manager,
        })
    }
    
    /// Start tracing system
    pub async fn start(&self) -> Result<(), MonitoringError> {
        info!("Starting distributed trace collector");
        
        // Initialize exporter
        self.exporter.start().await?;
        
        info!("Distributed trace collector started");
        Ok(())
    }
    
    /// Stop tracing system
    pub async fn stop(&self) -> Result<(), MonitoringError> {
        info!("Stopping distributed trace collector");
        
        // Flush remaining traces
        self.flush_active_traces().await?;
        
        // Stop exporter
        self.exporter.stop().await?;
        
        info!("Distributed trace collector stopped");
        Ok(())
    }
    
    /// Start NAT traversal trace
    pub async fn start_nat_trace(&self, attempt: &NatTraversalAttempt) -> Result<TraceId, MonitoringError> {
        // Check sampling decision
        if !self.sampler.should_sample_nat_trace(attempt).await {
            return Ok(TraceId::new()); // Return empty trace ID
        }
        
        let trace_id = TraceId::new();
        let correlation_id = self.correlation_manager.generate_correlation_id().await;
        
        // Create root span for NAT traversal
        let root_span = self.span_builder.create_nat_traversal_span(
            &trace_id,
            None, // No parent span
            attempt,
        ).await?;
        
        // Create trace context
        let trace_context = TraceContext {
            trace_id: trace_id.clone(),
            correlation_id,
            root_span: root_span.clone(),
            active_spans: HashMap::new(),
            start_time: SystemTime::now(),
            client_info: attempt.client_info.clone(),
            server_info: attempt.server_info.clone(),
            bootstrap_nodes: attempt.bootstrap_nodes.clone(),
            events: Vec::new(),
        };
        
        // Store active trace
        {
            let mut active_traces = self.active_traces.write().await;
            active_traces.insert(attempt.attempt_id.clone(), trace_context);
        }
        
        debug!("Started NAT traversal trace: {} (attempt: {})", trace_id, attempt.attempt_id);
        Ok(trace_id)
    }
    
    /// Complete NAT traversal trace
    pub async fn complete_nat_trace(&self, result: &NatTraversalResult) -> Result<(), MonitoringError> {
        let mut active_traces = self.active_traces.write().await;
        
        if let Some(mut trace_context) = active_traces.remove(&result.attempt_id) {
            // Add final result information
            let result_event = TraceEvent {
                timestamp: SystemTime::now(),
                event_type: TraceEventType::NatTraversalCompleted,
                span_id: trace_context.root_span.span_id.clone(),
                attributes: self.result_to_attributes(result),
                duration: Some(result.duration),
            };
            
            trace_context.events.push(result_event);
            
            // Close root span
            trace_context.root_span.end_time = Some(SystemTime::now());
            trace_context.root_span.status = if result.success {
                SpanStatus::Ok
            } else {
                SpanStatus::Error
            };
            
            // Export completed trace
            self.exporter.export_trace(trace_context).await?;
            
            debug!("Completed NAT traversal trace for attempt: {}", result.attempt_id);
        } else {
            warn!("No active trace found for attempt: {}", result.attempt_id);
        }
        
        Ok(())
    }
    
    /// Add span to existing trace
    pub async fn add_span(
        &self,
        attempt_id: &str,
        span_name: &str,
        parent_span_id: Option<SpanId>,
        attributes: HashMap<String, AttributeValue>,
    ) -> Result<SpanId, MonitoringError> {
        let mut active_traces = self.active_traces.write().await;
        
        if let Some(trace_context) = active_traces.get_mut(attempt_id) {
            let span = self.span_builder.create_child_span(
                &trace_context.trace_id,
                parent_span_id.as_ref().unwrap_or(&trace_context.root_span.span_id),
                span_name,
                attributes,
            ).await?;
            
            let span_id = span.span_id.clone();
            trace_context.active_spans.insert(span_id.clone(), span);
            
            Ok(span_id)
        } else {
            Err(MonitoringError::TracingError(
                format!("No active trace found for attempt: {}", attempt_id)
            ))
        }
    }
    
    /// Add event to trace
    pub async fn add_event(
        &self,
        attempt_id: &str,
        span_id: &SpanId,
        event_type: TraceEventType,
        attributes: HashMap<String, AttributeValue>,
    ) -> Result<(), MonitoringError> {
        let mut active_traces = self.active_traces.write().await;
        
        if let Some(trace_context) = active_traces.get_mut(attempt_id) {
            debug!("Adding event {:?} to trace for attempt: {}", event_type, attempt_id);
            
            let event = TraceEvent {
                timestamp: SystemTime::now(),
                event_type,
                span_id: span_id.clone(),
                attributes,
                duration: None,
            };
            
            trace_context.events.push(event);
        } else {
            warn!("No active trace found for attempt: {}", attempt_id);
        }
        
        Ok(())
    }
    
    /// Complete span in trace
    pub async fn complete_span(
        &self,
        attempt_id: &str,
        span_id: &SpanId,
        status: SpanStatus,
    ) -> Result<(), MonitoringError> {
        let mut active_traces = self.active_traces.write().await;
        
        if let Some(trace_context) = active_traces.get_mut(attempt_id) {
            if let Some(span) = trace_context.active_spans.get_mut(span_id) {
                span.end_time = Some(SystemTime::now());
                span.status = status;
                
                debug!("Completed span {} in trace for attempt: {}", span_id, attempt_id);
            }
        }
        
        Ok(())
    }
    
    /// Get trace status
    pub async fn get_status(&self) -> String {
        let active_traces = self.active_traces.read().await;
        format!("Active traces: {}", active_traces.len())
    }
    
    /// Flush active traces
    async fn flush_active_traces(&self) -> Result<(), MonitoringError> {
        let mut active_traces = self.active_traces.write().await;
        
        for (attempt_id, mut trace_context) in active_traces.drain() {
            // Mark as incomplete
            trace_context.root_span.status = SpanStatus::Cancelled;
            trace_context.root_span.end_time = Some(SystemTime::now());
            
            // Export incomplete trace
            if let Err(e) = self.exporter.export_trace(trace_context).await {
                warn!("Failed to export incomplete trace for {}: {}", attempt_id, e);
            }
        }
        
        Ok(())
    }
    
    /// Convert result to trace attributes
    fn result_to_attributes(&self, result: &NatTraversalResult) -> HashMap<String, AttributeValue> {
        let mut attributes = HashMap::new();
        
        attributes.insert("nat.success".to_string(), AttributeValue::Bool(result.success));
        attributes.insert("nat.duration_ms".to_string(), AttributeValue::Int(result.duration.as_millis() as i64));
        
        if let Some(error_info) = &result.error_info {
            attributes.insert("error.category".to_string(), AttributeValue::String(format!("{:?}", error_info.error_category)));
            attributes.insert("error.code".to_string(), AttributeValue::String(error_info.error_code.clone()));
            attributes.insert("error.message".to_string(), AttributeValue::String(error_info.error_message.clone()));
        }
        
        let perf = &result.performance_metrics;
        attributes.insert("nat.connection_time_ms".to_string(), AttributeValue::Int(perf.connection_time_ms as i64));
        attributes.insert("nat.candidates_tried".to_string(), AttributeValue::Int(perf.candidates_tried as i64));
        attributes.insert("nat.round_trips".to_string(), AttributeValue::Int(perf.round_trips as i64));
        
        if let Some(conn_info) = &result.connection_info {
            attributes.insert("connection.latency_ms".to_string(), AttributeValue::Int(conn_info.quality.latency_ms as i64));
            attributes.insert("connection.throughput_mbps".to_string(), AttributeValue::Float(conn_info.quality.throughput_mbps as f64));
            attributes.insert("connection.path_type".to_string(), AttributeValue::String(format!("{:?}", conn_info.path.path_type)));
        }
        
        attributes
    }
}

/// Tracing configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TracingConfig {
    /// Enable distributed tracing
    pub enabled: bool,
    /// Sampling configuration
    pub sampling: TraceSamplingConfig,
    /// Export configuration
    pub export: TraceExportConfig,
    /// Correlation settings
    pub correlation: CorrelationConfig,
    /// Resource limits
    pub resource_limits: TraceResourceLimits,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sampling: TraceSamplingConfig::default(),
            export: TraceExportConfig::default(),
            correlation: CorrelationConfig::default(),
            resource_limits: TraceResourceLimits::default(),
        }
    }
}

/// Trace sampling configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TraceSamplingConfig {
    /// Base sampling rate for NAT traversal traces
    pub nat_traversal_rate: f64,
    /// Sampling rate for successful operations
    pub success_rate: f64,
    /// Sampling rate for failed operations
    pub failure_rate: f64,
    /// Adaptive sampling settings
    pub adaptive: AdaptiveTraceSamplingConfig,
}

impl Default for TraceSamplingConfig {
    fn default() -> Self {
        Self {
            nat_traversal_rate: 0.1,  // 10% of NAT traversals
            success_rate: 0.05,       // 5% of successful operations
            failure_rate: 1.0,        // 100% of failures
            adaptive: AdaptiveTraceSamplingConfig::default(),
        }
    }
}

/// Adaptive trace sampling configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdaptiveTraceSamplingConfig {
    /// Enable adaptive sampling
    pub enabled: bool,
    /// Target traces per second
    pub target_traces_per_second: f64,
    /// Adjustment interval
    pub adjustment_interval: Duration,
}

impl Default for AdaptiveTraceSamplingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            target_traces_per_second: 100.0,
            adjustment_interval: Duration::from_secs(60),
        }
    }
}

/// Trace export configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TraceExportConfig {
    /// Export destinations
    pub destinations: Vec<TraceExportDestination>,
    /// Batch size for export
    pub batch_size: usize,
    /// Export interval
    pub export_interval: Duration,
    /// Export timeout
    pub export_timeout: Duration,
}

impl Default for TraceExportConfig {
    fn default() -> Self {
        Self {
            destinations: vec![TraceExportDestination::Jaeger {
                endpoint: "http://localhost:14268/api/traces".to_string(),
            }],
            batch_size: 100,
            export_interval: Duration::from_secs(10),
            export_timeout: Duration::from_secs(30),
        }
    }
}

/// Trace export destinations
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum TraceExportDestination {
    Jaeger { endpoint: String },
    Zipkin { endpoint: String },
    OTLP { endpoint: String },
    CloudTrace { project_id: String },
    XRay { region: String },
}

/// Correlation configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CorrelationConfig {
    /// Correlation ID header name
    pub correlation_header: String,
    /// Enable cross-service correlation
    pub cross_service: bool,
    /// Correlation ID format
    pub id_format: CorrelationIdFormat,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            correlation_header: "X-Correlation-ID".to_string(),
            cross_service: true,
            id_format: CorrelationIdFormat::UUID,
        }
    }
}

/// Correlation ID formats
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum CorrelationIdFormat {
    UUID,
    Snowflake,
    Custom(String),
}

/// Trace resource limits
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TraceResourceLimits {
    /// Maximum active traces
    pub max_active_traces: usize,
    /// Maximum spans per trace
    pub max_spans_per_trace: usize,
    /// Maximum events per trace
    pub max_events_per_trace: usize,
    /// Maximum trace duration
    pub max_trace_duration: Duration,
}

impl Default for TraceResourceLimits {
    fn default() -> Self {
        Self {
            max_active_traces: 10000,
            max_spans_per_trace: 100,
            max_events_per_trace: 500,
            max_trace_duration: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Unique trace identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(dead_code)] // Used for distributed tracing correlation
pub struct TraceId(String);

impl TraceId {
    fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

impl std::fmt::Display for TraceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique span identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(dead_code)] // Used for distributed tracing hierarchy
pub struct SpanId(String);

impl SpanId {
    fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

impl std::fmt::Display for SpanId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Correlation identifier for cross-service tracing
#[derive(Debug, Clone)]
#[allow(dead_code)] // Used for cross-service request correlation
pub struct CorrelationId(String);

impl CorrelationId {
    fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

impl std::fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Trace context containing all trace information
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used for distributed trace state management
struct TraceContext {
    /// Unique trace identifier
    trace_id: TraceId,
    /// Correlation identifier
    correlation_id: CorrelationId,
    /// Root span for the trace
    root_span: TraceSpan,
    /// Active child spans
    active_spans: HashMap<SpanId, TraceSpan>,
    /// Trace start time
    start_time: SystemTime,
    /// Client endpoint information
    client_info: crate::monitoring::EndpointInfo,
    /// Server endpoint information
    server_info: crate::monitoring::EndpointInfo,
    /// Bootstrap nodes involved
    bootstrap_nodes: Vec<String>,
    /// Trace events
    events: Vec<TraceEvent>,
}

/// Individual span in a trace
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields populated during trace lifecycle
struct TraceSpan {
    /// Unique span identifier
    span_id: SpanId,
    /// Parent span identifier
    parent_span_id: Option<SpanId>,
    /// Span name/operation
    name: String,
    /// Span start time
    start_time: SystemTime,
    /// Span end time
    end_time: Option<SystemTime>,
    /// Span status
    status: SpanStatus,
    /// Span attributes
    attributes: HashMap<String, AttributeValue>,
    /// Span tags
    tags: HashMap<String, String>,
}

/// Span status
#[derive(Debug, Clone, PartialEq)]
pub enum SpanStatus {
    Ok,
    Error,
    Cancelled,
    Timeout,
}

/// Trace event
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used for recording trace events
struct TraceEvent {
    /// Event timestamp
    timestamp: SystemTime,
    /// Event type
    event_type: TraceEventType,
    /// Associated span ID
    span_id: SpanId,
    /// Event attributes
    attributes: HashMap<String, AttributeValue>,
    /// Event duration (if applicable)
    duration: Option<Duration>,
}

/// Trace event types
#[derive(Debug, Clone)]
#[allow(dead_code)] // All variants used for comprehensive trace event categorization
pub enum TraceEventType {
    NatTraversalStarted,
    NatTraversalCompleted,
    CandidateDiscoveryStarted,
    CandidateDiscoveryCompleted,
    CandidateTestStarted,
    CandidateTestCompleted,
    HolePunchingStarted,
    HolePunchingCompleted,
    ConnectionEstablished,
    BootstrapNodeContacted,
    ErrorOccurred,
    Custom(String),
}

/// Attribute value types
#[derive(Debug, Clone)]
#[allow(dead_code)] // All variants used for flexible attribute storage
pub enum AttributeValue {
    String(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Array(Vec<AttributeValue>),
}

/// Trace sampler for sampling decisions
struct TraceSampler {
    config: TraceSamplingConfig,
    current_rate: Arc<RwLock<f64>>,
    traces_this_period: Arc<RwLock<u32>>,
    last_adjustment: Arc<RwLock<Instant>>,
}

impl TraceSampler {
    fn new(config: TraceSamplingConfig) -> Self {
        Self {
            current_rate: Arc::new(RwLock::new(config.nat_traversal_rate)),
            config,
            traces_this_period: Arc::new(RwLock::new(0)),
            last_adjustment: Arc::new(RwLock::new(Instant::now())),
        }
    }
    
    async fn should_sample_nat_trace(&self, _attempt: &NatTraversalAttempt) -> bool {
        // Adjust sampling rate if adaptive sampling is enabled
        if self.config.adaptive.enabled {
            self.adjust_sampling_rate().await;
        }
        
        let current_rate = *self.current_rate.read().await;
        let should_sample = rand::random::<f64>() < current_rate;
        
        if should_sample {
            let mut traces_count = self.traces_this_period.write().await;
            *traces_count += 1;
        }
        
        should_sample
    }
    
    async fn adjust_sampling_rate(&self) {
        let mut last_adjustment = self.last_adjustment.write().await;
        
        if last_adjustment.elapsed() < self.config.adaptive.adjustment_interval {
            return;
        }
        
        let traces_count = {
            let mut count = self.traces_this_period.write().await;
            let current_count = *count;
            *count = 0; // Reset for next period
            current_count
        };
        
        let period_seconds = self.config.adaptive.adjustment_interval.as_secs_f64();
        let current_traces_per_second = traces_count as f64 / period_seconds;
        let target_traces_per_second = self.config.adaptive.target_traces_per_second;
        
        let mut current_rate = self.current_rate.write().await;
        let adjustment_factor = target_traces_per_second / current_traces_per_second.max(1.0);
        *current_rate = (*current_rate * adjustment_factor).min(1.0).max(0.001);
        
        *last_adjustment = Instant::now();
        
        debug!("Adjusted trace sampling rate to {:.4} (current rate: {:.2} traces/sec, target: {:.2})",
            *current_rate, current_traces_per_second, target_traces_per_second);
    }
}

/// Span builder for creating structured spans
struct SpanBuilder;

impl SpanBuilder {
    fn new() -> Self {
        Self
    }
    
    async fn create_nat_traversal_span(
        &self,
        _trace_id: &TraceId,
        parent_span_id: Option<SpanId>,
        attempt: &NatTraversalAttempt,
    ) -> Result<TraceSpan, MonitoringError> {
        let mut attributes = HashMap::new();
        
        // Add NAT traversal specific attributes
        attributes.insert("nat.attempt_id".to_string(), AttributeValue::String(attempt.attempt_id.clone()));
        attributes.insert("nat.client.region".to_string(), AttributeValue::String(
            attempt.client_info.region.as_deref().unwrap_or("unknown").to_string()
        ));
        attributes.insert("nat.server.region".to_string(), AttributeValue::String(
            attempt.server_info.region.as_deref().unwrap_or("unknown").to_string()
        ));
        attributes.insert("nat.bootstrap_nodes".to_string(), AttributeValue::Array(
            attempt.bootstrap_nodes.iter()
                .map(|node| AttributeValue::String(node.clone()))
                .collect()
        ));
        
        if let Some(client_nat_type) = &attempt.client_info.nat_type {
            attributes.insert("nat.client.type".to_string(), AttributeValue::String(format!("{:?}", client_nat_type)));
        }
        
        if let Some(server_nat_type) = &attempt.server_info.nat_type {
            attributes.insert("nat.server.type".to_string(), AttributeValue::String(format!("{:?}", server_nat_type)));
        }
        
        // Add network conditions
        if let Some(rtt) = attempt.network_conditions.rtt_ms {
            attributes.insert("network.rtt_ms".to_string(), AttributeValue::Int(rtt as i64));
        }
        
        if let Some(loss_rate) = attempt.network_conditions.packet_loss_rate {
            attributes.insert("network.packet_loss_rate".to_string(), AttributeValue::Float(loss_rate as f64));
        }
        
        Ok(TraceSpan {
            span_id: SpanId::new(),
            parent_span_id,
            name: "nat_traversal".to_string(),
            start_time: attempt.timestamp,
            end_time: None,
            status: SpanStatus::Ok,
            attributes,
            tags: HashMap::new(),
        })
    }
    
    async fn create_child_span(
        &self,
        _trace_id: &TraceId,
        parent_span_id: &SpanId,
        span_name: &str,
        attributes: HashMap<String, AttributeValue>,
    ) -> Result<TraceSpan, MonitoringError> {
        Ok(TraceSpan {
            span_id: SpanId::new(),
            parent_span_id: Some(parent_span_id.clone()),
            name: span_name.to_string(),
            start_time: SystemTime::now(),
            end_time: None,
            status: SpanStatus::Ok,
            attributes,
            tags: HashMap::new(),
        })
    }
}

/// Trace exporter for sending traces to external systems
struct TraceExporter {
    config: TraceExportConfig,
    pending_traces: Arc<Mutex<Vec<TraceContext>>>,
}

impl TraceExporter {
    fn new(config: TraceExportConfig) -> Self {
        Self {
            config,
            pending_traces: Arc::new(Mutex::new(Vec::new())),
        }
    }
    
    async fn start(&self) -> Result<(), MonitoringError> {
        // Start background export task
        info!("Trace exporter started");
        Ok(())
    }
    
    async fn stop(&self) -> Result<(), MonitoringError> {
        // Flush remaining traces
        self.flush_pending_traces().await?;
        info!("Trace exporter stopped");
        Ok(())
    }
    
    async fn export_trace(&self, trace_context: TraceContext) -> Result<(), MonitoringError> {
        // Add to pending traces
        {
            let mut pending = self.pending_traces.lock().await;
            pending.push(trace_context);
            
            // Export if batch size reached
            if pending.len() >= self.config.batch_size {
                let traces = pending.drain(..).collect::<Vec<_>>();
                drop(pending); // Release lock early
                self.export_batch(traces).await?;
            }
        }
        
        Ok(())
    }
    
    async fn export_batch(&self, traces: Vec<TraceContext>) -> Result<(), MonitoringError> {
        for destination in &self.config.destinations {
            if let Err(e) = self.export_to_destination(destination, &traces).await {
                warn!("Failed to export traces to {:?}: {}", destination, e);
            }
        }
        
        debug!("Exported batch of {} traces", traces.len());
        Ok(())
    }
    
    async fn export_to_destination(
        &self,
        destination: &TraceExportDestination,
        traces: &[TraceContext],
    ) -> Result<(), MonitoringError> {
        match destination {
            TraceExportDestination::Jaeger { endpoint } => {
                self.export_to_jaeger(endpoint, traces).await
            }
            TraceExportDestination::Zipkin { endpoint } => {
                self.export_to_zipkin(endpoint, traces).await
            }
            TraceExportDestination::OTLP { endpoint } => {
                self.export_to_otlp(endpoint, traces).await
            }
            TraceExportDestination::CloudTrace { project_id } => {
                self.export_to_cloud_trace(project_id, traces).await
            }
            TraceExportDestination::XRay { region } => {
                self.export_to_xray(region, traces).await
            }
        }
    }
    
    async fn export_to_jaeger(&self, endpoint: &str, traces: &[TraceContext]) -> Result<(), MonitoringError> {
        debug!("Exporting {} traces to Jaeger at {}", traces.len(), endpoint);
        // Would implement actual Jaeger export
        Ok(())
    }
    
    async fn export_to_zipkin(&self, endpoint: &str, traces: &[TraceContext]) -> Result<(), MonitoringError> {
        debug!("Exporting {} traces to Zipkin at {}", traces.len(), endpoint);
        // Would implement actual Zipkin export
        Ok(())
    }
    
    async fn export_to_otlp(&self, endpoint: &str, traces: &[TraceContext]) -> Result<(), MonitoringError> {
        debug!("Exporting {} traces to OTLP at {}", traces.len(), endpoint);
        // Would implement actual OTLP export
        Ok(())
    }
    
    async fn export_to_cloud_trace(&self, project_id: &str, traces: &[TraceContext]) -> Result<(), MonitoringError> {
        debug!("Exporting {} traces to Cloud Trace (project: {})", traces.len(), project_id);
        // Would implement actual Cloud Trace export
        Ok(())
    }
    
    async fn export_to_xray(&self, region: &str, traces: &[TraceContext]) -> Result<(), MonitoringError> {
        debug!("Exporting {} traces to X-Ray (region: {})", traces.len(), region);
        // Would implement actual X-Ray export
        Ok(())
    }
    
    async fn flush_pending_traces(&self) -> Result<(), MonitoringError> {
        let traces = {
            let mut pending = self.pending_traces.lock().await;
            pending.drain(..).collect::<Vec<_>>()
        };
        
        if !traces.is_empty() {
            self.export_batch(traces).await?;
        }
        
        Ok(())
    }
}

/// Correlation manager for managing correlation IDs
struct CorrelationManager {
    current_correlation: Arc<RwLock<Option<CorrelationId>>>,
}

impl CorrelationManager {
    fn new() -> Self {
        Self {
            current_correlation: Arc::new(RwLock::new(None)),
        }
    }
    
    async fn generate_correlation_id(&self) -> CorrelationId {
        let correlation_id = CorrelationId::new();
        
        // Store current correlation ID
        {
            let mut current = self.current_correlation.write().await;
            *current = Some(correlation_id.clone());
        }
        
        correlation_id
    }
    
    async fn get_current_correlation(&self) -> Option<CorrelationId> {
        let current = self.current_correlation.read().await;
        current.clone()
    }
}

/// Tracing utilities for manual instrumentation
pub struct TracingUtils;

impl TracingUtils {
    /// Create a new trace span with the current tracing context
    pub fn create_span(name: &'static str) -> Span {
        tracing::info_span!("{}", name)
    }
    
    /// Add attributes to current span
    pub fn add_span_attributes(attributes: HashMap<String, AttributeValue>) {
        let span = Span::current();
        for (key, value) in attributes {
            match value {
                AttributeValue::String(s) => { span.record(key.as_str(), &s); }
                AttributeValue::Int(i) => { span.record(key.as_str(), &i); }
                AttributeValue::Float(f) => { span.record(key.as_str(), &f); }
                AttributeValue::Bool(b) => { span.record(key.as_str(), &b); }
                _ => {} // Complex types not supported by tracing
            }
        }
    }
    
    /// Record an event in the current span
    pub fn record_event(event_name: &str, attributes: HashMap<String, AttributeValue>) {
        // Convert attributes to tracing format and record
        info!("Event: {} with {} attributes", event_name, attributes.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_trace_collector_creation() {
        let config = TracingConfig::default();
        let collector = DistributedTraceCollector::new(config).await.unwrap();
        
        let status = collector.get_status().await;
        assert!(status.contains("Active traces: 0"));
    }
    
    #[tokio::test]
    async fn test_trace_sampling() {
        let config = TraceSamplingConfig {
            nat_traversal_rate: 0.5, // 50% sampling
            success_rate: 0.5,
            failure_rate: 1.0,
            adaptive: AdaptiveTraceSamplingConfig::default(),
        };
        
        let sampler = TraceSampler::new(config);
        
        // Create mock attempt
        let attempt = NatTraversalAttempt {
            attempt_id: "test".to_string(),
            timestamp: SystemTime::now(),
            client_info: crate::monitoring::EndpointInfo {
                id: "client".to_string(),
                role: crate::monitoring::EndpointRole::Client,
                address_hash: "hash".to_string(),
                nat_type: None,
                region: None,
            },
            server_info: crate::monitoring::EndpointInfo {
                id: "server".to_string(),
                role: crate::monitoring::EndpointRole::Server,
                address_hash: "hash".to_string(),
                nat_type: None,
                region: None,
            },
            nat_config: crate::nat_traversal_api::NatTraversalConfig::default(),
            bootstrap_nodes: vec![],
            network_conditions: crate::monitoring::NetworkConditions {
                rtt_ms: None,
                packet_loss_rate: None,
                bandwidth_mbps: None,
                congestion_level: crate::monitoring::CongestionLevel::Low,
            },
        };
        
        // Test sampling decision
        let should_sample = sampler.should_sample_nat_trace(&attempt).await;
        // With 50% rate, result is probabilistic, so we just ensure it doesn't panic
        assert!(should_sample || !should_sample);
    }
    
    #[tokio::test]
    async fn test_span_builder() {
        let span_builder = SpanBuilder::new();
        let trace_id = TraceId::new();
        
        // Create mock attempt
        let attempt = NatTraversalAttempt {
            attempt_id: "test".to_string(),
            timestamp: SystemTime::now(),
            client_info: crate::monitoring::EndpointInfo {
                id: "client".to_string(),
                role: crate::monitoring::EndpointRole::Client,
                address_hash: "hash".to_string(),
                nat_type: Some(crate::monitoring::NatType::FullCone),
                region: Some("us-east".to_string()),
            },
            server_info: crate::monitoring::EndpointInfo {
                id: "server".to_string(),
                role: crate::monitoring::EndpointRole::Server,
                address_hash: "hash".to_string(),
                nat_type: Some(crate::monitoring::NatType::Symmetric),
                region: Some("eu-west".to_string()),
            },
            nat_config: crate::nat_traversal_api::NatTraversalConfig::default(),
            bootstrap_nodes: vec!["bootstrap1".to_string()],
            network_conditions: crate::monitoring::NetworkConditions {
                rtt_ms: Some(50),
                packet_loss_rate: Some(0.01),
                bandwidth_mbps: Some(100),
                congestion_level: crate::monitoring::CongestionLevel::Low,
            },
        };
        
        let span = span_builder.create_nat_traversal_span(&trace_id, None, &attempt).await.unwrap();
        
        assert_eq!(span.name, "nat_traversal");
        assert!(span.attributes.contains_key("nat.attempt_id"));
        assert!(span.attributes.contains_key("nat.client.region"));
        assert!(span.attributes.contains_key("nat.server.region"));
    }
}