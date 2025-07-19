//! Structured Logging for NAT Traversal Operations
//!
//! This module provides comprehensive structured logging for all NAT traversal
//! phases, frame transmission/reception, and diagnostic information.

use std::{
    collections::HashMap,
    net::SocketAddr,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn, Span};

use crate::{
    monitoring::{ErrorCategory, NatType},
    nat_traversal_api::PeerId,
    VarInt,
};

/// Structured logger for NAT traversal operations
pub struct NatTraversalLogger {
    /// Logger configuration
    config: LoggingConfig,
    /// Current logging context
    context: LoggingContext,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Enable debug logging for frame transmission
    pub enable_frame_debug: bool,
    /// Enable performance logging
    pub enable_performance_logging: bool,
    /// Enable failure analysis logging
    pub enable_failure_analysis: bool,
    /// Log level for different phases
    pub phase_log_levels: HashMap<String, String>,
    /// Include sensitive information in logs
    pub include_sensitive_info: bool,
    /// Maximum log message size
    pub max_message_size: usize,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            enable_frame_debug: true,
            enable_performance_logging: true,
            enable_failure_analysis: true,
            phase_log_levels: HashMap::from([
                ("discovery".to_string(), "info".to_string()),
                ("coordination".to_string(), "info".to_string()),
                ("hole_punching".to_string(), "debug".to_string()),
                ("validation".to_string(), "info".to_string()),
            ]),
            include_sensitive_info: false,
            max_message_size: 4096,
        }
    }
}

/// Logging context for correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingContext {
    /// Session ID for correlation
    pub session_id: String,
    /// Peer ID being connected to
    pub peer_id: Option<PeerId>,
    /// Local endpoint role
    pub endpoint_role: String,
    /// Bootstrap node being used
    pub bootstrap_node: Option<SocketAddr>,
    /// Current phase
    pub current_phase: NatTraversalPhase,
    /// Additional context fields
    pub context_fields: HashMap<String, String>,
}

/// NAT traversal phases for logging
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NatTraversalPhase {
    Initialization,
    CandidateDiscovery,
    BootstrapCoordination,
    HolePunching,
    PathValidation,
    ConnectionEstablishment,
    Completed,
    Failed,
}

impl std::fmt::Display for NatTraversalPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatTraversalPhase::Initialization => write!(f, "initialization"),
            NatTraversalPhase::CandidateDiscovery => write!(f, "candidate_discovery"),
            NatTraversalPhase::BootstrapCoordination => write!(f, "bootstrap_coordination"),
            NatTraversalPhase::HolePunching => write!(f, "hole_punching"),
            NatTraversalPhase::PathValidation => write!(f, "path_validation"),
            NatTraversalPhase::ConnectionEstablishment => write!(f, "connection_establishment"),
            NatTraversalPhase::Completed => write!(f, "completed"),
            NatTraversalPhase::Failed => write!(f, "failed"),
        }
    }
}

impl NatTraversalLogger {
    /// Create new NAT traversal logger
    pub fn new(config: LoggingConfig) -> Self {
        Self {
            config,
            context: LoggingContext {
                session_id: uuid::Uuid::new_v4().to_string(),
                peer_id: None,
                endpoint_role: "unknown".to_string(),
                bootstrap_node: None,
                current_phase: NatTraversalPhase::Initialization,
                context_fields: HashMap::new(),
            },
        }
    }

    /// Set logging context
    pub fn set_context(&mut self, context: LoggingContext) {
        self.context = context;
    }

    /// Update current phase
    pub fn set_phase(&mut self, phase: NatTraversalPhase) {
        self.context.current_phase = phase;
    }

    /// Add context field
    pub fn add_context(&mut self, key: String, value: String) {
        self.context.context_fields.insert(key, value);
    }

    /// Log phase transition
    pub fn log_phase_transition(&self, from_phase: NatTraversalPhase, to_phase: NatTraversalPhase, duration: Option<Duration>) {
        let span = tracing::info_span!(
            "nat_traversal_phase_transition",
            session_id = %self.context.session_id,
            peer_id = ?self.context.peer_id,
            from_phase = %from_phase,
            to_phase = %to_phase,
            duration_ms = duration.map(|d| d.as_millis()),
        );

        let _enter = span.enter();
        info!(
            "NAT traversal phase transition: {} -> {} (duration: {:?})",
            from_phase, to_phase, duration
        );
    }

    /// Log candidate discovery start
    pub fn log_candidate_discovery_start(&self, bootstrap_nodes: &[SocketAddr], nat_type: Option<NatType>) {
        let span = tracing::info_span!(
            "candidate_discovery_start",
            session_id = %self.context.session_id,
            peer_id = ?self.context.peer_id,
            bootstrap_count = bootstrap_nodes.len(),
            nat_type = ?nat_type,
        );

        let _enter = span.enter();
        info!(
            "Starting candidate discovery with {} bootstrap nodes (NAT type: {:?})",
            bootstrap_nodes.len(), nat_type
        );

        for (i, node) in bootstrap_nodes.iter().enumerate() {
            debug!("Bootstrap node {}: {}", i + 1, self.sanitize_address(*node));
        }
    }

    /// Log candidate discovered
    pub fn log_candidate_discovered(&self, candidate: &CandidateInfo) {
        let span = tracing::debug_span!(
            "candidate_discovered",
            session_id = %self.context.session_id,
            peer_id = ?self.context.peer_id,
            candidate_type = %candidate.candidate_type,
            priority = candidate.priority,
            source = %candidate.source,
        );

        let _enter = span.enter();
        debug!(
            "Discovered candidate: {} (type: {}, priority: {}, source: {})",
            self.sanitize_address(candidate.address),
            candidate.candidate_type,
            candidate.priority,
            candidate.source
        );
    }

    /// Log bootstrap coordination request
    pub fn log_coordination_request(&self, coordinator: SocketAddr, round_id: VarInt, candidates: &[CandidateInfo]) {
        let span = tracing::info_span!(
            "coordination_request",
            session_id = %self.context.session_id,
            peer_id = ?self.context.peer_id,
            coordinator = %self.sanitize_address(coordinator),
            round_id = %round_id,
            candidate_count = candidates.len(),
        );

        let _enter = span.enter();
        info!(
            "Sending coordination request to {} (round: {}, candidates: {})",
            self.sanitize_address(coordinator), round_id, candidates.len()
        );

        if self.config.enable_frame_debug {
            for candidate in candidates {
                debug!(
                    "Candidate in request: {} (priority: {})",
                    self.sanitize_address(candidate.address), candidate.priority
                );
            }
        }
    }

    /// Log coordination response
    pub fn log_coordination_response(&self, coordinator: SocketAddr, success: bool, peer_candidates: Option<&[CandidateInfo]>) {
        let span = tracing::info_span!(
            "coordination_response",
            session_id = %self.context.session_id,
            peer_id = ?self.context.peer_id,
            coordinator = %self.sanitize_address(coordinator),
            success = success,
            peer_candidate_count = peer_candidates.map(|c| c.len()),
        );

        let _enter = span.enter();
        if success {
            info!(
                "Received coordination response from {} (peer candidates: {})",
                self.sanitize_address(coordinator),
                peer_candidates.map(|c| c.len()).unwrap_or(0)
            );

            if let Some(candidates) = peer_candidates {
                if self.config.enable_frame_debug {
                    for candidate in candidates {
                        debug!(
                            "Peer candidate: {} (priority: {})",
                            self.sanitize_address(candidate.address), candidate.priority
                        );
                    }
                }
            }
        } else {
            warn!(
                "Coordination request to {} failed",
                self.sanitize_address(coordinator)
            );
        }
    }

    /// Log hole punching start
    pub fn log_hole_punching_start(&self, target_addresses: &[SocketAddr], strategy: &str) {
        let span = tracing::info_span!(
            "hole_punching_start",
            session_id = %self.context.session_id,
            peer_id = ?self.context.peer_id,
            target_count = target_addresses.len(),
            strategy = strategy,
        );

        let _enter = span.enter();
        info!(
            "Starting hole punching to {} targets (strategy: {})",
            target_addresses.len(), strategy
        );

        for (i, addr) in target_addresses.iter().enumerate() {
            debug!("Hole punch target {}: {}", i + 1, self.sanitize_address(*addr));
        }
    }

    /// Log hole punching attempt
    pub fn log_hole_punch_attempt(&self, target: SocketAddr, attempt_number: u32, packet_size: usize) {
        if self.config.enable_frame_debug {
            let span = tracing::debug_span!(
                "hole_punch_attempt",
                session_id = %self.context.session_id,
                peer_id = ?self.context.peer_id,
                target = %self.sanitize_address(target),
                attempt = attempt_number,
                packet_size = packet_size,
            );

            let _enter = span.enter();
            debug!(
                "Hole punch attempt {} to {} (packet size: {} bytes)",
                attempt_number, self.sanitize_address(target), packet_size
            );
        }
    }

    /// Log hole punching result
    pub fn log_hole_punch_result(&self, target: SocketAddr, success: bool, response_time: Option<Duration>) {
        let span = tracing::info_span!(
            "hole_punch_result",
            session_id = %self.context.session_id,
            peer_id = ?self.context.peer_id,
            target = %self.sanitize_address(target),
            success = success,
            response_time_ms = response_time.map(|d| d.as_millis()),
        );

        let _enter = span.enter();
        if success {
            info!(
                "Hole punch to {} succeeded (response time: {:?})",
                self.sanitize_address(target), response_time
            );
        } else {
            warn!(
                "Hole punch to {} failed",
                self.sanitize_address(target)
            );
        }
    }

    /// Log path validation start
    pub fn log_path_validation_start(&self, paths: &[SocketAddr]) {
        let span = tracing::info_span!(
            "path_validation_start",
            session_id = %self.context.session_id,
            peer_id = ?self.context.peer_id,
            path_count = paths.len(),
        );

        let _enter = span.enter();
        info!("Starting path validation for {} paths", paths.len());

        for (i, path) in paths.iter().enumerate() {
            debug!("Validating path {}: {}", i + 1, self.sanitize_address(*path));
        }
    }

    /// Log path validation result
    pub fn log_path_validation_result(&self, path: SocketAddr, success: bool, rtt: Option<Duration>, error: Option<&str>) {
        let span = tracing::info_span!(
            "path_validation_result",
            session_id = %self.context.session_id,
            peer_id = ?self.context.peer_id,
            path = %self.sanitize_address(path),
            success = success,
            rtt_ms = rtt.map(|d| d.as_millis()),
            error = error,
        );

        let _enter = span.enter();
        if success {
            info!(
                "Path validation to {} succeeded (RTT: {:?})",
                self.sanitize_address(path), rtt
            );
        } else {
            warn!(
                "Path validation to {} failed: {}",
                self.sanitize_address(path),
                error.unwrap_or("unknown error")
            );
        }
    }

    /// Log connection establishment
    pub fn log_connection_established(&self, remote_address: SocketAddr, total_time: Duration, method: &str) {
        let span = tracing::info_span!(
            "connection_established",
            session_id = %self.context.session_id,
            peer_id = ?self.context.peer_id,
            remote_address = %self.sanitize_address(remote_address),
            total_time_ms = total_time.as_millis(),
            method = method,
        );

        let _enter = span.enter();
        info!(
            "Connection established to {} via {} (total time: {:?})",
            self.sanitize_address(remote_address), method, total_time
        );
    }

    /// Log NAT traversal failure
    pub fn log_traversal_failure(&self, error_category: ErrorCategory, error_message: &str, total_time: Duration, attempts: u32) {
        let span = tracing::error_span!(
            "nat_traversal_failure",
            session_id = %self.context.session_id,
            peer_id = ?self.context.peer_id,
            error_category = ?error_category,
            total_time_ms = total_time.as_millis(),
            attempts = attempts,
        );

        let _enter = span.enter();
        error!(
            "NAT traversal failed: {} (category: {:?}, time: {:?}, attempts: {})",
            error_message, error_category, total_time, attempts
        );
    }

    /// Log frame transmission
    pub fn log_frame_transmission(&self, frame_type: &str, destination: SocketAddr, frame_size: usize, sequence: Option<u64>) {
        if self.config.enable_frame_debug {
            let span = tracing::debug_span!(
                "frame_transmission",
                session_id = %self.context.session_id,
                peer_id = ?self.context.peer_id,
                frame_type = frame_type,
                destination = %self.sanitize_address(destination),
                frame_size = frame_size,
                sequence = sequence,
            );

            let _enter = span.enter();
            debug!(
                "Transmitting {} frame to {} (size: {} bytes, seq: {:?})",
                frame_type, self.sanitize_address(destination), frame_size, sequence
            );
        }
    }

    /// Log frame reception
    pub fn log_frame_reception(&self, frame_type: &str, source: SocketAddr, frame_size: usize, sequence: Option<u64>) {
        if self.config.enable_frame_debug {
            let span = tracing::debug_span!(
                "frame_reception",
                session_id = %self.context.session_id,
                peer_id = ?self.context.peer_id,
                frame_type = frame_type,
                source = %self.sanitize_address(source),
                frame_size = frame_size,
                sequence = sequence,
            );

            let _enter = span.enter();
            debug!(
                "Received {} frame from {} (size: {} bytes, seq: {:?})",
                frame_type, self.sanitize_address(source), frame_size, sequence
            );
        }
    }

    /// Log performance metrics
    pub fn log_performance_metrics(&self, metrics: &PerformanceMetrics) {
        if self.config.enable_performance_logging {
            let span = tracing::info_span!(
                "performance_metrics",
                session_id = %self.context.session_id,
                peer_id = ?self.context.peer_id,
                connection_time_ms = metrics.connection_time_ms,
                first_candidate_time_ms = metrics.first_candidate_time_ms,
                candidates_tried = metrics.candidates_tried,
                round_trips = metrics.round_trips,
                setup_bytes = metrics.setup_bytes,
            );

            let _enter = span.enter();
            info!(
                "Performance metrics - Connection: {}ms, First candidate: {}ms, Candidates tried: {}, Round trips: {}, Setup bytes: {}",
                metrics.connection_time_ms,
                metrics.first_candidate_time_ms,
                metrics.candidates_tried,
                metrics.round_trips,
                metrics.setup_bytes
            );
        }
    }

    /// Log diagnostic information for failures
    pub fn log_failure_diagnostics(&self, diagnostics: &FailureDiagnostics) {
        if self.config.enable_failure_analysis {
            let span = tracing::warn_span!(
                "failure_diagnostics",
                session_id = %self.context.session_id,
                peer_id = ?self.context.peer_id,
                failure_stage = %diagnostics.failure_stage,
                primary_cause = %diagnostics.primary_cause,
                confidence = diagnostics.confidence,
            );

            let _enter = span.enter();
            warn!(
                "Failure diagnostics - Stage: {}, Cause: {}, Confidence: {:.2}",
                diagnostics.failure_stage, diagnostics.primary_cause, diagnostics.confidence
            );

            for (i, factor) in diagnostics.contributing_factors.iter().enumerate() {
                debug!("Contributing factor {}: {}", i + 1, factor);
            }

            for (i, suggestion) in diagnostics.recovery_suggestions.iter().enumerate() {
                info!("Recovery suggestion {}: {}", i + 1, suggestion);
            }
        }
    }

    /// Create a tracing span for NAT traversal operation
    pub fn create_traversal_span(&self, operation: &str) -> Span {
        tracing::info_span!(
            "nat_traversal_operation",
            session_id = %self.context.session_id,
            peer_id = ?self.context.peer_id,
            operation = operation,
            phase = %self.context.current_phase,
            endpoint_role = %self.context.endpoint_role,
        )
    }

    /// Sanitize address for logging (remove sensitive information if configured)
    fn sanitize_address(&self, addr: SocketAddr) -> String {
        if self.config.include_sensitive_info {
            addr.to_string()
        } else {
            // Hash the IP address for privacy while maintaining uniqueness
            let ip_hash = self.hash_ip(addr.ip());
            format!("{}:{}", ip_hash, addr.port())
        }
    }

    /// Hash IP address for privacy
    fn hash_ip(&self, ip: std::net::IpAddr) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        ip.hash(&mut hasher);
        format!("ip_{:x}", hasher.finish() & 0xFFFF) // Use only last 16 bits for readability
    }
}

/// Candidate information for logging
#[derive(Debug, Clone)]
pub struct CandidateInfo {
    pub address: SocketAddr,
    pub candidate_type: String,
    pub priority: u32,
    pub source: String,
}

/// Performance metrics for logging
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub connection_time_ms: u64,
    pub first_candidate_time_ms: u64,
    pub candidates_tried: u32,
    pub round_trips: u32,
    pub setup_bytes: u64,
}

/// Failure diagnostics for logging
#[derive(Debug, Clone)]
pub struct FailureDiagnostics {
    pub failure_stage: String,
    pub primary_cause: String,
    pub confidence: f64,
    pub contributing_factors: Vec<String>,
    pub recovery_suggestions: Vec<String>,
}

/// Troubleshooting guide generator
pub struct TroubleshootingGuide;

impl TroubleshootingGuide {
    /// Generate troubleshooting guide based on failure patterns
    pub fn generate_guide(error_category: ErrorCategory, failure_stage: &str, context: &HashMap<String, String>) -> String {
        let mut guide = String::new();
        
        guide.push_str(&format!("# Troubleshooting Guide: {:?} at {}\n\n", error_category, failure_stage));
        
        match error_category {
            ErrorCategory::NetworkConnectivity => {
                guide.push_str("## Network Connectivity Issues\n\n");
                guide.push_str("### Common Causes:\n");
                guide.push_str("- Bootstrap nodes are unreachable\n");
                guide.push_str("- Firewall blocking UDP traffic\n");
                guide.push_str("- Network interface down\n");
                guide.push_str("- DNS resolution failures\n\n");
                
                guide.push_str("### Diagnostic Steps:\n");
                guide.push_str("1. Check network interface status: `ip addr show`\n");
                guide.push_str("2. Test bootstrap node connectivity: `nc -u <bootstrap_ip> <port>`\n");
                guide.push_str("3. Check firewall rules: `iptables -L` or `ufw status`\n");
                guide.push_str("4. Verify DNS resolution: `nslookup <bootstrap_hostname>`\n\n");
                
                guide.push_str("### Recovery Actions:\n");
                guide.push_str("- Restart network interface\n");
                guide.push_str("- Update firewall rules to allow UDP traffic\n");
                guide.push_str("- Try alternative bootstrap nodes\n");
                guide.push_str("- Check network configuration\n");
            }
            
            ErrorCategory::NatTraversal => {
                guide.push_str("## NAT Traversal Issues\n\n");
                guide.push_str("### Common Causes:\n");
                guide.push_str("- Symmetric NAT preventing hole punching\n");
                guide.push_str("- Aggressive NAT timeout settings\n");
                guide.push_str("- Carrier-grade NAT (CGNAT)\n");
                guide.push_str("- Coordination timing issues\n\n");
                
                guide.push_str("### Diagnostic Steps:\n");
                guide.push_str("1. Detect NAT type using STUN\n");
                guide.push_str("2. Check NAT timeout behavior\n");
                guide.push_str("3. Verify bootstrap node coordination\n");
                guide.push_str("4. Test with different candidate pairs\n\n");
                
                guide.push_str("### Recovery Actions:\n");
                guide.push_str("- Enable relay fallback\n");
                guide.push_str("- Adjust coordination timing\n");
                guide.push_str("- Try different bootstrap nodes\n");
                guide.push_str("- Consider TURN relay servers\n");
            }
            
            ErrorCategory::Timeout => {
                guide.push_str("## Timeout Issues\n\n");
                guide.push_str("### Common Causes:\n");
                guide.push_str("- Network latency higher than expected\n");
                guide.push_str("- Aggressive timeout configuration\n");
                guide.push_str("- Bootstrap node overload\n");
                guide.push_str("- Packet loss causing retransmissions\n\n");
                
                guide.push_str("### Diagnostic Steps:\n");
                guide.push_str("1. Measure network latency: `ping <bootstrap_node>`\n");
                guide.push_str("2. Check packet loss: `mtr <bootstrap_node>`\n");
                guide.push_str("3. Monitor bootstrap node response times\n");
                guide.push_str("4. Review timeout configuration\n\n");
                
                guide.push_str("### Recovery Actions:\n");
                guide.push_str("- Increase timeout values\n");
                guide.push_str("- Implement adaptive timeouts\n");
                guide.push_str("- Use multiple bootstrap nodes\n");
                guide.push_str("- Optimize network path\n");
            }
            
            _ => {
                guide.push_str("## General Troubleshooting\n\n");
                guide.push_str("### Basic Diagnostic Steps:\n");
                guide.push_str("1. Check system logs for errors\n");
                guide.push_str("2. Verify configuration settings\n");
                guide.push_str("3. Test with minimal configuration\n");
                guide.push_str("4. Enable debug logging\n\n");
            }
        }
        
        // Add context-specific information
        if !context.is_empty() {
            guide.push_str("## Context Information:\n");
            for (key, value) in context {
                guide.push_str(&format!("- {}: {}\n", key, value));
            }
            guide.push('\n');
        }
        
        guide.push_str("## Additional Resources:\n");
        guide.push_str("- NAT Traversal RFC: https://tools.ietf.org/html/rfc5389\n");
        guide.push_str("- QUIC NAT Traversal Draft: https://datatracker.ietf.org/doc/draft-seemann-quic-nat-traversal/\n");
        guide.push_str("- Project Documentation: https://github.com/your-org/ant-quic\n");
        
        guide
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phase_display() {
        assert_eq!(NatTraversalPhase::CandidateDiscovery.to_string(), "candidate_discovery");
        assert_eq!(NatTraversalPhase::HolePunching.to_string(), "hole_punching");
    }

    #[test]
    fn test_troubleshooting_guide_generation() {
        let context = HashMap::from([
            ("nat_type".to_string(), "Symmetric".to_string()),
            ("bootstrap_nodes".to_string(), "2".to_string()),
        ]);
        
        let guide = TroubleshootingGuide::generate_guide(
            ErrorCategory::NatTraversal,
            "hole_punching",
            &context
        );
        
        assert!(guide.contains("NAT Traversal Issues"));
        assert!(guide.contains("Symmetric NAT"));
        assert!(guide.contains("nat_type: Symmetric"));
    }

    #[test]
    fn test_address_sanitization() {
        let config = LoggingConfig {
            include_sensitive_info: false,
            ..LoggingConfig::default()
        };
        
        let logger = NatTraversalLogger::new(config);
        let addr: SocketAddr = "192.168.1.100:9000".parse().unwrap();
        let sanitized = logger.sanitize_address(addr);
        
        // Should not contain the original IP
        assert!(!sanitized.contains("192.168.1.100"));
        // Should contain the port
        assert!(sanitized.contains("9000"));
        // Should contain hash prefix
        assert!(sanitized.starts_with("ip_"));
    }
}