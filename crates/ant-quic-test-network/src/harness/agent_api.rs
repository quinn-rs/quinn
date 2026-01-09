use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use uuid::Uuid;

use super::{ArtifactManifest, AttemptResult, NatProfileSpec, ScenarioSpec};
use crate::registry::NatType;

pub const FALLBACK_SOCKET_ADDR: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

/// Error type for socket address parsing failures
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketAddrParseError {
    /// The input string that failed to parse
    pub input: String,
    /// The reason for the failure
    pub reason: String,
}

impl std::fmt::Display for SocketAddrParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "failed to parse socket address '{}': {}",
            self.input, self.reason
        )
    }
}

impl std::error::Error for SocketAddrParseError {}

/// Parse a socket address string, returning an error with context on failure.
///
/// This function explicitly fails rather than silently falling back to a default,
/// ensuring that configuration errors are caught early.
pub fn parse_socket_addr(s: &str) -> Result<SocketAddr, SocketAddrParseError> {
    s.parse()
        .map_err(|e: std::net::AddrParseError| SocketAddrParseError {
            input: s.to_string(),
            reason: e.to_string(),
        })
}

/// Parse a socket address with explicit fallback handling.
///
/// **DEPRECATED**: This function silently falls back to `0.0.0.0:0` on parse failure,
/// which can mask configuration errors. Use `parse_socket_addr()` instead and handle
/// errors explicitly.
#[deprecated(
    since = "0.2.0",
    note = "Use parse_socket_addr() and handle errors explicitly"
)]
pub fn parse_socket_addr_or_fallback(s: &str) -> SocketAddr {
    s.parse().unwrap_or(FALLBACK_SOCKET_ADDR)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub agent_id: String,
    pub version: String,
    pub capabilities: AgentCapabilities,
    pub api_base_url: String,
    pub p2p_listen_addr: SocketAddr,
    pub nat_profiles_available: Vec<String>,
    pub status: AgentStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCapabilities {
    pub protocol_version: u32,
    pub supported_artifact_types: Vec<String>,
    pub supported_nat_profiles: Vec<NatType>,
    pub max_concurrent_tests: u32,
    pub can_capture_pcaps: bool,
    pub can_simulate_nat: bool,
    pub has_docker: bool,
    pub has_tc: bool,
}

impl Default for AgentCapabilities {
    fn default() -> Self {
        Self {
            protocol_version: 1,
            supported_artifact_types: vec!["agent_log".into(), "sut_log".into(), "metrics".into()],
            supported_nat_profiles: vec![NatType::None, NatType::FullCone],
            max_concurrent_tests: 4,
            can_capture_pcaps: false,
            can_simulate_nat: false,
            has_docker: false,
            has_tc: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    #[default]
    Idle,
    Running,
    Error,
    Offline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartRunRequest {
    pub run_id: Uuid,
    pub scenario: ScenarioSpec,
    pub agent_role: String,
    pub peer_agents: Vec<PeerAgentInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAgentInfo {
    pub agent_id: String,
    pub api_base_url: Option<String>,
    pub p2p_listen_addr: SocketAddr,
    pub nat_profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartRunResponse {
    pub success: bool,
    pub run_id: Uuid,
    pub error: Option<String>,
    pub estimated_duration_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StopRunRequest {
    pub run_id: Uuid,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StopRunResponse {
    pub success: bool,
    pub run_id: Uuid,
    pub attempts_completed: u32,
    pub artifacts_uploaded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunStatusRequest {
    pub run_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunStatusResponse {
    pub run_id: Uuid,
    pub status: RunStatus,
    pub progress: RunProgress,
    pub current_stage: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Pending,
    Preflight,
    Running,
    Uploading,
    Completed,
    Failed,
    Cancelled,
}

impl RunStatus {
    /// Returns true if this is a terminal state (no further transitions possible).
    ///
    /// Uses exhaustive matching to ensure compile-time safety when new variants are added.
    pub fn is_terminal(&self) -> bool {
        match self {
            RunStatus::Pending
            | RunStatus::Preflight
            | RunStatus::Running
            | RunStatus::Uploading => false,
            RunStatus::Completed | RunStatus::Failed | RunStatus::Cancelled => true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunProgress {
    pub total_attempts: u32,
    pub completed_attempts: u32,
    pub successful_attempts: u32,
    pub failed_attempts: u32,
    pub current_attempt: Option<u32>,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetResultsRequest {
    pub run_id: Uuid,
    pub format: ResultFormat,
    pub include_artifacts: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultFormat {
    Jsonl,
    Json,
    Summary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetResultsResponse {
    pub run_id: Uuid,
    pub results: Vec<AttemptResult>,
    pub artifacts: Option<Vec<ArtifactManifest>>,
    pub summary: Option<super::RunSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyProfileRequest {
    pub profile: NatProfileSpec,
    pub interface: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyProfileResponse {
    pub success: bool,
    pub profile_name: String,
    pub error: Option<String>,
    pub nat_type_detected: Option<NatType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearProfileRequest {
    pub interface: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearProfileResponse {
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StartRunResult {
    pub run_id: Uuid,
    pub started_agents: Vec<String>,
    pub failed_agents: Vec<(String, String)>,
}

impl StartRunResult {
    pub fn new(run_id: Uuid) -> Self {
        Self {
            run_id,
            started_agents: Vec::new(),
            failed_agents: Vec::new(),
        }
    }

    pub fn record_success(&mut self, agent_id: &str) {
        self.started_agents.push(agent_id.to_string());
    }

    pub fn record_failure(&mut self, agent_id: &str, error: &str) {
        self.failed_agents
            .push((agent_id.to_string(), error.to_string()));
    }

    pub fn has_any_success(&self) -> bool {
        !self.started_agents.is_empty()
    }

    pub fn all_succeeded(&self) -> bool {
        self.failed_agents.is_empty() && !self.started_agents.is_empty()
    }

    pub fn successful_agents(&self) -> &[String] {
        &self.started_agents
    }

    pub fn failed_agents(&self) -> &[(String, String)] {
        &self.failed_agents
    }
}

#[derive(Debug, Clone)]
pub struct CollectionResult<T> {
    pub items: Vec<T>,
    pub failed_sources: Vec<(String, String)>,
}

impl<T> CollectionResult<T> {
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            failed_sources: Vec::new(),
        }
    }

    pub fn add_items(&mut self, _source: &str, mut items: Vec<T>) {
        self.items.append(&mut items);
    }

    pub fn record_failure(&mut self, source: &str, error: &str) {
        self.failed_sources
            .push((source.to_string(), error.to_string()));
    }

    pub fn is_complete(&self) -> bool {
        self.failed_sources.is_empty()
    }
}

impl<T> Default for CollectionResult<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct StatusPollResult {
    pub statuses: std::collections::HashMap<String, RunStatusResponse>,
    pub failed_agents: Vec<(String, String)>,
    pub expected_count: usize,
}

impl StatusPollResult {
    pub fn new(expected_count: usize) -> Self {
        Self {
            statuses: std::collections::HashMap::new(),
            failed_agents: Vec::new(),
            expected_count,
        }
    }

    pub fn record_status(&mut self, agent_id: &str, status: RunStatusResponse) {
        self.statuses.insert(agent_id.to_string(), status);
    }

    pub fn record_failure(&mut self, agent_id: &str, error: &str) {
        self.failed_agents
            .push((agent_id.to_string(), error.to_string()));
    }

    pub fn all_responded(&self) -> bool {
        self.statuses.len() + self.failed_agents.len() >= self.expected_count
    }

    /// Returns true if all agents have reached a terminal state.
    ///
    /// An agent is considered terminal if:
    /// - It responded with a terminal RunStatus (Completed, Failed, Cancelled), OR
    /// - It failed to respond (communication failure - won't recover)
    ///
    /// Callers should check `failed_agents` separately to handle communication failures.
    pub fn all_complete(&self) -> bool {
        if !self.all_responded() {
            return false;
        }
        // Failed agents are terminal from polling perspective - they won't provide further updates.
        // All responding agents must also be in terminal state.
        self.statuses.values().all(|s| s.status.is_terminal())
    }

    pub fn missing_count(&self) -> usize {
        self.expected_count
            .saturating_sub(self.statuses.len() + self.failed_agents.len())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResponse {
    pub healthy: bool,
    pub agent_id: String,
    pub version: String,
    pub status: AgentStatus,
    pub uptime_secs: u64,
    pub active_runs: Vec<Uuid>,
    pub last_error: Option<String>,
    pub p2p_listen_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRequest {
    pub orchestrator_id: String,
    pub protocol_version: u32,
    pub required_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub compatible: bool,
    pub agent_info: AgentInfo,
    pub missing_capabilities: Vec<String>,
    pub warnings: Vec<String>,
}

impl HandshakeResponse {
    pub fn compatible(agent_info: AgentInfo) -> Self {
        Self {
            compatible: true,
            agent_info,
            missing_capabilities: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn incompatible(agent_info: AgentInfo, missing: Vec<String>) -> Self {
        Self {
            compatible: false,
            agent_info,
            missing_capabilities: missing,
            warnings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BarrierRequest {
    pub run_id: Uuid,
    pub barrier_name: String,
    pub agent_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BarrierResponse {
    pub released: bool,
    pub barrier_name: String,
    pub all_agents_ready: bool,
    pub waiting_agents: Vec<String>,
    pub timeout: bool,
}

pub mod endpoints {
    pub const HEALTH: &str = "/health";
    pub const HANDSHAKE: &str = "/handshake";
    pub const RUN_START: &str = "/run/start";
    pub const RUN_STOP: &str = "/run/{id}/stop";
    pub const RUN_STATUS: &str = "/run/{id}/status";
    pub const RUN_RESULTS: &str = "/run/{id}/results";
    pub const PROFILE_APPLY: &str = "/node/profile";
    pub const PROFILE_CLEAR: &str = "/node/profile/clear";
    pub const BARRIER: &str = "/barrier";
}

#[derive(Debug, Clone)]
pub struct AgentClient {
    pub base_url: String,
    pub agent_id: String,
    pub p2p_listen_addr: SocketAddr,
}

impl AgentClient {
    pub fn new(base_url: &str, agent_id: &str, p2p_listen_addr: SocketAddr) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            agent_id: agent_id.to_string(),
            p2p_listen_addr,
        }
    }

    pub fn health_url(&self) -> String {
        format!("{}{}", self.base_url, endpoints::HEALTH)
    }

    pub fn handshake_url(&self) -> String {
        format!("{}{}", self.base_url, endpoints::HANDSHAKE)
    }

    pub fn start_run_url(&self) -> String {
        format!("{}{}", self.base_url, endpoints::RUN_START)
    }

    pub fn stop_run_url(&self, run_id: Uuid) -> String {
        format!("{}/run/{}/stop", self.base_url, run_id)
    }

    pub fn status_url(&self, run_id: Uuid) -> String {
        format!("{}/run/{}/status", self.base_url, run_id)
    }

    pub fn results_url(&self, run_id: Uuid) -> String {
        format!("{}/run/{}/results", self.base_url, run_id)
    }

    pub fn apply_profile_url(&self) -> String {
        format!("{}{}", self.base_url, endpoints::PROFILE_APPLY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_capabilities_default() {
        let caps = AgentCapabilities::default();
        assert_eq!(caps.protocol_version, 1);
        assert!(!caps.can_capture_pcaps);
    }

    #[test]
    fn test_agent_client_urls() {
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let client = AgentClient::new("http://localhost:8080", "agent-1", addr);
        assert_eq!(client.health_url(), "http://localhost:8080/health");

        let run_id = Uuid::new_v4();
        assert!(client.status_url(run_id).contains(&run_id.to_string()));
    }

    #[test]
    fn test_handshake_response_compatible() {
        let agent_info = AgentInfo {
            agent_id: "agent-1".into(),
            version: "0.1.0".into(),
            capabilities: AgentCapabilities::default(),
            api_base_url: "http://127.0.0.1:8080".into(),
            p2p_listen_addr: "127.0.0.1:9000".parse().unwrap(),
            nat_profiles_available: vec!["none".into()],
            status: AgentStatus::Idle,
        };

        let response = HandshakeResponse::compatible(agent_info);
        assert!(response.compatible);
        assert!(response.missing_capabilities.is_empty());
    }

    #[test]
    fn test_run_status_serialization() {
        let status = RunStatus::Running;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"running\"");
    }

    #[test]
    fn test_fallback_addr_is_unspecified_port_zero() {
        assert!(FALLBACK_SOCKET_ADDR.ip().is_unspecified());
        assert_eq!(FALLBACK_SOCKET_ADDR.port(), 0);
    }

    // ==================== parse_socket_addr (new API) ====================

    #[test]
    fn test_parse_socket_addr_valid_ipv4() {
        let result = parse_socket_addr("192.168.1.100:8080");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), "192.168.1.100:8080");
    }

    #[test]
    fn test_parse_socket_addr_valid_ipv6() {
        let result = parse_socket_addr("[::1]:9000");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), "[::1]:9000");
    }

    #[test]
    fn test_parse_socket_addr_invalid_returns_error() {
        let result = parse_socket_addr("not-an-address");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.input, "not-an-address");
        assert!(!err.reason.is_empty());
    }

    #[test]
    fn test_parse_socket_addr_http_url_returns_error() {
        let result = parse_socket_addr("http://localhost:8080");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.input, "http://localhost:8080");
    }

    #[test]
    fn test_parse_socket_addr_empty_returns_error() {
        let result = parse_socket_addr("");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.input, "");
    }

    #[test]
    fn test_parse_socket_addr_missing_port_returns_error() {
        let result = parse_socket_addr("192.168.1.1");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.input, "192.168.1.1");
    }

    #[test]
    fn test_socket_addr_parse_error_display() {
        let err = SocketAddrParseError {
            input: "bad:addr".to_string(),
            reason: "invalid format".to_string(),
        };
        let display = format!("{}", err);
        assert!(display.contains("bad:addr"));
        assert!(display.contains("invalid format"));
    }

    // ==================== parse_socket_addr_or_fallback (deprecated) ====================

    #[test]
    #[allow(deprecated)]
    fn test_parse_socket_addr_or_fallback_invalid_returns_fallback() {
        let result = parse_socket_addr_or_fallback("not-an-address");
        assert_eq!(result, FALLBACK_SOCKET_ADDR);
    }

    #[test]
    #[allow(deprecated)]
    fn test_parse_socket_addr_or_fallback_empty_returns_fallback() {
        let result = parse_socket_addr_or_fallback("");
        assert_eq!(result, FALLBACK_SOCKET_ADDR);
    }

    #[test]
    fn test_agent_info_has_separate_api_and_p2p_addresses() {
        let info = AgentInfo {
            agent_id: "agent-1".into(),
            version: "0.1.0".into(),
            capabilities: AgentCapabilities::default(),
            api_base_url: "http://agent-1.example.com:8080".into(),
            p2p_listen_addr: "192.168.1.100:9000".parse().unwrap(),
            nat_profiles_available: vec!["none".into()],
            status: AgentStatus::Idle,
        };

        assert_eq!(info.api_base_url, "http://agent-1.example.com:8080");
        assert_eq!(info.p2p_listen_addr.to_string(), "192.168.1.100:9000");
    }

    #[test]
    fn test_peer_agent_info_has_separate_api_and_p2p_addresses() {
        let peer = PeerAgentInfo {
            agent_id: "peer-1".into(),
            api_base_url: Some("http://peer-1.example.com:8080".into()),
            p2p_listen_addr: "10.0.0.1:9000".parse().unwrap(),
            nat_profile: Some("full_cone".into()),
        };

        assert_eq!(
            peer.api_base_url,
            Some("http://peer-1.example.com:8080".into())
        );
        assert_eq!(peer.p2p_listen_addr.to_string(), "10.0.0.1:9000");
    }

    #[test]
    fn test_peer_agent_info_api_url_is_optional() {
        let peer = PeerAgentInfo {
            agent_id: "peer-2".into(),
            api_base_url: None,
            p2p_listen_addr: "10.0.0.2:9000".parse().unwrap(),
            nat_profile: None,
        };

        assert!(peer.api_base_url.is_none());
    }

    #[test]
    fn test_start_run_result_all_success() {
        let run_id = Uuid::new_v4();
        let mut result = StartRunResult::new(run_id);
        result.record_success("agent-1");
        result.record_success("agent-2");

        assert!(result.has_any_success());
        assert!(result.all_succeeded());
        assert_eq!(result.successful_agents().len(), 2);
        assert!(result.failed_agents().is_empty());
    }

    #[test]
    fn test_start_run_result_partial_failure() {
        let run_id = Uuid::new_v4();
        let mut result = StartRunResult::new(run_id);
        result.record_success("agent-1");
        result.record_failure("agent-2", "Connection refused");

        assert!(result.has_any_success());
        assert!(!result.all_succeeded());
        assert_eq!(result.successful_agents().len(), 1);
        assert_eq!(result.failed_agents().len(), 1);
    }

    #[test]
    fn test_start_run_result_all_failed() {
        let run_id = Uuid::new_v4();
        let mut result = StartRunResult::new(run_id);
        result.record_failure("agent-1", "Timeout");
        result.record_failure("agent-2", "Connection refused");

        assert!(!result.has_any_success());
        assert!(!result.all_succeeded());
        assert!(result.successful_agents().is_empty());
        assert_eq!(result.failed_agents().len(), 2);
    }

    #[test]
    fn test_collection_result_complete() {
        let mut result = CollectionResult::<String>::new();
        result.add_items("agent-1", vec!["a".into(), "b".into()]);
        result.add_items("agent-2", vec!["c".into()]);

        assert!(result.is_complete());
        assert_eq!(result.items.len(), 3);
        assert!(result.failed_sources.is_empty());
    }

    #[test]
    fn test_collection_result_partial() {
        let mut result = CollectionResult::<String>::new();
        result.add_items("agent-1", vec!["a".into()]);
        result.record_failure("agent-2", "Network error");

        assert!(!result.is_complete());
        assert_eq!(result.items.len(), 1);
        assert_eq!(result.failed_sources.len(), 1);
    }

    #[test]
    fn test_collection_result_all_failed() {
        let mut result = CollectionResult::<String>::new();
        result.record_failure("agent-1", "Timeout");
        result.record_failure("agent-2", "DNS error");

        assert!(!result.is_complete());
        assert!(result.items.is_empty());
        assert_eq!(result.failed_sources.len(), 2);
    }

    #[test]
    fn test_agent_client_stores_p2p_listen_addr() {
        let p2p_addr: SocketAddr = "192.168.1.100:9000".parse().unwrap();
        let client = AgentClient::new("http://localhost:8080", "agent-1", p2p_addr);

        assert_eq!(client.base_url, "http://localhost:8080");
        assert_eq!(client.agent_id, "agent-1");
        assert_eq!(client.p2p_listen_addr, p2p_addr);
    }

    #[test]
    fn test_agent_client_p2p_addr_not_fallback_when_discovered() {
        let discovered_addr: SocketAddr = "10.0.0.5:9000".parse().unwrap();
        let client = AgentClient::new("http://agent.example.com:8080", "agent-x", discovered_addr);

        assert_ne!(client.p2p_listen_addr, FALLBACK_SOCKET_ADDR);
        assert_eq!(client.p2p_listen_addr.port(), 9000);
    }

    fn make_completed_status() -> RunStatusResponse {
        RunStatusResponse {
            run_id: Uuid::new_v4(),
            status: RunStatus::Completed,
            progress: RunProgress {
                total_attempts: 10,
                completed_attempts: 10,
                successful_attempts: 10,
                failed_attempts: 0,
                current_attempt: None,
                elapsed_ms: 5000,
            },
            current_stage: None,
            error: None,
        }
    }

    fn make_cancelled_status() -> RunStatusResponse {
        RunStatusResponse {
            run_id: Uuid::new_v4(),
            status: RunStatus::Cancelled,
            progress: RunProgress {
                total_attempts: 10,
                completed_attempts: 5,
                successful_attempts: 5,
                failed_attempts: 0,
                current_attempt: None,
                elapsed_ms: 2500,
            },
            current_stage: None,
            error: None,
        }
    }

    #[test]
    fn test_status_poll_result_all_responded_when_all_succeed() {
        let mut result = StatusPollResult::new(2);
        result.record_status("agent-1", make_completed_status());
        result.record_status("agent-2", make_completed_status());

        assert!(result.all_responded());
        assert!(result.all_complete());
        assert_eq!(result.missing_count(), 0);
    }

    #[test]
    fn test_status_poll_result_not_complete_when_agent_missing() {
        let mut result = StatusPollResult::new(3);
        result.record_status("agent-1", make_completed_status());
        result.record_status("agent-2", make_completed_status());

        assert!(!result.all_responded());
        assert!(!result.all_complete());
        assert_eq!(result.missing_count(), 1);
    }

    #[test]
    fn test_status_poll_result_tracks_failed_agents() {
        let mut result = StatusPollResult::new(2);
        result.record_status("agent-1", make_completed_status());
        result.record_failure("agent-2", "Connection timeout");

        assert!(result.all_responded());
        // Failed agents are terminal - they won't recover, so polling is complete.
        // Callers should check failed_agents separately.
        assert!(
            result.all_complete(),
            "Failed agents should be treated as terminal"
        );
        assert_eq!(result.failed_agents.len(), 1);
    }

    #[test]
    fn test_status_poll_result_cancelled_is_terminal() {
        let mut result = StatusPollResult::new(2);
        result.record_status("agent-1", make_completed_status());
        result.record_status("agent-2", make_cancelled_status());

        assert!(result.all_responded());
        assert!(
            result.all_complete(),
            "Cancelled status should be treated as terminal"
        );
    }

    #[test]
    fn test_run_status_is_terminal() {
        // Non-terminal states
        assert!(!RunStatus::Pending.is_terminal());
        assert!(!RunStatus::Preflight.is_terminal());
        assert!(!RunStatus::Running.is_terminal());
        assert!(!RunStatus::Uploading.is_terminal());

        // Terminal states
        assert!(RunStatus::Completed.is_terminal());
        assert!(RunStatus::Failed.is_terminal());
        assert!(RunStatus::Cancelled.is_terminal());
    }

    #[test]
    fn test_all_complete_with_running_agent_returns_false() {
        let mut result = StatusPollResult::new(2);
        result.record_status("agent-1", make_completed_status());
        result.record_status(
            "agent-2",
            RunStatusResponse {
                run_id: Uuid::new_v4(),
                status: RunStatus::Running,
                progress: RunProgress {
                    total_attempts: 10,
                    completed_attempts: 5,
                    successful_attempts: 5,
                    failed_attempts: 0,
                    current_attempt: Some(6),
                    elapsed_ms: 2500,
                },
                current_stage: None,
                error: None,
            },
        );

        assert!(result.all_responded());
        assert!(
            !result.all_complete(),
            "Should not be complete while agent is still Running"
        );
    }
}
