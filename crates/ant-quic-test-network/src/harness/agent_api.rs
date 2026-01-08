use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use uuid::Uuid;

use super::{ArtifactManifest, AttemptResult, NatProfileSpec, ScenarioSpec};
use crate::registry::NatType;

pub const FALLBACK_SOCKET_ADDR: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

pub fn parse_socket_addr_or_fallback(s: &str) -> SocketAddr {
    s.parse().unwrap_or(FALLBACK_SOCKET_ADDR)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub agent_id: String,
    pub version: String,
    pub capabilities: AgentCapabilities,
    pub listen_addr: SocketAddr,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Idle,
    Running,
    Error,
    Offline,
}

impl Default for AgentStatus {
    fn default() -> Self {
        Self::Idle
    }
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
    pub listen_addr: SocketAddr,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResponse {
    pub healthy: bool,
    pub agent_id: String,
    pub version: String,
    pub status: AgentStatus,
    pub uptime_secs: u64,
    pub active_runs: Vec<Uuid>,
    pub last_error: Option<String>,
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
}

impl AgentClient {
    pub fn new(base_url: &str, agent_id: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            agent_id: agent_id.to_string(),
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
        let client = AgentClient::new("http://localhost:8080", "agent-1");
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
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
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

    #[test]
    fn test_parse_socket_addr_valid_ipv4() {
        let result = parse_socket_addr_or_fallback("192.168.1.100:8080");
        assert_eq!(result.to_string(), "192.168.1.100:8080");
    }

    #[test]
    fn test_parse_socket_addr_valid_ipv6() {
        let result = parse_socket_addr_or_fallback("[::1]:9000");
        assert_eq!(result.to_string(), "[::1]:9000");
    }

    #[test]
    fn test_parse_socket_addr_invalid_returns_fallback() {
        let result = parse_socket_addr_or_fallback("not-an-address");
        assert_eq!(result, FALLBACK_SOCKET_ADDR);
    }

    #[test]
    fn test_parse_socket_addr_http_url_returns_fallback() {
        let result = parse_socket_addr_or_fallback("http://localhost:8080");
        assert_eq!(result, FALLBACK_SOCKET_ADDR);
    }

    #[test]
    fn test_parse_socket_addr_empty_returns_fallback() {
        let result = parse_socket_addr_or_fallback("");
        assert_eq!(result, FALLBACK_SOCKET_ADDR);
    }

    #[test]
    fn test_parse_socket_addr_missing_port_returns_fallback() {
        let result = parse_socket_addr_or_fallback("192.168.1.1");
        assert_eq!(result, FALLBACK_SOCKET_ADDR);
    }
}
