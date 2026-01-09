//! Local Agent Integration
//!
//! This module provides in-process local agent implementations for development
//! and mixed local/VPS testing scenarios. Local agents run in the same process
//! as the orchestrator, avoiding HTTP overhead and enabling faster iteration.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                         Orchestrator                                 │
//! │  ┌─────────────────────────────────────────────────────────────────┐│
//! │  │                   AgentEndpoint trait                            ││
//! │  │  - start_run()   - get_status()   - collect_results()           ││
//! │  └──────────────────┬──────────────────┬───────────────────────────┘│
//! │                     │                  │                            │
//! │         ┌───────────▼────────┐  ┌──────▼───────────┐               │
//! │         │   LocalAgent       │  │   RemoteAgent    │               │
//! │         │ (in-process)       │  │ (HTTP client)    │               │
//! │         └───────────┬────────┘  └──────┬───────────┘               │
//! │                     │                  │                            │
//! └─────────────────────┼──────────────────┼────────────────────────────┘
//!                       │                  │
//!                       ▼                  ▼
//!              Local QUIC Node        VPS test-agent
//! ```
//!
//! # Example
//!
//! ```ignore
//! use ant_quic_test_network::harness::{LocalAgent, AgentEndpoint, ScenarioSpec};
//!
//! // Create a local agent
//! let local = LocalAgent::new("local-dev").await?;
//!
//! // Mix with VPS agents
//! let mut endpoints: Vec<Box<dyn AgentEndpoint>> = vec![
//!     Box::new(local),
//!     Box::new(RemoteAgent::new("http://vps-1:8080")),
//! ];
//!
//! // Run tests across all agents
//! orchestrator.run_matrix(endpoints, scenario).await?;
//! ```

use super::{
    AgentCapabilities, AgentClient, AgentInfo, AgentStatus, ApplyProfileResponse, AttemptResult,
    ClearProfileResponse, CollectionResult, FailureCategory, GetResultsResponse, HandshakeResponse,
    HealthCheckResponse, IpMode, NatProfileSpec, PeerAgentInfo, RunProgress, RunStatus,
    RunStatusResponse, RunSummary, ScenarioSpec, StartRunRequest, StartRunResponse,
    StartRunResult, StatusPollResult, StopRunResponse,
};
use crate::registry::{ConnectionMethod, FailureReasonCode, NatType, SuccessLevel};
use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Trait for unified agent interaction (local or remote).
///
/// This trait abstracts the differences between in-process local agents
/// and remote VPS agents accessed via HTTP, allowing the orchestrator
/// to treat them uniformly.
#[async_trait::async_trait]
pub trait AgentEndpoint: Send + Sync {
    /// Get the agent's unique identifier.
    fn agent_id(&self) -> &str;

    /// Get the agent's P2P listen address.
    fn p2p_listen_addr(&self) -> SocketAddr;

    /// Check if the agent is healthy and ready.
    async fn health_check(&self) -> Result<HealthCheckResponse>;

    /// Perform handshake to verify compatibility.
    async fn handshake(&self, orchestrator_id: &str, protocol_version: u32) -> Result<HandshakeResponse>;

    /// Start a test run on this agent.
    async fn start_run(&self, request: StartRunRequest) -> Result<StartRunResponse>;

    /// Get the status of a running test.
    async fn get_status(&self, run_id: Uuid) -> Result<RunStatusResponse>;

    /// Stop a running test.
    async fn stop_run(&self, run_id: Uuid, reason: Option<&str>) -> Result<StopRunResponse>;

    /// Collect results from a completed test run.
    async fn collect_results(&self, run_id: Uuid) -> Result<GetResultsResponse>;

    /// Apply a NAT profile to the agent.
    async fn apply_profile(&self, profile: NatProfileSpec) -> Result<ApplyProfileResponse>;

    /// Clear any applied NAT profile.
    async fn clear_profile(&self) -> Result<ClearProfileResponse>;

    /// Check if this is a local (in-process) agent.
    fn is_local(&self) -> bool;

    /// Get agent info for peer communication.
    fn as_peer_info(&self) -> PeerAgentInfo;
}

/// State for an active test run on a local agent.
#[derive(Debug, Clone)]
struct LocalActiveRun {
    scenario: ScenarioSpec,
    peer_agents: Vec<PeerAgentInfo>,
    status: RunStatus,
    progress: RunProgress,
    started_at: Instant,
    results: Vec<AttemptResult>,
}

/// In-process local agent for development and testing.
///
/// This agent runs in the same process as the orchestrator,
/// avoiding HTTP overhead and enabling faster test iteration.
/// It simulates the same behavior as VPS test-agents but with
/// direct function calls instead of network requests.
pub struct LocalAgent {
    agent_id: String,
    version: String,
    capabilities: AgentCapabilities,
    p2p_listen_addr: SocketAddr,
    status: Arc<RwLock<AgentStatus>>,
    active_runs: Arc<RwLock<HashMap<Uuid, LocalActiveRun>>>,
    started_at: Instant,
    applied_profile: Arc<RwLock<Option<NatProfileSpec>>>,
    detected_nat_type: Arc<RwLock<NatType>>,
}

impl LocalAgent {
    /// Create a new local agent with the given ID.
    pub async fn new(agent_id: &str) -> Result<Self> {
        let p2p_addr = Self::discover_local_address().await?;

        Ok(Self {
            agent_id: agent_id.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities: AgentCapabilities {
                protocol_version: 1,
                supported_artifact_types: vec!["agent_log".into(), "sut_log".into(), "metrics".into()],
                supported_nat_profiles: vec![NatType::None, NatType::FullCone, NatType::AddressRestricted],
                max_concurrent_tests: 4,
                can_capture_pcaps: false,
                can_simulate_nat: true,
                has_docker: false,
                has_tc: cfg!(target_os = "linux"),
            },
            p2p_listen_addr: p2p_addr,
            status: Arc::new(RwLock::new(AgentStatus::Idle)),
            active_runs: Arc::new(RwLock::new(HashMap::new())),
            started_at: Instant::now(),
            applied_profile: Arc::new(RwLock::new(None)),
            detected_nat_type: Arc::new(RwLock::new(NatType::Unknown)),
        })
    }

    /// Create a local agent with a specific P2P address (for testing).
    pub fn with_address(agent_id: &str, p2p_listen_addr: SocketAddr) -> Self {
        Self {
            agent_id: agent_id.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities: AgentCapabilities::default(),
            p2p_listen_addr,
            status: Arc::new(RwLock::new(AgentStatus::Idle)),
            active_runs: Arc::new(RwLock::new(HashMap::new())),
            started_at: Instant::now(),
            applied_profile: Arc::new(RwLock::new(None)),
            detected_nat_type: Arc::new(RwLock::new(NatType::Unknown)),
        }
    }

    /// Discover the local network address for P2P communication.
    async fn discover_local_address() -> Result<SocketAddr> {
        // Try to find a suitable local address
        // In a real implementation, this would bind a UDP socket and discover the address
        let local_ip = local_ip_address::local_ip()
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

        // Use a dynamic port (0) that will be assigned when actually binding
        Ok(SocketAddr::new(local_ip, 0))
    }

    /// Get the agent info structure.
    pub fn info(&self) -> AgentInfo {
        AgentInfo {
            agent_id: self.agent_id.clone(),
            version: self.version.clone(),
            capabilities: self.capabilities.clone(),
            api_base_url: format!("local://{}", self.agent_id),
            p2p_listen_addr: self.p2p_listen_addr,
            nat_profiles_available: self.capabilities.supported_nat_profiles
                .iter()
                .map(|n| format!("{:?}", n))
                .collect(),
            status: AgentStatus::Idle,
        }
    }

    /// Execute a test run in the background.
    async fn execute_test_run(&self, run_id: Uuid) {
        let runs = self.active_runs.clone();
        let agent_id = self.agent_id.clone();
        let detected_nat = self.detected_nat_type.clone();

        tokio::spawn(async move {
            // Get the run details
            let (scenario, peer_agents) = {
                let runs_guard = runs.read().await;
                match runs_guard.get(&run_id) {
                    Some(run) => (run.scenario.clone(), run.peer_agents.clone()),
                    None => return,
                }
            };

            // Update status to running
            {
                let mut runs_guard = runs.write().await;
                if let Some(run) = runs_guard.get_mut(&run_id) {
                    run.status = RunStatus::Running;
                }
            }

            let attempts_per_cell = scenario.test_matrix.attempts_per_cell;
            let attempt_timeout = scenario.timing.attempt_timeout;
            let nat_type = *detected_nat.read().await;

            // Execute tests against each peer
            for (peer_idx, peer) in peer_agents.iter().enumerate() {
                if peer.agent_id == agent_id {
                    continue; // Skip self
                }

                for attempt in 0..attempts_per_cell {
                    let attempt_id = (peer_idx as u32 * attempts_per_cell) + attempt;

                    // Simulate connectivity test
                    let result = Self::simulate_connectivity_test(
                        &agent_id,
                        run_id,
                        attempt_id,
                        peer,
                        nat_type,
                        attempt_timeout,
                    ).await;

                    // Record result
                    {
                        let mut runs_guard = runs.write().await;
                        if let Some(run) = runs_guard.get_mut(&run_id) {
                            if result.success {
                                run.progress.successful_attempts += 1;
                            } else {
                                run.progress.failed_attempts += 1;
                            }
                            run.progress.completed_attempts += 1;
                            run.progress.current_attempt = Some(attempt_id);
                            run.progress.elapsed_ms = run.started_at.elapsed().as_millis() as u64;
                            run.results.push(result);
                        }
                    }
                }
            }

            // Mark as completed
            {
                let mut runs_guard = runs.write().await;
                if let Some(run) = runs_guard.get_mut(&run_id) {
                    run.status = RunStatus::Completed;
                    run.progress.current_attempt = None;
                    run.progress.elapsed_ms = run.started_at.elapsed().as_millis() as u64;
                }
            }

            info!("Local agent {} completed run {}", agent_id, run_id);
        });
    }

    /// Simulate a connectivity test to a peer.
    async fn simulate_connectivity_test(
        agent_id: &str,
        run_id: Uuid,
        attempt_id: u32,
        peer: &PeerAgentInfo,
        local_nat: NatType,
        _timeout: Duration,
    ) -> AttemptResult {
        // Simulate network latency based on address characteristics
        let simulated_rtt = Self::simulate_rtt(peer.p2p_listen_addr);

        let mut result = AttemptResult::new(run_id, "connectivity_test", attempt_id)
            .with_dimensions(
                local_nat,
                NatType::Unknown, // We don't know peer's NAT type
                IpMode::Ipv4Only,
            )
            .with_agents(agent_id, &peer.agent_id);

        // Simulate success/failure based on NAT types and address reachability
        let success_probability = Self::calculate_success_probability(local_nat, peer.p2p_listen_addr);
        let random_val: f64 = rand::random();

        if random_val < success_probability {
            if let Some(rtt) = simulated_rtt {
                result.record_success(ConnectionMethod::Direct, u64::from(rtt), SuccessLevel::Usable);
            } else {
                result.record_failure(
                    "Simulated timeout",
                    FailureReasonCode::Timeout,
                    FailureCategory::SutConnectivityFailure,
                );
            }
        } else {
            result.record_failure(
                "Simulated NAT traversal failure",
                FailureReasonCode::AddressUnreachable,
                FailureCategory::SutConnectivityFailure,
            );
        }

        // Simulate the timeout delay
        tokio::time::sleep(Duration::from_millis(simulated_rtt.unwrap_or(50) as u64)).await;

        result
    }

    /// Simulate RTT based on address characteristics.
    fn simulate_rtt(addr: SocketAddr) -> Option<u32> {
        if addr.ip().is_loopback() {
            Some(1) // Local loopback is very fast
        } else if addr.ip().is_unspecified() {
            None // Can't connect to unspecified address
        } else {
            // Simulate variable RTT for remote addresses
            let base_rtt = if addr.ip().is_ipv6() { 30 } else { 25 };
            let jitter: u32 = rand::random::<u32>() % 20;
            Some(base_rtt + jitter)
        }
    }

    /// Calculate success probability based on NAT type and address.
    fn calculate_success_probability(local_nat: NatType, peer_addr: SocketAddr) -> f64 {
        if peer_addr.ip().is_loopback() {
            return 1.0; // Always succeed for loopback
        }
        if peer_addr.ip().is_unspecified() {
            return 0.0; // Never succeed for unspecified
        }

        // Base probability depends on local NAT type
        match local_nat {
            NatType::None => 0.95,
            NatType::FullCone => 0.90,
            NatType::AddressRestricted => 0.75,
            NatType::PortRestricted => 0.60,
            NatType::Symmetric => 0.40,
            NatType::Cgnat => 0.30,
            NatType::DoubleNat => 0.25,
            NatType::HairpinNat => 0.70,
            NatType::MobileCarrier => 0.35,
            NatType::Unknown => 0.50,
            // Catch-all for any future NAT types
            _ => 0.50,
        }
    }
}

#[async_trait::async_trait]
impl AgentEndpoint for LocalAgent {
    fn agent_id(&self) -> &str {
        &self.agent_id
    }

    fn p2p_listen_addr(&self) -> SocketAddr {
        self.p2p_listen_addr
    }

    async fn health_check(&self) -> Result<HealthCheckResponse> {
        let status = *self.status.read().await;
        let runs = self.active_runs.read().await;
        let active_run_ids: Vec<Uuid> = runs.keys().copied().collect();

        Ok(HealthCheckResponse {
            healthy: true,
            agent_id: self.agent_id.clone(),
            version: self.version.clone(),
            status,
            uptime_secs: self.started_at.elapsed().as_secs(),
            active_runs: active_run_ids,
            last_error: None,
            p2p_listen_addr: Some(self.p2p_listen_addr),
        })
    }

    async fn handshake(&self, orchestrator_id: &str, protocol_version: u32) -> Result<HandshakeResponse> {
        debug!(
            "Local agent {} handshake with orchestrator {} (protocol v{})",
            self.agent_id, orchestrator_id, protocol_version
        );

        let compatible = protocol_version >= 1;
        let info = self.info();

        if compatible {
            Ok(HandshakeResponse::compatible(info))
        } else {
            Ok(HandshakeResponse::incompatible(
                info,
                vec!["protocol_version".to_string()],
            ))
        }
    }

    async fn start_run(&self, request: StartRunRequest) -> Result<StartRunResponse> {
        let run_id = request.run_id;

        // Check if already running
        {
            let runs = self.active_runs.read().await;
            if runs.contains_key(&run_id) {
                return Ok(StartRunResponse {
                    success: false,
                    run_id,
                    error: Some("Run already exists".to_string()),
                    estimated_duration_secs: 0,
                });
            }
        }

        // Create active run
        let active_run = LocalActiveRun {
            scenario: request.scenario.clone(),
            peer_agents: request.peer_agents.clone(),
            status: RunStatus::Preflight,
            progress: RunProgress {
                total_attempts: request.scenario.test_matrix.attempts_per_cell
                    * (request.peer_agents.len() as u32).saturating_sub(1),
                completed_attempts: 0,
                successful_attempts: 0,
                failed_attempts: 0,
                current_attempt: Some(0),
                elapsed_ms: 0,
            },
            started_at: Instant::now(),
            results: Vec::new(),
        };

        {
            let mut runs = self.active_runs.write().await;
            runs.insert(run_id, active_run);
        }

        // Start test execution in background
        self.execute_test_run(run_id).await;

        let estimated_duration = request.scenario.timing.attempt_timeout.as_secs();

        Ok(StartRunResponse {
            success: true,
            run_id,
            error: None,
            estimated_duration_secs: estimated_duration,
        })
    }

    async fn get_status(&self, run_id: Uuid) -> Result<RunStatusResponse> {
        let runs = self.active_runs.read().await;

        match runs.get(&run_id) {
            Some(run) => Ok(RunStatusResponse {
                run_id,
                status: run.status,
                progress: run.progress.clone(),
                current_stage: Some(format!("{:?}", run.status)),
                error: None,
            }),
            None => Ok(RunStatusResponse {
                run_id,
                status: RunStatus::Failed,
                progress: RunProgress {
                    total_attempts: 0,
                    completed_attempts: 0,
                    successful_attempts: 0,
                    failed_attempts: 0,
                    current_attempt: None,
                    elapsed_ms: 0,
                },
                current_stage: None,
                error: Some("Run not found".to_string()),
            }),
        }
    }

    async fn stop_run(&self, run_id: Uuid, reason: Option<&str>) -> Result<StopRunResponse> {
        let mut runs = self.active_runs.write().await;

        if let Some(run) = runs.get_mut(&run_id) {
            run.status = RunStatus::Cancelled;
            info!(
                "Local agent {} stopped run {}: {:?}",
                self.agent_id,
                run_id,
                reason
            );

            Ok(StopRunResponse {
                success: true,
                run_id,
                attempts_completed: run.progress.completed_attempts,
                artifacts_uploaded: false,
            })
        } else {
            Ok(StopRunResponse {
                success: false,
                run_id,
                attempts_completed: 0,
                artifacts_uploaded: false,
            })
        }
    }

    async fn collect_results(&self, run_id: Uuid) -> Result<GetResultsResponse> {
        let runs = self.active_runs.read().await;

        match runs.get(&run_id) {
            Some(run) => {
                let summary = RunSummary::from_attempts(run_id, &run.scenario.name, &run.results);

                Ok(GetResultsResponse {
                    run_id,
                    results: run.results.clone(),
                    artifacts: None,
                    summary: Some(summary),
                })
            }
            None => Ok(GetResultsResponse {
                run_id,
                results: Vec::new(),
                artifacts: None,
                summary: None,
            }),
        }
    }

    async fn apply_profile(&self, profile: NatProfileSpec) -> Result<ApplyProfileResponse> {
        let nat_type = profile.nat_type;

        {
            let mut applied = self.applied_profile.write().await;
            *applied = Some(profile.clone());
        }

        {
            let mut detected = self.detected_nat_type.write().await;
            *detected = nat_type;
        }

        info!(
            "Local agent {} applied NAT profile: {:?}",
            self.agent_id, nat_type
        );

        Ok(ApplyProfileResponse {
            success: true,
            profile_name: profile.name,
            error: None,
            nat_type_detected: Some(nat_type),
        })
    }

    async fn clear_profile(&self) -> Result<ClearProfileResponse> {
        {
            let mut applied = self.applied_profile.write().await;
            *applied = None;
        }

        {
            let mut detected = self.detected_nat_type.write().await;
            *detected = NatType::Unknown;
        }

        info!("Local agent {} cleared NAT profile", self.agent_id);

        Ok(ClearProfileResponse {
            success: true,
            error: None,
        })
    }

    fn is_local(&self) -> bool {
        true
    }

    fn as_peer_info(&self) -> PeerAgentInfo {
        PeerAgentInfo {
            agent_id: self.agent_id.clone(),
            api_base_url: Some(format!("local://{}", self.agent_id)),
            p2p_listen_addr: self.p2p_listen_addr,
            nat_profile: None,
        }
    }
}

/// Remote agent accessed via HTTP.
///
/// This wraps an `AgentClient` to implement the `AgentEndpoint` trait,
/// allowing remote VPS agents to be used interchangeably with local agents.
pub struct RemoteAgent {
    client: AgentClient,
    http_client: reqwest::Client,
}

impl RemoteAgent {
    /// Create a new remote agent from discovery info.
    pub fn new(agent_id: &str, base_url: &str, p2p_listen_addr: SocketAddr) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client: AgentClient::new(base_url, agent_id, p2p_listen_addr),
            http_client,
        }
    }

    /// Create from an existing AgentClient.
    pub fn from_client(client: AgentClient) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self { client, http_client }
    }
}

#[async_trait::async_trait]
impl AgentEndpoint for RemoteAgent {
    fn agent_id(&self) -> &str {
        &self.client.agent_id
    }

    fn p2p_listen_addr(&self) -> SocketAddr {
        self.client.p2p_listen_addr
    }

    async fn health_check(&self) -> Result<HealthCheckResponse> {
        let resp = self.http_client
            .get(self.client.health_url())
            .send()
            .await?;

        Ok(resp.json().await?)
    }

    async fn handshake(&self, orchestrator_id: &str, protocol_version: u32) -> Result<HandshakeResponse> {
        let request = super::HandshakeRequest {
            orchestrator_id: orchestrator_id.to_string(),
            protocol_version,
            required_capabilities: vec![],
        };

        let resp = self.http_client
            .post(self.client.handshake_url())
            .json(&request)
            .send()
            .await?;

        Ok(resp.json().await?)
    }

    async fn start_run(&self, request: StartRunRequest) -> Result<StartRunResponse> {
        let resp = self.http_client
            .post(self.client.start_run_url())
            .json(&request)
            .send()
            .await?;

        Ok(resp.json().await?)
    }

    async fn get_status(&self, run_id: Uuid) -> Result<RunStatusResponse> {
        let resp = self.http_client
            .get(self.client.status_url(run_id))
            .send()
            .await?;

        Ok(resp.json().await?)
    }

    async fn stop_run(&self, run_id: Uuid, reason: Option<&str>) -> Result<StopRunResponse> {
        let request = super::StopRunRequest {
            run_id,
            reason: reason.map(String::from),
        };

        let resp = self.http_client
            .post(self.client.stop_run_url(run_id))
            .json(&request)
            .send()
            .await?;

        Ok(resp.json().await?)
    }

    async fn collect_results(&self, run_id: Uuid) -> Result<GetResultsResponse> {
        let request = super::GetResultsRequest {
            run_id,
            format: super::ResultFormat::Json,
            include_artifacts: false,
        };

        let resp = self.http_client
            .post(self.client.results_url(run_id))
            .json(&request)
            .send()
            .await?;

        Ok(resp.json().await?)
    }

    async fn apply_profile(&self, profile: NatProfileSpec) -> Result<ApplyProfileResponse> {
        let request = super::ApplyProfileRequest {
            profile,
            interface: None,
        };

        let resp = self.http_client
            .post(self.client.apply_profile_url())
            .json(&request)
            .send()
            .await?;

        Ok(resp.json().await?)
    }

    async fn clear_profile(&self) -> Result<ClearProfileResponse> {
        let request = super::ClearProfileRequest { interface: None };

        let resp = self.http_client
            .post(format!("{}/node/profile/clear", self.client.base_url))
            .json(&request)
            .send()
            .await?;

        Ok(resp.json().await?)
    }

    fn is_local(&self) -> bool {
        false
    }

    fn as_peer_info(&self) -> PeerAgentInfo {
        PeerAgentInfo {
            agent_id: self.client.agent_id.clone(),
            api_base_url: Some(self.client.base_url.clone()),
            p2p_listen_addr: self.client.p2p_listen_addr,
            nat_profile: None,
        }
    }
}

/// Mixed orchestrator that can coordinate both local and remote agents.
///
/// This orchestrator provides a unified interface for running tests across
/// any combination of local (in-process) and remote (VPS) agents.
pub struct MixedOrchestrator {
    agents: Vec<Box<dyn AgentEndpoint>>,
    run_id: Option<Uuid>,
}

impl MixedOrchestrator {
    /// Create a new mixed orchestrator.
    pub fn new() -> Self {
        Self {
            agents: Vec::new(),
            run_id: None,
        }
    }

    /// Add a local agent.
    pub fn add_local(&mut self, agent: LocalAgent) {
        self.agents.push(Box::new(agent));
    }

    /// Add a remote agent.
    pub fn add_remote(&mut self, agent: RemoteAgent) {
        self.agents.push(Box::new(agent));
    }

    /// Add any agent implementing AgentEndpoint.
    pub fn add_agent(&mut self, agent: Box<dyn AgentEndpoint>) {
        self.agents.push(agent);
    }

    /// Get the number of agents.
    pub fn agent_count(&self) -> usize {
        self.agents.len()
    }

    /// Get the number of local agents.
    pub fn local_agent_count(&self) -> usize {
        self.agents.iter().filter(|a| a.is_local()).count()
    }

    /// Get the number of remote agents.
    pub fn remote_agent_count(&self) -> usize {
        self.agents.iter().filter(|a| !a.is_local()).count()
    }

    /// Health check all agents.
    pub async fn health_check_all(&self) -> Vec<(String, Result<HealthCheckResponse>)> {
        let mut results = Vec::new();

        for agent in &self.agents {
            let result = agent.health_check().await;
            results.push((agent.agent_id().to_string(), result));
        }

        results
    }

    /// Handshake with all agents.
    pub async fn handshake_all(&self, orchestrator_id: &str) -> Vec<(String, Result<HandshakeResponse>)> {
        let mut results = Vec::new();

        for agent in &self.agents {
            let result = agent.handshake(orchestrator_id, 1).await;
            results.push((agent.agent_id().to_string(), result));
        }

        results
    }

    /// Start a test run across all agents.
    pub async fn start_run(&mut self, scenario: ScenarioSpec) -> Result<StartRunResult> {
        let run_id = Uuid::new_v4();
        self.run_id = Some(run_id);

        let mut result = StartRunResult::new(run_id);

        // Build peer info for all agents
        let peer_agents: Vec<PeerAgentInfo> = self.agents
            .iter()
            .map(|a| a.as_peer_info())
            .collect();

        for agent in &self.agents {
            let request = StartRunRequest {
                run_id,
                scenario: scenario.clone(),
                agent_role: "peer".to_string(),
                peer_agents: peer_agents.clone(),
            };

            match agent.start_run(request).await {
                Ok(resp) if resp.success => {
                    info!("Started run {} on agent {}", run_id, agent.agent_id());
                    result.record_success(agent.agent_id());
                }
                Ok(resp) => {
                    let err = resp.error.unwrap_or_else(|| "Unknown error".to_string());
                    warn!("Failed to start run on {}: {}", agent.agent_id(), err);
                    result.record_failure(agent.agent_id(), &err);
                }
                Err(e) => {
                    warn!("Failed to start run on {}: {}", agent.agent_id(), e);
                    result.record_failure(agent.agent_id(), &e.to_string());
                }
            }
        }

        if !result.has_any_success() {
            anyhow::bail!(
                "Failed to start run on ANY agent. Failures: {:?}",
                result.failed_agents()
            );
        }

        Ok(result)
    }

    /// Get status from all agents.
    pub async fn get_status(&self, run_id: Uuid) -> StatusPollResult {
        let mut result = StatusPollResult::new(self.agents.len());

        for agent in &self.agents {
            match agent.get_status(run_id).await {
                Ok(status) => {
                    result.record_status(agent.agent_id(), status);
                }
                Err(e) => {
                    result.record_failure(agent.agent_id(), &e.to_string());
                }
            }
        }

        result
    }

    /// Stop the run on all agents.
    pub async fn stop_run(&self, run_id: Uuid, reason: Option<&str>) -> Result<()> {
        for agent in &self.agents {
            if let Err(e) = agent.stop_run(run_id, reason).await {
                warn!("Failed to stop run on {}: {}", agent.agent_id(), e);
            }
        }
        Ok(())
    }

    /// Collect results from all agents.
    pub async fn collect_results(&self, run_id: Uuid) -> CollectionResult<AttemptResult> {
        let mut collection = CollectionResult::new();

        for agent in &self.agents {
            match agent.collect_results(run_id).await {
                Ok(results) => {
                    info!(
                        "Collected {} results from {}",
                        results.results.len(),
                        agent.agent_id()
                    );
                    collection.add_items(agent.agent_id(), results.results);
                }
                Err(e) => {
                    warn!("Failed to collect results from {}: {}", agent.agent_id(), e);
                    collection.record_failure(agent.agent_id(), &e.to_string());
                }
            }
        }

        collection
    }

    /// Run a complete test and wait for completion.
    pub async fn run_and_wait(
        &mut self,
        scenario: ScenarioSpec,
        poll_interval: Duration,
        timeout: Duration,
    ) -> Result<CollectionResult<AttemptResult>> {
        let start_result = self.start_run(scenario).await?;
        let run_id = start_result.run_id;
        let deadline = Instant::now() + timeout;

        info!(
            "Run {} started on {}/{} agents",
            run_id,
            start_result.successful_agents().len(),
            start_result.successful_agents().len() + start_result.failed_agents().len()
        );

        // Poll until complete or timeout
        loop {
            if Instant::now() > deadline {
                warn!("Run {} timed out, stopping...", run_id);
                self.stop_run(run_id, Some("Timeout")).await?;
                break;
            }

            tokio::time::sleep(poll_interval).await;

            let status = self.get_status(run_id).await;

            if status.all_complete() {
                info!("Run {} completed", run_id);
                break;
            }

            let progress: u32 = status.statuses
                .values()
                .map(|s| s.progress.completed_attempts)
                .sum();

            debug!(
                "Progress: {} attempts ({}/{} agents)",
                progress,
                status.statuses.len(),
                self.agents.len()
            );
        }

        // Collect and return results
        Ok(self.collect_results(run_id).await)
    }
}

impl Default for MixedOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_agent_creation() {
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let agent = LocalAgent::with_address("test-local", addr);

        assert_eq!(agent.agent_id(), "test-local");
        assert_eq!(agent.p2p_listen_addr(), addr);
        assert!(agent.is_local());
    }

    #[test]
    fn test_remote_agent_creation() {
        let addr: SocketAddr = "192.168.1.100:9000".parse().unwrap();
        let agent = RemoteAgent::new("test-remote", "http://vps:8080", addr);

        assert_eq!(agent.agent_id(), "test-remote");
        assert_eq!(agent.p2p_listen_addr(), addr);
        assert!(!agent.is_local());
    }

    #[test]
    fn test_mixed_orchestrator_counts() {
        let mut orch = MixedOrchestrator::new();

        let local_addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let remote_addr: SocketAddr = "192.168.1.100:9000".parse().unwrap();

        orch.add_local(LocalAgent::with_address("local-1", local_addr));
        orch.add_remote(RemoteAgent::new("remote-1", "http://vps:8080", remote_addr));

        assert_eq!(orch.agent_count(), 2);
        assert_eq!(orch.local_agent_count(), 1);
        assert_eq!(orch.remote_agent_count(), 1);
    }

    #[test]
    fn test_local_agent_as_peer_info() {
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let agent = LocalAgent::with_address("test-local", addr);

        let peer_info = agent.as_peer_info();
        assert_eq!(peer_info.agent_id, "test-local");
        assert_eq!(peer_info.p2p_listen_addr, addr);
        assert!(peer_info.api_base_url.is_some());
    }

    #[test]
    fn test_simulate_rtt() {
        let loopback: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        assert_eq!(LocalAgent::simulate_rtt(loopback), Some(1));

        let unspecified: SocketAddr = "0.0.0.0:0".parse().unwrap();
        assert_eq!(LocalAgent::simulate_rtt(unspecified), None);

        let remote: SocketAddr = "192.168.1.100:9000".parse().unwrap();
        let rtt = LocalAgent::simulate_rtt(remote);
        assert!(rtt.is_some());
        assert!(rtt.unwrap() >= 25);
    }

    #[test]
    fn test_calculate_success_probability() {
        let loopback: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        assert_eq!(LocalAgent::calculate_success_probability(NatType::None, loopback), 1.0);

        let unspecified: SocketAddr = "0.0.0.0:0".parse().unwrap();
        assert_eq!(LocalAgent::calculate_success_probability(NatType::None, unspecified), 0.0);

        let remote: SocketAddr = "192.168.1.100:9000".parse().unwrap();
        assert!(LocalAgent::calculate_success_probability(NatType::None, remote) > 0.9);
        assert!(LocalAgent::calculate_success_probability(NatType::Symmetric, remote) < 0.5);
    }

    #[tokio::test]
    async fn test_local_agent_health_check() {
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let agent = LocalAgent::with_address("test-local", addr);

        let health = agent.health_check().await.unwrap();
        assert!(health.healthy);
        assert_eq!(health.agent_id, "test-local");
        assert!(health.p2p_listen_addr.is_some());
    }

    #[tokio::test]
    async fn test_local_agent_handshake() {
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let agent = LocalAgent::with_address("test-local", addr);

        let handshake = agent.handshake("test-orchestrator", 1).await.unwrap();
        assert!(handshake.compatible);
        assert!(handshake.missing_capabilities.is_empty());
    }
}
