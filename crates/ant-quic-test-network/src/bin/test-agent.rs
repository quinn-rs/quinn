//! Test Agent for distributed P2P connectivity testing.
//!
//! This agent runs on VPS nodes and responds to orchestrator commands
//! to participate in connectivity matrix tests.
//!
//! # Usage
//!
//! ```bash
//! # Run with default settings (binds to 0.0.0.0:8080 for API, dynamic port for P2P)
//! test-agent
//!
//! # Specify custom ports
//! test-agent --api-port 8081 --p2p-port 9001
//!
//! # With agent ID from environment
//! AGENT_ID=saorsa-4 test-agent
//! ```

use ant_quic_test_network::harness::{
    AgentCapabilities, AgentInfo, AgentStatus, ApplyProfileRequest, ApplyProfileResponse,
    AttemptResult, BarrierRequest, BarrierResponse, ClearProfileRequest, ClearProfileResponse,
    FailureCategory, GetResultsResponse, HandshakeRequest, HandshakeResponse, HealthCheckResponse,
    IpMode, PeerAgentInfo, RunProgress, RunStatus, RunStatusResponse, RunSummary, ScenarioSpec,
    StartRunRequest, StartRunResponse, StopRunRequest, StopRunResponse,
};
use ant_quic_test_network::registry::{ConnectionMethod, FailureReasonCode, NatType, SuccessLevel};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use clap::Parser;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "test-agent")]
#[command(about = "Test agent for distributed P2P connectivity testing")]
#[command(version)]
struct Cli {
    /// API server listen address
    #[arg(long, default_value = "0.0.0.0")]
    api_host: String,

    /// API server port
    #[arg(long, default_value = "8080")]
    api_port: u16,

    /// P2P listen port (0 for dynamic)
    #[arg(long, default_value = "0")]
    p2p_port: u16,

    /// Agent ID (default: hostname or AGENT_ID env var)
    #[arg(long)]
    agent_id: Option<String>,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Enable NAT simulation capabilities
    #[arg(long)]
    enable_nat_sim: bool,

    /// Enable Docker-based testing
    #[arg(long)]
    enable_docker: bool,

    /// Maximum concurrent test runs
    #[arg(long, default_value = "4")]
    max_concurrent: u32,
}

/// State for an active test run.
#[derive(Debug, Clone)]
struct ActiveRun {
    scenario: ScenarioSpec,
    peer_agents: Vec<PeerAgentInfo>,
    status: RunStatus,
    progress: RunProgress,
    started_at: Instant,
    results: Vec<AttemptResult>,
    current_stage: Option<String>,
    error: Option<String>,
}

/// Shared agent state.
struct AgentState {
    agent_id: String,
    start_time: Instant,
    p2p_listen_addr: SocketAddr,
    capabilities: AgentCapabilities,
    active_runs: RwLock<HashMap<Uuid, ActiveRun>>,
    current_status: RwLock<AgentStatus>,
    last_error: RwLock<Option<String>>,
    // Barrier coordination
    barriers: RwLock<HashMap<String, Vec<String>>>,
}

impl AgentState {
    fn new(agent_id: String, p2p_listen_addr: SocketAddr, capabilities: AgentCapabilities) -> Self {
        Self {
            agent_id,
            start_time: Instant::now(),
            p2p_listen_addr,
            capabilities,
            active_runs: RwLock::new(HashMap::new()),
            current_status: RwLock::new(AgentStatus::Idle),
            last_error: RwLock::new(None),
            barriers: RwLock::new(HashMap::new()),
        }
    }

    fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
}

type SharedState = Arc<AgentState>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(&cli.log_level)
        .init();

    // Determine agent ID
    let agent_id = cli.agent_id.unwrap_or_else(|| {
        std::env::var("HOSTNAME")
            .or_else(|_| hostname::get().map(|s| s.to_string_lossy().to_string()))
            .unwrap_or_else(|_| format!("agent-{}", Uuid::new_v4().as_simple()))
    });

    info!("Starting test-agent {} v{}", agent_id, VERSION);

    // Bind P2P UDP socket to discover actual port
    let p2p_bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), cli.p2p_port);
    let p2p_socket = UdpSocket::bind(p2p_bind_addr).await?;
    let p2p_listen_addr = p2p_socket.local_addr()?;
    info!("P2P UDP socket bound to {}", p2p_listen_addr);

    // Build capabilities based on CLI flags
    let capabilities = AgentCapabilities {
        protocol_version: 1,
        supported_artifact_types: vec![
            "agent_log".into(),
            "sut_log".into(),
            "metrics".into(),
            "pcap".into(),
        ],
        supported_nat_profiles: vec![
            NatType::None,
            NatType::FullCone,
            NatType::AddressRestricted,
            NatType::PortRestricted,
            NatType::Symmetric,
        ],
        max_concurrent_tests: cli.max_concurrent,
        can_capture_pcaps: true,
        can_simulate_nat: cli.enable_nat_sim,
        has_docker: cli.enable_docker,
        has_tc: check_tc_available(),
    };

    // Create shared state
    let state = Arc::new(AgentState::new(
        agent_id.clone(),
        p2p_listen_addr,
        capabilities,
    ));

    // Build router
    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/handshake", post(handshake_handler))
        .route("/run/start", post(start_run_handler))
        .route("/run/{id}/stop", post(stop_run_handler))
        .route("/run/{id}/status", get(status_handler))
        .route("/run/{id}/results", get(results_handler))
        .route("/node/profile", post(apply_profile_handler))
        .route("/node/profile/clear", post(clear_profile_handler))
        .route("/barrier", post(barrier_handler))
        .with_state(state.clone());

    // Spawn P2P handler task
    let p2p_state = state.clone();
    tokio::spawn(async move {
        handle_p2p_traffic(p2p_socket, p2p_state).await;
    });

    // Start HTTP server
    let api_addr: SocketAddr = format!("{}:{}", cli.api_host, cli.api_port).parse()?;
    info!("API server listening on {}", api_addr);
    info!("Agent {} ready for orchestrator connections", agent_id);

    let listener = tokio::net::TcpListener::bind(api_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Check if `tc` (traffic control) is available for NAT simulation.
fn check_tc_available() -> bool {
    std::process::Command::new("tc")
        .arg("-V")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Handle incoming P2P UDP traffic.
async fn handle_p2p_traffic(socket: UdpSocket, state: SharedState) {
    let mut buf = [0u8; 65535];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, src)) => {
                // Log P2P traffic for debugging
                info!("Received {} bytes from {} (P2P)", len, src);

                // Simple echo for connectivity testing
                if let Err(e) = socket.send_to(&buf[..len], src).await {
                    warn!("Failed to echo P2P packet to {}: {}", src, e);
                }
            }
            Err(e) => {
                error!("P2P socket error: {}", e);
                *state.last_error.write().await = Some(format!("P2P socket error: {}", e));
            }
        }
    }
}

// =============================================================================
// HTTP Handlers
// =============================================================================

async fn health_handler(State(state): State<SharedState>) -> Json<HealthCheckResponse> {
    let active_runs = state.active_runs.read().await;
    let current_status = *state.current_status.read().await;
    let last_error = state.last_error.read().await.clone();

    Json(HealthCheckResponse {
        healthy: current_status != AgentStatus::Error,
        agent_id: state.agent_id.clone(),
        version: VERSION.to_string(),
        status: current_status,
        uptime_secs: state.uptime_secs(),
        active_runs: active_runs.keys().cloned().collect(),
        last_error,
        p2p_listen_addr: Some(state.p2p_listen_addr),
    })
}

async fn handshake_handler(
    State(state): State<SharedState>,
    Json(request): Json<HandshakeRequest>,
) -> Json<HandshakeResponse> {
    info!(
        "Handshake from orchestrator {} (protocol v{})",
        request.orchestrator_id, request.protocol_version
    );

    // Check required capabilities
    let mut missing = Vec::new();
    for cap in &request.required_capabilities {
        match cap.as_str() {
            "nat_sim" if !state.capabilities.can_simulate_nat => missing.push(cap.clone()),
            "docker" if !state.capabilities.has_docker => missing.push(cap.clone()),
            "tc" if !state.capabilities.has_tc => missing.push(cap.clone()),
            "pcap" if !state.capabilities.can_capture_pcaps => missing.push(cap.clone()),
            _ => {}
        }
    }

    let current_status = *state.current_status.read().await;
    let agent_info = AgentInfo {
        agent_id: state.agent_id.clone(),
        version: VERSION.to_string(),
        capabilities: state.capabilities.clone(),
        api_base_url: String::new(), // Orchestrator knows our URL
        p2p_listen_addr: state.p2p_listen_addr,
        nat_profiles_available: state
            .capabilities
            .supported_nat_profiles
            .iter()
            .map(|n| format!("{:?}", n))
            .collect(),
        status: current_status,
    };

    if missing.is_empty() {
        Json(HandshakeResponse::compatible(agent_info))
    } else {
        Json(HandshakeResponse::incompatible(agent_info, missing))
    }
}

async fn start_run_handler(
    State(state): State<SharedState>,
    Json(request): Json<StartRunRequest>,
) -> Result<Json<StartRunResponse>, StatusCode> {
    let run_id = request.run_id;
    info!(
        "Starting run {} with scenario {:?}",
        run_id, request.scenario.name
    );

    // Check if we're at capacity
    let active_count = state.active_runs.read().await.len();
    if active_count >= state.capabilities.max_concurrent_tests as usize {
        return Ok(Json(StartRunResponse {
            success: false,
            run_id,
            error: Some(format!(
                "At capacity: {} active runs (max {})",
                active_count, state.capabilities.max_concurrent_tests
            )),
            estimated_duration_secs: 0,
        }));
    }

    // Create active run
    let active_run = ActiveRun {
        scenario: request.scenario.clone(),
        peer_agents: request.peer_agents.clone(),
        status: RunStatus::Preflight,
        progress: RunProgress {
            total_attempts: request.scenario.test_matrix.attempts_per_cell,
            completed_attempts: 0,
            successful_attempts: 0,
            failed_attempts: 0,
            current_attempt: Some(0),
            elapsed_ms: 0,
        },
        started_at: Instant::now(),
        results: Vec::new(),
        current_stage: Some("preflight".to_string()),
        error: None,
    };

    // Store the run
    state.active_runs.write().await.insert(run_id, active_run);
    *state.current_status.write().await = AgentStatus::Running;

    // Spawn the actual test execution
    let run_state = state.clone();
    tokio::spawn(async move {
        execute_test_run(run_id, run_state).await;
    });

    let estimated_duration = request.scenario.timing.attempt_timeout.as_secs();

    Ok(Json(StartRunResponse {
        success: true,
        run_id,
        error: None,
        estimated_duration_secs: estimated_duration,
    }))
}

async fn execute_test_run(run_id: Uuid, state: SharedState) {
    info!("Executing test run {}", run_id);

    // Update status to Running
    {
        let mut runs = state.active_runs.write().await;
        if let Some(run) = runs.get_mut(&run_id) {
            run.status = RunStatus::Running;
            run.current_stage = Some("running".to_string());
        }
    }

    // Get run details
    let (total_attempts, peer_agents) = {
        let runs = state.active_runs.read().await;
        match runs.get(&run_id) {
            Some(run) => (run.progress.total_attempts, run.peer_agents.clone()),
            None => return,
        }
    };

    // Execute test attempts
    for attempt in 0..total_attempts {
        // Check if run was cancelled
        {
            let runs = state.active_runs.read().await;
            if let Some(run) = runs.get(&run_id) {
                if run.status == RunStatus::Cancelled {
                    break;
                }
            }
        }

        // Simulate connectivity test to each peer
        let mut attempt_results = Vec::new();
        for (peer_idx, peer) in peer_agents.iter().enumerate() {
            let attempt_num = attempt * peer_agents.len() as u32 + peer_idx as u32;
            let result = simulate_connectivity_test(&state, run_id, attempt_num, peer).await;
            attempt_results.push(result);
        }

        // Update progress
        {
            let mut runs = state.active_runs.write().await;
            if let Some(run) = runs.get_mut(&run_id) {
                run.progress.completed_attempts = attempt + 1;
                run.progress.current_attempt = Some(attempt + 1);
                run.progress.elapsed_ms = run.started_at.elapsed().as_millis() as u64;

                for result in &attempt_results {
                    if result.success {
                        run.progress.successful_attempts += 1;
                    } else {
                        run.progress.failed_attempts += 1;
                    }
                    run.results.push(result.clone());
                }
            }
        }

        // Small delay between attempts
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    // Mark as completed
    {
        let mut runs = state.active_runs.write().await;
        if let Some(run) = runs.get_mut(&run_id) {
            if run.status != RunStatus::Cancelled {
                run.status = RunStatus::Completed;
                run.current_stage = None;
            }
            run.progress.elapsed_ms = run.started_at.elapsed().as_millis() as u64;
        }
    }

    // Update agent status if no more active runs
    {
        let runs = state.active_runs.read().await;
        let has_active = runs
            .values()
            .any(|r| r.status == RunStatus::Running || r.status == RunStatus::Preflight);
        if !has_active {
            *state.current_status.write().await = AgentStatus::Idle;
        }
    }

    info!("Test run {} completed", run_id);
}

async fn simulate_connectivity_test(
    state: &SharedState,
    run_id: Uuid,
    attempt_id: u32,
    peer: &PeerAgentInfo,
) -> AttemptResult {
    // Simulate a connectivity test (in real implementation, this would do actual QUIC connection)
    let connect_time_ms = simulate_rtt(peer.p2p_listen_addr);

    let mut result = AttemptResult::new(run_id, "connectivity_test", attempt_id)
        .with_dimensions(
            NatType::Unknown, // NAT type would be detected in real implementation
            NatType::Unknown,
            IpMode::Ipv4Only,
        )
        .with_agents(&state.agent_id, &peer.agent_id);

    if let Some(time_ms) = connect_time_ms {
        result.record_success(ConnectionMethod::Direct, time_ms, SuccessLevel::Usable);
    } else {
        result.record_failure(
            "Connection timeout",
            FailureReasonCode::Timeout,
            FailureCategory::SutConnectivityFailure,
        );
    }

    result
}

fn simulate_rtt(addr: SocketAddr) -> Option<u64> {
    // Simulate RTT based on address (for testing purposes)
    // In real implementation, this would measure actual connectivity
    if addr.port() == 0 {
        return None; // Invalid address
    }

    // Simulate variable latency based on IP
    let base_rtt = match addr.ip() {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            (octets[0] as u64 % 50) + 10
        }
        IpAddr::V6(_) => 25,
    };

    // 90% success rate simulation
    if rand::random::<f64>() < 0.9 {
        Some(base_rtt + rand::random::<u64>() % 20)
    } else {
        None
    }
}

async fn stop_run_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<Uuid>,
    Json(request): Json<StopRunRequest>,
) -> Result<Json<StopRunResponse>, StatusCode> {
    info!("Stopping run {} (reason: {:?})", run_id, request.reason);

    let mut runs = state.active_runs.write().await;
    if let Some(run) = runs.get_mut(&run_id) {
        run.status = RunStatus::Cancelled;
        run.error = request.reason;
        run.progress.elapsed_ms = run.started_at.elapsed().as_millis() as u64;

        Ok(Json(StopRunResponse {
            success: true,
            run_id,
            attempts_completed: run.progress.completed_attempts,
            artifacts_uploaded: false,
        }))
    } else {
        Ok(Json(StopRunResponse {
            success: false,
            run_id,
            attempts_completed: 0,
            artifacts_uploaded: false,
        }))
    }
}

async fn status_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<Uuid>,
) -> Result<Json<RunStatusResponse>, StatusCode> {
    let runs = state.active_runs.read().await;
    if let Some(run) = runs.get(&run_id) {
        Ok(Json(RunStatusResponse {
            run_id,
            status: run.status,
            progress: run.progress.clone(),
            current_stage: run.current_stage.clone(),
            error: run.error.clone(),
        }))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn results_handler(
    State(state): State<SharedState>,
    Path(run_id): Path<Uuid>,
) -> Result<Json<GetResultsResponse>, StatusCode> {
    let runs = state.active_runs.read().await;
    if let Some(run) = runs.get(&run_id) {
        // Use RunSummary::from_attempts to generate proper summary with all fields
        let summary = RunSummary::from_attempts(run_id, &run.scenario.name, &run.results);

        Ok(Json(GetResultsResponse {
            run_id,
            results: run.results.clone(),
            artifacts: None,
            summary: Some(summary),
        }))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn apply_profile_handler(
    State(state): State<SharedState>,
    Json(request): Json<ApplyProfileRequest>,
) -> Json<ApplyProfileResponse> {
    info!("Applying NAT profile: {:?}", request.profile.name);

    if !state.capabilities.can_simulate_nat {
        return Json(ApplyProfileResponse {
            success: false,
            profile_name: request.profile.name.clone(),
            error: Some("NAT simulation not enabled on this agent".to_string()),
            nat_type_detected: None,
        });
    }

    // In a real implementation, this would configure iptables/tc rules
    // For now, just acknowledge the request
    Json(ApplyProfileResponse {
        success: true,
        profile_name: request.profile.name,
        error: None,
        nat_type_detected: Some(NatType::FullCone),
    })
}

async fn clear_profile_handler(
    State(state): State<SharedState>,
    Json(_request): Json<ClearProfileRequest>,
) -> Json<ClearProfileResponse> {
    info!("Clearing NAT profile");

    if !state.capabilities.can_simulate_nat {
        return Json(ClearProfileResponse {
            success: true, // Nothing to clear
            error: None,
        });
    }

    // In a real implementation, this would remove iptables/tc rules
    Json(ClearProfileResponse {
        success: true,
        error: None,
    })
}

async fn barrier_handler(
    State(state): State<SharedState>,
    Json(request): Json<BarrierRequest>,
) -> Json<BarrierResponse> {
    let barrier_key = format!("{}:{}", request.run_id, request.barrier_name);
    info!(
        "Barrier request from {} for {} (run {})",
        request.agent_id, request.barrier_name, request.run_id
    );

    let mut barriers = state.barriers.write().await;

    // Add agent to waiting list and check count
    let waiting_agents = barriers.entry(barrier_key.clone()).or_insert_with(Vec::new);
    if !waiting_agents.contains(&request.agent_id) {
        waiting_agents.push(request.agent_id.clone());
    }

    // For simplicity, release barrier after 2 agents (configurable in real implementation)
    let all_ready = waiting_agents.len() >= 2;

    // Capture waiting agents before potentially removing the entry
    let response_waiting = if all_ready {
        Vec::new()
    } else {
        waiting_agents.clone()
    };

    // Now we can safely remove since we're done with the reference
    if all_ready {
        info!("Barrier {} released", request.barrier_name);
        barriers.remove(&barrier_key);
    }

    Json(BarrierResponse {
        released: all_ready,
        barrier_name: request.barrier_name,
        all_agents_ready: all_ready,
        waiting_agents: response_waiting,
        timeout: false,
    })
}
