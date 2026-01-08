use ant_quic_test_network::{
    harness::{
        AgentCapabilities, AgentClient, AgentInfo, AttemptResult, CollectionResult,
        FALLBACK_SOCKET_ADDR, GetResultsRequest, GetResultsResponse, HandshakeRequest,
        HandshakeResponse, HealthCheckResponse, ResultFormat, RunStatusResponse, RunSummary,
        ScenarioSpec, StartRunRequest, StartRunResponse, StartRunResult, StatusPollResult,
        StopRunResponse,
    },
    orchestrator::NatTestMatrix,
};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "saorsa-testctl")]
#[command(about = "Orchestrator for distributed P2P network testing")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, default_value = "info")]
    log_level: String,

    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    Run {
        #[arg(long)]
        scenario: String,

        #[arg(long)]
        agents: Vec<String>,

        #[arg(long, default_value = "100")]
        attempts: u32,

        #[arg(long)]
        output: Option<PathBuf>,

        #[arg(long)]
        seed: Option<u64>,
    },

    Status {
        #[arg(long)]
        run_id: Uuid,

        #[arg(long)]
        agents: Vec<String>,
    },

    Stop {
        #[arg(long)]
        run_id: Uuid,

        #[arg(long)]
        agents: Vec<String>,

        #[arg(long)]
        reason: Option<String>,
    },

    Results {
        #[arg(long)]
        run_id: Uuid,

        #[arg(long)]
        agents: Vec<String>,

        #[arg(long, default_value = "jsonl")]
        format: String,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    Discover {
        #[arg(long)]
        registry: Option<String>,

        #[arg(long)]
        agents: Vec<String>,
    },

    Validate {
        #[arg(long)]
        scenario: PathBuf,
    },

    Matrix {
        #[arg(long, default_value = "minimal")]
        scope: String,

        #[arg(long)]
        output: Option<PathBuf>,
    },

    Report {
        #[arg(long)]
        run_id: Uuid,

        #[arg(long, default_value = "markdown")]
        format: String,

        #[arg(long)]
        output: Option<PathBuf>,

        #[arg(long)]
        results_file: Option<PathBuf>,

        #[arg(long)]
        agents: Vec<String>,
    },
}

struct Orchestrator {
    agents: HashMap<String, AgentClient>,
    run_id: Option<Uuid>,
}

impl Orchestrator {
    fn new() -> Self {
        Self {
            agents: HashMap::new(),
            run_id: None,
        }
    }

    fn add_agent(&mut self, agent_id: &str, base_url: &str, p2p_listen_addr: SocketAddr) {
        let client = AgentClient::new(base_url, agent_id, p2p_listen_addr);
        self.agents.insert(agent_id.to_string(), client);
    }

    async fn discover_agents(&mut self, agent_urls: &[String]) -> Result<Vec<AgentInfo>> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;

        let mut discovered = Vec::new();

        for url in agent_urls {
            let health_url = format!("{}/health", url.trim_end_matches('/'));
            match client.get(&health_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<HealthCheckResponse>().await {
                        Ok(health) => {
                            let p2p_addr = match health.p2p_listen_addr {
                                Some(addr) => addr,
                                None => {
                                    warn!(
                                        "Agent {} at {} did not report p2p_listen_addr; using fallback 0.0.0.0:0 which may cause test failures",
                                        health.agent_id, url
                                    );
                                    FALLBACK_SOCKET_ADDR
                                }
                            };
                            let agent_info = AgentInfo {
                                agent_id: health.agent_id.clone(),
                                version: health.version,
                                capabilities: AgentCapabilities::default(),
                                api_base_url: url.clone(),
                                p2p_listen_addr: p2p_addr,
                                nat_profiles_available: vec![],
                                status: health.status,
                            };
                            self.add_agent(&health.agent_id, url, p2p_addr);
                            discovered.push(agent_info);
                            info!("Discovered agent: {} at {}", health.agent_id, url);
                        }
                        Err(e) => {
                            error!(
                                "Agent at {} returned invalid JSON: {}. Schema mismatch?",
                                url, e
                            );
                        }
                    }
                }
                Ok(resp) => {
                    warn!("Agent at {} returned status {}", url, resp.status());
                }
                Err(e) => {
                    warn!("Failed to reach agent at {}: {}", url, e);
                }
            }
        }

        Ok(discovered)
    }

    async fn handshake_agents(&self) -> Result<Vec<HandshakeResponse>> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;

        let request = HandshakeRequest {
            orchestrator_id: "saorsa-testctl".to_string(),
            protocol_version: 1,
            required_capabilities: vec![],
        };

        let mut responses = Vec::new();

        for (agent_id, agent_client) in &self.agents {
            let url = agent_client.handshake_url();
            match client.post(&url).json(&request).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<HandshakeResponse>().await {
                        Ok(handshake) => {
                            if handshake.compatible {
                                info!("Handshake successful with {}", agent_id);
                            } else {
                                warn!(
                                    "Agent {} missing capabilities: {:?}",
                                    agent_id, handshake.missing_capabilities
                                );
                            }
                            responses.push(handshake);
                        }
                        Err(e) => {
                            error!("Handshake response from {} invalid JSON: {}", agent_id, e);
                        }
                    }
                }
                Ok(resp) => {
                    error!("Handshake with {} failed: {}", agent_id, resp.status());
                }
                Err(e) => {
                    error!("Failed to handshake with {}: {}", agent_id, e);
                }
            }
        }

        Ok(responses)
    }

    async fn start_run(&mut self, scenario: ScenarioSpec) -> Result<StartRunResult> {
        let run_id = Uuid::new_v4();
        self.run_id = Some(run_id);
        let mut result = StartRunResult::new(run_id);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        let peer_agents: Vec<_> = self
            .agents
            .iter()
            .map(|(id, c)| ant_quic_test_network::harness::PeerAgentInfo {
                agent_id: id.clone(),
                api_base_url: Some(c.base_url.clone()),
                p2p_listen_addr: c.p2p_listen_addr,
                nat_profile: None,
            })
            .collect();

        for (agent_id, agent_client) in &self.agents {
            let request = StartRunRequest {
                run_id,
                scenario: scenario.clone(),
                agent_role: "peer".to_string(),
                peer_agents: peer_agents.clone(),
            };

            let url = agent_client.start_run_url();
            match client.post(&url).json(&request).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<StartRunResponse>().await {
                        Ok(start_resp) if start_resp.success => {
                            info!("Started run {} on agent {}", run_id, agent_id);
                            result.record_success(agent_id);
                        }
                        Ok(start_resp) => {
                            let err = start_resp
                                .error
                                .unwrap_or_else(|| "Unknown error".to_string());
                            error!("Failed to start run on {}: {}", agent_id, err);
                            result.record_failure(agent_id, &err);
                        }
                        Err(e) => {
                            error!("Failed to parse response from {}: {}", agent_id, e);
                            result.record_failure(agent_id, &format!("JSON parse error: {}", e));
                        }
                    }
                }
                Ok(resp) => {
                    let err = format!("HTTP {}", resp.status());
                    error!("Start run on {} returned: {}", agent_id, err);
                    result.record_failure(agent_id, &err);
                }
                Err(e) => {
                    error!("Failed to start run on {}: {}", agent_id, e);
                    result.record_failure(agent_id, &e.to_string());
                }
            }
        }

        if !result.has_any_success() {
            anyhow::bail!(
                "Failed to start run on ANY agent. Failures: {:?}",
                result.failed_agents()
            );
        }

        if !result.all_succeeded() {
            warn!(
                "Run {} started on {}/{} agents. Failed: {:?}",
                run_id,
                result.successful_agents().len(),
                result.successful_agents().len() + result.failed_agents().len(),
                result.failed_agents()
            );
        }

        Ok(result)
    }

    async fn get_status(&self, run_id: Uuid) -> Result<StatusPollResult> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;

        let mut result = StatusPollResult::new(self.agents.len());

        for (agent_id, agent_client) in &self.agents {
            let url = agent_client.status_url(run_id);
            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<RunStatusResponse>().await {
                        Ok(status) => {
                            result.record_status(agent_id, status);
                        }
                        Err(e) => {
                            let err = format!("JSON parse error: {}", e);
                            error!("Failed to parse status response from {}: {}", agent_id, e);
                            result.record_failure(agent_id, &err);
                        }
                    }
                }
                Ok(resp) => {
                    let err = format!("HTTP {}", resp.status());
                    warn!("Status request to {} failed: {}", agent_id, err);
                    result.record_failure(agent_id, &err);
                }
                Err(e) => {
                    let err = e.to_string();
                    warn!("Failed to get status from {}: {}", agent_id, err);
                    result.record_failure(agent_id, &err);
                }
            }
        }

        Ok(result)
    }

    async fn stop_run(&self, run_id: Uuid, reason: Option<&str>) -> Result<()> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;

        for (agent_id, agent_client) in &self.agents {
            let url = agent_client.stop_run_url(run_id);
            let request = ant_quic_test_network::harness::StopRunRequest {
                run_id,
                reason: reason.map(String::from),
            };

            match client.post(&url).json(&request).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<StopRunResponse>().await {
                        Ok(stop_resp) => {
                            info!(
                                "Stopped run on {}: {} attempts completed",
                                agent_id, stop_resp.attempts_completed
                            );
                        }
                        Err(e) => {
                            error!("Failed to parse stop response from {}: {}", agent_id, e);
                        }
                    }
                }
                _ => {
                    warn!("Failed to stop run on {}", agent_id);
                }
            }
        }

        Ok(())
    }

    async fn collect_results(&self, run_id: Uuid) -> Result<CollectionResult<AttemptResult>> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()?;

        let mut collection = CollectionResult::new();

        for (agent_id, agent_client) in &self.agents {
            let url = agent_client.results_url(run_id);
            let request = GetResultsRequest {
                run_id,
                format: ResultFormat::Json,
                include_artifacts: false,
            };

            match client.post(&url).json(&request).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<GetResultsResponse>().await {
                        Ok(results_resp) => {
                            info!(
                                "Collected {} results from {}",
                                results_resp.results.len(),
                                agent_id
                            );
                            collection.add_items(agent_id, results_resp.results);
                        }
                        Err(e) => {
                            error!("Failed to parse results from {}: {}", agent_id, e);
                            collection
                                .record_failure(agent_id, &format!("JSON parse error: {}", e));
                        }
                    }
                }
                Ok(resp) => {
                    let err = format!("HTTP {}", resp.status());
                    warn!("Failed to collect results from {}: {}", agent_id, err);
                    collection.record_failure(agent_id, &err);
                }
                Err(e) => {
                    warn!("Failed to collect results from {}: {}", agent_id, e);
                    collection.record_failure(agent_id, &e.to_string());
                }
            }
        }

        if !collection.is_complete() {
            warn!(
                "Results collection incomplete. Failed sources: {:?}",
                collection.failed_sources
            );
        }

        Ok(collection)
    }
}

fn load_scenario(name: &str) -> Result<ScenarioSpec> {
    match name {
        "connectivity_matrix" => Ok(ScenarioSpec::connectivity_matrix()),
        "ci_fast" => Ok(ScenarioSpec::ci_fast()),
        "gossip_coverage" => Ok(ScenarioSpec::gossip_coverage()),
        "oracle_suite" => Ok(ScenarioSpec::oracle_suite()),
        _ => Err(anyhow::anyhow!("Unknown scenario: {}", name)),
    }
}

fn generate_matrix_report(scope: &str) -> String {
    let matrix = match scope {
        "minimal" => NatTestMatrix::minimal(),
        "comprehensive" | "full" => NatTestMatrix::comprehensive(),
        _ => NatTestMatrix::minimal(),
    };

    let summary = matrix.rate_summary();

    let mut report = String::new();
    report.push_str("# NAT Connectivity Matrix\n\n");
    report.push_str("## Summary\n");
    report.push_str(&format!("- Total combinations: {}\n", summary.total));
    report.push_str(&format!("- Easy (≥90%): {}\n", summary.easy));
    report.push_str(&format!("- Moderate (70-89%): {}\n", summary.moderate));
    report.push_str(&format!("- Hard (50-69%): {}\n", summary.hard));
    report.push_str(&format!("- Very Hard (<50%): {}\n", summary.very_hard));
    report.push_str(&format!(
        "- Average expected rate: {:.1}%\n\n",
        summary.avg_expected_rate * 100.0
    ));

    report.push_str("## Matrix\n\n");
    report.push_str("| Source | Destination | Method | Expected |\n");
    report.push_str("|--------|-------------|--------|----------|\n");

    for pair in &matrix.combinations {
        report.push_str(&format!(
            "| {} | {} | {} | {:.0}% |\n",
            pair.source_nat,
            pair.dest_nat,
            pair.expected_method,
            pair.expected_success_rate * 100.0
        ));
    }

    report
}

fn generate_run_report(run_id: Uuid, results: &[AttemptResult], format: &str) -> String {
    let summary = RunSummary::from_attempts(run_id, "unknown", results);

    match format {
        "markdown" => {
            let mut report = String::new();
            report.push_str(&format!("# Test Run Report: {}\n\n", run_id));
            report.push_str("## Summary\n\n");
            report.push_str(&format!("- Total attempts: {}\n", summary.total_attempts));
            report.push_str(&format!("- Successful: {}\n", summary.successful_attempts));
            report.push_str(&format!("- Failed: {}\n", summary.failed_attempts));
            report.push_str(&format!(
                "- Success rate: {:.1}%\n",
                summary.success_rate * 100.0
            ));
            report.push_str(&format!(
                "- Harness failures: {}\n",
                summary.harness_failures
            ));
            report.push_str(&format!("- SUT failures: {}\n", summary.sut_failures));
            report.push_str(&format!(
                "- Infrastructure flakes: {}\n\n",
                summary.infrastructure_failures
            ));

            if let Some(p50) = summary.latency_p50_ms {
                report.push_str("## Latency\n\n");
                report.push_str(&format!("- p50: {}ms\n", p50));
                if let Some(p95) = summary.latency_p95_ms {
                    report.push_str(&format!("- p95: {}ms\n", p95));
                }
                if let Some(p99) = summary.latency_p99_ms {
                    report.push_str(&format!("- p99: {}ms\n", p99));
                }
            }

            report.push_str("\n## By Dimension\n\n");
            report.push_str("| Dimension | Total | Success | Rate |\n");
            report.push_str("|-----------|-------|---------|------|\n");
            for (dim, stats) in &summary.by_dimension {
                report.push_str(&format!(
                    "| {} | {} | {} | {:.1}% |\n",
                    dim,
                    stats.total,
                    stats.successful,
                    stats.success_rate * 100.0
                ));
            }

            report
        }
        "json" => serde_json::to_string_pretty(&summary).unwrap_or_default(),
        _ => format!("{:?}", summary),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(&cli.log_level)
        .init();

    let mut orchestrator = Orchestrator::new();

    match cli.command {
        Commands::Run {
            scenario,
            agents,
            attempts,
            output,
            seed,
        } => {
            if agents.is_empty() {
                anyhow::bail!("At least one agent URL required (--agents)");
            }

            let discovered = orchestrator.discover_agents(&agents).await?;
            if discovered.is_empty() {
                anyhow::bail!("No agents discovered");
            }

            orchestrator.handshake_agents().await?;

            let mut scenario_spec = load_scenario(&scenario)?;
            if let Some(s) = seed {
                scenario_spec.seed = Some(s);
            }
            scenario_spec.test_matrix.attempts_per_cell = attempts;

            info!("Starting run with scenario: {}", scenario);
            let start_result = orchestrator.start_run(scenario_spec).await?;
            let run_id = start_result.run_id;
            info!(
                "Run started: {} ({}/{} agents)",
                run_id,
                start_result.successful_agents().len(),
                start_result.successful_agents().len() + start_result.failed_agents().len()
            );

            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let poll_result = orchestrator.get_status(run_id).await?;

                if poll_result.all_complete() {
                    break;
                }

                if !poll_result.failed_agents.is_empty() {
                    warn!(
                        "Status poll: {}/{} agents failed to respond",
                        poll_result.failed_agents.len(),
                        poll_result.expected_count
                    );
                }

                let total_progress: u32 = poll_result
                    .statuses
                    .values()
                    .map(|s| s.progress.completed_attempts)
                    .sum();
                info!(
                    "Progress: {} attempts completed ({}/{} agents reporting)",
                    total_progress,
                    poll_result.statuses.len(),
                    poll_result.expected_count
                );
            }

            let collection = orchestrator.collect_results(run_id).await?;
            let summary = RunSummary::from_attempts(run_id, &scenario, &collection.items);

            info!(
                "Run complete: {}/{} successful ({:.1}%)",
                summary.successful_attempts,
                summary.total_attempts,
                summary.success_rate * 100.0
            );

            if !collection.is_complete() {
                warn!(
                    "WARNING: Results incomplete - {} sources failed",
                    collection.failed_sources.len()
                );
            }

            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&collection.items)?;
                std::fs::write(&output_path, json)?;
                info!("Results written to {:?}", output_path);
            }
        }

        Commands::Status { run_id, agents } => {
            if agents.is_empty() {
                anyhow::bail!("At least one agent URL required");
            }

            orchestrator.discover_agents(&agents).await?;
            let poll_result = orchestrator.get_status(run_id).await?;

            for (agent_id, status) in &poll_result.statuses {
                println!(
                    "{}: {:?} - {}/{} completed",
                    agent_id,
                    status.status,
                    status.progress.completed_attempts,
                    status.progress.total_attempts
                );
            }

            if !poll_result.failed_agents.is_empty() {
                for (agent_id, err) in &poll_result.failed_agents {
                    println!("{}: FAILED - {}", agent_id, err);
                }
            }
        }

        Commands::Stop {
            run_id,
            agents,
            reason,
        } => {
            if agents.is_empty() {
                anyhow::bail!("At least one agent URL required");
            }

            orchestrator.discover_agents(&agents).await?;
            orchestrator.stop_run(run_id, reason.as_deref()).await?;
            info!("Run {} stopped", run_id);
        }

        Commands::Results {
            run_id,
            agents,
            format,
            output,
        } => {
            if agents.is_empty() {
                anyhow::bail!("At least one agent URL required");
            }

            orchestrator.discover_agents(&agents).await?;
            let collection = orchestrator.collect_results(run_id).await?;

            if !collection.is_complete() {
                warn!(
                    "WARNING: Results incomplete - {} sources failed: {:?}",
                    collection.failed_sources.len(),
                    collection.failed_sources
                );
            }

            let output_str = match format.as_str() {
                "json" => serde_json::to_string_pretty(&collection.items)?,
                "jsonl" => collection
                    .items
                    .iter()
                    .filter_map(|r| r.to_jsonl().ok())
                    .collect::<Vec<_>>()
                    .join("\n"),
                _ => format!("{:?}", collection.items),
            };

            if let Some(output_path) = output {
                std::fs::write(&output_path, &output_str)?;
                info!("Results written to {:?}", output_path);
            } else {
                println!("{}", output_str);
            }
        }

        Commands::Discover { registry, agents } => {
            let urls = if agents.is_empty() {
                if let Some(reg) = registry {
                    vec![reg]
                } else {
                    vec!["http://localhost:8080".to_string()]
                }
            } else {
                agents
            };

            let discovered = orchestrator.discover_agents(&urls).await?;
            println!("Discovered {} agents:", discovered.len());
            for agent in discovered {
                println!(
                    "  - {}: {} ({:?})",
                    agent.agent_id, agent.version, agent.status
                );
            }
        }

        Commands::Validate { scenario } => {
            let content = std::fs::read_to_string(&scenario)?;
            let spec: ScenarioSpec = serde_json::from_str(&content)
                .or_else(|_| serde_yaml::from_str(&content))
                .context("Failed to parse scenario file")?;

            match spec.validate() {
                Ok(()) => {
                    println!("Scenario '{}' is valid", spec.id);
                    println!("  - Name: {}", spec.name);
                    println!("  - Suite: {:?}", spec.suite);
                    println!("  - NAT profiles: {}", spec.nat_profiles.len());
                    println!("  - Estimated duration: {:?}", spec.estimated_duration());
                }
                Err(errors) => {
                    eprintln!("Scenario validation failed:");
                    for err in errors {
                        eprintln!("  - {}", err);
                    }
                    std::process::exit(1);
                }
            }
        }

        Commands::Matrix { scope, output } => {
            let report = generate_matrix_report(&scope);

            if let Some(output_path) = output {
                std::fs::write(&output_path, &report)?;
                info!("Matrix report written to {:?}", output_path);
            } else {
                println!("{}", report);
            }
        }

        Commands::Report {
            run_id,
            format,
            output,
            results_file,
            agents,
        } => {
            let results: Vec<AttemptResult> = if let Some(file_path) = results_file {
                let content = std::fs::read_to_string(&file_path)?;
                if file_path.extension().is_some_and(|e| e == "jsonl") {
                    content
                        .lines()
                        .filter_map(|line| serde_json::from_str(line).ok())
                        .collect()
                } else {
                    serde_json::from_str(&content)?
                }
            } else if !agents.is_empty() {
                orchestrator.discover_agents(&agents).await?;
                let collection = orchestrator.collect_results(run_id).await?;
                if !collection.is_complete() {
                    warn!(
                        "WARNING: Results incomplete - {} sources failed",
                        collection.failed_sources.len()
                    );
                }
                collection.items
            } else {
                anyhow::bail!("Either --results-file or --agents required");
            };

            let report = generate_run_report(run_id, &results, &format);

            if let Some(output_path) = output {
                std::fs::write(&output_path, &report)?;
                info!("Report written to {:?}", output_path);
            } else {
                println!("{}", report);
            }
        }
    }

    Ok(())
}
