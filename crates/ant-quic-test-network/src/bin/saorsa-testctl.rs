use ant_quic_test_network::{
    harness::{
        AgentCapabilities, AgentClient, AgentInfo, AttemptResult, GetResultsRequest,
        GetResultsResponse, HandshakeRequest, HandshakeResponse, HealthCheckResponse, ResultFormat,
        RunStatus, RunStatusResponse, RunSummary, ScenarioSpec, StartRunRequest, StartRunResponse,
        StopRunResponse,
    },
    orchestrator::NatTestMatrix,
};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::collections::HashMap;
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

    fn add_agent(&mut self, agent_id: &str, base_url: &str) {
        let client = AgentClient::new(base_url, agent_id);
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
                    if let Ok(health) = resp.json::<HealthCheckResponse>().await {
                        let agent_info = AgentInfo {
                            agent_id: health.agent_id.clone(),
                            version: health.version,
                            capabilities: AgentCapabilities::default(),
                            listen_addr: url
                                .parse()
                                .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                            nat_profiles_available: vec![],
                            status: health.status,
                        };
                        self.add_agent(&health.agent_id, url);
                        discovered.push(agent_info);
                        info!("Discovered agent: {} at {}", health.agent_id, url);
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
                    if let Ok(handshake) = resp.json::<HandshakeResponse>().await {
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

    async fn start_run(&mut self, scenario: ScenarioSpec) -> Result<Uuid> {
        let run_id = Uuid::new_v4();
        self.run_id = Some(run_id);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        let peer_agents: Vec<_> = self
            .agents
            .iter()
            .map(|(id, c)| ant_quic_test_network::harness::PeerAgentInfo {
                agent_id: id.clone(),
                listen_addr: c
                    .base_url
                    .parse()
                    .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
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
                    if let Ok(start_resp) = resp.json::<StartRunResponse>().await {
                        if start_resp.success {
                            info!("Started run {} on agent {}", run_id, agent_id);
                        } else {
                            error!(
                                "Failed to start run on {}: {:?}",
                                agent_id, start_resp.error
                            );
                        }
                    }
                }
                Ok(resp) => {
                    error!("Start run on {} returned: {}", agent_id, resp.status());
                }
                Err(e) => {
                    error!("Failed to start run on {}: {}", agent_id, e);
                }
            }
        }

        Ok(run_id)
    }

    async fn get_status(&self, run_id: Uuid) -> Result<HashMap<String, RunStatusResponse>> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;

        let mut statuses = HashMap::new();

        for (agent_id, agent_client) in &self.agents {
            let url = agent_client.status_url(run_id);
            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(status) = resp.json::<RunStatusResponse>().await {
                        statuses.insert(agent_id.clone(), status);
                    }
                }
                _ => {
                    warn!("Failed to get status from {}", agent_id);
                }
            }
        }

        Ok(statuses)
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
                    if let Ok(stop_resp) = resp.json::<StopRunResponse>().await {
                        info!(
                            "Stopped run on {}: {} attempts completed",
                            agent_id, stop_resp.attempts_completed
                        );
                    }
                }
                _ => {
                    warn!("Failed to stop run on {}", agent_id);
                }
            }
        }

        Ok(())
    }

    async fn collect_results(&self, run_id: Uuid) -> Result<Vec<AttemptResult>> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()?;

        let mut all_results = Vec::new();

        for (agent_id, agent_client) in &self.agents {
            let url = agent_client.results_url(run_id);
            let request = GetResultsRequest {
                run_id,
                format: ResultFormat::Json,
                include_artifacts: false,
            };

            match client.post(&url).json(&request).send().await {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(results_resp) = resp.json::<GetResultsResponse>().await {
                        info!(
                            "Collected {} results from {}",
                            results_resp.results.len(),
                            agent_id
                        );
                        all_results.extend(results_resp.results);
                    }
                }
                _ => {
                    warn!("Failed to collect results from {}", agent_id);
                }
            }
        }

        Ok(all_results)
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
    report.push_str(&format!("## Summary\n"));
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
            let run_id = orchestrator.start_run(scenario_spec).await?;
            info!("Run started: {}", run_id);

            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let statuses = orchestrator.get_status(run_id).await?;

                let all_complete = statuses
                    .values()
                    .all(|s| matches!(s.status, RunStatus::Completed | RunStatus::Failed));

                if all_complete {
                    break;
                }

                let total_progress: u32 = statuses
                    .values()
                    .map(|s| s.progress.completed_attempts)
                    .sum();
                info!("Progress: {} attempts completed", total_progress);
            }

            let results = orchestrator.collect_results(run_id).await?;
            let summary = RunSummary::from_attempts(run_id, &scenario, &results);

            info!(
                "Run complete: {}/{} successful ({:.1}%)",
                summary.successful_attempts,
                summary.total_attempts,
                summary.success_rate * 100.0
            );

            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&results)?;
                std::fs::write(&output_path, json)?;
                info!("Results written to {:?}", output_path);
            }
        }

        Commands::Status { run_id, agents } => {
            if agents.is_empty() {
                anyhow::bail!("At least one agent URL required");
            }

            orchestrator.discover_agents(&agents).await?;
            let statuses = orchestrator.get_status(run_id).await?;

            for (agent_id, status) in statuses {
                println!(
                    "{}: {:?} - {}/{} completed",
                    agent_id,
                    status.status,
                    status.progress.completed_attempts,
                    status.progress.total_attempts
                );
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
            let results = orchestrator.collect_results(run_id).await?;

            let output_str = match format.as_str() {
                "json" => serde_json::to_string_pretty(&results)?,
                "jsonl" => results
                    .iter()
                    .filter_map(|r| r.to_jsonl().ok())
                    .collect::<Vec<_>>()
                    .join("\n"),
                _ => format!("{:?}", results),
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
                if file_path.extension().map_or(false, |e| e == "jsonl") {
                    content
                        .lines()
                        .filter_map(|line| serde_json::from_str(line).ok())
                        .collect()
                } else {
                    serde_json::from_str(&content)?
                }
            } else if !agents.is_empty() {
                orchestrator.discover_agents(&agents).await?;
                orchestrator.collect_results(run_id).await?
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
