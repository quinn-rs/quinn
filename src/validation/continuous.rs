//! Continuous Validation Pipeline
//!
//! This module implements a continuous validation system that runs validation
//! scenarios on a schedule, tracks baselines, and detects regressions.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use tokio::{sync::RwLock, time::interval};
use tracing::{debug, error, info, warn};

use crate::validation::{
    ValidationError, ValidationSchedule, BaselinePolicy, AlertConfig, AlertDestination,
    AlertThresholds, ScenarioResult, ScenarioMetrics, MetricType, AggregatedMetric,
    ValidationScenarioExecutor, AnalysisConfig, StatisticalMethod,
};

/// Continuous validation engine
pub struct ContinuousValidationEngine {
    /// Validation schedule
    schedule: ValidationSchedule,
    /// Baseline tracking
    baseline_tracker: Arc<RwLock<BaselineTracker>>,
    /// Alert manager
    alert_manager: Arc<AlertManager>,
    /// Scenario executor
    scenario_executor: Arc<ValidationScenarioExecutor>,
    /// Validation history
    history: Arc<RwLock<ValidationHistory>>,
    /// Running tasks
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl ContinuousValidationEngine {
    /// Create new continuous validation engine
    pub fn new(
        schedule: ValidationSchedule,
        baseline_policy: BaselinePolicy,
        alert_config: AlertConfig,
        scenario_executor: Arc<ValidationScenarioExecutor>,
    ) -> Self {
        Self {
            schedule,
            baseline_tracker: Arc::new(RwLock::new(BaselineTracker::new(baseline_policy))),
            alert_manager: Arc::new(AlertManager::new(alert_config)),
            scenario_executor,
            history: Arc::new(RwLock::new(ValidationHistory::new())),
            tasks: Vec::new(),
        }
    }
    
    /// Start continuous validation
    pub async fn start(&mut self) -> Result<(), ValidationError> {
        info!("Starting continuous validation with schedule: {}", self.schedule.cron_expression);
        
        // Parse cron expression and start scheduler
        let scheduler_task = self.start_scheduler().await?;
        self.tasks.push(scheduler_task);
        
        // Start baseline update task
        let baseline_task = self.start_baseline_updater().await?;
        self.tasks.push(baseline_task);
        
        // Start alert monitoring task
        let alert_task = self.start_alert_monitor().await?;
        self.tasks.push(alert_task);
        
        Ok(())
    }
    
    /// Start validation scheduler
    async fn start_scheduler(&self) -> Result<tokio::task::JoinHandle<()>, ValidationError> {
        let schedule = self.schedule.clone();
        let executor = self.scenario_executor.clone();
        let history = self.history.clone();
        let baseline_tracker = self.baseline_tracker.clone();
        
        let handle = tokio::spawn(async move {
            // For simplicity, use interval instead of full cron parsing
            let interval_duration = Self::parse_cron_to_interval(&schedule.cron_expression);
            let mut scheduler = interval(interval_duration);
            
            loop {
                scheduler.tick().await;
                
                info!("Starting scheduled validation run");
                let run_result = Self::execute_validation_run(&executor, &schedule).await;
                
                match run_result {
                    Ok(results) => {
                        info!("Validation run completed with {} scenarios", results.len());
                        
                        // Store results in history
                        let mut hist = history.write().await;
                        hist.add_run(ValidationRun {
                            timestamp: SystemTime::now(),
                            results,
                            success: true,
                        });
                        
                        // Update baselines
                        let mut tracker = baseline_tracker.write().await;
                        tracker.update_with_results(&hist).await;
                    }
                    Err(e) => {
                        error!("Validation run failed: {}", e);
                        
                        let mut hist = history.write().await;
                        hist.add_run(ValidationRun {
                            timestamp: SystemTime::now(),
                            results: vec![],
                            success: false,
                        });
                    }
                }
            }
        });
        
        Ok(handle)
    }
    
    /// Parse cron expression to interval (simplified)
    fn parse_cron_to_interval(cron_expr: &str) -> Duration {
        // Simplified cron parsing - in production would use a proper cron library
        match cron_expr {
            "0 */6 * * *" => Duration::from_secs(6 * 3600), // Every 6 hours
            "0 0 * * *" => Duration::from_secs(24 * 3600),  // Daily
            "0 0 * * 0" => Duration::from_secs(7 * 24 * 3600), // Weekly
            _ => Duration::from_secs(3600), // Default to hourly
        }
    }
    
    /// Execute a validation run
    async fn execute_validation_run(
        executor: &ValidationScenarioExecutor,
        schedule: &ValidationSchedule,
    ) -> Result<Vec<ScenarioResult>, ValidationError> {
        let mut results = Vec::new();
        
        // Execute scenarios in priority order
        for scenario_id in &schedule.priority_order {
            debug!("Executing scenario: {}", scenario_id);
            
            let result = match scenario_id.as_str() {
                "basic_connectivity" => {
                    let config = crate::validation::scenarios::BasicConnectivityConfig {
                        endpoint_pairs: vec![
                            ("us-east-primary".to_string(), "us-west-primary".to_string()),
                        ],
                        success_criteria: crate::validation::SuccessCriteria {
                            min_success_rate: 0.95,
                            max_connection_time_ms: 5000,
                            max_failure_rate: 0.05,
                            min_throughput_mbps: Some(10),
                            max_latency_ms: Some(200),
                        },
                        timeout: Duration::from_secs(60),
                    };
                    executor.execute_basic_connectivity(config).await
                }
                "stress_test" => {
                    let config = crate::validation::scenarios::StressTestConfig {
                        concurrent_connections: 100,
                        connection_rate: Some(10.0),
                        duration: Duration::from_secs(300),
                        success_criteria: crate::validation::SuccessCriteria {
                            min_success_rate: 0.9,
                            max_connection_time_ms: 10000,
                            max_failure_rate: 0.1,
                            min_throughput_mbps: None,
                            max_latency_ms: None,
                        },
                    };
                    executor.execute_stress_test(config).await
                }
                _ => {
                    warn!("Unknown scenario: {}", scenario_id);
                    continue;
                }
            };
            
            match result {
                Ok(scenario_result) => results.push(scenario_result),
                Err(e) => {
                    error!("Scenario {} failed: {}", scenario_id, e);
                    // Continue with other scenarios
                }
            }
        }
        
        Ok(results)
    }
    
    /// Start baseline updater task
    async fn start_baseline_updater(&self) -> Result<tokio::task::JoinHandle<()>, ValidationError> {
        let baseline_tracker = self.baseline_tracker.clone();
        let history = self.history.clone();
        
        let handle = tokio::spawn(async move {
            let mut update_interval = interval(Duration::from_secs(3600)); // Update hourly
            
            loop {
                update_interval.tick().await;
                
                let hist = history.read().await;
                let mut tracker = baseline_tracker.write().await;
                
                if let Err(e) = tracker.update_with_results(&hist).await {
                    warn!("Failed to update baselines: {}", e);
                }
            }
        });
        
        Ok(handle)
    }
    
    /// Start alert monitoring task
    async fn start_alert_monitor(&self) -> Result<tokio::task::JoinHandle<()>, ValidationError> {
        let alert_manager = self.alert_manager.clone();
        let baseline_tracker = self.baseline_tracker.clone();
        let history = self.history.clone();
        
        let handle = tokio::spawn(async move {
            let mut check_interval = interval(Duration::from_secs(300)); // Check every 5 minutes
            
            loop {
                check_interval.tick().await;
                
                let hist = history.read().await;
                let tracker = baseline_tracker.read().await;
                
                if let Some(latest_run) = hist.get_latest_run() {
                    if let Err(e) = alert_manager.check_for_alerts(latest_run, &tracker).await {
                        warn!("Alert check failed: {}", e);
                    }
                }
            }
        });
        
        Ok(handle)
    }
    
    /// Get validation history summary
    pub async fn get_history_summary(&self, period: Duration) -> ValidationHistorySummary {
        let history = self.history.read().await;
        history.get_summary(period)
    }
    
    /// Get current baselines
    pub async fn get_current_baselines(&self) -> HashMap<String, BaselineMetric> {
        let tracker = self.baseline_tracker.read().await;
        tracker.get_current_baselines()
    }
    
    /// Force a validation run
    pub async fn trigger_validation_run(&self) -> Result<Vec<ScenarioResult>, ValidationError> {
        info!("Triggering manual validation run");
        Self::execute_validation_run(&self.scenario_executor, &self.schedule).await
    }
    
    /// Stop continuous validation
    pub async fn stop(&mut self) {
        info!("Stopping continuous validation");
        
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

/// Baseline tracking system
struct BaselineTracker {
    /// Baseline policy configuration
    policy: BaselinePolicy,
    /// Current baselines for each scenario
    baselines: HashMap<String, BaselineMetric>,
    /// Baseline update history
    update_history: Vec<BaselineUpdate>,
}

impl BaselineTracker {
    /// Create new baseline tracker
    fn new(policy: BaselinePolicy) -> Self {
        Self {
            policy,
            baselines: HashMap::new(),
            update_history: Vec::new(),
        }
    }
    
    /// Update baselines with new results
    async fn update_with_results(&mut self, history: &ValidationHistory) -> Result<(), ValidationError> {
        let recent_runs = history.get_recent_runs(self.policy.min_runs as usize);
        
        if recent_runs.len() < self.policy.min_runs as usize {
            debug!("Not enough runs for baseline update: {} < {}", recent_runs.len(), self.policy.min_runs);
            return Ok(());
        }
        
        // Calculate new baselines for each scenario
        let mut scenario_metrics: HashMap<String, Vec<&ScenarioMetrics>> = HashMap::new();
        
        for run in &recent_runs {
            for result in &run.results {
                scenario_metrics.entry(result.scenario_id.clone())
                    .or_insert_with(Vec::new)
                    .push(&result.metrics);
            }
        }
        
        for (scenario_id, metrics_list) in scenario_metrics {
            if let Some(new_baseline) = self.calculate_baseline(&metrics_list) {
                let should_update = match self.baselines.get(&scenario_id) {
                    Some(current) => self.should_update_baseline(current, &new_baseline),
                    None => true, // Always update if no baseline exists
                };
                
                if should_update {
                    info!("Updating baseline for scenario: {}", scenario_id);
                    self.baselines.insert(scenario_id.clone(), new_baseline.clone());
                    self.update_history.push(BaselineUpdate {
                        scenario_id,
                        timestamp: SystemTime::now(),
                        new_baseline,
                    });
                }
            }
        }
        
        Ok(())
    }
    
    /// Calculate baseline from metrics
    fn calculate_baseline(&self, metrics_list: &[&ScenarioMetrics]) -> Option<BaselineMetric> {
        if metrics_list.is_empty() {
            return None;
        }
        
        let success_rates: Vec<f32> = metrics_list.iter()
            .map(|m| {
                if m.connections_attempted > 0 {
                    m.connections_successful as f32 / m.connections_attempted as f32
                } else {
                    0.0
                }
            })
            .collect();
        
        let latencies: Vec<f64> = metrics_list.iter()
            .map(|m| m.average_latency_ms)
            .collect();
        
        Some(BaselineMetric {
            success_rate: Self::calculate_mean(&success_rates),
            latency_ms: Self::calculate_mean(&latencies),
            packet_loss_rate: Self::calculate_mean(
                &metrics_list.iter().map(|m| m.packet_loss_rate as f64).collect::<Vec<_>>()
            ),
            confidence_interval: self.policy.confidence_interval,
            sample_size: metrics_list.len(),
            last_updated: SystemTime::now(),
        })
    }
    
    /// Calculate mean of values
    fn calculate_mean<T: Into<f64> + Copy>(values: &[T]) -> f64 {
        if values.is_empty() {
            return 0.0;
        }
        
        values.iter().map(|v| (*v).into()).sum::<f64>() / values.len() as f64
    }
    
    /// Check if baseline should be updated
    fn should_update_baseline(&self, current: &BaselineMetric, new: &BaselineMetric) -> bool {
        let improvement = new.success_rate - current.success_rate;
        improvement >= self.policy.improvement_threshold
    }
    
    /// Get current baselines
    fn get_current_baselines(&self) -> HashMap<String, BaselineMetric> {
        self.baselines.clone()
    }
}

/// Baseline metric
#[derive(Debug, Clone)]
pub struct BaselineMetric {
    /// Expected success rate
    pub success_rate: f64,
    /// Expected latency in ms
    pub latency_ms: f64,
    /// Expected packet loss rate
    pub packet_loss_rate: f64,
    /// Confidence interval
    pub confidence_interval: f32,
    /// Sample size used for baseline
    pub sample_size: usize,
    /// Last update time
    pub last_updated: SystemTime,
}

/// Baseline update record
struct BaselineUpdate {
    scenario_id: String,
    timestamp: SystemTime,
    new_baseline: BaselineMetric,
}

/// Alert management system
struct AlertManager {
    /// Alert configuration
    config: AlertConfig,
    /// Alert history
    alert_history: VecDeque<Alert>,
    /// Alert suppression state
    suppressed_alerts: HashMap<String, SystemTime>,
}

impl AlertManager {
    /// Create new alert manager
    fn new(config: AlertConfig) -> Self {
        Self {
            config,
            alert_history: VecDeque::new(),
            suppressed_alerts: HashMap::new(),
        }
    }
    
    /// Check for alerts based on latest results
    async fn check_for_alerts(
        &self,
        latest_run: &ValidationRun,
        baseline_tracker: &BaselineTracker,
    ) -> Result<(), ValidationError> {
        let baselines = baseline_tracker.get_current_baselines();
        
        for result in &latest_run.results {
            if let Some(baseline) = baselines.get(&result.scenario_id) {
                self.check_scenario_alerts(result, baseline).await?;
            }
        }
        
        Ok(())
    }
    
    /// Check alerts for specific scenario
    async fn check_scenario_alerts(
        &self,
        result: &ScenarioResult,
        baseline: &BaselineMetric,
    ) -> Result<(), ValidationError> {
        let current_success_rate = if result.metrics.connections_attempted > 0 {
            result.metrics.connections_successful as f64 / result.metrics.connections_attempted as f64
        } else {
            0.0
        };
        
        // Check success rate drop
        let success_rate_drop = baseline.success_rate - current_success_rate;
        if success_rate_drop > self.config.thresholds.success_rate_drop as f64 {
            let alert = Alert {
                id: format!("success_rate_drop_{}_{}", result.scenario_id, SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()),
                alert_type: AlertType::SuccessRateDrop,
                scenario_id: result.scenario_id.clone(),
                message: format!("Success rate dropped by {:.2}% for scenario {}", 
                    success_rate_drop * 100.0, result.scenario_id),
                severity: AlertSeverity::High,
                timestamp: SystemTime::now(),
                current_value: current_success_rate,
                baseline_value: baseline.success_rate,
            };
            
            self.send_alert(alert).await?;
        }
        
        // Check latency increase
        let latency_increase_percent = if baseline.latency_ms > 0.0 {
            ((result.metrics.average_latency_ms - baseline.latency_ms) / baseline.latency_ms) * 100.0
        } else {
            0.0
        };
        
        if latency_increase_percent > self.config.thresholds.latency_increase_percent as f64 {
            let alert = Alert {
                id: format!("latency_increase_{}_{}", result.scenario_id, SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()),
                alert_type: AlertType::LatencyIncrease,
                scenario_id: result.scenario_id.clone(),
                message: format!("Latency increased by {:.1}% for scenario {}", 
                    latency_increase_percent, result.scenario_id),
                severity: AlertSeverity::Medium,
                timestamp: SystemTime::now(),
                current_value: result.metrics.average_latency_ms,
                baseline_value: baseline.latency_ms,
            };
            
            self.send_alert(alert).await?;
        }
        
        Ok(())
    }
    
    /// Send alert to configured destinations
    async fn send_alert(&self, alert: Alert) -> Result<(), ValidationError> {
        // Check if alert is suppressed
        if self.is_alert_suppressed(&alert) {
            debug!("Alert {} is suppressed", alert.id);
            return Ok(());
        }
        
        info!("Sending alert: {}", alert.message);
        
        for destination in &self.config.destinations {
            if let Err(e) = self.send_to_destination(&alert, destination).await {
                warn!("Failed to send alert to {:?}: {}", destination, e);
            }
        }
        
        Ok(())
    }
    
    /// Check if alert is suppressed
    fn is_alert_suppressed(&self, alert: &Alert) -> bool {
        // Check suppression rules
        for rule in &self.config.suppression_rules {
            if self.alert_matches_suppression_rule(alert, rule) {
                if let Some(&suppressed_until) = self.suppressed_alerts.get(&rule.id) {
                    if SystemTime::now() < suppressed_until {
                        return true;
                    }
                }
            }
        }
        false
    }
    
    /// Check if alert matches suppression rule
    fn alert_matches_suppression_rule(&self, _alert: &Alert, _rule: &crate::validation::SuppressionRule) -> bool {
        // Simplified rule matching - in production would parse rule conditions
        false
    }
    
    /// Send alert to specific destination
    async fn send_to_destination(&self, alert: &Alert, destination: &AlertDestination) -> Result<(), ValidationError> {
        match destination {
            AlertDestination::Email(email) => {
                info!("Sending email alert to {}: {}", email, alert.message);
                // In real implementation, would send actual email
            }
            AlertDestination::Slack(webhook_url) => {
                info!("Sending Slack alert to {}: {}", webhook_url, alert.message);
                // In real implementation, would send to Slack webhook
            }
            AlertDestination::Webhook(url) => {
                info!("Sending webhook alert to {}: {}", url, alert.message);
                // In real implementation, would send HTTP POST
            }
            AlertDestination::PagerDuty(key) => {
                info!("Sending PagerDuty alert with key {}: {}", key, alert.message);
                // In real implementation, would send to PagerDuty API
            }
        }
        
        Ok(())
    }
}

/// Alert types
#[derive(Debug, Clone)]
enum AlertType {
    SuccessRateDrop,
    LatencyIncrease,
    ErrorRateHigh,
}

/// Alert severity levels
#[derive(Debug, Clone)]
enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Alert structure
#[derive(Debug, Clone)]
struct Alert {
    id: String,
    alert_type: AlertType,
    scenario_id: String,
    message: String,
    severity: AlertSeverity,
    timestamp: SystemTime,
    current_value: f64,
    baseline_value: f64,
}

/// Validation history storage
struct ValidationHistory {
    /// Recent validation runs
    runs: VecDeque<ValidationRun>,
    /// Maximum runs to keep
    max_runs: usize,
}

impl ValidationHistory {
    /// Create new validation history
    fn new() -> Self {
        Self {
            runs: VecDeque::new(),
            max_runs: 1000,
        }
    }
    
    /// Add a validation run
    fn add_run(&mut self, run: ValidationRun) {
        self.runs.push_back(run);
        
        // Enforce maximum runs limit
        while self.runs.len() > self.max_runs {
            self.runs.pop_front();
        }
    }
    
    /// Get recent runs
    fn get_recent_runs(&self, count: usize) -> Vec<&ValidationRun> {
        self.runs.iter().rev().take(count).collect()
    }
    
    /// Get latest run
    fn get_latest_run(&self) -> Option<&ValidationRun> {
        self.runs.back()
    }
    
    /// Get history summary
    fn get_summary(&self, period: Duration) -> ValidationHistorySummary {
        let cutoff = SystemTime::now() - period;
        let relevant_runs: Vec<_> = self.runs.iter()
            .filter(|run| run.timestamp >= cutoff)
            .collect();
        
        let total_runs = relevant_runs.len();
        let successful_runs = relevant_runs.iter().filter(|run| run.success).count();
        let success_rate = if total_runs > 0 {
            successful_runs as f64 / total_runs as f64
        } else {
            0.0
        };
        
        ValidationHistorySummary {
            period,
            total_runs,
            successful_runs,
            success_rate,
            latest_run_time: self.runs.back().map(|r| r.timestamp),
        }
    }
}

/// Validation run record
#[derive(Debug, Clone)]
pub struct ValidationRun {
    /// When the run occurred
    pub timestamp: SystemTime,
    /// Results from scenarios
    pub results: Vec<ScenarioResult>,
    /// Whether the run was successful
    pub success: bool,
}

/// Validation history summary
#[derive(Debug)]
pub struct ValidationHistorySummary {
    /// Summary period
    pub period: Duration,
    /// Total runs in period
    pub total_runs: usize,
    /// Successful runs
    pub successful_runs: usize,
    /// Success rate
    pub success_rate: f64,
    /// Latest run timestamp
    pub latest_run_time: Option<SystemTime>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::workflow::{WorkflowRegistry, InMemoryStateStore, WorkflowEngineConfig, WorkflowEngine};

    #[tokio::test]
    async fn test_baseline_calculation() {
        let policy = BaselinePolicy {
            min_runs: 5,
            confidence_interval: 0.95,
            improvement_threshold: 0.05,
        };
        
        let mut tracker = BaselineTracker::new(policy);
        
        let metrics = vec![
            ScenarioMetrics {
                connections_attempted: 100,
                connections_successful: 95,
                average_latency_ms: 50.0,
                packet_loss_rate: 0.01,
            },
            ScenarioMetrics {
                connections_attempted: 100,
                connections_successful: 97,
                average_latency_ms: 45.0,
                packet_loss_rate: 0.005,
            },
        ];
        
        let baseline = tracker.calculate_baseline(&metrics.iter().collect::<Vec<_>>()).unwrap();
        assert_eq!(baseline.success_rate, 0.96);
        assert_eq!(baseline.latency_ms, 47.5);
    }
    
    #[tokio::test]
    async fn test_validation_history() {
        let mut history = ValidationHistory::new();
        
        let run = ValidationRun {
            timestamp: SystemTime::now(),
            results: vec![],
            success: true,
        };
        
        history.add_run(run);
        assert_eq!(history.runs.len(), 1);
        
        let summary = history.get_summary(Duration::from_secs(3600));
        assert_eq!(summary.total_runs, 1);
        assert_eq!(summary.successful_runs, 1);
        assert_eq!(summary.success_rate, 1.0);
    }
}