//! Result Analysis and Statistical Methods
//!
//! This module provides comprehensive statistical analysis of validation results,
//! regression detection, and performance trend analysis.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, SystemTime},
};

use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::validation::{
    ValidationError, ScenarioResult, ScenarioMetrics, StatisticalMethod,
    AnomalyDetectionConfig, AnomalyAlgorithm, AnomalyRule, ComparisonOperator,
    ReportFormat, ValidationRun,
};

/// Result analysis engine
pub struct ResultAnalysisEngine {
    /// Historical results
    history: Arc<RwLock<ResultHistory>>,
    /// Statistical analyzer
    statistical_analyzer: StatisticalAnalyzer,
    /// Anomaly detector
    anomaly_detector: AnomalyDetector,
    /// Report generator
    report_generator: ReportGenerator,
    /// Analysis configuration
    config: AnalysisConfiguration,
}

impl ResultAnalysisEngine {
    /// Create new result analysis engine
    pub fn new(config: AnalysisConfiguration) -> Self {
        Self {
            history: Arc::new(RwLock::new(ResultHistory::new())),
            statistical_analyzer: StatisticalAnalyzer::new(config.statistical_methods.clone()),
            anomaly_detector: AnomalyDetector::new(config.anomaly_detection.clone()),
            report_generator: ReportGenerator::new(),
            config,
        }
    }
    
    /// Analyze new results
    pub async fn analyze_results(&self, results: Vec<ScenarioResult>) -> Result<AnalysisReport, ValidationError> {
        info!("Analyzing {} scenario results", results.len());
        
        // Store results in history
        {
            let mut history = self.history.write().await;
            for result in &results {
                history.add_result(result.clone());
            }
        }
        
        // Perform statistical analysis
        let statistical_summary = self.statistical_analyzer.analyze(&results).await?;
        
        // Check for anomalies
        let anomalies = {
            let history = self.history.read().await;
            self.anomaly_detector.detect_anomalies(&results, &history).await?
        };
        
        // Detect regressions
        let regressions = {
            let history = self.history.read().await;
            self.detect_regressions(&results, &history).await?
        };
        
        // Generate analysis report
        let report = AnalysisReport {
            analysis_time: SystemTime::now(),
            results_analyzed: results.len(),
            statistical_summary,
            anomalies,
            regressions,
            overall_health: self.calculate_overall_health(&results).await,
            recommendations: self.generate_recommendations(&results, &anomalies, &regressions).await,
        };
        
        info!("Analysis completed: {} anomalies, {} regressions detected", 
            report.anomalies.len(), report.regressions.len());
        
        Ok(report)
    }
    
    /// Detect performance regressions
    async fn detect_regressions(
        &self,
        current_results: &[ScenarioResult],
        history: &ResultHistory,
    ) -> Result<Vec<Regression>, ValidationError> {
        let mut regressions = Vec::new();
        
        for result in current_results {
            if let Some(baseline) = history.get_baseline(&result.scenario_id) {
                let regression = self.check_for_regression(result, &baseline).await;
                if let Some(reg) = regression {
                    regressions.push(reg);
                }
            }
        }
        
        Ok(regressions)
    }
    
    /// Check for regression in a single result
    async fn check_for_regression(
        &self,
        result: &ScenarioResult,
        baseline: &BaselineMetrics,
    ) -> Option<Regression> {
        let current_success_rate = if result.metrics.connections_attempted > 0 {
            result.metrics.connections_successful as f64 / result.metrics.connections_attempted as f64
        } else {
            0.0
        };
        
        // Check success rate regression
        if current_success_rate < baseline.success_rate - self.config.regression_thresholds.success_rate_drop {
            return Some(Regression {
                scenario_id: result.scenario_id.clone(),
                regression_type: RegressionType::SuccessRate,
                severity: self.calculate_severity(
                    baseline.success_rate - current_success_rate,
                    self.config.regression_thresholds.success_rate_drop,
                ),
                current_value: current_success_rate,
                baseline_value: baseline.success_rate,
                confidence: self.calculate_confidence(&baseline, result).await,
                description: format!(
                    "Success rate dropped from {:.2}% to {:.2}%",
                    baseline.success_rate * 100.0,
                    current_success_rate * 100.0
                ),
            });
        }
        
        // Check latency regression
        let latency_increase = result.metrics.average_latency_ms - baseline.average_latency_ms;
        let latency_threshold = baseline.average_latency_ms * self.config.regression_thresholds.latency_increase_percent;
        
        if latency_increase > latency_threshold {
            return Some(Regression {
                scenario_id: result.scenario_id.clone(),
                regression_type: RegressionType::Latency,
                severity: self.calculate_severity(
                    latency_increase / baseline.average_latency_ms,
                    self.config.regression_thresholds.latency_increase_percent,
                ),
                current_value: result.metrics.average_latency_ms,
                baseline_value: baseline.average_latency_ms,
                confidence: self.calculate_confidence(&baseline, result).await,
                description: format!(
                    "Latency increased from {:.1}ms to {:.1}ms",
                    baseline.average_latency_ms,
                    result.metrics.average_latency_ms
                ),
            });
        }
        
        None
    }
    
    /// Calculate regression severity
    fn calculate_severity(&self, actual_change: f64, threshold: f64) -> RegressionSeverity {
        let severity_ratio = actual_change / threshold;
        
        if severity_ratio >= 3.0 {
            RegressionSeverity::Critical
        } else if severity_ratio >= 2.0 {
            RegressionSeverity::High
        } else if severity_ratio >= 1.5 {
            RegressionSeverity::Medium
        } else {
            RegressionSeverity::Low
        }
    }
    
    /// Calculate confidence in regression detection
    async fn calculate_confidence(&self, baseline: &BaselineMetrics, result: &ScenarioResult) -> f64 {
        // Simple confidence calculation based on sample sizes and variance
        let baseline_samples = baseline.sample_count as f64;
        let current_samples = result.metrics.connections_attempted as f64;
        
        // More samples = higher confidence
        let sample_confidence = (baseline_samples + current_samples) / (baseline_samples + current_samples + 10.0);
        
        // Higher variance = lower confidence
        let variance_confidence = 1.0 / (1.0 + baseline.variance);
        
        (sample_confidence * variance_confidence).min(1.0)
    }
    
    /// Calculate overall system health
    async fn calculate_overall_health(&self, results: &[ScenarioResult]) -> OverallHealth {
        if results.is_empty() {
            return OverallHealth {
                score: 0.0,
                status: HealthStatus::Unknown,
                details: "No results to analyze".to_string(),
            };
        }
        
        let success_count = results.iter().filter(|r| r.success).count();
        let success_rate = success_count as f64 / results.len() as f64;
        
        let avg_latency = results.iter()
            .map(|r| r.metrics.average_latency_ms)
            .sum::<f64>() / results.len() as f64;
        
        let avg_packet_loss = results.iter()
            .map(|r| r.metrics.packet_loss_rate as f64)
            .sum::<f64>() / results.len() as f64;
        
        // Calculate health score (0-100)
        let success_score = success_rate * 40.0; // 40% weight
        let latency_score = ((1000.0 - avg_latency.min(1000.0)) / 1000.0) * 30.0; // 30% weight
        let packet_loss_score = (1.0 - avg_packet_loss.min(1.0)) * 30.0; // 30% weight
        
        let total_score = success_score + latency_score + packet_loss_score;
        
        let status = if total_score >= 90.0 {
            HealthStatus::Excellent
        } else if total_score >= 75.0 {
            HealthStatus::Good
        } else if total_score >= 60.0 {
            HealthStatus::Fair
        } else if total_score >= 40.0 {
            HealthStatus::Poor
        } else {
            HealthStatus::Critical
        };
        
        OverallHealth {
            score: total_score,
            status,
            details: format!(
                "Success: {:.1}%, Latency: {:.1}ms, Packet Loss: {:.2}%",
                success_rate * 100.0,
                avg_latency,
                avg_packet_loss * 100.0
            ),
        }
    }
    
    /// Generate recommendations based on analysis
    async fn generate_recommendations(
        &self,
        results: &[ScenarioResult],
        anomalies: &[Anomaly],
        regressions: &[Regression],
    ) -> Vec<Recommendation> {
        let mut recommendations = Vec::new();
        
        // Recommendations based on regressions
        for regression in regressions {
            match regression.regression_type {
                RegressionType::SuccessRate => {
                    recommendations.push(Recommendation {
                        priority: recommendation_priority_from_severity(&regression.severity),
                        category: RecommendationCategory::Performance,
                        title: "Address Success Rate Regression".to_string(),
                        description: format!(
                            "Success rate for {} has dropped significantly. Consider reviewing NAT traversal logic and network conditions.",
                            regression.scenario_id
                        ),
                        actions: vec![
                            "Review recent code changes".to_string(),
                            "Check network infrastructure".to_string(),
                            "Analyze failed connection patterns".to_string(),
                        ],
                    });
                }
                RegressionType::Latency => {
                    recommendations.push(Recommendation {
                        priority: recommendation_priority_from_severity(&regression.severity),
                        category: RecommendationCategory::Performance,
                        title: "Investigate Latency Increase".to_string(),
                        description: format!(
                            "Latency for {} has increased beyond acceptable thresholds.",
                            regression.scenario_id
                        ),
                        actions: vec![
                            "Profile application performance".to_string(),
                            "Check network routing".to_string(),
                            "Review timeout configurations".to_string(),
                        ],
                    });
                }
            }
        }
        
        // Recommendations based on anomalies
        for anomaly in anomalies {
            recommendations.push(Recommendation {
                priority: RecommendationPriority::Medium,
                category: RecommendationCategory::Monitoring,
                title: "Investigate Anomaly".to_string(),
                description: format!("Anomaly detected: {}", anomaly.description),
                actions: vec![
                    "Review metrics around anomaly timeframe".to_string(),
                    "Check for external factors".to_string(),
                ],
            });
        }
        
        // General recommendations based on overall results
        let failed_results = results.iter().filter(|r| !r.success).count();
        if failed_results > 0 {
            recommendations.push(Recommendation {
                priority: RecommendationPriority::High,
                category: RecommendationCategory::Reliability,
                title: "Address Test Failures".to_string(),
                description: format!("{} out of {} tests failed", failed_results, results.len()),
                actions: vec![
                    "Review error logs for failed tests".to_string(),
                    "Check test environment stability".to_string(),
                    "Consider adjusting test parameters".to_string(),
                ],
            });
        }
        
        recommendations
    }
    
    /// Generate detailed analysis report
    pub async fn generate_report(&self, format: ReportFormat, period: Duration) -> Result<AnalysisReportDocument, ValidationError> {
        let history = self.history.read().await;
        let recent_results = history.get_results_since(SystemTime::now() - period);
        
        if recent_results.is_empty() {
            return Err(ValidationError::AnalysisError("No results found for specified period".to_string()));
        }
        
        let analysis = self.analyze_results(recent_results).await?;
        let trends = self.calculate_trends(&history, period).await?;
        
        let document = self.report_generator.generate_document(analysis, trends, format).await?;
        
        Ok(document)
    }
    
    /// Calculate performance trends
    async fn calculate_trends(&self, history: &ResultHistory, period: Duration) -> Result<TrendAnalysis, ValidationError> {
        let cutoff = SystemTime::now() - period;
        let time_series = history.get_time_series_since(cutoff);
        
        let mut scenario_trends = HashMap::new();
        
        for (scenario_id, points) in time_series {
            if points.len() < 2 {
                continue; // Need at least 2 points for trend
            }
            
            let trend = self.calculate_scenario_trend(&points).await;
            scenario_trends.insert(scenario_id, trend);
        }
        
        Ok(TrendAnalysis {
            period,
            scenario_trends,
            overall_trend: self.calculate_overall_trend(&scenario_trends).await,
        })
    }
    
    /// Calculate trend for a specific scenario
    async fn calculate_scenario_trend(&self, points: &[(SystemTime, ScenarioMetrics)]) -> ScenarioTrend {
        // Simple linear regression for success rate
        let success_rates: Vec<f64> = points.iter()
            .map(|(_, metrics)| {
                if metrics.connections_attempted > 0 {
                    metrics.connections_successful as f64 / metrics.connections_attempted as f64
                } else {
                    0.0
                }
            })
            .collect();
        
        let success_rate_trend = self.calculate_linear_trend(&success_rates);
        
        // Simple trend for latency
        let latencies: Vec<f64> = points.iter().map(|(_, m)| m.average_latency_ms).collect();
        let latency_trend = self.calculate_linear_trend(&latencies);
        
        ScenarioTrend {
            success_rate_trend,
            latency_trend,
            sample_count: points.len(),
            direction: if success_rate_trend > 0.01 {
                TrendDirection::Improving
            } else if success_rate_trend < -0.01 {
                TrendDirection::Degrading
            } else {
                TrendDirection::Stable
            },
        }
    }
    
    /// Calculate linear trend (slope)
    fn calculate_linear_trend(&self, values: &[f64]) -> f64 {
        if values.len() < 2 {
            return 0.0;
        }
        
        let n = values.len() as f64;
        let x_sum: f64 = (0..values.len()).map(|i| i as f64).sum();
        let y_sum: f64 = values.iter().sum();
        let xy_sum: f64 = values.iter().enumerate()
            .map(|(i, &y)| i as f64 * y)
            .sum();
        let x_squared_sum: f64 = (0..values.len()).map(|i| (i as f64).powi(2)).sum();
        
        let denominator = n * x_squared_sum - x_sum.powi(2);
        if denominator.abs() < f64::EPSILON {
            return 0.0;
        }
        
        (n * xy_sum - x_sum * y_sum) / denominator
    }
    
    /// Calculate overall trend across all scenarios
    async fn calculate_overall_trend(&self, scenario_trends: &HashMap<String, ScenarioTrend>) -> OverallTrend {
        if scenario_trends.is_empty() {
            return OverallTrend {
                direction: TrendDirection::Stable,
                confidence: 0.0,
                summary: "No trend data available".to_string(),
            };
        }
        
        let improving_count = scenario_trends.values()
            .filter(|t| matches!(t.direction, TrendDirection::Improving))
            .count();
        
        let degrading_count = scenario_trends.values()
            .filter(|t| matches!(t.direction, TrendDirection::Degrading))
            .count();
        
        let total_count = scenario_trends.len();
        
        let direction = if improving_count > degrading_count {
            TrendDirection::Improving
        } else if degrading_count > improving_count {
            TrendDirection::Degrading
        } else {
            TrendDirection::Stable
        };
        
        let confidence = (improving_count.max(degrading_count) as f64) / (total_count as f64);
        
        OverallTrend {
            direction,
            confidence,
            summary: format!(
                "{} scenarios improving, {} degrading, {} stable",
                improving_count,
                degrading_count,
                total_count - improving_count - degrading_count
            ),
        }
    }
}

/// Analysis configuration
#[derive(Debug, Clone)]
pub struct AnalysisConfiguration {
    /// Statistical methods to use
    pub statistical_methods: Vec<StatisticalMethod>,
    /// Anomaly detection configuration
    pub anomaly_detection: AnomalyDetectionConfig,
    /// Regression detection thresholds
    pub regression_thresholds: RegressionThresholds,
}

/// Regression detection thresholds
#[derive(Debug, Clone)]
pub struct RegressionThresholds {
    /// Success rate drop threshold
    pub success_rate_drop: f64,
    /// Latency increase percentage threshold
    pub latency_increase_percent: f64,
    /// Packet loss increase threshold
    pub packet_loss_increase: f64,
}

/// Statistical analyzer
struct StatisticalAnalyzer {
    methods: Vec<StatisticalMethod>,
}

impl StatisticalAnalyzer {
    fn new(methods: Vec<StatisticalMethod>) -> Self {
        Self { methods }
    }
    
    async fn analyze(&self, results: &[ScenarioResult]) -> Result<StatisticalSummary, ValidationError> {
        let mut summary = StatisticalSummary {
            scenario_summaries: HashMap::new(),
            cross_scenario_analysis: CrossScenarioAnalysis::default(),
        };
        
        // Group results by scenario
        let mut scenario_groups: HashMap<String, Vec<&ScenarioResult>> = HashMap::new();
        for result in results {
            scenario_groups.entry(result.scenario_id.clone())
                .or_insert_with(Vec::new)
                .push(result);
        }
        
        // Analyze each scenario
        for (scenario_id, scenario_results) in scenario_groups {
            let scenario_summary = self.analyze_scenario(&scenario_results).await?;
            summary.scenario_summaries.insert(scenario_id, scenario_summary);
        }
        
        // Cross-scenario analysis
        summary.cross_scenario_analysis = self.analyze_cross_scenario(results).await?;
        
        Ok(summary)
    }
    
    async fn analyze_scenario(&self, results: &[&ScenarioResult]) -> Result<ScenarioSummary, ValidationError> {
        let success_rates: Vec<f64> = results.iter()
            .map(|r| {
                if r.metrics.connections_attempted > 0 {
                    r.metrics.connections_successful as f64 / r.metrics.connections_attempted as f64
                } else {
                    0.0
                }
            })
            .collect();
        
        let latencies: Vec<f64> = results.iter().map(|r| r.metrics.average_latency_ms).collect();
        
        Ok(ScenarioSummary {
            sample_count: results.len(),
            success_rate_stats: self.calculate_descriptive_stats(&success_rates),
            latency_stats: self.calculate_descriptive_stats(&latencies),
            correlation_analysis: self.calculate_correlations(&success_rates, &latencies).await,
        })
    }
    
    fn calculate_descriptive_stats(&self, values: &[f64]) -> DescriptiveStats {
        if values.is_empty() {
            return DescriptiveStats::default();
        }
        
        let mut sorted_values = values.to_vec();
        sorted_values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        let min = sorted_values[0];
        let max = sorted_values[sorted_values.len() - 1];
        
        let median = if sorted_values.len() % 2 == 0 {
            (sorted_values[sorted_values.len() / 2 - 1] + sorted_values[sorted_values.len() / 2]) / 2.0
        } else {
            sorted_values[sorted_values.len() / 2]
        };
        
        let variance = values.iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f64>() / values.len() as f64;
        
        let std_dev = variance.sqrt();
        
        DescriptiveStats {
            mean,
            median,
            min,
            max,
            std_dev,
            variance,
        }
    }
    
    async fn calculate_correlations(&self, x: &[f64], y: &[f64]) -> CorrelationAnalysis {
        if x.len() != y.len() || x.len() < 2 {
            return CorrelationAnalysis::default();
        }
        
        let n = x.len() as f64;
        let x_mean = x.iter().sum::<f64>() / n;
        let y_mean = y.iter().sum::<f64>() / n;
        
        let numerator: f64 = x.iter().zip(y.iter())
            .map(|(xi, yi)| (xi - x_mean) * (yi - y_mean))
            .sum();
        
        let x_variance: f64 = x.iter().map(|xi| (xi - x_mean).powi(2)).sum();
        let y_variance: f64 = y.iter().map(|yi| (yi - y_mean).powi(2)).sum();
        
        let denominator = (x_variance * y_variance).sqrt();
        
        let correlation = if denominator > f64::EPSILON {
            numerator / denominator
        } else {
            0.0
        };
        
        CorrelationAnalysis {
            pearson_correlation: correlation,
            correlation_strength: if correlation.abs() > 0.7 {
                "Strong".to_string()
            } else if correlation.abs() > 0.3 {
                "Moderate".to_string()
            } else {
                "Weak".to_string()
            },
        }
    }
    
    async fn analyze_cross_scenario(&self, results: &[ScenarioResult]) -> Result<CrossScenarioAnalysis, ValidationError> {
        // Group by time windows to analyze temporal patterns
        let mut time_windows = HashMap::new();
        
        for result in results {
            // Group into 5-minute windows (simplified)
            let window = (result.duration.as_secs() / 300) * 300;
            time_windows.entry(window)
                .or_insert_with(Vec::new)
                .push(result);
        }
        
        Ok(CrossScenarioAnalysis {
            temporal_patterns: self.analyze_temporal_patterns(&time_windows).await,
            scenario_interactions: self.analyze_scenario_interactions(results).await,
        })
    }
    
    async fn analyze_temporal_patterns(&self, _time_windows: &HashMap<u64, Vec<&ScenarioResult>>) -> String {
        // Simplified temporal pattern analysis
        "No significant temporal patterns detected".to_string()
    }
    
    async fn analyze_scenario_interactions(&self, _results: &[ScenarioResult]) -> String {
        // Simplified interaction analysis
        "No significant cross-scenario interactions detected".to_string()
    }
}

/// Anomaly detector
struct AnomalyDetector {
    config: AnomalyDetectionConfig,
}

impl AnomalyDetector {
    fn new(config: AnomalyDetectionConfig) -> Self {
        Self { config }
    }
    
    async fn detect_anomalies(
        &self,
        results: &[ScenarioResult],
        history: &ResultHistory,
    ) -> Result<Vec<Anomaly>, ValidationError> {
        let mut anomalies = Vec::new();
        
        for algorithm in &self.config.algorithms {
            let detected = self.apply_algorithm(algorithm, results, history).await?;
            anomalies.extend(detected);
        }
        
        Ok(anomalies)
    }
    
    async fn apply_algorithm(
        &self,
        algorithm: &AnomalyAlgorithm,
        results: &[ScenarioResult],
        history: &ResultHistory,
    ) -> Result<Vec<Anomaly>, ValidationError> {
        match algorithm {
            AnomalyAlgorithm::StatisticalProcessControl => {
                self.statistical_process_control(results, history).await
            }
            AnomalyAlgorithm::RuleBased(rules) => {
                self.rule_based_detection(rules, results).await
            }
            AnomalyAlgorithm::MachineLearning(_model) => {
                // Placeholder for ML-based detection
                Ok(vec![])
            }
        }
    }
    
    async fn statistical_process_control(
        &self,
        results: &[ScenarioResult],
        history: &ResultHistory,
    ) -> Result<Vec<Anomaly>, ValidationError> {
        let mut anomalies = Vec::new();
        
        for result in results {
            if let Some(baseline) = history.get_baseline(&result.scenario_id) {
                let current_success_rate = if result.metrics.connections_attempted > 0 {
                    result.metrics.connections_successful as f64 / result.metrics.connections_attempted as f64
                } else {
                    0.0
                };
                
                // Check if value is outside control limits (3 sigma)
                let control_limit = 3.0 * baseline.std_dev;
                if (current_success_rate - baseline.success_rate).abs() > control_limit {
                    anomalies.push(Anomaly {
                        scenario_id: result.scenario_id.clone(),
                        anomaly_type: AnomalyType::StatisticalOutlier,
                        severity: AnomalySeverity::Medium,
                        description: format!(
                            "Success rate {:.2}% is outside 3-sigma control limits for scenario {}",
                            current_success_rate * 100.0,
                            result.scenario_id
                        ),
                        detected_at: SystemTime::now(),
                        confidence: 0.95,
                    });
                }
            }
        }
        
        Ok(anomalies)
    }
    
    async fn rule_based_detection(
        &self,
        rules: &[AnomalyRule],
        results: &[ScenarioResult],
    ) -> Result<Vec<Anomaly>, ValidationError> {
        let mut anomalies = Vec::new();
        
        for result in results {
            for rule in rules {
                if self.evaluate_rule(rule, result).await {
                    anomalies.push(Anomaly {
                        scenario_id: result.scenario_id.clone(),
                        anomaly_type: AnomalyType::RuleViolation,
                        severity: AnomalySeverity::Low,
                        description: format!("Rule '{}' violated for scenario {}", rule.name, result.scenario_id),
                        detected_at: SystemTime::now(),
                        confidence: 0.8,
                    });
                }
            }
        }
        
        Ok(anomalies)
    }
    
    async fn evaluate_rule(&self, rule: &AnomalyRule, result: &ScenarioResult) -> bool {
        let metric_value = match rule.metric.as_str() {
            "success_rate" => {
                if result.metrics.connections_attempted > 0 {
                    result.metrics.connections_successful as f64 / result.metrics.connections_attempted as f64
                } else {
                    0.0
                }
            }
            "latency" => result.metrics.average_latency_ms,
            "packet_loss" => result.metrics.packet_loss_rate as f64,
            _ => return false,
        };
        
        match rule.operator {
            ComparisonOperator::GreaterThan => metric_value > rule.threshold,
            ComparisonOperator::LessThan => metric_value < rule.threshold,
            ComparisonOperator::Equal => (metric_value - rule.threshold).abs() < f64::EPSILON,
            ComparisonOperator::NotEqual => (metric_value - rule.threshold).abs() > f64::EPSILON,
        }
    }
}

/// Report generator
struct ReportGenerator;

impl ReportGenerator {
    fn new() -> Self {
        Self
    }
    
    async fn generate_document(
        &self,
        analysis: AnalysisReport,
        trends: TrendAnalysis,
        format: ReportFormat,
    ) -> Result<AnalysisReportDocument, ValidationError> {
        let content = match format {
            ReportFormat::Html => self.generate_html_report(&analysis, &trends).await?,
            ReportFormat::Markdown => self.generate_markdown_report(&analysis, &trends).await?,
            ReportFormat::Json => self.generate_json_report(&analysis, &trends).await?,
            ReportFormat::Pdf => {
                // For PDF, generate HTML first then convert (simplified)
                self.generate_html_report(&analysis, &trends).await?
            }
        };
        
        Ok(AnalysisReportDocument {
            format,
            content: content.into_bytes(),
            generated_at: SystemTime::now(),
            title: "Validation Analysis Report".to_string(),
            summary: analysis.overall_health.details,
        })
    }
    
    async fn generate_html_report(
        &self,
        analysis: &AnalysisReport,
        trends: &TrendAnalysis,
    ) -> Result<String, ValidationError> {
        let mut html = String::new();
        
        html.push_str("<!DOCTYPE html>\n<html><head><title>Validation Analysis Report</title></head><body>\n");
        html.push_str(&format!("<h1>Validation Analysis Report</h1>\n"));
        html.push_str(&format!("<p>Generated: {:?}</p>\n", analysis.analysis_time));
        
        // Overall health
        html.push_str(&format!("<h2>Overall Health</h2>\n"));
        html.push_str(&format!("<p>Score: {:.1}/100 ({})</p>\n", 
            analysis.overall_health.score, 
            format!("{:?}", analysis.overall_health.status)));
        html.push_str(&format!("<p>{}</p>\n", analysis.overall_health.details));
        
        // Regressions
        if !analysis.regressions.is_empty() {
            html.push_str("<h2>Regressions Detected</h2>\n<ul>\n");
            for regression in &analysis.regressions {
                html.push_str(&format!("<li>{}: {} ({:?})</li>\n", 
                    regression.scenario_id, regression.description, regression.severity));
            }
            html.push_str("</ul>\n");
        }
        
        // Recommendations
        if !analysis.recommendations.is_empty() {
            html.push_str("<h2>Recommendations</h2>\n<ul>\n");
            for rec in &analysis.recommendations {
                html.push_str(&format!("<li><strong>{}:</strong> {}</li>\n", rec.title, rec.description));
            }
            html.push_str("</ul>\n");
        }
        
        html.push_str("</body></html>");
        
        Ok(html)
    }
    
    async fn generate_markdown_report(
        &self,
        analysis: &AnalysisReport,
        _trends: &TrendAnalysis,
    ) -> Result<String, ValidationError> {
        let mut md = String::new();
        
        md.push_str("# Validation Analysis Report\n\n");
        md.push_str(&format!("Generated: {:?}\n\n", analysis.analysis_time));
        
        md.push_str("## Overall Health\n\n");
        md.push_str(&format!("**Score:** {:.1}/100 ({:?})\n\n", 
            analysis.overall_health.score, analysis.overall_health.status));
        md.push_str(&format!("{}\n\n", analysis.overall_health.details));
        
        if !analysis.regressions.is_empty() {
            md.push_str("## Regressions Detected\n\n");
            for regression in &analysis.regressions {
                md.push_str(&format!("- **{}:** {} ({:?})\n", 
                    regression.scenario_id, regression.description, regression.severity));
            }
            md.push_str("\n");
        }
        
        Ok(md)
    }
    
    async fn generate_json_report(
        &self,
        analysis: &AnalysisReport,
        trends: &TrendAnalysis,
    ) -> Result<String, ValidationError> {
        let report_data = serde_json::json!({
            "analysis": {
                "timestamp": analysis.analysis_time,
                "results_analyzed": analysis.results_analyzed,
                "overall_health": {
                    "score": analysis.overall_health.score,
                    "status": format!("{:?}", analysis.overall_health.status),
                    "details": analysis.overall_health.details
                },
                "regressions": analysis.regressions.len(),
                "anomalies": analysis.anomalies.len(),
                "recommendations": analysis.recommendations.len()
            },
            "trends": {
                "period_days": trends.period.as_secs() / 86400,
                "scenario_count": trends.scenario_trends.len(),
                "overall_direction": format!("{:?}", trends.overall_trend.direction)
            }
        });
        
        serde_json::to_string_pretty(&report_data)
            .map_err(|e| ValidationError::AnalysisError(format!("JSON serialization failed: {}", e)))
    }
}

// Helper function for mapping severity to priority
fn recommendation_priority_from_severity(severity: &RegressionSeverity) -> RecommendationPriority {
    match severity {
        RegressionSeverity::Critical => RecommendationPriority::Critical,
        RegressionSeverity::High => RecommendationPriority::High,
        RegressionSeverity::Medium => RecommendationPriority::Medium,
        RegressionSeverity::Low => RecommendationPriority::Low,
    }
}

/// Result history storage
struct ResultHistory {
    /// Results by scenario
    scenario_results: HashMap<String, VecDeque<ScenarioResult>>,
    /// Calculated baselines
    baselines: HashMap<String, BaselineMetrics>,
    /// Maximum results to keep per scenario
    max_results_per_scenario: usize,
}

impl ResultHistory {
    fn new() -> Self {
        Self {
            scenario_results: HashMap::new(),
            baselines: HashMap::new(),
            max_results_per_scenario: 1000,
        }
    }
    
    fn add_result(&mut self, result: ScenarioResult) {
        let scenario_results = self.scenario_results
            .entry(result.scenario_id.clone())
            .or_insert_with(VecDeque::new);
        
        scenario_results.push_back(result);
        
        // Enforce size limit
        while scenario_results.len() > self.max_results_per_scenario {
            scenario_results.pop_front();
        }
        
        // Update baseline if needed
        if scenario_results.len() >= 10 {
            self.update_baseline(&scenario_results.back().unwrap().scenario_id);
        }
    }
    
    fn update_baseline(&mut self, scenario_id: &str) {
        if let Some(results) = self.scenario_results.get(scenario_id) {
            let recent_results: Vec<_> = results.iter().rev().take(20).collect();
            
            if recent_results.len() >= 10 {
                let baseline = self.calculate_baseline(&recent_results);
                self.baselines.insert(scenario_id.to_string(), baseline);
            }
        }
    }
    
    fn calculate_baseline(&self, results: &[&ScenarioResult]) -> BaselineMetrics {
        let success_rates: Vec<f64> = results.iter()
            .map(|r| {
                if r.metrics.connections_attempted > 0 {
                    r.metrics.connections_successful as f64 / r.metrics.connections_attempted as f64
                } else {
                    0.0
                }
            })
            .collect();
        
        let latencies: Vec<f64> = results.iter().map(|r| r.metrics.average_latency_ms).collect();
        
        let success_rate_mean = success_rates.iter().sum::<f64>() / success_rates.len() as f64;
        let latency_mean = latencies.iter().sum::<f64>() / latencies.len() as f64;
        
        let variance = success_rates.iter()
            .map(|&rate| (rate - success_rate_mean).powi(2))
            .sum::<f64>() / success_rates.len() as f64;
        
        BaselineMetrics {
            success_rate: success_rate_mean,
            average_latency_ms: latency_mean,
            std_dev: variance.sqrt(),
            variance,
            sample_count: results.len(),
            last_updated: SystemTime::now(),
        }
    }
    
    fn get_baseline(&self, scenario_id: &str) -> Option<&BaselineMetrics> {
        self.baselines.get(scenario_id)
    }
    
    fn get_results_since(&self, cutoff: SystemTime) -> Vec<ScenarioResult> {
        let mut results = Vec::new();
        
        for scenario_results in self.scenario_results.values() {
            for result in scenario_results {
                // Simplified time comparison - in real implementation would use proper timestamps
                results.push(result.clone());
            }
        }
        
        results
    }
    
    fn get_time_series_since(&self, cutoff: SystemTime) -> HashMap<String, Vec<(SystemTime, ScenarioMetrics)>> {
        let mut time_series = HashMap::new();
        
        for (scenario_id, results) in &self.scenario_results {
            let mut points = Vec::new();
            for result in results {
                // Simplified - in real implementation would have proper timestamps
                points.push((SystemTime::now(), result.metrics.clone()));
            }
            time_series.insert(scenario_id.clone(), points);
        }
        
        time_series
    }
}

// Data structures for analysis results

/// Analysis report
#[derive(Debug)]
pub struct AnalysisReport {
    pub analysis_time: SystemTime,
    pub results_analyzed: usize,
    pub statistical_summary: StatisticalSummary,
    pub anomalies: Vec<Anomaly>,
    pub regressions: Vec<Regression>,
    pub overall_health: OverallHealth,
    pub recommendations: Vec<Recommendation>,
}

/// Statistical summary
#[derive(Debug)]
struct StatisticalSummary {
    scenario_summaries: HashMap<String, ScenarioSummary>,
    cross_scenario_analysis: CrossScenarioAnalysis,
}

/// Scenario-specific statistical summary
#[derive(Debug)]
struct ScenarioSummary {
    sample_count: usize,
    success_rate_stats: DescriptiveStats,
    latency_stats: DescriptiveStats,
    correlation_analysis: CorrelationAnalysis,
}

/// Descriptive statistics
#[derive(Debug, Default)]
struct DescriptiveStats {
    mean: f64,
    median: f64,
    min: f64,
    max: f64,
    std_dev: f64,
    variance: f64,
}

/// Correlation analysis
#[derive(Debug, Default)]
struct CorrelationAnalysis {
    pearson_correlation: f64,
    correlation_strength: String,
}

/// Cross-scenario analysis
#[derive(Debug, Default)]
struct CrossScenarioAnalysis {
    temporal_patterns: String,
    scenario_interactions: String,
}

/// Detected anomaly
#[derive(Debug)]
pub struct Anomaly {
    pub scenario_id: String,
    pub anomaly_type: AnomalyType,
    pub severity: AnomalySeverity,
    pub description: String,
    pub detected_at: SystemTime,
    pub confidence: f64,
}

/// Types of anomalies
#[derive(Debug)]
pub enum AnomalyType {
    StatisticalOutlier,
    RuleViolation,
    PerformanceSpike,
    PatternDeviation,
}

/// Anomaly severity levels
#[derive(Debug)]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Detected regression
#[derive(Debug)]
pub struct Regression {
    pub scenario_id: String,
    pub regression_type: RegressionType,
    pub severity: RegressionSeverity,
    pub current_value: f64,
    pub baseline_value: f64,
    pub confidence: f64,
    pub description: String,
}

/// Types of regressions
#[derive(Debug)]
pub enum RegressionType {
    SuccessRate,
    Latency,
    PacketLoss,
}

/// Regression severity levels
#[derive(Debug)]
pub enum RegressionSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Overall system health
#[derive(Debug)]
pub struct OverallHealth {
    pub score: f64,
    pub status: HealthStatus,
    pub details: String,
}

/// Health status levels
#[derive(Debug)]
pub enum HealthStatus {
    Excellent,
    Good,
    Fair,
    Poor,
    Critical,
    Unknown,
}

/// Recommendation
#[derive(Debug)]
pub struct Recommendation {
    pub priority: RecommendationPriority,
    pub category: RecommendationCategory,
    pub title: String,
    pub description: String,
    pub actions: Vec<String>,
}

/// Recommendation priority levels
#[derive(Debug)]
pub enum RecommendationPriority {
    Low,
    Medium,
    High,
    Critical,
}

/// Recommendation categories
#[derive(Debug)]
pub enum RecommendationCategory {
    Performance,
    Reliability,
    Security,
    Monitoring,
    Configuration,
}

/// Baseline metrics
#[derive(Debug)]
struct BaselineMetrics {
    success_rate: f64,
    average_latency_ms: f64,
    std_dev: f64,
    variance: f64,
    sample_count: usize,
    last_updated: SystemTime,
}

/// Trend analysis
#[derive(Debug)]
struct TrendAnalysis {
    period: Duration,
    scenario_trends: HashMap<String, ScenarioTrend>,
    overall_trend: OverallTrend,
}

/// Scenario-specific trend
#[derive(Debug)]
struct ScenarioTrend {
    success_rate_trend: f64,
    latency_trend: f64,
    sample_count: usize,
    direction: TrendDirection,
}

/// Overall trend across scenarios
#[derive(Debug)]
struct OverallTrend {
    direction: TrendDirection,
    confidence: f64,
    summary: String,
}

/// Trend direction
#[derive(Debug)]
enum TrendDirection {
    Improving,
    Stable,
    Degrading,
}

/// Analysis report document
#[derive(Debug)]
pub struct AnalysisReportDocument {
    pub format: ReportFormat,
    pub content: Vec<u8>,
    pub generated_at: SystemTime,
    pub title: String,
    pub summary: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_result_analysis() {
        let config = AnalysisConfiguration {
            statistical_methods: vec![StatisticalMethod::TTest],
            anomaly_detection: AnomalyDetectionConfig {
                algorithms: vec![AnomalyAlgorithm::StatisticalProcessControl],
                sensitivity: 0.8,
                training_period: Duration::from_secs(3600),
            },
            regression_thresholds: RegressionThresholds {
                success_rate_drop: 0.05,
                latency_increase_percent: 0.2,
                packet_loss_increase: 0.02,
            },
        };
        
        let engine = ResultAnalysisEngine::new(config);
        
        let results = vec![
            ScenarioResult {
                scenario_id: "test_scenario".to_string(),
                success: true,
                duration: Duration::from_secs(30),
                metrics: ScenarioMetrics {
                    connections_attempted: 100,
                    connections_successful: 95,
                    average_latency_ms: 50.0,
                    packet_loss_rate: 0.01,
                },
                errors: vec![],
            },
        ];
        
        let report = engine.analyze_results(results).await.unwrap();
        assert_eq!(report.results_analyzed, 1);
        assert!(report.overall_health.score > 0.0);
    }
}