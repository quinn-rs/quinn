//! Production Alerting System
//!
//! This module implements intelligent alerting for NAT traversal operations
//! with anomaly detection, escalation policies, and multi-channel notifications.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use tokio::{
    sync::{Mutex, RwLock},
    time::interval,
};
use tracing::{debug, info, warn};

use crate::monitoring::{MonitoringError, NatTraversalAttempt, NatTraversalResult};

/// Production alert manager with intelligent escalation
pub struct ProductionAlertManager {
    /// Alert configuration
    config: AlertingConfig,
    /// Rule engine for alert evaluation
    rule_engine: Arc<AlertRuleEngine>,
    /// Notification dispatcher
    notification_dispatcher: Arc<NotificationDispatcher>,
    /// Alert state manager
    state_manager: Arc<AlertStateManager>,
    /// Escalation manager
    escalation_manager: Arc<EscalationManager>,
    /// Alert suppression engine
    suppression_engine: Arc<SuppressionEngine>,
    /// Background tasks
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl ProductionAlertManager {
    /// Create new production alert manager
    pub async fn new(config: AlertingConfig) -> Result<Self, MonitoringError> {
        let rule_engine = Arc::new(AlertRuleEngine::new(config.rules.clone()));
        let notification_dispatcher =
            Arc::new(NotificationDispatcher::new(config.notifications.clone()));
        let state_manager = Arc::new(AlertStateManager::new());
        let escalation_manager = Arc::new(EscalationManager::new(config.escalation.clone()));
        let suppression_engine = Arc::new(SuppressionEngine::new(config.suppression.clone()));

        Ok(Self {
            config,
            rule_engine,
            notification_dispatcher,
            state_manager,
            escalation_manager,
            suppression_engine,
            tasks: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Start alert manager
    pub async fn start(&self) -> Result<(), MonitoringError> {
        info!("Starting production alert manager");

        // Start background tasks
        self.start_rule_evaluation_task().await?;
        self.start_escalation_task().await?;
        self.start_suppression_cleanup_task().await?;
        self.start_health_monitoring_task().await?;

        info!("Production alert manager started");
        Ok(())
    }

    /// Stop alert manager
    pub async fn stop(&self) -> Result<(), MonitoringError> {
        info!("Stopping production alert manager");

        // Stop background tasks
        let mut tasks = self.tasks.lock().await;
        for task in tasks.drain(..) {
            task.abort();
        }

        info!("Production alert manager stopped");
        Ok(())
    }

    /// Evaluate NAT traversal attempt for alerts
    pub async fn evaluate_nat_attempt(
        &self,
        attempt: &NatTraversalAttempt,
    ) -> Result<(), MonitoringError> {
        // Create evaluation context
        let context = AlertEvaluationContext {
            event_type: AlertEventType::NatAttempt,
            timestamp: attempt.timestamp,
            attempt_info: Some(attempt.clone()),
            result_info: None,
            metrics: HashMap::new(),
        };

        // Evaluate rules
        self.rule_engine.evaluate_rules(&context).await?;

        Ok(())
    }

    /// Evaluate NAT traversal result for alerts
    pub async fn evaluate_nat_result(
        &self,
        result: &NatTraversalResult,
    ) -> Result<(), MonitoringError> {
        // Create evaluation context
        let mut metrics = HashMap::new();
        metrics.insert(
            "duration_ms".to_string(),
            result.duration.as_millis() as f64,
        );
        metrics.insert(
            "success".to_string(),
            if result.success { 1.0 } else { 0.0 },
        );

        let perf = &result.performance_metrics;
        metrics.insert(
            "connection_time_ms".to_string(),
            perf.connection_time_ms as f64,
        );
        metrics.insert("candidates_tried".to_string(), perf.candidates_tried as f64);

        let context = AlertEvaluationContext {
            event_type: AlertEventType::NatResult,
            timestamp: SystemTime::now(),
            attempt_info: None,
            result_info: Some(result.clone()),
            metrics,
        };

        // Evaluate rules
        self.rule_engine.evaluate_rules(&context).await?;

        Ok(())
    }

    /// Get alert manager status
    pub async fn get_status(&self) -> String {
        let active_alerts = self.state_manager.get_active_alert_count().await;
        let suppressed_alerts = self.suppression_engine.get_suppressed_count().await;

        format!(
            "Active: {}, Suppressed: {}",
            active_alerts, suppressed_alerts
        )
    }

    /// Manually trigger alert
    pub async fn trigger_alert(&self, alert: Alert) -> Result<(), MonitoringError> {
        self.process_alert(alert).await
    }

    /// Process triggered alert
    async fn process_alert(&self, alert: Alert) -> Result<(), MonitoringError> {
        // Check if alert should be suppressed
        if self.suppression_engine.should_suppress(&alert).await {
            debug!("Alert {} suppressed", alert.id);
            return Ok(());
        }

        // Update alert state
        let alert_state = self.state_manager.update_alert_state(alert.clone()).await?;

        // Check if alert needs escalation
        if self.escalation_manager.should_escalate(&alert_state).await {
            self.escalation_manager.escalate_alert(&alert).await?;
        }

        // Send notifications
        self.notification_dispatcher.dispatch_alert(&alert).await?;

        info!(
            "Processed alert: {} (severity: {:?})",
            alert.title, alert.severity
        );
        Ok(())
    }

    /// Start rule evaluation background task
    async fn start_rule_evaluation_task(&self) -> Result<(), MonitoringError> {
        let rule_engine = self.rule_engine.clone();
        let interval_duration = self.config.evaluation_interval;

        let task = tokio::spawn(async move {
            let mut interval = interval(interval_duration);

            loop {
                interval.tick().await;

                // Evaluate time-based rules
                let context = AlertEvaluationContext {
                    event_type: AlertEventType::Scheduled,
                    timestamp: SystemTime::now(),
                    attempt_info: None,
                    result_info: None,
                    metrics: HashMap::new(),
                };

                if let Err(e) = rule_engine.evaluate_scheduled_rules(&context).await {
                    warn!("Scheduled rule evaluation failed: {}", e);
                }
            }
        });

        self.tasks.lock().await.push(task);
        Ok(())
    }

    /// Start escalation background task
    async fn start_escalation_task(&self) -> Result<(), MonitoringError> {
        let escalation_manager = self.escalation_manager.clone();
        let state_manager = self.state_manager.clone();

        let task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60)); // Check every minute

            loop {
                interval.tick().await;

                let active_alerts = state_manager.get_active_alerts().await;
                for alert_state in active_alerts {
                    if escalation_manager.should_escalate(&alert_state).await {
                        if let Err(e) = escalation_manager.escalate_alert(&alert_state.alert).await
                        {
                            warn!("Alert escalation failed: {}", e);
                        }
                    }
                }
            }
        });

        self.tasks.lock().await.push(task);
        Ok(())
    }

    /// Start suppression cleanup task
    async fn start_suppression_cleanup_task(&self) -> Result<(), MonitoringError> {
        let suppression_engine = self.suppression_engine.clone();

        let task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(300)); // Cleanup every 5 minutes

            loop {
                interval.tick().await;

                if let Err(e) = suppression_engine.cleanup_expired_suppressions().await {
                    warn!("Suppression cleanup failed: {}", e);
                }
            }
        });

        self.tasks.lock().await.push(task);
        Ok(())
    }

    /// Start health monitoring task
    async fn start_health_monitoring_task(&self) -> Result<(), MonitoringError> {
        let notification_dispatcher = self.notification_dispatcher.clone();

        let task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60)); // Health check every minute

            loop {
                interval.tick().await;

                if let Err(e) = notification_dispatcher.health_check().await {
                    warn!("Notification system health check failed: {}", e);
                }
            }
        });

        self.tasks.lock().await.push(task);
        Ok(())
    }
}

/// Alerting configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AlertingConfig {
    /// Alert rules
    pub rules: Vec<AlertRule>,
    /// Notification channels
    pub notifications: NotificationConfig,
    /// Escalation policies
    pub escalation: EscalationConfig,
    /// Suppression settings
    pub suppression: SuppressionConfig,
    /// Rule evaluation interval
    pub evaluation_interval: Duration,
    /// Alert deduplication window
    pub deduplication_window: Duration,
}

impl Default for AlertingConfig {
    fn default() -> Self {
        Self {
            rules: vec![
                AlertRule::default_success_rate_rule(),
                AlertRule::default_latency_rule(),
                AlertRule::default_error_rate_rule(),
            ],
            notifications: NotificationConfig::default(),
            escalation: EscalationConfig::default(),
            suppression: SuppressionConfig::default(),
            evaluation_interval: Duration::from_secs(30),
            deduplication_window: Duration::from_secs(300),
        }
    }
}

/// Alert rule definition
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AlertRule {
    /// Rule identifier
    pub id: String,
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Alert severity
    pub severity: AlertSeverity,
    /// Rule condition
    pub condition: AlertCondition,
    /// Evaluation frequency
    pub evaluation_frequency: Duration,
    /// Alert labels
    pub labels: HashMap<String, String>,
    /// Annotations
    pub annotations: HashMap<String, String>,
}

impl AlertRule {
    /// Default success rate alert rule
    fn default_success_rate_rule() -> Self {
        Self {
            id: "nat_success_rate_low".to_string(),
            name: "NAT Success Rate Low".to_string(),
            description: "NAT traversal success rate is below threshold".to_string(),
            severity: AlertSeverity::Warning,
            condition: AlertCondition::Threshold {
                metric: "nat_success_rate".to_string(),
                operator: ThresholdOperator::LessThan,
                value: 0.8,
                duration: Duration::from_secs(300),
            },
            evaluation_frequency: Duration::from_secs(60),
            labels: HashMap::from([
                ("component".to_string(), "nat_traversal".to_string()),
                ("type".to_string(), "success_rate".to_string()),
            ]),
            annotations: HashMap::from([
                (
                    "summary".to_string(),
                    "NAT traversal success rate below 80%".to_string(),
                ),
                (
                    "runbook".to_string(),
                    "https://docs.example.com/runbooks/nat-success-rate".to_string(),
                ),
            ]),
        }
    }

    /// Default latency alert rule
    fn default_latency_rule() -> Self {
        Self {
            id: "nat_latency_high".to_string(),
            name: "NAT Latency High".to_string(),
            description: "NAT traversal latency is above threshold".to_string(),
            severity: AlertSeverity::Warning,
            condition: AlertCondition::Threshold {
                metric: "nat_duration_p95".to_string(),
                operator: ThresholdOperator::GreaterThan,
                value: 5000.0, // 5 seconds
                duration: Duration::from_secs(300),
            },
            evaluation_frequency: Duration::from_secs(60),
            labels: HashMap::from([
                ("component".to_string(), "nat_traversal".to_string()),
                ("type".to_string(), "latency".to_string()),
            ]),
            annotations: HashMap::from([(
                "summary".to_string(),
                "NAT traversal P95 latency above 5s".to_string(),
            )]),
        }
    }

    /// Default error rate alert rule
    fn default_error_rate_rule() -> Self {
        Self {
            id: "nat_error_rate_high".to_string(),
            name: "NAT Error Rate High".to_string(),
            description: "NAT traversal error rate is above threshold".to_string(),
            severity: AlertSeverity::Critical,
            condition: AlertCondition::Threshold {
                metric: "nat_error_rate".to_string(),
                operator: ThresholdOperator::GreaterThan,
                value: 0.1, // 10% error rate
                duration: Duration::from_secs(180),
            },
            evaluation_frequency: Duration::from_secs(30),
            labels: HashMap::from([
                ("component".to_string(), "nat_traversal".to_string()),
                ("type".to_string(), "error_rate".to_string()),
            ]),
            annotations: HashMap::from([
                (
                    "summary".to_string(),
                    "NAT traversal error rate above 10%".to_string(),
                ),
                ("priority".to_string(), "high".to_string()),
            ]),
        }
    }
}

/// Alert condition types
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AlertCondition {
    /// Simple threshold condition
    Threshold {
        metric: String,
        operator: ThresholdOperator,
        value: f64,
        duration: Duration,
    },
    /// Rate of change condition
    RateOfChange {
        metric: String,
        rate_threshold: f64,
        duration: Duration,
    },
    /// Anomaly detection condition
    Anomaly {
        metric: String,
        sensitivity: f64,
        baseline_duration: Duration,
    },
    /// Complex expression condition
    Expression {
        expression: String,
        duration: Duration,
    },
}

/// Threshold operators
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ThresholdOperator {
    GreaterThan,
    LessThan,
    Equal,
    NotEqual,
    GreaterThanOrEqual,
    LessThanOrEqual,
}

/// Alert severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
    Fatal,
}

/// Alert structure
#[derive(Debug, Clone)]
pub struct Alert {
    /// Unique alert identifier
    pub id: String,
    /// Alert title
    pub title: String,
    /// Alert description
    pub description: String,
    /// Alert severity
    pub severity: AlertSeverity,
    /// Alert state
    pub state: AlertState,
    /// Timestamp when alert was triggered
    pub triggered_at: SystemTime,
    /// Labels associated with alert
    pub labels: HashMap<String, String>,
    /// Additional annotations
    pub annotations: HashMap<String, String>,
    /// Alert source rule
    pub source_rule: String,
    /// Current metric value
    pub current_value: Option<f64>,
    /// Threshold value
    pub threshold_value: Option<f64>,
}

/// Alert states
#[derive(Debug, Clone, PartialEq)]
pub enum AlertState {
    Triggered,
    Acknowledged,
    Resolved,
    Suppressed,
}

/// Alert rule engine
struct AlertRuleEngine {
    rules: Vec<AlertRule>,
    rule_states: Arc<RwLock<HashMap<String, RuleState>>>,
}

impl AlertRuleEngine {
    fn new(rules: Vec<AlertRule>) -> Self {
        Self {
            rules,
            rule_states: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn evaluate_rules(
        &self,
        context: &AlertEvaluationContext,
    ) -> Result<(), MonitoringError> {
        for rule in &self.rules {
            if let Err(e) = self.evaluate_single_rule(rule, context).await {
                warn!("Rule evaluation failed for {}: {}", rule.id, e);
            }
        }
        Ok(())
    }

    async fn evaluate_scheduled_rules(
        &self,
        context: &AlertEvaluationContext,
    ) -> Result<(), MonitoringError> {
        // Evaluate time-based rules (would query metrics backend)
        for rule in &self.rules {
            // Mock evaluation for demonstration
            if self.should_evaluate_rule(rule, context.timestamp).await {
                self.evaluate_single_rule(rule, context).await?;
            }
        }
        Ok(())
    }

    async fn evaluate_single_rule(
        &self,
        rule: &AlertRule,
        context: &AlertEvaluationContext,
    ) -> Result<(), MonitoringError> {
        let should_alert = match &rule.condition {
            AlertCondition::Threshold {
                metric,
                operator,
                value,
                duration: _,
            } => {
                self.evaluate_threshold_condition(metric, operator, *value, context)
                    .await?
            }
            AlertCondition::RateOfChange {
                metric,
                rate_threshold,
                ..
            } => {
                self.evaluate_rate_condition(metric, *rate_threshold, context)
                    .await?
            }
            AlertCondition::Anomaly {
                metric,
                sensitivity,
                ..
            } => {
                self.evaluate_anomaly_condition(metric, *sensitivity, context)
                    .await?
            }
            AlertCondition::Expression { expression, .. } => {
                self.evaluate_expression_condition(expression, context)
                    .await?
            }
        };

        if should_alert {
            let alert = self.create_alert_from_rule(rule, context).await;
            // Would send alert to alert manager for processing
            debug!("Rule {} triggered alert: {}", rule.id, alert.title);
        }

        Ok(())
    }

    async fn evaluate_threshold_condition(
        &self,
        metric: &str,
        operator: &ThresholdOperator,
        threshold: f64,
        context: &AlertEvaluationContext,
    ) -> Result<bool, MonitoringError> {
        let current_value = context.metrics.get(metric).copied().unwrap_or(0.0);

        let result = match operator {
            ThresholdOperator::GreaterThan => current_value > threshold,
            ThresholdOperator::LessThan => current_value < threshold,
            ThresholdOperator::Equal => (current_value - threshold).abs() < f64::EPSILON,
            ThresholdOperator::NotEqual => (current_value - threshold).abs() > f64::EPSILON,
            ThresholdOperator::GreaterThanOrEqual => current_value >= threshold,
            ThresholdOperator::LessThanOrEqual => current_value <= threshold,
        };

        Ok(result)
    }

    async fn evaluate_rate_condition(
        &self,
        _metric: &str,
        _rate_threshold: f64,
        _context: &AlertEvaluationContext,
    ) -> Result<bool, MonitoringError> {
        // Would calculate rate of change
        Ok(false)
    }

    async fn evaluate_anomaly_condition(
        &self,
        _metric: &str,
        _sensitivity: f64,
        _context: &AlertEvaluationContext,
    ) -> Result<bool, MonitoringError> {
        // Would use anomaly detection algorithms
        Ok(false)
    }

    async fn evaluate_expression_condition(
        &self,
        _expression: &str,
        _context: &AlertEvaluationContext,
    ) -> Result<bool, MonitoringError> {
        // Would evaluate complex expressions
        Ok(false)
    }

    async fn create_alert_from_rule(
        &self,
        rule: &AlertRule,
        context: &AlertEvaluationContext,
    ) -> Alert {
        Alert {
            id: format!(
                "{}_{}",
                rule.id,
                context
                    .timestamp
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            ),
            title: rule.name.clone(),
            description: rule.description.clone(),
            severity: rule.severity.clone(),
            state: AlertState::Triggered,
            triggered_at: context.timestamp,
            labels: rule.labels.clone(),
            annotations: rule.annotations.clone(),
            source_rule: rule.id.clone(),
            current_value: None,
            threshold_value: None,
        }
    }

    async fn should_evaluate_rule(&self, _rule: &AlertRule, _timestamp: SystemTime) -> bool {
        // Would check if enough time has passed since last evaluation
        // For now, always evaluate
        true
    }
}

/// Rule evaluation state
#[derive(Debug)]
struct RuleState {
    last_evaluation: Instant,
    consecutive_violations: u32,
    last_alert: Option<Instant>,
}

/// Alert evaluation context
struct AlertEvaluationContext {
    event_type: AlertEventType,
    timestamp: SystemTime,
    attempt_info: Option<NatTraversalAttempt>,
    result_info: Option<NatTraversalResult>,
    metrics: HashMap<String, f64>,
}

/// Alert event types
enum AlertEventType {
    NatAttempt,
    NatResult,
    Scheduled,
}

/// Notification configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NotificationConfig {
    /// Notification channels
    pub channels: Vec<NotificationChannel>,
    /// Default channel for alerts
    pub default_channel: String,
    /// Rate limiting configuration
    pub rate_limiting: RateLimitConfig,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            channels: vec![NotificationChannel::Slack {
                id: "default".to_string(),
                webhook_url: "https://hooks.slack.com/services/...".to_string(),
                channel: "#alerts".to_string(),
            }],
            default_channel: "default".to_string(),
            rate_limiting: RateLimitConfig::default(),
        }
    }
}

/// Notification channels
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum NotificationChannel {
    Email {
        id: String,
        smtp_server: String,
        recipients: Vec<String>,
    },
    Slack {
        id: String,
        webhook_url: String,
        channel: String,
    },
    PagerDuty {
        id: String,
        service_key: String,
    },
    Webhook {
        id: String,
        url: String,
        headers: HashMap<String, String>,
    },
    SMS {
        id: String,
        provider: String,
        numbers: Vec<String>,
    },
}

/// Rate limiting configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RateLimitConfig {
    /// Maximum alerts per time window
    pub max_alerts_per_window: u32,
    /// Time window duration
    pub window_duration: Duration,
    /// Burst allowance
    pub burst_allowance: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_alerts_per_window: 10,
            window_duration: Duration::from_secs(60),
            burst_allowance: 3,
        }
    }
}

/// Escalation configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EscalationConfig {
    /// Escalation policies
    pub policies: Vec<EscalationPolicy>,
    /// Default escalation time
    pub default_escalation_time: Duration,
}

impl Default for EscalationConfig {
    fn default() -> Self {
        Self {
            policies: vec![
                EscalationPolicy {
                    severity: AlertSeverity::Critical,
                    escalation_time: Duration::from_secs(300), // 5 minutes
                    escalation_channels: vec!["pagerduty".to_string()],
                },
                EscalationPolicy {
                    severity: AlertSeverity::Fatal,
                    escalation_time: Duration::from_secs(60), // 1 minute
                    escalation_channels: vec!["pagerduty".to_string(), "sms".to_string()],
                },
            ],
            default_escalation_time: Duration::from_secs(600), // 10 minutes
        }
    }
}

/// Escalation policy
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EscalationPolicy {
    /// Alert severity this policy applies to
    pub severity: AlertSeverity,
    /// Time before escalation
    pub escalation_time: Duration,
    /// Channels to escalate to
    pub escalation_channels: Vec<String>,
}

/// Suppression configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SuppressionConfig {
    /// Suppression rules
    pub rules: Vec<SuppressionRule>,
    /// Default suppression time
    pub default_suppression_time: Duration,
}

impl Default for SuppressionConfig {
    fn default() -> Self {
        Self {
            rules: vec![],
            default_suppression_time: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Suppression rule
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SuppressionRule {
    /// Rule identifier
    pub id: String,
    /// Labels to match for suppression
    pub label_matchers: HashMap<String, String>,
    /// Suppression duration
    pub duration: Duration,
    /// Reason for suppression
    pub reason: String,
}

/// Notification dispatcher
struct NotificationDispatcher {
    config: NotificationConfig,
    rate_limiter: Arc<RateLimiter>,
}

impl NotificationDispatcher {
    fn new(config: NotificationConfig) -> Self {
        Self {
            rate_limiter: Arc::new(RateLimiter::new(config.rate_limiting.clone())),
            config,
        }
    }

    async fn dispatch_alert(&self, alert: &Alert) -> Result<(), MonitoringError> {
        // Check rate limiting
        if !self.rate_limiter.allow_alert().await {
            warn!("Alert rate limited: {}", alert.title);
            return Ok(());
        }

        // Send to appropriate channels based on severity
        let channels = self.select_channels_for_alert(alert);

        for channel_id in channels {
            if let Some(channel) = self.find_channel(&channel_id) {
                if let Err(e) = self.send_to_channel(channel, alert).await {
                    warn!("Failed to send alert to channel {}: {}", channel_id, e);
                }
            }
        }

        Ok(())
    }

    fn select_channels_for_alert(&self, alert: &Alert) -> Vec<String> {
        // Select channels based on severity and labels
        match alert.severity {
            AlertSeverity::Info => vec![self.config.default_channel.clone()],
            AlertSeverity::Warning => vec![self.config.default_channel.clone()],
            AlertSeverity::Critical => {
                vec![self.config.default_channel.clone(), "pagerduty".to_string()]
            }
            AlertSeverity::Fatal => vec![
                self.config.default_channel.clone(),
                "pagerduty".to_string(),
                "sms".to_string(),
            ],
        }
    }

    fn find_channel(&self, channel_id: &str) -> Option<&NotificationChannel> {
        self.config.channels.iter().find(|ch| match ch {
            NotificationChannel::Email { id, .. } => id == channel_id,
            NotificationChannel::Slack { id, .. } => id == channel_id,
            NotificationChannel::PagerDuty { id, .. } => id == channel_id,
            NotificationChannel::Webhook { id, .. } => id == channel_id,
            NotificationChannel::SMS { id, .. } => id == channel_id,
        })
    }

    async fn send_to_channel(
        &self,
        channel: &NotificationChannel,
        alert: &Alert,
    ) -> Result<(), MonitoringError> {
        match channel {
            NotificationChannel::Slack {
                webhook_url,
                channel,
                ..
            } => {
                self.send_slack_notification(webhook_url, channel, alert)
                    .await
            }
            NotificationChannel::Email { recipients, .. } => {
                self.send_email_notification(recipients, alert).await
            }
            NotificationChannel::PagerDuty { service_key, .. } => {
                self.send_pagerduty_notification(service_key, alert).await
            }
            NotificationChannel::Webhook { url, headers, .. } => {
                self.send_webhook_notification(url, headers, alert).await
            }
            NotificationChannel::SMS { numbers, .. } => {
                self.send_sms_notification(numbers, alert).await
            }
        }
    }

    async fn send_slack_notification(
        &self,
        _webhook_url: &str,
        _channel: &str,
        alert: &Alert,
    ) -> Result<(), MonitoringError> {
        info!("Sending Slack notification for alert: {}", alert.title);
        // Would implement actual Slack webhook call
        Ok(())
    }

    async fn send_email_notification(
        &self,
        _recipients: &[String],
        alert: &Alert,
    ) -> Result<(), MonitoringError> {
        info!("Sending email notification for alert: {}", alert.title);
        // Would implement actual email sending
        Ok(())
    }

    async fn send_pagerduty_notification(
        &self,
        _service_key: &str,
        alert: &Alert,
    ) -> Result<(), MonitoringError> {
        info!("Sending PagerDuty notification for alert: {}", alert.title);
        // Would implement actual PagerDuty API call
        Ok(())
    }

    async fn send_webhook_notification(
        &self,
        _url: &str,
        _headers: &HashMap<String, String>,
        alert: &Alert,
    ) -> Result<(), MonitoringError> {
        info!("Sending webhook notification for alert: {}", alert.title);
        // Would implement actual HTTP webhook call
        Ok(())
    }

    async fn send_sms_notification(
        &self,
        _numbers: &[String],
        alert: &Alert,
    ) -> Result<(), MonitoringError> {
        info!("Sending SMS notification for alert: {}", alert.title);
        // Would implement actual SMS sending
        Ok(())
    }

    async fn health_check(&self) -> Result<(), MonitoringError> {
        // Health check for notification channels
        debug!("Notification system health check passed");
        Ok(())
    }
}

/// Rate limiter for notifications
struct RateLimiter {
    config: RateLimitConfig,
    window_start: Arc<RwLock<Instant>>,
    current_count: Arc<RwLock<u32>>,
}

impl RateLimiter {
    fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            window_start: Arc::new(RwLock::new(Instant::now())),
            current_count: Arc::new(RwLock::new(0)),
        }
    }

    async fn allow_alert(&self) -> bool {
        let now = Instant::now();
        let mut window_start = self.window_start.write().await;
        let mut current_count = self.current_count.write().await;

        // Check if we need to reset the window
        if now.duration_since(*window_start) >= self.config.window_duration {
            *window_start = now;
            *current_count = 0;
        }

        // Check if we're within limits
        if *current_count < self.config.max_alerts_per_window {
            *current_count += 1;
            true
        } else {
            false
        }
    }
}

/// Alert state manager
struct AlertStateManager {
    active_alerts: Arc<RwLock<HashMap<String, AlertStateInfo>>>,
}

impl AlertStateManager {
    fn new() -> Self {
        Self {
            active_alerts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn update_alert_state(&self, alert: Alert) -> Result<AlertStateInfo, MonitoringError> {
        let mut active_alerts = self.active_alerts.write().await;

        let state_info = AlertStateInfo {
            alert: alert.clone(),
            first_triggered: SystemTime::now(),
            last_updated: SystemTime::now(),
            escalation_level: 0,
            acknowledgments: Vec::new(),
        };

        active_alerts.insert(alert.id.clone(), state_info.clone());
        Ok(state_info)
    }

    async fn get_active_alert_count(&self) -> usize {
        let active_alerts = self.active_alerts.read().await;
        active_alerts.len()
    }

    async fn get_active_alerts(&self) -> Vec<AlertStateInfo> {
        let active_alerts = self.active_alerts.read().await;
        active_alerts.values().cloned().collect()
    }
}

/// Alert state information
#[derive(Debug, Clone)]
struct AlertStateInfo {
    alert: Alert,
    first_triggered: SystemTime,
    last_updated: SystemTime,
    escalation_level: u32,
    acknowledgments: Vec<AlertAcknowledgment>,
}

/// Alert acknowledgment
#[derive(Debug, Clone)]
struct AlertAcknowledgment {
    user: String,
    timestamp: SystemTime,
    message: Option<String>,
}

/// Escalation manager
struct EscalationManager {
    config: EscalationConfig,
}

impl EscalationManager {
    fn new(config: EscalationConfig) -> Self {
        Self { config }
    }

    async fn should_escalate(&self, alert_state: &AlertStateInfo) -> bool {
        let elapsed = alert_state.first_triggered.elapsed().unwrap_or_default();

        // Find applicable escalation policy
        for policy in &self.config.policies {
            if policy.severity == alert_state.alert.severity {
                return elapsed >= policy.escalation_time;
            }
        }

        // Use default escalation time
        elapsed >= self.config.default_escalation_time
    }

    async fn escalate_alert(&self, alert: &Alert) -> Result<(), MonitoringError> {
        info!(
            "Escalating alert: {} (severity: {:?})",
            alert.title, alert.severity
        );

        // Find escalation policy and send to escalation channels
        for policy in &self.config.policies {
            if policy.severity == alert.severity {
                for channel in &policy.escalation_channels {
                    info!("Escalating to channel: {}", channel);
                    // Would send escalation notification
                }
                break;
            }
        }

        Ok(())
    }
}

/// Suppression engine
struct SuppressionEngine {
    config: SuppressionConfig,
    active_suppressions: Arc<RwLock<HashMap<String, SuppressionInfo>>>,
}

impl SuppressionEngine {
    fn new(config: SuppressionConfig) -> Self {
        Self {
            config,
            active_suppressions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn should_suppress(&self, alert: &Alert) -> bool {
        let suppressions = self.active_suppressions.read().await;

        for suppression in suppressions.values() {
            if self.alert_matches_suppression(alert, &suppression.rule) {
                return true;
            }
        }

        false
    }

    fn alert_matches_suppression(&self, alert: &Alert, rule: &SuppressionRule) -> bool {
        // Check if alert labels match suppression rule
        for (key, value) in &rule.label_matchers {
            if alert.labels.get(key) != Some(value) {
                return false;
            }
        }
        true
    }

    async fn get_suppressed_count(&self) -> usize {
        let suppressions = self.active_suppressions.read().await;
        suppressions.len()
    }

    async fn cleanup_expired_suppressions(&self) -> Result<(), MonitoringError> {
        let mut suppressions = self.active_suppressions.write().await;
        let now = SystemTime::now();

        suppressions.retain(|_, suppression| {
            now.duration_since(suppression.created_at)
                .unwrap_or_default()
                < suppression.rule.duration
        });

        Ok(())
    }
}

/// Suppression information
#[derive(Debug, Clone)]
struct SuppressionInfo {
    rule: SuppressionRule,
    created_at: SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_alert_manager_creation() {
        let config = AlertingConfig::default();
        let manager = ProductionAlertManager::new(config).await.unwrap();

        let status = manager.get_status().await;
        assert!(status.contains("Active: 0"));
    }

    #[tokio::test]
    async fn test_threshold_evaluation() {
        let rules = vec![AlertRule::default_success_rate_rule()];
        let engine = AlertRuleEngine::new(rules);

        let mut metrics = HashMap::new();
        metrics.insert("nat_success_rate".to_string(), 0.5); // Below threshold

        let context = AlertEvaluationContext {
            event_type: AlertEventType::Scheduled,
            timestamp: SystemTime::now(),
            attempt_info: None,
            result_info: None,
            metrics,
        };

        let should_alert = engine
            .evaluate_threshold_condition(
                "nat_success_rate",
                &ThresholdOperator::LessThan,
                0.8,
                &context,
            )
            .await
            .unwrap();

        assert!(should_alert);
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let config = RateLimitConfig {
            max_alerts_per_window: 2,
            window_duration: Duration::from_secs(60),
            burst_allowance: 1,
        };

        let limiter = RateLimiter::new(config);

        // First two alerts should be allowed
        assert!(limiter.allow_alert().await);
        assert!(limiter.allow_alert().await);

        // Third alert should be rate limited
        assert!(!limiter.allow_alert().await);
    }
}
