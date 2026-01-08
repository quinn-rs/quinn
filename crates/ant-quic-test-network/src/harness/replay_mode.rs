//! Replay Mode for Re-Running Classification from Artifacts
//!
//! This module provides the ability to replay test runs from collected
//! artifacts for debugging and re-classification purposes. This allows:
//! - Re-running failure classification with updated rules
//! - Debugging intermittent failures without re-running tests
//! - Comparing classification results across different classifier versions
//! - Validating classifier accuracy against known outcomes

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

use super::{DebugArtifactType, FailureCategory};

/// Source of replay data
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplaySource {
    /// Replay from a debug bundle
    DebugBundle { bundle_id: Uuid, path: PathBuf },
    /// Replay from structured logs
    StructuredLogs { path: PathBuf },
    /// Replay from artifact manifest
    ArtifactManifest { manifest_id: Uuid, path: PathBuf },
    /// Replay from attempt result
    AttemptResult { attempt_id: Uuid },
}

impl ReplaySource {
    /// Create a replay source from a debug bundle
    pub fn from_bundle(bundle_id: Uuid, path: impl Into<PathBuf>) -> Self {
        Self::DebugBundle {
            bundle_id,
            path: path.into(),
        }
    }

    /// Create a replay source from structured logs
    pub fn from_logs(path: impl Into<PathBuf>) -> Self {
        Self::StructuredLogs { path: path.into() }
    }

    /// Create a replay source from an artifact manifest
    pub fn from_manifest(manifest_id: Uuid, path: impl Into<PathBuf>) -> Self {
        Self::ArtifactManifest {
            manifest_id,
            path: path.into(),
        }
    }

    /// Create a replay source from an attempt result
    pub fn from_attempt(attempt_id: Uuid) -> Self {
        Self::AttemptResult { attempt_id }
    }

    /// Get the path if this source has one
    pub fn path(&self) -> Option<&PathBuf> {
        match self {
            Self::DebugBundle { path, .. } => Some(path),
            Self::StructuredLogs { path } => Some(path),
            Self::ArtifactManifest { path, .. } => Some(path),
            Self::AttemptResult { .. } => None,
        }
    }
}

/// Status of a replay session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReplayStatus {
    /// Replay not started
    #[default]
    NotStarted,
    /// Loading artifacts
    Loading,
    /// Parsing events
    Parsing,
    /// Running classification
    Classifying,
    /// Replay completed successfully
    Completed,
    /// Replay failed
    Failed,
}

impl ReplayStatus {
    /// Check if this is a terminal status
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }

    /// Check if replay is in progress
    pub fn is_in_progress(&self) -> bool {
        matches!(self, Self::Loading | Self::Parsing | Self::Classifying)
    }
}

/// A reconstructed event from artifacts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayEvent {
    /// Event ID
    pub id: Uuid,
    /// Timestamp of the original event
    pub timestamp: SystemTime,
    /// Event type
    pub event_type: ReplayEventType,
    /// Source agent
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Associated test ID
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_id: Option<Uuid>,
    /// Event data (type-specific)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub data: HashMap<String, serde_json::Value>,
}

impl ReplayEvent {
    /// Create a new replay event
    pub fn new(event_type: ReplayEventType) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: SystemTime::now(),
            event_type,
            agent_id: None,
            test_id: None,
            data: HashMap::new(),
        }
    }

    /// Set the timestamp
    pub fn with_timestamp(mut self, timestamp: SystemTime) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Set the agent ID
    pub fn with_agent(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    /// Set the test ID
    pub fn with_test(mut self, test_id: Uuid) -> Self {
        self.test_id = Some(test_id);
        self
    }

    /// Add data to the event, returning an error if serialization fails.
    ///
    /// This is the preferred method as it makes serialization failures explicit.
    pub fn try_with_data(
        mut self,
        key: impl Into<String>,
        value: impl Serialize,
    ) -> Result<Self, serde_json::Error> {
        let v = serde_json::to_value(value)?;
        self.data.insert(key.into(), v);
        Ok(self)
    }

    /// Add data to the event, silently dropping serialization failures.
    ///
    /// **DEPRECATED**: This method silently drops serialization errors, which can
    /// cause data loss without any indication. Use `try_with_data()` instead.
    #[deprecated(
        since = "0.2.0",
        note = "Use try_with_data() to handle serialization errors explicitly"
    )]
    pub fn with_data(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.data.insert(key.into(), v);
        }
        self
    }
}

/// Types of replay events
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayEventType {
    /// Connection attempt
    ConnectionAttempt,
    /// Connection established
    ConnectionEstablished,
    /// Connection failed
    ConnectionFailed,
    /// Packet sent
    PacketSent,
    /// Packet received
    PacketReceived,
    /// NAT traversal started
    NatTraversalStarted,
    /// NAT traversal completed
    NatTraversalCompleted,
    /// NAT traversal failed
    NatTraversalFailed,
    /// Timeout occurred
    Timeout,
    /// Error occurred
    Error,
    /// Agent started
    AgentStarted,
    /// Agent stopped
    AgentStopped,
    /// Test started
    TestStarted,
    /// Test completed
    TestCompleted,
    /// Custom event
    Custom(String),
}

/// Result of classification during replay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationResult {
    /// The failure class assigned
    pub failure_category: FailureCategory,
    /// Confidence score (0.0-1.0)
    pub confidence: f64,
    /// Evidence supporting this classification
    pub evidence: Vec<String>,
    /// Alternative classifications considered
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alternatives: Vec<(FailureCategory, f64)>,
}

impl ClassificationResult {
    /// Create a new classification result
    pub fn new(failure_category: FailureCategory, confidence: f64) -> Self {
        Self {
            failure_category,
            confidence,
            evidence: Vec::new(),
            alternatives: Vec::new(),
        }
    }

    /// Add evidence
    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence.push(evidence.into());
        self
    }

    /// Add alternative classification
    pub fn with_alternative(mut self, class: FailureCategory, confidence: f64) -> Self {
        self.alternatives.push((class, confidence));
        self
    }

    /// Check if this is a high-confidence classification
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.8
    }

    /// Check if there are competing alternatives
    pub fn has_close_alternatives(&self) -> bool {
        self.alternatives
            .iter()
            .any(|(_, conf)| self.confidence - conf < 0.2)
    }
}

/// Comparison between original and replay classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationComparison {
    /// Original classification
    pub original: Option<FailureCategory>,
    /// Replay classification
    pub replay: ClassificationResult,
    /// Whether classifications match
    pub matches: bool,
    /// Difference in confidence if applicable
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_delta: Option<f64>,
}

impl ClassificationComparison {
    /// Create a new comparison
    pub fn new(original: Option<FailureCategory>, replay: ClassificationResult) -> Self {
        let matches = original.as_ref() == Some(&replay.failure_category);
        Self {
            original,
            replay,
            matches,
            confidence_delta: None,
        }
    }

    /// Set confidence delta
    pub fn with_confidence_delta(mut self, delta: f64) -> Self {
        self.confidence_delta = Some(delta);
        self
    }
}

/// Statistics from a replay session
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReplayStatistics {
    /// Total events processed
    pub events_processed: usize,
    /// Events by type
    pub events_by_type: HashMap<String, usize>,
    /// Artifacts loaded
    pub artifacts_loaded: usize,
    /// Artifact types loaded
    pub artifact_types: Vec<DebugArtifactType>,
    /// Time spent loading
    pub load_duration: Option<Duration>,
    /// Time spent parsing
    pub parse_duration: Option<Duration>,
    /// Time spent classifying
    pub classify_duration: Option<Duration>,
    /// Total replay duration
    pub total_duration: Option<Duration>,
}

impl ReplayStatistics {
    /// Create new empty statistics
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an event
    pub fn record_event(&mut self, event_type: &ReplayEventType) {
        self.events_processed += 1;
        let type_name = format!("{event_type:?}");
        *self.events_by_type.entry(type_name).or_insert(0) += 1;
    }

    /// Record artifact loaded
    pub fn record_artifact(&mut self, artifact_type: DebugArtifactType) {
        self.artifacts_loaded += 1;
        if !self.artifact_types.contains(&artifact_type) {
            self.artifact_types.push(artifact_type);
        }
    }
}

/// A replay session for re-running classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaySession {
    /// Session ID
    pub session_id: Uuid,
    /// Original run ID being replayed
    pub run_id: Uuid,
    /// Optional test ID for targeted replay
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_id: Option<Uuid>,
    /// Source of replay data
    pub source: ReplaySource,
    /// Current status
    pub status: ReplayStatus,
    /// When replay started
    pub started_at: Option<SystemTime>,
    /// When replay completed
    pub completed_at: Option<SystemTime>,
    /// Events reconstructed during replay
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<ReplayEvent>,
    /// Classification result
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<ClassificationResult>,
    /// Comparison with original classification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comparison: Option<ClassificationComparison>,
    /// Replay statistics
    pub statistics: ReplayStatistics,
    /// Error message if failed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ReplaySession {
    /// Create a new replay session
    pub fn new(run_id: Uuid, source: ReplaySource) -> Self {
        Self {
            session_id: Uuid::new_v4(),
            run_id,
            test_id: None,
            source,
            status: ReplayStatus::NotStarted,
            started_at: None,
            completed_at: None,
            events: Vec::new(),
            classification: None,
            comparison: None,
            statistics: ReplayStatistics::new(),
            error: None,
        }
    }

    /// Create a replay session for a specific test
    pub fn for_test(run_id: Uuid, test_id: Uuid, source: ReplaySource) -> Self {
        let mut session = Self::new(run_id, source);
        session.test_id = Some(test_id);
        session
    }

    /// Start the replay
    pub fn start(&mut self) {
        self.started_at = Some(SystemTime::now());
        self.status = ReplayStatus::Loading;
    }

    /// Transition to parsing phase
    pub fn start_parsing(&mut self) {
        self.status = ReplayStatus::Parsing;
    }

    /// Transition to classification phase
    pub fn start_classifying(&mut self) {
        self.status = ReplayStatus::Classifying;
    }

    /// Add an event to the replay
    pub fn add_event(&mut self, event: ReplayEvent) {
        self.statistics.record_event(&event.event_type);
        self.events.push(event);
    }

    /// Complete the replay successfully
    pub fn complete(&mut self, classification: ClassificationResult) {
        self.completed_at = Some(SystemTime::now());
        self.status = ReplayStatus::Completed;
        self.classification = Some(classification);

        // Calculate total duration
        if let (Some(start), Some(end)) = (self.started_at, self.completed_at) {
            self.statistics.total_duration = end.duration_since(start).ok();
        }
    }

    /// Complete with comparison to original
    pub fn complete_with_comparison(
        &mut self,
        classification: ClassificationResult,
        original: Option<FailureCategory>,
    ) {
        let comparison = ClassificationComparison::new(original, classification.clone());
        self.comparison = Some(comparison);
        self.complete(classification);
    }

    /// Fail the replay
    pub fn fail(&mut self, error: impl Into<String>) {
        self.completed_at = Some(SystemTime::now());
        self.status = ReplayStatus::Failed;
        self.error = Some(error.into());
    }

    /// Get replay duration
    pub fn duration(&self) -> Option<Duration> {
        let started = self.started_at?;
        let ended = self.completed_at.unwrap_or_else(SystemTime::now);
        ended.duration_since(started).ok()
    }

    /// Check if replay succeeded
    pub fn is_success(&self) -> bool {
        self.status == ReplayStatus::Completed && self.classification.is_some()
    }

    /// Check if classification changed from original
    pub fn classification_changed(&self) -> bool {
        self.comparison.as_ref().is_some_and(|c| !c.matches)
    }

    /// Get events for a specific agent
    pub fn events_for_agent(&self, agent_id: &str) -> Vec<&ReplayEvent> {
        self.events
            .iter()
            .filter(|e| e.agent_id.as_deref() == Some(agent_id))
            .collect()
    }

    /// Get events of a specific type
    pub fn events_of_type(&self, event_type: &ReplayEventType) -> Vec<&ReplayEvent> {
        self.events
            .iter()
            .filter(|e| &e.event_type == event_type)
            .collect()
    }

    /// Get unique agent IDs from events
    pub fn agent_ids(&self) -> Vec<String> {
        let mut ids: Vec<_> = self
            .events
            .iter()
            .filter_map(|e| e.agent_id.clone())
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }
}

/// Configuration for replay operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayConfig {
    /// Whether to include packet-level events
    pub include_packets: bool,
    /// Whether to include timing events
    pub include_timing: bool,
    /// Maximum events to process (0 = unlimited)
    pub max_events: usize,
    /// Timeout for replay operation
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    /// Classifier version to use
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classifier_version: Option<String>,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            include_packets: true,
            include_timing: true,
            max_events: 0,
            timeout: Duration::from_secs(300),
            classifier_version: None,
        }
    }
}

impl ReplayConfig {
    /// Create a fast config (no packets, limited events)
    pub fn fast() -> Self {
        Self {
            include_packets: false,
            include_timing: false,
            max_events: 1000,
            timeout: Duration::from_secs(60),
            classifier_version: None,
        }
    }

    /// Create a detailed config (all events)
    pub fn detailed() -> Self {
        Self {
            include_packets: true,
            include_timing: true,
            max_events: 0,
            timeout: Duration::from_secs(600),
            classifier_version: None,
        }
    }

    /// Set classifier version
    pub fn with_classifier_version(mut self, version: impl Into<String>) -> Self {
        self.classifier_version = Some(version.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== ReplaySource Tests ====================

    #[test]
    fn test_replay_source_from_bundle() {
        let bundle_id = Uuid::new_v4();
        let source = ReplaySource::from_bundle(bundle_id, "/tmp/bundle");

        match source {
            ReplaySource::DebugBundle {
                bundle_id: id,
                path,
            } => {
                assert_eq!(id, bundle_id);
                assert_eq!(path, PathBuf::from("/tmp/bundle"));
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_replay_source_from_logs() {
        let source = ReplaySource::from_logs("/tmp/logs.jsonl");
        match source {
            ReplaySource::StructuredLogs { path } => {
                assert_eq!(path, PathBuf::from("/tmp/logs.jsonl"));
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_replay_source_from_manifest() {
        let manifest_id = Uuid::new_v4();
        let source = ReplaySource::from_manifest(manifest_id, "/tmp/manifest.json");

        match source {
            ReplaySource::ArtifactManifest {
                manifest_id: id,
                path,
            } => {
                assert_eq!(id, manifest_id);
                assert_eq!(path, PathBuf::from("/tmp/manifest.json"));
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_replay_source_from_attempt() {
        let attempt_id = Uuid::new_v4();
        let source = ReplaySource::from_attempt(attempt_id);

        match source {
            ReplaySource::AttemptResult { attempt_id: id } => {
                assert_eq!(id, attempt_id);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_replay_source_path() {
        let source = ReplaySource::from_logs("/tmp/logs.jsonl");
        assert_eq!(source.path(), Some(&PathBuf::from("/tmp/logs.jsonl")));

        let source = ReplaySource::from_attempt(Uuid::new_v4());
        assert!(source.path().is_none());
    }

    // ==================== ReplayStatus Tests ====================

    #[test]
    fn test_replay_status_default() {
        assert_eq!(ReplayStatus::default(), ReplayStatus::NotStarted);
    }

    #[test]
    fn test_replay_status_is_terminal() {
        assert!(!ReplayStatus::NotStarted.is_terminal());
        assert!(!ReplayStatus::Loading.is_terminal());
        assert!(!ReplayStatus::Parsing.is_terminal());
        assert!(!ReplayStatus::Classifying.is_terminal());
        assert!(ReplayStatus::Completed.is_terminal());
        assert!(ReplayStatus::Failed.is_terminal());
    }

    #[test]
    fn test_replay_status_is_in_progress() {
        assert!(!ReplayStatus::NotStarted.is_in_progress());
        assert!(ReplayStatus::Loading.is_in_progress());
        assert!(ReplayStatus::Parsing.is_in_progress());
        assert!(ReplayStatus::Classifying.is_in_progress());
        assert!(!ReplayStatus::Completed.is_in_progress());
        assert!(!ReplayStatus::Failed.is_in_progress());
    }

    // ==================== ReplayEvent Tests ====================

    #[test]
    fn test_replay_event_new() {
        let event = ReplayEvent::new(ReplayEventType::ConnectionAttempt);

        assert_eq!(event.event_type, ReplayEventType::ConnectionAttempt);
        assert!(event.agent_id.is_none());
        assert!(event.test_id.is_none());
        assert!(event.data.is_empty());
    }

    #[test]
    fn test_replay_event_with_agent() {
        let event = ReplayEvent::new(ReplayEventType::ConnectionAttempt).with_agent("agent-1");

        assert_eq!(event.agent_id, Some("agent-1".to_string()));
    }

    #[test]
    fn test_replay_event_with_test() {
        let test_id = Uuid::new_v4();
        let event = ReplayEvent::new(ReplayEventType::ConnectionAttempt).with_test(test_id);

        assert_eq!(event.test_id, Some(test_id));
    }

    #[test]
    fn test_replay_event_try_with_data() {
        let event = ReplayEvent::new(ReplayEventType::ConnectionAttempt)
            .try_with_data("port", 9000)
            .unwrap()
            .try_with_data("protocol", "quic")
            .unwrap();

        assert_eq!(event.data.get("port"), Some(&serde_json::json!(9000)));
        assert_eq!(event.data.get("protocol"), Some(&serde_json::json!("quic")));
    }

    #[test]
    #[allow(deprecated)]
    fn test_replay_event_with_data_deprecated() {
        let event = ReplayEvent::new(ReplayEventType::ConnectionAttempt)
            .with_data("port", 9000)
            .with_data("protocol", "quic");

        assert_eq!(event.data.get("port"), Some(&serde_json::json!(9000)));
        assert_eq!(event.data.get("protocol"), Some(&serde_json::json!("quic")));
    }

    // ==================== ClassificationResult Tests ====================

    #[test]
    fn test_classification_result_new() {
        let result = ClassificationResult::new(FailureCategory::SutConnectivityFailure, 0.9);

        assert_eq!(
            result.failure_category,
            FailureCategory::SutConnectivityFailure
        );
        assert_eq!(result.confidence, 0.9);
        assert!(result.evidence.is_empty());
        assert!(result.alternatives.is_empty());
    }

    #[test]
    fn test_classification_result_with_evidence() {
        let result = ClassificationResult::new(FailureCategory::SutConnectivityFailure, 0.9)
            .with_evidence("No response to SYN packets")
            .with_evidence("ICMP unreachable received");

        assert_eq!(result.evidence.len(), 2);
    }

    #[test]
    fn test_classification_result_with_alternative() {
        let result = ClassificationResult::new(FailureCategory::SutConnectivityFailure, 0.9)
            .with_alternative(FailureCategory::InfrastructureFlake, 0.7)
            .with_alternative(FailureCategory::HarnessOrchestrationError, 0.5);

        assert_eq!(result.alternatives.len(), 2);
    }

    #[test]
    fn test_classification_result_is_high_confidence() {
        let high = ClassificationResult::new(FailureCategory::SutConnectivityFailure, 0.9);
        assert!(high.is_high_confidence());

        let low = ClassificationResult::new(FailureCategory::SutConnectivityFailure, 0.5);
        assert!(!low.is_high_confidence());

        let boundary = ClassificationResult::new(FailureCategory::SutConnectivityFailure, 0.8);
        assert!(boundary.is_high_confidence());
    }

    #[test]
    fn test_classification_result_has_close_alternatives() {
        let result = ClassificationResult::new(FailureCategory::SutConnectivityFailure, 0.9)
            .with_alternative(FailureCategory::InfrastructureFlake, 0.85);
        assert!(result.has_close_alternatives());

        let result = ClassificationResult::new(FailureCategory::SutConnectivityFailure, 0.9)
            .with_alternative(FailureCategory::InfrastructureFlake, 0.5);
        assert!(!result.has_close_alternatives());
    }

    // ==================== ClassificationComparison Tests ====================

    #[test]
    fn test_classification_comparison_matches() {
        let original = Some(FailureCategory::SutConnectivityFailure);
        let replay = ClassificationResult::new(FailureCategory::SutConnectivityFailure, 0.9);
        let comparison = ClassificationComparison::new(original, replay);

        assert!(comparison.matches);
    }

    #[test]
    fn test_classification_comparison_no_match() {
        let original = Some(FailureCategory::InfrastructureFlake);
        let replay = ClassificationResult::new(FailureCategory::SutConnectivityFailure, 0.9);
        let comparison = ClassificationComparison::new(original, replay);

        assert!(!comparison.matches);
    }

    #[test]
    fn test_classification_comparison_no_original() {
        let replay = ClassificationResult::new(FailureCategory::SutConnectivityFailure, 0.9);
        let comparison = ClassificationComparison::new(None, replay);

        assert!(!comparison.matches);
    }

    #[test]
    fn test_classification_comparison_with_delta() {
        let original = Some(FailureCategory::SutConnectivityFailure);
        let replay = ClassificationResult::new(FailureCategory::SutConnectivityFailure, 0.9);
        let comparison = ClassificationComparison::new(original, replay).with_confidence_delta(0.1);

        assert_eq!(comparison.confidence_delta, Some(0.1));
    }

    // ==================== ReplayStatistics Tests ====================

    #[test]
    fn test_replay_statistics_new() {
        let stats = ReplayStatistics::new();

        assert_eq!(stats.events_processed, 0);
        assert!(stats.events_by_type.is_empty());
        assert_eq!(stats.artifacts_loaded, 0);
    }

    #[test]
    fn test_replay_statistics_record_event() {
        let mut stats = ReplayStatistics::new();

        stats.record_event(&ReplayEventType::ConnectionAttempt);
        stats.record_event(&ReplayEventType::ConnectionAttempt);
        stats.record_event(&ReplayEventType::Timeout);

        assert_eq!(stats.events_processed, 3);
        assert_eq!(stats.events_by_type.get("ConnectionAttempt"), Some(&2));
        assert_eq!(stats.events_by_type.get("Timeout"), Some(&1));
    }

    #[test]
    fn test_replay_statistics_record_artifact() {
        let mut stats = ReplayStatistics::new();

        stats.record_artifact(DebugArtifactType::PacketCapture);
        stats.record_artifact(DebugArtifactType::DockerLogs);
        stats.record_artifact(DebugArtifactType::PacketCapture); // Duplicate type

        assert_eq!(stats.artifacts_loaded, 3);
        assert_eq!(stats.artifact_types.len(), 2); // Deduped
    }

    // ==================== ReplaySession Tests ====================

    #[test]
    fn test_replay_session_new() {
        let run_id = Uuid::new_v4();
        let source = ReplaySource::from_logs("/tmp/logs.jsonl");
        let session = ReplaySession::new(run_id, source);

        assert_eq!(session.run_id, run_id);
        assert_eq!(session.status, ReplayStatus::NotStarted);
        assert!(session.started_at.is_none());
        assert!(session.events.is_empty());
    }

    #[test]
    fn test_replay_session_for_test() {
        let run_id = Uuid::new_v4();
        let test_id = Uuid::new_v4();
        let source = ReplaySource::from_logs("/tmp/logs.jsonl");
        let session = ReplaySession::for_test(run_id, test_id, source);

        assert_eq!(session.test_id, Some(test_id));
    }

    #[test]
    fn test_replay_session_start() {
        let run_id = Uuid::new_v4();
        let source = ReplaySource::from_logs("/tmp/logs.jsonl");
        let mut session = ReplaySession::new(run_id, source);

        session.start();

        assert_eq!(session.status, ReplayStatus::Loading);
        assert!(session.started_at.is_some());
    }

    #[test]
    fn test_replay_session_transitions() {
        let run_id = Uuid::new_v4();
        let source = ReplaySource::from_logs("/tmp/logs.jsonl");
        let mut session = ReplaySession::new(run_id, source);

        session.start();
        assert_eq!(session.status, ReplayStatus::Loading);

        session.start_parsing();
        assert_eq!(session.status, ReplayStatus::Parsing);

        session.start_classifying();
        assert_eq!(session.status, ReplayStatus::Classifying);
    }

    #[test]
    fn test_replay_session_add_event() {
        let run_id = Uuid::new_v4();
        let source = ReplaySource::from_logs("/tmp/logs.jsonl");
        let mut session = ReplaySession::new(run_id, source);

        let event = ReplayEvent::new(ReplayEventType::ConnectionAttempt);
        session.add_event(event);

        assert_eq!(session.events.len(), 1);
        assert_eq!(session.statistics.events_processed, 1);
    }

    #[test]
    fn test_replay_session_complete() {
        let run_id = Uuid::new_v4();
        let source = ReplaySource::from_logs("/tmp/logs.jsonl");
        let mut session = ReplaySession::new(run_id, source);

        session.start();
        let classification =
            ClassificationResult::new(FailureCategory::SutConnectivityFailure, 0.9);
        session.complete(classification);

        assert_eq!(session.status, ReplayStatus::Completed);
        assert!(session.completed_at.is_some());
        assert!(session.classification.is_some());
        assert!(session.is_success());
    }

    #[test]
    fn test_replay_session_complete_with_comparison() {
        let run_id = Uuid::new_v4();
        let source = ReplaySource::from_logs("/tmp/logs.jsonl");
        let mut session = ReplaySession::new(run_id, source);

        session.start();
        let classification = ClassificationResult::new(FailureCategory::InfrastructureFlake, 0.9);
        session.complete_with_comparison(
            classification,
            Some(FailureCategory::SutConnectivityFailure),
        );

        assert!(session.comparison.is_some());
        assert!(!session.comparison.as_ref().unwrap().matches);
        assert!(session.classification_changed());
    }

    #[test]
    fn test_replay_session_fail() {
        let run_id = Uuid::new_v4();
        let source = ReplaySource::from_logs("/tmp/logs.jsonl");
        let mut session = ReplaySession::new(run_id, source);

        session.start();
        session.fail("Failed to load artifacts");

        assert_eq!(session.status, ReplayStatus::Failed);
        assert_eq!(session.error, Some("Failed to load artifacts".to_string()));
        assert!(!session.is_success());
    }

    #[test]
    fn test_replay_session_events_for_agent() {
        let run_id = Uuid::new_v4();
        let source = ReplaySource::from_logs("/tmp/logs.jsonl");
        let mut session = ReplaySession::new(run_id, source);

        session
            .add_event(ReplayEvent::new(ReplayEventType::ConnectionAttempt).with_agent("agent-1"));
        session
            .add_event(ReplayEvent::new(ReplayEventType::ConnectionAttempt).with_agent("agent-2"));
        session.add_event(ReplayEvent::new(ReplayEventType::Timeout).with_agent("agent-1"));

        let agent1_events = session.events_for_agent("agent-1");
        assert_eq!(agent1_events.len(), 2);
    }

    #[test]
    fn test_replay_session_events_of_type() {
        let run_id = Uuid::new_v4();
        let source = ReplaySource::from_logs("/tmp/logs.jsonl");
        let mut session = ReplaySession::new(run_id, source);

        session.add_event(ReplayEvent::new(ReplayEventType::ConnectionAttempt));
        session.add_event(ReplayEvent::new(ReplayEventType::ConnectionAttempt));
        session.add_event(ReplayEvent::new(ReplayEventType::Timeout));

        let attempts = session.events_of_type(&ReplayEventType::ConnectionAttempt);
        assert_eq!(attempts.len(), 2);
    }

    #[test]
    fn test_replay_session_agent_ids() {
        let run_id = Uuid::new_v4();
        let source = ReplaySource::from_logs("/tmp/logs.jsonl");
        let mut session = ReplaySession::new(run_id, source);

        session
            .add_event(ReplayEvent::new(ReplayEventType::ConnectionAttempt).with_agent("agent-2"));
        session
            .add_event(ReplayEvent::new(ReplayEventType::ConnectionAttempt).with_agent("agent-1"));
        session.add_event(ReplayEvent::new(ReplayEventType::Timeout).with_agent("agent-2"));

        let ids = session.agent_ids();
        assert_eq!(ids, vec!["agent-1", "agent-2"]);
    }

    // ==================== ReplayConfig Tests ====================

    #[test]
    fn test_replay_config_default() {
        let config = ReplayConfig::default();

        assert!(config.include_packets);
        assert!(config.include_timing);
        assert_eq!(config.max_events, 0);
        assert_eq!(config.timeout, Duration::from_secs(300));
    }

    #[test]
    fn test_replay_config_fast() {
        let config = ReplayConfig::fast();

        assert!(!config.include_packets);
        assert!(!config.include_timing);
        assert_eq!(config.max_events, 1000);
        assert_eq!(config.timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_replay_config_detailed() {
        let config = ReplayConfig::detailed();

        assert!(config.include_packets);
        assert!(config.include_timing);
        assert_eq!(config.max_events, 0);
        assert_eq!(config.timeout, Duration::from_secs(600));
    }

    #[test]
    fn test_replay_config_with_classifier_version() {
        let config = ReplayConfig::default().with_classifier_version("v2.1.0");

        assert_eq!(config.classifier_version, Some("v2.1.0".to_string()));
    }

    // ==================== Serialization Tests ====================

    #[test]
    fn test_replay_session_roundtrip() {
        let run_id = Uuid::new_v4();
        let source = ReplaySource::from_logs("/tmp/logs.jsonl");
        let mut session = ReplaySession::new(run_id, source);

        session.start();
        session
            .add_event(ReplayEvent::new(ReplayEventType::ConnectionAttempt).with_agent("agent-1"));
        let classification =
            ClassificationResult::new(FailureCategory::SutConnectivityFailure, 0.9);
        session.complete(classification);

        let json = serde_json::to_string(&session).unwrap();
        let restored: ReplaySession = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.run_id, session.run_id);
        assert_eq!(restored.status, ReplayStatus::Completed);
        assert_eq!(restored.events.len(), 1);
    }

    #[test]
    fn test_classification_result_roundtrip() {
        let result = ClassificationResult::new(FailureCategory::SutConnectivityFailure, 0.9)
            .with_evidence("Evidence 1")
            .with_alternative(FailureCategory::InfrastructureFlake, 0.7);

        let json = serde_json::to_string(&result).unwrap();
        let restored: ClassificationResult = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.failure_category, result.failure_category);
        assert_eq!(restored.evidence.len(), 1);
        assert_eq!(restored.alternatives.len(), 1);
    }
}
