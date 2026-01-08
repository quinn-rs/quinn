//! Debug Bundle Collection
//!
//! This module provides types for collecting and managing debug artifacts
//! from distributed test runs. Debug bundles can include:
//! - Packet captures (pcaps)
//! - Connection tracking dumps (conntrack)
//! - Docker/container logs
//! - System logs
//! - Core dumps
//! - Configuration snapshots
//!
//! Each bundle is associated with a run and optionally a specific test,
//! allowing for targeted debugging of failures.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// Type of debug artifact
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugArtifactType {
    /// Network packet capture (pcap format)
    PacketCapture,
    /// Connection tracking dump (conntrack)
    ConntrackDump,
    /// Docker container logs
    DockerLogs,
    /// System logs (syslog, journal)
    SystemLogs,
    /// Application logs
    ApplicationLogs,
    /// Core dump from crash
    CoreDump,
    /// Configuration snapshot
    ConfigSnapshot,
    /// Network interface state
    NetworkState,
    /// Process state (ps, top output)
    ProcessState,
    /// Memory dump
    MemoryDump,
    /// Firewall rules (iptables, nftables)
    FirewallRules,
    /// NAT state
    NatState,
    /// Custom artifact type
    Custom(String),
}

impl std::fmt::Display for DebugArtifactType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PacketCapture => write!(f, "pcap"),
            Self::ConntrackDump => write!(f, "conntrack"),
            Self::DockerLogs => write!(f, "docker-logs"),
            Self::SystemLogs => write!(f, "system-logs"),
            Self::ApplicationLogs => write!(f, "app-logs"),
            Self::CoreDump => write!(f, "core-dump"),
            Self::ConfigSnapshot => write!(f, "config"),
            Self::NetworkState => write!(f, "network-state"),
            Self::ProcessState => write!(f, "process-state"),
            Self::MemoryDump => write!(f, "memory-dump"),
            Self::FirewallRules => write!(f, "firewall"),
            Self::NatState => write!(f, "nat-state"),
            Self::Custom(name) => write!(f, "custom-{name}"),
        }
    }
}

/// Compression method used for artifact
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CompressionMethod {
    /// No compression
    #[default]
    None,
    /// Gzip compression
    Gzip,
    /// Zstd compression
    Zstd,
    /// Xz compression
    Xz,
}

/// Status of artifact collection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CollectionStatus {
    /// Collection pending
    #[default]
    Pending,
    /// Currently collecting
    InProgress,
    /// Successfully collected
    Collected,
    /// Collection failed
    Failed,
    /// Artifact not available (e.g., no permission)
    Unavailable,
    /// Artifact skipped (e.g., too large)
    Skipped,
}

impl CollectionStatus {
    /// Check if this is a terminal status
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Collected | Self::Failed | Self::Unavailable | Self::Skipped
        )
    }

    /// Check if collection succeeded
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Collected)
    }
}

/// A single debug artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugArtifact {
    /// Unique ID for this artifact
    pub id: Uuid,
    /// Type of artifact
    pub artifact_type: DebugArtifactType,
    /// Agent that collected this artifact
    pub source_agent: String,
    /// When collection started
    pub collection_started: Option<SystemTime>,
    /// When collection completed
    pub collection_completed: Option<SystemTime>,
    /// Collection status
    pub status: CollectionStatus,
    /// Path to the artifact file (relative to bundle root)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<PathBuf>,
    /// Size in bytes (if collected)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    /// Compression method used
    pub compression: CompressionMethod,
    /// SHA-256 hash of the artifact (for integrity)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256_hash: Option<String>,
    /// Error message if collection failed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    /// Additional metadata
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

impl DebugArtifact {
    /// Create a new artifact in pending state
    pub fn new(artifact_type: DebugArtifactType, source_agent: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            artifact_type,
            source_agent: source_agent.into(),
            collection_started: None,
            collection_completed: None,
            status: CollectionStatus::Pending,
            file_path: None,
            size_bytes: None,
            compression: CompressionMethod::None,
            sha256_hash: None,
            error_message: None,
            metadata: HashMap::new(),
        }
    }

    /// Mark collection as started
    pub fn start_collection(&mut self) {
        self.collection_started = Some(SystemTime::now());
        self.status = CollectionStatus::InProgress;
    }

    /// Mark collection as completed successfully
    pub fn complete_collection(
        &mut self,
        file_path: PathBuf,
        size_bytes: u64,
        sha256_hash: Option<String>,
    ) {
        self.collection_completed = Some(SystemTime::now());
        self.status = CollectionStatus::Collected;
        self.file_path = Some(file_path);
        self.size_bytes = Some(size_bytes);
        self.sha256_hash = sha256_hash;
    }

    /// Mark collection as failed
    pub fn fail_collection(&mut self, error: impl Into<String>) {
        self.collection_completed = Some(SystemTime::now());
        self.status = CollectionStatus::Failed;
        self.error_message = Some(error.into());
    }

    /// Mark artifact as unavailable
    pub fn mark_unavailable(&mut self, reason: impl Into<String>) {
        self.status = CollectionStatus::Unavailable;
        self.error_message = Some(reason.into());
    }

    /// Mark artifact as skipped
    pub fn mark_skipped(&mut self, reason: impl Into<String>) {
        self.status = CollectionStatus::Skipped;
        self.error_message = Some(reason.into());
    }

    /// Get collection duration if available
    pub fn collection_duration(&self) -> Option<Duration> {
        let started = self.collection_started?;
        let completed = self.collection_completed?;
        completed.duration_since(started).ok()
    }

    /// Add metadata key-value pair
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Set compression method
    pub fn with_compression(mut self, compression: CompressionMethod) -> Self {
        self.compression = compression;
        self
    }
}

/// Collection request specifying what to collect
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionRequest {
    /// Request ID
    pub request_id: Uuid,
    /// Run ID this request is for
    pub run_id: Uuid,
    /// Optional test ID for targeted collection
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_id: Option<Uuid>,
    /// Artifact types to collect
    pub artifact_types: Vec<DebugArtifactType>,
    /// Target agents (empty = all agents)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_agents: Vec<String>,
    /// Maximum size per artifact (bytes)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_artifact_size: Option<u64>,
    /// Maximum total bundle size (bytes)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bundle_size: Option<u64>,
    /// Requested compression method
    pub compression: CompressionMethod,
    /// Collection timeout
    #[serde(with = "humantime_serde", default = "default_timeout")]
    pub timeout: Duration,
    /// When request was created
    pub created_at: SystemTime,
}

fn default_timeout() -> Duration {
    Duration::from_secs(300) // 5 minutes
}

impl CollectionRequest {
    /// Create a new collection request
    pub fn new(run_id: Uuid, artifact_types: Vec<DebugArtifactType>) -> Self {
        Self {
            request_id: Uuid::new_v4(),
            run_id,
            test_id: None,
            artifact_types,
            target_agents: Vec::new(),
            max_artifact_size: None,
            max_bundle_size: None,
            compression: CompressionMethod::Gzip,
            timeout: default_timeout(),
            created_at: SystemTime::now(),
        }
    }

    /// Set test ID for targeted collection
    pub fn for_test(mut self, test_id: Uuid) -> Self {
        self.test_id = Some(test_id);
        self
    }

    /// Set target agents
    pub fn with_target_agents(mut self, agents: Vec<String>) -> Self {
        self.target_agents = agents;
        self
    }

    /// Set maximum artifact size
    pub fn with_max_artifact_size(mut self, max_bytes: u64) -> Self {
        self.max_artifact_size = Some(max_bytes);
        self
    }

    /// Set maximum bundle size
    pub fn with_max_bundle_size(mut self, max_bytes: u64) -> Self {
        self.max_bundle_size = Some(max_bytes);
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Check if a specific agent should be collected from
    pub fn should_collect_from(&self, agent_id: &str) -> bool {
        self.target_agents.is_empty() || self.target_agents.contains(&agent_id.to_string())
    }
}

/// Manifest describing the contents of a debug bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    /// Bundle ID
    pub bundle_id: Uuid,
    /// Associated run ID
    pub run_id: Uuid,
    /// Associated test ID (if targeted)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_id: Option<Uuid>,
    /// When bundle creation started
    pub created_at: SystemTime,
    /// When bundle was finalized
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalized_at: Option<SystemTime>,
    /// All artifacts in the bundle
    pub artifacts: Vec<DebugArtifact>,
    /// Total size of all artifacts (bytes)
    pub total_size_bytes: u64,
    /// Number of artifacts collected successfully
    pub artifacts_collected: usize,
    /// Number of artifacts that failed
    pub artifacts_failed: usize,
    /// Agents that contributed to this bundle
    pub contributing_agents: Vec<String>,
    /// Bundle-level metadata
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

impl BundleManifest {
    /// Create a new empty manifest
    pub fn new(run_id: Uuid) -> Self {
        Self {
            bundle_id: Uuid::new_v4(),
            run_id,
            test_id: None,
            created_at: SystemTime::now(),
            finalized_at: None,
            artifacts: Vec::new(),
            total_size_bytes: 0,
            artifacts_collected: 0,
            artifacts_failed: 0,
            contributing_agents: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Create manifest for a specific test
    pub fn for_test(run_id: Uuid, test_id: Uuid) -> Self {
        let mut manifest = Self::new(run_id);
        manifest.test_id = Some(test_id);
        manifest
    }

    /// Add an artifact to the manifest
    pub fn add_artifact(&mut self, artifact: DebugArtifact) {
        // Update contributing agents
        if !self.contributing_agents.contains(&artifact.source_agent) {
            self.contributing_agents.push(artifact.source_agent.clone());
        }

        // Update counters
        match artifact.status {
            CollectionStatus::Collected => {
                self.artifacts_collected += 1;
                if let Some(size) = artifact.size_bytes {
                    self.total_size_bytes += size;
                }
            }
            CollectionStatus::Failed => {
                self.artifacts_failed += 1;
            }
            _ => {}
        }

        self.artifacts.push(artifact);
    }

    /// Finalize the manifest
    pub fn finalize(&mut self) {
        self.finalized_at = Some(SystemTime::now());
        self.contributing_agents.sort();
    }

    /// Get artifacts by type
    pub fn artifacts_by_type(&self, artifact_type: &DebugArtifactType) -> Vec<&DebugArtifact> {
        self.artifacts
            .iter()
            .filter(|a| &a.artifact_type == artifact_type)
            .collect()
    }

    /// Get artifacts from a specific agent
    pub fn artifacts_from_agent(&self, agent_id: &str) -> Vec<&DebugArtifact> {
        self.artifacts
            .iter()
            .filter(|a| a.source_agent == agent_id)
            .collect()
    }

    /// Get all successfully collected artifacts
    pub fn collected_artifacts(&self) -> Vec<&DebugArtifact> {
        self.artifacts
            .iter()
            .filter(|a| a.status.is_success())
            .collect()
    }

    /// Get all failed artifacts
    pub fn failed_artifacts(&self) -> Vec<&DebugArtifact> {
        self.artifacts
            .iter()
            .filter(|a| a.status == CollectionStatus::Failed)
            .collect()
    }

    /// Check if bundle has any pcaps
    pub fn has_pcaps(&self) -> bool {
        self.artifacts
            .iter()
            .any(|a| a.artifact_type == DebugArtifactType::PacketCapture && a.status.is_success())
    }

    /// Check if bundle has any logs
    pub fn has_logs(&self) -> bool {
        self.artifacts.iter().any(|a| {
            matches!(
                a.artifact_type,
                DebugArtifactType::DockerLogs
                    | DebugArtifactType::SystemLogs
                    | DebugArtifactType::ApplicationLogs
            ) && a.status.is_success()
        })
    }

    /// Get collection success rate (0.0-1.0)
    pub fn success_rate(&self) -> f64 {
        let total = self.artifacts_collected + self.artifacts_failed;
        if total == 0 {
            return 1.0; // No artifacts requested
        }
        self.artifacts_collected as f64 / total as f64
    }

    /// Check if bundle is complete (all artifacts terminal)
    pub fn is_complete(&self) -> bool {
        self.artifacts.iter().all(|a| a.status.is_terminal())
    }

    /// Add metadata to the bundle
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Complete debug bundle containing manifest and artifact references
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugBundle {
    /// Bundle manifest
    pub manifest: BundleManifest,
    /// Root path where artifacts are stored
    pub root_path: PathBuf,
    /// Whether bundle has been finalized
    pub is_finalized: bool,
}

impl DebugBundle {
    /// Create a new debug bundle
    pub fn new(run_id: Uuid, root_path: PathBuf) -> Self {
        Self {
            manifest: BundleManifest::new(run_id),
            root_path,
            is_finalized: false,
        }
    }

    /// Create a bundle for a specific test
    pub fn for_test(run_id: Uuid, test_id: Uuid, root_path: PathBuf) -> Self {
        Self {
            manifest: BundleManifest::for_test(run_id, test_id),
            root_path,
            is_finalized: false,
        }
    }

    /// Get the bundle ID
    pub fn bundle_id(&self) -> Uuid {
        self.manifest.bundle_id
    }

    /// Add an artifact to the bundle
    pub fn add_artifact(&mut self, artifact: DebugArtifact) {
        if !self.is_finalized {
            self.manifest.add_artifact(artifact);
        }
    }

    /// Finalize the bundle
    pub fn finalize(&mut self) {
        if !self.is_finalized {
            self.manifest.finalize();
            self.is_finalized = true;
        }
    }

    /// Get the path for a new artifact
    pub fn artifact_path(&self, artifact_type: &DebugArtifactType, agent_id: &str) -> PathBuf {
        self.root_path
            .join(agent_id)
            .join(format!("{}.dat", artifact_type))
    }

    /// Get total size
    pub fn total_size(&self) -> u64 {
        self.manifest.total_size_bytes
    }

    /// Get artifacts count
    pub fn artifact_count(&self) -> usize {
        self.manifest.artifacts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== DebugArtifactType Tests ====================

    #[test]
    fn test_artifact_type_display() {
        assert_eq!(format!("{}", DebugArtifactType::PacketCapture), "pcap");
        assert_eq!(format!("{}", DebugArtifactType::ConntrackDump), "conntrack");
        assert_eq!(format!("{}", DebugArtifactType::DockerLogs), "docker-logs");
        assert_eq!(
            format!("{}", DebugArtifactType::Custom("test".to_string())),
            "custom-test"
        );
    }

    #[test]
    fn test_artifact_type_serialization() {
        let json = serde_json::to_string(&DebugArtifactType::PacketCapture).unwrap();
        assert_eq!(json, "\"packet_capture\"");

        let restored: DebugArtifactType = serde_json::from_str("\"docker_logs\"").unwrap();
        assert_eq!(restored, DebugArtifactType::DockerLogs);
    }

    // ==================== CollectionStatus Tests ====================

    #[test]
    fn test_collection_status_default() {
        assert_eq!(CollectionStatus::default(), CollectionStatus::Pending);
    }

    #[test]
    fn test_collection_status_is_terminal() {
        assert!(!CollectionStatus::Pending.is_terminal());
        assert!(!CollectionStatus::InProgress.is_terminal());
        assert!(CollectionStatus::Collected.is_terminal());
        assert!(CollectionStatus::Failed.is_terminal());
        assert!(CollectionStatus::Unavailable.is_terminal());
        assert!(CollectionStatus::Skipped.is_terminal());
    }

    #[test]
    fn test_collection_status_is_success() {
        assert!(!CollectionStatus::Pending.is_success());
        assert!(!CollectionStatus::Failed.is_success());
        assert!(CollectionStatus::Collected.is_success());
    }

    // ==================== DebugArtifact Tests ====================

    #[test]
    fn test_artifact_new() {
        let artifact = DebugArtifact::new(DebugArtifactType::PacketCapture, "agent-1");

        assert_eq!(artifact.artifact_type, DebugArtifactType::PacketCapture);
        assert_eq!(artifact.source_agent, "agent-1");
        assert_eq!(artifact.status, CollectionStatus::Pending);
        assert!(artifact.collection_started.is_none());
        assert!(artifact.file_path.is_none());
    }

    #[test]
    fn test_artifact_start_collection() {
        let mut artifact = DebugArtifact::new(DebugArtifactType::PacketCapture, "agent-1");
        artifact.start_collection();

        assert_eq!(artifact.status, CollectionStatus::InProgress);
        assert!(artifact.collection_started.is_some());
    }

    #[test]
    fn test_artifact_complete_collection() {
        let mut artifact = DebugArtifact::new(DebugArtifactType::PacketCapture, "agent-1");
        artifact.start_collection();
        artifact.complete_collection(
            PathBuf::from("agent-1/capture.pcap"),
            1024,
            Some("abc123".to_string()),
        );

        assert_eq!(artifact.status, CollectionStatus::Collected);
        assert!(artifact.collection_completed.is_some());
        assert_eq!(
            artifact.file_path,
            Some(PathBuf::from("agent-1/capture.pcap"))
        );
        assert_eq!(artifact.size_bytes, Some(1024));
        assert_eq!(artifact.sha256_hash, Some("abc123".to_string()));
    }

    #[test]
    fn test_artifact_fail_collection() {
        let mut artifact = DebugArtifact::new(DebugArtifactType::PacketCapture, "agent-1");
        artifact.start_collection();
        artifact.fail_collection("Permission denied");

        assert_eq!(artifact.status, CollectionStatus::Failed);
        assert_eq!(
            artifact.error_message,
            Some("Permission denied".to_string())
        );
    }

    #[test]
    fn test_artifact_mark_unavailable() {
        let mut artifact = DebugArtifact::new(DebugArtifactType::CoreDump, "agent-1");
        artifact.mark_unavailable("No crash occurred");

        assert_eq!(artifact.status, CollectionStatus::Unavailable);
        assert_eq!(
            artifact.error_message,
            Some("No crash occurred".to_string())
        );
    }

    #[test]
    fn test_artifact_mark_skipped() {
        let mut artifact = DebugArtifact::new(DebugArtifactType::PacketCapture, "agent-1");
        artifact.mark_skipped("File too large");

        assert_eq!(artifact.status, CollectionStatus::Skipped);
    }

    #[test]
    fn test_artifact_collection_duration() {
        let mut artifact = DebugArtifact::new(DebugArtifactType::PacketCapture, "agent-1");

        // No duration before start
        assert!(artifact.collection_duration().is_none());

        artifact.start_collection();
        // No duration before completion
        assert!(artifact.collection_duration().is_none());

        artifact.complete_collection(PathBuf::from("test.pcap"), 100, None);
        // Now we have a duration
        assert!(artifact.collection_duration().is_some());
    }

    #[test]
    fn test_artifact_with_metadata() {
        let artifact = DebugArtifact::new(DebugArtifactType::PacketCapture, "agent-1")
            .with_metadata("interface", "eth0")
            .with_metadata("filter", "port 9000");

        assert_eq!(
            artifact.metadata.get("interface"),
            Some(&"eth0".to_string())
        );
        assert_eq!(
            artifact.metadata.get("filter"),
            Some(&"port 9000".to_string())
        );
    }

    #[test]
    fn test_artifact_with_compression() {
        let artifact = DebugArtifact::new(DebugArtifactType::PacketCapture, "agent-1")
            .with_compression(CompressionMethod::Gzip);

        assert_eq!(artifact.compression, CompressionMethod::Gzip);
    }

    // ==================== CollectionRequest Tests ====================

    #[test]
    fn test_collection_request_new() {
        let run_id = Uuid::new_v4();
        let request = CollectionRequest::new(
            run_id,
            vec![
                DebugArtifactType::PacketCapture,
                DebugArtifactType::DockerLogs,
            ],
        );

        assert_eq!(request.run_id, run_id);
        assert_eq!(request.artifact_types.len(), 2);
        assert!(request.test_id.is_none());
        assert!(request.target_agents.is_empty());
        assert_eq!(request.compression, CompressionMethod::Gzip);
    }

    #[test]
    fn test_collection_request_for_test() {
        let run_id = Uuid::new_v4();
        let test_id = Uuid::new_v4();
        let request = CollectionRequest::new(run_id, vec![DebugArtifactType::PacketCapture])
            .for_test(test_id);

        assert_eq!(request.test_id, Some(test_id));
    }

    #[test]
    fn test_collection_request_with_target_agents() {
        let run_id = Uuid::new_v4();
        let request = CollectionRequest::new(run_id, vec![DebugArtifactType::PacketCapture])
            .with_target_agents(vec!["agent-1".to_string(), "agent-2".to_string()]);

        assert_eq!(request.target_agents.len(), 2);
    }

    #[test]
    fn test_collection_request_should_collect_from() {
        let run_id = Uuid::new_v4();

        // Empty target_agents means collect from all
        let request = CollectionRequest::new(run_id, vec![DebugArtifactType::PacketCapture]);
        assert!(request.should_collect_from("agent-1"));
        assert!(request.should_collect_from("agent-99"));

        // With specific targets
        let request = CollectionRequest::new(run_id, vec![DebugArtifactType::PacketCapture])
            .with_target_agents(vec!["agent-1".to_string()]);
        assert!(request.should_collect_from("agent-1"));
        assert!(!request.should_collect_from("agent-2"));
    }

    #[test]
    fn test_collection_request_with_limits() {
        let run_id = Uuid::new_v4();
        let request = CollectionRequest::new(run_id, vec![DebugArtifactType::PacketCapture])
            .with_max_artifact_size(1024 * 1024)
            .with_max_bundle_size(10 * 1024 * 1024);

        assert_eq!(request.max_artifact_size, Some(1024 * 1024));
        assert_eq!(request.max_bundle_size, Some(10 * 1024 * 1024));
    }

    #[test]
    fn test_collection_request_with_timeout() {
        let run_id = Uuid::new_v4();
        let request = CollectionRequest::new(run_id, vec![DebugArtifactType::PacketCapture])
            .with_timeout(Duration::from_secs(60));

        assert_eq!(request.timeout, Duration::from_secs(60));
    }

    // ==================== BundleManifest Tests ====================

    #[test]
    fn test_bundle_manifest_new() {
        let run_id = Uuid::new_v4();
        let manifest = BundleManifest::new(run_id);

        assert_eq!(manifest.run_id, run_id);
        assert!(manifest.test_id.is_none());
        assert!(manifest.artifacts.is_empty());
        assert_eq!(manifest.total_size_bytes, 0);
        assert_eq!(manifest.artifacts_collected, 0);
        assert_eq!(manifest.artifacts_failed, 0);
    }

    #[test]
    fn test_bundle_manifest_for_test() {
        let run_id = Uuid::new_v4();
        let test_id = Uuid::new_v4();
        let manifest = BundleManifest::for_test(run_id, test_id);

        assert_eq!(manifest.test_id, Some(test_id));
    }

    #[test]
    fn test_bundle_manifest_add_artifact() {
        let run_id = Uuid::new_v4();
        let mut manifest = BundleManifest::new(run_id);

        let mut artifact = DebugArtifact::new(DebugArtifactType::PacketCapture, "agent-1");
        artifact.start_collection();
        artifact.complete_collection(PathBuf::from("test.pcap"), 1024, None);

        manifest.add_artifact(artifact);

        assert_eq!(manifest.artifacts.len(), 1);
        assert_eq!(manifest.artifacts_collected, 1);
        assert_eq!(manifest.total_size_bytes, 1024);
        assert!(
            manifest
                .contributing_agents
                .contains(&"agent-1".to_string())
        );
    }

    #[test]
    fn test_bundle_manifest_add_failed_artifact() {
        let run_id = Uuid::new_v4();
        let mut manifest = BundleManifest::new(run_id);

        let mut artifact = DebugArtifact::new(DebugArtifactType::PacketCapture, "agent-1");
        artifact.fail_collection("Error");

        manifest.add_artifact(artifact);

        assert_eq!(manifest.artifacts_failed, 1);
        assert_eq!(manifest.artifacts_collected, 0);
    }

    #[test]
    fn test_bundle_manifest_finalize() {
        let run_id = Uuid::new_v4();
        let mut manifest = BundleManifest::new(run_id);

        let mut artifact = DebugArtifact::new(DebugArtifactType::PacketCapture, "agent-1");
        artifact.complete_collection(PathBuf::from("test.pcap"), 100, None);
        manifest.add_artifact(artifact);

        assert!(manifest.finalized_at.is_none());
        manifest.finalize();
        assert!(manifest.finalized_at.is_some());
    }

    #[test]
    fn test_bundle_manifest_artifacts_by_type() {
        let run_id = Uuid::new_v4();
        let mut manifest = BundleManifest::new(run_id);

        let mut pcap = DebugArtifact::new(DebugArtifactType::PacketCapture, "agent-1");
        pcap.complete_collection(PathBuf::from("test.pcap"), 100, None);
        manifest.add_artifact(pcap);

        let mut logs = DebugArtifact::new(DebugArtifactType::DockerLogs, "agent-1");
        logs.complete_collection(PathBuf::from("logs.txt"), 50, None);
        manifest.add_artifact(logs);

        let pcaps = manifest.artifacts_by_type(&DebugArtifactType::PacketCapture);
        assert_eq!(pcaps.len(), 1);

        let docker_logs = manifest.artifacts_by_type(&DebugArtifactType::DockerLogs);
        assert_eq!(docker_logs.len(), 1);
    }

    #[test]
    fn test_bundle_manifest_artifacts_from_agent() {
        let run_id = Uuid::new_v4();
        let mut manifest = BundleManifest::new(run_id);

        let mut a1 = DebugArtifact::new(DebugArtifactType::PacketCapture, "agent-1");
        a1.complete_collection(PathBuf::from("a1.pcap"), 100, None);
        manifest.add_artifact(a1);

        let mut a2 = DebugArtifact::new(DebugArtifactType::PacketCapture, "agent-2");
        a2.complete_collection(PathBuf::from("a2.pcap"), 100, None);
        manifest.add_artifact(a2);

        let agent1_artifacts = manifest.artifacts_from_agent("agent-1");
        assert_eq!(agent1_artifacts.len(), 1);
    }

    #[test]
    fn test_bundle_manifest_has_pcaps() {
        let run_id = Uuid::new_v4();
        let mut manifest = BundleManifest::new(run_id);
        assert!(!manifest.has_pcaps());

        let mut pcap = DebugArtifact::new(DebugArtifactType::PacketCapture, "agent-1");
        pcap.complete_collection(PathBuf::from("test.pcap"), 100, None);
        manifest.add_artifact(pcap);

        assert!(manifest.has_pcaps());
    }

    #[test]
    fn test_bundle_manifest_has_logs() {
        let run_id = Uuid::new_v4();
        let mut manifest = BundleManifest::new(run_id);
        assert!(!manifest.has_logs());

        let mut logs = DebugArtifact::new(DebugArtifactType::DockerLogs, "agent-1");
        logs.complete_collection(PathBuf::from("logs.txt"), 100, None);
        manifest.add_artifact(logs);

        assert!(manifest.has_logs());
    }

    #[test]
    fn test_bundle_manifest_success_rate() {
        let run_id = Uuid::new_v4();
        let mut manifest = BundleManifest::new(run_id);

        // No artifacts = 100% success
        assert_eq!(manifest.success_rate(), 1.0);

        // One success
        let mut a1 = DebugArtifact::new(DebugArtifactType::PacketCapture, "agent-1");
        a1.complete_collection(PathBuf::from("a1.pcap"), 100, None);
        manifest.add_artifact(a1);
        assert_eq!(manifest.success_rate(), 1.0);

        // One failure
        let mut a2 = DebugArtifact::new(DebugArtifactType::DockerLogs, "agent-1");
        a2.fail_collection("Error");
        manifest.add_artifact(a2);
        assert_eq!(manifest.success_rate(), 0.5);
    }

    #[test]
    fn test_bundle_manifest_is_complete() {
        let run_id = Uuid::new_v4();
        let mut manifest = BundleManifest::new(run_id);

        // Empty is complete
        assert!(manifest.is_complete());

        // Pending artifact = not complete
        let pending = DebugArtifact::new(DebugArtifactType::PacketCapture, "agent-1");
        manifest.add_artifact(pending);
        assert!(!manifest.is_complete());
    }

    #[test]
    fn test_bundle_manifest_is_complete_with_terminal() {
        let run_id = Uuid::new_v4();
        let mut manifest = BundleManifest::new(run_id);

        let mut collected = DebugArtifact::new(DebugArtifactType::PacketCapture, "agent-1");
        collected.complete_collection(PathBuf::from("a.pcap"), 100, None);
        manifest.add_artifact(collected);

        let mut failed = DebugArtifact::new(DebugArtifactType::DockerLogs, "agent-1");
        failed.fail_collection("Error");
        manifest.add_artifact(failed);

        assert!(manifest.is_complete());
    }

    // ==================== DebugBundle Tests ====================

    #[test]
    fn test_debug_bundle_new() {
        let run_id = Uuid::new_v4();
        let bundle = DebugBundle::new(run_id, PathBuf::from("/tmp/debug"));

        assert_eq!(bundle.manifest.run_id, run_id);
        assert_eq!(bundle.root_path, PathBuf::from("/tmp/debug"));
        assert!(!bundle.is_finalized);
    }

    #[test]
    fn test_debug_bundle_for_test() {
        let run_id = Uuid::new_v4();
        let test_id = Uuid::new_v4();
        let bundle = DebugBundle::for_test(run_id, test_id, PathBuf::from("/tmp/debug"));

        assert_eq!(bundle.manifest.test_id, Some(test_id));
    }

    #[test]
    fn test_debug_bundle_add_artifact() {
        let run_id = Uuid::new_v4();
        let mut bundle = DebugBundle::new(run_id, PathBuf::from("/tmp/debug"));

        let mut artifact = DebugArtifact::new(DebugArtifactType::PacketCapture, "agent-1");
        artifact.complete_collection(PathBuf::from("test.pcap"), 100, None);
        bundle.add_artifact(artifact);

        assert_eq!(bundle.artifact_count(), 1);
        assert_eq!(bundle.total_size(), 100);
    }

    #[test]
    fn test_debug_bundle_finalize() {
        let run_id = Uuid::new_v4();
        let mut bundle = DebugBundle::new(run_id, PathBuf::from("/tmp/debug"));

        bundle.finalize();
        assert!(bundle.is_finalized);
        assert!(bundle.manifest.finalized_at.is_some());

        // Should not allow adding after finalize
        let artifact = DebugArtifact::new(DebugArtifactType::PacketCapture, "agent-1");
        bundle.add_artifact(artifact);
        assert_eq!(bundle.artifact_count(), 0); // Not added
    }

    #[test]
    fn test_debug_bundle_artifact_path() {
        let run_id = Uuid::new_v4();
        let bundle = DebugBundle::new(run_id, PathBuf::from("/tmp/debug"));

        let path = bundle.artifact_path(&DebugArtifactType::PacketCapture, "agent-1");
        assert_eq!(path, PathBuf::from("/tmp/debug/agent-1/pcap.dat"));
    }

    #[test]
    fn test_debug_bundle_bundle_id() {
        let run_id = Uuid::new_v4();
        let bundle = DebugBundle::new(run_id, PathBuf::from("/tmp/debug"));

        let id = bundle.bundle_id();
        assert_eq!(id, bundle.manifest.bundle_id);
    }

    // ==================== Serialization Tests ====================

    #[test]
    fn test_artifact_roundtrip() {
        let mut artifact = DebugArtifact::new(DebugArtifactType::PacketCapture, "agent-1")
            .with_metadata("test", "value")
            .with_compression(CompressionMethod::Gzip);
        artifact.start_collection();
        artifact.complete_collection(
            PathBuf::from("test.pcap"),
            1024,
            Some("hash123".to_string()),
        );

        let json = serde_json::to_string(&artifact).unwrap();
        let restored: DebugArtifact = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.artifact_type, artifact.artifact_type);
        assert_eq!(restored.source_agent, artifact.source_agent);
        assert_eq!(restored.status, artifact.status);
        assert_eq!(restored.size_bytes, artifact.size_bytes);
    }

    #[test]
    fn test_manifest_roundtrip() {
        let run_id = Uuid::new_v4();
        let mut manifest = BundleManifest::new(run_id);

        let mut artifact = DebugArtifact::new(DebugArtifactType::PacketCapture, "agent-1");
        artifact.complete_collection(PathBuf::from("test.pcap"), 1024, None);
        manifest.add_artifact(artifact);
        manifest.finalize();

        let json = serde_json::to_string(&manifest).unwrap();
        let restored: BundleManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.run_id, manifest.run_id);
        assert_eq!(restored.artifacts.len(), 1);
        assert_eq!(restored.artifacts_collected, 1);
    }
}
