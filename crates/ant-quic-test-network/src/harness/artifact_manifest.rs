use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactManifest {
    pub run_id: Uuid,
    pub attempt_id: u32,
    pub created_at_ms: u64,
    pub agent_id: String,
    pub artifacts: Vec<ArtifactEntry>,
    pub checksums: HashMap<String, String>,
    pub complete: bool,
    pub capture_duration_ms: u64,
}

impl ArtifactManifest {
    pub fn new(run_id: Uuid, attempt_id: u32, agent_id: &str) -> Self {
        Self {
            run_id,
            attempt_id,
            created_at_ms: crate::registry::unix_timestamp_ms(),
            agent_id: agent_id.to_string(),
            artifacts: Vec::new(),
            checksums: HashMap::new(),
            complete: false,
            capture_duration_ms: 0,
        }
    }

    pub fn add_artifact(&mut self, entry: ArtifactEntry) {
        if let Some(checksum) = &entry.sha256 {
            self.checksums.insert(entry.path.clone(), checksum.clone());
        }
        self.artifacts.push(entry);
    }

    pub fn mark_complete(&mut self, capture_duration_ms: u64) {
        self.complete = true;
        self.capture_duration_ms = capture_duration_ms;
    }

    pub fn verify_integrity(&self) -> bool {
        for artifact in &self.artifacts {
            if artifact.required && artifact.sha256.is_none() {
                return false;
            }
        }
        self.complete
    }

    pub fn get_artifact(&self, artifact_type: ArtifactType) -> Option<&ArtifactEntry> {
        self.artifacts
            .iter()
            .find(|a| a.artifact_type == artifact_type)
    }

    pub fn missing_required(&self) -> Vec<ArtifactType> {
        let mut missing = Vec::new();
        let required_types = [ArtifactType::AgentLog, ArtifactType::SutLog];

        for required in required_types {
            if self.get_artifact(required).is_none() {
                missing.push(required);
            }
        }
        missing
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactEntry {
    pub artifact_type: ArtifactType,
    pub path: String,
    pub size_bytes: u64,
    pub sha256: Option<String>,
    pub compressed: bool,
    pub compression_ratio: Option<f32>,
    pub required: bool,
    pub metadata: HashMap<String, String>,
}

impl ArtifactEntry {
    pub fn new(artifact_type: ArtifactType, path: &str) -> Self {
        Self {
            artifact_type,
            path: path.to_string(),
            size_bytes: 0,
            sha256: None,
            compressed: false,
            compression_ratio: None,
            required: artifact_type.is_required(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_size(mut self, size_bytes: u64) -> Self {
        self.size_bytes = size_bytes;
        self
    }

    pub fn with_checksum(mut self, sha256: &str) -> Self {
        self.sha256 = Some(sha256.to_string());
        self
    }

    pub fn with_compression(mut self, ratio: f32) -> Self {
        self.compressed = true;
        self.compression_ratio = Some(ratio);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    AgentLog,
    SutLog,
    Pcap,
    NatState,
    ProcessState,
    MetricsSnapshot,
    ConntrackDump,
    IptablesDump,
    RouteTable,
    SocketList,
    DockerLogs,
    Screenshot,
    Custom,
}

impl ArtifactType {
    pub fn is_required(&self) -> bool {
        matches!(self, Self::AgentLog | Self::SutLog)
    }

    pub fn file_extension(&self) -> &'static str {
        match self {
            Self::AgentLog | Self::SutLog | Self::DockerLogs => "log",
            Self::Pcap => "pcap.zst",
            Self::NatState | Self::ProcessState | Self::MetricsSnapshot => "json",
            Self::ConntrackDump | Self::IptablesDump | Self::RouteTable | Self::SocketList => "txt",
            Self::Screenshot => "png",
            Self::Custom => "bin",
        }
    }

    pub fn default_filename(&self, attempt_id: u32) -> String {
        format!("attempt-{:04}.{}", attempt_id, self.file_extension())
    }
}

impl std::fmt::Display for ArtifactType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AgentLog => write!(f, "Agent Log"),
            Self::SutLog => write!(f, "SUT Log"),
            Self::Pcap => write!(f, "Packet Capture"),
            Self::NatState => write!(f, "NAT State"),
            Self::ProcessState => write!(f, "Process State"),
            Self::MetricsSnapshot => write!(f, "Metrics Snapshot"),
            Self::ConntrackDump => write!(f, "Conntrack Dump"),
            Self::IptablesDump => write!(f, "IPTables Dump"),
            Self::RouteTable => write!(f, "Route Table"),
            Self::SocketList => write!(f, "Socket List"),
            Self::DockerLogs => write!(f, "Docker Logs"),
            Self::Screenshot => write!(f, "Screenshot"),
            Self::Custom => write!(f, "Custom"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatStateCapture {
    pub timestamp_ms: u64,
    pub iptables_nat: String,
    pub iptables_filter: String,
    pub conntrack_entries: Vec<ConntrackEntry>,
    pub nat_type_detected: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConntrackEntry {
    pub protocol: String,
    pub src: String,
    pub dst: String,
    pub sport: u16,
    pub dport: u16,
    pub state: String,
    pub timeout_secs: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessStateCapture {
    pub timestamp_ms: u64,
    pub pids: Vec<ProcessInfo>,
    pub open_sockets: Vec<SocketInfo>,
    pub routes: Vec<RouteInfo>,
    pub memory_mb: u64,
    pub cpu_percent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub memory_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketInfo {
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: Option<String>,
    pub state: String,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteInfo {
    pub destination: String,
    pub gateway: Option<String>,
    pub interface: String,
    pub flags: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactBundle {
    pub manifest: ArtifactManifest,
    pub base_path: PathBuf,
}

impl ArtifactBundle {
    pub fn new(manifest: ArtifactManifest, base_path: PathBuf) -> Self {
        Self {
            manifest,
            base_path,
        }
    }

    pub fn artifact_path(&self, artifact_type: ArtifactType) -> Option<PathBuf> {
        self.manifest
            .get_artifact(artifact_type)
            .map(|entry| self.base_path.join(&entry.path))
    }

    pub fn total_size_bytes(&self) -> u64 {
        self.manifest.artifacts.iter().map(|a| a.size_bytes).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_artifact_manifest_new() {
        let run_id = Uuid::new_v4();
        let manifest = ArtifactManifest::new(run_id, 1, "agent-1");
        assert_eq!(manifest.run_id, run_id);
        assert_eq!(manifest.attempt_id, 1);
        assert!(!manifest.complete);
    }

    #[test]
    fn test_artifact_manifest_add_artifact() {
        let mut manifest = ArtifactManifest::new(Uuid::new_v4(), 1, "agent-1");
        let entry = ArtifactEntry::new(ArtifactType::AgentLog, "logs/agent.log")
            .with_size(1024)
            .with_checksum("abc123");
        manifest.add_artifact(entry);

        assert_eq!(manifest.artifacts.len(), 1);
        assert!(manifest.checksums.contains_key("logs/agent.log"));
    }

    #[test]
    fn test_artifact_type_required() {
        assert!(ArtifactType::AgentLog.is_required());
        assert!(ArtifactType::SutLog.is_required());
        assert!(!ArtifactType::Pcap.is_required());
    }

    #[test]
    fn test_artifact_type_extension() {
        assert_eq!(ArtifactType::AgentLog.file_extension(), "log");
        assert_eq!(ArtifactType::Pcap.file_extension(), "pcap.zst");
        assert_eq!(ArtifactType::NatState.file_extension(), "json");
    }
}
