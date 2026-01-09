//! Structured Logging with Run/Test/Agent Correlation
//!
//! This module provides structured log entries that include correlation IDs
//! for tracking logs across distributed test runs. Each log entry contains:
//! - Run ID: Identifies the overall test run
//! - Test ID: Identifies the specific test within the run
//! - Agent ID: Identifies which agent generated the log
//!
//! Logs can be serialized to JSON for transport and aggregation.

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// Log severity level
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogLevel {
    /// Detailed debugging information
    Trace,
    /// Debugging information
    Debug,
    /// Informational messages
    #[default]
    Info,
    /// Warning conditions
    Warn,
    /// Error conditions
    Error,
    /// Critical failures
    Fatal,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Trace => write!(f, "TRACE"),
            Self::Debug => write!(f, "DEBUG"),
            Self::Info => write!(f, "INFO"),
            Self::Warn => write!(f, "WARN"),
            Self::Error => write!(f, "ERROR"),
            Self::Fatal => write!(f, "FATAL"),
        }
    }
}

/// Correlation context for linking logs across distributed components
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LogContext {
    /// Unique identifier for the entire test run
    pub run_id: Uuid,
    /// Unique identifier for the specific test (optional for run-level logs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_id: Option<Uuid>,
    /// Identifier of the agent that generated this log
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Stage of the test execution
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
}

impl LogContext {
    /// Create a new context with just a run ID
    pub fn for_run(run_id: Uuid) -> Self {
        Self {
            run_id,
            test_id: None,
            agent_id: None,
            stage: None,
        }
    }

    /// Create a context with run and test IDs
    pub fn for_test(run_id: Uuid, test_id: Uuid) -> Self {
        Self {
            run_id,
            test_id: Some(test_id),
            agent_id: None,
            stage: None,
        }
    }

    /// Create a context with run, test, and agent IDs
    pub fn for_agent(run_id: Uuid, test_id: Uuid, agent_id: impl Into<String>) -> Self {
        Self {
            run_id,
            test_id: Some(test_id),
            agent_id: Some(agent_id.into()),
            stage: None,
        }
    }

    /// Add stage information to the context
    pub fn with_stage(mut self, stage: impl Into<String>) -> Self {
        self.stage = Some(stage.into());
        self
    }

    /// Create a child context for a specific test
    pub fn child_for_test(&self, test_id: Uuid) -> Self {
        Self {
            run_id: self.run_id,
            test_id: Some(test_id),
            agent_id: self.agent_id.clone(),
            stage: self.stage.clone(),
        }
    }

    /// Create a child context for a specific agent
    pub fn child_for_agent(&self, agent_id: impl Into<String>) -> Self {
        Self {
            run_id: self.run_id,
            test_id: self.test_id,
            agent_id: Some(agent_id.into()),
            stage: self.stage.clone(),
        }
    }
}

/// Log category for filtering and routing
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LogCategory {
    /// Harness coordination events
    #[default]
    Harness,
    /// Agent lifecycle events
    Agent,
    /// Network/connection events
    Network,
    /// Test execution events
    Test,
    /// Performance/timing events
    Performance,
    /// Security/authentication events
    Security,
    /// Resource usage events
    Resource,
    /// Custom category
    Custom(String),
}

/// Structured log entry with correlation IDs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredLogEntry {
    /// Unique ID for this log entry
    pub id: Uuid,
    /// Timestamp when the log was created
    pub timestamp: SystemTime,
    /// Correlation context
    pub context: LogContext,
    /// Log severity level
    pub level: LogLevel,
    /// Log category for filtering
    pub category: LogCategory,
    /// Human-readable message
    pub message: String,
    /// Structured data fields
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub fields: std::collections::HashMap<String, serde_json::Value>,
    /// Source file (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
    /// Source line number (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_line: Option<u32>,
}

impl StructuredLogEntry {
    /// Create a new log entry
    pub fn new(context: LogContext, level: LogLevel, message: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: SystemTime::now(),
            context,
            level,
            category: LogCategory::default(),
            message: message.into(),
            fields: std::collections::HashMap::new(),
            source_file: None,
            source_line: None,
        }
    }

    /// Set the category
    pub fn with_category(mut self, category: LogCategory) -> Self {
        self.category = category;
        self
    }

    /// Add a field to the log entry, returning an error if serialization fails.
    ///
    /// This is the preferred method as it makes serialization failures explicit.
    pub fn try_with_field(
        mut self,
        key: impl Into<String>,
        value: impl Serialize,
    ) -> Result<Self, serde_json::Error> {
        let v = serde_json::to_value(value)?;
        self.fields.insert(key.into(), v);
        Ok(self)
    }

    /// Add a field to the log entry, silently dropping serialization failures.
    ///
    /// **DEPRECATED**: This method silently drops serialization errors, which can
    /// cause data loss without any indication. Use `try_with_field()` instead.
    #[deprecated(
        since = "0.2.0",
        note = "Use try_with_field() to handle serialization errors explicitly"
    )]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.fields.insert(key.into(), v);
        }
        self
    }

    /// Add source location
    pub fn with_source(mut self, file: impl Into<String>, line: u32) -> Self {
        self.source_file = Some(file.into());
        self.source_line = Some(line);
        self
    }

    /// Check if this is an error or higher level
    pub fn is_error(&self) -> bool {
        self.level >= LogLevel::Error
    }

    /// Check if this is a warning or higher level
    pub fn is_warning_or_higher(&self) -> bool {
        self.level >= LogLevel::Warn
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialize to pretty JSON string
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// A batch of log entries for efficient transport
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogBatch {
    /// The log entries in this batch
    pub entries: Vec<StructuredLogEntry>,
    /// When this batch was created
    pub created_at: Option<SystemTime>,
    /// Source agent (if from a single agent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_agent: Option<String>,
}

impl LogBatch {
    /// Create a new empty batch
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            created_at: Some(SystemTime::now()),
            source_agent: None,
        }
    }

    /// Create a batch from an agent
    pub fn from_agent(agent_id: impl Into<String>) -> Self {
        Self {
            entries: Vec::new(),
            created_at: Some(SystemTime::now()),
            source_agent: Some(agent_id.into()),
        }
    }

    /// Add an entry to the batch
    pub fn add(&mut self, entry: StructuredLogEntry) {
        self.entries.push(entry);
    }

    /// Check if the batch is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Filter entries by level
    pub fn filter_by_level(&self, min_level: LogLevel) -> Vec<&StructuredLogEntry> {
        self.entries
            .iter()
            .filter(|e| e.level >= min_level)
            .collect()
    }

    /// Filter entries by category
    pub fn filter_by_category(&self, category: &LogCategory) -> Vec<&StructuredLogEntry> {
        self.entries
            .iter()
            .filter(|e| &e.category == category)
            .collect()
    }

    /// Filter entries by run ID
    pub fn filter_by_run(&self, run_id: Uuid) -> Vec<&StructuredLogEntry> {
        self.entries
            .iter()
            .filter(|e| e.context.run_id == run_id)
            .collect()
    }

    /// Filter entries by test ID
    pub fn filter_by_test(&self, test_id: Uuid) -> Vec<&StructuredLogEntry> {
        self.entries
            .iter()
            .filter(|e| e.context.test_id == Some(test_id))
            .collect()
    }

    /// Filter entries by agent ID
    pub fn filter_by_agent(&self, agent_id: &str) -> Vec<&StructuredLogEntry> {
        self.entries
            .iter()
            .filter(|e| e.context.agent_id.as_deref() == Some(agent_id))
            .collect()
    }

    /// Get all errors in this batch
    pub fn errors(&self) -> Vec<&StructuredLogEntry> {
        self.filter_by_level(LogLevel::Error)
    }

    /// Get time span covered by this batch
    pub fn time_span(&self) -> Option<Duration> {
        if self.entries.len() < 2 {
            return None;
        }
        let times: Vec<_> = self.entries.iter().map(|e| e.timestamp).collect();
        let min = times.iter().min()?;
        let max = times.iter().max()?;
        max.duration_since(*min).ok()
    }

    /// Serialize to JSON Lines format (one entry per line)
    pub fn to_jsonl(&self) -> Result<String, serde_json::Error> {
        let mut lines = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            lines.push(serde_json::to_string(entry)?);
        }
        Ok(lines.join("\n"))
    }

    /// Parse from JSON Lines format
    pub fn from_jsonl(jsonl: &str) -> Result<Self, serde_json::Error> {
        let mut entries = Vec::new();
        for line in jsonl.lines() {
            if !line.trim().is_empty() {
                entries.push(serde_json::from_str(line)?);
            }
        }
        Ok(Self {
            entries,
            created_at: Some(SystemTime::now()),
            source_agent: None,
        })
    }
}

/// Log aggregator for combining logs from multiple agents
#[derive(Debug, Default)]
pub struct LogAggregator {
    /// All collected entries
    entries: Vec<StructuredLogEntry>,
    /// Run ID being aggregated
    run_id: Option<Uuid>,
}

impl LogAggregator {
    /// Create a new aggregator
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an aggregator for a specific run
    pub fn for_run(run_id: Uuid) -> Self {
        Self {
            entries: Vec::new(),
            run_id: Some(run_id),
        }
    }

    /// Add a batch of logs
    pub fn add_batch(&mut self, batch: LogBatch) {
        for entry in batch.entries {
            // If we have a run_id filter, only accept matching entries
            if let Some(run_id) = self.run_id {
                if entry.context.run_id == run_id {
                    self.entries.push(entry);
                }
            } else {
                self.entries.push(entry);
            }
        }
    }

    /// Add a single entry
    pub fn add_entry(&mut self, entry: StructuredLogEntry) {
        if let Some(run_id) = self.run_id {
            if entry.context.run_id == run_id {
                self.entries.push(entry);
            }
        } else {
            self.entries.push(entry);
        }
    }

    /// Get all entries sorted by timestamp
    pub fn sorted_entries(&self) -> Vec<&StructuredLogEntry> {
        let mut entries: Vec<_> = self.entries.iter().collect();
        entries.sort_by_key(|e| e.timestamp);
        entries
    }

    /// Get entries for a specific test
    pub fn entries_for_test(&self, test_id: Uuid) -> Vec<&StructuredLogEntry> {
        self.entries
            .iter()
            .filter(|e| e.context.test_id == Some(test_id))
            .collect()
    }

    /// Get entries for a specific agent
    pub fn entries_for_agent(&self, agent_id: &str) -> Vec<&StructuredLogEntry> {
        self.entries
            .iter()
            .filter(|e| e.context.agent_id.as_deref() == Some(agent_id))
            .collect()
    }

    /// Get all unique agent IDs
    pub fn agent_ids(&self) -> Vec<String> {
        let mut ids: Vec<_> = self
            .entries
            .iter()
            .filter_map(|e| e.context.agent_id.clone())
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// Get all unique test IDs
    pub fn test_ids(&self) -> Vec<Uuid> {
        let mut ids: Vec<_> = self
            .entries
            .iter()
            .filter_map(|e| e.context.test_id)
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// Get error summary grouped by category
    pub fn error_summary(&self) -> std::collections::HashMap<LogCategory, usize> {
        let mut summary = std::collections::HashMap::new();
        for entry in &self.entries {
            if entry.is_error() {
                *summary.entry(entry.category.clone()).or_insert(0) += 1;
            }
        }
        summary
    }

    /// Get total entry count
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Export to a LogBatch
    pub fn to_batch(&self) -> LogBatch {
        LogBatch {
            entries: self.entries.clone(),
            created_at: Some(SystemTime::now()),
            source_agent: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== LogLevel Tests ====================

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
        assert!(LogLevel::Error < LogLevel::Fatal);
    }

    #[test]
    fn test_log_level_display() {
        assert_eq!(format!("{}", LogLevel::Trace), "TRACE");
        assert_eq!(format!("{}", LogLevel::Debug), "DEBUG");
        assert_eq!(format!("{}", LogLevel::Info), "INFO");
        assert_eq!(format!("{}", LogLevel::Warn), "WARN");
        assert_eq!(format!("{}", LogLevel::Error), "ERROR");
        assert_eq!(format!("{}", LogLevel::Fatal), "FATAL");
    }

    #[test]
    fn test_log_level_default() {
        assert_eq!(LogLevel::default(), LogLevel::Info);
    }

    #[test]
    fn test_log_level_serialization() {
        let json = serde_json::to_string(&LogLevel::Error).unwrap();
        assert_eq!(json, "\"ERROR\"");

        let level: LogLevel = serde_json::from_str("\"WARN\"").unwrap();
        assert_eq!(level, LogLevel::Warn);
    }

    // ==================== LogContext Tests ====================

    #[test]
    fn test_log_context_for_run() {
        let run_id = Uuid::new_v4();
        let ctx = LogContext::for_run(run_id);

        assert_eq!(ctx.run_id, run_id);
        assert!(ctx.test_id.is_none());
        assert!(ctx.agent_id.is_none());
        assert!(ctx.stage.is_none());
    }

    #[test]
    fn test_log_context_for_test() {
        let run_id = Uuid::new_v4();
        let test_id = Uuid::new_v4();
        let ctx = LogContext::for_test(run_id, test_id);

        assert_eq!(ctx.run_id, run_id);
        assert_eq!(ctx.test_id, Some(test_id));
        assert!(ctx.agent_id.is_none());
    }

    #[test]
    fn test_log_context_for_agent() {
        let run_id = Uuid::new_v4();
        let test_id = Uuid::new_v4();
        let ctx = LogContext::for_agent(run_id, test_id, "agent-1");

        assert_eq!(ctx.run_id, run_id);
        assert_eq!(ctx.test_id, Some(test_id));
        assert_eq!(ctx.agent_id, Some("agent-1".to_string()));
    }

    #[test]
    fn test_log_context_with_stage() {
        let run_id = Uuid::new_v4();
        let ctx = LogContext::for_run(run_id).with_stage("preflight");

        assert_eq!(ctx.stage, Some("preflight".to_string()));
    }

    #[test]
    fn test_log_context_child_for_test() {
        let run_id = Uuid::new_v4();
        let test_id = Uuid::new_v4();
        let parent = LogContext::for_run(run_id).with_stage("running");
        let child = parent.child_for_test(test_id);

        assert_eq!(child.run_id, run_id);
        assert_eq!(child.test_id, Some(test_id));
        assert_eq!(child.stage, Some("running".to_string()));
    }

    #[test]
    fn test_log_context_child_for_agent() {
        let run_id = Uuid::new_v4();
        let test_id = Uuid::new_v4();
        let parent = LogContext::for_test(run_id, test_id);
        let child = parent.child_for_agent("agent-2");

        assert_eq!(child.run_id, run_id);
        assert_eq!(child.test_id, Some(test_id));
        assert_eq!(child.agent_id, Some("agent-2".to_string()));
    }

    #[test]
    fn test_log_context_serialization_skips_none() {
        let run_id = Uuid::new_v4();
        let ctx = LogContext::for_run(run_id);
        let json = serde_json::to_string(&ctx).unwrap();

        // Should not contain test_id, agent_id, or stage keys
        assert!(!json.contains("test_id"));
        assert!(!json.contains("agent_id"));
        assert!(!json.contains("stage"));
    }

    // ==================== LogCategory Tests ====================

    #[test]
    fn test_log_category_default() {
        assert_eq!(LogCategory::default(), LogCategory::Harness);
    }

    #[test]
    fn test_log_category_custom() {
        let cat = LogCategory::Custom("my_category".to_string());
        let json = serde_json::to_string(&cat).unwrap();
        assert!(json.contains("custom"));
        assert!(json.contains("my_category"));
    }

    #[test]
    fn test_log_category_serialization() {
        let json = serde_json::to_string(&LogCategory::Network).unwrap();
        assert_eq!(json, "\"network\"");

        let cat: LogCategory = serde_json::from_str("\"security\"").unwrap();
        assert_eq!(cat, LogCategory::Security);
    }

    // ==================== StructuredLogEntry Tests ====================

    #[test]
    fn test_log_entry_new() {
        let run_id = Uuid::new_v4();
        let ctx = LogContext::for_run(run_id);
        let entry = StructuredLogEntry::new(ctx, LogLevel::Info, "Test message");

        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(entry.message, "Test message");
        assert_eq!(entry.context.run_id, run_id);
        assert!(entry.fields.is_empty());
    }

    #[test]
    fn test_log_entry_with_category() {
        let ctx = LogContext::for_run(Uuid::new_v4());
        let entry =
            StructuredLogEntry::new(ctx, LogLevel::Info, "msg").with_category(LogCategory::Network);

        assert_eq!(entry.category, LogCategory::Network);
    }

    #[test]
    fn test_log_entry_try_with_field() {
        let ctx = LogContext::for_run(Uuid::new_v4());
        let entry = StructuredLogEntry::new(ctx, LogLevel::Info, "msg")
            .try_with_field("count", 42)
            .unwrap()
            .try_with_field("name", "test")
            .unwrap();

        assert_eq!(entry.fields.get("count"), Some(&serde_json::json!(42)));
        assert_eq!(entry.fields.get("name"), Some(&serde_json::json!("test")));
    }

    #[test]
    #[allow(deprecated)]
    fn test_log_entry_with_field_deprecated() {
        let ctx = LogContext::for_run(Uuid::new_v4());
        let entry = StructuredLogEntry::new(ctx, LogLevel::Info, "msg")
            .with_field("count", 42)
            .with_field("name", "test");

        assert_eq!(entry.fields.get("count"), Some(&serde_json::json!(42)));
        assert_eq!(entry.fields.get("name"), Some(&serde_json::json!("test")));
    }

    #[test]
    fn test_log_entry_with_source() {
        let ctx = LogContext::for_run(Uuid::new_v4());
        let entry = StructuredLogEntry::new(ctx, LogLevel::Info, "msg").with_source("test.rs", 42);

        assert_eq!(entry.source_file, Some("test.rs".to_string()));
        assert_eq!(entry.source_line, Some(42));
    }

    #[test]
    fn test_log_entry_is_error() {
        let ctx = LogContext::for_run(Uuid::new_v4());

        assert!(!StructuredLogEntry::new(ctx.clone(), LogLevel::Info, "msg").is_error());
        assert!(!StructuredLogEntry::new(ctx.clone(), LogLevel::Warn, "msg").is_error());
        assert!(StructuredLogEntry::new(ctx.clone(), LogLevel::Error, "msg").is_error());
        assert!(StructuredLogEntry::new(ctx, LogLevel::Fatal, "msg").is_error());
    }

    #[test]
    fn test_log_entry_is_warning_or_higher() {
        let ctx = LogContext::for_run(Uuid::new_v4());

        assert!(
            !StructuredLogEntry::new(ctx.clone(), LogLevel::Info, "msg").is_warning_or_higher()
        );
        assert!(StructuredLogEntry::new(ctx.clone(), LogLevel::Warn, "msg").is_warning_or_higher());
        assert!(
            StructuredLogEntry::new(ctx.clone(), LogLevel::Error, "msg").is_warning_or_higher()
        );
        assert!(StructuredLogEntry::new(ctx, LogLevel::Fatal, "msg").is_warning_or_higher());
    }

    #[test]
    fn test_log_entry_to_json() {
        let ctx = LogContext::for_run(Uuid::new_v4());
        let entry = StructuredLogEntry::new(ctx, LogLevel::Info, "Test");

        let json = entry.to_json().unwrap();
        assert!(json.contains("\"level\":\"INFO\""));
        assert!(json.contains("\"message\":\"Test\""));
    }

    #[test]
    fn test_log_entry_roundtrip() {
        let ctx = LogContext::for_agent(Uuid::new_v4(), Uuid::new_v4(), "agent-1");
        let entry = StructuredLogEntry::new(ctx, LogLevel::Warn, "Warning message")
            .with_category(LogCategory::Network)
            .try_with_field("bytes", 1024)
            .unwrap();

        let json = entry.to_json().unwrap();
        let restored: StructuredLogEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.level, LogLevel::Warn);
        assert_eq!(restored.message, "Warning message");
        assert_eq!(restored.category, LogCategory::Network);
        assert_eq!(restored.context.agent_id, Some("agent-1".to_string()));
    }

    // ==================== LogBatch Tests ====================

    #[test]
    fn test_log_batch_new() {
        let batch = LogBatch::new();
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);
        assert!(batch.created_at.is_some());
    }

    #[test]
    fn test_log_batch_from_agent() {
        let batch = LogBatch::from_agent("agent-1");
        assert_eq!(batch.source_agent, Some("agent-1".to_string()));
    }

    #[test]
    fn test_log_batch_add() {
        let mut batch = LogBatch::new();
        let ctx = LogContext::for_run(Uuid::new_v4());
        let entry = StructuredLogEntry::new(ctx, LogLevel::Info, "msg");

        batch.add(entry);
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn test_log_batch_filter_by_level() {
        let mut batch = LogBatch::new();
        let run_id = Uuid::new_v4();
        let ctx = LogContext::for_run(run_id);

        batch.add(StructuredLogEntry::new(ctx.clone(), LogLevel::Info, "info"));
        batch.add(StructuredLogEntry::new(ctx.clone(), LogLevel::Warn, "warn"));
        batch.add(StructuredLogEntry::new(
            ctx.clone(),
            LogLevel::Error,
            "error",
        ));
        batch.add(StructuredLogEntry::new(ctx, LogLevel::Debug, "debug"));

        let warnings = batch.filter_by_level(LogLevel::Warn);
        assert_eq!(warnings.len(), 2); // Warn and Error
    }

    #[test]
    fn test_log_batch_filter_by_category() {
        let mut batch = LogBatch::new();
        let ctx = LogContext::for_run(Uuid::new_v4());

        batch.add(
            StructuredLogEntry::new(ctx.clone(), LogLevel::Info, "net1")
                .with_category(LogCategory::Network),
        );
        batch.add(
            StructuredLogEntry::new(ctx.clone(), LogLevel::Info, "net2")
                .with_category(LogCategory::Network),
        );
        batch.add(
            StructuredLogEntry::new(ctx, LogLevel::Info, "harness")
                .with_category(LogCategory::Harness),
        );

        let network_logs = batch.filter_by_category(&LogCategory::Network);
        assert_eq!(network_logs.len(), 2);
    }

    #[test]
    fn test_log_batch_filter_by_run() {
        let mut batch = LogBatch::new();
        let run_id_1 = Uuid::new_v4();
        let run_id_2 = Uuid::new_v4();

        batch.add(StructuredLogEntry::new(
            LogContext::for_run(run_id_1),
            LogLevel::Info,
            "run1",
        ));
        batch.add(StructuredLogEntry::new(
            LogContext::for_run(run_id_1),
            LogLevel::Info,
            "run1 again",
        ));
        batch.add(StructuredLogEntry::new(
            LogContext::for_run(run_id_2),
            LogLevel::Info,
            "run2",
        ));

        let run1_logs = batch.filter_by_run(run_id_1);
        assert_eq!(run1_logs.len(), 2);
    }

    #[test]
    fn test_log_batch_filter_by_test() {
        let mut batch = LogBatch::new();
        let run_id = Uuid::new_v4();
        let test_id_1 = Uuid::new_v4();
        let test_id_2 = Uuid::new_v4();

        batch.add(StructuredLogEntry::new(
            LogContext::for_test(run_id, test_id_1),
            LogLevel::Info,
            "test1",
        ));
        batch.add(StructuredLogEntry::new(
            LogContext::for_test(run_id, test_id_2),
            LogLevel::Info,
            "test2",
        ));

        let test1_logs = batch.filter_by_test(test_id_1);
        assert_eq!(test1_logs.len(), 1);
        assert_eq!(test1_logs[0].message, "test1");
    }

    #[test]
    fn test_log_batch_filter_by_agent() {
        let mut batch = LogBatch::new();
        let run_id = Uuid::new_v4();
        let test_id = Uuid::new_v4();

        batch.add(StructuredLogEntry::new(
            LogContext::for_agent(run_id, test_id, "agent-1"),
            LogLevel::Info,
            "from agent 1",
        ));
        batch.add(StructuredLogEntry::new(
            LogContext::for_agent(run_id, test_id, "agent-2"),
            LogLevel::Info,
            "from agent 2",
        ));

        let agent1_logs = batch.filter_by_agent("agent-1");
        assert_eq!(agent1_logs.len(), 1);
    }

    #[test]
    fn test_log_batch_errors() {
        let mut batch = LogBatch::new();
        let ctx = LogContext::for_run(Uuid::new_v4());

        batch.add(StructuredLogEntry::new(ctx.clone(), LogLevel::Info, "info"));
        batch.add(StructuredLogEntry::new(
            ctx.clone(),
            LogLevel::Error,
            "error1",
        ));
        batch.add(StructuredLogEntry::new(
            ctx.clone(),
            LogLevel::Fatal,
            "fatal",
        ));
        batch.add(StructuredLogEntry::new(ctx, LogLevel::Warn, "warn"));

        let errors = batch.errors();
        assert_eq!(errors.len(), 2); // Error and Fatal
    }

    #[test]
    fn test_log_batch_time_span_empty() {
        let batch = LogBatch::new();
        assert!(batch.time_span().is_none());
    }

    #[test]
    fn test_log_batch_time_span_single() {
        let mut batch = LogBatch::new();
        let ctx = LogContext::for_run(Uuid::new_v4());
        batch.add(StructuredLogEntry::new(ctx, LogLevel::Info, "single"));
        assert!(batch.time_span().is_none());
    }

    #[test]
    fn test_log_batch_to_jsonl() {
        let mut batch = LogBatch::new();
        let ctx = LogContext::for_run(Uuid::new_v4());

        batch.add(StructuredLogEntry::new(
            ctx.clone(),
            LogLevel::Info,
            "first",
        ));
        batch.add(StructuredLogEntry::new(ctx, LogLevel::Warn, "second"));

        let jsonl = batch.to_jsonl().unwrap();
        let lines: Vec<_> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"first\""));
        assert!(lines[1].contains("\"second\""));
    }

    #[test]
    fn test_log_batch_from_jsonl() {
        let mut batch = LogBatch::new();
        let ctx = LogContext::for_run(Uuid::new_v4());
        batch.add(StructuredLogEntry::new(ctx.clone(), LogLevel::Info, "one"));
        batch.add(StructuredLogEntry::new(ctx, LogLevel::Warn, "two"));

        let jsonl = batch.to_jsonl().unwrap();
        let restored = LogBatch::from_jsonl(&jsonl).unwrap();

        assert_eq!(restored.len(), 2);
        assert_eq!(restored.entries[0].message, "one");
        assert_eq!(restored.entries[1].message, "two");
    }

    // ==================== LogAggregator Tests ====================

    #[test]
    fn test_log_aggregator_new() {
        let agg = LogAggregator::new();
        assert!(agg.is_empty());
        assert_eq!(agg.len(), 0);
    }

    #[test]
    fn test_log_aggregator_for_run() {
        let run_id = Uuid::new_v4();
        let agg = LogAggregator::for_run(run_id);
        assert_eq!(agg.run_id, Some(run_id));
    }

    #[test]
    fn test_log_aggregator_add_batch() {
        let mut agg = LogAggregator::new();
        let mut batch = LogBatch::new();
        let ctx = LogContext::for_run(Uuid::new_v4());
        batch.add(StructuredLogEntry::new(ctx.clone(), LogLevel::Info, "one"));
        batch.add(StructuredLogEntry::new(ctx, LogLevel::Warn, "two"));

        agg.add_batch(batch);
        assert_eq!(agg.len(), 2);
    }

    #[test]
    fn test_log_aggregator_filters_by_run() {
        let run_id = Uuid::new_v4();
        let other_run_id = Uuid::new_v4();
        let mut agg = LogAggregator::for_run(run_id);

        agg.add_entry(StructuredLogEntry::new(
            LogContext::for_run(run_id),
            LogLevel::Info,
            "matching",
        ));
        agg.add_entry(StructuredLogEntry::new(
            LogContext::for_run(other_run_id),
            LogLevel::Info,
            "not matching",
        ));

        assert_eq!(agg.len(), 1);
        assert_eq!(agg.sorted_entries()[0].message, "matching");
    }

    #[test]
    fn test_log_aggregator_sorted_entries() {
        let mut agg = LogAggregator::new();
        let ctx = LogContext::for_run(Uuid::new_v4());

        // Add in random order - they should be sorted by timestamp
        agg.add_entry(StructuredLogEntry::new(
            ctx.clone(),
            LogLevel::Info,
            "first",
        ));
        agg.add_entry(StructuredLogEntry::new(
            ctx.clone(),
            LogLevel::Info,
            "second",
        ));
        agg.add_entry(StructuredLogEntry::new(ctx, LogLevel::Info, "third"));

        let sorted = agg.sorted_entries();
        assert_eq!(sorted.len(), 3);
        // Since they were added in sequence with SystemTime::now(), they should be in order
        assert_eq!(sorted[0].message, "first");
        assert_eq!(sorted[2].message, "third");
    }

    #[test]
    fn test_log_aggregator_entries_for_test() {
        let mut agg = LogAggregator::new();
        let run_id = Uuid::new_v4();
        let test_id_1 = Uuid::new_v4();
        let test_id_2 = Uuid::new_v4();

        agg.add_entry(StructuredLogEntry::new(
            LogContext::for_test(run_id, test_id_1),
            LogLevel::Info,
            "test1",
        ));
        agg.add_entry(StructuredLogEntry::new(
            LogContext::for_test(run_id, test_id_2),
            LogLevel::Info,
            "test2",
        ));

        let entries = agg.entries_for_test(test_id_1);
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_log_aggregator_entries_for_agent() {
        let mut agg = LogAggregator::new();
        let run_id = Uuid::new_v4();
        let test_id = Uuid::new_v4();

        agg.add_entry(StructuredLogEntry::new(
            LogContext::for_agent(run_id, test_id, "agent-1"),
            LogLevel::Info,
            "msg1",
        ));
        agg.add_entry(StructuredLogEntry::new(
            LogContext::for_agent(run_id, test_id, "agent-2"),
            LogLevel::Info,
            "msg2",
        ));

        let entries = agg.entries_for_agent("agent-1");
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_log_aggregator_agent_ids() {
        let mut agg = LogAggregator::new();
        let run_id = Uuid::new_v4();
        let test_id = Uuid::new_v4();

        agg.add_entry(StructuredLogEntry::new(
            LogContext::for_agent(run_id, test_id, "agent-2"),
            LogLevel::Info,
            "msg",
        ));
        agg.add_entry(StructuredLogEntry::new(
            LogContext::for_agent(run_id, test_id, "agent-1"),
            LogLevel::Info,
            "msg",
        ));
        agg.add_entry(StructuredLogEntry::new(
            LogContext::for_agent(run_id, test_id, "agent-2"),
            LogLevel::Info,
            "msg",
        ));

        let ids = agg.agent_ids();
        assert_eq!(ids, vec!["agent-1", "agent-2"]);
    }

    #[test]
    fn test_log_aggregator_test_ids() {
        let mut agg = LogAggregator::new();
        let run_id = Uuid::new_v4();
        let test_id_1 = Uuid::new_v4();
        let test_id_2 = Uuid::new_v4();

        agg.add_entry(StructuredLogEntry::new(
            LogContext::for_test(run_id, test_id_1),
            LogLevel::Info,
            "msg",
        ));
        agg.add_entry(StructuredLogEntry::new(
            LogContext::for_test(run_id, test_id_2),
            LogLevel::Info,
            "msg",
        ));
        agg.add_entry(StructuredLogEntry::new(
            LogContext::for_test(run_id, test_id_1),
            LogLevel::Info,
            "msg",
        ));

        let ids = agg.test_ids();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn test_log_aggregator_error_summary() {
        let mut agg = LogAggregator::new();
        let ctx = LogContext::for_run(Uuid::new_v4());

        agg.add_entry(
            StructuredLogEntry::new(ctx.clone(), LogLevel::Error, "net err")
                .with_category(LogCategory::Network),
        );
        agg.add_entry(
            StructuredLogEntry::new(ctx.clone(), LogLevel::Error, "net err 2")
                .with_category(LogCategory::Network),
        );
        agg.add_entry(
            StructuredLogEntry::new(ctx.clone(), LogLevel::Error, "sec err")
                .with_category(LogCategory::Security),
        );
        agg.add_entry(
            StructuredLogEntry::new(ctx, LogLevel::Info, "info")
                .with_category(LogCategory::Network),
        );

        let summary = agg.error_summary();
        assert_eq!(summary.get(&LogCategory::Network), Some(&2));
        assert_eq!(summary.get(&LogCategory::Security), Some(&1));
        assert!(!summary.contains_key(&LogCategory::Harness));
    }

    #[test]
    fn test_log_aggregator_to_batch() {
        let mut agg = LogAggregator::new();
        let ctx = LogContext::for_run(Uuid::new_v4());
        agg.add_entry(StructuredLogEntry::new(ctx.clone(), LogLevel::Info, "one"));
        agg.add_entry(StructuredLogEntry::new(ctx, LogLevel::Warn, "two"));

        let batch = agg.to_batch();
        assert_eq!(batch.len(), 2);
    }
}
