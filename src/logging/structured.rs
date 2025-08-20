// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use serde::{Deserialize, Serialize};
use tracing::Level;

use crate::ConnectionId;

/// Structured log event with full metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredLogEvent {
    pub timestamp: u64, // microseconds since epoch
    pub level: LogLevel,
    pub target: String,
    pub message: String,
    pub fields: Vec<(String, String)>,
    pub span_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
}

/// Serializable log level
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LogLevel {
    ERROR,
    WARN,
    INFO,
    DEBUG,
    TRACE,
}

impl From<Level> for LogLevel {
    fn from(level: Level) -> Self {
        match level {
            Level::ERROR => Self::ERROR,
            Level::WARN => Self::WARN,
            Level::INFO => Self::INFO,
            Level::DEBUG => Self::DEBUG,
            Level::TRACE => Self::TRACE,
        }
    }
}

impl StructuredLogEvent {
    /// Create a new structured log event
    pub fn new(level: Level, target: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            timestamp: crate::tracing::timestamp_now(),
            level: level.into(),
            target: target.into(),
            message: message.into(),
            fields: Vec::new(),
            span_id: None,
            trace_id: None,
            connection_id: None,
        }
    }

    /// Add a field to the event
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.push((key.into(), value.into()));
        self
    }

    /// Add multiple fields
    pub fn with_fields(mut self, fields: Vec<(String, String)>) -> Self {
        self.fields.extend(fields);
        self
    }

    /// Set the span ID
    pub fn with_span_id(mut self, span_id: impl Into<String>) -> Self {
        self.span_id = Some(span_id.into());
        self
    }

    /// Set the trace ID
    pub fn with_trace_id(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    /// Set the connection ID
    pub fn with_connection_id(mut self, conn_id: &ConnectionId) -> Self {
        self.connection_id = Some(format!("{conn_id:?}"));
        self
    }

    /// Convert to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Convert to pretty JSON
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Builder for structured events
pub struct StructuredEventBuilder {
    event: StructuredLogEvent,
}

impl StructuredEventBuilder {
    /// Create a new builder
    pub fn new(level: Level, target: &str, message: &str) -> Self {
        Self {
            event: StructuredLogEvent::new(level, target, message),
        }
    }

    /// Add a string field
    pub fn field(mut self, key: &str, value: &str) -> Self {
        self.event = self.event.with_field(key, value);
        self
    }

    /// Add a numeric field
    pub fn field_num<T: std::fmt::Display>(mut self, key: &str, value: T) -> Self {
        self.event = self.event.with_field(key, value.to_string());
        self
    }

    /// Add a boolean field
    pub fn field_bool(mut self, key: &str, value: bool) -> Self {
        self.event = self.event.with_field(key, value.to_string());
        self
    }

    /// Add an optional field
    pub fn field_opt<T: std::fmt::Display>(mut self, key: &str, value: Option<T>) -> Self {
        if let Some(v) = value {
            self.event = self.event.with_field(key, v.to_string());
        }
        self
    }

    /// Set connection ID
    pub fn connection_id(mut self, conn_id: &ConnectionId) -> Self {
        self.event = self.event.with_connection_id(conn_id);
        self
    }

    /// Set span ID
    pub fn span_id(mut self, span_id: &str) -> Self {
        self.event = self.event.with_span_id(span_id);
        self
    }

    /// Build the event
    pub fn build(self) -> StructuredLogEvent {
        self.event
    }
}

/// Format a structured event as JSON
pub(super) fn format_as_json(event: &super::LogEvent) -> String {
    let structured = StructuredLogEvent {
        timestamp: crate::tracing::timestamp_now(),
        level: event.level.into(),
        target: event.target.clone(),
        message: event.message.clone(),
        fields: event
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        span_id: event.span_id.clone(),
        trace_id: None,
        connection_id: None,
    };

    structured.to_json().unwrap_or_else(|_| {
        format!(
            r#"{{"error":"failed to serialize event","message":"{}"}}"#,
            event.message
        )
    })
}

/// Parse structured fields from a format string
pub fn parse_structured_fields(
    format_str: &str,
    args: &[&dyn std::fmt::Display],
) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    let parts = format_str.split("{}");
    let mut arg_idx = 0;

    for (i, part) in parts.enumerate() {
        if i > 0 && arg_idx < args.len() {
            // Extract field name from the previous part
            if let Some(field_name) = extract_field_name(part) {
                fields.push((field_name, args[arg_idx].to_string()));
            }
            arg_idx += 1;
        }
    }

    fields
}

fn extract_field_name(text: &str) -> Option<String> {
    // Look for patterns like "field_name=" or "field_name:"
    let trimmed = text.trim();
    if let Some(idx) = trimmed.rfind('=') {
        let name = trimmed[..idx].trim();
        if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Some(name.to_string());
        }
    }
    if let Some(idx) = trimmed.rfind(':') {
        let name = trimmed[..idx].trim();
        if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Some(name.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_structured_event_builder() {
        let event = StructuredEventBuilder::new(Level::INFO, "test", "Test message")
            .field("key1", "value1")
            .field_num("count", 42)
            .field_bool("enabled", true)
            .field_opt("optional", Some("present"))
            .field_opt::<String>("missing", None)
            .build();

        assert_eq!(event.level, LogLevel::INFO);
        assert_eq!(event.target, "test");
        assert_eq!(event.message, "Test message");
        assert_eq!(event.fields.len(), 4);
        assert!(
            event
                .fields
                .contains(&("key1".to_string(), "value1".to_string()))
        );
        assert!(
            event
                .fields
                .contains(&("count".to_string(), "42".to_string()))
        );
        assert!(
            event
                .fields
                .contains(&("enabled".to_string(), "true".to_string()))
        );
        assert!(
            event
                .fields
                .contains(&("optional".to_string(), "present".to_string()))
        );
    }

    #[test]
    fn test_json_serialization() {
        let event = StructuredLogEvent::new(Level::ERROR, "test::module", "Error occurred")
            .with_field("error_code", "E001")
            .with_field("details", "Connection timeout");

        let json = event.to_json().unwrap();
        assert!(json.contains(r#""level":"ERROR""#));
        assert!(json.contains(r#""target":"test::module""#));
        assert!(json.contains(r#""message":"Error occurred""#));
        assert!(json.contains(r#""error_code","E001""#));
    }
}
