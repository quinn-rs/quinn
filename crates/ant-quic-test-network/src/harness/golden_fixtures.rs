//! Golden Fixture Tests
//!
//! This module provides golden fixture tests for the harness types.
//! Golden fixtures are pre-serialized examples that validate:
//! - Serialization/deserialization roundtrips work correctly
//! - Schema changes are detected (backwards compatibility)
//! - JSON format matches expected structure
//!
//! If a test fails after a code change, it indicates a potential
//! breaking change to the wire format that needs careful review.

use serde::{Serialize, de::DeserializeOwned};
use std::collections::HashMap;

/// Result of comparing actual output against golden fixture
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoldenCompareResult {
    /// Outputs match exactly
    Match,
    /// Outputs differ - includes diff description
    Mismatch { expected: String, actual: String },
    /// Could not parse the golden fixture
    ParseError { error: String },
    /// Could not serialize the value
    SerializeError { error: String },
}

impl GoldenCompareResult {
    /// Check if comparison passed
    pub fn is_match(&self) -> bool {
        matches!(self, Self::Match)
    }

    /// Get error description if any
    pub fn error_description(&self) -> Option<String> {
        match self {
            Self::Match => None,
            Self::Mismatch { expected, actual } => Some(format!(
                "Golden fixture mismatch:\n  Expected: {expected}\n  Actual: {actual}"
            )),
            Self::ParseError { error } => Some(format!("Failed to parse golden fixture: {error}")),
            Self::SerializeError { error } => Some(format!("Failed to serialize value: {error}")),
        }
    }
}

/// A golden fixture with its expected JSON representation
#[derive(Debug, Clone)]
pub struct GoldenFixture<T> {
    /// Name of this fixture (for error messages)
    pub name: String,
    /// The value to test
    pub value: T,
    /// Expected JSON representation
    pub expected_json: String,
}

impl<T: Serialize + DeserializeOwned + PartialEq> GoldenFixture<T> {
    /// Create a new golden fixture
    pub fn new(name: impl Into<String>, value: T, expected_json: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value,
            expected_json: expected_json.into(),
        }
    }

    /// Validate the fixture - serialize value and compare to expected JSON
    pub fn validate(&self) -> GoldenCompareResult {
        // Serialize the value
        let actual_json = match serde_json::to_string_pretty(&self.value) {
            Ok(json) => json,
            Err(e) => {
                return GoldenCompareResult::SerializeError {
                    error: e.to_string(),
                };
            }
        };

        // Normalize both JSONs for comparison (parse and re-serialize)
        let expected_normalized = match normalize_json(&self.expected_json) {
            Ok(json) => json,
            Err(e) => {
                return GoldenCompareResult::ParseError {
                    error: e.to_string(),
                };
            }
        };

        let actual_normalized = match normalize_json(&actual_json) {
            Ok(json) => json,
            Err(e) => {
                return GoldenCompareResult::SerializeError {
                    error: format!("failed to normalize actual JSON: {e}"),
                };
            }
        };

        if expected_normalized == actual_normalized {
            GoldenCompareResult::Match
        } else {
            GoldenCompareResult::Mismatch {
                expected: expected_normalized,
                actual: actual_normalized,
            }
        }
    }

    /// Validate roundtrip: serialize then deserialize should equal original
    pub fn validate_roundtrip(&self) -> GoldenCompareResult {
        let json = match serde_json::to_string_pretty(&self.value) {
            Ok(j) => j,
            Err(e) => {
                return GoldenCompareResult::SerializeError {
                    error: e.to_string(),
                };
            }
        };

        let restored: T = match serde_json::from_str(&json) {
            Ok(v) => v,
            Err(e) => {
                return GoldenCompareResult::ParseError {
                    error: e.to_string(),
                };
            }
        };

        if self.value == restored {
            GoldenCompareResult::Match
        } else {
            // Serialize restored value to show what actually differs
            let restored_json = serde_json::to_string_pretty(&restored)
                .unwrap_or_else(|e| format!("<serialization failed: {e}>"));
            GoldenCompareResult::Mismatch {
                expected: json,
                actual: restored_json,
            }
        }
    }
}

/// Normalize JSON for comparison by parsing and re-serializing with sorted keys
fn normalize_json(json: &str) -> Result<String, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    serde_json::to_string_pretty(&value)
}

/// Registry of golden fixtures for a type
#[derive(Debug)]
pub struct FixtureRegistry<T> {
    /// Name of the type being tested
    pub type_name: String,
    /// All fixtures for this type
    pub fixtures: Vec<GoldenFixture<T>>,
}

impl<T: Serialize + DeserializeOwned + PartialEq> FixtureRegistry<T> {
    /// Create a new registry
    pub fn new(type_name: impl Into<String>) -> Self {
        Self {
            type_name: type_name.into(),
            fixtures: Vec::new(),
        }
    }

    /// Add a fixture to the registry (builder pattern)
    pub fn with_fixture(mut self, fixture: GoldenFixture<T>) -> Self {
        self.fixtures.push(fixture);
        self
    }

    /// Run all fixture validations
    pub fn validate_all(&self) -> Vec<(String, GoldenCompareResult)> {
        self.fixtures
            .iter()
            .map(|f| (f.name.clone(), f.validate()))
            .collect()
    }

    /// Run all roundtrip validations
    pub fn validate_roundtrips(&self) -> Vec<(String, GoldenCompareResult)> {
        self.fixtures
            .iter()
            .map(|f| (f.name.clone(), f.validate_roundtrip()))
            .collect()
    }

    /// Check all fixtures pass
    pub fn all_pass(&self) -> bool {
        self.validate_all().iter().all(|(_, r)| r.is_match())
    }
}

/// Summary of golden fixture test results
#[derive(Debug, Clone, Default)]
pub struct GoldenTestSummary {
    /// Total fixtures tested
    pub total: usize,
    /// Fixtures that passed
    pub passed: usize,
    /// Fixtures that failed
    pub failed: usize,
    /// Details of failures
    pub failures: HashMap<String, String>,
}

impl GoldenTestSummary {
    /// Create a new summary
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a result
    pub fn add_result(&mut self, name: &str, result: &GoldenCompareResult) {
        self.total += 1;
        if result.is_match() {
            self.passed += 1;
        } else {
            self.failed += 1;
            if let Some(desc) = result.error_description() {
                self.failures.insert(name.to_string(), desc);
            }
        }
    }

    /// Check if all tests passed
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }

    /// Get pass rate as percentage, if any tests were run.
    ///
    /// Returns `None` for empty test suites since no tests means
    /// no meaningful pass rate can be calculated.
    pub fn pass_rate(&self) -> Option<f64> {
        if self.total == 0 {
            None
        } else {
            Some((self.passed as f64 / self.total as f64) * 100.0)
        }
    }

    /// Get pass rate as percentage, returning a default value for empty suites.
    ///
    /// # Deprecated
    /// Use `pass_rate()` and handle the `None` case explicitly.
    /// Returning 100% for an empty suite is misleading since no tests
    /// actually passed.
    #[deprecated(
        since = "0.2.0",
        note = "Use pass_rate() and handle None explicitly to avoid misleading statistics"
    )]
    pub fn pass_rate_or_default(&self, default: f64) -> f64 {
        self.pass_rate().unwrap_or(default)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::{
        CompatibilityPolicy, CompatibilityResult, ComponentVersion, DebugArtifactType,
        FailureCategory, LogCategory, LogContext, LogLevel, RunStage, Version,
        VersionHandshakeRequest, VersionHandshakeResponse, VersionedComponent,
    };
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use uuid::Uuid;

    // Fixed timestamp for deterministic tests
    fn fixed_time() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1704067200) // 2024-01-01 00:00:00 UTC
    }

    fn fixed_uuid() -> Uuid {
        Uuid::parse_str("12345678-1234-1234-1234-123456789abc").expect("valid uuid")
    }

    // ==================== GoldenCompareResult Tests ====================

    #[test]
    fn test_golden_compare_result_is_match() {
        assert!(GoldenCompareResult::Match.is_match());
        assert!(
            !GoldenCompareResult::Mismatch {
                expected: "a".to_string(),
                actual: "b".to_string()
            }
            .is_match()
        );
    }

    #[test]
    fn test_golden_compare_result_error_description() {
        assert!(GoldenCompareResult::Match.error_description().is_none());

        let mismatch = GoldenCompareResult::Mismatch {
            expected: "a".to_string(),
            actual: "b".to_string(),
        };
        let desc = mismatch.error_description().unwrap();
        assert!(desc.contains("mismatch"));

        let parse_err = GoldenCompareResult::ParseError {
            error: "bad json".to_string(),
        };
        let desc = parse_err.error_description().unwrap();
        assert!(desc.contains("parse"));
    }

    // ==================== GoldenFixture Tests ====================

    #[test]
    fn test_golden_fixture_new() {
        let fixture = GoldenFixture::new(
            "test",
            Version::new(1, 0, 0),
            r#"{"major":1,"minor":0,"patch":0}"#,
        );

        assert_eq!(fixture.name, "test");
        assert_eq!(fixture.value, Version::new(1, 0, 0));
    }

    #[test]
    fn test_golden_fixture_validate_match() {
        let fixture = GoldenFixture::new(
            "version_100",
            Version::new(1, 0, 0),
            r#"{"major":1,"minor":0,"patch":0}"#,
        );

        let result = fixture.validate();
        assert!(result.is_match(), "Expected match, got: {:?}", result);
    }

    #[test]
    fn test_golden_fixture_validate_mismatch() {
        let fixture = GoldenFixture::new(
            "version_wrong",
            Version::new(1, 0, 0),
            r#"{"major":2,"minor":0,"patch":0}"#, // Wrong version
        );

        let result = fixture.validate();
        assert!(!result.is_match());
        assert!(matches!(result, GoldenCompareResult::Mismatch { .. }));
    }

    #[test]
    fn test_golden_fixture_validate_parse_error() {
        let fixture = GoldenFixture::new("bad_json", Version::new(1, 0, 0), r#"{not valid json"#);

        let result = fixture.validate();
        assert!(matches!(result, GoldenCompareResult::ParseError { .. }));
    }

    #[test]
    fn test_golden_fixture_validate_roundtrip() {
        let fixture = GoldenFixture::new(
            "version_roundtrip",
            Version::new(1, 2, 3),
            r#"{"major":1,"minor":2,"patch":3}"#,
        );

        let result = fixture.validate_roundtrip();
        assert!(result.is_match());
    }

    // ==================== FixtureRegistry Tests ====================

    #[test]
    fn test_fixture_registry_new() {
        let registry = FixtureRegistry::<Version>::new("Version");
        assert_eq!(registry.type_name, "Version");
        assert!(registry.fixtures.is_empty());
    }

    #[test]
    fn test_fixture_registry_add() {
        let registry = FixtureRegistry::new("Version")
            .with_fixture(GoldenFixture::new(
                "v1",
                Version::new(1, 0, 0),
                r#"{"major":1,"minor":0,"patch":0}"#,
            ))
            .with_fixture(GoldenFixture::new(
                "v2",
                Version::new(2, 0, 0),
                r#"{"major":2,"minor":0,"patch":0}"#,
            ));

        assert_eq!(registry.fixtures.len(), 2);
    }

    #[test]
    fn test_fixture_registry_validate_all() {
        let registry = FixtureRegistry::new("Version")
            .with_fixture(GoldenFixture::new(
                "v1",
                Version::new(1, 0, 0),
                r#"{"major":1,"minor":0,"patch":0}"#,
            ))
            .with_fixture(GoldenFixture::new(
                "v2",
                Version::new(2, 0, 0),
                r#"{"major":2,"minor":0,"patch":0}"#,
            ));

        let results = registry.validate_all();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|(_, r)| r.is_match()));
    }

    #[test]
    fn test_fixture_registry_all_pass() {
        let registry = FixtureRegistry::new("Version").with_fixture(GoldenFixture::new(
            "v1",
            Version::new(1, 0, 0),
            r#"{"major":1,"minor":0,"patch":0}"#,
        ));

        assert!(registry.all_pass());
    }

    #[test]
    fn test_fixture_registry_not_all_pass() {
        let registry = FixtureRegistry::new("Version")
            .with_fixture(GoldenFixture::new(
                "v1_good",
                Version::new(1, 0, 0),
                r#"{"major":1,"minor":0,"patch":0}"#,
            ))
            .with_fixture(GoldenFixture::new(
                "v1_bad",
                Version::new(1, 0, 0),
                r#"{"major":9,"minor":9,"patch":9}"#, // Wrong
            ));

        assert!(!registry.all_pass());
    }

    // ==================== GoldenTestSummary Tests ====================

    #[test]
    fn test_golden_test_summary_new() {
        let summary = GoldenTestSummary::new();
        assert_eq!(summary.total, 0);
        assert_eq!(summary.passed, 0);
        assert_eq!(summary.failed, 0);
    }

    #[test]
    fn test_golden_test_summary_add_result() {
        let mut summary = GoldenTestSummary::new();

        summary.add_result("test1", &GoldenCompareResult::Match);
        assert_eq!(summary.total, 1);
        assert_eq!(summary.passed, 1);
        assert_eq!(summary.failed, 0);

        summary.add_result(
            "test2",
            &GoldenCompareResult::Mismatch {
                expected: "a".to_string(),
                actual: "b".to_string(),
            },
        );
        assert_eq!(summary.total, 2);
        assert_eq!(summary.passed, 1);
        assert_eq!(summary.failed, 1);
    }

    #[test]
    fn test_golden_test_summary_all_passed() {
        let mut summary = GoldenTestSummary::new();
        summary.add_result("test1", &GoldenCompareResult::Match);
        assert!(summary.all_passed());

        summary.add_result(
            "test2",
            &GoldenCompareResult::ParseError {
                error: "err".to_string(),
            },
        );
        assert!(!summary.all_passed());
    }

    #[test]
    fn test_golden_test_summary_pass_rate() {
        let mut summary = GoldenTestSummary::new();
        // Empty suite returns None - no tests means no meaningful pass rate
        assert_eq!(summary.pass_rate(), None);

        summary.add_result("test1", &GoldenCompareResult::Match);
        summary.add_result("test2", &GoldenCompareResult::Match);
        assert_eq!(summary.pass_rate(), Some(100.0));

        summary.add_result(
            "test3",
            &GoldenCompareResult::Mismatch {
                expected: "a".to_string(),
                actual: "b".to_string(),
            },
        );
        summary.add_result(
            "test4",
            &GoldenCompareResult::Mismatch {
                expected: "a".to_string(),
                actual: "b".to_string(),
            },
        );
        assert_eq!(summary.pass_rate(), Some(50.0));
    }

    #[test]
    #[allow(deprecated)]
    fn test_golden_test_summary_pass_rate_or_default_deprecated() {
        let mut summary = GoldenTestSummary::new();
        // Empty suite with deprecated method - demonstrates the problematic behavior
        assert_eq!(summary.pass_rate_or_default(100.0), 100.0);
        assert_eq!(summary.pass_rate_or_default(0.0), 0.0);

        summary.add_result("test1", &GoldenCompareResult::Match);
        assert_eq!(summary.pass_rate_or_default(0.0), 100.0);
    }

    // ==================== Golden Fixtures for Harness Types ====================

    #[test]
    fn test_golden_version() {
        let registry = FixtureRegistry::new("Version")
            .with_fixture(GoldenFixture::new(
                "v0.1.0",
                Version::new(0, 1, 0),
                r#"{"major":0,"minor":1,"patch":0}"#,
            ))
            .with_fixture(GoldenFixture::new(
                "v1.0.0",
                Version::new(1, 0, 0),
                r#"{"major":1,"minor":0,"patch":0}"#,
            ))
            .with_fixture(GoldenFixture::new(
                "v12.34.56",
                Version::new(12, 34, 56),
                r#"{"major":12,"minor":34,"patch":56}"#,
            ));

        assert!(registry.all_pass(), "Version golden fixtures failed");
    }

    #[test]
    fn test_golden_versioned_component() {
        let registry = FixtureRegistry::new("VersionedComponent")
            .with_fixture(GoldenFixture::new(
                "protocol",
                VersionedComponent::Protocol,
                r#""protocol""#,
            ))
            .with_fixture(GoldenFixture::new(
                "schema",
                VersionedComponent::Schema,
                r#""schema""#,
            ))
            .with_fixture(GoldenFixture::new(
                "api",
                VersionedComponent::Api,
                r#""api""#,
            ))
            .with_fixture(GoldenFixture::new(
                "harness",
                VersionedComponent::Harness,
                r#""harness""#,
            ))
            .with_fixture(GoldenFixture::new(
                "agent",
                VersionedComponent::Agent,
                r#""agent""#,
            ));

        assert!(
            registry.all_pass(),
            "VersionedComponent golden fixtures failed"
        );
    }

    #[test]
    fn test_golden_compatibility_policy() {
        let registry = FixtureRegistry::new("CompatibilityPolicy")
            .with_fixture(GoldenFixture::new(
                "strict",
                CompatibilityPolicy::Strict,
                r#""strict""#,
            ))
            .with_fixture(GoldenFixture::new(
                "compatible",
                CompatibilityPolicy::Compatible,
                r#""compatible""#,
            ))
            .with_fixture(GoldenFixture::new(
                "lenient",
                CompatibilityPolicy::Lenient,
                r#""lenient""#,
            ));

        assert!(
            registry.all_pass(),
            "CompatibilityPolicy golden fixtures failed"
        );
    }

    #[test]
    fn test_golden_compatibility_result() {
        let registry = FixtureRegistry::new("CompatibilityResult")
            .with_fixture(GoldenFixture::new(
                "compatible",
                CompatibilityResult::Compatible,
                r#""compatible""#,
            ))
            .with_fixture(GoldenFixture::new(
                "compatible_with_warning",
                CompatibilityResult::CompatibleWithWarning {
                    warning: "minor version mismatch".to_string(),
                },
                r#"{"compatible_with_warning":{"warning":"minor version mismatch"}}"#,
            ))
            .with_fixture(GoldenFixture::new(
                "incompatible",
                CompatibilityResult::Incompatible {
                    reason: "major version mismatch".to_string(),
                },
                r#"{"incompatible":{"reason":"major version mismatch"}}"#,
            ));

        assert!(
            registry.all_pass(),
            "CompatibilityResult golden fixtures failed"
        );
    }

    #[test]
    fn test_golden_component_version() {
        let cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 0, 0))
            .with_min_supported(Version::new(0, 9, 0))
            .with_feature("compression");

        let expected = r#"{
            "component": "protocol",
            "version": {"major": 1, "minor": 0, "patch": 0},
            "min_supported": {"major": 0, "minor": 9, "patch": 0},
            "features": ["compression"]
        }"#;

        let fixture = GoldenFixture::new("protocol_v1", cv, expected);
        let result = fixture.validate();
        assert!(result.is_match(), "ComponentVersion golden: {:?}", result);
    }

    #[test]
    fn test_golden_log_level() {
        // LogLevel uses #[serde(rename_all = "UPPERCASE")]
        let registry = FixtureRegistry::new("LogLevel")
            .with_fixture(GoldenFixture::new("trace", LogLevel::Trace, r#""TRACE""#))
            .with_fixture(GoldenFixture::new("debug", LogLevel::Debug, r#""DEBUG""#))
            .with_fixture(GoldenFixture::new("info", LogLevel::Info, r#""INFO""#))
            .with_fixture(GoldenFixture::new("warn", LogLevel::Warn, r#""WARN""#))
            .with_fixture(GoldenFixture::new("error", LogLevel::Error, r#""ERROR""#));

        assert!(registry.all_pass(), "LogLevel golden fixtures failed");
    }

    #[test]
    fn test_golden_log_category() {
        let registry = FixtureRegistry::new("LogCategory")
            .with_fixture(GoldenFixture::new(
                "harness",
                LogCategory::Harness,
                r#""harness""#,
            ))
            .with_fixture(GoldenFixture::new(
                "agent",
                LogCategory::Agent,
                r#""agent""#,
            ))
            .with_fixture(GoldenFixture::new(
                "network",
                LogCategory::Network,
                r#""network""#,
            ))
            .with_fixture(GoldenFixture::new("test", LogCategory::Test, r#""test""#))
            .with_fixture(GoldenFixture::new(
                "performance",
                LogCategory::Performance,
                r#""performance""#,
            ))
            .with_fixture(GoldenFixture::new(
                "security",
                LogCategory::Security,
                r#""security""#,
            ))
            .with_fixture(GoldenFixture::new(
                "resource",
                LogCategory::Resource,
                r#""resource""#,
            ))
            .with_fixture(GoldenFixture::new(
                "custom",
                LogCategory::Custom("my_category".to_string()),
                r#"{"custom":"my_category"}"#,
            ));

        assert!(registry.all_pass(), "LogCategory golden fixtures failed");
    }

    #[test]
    fn test_golden_failure_category() {
        let registry = FixtureRegistry::new("FailureCategory")
            .with_fixture(GoldenFixture::new(
                "harness_preflight",
                FailureCategory::HarnessPreflightError,
                r#""harness_preflight_error""#,
            ))
            .with_fixture(GoldenFixture::new(
                "harness_orchestration",
                FailureCategory::HarnessOrchestrationError,
                r#""harness_orchestration_error""#,
            ))
            .with_fixture(GoldenFixture::new(
                "harness_observation",
                FailureCategory::HarnessObservationError,
                r#""harness_observation_error""#,
            ))
            .with_fixture(GoldenFixture::new(
                "sut_connectivity",
                FailureCategory::SutConnectivityFailure,
                r#""sut_connectivity_failure""#,
            ))
            .with_fixture(GoldenFixture::new(
                "sut_behavior",
                FailureCategory::SutBehaviorMismatch,
                r#""sut_behavior_mismatch""#,
            ))
            .with_fixture(GoldenFixture::new(
                "infrastructure_flake",
                FailureCategory::InfrastructureFlake,
                r#""infrastructure_flake""#,
            ));

        assert!(
            registry.all_pass(),
            "FailureCategory golden fixtures failed"
        );
    }

    #[test]
    fn test_golden_run_stage() {
        // Use actual variants from run_recovery.rs
        let registry = FixtureRegistry::new("RunStage")
            .with_fixture(GoldenFixture::new("init", RunStage::Init, r#""init""#))
            .with_fixture(GoldenFixture::new(
                "preflight",
                RunStage::Preflight,
                r#""preflight""#,
            ))
            .with_fixture(GoldenFixture::new(
                "discovery",
                RunStage::Discovery,
                r#""discovery""#,
            ))
            .with_fixture(GoldenFixture::new(
                "running",
                RunStage::Running,
                r#""running""#,
            ))
            .with_fixture(GoldenFixture::new(
                "paused",
                RunStage::Paused,
                r#""paused""#,
            ))
            .with_fixture(GoldenFixture::new(
                "collecting",
                RunStage::Collecting,
                r#""collecting""#,
            ))
            .with_fixture(GoldenFixture::new(
                "uploading",
                RunStage::Uploading,
                r#""uploading""#,
            ))
            .with_fixture(GoldenFixture::new(
                "completed",
                RunStage::Completed,
                r#""completed""#,
            ))
            .with_fixture(GoldenFixture::new(
                "failed",
                RunStage::Failed,
                r#""failed""#,
            ))
            .with_fixture(GoldenFixture::new(
                "cancelled",
                RunStage::Cancelled,
                r#""cancelled""#,
            ));

        assert!(registry.all_pass(), "RunStage golden fixtures failed");
    }

    #[test]
    fn test_golden_debug_artifact_type() {
        // Use actual variants from debug_bundle.rs
        let registry = FixtureRegistry::new("DebugArtifactType")
            .with_fixture(GoldenFixture::new(
                "packet_capture",
                DebugArtifactType::PacketCapture,
                r#""packet_capture""#,
            ))
            .with_fixture(GoldenFixture::new(
                "conntrack_dump",
                DebugArtifactType::ConntrackDump,
                r#""conntrack_dump""#,
            ))
            .with_fixture(GoldenFixture::new(
                "docker_logs",
                DebugArtifactType::DockerLogs,
                r#""docker_logs""#,
            ))
            .with_fixture(GoldenFixture::new(
                "system_logs",
                DebugArtifactType::SystemLogs,
                r#""system_logs""#,
            ))
            .with_fixture(GoldenFixture::new(
                "application_logs",
                DebugArtifactType::ApplicationLogs,
                r#""application_logs""#,
            ))
            .with_fixture(GoldenFixture::new(
                "core_dump",
                DebugArtifactType::CoreDump,
                r#""core_dump""#,
            ))
            .with_fixture(GoldenFixture::new(
                "config_snapshot",
                DebugArtifactType::ConfigSnapshot,
                r#""config_snapshot""#,
            ))
            .with_fixture(GoldenFixture::new(
                "network_state",
                DebugArtifactType::NetworkState,
                r#""network_state""#,
            ))
            .with_fixture(GoldenFixture::new(
                "process_state",
                DebugArtifactType::ProcessState,
                r#""process_state""#,
            ))
            .with_fixture(GoldenFixture::new(
                "memory_dump",
                DebugArtifactType::MemoryDump,
                r#""memory_dump""#,
            ));

        assert!(
            registry.all_pass(),
            "DebugArtifactType golden fixtures failed"
        );
    }

    // ==================== Complex Type Golden Fixtures ====================

    #[test]
    fn test_golden_log_context() {
        // Use actual fields from structured_logging.rs
        let ctx = LogContext {
            run_id: fixed_uuid(),
            test_id: Some(fixed_uuid()),
            agent_id: Some("agent-nyc-1".to_string()),
            stage: None,
        };

        let expected = r#"{
            "run_id": "12345678-1234-1234-1234-123456789abc",
            "test_id": "12345678-1234-1234-1234-123456789abc",
            "agent_id": "agent-nyc-1"
        }"#;

        let fixture = GoldenFixture::new("log_context", ctx, expected);
        let result = fixture.validate();
        assert!(result.is_match(), "LogContext golden: {:?}", result);
    }

    // ==================== Version Handshake Golden Fixtures ====================

    #[test]
    fn test_golden_version_handshake_request_roundtrip() {
        let cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 0, 0));
        let request = VersionHandshakeRequest::new("ctl-1", "controller")
            .with_version(cv)
            .with_policy(CompatibilityPolicy::Compatible)
            .with_capability("compression")
            // Fix timestamp and ID for determinism
            .with_fixed_timestamp(fixed_time())
            .with_fixed_id(fixed_uuid());

        let expected_json = r#"{
            "request_id": "12345678-1234-1234-1234-123456789abc",
            "sender_id": "ctl-1",
            "sender_role": "controller",
            "versions": {
                "protocol": {
                    "component": "protocol",
                    "version": {
                        "major": 1,
                        "minor": 0,
                        "patch": 0
                    },
                    "min_supported": {
                        "major": 1,
                        "minor": 0,
                        "patch": 0
                    }
                }
            },
            "policy": "compatible",
            "timestamp": {
                "secs_since_epoch": 1704067200,
                "nanos_since_epoch": 0
            },
            "capabilities": ["compression"]
        }"#;

        let fixture = GoldenFixture::new("version_handshake_request", request, expected_json);
        let result = fixture.validate();
        assert!(
            result.is_match(),
            "VersionHandshakeRequest golden: {:?}",
            result
        );
    }

    #[test]
    fn test_golden_version_handshake_response_roundtrip() {
        let response = VersionHandshakeResponse::accept(fixed_uuid(), "agent-1")
            .with_negotiated_version(VersionedComponent::Protocol, Version::new(1, 0, 0))
            .with_result(
                VersionedComponent::Protocol,
                CompatibilityResult::Compatible,
            )
            // Fix timestamp and ID for determinism
            .with_fixed_timestamp(fixed_time())
            .with_fixed_id(fixed_uuid());

        let expected_json = r#"{
            "request_id": "12345678-1234-1234-1234-123456789abc",
            "response_id": "12345678-1234-1234-1234-123456789abc",
            "responder_id": "agent-1",
            "accepted": true,
            "negotiated_versions": {
                "protocol": {
                    "major": 1,
                    "minor": 0,
                    "patch": 0
                }
            },
            "compatibility_results": {
                "protocol": "compatible"
            },
            "timestamp": {
                "secs_since_epoch": 1704067200,
                "nanos_since_epoch": 0
            }
        }"#;

        let fixture = GoldenFixture::new("version_handshake_response", response, expected_json);
        let result = fixture.validate();
        assert!(
            result.is_match(),
            "VersionHandshakeResponse golden: {:?}",
            result
        );
    }

    // ==================== Integration Test ====================

    #[test]
    fn test_all_enum_golden_fixtures() {
        let mut summary = GoldenTestSummary::new();

        // Version
        let version_registry = FixtureRegistry::new("Version").with_fixture(GoldenFixture::new(
            "v1",
            Version::new(1, 0, 0),
            r#"{"major":1,"minor":0,"patch":0}"#,
        ));
        for (name, result) in version_registry.validate_all() {
            summary.add_result(&format!("Version::{name}"), &result);
        }

        // CompatibilityPolicy
        let policy_registry =
            FixtureRegistry::new("CompatibilityPolicy").with_fixture(GoldenFixture::new(
                "compatible",
                CompatibilityPolicy::Compatible,
                r#""compatible""#,
            ));
        for (name, result) in policy_registry.validate_all() {
            summary.add_result(&format!("CompatibilityPolicy::{name}"), &result);
        }

        // LogLevel (uses UPPERCASE)
        let level_registry = FixtureRegistry::new("LogLevel").with_fixture(GoldenFixture::new(
            "info",
            LogLevel::Info,
            r#""INFO""#,
        ));
        for (name, result) in level_registry.validate_all() {
            summary.add_result(&format!("LogLevel::{name}"), &result);
        }

        // RunStage
        let stage_registry = FixtureRegistry::new("RunStage").with_fixture(GoldenFixture::new(
            "running",
            RunStage::Running,
            r#""running""#,
        ));
        for (name, result) in stage_registry.validate_all() {
            summary.add_result(&format!("RunStage::{name}"), &result);
        }

        assert!(
            summary.all_passed(),
            "Golden fixture failures: {:?}",
            summary.failures
        );
        assert_eq!(summary.pass_rate(), Some(100.0));
    }
}
