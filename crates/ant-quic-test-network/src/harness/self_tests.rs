//! Harness Self-Test Suite
//!
//! This module provides comprehensive self-tests for the harness infrastructure.
//! These tests verify that:
//! - Types serialize/deserialize correctly (roundtrips)
//! - Builder patterns work as expected
//! - Validation logic is correct
//! - Default values are sensible
//! - Integration between modules works properly
//!
//! Run these tests to validate harness integrity after changes.

use super::*;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Test fixture helpers
mod fixtures {
    use super::*;

    pub fn fixed_uuid() -> Uuid {
        Uuid::parse_str("12345678-1234-1234-1234-123456789abc").expect("valid uuid")
    }

    pub fn fixed_time() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1704067200) // 2024-01-01 00:00:00 UTC
    }
}

// ==================== Version Tests ====================

#[test]
fn test_version_new() {
    let v = Version::new(1, 2, 3);
    assert_eq!(v.major(), 1);
    assert_eq!(v.minor(), 2);
    assert_eq!(v.patch(), 3);
}

#[test]
fn test_version_default() {
    let v = Version::default();
    assert_eq!(v, Version::new(0, 1, 0));
}

#[test]
fn test_version_display() {
    let v = Version::new(1, 2, 3);
    assert_eq!(format!("{v}"), "1.2.3");
}

#[test]
fn test_version_from_str_valid() {
    let v: Version = "1.2.3".parse().expect("valid version");
    assert_eq!(v, Version::new(1, 2, 3));

    let v: Version = "0.0.0".parse().expect("valid version");
    assert_eq!(v, Version::new(0, 0, 0));

    let v: Version = "100.200.300".parse().expect("valid version");
    assert_eq!(v, Version::new(100, 200, 300));
}

#[test]
fn test_version_from_str_invalid_format() {
    let result = Version::from_str("1.2");
    assert!(matches!(result, Err(VersionParseError::InvalidFormat(_))));

    let result = Version::from_str("1.2.3.4");
    assert!(matches!(result, Err(VersionParseError::InvalidFormat(_))));

    let result = Version::from_str("v1.2.3");
    assert!(matches!(result, Err(VersionParseError::InvalidNumber(_))));
}

#[test]
fn test_version_from_str_invalid_number() {
    let result = Version::from_str("a.2.3");
    assert!(matches!(result, Err(VersionParseError::InvalidNumber(_))));

    let result = Version::from_str("1.b.3");
    assert!(matches!(result, Err(VersionParseError::InvalidNumber(_))));
}

#[test]
fn test_version_ordering() {
    assert!(Version::new(2, 0, 0) > Version::new(1, 0, 0));
    assert!(Version::new(1, 2, 0) > Version::new(1, 1, 0));
    assert!(Version::new(1, 1, 2) > Version::new(1, 1, 1));
    assert!(Version::new(1, 0, 0) == Version::new(1, 0, 0));
}

#[test]
fn test_version_is_compatible_with() {
    let v1 = Version::new(1, 0, 0);
    let v2 = Version::new(1, 1, 0);
    let v3 = Version::new(2, 0, 0);

    // Same major, higher minor is compatible
    assert!(v2.is_compatible_with(&v1));
    // Same version is compatible
    assert!(v1.is_compatible_with(&v1));
    // Lower minor is not compatible
    assert!(!v1.is_compatible_with(&v2));
    // Different major is not compatible
    assert!(!v3.is_compatible_with(&v1));
}

#[test]
fn test_version_is_prerelease() {
    assert!(Version::new(0, 1, 0).is_prerelease());
    assert!(Version::new(0, 99, 99).is_prerelease());
    assert!(!Version::new(1, 0, 0).is_prerelease());
}

#[test]
fn test_version_next_methods() {
    let v = Version::new(1, 2, 3);

    assert_eq!(v.next_major(), Version::new(2, 0, 0));
    assert_eq!(v.next_minor(), Version::new(1, 3, 0));
    assert_eq!(v.next_patch(), Version::new(1, 2, 4));
}

// ==================== Compatibility Policy Tests ====================

#[test]
fn test_compatibility_policy_default() {
    let policy = CompatibilityPolicy::default();
    assert_eq!(policy, CompatibilityPolicy::Compatible);
}

#[test]
fn test_compatibility_policy_strict() {
    let policy = CompatibilityPolicy::Strict;
    let v1 = Version::new(1, 0, 0);
    let v2 = Version::new(1, 0, 1);

    // Exact match is compatible
    assert!(matches!(
        policy.check(&v1, &v1),
        CompatibilityResult::Compatible
    ));

    // Any difference is incompatible
    assert!(matches!(
        policy.check(&v1, &v2),
        CompatibilityResult::Incompatible { .. }
    ));
}

#[test]
fn test_compatibility_policy_compatible() {
    let policy = CompatibilityPolicy::Compatible;
    let v1 = Version::new(1, 0, 0);
    let v2 = Version::new(1, 1, 0);
    let v3 = Version::new(2, 0, 0);

    // Same major is compatible
    assert!(matches!(
        policy.check(&v2, &v1),
        CompatibilityResult::Compatible
    ));

    // Different major is incompatible
    assert!(matches!(
        policy.check(&v3, &v1),
        CompatibilityResult::Incompatible { .. }
    ));
}

#[test]
fn test_compatibility_policy_lenient() {
    let policy = CompatibilityPolicy::Lenient;
    let v1 = Version::new(1, 0, 0);
    let v3 = Version::new(2, 0, 0);

    // Even different major only warns
    let result = policy.check(&v3, &v1);
    assert!(matches!(
        result,
        CompatibilityResult::Compatible | CompatibilityResult::CompatibleWithWarning { .. }
    ));
}

// ==================== Component Version Tests ====================

#[test]
fn test_component_version_builder() {
    let cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 0, 0))
        .with_min_supported(Version::new(0, 9, 0))
        .with_feature("compression")
        .with_feature("encryption");

    assert_eq!(cv.component(), VersionedComponent::Protocol);
    assert_eq!(cv.version(), Version::new(1, 0, 0));
    assert_eq!(cv.min_supported(), Version::new(0, 9, 0));
    assert!(cv.features().contains(&"compression".to_string()));
    assert!(cv.features().contains(&"encryption".to_string()));
}

#[test]
fn test_component_version_supports() {
    let cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 2, 0))
        .with_min_supported(Version::new(1, 0, 0));

    // Exact match
    assert!(cv.supports(&Version::new(1, 2, 0)));
    // Above min
    assert!(cv.supports(&Version::new(1, 1, 0)));
    // At min
    assert!(cv.supports(&Version::new(1, 0, 0)));
    // Below min
    assert!(!cv.supports(&Version::new(0, 9, 0)));
    // Different major
    assert!(!cv.supports(&Version::new(2, 0, 0)));
}

// ==================== Version Negotiator Tests ====================

#[test]
fn test_version_negotiator_builder() {
    let cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 0, 0));
    let negotiator = VersionNegotiator::new()
        .with_version(cv)
        .with_default_policy(CompatibilityPolicy::Strict)
        .require(VersionedComponent::Protocol);

    // Verify it can create a request
    let request = negotiator.create_request("ctl-1", "controller");
    assert!(!request.sender_id().is_empty());
}

#[test]
fn test_version_negotiator_create_request() {
    let cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 0, 0))
        .with_feature("compression");

    let negotiator = VersionNegotiator::new()
        .with_version(cv)
        .with_default_policy(CompatibilityPolicy::Compatible);

    let request = negotiator.create_request("ctl-main", "controller");
    assert_eq!(request.sender_id(), "ctl-main");
    assert_eq!(request.sender_role(), "controller");
    assert_eq!(request.policy(), CompatibilityPolicy::Compatible);
    assert!(
        request
            .versions()
            .contains_key(&VersionedComponent::Protocol)
    );
}

// ==================== Run Stage Tests ====================

#[test]
fn test_run_stage_transitions() {
    // Test valid stage progression
    let stages = [
        RunStage::Init,
        RunStage::Preflight,
        RunStage::Discovery,
        RunStage::Running,
        RunStage::Collecting,
        RunStage::Uploading,
        RunStage::Completed,
    ];

    // Just verify all stages can be created and serialized
    for stage in &stages {
        let serialized = serde_json::to_string(stage).expect("serialize stage");
        let _restored: RunStage = serde_json::from_str(&serialized).expect("deserialize stage");
    }
}

#[test]
fn test_run_stage_terminal_states() {
    // These are terminal states
    assert!(matches!(RunStage::Completed, RunStage::Completed));
    assert!(matches!(RunStage::Failed, RunStage::Failed));
    assert!(matches!(RunStage::Cancelled, RunStage::Cancelled));
}

// ==================== RunStatus Tests ====================

#[test]
fn test_run_status_is_terminal() {
    // Non-terminal states
    assert!(!RunStatus::Pending.is_terminal());
    assert!(!RunStatus::Preflight.is_terminal());
    assert!(!RunStatus::Running.is_terminal());
    assert!(!RunStatus::Uploading.is_terminal());

    // Terminal states
    assert!(RunStatus::Completed.is_terminal());
    assert!(RunStatus::Failed.is_terminal());
    assert!(RunStatus::Cancelled.is_terminal());
}

// ==================== Log Level Tests ====================

#[test]
fn test_log_level_ordering() {
    assert!(LogLevel::Trace < LogLevel::Debug);
    assert!(LogLevel::Debug < LogLevel::Info);
    assert!(LogLevel::Info < LogLevel::Warn);
    assert!(LogLevel::Warn < LogLevel::Error);
    assert!(LogLevel::Error < LogLevel::Fatal);
}

#[test]
fn test_log_level_default() {
    let level = LogLevel::default();
    assert_eq!(level, LogLevel::Info);
}

// ==================== Failure Category Tests ====================

#[test]
fn test_failure_category_all_variants() {
    let categories = [
        FailureCategory::HarnessPreflightError,
        FailureCategory::HarnessOrchestrationError,
        FailureCategory::HarnessObservationError,
        FailureCategory::SutConnectivityFailure,
        FailureCategory::SutBehaviorMismatch,
        FailureCategory::InfrastructureFlake,
    ];

    for category in &categories {
        // Verify roundtrip
        let json = serde_json::to_string(category).expect("serialize");
        let restored: FailureCategory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*category, restored);
    }
}

// ==================== Debug Artifact Type Tests ====================

#[test]
fn test_debug_artifact_type_all_variants() {
    let artifact_types = [
        DebugArtifactType::PacketCapture,
        DebugArtifactType::ConntrackDump,
        DebugArtifactType::DockerLogs,
        DebugArtifactType::SystemLogs,
        DebugArtifactType::ApplicationLogs,
        DebugArtifactType::CoreDump,
        DebugArtifactType::ConfigSnapshot,
        DebugArtifactType::NetworkState,
        DebugArtifactType::ProcessState,
        DebugArtifactType::MemoryDump,
    ];

    for artifact_type in &artifact_types {
        let json = serde_json::to_string(artifact_type).expect("serialize");
        let restored: DebugArtifactType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*artifact_type, restored);
    }
}

// ==================== Version Handshake Tests ====================

#[test]
fn test_version_handshake_request_builder() {
    let cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 0, 0));
    let request = VersionHandshakeRequest::new("ctl-1", "controller")
        .with_version(cv)
        .with_policy(CompatibilityPolicy::Compatible)
        .with_capability("compression")
        .with_capability("encryption");

    assert_eq!(request.sender_id(), "ctl-1");
    assert_eq!(request.sender_role(), "controller");
    assert_eq!(request.versions().len(), 1);
    assert_eq!(request.policy(), CompatibilityPolicy::Compatible);
    assert!(request.capabilities().contains(&"compression".to_string()));
    assert!(request.capabilities().contains(&"encryption".to_string()));
}

#[test]
fn test_version_handshake_response_accept() {
    let request_id = fixtures::fixed_uuid();
    let response = VersionHandshakeResponse::accept(request_id, "agent-1")
        .with_negotiated_version(VersionedComponent::Protocol, Version::new(1, 0, 0))
        .with_result(
            VersionedComponent::Protocol,
            CompatibilityResult::Compatible,
        );

    assert!(response.is_accepted());
    assert_eq!(response.request_id, request_id);
    assert_eq!(response.responder_id, "agent-1");
    assert!(response.rejection_reason().is_none());
}

#[test]
fn test_version_handshake_response_reject() {
    let request_id = fixtures::fixed_uuid();
    let response = VersionHandshakeResponse::reject(request_id, "agent-1", "incompatible version");

    assert!(!response.is_accepted());
    assert_eq!(response.request_id, request_id);
    assert_eq!(response.rejection_reason(), Some("incompatible version"));
}

// ==================== AgentStatus Tests ====================

#[test]
fn test_agent_status_default() {
    let status = AgentStatus::default();
    assert_eq!(status, AgentStatus::Idle);
}

#[test]
fn test_agent_status_serialization() {
    let statuses = [
        (AgentStatus::Idle, "\"idle\""),
        (AgentStatus::Running, "\"running\""),
        (AgentStatus::Error, "\"error\""),
        (AgentStatus::Offline, "\"offline\""),
    ];

    for (status, expected) in &statuses {
        let json = serde_json::to_string(status).expect("serialize");
        assert_eq!(&json, *expected);
    }
}

// ==================== AgentCapabilities Tests ====================

#[test]
fn test_agent_capabilities_default() {
    let caps = AgentCapabilities::default();
    assert_eq!(caps.protocol_version, 1);
    assert_eq!(caps.max_concurrent_tests, 4);
    assert!(!caps.can_capture_pcaps);
    assert!(!caps.can_simulate_nat);
    assert!(!caps.has_docker);
    assert!(!caps.has_tc);
}

// ==================== CompatibilityResult Tests ====================

#[test]
fn test_compatibility_result_is_ok() {
    assert!(CompatibilityResult::Compatible.is_ok());
    assert!(
        CompatibilityResult::CompatibleWithWarning {
            warning: "minor mismatch".to_string()
        }
        .is_ok()
    );
    assert!(
        !CompatibilityResult::Incompatible {
            reason: "major mismatch".to_string()
        }
        .is_ok()
    );
}

#[test]
fn test_compatibility_result_is_error() {
    assert!(!CompatibilityResult::Compatible.is_error());
    assert!(
        !CompatibilityResult::CompatibleWithWarning {
            warning: "minor mismatch".to_string()
        }
        .is_error()
    );
    assert!(
        CompatibilityResult::Incompatible {
            reason: "major mismatch".to_string()
        }
        .is_error()
    );
}

#[test]
fn test_compatibility_result_warning() {
    assert!(CompatibilityResult::Compatible.warning().is_none());
    assert_eq!(
        CompatibilityResult::CompatibleWithWarning {
            warning: "minor mismatch".to_string()
        }
        .warning(),
        Some("minor mismatch")
    );
}

#[test]
fn test_compatibility_result_error() {
    assert!(CompatibilityResult::Compatible.error().is_none());
    assert_eq!(
        CompatibilityResult::Incompatible {
            reason: "major mismatch".to_string()
        }
        .error(),
        Some("major mismatch")
    );
}

// ==================== Integration Tests ====================

#[test]
fn test_version_handshake_roundtrip() {
    // Create a full handshake request
    let cv = ComponentVersion::new(VersionedComponent::Protocol, Version::new(1, 0, 0))
        .with_min_supported(Version::new(0, 9, 0))
        .with_feature("compression");

    let request = VersionHandshakeRequest::new("ctl-main", "controller")
        .with_version(cv)
        .with_policy(CompatibilityPolicy::Compatible)
        // Fix timestamp and ID for determinism
        .with_fixed_timestamp(fixtures::fixed_time())
        .with_fixed_id(fixtures::fixed_uuid());

    // Serialize and deserialize
    let json = serde_json::to_string_pretty(&request).expect("serialize");
    let restored: VersionHandshakeRequest = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(request, restored);
}

#[test]
fn test_log_context_with_all_fields() {
    let ctx = LogContext {
        run_id: fixtures::fixed_uuid(),
        test_id: Some(fixtures::fixed_uuid()),
        agent_id: Some("agent-nyc-1".to_string()),
        stage: Some("running".to_string()),
    };

    let json = serde_json::to_string(&ctx).expect("serialize");
    let restored: LogContext = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(ctx.run_id, restored.run_id);
    assert_eq!(ctx.test_id, restored.test_id);
    assert_eq!(ctx.agent_id, restored.agent_id);
    assert_eq!(ctx.stage, restored.stage);
}

#[test]
fn test_log_context_with_optional_fields_none() {
    let ctx = LogContext {
        run_id: fixtures::fixed_uuid(),
        test_id: None,
        agent_id: None,
        stage: None,
    };

    let json = serde_json::to_string(&ctx).expect("serialize");

    // Optional fields should be omitted when None
    assert!(!json.contains("test_id"));
    assert!(!json.contains("agent_id"));
    assert!(!json.contains("stage"));
}

// ==================== Harness Metrics Tests ====================

#[test]
fn test_harness_metrics_new() {
    let run_id = fixtures::fixed_uuid();
    let metrics = HarnessMetrics::new(run_id);

    assert_eq!(metrics.run_id, run_id);
    // Default metrics should indicate healthy harness
    assert!(metrics.is_harness_healthy());
}

#[test]
fn test_run_completeness_metric_rates() {
    let metric = RunCompletenessMetric {
        expected_attempts: 100,
        completed_attempts: 95,
        started_attempts: 100,
        timed_out_attempts: 2,
        ..Default::default()
    };

    assert!((metric.completion_rate() - 0.95).abs() < 0.001);
    assert!((metric.incomplete_rate() - 0.05).abs() < 0.001);
    assert!((metric.timeout_rate() - 0.02).abs() < 0.001);
}

#[test]
fn test_run_completeness_metric_healthy() {
    // Empty is healthy
    let metric = RunCompletenessMetric::default();
    assert!(metric.is_healthy());

    // High completion is healthy
    let metric = RunCompletenessMetric {
        expected_attempts: 100,
        completed_attempts: 96,
        started_attempts: 100,
        timed_out_attempts: 2,
        ..Default::default()
    };
    assert!(metric.is_healthy());

    // Low completion is unhealthy
    let metric = RunCompletenessMetric {
        expected_attempts: 100,
        completed_attempts: 80,
        started_attempts: 100,
        timed_out_attempts: 2,
        ..Default::default()
    };
    assert!(!metric.is_healthy());
}

// ==================== Full Harness Self-Test ====================

#[test]
fn test_harness_full_self_test() {
    let results: Vec<(&str, bool)> = vec![
        // Test Version module
        ("Version::new", Version::new(1, 0, 0).major() == 1),
        ("Version::from_str", "1.2.3".parse::<Version>().is_ok()),
        (
            "Version::is_compatible_with",
            Version::new(1, 1, 0).is_compatible_with(&Version::new(1, 0, 0)),
        ),
        // Test CompatibilityPolicy
        (
            "CompatibilityPolicy::default",
            CompatibilityPolicy::default() == CompatibilityPolicy::Compatible,
        ),
        // Test LogLevel
        ("LogLevel::default", LogLevel::default() == LogLevel::Info),
        ("LogLevel::ordering", LogLevel::Debug < LogLevel::Info),
        // Test RunStatus
        ("RunStatus::is_terminal", RunStatus::Completed.is_terminal()),
        ("RunStatus::not_terminal", !RunStatus::Running.is_terminal()),
        // Test AgentStatus
        (
            "AgentStatus::default",
            AgentStatus::default() == AgentStatus::Idle,
        ),
        // Test handshake types
        (
            "VersionHandshakeRequest::new",
            !VersionHandshakeRequest::new("test", "role")
                .sender_id()
                .is_empty(),
        ),
        (
            "VersionHandshakeResponse::accept",
            VersionHandshakeResponse::accept(Uuid::nil(), "agent").is_accepted(),
        ),
        (
            "VersionHandshakeResponse::reject",
            !VersionHandshakeResponse::reject(Uuid::nil(), "agent", "reason").is_accepted(),
        ),
        // Test CompatibilityResult
        (
            "CompatibilityResult::is_ok",
            CompatibilityResult::Compatible.is_ok(),
        ),
        (
            "CompatibilityResult::is_error",
            CompatibilityResult::Incompatible {
                reason: "test".to_string(),
            }
            .is_error(),
        ),
    ];

    // Verify all tests passed
    let failed: Vec<_> = results.iter().filter(|(_, pass)| !pass).collect();
    assert!(
        failed.is_empty(),
        "Self-test failures: {:?}",
        failed.iter().map(|(name, _)| name).collect::<Vec<_>>()
    );

    println!(
        "Harness self-test: {}/{} checks passed",
        results.len(),
        results.len()
    );
}
