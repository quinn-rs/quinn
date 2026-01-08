//! Failure Classification Oracle Tests
//!
//! This module provides comprehensive oracle tests for the failure classification system.
//! Oracle tests verify that the classification algorithm produces expected results for
//! all combinations of:
//! - FailureReasonCode variants
//! - Harness health states
//! - Test execution states
//!
//! These tests serve as a specification for the classification logic and catch
//! any regressions in the classification algorithm.

use super::{ClassifiedFailure, FailureBreakdown, FailureCategory, FailureEvidence};
use crate::registry::FailureReasonCode;

/// Oracle table entry defining expected classification for a scenario
#[derive(Debug, Clone)]
pub struct OracleEntry {
    /// Failure reason code
    pub reason: FailureReasonCode,
    /// Was the harness healthy?
    pub harness_healthy: bool,
    /// Did the test run as intended?
    pub test_ran_as_intended: bool,
    /// Expected classification (None for success)
    pub expected_category: Option<FailureCategory>,
    /// Human-readable description of the scenario
    pub description: &'static str,
}

impl OracleEntry {
    pub const fn new(
        reason: FailureReasonCode,
        harness_healthy: bool,
        test_ran_as_intended: bool,
        expected_category: Option<FailureCategory>,
        description: &'static str,
    ) -> Self {
        Self {
            reason,
            harness_healthy,
            test_ran_as_intended,
            expected_category,
            description,
        }
    }

    /// Verify this oracle entry against the actual implementation
    pub fn verify(&self) -> OracleResult {
        let actual = FailureCategory::from_context(
            self.reason,
            self.harness_healthy,
            self.test_ran_as_intended,
        );

        OracleResult {
            entry: self.clone(),
            actual,
            passed: actual == self.expected_category,
        }
    }
}

/// Result of verifying an oracle entry
#[derive(Debug)]
pub struct OracleResult {
    pub entry: OracleEntry,
    pub actual: Option<FailureCategory>,
    pub passed: bool,
}

impl OracleResult {
    pub fn error_message(&self) -> Option<String> {
        if self.passed {
            None
        } else {
            Some(format!(
                "Oracle mismatch for {:?} (harness_healthy={}, test_ran_as_intended={}): expected {:?}, got {:?}. Scenario: {}",
                self.entry.reason,
                self.entry.harness_healthy,
                self.entry.test_ran_as_intended,
                self.entry.expected_category,
                self.actual,
                self.entry.description
            ))
        }
    }
}

/// Complete oracle table for failure classification
pub fn oracle_table() -> Vec<OracleEntry> {
    vec![
        // ==================== Success Cases ====================
        OracleEntry::new(
            FailureReasonCode::Success,
            true,
            true,
            None,
            "Success with healthy harness should not classify as failure",
        ),
        OracleEntry::new(
            FailureReasonCode::Success,
            false,
            true,
            None,
            "Success should return None even with unhealthy harness",
        ),
        OracleEntry::new(
            FailureReasonCode::Success,
            true,
            false,
            None,
            "Success should return None even if test didn't run as intended",
        ),
        OracleEntry::new(
            FailureReasonCode::Success,
            false,
            false,
            None,
            "Success should always return None regardless of context",
        ),
        // ==================== Harness Health Priority ====================
        // When harness is unhealthy (false, _), it takes highest precedence
        // All failure codes with unhealthy harness -> HarnessPreflightError
        OracleEntry::new(
            FailureReasonCode::Timeout,
            false,
            true,
            Some(FailureCategory::HarnessPreflightError),
            "Timeout with unhealthy harness -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::Timeout,
            false,
            false,
            Some(FailureCategory::HarnessPreflightError),
            "Timeout with unhealthy harness (test failed) -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::ConnectionRefused,
            false,
            true,
            Some(FailureCategory::HarnessPreflightError),
            "ConnectionRefused with unhealthy harness -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::ConnectionRefused,
            false,
            false,
            Some(FailureCategory::HarnessPreflightError),
            "ConnectionRefused with unhealthy harness (test failed) -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::HandshakeFailed,
            false,
            true,
            Some(FailureCategory::HarnessPreflightError),
            "HandshakeFailed with unhealthy harness -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::HandshakeFailed,
            false,
            false,
            Some(FailureCategory::HarnessPreflightError),
            "HandshakeFailed with unhealthy harness (test failed) -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::CryptoError,
            false,
            true,
            Some(FailureCategory::HarnessPreflightError),
            "CryptoError with unhealthy harness -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::CryptoError,
            false,
            false,
            Some(FailureCategory::HarnessPreflightError),
            "CryptoError with unhealthy harness (test failed) -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::TlsError,
            false,
            true,
            Some(FailureCategory::HarnessPreflightError),
            "TlsError with unhealthy harness -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::TlsError,
            false,
            false,
            Some(FailureCategory::HarnessPreflightError),
            "TlsError with unhealthy harness (test failed) -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::PqcNegotiationFailed,
            false,
            true,
            Some(FailureCategory::HarnessPreflightError),
            "PqcNegotiationFailed with unhealthy harness -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::PqcNegotiationFailed,
            false,
            false,
            Some(FailureCategory::HarnessPreflightError),
            "PqcNegotiationFailed with unhealthy harness (test failed) -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::ProtocolViolation,
            false,
            true,
            Some(FailureCategory::HarnessPreflightError),
            "ProtocolViolation with unhealthy harness -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::ProtocolViolation,
            false,
            false,
            Some(FailureCategory::HarnessPreflightError),
            "ProtocolViolation with unhealthy harness (test failed) -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::DataVerificationFailed,
            false,
            true,
            Some(FailureCategory::HarnessPreflightError),
            "DataVerificationFailed with unhealthy harness -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::DataVerificationFailed,
            false,
            false,
            Some(FailureCategory::HarnessPreflightError),
            "DataVerificationFailed with unhealthy harness (test failed) -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::AddressUnreachable,
            false,
            true,
            Some(FailureCategory::HarnessPreflightError),
            "AddressUnreachable with unhealthy harness -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::AddressUnreachable,
            false,
            false,
            Some(FailureCategory::HarnessPreflightError),
            "AddressUnreachable with unhealthy harness (test failed) -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::NoRouteToHost,
            false,
            true,
            Some(FailureCategory::HarnessPreflightError),
            "NoRouteToHost with unhealthy harness -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::NoRouteToHost,
            false,
            false,
            Some(FailureCategory::HarnessPreflightError),
            "NoRouteToHost with unhealthy harness (test failed) -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::PortUnreachable,
            false,
            true,
            Some(FailureCategory::HarnessPreflightError),
            "PortUnreachable with unhealthy harness -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::PortUnreachable,
            false,
            false,
            Some(FailureCategory::HarnessPreflightError),
            "PortUnreachable with unhealthy harness (test failed) -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::NatBindingExpired,
            false,
            true,
            Some(FailureCategory::HarnessPreflightError),
            "NatBindingExpired with unhealthy harness -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::NatBindingExpired,
            false,
            false,
            Some(FailureCategory::HarnessPreflightError),
            "NatBindingExpired with unhealthy harness (test failed) -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::RelayUnavailable,
            false,
            true,
            Some(FailureCategory::HarnessPreflightError),
            "RelayUnavailable with unhealthy harness -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::RelayUnavailable,
            false,
            false,
            Some(FailureCategory::HarnessPreflightError),
            "RelayUnavailable with unhealthy harness (test failed) -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::CoordinatorUnreachable,
            false,
            true,
            Some(FailureCategory::HarnessPreflightError),
            "CoordinatorUnreachable with unhealthy harness -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::CoordinatorUnreachable,
            false,
            false,
            Some(FailureCategory::HarnessPreflightError),
            "CoordinatorUnreachable with unhealthy harness (test failed) -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::PmtuBlackhole,
            false,
            true,
            Some(FailureCategory::HarnessPreflightError),
            "PmtuBlackhole with unhealthy harness -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::PmtuBlackhole,
            false,
            false,
            Some(FailureCategory::HarnessPreflightError),
            "PmtuBlackhole with unhealthy harness (test failed) -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::StreamReset,
            false,
            true,
            Some(FailureCategory::HarnessPreflightError),
            "StreamReset with unhealthy harness -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::StreamReset,
            false,
            false,
            Some(FailureCategory::HarnessPreflightError),
            "StreamReset with unhealthy harness (test failed) -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::KeepaliveTimeout,
            false,
            true,
            Some(FailureCategory::HarnessPreflightError),
            "KeepaliveTimeout with unhealthy harness -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::KeepaliveTimeout,
            false,
            false,
            Some(FailureCategory::HarnessPreflightError),
            "KeepaliveTimeout with unhealthy harness (test failed) -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::MigrationFailed,
            false,
            true,
            Some(FailureCategory::HarnessPreflightError),
            "MigrationFailed with unhealthy harness -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::MigrationFailed,
            false,
            false,
            Some(FailureCategory::HarnessPreflightError),
            "MigrationFailed with unhealthy harness (test failed) -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::RateLimited,
            false,
            true,
            Some(FailureCategory::HarnessPreflightError),
            "RateLimited with unhealthy harness -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::RateLimited,
            false,
            false,
            Some(FailureCategory::HarnessPreflightError),
            "RateLimited with unhealthy harness (test failed) -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::ResourceExhausted,
            false,
            true,
            Some(FailureCategory::HarnessPreflightError),
            "ResourceExhausted with unhealthy harness -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::ResourceExhausted,
            false,
            false,
            Some(FailureCategory::HarnessPreflightError),
            "ResourceExhausted with unhealthy harness (test failed) -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::InternalError,
            false,
            true,
            Some(FailureCategory::HarnessPreflightError),
            "InternalError with unhealthy harness -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::InternalError,
            false,
            false,
            Some(FailureCategory::HarnessPreflightError),
            "InternalError with unhealthy harness (test failed) -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::Unknown,
            false,
            true,
            Some(FailureCategory::HarnessPreflightError),
            "Unknown with unhealthy harness -> preflight error",
        ),
        OracleEntry::new(
            FailureReasonCode::Unknown,
            false,
            false,
            Some(FailureCategory::HarnessPreflightError),
            "Unknown with unhealthy harness (test failed) -> preflight error",
        ),
        // ==================== Test Execution Priority ====================
        // When test didn't run as intended (true, false) -> HarnessOrchestrationError
        OracleEntry::new(
            FailureReasonCode::Timeout,
            true,
            false,
            Some(FailureCategory::HarnessOrchestrationError),
            "Timeout with test not run as intended -> orchestration error",
        ),
        OracleEntry::new(
            FailureReasonCode::ConnectionRefused,
            true,
            false,
            Some(FailureCategory::HarnessOrchestrationError),
            "ConnectionRefused with test not run as intended -> orchestration error",
        ),
        OracleEntry::new(
            FailureReasonCode::HandshakeFailed,
            true,
            false,
            Some(FailureCategory::HarnessOrchestrationError),
            "HandshakeFailed with test not run as intended -> orchestration error",
        ),
        OracleEntry::new(
            FailureReasonCode::CryptoError,
            true,
            false,
            Some(FailureCategory::HarnessOrchestrationError),
            "CryptoError with test not run as intended -> orchestration error",
        ),
        OracleEntry::new(
            FailureReasonCode::TlsError,
            true,
            false,
            Some(FailureCategory::HarnessOrchestrationError),
            "TlsError with test not run as intended -> orchestration error",
        ),
        OracleEntry::new(
            FailureReasonCode::PqcNegotiationFailed,
            true,
            false,
            Some(FailureCategory::HarnessOrchestrationError),
            "PqcNegotiationFailed with test not run as intended -> orchestration error",
        ),
        OracleEntry::new(
            FailureReasonCode::ProtocolViolation,
            true,
            false,
            Some(FailureCategory::HarnessOrchestrationError),
            "ProtocolViolation with test not run as intended -> orchestration error",
        ),
        OracleEntry::new(
            FailureReasonCode::DataVerificationFailed,
            true,
            false,
            Some(FailureCategory::HarnessOrchestrationError),
            "DataVerificationFailed with test not run as intended -> orchestration error",
        ),
        OracleEntry::new(
            FailureReasonCode::AddressUnreachable,
            true,
            false,
            Some(FailureCategory::HarnessOrchestrationError),
            "AddressUnreachable with test not run as intended -> orchestration error",
        ),
        OracleEntry::new(
            FailureReasonCode::NoRouteToHost,
            true,
            false,
            Some(FailureCategory::HarnessOrchestrationError),
            "NoRouteToHost with test not run as intended -> orchestration error",
        ),
        OracleEntry::new(
            FailureReasonCode::PortUnreachable,
            true,
            false,
            Some(FailureCategory::HarnessOrchestrationError),
            "PortUnreachable with test not run as intended -> orchestration error",
        ),
        OracleEntry::new(
            FailureReasonCode::NatBindingExpired,
            true,
            false,
            Some(FailureCategory::HarnessOrchestrationError),
            "NatBindingExpired with test not run as intended -> orchestration error",
        ),
        OracleEntry::new(
            FailureReasonCode::RelayUnavailable,
            true,
            false,
            Some(FailureCategory::HarnessOrchestrationError),
            "RelayUnavailable with test not run as intended -> orchestration error",
        ),
        OracleEntry::new(
            FailureReasonCode::CoordinatorUnreachable,
            true,
            false,
            Some(FailureCategory::HarnessOrchestrationError),
            "CoordinatorUnreachable with test not run as intended -> orchestration error",
        ),
        OracleEntry::new(
            FailureReasonCode::PmtuBlackhole,
            true,
            false,
            Some(FailureCategory::HarnessOrchestrationError),
            "PmtuBlackhole with test not run as intended -> orchestration error",
        ),
        OracleEntry::new(
            FailureReasonCode::StreamReset,
            true,
            false,
            Some(FailureCategory::HarnessOrchestrationError),
            "StreamReset with test not run as intended -> orchestration error",
        ),
        OracleEntry::new(
            FailureReasonCode::KeepaliveTimeout,
            true,
            false,
            Some(FailureCategory::HarnessOrchestrationError),
            "KeepaliveTimeout with test not run as intended -> orchestration error",
        ),
        OracleEntry::new(
            FailureReasonCode::MigrationFailed,
            true,
            false,
            Some(FailureCategory::HarnessOrchestrationError),
            "MigrationFailed with test not run as intended -> orchestration error",
        ),
        OracleEntry::new(
            FailureReasonCode::RateLimited,
            true,
            false,
            Some(FailureCategory::HarnessOrchestrationError),
            "RateLimited with test not run as intended -> orchestration error",
        ),
        OracleEntry::new(
            FailureReasonCode::ResourceExhausted,
            true,
            false,
            Some(FailureCategory::HarnessOrchestrationError),
            "ResourceExhausted with test not run as intended -> orchestration error",
        ),
        OracleEntry::new(
            FailureReasonCode::InternalError,
            true,
            false,
            Some(FailureCategory::HarnessOrchestrationError),
            "InternalError with test not run as intended -> orchestration error",
        ),
        OracleEntry::new(
            FailureReasonCode::Unknown,
            true,
            false,
            Some(FailureCategory::HarnessOrchestrationError),
            "Unknown with test not run as intended -> orchestration error",
        ),
        // ==================== Connectivity Failures (Healthy Harness, Good Test) ====================
        OracleEntry::new(
            FailureReasonCode::Timeout,
            true,
            true,
            Some(FailureCategory::SutConnectivityFailure),
            "Timeout with healthy harness is SUT connectivity failure",
        ),
        OracleEntry::new(
            FailureReasonCode::ConnectionRefused,
            true,
            true,
            Some(FailureCategory::SutConnectivityFailure),
            "Connection refused is SUT connectivity failure",
        ),
        OracleEntry::new(
            FailureReasonCode::HandshakeFailed,
            true,
            true,
            Some(FailureCategory::SutConnectivityFailure),
            "Handshake failure is SUT connectivity failure",
        ),
        OracleEntry::new(
            FailureReasonCode::AddressUnreachable,
            true,
            true,
            Some(FailureCategory::SutConnectivityFailure),
            "Address unreachable is SUT connectivity failure",
        ),
        OracleEntry::new(
            FailureReasonCode::NoRouteToHost,
            true,
            true,
            Some(FailureCategory::SutConnectivityFailure),
            "No route to host is SUT connectivity failure",
        ),
        OracleEntry::new(
            FailureReasonCode::PortUnreachable,
            true,
            true,
            Some(FailureCategory::SutConnectivityFailure),
            "Port unreachable is SUT connectivity failure",
        ),
        OracleEntry::new(
            FailureReasonCode::NatBindingExpired,
            true,
            true,
            Some(FailureCategory::SutConnectivityFailure),
            "NAT binding expired is SUT connectivity failure",
        ),
        OracleEntry::new(
            FailureReasonCode::RelayUnavailable,
            true,
            true,
            Some(FailureCategory::SutConnectivityFailure),
            "Relay unavailable is SUT connectivity failure",
        ),
        OracleEntry::new(
            FailureReasonCode::CoordinatorUnreachable,
            true,
            true,
            Some(FailureCategory::SutConnectivityFailure),
            "Coordinator unreachable is SUT connectivity failure",
        ),
        OracleEntry::new(
            FailureReasonCode::PmtuBlackhole,
            true,
            true,
            Some(FailureCategory::SutConnectivityFailure),
            "PMTU blackhole is SUT connectivity failure",
        ),
        OracleEntry::new(
            FailureReasonCode::StreamReset,
            true,
            true,
            Some(FailureCategory::SutConnectivityFailure),
            "Stream reset is SUT connectivity failure",
        ),
        OracleEntry::new(
            FailureReasonCode::KeepaliveTimeout,
            true,
            true,
            Some(FailureCategory::SutConnectivityFailure),
            "Keepalive timeout is SUT connectivity failure",
        ),
        OracleEntry::new(
            FailureReasonCode::MigrationFailed,
            true,
            true,
            Some(FailureCategory::SutConnectivityFailure),
            "Migration failed is SUT connectivity failure",
        ),
        // ==================== Behavior Mismatch (Healthy Harness, Good Test) ====================
        OracleEntry::new(
            FailureReasonCode::CryptoError,
            true,
            true,
            Some(FailureCategory::SutBehaviorMismatch),
            "Crypto error is SUT behavior mismatch",
        ),
        OracleEntry::new(
            FailureReasonCode::TlsError,
            true,
            true,
            Some(FailureCategory::SutBehaviorMismatch),
            "TLS error is SUT behavior mismatch",
        ),
        OracleEntry::new(
            FailureReasonCode::PqcNegotiationFailed,
            true,
            true,
            Some(FailureCategory::SutBehaviorMismatch),
            "PQC negotiation failed is SUT behavior mismatch",
        ),
        OracleEntry::new(
            FailureReasonCode::ProtocolViolation,
            true,
            true,
            Some(FailureCategory::SutBehaviorMismatch),
            "Protocol violation is SUT behavior mismatch",
        ),
        OracleEntry::new(
            FailureReasonCode::DataVerificationFailed,
            true,
            true,
            Some(FailureCategory::SutBehaviorMismatch),
            "Data verification failed is SUT behavior mismatch",
        ),
        // ==================== Infrastructure Flakes (Healthy Harness, Good Test) ====================
        OracleEntry::new(
            FailureReasonCode::RateLimited,
            true,
            true,
            Some(FailureCategory::InfrastructureFlake),
            "Rate limited is infrastructure flake",
        ),
        OracleEntry::new(
            FailureReasonCode::ResourceExhausted,
            true,
            true,
            Some(FailureCategory::InfrastructureFlake),
            "Resource exhausted is infrastructure flake",
        ),
        // ==================== Observation Errors (Healthy Harness, Good Test) ====================
        OracleEntry::new(
            FailureReasonCode::InternalError,
            true,
            true,
            Some(FailureCategory::HarnessObservationError),
            "Internal error is harness observation error",
        ),
        OracleEntry::new(
            FailureReasonCode::Unknown,
            true,
            true,
            Some(FailureCategory::HarnessObservationError),
            "Unknown error is harness observation error",
        ),
    ]
}

/// Run all oracle tests and return summary
pub fn run_oracle_suite() -> OracleSuiteResult {
    let entries = oracle_table();
    let results: Vec<OracleResult> = entries.iter().map(|e| e.verify()).collect();

    let passed = results.iter().filter(|r| r.passed).count();
    let failed = results.iter().filter(|r| !r.passed).count();
    let errors: Vec<String> = results.iter().filter_map(|r| r.error_message()).collect();

    OracleSuiteResult {
        total: results.len(),
        passed,
        failed,
        errors,
    }
}

/// Summary of oracle suite execution
#[derive(Debug)]
pub struct OracleSuiteResult {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

impl OracleSuiteResult {
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Oracle Table Completeness ====================

    #[test]
    fn test_oracle_table_covers_all_failure_reason_codes() {
        let entries = oracle_table();

        // All FailureReasonCode variants that should appear in oracle
        let expected_codes = [
            FailureReasonCode::Success,
            FailureReasonCode::Timeout,
            FailureReasonCode::ConnectionRefused,
            FailureReasonCode::HandshakeFailed,
            FailureReasonCode::CryptoError,
            FailureReasonCode::PmtuBlackhole,
            FailureReasonCode::NatBindingExpired,
            FailureReasonCode::AddressUnreachable,
            FailureReasonCode::NoRouteToHost,
            FailureReasonCode::PortUnreachable,
            FailureReasonCode::TlsError,
            FailureReasonCode::PqcNegotiationFailed,
            FailureReasonCode::StreamReset,
            FailureReasonCode::DataVerificationFailed,
            FailureReasonCode::KeepaliveTimeout,
            FailureReasonCode::MigrationFailed,
            FailureReasonCode::RelayUnavailable,
            FailureReasonCode::CoordinatorUnreachable,
            FailureReasonCode::RateLimited,
            FailureReasonCode::ResourceExhausted,
            FailureReasonCode::ProtocolViolation,
            FailureReasonCode::InternalError,
            FailureReasonCode::Unknown,
        ];

        for code in &expected_codes {
            let found = entries
                .iter()
                .any(|e| std::mem::discriminant(&e.reason) == std::mem::discriminant(code));
            assert!(found, "Oracle table missing entry for {:?}", code);
        }
    }

    #[test]
    fn test_oracle_table_covers_all_4_context_combinations() {
        let entries = oracle_table();

        // All failure codes (excluding Success which has special handling)
        let failure_codes = [
            FailureReasonCode::Timeout,
            FailureReasonCode::ConnectionRefused,
            FailureReasonCode::HandshakeFailed,
            FailureReasonCode::CryptoError,
            FailureReasonCode::PmtuBlackhole,
            FailureReasonCode::NatBindingExpired,
            FailureReasonCode::AddressUnreachable,
            FailureReasonCode::NoRouteToHost,
            FailureReasonCode::PortUnreachable,
            FailureReasonCode::TlsError,
            FailureReasonCode::PqcNegotiationFailed,
            FailureReasonCode::StreamReset,
            FailureReasonCode::DataVerificationFailed,
            FailureReasonCode::KeepaliveTimeout,
            FailureReasonCode::MigrationFailed,
            FailureReasonCode::RelayUnavailable,
            FailureReasonCode::CoordinatorUnreachable,
            FailureReasonCode::RateLimited,
            FailureReasonCode::ResourceExhausted,
            FailureReasonCode::ProtocolViolation,
            FailureReasonCode::InternalError,
            FailureReasonCode::Unknown,
        ];

        // All 4 context combinations
        let contexts = [
            (true, true),   // Healthy harness, test ran as intended
            (true, false),  // Healthy harness, test didn't run as intended
            (false, true),  // Unhealthy harness, test ran as intended
            (false, false), // Unhealthy harness, test didn't run as intended
        ];

        for code in &failure_codes {
            for (harness_healthy, test_ran) in &contexts {
                let found = entries.iter().any(|e| {
                    std::mem::discriminant(&e.reason) == std::mem::discriminant(code)
                        && e.harness_healthy == *harness_healthy
                        && e.test_ran_as_intended == *test_ran
                });
                assert!(
                    found,
                    "Oracle table missing entry for {:?} with context (harness_healthy={}, test_ran={})",
                    code, harness_healthy, test_ran
                );
            }
        }

        // Verify Success has all 4 combinations
        for (harness_healthy, test_ran) in &contexts {
            let found = entries.iter().any(|e| {
                e.reason == FailureReasonCode::Success
                    && e.harness_healthy == *harness_healthy
                    && e.test_ran_as_intended == *test_ran
            });
            assert!(
                found,
                "Oracle table missing Success entry with context (harness_healthy={}, test_ran={})",
                harness_healthy, test_ran
            );
        }
    }

    // ==================== Full Oracle Suite ====================

    #[test]
    fn test_oracle_suite_all_pass() {
        let result = run_oracle_suite();

        if !result.all_passed() {
            for error in &result.errors {
                eprintln!("Oracle failure: {error}");
            }
            panic!(
                "Oracle suite failed: {}/{} passed",
                result.passed, result.total
            );
        }

        assert!(result.all_passed());
        assert!(result.total > 0);
        println!(
            "Oracle suite: {}/{} tests passed",
            result.passed, result.total
        );
    }

    // ==================== Individual Classification Tests ====================

    #[test]
    fn test_success_never_classified() {
        // Success should never be classified as a failure, regardless of context
        let contexts = [(true, true), (true, false), (false, true), (false, false)];

        for (harness_healthy, test_ran) in contexts {
            let result = FailureCategory::from_context(
                FailureReasonCode::Success,
                harness_healthy,
                test_ran,
            );
            assert!(
                result.is_none(),
                "Success should not be classified (harness_healthy={harness_healthy}, test_ran={test_ran})"
            );
        }
    }

    #[test]
    fn test_unhealthy_harness_overrides_all() {
        // When harness is unhealthy, all failures should be HarnessPreflightError
        let failure_codes = [
            FailureReasonCode::Timeout,
            FailureReasonCode::CryptoError,
            FailureReasonCode::RateLimited,
            FailureReasonCode::InternalError,
        ];

        for code in &failure_codes {
            let result = FailureCategory::from_context(*code, false, true);
            assert_eq!(
                result,
                Some(FailureCategory::HarnessPreflightError),
                "Unhealthy harness should override {:?}",
                code
            );
        }
    }

    #[test]
    fn test_test_not_ran_overrides_sut_classification() {
        // When test didn't run as intended (but harness was healthy), should be orchestration error
        let failure_codes = [
            FailureReasonCode::Timeout,
            FailureReasonCode::CryptoError,
            FailureReasonCode::RateLimited,
        ];

        for code in &failure_codes {
            let result = FailureCategory::from_context(*code, true, false);
            assert_eq!(
                result,
                Some(FailureCategory::HarnessOrchestrationError),
                "Test not ran should override {:?}",
                code
            );
        }
    }

    #[test]
    fn test_connectivity_failures_under_normal_conditions() {
        let connectivity_codes = [
            FailureReasonCode::Timeout,
            FailureReasonCode::ConnectionRefused,
            FailureReasonCode::HandshakeFailed,
            FailureReasonCode::AddressUnreachable,
            FailureReasonCode::NoRouteToHost,
            FailureReasonCode::PortUnreachable,
            FailureReasonCode::NatBindingExpired,
            FailureReasonCode::RelayUnavailable,
            FailureReasonCode::CoordinatorUnreachable,
            FailureReasonCode::PmtuBlackhole,
            FailureReasonCode::StreamReset,
            FailureReasonCode::KeepaliveTimeout,
            FailureReasonCode::MigrationFailed,
        ];

        for code in &connectivity_codes {
            let result = FailureCategory::from_context(*code, true, true);
            assert_eq!(
                result,
                Some(FailureCategory::SutConnectivityFailure),
                "{:?} should be SUT connectivity failure under normal conditions",
                code
            );
        }
    }

    #[test]
    fn test_behavior_failures_under_normal_conditions() {
        let behavior_codes = [
            FailureReasonCode::CryptoError,
            FailureReasonCode::TlsError,
            FailureReasonCode::PqcNegotiationFailed,
            FailureReasonCode::ProtocolViolation,
            FailureReasonCode::DataVerificationFailed,
        ];

        for code in &behavior_codes {
            let result = FailureCategory::from_context(*code, true, true);
            assert_eq!(
                result,
                Some(FailureCategory::SutBehaviorMismatch),
                "{:?} should be SUT behavior mismatch under normal conditions",
                code
            );
        }
    }

    #[test]
    fn test_infrastructure_flakes_under_normal_conditions() {
        let flake_codes = [
            FailureReasonCode::RateLimited,
            FailureReasonCode::ResourceExhausted,
        ];

        for code in &flake_codes {
            let result = FailureCategory::from_context(*code, true, true);
            assert_eq!(
                result,
                Some(FailureCategory::InfrastructureFlake),
                "{:?} should be infrastructure flake under normal conditions",
                code
            );
        }
    }

    #[test]
    fn test_observation_errors_under_normal_conditions() {
        let observation_codes = [FailureReasonCode::InternalError, FailureReasonCode::Unknown];

        for code in &observation_codes {
            let result = FailureCategory::from_context(*code, true, true);
            assert_eq!(
                result,
                Some(FailureCategory::HarnessObservationError),
                "{:?} should be harness observation error under normal conditions",
                code
            );
        }
    }

    // ==================== Classification Properties ====================

    #[test]
    fn test_is_harness_error_property() {
        assert!(FailureCategory::HarnessPreflightError.is_harness_error());
        assert!(FailureCategory::HarnessOrchestrationError.is_harness_error());
        assert!(FailureCategory::HarnessObservationError.is_harness_error());
        assert!(!FailureCategory::SutConnectivityFailure.is_harness_error());
        assert!(!FailureCategory::SutBehaviorMismatch.is_harness_error());
        assert!(!FailureCategory::InfrastructureFlake.is_harness_error());
    }

    #[test]
    fn test_is_sut_error_property() {
        assert!(!FailureCategory::HarnessPreflightError.is_sut_error());
        assert!(!FailureCategory::HarnessOrchestrationError.is_sut_error());
        assert!(!FailureCategory::HarnessObservationError.is_sut_error());
        assert!(FailureCategory::SutConnectivityFailure.is_sut_error());
        assert!(FailureCategory::SutBehaviorMismatch.is_sut_error());
        assert!(!FailureCategory::InfrastructureFlake.is_sut_error());
    }

    #[test]
    fn test_is_infrastructure_error_property() {
        assert!(!FailureCategory::HarnessPreflightError.is_infrastructure_error());
        assert!(!FailureCategory::HarnessOrchestrationError.is_infrastructure_error());
        assert!(!FailureCategory::HarnessObservationError.is_infrastructure_error());
        assert!(!FailureCategory::SutConnectivityFailure.is_infrastructure_error());
        assert!(!FailureCategory::SutBehaviorMismatch.is_infrastructure_error());
        assert!(FailureCategory::InfrastructureFlake.is_infrastructure_error());
    }

    #[test]
    fn test_should_retry_property() {
        // Only infrastructure flakes should be retried
        assert!(!FailureCategory::HarnessPreflightError.should_retry());
        assert!(!FailureCategory::HarnessOrchestrationError.should_retry());
        assert!(!FailureCategory::HarnessObservationError.should_retry());
        assert!(!FailureCategory::SutConnectivityFailure.should_retry());
        assert!(!FailureCategory::SutBehaviorMismatch.should_retry());
        assert!(FailureCategory::InfrastructureFlake.should_retry());
    }

    #[test]
    fn test_counts_against_sut_matches_is_sut_error() {
        for category in [
            FailureCategory::HarnessPreflightError,
            FailureCategory::HarnessOrchestrationError,
            FailureCategory::HarnessObservationError,
            FailureCategory::SutConnectivityFailure,
            FailureCategory::SutBehaviorMismatch,
            FailureCategory::InfrastructureFlake,
        ] {
            assert_eq!(
                category.counts_against_sut(),
                category.is_sut_error(),
                "{:?}.counts_against_sut() should match is_sut_error()",
                category
            );
        }
    }

    #[test]
    fn test_counts_against_harness_matches_is_harness_error() {
        for category in [
            FailureCategory::HarnessPreflightError,
            FailureCategory::HarnessOrchestrationError,
            FailureCategory::HarnessObservationError,
            FailureCategory::SutConnectivityFailure,
            FailureCategory::SutBehaviorMismatch,
            FailureCategory::InfrastructureFlake,
        ] {
            assert_eq!(
                category.counts_against_harness(),
                category.is_harness_error(),
                "{:?}.counts_against_harness() should match is_harness_error()",
                category
            );
        }
    }

    // ==================== FailureBreakdown Tests ====================

    #[test]
    fn test_failure_breakdown_record_all_categories() {
        let mut breakdown = FailureBreakdown::default();

        breakdown.record(FailureCategory::HarnessPreflightError);
        breakdown.record(FailureCategory::HarnessOrchestrationError);
        breakdown.record(FailureCategory::HarnessObservationError);
        breakdown.record(FailureCategory::SutConnectivityFailure);
        breakdown.record(FailureCategory::SutBehaviorMismatch);
        breakdown.record(FailureCategory::InfrastructureFlake);

        assert_eq!(breakdown.harness_preflight, 1);
        assert_eq!(breakdown.harness_orchestration, 1);
        assert_eq!(breakdown.harness_observation, 1);
        assert_eq!(breakdown.sut_connectivity, 1);
        assert_eq!(breakdown.sut_behavior, 1);
        assert_eq!(breakdown.infrastructure, 1);
        assert_eq!(breakdown.total(), 6);
        assert_eq!(breakdown.total_harness(), 3);
        assert_eq!(breakdown.total_sut(), 2);
    }

    #[test]
    fn test_failure_breakdown_harness_healthy() {
        let mut breakdown = FailureBreakdown::default();
        assert!(breakdown.harness_healthy());

        breakdown.record(FailureCategory::SutConnectivityFailure);
        assert!(breakdown.harness_healthy());

        breakdown.record(FailureCategory::HarnessPreflightError);
        assert!(!breakdown.harness_healthy());
    }

    // ==================== ClassifiedFailure Tests ====================

    #[test]
    fn test_classified_failure_with_evidence() {
        let evidence = FailureEvidence {
            agent_log_excerpt: Some("Error in log".to_string()),
            timeout_at_stage: Some("handshake".to_string()),
            ..Default::default()
        };

        let failure = ClassifiedFailure::try_new(
            FailureReasonCode::Timeout,
            "Connection timed out",
            true,
            true,
        )
        .expect("Timeout should classify as failure")
        .with_evidence(evidence);

        assert!(failure.evidence.has_evidence());
        assert_eq!(
            failure.evidence.agent_log_excerpt,
            Some("Error in log".to_string())
        );
    }

    #[test]
    fn test_failure_evidence_has_evidence() {
        let empty = FailureEvidence::default();
        assert!(!empty.has_evidence());

        let with_log = FailureEvidence {
            agent_log_excerpt: Some("log".to_string()),
            ..Default::default()
        };
        assert!(with_log.has_evidence());

        let with_pcap = FailureEvidence {
            pcap_summary: Some("packets".to_string()),
            ..Default::default()
        };
        assert!(with_pcap.has_evidence());
    }
}
