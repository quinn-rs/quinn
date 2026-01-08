use crate::registry::FailureReasonCode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCategory {
    HarnessPreflightError,
    HarnessOrchestrationError,
    HarnessObservationError,
    SutConnectivityFailure,
    SutBehaviorMismatch,
    InfrastructureFlake,
}

impl FailureCategory {
    pub fn is_harness_error(&self) -> bool {
        matches!(
            self,
            Self::HarnessPreflightError
                | Self::HarnessOrchestrationError
                | Self::HarnessObservationError
        )
    }

    pub fn is_sut_error(&self) -> bool {
        matches!(
            self,
            Self::SutConnectivityFailure | Self::SutBehaviorMismatch
        )
    }

    pub fn is_infrastructure_error(&self) -> bool {
        matches!(self, Self::InfrastructureFlake)
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::HarnessPreflightError => "Harness setup failed before test could run",
            Self::HarnessOrchestrationError => "Harness coordination failed during test",
            Self::HarnessObservationError => "Harness could not observe test outcome",
            Self::SutConnectivityFailure => "SUT failed to establish connectivity",
            Self::SutBehaviorMismatch => "SUT behavior did not match expectations",
            Self::InfrastructureFlake => "Transient infrastructure issue",
        }
    }

    pub fn from_context(
        reason: FailureReasonCode,
        harness_healthy: bool,
        test_ran_as_intended: bool,
    ) -> Option<Self> {
        if reason == FailureReasonCode::Success {
            return None;
        }

        if !harness_healthy {
            return Some(Self::HarnessPreflightError);
        }

        if !test_ran_as_intended {
            return Some(Self::HarnessOrchestrationError);
        }

        Some(match reason {
            FailureReasonCode::Timeout
            | FailureReasonCode::ConnectionRefused
            | FailureReasonCode::HandshakeFailed
            | FailureReasonCode::AddressUnreachable
            | FailureReasonCode::NoRouteToHost
            | FailureReasonCode::PortUnreachable
            | FailureReasonCode::NatBindingExpired
            | FailureReasonCode::RelayUnavailable
            | FailureReasonCode::CoordinatorUnreachable => Self::SutConnectivityFailure,

            FailureReasonCode::CryptoError
            | FailureReasonCode::TlsError
            | FailureReasonCode::PqcNegotiationFailed
            | FailureReasonCode::ProtocolViolation
            | FailureReasonCode::DataVerificationFailed => Self::SutBehaviorMismatch,

            FailureReasonCode::PmtuBlackhole
            | FailureReasonCode::StreamReset
            | FailureReasonCode::KeepaliveTimeout
            | FailureReasonCode::MigrationFailed => Self::SutConnectivityFailure,

            FailureReasonCode::RateLimited | FailureReasonCode::ResourceExhausted => {
                Self::InfrastructureFlake
            }

            FailureReasonCode::InternalError | FailureReasonCode::Unknown => {
                Self::HarnessObservationError
            }

            FailureReasonCode::Success => unreachable!("Success handled above"),
        })
    }

    pub fn should_retry(&self) -> bool {
        matches!(self, Self::InfrastructureFlake)
    }

    pub fn counts_against_sut(&self) -> bool {
        self.is_sut_error()
    }

    pub fn counts_against_harness(&self) -> bool {
        self.is_harness_error()
    }
}

impl std::fmt::Display for FailureCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HarnessPreflightError => write!(f, "Harness Preflight Error"),
            Self::HarnessOrchestrationError => write!(f, "Harness Orchestration Error"),
            Self::HarnessObservationError => write!(f, "Harness Observation Error"),
            Self::SutConnectivityFailure => write!(f, "SUT Connectivity Failure"),
            Self::SutBehaviorMismatch => write!(f, "SUT Behavior Mismatch"),
            Self::InfrastructureFlake => write!(f, "Infrastructure Flake"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifiedFailure {
    pub category: FailureCategory,
    pub reason_code: FailureReasonCode,
    pub message: String,
    pub harness_healthy: bool,
    pub test_ran_as_intended: bool,
    pub evidence: FailureEvidence,
}

impl ClassifiedFailure {
    /// Create a new classified failure, explicitly handling the case when classification fails.
    ///
    /// **DEPRECATED**: This function silently falls back to `HarnessObservationError` when
    /// `from_context` returns `None` (e.g., for Success codes). This can corrupt failure
    /// statistics. Use `try_new()` instead and handle the `None` case explicitly.
    ///
    /// # Panics in debug builds
    /// In debug builds, this function panics if called with a Success reason code,
    /// as this indicates a programming error.
    #[deprecated(
        since = "0.2.0",
        note = "Use try_new() and handle the None case explicitly to avoid corrupting failure statistics"
    )]
    pub fn new(
        reason_code: FailureReasonCode,
        message: &str,
        harness_healthy: bool,
        test_ran_as_intended: bool,
    ) -> Self {
        debug_assert!(
            reason_code != FailureReasonCode::Success,
            "ClassifiedFailure::new called with Success code - use try_new() instead"
        );
        let category =
            FailureCategory::from_context(reason_code, harness_healthy, test_ran_as_intended)
                .unwrap_or(FailureCategory::HarnessObservationError);
        Self {
            category,
            reason_code,
            message: message.to_string(),
            harness_healthy,
            test_ran_as_intended,
            evidence: FailureEvidence::default(),
        }
    }

    /// Create a new classified failure, returning `None` if the reason code is Success.
    ///
    /// This is the preferred way to create a `ClassifiedFailure` as it forces callers
    /// to handle the case where classification is not appropriate (e.g., for success outcomes).
    pub fn try_new(
        reason_code: FailureReasonCode,
        message: &str,
        harness_healthy: bool,
        test_ran_as_intended: bool,
    ) -> Option<Self> {
        let category =
            FailureCategory::from_context(reason_code, harness_healthy, test_ran_as_intended)?;
        Some(Self {
            category,
            reason_code,
            message: message.to_string(),
            harness_healthy,
            test_ran_as_intended,
            evidence: FailureEvidence::default(),
        })
    }

    pub fn with_evidence(mut self, evidence: FailureEvidence) -> Self {
        self.evidence = evidence;
        self
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FailureEvidence {
    pub agent_log_excerpt: Option<String>,
    pub sut_log_excerpt: Option<String>,
    pub pcap_summary: Option<String>,
    pub nat_state: Option<String>,
    pub frames_observed: Option<u32>,
    pub timeout_at_stage: Option<String>,
    pub connection_state: Option<String>,
}

impl FailureEvidence {
    pub fn has_evidence(&self) -> bool {
        self.agent_log_excerpt.is_some()
            || self.sut_log_excerpt.is_some()
            || self.pcap_summary.is_some()
            || self.nat_state.is_some()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FailureBreakdown {
    pub harness_preflight: u32,
    pub harness_orchestration: u32,
    pub harness_observation: u32,
    pub sut_connectivity: u32,
    pub sut_behavior: u32,
    pub infrastructure: u32,
}

impl FailureBreakdown {
    pub fn record(&mut self, category: FailureCategory) {
        match category {
            FailureCategory::HarnessPreflightError => self.harness_preflight += 1,
            FailureCategory::HarnessOrchestrationError => self.harness_orchestration += 1,
            FailureCategory::HarnessObservationError => self.harness_observation += 1,
            FailureCategory::SutConnectivityFailure => self.sut_connectivity += 1,
            FailureCategory::SutBehaviorMismatch => self.sut_behavior += 1,
            FailureCategory::InfrastructureFlake => self.infrastructure += 1,
        }
    }

    pub fn total_harness(&self) -> u32 {
        self.harness_preflight + self.harness_orchestration + self.harness_observation
    }

    pub fn total_sut(&self) -> u32 {
        self.sut_connectivity + self.sut_behavior
    }

    pub fn total(&self) -> u32 {
        self.total_harness() + self.total_sut() + self.infrastructure
    }

    pub fn harness_healthy(&self) -> bool {
        self.total_harness() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failure_category_classification() {
        assert!(FailureCategory::HarnessPreflightError.is_harness_error());
        assert!(FailureCategory::SutConnectivityFailure.is_sut_error());
        assert!(FailureCategory::InfrastructureFlake.is_infrastructure_error());
    }

    #[test]
    fn test_failure_category_from_context() {
        let cat = FailureCategory::from_context(FailureReasonCode::Timeout, true, true);
        assert_eq!(cat, Some(FailureCategory::SutConnectivityFailure));

        let cat = FailureCategory::from_context(FailureReasonCode::Timeout, false, true);
        assert_eq!(cat, Some(FailureCategory::HarnessPreflightError));

        let cat = FailureCategory::from_context(FailureReasonCode::Timeout, true, false);
        assert_eq!(cat, Some(FailureCategory::HarnessOrchestrationError));

        let cat = FailureCategory::from_context(FailureReasonCode::CryptoError, true, true);
        assert_eq!(cat, Some(FailureCategory::SutBehaviorMismatch));
    }

    #[test]
    fn test_failure_breakdown() {
        let mut breakdown = FailureBreakdown::default();
        breakdown.record(FailureCategory::SutConnectivityFailure);
        breakdown.record(FailureCategory::SutConnectivityFailure);
        breakdown.record(FailureCategory::HarnessPreflightError);

        assert_eq!(breakdown.sut_connectivity, 2);
        assert_eq!(breakdown.harness_preflight, 1);
        assert_eq!(breakdown.total_sut(), 2);
        assert_eq!(breakdown.total_harness(), 1);
        assert!(!breakdown.harness_healthy());
    }

    #[test]
    #[allow(deprecated)]
    fn test_classified_failure() {
        let failure = ClassifiedFailure::new(
            FailureReasonCode::Timeout,
            "Connection timed out after 30s",
            true,
            true,
        );
        assert_eq!(failure.category, FailureCategory::SutConnectivityFailure);
        assert!(failure.category.counts_against_sut());
    }

    #[test]
    fn test_from_context_success_returns_none() {
        let result = FailureCategory::from_context(FailureReasonCode::Success, true, true);
        assert!(result.is_none(), "Success should not classify as a failure");
    }

    #[test]
    fn test_from_context_success_with_unhealthy_harness_returns_none() {
        let result = FailureCategory::from_context(FailureReasonCode::Success, false, true);
        assert!(
            result.is_none(),
            "Success should return None regardless of harness state"
        );
    }

    #[test]
    fn test_from_context_failure_returns_some() {
        let result = FailureCategory::from_context(FailureReasonCode::Timeout, true, true);
        assert!(result.is_some(), "Timeout should classify as a failure");
        assert_eq!(result.unwrap(), FailureCategory::SutConnectivityFailure);
    }

    #[test]
    fn test_classified_failure_new_with_success_returns_none() {
        let result = ClassifiedFailure::try_new(
            FailureReasonCode::Success,
            "This is actually a success",
            true,
            true,
        );
        assert!(
            result.is_none(),
            "ClassifiedFailure::try_new should return None for Success"
        );
    }
}
