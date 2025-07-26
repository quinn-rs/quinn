/// IETF Compliance Validator Framework
/// 
/// This module provides comprehensive validation of QUIC implementation
/// against IETF specifications including RFC 9000, draft-ietf-quic-address-discovery,
/// and draft-seemann-quic-nat-traversal.

use std::collections::HashMap;
use std::path::Path;
use std::fmt;

pub mod rfc_parser;
pub mod spec_validator;
pub mod endpoint_tester;
pub mod report_generator;

#[cfg(test)]
mod tests;

/// Represents a compliance requirement from an IETF specification
#[derive(Debug, Clone, PartialEq)]
pub struct ComplianceRequirement {
    /// Specification ID (e.g., "RFC9000", "draft-ietf-quic-address-discovery-00")
    pub spec_id: String,
    /// Section reference (e.g., "7.2.1")
    pub section: String,
    /// Requirement level (MUST, SHOULD, MAY)
    pub level: RequirementLevel,
    /// Human-readable description
    pub description: String,
    /// Category of requirement
    pub category: RequirementCategory,
}

/// Requirement levels from RFC 2119
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RequirementLevel {
    /// Absolute requirement
    Must,
    /// Absolute prohibition
    MustNot,
    /// Recommended
    Should,
    /// Not recommended
    ShouldNot,
    /// Optional
    May,
}

impl fmt::Display for RequirementLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Must => write!(f, "MUST"),
            Self::MustNot => write!(f, "MUST NOT"),
            Self::Should => write!(f, "SHOULD"),
            Self::ShouldNot => write!(f, "SHOULD NOT"),
            Self::May => write!(f, "MAY"),
        }
    }
}

/// Categories of requirements for organized testing
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RequirementCategory {
    /// Transport protocol requirements
    Transport,
    /// Frame encoding/decoding
    FrameFormat,
    /// Transport parameters
    TransportParameters,
    /// Connection establishment
    ConnectionEstablishment,
    /// NAT traversal
    NatTraversal,
    /// Address discovery
    AddressDiscovery,
    /// Error handling
    ErrorHandling,
    /// Security requirements
    Security,
    /// Performance requirements
    Performance,
}

/// Result of a compliance validation
#[derive(Debug, Clone)]
pub struct ComplianceResult {
    /// The requirement being validated
    pub requirement: ComplianceRequirement,
    /// Whether the requirement is met
    pub compliant: bool,
    /// Detailed explanation
    pub details: String,
    /// Evidence (e.g., test results, packet captures)
    pub evidence: Vec<Evidence>,
}

/// Evidence supporting compliance validation
#[derive(Debug, Clone)]
pub enum Evidence {
    /// Test result
    TestResult {
        test_name: String,
        passed: bool,
        output: String,
    },
    /// Packet capture showing behavior
    PacketCapture {
        description: String,
        packets: Vec<u8>,
    },
    /// Code reference
    CodeReference {
        file: String,
        line: usize,
        snippet: String,
    },
    /// External endpoint test
    EndpointTest {
        endpoint: String,
        result: String,
    },
}

/// Main compliance validator
pub struct ComplianceValidator {
    /// Parsed requirements from specifications
    requirements: Vec<ComplianceRequirement>,
    /// Validators for specific specs
    validators: HashMap<String, Box<dyn SpecValidator>>,
    /// Test endpoints for real-world validation
    test_endpoints: Vec<String>,
}

impl Default for ComplianceValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl ComplianceValidator {
    /// Create a new compliance validator
    pub fn new() -> Self {
        Self {
            requirements: Vec::new(),
            validators: HashMap::new(),
            test_endpoints: Vec::new(),
        }
    }

    /// Load requirements from RFC documents
    pub fn load_requirements(&mut self, rfc_path: &Path) -> Result<(), ValidationError> {
        let parser = rfc_parser::RfcParser::new();
        let requirements = parser.parse_file(rfc_path)?;
        self.requirements.extend(requirements);
        Ok(())
    }

    /// Register a specification validator
    pub fn register_validator(&mut self, spec_id: String, validator: Box<dyn SpecValidator>) {
        self.validators.insert(spec_id, validator);
    }

    /// Add test endpoint for real-world validation
    pub fn add_test_endpoint(&mut self, endpoint: String) {
        self.test_endpoints.push(endpoint);
    }

    /// Run all compliance validations
    pub fn validate_all(&self) -> ComplianceReport {
        let mut results = Vec::new();
        
        for requirement in &self.requirements {
            if let Some(validator) = self.validators.get(&requirement.spec_id) {
                let result = validator.validate(requirement);
                results.push(result);
            } else {
                results.push(ComplianceResult {
                    requirement: requirement.clone(),
                    compliant: false,
                    details: format!("No validator registered for {}", requirement.spec_id),
                    evidence: vec![],
                });
            }
        }

        ComplianceReport::new(results)
    }

    /// Validate against real endpoints
    pub async fn validate_endpoints(&self) -> EndpointValidationReport {
        let mut tester = endpoint_tester::EndpointTester::new();
        for endpoint in &self.test_endpoints {
            tester.add_endpoint(endpoint.clone());
        }
        tester.test_all_endpoints().await
    }
}

/// Trait for specification-specific validators
pub trait SpecValidator: Send + Sync {
    /// Validate a specific requirement
    fn validate(&self, requirement: &ComplianceRequirement) -> ComplianceResult;
    
    /// Get the specification ID this validator handles
    fn spec_id(&self) -> &str;
}

/// Compliance validation report
#[derive(Debug)]
pub struct ComplianceReport {
    /// All validation results
    pub results: Vec<ComplianceResult>,
    /// Summary statistics
    pub summary: ComplianceSummary,
    /// Timestamp
    pub timestamp: std::time::SystemTime,
}

impl ComplianceReport {
    fn new(results: Vec<ComplianceResult>) -> Self {
        let summary = ComplianceSummary::from_results(&results);
        Self {
            results,
            summary,
            timestamp: std::time::SystemTime::now(),
        }
    }

    /// Generate HTML report
    pub fn to_html(&self) -> String {
        report_generator::generate_html_report(self)
    }

    /// Generate JSON report
    pub fn to_json(&self) -> serde_json::Value {
        report_generator::generate_json_report(self)
    }
}

/// Summary of compliance results
#[derive(Debug)]
pub struct ComplianceSummary {
    /// Total requirements tested
    pub total_requirements: usize,
    /// Requirements passed
    pub passed: usize,
    /// Requirements failed
    pub failed: usize,
    /// Pass rate by requirement level
    pub pass_rate_by_level: HashMap<RequirementLevel, f64>,
    /// Pass rate by category
    pub pass_rate_by_category: HashMap<RequirementCategory, f64>,
}

impl ComplianceSummary {
    fn from_results(results: &[ComplianceResult]) -> Self {
        let total_requirements = results.len();
        let passed = results.iter().filter(|r| r.compliant).count();
        let failed = total_requirements - passed;

        let mut pass_rate_by_level = HashMap::new();
        let mut pass_rate_by_category = HashMap::new();

        // Calculate pass rates by level
        for level in &[
            RequirementLevel::Must,
            RequirementLevel::MustNot,
            RequirementLevel::Should,
            RequirementLevel::ShouldNot,
            RequirementLevel::May,
        ] {
            let level_results: Vec<_> = results
                .iter()
                .filter(|r| &r.requirement.level == level)
                .collect();
            
            if !level_results.is_empty() {
                let level_passed = level_results.iter().filter(|r| r.compliant).count();
                let pass_rate = level_passed as f64 / level_results.len() as f64;
                pass_rate_by_level.insert(level.clone(), pass_rate);
            }
        }

        // Calculate pass rates by category
        for category in &[
            RequirementCategory::Transport,
            RequirementCategory::FrameFormat,
            RequirementCategory::TransportParameters,
            RequirementCategory::ConnectionEstablishment,
            RequirementCategory::NatTraversal,
            RequirementCategory::AddressDiscovery,
            RequirementCategory::ErrorHandling,
            RequirementCategory::Security,
            RequirementCategory::Performance,
        ] {
            let category_results: Vec<_> = results
                .iter()
                .filter(|r| &r.requirement.category == category)
                .collect();
            
            if !category_results.is_empty() {
                let category_passed = category_results.iter().filter(|r| r.compliant).count();
                let pass_rate = category_passed as f64 / category_results.len() as f64;
                pass_rate_by_category.insert(category.clone(), pass_rate);
            }
        }

        Self {
            total_requirements,
            passed,
            failed,
            pass_rate_by_level,
            pass_rate_by_category,
        }
    }

    /// Overall compliance percentage
    pub fn compliance_percentage(&self) -> f64 {
        if self.total_requirements == 0 {
            0.0
        } else {
            (self.passed as f64 / self.total_requirements as f64) * 100.0
        }
    }

    /// Check if MUST requirements are met (minimum for compliance)
    pub fn must_requirements_met(&self) -> bool {
        self.pass_rate_by_level
            .get(&RequirementLevel::Must)
            .map(|&rate| rate == 1.0)
            .unwrap_or(true)
    }
}

/// Report from endpoint validation
#[derive(Debug)]
pub struct EndpointValidationReport {
    /// Results per endpoint
    pub endpoint_results: HashMap<String, EndpointResult>,
    /// Overall success rate
    pub success_rate: f64,
    /// Common issues found
    pub common_issues: Vec<String>,
}

/// Result of testing against a specific endpoint
#[derive(Debug)]
pub struct EndpointResult {
    /// Endpoint URL
    pub endpoint: String,
    /// Whether connection succeeded
    pub connected: bool,
    /// Supported QUIC versions
    pub quic_versions: Vec<u32>,
    /// Supported extensions
    pub extensions: Vec<String>,
    /// Compliance issues found
    pub issues: Vec<String>,
}

/// Errors that can occur during validation
#[derive(Debug)]
pub enum ValidationError {
    /// Error parsing RFC
    RfcParseError(String),
    /// Error loading specification
    SpecLoadError(String),
    /// Error running validation
    ValidationError(String),
    /// IO error
    IoError(std::io::Error),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RfcParseError(e) => write!(f, "RFC parse error: {e}"),
            Self::SpecLoadError(e) => write!(f, "Specification load error: {e}"),
            Self::ValidationError(e) => write!(f, "Validation error: {e}"),
            Self::IoError(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl std::error::Error for ValidationError {}

impl From<std::io::Error> for ValidationError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}