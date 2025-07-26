use super::*;

#[test]
fn test_compliance_requirement_creation() {
    let req = ComplianceRequirement {
        spec_id: "RFC9000".to_string(),
        section: "7.2.1".to_string(),
        level: RequirementLevel::Must,
        description: "Endpoints MUST NOT send data on any stream without ensuring that stream flow control credit is available".to_string(),
        category: RequirementCategory::Transport,
    };

    assert_eq!(req.spec_id, "RFC9000");
    assert_eq!(req.level, RequirementLevel::Must);
    assert_eq!(req.category, RequirementCategory::Transport);
}

#[test]
fn test_compliance_validator_new() {
    let validator = ComplianceValidator::new();
    assert!(validator.requirements.is_empty());
    assert!(validator.validators.is_empty());
    assert!(validator.test_endpoints.is_empty());
}

#[test]
fn test_add_test_endpoint() {
    let mut validator = ComplianceValidator::new();
    validator.add_test_endpoint("quic.tech:443".to_string());
    validator.add_test_endpoint("cloudflare.com:443".to_string());
    
    assert_eq!(validator.test_endpoints.len(), 2);
    assert_eq!(validator.test_endpoints[0], "quic.tech:443");
    assert_eq!(validator.test_endpoints[1], "cloudflare.com:443");
}

#[test]
fn test_compliance_summary_calculation() {
    let results = vec![
        ComplianceResult {
            requirement: ComplianceRequirement {
                spec_id: "RFC9000".to_string(),
                section: "7.2".to_string(),
                level: RequirementLevel::Must,
                description: "Test requirement 1".to_string(),
                category: RequirementCategory::Transport,
            },
            compliant: true,
            details: "Passed".to_string(),
            evidence: vec![],
        },
        ComplianceResult {
            requirement: ComplianceRequirement {
                spec_id: "RFC9000".to_string(),
                section: "7.3".to_string(),
                level: RequirementLevel::Must,
                description: "Test requirement 2".to_string(),
                category: RequirementCategory::Transport,
            },
            compliant: false,
            details: "Failed".to_string(),
            evidence: vec![],
        },
        ComplianceResult {
            requirement: ComplianceRequirement {
                spec_id: "RFC9000".to_string(),
                section: "8.1".to_string(),
                level: RequirementLevel::Should,
                description: "Test requirement 3".to_string(),
                category: RequirementCategory::ErrorHandling,
            },
            compliant: true,
            details: "Passed".to_string(),
            evidence: vec![],
        },
    ];

    let summary = ComplianceSummary::from_results(&results);
    
    assert_eq!(summary.total_requirements, 3);
    assert_eq!(summary.passed, 2);
    assert_eq!(summary.failed, 1);
    assert!((summary.compliance_percentage() - 66.66666666666667).abs() < 0.00001);
    assert!(!summary.must_requirements_met()); // One MUST requirement failed
    
    // Check pass rates by level
    assert_eq!(summary.pass_rate_by_level.get(&RequirementLevel::Must), Some(&0.5));
    assert_eq!(summary.pass_rate_by_level.get(&RequirementLevel::Should), Some(&1.0));
    
    // Check pass rates by category
    assert_eq!(summary.pass_rate_by_category.get(&RequirementCategory::Transport), Some(&0.5));
    assert_eq!(summary.pass_rate_by_category.get(&RequirementCategory::ErrorHandling), Some(&1.0));
}

#[test]
fn test_must_requirements_met() {
    // All MUST requirements pass
    let results = vec![
        ComplianceResult {
            requirement: ComplianceRequirement {
                spec_id: "RFC9000".to_string(),
                section: "7.2".to_string(),
                level: RequirementLevel::Must,
                description: "Test".to_string(),
                category: RequirementCategory::Transport,
            },
            compliant: true,
            details: "Passed".to_string(),
            evidence: vec![],
        },
    ];
    
    let summary = ComplianceSummary::from_results(&results);
    assert!(summary.must_requirements_met());
    
    // No MUST requirements
    let results = vec![
        ComplianceResult {
            requirement: ComplianceRequirement {
                spec_id: "RFC9000".to_string(),
                section: "7.2".to_string(),
                level: RequirementLevel::Should,
                description: "Test".to_string(),
                category: RequirementCategory::Transport,
            },
            compliant: false,
            details: "Failed".to_string(),
            evidence: vec![],
        },
    ];
    
    let summary = ComplianceSummary::from_results(&results);
    assert!(summary.must_requirements_met()); // No MUST requirements, so technically met
}

#[test]
fn test_evidence_types() {
    let test_evidence = Evidence::TestResult {
        test_name: "test_transport_parameters".to_string(),
        passed: true,
        output: "All assertions passed".to_string(),
    };
    
    let packet_evidence = Evidence::PacketCapture {
        description: "Initial handshake".to_string(),
        packets: vec![0x01, 0x02, 0x03],
    };
    
    let code_evidence = Evidence::CodeReference {
        file: "src/transport.rs".to_string(),
        line: 123,
        snippet: "validate_parameters(&params)?;".to_string(),
    };
    
    let endpoint_evidence = Evidence::EndpointTest {
        endpoint: "cloudflare.com:443".to_string(),
        result: "Successfully connected with QUIC v1".to_string(),
    };
    
    match test_evidence {
        Evidence::TestResult { test_name, passed, .. } => {
            assert_eq!(test_name, "test_transport_parameters");
            assert!(passed);
        }
        _ => panic!("Wrong evidence type"),
    }
    
    match packet_evidence {
        Evidence::PacketCapture { packets, .. } => {
            assert_eq!(packets.len(), 3);
        }
        _ => panic!("Wrong evidence type"),
    }
    
    match code_evidence {
        Evidence::CodeReference { line, .. } => {
            assert_eq!(line, 123);
        }
        _ => panic!("Wrong evidence type"),
    }
    
    match endpoint_evidence {
        Evidence::EndpointTest { endpoint, .. } => {
            assert_eq!(endpoint, "cloudflare.com:443");
        }
        _ => panic!("Wrong evidence type"),
    }
}

// Mock validator for testing
struct MockValidator {
    spec_id: String,
    pass_all: bool,
}

impl SpecValidator for MockValidator {
    fn validate(&self, requirement: &ComplianceRequirement) -> ComplianceResult {
        ComplianceResult {
            requirement: requirement.clone(),
            compliant: self.pass_all,
            details: if self.pass_all { 
                "Mock validation passed".to_string() 
            } else { 
                "Mock validation failed".to_string() 
            },
            evidence: vec![
                Evidence::TestResult {
                    test_name: "mock_test".to_string(),
                    passed: self.pass_all,
                    output: "Mock test output".to_string(),
                }
            ],
        }
    }
    
    fn spec_id(&self) -> &str {
        &self.spec_id
    }
}

#[test]
fn test_validator_registration() {
    let mut validator = ComplianceValidator::new();
    
    let mock = Box::new(MockValidator {
        spec_id: "RFC9000".to_string(),
        pass_all: true,
    });
    
    validator.register_validator("RFC9000".to_string(), mock);
    assert_eq!(validator.validators.len(), 1);
    assert!(validator.validators.contains_key("RFC9000"));
}

#[test]
fn test_validate_all_with_mock() {
    let mut validator = ComplianceValidator::new();
    
    // Add some requirements
    validator.requirements = vec![
        ComplianceRequirement {
            spec_id: "RFC9000".to_string(),
            section: "7.2".to_string(),
            level: RequirementLevel::Must,
            description: "Test requirement".to_string(),
            category: RequirementCategory::Transport,
        },
        ComplianceRequirement {
            spec_id: "RFC9001".to_string(),
            section: "5.1".to_string(),
            level: RequirementLevel::Should,
            description: "Another test".to_string(),
            category: RequirementCategory::Security,
        },
    ];
    
    // Register validator for RFC9000 only
    let mock = Box::new(MockValidator {
        spec_id: "RFC9000".to_string(),
        pass_all: true,
    });
    validator.register_validator("RFC9000".to_string(), mock);
    
    let report = validator.validate_all();
    
    assert_eq!(report.results.len(), 2);
    assert!(report.results[0].compliant); // RFC9000 has validator
    assert!(!report.results[1].compliant); // RFC9001 has no validator
    assert_eq!(report.summary.total_requirements, 2);
    assert_eq!(report.summary.passed, 1);
    assert_eq!(report.summary.failed, 1);
}

#[test]
fn test_validation_error_display() {
    let err = ValidationError::RfcParseError("Invalid format".to_string());
    assert_eq!(err.to_string(), "RFC parse error: Invalid format");
    
    let err = ValidationError::SpecLoadError("File not found".to_string());
    assert_eq!(err.to_string(), "Specification load error: File not found");
    
    let err = ValidationError::ValidationError("Test failed".to_string());
    assert_eq!(err.to_string(), "Validation error: Test failed");
}

#[test]
fn test_endpoint_result() {
    let result = EndpointResult {
        endpoint: "example.com:443".to_string(),
        connected: true,
        quic_versions: vec![0x00000001], // QUIC v1
        extensions: vec!["address_discovery".to_string()],
        issues: vec![],
    };
    
    assert!(result.connected);
    assert_eq!(result.quic_versions, vec![1]);
    assert_eq!(result.extensions.len(), 1);
    assert!(result.issues.is_empty());
}

#[test]
fn test_endpoint_validation_report() {
    let mut endpoint_results = HashMap::new();
    
    endpoint_results.insert(
        "endpoint1".to_string(),
        EndpointResult {
            endpoint: "endpoint1".to_string(),
            connected: true,
            quic_versions: vec![1],
            extensions: vec![],
            issues: vec![],
        }
    );
    
    endpoint_results.insert(
        "endpoint2".to_string(),
        EndpointResult {
            endpoint: "endpoint2".to_string(),
            connected: false,
            quic_versions: vec![],
            extensions: vec![],
            issues: vec!["Connection failed".to_string()],
        }
    );
    
    let report = EndpointValidationReport {
        endpoint_results,
        success_rate: 0.5,
        common_issues: vec!["Connection failures".to_string()],
    };
    
    assert_eq!(report.endpoint_results.len(), 2);
    assert_eq!(report.success_rate, 0.5);
    assert_eq!(report.common_issues.len(), 1);
}

#[test]
fn test_compliance_report_timestamp() {
    let results = vec![];
    let report = ComplianceReport::new(results);
    
    // Check that timestamp is recent (within last second)
    let now = std::time::SystemTime::now();
    let duration = now.duration_since(report.timestamp).unwrap();
    assert!(duration.as_secs() < 1);
}