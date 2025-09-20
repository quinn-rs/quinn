// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

/// RFC Parser Module
///
/// Parses IETF RFC documents and extracts compliance requirements
use super::{ComplianceRequirement, RequirementCategory, RequirementLevel, ValidationError};
use regex::Regex;
use std::fs;
use std::path::Path;

/// Parser for RFC documents
pub struct RfcParser {
    /// Regex patterns for requirement extraction
    must_pattern: Regex,
    must_not_pattern: Regex,
    should_pattern: Regex,
    should_not_pattern: Regex,
    may_pattern: Regex,
}

impl Default for RfcParser {
    fn default() -> Self {
        Self::new()
    }
}

impl RfcParser {
    /// Create a new RFC parser
    #[allow(clippy::expect_used)]
    pub fn new() -> Self {
        Self {
            // RFC 2119 keywords - match whole words with word boundaries
            must_pattern: Regex::new(r"\b(MUST|SHALL|REQUIRED)\b")
                .expect("Static regex pattern should always compile"),
            must_not_pattern: Regex::new(r"\b(MUST NOT|SHALL NOT)\b")
                .expect("Static regex pattern should always compile"),
            should_pattern: Regex::new(r"\b(SHOULD|RECOMMENDED)\b")
                .expect("Static regex pattern should always compile"),
            should_not_pattern: Regex::new(r"\b(SHOULD NOT|NOT RECOMMENDED)\b")
                .expect("Static regex pattern should always compile"),
            may_pattern: Regex::new(r"\b(MAY|OPTIONAL)\b")
                .expect("Static regex pattern should always compile"),
        }
    }

    /// Parse an RFC file and extract requirements
    pub fn parse_file(&self, path: &Path) -> Result<Vec<ComplianceRequirement>, ValidationError> {
        let content = fs::read_to_string(path)?;
        let spec_id = self.extract_spec_id(path)?;

        Ok(self.parse_content(&content, &spec_id))
    }

    /// Parse RFC content and extract requirements
    pub fn parse_content(&self, content: &str, spec_id: &str) -> Vec<ComplianceRequirement> {
        let mut requirements = Vec::new();

        // Split into sections
        let sections = self.split_into_sections(content);

        for (section_num, section_content) in sections {
            // Extract requirements from each section
            let section_reqs =
                self.extract_requirements_from_section(spec_id, &section_num, &section_content);
            requirements.extend(section_reqs);
        }

        requirements
    }

    /// Split RFC content into sections
    #[allow(clippy::expect_used)]
    fn split_into_sections(&self, content: &str) -> Vec<(String, String)> {
        let mut sections = Vec::new();
        let section_regex = Regex::new(r"(?m)^(\d+(?:\.\d+)*)\s+(.+)$")
            .expect("Static regex pattern should always compile");

        let mut current_section = String::new();
        let mut current_content = String::new();

        for line in content.lines() {
            if let Some(captures) = section_regex.captures(line) {
                // Found new section
                if !current_section.is_empty() {
                    sections.push((current_section.clone(), current_content.clone()));
                }
                current_section = captures[1].to_string();
                current_content = String::new();
            } else {
                current_content.push_str(line);
                current_content.push('\n');
            }
        }

        // Add last section
        if !current_section.is_empty() {
            sections.push((current_section, current_content));
        }

        sections
    }

    /// Extract requirements from a section
    fn extract_requirements_from_section(
        &self,
        spec_id: &str,
        section: &str,
        content: &str,
    ) -> Vec<ComplianceRequirement> {
        let mut requirements = Vec::new();

        // Split into sentences for better requirement extraction
        let sentences = self.split_into_sentences(content);

        for sentence in sentences {
            if let Some(req) = self.extract_requirement_from_sentence(spec_id, section, &sentence) {
                requirements.push(req);
            }
        }

        requirements
    }

    /// Split text into sentences
    #[allow(clippy::expect_used)]
    fn split_into_sentences(&self, text: &str) -> Vec<String> {
        // Simple sentence splitter - can be improved
        let sentence_regex =
            Regex::new(r"[.!?]+\s+").expect("Static regex pattern should always compile");
        sentence_regex
            .split(text)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// Extract requirement from a sentence
    fn extract_requirement_from_sentence(
        &self,
        spec_id: &str,
        section: &str,
        sentence: &str,
    ) -> Option<ComplianceRequirement> {
        // Check for requirement keywords
        let level = if self.must_not_pattern.is_match(sentence) {
            RequirementLevel::MustNot
        } else if self.should_not_pattern.is_match(sentence) {
            RequirementLevel::ShouldNot
        } else if self.must_pattern.is_match(sentence) {
            RequirementLevel::Must
        } else if self.should_pattern.is_match(sentence) {
            RequirementLevel::Should
        } else if self.may_pattern.is_match(sentence) {
            RequirementLevel::May
        } else {
            return None;
        };

        // Categorize the requirement
        let category = self.categorize_requirement(sentence);

        Some(ComplianceRequirement {
            spec_id: spec_id.to_string(),
            section: section.to_string(),
            level,
            description: sentence.to_string(),
            category,
        })
    }

    /// Categorize requirement based on content
    fn categorize_requirement(&self, description: &str) -> RequirementCategory {
        let lower = description.to_lowercase();

        if lower.contains("transport parameter") || lower.contains("transport_parameter") {
            RequirementCategory::TransportParameters
        } else if lower.contains("frame")
            || lower.contains("encoding")
            || lower.contains("decoding")
        {
            RequirementCategory::FrameFormat
        } else if lower.contains("nat")
            || lower.contains("traversal")
            || lower.contains("hole punch")
        {
            RequirementCategory::NatTraversal
        } else if lower.contains("address") && lower.contains("discovery") {
            RequirementCategory::AddressDiscovery
        } else if lower.contains("error") || lower.contains("close") || lower.contains("reset") {
            RequirementCategory::ErrorHandling
        } else if lower.contains("crypto")
            || lower.contains("security")
            || lower.contains("authentication")
        {
            RequirementCategory::Security
        } else if lower.contains("connection")
            || lower.contains("handshake")
            || lower.contains("establishment")
        {
            RequirementCategory::ConnectionEstablishment
        } else if lower.contains("performance")
            || lower.contains("throughput")
            || lower.contains("latency")
        {
            RequirementCategory::Performance
        } else {
            RequirementCategory::Transport
        }
    }

    /// Extract spec ID from file path
    fn extract_spec_id(&self, path: &Path) -> Result<String, ValidationError> {
        let filename = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| ValidationError::RfcParseError("Invalid file path".to_string()))?;

        // Extract RFC number or draft name
        if filename.starts_with("rfc") {
            Ok(filename.to_uppercase())
        } else if filename.contains("draft") {
            Ok(filename.to_string())
        } else {
            Ok(format!("spec-{filename}"))
        }
    }
}

/// Parse specific QUIC RFCs
pub struct QuicRfcParser {
    parser: RfcParser,
}

impl Default for QuicRfcParser {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicRfcParser {
    /// Create a new QUIC RFC parser wrapper
    pub fn new() -> Self {
        Self {
            parser: RfcParser::new(),
        }
    }

    /// Parse RFC 9000 (QUIC Transport Protocol)
    pub fn parse_rfc9000(&self, content: &str) -> Vec<ComplianceRequirement> {
        let mut requirements = self.parser.parse_content(content, "RFC9000");

        // Add specific known requirements that might need special handling
        self.add_rfc9000_specific_requirements(&mut requirements);

        requirements
    }

    /// Parse draft-ietf-quic-address-discovery
    pub fn parse_address_discovery_draft(&self, content: &str) -> Vec<ComplianceRequirement> {
        let mut requirements = self
            .parser
            .parse_content(content, "draft-ietf-quic-address-discovery-00");

        // Add specific requirements for address discovery
        self.add_address_discovery_requirements(&mut requirements);

        requirements
    }

    /// Parse draft-seemann-quic-nat-traversal
    pub fn parse_nat_traversal_draft(&self, content: &str) -> Vec<ComplianceRequirement> {
        let mut requirements = self
            .parser
            .parse_content(content, "draft-seemann-quic-nat-traversal-02");

        // Add specific requirements for NAT traversal
        self.add_nat_traversal_requirements(&mut requirements);

        requirements
    }

    /// Add RFC 9000 specific requirements
    fn add_rfc9000_specific_requirements(&self, requirements: &mut Vec<ComplianceRequirement>) {
        // Add critical requirements that might be missed by simple pattern matching
        requirements.push(ComplianceRequirement {
            spec_id: "RFC9000".to_string(),
            section: "4.1".to_string(),
            level: RequirementLevel::Must,
            description: "Endpoints MUST validate transport parameters during handshake"
                .to_string(),
            category: RequirementCategory::TransportParameters,
        });

        requirements.push(ComplianceRequirement {
            spec_id: "RFC9000".to_string(),
            section: "12.4".to_string(),
            level: RequirementLevel::Must,
            description:
                "An endpoint MUST NOT send data on a stream without available flow control credit"
                    .to_string(),
            category: RequirementCategory::Transport,
        });
    }

    /// Add address discovery specific requirements
    fn add_address_discovery_requirements(&self, requirements: &mut Vec<ComplianceRequirement>) {
        requirements.push(ComplianceRequirement {
            spec_id: "draft-ietf-quic-address-discovery-00".to_string(),
            section: "3.1".to_string(),
            level: RequirementLevel::Must,
            description:
                "OBSERVED_ADDRESS frames MUST include monotonically increasing sequence numbers"
                    .to_string(),
            category: RequirementCategory::AddressDiscovery,
        });

        requirements.push(ComplianceRequirement {
            spec_id: "draft-ietf-quic-address-discovery-00".to_string(),
            section: "3.2".to_string(),
            level: RequirementLevel::Must,
            description:
                "The IP version MUST be determined by the least significant bit of the frame type"
                    .to_string(),
            category: RequirementCategory::AddressDiscovery,
        });
    }

    /// Add NAT traversal specific requirements
    fn add_nat_traversal_requirements(&self, requirements: &mut Vec<ComplianceRequirement>) {
        requirements.push(ComplianceRequirement {
            spec_id: "draft-seemann-quic-nat-traversal-02".to_string(),
            section: "4.1".to_string(),
            level: RequirementLevel::Must,
            description: "Clients MUST send empty NAT traversal transport parameter".to_string(),
            category: RequirementCategory::NatTraversal,
        });

        requirements.push(ComplianceRequirement {
            spec_id: "draft-seemann-quic-nat-traversal-02".to_string(),
            section: "4.1".to_string(),
            level: RequirementLevel::Must,
            description: "Servers MUST send concurrency limit in NAT traversal transport parameter"
                .to_string(),
            category: RequirementCategory::NatTraversal,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc_parser_creation() {
        let parser = RfcParser::new();
        assert!(parser.must_pattern.is_match("MUST implement"));
        assert!(parser.must_not_pattern.is_match("MUST NOT send"));
        assert!(parser.should_pattern.is_match("SHOULD use"));
        assert!(parser.should_not_pattern.is_match("SHOULD NOT ignore"));
        assert!(parser.may_pattern.is_match("MAY include"));
    }

    #[test]
    fn test_requirement_extraction() {
        let parser = RfcParser::new();
        let sentence = "Endpoints MUST validate all received transport parameters.";

        let req = parser.extract_requirement_from_sentence("RFC9000", "4.1", sentence);
        assert!(req.is_some());

        let req = req.unwrap();
        assert_eq!(req.level, RequirementLevel::Must);
        assert_eq!(req.category, RequirementCategory::TransportParameters);
    }

    #[test]
    fn test_categorization() {
        let parser = RfcParser::new();

        assert_eq!(
            parser.categorize_requirement("transport parameter validation"),
            RequirementCategory::TransportParameters
        );

        assert_eq!(
            parser.categorize_requirement("frame encoding rules"),
            RequirementCategory::FrameFormat
        );

        assert_eq!(
            parser.categorize_requirement("NAT traversal mechanism"),
            RequirementCategory::NatTraversal
        );
    }

    #[test]
    fn test_sentence_splitting() {
        let parser = RfcParser::new();
        let text = "This is sentence one. This is sentence two! And sentence three?";

        let sentences = parser.split_into_sentences(text);
        assert_eq!(sentences.len(), 3);
        assert_eq!(sentences[0], "This is sentence one");
        assert_eq!(sentences[1], "This is sentence two");
        assert_eq!(sentences[2], "And sentence three?");
    }

    #[test]
    fn test_quic_rfc_parser() {
        let parser = QuicRfcParser::new();
        let content = "Endpoints MUST validate parameters. They SHOULD log errors.";

        let requirements = parser.parse_rfc9000(content);
        assert!(requirements.len() >= 2); // At least parsed + added requirements
    }
}
