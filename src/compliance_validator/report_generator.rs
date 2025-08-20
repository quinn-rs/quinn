// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


/// Report Generator Module
///
/// Generates compliance reports in various formats
use super::{ComplianceReport, ComplianceResult, Evidence};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::collections::HashMap;

/// Generate HTML compliance report
pub fn generate_html_report(report: &ComplianceReport) -> String {
    let timestamp: DateTime<Utc> = report.timestamp.into();
    let mut html = String::new();

    // HTML header
    html.push_str(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QUIC Compliance Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3 { color: #2c3e50; }
        .summary {
            background: #ecf0f1;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        .compliance-score {
            font-size: 48px;
            font-weight: bold;
            color: #27ae60;
        }
        .requirement {
            border: 1px solid #ddd;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 4px;
        }
        .requirement.passed {
            border-left: 4px solid #27ae60;
            background: #f0fff4;
        }
        .requirement.failed {
            border-left: 4px solid #e74c3c;
            background: #fff5f5;
        }
        .level-must { color: #e74c3c; font-weight: bold; }
        .level-should { color: #f39c12; font-weight: bold; }
        .level-may { color: #3498db; }
        .evidence {
            background: #f8f9fa;
            padding: 10px;
            margin-top: 10px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9em;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th { background: #34495e; color: white; }
        .category-chart {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            margin: 20px 0;
        }
        .category-item {
            flex: 1;
            min-width: 200px;
            background: #ecf0f1;
            padding: 15px;
            border-radius: 4px;
            text-align: center;
        }
        .progress-bar {
            width: 100%;
            height: 20px;
            background: #ddd;
            border-radius: 10px;
            overflow: hidden;
            margin: 10px 0;
        }
        .progress-fill {
            height: 100%;
            background: #27ae60;
            transition: width 0.3s;
        }
    </style>
</head>
<body>
"#,
    );

    // Title and summary
    html.push_str(&format!(
        r#"
    <h1>QUIC Compliance Report</h1>
    <p>Generated: {}</p>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="compliance-score">{:.1}%</div>
        <p>Overall Compliance Score</p>
        
        <div class="progress-bar">
            <div class="progress-fill" style="width: {:.1}%"></div>
        </div>
        
        <table>
            <tr>
                <th>Metric</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Total Requirements</td>
                <td>{}</td>
            </tr>
            <tr>
                <td>Passed</td>
                <td>{}</td>
            </tr>
            <tr>
                <td>Failed</td>
                <td>{}</td>
            </tr>
            <tr>
                <td>MUST Requirements Met</td>
                <td>{}</td>
            </tr>
        </table>
    </div>
"#,
        timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
        report.summary.compliance_percentage(),
        report.summary.compliance_percentage(),
        report.summary.total_requirements,
        report.summary.passed,
        report.summary.failed,
        if report.summary.must_requirements_met() {
            "✅ Yes"
        } else {
            "❌ No"
        }
    ));

    // Compliance by category
    html.push_str(
        r#"
    <h2>Compliance by Category</h2>
    <div class="category-chart">
"#,
    );

    for (category, pass_rate) in &report.summary.pass_rate_by_category {
        html.push_str(&format!(
            r#"
        <div class="category-item">
            <h4>{:?}</h4>
            <div class="compliance-score">{:.0}%</div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: {:.0}%"></div>
            </div>
        </div>
"#,
            category,
            pass_rate * 100.0,
            pass_rate * 100.0
        ));
    }

    html.push_str("</div>");

    // Detailed results
    html.push_str(
        r#"
    <h2>Detailed Results</h2>
"#,
    );

    // Group by specification
    let mut by_spec: HashMap<&str, Vec<&ComplianceResult>> = HashMap::new();
    for result in &report.results {
        by_spec
            .entry(&result.requirement.spec_id)
            .or_default()
            .push(result);
    }

    for (spec_id, results) in by_spec {
        html.push_str(&format!("<h3>{spec_id}</h3>"));

        for result in results {
            let status_class = if result.compliant { "passed" } else { "failed" };
            let status_icon = if result.compliant { "✅" } else { "❌" };

            html.push_str(&format!(
                r#"
        <div class="requirement {}">
            <h4>{} {} - Section {}</h4>
            <p class="level-{:?}">Level: {:?}</p>
            <p><strong>Requirement:</strong> {}</p>
            <p><strong>Status:</strong> {}</p>
            <p><strong>Details:</strong> {}</p>
"#,
                status_class,
                status_icon,
                result.requirement.spec_id,
                result.requirement.section,
                result.requirement.level.to_string().to_lowercase(),
                result.requirement.level,
                result.requirement.description,
                if result.compliant {
                    "COMPLIANT"
                } else {
                    "NON-COMPLIANT"
                },
                result.details
            ));

            // Add evidence
            if !result.evidence.is_empty() {
                html.push_str("<h5>Evidence:</h5>");
                for evidence in &result.evidence {
                    html.push_str(r#"<div class="evidence">"#);
                    match evidence {
                        Evidence::TestResult {
                            test_name,
                            passed,
                            output,
                        } => {
                            html.push_str(&format!(
                                "Test: {} - {}<br>Output: {}",
                                test_name,
                                if *passed { "PASSED" } else { "FAILED" },
                                html_escape(output)
                            ));
                        }
                        Evidence::CodeReference {
                            file,
                            line,
                            snippet,
                        } => {
                            html.push_str(&format!(
                                "Code: {}:{}<br>{}",
                                file,
                                line,
                                html_escape(snippet)
                            ));
                        }
                        Evidence::EndpointTest { endpoint, result } => {
                            html.push_str(&format!(
                                "Endpoint: {}<br>Result: {}",
                                endpoint,
                                html_escape(result)
                            ));
                        }
                        Evidence::PacketCapture { description, .. } => {
                            html.push_str(&format!("Packet Capture: {description}"));
                        }
                    }
                    html.push_str("</div>");
                }
            }

            html.push_str("</div>");
        }
    }

    // Footer
    html.push_str(
        r#"
</body>
</html>
"#,
    );

    html
}

/// Generate JSON compliance report
pub fn generate_json_report(report: &ComplianceReport) -> Value {
    let timestamp: DateTime<Utc> = report.timestamp.into();

    let mut results_json = Vec::new();
    for result in &report.results {
        let mut evidence_json = Vec::new();
        for ev in &result.evidence {
            evidence_json.push(match ev {
                Evidence::TestResult {
                    test_name,
                    passed,
                    output,
                } => json!({
                    "type": "test_result",
                    "test_name": test_name,
                    "passed": passed,
                    "output": output
                }),
                Evidence::CodeReference {
                    file,
                    line,
                    snippet,
                } => json!({
                    "type": "code_reference",
                    "file": file,
                    "line": line,
                    "snippet": snippet
                }),
                Evidence::EndpointTest { endpoint, result } => json!({
                    "type": "endpoint_test",
                    "endpoint": endpoint,
                    "result": result
                }),
                Evidence::PacketCapture {
                    description,
                    packets,
                } => json!({
                    "type": "packet_capture",
                    "description": description,
                    "packet_count": packets.len()
                }),
            });
        }

        results_json.push(json!({
            "requirement": {
                "spec_id": result.requirement.spec_id,
                "section": result.requirement.section,
                "level": format!("{:?}", result.requirement.level),
                "category": format!("{:?}", result.requirement.category),
                "description": result.requirement.description
            },
            "compliant": result.compliant,
            "details": result.details,
            "evidence": evidence_json
        }));
    }

    // Calculate category statistics
    let mut category_stats = HashMap::new();
    for (cat, rate) in &report.summary.pass_rate_by_category {
        category_stats.insert(format!("{cat:?}"), rate * 100.0);
    }

    // Calculate level statistics
    let mut level_stats = HashMap::new();
    for (level, rate) in &report.summary.pass_rate_by_level {
        level_stats.insert(format!("{level:?}"), rate * 100.0);
    }

    json!({
        "report": {
            "timestamp": timestamp.to_rfc3339(),
            "type": "quic_compliance_report",
            "version": "1.0"
        },
        "summary": {
            "compliance_percentage": report.summary.compliance_percentage(),
            "total_requirements": report.summary.total_requirements,
            "passed": report.summary.passed,
            "failed": report.summary.failed,
            "must_requirements_met": report.summary.must_requirements_met(),
            "pass_rate_by_category": category_stats,
            "pass_rate_by_level": level_stats
        },
        "results": results_json
    })
}

/// Generate markdown compliance report
pub fn generate_markdown_report(report: &ComplianceReport) -> String {
    let timestamp: DateTime<Utc> = report.timestamp.into();
    let mut md = String::new();

    // Header
    md.push_str(&format!(
        r#"# QUIC Compliance Report

Generated: {}

## Executive Summary

**Overall Compliance Score: {:.1}%**

| Metric | Value |
|--------|-------|
| Total Requirements | {} |
| Passed | {} |
| Failed | {} |
| MUST Requirements Met | {} |

"#,
        timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
        report.summary.compliance_percentage(),
        report.summary.total_requirements,
        report.summary.passed,
        report.summary.failed,
        if report.summary.must_requirements_met() {
            "✅ Yes"
        } else {
            "❌ No"
        }
    ));

    // Compliance by category
    md.push_str("## Compliance by Category\n\n");
    md.push_str("| Category | Pass Rate |\n");
    md.push_str("|----------|----------|\n");

    for (category, pass_rate) in &report.summary.pass_rate_by_category {
        md.push_str(&format!("| {:?} | {:.1}% |\n", category, pass_rate * 100.0));
    }

    md.push_str("\n## Compliance by Level\n\n");
    md.push_str("| Level | Pass Rate |\n");
    md.push_str("|-------|----------|\n");

    for (level, pass_rate) in &report.summary.pass_rate_by_level {
        md.push_str(&format!("| {:?} | {:.1}% |\n", level, pass_rate * 100.0));
    }

    // Detailed results
    md.push_str("\n## Detailed Results\n\n");

    // Group by specification
    let mut by_spec: HashMap<&str, Vec<&ComplianceResult>> = HashMap::new();
    for result in &report.results {
        by_spec
            .entry(&result.requirement.spec_id)
            .or_default()
            .push(result);
    }

    for (spec_id, results) in by_spec {
        md.push_str(&format!("### {spec_id}\n\n"));

        for result in results {
            let status = if result.compliant {
                "✅ COMPLIANT"
            } else {
                "❌ NON-COMPLIANT"
            };

            md.push_str(&format!(
                r#"#### {} - Section {}

**Level:** {:?}  
**Status:** {}  
**Requirement:** {}  
**Details:** {}

"#,
                result.requirement.spec_id,
                result.requirement.section,
                result.requirement.level,
                status,
                result.requirement.description,
                result.details
            ));

            // Add evidence
            if !result.evidence.is_empty() {
                md.push_str("**Evidence:**\n\n");
                for evidence in &result.evidence {
                    match evidence {
                        Evidence::TestResult {
                            test_name, passed, ..
                        } => {
                            md.push_str(&format!(
                                "- Test `{}`: {}\n",
                                test_name,
                                if *passed { "PASSED" } else { "FAILED" }
                            ));
                        }
                        Evidence::CodeReference { file, line, .. } => {
                            md.push_str(&format!("- Code reference: `{file}:{line}`\n"));
                        }
                        Evidence::EndpointTest { endpoint, .. } => {
                            md.push_str(&format!("- Endpoint test: `{endpoint}`\n"));
                        }
                        Evidence::PacketCapture { description, .. } => {
                            md.push_str(&format!("- Packet capture: {description}\n"));
                        }
                    }
                }
                md.push('\n');
            }
        }
    }

    md
}

/// HTML escape helper
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance_validator::{
        ComplianceRequirement, RequirementCategory, RequirementLevel,
    };

    fn create_test_report() -> ComplianceReport {
        let results = vec![ComplianceResult {
            requirement: ComplianceRequirement {
                spec_id: "RFC9000".to_string(),
                section: "7.2".to_string(),
                level: RequirementLevel::Must,
                description: "Test requirement".to_string(),
                category: RequirementCategory::Transport,
            },
            compliant: true,
            details: "Passed".to_string(),
            evidence: vec![Evidence::TestResult {
                test_name: "test_transport".to_string(),
                passed: true,
                output: "All good".to_string(),
            }],
        }];

        ComplianceReport::new(results)
    }

    #[test]
    fn test_html_report_generation() {
        let report = create_test_report();
        let html = generate_html_report(&report);

        assert!(html.contains("QUIC Compliance Report"));
        assert!(html.contains("100.0%")); // Compliance score
        assert!(html.contains("RFC9000"));
        assert!(html.contains("✅"));
    }

    #[test]
    fn test_json_report_generation() {
        let report = create_test_report();
        let json = generate_json_report(&report);

        assert_eq!(json["summary"]["compliance_percentage"], 100.0);
        assert_eq!(json["summary"]["total_requirements"], 1);
        assert_eq!(json["summary"]["passed"], 1);
        assert_eq!(json["results"][0]["compliant"], true);
    }

    #[test]
    fn test_markdown_report_generation() {
        let report = create_test_report();
        let md = generate_markdown_report(&report);

        assert!(md.contains("# QUIC Compliance Report"));
        assert!(md.contains("Overall Compliance Score: 100.0%"));
        assert!(md.contains("✅ COMPLIANT"));
        assert!(md.contains("RFC9000"));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<test>"), "&lt;test&gt;");
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
    }
}
