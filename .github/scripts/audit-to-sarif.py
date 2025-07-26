#!/usr/bin/env python3
"""Convert cargo-audit JSON output to SARIF format for GitHub Security tab."""

import json
import sys
from typing import Dict, List, Any
from pathlib import Path

def severity_to_level(severity: str) -> str:
    """Convert cargo-audit severity to SARIF level."""
    severity_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "informational": "note",
        "unknown": "note"
    }
    return severity_map.get(severity.lower(), "note")

def create_sarif_result(vulnerability: Dict[str, Any], package: Dict[str, Any]) -> Dict[str, Any]:
    """Create a SARIF result from a vulnerability."""
    advisory = vulnerability.get("advisory", {})
    
    # Build the message
    message = {
        "text": advisory.get("description", "Security vulnerability detected")
    }
    
    # Create the result
    result = {
        "ruleId": advisory.get("id", "unknown"),
        "level": severity_to_level(advisory.get("severity", "unknown")),
        "message": message,
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": "Cargo.lock",
                    "uriBaseId": "ROOTPATH"
                },
                "region": {
                    "startLine": 1,
                    "startColumn": 1,
                    "endLine": 1,
                    "endColumn": 1
                }
            }
        }],
        "partialFingerprints": {
            "primaryLocationLineHash": f"{package.get('name', 'unknown')}:{package.get('version', 'unknown')}"
        },
        "properties": {
            "package": package.get("name", "unknown"),
            "version": package.get("version", "unknown"),
            "severity": advisory.get("severity", "unknown"),
            "cvss": advisory.get("cvss", "N/A")
        }
    }
    
    # Add fix information if available
    if "patched_versions" in vulnerability:
        result["fixes"] = [{
            "description": {
                "text": f"Update to version {vulnerability['patched_versions']}"
            }
        }]
    
    # Add related locations for affected functions if available
    if "affected_functions" in vulnerability:
        result["relatedLocations"] = []
        for func in vulnerability["affected_functions"]:
            result["relatedLocations"].append({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": "src/lib.rs",  # Placeholder
                        "uriBaseId": "ROOTPATH"
                    }
                },
                "message": {
                    "text": f"Affected function: {func}"
                }
            })
    
    return result

def create_sarif_rule(advisory: Dict[str, Any]) -> Dict[str, Any]:
    """Create a SARIF rule from an advisory."""
    return {
        "id": advisory.get("id", "unknown"),
        "name": advisory.get("id", "unknown"),
        "shortDescription": {
            "text": advisory.get("title", "Security vulnerability")
        },
        "fullDescription": {
            "text": advisory.get("description", "No description available")
        },
        "help": {
            "text": f"See {advisory.get('url', 'https://rustsec.org')} for more information",
            "markdown": f"See [{advisory.get('id', 'advisory')}]({advisory.get('url', 'https://rustsec.org')}) for more information"
        },
        "defaultConfiguration": {
            "level": severity_to_level(advisory.get("severity", "unknown"))
        },
        "properties": {
            "tags": ["security", "vulnerability", "dependency"],
            "precision": "high",
            "security-severity": advisory.get("cvss", "0.0")
        }
    }

def convert_to_sarif(audit_json: Dict[str, Any]) -> Dict[str, Any]:
    """Convert cargo-audit JSON to SARIF format."""
    vulnerabilities = audit_json.get("vulnerabilities", {})
    
    # Create results and rules
    results = []
    rules = []
    seen_rules = set()
    
    # Process each vulnerability
    for vuln_list in vulnerabilities.get("list", []):
        if isinstance(vuln_list, dict):
            advisory = vuln_list.get("advisory", {})
            package = vuln_list.get("package", {})
            
            # Create result
            result = create_sarif_result(vuln_list, package)
            results.append(result)
            
            # Create rule if not already added
            rule_id = advisory.get("id", "unknown")
            if rule_id not in seen_rules:
                rule = create_sarif_rule(advisory)
                rules.append(rule)
                seen_rules.add(rule_id)
    
    # Create SARIF document
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "cargo-audit",
                    "informationUri": "https://github.com/RustSec/cargo-audit",
                    "version": "0.18.0",
                    "rules": rules
                }
            },
            "results": results,
            "columnKind": "utf16CodeUnits",
            "properties": {
                "audit_metadata": {
                    "total_vulnerabilities": vulnerabilities.get("count", 0),
                    "timestamp": audit_json.get("timestamp", "")
                }
            }
        }]
    }
    
    return sarif

def main():
    """Main function to convert cargo-audit JSON to SARIF."""
    if len(sys.argv) != 3:
        print("Usage: audit-to-sarif.py <input.json> <output.sarif>")
        sys.exit(1)
    
    input_file = Path(sys.argv[1])
    output_file = Path(sys.argv[2])
    
    try:
        # Read input JSON
        with open(input_file, 'r') as f:
            audit_data = json.load(f)
        
        # Convert to SARIF
        sarif_data = convert_to_sarif(audit_data)
        
        # Write output SARIF
        with open(output_file, 'w') as f:
            json.dump(sarif_data, f, indent=2)
        
        print(f"Successfully converted {input_file} to {output_file}")
        
    except FileNotFoundError:
        print(f"Error: Input file {input_file} not found")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in input file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()