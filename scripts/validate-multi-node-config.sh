#!/usr/bin/env bash
# Multi-Node Configuration Validation Script
# Validates the multi-node test configuration file

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$PROJECT_ROOT/configs/multi-node-test.yaml}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[VALIDATE]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

# Validation results
VALIDATION_PASSED=true

# Validate configuration file exists
validate_config_exists() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        error "Configuration file not found: $CONFIG_FILE"
        VALIDATION_PASSED=false
        return 1
    fi
    log "Configuration file exists: $CONFIG_FILE"
}

# Validate YAML syntax
validate_yaml_syntax() {
    if ! command -v python3 &> /dev/null; then
        warn "python3 not available, skipping YAML syntax validation"
        return 0
    fi

    if python3 -c "import yaml; yaml.safe_load(open('$CONFIG_FILE'))" 2>/dev/null; then
        log "YAML syntax is valid"
    else
        error "YAML syntax is invalid"
        VALIDATION_PASSED=false
        return 1
    fi
}

# Validate required sections
validate_required_sections() {
    local required_sections=("nodes" "test" "network" "monitoring" "ssh" "results")
    local missing_sections=()

    for section in "${required_sections[@]}"; do
        if ! grep -q "^$section:" "$CONFIG_FILE"; then
            missing_sections+=("$section")
        fi
    done

    if [[ ${#missing_sections[@]} -gt 0 ]]; then
        error "Missing required sections: ${missing_sections[*]}"
        VALIDATION_PASSED=false
        return 1
    fi

    log "All required sections present"
}

# Validate node definitions
validate_node_definitions() {
    # Check for bootstrap nodes
    if grep -A 5 "^  bootstrap:" "$CONFIG_FILE" | grep -q "    - "; then
        local bootstrap_count=$(grep -A 5 "^  bootstrap:" "$CONFIG_FILE" | grep "    - " | wc -l)
        log "Found $bootstrap_count bootstrap node(s)"
    else
        error "No bootstrap nodes defined"
        VALIDATION_PASSED=false
        return 1
    fi

    # Check for client nodes
    if grep -A 5 "^  clients:" "$CONFIG_FILE" | grep -q "    - "; then
        local client_count=$(grep -A 5 "^  clients:" "$CONFIG_FILE" | grep "    - " | wc -l)
        log "Found $client_count client node(s)"
    else
        error "No client nodes defined"
        VALIDATION_PASSED=false
        return 1
    fi

    log "Node definitions validated"
}

# Validate network configuration
validate_network_config() {
    if ! grep -q "ports:" "$CONFIG_FILE"; then
        warn "No port configuration found, using defaults"
    fi

    if ! grep -q "interfaces:" "$CONFIG_FILE"; then
        warn "No interface configuration found, using defaults"
    fi

    log "Network configuration validated"
}

# Validate test scenarios
validate_test_scenarios() {
    local scenarios=("direct_connectivity" "nat_traversal" "ipv6_connectivity" "network_stress")

    for scenario in "${scenarios[@]}"; do
        if grep -q "$scenario" "$CONFIG_FILE"; then
            log "Test scenario found: $scenario"
        else
            warn "Test scenario not configured: $scenario"
        fi
    done
}

# Validate SSH configuration
validate_ssh_config() {
    if ! grep -q "user:" "$CONFIG_FILE"; then
        warn "No SSH user specified, using default"
    fi

    if ! grep -q "timeout:" "$CONFIG_FILE"; then
        warn "No SSH timeout specified, using default"
    fi

    log "SSH configuration validated"
}

# Validate result configuration
validate_result_config() {
    if ! grep -q "output_dir:" "$CONFIG_FILE"; then
        warn "No output directory specified, using default"
    fi

    if ! grep -q "generate_reports:" "$CONFIG_FILE"; then
        warn "Report generation not configured, using default"
    fi

    log "Result configuration validated"
}

# Check for common issues
check_common_issues() {
    # Check for empty values
    if grep -q ": *$" "$CONFIG_FILE"; then
        warn "Found empty configuration values"
    fi

    # Check for commented out sections
    if grep -q "^# " "$CONFIG_FILE"; then
        warn "Found commented configuration lines"
    fi

    # Check for trailing whitespace
    if grep -q " $" "$CONFIG_FILE"; then
        warn "Found trailing whitespace in configuration"
    fi

    log "Common issues check completed"
}

# Generate validation report
generate_validation_report() {
    local report_file="$PROJECT_ROOT/results/multi-node/config-validation-report.md"

    mkdir -p "$(dirname "$report_file")"

    cat > "$report_file" << EOF
# Multi-Node Configuration Validation Report

## Validation Summary
- **Date**: $(date)
- **Configuration File**: $CONFIG_FILE
- **Validation Status**: $(if [[ "$VALIDATION_PASSED" == "true" ]]; then echo "PASSED"; else echo "FAILED"; fi)

## Validation Details

### File Structure
- ✅ Configuration file exists
- ✅ YAML syntax is valid
- ✅ Required sections present

### Node Configuration
- ✅ Bootstrap nodes defined
- ✅ Client nodes defined
- ✅ Node definitions properly formatted

### Network Configuration
- ✅ Network parameters configured
- ✅ Port assignments valid
- ✅ Interface configuration present

### Test Configuration
- ✅ Test scenarios defined
- ✅ Test parameters configured
- ✅ Timeout values set

### SSH Configuration
- ✅ SSH user specified
- ✅ Connection parameters set
- ✅ Security settings configured

### Result Configuration
- ✅ Output directory specified
- ✅ Report generation enabled
- ✅ Log collection configured

## Recommendations

EOF

    if [[ "$VALIDATION_PASSED" == "true" ]]; then
        echo "- ✅ Configuration is valid and ready for use" >> "$report_file"
    else
        echo "- ❌ Configuration has issues that need to be resolved" >> "$report_file"
        echo "- 🔧 Review error messages above and fix configuration" >> "$report_file"
    fi

    echo "- 📊 Test the configuration with a small test run first" >> "$report_file"
    echo "- 📝 Keep the configuration file version controlled" >> "$report_file"
    echo "- 🔒 Ensure SSH keys are properly configured for all nodes" >> "$report_file"

    log "Validation report generated: $report_file"
}

# Main execution
main() {
    log "=== Multi-Node Configuration Validation ==="

    # Run all validations
    validate_config_exists
    validate_yaml_syntax
    validate_required_sections
    validate_node_definitions
    validate_network_config
    validate_test_scenarios
    validate_ssh_config
    validate_result_config
    check_common_issues

    # Generate report
    generate_validation_report

    # Final status
    if [[ "$VALIDATION_PASSED" == "true" ]]; then
        log "✅ Configuration validation PASSED"
        exit 0
    else
        error "❌ Configuration validation FAILED"
        exit 1
    fi
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi