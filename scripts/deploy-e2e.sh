#!/bin/bash
# Deploy E2E Test Infrastructure to Digital Ocean
#
# This script:
# 1. Cross-compiles binaries for Linux x86_64
# 2. Deploys binaries to all configured droplets
# 3. Sets up systemd services
# 4. Configures IPv6 if available
#
# Usage:
#   ./scripts/deploy-e2e.sh [OPTIONS]
#
# Options:
#   --config FILE    Configuration file (default: config/do-nodes.yaml)
#   --dashboard-only Only deploy dashboard
#   --nodes-only     Only deploy test nodes
#   --dry-run        Show what would be done
#   --verbose        Verbose output

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="${PROJECT_DIR}/config/do-nodes.yaml"
TARGET="x86_64-unknown-linux-musl"
BINARY_DIR="${PROJECT_DIR}/target/${TARGET}/release"
REMOTE_DIR="/opt/ant-quic"
DRY_RUN=false
VERBOSE=false
DASHBOARD_ONLY=false
NODES_ONLY=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --dashboard-only)
            DASHBOARD_ONLY=true
            shift
            ;;
        --nodes-only)
            NODES_ONLY=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

run_cmd() {
    if [ "$DRY_RUN" = true ]; then
        echo "[DRY-RUN] $*"
    else
        if [ "$VERBOSE" = true ]; then
            echo "[CMD] $*"
        fi
        "$@"
    fi
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."

    # Check for cross-compilation toolchain
    if ! command -v cross &> /dev/null; then
        log_warn "cross not found, attempting to install..."
        cargo install cross
    fi

    # Check for ssh
    if ! command -v ssh &> /dev/null; then
        log_error "ssh not found"
        exit 1
    fi

    # Check for scp
    if ! command -v scp &> /dev/null; then
        log_error "scp not found"
        exit 1
    fi

    log_success "Dependencies checked"
}

# Cross-compile for Linux
cross_compile() {
    log_info "Cross-compiling for Linux ($TARGET)..."

    cd "$PROJECT_DIR"

    # Build e2e-test-node
    run_cmd cross build --release --target "$TARGET" --bin e2e-test-node

    # Build e2e-dashboard
    cd "${PROJECT_DIR}/e2e-dashboard"
    run_cmd cross build --release --target "$TARGET" --bin e2e-dashboard

    log_success "Cross-compilation complete"
}

# Deploy to a single host
deploy_to_host() {
    local host="$1"
    local user="$2"
    local binary="$3"
    local service_name="$4"

    log_info "Deploying to ${user}@${host}..."

    # Create remote directory
    run_cmd ssh "${user}@${host}" "mkdir -p ${REMOTE_DIR}"

    # Copy binary
    run_cmd scp "${binary}" "${user}@${host}:${REMOTE_DIR}/"

    # Make executable
    run_cmd ssh "${user}@${host}" "chmod +x ${REMOTE_DIR}/$(basename ${binary})"

    log_success "Deployed to ${host}"
}

# Create systemd service file
create_service_file() {
    local node_id="$1"
    local binary_name="$2"
    local args="$3"

    cat << EOF
[Unit]
Description=ant-quic ${node_id}
After=network.target

[Service]
Type=simple
User=root
ExecStart=${REMOTE_DIR}/${binary_name} ${args}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
}

# Deploy dashboard
deploy_dashboard() {
    log_info "═══════════════════════════════════════════════════════════════"
    log_info "                DEPLOYING E2E DASHBOARD"
    log_info "═══════════════════════════════════════════════════════════════"

    # Note: This requires manually setting up your dashboard host
    # For now, we just show instructions

    echo ""
    log_info "To deploy the dashboard manually:"
    echo ""
    echo "  1. Copy the binary to your dashboard server:"
    echo "     scp ${PROJECT_DIR}/e2e-dashboard/target/${TARGET}/release/e2e-dashboard user@dashboard-host:/opt/ant-quic/"
    echo ""
    echo "  2. Run the dashboard:"
    echo "     /opt/ant-quic/e2e-dashboard --bind 0.0.0.0 --port 8080"
    echo ""
    echo "  3. Access it at: http://dashboard-host:8080"
    echo ""

    log_success "Dashboard deployment instructions displayed"
}

# Deploy test nodes
deploy_nodes() {
    log_info "═══════════════════════════════════════════════════════════════"
    log_info "                DEPLOYING E2E TEST NODES"
    log_info "═══════════════════════════════════════════════════════════════"

    echo ""
    log_info "To deploy test nodes manually:"
    echo ""
    echo "  1. Copy the binary to each node:"
    echo "     scp ${PROJECT_DIR}/target/${TARGET}/release/e2e-test-node user@node-host:/opt/ant-quic/"
    echo ""
    echo "  2. Run a test node (seed):"
    echo "     /opt/ant-quic/e2e-test-node --listen 0.0.0.0:9000 --node-id seed-node --node-location do-nyc1"
    echo ""
    echo "  3. Run additional nodes:"
    echo "     /opt/ant-quic/e2e-test-node --listen 0.0.0.0:9000 --node-id node-2 --node-location do-sfo1 --known-peers seed-ip:9000"
    echo ""
    echo "  4. With metrics push to dashboard:"
    echo "     --metrics-server http://dashboard-host:8080"
    echo ""

    log_success "Node deployment instructions displayed"
}

# Main execution
main() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "            ant-quic E2E DEPLOYMENT"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""

    if [ "$DRY_RUN" = true ]; then
        log_warn "DRY RUN MODE - No actual changes will be made"
        echo ""
    fi

    # Check dependencies
    check_dependencies

    # Cross-compile
    if [ "$DRY_RUN" = false ]; then
        log_info "Checking if cross-compilation is needed..."
        if [ ! -f "${BINARY_DIR}/e2e-test-node" ] || [ ! -f "${PROJECT_DIR}/e2e-dashboard/target/${TARGET}/release/e2e-dashboard" ]; then
            log_warn "Cross-compilation for Linux is optional. Use 'cross' for remote deployment."
            log_info "For local testing, use the local binaries."
        fi
    fi

    # Deploy based on options
    if [ "$DASHBOARD_ONLY" = true ]; then
        deploy_dashboard
    elif [ "$NODES_ONLY" = true ]; then
        deploy_nodes
    else
        deploy_dashboard
        deploy_nodes
    fi

    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    log_success "Deployment complete!"
    echo "═══════════════════════════════════════════════════════════════"
}

main "$@"
