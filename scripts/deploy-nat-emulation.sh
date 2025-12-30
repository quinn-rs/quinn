#!/bin/bash
# Deploy NAT emulation Docker containers to existing VPS nodes
#
# This script deploys Docker-based NAT emulation infrastructure to test
# ant-quic NAT traversal capabilities comprehensively.
#
# Usage:
#   ./scripts/deploy-nat-emulation.sh [--node NODE_NAME] [--dry-run]
#
# Options:
#   --node NODE_NAME  Deploy to specific node only (e.g., fullcone, symmetric)
#   --dry-run         Show what would be deployed without actually deploying

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DOCKER_DIR="$PROJECT_ROOT/docker/nat-emulation"

# VPS Node configuration
# Format: name:ip:nat_types
declare -A NODES
NODES=(
    ["fullcone"]="67.205.158.158:fullcone"
    ["restricted"]="161.35.231.80:restricted,hairpin"
    ["portrestricted"]="178.62.192.11:portrestricted"
    ["symmetric"]="159.65.90.128:symmetric,cgnat"
)

# Remote paths
REMOTE_BASE="/opt/ant-quic/nat-emulation"

# Parse arguments
DRY_RUN=false
TARGET_NODE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --node)
            TARGET_NODE="$2"
            shift 2
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    if [[ ! -d "$DOCKER_DIR" ]]; then
        log_error "Docker NAT emulation directory not found: $DOCKER_DIR"
        exit 1
    fi

    if [[ ! -f "$DOCKER_DIR/docker-compose.yml" ]]; then
        log_error "docker-compose.yml not found in $DOCKER_DIR"
        exit 1
    fi

    if ! command -v ssh &> /dev/null; then
        log_error "ssh command not found"
        exit 1
    fi

    if ! command -v scp &> /dev/null; then
        log_error "scp command not found"
        exit 1
    fi

    log_success "Prerequisites check passed"
}

# Check SSH connectivity to a node
check_ssh() {
    local ip="$1"
    local name="$2"

    log_info "Checking SSH connectivity to $name ($ip)..."

    if ssh -o ConnectTimeout=5 -o BatchMode=yes "root@$ip" "echo ok" &> /dev/null; then
        log_success "SSH connection to $name successful"
        return 0
    else
        log_warn "Cannot connect to $name via SSH"
        return 1
    fi
}

# Install Docker on remote node if not present
ensure_docker() {
    local ip="$1"
    local name="$2"

    log_info "Ensuring Docker is installed on $name..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would check/install Docker on $name"
        return 0
    fi

    # Check if Docker is installed
    if ssh "root@$ip" "command -v docker" &> /dev/null; then
        log_success "Docker already installed on $name"
    else
        log_info "Installing Docker on $name..."
        ssh "root@$ip" "curl -fsSL https://get.docker.com | sh"
        log_success "Docker installed on $name"
    fi

    # Check if docker-compose is installed
    if ssh "root@$ip" "command -v docker-compose || docker compose version" &> /dev/null; then
        log_success "docker-compose available on $name"
    else
        log_info "Installing docker-compose plugin on $name..."
        ssh "root@$ip" "apt-get update && apt-get install -y docker-compose-plugin"
    fi
}

# Deploy NAT emulation to a specific node
deploy_to_node() {
    local name="$1"
    local config="${NODES[$name]}"

    IFS=':' read -r ip nat_types <<< "$config"

    log_info "Deploying to $name ($ip) with NAT types: $nat_types"

    if ! check_ssh "$ip" "$name"; then
        log_error "Skipping $name due to SSH connectivity issues"
        return 1
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would deploy NAT emulation to $name"
        log_info "[DRY-RUN]   - Create directory: $REMOTE_BASE"
        log_info "[DRY-RUN]   - Copy Docker files"
        log_info "[DRY-RUN]   - Build and start containers for: $nat_types"
        return 0
    fi

    # Ensure Docker is available
    ensure_docker "$ip" "$name"

    # Create remote directory
    log_info "Creating remote directory on $name..."
    ssh "root@$ip" "mkdir -p $REMOTE_BASE"

    # Copy Docker configurations
    log_info "Copying Docker configurations to $name..."
    scp -r "$DOCKER_DIR"/* "root@$ip:$REMOTE_BASE/"

    # Build and start specific NAT containers
    log_info "Building and starting NAT containers on $name..."

    # Parse NAT types and start appropriate services
    IFS=',' read -ra NAT_ARRAY <<< "$nat_types"
    local services=""
    for nat in "${NAT_ARRAY[@]}"; do
        case "$nat" in
            fullcone)
                services+=" nat-fullcone node-fullcone"
                ;;
            restricted)
                services+=" nat-restricted node-restricted"
                ;;
            portrestricted)
                services+=" nat-portrestricted node-portrestricted"
                ;;
            symmetric)
                services+=" nat-symmetric node-symmetric"
                ;;
            cgnat)
                services+=" nat-cgnat node-cgnat"
                ;;
            hairpin)
                services+=" nat-hairpin node-hairpin"
                ;;
            doublenat)
                services+=" nat-doublenat-outer nat-doublenat-inner node-doublenat"
                ;;
            *)
                log_warn "Unknown NAT type: $nat"
                ;;
        esac
    done

    # Build and start services
    ssh "root@$ip" "cd $REMOTE_BASE && docker compose build $services && docker compose up -d $services"

    log_success "Deployment to $name completed"
}

# Deploy to all configured nodes
deploy_all() {
    log_info "Deploying NAT emulation to all configured nodes..."

    local failed=0
    for name in "${!NODES[@]}"; do
        if ! deploy_to_node "$name"; then
            ((failed++))
        fi
    done

    if [[ $failed -eq 0 ]]; then
        log_success "All deployments completed successfully"
    else
        log_warn "$failed deployment(s) failed"
    fi
}

# Show status of NAT containers on all nodes
show_status() {
    log_info "Checking NAT container status on all nodes..."

    for name in "${!NODES[@]}"; do
        local config="${NODES[$name]}"
        IFS=':' read -r ip nat_types <<< "$config"

        echo ""
        log_info "=== $name ($ip) ==="

        if check_ssh "$ip" "$name" 2>/dev/null; then
            ssh "root@$ip" "cd $REMOTE_BASE 2>/dev/null && docker compose ps 2>/dev/null || echo 'No NAT containers running'"
        fi
    done
}

# Stop NAT containers on a node
stop_node() {
    local name="$1"
    local config="${NODES[$name]}"

    IFS=':' read -r ip nat_types <<< "$config"

    log_info "Stopping NAT containers on $name ($ip)..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would stop containers on $name"
        return 0
    fi

    if check_ssh "$ip" "$name"; then
        ssh "root@$ip" "cd $REMOTE_BASE && docker compose down" || true
        log_success "Containers stopped on $name"
    fi
}

# Main entry point
main() {
    echo ""
    log_info "NAT Emulation Deployment Script"
    echo "=================================="

    check_prerequisites

    if [[ -n "$TARGET_NODE" ]]; then
        if [[ -v "NODES[$TARGET_NODE]" ]]; then
            deploy_to_node "$TARGET_NODE"
        else
            log_error "Unknown node: $TARGET_NODE"
            log_info "Available nodes: ${!NODES[*]}"
            exit 1
        fi
    else
        deploy_all
    fi

    echo ""
    log_info "Deployment summary:"
    show_status
}

# Run main
main "$@"
