#!/usr/bin/env bash
# deploy-test-network.sh - Deploy ant-quic test network from GitHub releases
#
# Usage:
#   ./scripts/deploy-test-network.sh deploy    # Download + deploy all nodes
#   ./scripts/deploy-test-network.sh start     # Start all services
#   ./scripts/deploy-test-network.sh stop      # Stop all services
#   ./scripts/deploy-test-network.sh restart   # Restart all services
#   ./scripts/deploy-test-network.sh status    # Show node status
#   ./scripts/deploy-test-network.sh logs      # Tail logs from all nodes
#   ./scripts/deploy-test-network.sh dashboard # Open dashboard in browser
#
# Options:
#   --version X.Y.Z  # Specify release version (default: latest)
#   --node NAME      # Target specific node (saorsa-1, saorsa-2, saorsa-3)
#   --dry-run        # Show commands without executing

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
GITHUB_REPO="dirvine/ant-quic"
INSTALL_DIR="/opt/ant-quic-test"
SERVICE_NAME="ant-quic-test"
REGISTRY_PORT="8080"

# Node definitions (bash 3.x compatible)
NODE_NAMES="saorsa-1 saorsa-2 saorsa-3"

get_node_hostname() {
    case "$1" in
        saorsa-1) echo "saorsa-1.saorsalabs.com" ;;
        saorsa-2) echo "saorsa-2.saorsalabs.com" ;;
        saorsa-3) echo "saorsa-3.saorsalabs.com" ;;
    esac
}

get_node_ip() {
    case "$1" in
        saorsa-1) echo "77.42.75.115" ;;
        saorsa-2) echo "162.243.167.201" ;;
        saorsa-3) echo "159.65.221.230" ;;
    esac
}

get_node_role() {
    case "$1" in
        saorsa-1) echo "registry" ;;   # Registry server with dashboard
        saorsa-2) echo "node" ;;       # Test node
        saorsa-3) echo "node" ;;       # Test node
    esac
}

# Registry node hosts the dashboard
REGISTRY_NODE="saorsa-1"
REGISTRY_HOSTNAME=$(get_node_hostname "$REGISTRY_NODE")
REGISTRY_URL="https://quic.saorsalabs.com"
DASHBOARD_URL="${REGISTRY_URL}"

# Parse arguments
VERSION=""
TARGET_NODE=""
DRY_RUN=false
COMMAND=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --node)
            TARGET_NODE="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        deploy|start|stop|restart|status|logs|dashboard|health)
            COMMAND="$1"
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Get latest version if not specified
get_latest_version() {
    curl -s "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | \
        grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/'
}

# Log functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Execute command on remote node
remote_exec() {
    local node=$1
    local cmd=$2
    local hostname
    hostname=$(get_node_hostname "$node")

    if $DRY_RUN; then
        echo -e "${YELLOW}[DRY-RUN]${NC} ssh root@${hostname} '$cmd'"
    else
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "root@${hostname}" "$cmd"
    fi
}

# Generate systemd service file for registry server
generate_registry_service_file() {
    cat << EOF
[Unit]
Description=ant-quic Test Network Registry Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/ant-quic-test --registry --port ${REGISTRY_PORT}
Restart=always
RestartSec=5
StandardOutput=append:/var/log/ant-quic-test.log
StandardError=append:/var/log/ant-quic-test.log
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF
}

# Generate systemd service file for test node
generate_node_service_file() {
    cat << EOF
[Unit]
Description=ant-quic Test Network Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/ant-quic-test --registry-url ${REGISTRY_URL}
Restart=always
RestartSec=5
StandardOutput=append:/var/log/ant-quic-test.log
StandardError=append:/var/log/ant-quic-test.log
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF
}

# Deploy to a single node
deploy_node() {
    local node=$1
    local version=$2
    local hostname
    local role
    hostname=$(get_node_hostname "$node")
    role=$(get_node_role "$node")

    log_info "Deploying to ${node} (${hostname}) as ${role}..."

    # Create install directory
    remote_exec "$node" "mkdir -p ${INSTALL_DIR}"

    # Download binary
    local release_url="https://github.com/${GITHUB_REPO}/releases/download/v${version}"
    local archive="ant-quic-test-x86_64-linux.tar.gz"

    log_info "  Downloading ant-quic-test v${version}..."
    remote_exec "$node" "cd ${INSTALL_DIR} && wget -q -O ${archive} ${release_url}/${archive}"
    remote_exec "$node" "cd ${INSTALL_DIR} && tar -xzf ${archive} && rm ${archive}"
    remote_exec "$node" "chmod +x ${INSTALL_DIR}/ant-quic-test"

    # Generate and install appropriate service file
    log_info "  Installing systemd service (${role})..."
    local service_file
    if [[ "$role" == "registry" ]]; then
        service_file=$(generate_registry_service_file)
    else
        service_file=$(generate_node_service_file)
    fi

    if $DRY_RUN; then
        echo -e "${YELLOW}[DRY-RUN]${NC} Would write service file for ${node}"
        echo "$service_file"
    else
        echo "$service_file" | ssh "root@${hostname}" "cat > /etc/systemd/system/${SERVICE_NAME}.service"
    fi

    # Reload systemd
    remote_exec "$node" "systemctl daemon-reload"

    log_success "  Deployed to ${node} (${role})"
}

# Command: deploy
cmd_deploy() {
    if [[ -z "$VERSION" ]]; then
        VERSION=$(get_latest_version)
        if [[ -z "$VERSION" ]]; then
            log_error "Could not determine latest version. Please specify with --version"
            exit 1
        fi
        log_info "Using latest version: v${VERSION}"
    fi

    local nodes_to_deploy
    if [[ -n "$TARGET_NODE" ]]; then
        nodes_to_deploy="$TARGET_NODE"
    else
        nodes_to_deploy="$NODE_NAMES"
    fi

    # Deploy registry first
    if [[ -z "$TARGET_NODE" ]]; then
        deploy_node "$REGISTRY_NODE" "$VERSION"
    fi

    for node in $nodes_to_deploy; do
        if [[ "$node" != "$REGISTRY_NODE" ]]; then
            deploy_node "$node" "$VERSION"
        fi
    done

    log_success "Deployment complete!"
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║               ant-quic Test Network Deployed!                 ║${NC}"
    echo -e "${CYAN}║                   \"We will be legion!!\"                       ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    log_info "Run './scripts/deploy-test-network.sh start' to start services"
    log_info "Dashboard will be available at: ${DASHBOARD_URL}"
}

# Command: start
cmd_start() {
    local nodes_to_start
    if [[ -n "$TARGET_NODE" ]]; then
        nodes_to_start="$TARGET_NODE"
    else
        nodes_to_start="$NODE_NAMES"
    fi

    # Start registry first (it must be running before nodes can register)
    if [[ -z "$TARGET_NODE" ]] || [[ "$TARGET_NODE" == "$REGISTRY_NODE" ]]; then
        log_info "Starting registry server on ${REGISTRY_NODE}..."
        remote_exec "$REGISTRY_NODE" "systemctl start ${SERVICE_NAME}"
        sleep 3  # Give registry time to start
    fi

    # Start other nodes
    for node in $nodes_to_start; do
        if [[ "$node" != "$REGISTRY_NODE" ]]; then
            log_info "Starting test node on ${node}..."
            remote_exec "$node" "systemctl start ${SERVICE_NAME}"
        fi
    done

    log_success "Services started"
    echo ""
    log_info "Dashboard: ${DASHBOARD_URL}"
    log_info "Run './scripts/deploy-test-network.sh status' to verify"
}

# Command: stop
cmd_stop() {
    local nodes_to_stop
    if [[ -n "$TARGET_NODE" ]]; then
        nodes_to_stop="$TARGET_NODE"
    else
        nodes_to_stop="$NODE_NAMES"
    fi

    for node in $nodes_to_stop; do
        log_info "Stopping ${SERVICE_NAME} on ${node}..."
        remote_exec "$node" "systemctl stop ${SERVICE_NAME} 2>/dev/null || true"
    done

    log_success "Services stopped"
}

# Command: restart
cmd_restart() {
    cmd_stop
    sleep 2
    cmd_start
}

# Command: status
cmd_status() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           ant-quic Test Network Status                        ║${NC}"
    echo -e "${CYAN}║                 \"We will be legion!!\"                         ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    for node in $NODE_NAMES; do
        local hostname
        local ip
        local role
        hostname=$(get_node_hostname "$node")
        ip=$(get_node_ip "$node")
        role=$(get_node_role "$node")

        echo -e "${BLUE}${node}${NC} (${hostname} / ${ip}) - ${YELLOW}${role}${NC}"

        # Check service status
        local status
        status=$(remote_exec "$node" "systemctl is-active ${SERVICE_NAME} 2>/dev/null || echo 'inactive'")
        if [[ "$status" == "active" ]]; then
            echo -e "  Status: ${GREEN}● running${NC}"

            # Get some metrics if available
            local uptime
            uptime=$(remote_exec "$node" "systemctl show ${SERVICE_NAME} --property=ActiveEnterTimestamp 2>/dev/null | cut -d= -f2" || echo "unknown")
            echo -e "  Started: ${uptime}"
        else
            echo -e "  Status: ${RED}○ ${status}${NC}"
        fi

        # Show role-specific info
        if [[ "$role" == "registry" ]]; then
            echo -e "  Dashboard: ${DASHBOARD_URL}"
        else
            echo -e "  Registry: ${REGISTRY_URL}"
        fi

        echo ""
    done

    # Check registry API
    echo "Registry API health:"
    if curl -s --connect-timeout 5 "${REGISTRY_URL}/health" > /dev/null 2>&1; then
        echo -e "  ${GREEN}● Reachable${NC} at ${REGISTRY_URL}"

        # Get network stats
        local stats
        if stats=$(curl -s --connect-timeout 5 "${REGISTRY_URL}/api/stats" 2>/dev/null); then
            local total_nodes
            local active_nodes
            total_nodes=$(echo "$stats" | grep -o '"total_nodes":[0-9]*' | cut -d: -f2 || echo "0")
            active_nodes=$(echo "$stats" | grep -o '"active_nodes":[0-9]*' | cut -d: -f2 || echo "0")
            echo -e "  Nodes: ${CYAN}${active_nodes}${NC} active / ${total_nodes} total"
        fi
    else
        echo -e "  ${RED}○ Unreachable${NC}"
    fi
    echo ""
}

# Command: logs
cmd_logs() {
    local nodes_to_log
    if [[ -n "$TARGET_NODE" ]]; then
        nodes_to_log="$TARGET_NODE"
    else
        nodes_to_log="$NODE_NAMES"
    fi

    for node in $nodes_to_log; do
        local role
        role=$(get_node_role "$node")
        echo -e "\n${BLUE}=== Logs from ${node} (${role}) ===${NC}\n"
        remote_exec "$node" "tail -50 /var/log/ant-quic-test.log 2>/dev/null || journalctl -u ${SERVICE_NAME} -n 50 --no-pager"
    done
}

# Command: dashboard
cmd_dashboard() {
    log_info "Opening dashboard at ${DASHBOARD_URL}"
    if command -v open &> /dev/null; then
        open "${DASHBOARD_URL}"
    elif command -v xdg-open &> /dev/null; then
        xdg-open "${DASHBOARD_URL}"
    else
        echo "Dashboard URL: ${DASHBOARD_URL}"
    fi
}

# Command: health
cmd_health() {
    echo ""
    echo "Checking node connectivity..."
    echo ""

    for node in $NODE_NAMES; do
        local hostname
        hostname=$(get_node_hostname "$node")
        echo -n "${node}: "
        if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "root@${hostname}" "echo ok" 2>/dev/null; then
            echo -e "${GREEN}SSH OK${NC}"
        else
            echo -e "${RED}SSH FAILED${NC}"
        fi
    done
    echo ""
}

# Show usage
show_usage() {
    cat << EOF
${CYAN}╔═══════════════════════════════════════════════════════════════╗
║         ant-quic Test Network Deployment Tool                 ║
║                   "We will be legion!!"                       ║
╚═══════════════════════════════════════════════════════════════╝${NC}

Usage: $0 <command> [options]

Commands:
  deploy    Download binaries from GitHub releases and deploy to all nodes
  start     Start all test network services
  stop      Stop all test network services
  restart   Restart all test network services
  status    Show status of all nodes and services
  logs      Tail logs from all nodes
  dashboard Open the dashboard in browser
  health    Check SSH connectivity to all nodes

Options:
  --version X.Y.Z  Specify release version (default: latest)
  --node NAME      Target specific node (saorsa-1, saorsa-2, saorsa-3)
  --dry-run        Show commands without executing

Examples:
  $0 deploy                          # Deploy latest version to all nodes
  $0 deploy --version 0.14.0         # Deploy specific version
  $0 deploy --node saorsa-1          # Deploy only to registry node
  $0 start                           # Start all services
  $0 status                          # Check status
  $0 logs --node saorsa-2            # View logs from specific node

Nodes:
  saorsa-1  Registry server with web dashboard (${REGISTRY_URL})
  saorsa-2  Test node (auto-registers with registry)
  saorsa-3  Test node (auto-registers with registry)

Dashboard: ${DASHBOARD_URL}

Network Architecture:
  ┌─────────────────┐
  │   saorsa-1      │  Registry + Dashboard
  │  ${REGISTRY_URL}│  POST /api/register
  └────────┬────────┘  GET  /api/peers
           │           WS   /ws/live
     ┌─────┴─────┐
     │           │
┌────▼────┐ ┌────▼────┐
│ saorsa-2│ │ saorsa-3│  Test Nodes
│  (TUI)  │ │  (TUI)  │  Auto-connect
└─────────┘ └─────────┘  5KB test packets
EOF
}

# Main
if [[ -z "$COMMAND" ]]; then
    show_usage
    exit 0
fi

case $COMMAND in
    deploy)
        cmd_deploy
        ;;
    start)
        cmd_start
        ;;
    stop)
        cmd_stop
        ;;
    restart)
        cmd_restart
        ;;
    status)
        cmd_status
        ;;
    logs)
        cmd_logs
        ;;
    dashboard)
        cmd_dashboard
        ;;
    health)
        cmd_health
        ;;
    *)
        show_usage
        exit 1
        ;;
esac
