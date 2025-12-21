#!/usr/bin/env bash
# deploy-bootstrap-network.sh - Deploy ant-quic bootstrap network from GitHub releases
#
# Usage:
#   ./scripts/deploy-bootstrap-network.sh deploy    # Download + deploy all nodes
#   ./scripts/deploy-bootstrap-network.sh start     # Start all services
#   ./scripts/deploy-bootstrap-network.sh stop      # Stop all services
#   ./scripts/deploy-bootstrap-network.sh restart   # Restart all services
#   ./scripts/deploy-bootstrap-network.sh status    # Show node status
#   ./scripts/deploy-bootstrap-network.sh logs      # Tail logs from all nodes
#   ./scripts/deploy-bootstrap-network.sh dashboard # Open dashboard in browser
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
NC='\033[0m' # No Color

# Configuration
GITHUB_REPO="dirvine/ant-quic"
INSTALL_DIR="/opt/ant-quic"
SERVICE_NAME="ant-quic"
DASHBOARD_PORT="8080"
QUIC_PORT="9000"

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

get_node_location() {
    case "$1" in
        saorsa-1) echo "hetzner-eu" ;;
        saorsa-2) echo "do-nyc" ;;
        saorsa-3) echo "do-nyc" ;;
    esac
}

# Dashboard node
DASHBOARD_NODE="saorsa-1"
DASHBOARD_HOSTNAME=$(get_node_hostname "$DASHBOARD_NODE")
DASHBOARD_URL="http://${DASHBOARD_HOSTNAME}:${DASHBOARD_PORT}"

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

# Copy file to remote node
remote_copy() {
    local src=$1
    local node=$2
    local dest=$3
    local hostname
    hostname=$(get_node_hostname "$node")

    if $DRY_RUN; then
        echo -e "${YELLOW}[DRY-RUN]${NC} scp $src root@${hostname}:$dest"
    else
        scp -o StrictHostKeyChecking=no "$src" "root@${hostname}:$dest"
    fi
}

# Get all bootstrap peers except the current node (uses IPs for SocketAddr compatibility)
get_peers_for_node() {
    local current_node=$1
    local peers=""
    for node in $NODE_NAMES; do
        if [[ "$node" != "$current_node" ]]; then
            if [[ -n "$peers" ]]; then
                peers="${peers},"
            fi
            peers="${peers}$(get_node_ip "$node"):${QUIC_PORT}"
        fi
    done
    echo "$peers"
}

# Generate systemd service file
generate_service_file() {
    local node=$1
    local peers
    local location
    peers=$(get_peers_for_node "$node")
    location=$(get_node_location "$node")

    # Build the ExecStart command
    local exec_cmd="${INSTALL_DIR}/ant-quic"
    exec_cmd="${exec_cmd} --listen 0.0.0.0:${QUIC_PORT}"
    exec_cmd="${exec_cmd} --known-peers ${peers}"
    exec_cmd="${exec_cmd} --node-id ${node}"
    exec_cmd="${exec_cmd} --node-location ${location}"

    # Only non-dashboard nodes send metrics to the dashboard
    if [[ "$node" != "$DASHBOARD_NODE" ]]; then
        exec_cmd="${exec_cmd} --metrics-server ${DASHBOARD_URL}"
    fi

    exec_cmd="${exec_cmd} --stats --stats-interval 30"

    cat << EOF
[Unit]
Description=ant-quic P2P Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${exec_cmd}
Restart=always
RestartSec=5
StandardOutput=append:/var/log/ant-quic.log
StandardError=append:/var/log/ant-quic.log

[Install]
WantedBy=multi-user.target
EOF
}

# Generate dashboard systemd service file
generate_dashboard_service_file() {
    cat << EOF
[Unit]
Description=ant-quic E2E Dashboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/e2e-dashboard -b 0.0.0.0 -p ${DASHBOARD_PORT}
Restart=always
RestartSec=5
StandardOutput=append:/var/log/e2e-dashboard.log
StandardError=append:/var/log/e2e-dashboard.log

[Install]
WantedBy=multi-user.target
EOF
}

# Deploy to a single node
deploy_node() {
    local node=$1
    local version=$2
    local hostname
    hostname=$(get_node_hostname "$node")

    log_info "Deploying to ${node} (${hostname})..."

    # Create install directory
    remote_exec "$node" "mkdir -p ${INSTALL_DIR}"

    # Download binary
    local release_url="https://github.com/${GITHUB_REPO}/releases/download/v${version}"
    local archive="ant-quic-x86_64-linux.tar.gz"

    log_info "  Downloading ant-quic v${version}..."
    remote_exec "$node" "cd ${INSTALL_DIR} && wget -q -O ${archive} ${release_url}/${archive}"
    remote_exec "$node" "cd ${INSTALL_DIR} && tar -xzf ${archive} && rm ${archive}"
    remote_exec "$node" "chmod +x ${INSTALL_DIR}/ant-quic"

    # Download dashboard for the dashboard node
    if [[ "$node" == "$DASHBOARD_NODE" ]]; then
        log_info "  Downloading e2e-dashboard v${version}..."
        local dashboard_archive="e2e-dashboard-x86_64-linux.tar.gz"
        remote_exec "$node" "cd ${INSTALL_DIR} && wget -q -O ${dashboard_archive} ${release_url}/${dashboard_archive} || echo 'Dashboard not in release, skipping'"
        remote_exec "$node" "cd ${INSTALL_DIR} && tar -xzf ${dashboard_archive} 2>/dev/null && rm -f ${dashboard_archive} || true"
        remote_exec "$node" "chmod +x ${INSTALL_DIR}/e2e-dashboard 2>/dev/null || true"
    fi

    # Generate and install service file
    log_info "  Installing systemd service..."
    local service_file=$(generate_service_file "$node")
    if $DRY_RUN; then
        echo -e "${YELLOW}[DRY-RUN]${NC} Would write service file for ${node}"
        echo "$service_file"
    else
        echo "$service_file" | ssh "root@${hostname}" "cat > /etc/systemd/system/${SERVICE_NAME}.service"
    fi

    # Install dashboard service on dashboard node
    if [[ "$node" == "$DASHBOARD_NODE" ]]; then
        log_info "  Installing dashboard systemd service..."
        local dashboard_service=$(generate_dashboard_service_file)
        if $DRY_RUN; then
            echo -e "${YELLOW}[DRY-RUN]${NC} Would write dashboard service file"
        else
            echo "$dashboard_service" | ssh "root@${hostname}" "cat > /etc/systemd/system/e2e-dashboard.service"
        fi
    fi

    # Reload systemd
    remote_exec "$node" "systemctl daemon-reload"

    log_success "  Deployed to ${node}"
}

# Command: deploy
cmd_deploy() {
    if [[ -z "$VERSION" ]]; then
        VERSION=$(get_latest_version)
        log_info "Using latest version: v${VERSION}"
    fi

    local nodes_to_deploy
    if [[ -n "$TARGET_NODE" ]]; then
        nodes_to_deploy="$TARGET_NODE"
    else
        nodes_to_deploy="$NODE_NAMES"
    fi

    for node in $nodes_to_deploy; do
        deploy_node "$node" "$VERSION"
    done

    log_success "Deployment complete!"
    log_info "Run './scripts/deploy-bootstrap-network.sh start' to start services"
}

# Command: start
cmd_start() {
    local nodes_to_start
    if [[ -n "$TARGET_NODE" ]]; then
        nodes_to_start="$TARGET_NODE"
    else
        nodes_to_start="$NODE_NAMES"
    fi

    # Start dashboard first
    if [[ -z "$TARGET_NODE" ]] || [[ "$TARGET_NODE" == "$DASHBOARD_NODE" ]]; then
        log_info "Starting dashboard on ${DASHBOARD_NODE}..."
        remote_exec "$DASHBOARD_NODE" "systemctl start e2e-dashboard 2>/dev/null || true"
        sleep 2
    fi

    for node in $nodes_to_start; do
        log_info "Starting ${SERVICE_NAME} on ${node}..."
        remote_exec "$node" "systemctl start ${SERVICE_NAME}"
    done

    log_success "Services started"
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
        if [[ "$node" == "$DASHBOARD_NODE" ]]; then
            remote_exec "$node" "systemctl stop e2e-dashboard 2>/dev/null || true"
        fi
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
    echo "==========================================="
    echo "       ant-quic Bootstrap Network Status"
    echo "==========================================="
    echo ""

    for node in $NODE_NAMES; do
        local hostname
        local ip
        hostname=$(get_node_hostname "$node")
        ip=$(get_node_ip "$node")
        echo -e "${BLUE}${node}${NC} (${hostname} / ${ip})"

        # Check service status
        local status
        status=$(remote_exec "$node" "systemctl is-active ${SERVICE_NAME} 2>/dev/null || echo 'inactive'")
        if [[ "$status" == "active" ]]; then
            echo -e "  ant-quic: ${GREEN}running${NC}"
        else
            echo -e "  ant-quic: ${RED}${status}${NC}"
        fi

        # Check dashboard on dashboard node
        if [[ "$node" == "$DASHBOARD_NODE" ]]; then
            local dashboard_status
            dashboard_status=$(remote_exec "$node" "systemctl is-active e2e-dashboard 2>/dev/null || echo 'inactive'")
            if [[ "$dashboard_status" == "active" ]]; then
                echo -e "  dashboard: ${GREEN}running${NC} (${DASHBOARD_URL})"
            else
                echo -e "  dashboard: ${RED}${dashboard_status}${NC}"
            fi
        fi

        echo ""
    done

    # Check dashboard API
    echo "Dashboard API health:"
    if curl -s --connect-timeout 5 "${DASHBOARD_URL}/api/metrics" > /dev/null 2>&1; then
        echo -e "  ${GREEN}Reachable${NC} at ${DASHBOARD_URL}"
    else
        echo -e "  ${RED}Unreachable${NC}"
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
        echo -e "\n${BLUE}=== Logs from ${node} ===${NC}\n"
        remote_exec "$node" "tail -50 /var/log/ant-quic.log 2>/dev/null || journalctl -u ${SERVICE_NAME} -n 50 --no-pager"
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
Usage: $0 <command> [options]

Commands:
  deploy    Download binaries from GitHub releases and deploy to all nodes
  start     Start all ant-quic services
  stop      Stop all ant-quic services
  restart   Restart all ant-quic services
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
  $0 deploy --node saorsa-1          # Deploy only to saorsa-1
  $0 start                           # Start all services
  $0 status                          # Check status
  $0 logs --node saorsa-2            # View logs from specific node

Nodes:
  saorsa-1  saorsa-1.saorsalabs.com (Dashboard + Primary bootstrap)
  saorsa-2  saorsa-2.saorsalabs.com (Bootstrap peer)
  saorsa-3  saorsa-3.saorsalabs.com (NAT test node)

Dashboard: ${DASHBOARD_URL}
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
