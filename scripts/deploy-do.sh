#!/bin/bash

# DigitalOcean Deployment Script for ant-quic
# This script handles deployment to DigitalOcean droplets

set -euo pipefail

# Configuration
DO_USER="${DO_USER:-root}"
DO_HOST="${DO_HOST:-}"
DO_PORT="${DO_PORT:-22}"
DO_KEY="${DO_SSH_KEY:-~/.ssh/id_rsa}"
DEPLOY_DIR="${DEPLOY_DIR:-/opt/ant-quic}"
SERVICE_NAME="ant-quic"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*" >&2
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    if [ -z "$DO_HOST" ]; then
        error "DO_HOST environment variable is not set"
        exit 1
    fi
    
    if [ ! -f "$DO_KEY" ]; then
        error "SSH key not found at $DO_KEY"
        exit 1
    fi
    
    # Check SSH connectivity
    if ! ssh -q -o BatchMode=yes -o ConnectTimeout=5 -i "$DO_KEY" -p "$DO_PORT" "$DO_USER@$DO_HOST" exit; then
        error "Cannot connect to $DO_USER@$DO_HOST:$DO_PORT"
        exit 1
    fi
    
    log "Prerequisites check passed"
}

# Build release binary
build_release() {
    log "Building release binary..."
    
    # Check if we're in the project root
    if [ ! -f "Cargo.toml" ]; then
        error "Not in project root directory"
        exit 1
    fi
    
    # Build with all features including PQC
    cargo build --release --features "pqc aws-lc-rs" --bin ant-quic
    
    if [ ! -f "target/release/ant-quic" ]; then
        error "Build failed - binary not found"
        exit 1
    fi
    
    log "Build successful"
}

# Deploy to DigitalOcean
deploy() {
    local git_sha="$(git rev-parse HEAD)"
    local branch="$(git rev-parse --abbrev-ref HEAD)"
    
    log "Deploying ant-quic to $DO_HOST"
    log "Git SHA: $git_sha"
    log "Branch: $branch"
    
    # Create deployment directory on remote
    ssh -i "$DO_KEY" -p "$DO_PORT" "$DO_USER@$DO_HOST" << EOF
        set -e
        
        # Create directories
        mkdir -p $DEPLOY_DIR/bin
        mkdir -p $DEPLOY_DIR/config
        mkdir -p $DEPLOY_DIR/logs
        mkdir -p $DEPLOY_DIR/data
        
        # Create deployment info file
        cat > $DEPLOY_DIR/deployment.json << 'DEPLOYMENT'
{
    "git_sha": "$git_sha",
    "branch": "$branch",
    "deployed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "deployed_by": "$(whoami)@$(hostname)"
}
DEPLOYMENT
EOF
    
    # Copy binary
    log "Copying binary..."
    scp -i "$DO_KEY" -P "$DO_PORT" target/release/ant-quic "$DO_USER@$DO_HOST:$DEPLOY_DIR/bin/ant-quic.new"
    
    # Copy configuration files
    log "Copying configuration..."
    if [ -d "deploy/config" ]; then
        scp -i "$DO_KEY" -P "$DO_PORT" -r deploy/config/* "$DO_USER@$DO_HOST:$DEPLOY_DIR/config/"
    fi
    
    # Copy systemd service file
    log "Installing systemd service..."
    cat > /tmp/ant-quic.service << EOF
[Unit]
Description=ant-quic P2P QUIC Node
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=$DO_USER
Group=$DO_USER
WorkingDirectory=$DEPLOY_DIR
Environment="RUST_LOG=info"
Environment="RUST_BACKTRACE=1"
ExecStart=$DEPLOY_DIR/bin/ant-quic --listen 0.0.0.0:9000 --force-coordinator --dashboard
Restart=always
RestartSec=10
KillMode=mixed
KillSignal=SIGTERM

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DEPLOY_DIR/logs $DEPLOY_DIR/data

# Logging
StandardOutput=append:$DEPLOY_DIR/logs/ant-quic.log
StandardError=append:$DEPLOY_DIR/logs/ant-quic.error.log

[Install]
WantedBy=multi-user.target
EOF
    
    scp -i "$DO_KEY" -P "$DO_PORT" /tmp/ant-quic.service "$DO_USER@$DO_HOST:/tmp/"
    rm /tmp/ant-quic.service
    
    # Perform deployment
    ssh -i "$DO_KEY" -p "$DO_PORT" "$DO_USER@$DO_HOST" << 'EOF'
        set -e
        
        # Make binary executable
        chmod +x $DEPLOY_DIR/bin/ant-quic.new
        
        # Test new binary
        if ! $DEPLOY_DIR/bin/ant-quic.new --version; then
            echo "New binary test failed"
            exit 1
        fi
        
        # Install systemd service
        sudo cp /tmp/ant-quic.service /etc/systemd/system/
        sudo systemctl daemon-reload
        
        # Stop existing service if running
        if systemctl is-active --quiet $SERVICE_NAME; then
            echo "Stopping existing service..."
            sudo systemctl stop $SERVICE_NAME
            sleep 2
        fi
        
        # Backup old binary
        if [ -f "$DEPLOY_DIR/bin/ant-quic" ]; then
            mv $DEPLOY_DIR/bin/ant-quic $DEPLOY_DIR/bin/ant-quic.backup
        fi
        
        # Deploy new binary
        mv $DEPLOY_DIR/bin/ant-quic.new $DEPLOY_DIR/bin/ant-quic
        
        # Start service
        echo "Starting service..."
        sudo systemctl enable $SERVICE_NAME
        sudo systemctl start $SERVICE_NAME
        
        # Wait for service to start
        sleep 5
        
        # Check service status
        if systemctl is-active --quiet $SERVICE_NAME; then
            echo "Service started successfully"
            systemctl status $SERVICE_NAME --no-pager
        else
            echo "Service failed to start"
            journalctl -u $SERVICE_NAME -n 50 --no-pager
            exit 1
        fi
EOF
    
    log "Deployment completed successfully"
}

# Health check
health_check() {
    log "Running health check..."
    
    # Check if service is running
    if ssh -i "$DO_KEY" -p "$DO_PORT" "$DO_USER@$DO_HOST" "systemctl is-active --quiet $SERVICE_NAME"; then
        log "Service is active"
    else
        error "Service is not active"
        return 1
    fi
    
    # Check if port is listening
    if ssh -i "$DO_KEY" -p "$DO_PORT" "$DO_USER@$DO_HOST" "netstat -tln | grep -q :9000"; then
        log "Port 9000 is listening"
    else
        error "Port 9000 is not listening"
        return 1
    fi
    
    # Try to connect
    log "Testing connectivity..."
    if timeout 10 cargo run --release --bin ant-quic -- --bootstrap "$DO_HOST:9000" --minimal; then
        log "Successfully connected to deployed instance"
    else
        warning "Could not connect to deployed instance"
    fi
    
    return 0
}

# Rollback deployment
rollback() {
    log "Rolling back deployment..."
    
    ssh -i "$DO_KEY" -p "$DO_PORT" "$DO_USER@$DO_HOST" << 'EOF'
        set -e
        
        if [ ! -f "$DEPLOY_DIR/bin/ant-quic.backup" ]; then
            echo "No backup found to rollback to"
            exit 1
        fi
        
        # Stop service
        sudo systemctl stop $SERVICE_NAME
        
        # Restore backup
        mv $DEPLOY_DIR/bin/ant-quic.backup $DEPLOY_DIR/bin/ant-quic
        
        # Start service
        sudo systemctl start $SERVICE_NAME
        
        echo "Rollback completed"
EOF
}

# Main deployment flow
main() {
    local action="${1:-deploy}"
    
    case "$action" in
        deploy)
            check_prerequisites
            build_release
            deploy
            health_check || {
                error "Health check failed, rolling back..."
                rollback
                exit 1
            }
            ;;
        health)
            check_prerequisites
            health_check
            ;;
        rollback)
            check_prerequisites
            rollback
            ;;
        logs)
            check_prerequisites
            ssh -i "$DO_KEY" -p "$DO_PORT" "$DO_USER@$DO_HOST" "journalctl -u $SERVICE_NAME -f"
            ;;
        status)
            check_prerequisites
            ssh -i "$DO_KEY" -p "$DO_PORT" "$DO_USER@$DO_HOST" "systemctl status $SERVICE_NAME --no-pager"
            ;;
        *)
            echo "Usage: $0 [deploy|health|rollback|logs|status]"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"