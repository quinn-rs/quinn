#!/bin/bash
# Quick deployment script for ant-quic on Digital Ocean

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TERRAFORM_DIR="${SCRIPT_DIR}/terraform"
ANSIBLE_DIR="${SCRIPT_DIR}/ansible"

# Functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

check_requirements() {
    log "Checking requirements..."
    
    # Check for required tools
    for cmd in terraform ansible-playbook ssh jq; do
        if ! command -v $cmd &> /dev/null; then
            error "$cmd is required but not installed."
        fi
    done
    
    # Check for DO token
    if [ -z "$DO_TOKEN" ] && [ -z "$TF_VAR_do_token" ]; then
        error "Digital Ocean API token not set. Export DO_TOKEN or TF_VAR_do_token"
    fi
    
    log "All requirements satisfied"
}

provision_infrastructure() {
    log "Provisioning infrastructure with Terraform..."
    
    cd "$TERRAFORM_DIR"
    
    # Initialize Terraform
    if [ ! -d .terraform ]; then
        terraform init || error "Terraform init failed"
    fi
    
    # Plan deployment
    terraform plan -out=tfplan || error "Terraform plan failed"
    
    # Apply if user confirms
    read -p "Deploy infrastructure? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        terraform apply tfplan || error "Terraform apply failed"
        
        # Save outputs
        terraform output -json > ../terraform-outputs.json
        
        # Extract IPs
        FLOATING_IP=$(jq -r '.floating_ip.value' ../terraform-outputs.json)
        DROPLET_ID=$(jq -r '.droplet_id.value' ../terraform-outputs.json)
        
        log "Infrastructure created successfully"
        log "Floating IP: $FLOATING_IP"
        log "Droplet ID: $DROPLET_ID"
    else
        warn "Infrastructure deployment cancelled"
        exit 0
    fi
    
    cd "$SCRIPT_DIR"
}

configure_server() {
    log "Configuring server with Ansible..."
    
    cd "$ANSIBLE_DIR"
    
    # Get server IP from Terraform or user
    if [ -f ../terraform-outputs.json ]; then
        SERVER_IP=$(jq -r '.floating_ip.value' ../terraform-outputs.json)
    else
        read -p "Enter server IP: " SERVER_IP
    fi
    
    # Update inventory
    sed -i.bak "s/YOUR_DO_IP/${SERVER_IP}/g" inventory.ini
    
    # Get configuration
    read -p "Domain name (or press Enter to skip): " DOMAIN_NAME
    read -p "Email for Let's Encrypt (or press Enter to skip): " CERTBOT_EMAIL
    
    # Set environment variables
    export ANSIBLE_HOST_KEY_CHECKING=False
    [ -n "$DOMAIN_NAME" ] && export DOMAIN_NAME
    [ -n "$CERTBOT_EMAIL" ] && export CERTBOT_EMAIL
    
    # Wait for server to be ready
    log "Waiting for server to be ready..."
    for i in {1..30}; do
        if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@${SERVER_IP} "echo ready" &>/dev/null; then
            break
        fi
        echo -n "."
        sleep 10
    done
    echo
    
    # Run playbook
    ansible-playbook -i inventory.ini playbook.yml || error "Ansible playbook failed"
    
    log "Server configured successfully"
    cd "$SCRIPT_DIR"
}

test_deployment() {
    log "Testing deployment..."
    
    if [ -f terraform-outputs.json ]; then
        SERVER_IP=$(jq -r '.floating_ip.value' terraform-outputs.json)
    else
        read -p "Enter server IP to test: " SERVER_IP
    fi
    
    # Test SSH
    log "Testing SSH connectivity..."
    ssh -o ConnectTimeout=5 root@${SERVER_IP} "echo 'SSH OK'" || warn "SSH test failed"
    
    # Test QUIC port
    log "Testing QUIC port..."
    nc -u -z -w 5 ${SERVER_IP} 9000 && log "QUIC port is open" || warn "QUIC port test failed"
    
    # Test health endpoint
    if [ -n "$DOMAIN_NAME" ]; then
        log "Testing health endpoint..."
        curl -sf https://${DOMAIN_NAME}/health && log "Health check OK" || warn "Health check failed"
    fi
    
    # Test with ant-quic client
    if command -v ant-quic &> /dev/null; then
        log "Testing with ant-quic client..."
        timeout 10 ant-quic --connect ${SERVER_IP}:9000 || warn "ant-quic connection test failed"
    fi
    
    log "Deployment testing complete"
}

show_info() {
    log "Deployment Information:"
    
    if [ -f terraform-outputs.json ]; then
        echo
        echo "Server Details:"
        echo "  Floating IP: $(jq -r '.floating_ip.value' terraform-outputs.json)"
        echo "  IPv6: $(jq -r '.ipv6_address.value' terraform-outputs.json)"
        echo "  Droplet ID: $(jq -r '.droplet_id.value' terraform-outputs.json)"
    fi
    
    echo
    echo "Service Management:"
    echo "  Start:   ssh root@SERVER_IP 'systemctl start ant-quic'"
    echo "  Stop:    ssh root@SERVER_IP 'systemctl stop ant-quic'"
    echo "  Status:  ssh root@SERVER_IP 'systemctl status ant-quic'"
    echo "  Logs:    ssh root@SERVER_IP 'journalctl -u ant-quic -f'"
    
    echo
    echo "Testing:"
    echo "  Health:  curl https://DOMAIN/health"
    echo "  Connect: ant-quic --connect SERVER_IP:9000"
    
    echo
    echo "Documentation:"
    echo "  External Testing: docs/EXTERNAL_TESTING_GUIDE.md"
    echo "  Deployment: deploy/digitalocean/README.md"
}

destroy_infrastructure() {
    warn "This will destroy all infrastructure!"
    read -p "Are you sure? Type 'yes' to confirm: " CONFIRM
    
    if [ "$CONFIRM" = "yes" ]; then
        cd "$TERRAFORM_DIR"
        terraform destroy -auto-approve
        cd "$SCRIPT_DIR"
        rm -f terraform-outputs.json
        log "Infrastructure destroyed"
    else
        log "Destruction cancelled"
    fi
}

# Main menu
main() {
    echo "ant-quic Digital Ocean Deployment"
    echo "================================="
    echo
    echo "1) Full deployment (Terraform + Ansible)"
    echo "2) Provision infrastructure only (Terraform)"
    echo "3) Configure server only (Ansible)"
    echo "4) Test deployment"
    echo "5) Show deployment info"
    echo "6) Destroy infrastructure"
    echo "0) Exit"
    echo
    read -p "Select option: " -n 1 -r
    echo
    
    case $REPLY in
        1)
            check_requirements
            provision_infrastructure
            configure_server
            test_deployment
            show_info
            ;;
        2)
            check_requirements
            provision_infrastructure
            ;;
        3)
            configure_server
            ;;
        4)
            test_deployment
            ;;
        5)
            show_info
            ;;
        6)
            destroy_infrastructure
            ;;
        0)
            exit 0
            ;;
        *)
            error "Invalid option"
            ;;
    esac
}

# Run main if not sourced
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main
fi