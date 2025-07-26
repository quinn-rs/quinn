#!/bin/bash
# NAT Simulator Entrypoint Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[NAT-SIM]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Enable IP forwarding
log "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

# Clear existing iptables rules
log "Clearing existing iptables rules..."
iptables -t nat -F
iptables -t filter -F
iptables -t mangle -F

# Set default policies
iptables -P INPUT ACCEPT
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow established connections
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Configure NAT based on type
case "$NAT_TYPE" in
    "full-cone")
        log "Configuring Full Cone NAT..."
        /scripts/full-cone.sh
        ;;
    "restricted")
        log "Configuring Restricted Cone NAT..."
        /scripts/restricted.sh
        ;;
    "port-restricted")
        log "Configuring Port Restricted NAT..."
        /scripts/port-restricted.sh
        ;;
    "symmetric")
        log "Configuring Symmetric NAT..."
        /scripts/symmetric.sh
        ;;
    "cgnat")
        log "Configuring Carrier-Grade NAT..."
        /scripts/cgnat.sh
        ;;
    *)
        error "Unknown NAT type: $NAT_TYPE"
        ;;
esac

# Log NAT configuration
log "NAT Configuration:"
log "  Type: $NAT_TYPE"
log "  Internal Network: $INTERNAL_NET"
log "  External Interface: $EXTERNAL_IFACE"
log "  Internal Interface: $INTERNAL_IFACE"

# Show iptables rules
if [ "$LOG_LEVEL" = "debug" ]; then
    log "Current iptables rules:"
    iptables -t nat -L -n -v
    iptables -t filter -L -n -v
fi

# Keep container running
if [ "$1" = "start" ]; then
    log "NAT simulator ready. Press Ctrl+C to stop."
    
    # Monitor conntrack entries if in debug mode
    if [ "$LOG_LEVEL" = "debug" ]; then
        while true; do
            sleep 10
            echo "Active connections:"
            conntrack -L 2>/dev/null | head -20
        done
    else
        # Just keep the container alive
        tail -f /dev/null
    fi
fi

exec "$@"