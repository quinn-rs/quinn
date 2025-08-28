#!/bin/bash
# NAT Gateway Entry Point Script
# Configures various NAT types for testing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[NAT-GATEWAY]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Validate environment variables
NAT_TYPE=${NAT_TYPE:-full_cone}
WAN_INTERFACE=${WAN_INTERFACE:-eth0}
LAN_INTERFACE=${LAN_INTERFACE:-eth1}
LOG_LEVEL=${LOG_LEVEL:-info}

log "Starting NAT Gateway with type: $NAT_TYPE"
log "WAN Interface: $WAN_INTERFACE, LAN Interface: $LAN_INTERFACE"
# Normalize NAT type to underscore form for case matching
NAT_TYPE_NORM=${NAT_TYPE//-/_}

# Enable kernel parameters
sysctl -w net.ipv4.ip_forward=1 || true
sysctl -w net.ipv4.conf.all.forwarding=1 || true
sysctl -w net.ipv6.conf.all.forwarding=1 || true

# Disable reverse path filtering for NAT traversal testing
sysctl -w net.ipv4.conf.all.rp_filter=0 || true
sysctl -w net.ipv4.conf.default.rp_filter=0 || true
sysctl -w net.ipv4.conf.$WAN_INTERFACE.rp_filter=0 || true
sysctl -w net.ipv4.conf.$LAN_INTERFACE.rp_filter=0 || true

# Set up routing between networks
# Get IP addresses of interfaces
WAN_IP=$(ip -4 addr show $WAN_INTERFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
LAN_IP=$(ip -4 addr show $LAN_INTERFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

if [ -n "$WAN_IP" ] && [ -n "$LAN_IP" ]; then
    log "Setting up routing: WAN=$WAN_IP ($WAN_INTERFACE), LAN=$LAN_IP ($LAN_INTERFACE)"

    # Add routes for internet network access
    # Route to bootstrap and other internet hosts
    ip route add 203.0.113.0/24 dev $WAN_INTERFACE 2>/dev/null || true

    # Enable proxy ARP for better connectivity
    sysctl -w net.ipv4.conf.$WAN_INTERFACE.proxy_arp=1 || true
    sysctl -w net.ipv4.conf.$LAN_INTERFACE.proxy_arp=1 || true

    # Add iptables rules to allow forwarding from LAN to WAN
    iptables -A FORWARD -i $LAN_INTERFACE -o $WAN_INTERFACE -j ACCEPT
    iptables -A FORWARD -i $WAN_INTERFACE -o $LAN_INTERFACE -m state --state ESTABLISHED,RELATED -j ACCEPT

    # NAT from LAN to WAN
    iptables -t nat -A POSTROUTING -o $WAN_INTERFACE -j MASQUERADE

    log "Routing setup complete"
else
    warn "Could not determine IP addresses for routing setup"
fi

# Load required kernel modules
modprobe nf_conntrack 2>/dev/null || true
modprobe nf_conntrack_ipv4 2>/dev/null || true
modprobe nf_nat 2>/dev/null || true
modprobe iptable_nat 2>/dev/null || true

# Set connection tracking parameters for better NAT traversal
sysctl -w net.netfilter.nf_conntrack_max=1000000 || true
sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=7440 || true
sysctl -w net.netfilter.nf_conntrack_udp_timeout=60 || true
sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=180 || true

# Clear existing iptables rules
iptables -F
iptables -t nat -F
iptables -t mangle -F
iptables -X

# Default policies
iptables -P INPUT ACCEPT
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Configure NAT based on type
case "$NAT_TYPE_NORM" in
    full_cone)
        log "Configuring Full Cone NAT (Endpoint Independent)"
        
        # Full cone NAT - most permissive
        # Any external host can send packets to the internal host once a mapping exists
        iptables -t nat -A POSTROUTING -o $WAN_INTERFACE -j MASQUERADE
        iptables -A FORWARD -i $LAN_INTERFACE -o $WAN_INTERFACE -j ACCEPT
        iptables -A FORWARD -i $WAN_INTERFACE -o $LAN_INTERFACE -j ACCEPT
        
        # Enable connection tracking helpers if available
        if [ -w /proc/sys/net/netfilter/nf_conntrack_helper ]; then
            echo 1 > /proc/sys/net/netfilter/nf_conntrack_helper || true
        fi
        ;;
        
    symmetric)
        log "Configuring Symmetric NAT (Endpoint Dependent)"
        
        # Symmetric NAT - most restrictive
        # Different external endpoints see different external ports
        iptables -t nat -A POSTROUTING -o $WAN_INTERFACE -j MASQUERADE --random
        iptables -A FORWARD -i $LAN_INTERFACE -o $WAN_INTERFACE -j ACCEPT
        iptables -A FORWARD -i $WAN_INTERFACE -o $LAN_INTERFACE -m state --state ESTABLISHED,RELATED -j ACCEPT
        
        # Restrict new incoming connections
        iptables -A FORWARD -i $WAN_INTERFACE -o $LAN_INTERFACE -m state --state NEW -j DROP
        ;;
        
    port_restricted|port-restricted)
        log "Configuring Port Restricted NAT"
        
        # Port restricted NAT - middle ground
        # External host must send from the same port that received packets
        iptables -t nat -A POSTROUTING -o $WAN_INTERFACE -j MASQUERADE
        iptables -A FORWARD -i $LAN_INTERFACE -o $WAN_INTERFACE -j ACCEPT
        
        # Create a custom chain for port restriction
        iptables -N PORT_RESTRICT
        iptables -A FORWARD -i $WAN_INTERFACE -o $LAN_INTERFACE -j PORT_RESTRICT
        iptables -A PORT_RESTRICT -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A PORT_RESTRICT -m state --state NEW -m recent --name portscan --set -j DROP
        ;;
        
    cgnat)
        log "Configuring Carrier Grade NAT (RFC 6598)"
        
        # CGNAT uses the 100.64.0.0/10 address space
        CGNAT_POOL_START=${CGNAT_POOL_START:-100.64.0.1}
        CGNAT_POOL_END=${CGNAT_POOL_END:-100.64.255.254}
        
        # Configure CGNAT with limited port ranges per subscriber
        iptables -t nat -A POSTROUTING -o $WAN_INTERFACE -j SNAT --to-source $CGNAT_POOL_START-$CGNAT_POOL_END
        iptables -A FORWARD -i $LAN_INTERFACE -o $WAN_INTERFACE -j ACCEPT
        iptables -A FORWARD -i $WAN_INTERFACE -o $LAN_INTERFACE -m state --state ESTABLISHED,RELATED -j ACCEPT
        
        # Limit port allocations per internal IP (simulate CGNAT port exhaustion)
        iptables -t nat -A POSTROUTING -o $WAN_INTERFACE -m statistic --mode nth --every 10 --packet 0 -j MASQUERADE
        ;;
        
    *)
        error "Unknown NAT type: $NAT_TYPE"
        ;;
esac

# Add logging rules based on log level
if [ "$LOG_LEVEL" = "debug" ] || [ "$LOG_LEVEL" = "trace" ]; then
    log "Enabling packet logging"
    iptables -A FORWARD -j LOG --log-prefix "[NAT-FWD] " --log-level 7
    iptables -t nat -A POSTROUTING -j LOG --log-prefix "[NAT-POST] " --log-level 7
fi

# Show final configuration
log "NAT configuration complete. Current rules:"
iptables -L -n -v
echo "---"
iptables -t nat -L -n -v

# Monitor connection tracking
log "Starting connection tracking monitor"

# Keep the container running and monitor connections
while true; do
    if [ "$LOG_LEVEL" = "debug" ] || [ "$LOG_LEVEL" = "trace" ]; then
        conntrack -L -p udp 2>/dev/null | grep -E "sport=(9000|[0-9]{5})" || true
    fi
    sleep 5
done