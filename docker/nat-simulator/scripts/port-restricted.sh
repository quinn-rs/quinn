#!/bin/bash
# Port Restricted Cone NAT Configuration
# External host can send packets back only if the internal host
# has sent packets to that specific IP:port combination

set -e

# Enable connection tracking
modprobe nf_conntrack

# Basic SNAT for outgoing connections
iptables -t nat -A POSTROUTING -o $EXTERNAL_IFACE -j MASQUERADE

# Allow forwarding from internal network
iptables -A FORWARD -i $INTERNAL_IFACE -o $EXTERNAL_IFACE -j ACCEPT

# Port Restricted behavior: Strict IP:port matching for return traffic
# Only established connections with exact port matches are allowed
iptables -A FORWARD -i $EXTERNAL_IFACE -o $INTERNAL_IFACE -m state --state ESTABLISHED -j ACCEPT

# Create custom chain for port-restricted behavior
iptables -t filter -N PORT_RESTRICTED 2>/dev/null || true
iptables -t filter -F PORT_RESTRICTED

# Enforce port-level restriction
iptables -A FORWARD -i $EXTERNAL_IFACE -o $INTERNAL_IFACE -m state --state NEW,RELATED -j PORT_RESTRICTED
iptables -A PORT_RESTRICTED -m conntrack --ctstate RELATED -j ACCEPT
iptables -A PORT_RESTRICTED -j DROP

# Configure stricter connection tracking
echo "1" > /proc/sys/net/netfilter/nf_conntrack_tcp_strict

# Log dropped packets in debug mode
if [ "$LOG_LEVEL" = "debug" ]; then
    iptables -A PORT_RESTRICTED -j LOG --log-prefix "PORT-RESTRICTED-DROP: " --log-level 4 -m limit --limit 5/min
fi

echo "Port Restricted Cone NAT configured successfully"