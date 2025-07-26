#!/bin/bash
# Restricted Cone NAT Configuration
# Once an internal address is mapped to external, an external host
# can send packets back only if the internal host has sent packets to it

set -e

# Enable connection tracking
modprobe nf_conntrack

# Basic SNAT for outgoing connections
iptables -t nat -A POSTROUTING -o $EXTERNAL_IFACE -j MASQUERADE

# Allow forwarding from internal network
iptables -A FORWARD -i $INTERNAL_IFACE -o $EXTERNAL_IFACE -j ACCEPT

# Restricted Cone behavior: Only allow return traffic from contacted hosts
# We use connection tracking to enforce IP-level restriction
iptables -A FORWARD -i $EXTERNAL_IFACE -o $INTERNAL_IFACE -m state --state ESTABLISHED,RELATED -j ACCEPT

# Create custom chain for restricted cone behavior
iptables -t filter -N RESTRICTED_CONE 2>/dev/null || true
iptables -t filter -F RESTRICTED_CONE

# Track outgoing connections and allow return traffic only from contacted IPs
iptables -A FORWARD -i $EXTERNAL_IFACE -o $INTERNAL_IFACE -j RESTRICTED_CONE
iptables -A RESTRICTED_CONE -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A RESTRICTED_CONE -j DROP

# Log dropped packets in debug mode
if [ "$LOG_LEVEL" = "debug" ]; then
    iptables -A RESTRICTED_CONE -j LOG --log-prefix "RESTRICTED-DROP: " --log-level 4 -m limit --limit 5/min
fi

echo "Restricted Cone NAT configured successfully"