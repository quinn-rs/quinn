#!/bin/bash
# Full Cone NAT Configuration
# Once an internal address (iAddr:iPort) is mapped to external (eAddr:ePort),
# any external host can send packets to iAddr:iPort by sending to eAddr:ePort

set -e

# Enable connection tracking
modprobe nf_conntrack

# Basic SNAT for outgoing connections
iptables -t nat -A POSTROUTING -o $EXTERNAL_IFACE -j MASQUERADE

# Allow all forwarding from internal network
iptables -A FORWARD -i $INTERNAL_IFACE -o $EXTERNAL_IFACE -j ACCEPT

# Full Cone behavior: Accept all incoming packets to mapped ports
# This is the key difference - we accept from any source
iptables -A FORWARD -i $EXTERNAL_IFACE -o $INTERNAL_IFACE -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i $EXTERNAL_IFACE -o $INTERNAL_IFACE -m conntrack --ctstate DNAT -j ACCEPT

# Log new mappings if in debug mode
if [ "$LOG_LEVEL" = "debug" ]; then
    iptables -t nat -A POSTROUTING -o $EXTERNAL_IFACE -j LOG --log-prefix "NAT-MAP: " --log-level 4
fi

echo "Full Cone NAT configured successfully"