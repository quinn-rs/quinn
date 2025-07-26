#!/bin/bash
# Symmetric NAT Configuration
# Each request from the same internal IP:port to different destinations
# gets mapped to different external ports

set -e

# Enable connection tracking
modprobe nf_conntrack

# Symmetric NAT uses different external ports for different destinations
# We achieve this using SNAT with random port allocation
iptables -t nat -A POSTROUTING -o $EXTERNAL_IFACE -j SNAT \
    --to-source $(ip addr show $EXTERNAL_IFACE | grep 'inet ' | awk '{print $2}' | cut -d/ -f1) \
    --random-fully

# Allow forwarding from internal network
iptables -A FORWARD -i $INTERNAL_IFACE -o $EXTERNAL_IFACE -j ACCEPT

# Symmetric NAT behavior: Very restrictive
# Only allow return traffic that matches exact connection tuple
iptables -A FORWARD -i $EXTERNAL_IFACE -o $INTERNAL_IFACE -m state --state ESTABLISHED -j ACCEPT

# Drop everything else
iptables -A FORWARD -i $EXTERNAL_IFACE -o $INTERNAL_IFACE -j DROP

# Configure aggressive connection tracking timeouts
echo "30" > /proc/sys/net/netfilter/nf_conntrack_udp_timeout
echo "60" > /proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream

# Disable connection tracking helpers (more symmetric behavior)
for helper in /proc/sys/net/netfilter/nf_conntrack_helper_*; do
    echo 0 > $helper 2>/dev/null || true
done

# Log mapping changes in debug mode
if [ "$LOG_LEVEL" = "debug" ]; then
    iptables -t nat -A POSTROUTING -o $EXTERNAL_IFACE -j LOG --log-prefix "SYMMETRIC-NAT: " --log-level 4
    iptables -A FORWARD -i $EXTERNAL_IFACE -o $INTERNAL_IFACE -m state --state NEW -j LOG --log-prefix "SYMMETRIC-DROP: " --log-level 4
fi

echo "Symmetric NAT configured successfully"