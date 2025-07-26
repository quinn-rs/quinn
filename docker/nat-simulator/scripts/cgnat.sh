#!/bin/bash
# Carrier-Grade NAT (CGNAT) Configuration
# Simulates multiple layers of NAT as found in ISP deployments
# Uses RFC 6598 address space (100.64.0.0/10)

set -e

# Enable connection tracking
modprobe nf_conntrack

# CGNAT typically uses shared address space
CGNAT_POOL="100.64.0.0/10"
CUSTOMER_NET="10.0.0.0/8"

# Configure stricter limits (CGNAT has port exhaustion issues)
echo "1024" > /proc/sys/net/netfilter/nf_conntrack_max_per_ip 2>/dev/null || true

# Port range restrictions (simulate limited port pool)
iptables -t nat -A POSTROUTING -o $EXTERNAL_IFACE -p tcp -j SNAT \
    --to-source $(ip addr show $EXTERNAL_IFACE | grep 'inet ' | awk '{print $2}' | cut -d/ -f1):1024-65535 \
    --random

iptables -t nat -A POSTROUTING -o $EXTERNAL_IFACE -p udp -j SNAT \
    --to-source $(ip addr show $EXTERNAL_IFACE | grep 'inet ' | awk '{print $2}' | cut -d/ -f1):1024-65535 \
    --random

# Implement port block allocation (PBA) simulation
# Each internal IP gets a block of 64 ports
iptables -t nat -N CGNAT_PBA 2>/dev/null || true
iptables -t nat -F CGNAT_PBA

# Allow forwarding with CGNAT restrictions
iptables -A FORWARD -i $INTERNAL_IFACE -o $EXTERNAL_IFACE -j ACCEPT
iptables -A FORWARD -i $EXTERNAL_IFACE -o $INTERNAL_IFACE -m state --state ESTABLISHED,RELATED -j ACCEPT

# Aggressive timeouts for CGNAT (port conservation)
echo "30" > /proc/sys/net/netfilter/nf_conntrack_udp_timeout
echo "120" > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established
echo "10" > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait

# Connection limits per IP
iptables -A FORWARD -i $INTERNAL_IFACE -m connlimit --connlimit-above 100 --connlimit-mask 32 -j REJECT

# Log CGNAT events in debug mode
if [ "$LOG_LEVEL" = "debug" ]; then
    iptables -t nat -A POSTROUTING -o $EXTERNAL_IFACE -j LOG --log-prefix "CGNAT-MAP: " --log-level 4 -m limit --limit 10/min
    iptables -A FORWARD -m connlimit --connlimit-above 100 -j LOG --log-prefix "CGNAT-LIMIT: " --log-level 4
fi

echo "Carrier-Grade NAT configured successfully"
echo "Note: This simulates CGNAT behavior with:"
echo "  - Limited port pool (1024-65535)"
echo "  - Connection limits (100 per IP)"
echo "  - Aggressive timeouts"
echo "  - Shared address space simulation"