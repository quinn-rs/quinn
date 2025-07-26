#!/bin/bash
# Carrier Grade NAT (CGNAT) Configuration
# Simulates ISP-level NAT with limited port ranges

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# CGNAT address pool (RFC 6598)
CGNAT_POOL_START=${CGNAT_POOL_START:-100.64.0.1}
CGNAT_POOL_END=${CGNAT_POOL_END:-100.64.0.254}

# Configure CGNAT with port range limitations
# Typical CGNAT allocates 1000-4000 ports per subscriber
iptables -t nat -A POSTROUTING -o $WAN_INTERFACE -p tcp -j SNAT --to-source $CGNAT_POOL_START-$CGNAT_POOL_END:1024-4999
iptables -t nat -A POSTROUTING -o $WAN_INTERFACE -p udp -j SNAT --to-source $CGNAT_POOL_START-$CGNAT_POOL_END:1024-4999

# Forward established connections
iptables -A FORWARD -i $LAN_INTERFACE -o $WAN_INTERFACE -j ACCEPT  
iptables -A FORWARD -i $WAN_INTERFACE -o $LAN_INTERFACE -m state --state ESTABLISHED,RELATED -j ACCEPT

# Simulate port exhaustion by limiting connections per IP
iptables -A FORWARD -i $LAN_INTERFACE -p udp -m limit --limit 100/minute --limit-burst 200 -j ACCEPT
iptables -A FORWARD -i $LAN_INTERFACE -p udp -j DROP

# Aggressive timeouts to simulate port recycling
sysctl -w net.netfilter.nf_conntrack_udp_timeout=30
sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=60

# Log CGNAT events
iptables -t nat -A POSTROUTING -j LOG --log-prefix "[CGNAT] " --log-level 6