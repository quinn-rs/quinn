#!/bin/bash
# Symmetric NAT Configuration  
# Most restrictive - different external endpoints get different port mappings

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Configure Symmetric NAT with random port allocation
iptables -t nat -A POSTROUTING -o $WAN_INTERFACE -j MASQUERADE --random-fully

# Only allow outbound initiated connections
iptables -A FORWARD -i $LAN_INTERFACE -o $WAN_INTERFACE -j ACCEPT
iptables -A FORWARD -i $WAN_INTERFACE -o $LAN_INTERFACE -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i $WAN_INTERFACE -o $LAN_INTERFACE -m state --state NEW -j DROP

# Strict connection tracking
sysctl -w net.netfilter.nf_conntrack_udp_timeout=30
sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=60

# Disable connection tracking helpers
echo 0 > /proc/sys/net/netfilter/nf_conntrack_helper