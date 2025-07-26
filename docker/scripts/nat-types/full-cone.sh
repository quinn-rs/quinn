#!/bin/bash
# Full Cone NAT Configuration
# Most permissive NAT type - allows any external host to send to mapped port

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Configure Full Cone NAT behavior
iptables -t nat -A POSTROUTING -o $WAN_INTERFACE -j MASQUERADE
iptables -A FORWARD -i $LAN_INTERFACE -o $WAN_INTERFACE -j ACCEPT
iptables -A FORWARD -i $WAN_INTERFACE -o $LAN_INTERFACE -j ACCEPT

# Set permissive connection tracking timeouts
sysctl -w net.netfilter.nf_conntrack_udp_timeout=30
sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=120

# Allow incoming packets to established mappings from any source
iptables -t nat -A PREROUTING -i $WAN_INTERFACE -j ACCEPT