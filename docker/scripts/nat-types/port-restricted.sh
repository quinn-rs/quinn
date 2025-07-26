#!/bin/bash
# Port Restricted NAT Configuration
# External host must use same port that received packets

# Enable IP forwarding  
echo 1 > /proc/sys/net/ipv4/ip_forward

# Basic NAT setup
iptables -t nat -A POSTROUTING -o $WAN_INTERFACE -j MASQUERADE
iptables -A FORWARD -i $LAN_INTERFACE -o $WAN_INTERFACE -j ACCEPT

# Port restriction rules - track source ports
iptables -N PORT_RESTRICT 2>/dev/null || true
iptables -F PORT_RESTRICT

# Allow established connections
iptables -A PORT_RESTRICT -m state --state ESTABLISHED,RELATED -j ACCEPT

# For new connections, check if source port matches
iptables -A PORT_RESTRICT -m state --state NEW -j LOG --log-prefix "[PORT-RESTRICT] "
iptables -A PORT_RESTRICT -m state --state NEW -j DROP

# Apply port restriction to incoming traffic
iptables -A FORWARD -i $WAN_INTERFACE -o $LAN_INTERFACE -j PORT_RESTRICT

# Connection tracking parameters
sysctl -w net.netfilter.nf_conntrack_udp_timeout=60
sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=180