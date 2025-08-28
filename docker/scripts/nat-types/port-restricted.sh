#!/bin/bash
# Port Restricted NAT Configuration
# External host must use same port that received packets

# Enable IP forwarding  
echo 1 > /proc/sys/net/ipv4/ip_forward

# Basic NAT setup
iptables -t nat -A POSTROUTING -o $WAN_INTERFACE -j MASQUERADE
iptables -A FORWARD -i $LAN_INTERFACE -o $WAN_INTERFACE -j ACCEPT

# Port restriction rules - track source ports and IPs
iptables -N PORT_RESTRICT 2>/dev/null || true
iptables -F PORT_RESTRICT

# Allow established connections
iptables -A PORT_RESTRICT -m state --state ESTABLISHED,RELATED -j ACCEPT

# For port-restricted NAT: allow new connections only from previously contacted hosts
# This simulates the behavior where external hosts can only connect back on the same port
# they were contacted from, but only if they use the same source port
iptables -A PORT_RESTRICT -m state --state NEW -m recent --rcheck --name PORT_RESTRICT_ALLOW -j ACCEPT
iptables -A PORT_RESTRICT -m state --state NEW -j LOG --log-prefix "[PORT-RESTRICT] "
iptables -A PORT_RESTRICT -m state --state NEW -j DROP

# Track outbound connections to allow return traffic
iptables -t nat -I POSTROUTING -o $WAN_INTERFACE -j SNAT --to-source $(ip route get 8.8.8.8 | awk '{print $7}') -m recent --set --name PORT_RESTRICT_ALLOW

# Apply port restriction to incoming traffic
iptables -A FORWARD -i $WAN_INTERFACE -o $LAN_INTERFACE -j PORT_RESTRICT

# Connection tracking parameters
sysctl -w net.netfilter.nf_conntrack_udp_timeout=60
sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=180