#!/bin/sh
# Setup symmetric NAT using iptables

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Set up symmetric NAT (most restrictive)
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE --random

# Log NAT setup
echo "Symmetric NAT configured"
iptables -t nat -L -v -n

# Run ant-quic with provided arguments
exec /usr/local/bin/ant-quic "$@"