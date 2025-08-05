# Symmetric NAT simulation for ant-quic
FROM ant-quic-base:latest

# Install iptables for NAT simulation
RUN apk add --no-cache iptables

# Set up NAT rules (symmetric NAT)
COPY docker/setup-symmetric-nat.sh /setup-nat.sh
RUN chmod +x /setup-nat.sh

# Entry point that sets up NAT and runs ant-quic
ENTRYPOINT ["/setup-nat.sh"]