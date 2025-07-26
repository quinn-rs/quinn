# NAT Simulator for ant-quic testing
FROM alpine:3.19

# Install required packages
RUN apk add --no-cache \
    iptables \
    iproute2 \
    bash \
    tcpdump \
    conntrack-tools \
    iputils \
    curl \
    jq \
    socat

# Create directories
RUN mkdir -p /scripts /configs /logs

# Copy NAT simulation scripts
COPY scripts/*.sh /scripts/
RUN chmod +x /scripts/*.sh

# Copy configuration files
COPY configs/* /configs/

# Enable IP forwarding
RUN echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf && \
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf

# Default environment variables
ENV NAT_TYPE="full-cone" \
    INTERNAL_NET="192.168.100.0/24" \
    EXTERNAL_IFACE="eth0" \
    INTERNAL_IFACE="eth1" \
    LOG_LEVEL="info"

# Entry point script
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["start"]