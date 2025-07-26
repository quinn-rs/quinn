#!/bin/bash
# User data script for initial ant-quic setup on Digital Ocean

set -e

# Update system
apt-get update
apt-get upgrade -y

# Install required packages
apt-get install -y \
    build-essential \
    curl \
    git \
    htop \
    iotop \
    jq \
    net-tools \
    nginx \
    certbot \
    python3-certbot-nginx \
    prometheus-node-exporter \
    ufw \
    vim \
    wget

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
usermod -aG docker ubuntu

# Install Rust (for building ant-quic)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Create ant-quic user
useradd -m -s /bin/bash ant-quic
usermod -aG docker ant-quic

# Setup directories
mkdir -p /opt/ant-quic/{bin,config,logs,data}
mkdir -p /var/log/ant-quic

# Configure firewall
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp          # SSH
ufw allow 80/tcp          # HTTP
ufw allow 443/tcp         # HTTPS
ufw allow 9000:9010/udp   # QUIC
ufw --force enable

# Setup systemd service
cat > /etc/systemd/system/ant-quic.service << 'EOF'
[Unit]
Description=ant-quic QUIC server
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=ant-quic
Group=ant-quic
WorkingDirectory=/opt/ant-quic
ExecStart=/opt/ant-quic/bin/ant-quic \
    --listen 0.0.0.0:9000 \
    --force-coordinator \
    --dashboard \
    --log-level debug \
    --config /opt/ant-quic/config/server.toml
Restart=always
RestartSec=10
StandardOutput=append:/var/log/ant-quic/ant-quic.log
StandardError=append:/var/log/ant-quic/ant-quic-error.log

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/ant-quic/data /var/log/ant-quic

[Install]
WantedBy=multi-user.target
EOF

# Create config file
cat > /opt/ant-quic/config/server.toml << 'EOF'
# ant-quic server configuration

[server]
bind_addr = "0.0.0.0:9000"
role = "bootstrap"
enable_coordinator = true

[nat_traversal]
enable_discovery = true
max_candidates = 100
coordination_timeout_secs = 30

[tls]
cert_path = "/opt/ant-quic/certs/cert.pem"
key_path = "/opt/ant-quic/certs/key.pem"

[logging]
level = "debug"
format = "json"
output = "/var/log/ant-quic/ant-quic.json"

[metrics]
enable = true
bind_addr = "127.0.0.1:9100"
EOF

# Setup Nginx for monitoring dashboard
cat > /etc/nginx/sites-available/ant-quic << 'EOF'
server {
    listen 80;
    server_name _;
    
    location / {
        return 301 https://$host$request_uri;
    }
    
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
}

server {
    listen 443 ssl http2;
    server_name _;
    
    # SSL configuration will be added by certbot
    
    location / {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
    
    location /metrics {
        proxy_pass http://localhost:9100/metrics;
        allow 127.0.0.1;
        deny all;
    }
}
EOF

ln -s /etc/nginx/sites-available/ant-quic /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Setup log rotation
cat > /etc/logrotate.d/ant-quic << 'EOF'
/var/log/ant-quic/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 ant-quic ant-quic
    sharedscripts
    postrotate
        systemctl reload ant-quic || true
    endscript
}
EOF

# Setup monitoring with Prometheus node exporter
cat > /etc/default/prometheus-node-exporter << 'EOF'
ARGS="--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($|/) \
      --collector.netclass.ignored-devices=^(veth.*|docker.*)$ \
      --collector.textfile.directory=/var/lib/prometheus/node-exporter"
EOF

# Create monitoring script
cat > /opt/ant-quic/bin/monitor.sh << 'EOF'
#!/bin/bash
# Monitoring script for ant-quic

while true; do
    # Check if ant-quic is running
    if systemctl is-active --quiet ant-quic; then
        echo "ant_quic_up 1" > /var/lib/prometheus/node-exporter/ant-quic.prom
    else
        echo "ant_quic_up 0" > /var/lib/prometheus/node-exporter/ant-quic.prom
    fi
    
    # Get connection count
    CONNECTIONS=$(ss -u -a -n | grep :9000 | wc -l)
    echo "ant_quic_connections $CONNECTIONS" >> /var/lib/prometheus/node-exporter/ant-quic.prom
    
    sleep 30
done
EOF

chmod +x /opt/ant-quic/bin/monitor.sh

# Setup monitoring service
cat > /etc/systemd/system/ant-quic-monitor.service << 'EOF'
[Unit]
Description=ant-quic monitoring
After=ant-quic.service

[Service]
Type=simple
ExecStart=/opt/ant-quic/bin/monitor.sh
Restart=always
User=ant-quic

[Install]
WantedBy=multi-user.target
EOF

# Create health check endpoint
cat > /opt/ant-quic/bin/health-check.sh << 'EOF'
#!/bin/bash
# Health check for ant-quic

# Check if service is running
systemctl is-active --quiet ant-quic || exit 1

# Check if port is listening
ss -lnu | grep -q :9000 || exit 1

# Check if we can reach the service
timeout 2 nc -u -z localhost 9000 || exit 1

echo "OK"
exit 0
EOF

chmod +x /opt/ant-quic/bin/health-check.sh

# Fix permissions
chown -R ant-quic:ant-quic /opt/ant-quic
chown -R ant-quic:ant-quic /var/log/ant-quic

# Enable services
systemctl daemon-reload
systemctl enable ant-quic
systemctl enable ant-quic-monitor
systemctl enable prometheus-node-exporter
systemctl restart nginx

# Setup auto-updates
cat > /etc/cron.daily/ant-quic-update << 'EOF'
#!/bin/bash
# Auto-update ant-quic binary

GITHUB_REPO="dirvine/ant-quic"
INSTALL_DIR="/opt/ant-quic/bin"
CURRENT_VERSION=$(${INSTALL_DIR}/ant-quic --version 2>/dev/null | awk '{print $2}')

# Check for new release
LATEST_VERSION=$(curl -s https://api.github.com/repos/${GITHUB_REPO}/releases/latest | jq -r .tag_name)

if [ "$CURRENT_VERSION" != "$LATEST_VERSION" ] && [ -n "$LATEST_VERSION" ]; then
    echo "Updating ant-quic from $CURRENT_VERSION to $LATEST_VERSION"
    
    # Download new version
    cd /tmp
    wget -q "https://github.com/${GITHUB_REPO}/releases/download/${LATEST_VERSION}/ant-quic-linux-x86_64.tar.gz"
    tar -xzf ant-quic-linux-x86_64.tar.gz
    
    # Backup current version
    cp ${INSTALL_DIR}/ant-quic ${INSTALL_DIR}/ant-quic.backup
    
    # Install new version
    mv ant-quic ${INSTALL_DIR}/ant-quic
    chown ant-quic:ant-quic ${INSTALL_DIR}/ant-quic
    chmod +x ${INSTALL_DIR}/ant-quic
    
    # Restart service
    systemctl restart ant-quic
    
    # Cleanup
    rm -f /tmp/ant-quic-linux-x86_64.tar.gz
fi
EOF

chmod +x /etc/cron.daily/ant-quic-update

# Final message
echo "ant-quic server setup complete!"
echo "Next steps:"
echo "1. Upload ant-quic binary to /opt/ant-quic/bin/"
echo "2. Generate TLS certificates"
echo "3. Start the service: systemctl start ant-quic"
echo "4. Check status: systemctl status ant-quic"