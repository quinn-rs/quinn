#!/bin/bash
# Check HTTP/3 support for various endpoints

echo "=== HTTP/3 Support Checker ==="
echo "Checking QUIC/HTTP/3 support for public endpoints..."
echo

# Function to check HTTP/3 support using curl
check_http3() {
    local url=$1
    local name=$2
    
    echo -n "Checking $name ($url)... "
    
    # Check if curl supports HTTP/3
    if ! curl --version | grep -q HTTP3; then
        echo "ERROR: curl doesn't support HTTP/3. Install curl with HTTP/3 support."
        return
    fi
    
    # Try HTTP/3 connection
    if curl --http3 -s -o /dev/null -w "%{http_version}\n" --connect-timeout 5 "$url" 2>/dev/null | grep -q "3"; then
        echo "✅ HTTP/3 supported"
    else
        # Fallback check for alt-svc header
        if curl -sI "$url" | grep -i "alt-svc" | grep -q "h3"; then
            echo "✅ HTTP/3 advertised (alt-svc)"
        else
            echo "❌ No HTTP/3 support detected"
        fi
    fi
}

# Test major endpoints
check_http3 "https://www.google.com" "Google"
check_http3 "https://cloudflare.com" "Cloudflare"
check_http3 "https://facebook.com" "Facebook"
check_http3 "https://www.litespeedtech.com" "LiteSpeed"
check_http3 "https://quic.nginx.org" "NGINX"
check_http3 "https://cloudflare-quic.com" "Cloudflare QUIC Test"
check_http3 "https://quic.rocks:4433" "Google QUIC Test"

echo
echo "=== Using ngtcp2 client (if available) ==="

# Check with ngtcp2 client if available
if command -v ngtcp2 &> /dev/null; then
    echo "Testing with ngtcp2 client..."
    ngtcp2 https://cloudflare-quic.com 2>&1 | head -5
else
    echo "ngtcp2 client not found. Install from: https://github.com/ngtcp2/ngtcp2"
fi

echo
echo "=== Chrome QUIC Status ==="
echo "To check QUIC sessions in Chrome, visit: chrome://net-internals/#quic"
echo
echo "=== Testing Complete ==="