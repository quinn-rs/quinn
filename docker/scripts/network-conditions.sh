#!/bin/bash
# Network conditions simulation script for Docker NAT testing
# This script applies various network conditions to simulate real-world scenarios

set -e

# Function to display usage
usage() {
    echo "Usage: $0 <action> <profile>"
    echo ""
    echo "Actions:"
    echo "  apply    - Apply network profile"
    echo "  reset    - Reset to normal conditions"
    echo ""
    echo "Profiles:"
    echo "  normal       - No network restrictions"
    echo "  satellite    - High latency (500ms)"
    echo "  lossy_wifi   - 5% packet loss"
    echo "  congested    - Limited bandwidth with queue"
    echo "  3g           - 3G mobile network simulation"
    echo "  4g           - 4G LTE network simulation"
    exit 1
}

# Check arguments
if [ $# -lt 1 ]; then
    usage
fi

ACTION=$1
PROFILE=${2:-normal}

# Container names to apply conditions to
CONTAINERS=(
    "ant-quic-client1"
    "ant-quic-client2"
    "ant-quic-client3"
    "ant-quic-client4"
)

# Function to apply tc rules to a container
apply_to_container() {
    local container=$1
    local interface="eth0"
    
    # Check if container is running
    if ! docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        echo "Warning: Container $container not running, skipping..."
        return
    fi
    
    case $PROFILE in
        normal)
            # Reset any existing rules
            docker exec $container tc qdisc del dev $interface root 2>/dev/null || true
            echo "Reset network conditions for $container"
            ;;
            
        satellite)
            # High latency satellite connection (500ms RTT)
            docker exec $container tc qdisc del dev $interface root 2>/dev/null || true
            docker exec $container tc qdisc add dev $interface root netem delay 250ms 50ms distribution normal
            echo "Applied satellite profile (500ms latency) to $container"
            ;;
            
        lossy_wifi)
            # WiFi with 5% packet loss and slight jitter
            docker exec $container tc qdisc del dev $interface root 2>/dev/null || true
            docker exec $container tc qdisc add dev $interface root netem loss 5% delay 20ms 5ms distribution normal
            echo "Applied lossy WiFi profile (5% loss) to $container"
            ;;
            
        congested)
            # Congested network with limited bandwidth
            docker exec $container tc qdisc del dev $interface root 2>/dev/null || true
            # Add HTB for bandwidth control
            docker exec $container tc qdisc add dev $interface root handle 1: htb default 30
            docker exec $container tc class add dev $interface parent 1: classid 1:1 htb rate 1mbit
            docker exec $container tc class add dev $interface parent 1:1 classid 1:30 htb rate 512kbit ceil 1mbit
            # Add netem for latency/jitter on top
            docker exec $container tc qdisc add dev $interface parent 1:30 handle 30: netem delay 50ms 10ms
            echo "Applied congested profile (1Mbps limit) to $container"
            ;;
            
        3g)
            # 3G mobile network simulation
            docker exec $container tc qdisc del dev $interface root 2>/dev/null || true
            # Bandwidth: ~384kbps down, latency: 150ms, loss: 2%
            docker exec $container tc qdisc add dev $interface root handle 1: htb default 30
            docker exec $container tc class add dev $interface parent 1: classid 1:1 htb rate 384kbit
            docker exec $container tc class add dev $interface parent 1:1 classid 1:30 htb rate 384kbit
            docker exec $container tc qdisc add dev $interface parent 1:30 handle 30: netem delay 150ms 50ms loss 2%
            echo "Applied 3G profile to $container"
            ;;
            
        4g)
            # 4G LTE network simulation  
            docker exec $container tc qdisc del dev $interface root 2>/dev/null || true
            # Bandwidth: ~50Mbps down, latency: 50ms, loss: 0.1%
            docker exec $container tc qdisc add dev $interface root handle 1: htb default 30
            docker exec $container tc class add dev $interface parent 1: classid 1:1 htb rate 50mbit
            docker exec $container tc class add dev $interface parent 1:1 classid 1:30 htb rate 50mbit
            docker exec $container tc qdisc add dev $interface parent 1:30 handle 30: netem delay 50ms 10ms loss 0.1%
            echo "Applied 4G LTE profile to $container"
            ;;
            
        *)
            echo "Unknown profile: $PROFILE"
            exit 1
            ;;
    esac
}

# Function to reset all containers
reset_all() {
    echo "Resetting network conditions for all containers..."
    for container in "${CONTAINERS[@]}"; do
        if docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
            docker exec $container tc qdisc del dev eth0 root 2>/dev/null || true
            echo "Reset $container"
        fi
    done
}

# Main logic
case $ACTION in
    apply)
        echo "Applying network profile: $PROFILE"
        for container in "${CONTAINERS[@]}"; do
            apply_to_container $container
        done
        echo "Network conditions applied successfully"
        ;;
        
    reset)
        reset_all
        echo "Network conditions reset successfully"
        ;;
        
    *)
        echo "Unknown action: $ACTION"
        usage
        ;;
esac