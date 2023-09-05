#!/usr/bin/env bash

SERVICE=client
PERF_CLIENT_ARGS="--keylog --duration 5 172.42.0.2:4433"

LATENCY=0
CAPTURE=0
OPEN=0

function usage() {
	echo "usage: $0 [-hco] [-l number]"
	echo "  -h      display help"
	echo "  -c      enable packet capture"
	echo "  -o      open packet capture"
	echo "  -l number   specify simulated latency in ms (default: ${LATENCY}ms)"
	exit 1
}

while getopts "hcl:" opt; do
	case $opt in
		c) CAPTURE=1;;
		o) OPEN=1;;
		l) LATENCY=$OPTARG;;
		h) usage;;
		*) usage;;
	esac
done

mkdir -p ./work

echo "Launching docker ${SERVICE}"
docker compose up -d --force-recreate ${SERVICE}
if [ ${LATENCY} -ne 0 ]; then
	echo "Enforcing a latency of ${LATENCY}ms"
	docker compose exec -it ${SERVICE} tc qdisc add dev eth0 root netem delay ${LATENCY}ms
fi

# FIXME disable GSO due to this issue
# https://gitlab.com/wireshark/wireshark/-/issues/19109
docker compose exec -it ${SERVICE} ethtool -K eth0 tx-udp-segmentation off

if [ ${CAPTURE} -eq 1 ]; then
	echo "Starting capture within docker"
	docker compose exec -d ${SERVICE} tcpdump -ni eth0 -s0 -w /root/.local/share/quinn/${SERVICE}.pcap udp and port 4433
fi

echo "Launching quinn perf client"
docker compose exec -it ${SERVICE} /root/perf_client ${PERF_CLIENT_ARGS}

if [ ${CAPTURE} -eq 1 ]; then
	echo "Stopping capture within docker"
	docker compose exec -it ${SERVICE} killall -STOP tcpdump
fi

if [ ${LATENCY} -ne 0 ]; then
	echo "Dumping QOS stats"
	docker compose exec -it ${SERVICE} tc -s qdisc ls dev eth0
fi

if [ ${CAPTURE} -eq 1 ] && [ ${OPEN} -eq 1 ]; then
	wireshark -o tls.keylog_file:./work/${SERVICE}.key ./work/${SERVICE}.pcap
fi
