#!/usr/bin/env -S bash -eu

SERVICE=client
PERF_CLIENT_ARGS="--keylog --duration 5 172.42.0.2:4433"

LATENCY=0
GSO=0
CAPTURE=0
OPEN=0

function usage() {
	echo "usage: $0 [-cgho] [-l number]"
	echo "  -c      enable packet capture"
	echo "  -g      enable GSO (default: disabled)"
	echo "  -h      display help"
	echo "  -l number   specify simulated latency in ms (default: ${LATENCY}ms)"
	echo "  -o      open packet capture"
	exit 1
}

while getopts "cghl:o" opt; do
	case $opt in
		c) CAPTURE=1;;
		g) GSO=1;;
		l) LATENCY=$OPTARG;;
		o) OPEN=1;;
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

if [ ${GSO} -eq 0 ]; then
	# FIXME disable GSO due to this issue
	# https://gitlab.com/wireshark/wireshark/-/issues/19109
	docker compose exec -it ${SERVICE} ethtool -K eth0 tx-udp-segmentation off
fi

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
