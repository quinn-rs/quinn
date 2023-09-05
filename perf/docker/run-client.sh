#!/usr/bin/env -S bash -eu

SERVICE=client

# quinn-perf client arguments
QUINN_PERF_SERVER="172.42.0.2:4433"
QUINN_PERF_DEFAULT_ARGS="--keylog"

LATENCY=0
LOSS=0
GSO=0
CAPTURE=0
OPEN=0
TOKIO_CONSOLE=0

function usage() {
	echo "usage: $0 [-cghot] [-l number] [-L number]"
	echo " -c      enable packet capture"
	echo " -g      enable GSO (default: disabled)"
	echo " -h      display help"
	echo " -l number   specify simulated latency in ms (default: ${LATENCY}ms)"
	echo " -L number   specify simulated packet loss in percentage (default: ${LOSS}%)"
	echo " -o      open packet capture"
	echo " -t      attach to tokio console"
	echo " -- args     can be used to add extra arguments to quinn-perf"
	exit 1
}

while getopts "cghl:L:ot" opt; do
	case $opt in
		c) CAPTURE=1;;
		g) GSO=1;;
		l) LATENCY=$OPTARG;;
		L) LOSS=$OPTARG;;
		o) OPEN=1;;
		t) TOKIO_CONSOLE=1;;
		h) usage;;
		*) usage;;
	esac
done

# extract optional additional arguments for quinn-perf
shift "$((OPTIND - 1))"
QUINN_PERF_EXTRA_ARGS="$*"

if [ ${TOKIO_CONSOLE} -eq 1 ]; then
	tokio-console http://127.0.0.1:6668
	exit 0
fi

mkdir -p ./work

echo "Launching docker ${SERVICE}"
docker compose up -d --force-recreate ${SERVICE}
if [ "${LATENCY}" -ne "0" ] || [ "${LOSS}" -ne "0" ]; then
	echo "Enforcing a latency of ${LATENCY}ms and a packet loss of ${LOSS}%"
	docker compose exec -it ${SERVICE} tc qdisc add dev eth0 root netem delay "${LATENCY}ms" loss "${LOSS}%"
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

echo "Launching quinn-perf client with arguments: ${QUINN_PERF_DEFAULT_ARGS} ${QUINN_PERF_EXTRA_ARGS} ${QUINN_PERF_SERVER}"
docker compose exec -it ${SERVICE} /root/quinn-perf client ${QUINN_PERF_DEFAULT_ARGS} ${QUINN_PERF_EXTRA_ARGS} ${QUINN_PERF_SERVER}

if [ ${CAPTURE} -eq 1 ]; then
	echo "Stopping capture within docker"
	docker compose exec -it ${SERVICE} killall -STOP tcpdump
fi

if [ "${LATENCY}" -ne "0" ] || [ "${LOSS}" -ne "0" ]; then
	echo "Dumping QOS stats"
	docker compose exec -it ${SERVICE} tc -s qdisc ls dev eth0
fi

if [ ${CAPTURE} -eq 1 ] && [ ${OPEN} -eq 1 ]; then
	wireshark -o tls.keylog_file:./work/${SERVICE}.key ./work/${SERVICE}.pcap
fi
