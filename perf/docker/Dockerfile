# https://hub.docker.com/_/debian
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y procps iputils-ping iproute2 ethtool tcpdump

WORKDIR /root

RUN mkdir -p .local/share/quinn

COPY ./entrypoint.sh .

COPY ./target/quinn-perf .

ENTRYPOINT [ "/root/entrypoint.sh" ]
