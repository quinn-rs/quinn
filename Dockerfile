# Multi-stage build for ant-quic
# Stage 1: Build
FROM rust:1.85-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Copy source code
COPY src ./src
COPY benches ./benches
COPY tests ./tests
COPY examples ./examples
# Note: docs/rfcs/ contains specifications but is not needed for the build

# Build release binary
RUN cargo build --release --bin ant-quic

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/ant-quic /usr/local/bin/ant-quic

# Expose QUIC UDP port
EXPOSE 9000/udp

# Default command
ENTRYPOINT ["ant-quic"]
CMD ["--help"]
