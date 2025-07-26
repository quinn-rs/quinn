# Multi-stage build for ant-quic

# Build stage
FROM rust:1.74-slim AS builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /usr/src/ant-quic

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src
COPY build.rs ./

# Build the application
RUN cargo build --release --bin ant-quic

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash antquic

# Copy binary from builder
COPY --from=builder /usr/src/ant-quic/target/release/ant-quic /usr/local/bin/ant-quic

# Set ownership
RUN chown antquic:antquic /usr/local/bin/ant-quic

# Switch to non-root user
USER antquic

# Expose default QUIC port
EXPOSE 9000/udp

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ant-quic --version || exit 1

# Default command
ENTRYPOINT ["ant-quic"]
CMD ["--help"]