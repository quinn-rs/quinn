# Base Dockerfile for ant-quic testing
FROM rust:1.85.1-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev openssl-dev perl make

# Set up working directory
WORKDIR /app

# Copy source code
COPY . .

# Build the project
RUN cargo build --release --bin ant-quic

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache libgcc openssl ca-certificates

# Copy the binary
COPY --from=builder /app/target/release/ant-quic /usr/local/bin/

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/ant-quic"]