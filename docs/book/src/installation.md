# Installation

## Requirements

### Minimum Rust Version

ant-quic requires Rust 1.85.0 or later.

### Platform Requirements

| Platform | Requirements |
|----------|-------------|
| Linux | glibc 2.17+ |
| Windows | Windows 10+ |
| macOS | macOS 10.13+ |

## Installing from crates.io

Add ant-quic to your project:

```bash
cargo add ant-quic
```

Or manually add to `Cargo.toml`:

```toml
[dependencies]
ant-quic = "0.4"
```

## Feature Flags

ant-quic supports various feature flags:

- `rustls-ring` (default): Use ring for cryptography
- `rustls-aws-lc-rs`: Use AWS-LC for cryptography
- `trace`: Enable tracing functionality
- `test-utils`: Testing utilities

Example with specific features:

```toml
[dependencies]
ant-quic = { version = "0.4", features = ["rustls-aws-lc-rs", "trace"] }
```

## Building from Source

```bash
git clone https://github.com/dirvine/ant-quic
cd ant-quic
cargo build --release
```

## Running the Binary

ant-quic includes a binary for testing:

```bash
cargo run --bin ant-quic -- --help
```
