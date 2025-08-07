# Contributing to ant-quic

## ⚠️ IMPORTANT: Repository Independence

**ant-quic is NOT a fork of Quinn - it's an independent project!**

- ❌ **DO NOT** create PRs to quinn-rs/quinn
- ❌ **DO NOT** reference "upstream" Quinn repository
- ✅ **DO** create PRs to github.com/dirvine/ant-quic
- ✅ **DO** treat this as a standalone project

Although GitHub may show this as a fork (legacy reason), ant-quic has diverged completely and is maintained independently.

## How to Contribute

1. Fork the repository from https://github.com/dirvine/ant-quic
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes and ensure tests pass: `cargo test`
4. Run formatting and linting: `cargo fmt && cargo clippy`
5. Push to YOUR fork: `git push origin feature/your-feature`
6. Create a PR to `dirvine/ant-quic:master` (NOT to quinn-rs/quinn!)

## Development Setup

```bash
# Clone YOUR fork
git clone https://github.com/YOUR-USERNAME/ant-quic.git
cd ant-quic

# Set up Git hooks to prevent accidental upstream pushes
git config core.hooksPath .githooks

# Build and test
cargo build --release
cargo test
```

## Code Standards

- All tests must pass
- No clippy warnings
- Code must be formatted with rustfmt
- Document public APIs
- Add tests for new features

## Questions?

Open an issue at https://github.com/dirvine/ant-quic/issues