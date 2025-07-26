<!-- 
This is a template for GitHub releases. 
It will be automatically populated by the release workflow.
-->

## ant-quic {{ VERSION }}

{{ BREAKING_CHANGES_WARNING }}

### 🎉 Highlights

<!-- Add 2-3 key highlights of this release -->
- 
- 
- 

### 📦 Installation

#### From crates.io
```bash
cargo install ant-quic --version {{ VERSION_NUMBER }}
```

#### Pre-built binaries
Download the appropriate binary for your platform from the assets below.

**Linux/macOS:**
```bash
# Download and extract (replace PLATFORM with your platform)
curl -L https://github.com/dirvine/ant-quic/releases/download/{{ VERSION }}/ant-quic-PLATFORM.tar.gz | tar xz

# Make executable and run
chmod +x ant-quic
./ant-quic --help
```

**Windows:**
```powershell
# Download and extract
Invoke-WebRequest -Uri "https://github.com/dirvine/ant-quic/releases/download/{{ VERSION }}/ant-quic-x86_64-windows.zip" -OutFile "ant-quic.zip"
Expand-Archive ant-quic.zip

# Run
.\ant-quic\ant-quic.exe --help
```

#### Docker
```bash
# Docker Hub
docker pull maidsafe/ant-quic:{{ VERSION_NUMBER }}

# GitHub Container Registry
docker pull ghcr.io/dirvine/ant-quic:{{ VERSION_NUMBER }}

# Run
docker run --rm -it maidsafe/ant-quic:{{ VERSION_NUMBER }} --help
```

### 📋 What's Changed

{{ CHANGELOG }}

### 🔒 Checksums

SHA256 checksums for all release artifacts are available in `checksums.txt`.

To verify a download:
```bash
# Linux/macOS
sha256sum -c checksums.txt

# Windows
certutil -hashfile ant-quic-x86_64-windows.zip SHA256
```

### 📊 Compatibility

- **Rust Version**: 1.74.1+
- **Platforms**: Linux, macOS, Windows (x86_64, ARM64)
- **QUIC Version**: RFC 9000 compliant

### 🙏 Contributors

Thank you to all contributors who made this release possible!

{{ CONTRIBUTORS }}

### 📚 Documentation

- [API Documentation](https://docs.rs/ant-quic/{{ VERSION_NUMBER }})
- [User Guide](https://github.com/dirvine/ant-quic/blob/{{ VERSION }}/README.md)
- [Examples](https://github.com/dirvine/ant-quic/tree/{{ VERSION }}/examples)

### 🐛 Reporting Issues

If you encounter any issues, please [open a GitHub issue](https://github.com/dirvine/ant-quic/issues/new).

---

**Full Changelog**: https://github.com/dirvine/ant-quic/compare/{{ PREVIOUS_TAG }}...{{ VERSION }}