# Release Process Documentation

This document describes the release process for ant-quic.

## Overview

ant-quic uses an automated release process that:
- Builds binaries for multiple platforms
- Publishes to crates.io
- Creates GitHub releases with changelog
- Publishes Docker images
- Generates release notes automatically

## Release Types

### Standard Release (vX.Y.Z)
For stable releases following semantic versioning.

### Pre-release (vX.Y.Z-beta.N)
For beta releases and release candidates.

## Release Workflow

### 1. Version Bump

#### Automated Method (Recommended)
```bash
# Trigger version bump workflow from GitHub Actions
# Go to Actions → Version Bump → Run workflow

# Select bump type:
# - patch: 1.0.0 → 1.0.1
# - minor: 1.0.0 → 1.1.0
# - major: 1.0.0 → 2.0.0
```

#### Manual Method
```bash
# Use the bump script
.github/scripts/bump-version.sh patch  # or minor/major

# Or manually:
# 1. Update version in Cargo.toml
# 2. Run: cargo update --workspace
# 3. Commit: git commit -m "chore(release): bump version to vX.Y.Z"
# 4. Tag: git tag -a vX.Y.Z -m "Release vX.Y.Z"
```

### 2. Create Release

Push the tag to trigger automated release:
```bash
git push origin main
git push origin vX.Y.Z
```

The release workflow will:
1. Validate version format
2. Run security checks
3. Build for all platforms
4. Generate changelog
5. Publish to crates.io
6. Create GitHub release
7. Push Docker images

### 3. Monitor Release

1. Check GitHub Actions for the release workflow
2. Verify all jobs complete successfully
3. Check the GitHub release page
4. Verify crates.io publication
5. Test Docker images

## Platform Support

Binaries are built for:
- Linux x86_64 (glibc)
- Linux x86_64 (musl)
- Linux ARM64
- Linux ARMv7
- macOS Intel
- macOS Apple Silicon
- Windows x86_64 (MSVC)
- Windows x86_64 (GNU)

Docker images support:
- linux/amd64
- linux/arm64
- linux/arm/v7

## Changelog Management

### Commit Convention
Use conventional commits for automatic changelog generation:

```
feat: add new feature
fix: fix bug
docs: update documentation
perf: improve performance
refactor: refactor code
test: add tests
chore: update dependencies
```

### Breaking Changes
Mark breaking changes in commit body:
```
feat: change API interface

BREAKING CHANGE: The connect() method now requires a Config parameter
```

### Changelog Generation
The changelog is automatically generated using git-cliff based on:
- Conventional commit messages
- PR references
- Breaking change markers

## Release Checklist

Before releasing:
- [ ] All tests pass
- [ ] No security vulnerabilities
- [ ] Documentation is updated
- [ ] Breaking changes are documented
- [ ] Version bump PR is merged
- [ ] CHANGELOG.md is reviewed

## Publishing Channels

### 1. GitHub Releases
- Binary downloads for all platforms
- Changelog and release notes
- Source code archives

### 2. crates.io
- Rust crate publication
- API documentation on docs.rs

### 3. Docker Hub
- Multi-architecture images
- Latest and version tags

### 4. GitHub Container Registry
- Alternative to Docker Hub
- Same images and tags

## Rollback Process

If issues are found after release:

1. **Delete the release tag** (if not widely distributed):
   ```bash
   git tag -d vX.Y.Z
   git push origin :refs/tags/vX.Y.Z
   ```

2. **Yank from crates.io** (if published):
   ```bash
   cargo yank --version X.Y.Z
   ```

3. **Create patch release**:
   ```bash
   .github/scripts/bump-version.sh patch
   # Fix issues
   git push origin vX.Y.Z+1
   ```

## Security Considerations

- Release workflow requires approval for first-time contributors
- Secrets are stored in GitHub repository settings
- Binary artifacts are signed with checksums
- Docker images are scanned for vulnerabilities

## Troubleshooting

### Build Failures
- Check platform-specific dependencies
- Verify cross-compilation setup
- Review workflow logs

### Publishing Failures
- Ensure CARGO_REGISTRY_TOKEN is set
- Check crates.io API status
- Verify Docker Hub credentials

### Changelog Issues
- Ensure commits follow convention
- Check git-cliff configuration
- Verify tag history

## Manual Release (Emergency)

If automation fails:

1. **Build locally**:
   ```bash
   # For each platform
   cargo build --release --target <TARGET>
   ```

2. **Create release manually**:
   - Go to GitHub Releases
   - Create new release
   - Upload binaries
   - Add changelog

3. **Publish to crates.io**:
   ```bash
   cargo publish
   ```

4. **Push Docker images**:
   ```bash
   docker buildx build --platform linux/amd64,linux/arm64 \
     -t yourusername/ant-quic:X.Y.Z \
     -t yourusername/ant-quic:latest \
     --push .
   ```

## Version Policy

- **Major**: Breaking API changes
- **Minor**: New features, backward compatible
- **Patch**: Bug fixes, performance improvements

Pre-release versions:
- **alpha**: Early development
- **beta**: Feature complete, testing
- **rc**: Release candidate

## Contact

For release issues:
- Create GitHub issue
- Contact maintainers
- Check GitHub Actions logs

## Automation Details

### Workflows
- `release.yml`: Main release workflow
- `release-enhanced.yml`: Enhanced with all features
- `version-bump.yml`: Automated version bumping

### Scripts
- `bump-version.sh`: Local version bump script
- `analyze-benchmarks.py`: Performance comparison

### Configuration
- `cliff.toml`: Changelog generation config
- `Dockerfile`: Container image definition