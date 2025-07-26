# Release Checklist

Use this checklist before creating a new release of ant-quic.

## Pre-Release Checks

### Code Quality
- [ ] All tests pass locally: `cargo test --all-features`
- [ ] No clippy warnings: `cargo clippy -- -D warnings`
- [ ] Code is formatted: `cargo fmt --all -- --check`
- [ ] Documentation builds: `cargo doc --no-deps`

### Security
- [ ] No security vulnerabilities: `cargo audit`
- [ ] Dependencies are up to date: `cargo outdated`
- [ ] License compliance: `cargo deny check`

### Performance
- [ ] Run benchmarks: `cargo bench`
- [ ] Compare with previous version: `make bench-compare`
- [ ] No significant regressions

### Documentation
- [ ] README.md is up to date
- [ ] CHANGELOG.md includes all changes
- [ ] API breaking changes are documented
- [ ] Examples still work

### Version
- [ ] Version in Cargo.toml is correct
- [ ] Version follows semantic versioning
- [ ] No references to old versions

## Release Process

### 1. Create Release Branch
```bash
git checkout -b release/vX.Y.Z
```

### 2. Update Version
```bash
# Use the automated workflow or:
make release-patch  # or release-minor/release-major
```

### 3. Update Documentation
- [ ] Update CHANGELOG.md
- [ ] Update version in README.md examples
- [ ] Update any version-specific documentation

### 4. Test Release
```bash
# Dry run
make release-dry-run

# Test Docker build
docker build -t ant-quic:test .
```

### 5. Create PR
- [ ] Create PR for release branch
- [ ] Wait for all CI checks to pass
- [ ] Get approval from maintainer

### 6. Merge and Tag
```bash
# After PR is merged
git checkout main
git pull origin main
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

### 7. Monitor Release
- [ ] Check GitHub Actions for release workflow
- [ ] Verify all platform builds succeed
- [ ] Check crates.io publication
- [ ] Verify Docker images are published

## Post-Release

### Verification
- [ ] Download and test binaries for each platform
- [ ] Test Docker images
- [ ] Verify crates.io installation: `cargo install ant-quic`
- [ ] Check documentation on docs.rs

### Communication
- [ ] Announce on Discord/Slack (if applicable)
- [ ] Update project website (if applicable)
- [ ] Tweet about release (if applicable)

### Cleanup
- [ ] Delete local release branch
- [ ] Update development version if needed
- [ ] Plan next release features

## Rollback Plan

If critical issues are found:

1. **Immediate Actions**
   - [ ] Yank from crates.io if needed
   - [ ] Draft GitHub release as "pre-release"
   - [ ] Communicate issue to users

2. **Fix and Re-release**
   - [ ] Create hotfix branch
   - [ ] Fix critical issues
   - [ ] Create patch release (X.Y.Z+1)

## Notes

- Always test on a clean environment
- Consider time zones when releasing
- Avoid Friday releases
- Have rollback plan ready
- Monitor user feedback after release