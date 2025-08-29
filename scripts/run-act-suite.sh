#!/usr/bin/env bash
set -euo pipefail

# Run key GitHub Actions workflows locally via act with caching and SSH.
# - Uses SSH agent from host for actions/checkout
# - Mounts host cargo cache and target dir for speed
# - Mounts Docker socket for Docker/NAT tests
# - Forces linux/amd64 container arch (helpful on Apple Silicon)

IMAGE_MAP=${IMAGE_MAP:-"ubuntu-latest=catthehacker/ubuntu:act-latest"}
ARCH=${ARCH:-"linux/amd64"}

# Defaults: disable SSH agent and docker.sock unless explicitly enabled
NO_SSH_AGENT=${NO_SSH_AGENT:-1}
NO_DOCKER_SOCK=${NO_DOCKER_SOCK:-1}

# Construct container options (baseline for most jobs)
CONTAINER_OPTS=()

# SSH agent forwarding (if available); allow disabling
if [[ "${NO_SSH_AGENT:-0}" != "1" && -n "${SSH_AUTH_SOCK:-}" && -S "${SSH_AUTH_SOCK}" ]]; then
  CONTAINER_OPTS+=("-v" "${SSH_AUTH_SOCK}:/tmp/ssh.sock" "-e" "SSH_AUTH_SOCK=/tmp/ssh.sock")
fi

# Known hosts for SSH
if [[ -f "${HOME}/.ssh/known_hosts" ]]; then
  CONTAINER_OPTS+=("-v" "${HOME}/.ssh/known_hosts:/root/.ssh/known_hosts:ro")
fi

# Cargo caches
mkdir -p "${HOME}/.cargo" || true
CONTAINER_OPTS+=("-v" "${HOME}/.cargo:/root/.cargo")
CONTAINER_OPTS+=("-v" "${HOME}/.cargo:/github/home/.cargo")

# Project target directory
mkdir -p target || true
CONTAINER_OPTS+=("-v" "${PWD}/target:/github/home/target")

# Docker socket (for NAT tests); allow disabling to avoid duplicate mounts
# NAT-specific container options (privileged + docker socket)
NAT_OPTS=()
if [[ "${NO_DOCKER_SOCK}" != "1" && -S "/var/run/docker.sock" ]]; then
  NAT_OPTS+=("--privileged" "-v" "/var/run/docker.sock:/var/run/docker.sock")
fi

# Common act flags
TOKEN_VALUE="${GITHUB_TOKEN:-dummy}"
COMMON=(
  "--container-architecture" "${ARCH}"
  "-P" "${IMAGE_MAP}"
  "--secret" "GITHUB_TOKEN=${TOKEN_VALUE}"
)

run() {
  echo "[run-act] $*"
  act "$@" "--container-options" "${CONTAINER_OPTS[*]}"
}

echo "Using act: $(act --version || echo not-found)"
echo "Image map: ${IMAGE_MAP}"
echo "Container arch: ${ARCH}"
echo "Container opts: ${CONTAINER_OPTS[*]}"

# 1) Quick Checks
run pull_request -W .github/workflows/quick-checks.yml "${COMMON[@]}"

# 2) Standard Tests (run core jobs individually for faster feedback)
run workflow_dispatch -W .github/workflows/standard-tests.yml -j test "${COMMON[@]}"
run workflow_dispatch -W .github/workflows/standard-tests.yml -j integration-tests "${COMMON[@]}"
run workflow_dispatch -W .github/workflows/standard-tests.yml -j doc-tests "${COMMON[@]}"
run workflow_dispatch -W .github/workflows/standard-tests.yml -j feature-combinations "${COMMON[@]}"
run workflow_dispatch -W .github/workflows/standard-tests.yml -j wasm-check "${COMMON[@]}"

# Optional: coverage (can be slow)
if [[ "${RUN_COVERAGE:-0}" == "1" ]]; then
  run workflow_dispatch -W .github/workflows/standard-tests.yml -j coverage "${COMMON[@]}"
fi

# 3) Security jobs (skip scorecard locally)
run workflow_dispatch -W .github/workflows/security.yml -j vulnerability-scan "${COMMON[@]}"
run workflow_dispatch -W .github/workflows/security.yml -j policy-check "${COMMON[@]}"
run workflow_dispatch -W .github/workflows/security.yml -j supply-chain "${COMMON[@]}"
run workflow_dispatch -W .github/workflows/security.yml -j sbom-generation "${COMMON[@]}"

# 4) NAT Docker tests (requires Docker socket)
# 4) NAT Docker tests (requires Docker socket) - use NAT_OPTS in addition
echo "[run-act] workflow_dispatch -W .github/workflows/nat-tests.yml -j docker-nat-tests ${COMMON[*]}"
act workflow_dispatch -W .github/workflows/nat-tests.yml -j docker-nat-tests "${COMMON[@]}" "--container-options" "${CONTAINER_OPTS[*]} ${NAT_OPTS[*]}"

# 5) Cross-platform (will run in Linux container; cross targets compile)
run push -W .github/workflows/cross-platform.yml -j cross-platform-test "${COMMON[@]}"

# 6) Performance benchmarks (baseline compare may noop)
run workflow_dispatch -W .github/workflows/performance.yml -j benchmarks "${COMMON[@]}"

# 7) External validation
run workflow_dispatch -W .github/workflows/external-validation.yml -j validate-endpoints "${COMMON[@]}"

# 8) Release build (Linux)
run workflow_dispatch -W .github/workflows/release.yml -j build "${COMMON[@]}"

# 9) Book build
run push -W .github/workflows/book.yml "${COMMON[@]}"

echo "All requested act runs invoked. Review above output for per-job results." 
