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

LABELS=()
STATUS=()
LOGPATH=()

record_result() {
  local label="$1"; local status="$2"; local log="$3"
  LABELS+=("$label"); STATUS+=("$status"); LOGPATH+=("$log")
}

run() {
  local label="$1"; shift
  mkdir -p act-logs
  local sanitized_label
  sanitized_label=$(sed 's/[^A-Za-z0-9_.-]/_/g' <<<"$label")
  local log="act-logs/${sanitized_label}.log"
  echo "[run-act] $label: $*" | tee "$log"
  if act "$@" "--container-options" "${CONTAINER_OPTS[*]}" 2>&1 | tee -a "$log"; then
    record_result "$label" success "$log"
  else
    record_result "$label" failure "$log"
  fi
}

run_with_opts() {
  local label="$1"; shift
  local extra_opts="$1"; shift
  mkdir -p act-logs
  local sanitized_label
  sanitized_label=$(sed 's/[^A-Za-z0-9_.-]/_/g' <<<"$label")
  local log="act-logs/${sanitized_label}.log"
  echo "[run-act] $label: $*" | tee "$log"
  if act "$@" "--container-options" "${CONTAINER_OPTS[*]} ${extra_opts}" 2>&1 | tee -a "$log"; then
    record_result "$label" success "$log"
  else
    record_result "$label" failure "$log"
  fi
}

echo "Using act: $(act --version || echo not-found)"
echo "Image map: ${IMAGE_MAP}"
echo "Container arch: ${ARCH}"
echo "Container opts: ${CONTAINER_OPTS[*]}"

# 1) Quick Checks
run "quick-checks" pull_request -W .github/workflows/quick-checks.yml "${COMMON[@]}"

# 2) Standard Tests (run core jobs individually for faster feedback)
run "standard-tests:test" workflow_dispatch -W .github/workflows/standard-tests.yml -j test "${COMMON[@]}"
run "standard-tests:integration-tests" workflow_dispatch -W .github/workflows/standard-tests.yml -j integration-tests "${COMMON[@]}"
run "standard-tests:doc-tests" workflow_dispatch -W .github/workflows/standard-tests.yml -j doc-tests "${COMMON[@]}"
run "standard-tests:feature-combinations" workflow_dispatch -W .github/workflows/standard-tests.yml -j feature-combinations "${COMMON[@]}"
run "standard-tests:wasm-check" workflow_dispatch -W .github/workflows/standard-tests.yml -j wasm-check "${COMMON[@]}"

# Optional: coverage (can be slow)
if [[ "${RUN_COVERAGE:-0}" == "1" ]]; then
  run "standard-tests:coverage" workflow_dispatch -W .github/workflows/standard-tests.yml -j coverage "${COMMON[@]}"
fi

# 3) Security jobs (skip scorecard locally)
run "security:vulnerability-scan" workflow_dispatch -W .github/workflows/security.yml -j vulnerability-scan "${COMMON[@]}"
run "security:policy-check" workflow_dispatch -W .github/workflows/security.yml -j policy-check "${COMMON[@]}"
run "security:supply-chain" workflow_dispatch -W .github/workflows/security.yml -j supply-chain "${COMMON[@]}"
run "security:sbom-generation" workflow_dispatch -W .github/workflows/security.yml -j sbom-generation "${COMMON[@]}"

# 4) NAT Docker tests (requires Docker socket)
# 4) NAT Docker tests (requires Docker socket) - use NAT_OPTS in addition
run_with_opts "nat-tests:docker-nat-tests" "${NAT_OPTS[*]}" workflow_dispatch -W .github/workflows/nat-tests.yml -j docker-nat-tests "${COMMON[@]}"

# 5) Cross-platform (will run in Linux container; cross targets compile)
run "cross-platform:test" push -W .github/workflows/cross-platform.yml -j cross-platform-test "${COMMON[@]}"

# 6) Performance benchmarks (baseline compare may noop)
run "performance:benchmarks" workflow_dispatch -W .github/workflows/performance.yml -j benchmarks "${COMMON[@]}"

# 7) External validation
run "external-validation:validate-endpoints" workflow_dispatch -W .github/workflows/external-validation.yml -j validate-endpoints "${COMMON[@]}"

# 8) Release build (Linux)
run "release:build" workflow_dispatch -W .github/workflows/release.yml -j build "${COMMON[@]}"

# 9) Book build
run "book:build" push -W .github/workflows/book.yml "${COMMON[@]}"

echo
echo "========== act run summary =========="
failures=0
tail_lines=${DEBUG_TAIL_LINES:-60}
for i in "${!LABELS[@]}"; do
  label="${LABELS[$i]}"; status="${STATUS[$i]}"; log="${LOGPATH[$i]}"
  if [[ "$status" == "success" ]]; then
    echo "✅ $label"
  else
    echo "❌ $label"
    failures=$((failures+1))
  fi
done

if [[ $failures -gt 0 ]]; then
  echo
  echo "------ debug info for failures (last ${tail_lines} lines) ------"
  for i in "${!LABELS[@]}"; do
    if [[ "${STATUS[$i]}" != "success" ]]; then
      echo "--- ${LABELS[$i]} ---"
      if [[ -f "${LOGPATH[$i]}" ]]; then
        tail -n "$tail_lines" "${LOGPATH[$i]}"
      else
        echo "(no log found at ${LOGPATH[$i]})"
      fi
      echo
    fi
  done
fi

echo "===================================="
exit $failures
