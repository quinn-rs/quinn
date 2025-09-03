#!/usr/bin/env bash
set -euo pipefail

# Monitor GitHub Actions workflow runs for this repository.
#
# Usage:
#   scripts/monitor_workflows.sh [--interval SECONDS] [--workflow NAME]...
#
# Examples:
#   scripts/monitor_workflows.sh --interval 20 --workflow "Quick Checks" --workflow "CI Consolidated"
#   scripts/monitor_workflows.sh --interval 30                 # monitor all workflows

INTERVAL=30
declare -a WF_FILTER=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --interval)
      INTERVAL=${2:-30}; shift 2 ;;
    --workflow)
      WF_FILTER+=("${2:-}"); shift 2 ;;
    *)
      echo "Unknown flag: $1" >&2; exit 1 ;;
  esac
done

REPO=$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null || true)
if [[ -z "${REPO}" ]]; then
  echo "Unable to determine repo via gh. Ensure you're in the repo directory and authenticated (gh auth status)." >&2
  exit 1
fi

echo "Monitoring GitHub Actions for ${REPO} (interval: ${INTERVAL}s)" >&2
if [[ ${#WF_FILTER[@]} -gt 0 ]]; then
  echo "Workflows: ${WF_FILTER[*]}" >&2
fi

while true; do
  echo "\n==== $(date -u "+%Y-%m-%dT%H:%M:%SZ") ===="
  if [[ ${#WF_FILTER[@]} -eq 0 ]]; then
    gh run list --limit 20 || true
  else
    # Use JSON output to filter by workflow names without requiring external jq.
    # gh --jq uses jq internally, so we can safely rely on it.
    jq_filter='map(select(.workflowName as $w | ['"${WF_FILTER[*]}"'] | index($w))) | .[] | [ .updatedAt, .workflowName, .status, (.conclusion // ""), .headBranch, (.databaseId|tostring), .url ] | @tsv'
    gh run list --limit 50 \
      --json databaseId,workflowName,status,conclusion,headBranch,updatedAt,url \
      --jq "$jq_filter" | sed -E $'s/\t/    /g' || true
  fi
  sleep "${INTERVAL}"
done

