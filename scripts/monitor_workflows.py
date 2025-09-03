#!/usr/bin/env python3
"""
Monitor GitHub Actions workflow runs for a repository.

Usage examples:
  scripts/monitor_workflows.py                          # auto-detect repo/branch, poll
  scripts/monitor_workflows.py --once                   # print snapshot and exit
  scripts/monitor_workflows.py --repo dirvine/ant-quic  # explicit repo
  scripts/monitor_workflows.py --branch main            # filter by branch
  scripts/monitor_workflows.py --interval 15            # poll interval seconds

Authentication:
  Uses token from one of: GITHUB_TOKEN, GH_TOKEN, GH_PAT, GIT_TOKEN (if present).
  Works unauthenticated too (public repos only, rate-limited by GitHub).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple


API = "https://api.github.com"


def eprint(*args: object, **kwargs) -> None:
    print(*args, file=sys.stderr, **kwargs)


def get_env_token() -> Optional[str]:
    for key in ("GITHUB_TOKEN", "GH_TOKEN", "GH_PAT", "GIT_TOKEN"):
        val = os.environ.get(key)
        if val:
            return val.strip()
    return None


def detect_repo_from_git() -> Optional[Tuple[str, str]]:
    try:
        import subprocess

        url = (
            subprocess.check_output([
                "git",
                "remote",
                "get-url",
                "origin",
            ])
            .decode()
            .strip()
        )
    except Exception:
        return None

    # Handle SSH and HTTPS forms
    # git@github.com:owner/repo.git
    m = re.match(r"git@github.com:(?P<owner>[^/]+)/(?P<repo>[^\.]+)(?:\.git)?$", url)
    if not m:
        # https://github.com/owner/repo.git
        m = re.match(r"https?://github.com/(?P<owner>[^/]+)/(?P<repo>[^\.]+)(?:\.git)?$", url)
    if not m:
        return None
    return m.group("owner"), m.group("repo")


def detect_branch_from_git() -> Optional[str]:
    try:
        import subprocess

        branch = (
            subprocess.check_output([
                "git",
                "rev-parse",
                "--abbrev-ref",
                "HEAD",
            ])
            .decode()
            .strip()
        )
        if branch and branch != "HEAD":
            return branch
    except Exception:
        pass
    return None


def gh_get(path: str, token: Optional[str], params: Optional[dict] = None) -> dict:
    url = API + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()
        return json.loads(data)


def iso_now() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S%z")


def fmt_run(run: dict) -> str:
    name = run.get("name") or run.get("display_title") or run.get("workflow_id")
    branch = run.get("head_branch")
    event = run.get("event")
    run_number = run.get("run_number")
    status = run.get("status")
    conclusion = run.get("conclusion")
    url = run.get("html_url")
    return f"{name} | {branch} | {event} | #{run_number} | {status}/{conclusion} | {url}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Monitor GitHub Actions workflow runs")
    parser.add_argument("--repo", help="<owner>/<repo> (auto-detected if omitted)")
    parser.add_argument("--branch", help="Branch to filter (auto-detected if omitted)")
    parser.add_argument("--interval", type=int, default=20, help="Poll interval in seconds")
    parser.add_argument("--once", action="store_true", help="Print a snapshot and exit")
    parser.add_argument("--limit", type=int, default=10, help="Max runs to display")
    args = parser.parse_args()

    if args.repo:
        if "/" not in args.repo:
            eprint("--repo must be in the form owner/repo")
            return 2
        owner, repo = args.repo.split("/", 1)
    else:
        detected = detect_repo_from_git()
        if not detected:
            eprint("Could not detect repo from git remotes; pass --repo owner/repo")
            return 2
        owner, repo = detected

    branch = args.branch or detect_branch_from_git()

    token = get_env_token()
    if token:
        eprint(f"[{iso_now()}] Using token from environment.")
    else:
        eprint(f"[{iso_now()}] No token found in env; using unauthenticated requests.")

    last_states: Dict[int, str] = {}

    def poll_once() -> int:
        params = {"per_page": args.limit}
        if branch:
            params["branch"] = branch
        try:
            data = gh_get(f"/repos/{owner}/{repo}/actions/runs", token, params)
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode()
            except Exception:
                body = str(e)
            eprint(f"HTTP error: {e.code} {e.reason}: {body}")
            return 1
        except Exception as e:
            eprint(f"Error: {e}")
            return 1

        runs = data.get("workflow_runs", [])
        if not runs:
            print(f"[{iso_now()}] No runs found for {owner}/{repo}" + (f" on {branch}" if branch else ""))
            return 0

        # Print initial snapshot (most recent first) or changes since last poll
        emitted = 0
        for run in runs:
            rid = run.get("id")
            state = f"{run.get('status')}/{run.get('conclusion')}"
            if rid not in last_states:
                print(f"[{iso_now()}] NEW   | {fmt_run(run)}")
                emitted += 1
            elif last_states.get(rid) != state:
                print(f"[{iso_now()}] UPDATE| {fmt_run(run)}")
                emitted += 1
            last_states[rid] = state

        if emitted == 0 and not args.once:
            print(f"[{iso_now()}] No changes.")

        return 0

    # Initial context
    eprint(
        f"Monitoring {owner}/{repo}" + (f" on branch {branch}" if branch else " (all branches)")
    )

    rc = poll_once()
    if args.once:
        return rc

    while True:
        time.sleep(max(2, args.interval))
        poll_once()


if __name__ == "__main__":
    sys.exit(main())

