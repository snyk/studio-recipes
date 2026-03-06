#!/usr/bin/env python3
"""
Scan Runner Module
==================

Manages background Snyk CLI scans: launching the scan_worker.py subprocess,
polling for completion, SARIF result parsing, and reading results.

The afterFileEdit hook calls launch_background_scan() to start a scan.
Throttling is natural: is_scan_running() prevents duplicate launches.

The Stop hook calls wait_for_scan() which polls for the completion marker,
then reads results (including parsed vulnerabilities) from scan.done.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


# =============================================================================
# CONFIGURATION
# =============================================================================

SCAN_WAIT_TIMEOUT = 90
POLL_INTERVAL_INITIAL = 1.0
POLL_INTERVAL_MAX = 3.0
PID_STALENESS_TIMEOUT = 600


# =============================================================================
# CACHE DIRECTORY MANAGEMENT
# =============================================================================

def get_cache_dir(workspace: str) -> str:
    workspace_hash = hashlib.sha256(workspace.encode()).hexdigest()[:8]
    return os.path.join(tempfile.gettempdir(), f"cursor-sai-{workspace_hash}")


def ensure_cache_dirs(workspace: str) -> str:
    cache_dir = get_cache_dir(workspace)
    os.makedirs(cache_dir, exist_ok=True)
    return cache_dir


# =============================================================================
# SCAN STATE MANAGEMENT
# =============================================================================

def get_scan_pid_file(workspace: str) -> str:
    return os.path.join(get_cache_dir(workspace), "scan.pid")


def get_scan_done_file(workspace: str) -> str:
    return os.path.join(get_cache_dir(workspace), "scan.done")


def is_scan_running(workspace: str) -> bool:
    pid_file = get_scan_pid_file(workspace)
    if not os.path.exists(pid_file):
        return False

    try:
        age = time.time() - os.path.getmtime(pid_file)
        if age > PID_STALENESS_TIMEOUT:
            _cleanup_pid_file(workspace)
            return False
    except OSError:
        pass

    try:
        with open(pid_file, "r") as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        return True
    except (ValueError, ProcessLookupError, OSError):
        _cleanup_pid_file(workspace)
        return False


def is_scan_complete(workspace: str) -> bool:
    return os.path.exists(get_scan_done_file(workspace))


def _cleanup_pid_file(workspace: str) -> None:
    pid_file = get_scan_pid_file(workspace)
    if os.path.exists(pid_file):
        try:
            os.remove(pid_file)
        except OSError:
            pass


# =============================================================================
# SARIF PARSING
# =============================================================================

def parse_sarif_results(json_output: str) -> List[Dict[str, Any]]:
    """Parse Snyk Code SARIF JSON output into a list of vulnerability dicts."""
    vulnerabilities: List[Dict[str, Any]] = []

    try:
        data = json.loads(json_output)
    except json.JSONDecodeError:
        return vulnerabilities

    for run in data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            message = result.get("message", {}).get("text", "")

            level = result.get("level", "warning")
            severity = {"error": "high", "warning": "medium", "note": "low"}.get(level, "medium")

            properties = result.get("properties", {})
            if "priorityScore" in properties:
                score = properties["priorityScore"]
                if score >= 700:
                    severity = "critical"
                elif score >= 500:
                    severity = "high"
                elif score >= 300:
                    severity = "medium"
                else:
                    severity = "low"

            cwe_list = properties.get("cwe", [])
            cwe = cwe_list[0] if cwe_list else None

            for loc in result.get("locations", []):
                phys_loc = loc.get("physicalLocation", {})
                artifact = phys_loc.get("artifactLocation", {})
                region = phys_loc.get("region", {})

                vulnerabilities.append({
                    "id": rule_id,
                    "title": rule_id.replace("/", " - ").replace("_", " ").title(),
                    "severity": severity,
                    "cwe": cwe,
                    "file_path": artifact.get("uri", "unknown"),
                    "start_line": region.get("startLine", 0),
                    "end_line": region.get("endLine", region.get("startLine", 0)),
                    "message": message,
                })

    return vulnerabilities


# =============================================================================
# BACKGROUND SCAN LAUNCHER
# =============================================================================

def launch_background_scan(workspace: str) -> bool:
    """Launch a background Snyk code scan as a detached subprocess.
    PID file is written by the launcher to close the race window."""
    ensure_cache_dirs(workspace)

    if is_scan_running(workspace):
        return False

    done_file = get_scan_done_file(workspace)
    if os.path.exists(done_file):
        os.remove(done_file)

    worker_script = str(Path(__file__).parent.resolve() / "scan_worker.py")
    env = os.environ.copy()
    env["SAI_WORKSPACE"] = workspace
    env["SAI_CACHE_DIR"] = get_cache_dir(workspace)
    env["SAI_LIB_DIR"] = str(Path(__file__).parent.resolve())

    try:
        proc = subprocess.Popen(
            [sys.executable, worker_script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            cwd=workspace,
            env=env,
        )
        pid_file = get_scan_pid_file(workspace)
        with open(pid_file, "w") as f:
            f.write(str(proc.pid))
        return True
    except Exception:
        return False


# =============================================================================
# SCAN COMPLETION
# =============================================================================

def _read_scan_status(workspace: str) -> Optional[str]:
    done_file = get_scan_done_file(workspace)
    try:
        with open(done_file, "r") as f:
            data = json.load(f)
        return data.get("status", "unknown")
    except (json.JSONDecodeError, IOError, FileNotFoundError):
        return None


def get_scan_completion_info(workspace: str) -> Optional[Dict[str, Any]]:
    """Read the full scan.done record (status, started_at, vulnerabilities)."""
    done_file = get_scan_done_file(workspace)
    try:
        with open(done_file, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError, FileNotFoundError):
        return None


def wait_for_scan(
    workspace: str, timeout: float = SCAN_WAIT_TIMEOUT, log_fn=None
) -> Optional[str]:
    """Wait for a background scan to complete. Returns the status string
    or None if the wait timed out."""
    if log_fn is None:
        log_fn = lambda msg: None

    if is_scan_complete(workspace):
        return _read_scan_status(workspace)

    if not is_scan_running(workspace) and not is_scan_complete(workspace):
        if not launch_background_scan(workspace):
            if is_scan_complete(workspace):
                return _read_scan_status(workspace)
            return None

    log_fn("[SAI] Waiting for security scan to complete...")

    start_time = time.time()
    poll_interval = POLL_INTERVAL_INITIAL

    while (time.time() - start_time) < timeout:
        if is_scan_complete(workspace):
            elapsed = time.time() - start_time
            log_fn(f"[SAI] Scan completed ({elapsed:.1f}s)")
            return _read_scan_status(workspace)

        if not is_scan_running(workspace) and not is_scan_complete(workspace):
            log_fn("[SAI] Scan process terminated unexpectedly")
            return None

        time.sleep(poll_interval)
        poll_interval = min(poll_interval * 1.5, POLL_INTERVAL_MAX)

    log_fn(f"[SAI] Scan timed out after {timeout:.0f}s")
    return None


def clear_scan_state(workspace: str) -> None:
    """Clear scan state files (PID, done marker)."""
    for file_path in [get_scan_pid_file(workspace), get_scan_done_file(workspace)]:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError:
                pass
