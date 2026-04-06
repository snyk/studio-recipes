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
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from platform_utils import (
    get_detached_popen_kwargs,
    get_snyk_binary_names,
    get_snyk_search_paths,
    is_pid_alive,
)


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
        if is_pid_alive(pid):
            return True
        _cleanup_pid_file(workspace)
        return False
    except (ValueError, OSError):
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
# PATH RESOLUTION
# =============================================================================

def _augment_path_for_snyk(env: Dict[str, str]) -> None:
    """Ensure the snyk binary is discoverable on PATH.

    IDE-spawned subprocesses often lack shell profile additions (nvm, volta).
    Probes common install locations and appends the matching bin directory.
    """
    if shutil.which("snyk", path=env.get("PATH", "")):
        return

    candidates = get_snyk_search_paths(env)
    binary_names = get_snyk_binary_names()

    for bin_dir in candidates:
        for name in binary_names:
            if os.path.isfile(os.path.join(bin_dir, name)):
                env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
                return


# =============================================================================
# AUTH TOKEN RESOLUTION
# =============================================================================

_SNYK_CONFIG_PATH = os.path.join(
    os.path.expanduser("~"), ".config", "configstore", "snyk.json"
)


def _get_snyk_config_path() -> str:
    """Return the path to the Snyk CLI config file.

    Uses the hardcoded well-known path (~/.config/configstore/snyk.json)
    rather than trusting XDG_CONFIG_HOME to avoid path-traversal via
    a manipulated environment variable.
    """
    return _SNYK_CONFIG_PATH


def check_snyk_auth() -> Optional[str]:
    """Check if Snyk is authenticated and return the token if found.

    Returns the API token string if authenticated, None otherwise.
    Checks SNYK_TOKEN env var first, then the Snyk CLI config file
    for API key or OAuth token storage.
    """
    token = os.environ.get("SNYK_TOKEN")
    if token:
        return token

    try:
        with open(_get_snyk_config_path(), "r") as f:
            config = json.load(f)
        api_key = config.get("api")
        if api_key and isinstance(api_key, str):
            return api_key
        if config.get("INTERNAL_OAUTH_TOKEN_STORAGE"):
            return "__oauth__"
    except (json.JSONDecodeError, IOError, FileNotFoundError):
        pass

    return None


def check_snyk_cli() -> Optional[str]:
    """Check if the Snyk CLI binary is discoverable on PATH.

    Probes the current PATH and common install locations (nvm, Volta,
    Homebrew, Scoop, etc.) via platform_utils helpers.

    Returns the path to the binary if found, None otherwise.
    """
    env = os.environ.copy()
    _augment_path_for_snyk(env)

    for name in get_snyk_binary_names():
        found = shutil.which(name, path=env.get("PATH", ""))
        if found:
            return found
    return None


def write_early_status(workspace: str, status: str, error_detail: str = "") -> None:
    """Write a scan.done marker without launching a scan.

    Used to short-circuit when preconditions fail (e.g. auth missing,
    CLI not found) so the stop handler doesn't wait for a scan that
    will never complete.
    """
    from datetime import datetime

    ensure_cache_dirs(workspace)
    done_file = get_scan_done_file(workspace)
    done_data = {
        "status": status,
        "completed_at": datetime.now().isoformat(),
        "started_at": datetime.now().isoformat(),
        "vulnerabilities": [],
    }
    if error_detail:
        done_data["error_detail"] = error_detail
    with open(done_file, "w") as f:
        json.dump(done_data, f)


def _ensure_snyk_token(env: Dict[str, str]) -> None:
    """Inject SNYK_TOKEN into env from the Snyk CLI config file if available.

    Covers legacy API-key auth (``api`` field) so the worker subprocess
    doesn't depend on the snyk binary to resolve the token.  OAuth tokens
    (``INTERNAL_OAUTH_TOKEN_STORAGE``) are read natively by the CLI from
    the config file and don't need to be passed via env.
    """
    if env.get("SNYK_TOKEN"):
        return

    try:
        with open(_get_snyk_config_path(), "r") as f:
            config = json.load(f)
        api_key = config.get("api")
        if api_key and isinstance(api_key, str):
            env["SNYK_TOKEN"] = api_key
    except (json.JSONDecodeError, IOError, FileNotFoundError):
        pass


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
    _augment_path_for_snyk(env)
    _ensure_snyk_token(env)
    env["SAI_WORKSPACE"] = workspace
    env["SAI_CACHE_DIR"] = get_cache_dir(workspace)
    env["SAI_LIB_DIR"] = str(Path(__file__).parent.resolve())

    try:
        proc = subprocess.Popen(
            [sys.executable, worker_script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=workspace,
            env=env,
            **get_detached_popen_kwargs(),
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
