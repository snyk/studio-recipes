#!/usr/bin/env python3
"""
Scan Runner Module
==================

Manages background Snyk CLI scans: launching the scan_worker.py subprocess,
polling for completion, SARIF result parsing, and reading results.

The PostToolUse hook calls launch_background_scan() to start a scan.
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
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

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
    return os.path.join(tempfile.gettempdir(), f"claude-sai-{workspace_hash}")


def ensure_cache_dirs(workspace: str) -> str:
    cache_dir = get_cache_dir(workspace)
    os.makedirs(cache_dir, exist_ok=True)
    return cache_dir


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

                vulnerabilities.append(
                    {
                        "id": rule_id,
                        "title": rule_id.replace("/", " - ").replace("_", " ").title(),
                        "severity": severity,
                        "cwe": cwe,
                        "file_path": artifact.get("uri", "unknown"),
                        "start_line": region.get("startLine", 0),
                        "end_line": region.get("endLine", region.get("startLine", 0)),
                        "message": message,
                    }
                )

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

_SNYK_CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".config", "configstore", "snyk.json")


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
        with open(_get_snyk_config_path()) as f:
            config = json.load(f)
        api_key = config.get("api")
        if api_key and isinstance(api_key, str):
            return api_key
        if config.get("INTERNAL_OAUTH_TOKEN_STORAGE"):
            return "__oauth__"
    except (OSError, json.JSONDecodeError, FileNotFoundError):
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
    CLI not found) so the Stop handler doesn't wait for a scan that
    will never complete.
    """
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
        with open(_get_snyk_config_path()) as f:
            config = json.load(f)
        api_key = config.get("api")
        if api_key and isinstance(api_key, str):
            env["SNYK_TOKEN"] = api_key
    except (OSError, json.JSONDecodeError, FileNotFoundError):
        pass


# =============================================================================
# SCAN CHANNEL
# =============================================================================


class _ScanChannel:
    """Generic background scan channel (SAST or SCA).

    Encapsulates all PID/done-file state management, subprocess launching,
    polling, and result reading for one scan type.  Parameterised by
    filenames, worker script, and a display name used in log messages.
    """

    def __init__(
        self,
        pid_filename: str,
        done_filename: str,
        worker_script: str,
        name: str,
    ) -> None:
        self._pid_filename = pid_filename
        self._done_filename = done_filename
        self._worker_script = worker_script
        self._name = name  # e.g. "scan" or "SCA scan"

    # --- File paths ---

    def pid_file(self, workspace: str) -> str:
        return os.path.join(get_cache_dir(workspace), self._pid_filename)

    def done_file(self, workspace: str) -> str:
        return os.path.join(get_cache_dir(workspace), self._done_filename)

    # --- State helpers ---

    def _cleanup_pid(self, workspace: str) -> None:
        path = self.pid_file(workspace)
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass

    def is_running(self, workspace: str) -> bool:
        pid_file = self.pid_file(workspace)
        if not os.path.exists(pid_file):
            return False

        try:
            age = time.time() - os.path.getmtime(pid_file)
            if age > PID_STALENESS_TIMEOUT:
                self._cleanup_pid(workspace)
                return False
        except OSError:
            pass

        try:
            with open(pid_file) as f:
                pid = int(f.read().strip())
            if is_pid_alive(pid):
                return True
            self._cleanup_pid(workspace)
            return False
        except (ValueError, OSError):
            self._cleanup_pid(workspace)
            return False

    def is_complete(self, workspace: str) -> bool:
        return os.path.exists(self.done_file(workspace))

    # --- Results ---

    def get_completion_info(self, workspace: str) -> Optional[Dict[str, Any]]:
        """Read the full done-file record (status, started_at, vulnerabilities)."""
        try:
            with open(self.done_file(workspace)) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError, FileNotFoundError):
            return None

    def _read_status(self, workspace: str) -> Optional[str]:
        info = self.get_completion_info(workspace)
        return info.get("status", "unknown") if info else None

    # --- Cleanup ---

    def clear_state(self, workspace: str) -> None:
        """Remove PID and done marker files."""
        for path in [self.pid_file(workspace), self.done_file(workspace)]:
            if os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass


_sast = _ScanChannel("scan.pid", "scan.done", "scan_worker.py", "scan")
_sca = _ScanChannel("sca_scan.pid", "sca_scan.done", "sca_scan_worker.py", "SCA scan")


# =============================================================================
# LAUNCH / WAIT HELPERS (module-level so patches on public API functions apply)
# =============================================================================


def _do_launch(
    workspace: str,
    is_running_fn,
    done_file_fn,
    pid_file_fn,
    worker_script: str,
) -> bool:
    """Launch a worker subprocess; catches any Exception so callers get False."""
    ensure_cache_dirs(workspace)
    if is_running_fn(workspace):
        return False
    done = done_file_fn(workspace)
    if os.path.exists(done):
        os.remove(done)
    worker = str(Path(__file__).parent.resolve() / worker_script)
    env = os.environ.copy()
    _augment_path_for_snyk(env)
    _ensure_snyk_token(env)
    env["SAI_WORKSPACE"] = workspace
    env["SAI_CACHE_DIR"] = get_cache_dir(workspace)
    env["SAI_LIB_DIR"] = str(Path(__file__).parent.resolve())
    try:
        proc = subprocess.Popen(
            [sys.executable, worker],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=workspace,
            env=env,
            **get_detached_popen_kwargs(),
        )
        with open(pid_file_fn(workspace), "w") as f:
            f.write(str(proc.pid))
        return True
    except Exception:
        return False


def _do_wait(
    workspace: str,
    is_complete_fn,
    is_running_fn,
    launch_fn,
    read_status_fn,
    name: str,
    timeout: float,
    log_fn,
) -> Optional[str]:
    """Poll until the scan completes, times out, or the process dies."""

    def _noop(_msg: str) -> None:
        pass

    if log_fn is None:
        log_fn = _noop

    if is_complete_fn(workspace):
        return read_status_fn(workspace)

    if not is_running_fn(workspace) and not is_complete_fn(workspace):
        if not launch_fn(workspace):
            if is_complete_fn(workspace):
                return read_status_fn(workspace)
            return None

    title = name[0].upper() + name[1:]
    log_fn(f"[SAI] Waiting for {name} to complete...")

    start_time = time.time()
    poll_interval = POLL_INTERVAL_INITIAL

    while (time.time() - start_time) < timeout:
        if is_complete_fn(workspace):
            elapsed = time.time() - start_time
            log_fn(f"[SAI] {title} completed ({elapsed:.1f}s)")
            return read_status_fn(workspace)

        if not is_running_fn(workspace) and not is_complete_fn(workspace):
            log_fn(f"[SAI] {title} process terminated unexpectedly")
            return None

        time.sleep(poll_interval)
        poll_interval = min(poll_interval * 1.5, POLL_INTERVAL_MAX)

    log_fn(f"[SAI] {title} timed out after {timeout:.0f}s")
    return None


# =============================================================================
# SCAN STATE MANAGEMENT — public API (SAST)
# =============================================================================


def get_scan_pid_file(workspace: str) -> str:
    return _sast.pid_file(workspace)


def get_scan_done_file(workspace: str) -> str:
    return _sast.done_file(workspace)


def is_scan_running(workspace: str) -> bool:
    return _sast.is_running(workspace)


def is_scan_complete(workspace: str) -> bool:
    return _sast.is_complete(workspace)


def _cleanup_pid_file(workspace: str) -> None:
    _sast._cleanup_pid(workspace)


def launch_background_scan(workspace: str) -> bool:
    """Launch a background Snyk code scan as a detached subprocess.
    PID file is written by the launcher to close the race window."""
    return _do_launch(
        workspace, is_scan_running, get_scan_done_file, get_scan_pid_file, "scan_worker.py"
    )


def get_scan_completion_info(workspace: str) -> Optional[Dict[str, Any]]:
    """Read the full scan.done record (status, started_at, vulnerabilities)."""
    return _sast.get_completion_info(workspace)


def _read_scan_status(workspace: str) -> Optional[str]:
    return _sast._read_status(workspace)


def wait_for_scan(workspace: str, timeout: float = SCAN_WAIT_TIMEOUT, log_fn=None) -> Optional[str]:
    """Wait for a background scan to complete. Returns the status string
    or None if the wait timed out."""
    return _do_wait(
        workspace,
        is_scan_complete,
        is_scan_running,
        launch_background_scan,
        _read_scan_status,
        "scan",
        timeout,
        log_fn,
    )


def clear_scan_state(workspace: str) -> None:
    """Clear scan state files (PID, done marker)."""
    _sast.clear_state(workspace)


# =============================================================================
# SCAN STATE MANAGEMENT — public API (SCA)
# =============================================================================


def get_sca_pid_file(workspace: str) -> str:
    return _sca.pid_file(workspace)


def get_sca_done_file(workspace: str) -> str:
    return _sca.done_file(workspace)


def is_sca_scan_running(workspace: str) -> bool:
    return _sca.is_running(workspace)


def is_sca_scan_complete(workspace: str) -> bool:
    return _sca.is_complete(workspace)


def _cleanup_sca_pid_file(workspace: str) -> None:
    _sca._cleanup_pid(workspace)


def launch_background_sca_scan(workspace: str) -> bool:
    """Launch a background Snyk SCA scan as a detached subprocess.
    PID file is written by the launcher to close the race window."""
    return _do_launch(
        workspace, is_sca_scan_running, get_sca_done_file, get_sca_pid_file, "sca_scan_worker.py"
    )


def get_sca_completion_info(workspace: str) -> Optional[Dict[str, Any]]:
    """Read the full sca_scan.done record (status, started_at, vulnerabilities)."""
    return _sca.get_completion_info(workspace)


def _read_sca_scan_status(workspace: str) -> Optional[str]:
    return _sca._read_status(workspace)


def wait_for_sca_scan(
    workspace: str, timeout: float = SCAN_WAIT_TIMEOUT, log_fn=None
) -> Optional[str]:
    """Wait for a background SCA scan to complete. Returns the status string
    or None if the wait timed out."""
    return _do_wait(
        workspace,
        is_sca_scan_complete,
        is_sca_scan_running,
        launch_background_sca_scan,
        _read_sca_scan_status,
        "SCA scan",
        timeout,
        log_fn,
    )


def clear_sca_scan_state(workspace: str) -> None:
    """Clear SCA scan state files (PID, done marker)."""
    _sca.clear_state(workspace)


# =============================================================================
# MANIFEST HASH UTILITIES
# =============================================================================

_MANIFEST_EXCLUSION_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        ".venv",
        "__pycache__",
        "target",
        "vendor",
        ".gradle",
        "build",
        "dist",
        ".tox",
        ".eggs",
        ".mypy_cache",
        ".ruff_cache",
        "pytest_cache",
    }
)


def snapshot_manifest_hashes(
    workspace: str,
    manifest_files: Set[str],
    manifest_suffixes: Set[str],
) -> Dict[str, str]:
    """Walk workspace and return SHA-256 hex digests for matching manifest files."""
    hashes: Dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(workspace, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in _MANIFEST_EXCLUSION_DIRS]
        for filename in filenames:
            if filename in manifest_files or Path(filename).suffix.lower() in manifest_suffixes:
                abs_path = os.path.join(dirpath, filename)
                try:
                    with open(abs_path, "rb") as f:
                        digest = hashlib.sha256(f.read()).hexdigest()
                    hashes[abs_path] = digest
                except OSError:
                    pass
    return hashes


def detect_manifest_changes(
    workspace: str,
    baseline: Dict[str, str],
    manifest_files: Set[str],
    manifest_suffixes: Set[str],
) -> List[str]:
    """Return paths of manifest files that changed, were added, or were deleted since baseline.

    Returns an empty list when baseline is empty (safe default — no comparison possible).
    """
    if not baseline:
        return []
    current = snapshot_manifest_hashes(workspace, manifest_files, manifest_suffixes)
    changed: List[str] = []
    for path, old_hash in baseline.items():
        if path not in current or current[path] != old_hash:
            changed.append(path)
    for path in current:
        if path not in baseline:
            changed.append(path)
    return changed
