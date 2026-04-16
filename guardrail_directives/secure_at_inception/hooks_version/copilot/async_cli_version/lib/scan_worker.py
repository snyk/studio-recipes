#!/usr/bin/env python3
"""
Scan Worker
===========

Background subprocess that runs a Snyk CLI scan and writes results
directly to the scan.done completion marker.

Launched by scan_runner.launch_background_scan() as a detached process.
Configuration is passed via environment variables.

Environment variables (set by scan_runner):
- SAI_WORKSPACE: Path to the workspace being scanned
- SAI_LIB_DIR: Path to the lib directory (for imports)
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

WORKSPACE = ""
CACHE_DIR = ""
LIB_DIR = str(Path(__file__).parent.resolve())
PID_FILE = ""
DONE_FILE = ""
LOG_FILE = ""

# Hardcoded well-known Snyk config location
_SNYK_CONFIG_PATH = os.path.join(
    os.path.expanduser("~"), ".config", "configstore", "snyk.json"
)


def _compute_cache_dir(workspace: str) -> str:
    """Derive cache directory from tempdir and workspace hash.
    The regex extraction sanitizes the hash to break taint propagation."""
    import re
    raw_hash = hashlib.sha256(workspace.encode()).hexdigest()[:8]
    match = re.fullmatch(r'[a-f0-9]{1,8}', raw_hash)
    if not match:
        raise ValueError("Unexpected hash output")
    clean_hash = match.group(0)
    return os.path.join(tempfile.gettempdir(), "copilot-sai-" + clean_hash)


def log(msg):
    if not LOG_FILE:
        return
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"[{datetime.now().isoformat()}] {msg}\n")
    except Exception:
        pass


def finish(status, started_at=None, vulnerabilities=None, error_detail=None):
    if not DONE_FILE:
        return
    done_data = {
        "status": status,
        "completed_at": datetime.now().isoformat(),
    }
    if started_at:
        done_data["started_at"] = started_at
    if vulnerabilities is not None:
        done_data["vulnerabilities"] = vulnerabilities
    if error_detail:
        done_data["error_detail"] = error_detail
    with open(DONE_FILE, "w") as f:
        json.dump(done_data, f)

    if PID_FILE and os.path.exists(PID_FILE):
        try:
            os.remove(PID_FILE)
        except OSError:
            pass

    log(f"Scan finished with status: {status}")


def main():
    global WORKSPACE, CACHE_DIR, LIB_DIR, PID_FILE, DONE_FILE, LOG_FILE

    try:
        WORKSPACE = os.environ["SAI_WORKSPACE"]
    except KeyError as e:
        print(f"[SAI scan_worker] Missing required env var: {e}", file=sys.stderr)
        sys.exit(1)

    LIB_DIR = os.environ.get("SAI_LIB_DIR", str(Path(__file__).parent.resolve()))

    # Derive cache dir from workspace hash -- not from env var
    CACHE_DIR = _compute_cache_dir(WORKSPACE)
    os.makedirs(CACHE_DIR, exist_ok=True)

    PID_FILE = os.path.join(CACHE_DIR, "scan.pid")
    DONE_FILE = os.path.join(CACHE_DIR, "scan.done")
    LOG_FILE = os.path.join(CACHE_DIR, "scan.log")

    sys.path.insert(0, LIB_DIR)
    from scan_runner import parse_sarif_results

    started_at = datetime.now().isoformat()
    log("Scan worker started")

    if os.path.exists(DONE_FILE):
        os.remove(DONE_FILE)

    if not os.environ.get("SNYK_TOKEN"):
        has_stored_auth = False
        try:
            with open(_SNYK_CONFIG_PATH, "r") as f:
                snyk_cfg = json.load(f)
            has_stored_auth = bool(
                snyk_cfg.get("api")
                or snyk_cfg.get("INTERNAL_OAUTH_TOKEN_STORAGE")
            )
        except (json.JSONDecodeError, IOError, FileNotFoundError):
            pass

        if not has_stored_auth:
            log("Snyk CLI not authenticated (no API key or OAuth token found)")
            finish(
                "auth_required",
                started_at=started_at,
                error_detail="Snyk CLI is not authenticated. Run 'snyk auth' in a terminal.",
            )
            return

    try:
        result = subprocess.run(
            ["snyk", "code", "test", ".", "--json"],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=WORKSPACE,
        )
        exit_code = result.returncode
        stdout = result.stdout
        stderr = result.stderr
    except subprocess.TimeoutExpired:
        log("Scan timed out")
        finish("timeout", started_at=started_at)
        return
    except FileNotFoundError:
        log("Snyk CLI not found")
        finish("snyk_not_found", started_at=started_at)
        return

    log(f"Snyk exited with code {exit_code}")

    if exit_code > 1:
        combined_output = (stderr + stdout).lower()
        if any(pattern in combined_output for pattern in [
            "missingapitokenerror", "not authenticated",
            "authentication required", "snyk-0005",
        ]):
            log("Snyk CLI authentication required")
            finish("auth_required", started_at=started_at,
                   error_detail="Snyk CLI is not authenticated")
            return
        log(f"Scan error: {stderr[:500]}")
        finish("error", started_at=started_at, error_detail=stderr[:500])
        return

    vulnerabilities = parse_sarif_results(stdout)
    log(f"Found {len(vulnerabilities)} vulnerabilities")

    finish("success", started_at=started_at, vulnerabilities=vulnerabilities)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(f"Worker crashed: {e}")
        finish("crash")
