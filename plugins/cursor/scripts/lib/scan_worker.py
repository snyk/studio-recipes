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
- SAI_CACHE_DIR: Path to the cache directory
- SAI_LIB_DIR: Path to the lib directory (for imports)
"""

import json
import os
import re
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

_CACHE_DIR_PATTERN = re.compile(r"^cursor-sai-[0-9a-f]{8}$")


def _validate_cache_dir(cache_dir: str) -> str:
    """Resolve and validate that cache_dir is a cursor-sai-* directory inside the system temp."""
    resolved = os.path.realpath(cache_dir)
    tmp_root = os.path.realpath(tempfile.gettempdir())
    if not resolved.startswith(tmp_root + os.sep):
        raise ValueError(f"Cache dir is not under temp directory: {resolved}")
    dir_name = os.path.basename(resolved)
    if not _CACHE_DIR_PATTERN.match(dir_name):
        raise ValueError(f"Cache dir does not match expected pattern: {dir_name}")
    return resolved


def _safe_path(cache_dir: str, filename: str) -> str:
    """Build a file path and verify it stays within the validated cache directory."""
    target = os.path.realpath(os.path.join(cache_dir, filename))
    if not target.startswith(os.path.realpath(cache_dir) + os.sep):
        raise ValueError(f"Path escapes cache directory: {target}")
    return target


def log(msg):
    if not LOG_FILE:
        return
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"[{datetime.now().isoformat()}] {msg}\n")
    except Exception:
        pass


def finish(status, started_at=None, vulnerabilities=None):
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
        CACHE_DIR = os.environ["SAI_CACHE_DIR"]
    except KeyError as e:
        print(f"[SAI scan_worker] Missing required env var: {e}", file=sys.stderr)
        sys.exit(1)

    LIB_DIR = os.environ.get("SAI_LIB_DIR", str(Path(__file__).parent.resolve()))

    CACHE_DIR = _validate_cache_dir(CACHE_DIR)
    PID_FILE = _safe_path(CACHE_DIR, "scan.pid")
    DONE_FILE = _safe_path(CACHE_DIR, "scan.done")
    LOG_FILE = _safe_path(CACHE_DIR, "scan.log")

    sys.path.insert(0, LIB_DIR)
    from scan_runner import parse_sarif_results

    started_at = datetime.now().isoformat()
    log("Scan worker started")

    if os.path.exists(DONE_FILE):
        os.remove(DONE_FILE)

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
        log(f"Scan error: {stderr[:500]}")
        finish("error", started_at=started_at)
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
