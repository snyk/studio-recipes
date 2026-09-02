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
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

WORKSPACE = ""
CACHE_DIR = ""
LIB_DIR = str(Path(__file__).parent.resolve())
PID_FILE = ""
DONE_FILE = ""
LOG_FILE: Optional[str] = None

from platform_utils import STUDIO_VERSION as SNYK_STUDIO_VERSION  # noqa: E402
from platform_utils import (  # noqa: E402
    ensure_process_in_kill_on_close_job,  # noqa: E402
    needs_shell,
    prepend_to_path,
    snyk_cli_from_sidecar,
)
from platform_utils import log as _platform_log  # noqa: E402

# Console apps (snyk / the cmd.exe shim) spawned from this windowless background
# worker allocate a new console window on Windows; CREATE_NO_WINDOW suppresses the
# flash. The flag only exists on Windows; elsewhere this is 0 (subprocess's
# default creationflags, i.e. a no-op).
_CREATE_NO_WINDOW = 0
if sys.platform == "win32":
    _CREATE_NO_WINDOW = subprocess.CREATE_NO_WINDOW

_IS_WINDOWS = sys.platform == "win32"
# Console apps (snyk / the cmd.exe shim) spawned from this windowless background
# worker allocate a new console window on Windows; CREATE_NO_WINDOW suppresses the
# flash. The flag only exists on Windows; elsewhere this is 0 (subprocess's
# default creationflags, i.e. a no-op).
_CREATE_NO_WINDOW = 0
if sys.platform == "win32":
    _CREATE_NO_WINDOW = subprocess.CREATE_NO_WINDOW

def log(msg: str, debug: bool = False) -> None:
    if not LOG_FILE:
        return
    _platform_log(f"[worker] {msg}", LOG_FILE, debug=debug)


def finish(
    status: str,
    started_at: Optional[str] = None,
    vulnerabilities: Optional[List[Dict[str, Any]]] = None,
    error_detail: Optional[str] = None,
) -> None:
    if not DONE_FILE:
        return
    done_data: Dict[str, Any] = {
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
            # Only remove the PID file if it still names this process: a
            # cancelled worker that gets here after scan_runner already
            # overwrote the file for a newer worker must not delete that
            # newer worker's PID out from under it.
            with open(PID_FILE) as f:
                owned = f.read().strip() == str(os.getpid())
            if owned:
                os.remove(PID_FILE)
        except OSError:
            pass

    log(f"Scan finished with status: {status}")


def main() -> None:
    global WORKSPACE, CACHE_DIR, LIB_DIR, PID_FILE, DONE_FILE, LOG_FILE

    try:
        WORKSPACE = os.environ["SAI_WORKSPACE"]
        CACHE_DIR = os.environ["SAI_CACHE_DIR"]
    except KeyError as e:
        print(f"[SAI scan_worker] Missing required env var: {e}", file=sys.stderr)
        sys.exit(1)

    LIB_DIR = os.environ.get("SAI_LIB_DIR", str(Path(__file__).parent.resolve()))

    PID_FILE = os.environ.get("SAI_PID_FILE") or os.path.join(CACHE_DIR, "scan.pid")
    DONE_FILE = os.environ.get("SAI_DONE_FILE") or os.path.join(CACHE_DIR, "scan.done")
    LOG_FILE = os.environ.get("SAI_LOG_FILE", None)

    sys.path.insert(0, LIB_DIR)
    from scan_runner import parse_sarif_results

    # Must happen before the snyk subprocess is spawned below: on Windows this
    # binds the worker (and any child it spawns from here on) to a
    # KILL_ON_JOB_CLOSE job, so cancel_scan/cancel_sca_scan terminating this
    # process also reaches the snyk CLI child instead of orphaning it.
    ensure_process_in_kill_on_close_job()

    started_at = datetime.now().isoformat()
    log("Scan worker started")

    if os.path.exists(DONE_FILE):
        os.remove(DONE_FILE)

    if not os.environ.get("SNYK_TOKEN"):
        config_dir = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
        snyk_config_path = os.path.join(config_dir, "configstore", "snyk.json")
        has_stored_auth = False
        try:
            with open(snyk_config_path) as f:
                snyk_cfg = json.load(f)
            has_stored_auth = bool(
                snyk_cfg.get("api") or snyk_cfg.get("INTERNAL_OAUTH_TOKEN_STORAGE")
            )
        except (OSError, json.JSONDecodeError, FileNotFoundError):
            pass

        if not has_stored_auth:
            log("Snyk CLI not authenticated (no API key or OAuth token found)")
            finish(
                "auth_required",
                started_at=started_at,
                error_detail="Snyk CLI is not authenticated. Run 'snyk auth' in a terminal.",
            )
            return

    snyk_bin = snyk_cli_from_sidecar() or shutil.which("snyk")
    if snyk_bin is None:
        log("Snyk CLI not found on PATH")
        finish("snyk_not_found", started_at=started_at)
        return

    env = os.environ.copy()
    snyk_bin_dir = os.path.dirname(snyk_bin)
    if snyk_bin_dir:
        prepend_to_path(env, snyk_bin_dir)
    env["SNYK_INTEGRATION_NAME"] = "STUDIO"
    env["SNYK_INTEGRATION_VERSION"] = SNYK_STUDIO_VERSION
    env["SNYK_INTEGRATION_ENVIRONMENT"] = "cursor"
    env["SNYK_INTEGRATION_ENVIRONMENT_VERSION"] = SNYK_STUDIO_VERSION
    try:
        _device_id = os.path.join(os.path.expanduser("~"), ".snyk-studio", "device-id")
        _machine_id = open(_device_id, encoding="utf-8-sig").read().strip()
        if _machine_id:
            env["INTERNAL_SNYK_CLIENT_MACHINE_ID"] = _machine_id
    except Exception:
        pass

    cmd = [snyk_bin, "code", "test", ".", "--json"]
    if needs_shell(snyk_bin):
        # Only .cmd/.bat shims (e.g. an npm-installed snyk.cmd) need cmd.exe's
        # own parsing; wrap explicitly here rather than passing shell=True
        # unconditionally, which would route every scan through an extra
        # cmd.exe process that "cancelling" this worker can't reach.
        cmd = ["cmd.exe", "/d", "/s", "/c", subprocess.list2cmdline(cmd)]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            # snyk always emits UTF-8 JSON regardless of platform; text=True
            # alone decodes using the ambient locale encoding instead (e.g.
            # cp1252 on Windows), which crashes on legitimate non-ASCII
            # characters in vulnerability descriptions (confirmed live:
            # curly quotes in a real CVE description). errors="replace" is a
            # belt-and-suspenders fallback if snyk ever emits something that
            # isn't valid UTF-8.
            encoding="utf-8",
            errors="replace",
            timeout=300,
            cwd=WORKSPACE,
            env=env,
            shell=False,
            creationflags=_CREATE_NO_WINDOW,
        )
        exit_code = result.returncode
        stdout = result.stdout
        stderr = result.stderr
    except subprocess.TimeoutExpired:
        log("Scan timed out")
        finish("timeout", started_at=started_at)
        return

    log(f"Snyk exited with code {exit_code}")

    if exit_code > 1:
        combined_output = (stderr + stdout).lower()
        if any(
            pattern in combined_output
            for pattern in [
                "missingapitokenerror",
                "not authenticated",
                "authentication required",
                "snyk-0005",
            ]
        ):
            log("Snyk CLI authentication required")
            finish(
                "auth_required", started_at=started_at, error_detail="Snyk CLI is not authenticated"
            )
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
