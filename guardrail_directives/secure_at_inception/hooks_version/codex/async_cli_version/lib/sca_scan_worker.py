#!/usr/bin/env python3
"""
SCA Scan Worker
===============

Background subprocess that runs a Snyk SCA scan and writes results
directly to the sca_scan.done completion marker.

Launched by scan_runner.launch_background_sca_scan() as a detached process.
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
from typing import Any, Dict, List, Optional, Set, Tuple

WORKSPACE = ""
CACHE_DIR = ""
LIB_DIR = str(Path(__file__).parent.resolve())
PID_FILE = ""
DONE_FILE = ""
LOG_FILE: Optional[str] = None

from platform_utils import STUDIO_VERSION as SNYK_STUDIO_VERSION  # noqa: E402
from platform_utils import (  # noqa: E402
    ensure_process_in_kill_on_close_job,  # noqa: E402
    get_snyk_config_path,
    is_auth_error,
    needs_shell,
    prepend_to_path,
    run_snyk_with_retry,
    snyk_cli_from_sidecar,
    with_attempts,
)
from platform_utils import log as _platform_log  # noqa: E402


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

    log(f"SCA scan finished with status: {status}")


def parse_snyk_test_results(json_output: str) -> List[Dict[str, Any]]:
    """Parse snyk test --json output into a list of vulnerability dicts.

    snyk test --json emits either a single project object or an array of
    project objects for monorepos.  Each project has a ``vulnerabilities``
    array whose entries are deduplicated by (id, packageName, version).
    """
    vulnerabilities: List[Dict[str, Any]] = []

    try:
        data = json.loads(json_output)
    except json.JSONDecodeError:
        return vulnerabilities

    projects = data if isinstance(data, list) else [data]

    seen: Set[Tuple[str, str, str]] = set()
    for project in projects:
        if not isinstance(project, dict):
            continue
        for vuln in project.get("vulnerabilities", []):
            pkg_name = vuln.get("packageName", "")
            version = vuln.get("version", "")
            vuln_id = vuln.get("id", "")
            dedup_key = (vuln_id, pkg_name, version)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            identifiers = vuln.get("identifiers") or {}
            cve_list = identifiers.get("CVE", [])
            cve = cve_list[0] if cve_list else None

            fixed_in = vuln.get("fixedIn", [])
            fix_available = bool(vuln.get("isUpgradable") or vuln.get("isPatchable") or fixed_in)

            vulnerabilities.append(
                {
                    "id": vuln_id,
                    "title": vuln.get("title", vuln_id),
                    "package_name": pkg_name,
                    "version": version,
                    "severity": vuln.get("severity", "unknown"),
                    "cve": cve,
                    "fix_available": fix_available,
                }
            )

    return vulnerabilities


def main() -> None:
    global WORKSPACE, CACHE_DIR, LIB_DIR, PID_FILE, DONE_FILE, LOG_FILE

    try:
        WORKSPACE = os.environ["SAI_WORKSPACE"]
        CACHE_DIR = os.environ["SAI_CACHE_DIR"]
    except KeyError as e:
        print(f"[SAI sca_scan_worker] Missing required env var: {e}", file=sys.stderr)
        sys.exit(1)

    LIB_DIR = os.environ.get("SAI_LIB_DIR", str(Path(__file__).parent.resolve()))

    PID_FILE = os.environ.get("SAI_PID_FILE") or os.path.join(CACHE_DIR, "sca_scan.pid")
    DONE_FILE = os.environ.get("SAI_DONE_FILE") or os.path.join(CACHE_DIR, "sca_scan.done")
    LOG_FILE = os.environ.get("SAI_LOG_FILE", None)

    sys.path.insert(0, LIB_DIR)
    from scan_runner import _force_disable_snyk_auth, _force_disable_snyk_cli

    # Must happen before the snyk subprocess is spawned below: on Windows this
    # binds the worker (and any child it spawns from here on) to a
    # KILL_ON_JOB_CLOSE job, so cancel_scan/cancel_sca_scan terminating this
    # process also reaches the snyk CLI child instead of orphaning it.
    ensure_process_in_kill_on_close_job()

    started_at = datetime.now().isoformat()
    log("SCA scan worker started")

    if os.path.exists(DONE_FILE):
        os.remove(DONE_FILE)

    if _force_disable_snyk_auth():
        log("Snyk auth disabled by environment override")
        finish(
            "auth_required",
            started_at=started_at,
            error_detail="Snyk CLI auth disabled by test environment override.",
        )
        return

    if not os.environ.get("SNYK_TOKEN"):
        has_stored_auth = False
        try:
            with open(get_snyk_config_path()) as f:
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

    if _force_disable_snyk_cli():
        log("Snyk CLI disabled by environment override")
        finish("snyk_not_found", started_at=started_at)
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
    env["SNYK_INTEGRATION_ENVIRONMENT"] = "codex_cli"
    env["SNYK_INTEGRATION_ENVIRONMENT_VERSION"] = SNYK_STUDIO_VERSION
    try:
        _device_id = os.path.join(os.path.expanduser("~"), ".snyk-studio", "device-id")
        _machine_id = open(_device_id, encoding="utf-8-sig").read().strip()
        if _machine_id:
            env["INTERNAL_SNYK_CLIENT_MACHINE_ID"] = _machine_id
    except Exception:
        pass

    cmd = [snyk_bin, "test", ".", "--json"]
    if needs_shell(snyk_bin):
        # Only .cmd/.bat shims (e.g. an npm-installed snyk.cmd) need cmd.exe's
        # own parsing; wrap explicitly here rather than passing shell=True
        # unconditionally, which would route every scan through an extra
        # cmd.exe process that "cancelling" this worker can't reach.
        cmd = ["cmd.exe", "/d", "/s", "/c", subprocess.list2cmdline(cmd)]
    try:
        exit_code, stdout, stderr, attempts = run_snyk_with_retry(
            cmd, env, WORKSPACE, log_fn=log, auth_retry=True
        )
    except subprocess.TimeoutExpired:
        log("SCA scan timed out")
        finish("timeout", started_at=started_at)
        return

    log(f"Snyk test exited with code {exit_code} (attempts={attempts})")

    if exit_code > 1:
        if is_auth_error(stderr + stdout):
            log("Snyk CLI authentication required")
            finish(
                "auth_required",
                started_at=started_at,
                error_detail=with_attempts("Snyk CLI is not authenticated", attempts),
            )
            return
        log(f"SCA scan error: {stderr[:500]}")
        finish(
            "error",
            started_at=started_at,
            error_detail=with_attempts(stderr[:500], attempts),
        )
        return

    vulnerabilities = parse_snyk_test_results(stdout)
    log(f"Found {len(vulnerabilities)} SCA vulnerabilities")

    finish("success", started_at=started_at, vulnerabilities=vulnerabilities)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(f"SCA worker crashed: {e}")
        finish("crash")
