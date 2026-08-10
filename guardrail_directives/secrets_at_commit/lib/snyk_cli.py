"""Snyk CLI discovery, auth, and the secrets-scan subprocess invocation."""

import fnmatch
import glob
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Literal, Optional, Tuple

from .findings import Finding, parse_secrets_results
from .proc import IS_WINDOWS, run_text

# CLI integration metadata published in _snyk_env() as SNYK_INTEGRATION_*.
# Other Studio hooks carry the same literal today; there is no shared generated
# version source in the installer payload yet.
SNYK_STUDIO_VERSION = "1.0.6"
_SNYK_BINARY_NAMES = ["snyk.cmd", "snyk.exe", "snyk"] if IS_WINDOWS else ["snyk"]

ScanStatus = Literal["success", "timeout", "error", "auth_required"]

_AUTH_ERROR_PATTERNS = (
    "missingapitokenerror",
    "not authenticated",
    "authentication required",
    "snyk-0005",
)


# GUI git clients often launch with a minimal PATH; probe common install
# locations rather than assume PATH is complete.
def _search_paths_unix(env: Dict[str, str]) -> List[str]:
    nvm_dir = env.get("NVM_DIR", os.path.expanduser("~/.nvm"))
    paths = sorted(glob.glob(os.path.join(nvm_dir, "versions", "node", "*", "bin")), reverse=True)
    paths.append(os.path.expanduser("~/.volta/bin"))
    paths.extend(["/usr/local/bin", "/opt/homebrew/bin"])
    return paths


def _search_paths_windows(env: Dict[str, str]) -> List[str]:
    paths: List[str] = []
    appdata = env.get("APPDATA", "")
    if appdata:
        paths.extend(sorted(glob.glob(os.path.join(appdata, "nvm", "v*")), reverse=True))
        paths.append(os.path.join(appdata, "npm"))
    local_appdata = env.get("LOCALAPPDATA", "")
    if local_appdata:
        paths.append(os.path.join(local_appdata, "Volta", "bin"))
    userprofile = env.get("USERPROFILE", "")
    if userprofile:
        paths.append(os.path.join(userprofile, "scoop", "shims"))
    choco = env.get("ChocolateyInstall", "")
    if choco:
        paths.append(os.path.join(choco, "bin"))
    program_files = env.get("ProgramFiles", "")
    if program_files:
        paths.append(os.path.join(program_files, "Snyk"))
    return paths


def _debug(message: str) -> None:
    if os.environ.get("SECRETS_HOOK_DEBUG") == "1":
        print(f"  [debug] {message}", file=sys.stderr)


# The installer writes this file for npm-managed and user-specified Snyk CLI
# selections. It has to win over PATH probing: after a user-specified install
# there may be no `snyk` on PATH at all, and any `snyk` that is there is not
# the binary the user asked Studio to use.
def _cli_path_sidecar() -> str:
    """Resolved per call, not at import, so `~` follows the caller's HOME."""
    return os.path.join(os.path.expanduser("~"), ".snyk-studio", "cli-path")


def _read_sidecar() -> Optional[str]:
    """Returns the sidecar's stripped contents, or None if it can't be read."""
    sidecar = _cli_path_sidecar()
    try:
        with open(sidecar, encoding="utf-8-sig") as f:
            return f.read().strip()
    except (OSError, UnicodeDecodeError):
        # Distinguish "exists but unreadable" from "not pinned at all":
        # the former silently falls back to the npm CLI the user opted out of.
        if os.path.exists(sidecar):
            _debug(f"pinned Snyk CLI file {sidecar} could not be read")
        return None


def _pin_problem(pinned: str) -> Optional[str]:
    """Returns why `pinned` is unusable, phrased to follow the sidecar path in
    a message, or None when it is usable."""
    if not pinned:
        return "is empty or unreadable"
    expanded = os.path.expanduser(pinned)
    if not os.path.isabs(expanded):
        # A relative pin would resolve against the scan workspace -- a
        # snapshot of the very content being committed -- at exec time.
        return f'pins "{pinned}", which is not an absolute path'
    if not os.path.isfile(expanded):
        return f'pins "{pinned}", which does not exist'
    if not os.access(expanded, os.X_OK):
        return f'pins "{pinned}", which is not executable'
    return None


def _snyk_cli_from_sidecar() -> Optional[str]:
    """Returns the installer-pinned CLI path, or None if unpinned/stale."""
    pinned = _read_sidecar()
    if pinned is None:
        return None
    problem = _pin_problem(pinned)
    if problem is None:
        return os.path.abspath(os.path.expanduser(pinned))
    _debug(f"{_cli_path_sidecar()} {problem}")
    return None


@dataclass(frozen=True)
class StaleSidecar:
    """A sidecar that exists but pins no usable CLI."""

    path: str
    problem: str


def stale_sidecar_pin() -> Optional[StaleSidecar]:
    """Returns the sidecar and why its pin is unusable, else None."""
    sidecar = _cli_path_sidecar()
    if not os.path.isfile(sidecar):
        return None
    problem = _pin_problem(_read_sidecar() or "")
    return StaleSidecar(sidecar, problem) if problem else None


def _prepend_to_path(env: Dict[str, str], bin_dir: str) -> None:
    """Puts `bin_dir` at the front, dropping any existing occurrence so it
    can't stay shadowed, and any empty entry -- empty means cwd on POSIX, which
    during a scan is the workspace snapshot of the content being committed."""
    entries = [p for p in env.get("PATH", "").split(os.pathsep) if p and p != bin_dir]
    env["PATH"] = os.pathsep.join([bin_dir, *entries])


def _augment_path_for_snyk(env: Dict[str, str]) -> None:
    pinned = _snyk_cli_from_sidecar()
    if pinned:
        # The scan execs the pin by absolute path, so this isn't for discovery:
        # it stops a `snyk` the CLI shells out to from reaching a different CLI
        # than the installer-selected one -- so the pin must lead PATH, not
        # merely appear on it.
        _prepend_to_path(env, os.path.dirname(pinned))
        return
    if shutil.which("snyk", path=env.get("PATH", "")):
        return
    search = _search_paths_windows(env) if IS_WINDOWS else _search_paths_unix(env)
    for bin_dir in search:
        for name in _SNYK_BINARY_NAMES:
            if os.path.isfile(os.path.join(bin_dir, name)):
                _prepend_to_path(env, bin_dir)
                return


def find_snyk_binary() -> Optional[str]:
    pinned = _snyk_cli_from_sidecar()
    if pinned:
        return pinned
    env = os.environ.copy()
    _augment_path_for_snyk(env)
    for name in _SNYK_BINARY_NAMES:
        found = shutil.which(name, path=env.get("PATH", ""))
        if found:
            return found
    return None


def _snyk_config_path() -> str:
    config_dir = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )
    return os.path.join(config_dir, "configstore", "snyk.json")


def check_snyk_auth() -> Optional[str]:
    """Returns the API token (or oauth sentinel) when authed, else None."""
    token = os.environ.get("SNYK_TOKEN")
    if token:
        return token
    try:
        # utf-8-sig: transparently strips a BOM if present (some Windows
        # tooling adds one), falls back to plain UTF-8 otherwise -- a BOM
        # would otherwise break json.load and be misread as "not
        # authenticated" even though the token is right there.
        with open(_snyk_config_path(), encoding="utf-8-sig") as f:
            config = json.load(f)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    api_key = config.get("api")
    if api_key and isinstance(api_key, str):
        return api_key
    if config.get("INTERNAL_OAUTH_TOKEN_STORAGE"):
        return "__oauth__"
    return None


def _snyk_env() -> Dict[str, str]:
    env = os.environ.copy()
    _augment_path_for_snyk(env)
    env["SNYK_INTEGRATION_NAME"] = "STUDIO"
    env["SNYK_INTEGRATION_VERSION"] = SNYK_STUDIO_VERSION
    env["SNYK_INTEGRATION_ENVIRONMENT"] = "git_precommit"
    env["SNYK_INTEGRATION_ENVIRONMENT_VERSION"] = SNYK_STUDIO_VERSION
    try:
        device_id_path = os.path.join(os.path.expanduser("~"), ".snyk-studio", "device-id")
        with open(device_id_path, encoding="utf-8-sig") as f:
            device_id = f.read().strip()
        if device_id:
            env["INTERNAL_SNYK_CLIENT_MACHINE_ID"] = device_id
    except (OSError, UnicodeDecodeError):
        pass
    return env


def _classify_failure(stderr: str, stdout: str) -> ScanStatus:
    combined = (stderr + stdout).lower()
    if any(p in combined for p in _AUTH_ERROR_PATTERNS):
        return "auth_required"
    return "error"


def resolve_scan_files(candidate_files: List[str]) -> List[str]:
    """Drops files matching SECRETS_IGNORE_PATHS (comma-separated globs,
    matched against the full relative path)."""
    patterns = [
        p.strip() for p in os.environ.get("SECRETS_IGNORE_PATHS", "").split(",") if p.strip()
    ]
    if not patterns:
        return candidate_files
    return [f for f in candidate_files if not any(fnmatch.fnmatch(f, p) for p in patterns)]


def run_secrets_scan(
    workspace: Path, snyk_bin: str, timeout: float
) -> Tuple[ScanStatus, List[Finding]]:
    """Scans the prepared workspace."""
    try:
        # shell=True on Windows lets cmd.exe launch npm's snyk.cmd shim.
        result = run_text(
            [snyk_bin, "secrets", "test", ".", "--json"],
            cwd=workspace,
            env=_snyk_env(),
            timeout=timeout,
            shell=IS_WINDOWS,
        )
    except subprocess.TimeoutExpired:
        return "timeout", []
    except OSError:
        return "error", []
    if result.returncode > 1:
        status = _classify_failure(result.stderr, result.stdout)
        _debug(f"snyk stderr: {result.stderr[:300]}")
        return status, []
    findings = parse_secrets_results(result.stdout)
    if findings is None:
        return "error", []
    return "success", findings


def run_concurrent_scans(
    current_workspace: Path,
    baseline_workspace: Path,
    snyk_bin: str,
    timeout: float,
) -> Tuple[Tuple[ScanStatus, List[Finding]], Tuple[ScanStatus, List[Finding]]]:
    """Runs the current and baseline scans concurrently. Threads work here
    despite the GIL because subprocess.run() releases it while blocked on
    the child process -- total time is ~= max(scan_a, scan_b)."""
    with ThreadPoolExecutor(max_workers=2) as pool:
        current_future = pool.submit(run_secrets_scan, current_workspace, snyk_bin, timeout)
        baseline_future = pool.submit(run_secrets_scan, baseline_workspace, snyk_bin, timeout)
        return current_future.result(), baseline_future.result()
