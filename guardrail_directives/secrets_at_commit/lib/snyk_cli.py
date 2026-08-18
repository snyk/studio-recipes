"""Snyk CLI discovery, auth, and the secrets-scan subprocess invocation."""

import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Literal, Optional, Tuple

from .findings import Finding, parse_secrets_results
from .proc import IS_WINDOWS, needs_shell, run_text

# CLI integration metadata published in _snyk_env() as SNYK_INTEGRATION_*.
# Other Studio hooks carry the same literal today; there is no shared generated
# version source in the installer payload yet.
SNYK_STUDIO_VERSION = "1.0.6"
_SNYK_BINARY_NAMES = ["snyk.cmd", "snyk.exe", "snyk"] if IS_WINDOWS else ["snyk"]

# A resolved path becomes cmd[0] in a shell=True subprocess call when it's a
# .cmd/.bat that needs one (see needs_shell) -- a real path can contain
# spaces/parens/backslashes, but never these, so reject them there rather
# than let cmd.exe reinterpret one. Off that path (native .exe, POSIX),
# there's no shell involved and these characters are just literal bytes.
_SHELL_UNSAFE_RE = re.compile(r'[&|^<>%!"`$;\r\n]')

ScanStatus = Literal[
    "success", "timeout", "error", "auth_required", "unparseable", "retries_exhausted"
]

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
    if needs_shell(pinned) and _SHELL_UNSAFE_RE.search(pinned):
        return f'pins "{pinned}", which contains unsafe characters'
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
        if found and not (needs_shell(found) and _SHELL_UNSAFE_RE.search(found)):
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


@dataclass(frozen=True)
class ScanInvocation:
    """Settings constant across every scan in one hook run. `remote_url`
    is passed explicitly since the scan workspace has no `.git` to
    auto-detect a remote from. `needs_shell` is decided once from
    `snyk_bin` (see lib.proc.needs_shell) -- carried here rather than
    recomputed so every consumer of this invocation agrees."""

    snyk_bin: str
    remote_url: Optional[str] = None
    needs_shell: bool = False


def run_secrets_scan(
    workspace: Path, invocation: ScanInvocation, timeout: Optional[float]
) -> Tuple[ScanStatus, List[Finding]]:
    """Scans the prepared workspace. `timeout=None` means no timeout at
    all (SECRETS_SCAN_TIMEOUT=-1) -- passed straight through to
    subprocess.run, which treats None the same way."""
    cmd = [invocation.snyk_bin, "secrets", "test", ".", "--json"]
    if invocation.remote_url:
        cmd.append(f"--remote-repo-url={invocation.remote_url}")
    try:
        # shell=True only for a .cmd/.bat snyk_bin (see invocation.needs_shell)
        # -- that's what lets cmd.exe launch npm's snyk.cmd shim; a native
        # .exe/extensionless binary never needs one.
        result = run_text(
            cmd,
            cwd=workspace,
            env=_snyk_env(),
            timeout=timeout,
            shell=invocation.needs_shell,
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
        return "unparseable", []
    return "success", findings


# Only "error" (didn't launch, or a non-auth non-zero exit) is treated as
# possibly transient; "unparseable"/"auth_required" won't change on retry.
MAX_SCAN_ATTEMPTS = 3  # one initial attempt plus up to two retries
_RETRYABLE_STATUSES = frozenset({"error"})


@dataclass(frozen=True)
class ScanAttempt:
    status: ScanStatus
    findings: List[Finding]
    attempts: int


def run_secrets_scan_with_retries(
    workspace: Path, invocation: ScanInvocation, deadline: Optional[float]
) -> ScanAttempt:
    """Retries a transient "error" up to twice, all attempts sharing one
    wall-clock `deadline` instead of each getting a fresh timeout.
    `deadline=None` (SECRETS_SCAN_TIMEOUT=-1) means no per-attempt timeout
    either; MAX_SCAN_ATTEMPTS still bounds the retry count. Returns
    "retries_exhausted" (not "error") if every attempt failed."""
    status: ScanStatus = "error"
    findings: List[Finding] = []
    attempts = 0
    while attempts < MAX_SCAN_ATTEMPTS:
        if deadline is None:
            remaining: Optional[float] = None
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return ScanAttempt("timeout", [], attempts)
        attempts += 1
        status, findings = run_secrets_scan(workspace, invocation, remaining)
        if status not in _RETRYABLE_STATUSES:
            return ScanAttempt(status, findings, attempts)
    return ScanAttempt("retries_exhausted", findings, attempts)


# Extra time beyond `deadline` to let a lane's thread return before we give
# up on it (subprocess kill/cleanup overhead).
RESULT_GRACE_SECONDS = 5.0


def run_concurrent_scans(
    current_workspace: Path,
    baseline_workspace: Path,
    invocation: ScanInvocation,
    deadline: Optional[float],
) -> Tuple[ScanAttempt, ScanAttempt]:
    """Runs the current and baseline scans concurrently, each retrying
    independently against the shared `deadline`.

    Both futures are waited on together for at most `RESULT_GRACE_SECONDS`
    beyond `deadline` -- a lane still not done by then is treated as timed
    out rather than blocking forever; the pool shuts down without waiting
    on it (subprocess.run's own timeout is what actually kills the child).

    `deadline=None` (SECRETS_SCAN_TIMEOUT=-1) waits for both lanes to
    finish, however long that takes. Both lanes share one `invocation`,
    so they resolve to the same `--remote-repo-url`."""
    pool = ThreadPoolExecutor(max_workers=2)
    try:
        current_future = pool.submit(
            run_secrets_scan_with_retries, current_workspace, invocation, deadline
        )
        baseline_future = pool.submit(
            run_secrets_scan_with_retries, baseline_workspace, invocation, deadline
        )
        wait_budget = (
            None
            if deadline is None
            else max(0.0, deadline - time.monotonic()) + RESULT_GRACE_SECONDS
        )
        _done, not_done = wait([current_future, baseline_future], timeout=wait_budget)

        def _result_or_timeout(future: "Future[ScanAttempt]") -> ScanAttempt:
            if future in not_done:
                # The lane's own attempt count is unknown (its thread never
                # returned), but it was actively scanning, not idle -- report
                # 1 rather than 0, which would misleadingly read as "no work
                # happened at all."
                return ScanAttempt("timeout", [], 1)
            return future.result()

        return _result_or_timeout(current_future), _result_or_timeout(baseline_future)
    finally:
        pool.shutdown(wait=False)
