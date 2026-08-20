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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Literal, Optional, Tuple

from . import proc
from .findings import Finding, parse_secrets_results
from .git_ops import is_safe_for_shell

# CLI integration metadata published in _snyk_env() as SNYK_INTEGRATION_*.
# Other Studio hooks carry the same literal today; there is no shared generated
# version source in the installer payload yet.
SNYK_STUDIO_VERSION = "1.0.6"
_SNYK_BINARY_NAMES = ["snyk.cmd", "snyk.exe", "snyk"] if proc.IS_WINDOWS else ["snyk"]

# A resolved path becomes cmd[0] in a shell=True subprocess call when it's a
# .cmd/.bat that needs one (see needs_shell) -- a real path can contain
# spaces/parens/backslashes, but never these, so reject them there rather
# than let cmd.exe reinterpret one. Off that path (native .exe, POSIX),
# there's no shell involved and these characters are just literal bytes.
_SHELL_UNSAFE_RE = re.compile(r'[&|^<>%!"`$;\r\n]')

ScanStatus = Literal["success", "timeout", "error", "unparseable", "retries_exhausted"]

_AUTH_ERROR_PATTERNS = (
    "missingapitokenerror",
    "not authenticated",
    "authentication required",
    "snyk-0005",
    "`snyk auth` to authenticate",
)


# Non-retryable exceptions that always allow the commit.
class NotEntitledError(Exception):
    """Org's Secrets setting is confirmed off."""

    def __init__(self, message: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message


class EntitlementCheckFailedError(Exception):
    """Entitlement lookup failed for a non-auth reason."""

    def __init__(self, message: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message


class AuthRequiredError(Exception):
    """CLI authentication is required; respects the failure policy."""

    def __init__(self, message: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message


class InvalidConfigError(Exception):
    """A Snyk configuration path is unsafe or invalid."""


class PermanentScanFailureError(Exception):
    """A non-retryable CLI validation or limit failure."""

    def __init__(self, fallback: str, message: Optional[str] = None) -> None:
        super().__init__(message or fallback)
        self.fallback = fallback
        self.message = message


# Exceptions a scan worker thread can raise that callers already know how
# to handle -- anything else gets wrapped as UnexpectedScanError instead
# (see run_concurrent_scans) so a genuine bug is never mistaken for one of
# these deliberate, non-retryable cases.
_EXPECTED_SCAN_EXCEPTIONS = (
    NotEntitledError,
    EntitlementCheckFailedError,
    AuthRequiredError,
    PermanentScanFailureError,
)


class UnexpectedScanError(Exception):
    """Wraps any worker-thread exception that isn't one of
    _EXPECTED_SCAN_EXCEPTIONS -- signals a genuine bug, not an anticipated
    CLI failure mode, so main()'s catch-all can tell the two apart."""


_NOT_ENTITLED_PATTERN = "is not supported for org"
_ENTITLEMENT_CHECK_FAILED_PATTERN = "unable to check if the secrets feature is enabled"


def _extract_error_message(stdout: str, stderr: str) -> Optional[str]:
    for blob in (stdout, stderr):
        try:
            parsed = json.loads(blob)
        except ValueError:
            continue
        error = parsed.get("error") if isinstance(parsed, dict) else None
        if isinstance(error, str) and error:
            return error
    return None


@dataclass(frozen=True)
class PermanentFailure:
    """A non-retryable CLI failure, matched by substring."""

    pattern: str  # substring to match in lowercased stderr+stdout
    fallback: str  # shown if the CLI's own error text couldn't be parsed


# Checked in order after auth/entitlement; first match wins.
_PERMANENT_FAILURES = (
    # CLI: "No supported files found."
    PermanentFailure(
        pattern="no supported files found",
        fallback="Snyk couldn't detect any supported files to scan; confirm you are committing "
        "the intended files",
    ),
    # CLI: "File count limit reached: too many files: 550 exceeds limit of 500"
    PermanentFailure(
        pattern="file count limit reached",
        fallback="this commit has more files than Snyk Secrets can scan at once -- "
        "try committing in smaller batches",
    ),
    # CLI: "file big.bin size 900000000 exceeds limit of 800000000 bytes"
    PermanentFailure(
        pattern="exceeds limit of",
        fallback="a file (or the total commit) is too large for Snyk Secrets to scan",
    ),
    # CLI: "Invalid --remote-repo-url: must be a valid git URL (e.g., ...)"
    PermanentFailure(
        pattern="must be a valid git url",
        fallback="the detected git remote URL isn't valid for Snyk Secrets -- check "
        "`git remote get-url origin`",
    ),
    # CLI: "No org provided."
    PermanentFailure(
        pattern="no org provided",
        fallback="Snyk couldn't determine which org to scan against -- run "
        "`snyk config set org=<your-org-id>`, or ask your Snyk administrator",
    ),
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
    if proc.needs_shell(pinned) and _SHELL_UNSAFE_RE.search(pinned):
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
    search = _search_paths_windows(env) if proc.IS_WINDOWS else _search_paths_unix(env)
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
        if found and not (proc.needs_shell(found) and _SHELL_UNSAFE_RE.search(found)):
            return found
    return None


def _snyk_config_path() -> str:
    config_dir = os.environ.get("XDG_CONFIG_HOME")
    if config_dir and (not os.path.isabs(config_dir)):
        raise InvalidConfigError(
            "XDG_CONFIG_HOME must be an absolute path; unset it or set it to an absolute directory"
        )
    if not config_dir:
        config_dir = os.path.join(os.path.expanduser("~"), ".config")
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
        with Path(_snyk_config_path()).open(encoding="utf-8-sig") as f:
            config = json.load(f)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    api_key = config.get("api")
    if api_key and isinstance(api_key, str):
        return api_key
    if config.get("INTERNAL_OAUTH_TOKEN_STORAGE"):
        return "__oauth__"
    return None


def build_snyk_env(snyk_bin: Optional[str] = None) -> Dict[str, str]:
    env = os.environ.copy()
    if snyk_bin:
        _prepend_to_path(env, os.path.dirname(snyk_bin))
    else:
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
    """Raises one of _EXPECTED_SCAN_EXCEPTIONS on a known pattern (see the
    classes' docstrings); anything else returns "error" (retryable)."""
    combined = (stderr + stdout).lower()
    if any(p in combined for p in _AUTH_ERROR_PATTERNS):
        raise AuthRequiredError(_extract_error_message(stdout, stderr))
    if _NOT_ENTITLED_PATTERN in combined:
        raise NotEntitledError(_extract_error_message(stdout, stderr))
    if _ENTITLEMENT_CHECK_FAILED_PATTERN in combined:
        raise EntitlementCheckFailedError(_extract_error_message(stdout, stderr))
    for failure in _PERMANENT_FAILURES:
        if failure.pattern in combined:
            raise PermanentScanFailureError(
                failure.fallback, _extract_error_message(stdout, stderr)
            )
    return "error"


@dataclass(frozen=True)
class ScanInvocation:
    """Settings constant across every scan in one hook run."""

    remote_url: Optional[str] = None
    needs_shell: bool = False
    env: Dict[str, str] = field(default_factory=dict)


def run_secrets_scan(
    workspace: Path, invocation: ScanInvocation, timeout: Optional[float]
) -> Tuple[ScanStatus, List[Finding]]:
    """Scans the prepared workspace. `timeout=None` means no timeout at
    all (SECRETS_SCAN_TIMEOUT=-1) -- passed straight through to
    subprocess.run, which treats None the same way."""
    cmd = ["snyk", "secrets", "test", ".", "--json"]
    remote_url = invocation.remote_url
    if proc.IS_WINDOWS and remote_url and not is_safe_for_shell(remote_url):
        remote_url = None
    if remote_url:
        cmd.append(f"--remote-repo-url={remote_url}")
    try:
        if proc.IS_WINDOWS:
            cmd = ["cmd.exe", "/d", "/s", "/c", subprocess.list2cmdline(cmd)]
        result = subprocess.run(
            cmd,
            cwd=workspace,
            env=invocation.env or build_snyk_env(),
            timeout=timeout,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            shell=False,
            creationflags=proc.CREATE_NO_WINDOW,
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


# Only "error" is treated as possibly transient; every exception raised
# above (auth, entitlement, permanent-failure) skips this by raising
# immediately instead of being returned as a status.
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
            try:
                return future.result()
            except _EXPECTED_SCAN_EXCEPTIONS:
                raise
            except Exception as e:
                raise UnexpectedScanError(f"{type(e).__name__}: {e}") from e

        current = _result_or_timeout(current_future)
        try:
            baseline = _result_or_timeout(baseline_future)
        except _EXPECTED_SCAN_EXCEPTIONS:
            if current.status != "success":
                raise
            # A baseline failure only weakens successful classification.
            baseline = ScanAttempt("error", [], 1)
        return current, baseline
    finally:
        pool.shutdown(wait=False)
