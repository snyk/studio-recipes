#!/usr/bin/env python3
"""
Platform Utilities
==================

Centralizes all platform-specific logic so that scan_runner, scan_worker,
and snyk_secure_at_inception remain cross-platform without inline conditionals.

Windows vs Unix differences handled:
  - Detached subprocess creation (start_new_session vs creationflags)
  - Process liveness checking (os.kill vs kernel32.OpenProcess)
  - Snyk binary search paths (nvm, Volta, Homebrew, Scoop, etc.)
  - File locking (fcntl vs msvcrt)
  - Path separator normalization
"""

import glob
import hashlib
import os
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Generator, Iterator, List, Optional, Tuple

_IS_WINDOWS = sys.platform == "win32"

STUDIO_VERSION: str = "1.0.17"

# Console apps (snyk / the cmd.exe shim) spawned from a windowless background
# worker allocate a new console window on Windows; CREATE_NO_WINDOW suppresses
# the flash. The flag only exists on Windows; elsewhere this is 0 (subprocess's
# default creationflags, i.e. a no-op).
_CREATE_NO_WINDOW = subprocess.CREATE_NO_WINDOW if _IS_WINDOWS else 0  # type: ignore[attr-defined]


# =============================================================================
# DETACHED SUBPROCESS CREATION
# =============================================================================


def get_detached_popen_kwargs() -> Dict[str, object]:
    """Return Popen kwargs for launching a detached background process."""
    if _IS_WINDOWS:
        return {
            "creationflags": (
                subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
                | subprocess.DETACHED_PROCESS  # type: ignore[attr-defined]
            ),
        }
    return {"start_new_session": True}


# =============================================================================
# SNYK CLI SUBPROCESS RETRY
# =============================================================================

_TRANSIENT_NETWORK_PATTERNS: Tuple[str, ...] = (
    "connection reset by peer",
    "read: connection reset",
    "econnreset",
    "broken pipe",
    "epipe",
    "connection refused",
    "econnrefused",
    "no such host",
    "name or service not known",
    "getaddrinfo",
    "tls handshake timeout",
    "handshake failure",
    "tls: use of closed connection",
    "etimedout",
    "i/o timeout",
    "connection timed out",
    "unexpected eof",
    "502 bad gateway",
    "503 service unavailable",
    "504 gateway timeout",
)

_RETRY_BACKOFFS_SECONDS: Tuple[int, ...] = (5, 15)

# Substrings the Snyk CLI emits when the stored OAuth/API token was rejected
# server-side. Matched case-insensitively against combined stderr+stdout.
_AUTH_ERROR_PATTERNS: Tuple[str, ...] = (
    "missingapitokenerror",
    "not authenticated",
    "authentication required",
    "snyk-0005",
    # `snyk code test` with a stale token answers
    # {"ok": false, "error": "Use `snyk auth` to authenticate.", ...} on stdout,
    # which none of the patterns above match. Getting this wrong now costs more
    # than it used to: auth_required is the one status the stop hook can offer a
    # recovery for, so a misclassified auth failure reads to the user as an
    # opaque CLI error.
    "snyk auth",
)

# Short backoff before the single auth-retry: long enough for a sibling
# `snyk` process that just won the OAuth refresh race to persist the new
# refresh_token to configstore, short enough to be invisible in a real scan.
_AUTH_RETRY_BACKOFF_SECONDS = 0.25


def is_transient_network_error(text: str) -> bool:
    lowered = text.lower()
    return any(pattern in lowered for pattern in _TRANSIENT_NETWORK_PATTERNS)


def is_auth_error(text: str) -> bool:
    lowered = text.lower()
    return any(pattern in lowered for pattern in _AUTH_ERROR_PATTERNS)


def with_attempts(detail: str, attempts: int) -> str:
    """Prefix a worker error detail with the retry count, when there was one.

    run_snyk_with_retry returns the attempt count; every status a worker can
    report off the back of it wants to say so, so the formatting lives next to
    the function that produces the number.
    """
    return f"(after {attempts} attempts) {detail}" if attempts > 1 else detail


def run_snyk_with_retry(
    cmd: List[str],
    env: Dict[str, str],
    cwd: str,
    log_fn: Optional[Callable[[str], None]] = None,
    auth_retry: bool = False,
) -> Tuple[int, str, str, int]:
    """Returns (exit_code, stdout, stderr, attempts_used).

    Retries on transient-network patterns up to len(_RETRY_BACKOFFS_SECONDS)
    additional times. When ``auth_retry=True``, also retries exactly once on
    an auth-flavored stderr — this covers the loser side of a concurrent
    OAuth-refresh race (rotating refresh_token, sibling `snyk` process just
    got a fresh access_token into the configstore) and brief mid-scan token
    expiries the CLI could not re-refresh in-flight.

    That auth retry is additive rather than borrowed: it gets its own extra
    attempt instead of consuming one from the transient-network budget, so an
    auth failure landing on the last scheduled attempt is still retried.

    Propagates subprocess.TimeoutExpired — a 300s hang means the CLI is
    genuinely stuck, not flaking, and retrying would just multiply the
    wait.
    """
    total_attempts = len(_RETRY_BACKOFFS_SECONDS) + 1
    result = None
    auth_backoff_attempted = False
    # The single auth retry is a bonus attempt, not one borrowed from the
    # transient-network budget: an auth error arriving on what would have been
    # the final attempt still has to get its retry, or the spurious
    # "not authenticated" this flag exists to suppress leaks through anyway.
    max_attempts = total_attempts
    attempt = 0
    while attempt < max_attempts:
        attempt += 1
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
            cwd=cwd,
            env=env,
            shell=False,
            creationflags=_CREATE_NO_WINDOW,
        )
        if result.returncode <= 1:
            return result.returncode, result.stdout, result.stderr, attempt
        combined = (result.stderr or "") + (result.stdout or "")
        if auth_retry and not auth_backoff_attempted and is_auth_error(combined):
            max_attempts = max(max_attempts, attempt + 1)
            if log_fn is not None:
                log_fn(
                    f"Attempt {attempt}/{max_attempts} hit auth error, "
                    f"retrying once after {_AUTH_RETRY_BACKOFF_SECONDS}s "
                    f"(concurrent OAuth refresh or brief mid-scan expiry)"
                )
            time.sleep(_AUTH_RETRY_BACKOFF_SECONDS)
            # Set only once the backoff has actually been served, so the flag
            # always reads as "the one auth retry has been spent".
            auth_backoff_attempted = True
            continue
        if not is_transient_network_error(combined):
            return result.returncode, result.stdout, result.stderr, attempt
        if attempt < max_attempts:
            backoff = _RETRY_BACKOFFS_SECONDS[attempt - 1]
            if log_fn is not None:
                snippet = (result.stderr or "").strip().splitlines()
                snippet_str = snippet[0][:120] if snippet else ""
                log_fn(
                    f"Attempt {attempt}/{max_attempts} hit transient network error "
                    f"({snippet_str!r}), retrying in {backoff}s"
                )
            time.sleep(backoff)
    assert result is not None
    return result.returncode, result.stdout, result.stderr, attempt


# =============================================================================
# PROCESS LIVENESS CHECK
# =============================================================================


def is_pid_alive(pid: int) -> bool:
    """Check whether a process with the given PID is still running."""
    if _IS_WINDOWS:
        return _is_pid_alive_windows(pid)
    return _is_pid_alive_unix(pid)


def _is_pid_alive_windows(pid: int) -> bool:
    import ctypes

    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    SYNCHRONIZE = 0x00100000
    handle = kernel32.OpenProcess(SYNCHRONIZE, False, pid)
    if handle:
        kernel32.CloseHandle(handle)
        return True
    return False


def _is_pid_alive_unix(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        # Process exists but we lack permission to signal it.
        return True


# =============================================================================
# PROCESS TREE TERMINATION
# =============================================================================


def terminate_process_tree(pid: int) -> None:
    """Terminate a process and any children it spawned.

    Signalling only ``pid`` is not enough here: the worker spends most of its
    life blocked in a subprocess.run() call waiting on the real ``snyk``
    child, and killing just the parent leaves that child running, orphaned,
    doing real scan work with nothing left to reap it. Workers are launched
    detached into their own session/process group (see
    get_detached_popen_kwargs), so on POSIX the whole tree shares one pgid
    and a single killpg reaches it. Windows has no process-group signal;
    instead the worker binds itself (and any child it spawns) to a
    KILL_ON_JOB_CLOSE job object at startup (see
    ensure_process_in_kill_on_close_job), so simply terminating the worker's
    own PID is enough -- Windows tears down the whole job the moment its last
    handle closes, which also covers a worker that dies some other way
    (crash, force-kill) without anyone calling this function at all.
    """
    if _IS_WINDOWS:
        _terminate_process_tree_windows(pid)
    else:
        _terminate_process_tree_unix(pid)


def _terminate_process_tree_unix(pid: int) -> None:
    import signal

    try:
        pgid = os.getpgid(pid)
    except OSError:
        return
    try:
        os.killpg(pgid, signal.SIGTERM)
    except OSError:
        pass


def _terminate_process_tree_windows(pid: int) -> None:
    import signal

    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass


# =============================================================================
# WINDOWS JOB OBJECT (kill-on-close)
# =============================================================================

_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9

# Kept alive for the lifetime of the process once set: closing the last
# handle to the job is what triggers KILL_ON_JOB_CLOSE, so this must never be
# allowed to go out of scope (and be garbage-collected/closed) while the
# worker is still meant to be protected.
_job_handle_keepalive: Optional[int] = None


def _build_job_object_structs() -> type:
    """Defines the ctypes structs lazily so importing this module never
    touches ctypes.Structure on a platform where it might behave oddly.
    Field layouts match WinNT.h; sizes/order are ABI-stable and unchanged
    since Windows NT."""
    import ctypes

    class IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_uint64),
            ("WriteOperationCount", ctypes.c_uint64),
            ("OtherOperationCount", ctypes.c_uint64),
            ("ReadTransferCount", ctypes.c_uint64),
            ("WriteTransferCount", ctypes.c_uint64),
            ("OtherTransferCount", ctypes.c_uint64),
        ]

    class JobObjectBasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", ctypes.c_uint32),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", ctypes.c_uint32),
            ("Affinity", ctypes.c_void_p),
            ("PriorityClass", ctypes.c_uint32),
            ("SchedulingClass", ctypes.c_uint32),
        ]

    class JobObjectExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JobObjectBasicLimitInformation),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    return JobObjectExtendedLimitInformation


def ensure_process_in_kill_on_close_job() -> None:
    """Bind this process (and any child it later spawns) to a Windows Job
    Object with KILL_ON_JOB_CLOSE, so the whole tree dies the moment this
    process's job handle closes -- on clean exit, on being killed by
    cancel_scan/cancel_sca_scan (terminate_process_tree), or on an
    ungraceful crash that never runs any cleanup code at all. Child
    processes join their creator's job automatically unless they opt out
    with CREATE_BREAKAWAY_FROM_JOB, which this codebase never sets.

    No-op on non-Windows. Best-effort: any failure (old Windows version,
    security software blocking job creation, an ABI surprise) is swallowed
    and the worker proceeds unprotected, exactly like before this existed.
    Must be called before the snyk subprocess is spawned.
    """
    global _job_handle_keepalive
    if not _IS_WINDOWS:
        return
    try:
        import ctypes

        JobObjectExtendedLimitInformation = _build_job_object_structs()

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel32.CreateJobObjectW.restype = ctypes.c_void_p
        kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p)
        kernel32.SetInformationJobObject.restype = ctypes.c_int
        kernel32.SetInformationJobObject.argtypes = (
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        )
        kernel32.AssignProcessToJobObject.restype = ctypes.c_int
        kernel32.AssignProcessToJobObject.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.GetCurrentProcess.argtypes = ()
        kernel32.CloseHandle.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)

        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            return

        info = JobObjectExtendedLimitInformation()
        info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        ok = kernel32.SetInformationJobObject(
            job,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not ok:
            kernel32.CloseHandle(job)
            return

        if not kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess()):
            kernel32.CloseHandle(job)
            return

        _job_handle_keepalive = job
    except OSError:
        pass


# =============================================================================
# SNYK BINARY SEARCH PATHS
# =============================================================================


def get_snyk_search_paths(env: Dict[str, str]) -> List[str]:
    """Return candidate directories where the Snyk CLI binary may reside."""
    if _IS_WINDOWS:
        return _get_snyk_search_paths_windows(env)
    return _get_snyk_search_paths_unix(env)


def _get_snyk_search_paths_windows(env: Dict[str, str]) -> List[str]:
    candidates: List[str] = []

    # nvm-windows: %APPDATA%\nvm\v*
    appdata = env.get("APPDATA", os.environ.get("APPDATA", ""))
    if appdata:
        nvm_root = os.path.join(appdata, "nvm")
        candidates.extend(sorted(glob.glob(os.path.join(nvm_root, "v*")), reverse=True))
        # npm global bin
        candidates.append(os.path.join(appdata, "npm"))

    # Volta on Windows: %LOCALAPPDATA%\Volta\bin
    local_appdata = env.get("LOCALAPPDATA", os.environ.get("LOCALAPPDATA", ""))
    if local_appdata:
        candidates.append(os.path.join(local_appdata, "Volta", "bin"))

    # Scoop: %USERPROFILE%\scoop\shims
    userprofile = env.get("USERPROFILE", os.environ.get("USERPROFILE", ""))
    if userprofile:
        candidates.append(os.path.join(userprofile, "scoop", "shims"))

    # Chocolatey: %ChocolateyInstall%\bin
    choco = env.get("ChocolateyInstall", os.environ.get("ChocolateyInstall", ""))
    if choco:
        candidates.append(os.path.join(choco, "bin"))

    # Standalone Snyk installer: %ProgramFiles%\Snyk
    program_files = env.get("ProgramFiles", os.environ.get("ProgramFiles", ""))
    if program_files:
        candidates.append(os.path.join(program_files, "Snyk"))

    return candidates


def _get_snyk_search_paths_unix(env: Dict[str, str]) -> List[str]:
    candidates: List[str] = []

    # NVM
    nvm_dir = env.get("NVM_DIR", os.path.expanduser("~/.nvm"))
    nvm_node_bins = sorted(
        glob.glob(os.path.join(nvm_dir, "versions", "node", "*", "bin")),
        reverse=True,
    )
    candidates.extend(nvm_node_bins)

    # Volta
    candidates.append(os.path.expanduser("~/.volta/bin"))

    # System paths
    candidates.extend(["/usr/local/bin", "/opt/homebrew/bin"])

    return candidates


# =============================================================================
# SNYK BINARY NAMES
# =============================================================================


def get_snyk_binary_names() -> List[str]:
    """Return the possible filenames for the Snyk CLI."""
    return ["snyk.cmd", "snyk.exe", "snyk"]


def needs_shell(binary_path: str) -> bool:
    """True only when launching ``binary_path`` requires cmd.exe's own parsing.

    Windows reroutes .cmd/.bat targets (e.g. an npm-installed ``snyk.cmd``
    shim) through cmd.exe regardless of how the caller invokes them; a native
    .exe launches directly via CreateProcess, no shell involved at all. This
    keeps ``shell=True`` (and the extra cmd.exe hop it spawns) scoped to the
    one case that actually needs it, instead of every Windows invocation.
    """
    return _IS_WINDOWS and binary_path.lower().endswith((".cmd", ".bat"))


# =============================================================================
# INSTALLER SIDECAR
# =============================================================================


_CLI_PATH_SIDECAR = os.path.join(os.path.expanduser("~"), ".snyk-studio", "cli-path")


def snyk_cli_from_sidecar() -> Optional[str]:
    """Return the absolute Snyk CLI path pinned by the installer.

    Reads ``~/.snyk-studio/cli-path`` (written for npm-managed and
    user-specified installs). Returns ``None`` if the sidecar is missing or the
    recorded path is not executable. Callers use this before falling back to
    ``PATH`` so installer-managed Snyk works even when ``snyk`` isn't on the
    IDE-inherited PATH.
    """
    try:
        with open(_CLI_PATH_SIDECAR, encoding="utf-8-sig") as f:
            pinned = f.read().strip()
    except (FileNotFoundError, OSError, UnicodeDecodeError):
        return None
    if not pinned:
        return None
    expanded = os.path.expanduser(pinned)
    if os.path.isabs(expanded) and os.path.isfile(expanded) and os.access(expanded, os.X_OK):
        return os.path.abspath(expanded)
    return None


def prepend_to_path(env: Dict[str, str], bin_dir: str) -> None:
    """Put ``bin_dir`` first on PATH, removing duplicates and empty entries."""
    entries = [p for p in env.get("PATH", "").split(os.pathsep) if p and p != bin_dir]
    env["PATH"] = os.pathsep.join([bin_dir, *entries])


# =============================================================================
# FILE LOCKING
# =============================================================================


@contextmanager
def file_lock(lock_path: str) -> Iterator[None]:
    """Cross-platform exclusive file lock.

    Uses fcntl on Unix and msvcrt on Windows.
    Falls back to a no-op if neither is available.
    """
    if _IS_WINDOWS:
        yield from _file_lock_windows(lock_path)
    else:
        yield from _file_lock_unix(lock_path)


def _file_lock_windows(lock_path: str) -> Generator[None, None, None]:
    import msvcrt

    fd = open(lock_path, "w")
    try:
        msvcrt.locking(fd.fileno(), msvcrt.LK_LOCK, 1)  # type: ignore[attr-defined]
        yield
    finally:
        try:
            msvcrt.locking(fd.fileno(), msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]
        except OSError:
            pass
        fd.close()


def _file_lock_unix(lock_path: str) -> Generator[None, None, None]:
    try:
        import fcntl
    except ImportError:
        # Platform has neither fcntl nor msvcrt — no-op.
        yield
        return

    fd = open(lock_path, "w")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        fd.close()


# =============================================================================
# SNYK CONFIG PATH
# =============================================================================


def get_snyk_config_path() -> str:
    """Return the path to the Snyk CLI config file.

    Mirrors the configstore npm package the Snyk CLI bundles, which takes its
    directory from xdg-basedir: XDG_CONFIG_HOME, else ~/.config. xdg-basedir
    has no Windows branch, so this is ~/.config/configstore/snyk.json on every
    platform, Windows included. XDG_CONFIG_HOME is honoured because the CLI
    honours it -- ignoring it reports auth_required for an authenticated user.
    """
    config_home = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return str(Path(config_home) / "configstore" / "snyk.json")


# =============================================================================
# PATH NORMALIZATION
# =============================================================================


def normalize_path(path: str) -> str:
    """Normalize a file path for cross-platform comparison.

    Converts backslashes to forward slashes, strips leading ./ and /.
    """
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path.lstrip("/")


# =============================================================================
# PERSISTENT LOGGING
# =============================================================================

# 1 MiB cap; on overflow the log rotates a single generation to log.txt.1,
# keeping total on-disk usage at ~2 MiB.
LOG_MAX_BYTES = 1 * 1024 * 1024


def workspace_hash(workspace: str) -> str:
    """Short hash of a workspace path, used to name the temp cache directory."""
    return hashlib.sha256(workspace.encode()).hexdigest()[:8]


def _safe_workspace_name(workspace: str) -> str:
    """Filesystem-safe basename of the workspace directory."""
    base = os.path.basename(os.path.normpath(workspace))
    safe = "".join(c if (c.isalnum() or c in "-_.") else "-" for c in base)
    return safe or "workspace"


def resolve_log_file(workspace: str) -> str:
    """Resolve the persistent log path for a workspace.

    Unix path: ``~/.snyk-studio/ades/copilot/ws/<workspace-name>/log.txt``.
    Windows path ``C:\\Users\\<user>\\.snyk-studio\\ades\\copilot\\ws\\<name>\\log.txt``.
    """
    name = _safe_workspace_name(workspace)
    return os.path.join(
        os.path.expanduser("~"), ".snyk-studio", "ades", "copilot", "ws", name, "log.txt"
    )


def parse_iso_timestamp(value: Optional[str]) -> Optional[datetime]:
    """Parse common ISO-8601 timestamp variants used by the hook and workers."""
    if not value:
        return None

    normalized = value.strip()
    if not normalized:
        return None
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        pass

    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(normalized, fmt)
        except ValueError:
            continue

    return None


def scan_duration_secs(scan_info: Optional[Dict[str, Any]]) -> Optional[float]:
    """Return elapsed scan time in seconds from scan_info timestamps, or None."""
    try:
        if scan_info is None:
            return None
        started = scan_info.get("started_at")
        completed = scan_info.get("completed_at")
        if not started or not completed:
            return None
        started_at = parse_iso_timestamp(started)
        completed_at = parse_iso_timestamp(completed)
        if started_at is None or completed_at is None:
            return None
        return (completed_at - started_at).total_seconds()
    except Exception:
        return None


def log(message: str, log_file: str, *, debug: bool = False) -> None:
    """Append a timestamped line to the persistent log (best-effort).

    Decision-level entries (debug=False) are always written. Debug-level
    entries (debug=True) are written only when COPILOT_HOOK_DEBUG=1. The
    parent dir is created 0700 and the file 0600 on first write. When the
    file exceeds LOG_MAX_BYTES it is atomically rotated to ``<log>.1``.
    Append + rotation are serialized via the cross-platform file_lock on a
    sibling ``<log>.lock`` path (never the log file itself, which file_lock
    would truncate). All exceptions are swallowed so logging never breaks
    the hook.
    """
    if not log_file:
        return
    if debug and os.environ.get("COPILOT_HOOK_DEBUG") != "1":
        return
    try:
        # Restrictive perms (dir 0700, file 0600) are set via the explicit mode
        # arguments to os.makedirs and os.open. Both modes have no group/other
        # bits so no umask value can widen them — no umask manipulation needed.
        parent = os.path.dirname(log_file)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, mode=0o700, exist_ok=True)
        with file_lock(log_file + ".lock"):
            try:
                if os.path.getsize(log_file) > LOG_MAX_BYTES:
                    os.replace(log_file, log_file + ".1")
            except FileNotFoundError:
                pass
            line = f"[{datetime.now().isoformat()}] {message}\n"
            fd = os.open(log_file, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
            try:
                os.write(fd, line.encode("utf-8", "replace"))
            finally:
                os.close(fd)
    except Exception:
        pass
