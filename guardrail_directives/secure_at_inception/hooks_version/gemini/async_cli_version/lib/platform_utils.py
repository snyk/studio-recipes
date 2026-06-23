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
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, Generator, Iterator, List, Optional

_IS_WINDOWS = sys.platform == "win32"

STUDIO_VERSION: str = "1.0.6"


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

    Unix path: ``~/.snyk-studio/ades/gemini/ws/<workspace-name>/log.txt``.
    Windows path ``C:\\Users\\<user>\\.snyk-studio\\ades\\gemini\\ws\\<name>\\log.txt``.
    """
    name = _safe_workspace_name(workspace)
    return os.path.join(
        os.path.expanduser("~"), ".snyk-studio", "ades", "gemini", "ws", name, "log.txt"
    )


def scan_duration_secs(scan_info: Optional[Dict[str, Any]]) -> Optional[float]:
    """Return elapsed scan time in seconds from scan_info timestamps, or None."""
    try:
        if scan_info is None:
            return None
        started = scan_info.get("started_at")
        completed = scan_info.get("completed_at")
        if not started or not completed:
            return None
        from datetime import datetime as _dt

        fmt = "%Y-%m-%dT%H:%M:%S.%f"
        fmt_short = "%Y-%m-%dT%H:%M:%S"

        def _parse(s: str) -> _dt:
            try:
                return _dt.strptime(s, fmt)
            except ValueError:
                return _dt.strptime(s, fmt_short)

        return (_parse(completed) - _parse(started)).total_seconds()
    except Exception:
        return None


def log(message: str, log_file: str, *, debug: bool = False) -> None:
    """Append a timestamped line to the persistent log (best-effort).

    Decision-level entries (debug=False) are always written. Debug-level
    entries (debug=True) are written only when GEMINI_HOOK_DEBUG=1. The
    parent dir is created 0700 and the file 0600 on first write. When the
    file exceeds LOG_MAX_BYTES it is atomically rotated to ``<log>.1``.
    Append + rotation are serialized via the cross-platform file_lock on a
    sibling ``<log>.lock`` path (never the log file itself, which file_lock
    would truncate). All exceptions are swallowed so logging never breaks
    the hook.
    """
    if not log_file:
        return
    if debug and os.environ.get("GEMINI_HOOK_DEBUG") != "1":
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
