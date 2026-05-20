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
import os
import subprocess
import sys
from contextlib import contextmanager
from typing import Dict, List

_IS_WINDOWS = sys.platform == "win32"


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
def file_lock(lock_path: str):
    """Cross-platform exclusive file lock.

    Uses fcntl on Unix and msvcrt on Windows.
    Falls back to a no-op if neither is available.
    """
    if _IS_WINDOWS:
        yield from _file_lock_windows(lock_path)
    else:
        yield from _file_lock_unix(lock_path)


def _file_lock_windows(lock_path: str):
    import msvcrt

    fd = open(lock_path, "w")
    try:
        msvcrt.locking(fd.fileno(), msvcrt.LK_LOCK, 1)
        yield
    finally:
        try:
            msvcrt.locking(fd.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        fd.close()


def _file_lock_unix(lock_path: str):
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
