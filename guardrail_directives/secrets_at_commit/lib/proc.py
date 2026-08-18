"""Shared subprocess.run() wrapper for this hook's git/snyk CLI calls."""

import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

IS_WINDOWS = sys.platform == "win32"

# subprocess.CREATE_NO_WINDOW only exists on Windows; must be an `if
# sys.platform ==` block (not a ternary) or mypy flags it on other platforms.
CREATE_NO_WINDOW = 0
if sys.platform == "win32":
    CREATE_NO_WINDOW = subprocess.CREATE_NO_WINDOW

# Bounds every plumbing git call (diff/checkout-index/ls-tree/archive) so a
# stuck git process (hung lock, slow network mount, etc.) can't hang the
# whole commit indefinitely -- these are metadata/local-object operations,
# not network calls, so seconds not minutes is the right order of magnitude.
GIT_TIMEOUT = 15.0


def quote_for_paste(value: str) -> str:
    """Quotes `value` for a hint the user copy-pastes into a terminal.

    Always POSIX quoting, not gated on `IS_WINDOWS` -- that's the hook's
    own OS, not the shell a human pastes into later, and cmd-style
    double-quoting wouldn't stop backticks/`$(...)` in Git Bash, which is
    common on Windows too."""
    return shlex.quote(value)


def needs_shell(binary_path: str) -> bool:
    """True only when launching `binary_path` requires cmd.exe's own
    parsing -- Windows reroutes .cmd/.bat targets through cmd.exe
    regardless of how the caller invokes them, but a native .exe or
    extensionless binary launches directly via CreateProcess, no shell
    involved at all."""
    return IS_WINDOWS and binary_path.lower().endswith((".cmd", ".bat"))


def bounded_git_timeout(deadline: Optional[float]) -> Optional[float]:
    """The timeout to use for one git subprocess call: `GIT_TIMEOUT` with
    no `deadline`, otherwise whatever's left of a shared wall-clock budget
    (a `time.monotonic()` value), capped at `GIT_TIMEOUT`. Returns None if
    the budget is already gone -- callers must treat that as an immediate
    failure, no process spawned."""
    if deadline is None:
        return GIT_TIMEOUT
    remaining = deadline - time.monotonic()
    return min(GIT_TIMEOUT, remaining) if remaining > 0 else None


def run_text(
    args: List[str],
    *,
    cwd: Optional[Path] = None,
    timeout: Optional[float] = None,
    env: Optional[Dict[str, str]] = None,
    shell: bool = False,
) -> "subprocess.CompletedProcess[str]":
    """subprocess.run, decoded as UTF-8 text (errors="replace") instead of
    the OS locale default. May raise OSError or subprocess.TimeoutExpired."""
    return subprocess.run(
        args,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=timeout,
        check=False,
        shell=shell,
        creationflags=CREATE_NO_WINDOW,
    )


def run_binary(
    args: List[str], *, cwd: Optional[Path] = None, timeout: Optional[float] = None
) -> "subprocess.CompletedProcess[bytes]":
    """Like run_text, but raw bytes -- for `git archive`'s tar stream."""
    return subprocess.run(
        args,
        cwd=cwd,
        capture_output=True,
        timeout=timeout,
        check=False,
        creationflags=CREATE_NO_WINDOW,
    )
