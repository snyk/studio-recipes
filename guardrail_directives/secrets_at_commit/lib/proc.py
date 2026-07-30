"""Shared subprocess.run() wrapper for this hook's git/snyk CLI calls."""

import subprocess
import sys
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
