"""Always-on, per-repo persistent log -- adopts the SAI hooks' own
`~/.snyk-studio/.../ws/<name>/log.txt` framework verbatim (see
`secure_at_inception`'s `platform_utils.py`), at a path specific to this
hook. Non-configurable: no env override, no opt-out.

Append-only, best-effort, rotated at 1 MiB, lock-serialized so concurrent
commits against the same repo don't clobber each other.
"""

import os
import sys
from contextlib import contextmanager
from datetime import datetime
from typing import Generator, Iterator

_IS_WINDOWS = sys.platform == "win32"

# On overflow the log rotates a single generation to log.txt.1.
LOG_MAX_BYTES = 1 * 1024 * 1024


@contextmanager
def file_lock(lock_path: str) -> Iterator[None]:
    """Cross-platform exclusive file lock (fcntl on Unix, msvcrt on
    Windows); no-op if neither is available."""
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
        yield  # no fcntl or msvcrt -- no-op
        return

    fd = open(lock_path, "w")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        fd.close()


def _safe_workspace_name(workspace: str) -> str:
    """Filesystem-safe basename of the workspace directory."""
    base = os.path.basename(os.path.normpath(workspace))
    safe = "".join(c if (c.isalnum() or c in "-_.") else "-" for c in base)
    return safe or "workspace"


def resolve_log_file(repo_root: str) -> str:
    """``~/.snyk-studio/git-hooks/secrets-hooks/ws/<repo-name>/log.txt``."""
    name = _safe_workspace_name(repo_root)
    return os.path.join(
        os.path.expanduser("~"),
        ".snyk-studio",
        "git-hooks",
        # Deliberately not the recipe id: this directory name predates the
        # rename to secrets-precommit-hook, and changing it would orphan logs
        # already on disk that the diagnostic bundle collects by walking the
        # log root. Nothing derives this literal from the manifest.
        "secrets-hooks",
        "ws",
        name,
        "log.txt",
    )


def append_log(message: str, log_file: str) -> None:
    """Appends a timestamped line to the persistent log; never raises."""
    if not log_file:
        return
    try:
        # umask, not chmod-after-create: avoids a TOCTOU window.
        parent = os.path.dirname(log_file)
        old_umask = os.umask(0o077)
        try:
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
        finally:
            os.umask(old_umask)
    except Exception:
        pass
