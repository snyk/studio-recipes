"""Materializes the staged index, or an arbitrary ref, into a temp dir so
a scan sees exactly that content, not the working tree."""

import os
import shutil
import subprocess
import tarfile
import tempfile
from contextlib import contextmanager
from io import BytesIO
from pathlib import Path
from typing import Iterator, List, Optional, Set, Tuple

from .proc import bounded_git_timeout, run_binary, run_text


class SnapshotError(Exception):
    """A snapshot operation failed; `str(exc)` is an actionable, user-facing
    reason -- callers should surface it directly rather than a generic
    fallback message."""


def _create_scratch_dir(prefix: str) -> Path:
    """`tempfile.mkdtemp`, but a failure (disk full, no permission, `TMPDIR`
    pointed somewhere unwritable) raises `SnapshotError` with enough detail
    to actually act on, instead of an opaque `OSError` further up, e.g.:
    "could not create a scratch directory under /tmp (No space left on
    device); check disk space and permissions there, or set TMPDIR to a
    writable location"."""
    try:
        return Path(tempfile.mkdtemp(prefix=prefix))
    except OSError as e:
        raise SnapshotError(
            f"could not create a scratch directory under {tempfile.gettempdir()} "
            f"({e.strerror or e}); check disk space and permissions there, or set "
            "TMPDIR to a writable location"
        ) from e


@contextmanager
def staged_snapshot(
    repo_root: Path, files: List[str], deadline: Optional[float] = None
) -> Iterator[Path]:
    """Checks out the index version of `files` into a fresh temp dir. An
    empty `files` list (never produced today -- callers already skip the
    scan entirely for a no-op commit) just checks out an empty directory,
    not an error. Any real failure raises `SnapshotError`; there is no
    silent-fallback path.

    `deadline`, if given, bounds the `git checkout-index` call to whatever's
    left of a shared wall-clock budget (see `bounded_git_timeout`)."""
    tmp_dir = _create_scratch_dir("snyk-secrets-")
    try:
        try:
            timeout = bounded_git_timeout(deadline)
            if timeout is None:
                raise SnapshotError(
                    "no time left to snapshot staged content -- the shared scan "
                    "deadline already passed"
                )
            # --prefix is always `/`-separated, regardless of platform.
            result = run_text(
                ["git", "checkout-index", f"--prefix={tmp_dir.as_posix()}/", "--", *files],
                cwd=repo_root,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as e:
            raise SnapshotError("git checkout-index timed out snapshotting staged content") from e
        except OSError as e:
            raise SnapshotError(f"could not run git checkout-index ({e.strerror or e})") from e
        if result.returncode != 0:
            raise SnapshotError(
                "could not snapshot staged content (git checkout-index failed): "
                f"{result.stderr.strip()}"
            )
        yield tmp_dir
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _existing_at_ref(
    repo_root: Path, ref: str, files: List[str], deadline: Optional[float] = None
) -> Set[str]:
    """Subset of `files` that exist at `ref`. `git archive` (below) aborts
    entirely on an unmatched pathspec; `git ls-tree` just omits it."""
    timeout = bounded_git_timeout(deadline)
    if timeout is None:
        return set()
    try:
        result = run_text(
            ["git", "ls-tree", "-r", "--name-only", "-z", ref, "--", *files],
            cwd=repo_root,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    if result.returncode != 0:
        return set()
    return {p for p in result.stdout.split("\0") if p}


def _extract_archive(archive_bytes: bytes, dest: Path) -> bool:
    """Extracts a `git archive` tar stream into `dest`. False on error."""
    try:
        with tarfile.open(fileobj=BytesIO(archive_bytes)) as tar:
            _extract_defensively(tar, dest)
    except (tarfile.TarError, OSError):
        return False
    return True


def _extract_defensively(tar: tarfile.TarFile, dest: Path) -> None:
    """Extract regular archive members into `dest` after validating paths."""
    dest = dest.resolve()
    for member in tar.getmembers():
        if member.type in (tarfile.XHDTYPE, tarfile.XGLTYPE):
            continue  # pax header metadata (e.g. git's pax_global_header), not real content
        if not (member.isfile() or member.isdir()):
            raise tarfile.TarError(f"refusing to extract non-regular member: {member.name}")
        target = (dest / member.name).resolve()
        if target != dest and dest not in target.parents:
            raise tarfile.TarError(f"refusing to extract path outside destination: {member.name}")
        permissions = member.mode & 0o777
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True, mode=permissions)
            target.chmod(permissions)
            continue
        source = tar.extractfile(member)
        if source is None:
            raise tarfile.TarError(f"could not read archive member: {member.name}")
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(dir=str(target.parent), prefix=f".{target.name}.")
        temp_path = Path(temp_name)
        try:
            with source, os.fdopen(fd, "wb") as output:
                shutil.copyfileobj(source, output)
            os.replace(temp_path, target)
        except BaseException:
            temp_path.unlink(missing_ok=True)
            raise
        target.chmod(permissions)


@contextmanager
def ref_snapshot(
    repo_root: Path, ref: str, files: List[str], deadline: Optional[float] = None
) -> Iterator[Tuple[Optional[Path], Set[str], bool]]:
    """Checks out `files` as they existed at `ref` into a fresh temp dir.
    Yields `(tmp_dir, existing_files, False)` on success, else `(None,
    set(), failed)`.

    A baseline is a nice-to-have, not a requirement -- unlike
    `staged_snapshot`, every failure here degrades to no-baseline rather
    than raising. `failed` says why: `False` means nothing was attempted
    (nothing scoped at `ref`, or the deadline was already gone); `True`
    means a snapshot was attempted and broke, which callers should
    surface rather than stay quiet about.

    `deadline`, if given, bounds every git call here to whatever's left of
    a shared wall-clock budget (see `bounded_git_timeout`)."""
    if not files:
        yield None, set(), False
        return

    existing = _existing_at_ref(repo_root, ref, files, deadline)
    if not existing:
        yield None, set(), False
        return

    try:
        tmp_dir = _create_scratch_dir("snyk-secrets-baseline-")
    except SnapshotError:
        yield None, set(), True
        return
    try:
        timeout = bounded_git_timeout(deadline)
        if timeout is None:
            # Files were confirmed to exist at `ref` above -- a baseline
            # was attempted, not skipped, it just ran out of shared budget
            # before `git archive` could run. That's the "broke" case, not
            # "nothing to do."
            yield None, set(), True
            return
        try:
            archive = run_binary(
                ["git", "archive", ref, "--", *sorted(existing)], cwd=repo_root, timeout=timeout
            )
        except (OSError, subprocess.TimeoutExpired):
            yield None, set(), True
            return
        if archive.returncode != 0 or not _extract_archive(archive.stdout, tmp_dir):
            yield None, set(), True
            return
        yield tmp_dir, existing, False
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
