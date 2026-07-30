"""Materializes the staged index, or an arbitrary ref, into a temp dir so
a scan sees exactly that content, not the working tree."""

import shutil
import subprocess
import sys
import tarfile
import tempfile
from contextlib import contextmanager
from io import BytesIO
from pathlib import Path
from typing import Iterator, List, Optional, Set, Tuple

from .proc import GIT_TIMEOUT, run_binary, run_text


@contextmanager
def staged_snapshot(repo_root: Path, files: List[str]) -> Iterator[Optional[Path]]:
    """Checks out the index version of `files` into a fresh temp dir.
    Yields None on failure; the caller decides whether to fail closed or
    use an explicit working-tree fallback."""
    if not files:
        yield None
        return
    tmp_dir = Path(tempfile.mkdtemp(prefix="snyk-secrets-"))
    try:
        try:
            # --prefix is always `/`-separated, regardless of platform.
            result = run_text(
                ["git", "checkout-index", f"--prefix={tmp_dir.as_posix()}/", "--", *files],
                cwd=repo_root,
                timeout=GIT_TIMEOUT,
            )
        except (OSError, subprocess.TimeoutExpired):
            result = None
        yield tmp_dir if result is not None and result.returncode == 0 else None
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _safe_snapshot_path(snapshot_root: Path, file_path: str) -> Optional[Path]:
    rel_path = Path(file_path)
    if rel_path.is_absolute() or ".." in rel_path.parts:
        return None
    target = snapshot_root / rel_path
    try:
        target.resolve().relative_to(snapshot_root.resolve())
    except (OSError, ValueError):
        return None
    return target


def _copy_working_tree_file(repo_root: Path, tmp_dir: Path, file_path: str) -> bool:
    source = _safe_snapshot_path(repo_root, file_path)
    dest = _safe_snapshot_path(tmp_dir, file_path)
    if source is None or dest is None:
        return False
    try:
        if not source.is_file():
            return False
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, dest)
    except OSError:
        return False
    return True


@contextmanager
def working_tree_snapshot(repo_root: Path, files: List[str]) -> Iterator[Optional[Path]]:
    """Copies the working-tree version of `files` into a fresh temp dir.
    This is only for the explicit staged-snapshot fallback path: less
    accurate than the index, but still scoped to the filtered file list and
    still never scans the original repository root."""
    if not files:
        yield None
        return
    tmp_dir = Path(tempfile.mkdtemp(prefix="snyk-secrets-working-tree-"))
    try:
        if all(_copy_working_tree_file(repo_root, tmp_dir, file_path) for file_path in files):
            yield tmp_dir
        else:
            yield None
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _existing_at_ref(repo_root: Path, ref: str, files: List[str]) -> Set[str]:
    """Subset of `files` that exist at `ref`. `git archive` (below) aborts
    entirely on an unmatched pathspec; `git ls-tree` just omits it."""
    try:
        result = run_text(
            ["git", "ls-tree", "-r", "--name-only", "-z", ref, "--", *files],
            cwd=repo_root,
            timeout=GIT_TIMEOUT,
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
            if sys.version_info >= (3, 12):
                tar.extractall(dest, filter="data")
            else:
                _extract_defensively(tar, dest)
    except (tarfile.TarError, OSError):
        return False
    return True


def _extract_defensively(tar: tarfile.TarFile, dest: Path) -> None:
    """Pre-3.12 stand-in for `filter="data"` (PEP 706): rejects path
    traversal/non-regular members, strips setuid bits, raises TarError."""
    dest = dest.resolve()
    for member in tar.getmembers():
        if member.type in (tarfile.XHDTYPE, tarfile.XGLTYPE):
            continue  # pax header metadata (e.g. git's pax_global_header), not real content
        if not (member.isfile() or member.isdir()):
            raise tarfile.TarError(f"refusing to extract non-regular member: {member.name}")
        target = (dest / member.name).resolve()
        if target != dest and dest not in target.parents:
            raise tarfile.TarError(f"refusing to extract path outside destination: {member.name}")
        member.mode &= 0o777
        tar.extract(member, dest)


@contextmanager
def ref_snapshot(
    repo_root: Path, ref: str, files: List[str]
) -> Iterator[Tuple[Optional[Path], Set[str]]]:
    """Checks out `files` as they existed at `ref` into a fresh temp dir.
    Yields `(None, set())` if none exist at `ref`, else `(tmp_dir,
    existing_files)`."""
    if not files:
        yield None, set()
        return

    existing = _existing_at_ref(repo_root, ref, files)
    if not existing:
        yield None, set()
        return

    tmp_dir = Path(tempfile.mkdtemp(prefix="snyk-secrets-baseline-"))
    try:
        try:
            archive = run_binary(
                ["git", "archive", ref, "--", *sorted(existing)], cwd=repo_root, timeout=GIT_TIMEOUT
            )
        except (OSError, subprocess.TimeoutExpired):
            yield None, set()
            return
        if archive.returncode != 0 or not _extract_archive(archive.stdout, tmp_dir):
            yield None, set()
            return
        yield tmp_dir, existing
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
