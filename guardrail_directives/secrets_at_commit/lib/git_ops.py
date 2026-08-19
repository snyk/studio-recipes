"""Git plumbing for the entry script: repo discovery, staged files/line
ranges, and rename detection."""

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Literal, Optional, Set, Tuple

from .diff_scope import BINARY_SENTINEL_RANGE, LineRanges, parse_added_line_ranges
from .proc import bounded_git_timeout, run_text


def find_repo_root(start: Path) -> Optional[Path]:
    try:
        cur = start.resolve()
    except OSError:
        return None
    for parent in [cur, *cur.parents]:
        if (parent / ".git").exists():
            return parent
    return None


def _debug_git_failure(cmd: List[str], detail: str) -> None:
    if os.environ.get("SECRETS_HOOK_DEBUG") == "1":
        print(f"  [debug] {' '.join(cmd)} {detail}", file=sys.stderr)


def _run_git(args: List[str], cwd: Path, deadline: Optional[float] = None) -> Optional[str]:
    """Runs `git <args>` and returns stdout, or None on failure (including
    a hung/too-slow git process, or a shared `deadline` with no time left
    -- see `bounded_git_timeout`)."""
    cmd = ["git", *args]
    timeout = bounded_git_timeout(deadline)
    if timeout is None:
        _debug_git_failure(cmd, "skipped: shared deadline already passed")
        return None
    try:
        result = run_text(cmd, cwd=cwd, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        _debug_git_failure(cmd, f"failed: {e}")
        return None
    if result.returncode != 0:
        _debug_git_failure(cmd, f"exited {result.returncode}: {result.stderr.strip()}")
        return None
    stdout: str = result.stdout
    return stdout


def get_staged_files(repo_root: Path, deadline: Optional[float] = None) -> Optional[List[str]]:
    """None means git failed (fail-closed); [] means nothing staged.

    Expected `git diff --name-only -z` output:
    `app.py\0src/lib.py\0`.
    """
    stdout = _run_git(
        ["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"], repo_root, deadline
    )
    if stdout is None:
        return None
    return [p for p in stdout.split("\0") if p]


def get_binary_files(repo_root: Path, deadline: Optional[float] = None) -> Set[str]:
    """Return staged files Git reports as binary, using each file's new path.

    Git calls this output "numstat" because it is the numeric diff-stat
    format: each changed file is reported as added-line count, deleted-line
    count, and path.

    Expected `git diff --numstat -z` records:

    - text file: `3\t1\tapp.py\0`
    - binary file: `-\t-\tsecret.bin\0`
    - rename/copy: `0\t0\t\0old.py\0new.py\0`

    We use that `-`/`-` binary marker instead of parsing the human-readable
    patch text. If this extra Git query fails, return an empty set; the scan
    still runs, just without the binary-file warning/range sharpening."""
    stdout = _run_git(
        ["-c", "core.quotePath=false", "diff", "--cached", "--numstat", "-z", "--diff-filter=ACMR"],
        repo_root,
        deadline,
    )
    if stdout is None:
        return set()

    binary: Set[str] = set()
    numstat_output_fields = stdout.split("\0")
    field_index = 0
    while field_index < len(numstat_output_fields):
        record_header = numstat_output_fields[field_index]
        field_index += 1
        if not record_header:
            continue
        parsed = _parse_numstat_record(record_header)
        if parsed is None:
            break
        added, deleted, name_field = parsed
        name, field_index = _consume_numstat_path(name_field, numstat_output_fields, field_index)
        if name is None:
            break
        if _numstat_record_is_binary(added, deleted):
            binary.add(name)
    return binary


def _parse_numstat_record(record: str) -> Optional[Tuple[str, str, str]]:
    """Parse the tab-delimited header from one `--numstat -z` record.

    Expected input is the first NUL-delimited field for a record:
    `3\t1\tapp.py`, `-\t-\tsecret.bin`, or `0\t0\t` for a rename/copy whose
    old and new paths follow as separate NUL-delimited fields.
    """
    parts = record.split("\t", 2)
    if len(parts) != 3:
        return None
    added, deleted, name_field = parts
    return added, deleted, name_field


def _consume_numstat_path(
    name_field: str, numstat_output_fields: List[str], next_field_index: int
) -> Tuple[Optional[str], int]:
    """Return the new path for one parsed `--numstat -z` record.

    For `3\t1\tapp.py\0`, `_parse_numstat_record()` already returned
    `name_field="app.py"`.

    For `0\t0\t\0old.py\0new.py\0`, `name_field` is empty and
    `next_field_index` points at `old.py`; this helper consumes both path
    fields and returns `new.py`.

    The new path is the one that can be scanned from the staged index.
    """
    if name_field:
        return name_field, next_field_index
    if next_field_index + 1 >= len(numstat_output_fields):
        return None, len(numstat_output_fields)
    return numstat_output_fields[next_field_index + 1], next_field_index + 2


def _numstat_record_is_binary(added: str, deleted: str) -> bool:
    """Git marks binary numstat rows with `-` for both added and deleted."""
    return added == "-" and deleted == "-"


def get_added_line_ranges(
    repo_root: Path, deadline: Optional[float] = None
) -> Optional[Tuple[LineRanges, List[str]]]:
    """None means git failed (fail-closed). Second element: paths git
    reports as binary -- already merged into the returned ranges via
    BINARY_SENTINEL_RANGE, returned separately too so callers can warn
    about them.

    Expected `git diff --cached -U0` output for a two-line addition:

    `+++ b/app.py`
    `@@ -10,0 +11,2 @@`

    `parse_added_line_ranges()` consumes those headers and maps the file to
    `[(11, 12)]`. Git's `-z` formats expose paths safely, but do not attach
    paths to exact hunk ranges, so this call reads unified patch headers.
    """
    stdout = _run_git(
        ["-c", "core.quotePath=false", "diff", "--cached", "--diff-filter=ACMR", "-U0"],
        repo_root,
        deadline,
    )
    if stdout is None:
        return None
    ranges = parse_added_line_ranges(stdout)

    binary_files = sorted(get_binary_files(repo_root, deadline))
    for path in binary_files:
        ranges[path] = [BINARY_SENTINEL_RANGE]
    return ranges, binary_files


def get_rename_map(repo_root: Path, deadline: Optional[float] = None) -> Dict[str, str]:
    """Maps {new_path: old_path} for staged renames. Fails soft to `{}` --
    a renamed file just falls back to line-diff.

    Copies aren't detected -- that needs `-C -C`, too expensive to add
    given the scan's own timeout budget.

    Expected `git diff --name-status -z --find-renames` output:
    `R100\0old.py\0new.py\0`.
    """
    stdout = _run_git(
        [
            "-c",
            "core.quotePath=false",
            "diff",
            "--cached",
            "--find-renames",
            "--diff-filter=R",
            "--name-status",
            "-z",
        ],
        repo_root,
        deadline,
    )
    if stdout is None:
        return {}

    # --diff-filter=R: every entry is "R<score>\0old\0new\0".
    parts = [p for p in stdout.split("\0") if p]
    renames: Dict[str, str] = {}
    i = 0
    while i + 2 < len(parts):
        status, old_path, new_path = parts[i], parts[i + 1], parts[i + 2]
        if status[:1] == "R":
            renames[new_path] = old_path
        i += 3
    return renames


_SAFE_REMOTE_URL_RE = re.compile(r"^[A-Za-z0-9.:/@_~+-]+$")

RemoteUrlStatus = Literal["ok", "unavailable", "rejected_unsafe"]


@dataclass(frozen=True)
class RemoteUrlDecision:
    """What we know about the repo's `origin` remote and whether it's
    usable. `url` is set only when status == "ok" -- callers that just
    need "is there something usable" can check `url` directly; callers
    that care why can check `status`."""

    url: Optional[str]
    status: RemoteUrlStatus

    @staticmethod
    def unavailable() -> "RemoteUrlDecision":
        return RemoteUrlDecision(None, "unavailable")

    @staticmethod
    def ok(url: str) -> "RemoteUrlDecision":
        return RemoteUrlDecision(url, "ok")

    def rejected(self) -> "RemoteUrlDecision":
        """Downgrades an "ok" decision once the resolved CLI's shell-need
        is known and this URL isn't safe for one."""
        return RemoteUrlDecision(None, "rejected_unsafe")


def is_safe_for_shell(url: str) -> bool:
    """Whether `url` is safe to hand to a shell=True subprocess or embed
    literally in a printed shell command. Only meaningful to check when a
    shell is actually involved -- see lib.proc.needs_shell."""
    return bool(_SAFE_REMOTE_URL_RE.match(url))


def get_remote_url(repo_root: Path, deadline: Optional[float] = None) -> RemoteUrlDecision:
    """The `origin` remote's URL, decided as far as we can here -- whether
    it's also safe for a shell-launched CLI depends on which Snyk binary
    gets resolved, not known yet at this point (see RemoteUrlDecision.rejected,
    applied once that's known)."""
    stdout = _run_git(["config", "--get", "remote.origin.url"], repo_root, deadline)
    if stdout is None:
        return RemoteUrlDecision.unavailable()
    url = stdout.strip()
    return RemoteUrlDecision.ok(url) if url else RemoteUrlDecision.unavailable()
