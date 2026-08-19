"""Maps a `git diff -U0` to the new-file line ranges it added/changed.
Also defines `ClassificationContext`, the shared input every
diff-classification strategy takes."""

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .findings import Finding

LineRanges = Dict[str, List[Tuple[int, int]]]

_PLUS_LINE_RE = re.compile(r"^\+\+\+ (.+?)(?:\t.*)?$")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

# A binary diff has no +++/@@ lines to derive a range from (git prints only
# "Binary files ... differ"); this sentinel marks "the whole file counts as
# added" so split_added_vs_pre_existing's overlap check needs no special
# case -- see get_binary_files() in git_ops.py, which maps binary paths to
# this range.
BINARY_SENTINEL_RANGE: Tuple[int, int] = (1, sys.maxsize)

_C_ESCAPES = {
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    '"': '"',
    "\\": "\\",
}
_OCTAL_DIGITS = set("01234567")


@dataclass(frozen=True)
class ClassificationContext:
    """Everything any added-vs-pre-existing classification strategy might
    need. Lives here (not the entry script) to avoid a circular import
    with lib/baseline.py."""

    findings: List[Finding]
    ranges: LineRanges
    current_snapshot_dir: Path
    baseline_findings: List[Finding] = field(default_factory=list)
    baseline_snapshot_dir: Optional[Path] = None
    baseline_files: Set[str] = field(default_factory=set)
    renames: Dict[str, str] = field(default_factory=dict)


def _norm_path(path: str) -> str:
    """git's diff output is always `/`-separated; Snyk's finding paths
    aren't guaranteed to be, so normalize before comparing."""
    return path.replace("\\", "/")


def _read_octal_byte(body: str, start: int) -> Tuple[Optional[int], int]:
    """Read up to three octal digits from a quoted Git path body.

    `start` points at the first digit after a backslash. Returns the decoded
    byte plus the first unconsumed index, or `(None, start)` if no octal
    digits are present. Example: in `b/\\303\\251.txt`, start=3 reads
    `303` as byte 0xC3 and returns `(195, 6)`.
    """
    end = start
    limit = min(start + 3, len(body))
    while end < limit and body[end] in _OCTAL_DIGITS:
        end += 1
    if end == start:
        return None, start
    return int(body[start:end], 8), end


def _read_quoted_path_escape(body: str, backslash_index: int) -> Tuple[bytes, int]:
    """Read one backslash escape from a quoted Git path body.

    `backslash_index` points at the backslash inside the already-unwrapped
    quoted token. Returns the escaped bytes plus the first unconsumed index.
    """
    escape_index = backslash_index + 1
    if escape_index >= len(body):
        return b"\\", backslash_index + 1

    marker = body[escape_index]
    if marker in _C_ESCAPES:
        return _C_ESCAPES[marker].encode("utf-8"), escape_index + 1
    if marker in _OCTAL_DIGITS:
        byte, next_index = _read_octal_byte(body, escape_index)
        if byte is not None:
            return bytes([byte]), next_index

    return marker.encode("utf-8"), escape_index + 1


def _unquote_git_path(raw: str) -> str:
    """Decode one path token from Git's quoted diff format.

    Unquoted tokens are returned unchanged. Quoted tokens use C-style escapes
    inside `"..."`; octal escapes represent raw bytes, so decode into bytes
    first and then UTF-8. Examples:

    - `"b/weird \\"quote\\".txt"` -> `b/weird "quote".txt`
    - `"b/\\303\\251.txt"` -> `b/\\u00e9.txt`

    We use Git's NUL-delimited formats where they include enough information
    (staged files, binary detection, renames). Added-line ranges only appear in
    unified patch hunks, and those hunks are attached to files by the `+++ ...`
    header. `-z` does not make that header NUL-delimited, so this is the one
    place we decode Git's quoted path token.
    """
    if len(raw) < 2 or raw[0] != '"' or raw[-1] != '"':
        return raw
    body = raw[1:-1]
    out = bytearray()
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out.extend(ch.encode("utf-8"))
            i += 1
            continue
        escaped_bytes, i = _read_quoted_path_escape(body, i)
        out.extend(escaped_bytes)
    return out.decode("utf-8", errors="replace")


def _parse_new_path(line: str) -> Optional[str]:
    """Parse the file header from one unified diff line.

    Expected form from `git diff -U0`: `+++ b/app.py` or
    `+++ "b/weird \\"quote\\".txt"`. Returns the new-side path without
    Git's `b/` prefix, or None for non-headers and deletions (`+++ /dev/null`).
    """
    match = _PLUS_LINE_RE.match(line)
    if not match:
        return None
    token = _unquote_git_path(match.group(1))
    if not token.startswith("b/"):
        return None
    return token[2:]


def _parse_hunk_range(line: str) -> Optional[Tuple[int, int]]:
    """Parse the new-side line range from one unified diff hunk header.

    Expected form from `git diff -U0`: `@@ -10,0 +11,2 @@`. The `+11,2`
    portion means "two changed lines starting at line 11", so this returns
    `(11, 12)`. Returns None for non-hunk lines and content-free hunks such as
    pure deletions.
    """
    match = _HUNK_RE.match(line)
    if not match:
        return None
    start = int(match.group(1))
    count = int(match.group(2)) if match.group(2) is not None else 1
    if count <= 0:
        return None
    return start, start + count - 1


def parse_added_line_ranges(diff_text: str) -> LineRanges:
    # Consumes the unified patch from get_added_line_ranges():
    #
    #   +++ b/app.py                 <- _parse_new_path()
    #   @@ -10,0 +11,2 @@           <- _parse_hunk_range()
    #
    # That maps to {"app.py": [(11, 12)]}. The patch body is not needed, and
    # binary files never produce +++/@@ lines; git_ops.py adds their sentinel.
    ranges: LineRanges = {}
    current_file: Optional[str] = None
    for line in diff_text.splitlines():
        new_path = _parse_new_path(line)
        if new_path is not None:
            current_file = new_path
            continue
        hunk_range = _parse_hunk_range(line)
        if hunk_range is not None and current_file is not None:
            ranges.setdefault(current_file, []).append(hunk_range)
    return ranges


def split_added_vs_pre_existing(
    findings: List[Finding], ranges: LineRanges
) -> Tuple[List[Finding], List[Finding], List[Finding]]:
    """Findings whose [start_line, end_line] span overlaps an added range
    are added; everything else is pre-existing. `removed` is always empty
    here -- no baseline text to detect a deletion against."""
    added: List[Finding] = []
    pre_existing: List[Finding] = []
    for f in findings:
        if f.start_line < 1:
            # No usable position (e.g. SARIF omitted startLine) -- can't
            # tell if it's new, and conservative-only means block rather
            # than silently drop it into pre-existing.
            added.append(f)
            continue
        file_ranges = ranges.get(_norm_path(f.file_path), [])
        overlaps = any(f.start_line <= hi and f.end_line >= lo for lo, hi in file_ranges)
        bucket = added if overlaps else pre_existing
        bucket.append(f)
    return added, pre_existing, []
