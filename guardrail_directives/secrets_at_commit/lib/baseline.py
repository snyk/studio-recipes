"""The "content" DiffStrategy: compares matched secret text between the
current and a baseline scan, instead of line position. Falls back to
diff_scope's line-range heuristic per finding when that's not possible."""

from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .diff_scope import ClassificationContext, split_added_vs_pre_existing
from .findings import Finding


def _norm_path(path: str) -> str:
    return path.replace("\\", "/")


def extract_finding_text(snapshot_dir: Path, file_path: str, finding: Finding) -> Optional[str]:
    """Reads the literal text `finding` matched. `file_path` is separate
    from `finding.file_path` so a baseline lookup can pass the
    rename-translated old path."""
    target = snapshot_dir / _norm_path(file_path)
    try:
        # An absolute or `..`-escaping file_path would otherwise let `/`
        # discard snapshot_dir entirely (a pathlib join with an absolute
        # right-hand side returns just that path) and read arbitrary files
        # off disk -- confirm the resolved target actually stays inside
        # the snapshot before reading it.
        target.resolve().relative_to(snapshot_dir.resolve())
    except (OSError, ValueError):
        return None
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    start_line, end_line = finding.start_line, finding.end_line
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        return None
    start_col, end_col = finding.start_column, finding.end_column
    if start_col < 1 or end_col < start_col:
        return None

    if start_line == end_line:
        line = lines[start_line - 1]
        if end_col - 1 > len(line):
            return None
        return line[start_col - 1 : end_col - 1]

    # Multi-line span (rare for a secret match): first line from
    # start_column, last line up to end_column, middle taken whole.
    first_line = lines[start_line - 1]
    last_line = lines[end_line - 1]
    if start_col - 1 > len(first_line) or end_col - 1 > len(last_line):
        return None
    first = first_line[start_col - 1 :]
    middle = lines[start_line : end_line - 1]
    last = last_line[: end_col - 1]
    return "\n".join([first, *middle, last])


def _baseline_text_index(ctx: ClassificationContext) -> Dict[str, Set[str]]:
    """Maps rule id -> matched texts seen anywhere in the baseline scan
    (not scoped per file -- an identical secret is "known" regardless of
    which file it was in)."""
    index: Dict[str, Set[str]] = {}
    if ctx.baseline_snapshot_dir is None:
        return index
    for bf in ctx.baseline_findings:
        text = extract_finding_text(ctx.baseline_snapshot_dir, bf.file_path, bf)
        if text is not None:
            index.setdefault(bf.id, set()).add(text)
    return index


def classify_by_content(ctx: ClassificationContext) -> Tuple[List[Finding], List[Finding]]:
    """The "content" DiffStrategy's classify function."""
    baseline_text_by_rule = _baseline_text_index(ctx)

    added: List[Finding] = []
    pre_existing: List[Finding] = []
    fallback: List[Finding] = []

    for f in ctx.findings:
        norm_path = _norm_path(f.file_path)
        lookup_path = ctx.renames.get(norm_path, norm_path)
        if lookup_path not in ctx.baseline_files:
            # No baseline content for this file (brand-new file, or an
            # unrecognized rename) -- line-diff handles that case fine.
            fallback.append(f)
            continue

        current_text = extract_finding_text(ctx.current_snapshot_dir, f.file_path, f)
        if current_text is None:
            fallback.append(f)
            continue

        if current_text in baseline_text_by_rule.get(f.id, set()):
            pre_existing.append(f)
        else:
            added.append(f)

    if fallback:
        fallback_added, fallback_pre_existing = split_added_vs_pre_existing(fallback, ctx.ranges)
        added.extend(fallback_added)
        pre_existing.extend(fallback_pre_existing)

    return added, pre_existing
