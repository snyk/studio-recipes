"""Compiler-style stderr formatting for secrets findings.

One line per finding, parseable as the MSVC `file(line,col):` diagnostic
form editors already recognise (VS Code's Problems panel, etc).
"""

import os
import sys
from typing import Dict, List, Optional, Tuple

from .findings import SEVERITY_ORDER, Finding
from .proc import quote_for_paste

_ANSI_RESET = "\033[0m"
_ANSI_DIM = "\033[2m"
_SEVERITY_ANSI = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
}


def supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(sys.stderr, "isatty") and sys.stderr.isatty()


def _colorize(severity: str, color: bool) -> str:
    if not color:
        return severity
    ansi = _SEVERITY_ANSI.get(severity.lower())
    return f"{ansi}{severity}{_ANSI_RESET}" if ansi else severity


def _suppression_tag(v: Finding, color: bool) -> str:
    if v.is_under_review:
        text, ansi = "(ignore request pending review)", _SEVERITY_ANSI["medium"]
    elif v.is_rejected:
        text, ansi = "(a previous ignore request was rejected)", _SEVERITY_ANSI["high"]
    elif v.is_ignored:
        text, ansi = "(already ignored)", _ANSI_DIM
    else:
        return ""
    return f" {ansi}{text}{_ANSI_RESET}" if color else f" {text}"


def _fmt_finding(v: Finding, color: bool) -> str:
    return (
        f"[{_colorize(v.severity or '?', color)}] "
        f"[{v.id or '?'}] "
        f"[{v.cwe or '-'}] "
        f"[{v.title or '?'}]"
        f"{_suppression_tag(v, color)}"
    )


_UNDEFINED_ID_PREFIX = "UNDEFINED-"


def _has_usable_finding_id(finding_id: str) -> bool:
    """`snyk ignore create` rejects an UNDEFINED-<uuid> fingerprint as an invalid UUID."""
    return not finding_id.startswith(_UNDEFINED_ID_PREFIX)


def _ignore_command(v: Finding, remote_url: Optional[str]) -> Optional[str]:
    """None when the command wouldn't be complete (`--remote-repo-url` is
    required by the CLI), or when one's already accepted or under review --
    re-suggesting it in either case is just noise."""
    if not v.finding_id or not _has_usable_finding_id(v.finding_id) or not remote_url:
        return None
    if v.is_under_review or v.is_ignored:
        return None
    # remote_url comes from `git config --get remote.origin.url`, not
    # trusted input -- needs real shell quoting, not just a double-quote
    # wrap, to stop $(...) / backticks executing on paste.
    return (
        f"snyk ignore create --finding-id={quote_for_paste(v.finding_id)} "
        f"--remote-repo-url={quote_for_paste(remote_url)}"
    )


def _fmt_group(
    file_path: str,
    line: int,
    column: int,
    findings: List[Finding],
    color: bool,
    remote_url: Optional[str],
    dim: bool,
) -> str:
    # When dim, the whole group renders in one flat gray, so per-word
    # severity/tag coloring (which would fight it) is turned off first.
    finding_color = color and not dim
    header = f"  - {file_path}({line},{column}):"
    if len(findings) == 1:
        lines = [f"{header} {_fmt_finding(findings[0], finding_color)}"]
        cmd = _ignore_command(findings[0], remote_url)
        if cmd:
            lines.append(f"      {cmd}")
    else:
        ordered = sorted(findings, key=lambda v: SEVERITY_ORDER.get(v.severity.lower(), 4))
        lines = [header]
        for v in ordered:
            lines.append(f"    {_fmt_finding(v, finding_color)}")
            cmd = _ignore_command(v, remote_url)
            if cmd:
                lines.append(f"        {cmd}")
    text = "\n".join(lines)
    return f"{_ANSI_DIM}{text}{_ANSI_RESET}" if color and dim else text


def print_findings(
    findings: List[Finding], remote_url: Optional[str] = None, *, dim: bool = False
) -> None:
    """Prints one compiler-style diagnostic line (or group) per finding.
    `remote_url` (the `origin` remote, if any) gates whether a ready-to-run
    ignore command is shown alongside each finding. `dim` grays out a
    group that's already known not to block, regardless of severity.

    Uses its own `print()` rather than snyk_secrets_at_commit.py's
    log()/log_cont() -- these lines (especially the `snyk ignore create`
    command) must stay copy-pasteable, so they're deliberately never
    word-wrapped."""
    color = supports_color()
    groups: Dict[Tuple[str, int, int], List[Finding]] = {}
    for v in findings:
        key = (v.file_path, v.start_line, v.start_column)
        groups.setdefault(key, []).append(v)

    # Worst severity first, then group size, then a stable tiebreak.
    ordered_keys = sorted(
        groups,
        key=lambda k: (
            min(SEVERITY_ORDER.get(v.severity.lower(), 4) for v in groups[k]),
            -len(groups[k]),
            k,
        ),
    )
    for key in ordered_keys:
        file_path, line, column = key
        print(
            _fmt_group(file_path, line, column, groups[key], color, remote_url, dim),
            file=sys.stderr,
        )
