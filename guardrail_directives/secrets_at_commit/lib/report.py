"""Compiler-style stderr formatting for secrets findings.

One line per finding, parseable as the MSVC `file(line,col):` diagnostic
form editors already recognise (VS Code's Problems panel, etc).
"""

import os
import sys
from typing import Dict, List, Tuple

from .findings import SEVERITY_ORDER, Finding

_ANSI_RESET = "\033[0m"
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


def _fmt_finding(v: Finding, color: bool) -> str:
    return (
        f"[{_colorize(v.severity or '?', color)}] "
        f"[{v.id or '?'}] "
        f"[{v.cwe or '-'}] "
        f"[{v.title or '?'}]"
    )


def _fmt_group(file_path: str, line: int, column: int, findings: List[Finding], color: bool) -> str:
    header = f"  - {file_path}({line},{column}):"
    if len(findings) == 1:
        return f"{header} {_fmt_finding(findings[0], color)}"
    ordered = sorted(findings, key=lambda v: SEVERITY_ORDER.get(v.severity.lower(), 4))
    return "\n".join([header] + [f"    {_fmt_finding(v, color)}" for v in ordered])


def print_findings(findings: List[Finding]) -> None:
    """Prints one compiler-style diagnostic line (or group) per finding."""
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
        print(_fmt_group(file_path, line, column, groups[key], color), file=sys.stderr)
