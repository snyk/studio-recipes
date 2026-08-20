"""Checkpoint timer, so latency (and where it went) is diagnosable without
guessing. Its output (via summary_line) reaches the persistent log for free
through the caller's own log_cont() -- see lib/persistent_log.py."""

import time
from typing import List, Optional, Tuple


class Timer:
    def __init__(self) -> None:
        self._marks: List[Tuple[str, float]] = [("start", time.monotonic())]

    def mark(self, name: str) -> None:
        self._marks.append((name, time.monotonic()))

    def segment_ms(self, from_name: str, to_name: str) -> Optional[float]:
        times = dict(self._marks)
        if from_name not in times or to_name not in times:
            return None
        return (times[to_name] - times[from_name]) * 1000

    def total_ms(self) -> float:
        return (self._marks[-1][1] - self._marks[0][1]) * 1000


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


_ANSI_RESET = "\033[0m"
_ANSI_BOLD_RED = "\033[1;31m"


def _blocking_clause(text: str, highlight: bool) -> str:
    return f"{_ANSI_BOLD_RED}{text}{_ANSI_RESET}" if highlight else text


def summary_line(
    timer: Timer,
    findings_count: int,
    *,
    pre_existing_count: int = 0,
    under_review_count: int = 0,
    added_ignored_count: int = 0,
    removed_count: int = 0,
    highlight_blocking: bool = False,
) -> str:
    """The closing "done in ..." line for a *successful* scan."""
    prefix = f"done in {timer.total_ms() / 1000:.1f}s"
    highlight = highlight_blocking and findings_count > 0
    under_review_suffix = (
        f" ({under_review_count} already under review)" if under_review_count else ""
    )
    if added_ignored_count:
        total = findings_count + added_ignored_count
        blocking = _blocking_clause(f"{findings_count} blocking", highlight)
        return (
            f"{prefix} -- {_plural(total, 'new finding')} introduced, "
            f"{blocking}{under_review_suffix}, {added_ignored_count} already ignored"
        )
    if findings_count == 0:
        # Keep the headline consistent with the history line below.
        noun = (
            "no blocking secrets found"
            if (pre_existing_count or removed_count)
            else "no secrets found"
        )
        return f"{prefix} -- {noun}"
    blocking = _blocking_clause(f"{_plural(findings_count, 'finding')} blocking", highlight)
    return f"{prefix} -- {blocking} commit{under_review_suffix}"


def history_line(pre_existing_count: int, removed_count: int) -> str:
    """Brief recap of pre-existing and removed findings."""
    parts = []
    if pre_existing_count:
        parts.append(_plural(pre_existing_count, "pre-existing finding"))
    if removed_count:
        parts.append(f"{_plural(removed_count, 'secret')} cleaned up")
    return f"history: {', '.join(parts)}" if parts else ""
