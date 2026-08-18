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


def summary_line(
    timer: Timer,
    findings_count: int,
    *,
    pre_existing_count: int = 0,
    under_review_count: int = 0,
    added_ignored_count: int = 0,
) -> str:
    """The closing "done in ..." line for a *successful* scan -- a failed
    scan gets its own message instead (see _handle_scan_failure)."""
    prefix = f"done in {timer.total_ms() / 1000:.1f}s"
    under_review_suffix = (
        f" ({under_review_count} already under review)" if under_review_count else ""
    )
    if added_ignored_count:
        # The printed list below still shows the already-ignored ones --
        # say so, or "no secrets found" would look inconsistent with it.
        total = findings_count + added_ignored_count
        return (
            f"{prefix} -- {_plural(total, 'new finding')} introduced, "
            f"{findings_count} blocking{under_review_suffix}"
        )
    if findings_count == 0:
        noun = "no blocking secrets found" if pre_existing_count else "no secrets found"
        return f"{prefix} -- {noun}"
    return f"{prefix} -- {_plural(findings_count, 'finding')} blocking commit{under_review_suffix}"


def pre_existing_notice(count: int) -> str:
    return f"{_plural(count, 'finding')} classified as pre-existing; not blocking this commit"


def pre_existing_ignored_notice(count: int) -> str:
    return f"{_plural(count, 'previously-ignored finding')} still present; not blocking this commit"


def pre_existing_under_review_notice(count: int) -> str:
    return (
        f"{_plural(count, 'pre-existing finding')} awaiting ignore review; not blocking this commit"
    )


def added_ignored_notice(count: int) -> str:
    return f"{_plural(count, 'new finding')} already covered by an ignore; not blocking this commit"


def removed_notice(count: int) -> str:
    return f"cleaned up {_plural(count, 'pre-existing secret')}, nice job"


def removed_ignored_notice(count: int) -> str:
    return f"cleaned up {_plural(count, 'previously-ignored secret')}, nice job"
