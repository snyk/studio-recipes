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


def summary_line(timer: Timer, findings_count: int, *, pre_existing_count: int = 0) -> str:
    """The closing "done in ..." line for a *successful* scan -- a failed
    scan gets its own message instead (see _handle_scan_failure)."""
    prefix = f"done in {timer.total_ms() / 1000:.1f}s"

    if findings_count == 0:
        noun = "no blocking secrets found" if pre_existing_count else "no secrets found"
        return f"{prefix} -- {noun}"
    return f"{prefix} -- {_plural(findings_count, 'finding')} blocking commit"


def pre_existing_notice(pre_existing_count: int) -> str:
    return (
        f"{_plural(pre_existing_count, 'finding')} classified as pre-existing; "
        "not blocking this commit"
    )
