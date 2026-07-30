#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# ///
"""
Snyk Secrets At Commit
=======================

Scans staged changes for hardcoded secrets before they reach a commit.
Only findings classified as part of this commit block it; pre-existing
findings are called out separately without file-level detail. Classification is
pluggable via SECRETS_DIFF_STRATEGY -- see DiffStrategy/`_DIFF_STRATEGIES`
below.

EXIT CODES:
  0  no blocking secrets
  1  secrets found, or a scan failure with SECRETS_BLOCK_ON_SCAN_FAILURE=1
  2  prerequisite failure -- can't safely determine what to scan.

Once a repository is resolved, each run also appends the same decision-level
lines shown on stderr to a persistent per-repo log under ~/.snyk-studio (see
lib/persistent_log.py).

TODO: "vuln is identifiable from this scan" is only confirmed for one
secret type so far (a fake AWS access key -- see
test_secrets_precommit_hooks.py's _fake_aws_access_key). Broaden to a
representative set of rules before relying on it more generally.

ENVIRONMENT:
  SECRETS_MIN_BLOCK_SEVERITY     min severity that blocks (default: medium)
  SECRETS_SCAN_TIMEOUT           seconds before giving up on the scan (default: 90)
  SECRETS_BLOCK_ON_SCAN_FAILURE  block instead of warn+allow on scan failure (default: 0)
  SECRETS_IGNORE_PATHS           comma-separated glob patterns for staged paths to skip
  SECRETS_FALLBACK_TO_WORKING_DIR
                                  allow working-tree scan if staged snapshot fails (default: 0)
  SECRETS_HOOK_DEBUG=1           verbose logging to stderr
  SECRETS_DIFF_STRATEGY          "line" (default) or "content" -- see DiffStrategy below
"""

import argparse
import os
import sys
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from lib.baseline import classify_by_content
from lib.diff_scope import ClassificationContext, LineRanges, split_added_vs_pre_existing
from lib.findings import Finding, filter_by_severity
from lib.git_ops import find_repo_root, get_added_line_ranges, get_rename_map, get_staged_files
from lib.index_snapshot import ref_snapshot, staged_snapshot, working_tree_snapshot
from lib.persistent_log import append_log, resolve_log_file
from lib.report import print_findings
from lib.snyk_cli import (
    ScanStatus,
    check_snyk_auth,
    find_snyk_binary,
    resolve_scan_files,
    run_concurrent_scans,
    run_secrets_scan,
)
from lib.timing import Timer, pre_existing_notice, summary_line

DEBUG = os.environ.get("SECRETS_HOOK_DEBUG", "0") == "1"

DEFAULT_SCAN_TIMEOUT = 90.0
MIN_SCAN_TIMEOUT = 1.0
DEFAULT_DIFF_STRATEGY = "line"

EXIT_OK = 0
EXIT_BLOCK = 1
EXIT_PREREQ = 2

# Set once repo_root is known, so log()/log_cont() can persist too.
_LOG_FILE: Optional[str] = None


class PrerequisiteFailure(Exception):
    def __init__(self, message: str, *, indent: bool = False) -> None:
        super().__init__(message)
        self.message = message
        self.indent = indent


def log(message: str) -> None:
    """The one leading `[snyk] ...` line per phase."""
    print(f"[snyk] {message}", file=sys.stderr)
    if _LOG_FILE:
        append_log(message, _LOG_FILE)


def log_cont(message: str) -> None:
    """A continuation line under the most recent log() line."""
    print(f"  {message}", file=sys.stderr)
    if _LOG_FILE:
        append_log(message, _LOG_FILE)


def debug(message: str) -> None:
    if DEBUG:
        log_cont(f"[debug] {message}")


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _scan_timeout() -> float:
    try:
        value = float(os.environ.get("SECRETS_SCAN_TIMEOUT", DEFAULT_SCAN_TIMEOUT))
    except ValueError:
        return DEFAULT_SCAN_TIMEOUT
    return value if value >= MIN_SCAN_TIMEOUT else MIN_SCAN_TIMEOUT


def _block_on_scan_failure() -> bool:
    return os.environ.get("SECRETS_BLOCK_ON_SCAN_FAILURE", "0") == "1"


def _fallback_to_working_dir() -> bool:
    return os.environ.get("SECRETS_FALLBACK_TO_WORKING_DIR", "0") == "1"


def _fail_open_or_block(
    problem: str, *, action_hint: Optional[str] = None, indent: bool = False
) -> int:
    """Logs `problem` with a fail-open/fail-closed suffix and returns the
    matching exit code."""
    emit = log_cont if indent else log
    blocking = _block_on_scan_failure()
    hints = [action_hint] if action_hint else []
    if blocking:
        verdict = "blocking commit"
    else:
        verdict = "allowing commit"
        hints.append("set SECRETS_BLOCK_ON_SCAN_FAILURE=1 to block instead")
    suffix = f" ({'; '.join(hints)})" if hints else ""
    emit(f"{problem}; {verdict}{suffix}")
    return EXIT_BLOCK if blocking else EXIT_OK


def _handle_scan_failure(status: ScanStatus) -> int:
    if status == "auth_required":
        return _fail_open_or_block("Snyk CLI not authenticated -- run `snyk auth`", indent=True)
    if status == "timeout":
        return _fail_open_or_block(
            f"scan timed out after {_scan_timeout():.0f}s",
            action_hint="run `snyk secrets test` manually to check",
            indent=True,
        )
    return _fail_open_or_block(
        "scan did not complete",
        action_hint="run `snyk secrets test` manually to check",
        indent=True,
    )


def _log_summary(
    timer: Timer,
    status: ScanStatus,
    findings_count: int,
    *,
    pre_existing_count: int = 0,
) -> None:
    """Prints the closing "done in ..." line for a successful scan only --
    a failed scan already got its own message from _handle_scan_failure."""
    timer.mark("end")
    if status == "success":
        scan_ms = timer.segment_ms("prereqs_checked", "scan_done")
        if scan_ms is not None:
            debug(f"scan took {scan_ms / 1000:.1f}s (total {timer.total_ms() / 1000:.1f}s)")
        if pre_existing_count:
            log_cont(pre_existing_notice(pre_existing_count))
        log_cont(summary_line(timer, findings_count, pre_existing_count=pre_existing_count))


@dataclass(frozen=True)
class ScanScope:
    """What to scan, which lines are newly added, and any rename mapping
    (populated only when the strategy needs a baseline scan)."""

    repo_root: Path
    files: List[str]
    ranges: LineRanges
    renames: Dict[str, str] = field(default_factory=dict)
    binary_files: List[str] = field(default_factory=list)


def resolve_scan_scope(
    cwd: Path, *, needs_renames: bool = False
) -> Tuple[Optional[ScanScope], Optional[int]]:
    """Returns (scope, None) to proceed, or (None, exit_code) to exit
    immediately. `needs_renames` skips the extra `get_rename_map` git call
    when the resolved strategy has no use for it."""
    repo_root = find_repo_root(cwd)

    if repo_root is None:
        log("not inside a git repository")
        return None, EXIT_PREREQ

    global _LOG_FILE
    _LOG_FILE = resolve_log_file(str(repo_root))

    staged = get_staged_files(repo_root)
    if staged is None:
        log("could not determine staged files; cannot safely scan staged changes")
        return None, EXIT_PREREQ
    if not staged:
        log("no staged files, skipping scan")
        return None, EXIT_OK

    scan_files = resolve_scan_files(staged)
    if not scan_files:
        log("no scannable files staged, skipping scan")
        return None, EXIT_OK

    line_ranges_result = get_added_line_ranges(repo_root)
    if line_ranges_result is None:
        log("could not determine added lines; cannot safely classify staged changes")
        return None, EXIT_PREREQ
    ranges, binary_files = line_ranges_result

    renames = get_rename_map(repo_root) if needs_renames else {}
    scope = ScanScope(
        repo_root=repo_root,
        files=scan_files,
        ranges=ranges,
        renames=renames,
        binary_files=binary_files,
    )
    return scope, None


def _classify_by_line_range(ctx: ClassificationContext) -> Tuple[List[Finding], List[Finding]]:
    """The "line" DiffStrategy's classify function."""
    # Explicit annotation: mypy infers Any here otherwise.
    result: Tuple[List[Finding], List[Finding]] = split_added_vs_pre_existing(
        ctx.findings, ctx.ranges
    )
    return result


@dataclass(frozen=True)
class DiffStrategy:
    """A pluggable way to classify findings as added-vs-pre-existing. New
    strategy: a `classify` function plus one `_DIFF_STRATEGIES` entry."""

    name: str
    needs_baseline_scan: bool
    classify: Callable[[ClassificationContext], Tuple[List[Finding], List[Finding]]]


_DIFF_STRATEGIES: Dict[str, DiffStrategy] = {
    "line": DiffStrategy("line", needs_baseline_scan=False, classify=_classify_by_line_range),
    "content": DiffStrategy("content", needs_baseline_scan=True, classify=classify_by_content),
}


def _resolve_diff_strategy() -> DiffStrategy:
    name = os.environ.get("SECRETS_DIFF_STRATEGY", DEFAULT_DIFF_STRATEGY).lower()
    return _DIFF_STRATEGIES.get(name, _DIFF_STRATEGIES[DEFAULT_DIFF_STRATEGY])


def parse_cli_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="snyk_secrets_at_commit",
        description="Scan staged changes for hardcoded secrets before they reach a commit.",
    )
    return parser.parse_args(argv)


def _ensure_not_repo_workspace(scope: ScanScope, workspace: Path) -> None:
    try:
        same_workspace = workspace.resolve() == scope.repo_root.resolve()
    except OSError:
        same_workspace = workspace.absolute() == scope.repo_root.absolute()
    if same_workspace:
        raise PrerequisiteFailure(
            "refusing to scan the repository working tree directly; "
            "scan workspace must be a prepared snapshot",
            indent=True,
        )


def _scan_prepared_workspace(
    scope: ScanScope,
    strategy: DiffStrategy,
    current_workspace: Path,
    workspace_source: str,
    snyk_bin: str,
    timeout: float,
    timer: Timer,
) -> Tuple[ScanStatus, List[Finding], List[Finding]]:
    _ensure_not_repo_workspace(scope, current_workspace)
    debug(f"scan workspace: {current_workspace} ({workspace_source})")

    if not strategy.needs_baseline_scan:
        return _scan_without_baseline(scope, strategy, current_workspace, snyk_bin, timeout, timer)
    return _scan_with_baseline(scope, strategy, current_workspace, snyk_bin, timeout, timer)


def _scan_and_classify(
    scope: ScanScope, strategy: DiffStrategy, snyk_bin: str, timeout: float, timer: Timer
) -> Tuple[ScanStatus, List[Finding], List[Finding]]:
    """Runs whichever scan(s) `strategy` needs and classifies the
    findings. A non-"success" status means empty, meaningless lists."""
    with staged_snapshot(scope.repo_root, scope.files) as snapshot_dir:
        if snapshot_dir is not None:
            return _scan_prepared_workspace(
                scope, strategy, Path(snapshot_dir), "staged snapshot", snyk_bin, timeout, timer
            )

        if not _fallback_to_working_dir():
            raise PrerequisiteFailure(
                "could not snapshot staged content (git checkout-index failed); "
                "cannot safely scan staged changes",
                indent=True,
            )

        log_cont(
            "could not snapshot staged content (git checkout-index failed); "
            "scanning the working tree because SECRETS_FALLBACK_TO_WORKING_DIR=1 "
            "-- results may not match what's staged"
        )
        with working_tree_snapshot(scope.repo_root, scope.files) as fallback_dir:
            if fallback_dir is None:
                raise PrerequisiteFailure(
                    "could not snapshot working-tree fallback content; "
                    "cannot safely scan staged changes",
                    indent=True,
                )
            return _scan_prepared_workspace(
                scope,
                strategy,
                Path(fallback_dir),
                "working-tree fallback snapshot",
                snyk_bin,
                timeout,
                timer,
            )


def _scan_without_baseline(
    scope: ScanScope,
    strategy: DiffStrategy,
    current_workspace: Path,
    snyk_bin: str,
    timeout: float,
    timer: Timer,
) -> Tuple[ScanStatus, List[Finding], List[Finding]]:
    """A strategy with no baseline scan (e.g. "line"): one scan, classified
    by `strategy.classify` directly against the diff's own added-line
    ranges."""
    debug(f"running current scan: workspace={current_workspace} target=.")
    status, findings = run_secrets_scan(current_workspace, snyk_bin, timeout)
    timer.mark("scan_done")
    if status != "success":
        return status, [], []
    ctx = ClassificationContext(
        findings=findings, ranges=scope.ranges, current_snapshot_dir=current_workspace
    )
    added, pre_existing = strategy.classify(ctx)
    return status, added, pre_existing


def _scan_with_baseline(
    scope: ScanScope,
    strategy: DiffStrategy,
    current_workspace: Path,
    snyk_bin: str,
    timeout: float,
    timer: Timer,
) -> Tuple[ScanStatus, List[Finding], List[Finding]]:
    """A strategy that needs a baseline scan (e.g. "content"): also scans
    HEAD's version of the same files (concurrently, so no added wall-clock
    latency) before handing both result sets to `strategy.classify`."""
    baseline_lookup_paths = [scope.renames.get(f, f) for f in scope.files]
    with ref_snapshot(scope.repo_root, "HEAD", baseline_lookup_paths) as (
        baseline_dir,
        baseline_files,
    ):
        if baseline_dir is None:
            # Nothing to compare against; classify_by_content degrades to
            # line-diff for an empty baseline_files.
            debug("baseline scan skipped: no scoped files exist at HEAD")
            debug(f"running current scan: workspace={current_workspace} target=.")
            status, findings = run_secrets_scan(current_workspace, snyk_bin, timeout)
            baseline_status: ScanStatus = "success"
            baseline_findings: List[Finding] = []
        else:
            _ensure_not_repo_workspace(scope, baseline_dir)
            debug(f"baseline scan workspace: {baseline_dir} ({len(baseline_files)} files)")
            debug(
                f"running concurrent scans: current_workspace={current_workspace} "
                f"baseline_workspace={baseline_dir} target=."
            )
            (status, findings), (baseline_status, baseline_findings) = run_concurrent_scans(
                current_workspace,
                baseline_dir,
                snyk_bin,
                timeout,
            )
        timer.mark("scan_done")
        if status != "success":
            return status, [], []

        effective_strategy = strategy
        effective_baseline_dir = baseline_dir
        effective_baseline_files = baseline_files
        if baseline_status != "success":
            debug(f"baseline scan {baseline_status}; using line-diff classification for this run")
            effective_strategy = _DIFF_STRATEGIES["line"]
            effective_baseline_dir = None
            effective_baseline_files = set()

        ctx = ClassificationContext(
            findings=findings,
            ranges=scope.ranges,
            current_snapshot_dir=current_workspace,
            baseline_findings=baseline_findings,
            baseline_snapshot_dir=effective_baseline_dir,
            baseline_files=effective_baseline_files,
            renames=scope.renames,
        )
        added, pre_existing = effective_strategy.classify(ctx)
        return status, added, pre_existing


def main(argv: Optional[List[str]] = None) -> int:
    parse_cli_args(argv)  # no flags defined; just handles --help/bad argv
    try:
        return _run()
    except PrerequisiteFailure as e:
        emit = log_cont if e.indent else log
        emit(e.message)
        return EXIT_PREREQ
    except Exception as e:
        # Last-resort safety net: a bug we didn't anticipate must still
        # respect the user's fail-open/fail-closed choice. Without this,
        # Python's own default nonzero exit on an uncaught exception would
        # coincide with EXIT_BLOCK and force-block every commit regardless
        # of SECRETS_BLOCK_ON_SCAN_FAILURE.
        if DEBUG:
            traceback.print_exc()
        # The exception's type name alone is still useful triage signal
        # for the (rare) exception raised with no message at all.
        detail = f"{type(e).__name__}: {e}" if str(e) else type(e).__name__
        return _fail_open_or_block(f"internal error: {detail}")


def _run() -> int:
    timer = Timer()

    strategy = _resolve_diff_strategy()
    scope, early_exit = resolve_scan_scope(Path.cwd(), needs_renames=strategy.needs_baseline_scan)
    if early_exit is not None:
        return early_exit
    if scope is None:
        # Unreachable per resolve_scan_scope's contract; never scan an unknown scope.
        log("internal error: no scan scope resolved; cannot safely scan staged changes")
        return EXIT_PREREQ

    snyk_bin = find_snyk_binary()
    if snyk_bin is None:
        return _fail_open_or_block(
            "Snyk CLI not found on PATH -- install with `npm install -g snyk`"
        )
    if check_snyk_auth() is None:
        return _fail_open_or_block("Snyk CLI not authenticated -- run `snyk auth`")
    timer.mark("prereqs_checked")

    timeout = _scan_timeout()
    log(
        f"Scanning {_plural(len(scope.files), 'staged file')} for secrets, up to "
        f"{timeout:.0f}s... (bypass with `git commit --no-verify`)"
    )
    if scope.binary_files:
        log_cont(
            f"{_plural(len(scope.binary_files), 'binary file')} staged; "
            "can't diff line-by-line, treating the whole file as in scope"
        )
    debug(f"diff strategy: {strategy.name}")
    debug(
        f"scan scope: {_plural(len(scope.files), 'file')}, "
        f"{_plural(len(scope.binary_files), 'binary file')}"
    )

    status, added, pre_existing = _scan_and_classify(scope, strategy, snyk_bin, timeout, timer)

    if status != "success":
        exit_code = _handle_scan_failure(status)
        _log_summary(timer, status, 0)
        return exit_code

    blocking = filter_by_severity(added)
    timer.mark("filtered")

    exit_code = EXIT_BLOCK if blocking else EXIT_OK
    _log_summary(
        timer,
        status,
        len(blocking),
        pre_existing_count=len(pre_existing),
    )
    if blocking:
        print_findings(blocking)

    return exit_code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("interrupted")
        sys.exit(EXIT_BLOCK)
