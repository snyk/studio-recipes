#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# ///
"""
Snyk Secrets At Commit
=======================

Scans staged changes for hardcoded secrets before they reach a commit.
Only findings classified as part of this commit block it; pre-existing
findings are called out separately without file-level detail.
Classification compares matched secret text against a HEAD baseline scan
(see DiffStrategy/`_DIFF_STRATEGIES` below), falling back to a line-range
heuristic per finding when there's no baseline to compare against.

EXIT CODES:
  0  no blocking secrets, or an entitlement failure (always allowed through
     unscanned, regardless of SECRETS_BLOCK_ON_SCAN_FAILURE)
  1  secrets found, or a scan failure with SECRETS_BLOCK_ON_SCAN_FAILURE=1
  2  prerequisite failure -- can't safely determine what to scan.

Once a repository is resolved, each run also appends the same decision-level
lines shown on stderr to a persistent per-repo log under ~/.snyk-studio (see
lib/persistent_log.py).

ENVIRONMENT:
  SECRETS_SCAN_TIMEOUT           seconds before giving up on the scan (default: 90)
  SECRETS_BLOCK_ON_SCAN_FAILURE  block instead of warn+allow on scan failure (default: 1);
                                 not applied to entitlement failures, which always warn+allow
  SECRETS_HOOK_DEBUG=1           verbose logging to stderr
"""

import argparse
import os
import re
import sys
import textwrap
import time
import traceback
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from lib import proc
from lib.baseline import classify_by_content
from lib.deprecated_flags import get_deprecated_flag_warnings
from lib.diff_scope import ClassificationContext, LineRanges, split_added_vs_pre_existing
from lib.findings import Finding
from lib.git_ops import (
    RemoteUrlDecision,
    find_repo_root,
    get_added_line_ranges,
    get_remote_url,
    get_rename_map,
    get_staged_files,
    is_safe_for_shell,
)
from lib.index_snapshot import SnapshotError, ref_snapshot, staged_snapshot
from lib.persistent_log import append_log, resolve_log_file
from lib.proc import needs_shell, quote_for_paste
from lib.report import print_findings, supports_color
from lib.snyk_cli import (
    AuthRequiredError,
    EntitlementCheckFailedError,
    InvalidConfigError,
    NotEntitledError,
    PermanentScanFailureError,
    ScanInvocation,
    ScanStatus,
    build_snyk_env,
    check_snyk_auth,
    find_snyk_binary,
    run_concurrent_scans,
    run_secrets_scan_with_retries,
    stale_sidecar_pin,
)
from lib.timing import (
    Timer,
    history_line,
    summary_line,
)

DEBUG = os.environ.get("SECRETS_HOOK_DEBUG", "0") == "1"

DEFAULT_SCAN_TIMEOUT = 90.0
MIN_SCAN_TIMEOUT = 1.0

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


_WRAP_WIDTH = 100
_LOG_PREFIX = "[snyk] "
_LOG_CONT_PREFIX = "  "
_WRAP_CONTINUATION_INDENT = "    "

# Non-breaking spaces keep this phrase from wrapping mid-line.
_SETTINGS_HINT = "Settings > Snyk Secrets"

# A placeholder unlikely to appear in a real message, used to protect
# spaces inside backtick-quoted commands from whitespace-splitting below.
_SPACE_PLACEHOLDER = "\x00"
_BACKTICK_SPAN_RE = re.compile(r"`[^`]*`")
_ANSI_SPAN_RE = re.compile(r"\033\[[0-9;]*m.*?\033\[0m")
_ANSI_CODE_RE = re.compile(r"\033\[[0-9;]*m")

_ANSI_RESET = "\033[0m"
_ANSI_DIM = "\033[2m"
_ANSI_GREEN = "\033[32m"
_ANSI_BOLD_RED = "\033[1;31m"


def _wrap_for_prefix(message: str, prefix: str, width: int = _WRAP_WIDTH) -> List[str]:
    """Word-wraps `message` to `width` columns, prefix/indent included.
    The first line is indented with `prefix`, every continuation line
    (including further wraps of a long first line) with
    `_WRAP_CONTINUATION_INDENT`. A backtick-quoted command is one atomic
    token and is never split, even if it alone exceeds `width`. `message`'s
    own line breaks (e.g. a multi-line exception) are preserved -- each is
    wrapped independently, not reflowed into the next."""
    lines: List[str] = []
    for i, raw_line in enumerate(message.split("\n")):
        indent = prefix if i == 0 else _WRAP_CONTINUATION_INDENT
        # Defuse any pre-existing placeholder byte first -- a real message
        # never intentionally contains one, so this can only prevent it
        # from being treated as a non-splittable character below, never
        # lose real content.
        raw_line = raw_line.replace(_SPACE_PLACEHOLDER, " ")
        protected = _BACKTICK_SPAN_RE.sub(
            lambda m: m.group(0).replace(" ", _SPACE_PLACEHOLDER), raw_line
        )
        protected = _ANSI_SPAN_RE.sub(
            lambda m: m.group(0).replace(" ", _SPACE_PLACEHOLDER), protected
        )
        wrapper = textwrap.TextWrapper(
            width=width,
            initial_indent=indent,
            subsequent_indent=_WRAP_CONTINUATION_INDENT,
            break_long_words=False,
            break_on_hyphens=False,
        )
        wrapped = wrapper.wrap(protected) or [indent]
        lines.extend(line.replace(_SPACE_PLACEHOLDER, " ") for line in wrapped)
    return lines


def _paint(line: str, color: Optional[str]) -> str:
    """Wraps an already-wrapped display line -- never call before
    word-wrapping, or escape codes would count toward line width."""
    if not color or not supports_color():
        return line
    return f"{color}{line}{_ANSI_RESET}"


def log(message: str, *, color: Optional[str] = None) -> None:
    """The one leading `[snyk] ...` line per phase, word-wrapped for
    display; the persisted log line stays whole, unwrapped, and uncolored."""
    for line in _wrap_for_prefix(message, _LOG_PREFIX):
        print(_paint(line, color), file=sys.stderr)
    if _LOG_FILE:
        append_log(_ANSI_CODE_RE.sub("", message), _LOG_FILE)


def log_cont(message: str, *, color: Optional[str] = None) -> None:
    """A continuation line under the most recent log() line, word-wrapped
    for display; the persisted log line stays whole, unwrapped, and uncolored."""
    for line in _wrap_for_prefix(message, _LOG_CONT_PREFIX):
        print(_paint(line, color), file=sys.stderr)
    if _LOG_FILE:
        append_log(_ANSI_CODE_RE.sub("", message), _LOG_FILE)


def debug(message: str) -> None:
    if DEBUG:
        log_cont(f"[debug] {message}", color=_ANSI_DIM)


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _scan_timeout() -> Optional[float]:
    """Seconds to allow for the scan, or None for no timeout at all --
    SECRETS_SCAN_TIMEOUT=-1 is the documented way to opt out entirely.
    Any other value is clamped to MIN_SCAN_TIMEOUT as before."""
    try:
        value = float(os.environ.get("SECRETS_SCAN_TIMEOUT", DEFAULT_SCAN_TIMEOUT))
    except ValueError:
        return DEFAULT_SCAN_TIMEOUT
    if value == -1:
        return None
    return value if value >= MIN_SCAN_TIMEOUT else MIN_SCAN_TIMEOUT


def _block_on_scan_failure() -> bool:
    return os.environ.get("SECRETS_BLOCK_ON_SCAN_FAILURE", "1") == "1"


def _fail_open_or_block(problem: str, *hints: str, indent: bool = False) -> int:
    """Logs `problem` with a fail-open/fail-closed suffix, then each hint
    on its own continuation line (never crammed onto the same line as
    `problem`), and returns the matching exit code."""
    emit = log_cont if indent else log
    blocking = _block_on_scan_failure()
    verdict = "blocking commit" if blocking else "allowing commit"
    emit(f"{problem}; {verdict}")
    for hint in hints:
        log_cont(hint)
    if blocking:
        log_cont(
            "set SECRETS_BLOCK_ON_SCAN_FAILURE=0 to allow the commit through scan failures instead"
        )
    return EXIT_BLOCK if blocking else EXIT_OK


def _auth_hint(snyk_bin: str) -> str:
    return f"run `{quote_for_paste(snyk_bin)} auth`"


# Fallback for when snyk auth's browser flow doesn't work on a managed device.
_AUTH_ADMIN_FALLBACK_HINT = "if that doesn't work, contact your Snyk administrator"


def _passthrough_or_fallback(message: Optional[str], fallback: str) -> str:
    """Prefers the CLI's own wording (glueing the settings phrase so it
    can't wrap mid-line); falls back to our own wording if extraction
    failed."""
    if message:
        return message.replace("Settings > Snyk Secrets", _SETTINGS_HINT)
    return fallback


def _cli_not_found_message() -> str:
    stale = stale_sidecar_pin()
    if stale:
        return (
            f"Snyk CLI unavailable -- {stale.path} {stale.problem}; re-run the installer "
            "with --cli-path pointing at a valid Snyk CLI, or contact your Snyk administrator"
        )
    return "Snyk CLI not found on PATH -- install with `npm install -g snyk`"


def _handle_scan_failure(status: ScanStatus, attempts: int, snyk_bin: str) -> int:
    """`snyk_bin` is interpolated into the hints: after a user-specified install
    there may be no `snyk` on PATH to suggest running. Auth/entitlement/
    permanent-failure errors are raised, not returned here -- handled in
    `_run()`."""
    manual_hint = f"run `{quote_for_paste(snyk_bin)} secrets test` manually to check"
    if status == "timeout":
        # attempts==0 means git operations alone ate the whole deadline
        # before a scan ever launched.
        timeout_msg = (
            "scan timed out before it could start (git operations used the full budget)"
            if attempts == 0
            else f"scan timed out after {_plural(attempts, 'attempt')}"
        )
        return _fail_open_or_block(
            timeout_msg,
            manual_hint,
            "increase SECRETS_SCAN_TIMEOUT or set it to -1 for no timeout",
            indent=True,
        )
    if status == "unparseable":
        return _fail_open_or_block(
            "scan output could not be parsed",
            manual_hint,
            indent=True,
        )
    # Only "retries_exhausted" remains -- every attempt failed the same way.
    return _fail_open_or_block(
        f"scan did not complete after {_plural(attempts, 'attempt')}",
        manual_hint,
        indent=True,
    )


def _log_summary(
    timer: Timer,
    status: ScanStatus,
    added: List[Finding],
    pre_existing: List[Finding],
    removed: List[Finding],
) -> None:
    """The closing "done in ..." headline. Only for a successful scan --
    a failure logs its own message."""
    timer.mark("end")
    if status != "success":
        return
    scan_ms = timer.segment_ms("prereqs_checked", "scan_done")
    if scan_ms is not None:
        debug(f"scan took {scan_ms / 1000:.1f}s (total {timer.total_ms() / 1000:.1f}s)")

    blocking = [f for f in added if not f.is_ignored]
    added_ignored = [f for f in added if f.is_ignored]
    under_review_count = len([f for f in blocking if f.is_under_review])
    line = summary_line(
        timer,
        len(blocking),
        pre_existing_count=len(pre_existing),
        under_review_count=under_review_count,
        added_ignored_count=len(added_ignored),
        removed_count=len(removed),
        highlight_blocking=supports_color(),
    )
    log_cont(line, color=None if blocking else _ANSI_GREEN)


@dataclass(frozen=True)
class ScanScope:
    """What to scan, which lines are newly added, and any rename mapping
    (populated only when the strategy needs a baseline scan)."""

    repo_root: Path
    files: List[str]
    ranges: LineRanges
    renames: Dict[str, str] = field(default_factory=dict)
    binary_files: List[str] = field(default_factory=list)
    remote_url: RemoteUrlDecision = field(default_factory=RemoteUrlDecision.unavailable)


_REMOTE_URL_STATUS_LABELS = {
    "unavailable": "no origin remote configured",
    "rejected_unsafe": "origin remote unsafe for the resolved Snyk CLI invocation",
}


def _remote_url_debug_label(decision: RemoteUrlDecision) -> str:
    return decision.url or f"(none -- {_REMOTE_URL_STATUS_LABELS[decision.status]})"


def resolve_scan_scope(
    cwd: Path, deadline: Optional[float], *, needs_renames: bool = False
) -> Tuple[Optional[ScanScope], Optional[int]]:
    """Returns (scope, None) to proceed, or (None, exit_code) to exit
    immediately. `needs_renames` skips the extra `get_rename_map` git call
    when the resolved strategy has no use for it.

    Deprecated-flag warnings are checked right after `_LOG_FILE` is set --
    early enough that every later early-return branch (no staged files, a
    prerequisite failure) still warns a user who's kept a deprecated env
    var set, but late enough that the warning is actually persisted (log()
    only appends to the per-repo log once _LOG_FILE is non-None). Only the
    "not inside a git repository" case (no _LOG_FILE possible at all) misses
    this warning -- nothing is lost there, since there's nowhere to persist
    it anyway.

    `deadline` bounds every git call here to the same shared wall-clock
    budget the scan step uses (see `_run`) -- these calls happen first, so
    without this they'd add unbounded time on top of the scan's own
    deadline instead of eating into it."""
    repo_root = find_repo_root(cwd)

    if repo_root is None:
        log("not inside a git repository")
        return None, EXIT_PREREQ

    global _LOG_FILE
    _LOG_FILE = resolve_log_file(str(repo_root))

    for warning in get_deprecated_flag_warnings():
        log(warning)

    staged = get_staged_files(repo_root, deadline)
    if staged is None:
        log("could not determine staged files; cannot safely scan staged changes")
        return None, EXIT_PREREQ
    if not staged:
        log("no staged files, skipping scan")
        return None, EXIT_OK

    line_ranges_result = get_added_line_ranges(repo_root, deadline)
    if line_ranges_result is None:
        log("could not determine added lines; cannot safely classify staged changes")
        return None, EXIT_PREREQ
    ranges, binary_files = line_ranges_result

    renames = get_rename_map(repo_root, deadline) if needs_renames else {}
    remote_url = get_remote_url(repo_root, deadline)
    scope = ScanScope(
        repo_root=repo_root,
        files=staged,
        ranges=ranges,
        renames=renames,
        binary_files=binary_files,
        remote_url=remote_url,
    )
    return scope, None


ClassifyResult = Tuple[List[Finding], List[Finding], List[Finding]]  # added, pre_existing, removed


def _classify_by_line_range(ctx: ClassificationContext) -> ClassifyResult:
    """The "line" DiffStrategy's classify function."""
    # Explicit annotation: mypy infers Any here otherwise.
    result: ClassifyResult = split_added_vs_pre_existing(ctx.findings, ctx.ranges)
    return result


@dataclass(frozen=True)
class DiffStrategy:
    """A pluggable way to classify findings. New strategy: a `classify`
    function plus one `_DIFF_STRATEGIES` entry."""

    name: str
    needs_baseline_scan: bool
    classify: Callable[[ClassificationContext], ClassifyResult]


_DIFF_STRATEGIES: Dict[str, DiffStrategy] = {
    "line": DiffStrategy("line", needs_baseline_scan=False, classify=_classify_by_line_range),
    "content": DiffStrategy("content", needs_baseline_scan=True, classify=classify_by_content),
}


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
    invocation: ScanInvocation,
    deadline: Optional[float],
    timer: Timer,
) -> Tuple[ScanStatus, int, List[Finding], List[Finding], List[Finding]]:
    _ensure_not_repo_workspace(scope, current_workspace)
    debug(f"scan workspace: {current_workspace} ({workspace_source})")

    if not strategy.needs_baseline_scan:
        return _scan_without_baseline(
            scope, strategy, current_workspace, invocation, deadline, timer
        )
    return _scan_with_baseline(scope, strategy, current_workspace, invocation, deadline, timer)


def _scan_and_classify(
    scope: ScanScope,
    strategy: DiffStrategy,
    invocation: ScanInvocation,
    deadline: Optional[float],
    timer: Timer,
) -> Tuple[ScanStatus, int, List[Finding], List[Finding], List[Finding]]:
    """Runs whichever scan(s) `strategy` needs and classifies the
    findings. A non-"success" status means empty, meaningless lists. The
    `int` is how many attempts the (possibly retried) current-workspace
    scan actually took.

    Raises `SnapshotError` (not `PrerequisiteFailure`) if the staged
    snapshot itself can't be prepared -- that's a runtime/environment
    failure (disk full, git subprocess issue), not a case where we don't
    know what to scan, so it should respect the user's fail-open/closed
    choice like any other scan failure. The caller (`_run`) handles it."""
    with staged_snapshot(scope.repo_root, scope.files, deadline) as snapshot_dir:
        return _scan_prepared_workspace(
            scope, strategy, snapshot_dir, "staged snapshot", invocation, deadline, timer
        )


def _scan_without_baseline(
    scope: ScanScope,
    strategy: DiffStrategy,
    current_workspace: Path,
    invocation: ScanInvocation,
    deadline: Optional[float],
    timer: Timer,
) -> Tuple[ScanStatus, int, List[Finding], List[Finding], List[Finding]]:
    """A strategy with no baseline scan (e.g. "line"): one scan, classified
    by `strategy.classify` directly against the diff's own added-line
    ranges."""
    debug(f"running current scan: workspace={current_workspace} target=.")
    attempt = run_secrets_scan_with_retries(current_workspace, invocation, deadline)
    status, findings = attempt.status, attempt.findings
    timer.mark("scan_done")
    if status != "success":
        return status, attempt.attempts, [], [], []
    ctx = ClassificationContext(
        findings=findings, ranges=scope.ranges, current_snapshot_dir=current_workspace
    )
    added, pre_existing, removed = strategy.classify(ctx)
    return status, attempt.attempts, added, pre_existing, removed


def _scan_with_baseline(
    scope: ScanScope,
    strategy: DiffStrategy,
    current_workspace: Path,
    invocation: ScanInvocation,
    deadline: Optional[float],
    timer: Timer,
) -> Tuple[ScanStatus, int, List[Finding], List[Finding], List[Finding]]:
    """A strategy that needs a baseline scan (e.g. "content"): also scans
    HEAD's version of the same files (concurrently, so no added wall-clock
    latency) before handing both result sets to `strategy.classify`."""
    baseline_lookup_paths = [scope.renames.get(f, f) for f in scope.files]
    with ref_snapshot(scope.repo_root, "HEAD", baseline_lookup_paths, deadline) as (
        baseline_dir,
        baseline_files,
        baseline_failed,
    ):
        if baseline_dir is None:
            # Nothing to compare against; classify_by_content degrades to
            # line-diff for an empty baseline_files.
            if baseline_failed:
                baseline_status = "unavailable"
            else:
                debug("baseline scan skipped: no scoped files exist at HEAD")
                baseline_status = "success"
            debug(f"running current scan: workspace={current_workspace} target=.")
            current_attempt = run_secrets_scan_with_retries(current_workspace, invocation, deadline)
            status, findings = current_attempt.status, current_attempt.findings
            baseline_findings: List[Finding] = []
        else:
            _ensure_not_repo_workspace(scope, baseline_dir)
            debug(f"baseline scan workspace: {baseline_dir} ({len(baseline_files)} files)")
            debug(
                f"running concurrent scans: current_workspace={current_workspace} "
                f"baseline_workspace={baseline_dir} target=."
            )
            current_attempt, baseline_attempt = run_concurrent_scans(
                current_workspace,
                baseline_dir,
                invocation,
                deadline,
            )
            status, findings = current_attempt.status, current_attempt.findings
            baseline_status, baseline_findings = baseline_attempt.status, baseline_attempt.findings
        timer.mark("scan_done")
        if status != "success":
            return status, current_attempt.attempts, [], [], []

        effective_strategy = strategy
        effective_baseline_dir = baseline_dir
        effective_baseline_files = baseline_files
        if baseline_status != "success":
            log_cont(
                f"baseline scan {baseline_status}; falling back to line-diff classification "
                "(weaker detection, won't report removed secrets)",
                color=_ANSI_DIM,
            )
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
        added, pre_existing, removed = effective_strategy.classify(ctx)
        return status, current_attempt.attempts, added, pre_existing, removed


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

    timeout = _scan_timeout()
    # A single process-wide monotonic clock, computed before any git or scan
    # work starts, so that work (not just the snyk subprocess itself) shares
    # one wall-clock budget instead of each having its own separate timeout
    # on top. Safe to read from multiple threads later (see
    # run_concurrent_scans): time.monotonic() isn't perturbed by wall-clock
    # adjustments, and reading it needs no extra locking.
    #
    # None (SECRETS_SCAN_TIMEOUT=-1) means no deadline at all -- every git
    # call still falls back to its own flat GIT_TIMEOUT, but nothing here
    # imposes an overall wall-clock ceiling.
    deadline = None if timeout is None else time.monotonic() + timeout

    strategy = _DIFF_STRATEGIES["content"]
    scope, early_exit = resolve_scan_scope(
        Path.cwd(), deadline, needs_renames=strategy.needs_baseline_scan
    )
    if early_exit is not None:
        return early_exit
    if scope is None:
        # Unreachable per resolve_scan_scope's contract; never scan an unknown scope.
        log("internal error: no scan scope resolved; cannot safely scan staged changes")
        return EXIT_PREREQ

    snyk_bin = find_snyk_binary()
    if snyk_bin is None:
        return _fail_open_or_block(_cli_not_found_message())
    if stale_sidecar_pin():
        return _fail_open_or_block(_cli_not_found_message())

    # Windows scans use cmd.exe, so reject its metacharacters up front.
    shell_needed = needs_shell(snyk_bin)
    remote_url = scope.remote_url
    if remote_url.url and proc.IS_WINDOWS and not is_safe_for_shell(remote_url.url):
        remote_url = remote_url.rejected()
    scope = replace(scope, remote_url=remote_url)
    invocation = ScanInvocation(
        snyk_bin=snyk_bin,
        remote_url=remote_url.url,
        needs_shell=shell_needed,
        env=build_snyk_env(snyk_bin),
    )

    try:
        authenticated = check_snyk_auth()
    except InvalidConfigError as e:
        return _fail_open_or_block(str(e))
    if authenticated is None:
        return _fail_open_or_block(
            "Snyk CLI not authenticated", _auth_hint(snyk_bin), _AUTH_ADMIN_FALLBACK_HINT
        )
    timer.mark("prereqs_checked")

    log(
        f"Scanning {_plural(len(scope.files), 'staged file')} for secrets... "
        "(bypass with `git commit --no-verify`)"
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
    debug(f"remote-repo-url: {_remote_url_debug_label(scope.remote_url)}")

    try:
        status, attempts, added, pre_existing, removed = _scan_and_classify(
            scope, strategy, invocation, deadline, timer
        )
    except SnapshotError as e:
        exit_code = _fail_open_or_block(str(e), indent=True)
        _log_summary(timer, "error", [], [], [])
        return exit_code
    except NotEntitledError as e:
        # Never gated by SECRETS_BLOCK_ON_SCAN_FAILURE -- entitlement can't
        # be fixed by retrying or reconfiguring.
        detail = _passthrough_or_fallback(e.message, "org is not entitled to Snyk Secrets")
        log_cont(f"{detail} -- allowing commit without scanning")
        return EXIT_OK
    except EntitlementCheckFailedError as e:
        fallback = "couldn't confirm whether Snyk Secrets is enabled for this Snyk Org"
        detail = _passthrough_or_fallback(e.message, fallback)
        log_cont(f"{detail} -- allowing commit without scanning")
        return EXIT_OK
    except AuthRequiredError as e:
        problem = _passthrough_or_fallback(e.message, "Snyk CLI not authenticated")
        exit_code = _fail_open_or_block(
            problem, _auth_hint(snyk_bin), _AUTH_ADMIN_FALLBACK_HINT, indent=True
        )
        _log_summary(timer, "error", [], [], [])
        return exit_code
    except PermanentScanFailureError as e:
        problem = _passthrough_or_fallback(e.message, e.fallback)
        manual_hint = f"run `{quote_for_paste(snyk_bin)} secrets test` manually to check"
        exit_code = _fail_open_or_block(problem, manual_hint, indent=True)
        _log_summary(timer, "error", [], [], [])
        return exit_code

    if status != "success":
        exit_code = _handle_scan_failure(status, attempts, snyk_bin)
        _log_summary(timer, status, [], [], [])
        return exit_code

    blocking = [f for f in added if not f.is_ignored]

    exit_code = EXIT_BLOCK if blocking else EXIT_OK
    _log_summary(timer, status, added, pre_existing, removed)
    if blocking:
        print_findings(blocking, scope.remote_url.url)
    history = history_line(len(pre_existing), len(removed))
    if history:
        log_cont(history, color=_ANSI_DIM)

    return exit_code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("interrupted")
        sys.exit(EXIT_BLOCK)
