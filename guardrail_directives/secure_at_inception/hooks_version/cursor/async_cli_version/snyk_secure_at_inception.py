#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# ///
"""
Cursor Hook: Snyk Secure At Inception
======================================

Launches background Snyk CLI scans on file edit, tracks modified
line ranges, and blocks the agent from stopping if new vulnerabilities were
introduced in agent-modified code.

WORKFLOW:
  1. sessionStart -> verify auth + CLI, launch cache-warming scan
  2. afterFileEdit -> track modified line ranges, launch background scan
  3. afterShellExecution -> detect Bash-driven manifest mutations, launch SCA scan
  4. stop -> wait for scan, filter results to modified lines, block if new vulns

INSTALLATION:
  1. Copy this script and lib/ to .cursor/hooks/
  2. chmod +x snyk_secure_at_inception.py
  3. Configure hooks.json (see hooks.json in this directory)

PREREQUISITES:
  - Python 3.8+
  - Snyk CLI (npm install -g snyk)
  - Snyk authentication (snyk auth)
"""

import json
import os
import re
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple, cast

SCRIPT_DIR = Path(__file__).parent.resolve()
LIB_DIR = SCRIPT_DIR / "lib"
sys.path.insert(0, str(LIB_DIR))

from platform_utils import (  # noqa: E402 — imports follow sys.path setup
    STUDIO_VERSION,
    file_lock,
    normalize_path,
    parse_iso_timestamp,
    resolve_log_file,
    scan_duration_secs,
)
from platform_utils import log as _shared_log  # noqa: E402 — imports follow sys.path setup
from scan_runner import (  # noqa: E402 — imports follow sys.path setup
    check_snyk_auth,
    check_snyk_cli,
    clear_manifest_hashes,
    clear_sca_baseline_state,
    clear_sca_scan_state,
    clear_scan_state,
    diff_manifest_hashes,
    ensure_cache_dirs,
    get_cache_dir,
    get_sca_baseline_completion_info,
    get_sca_completion_info,
    get_scan_completion_info,
    launch_background_sca_baseline_scan,
    launch_background_scan,
    load_manifest_hashes,
    save_manifest_hash_baseline,
    save_manifest_hash_last_scan,
    snapshot_manifest_hashes,
    trigger_sca_scan,
    trigger_scan,
    wait_for_sca_baseline_scan,
    wait_for_sca_scan,
    wait_for_scan,
    write_early_status,
)

# =============================================================================
# CONFIGURATION
# =============================================================================

DEBUG = os.environ.get("CURSOR_HOOK_DEBUG", "0") == "1"

# Resolved per-invocation in main() once the workspace is known (the hook is a
# short-lived process and the workspace comes from parsed stdin). Until then it
# is None: log_to_panel/debug_log degrade to stderr-only, and write_log is a no-op.
_LOG_FILE: Optional[str] = None

CODE_EXTENSIONS = {
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".py",
    ".java",
    ".kt",
    ".kts",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".vb",
    ".swift",
    ".m",
    ".mm",
    ".scala",
    ".rs",
    ".c",
    ".cpp",
    ".cc",
    ".h",
    ".hpp",
    ".cls",
    ".trigger",
    ".ex",
    ".exs",
    ".groovy",
    ".dart",
}

MANIFEST_FILES = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
    "build.sbt",
    "Gemfile",
    "Gemfile.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "packages.config",
    "packages.lock.json",
    "composer.json",
    "composer.lock",
    "Podfile",
    "Podfile.lock",
    "Package.swift",
    "Package.resolved",
    "mix.exs",
    "mix.lock",
    "pubspec.yaml",
    "pubspec.lock",
}

# No blanket ".lock": it matched any application runtime lock as a dependency
# manifest (observed triggering SCA on scheduled_tasks.lock and .venv/.lock).
# All 10 real lockfiles are named explicitly in MANIFEST_FILES.
MANIFEST_SUFFIXES = {".csproj", ".fsproj", ".vbproj"}

MAX_STOP_CYCLES = 3

# How each unscanned status reads in a log line and, where it differs, to the
# user. A status absent from this map is one where the scan actually ran and
# burned wall clock, and is reported by its raw status.
_UNSCANNED_REASON = {
    "auth_required": "Snyk CLI not authenticated",
    "snyk_not_found": "Snyk CLI not found on PATH",
}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Scan error detail is raw CLI stderr and can be multi-line. Panel log entries are
# one timestamped line each; the degraded-scan notice is a single line in the
# same log, so it gets the tighter cap. The workers already cap what they write;
# these guard the read side, which parses a done-file that a worker from a
# different install may have written.
LOG_DETAIL_MAX_LEN = 200
NOTICE_DETAIL_MAX_LEN = 160

# Emitted at most once per session when a scan could not run because the CLI is
# unauthenticated. Authenticating repairs the configstore every later background
# scan reads, so it is worth one round trip -- but it is handed to the user, not
# to an MCP tool: `snyk auth` is an interactive browser flow and the scan worker
# runs detached with DEVNULL stdin, so neither the hook nor the agent can
# complete it. Nothing here delegates scanning either; the MCP scan tools are
# the same binary that just failed.
# The opening clause names only the engine(s) that actually hit auth. SAST and
# SCA authenticate independently in practice -- a token good for `snyk code` can
# still 401 on `snyk test` -- so asserting the whole turn went unscanned would
# contradict a code scan that did complete.
_AUTH_PROMPT_SCOPE = {
    (True, True): "so this turn was not scanned",
    (True, False): "so this turn's code was not scanned",
    (False, True): "so this turn's dependencies were not scanned",
}


def _auth_prompt_reason(sast_unauthed: bool, sca_unauthed: bool) -> str:
    """One-per-session auth prompt, scoped to the engine(s) that failed."""
    scope = _AUTH_PROMPT_SCOPE.get((sast_unauthed, sca_unauthed), "so this turn was not scanned")
    return (
        f"Snyk security scanning is not authenticated, {scope}.\n\n"
        "Tell the user to run `snyk auth` in a terminal.\n\n"
        "Do NOT run any Snyk scan tools yourself -- the scan runs automatically in the "
        "background and will pick up this turn's changes on your next stop."
    )


# =============================================================================
# STOP HANDLER RESULT TYPES
# =============================================================================


@dataclass
class StopContext:
    """State and manifest-hash bookkeeping carried out of _check_stop_preconditions."""

    state: Dict[str, Any]
    hashes: Dict[str, Any]
    current_hashes: Dict[str, str]
    hash_changed_from_baseline: List[str]
    hash_changed_from_last_scan: List[str]


@dataclass
class SastResult:
    new_vulns: List[Dict[str, Any]] = field(default_factory=list)
    clean_file_paths: List[str] = field(default_factory=list)
    dirty_file_paths: List[str] = field(default_factory=list)
    unevaluated_file_paths: List[str] = field(default_factory=list)
    unscanned_status: str = ""
    unscanned_detail: str = ""
    scan_info: Optional[Dict[str, Any]] = None


@dataclass
class ScaResult:
    new_sca_vulns: List[Dict[str, Any]] = field(default_factory=list)
    unscanned_status: str = ""
    unscanned_detail: str = ""
    duration: Optional[float] = None
    changed_manifests: List[str] = field(default_factory=list)


def _severity_counts_dict(vulns: List[Dict[str, Any]]) -> Dict[str, int]:
    """Tally vulns into a critical/high/medium/low dict, e.g. for preventedIssuesBySeverity."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for vuln in vulns:
        sev = vuln.get("severity", "").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _severity_counts(vulns: List[Dict[str, Any]]) -> str:
    counts = _severity_counts_dict(vulns)
    return f"critical:{counts['critical']} high:{counts['high']} medium:{counts['medium']} low:{counts['low']}"


def _top_vuln_ids(vulns: List[Dict[str, Any]], max_result_count: int = 3) -> str:
    results: List[str] = []
    for vuln in vulns:
        if len(results) >= max_result_count:
            break
        vuln_id = vuln.get("id", "")
        if vuln_id:
            results.append(f"{vuln_id}({vuln.get('severity', 'unknown')})")
    return ", ".join(results)


def _prevented_issue_ids(
    sast_vulns: List[Dict[str, Any]], sca_vulns: List[Dict[str, Any]]
) -> List[str]:
    """Build the prefixed Snyk ID list for snyk_send_feedback's preventedIssueIds."""
    ids: List[str] = []
    for v in sast_vulns:
        vid = v.get("id")
        if vid:
            ids.append(f"sast:{vid}")
    for v in sca_vulns:
        vid = v.get("id")
        if vid:
            ids.append(f"sca:{vid}")
    return ids


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def debug_log(message: str) -> None:
    if DEBUG:
        print(f"[DEBUG] {message}", file=sys.stderr)
    _shared_log(message, _LOG_FILE, debug=True)


def log_to_panel(message: str) -> None:
    print(message, file=sys.stderr)
    if _LOG_FILE:
        _shared_log(message, _LOG_FILE, debug=False)


def write_log(message: str) -> None:
    """Persist routine, decision-level detail to the log file, same as
    log_to_panel, but never print to stderr -- for normal-flow operation that
    should have a full history in log.txt without tripping Cursor's
    stderr-based hook-error indicator."""
    if _LOG_FILE:
        _shared_log(message, _LOG_FILE, debug=False)


def output_response(response: Dict[str, Any]) -> None:
    print(json.dumps(response))
    # Flush explicitly: under `uvw run --gui-script` (pythonw) on Windows stdout is
    # a fully-buffered pipe, so the findings JSON must be flushed to reach the ADE.
    sys.stdout.flush()


def get_state_file_path(workspace: str) -> str:
    return os.path.join(get_cache_dir(workspace), "state.json")


def get_workspace(data: Dict[str, Any]) -> str:
    workspace_roots = data.get("workspace_roots", [])
    if workspace_roots:
        ws = str(workspace_roots[0])
        # Cursor on Windows delivers paths as /C:/... (POSIX-style drive letter).
        if (
            sys.platform == "win32"
            and len(ws) >= 3
            and ws[0] == "/"
            and ws[1].isalpha()
            and ws[2] == ":"
        ):
            ws = ws[1:]
        return ws

    file_path = data.get("file_path", "")
    if file_path:
        path = Path(file_path)
        for parent in path.parents:
            if (parent / ".cursor").exists():
                return str(parent)
            if (parent / ".git").exists():
                return str(parent)

    return os.getcwd()


def is_code_file(file_path: str) -> bool:
    return Path(file_path).suffix.lower() in CODE_EXTENSIONS


def _within_workspace(file_path: str, workspace: str) -> bool:
    """Whether an edited path belongs to the workspace we are securing.

    Defence-in-depth behind the extension allowlist, which already rejects the
    scratch files agents actually write (.md, .sh, .json, .txt). This exists so
    that widening CODE_EXTENSIONS later cannot silently start scanning outside
    the tree, and so a code-extension scratch file elsewhere on disk cannot
    trigger a scan of an unrelated workspace.

    Relative paths resolve against the workspace rather than the hook process's
    cwd, so "src/app.py" is contained while "../../escape/app.py" is not.

    Deliberately no separate tempdir denylist: containment already rejects a
    /tmp scratch file when the project lives elsewhere, and an explicit tempdir
    rule would reject a workspace that legitimately *is* a temp dir -- which is
    how every test fixture and many CI checkouts are laid out.
    """
    try:
        candidate = Path(file_path)
        if not candidate.is_absolute():
            candidate = Path(workspace) / candidate
        resolved = candidate.resolve()
        root = Path(workspace).resolve()
    except (OSError, ValueError):
        return False
    return resolved == root or root in resolved.parents


# Note: Bash-driven manifest mutations (`npm install`, `pip install`, etc.) bypass
# the afterFileEdit hook and won't trigger this path. The hash-diff in
# detect_manifest_changes still catches them when some code file is also edited.
def is_manifest_file(file_path: str) -> bool:
    p = Path(file_path)
    return p.name in MANIFEST_FILES or p.suffix.lower() in MANIFEST_SUFFIXES


# =============================================================================
# LINE TRACKING (computes which lines the agent modified)
# =============================================================================


def compute_modified_ranges(file_content: str, edits: List[Dict[str, str]]) -> List[Dict[str, int]]:
    """Locate new_string in post-edit file content to determine modified line ranges."""
    ranges: List[Dict[str, int]] = []
    search_offset = 0

    for edit in edits:
        new_str = edit.get("new_string", "")
        if not new_str:
            continue

        idx = file_content.find(new_str, search_offset)
        if idx < 0:
            idx = file_content.find(new_str)

        if idx >= 0:
            start_line = file_content[:idx].count("\n") + 1
            end_line = start_line + new_str.count("\n")
            ranges.append({"start": start_line, "end": end_line})
            search_offset = idx + len(new_str)

    return _merge_ranges(ranges)


def _merge_ranges(ranges: List[Dict[str, int]]) -> List[Dict[str, int]]:
    if not ranges:
        return []
    sorted_ranges = sorted(ranges, key=lambda r: r["start"])
    merged: List[Dict[str, int]] = [sorted_ranges[0].copy()]
    for current in sorted_ranges[1:]:
        last = merged[-1]
        if current["start"] <= last["end"] + 1:
            last["end"] = max(last["end"], current["end"])
        else:
            merged.append(current.copy())
    return merged


def _accumulate_ranges(
    existing: List[Dict[str, int]], new: List[Dict[str, int]]
) -> List[Dict[str, int]]:
    return _merge_ranges(existing + new)


# =============================================================================
# VULNERABILITY FILTERING (isolates new vulns on agent-modified lines)
# =============================================================================


def _paths_match(path_a: str, path_b: str) -> bool:
    """Segment-aware suffix comparison."""
    norm_a = normalize_path(path_a)
    norm_b = normalize_path(path_b)
    if norm_a == norm_b:
        return True
    parts_a = norm_a.split("/")
    parts_b = norm_b.split("/")
    shorter, longer = sorted([parts_a, parts_b], key=len)
    return bool(longer[-len(shorter) :] == shorter)


def _find_vulns_for_file(
    file_path: str,
    results_by_file: Dict[str, List[Dict[str, Any]]],
) -> Optional[List[Dict[str, Any]]]:
    if file_path in results_by_file:
        return results_by_file[file_path]
    normalized = normalize_path(file_path)
    for cached_path, vulns in results_by_file.items():
        if _paths_match(cached_path, normalized):
            return vulns
    return None


def _filter_new_vulns(
    vulns: List[Dict[str, Any]],
    modified_ranges: List[Dict[str, int]],
) -> List[Dict[str, Any]]:
    if not modified_ranges:
        return []
    return [
        v
        for v in vulns
        if any(r["start"] <= v.get("start_line", 0) <= r["end"] for r in modified_ranges)
        and v.get("start_line", 0) > 0
    ]


def _evaluate_files(
    tracked_files: Dict[str, Dict[str, Any]],
    results_by_file: Dict[str, List[Dict[str, Any]]],
) -> Dict[str, List[Dict[str, Any]]]:
    """Filter scan results per tracked file to only new vulns on modified lines.

    Files with no matching scan results are omitted from the returned dict,
    allowing callers to distinguish evaluated-clean (empty list) from
    unevaluated (key absent).
    """
    per_file: Dict[str, List[Dict[str, Any]]] = {}
    for file_path, file_info in tracked_files.items():
        modified_ranges = file_info.get("modified_ranges", [])
        if not modified_ranges:
            per_file[file_path] = []
            continue
        file_vulns = _find_vulns_for_file(file_path, results_by_file)
        if file_vulns is None:
            continue
        per_file[file_path] = _filter_new_vulns(file_vulns, modified_ranges)
    return per_file


def _truncate(text: str, max_len: int) -> str:
    """Truncate text to max_len, marking the cut with an ellipsis."""
    return text if len(text) <= max_len else text[: max_len - 3] + "..."


def _format_vuln_table(vulns: List[Dict[str, Any]]) -> str:
    if not vulns:
        return ""
    lines = [
        "| # | Severity | ID | Title | CWE | File | Line | Description |",
        "|---|----------|----|-------|-----|------|------|-------------|",
    ]
    for i, v in enumerate(vulns, 1):
        msg = v.get("message", "").replace("|", "/").replace("\n", " ")
        if len(msg) > 100:
            msg = msg[:97] + "..."
        lines.append(
            f"| {i} | {v.get('severity', '?')} | {v.get('id', '?')} "
            f"| {v.get('title', '?')} | {v.get('cwe', '-')} "
            f"| {v.get('file_path', '?')} | {v.get('start_line', 0)} | {msg} |"
        )
    return "\n".join(lines)


def _should_block_on_sca_severity(severity: str) -> bool:
    """Return True iff `severity` is at or above SAI_MIN_BLOCK_SEVERITY (default medium)."""
    threshold = os.environ.get("SAI_MIN_BLOCK_SEVERITY", "medium").lower()
    if threshold not in _SEVERITY_ORDER:
        threshold = "medium"
    return _SEVERITY_ORDER.get(severity.lower(), 4) <= _SEVERITY_ORDER[threshold]


def _format_sca_vuln_table(vulns: List[Dict[str, Any]]) -> str:
    if not vulns:
        return ""
    lines = [
        "| # | Severity | ID | Package | Version | CVE | Fix Available |",
        "|---|----------|----|---------|---------|-----|--------------|",
    ]
    for i, v in enumerate(vulns, 1):
        fix = "Yes" if v.get("fix_available") else "No"
        lines.append(
            f"| {i} | {v.get('severity', '?')} | {v.get('id', '?')} "
            f"| {v.get('package_name', '?')} | {v.get('version', '?')} "
            f"| {v.get('cve') or '-'} | {fix} |"
        )
    return "\n".join(lines)


# =============================================================================
# STATE MANAGEMENT
# =============================================================================


@contextmanager
def _state_lock(workspace: str) -> Generator[None, None, None]:
    """Exclusive file lock for state.json read-modify-write operations.
    Uses fcntl on Unix and msvcrt on Windows."""
    ensure_cache_dirs(workspace)
    lock_path = get_state_file_path(workspace) + ".lock"
    with file_lock(lock_path):
        yield


@contextmanager
def _mutate_state(workspace: str) -> Generator[Dict[str, Any], None, None]:
    """Read-modify-write state.json under the workspace lock."""
    with _state_lock(workspace):
        state = read_state(workspace)
        yield state
        write_state(workspace, state)


def read_state(workspace: str) -> Dict[str, Any]:
    state_file = get_state_file_path(workspace)
    try:
        if os.path.exists(state_file):
            with open(state_file) as f:
                return cast(Dict[str, Any], json.load(f))
    except (OSError, json.JSONDecodeError):
        pass
    return {
        "code_files": {},
        "stop_cycles": 0,
        "last_edit_ts": "",
        "last_update": None,
    }


def write_state(workspace: str, state: Dict[str, Any]) -> None:
    ensure_cache_dirs(workspace)
    state_file = get_state_file_path(workspace)
    state["last_update"] = datetime.now().isoformat()
    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)


def clear_state(workspace: str) -> None:
    """Clear per-cycle tracking state and regular scan files. Does not touch baselines."""
    state_file = get_state_file_path(workspace)
    if os.path.exists(state_file):
        try:
            os.remove(state_file)
        except OSError:
            pass
    clear_scan_state(workspace)
    clear_sca_scan_state(workspace)


def clear_baseline(workspace: str) -> None:
    """Clear baseline scan files. Called only at session start and max-cycles reset."""
    clear_sca_baseline_state(workspace)
    clear_manifest_hashes(workspace)


def has_pending_changes(state: Dict[str, Any]) -> bool:
    return bool(state.get("code_files"))


def _log_unscanned(
    engine: str, status: Optional[str], info: Optional[Dict[str, Any]]
) -> Tuple[str, str]:
    """Record why `engine` produced no results. Returns (status, flat detail).

    The detail is raw CLI stderr: flattened to one line here so it can go in a
    single timestamped log entry, and capped again at the narrower
    NOTICE_DETAIL_MAX_LEN by whoever renders it.
    """
    status = status or "unknown"
    detail = " ".join(((info or {}).get("error_detail") or "").split())
    suffix = f" (detail: {_truncate(detail, LOG_DETAIL_MAX_LEN)})" if detail else ""
    reason = _UNSCANNED_REASON.get(status)
    label = f"{engine} unscanned: {reason}" if reason else f"{engine} unscanned (status: {status})"
    log_to_panel(f"[SAI] {label}{suffix}")
    return status, detail


# =============================================================================
# HOOK HANDLERS
# =============================================================================


def handle_session_start(data: Dict[str, Any], workspace: str) -> None:
    """Verify prerequisites and launch a cache-warming scan at session start.

    Checks Snyk auth and CLI presence. If either is missing, reports via
    followup_message so the agent can inform the user. If all checks pass,
    launches a background scan to warm Snyk's internal analysis cache.
    """
    # One auth prompt per session, so a new session gets its prompt back. This
    # runs before the checks below deliberately: they return early when auth is
    # missing, which is precisely the session that needs the prompt re-armed.
    # Cursor's clear_state() further down would also drop it, but only on the
    # path where auth already works.
    with _mutate_state(workspace) as state:
        state.pop("auth_prompted", None)

    issues: List[str] = []

    # 1. Check Snyk auth
    if check_snyk_auth() is None:
        issues.append("auth")
        log_to_panel("[SAI] Snyk CLI not authenticated")

    # 2. Check Snyk CLI presence
    if check_snyk_cli() is None:
        issues.append("cli")
        log_to_panel("[SAI] Snyk CLI not found on PATH")

    # 3. Report issues via followup_message and write early status
    if issues:
        message_parts: List[str] = []
        if "cli" in issues:
            message_parts.append(
                "Snyk CLI is not installed or not on PATH. Security scanning "
                "requires the Snyk CLI. Install it with `npm install -g snyk` "
                "and authenticate with `snyk auth`."
            )
            write_early_status(
                workspace,
                "snyk_not_found",
                "Snyk CLI not found on PATH.",
            )
        elif "auth" in issues:
            message_parts.append(
                "Snyk CLI is not authenticated. Security scanning is unavailable "
                "until you run `snyk auth` in a terminal to authenticate."
            )
            write_early_status(
                workspace,
                "auth_required",
                "Snyk CLI is not authenticated. Run snyk auth.",
            )

        output_response({"followup_message": " ".join(message_parts)})
        return

    # Cursor has no source field -- sessionStart only fires for a genuinely
    # new conversation, so always clear state and (re)capture the baseline.
    write_log("[SAI] Snyk authenticated, CLI found")
    if _LOG_FILE:
        _shared_log(f"SessionStart: studio v{STUDIO_VERSION}", _LOG_FILE)
    clear_state(workspace)
    clear_baseline(workspace)
    if launch_background_sca_baseline_scan(workspace):
        write_log("[SAI] SCA baseline scan launched")
        save_manifest_hash_baseline(workspace, MANIFEST_FILES, MANIFEST_SUFFIXES)
    else:
        debug_log("SCA baseline scan not launched (already running or complete)")

    # SAST has no baseline concept -- always safe to warm.
    if launch_background_scan(workspace):
        write_log("[SAI] Cache-warming scan launched")
    else:
        debug_log("Cache-warm scan not launched (already running or complete)")

    output_response({"exit_code": 0})


# Package managers whose mutate verbs can rewrite a dependency manifest or
# lockfile. Matched against the whole shell command string, so `cd api && npm
# install` and `sudo pip install -r reqs.txt` are both caught.
_PKG_MANAGERS = (
    "npm",
    "yarn",
    "pnpm",
    "pip",
    "pip3",
    "pipenv",
    "poetry",
    "uv",
    "go",
    "cargo",
    "bundle",
    "composer",
    "mvn",
    "gradle",
    "dotnet",
)
_PKG_MUTATE_VERBS = (
    "install",
    "add",
    "update",
    "upgrade",
    "remove",
    "uninstall",
    "tidy",
    "sync",
    "get",
    "restore",
    "require",
    "ci",
    "vendor",
)
# JVM build tools spell dependency resolution as a goal/flag rather than a verb.
# They need their own pattern because the token that gives them away ("build",
# with a refresh flag) would match `go build` and `cargo build` if it were
# folded into the generic verb list above.
_JVM_BUILD_TOOLS = ("mvn", "gradle", "gradlew")
_JVM_DEP_TOKENS = ("dependency", "dependencies", "refresh-dependencies", "resolve")
_PKG_COMMAND_RE = re.compile(
    r"\b(?:" + "|".join(_PKG_MANAGERS) + r")\b[^&|;]*?\b(?:" + "|".join(_PKG_MUTATE_VERBS) + r")\b"
    r"|\b(?:" + "|".join(_JVM_BUILD_TOOLS) + r")\b[^&|;]*?(?:" + "|".join(_JVM_DEP_TOKENS) + r")",
    re.IGNORECASE,
)


def _may_touch_manifests(command: str) -> bool:
    """Whether a shell command plausibly mutates a dependency manifest.

    The afterShellExecution hook used to walk and hash the entire workspace on
    *every* command -- 43s and 11k files when the session was started from
    $HOME. This is only a fast path: the stop hook's hash diff is still the
    authoritative check, so a mutation this misses is caught at the end of the
    turn.
    """
    return bool(command) and bool(_PKG_COMMAND_RE.search(command))


def _trigger_sca_and_save(workspace: str, snapshot: Dict[str, str]) -> None:
    """Trigger an SCA scan and record snapshot as the new last-scan reference."""
    if trigger_sca_scan(workspace):
        write_log("[SAI] Background SCA scan launched")
        save_manifest_hash_last_scan(workspace, MANIFEST_FILES, MANIFEST_SUFFIXES, hashes=snapshot)


def handle_after_file_edit(data: Dict[str, Any], workspace: str) -> None:
    """Track file edits and launch background scans."""
    file_path = data.get("file_path", "")
    edits = data.get("edits", [])

    is_code = is_code_file(file_path)
    is_manifest = is_manifest_file(file_path)
    if not is_code and not is_manifest:
        debug_log(f"File not scannable, ignoring: {file_path}")
        output_response({"exit_code": 0})
        return

    if not _within_workspace(file_path, workspace):
        debug_log(f"File outside workspace, ignoring: {file_path}")
        output_response({"exit_code": 0})
        return

    if is_code:
        # Tracked with separators unified so the same file edited via
        # backslash- vs forward-slash-separated paths (both reported by
        # Windows tooling across separate tool calls) accumulates into one
        # entry instead of silently splitting into two. Only the separator
        # is touched -- unlike normalize_path, the rest of the path (leading
        # slash, ./ prefix) is left alone since this key never needs to be
        # suffix-matched, only self-consistent across calls.
        file_key = file_path.replace("\\", "/")
        with _state_lock(workspace):
            state = read_state(workspace)

            try:
                file_content = Path(file_path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                file_content = ""

            new_ranges = compute_modified_ranges(file_content, edits)
            code_files = state.get("code_files", {})
            existing = code_files.get(file_key, {}).get("modified_ranges", [])
            code_files[file_key] = {
                "modified_ranges": _accumulate_ranges(existing, new_ranges),
                "last_edit": datetime.now().isoformat(),
            }
            state["code_files"] = code_files
            state["last_edit_ts"] = datetime.now().isoformat()
            write_state(workspace, state)
            range_count = len(code_files[file_key]["modified_ranges"])

        write_log(f"[SAI] Tracked: {Path(file_path).name} ({range_count} range(s))")

        # Peek at cached scan status for early error detection.
        # If sessionStart or a prior scan_worker wrote an error status,
        # block immediately instead of waiting for the stop hook.
        scan_info = get_scan_completion_info(workspace)
        if scan_info:
            cached_status = scan_info.get("status")
            if cached_status in ("auth_required", "snyk_not_found"):
                log_to_panel(f"[SAI] Prerequisite issue detected: {cached_status}")
                clear_scan_state(workspace)  # Allow recovery on next edit

                if cached_status == "auth_required":
                    reason = (
                        "Snyk CLI is not authenticated. Security scanning cannot run. "
                        "Please run `snyk auth` in a terminal to authenticate, "
                        "then continue editing."
                    )
                else:
                    reason = (
                        "Snyk CLI is not installed or not on PATH. Security scanning "
                        "cannot run. Please install the Snyk CLI with "
                        "`npm install -g snyk` and authenticate with `snyk auth`, "
                        "then continue editing."
                    )
                output_response({"followup_message": reason})
                return

        if launch_background_scan(workspace):
            write_log("[SAI] Background scan launched")

    # NOTE: keeping is_manifest for now. But SCA scans usually need
    # the package manager to have actually installed packages. So an agent
    # file edit will not result in an SCA-detectable vuln.
    if is_manifest:
        write_log(f"[SAI] Manifest edit tracked: {Path(file_path).name}")
        snapshot = snapshot_manifest_hashes(workspace, MANIFEST_FILES, MANIFEST_SUFFIXES)
        _trigger_sca_and_save(workspace, snapshot)

    output_response({"exit_code": 0})


def _detect_manifest_mutation_from_shell(workspace: str) -> None:
    """Check whether manifests changed since the last known snapshot and, if so,
    trigger an SCA scan.

    Bash-driven manifest mutations (npm install, pip install, etc.) bypass the
    afterFileEdit path. Detect them by checking whether any manifest file
    actually changed on disk after the command ran.
    """
    write_log("[SAI] Package-manager command detected. Checking if manifests changed.")
    hashes = load_manifest_hashes(workspace) or {}
    # Before any scan has run this session, the only thing to compare against
    # is the session-start baseline; once last_scan is populated it's the
    # tighter reference for "is anything different since we last scanned?"
    compare_against = hashes.get("last_scan") or hashes.get("baseline", {})
    snapshot = snapshot_manifest_hashes(workspace, MANIFEST_FILES, MANIFEST_SUFFIXES)
    changed = diff_manifest_hashes(snapshot, compare_against)
    if changed:
        write_log(f"[SAI] Manifest change detected: {', '.join(Path(f).name for f in changed)}")
        _trigger_sca_and_save(workspace, snapshot)


def handle_after_shell_execution(data: Dict[str, Any], workspace: str) -> None:
    """Detect Bash-driven manifest mutations that bypass afterFileEdit."""
    command = str(data.get("command", ""))
    if not _may_touch_manifests(command):
        debug_log(f"Shell command cannot touch manifests, skipping walk: {command[:120]}")
        output_response({"exit_code": 0})
        return
    _detect_manifest_mutation_from_shell(workspace)
    output_response({"exit_code": 0})


def _check_stop_preconditions(workspace: str) -> Tuple[Optional[Dict[str, Any]], StopContext]:
    """Read state, compute manifest-hash diffs, and handle the no-pending-changes
    and max-cycles-reached early exits. Runs under _state_lock.

    Returns (early_response, ctx). If early_response is not None, the caller
    should output_response(early_response) and return immediately."""
    with _state_lock(workspace):
        state = read_state(workspace)

        hashes = load_manifest_hashes(workspace) or {}
        current_hashes = snapshot_manifest_hashes(workspace, MANIFEST_FILES, MANIFEST_SUFFIXES)
        hash_changed_from_baseline = diff_manifest_hashes(
            current_hashes, hashes.get("baseline", {})
        )
        hash_changed_from_last_scan = diff_manifest_hashes(
            current_hashes, hashes.get("last_scan", {})
        )

        ctx = StopContext(
            state=state,
            hashes=hashes,
            current_hashes=current_hashes,
            hash_changed_from_baseline=hash_changed_from_baseline,
            hash_changed_from_last_scan=hash_changed_from_last_scan,
        )

        if not has_pending_changes(state) and not hash_changed_from_baseline:
            write_log(
                f"[SAI] Stop: no pending changes (tracked files: {len(state.get('code_files', {}))}, "
                f"manifest hashes changed vs baseline: {len(hash_changed_from_baseline)})"
            )
            return {}, ctx

        stop_cycles = state.get("stop_cycles", 0)
        if stop_cycles >= MAX_STOP_CYCLES:
            # Intentional: giving up enforcement after MAX_STOP_CYCLES is expected
            # behavior, not a hook failure, so this stays off stderr.
            write_log(f"[SAI] Max cycles ({MAX_STOP_CYCLES}) reached, allowing stop")
            clear_state(workspace)
            # Clear and reset the SCA baseline to accept the current state.
            clear_baseline(workspace)
            if launch_background_sca_baseline_scan(workspace):
                save_manifest_hash_baseline(workspace, MANIFEST_FILES, MANIFEST_SUFFIXES)
            return {}, ctx

    # The cycle counter is advanced by the paths that actually block. A stop
    # that ends in an unscanned turn must not burn a fix cycle: three of those
    # would trip the max-cycles reset above, which clears tracking *and*
    # rebaselines SCA, hiding real dependency vulns once scanning recovers.
    return None, ctx


def _evaluate_sast(
    state: Dict[str, Any],
    workspace: str,
    code_files: Dict[str, Dict[str, Any]],
) -> SastResult:
    """Wait for the SAST scan, re-scanning once if stale, and filter results
    down to newly introduced vulns on agent-modified lines."""
    if not code_files:
        return SastResult()

    scan_status = wait_for_scan(workspace, log_fn=write_log)
    scan_succeeded = scan_status == "success"
    scan_info: Optional[Dict[str, Any]] = None

    # Stale detection: re-scan if edits happened after scan started
    if scan_succeeded:
        scan_info = get_scan_completion_info(workspace)
        last_edit_ts = state.get("last_edit_ts", "")
        started_at = (
            (scan_info.get("started_at") or scan_info.get("completed_at", "")) if scan_info else ""
        )

        if last_edit_ts and started_at and last_edit_ts > started_at:
            write_log("[SAI] Edits after scan started, re-scanning...")
            trigger_scan(workspace)
            scan_status = wait_for_scan(workspace, log_fn=write_log)
            scan_succeeded = scan_status == "success"
            scan_info = None

    if scan_succeeded:
        scan_info = scan_info or get_scan_completion_info(workspace)
        all_vulns = scan_info.get("vulnerabilities", []) if scan_info else []

        results_by_file: Dict[str, List[Dict[str, Any]]] = {}
        for v in all_vulns:
            fp = v.get("file_path", "")
            if fp:
                results_by_file.setdefault(fp, []).append(v)

        per_file_results = _evaluate_files(code_files, results_by_file)

        new_vulns: List[Dict[str, Any]] = []
        clean_file_paths: List[str] = []
        dirty_file_paths: List[str] = []
        unevaluated_file_paths: List[str] = []
        for fp in code_files:
            if fp in per_file_results:
                file_vulns = per_file_results[fp]
                if file_vulns:
                    dirty_file_paths.append(fp)
                    new_vulns.extend(file_vulns)
                else:
                    clean_file_paths.append(fp)
            else:
                unevaluated_file_paths.append(fp)

        new_vulns.sort(
            key=lambda v: (
                _SEVERITY_ORDER.get(v.get("severity", "low"), 4),
                v.get("file_path", ""),
                v.get("start_line", 0),
            )
        )

        return SastResult(
            new_vulns=new_vulns,
            clean_file_paths=clean_file_paths,
            dirty_file_paths=dirty_file_paths,
            unevaluated_file_paths=unevaluated_file_paths,
            scan_info=scan_info,
        )

    scan_info = get_scan_completion_info(workspace)
    status, detail = _log_unscanned("SAST", scan_status, scan_info)
    return SastResult(unscanned_status=status, unscanned_detail=detail, scan_info=scan_info)


def _evaluate_sca(
    workspace: str,
    code_files: Dict[str, Dict[str, Any]],
    manifests_changed: bool,
    hash_changed_from_baseline: List[str],
    hash_changed_from_last_scan: List[str],
    current_hashes: Dict[str, str],
    hashes: Dict[str, Any],
) -> ScaResult:
    """Wait for the SCA scan, re-scanning once if stale, and diff dependency
    vulns against the session-start baseline."""
    if not manifests_changed:
        return ScaResult()

    baseline_keys = None
    baseline_hashes = hashes.get("baseline") or {}
    changed_manifests = hash_changed_from_baseline if manifests_changed else []

    if manifests_changed:
        if hash_changed_from_baseline:
            debug_log(f"[SAI] Detected manifest change(s): {hash_changed_from_baseline}")

        # Re-run SCA only if manifests changed since the last scan
        if hash_changed_from_last_scan:
            write_log("[SAI] Manifest changes detected — re-running SCA scan")
            if trigger_sca_scan(workspace):
                write_log("[SAI] Background SCA scan launched")
                save_manifest_hash_last_scan(
                    workspace, MANIFEST_FILES, MANIFEST_SUFFIXES, hashes=current_hashes
                )

    # Ensure the session-start baseline is complete before comparing
    wait_for_sca_baseline_scan(workspace, log_fn=write_log)
    baseline_info = get_sca_baseline_completion_info(workspace)
    if baseline_info and baseline_info.get("status") == "success" and baseline_hashes:
        baseline_vulns = baseline_info.get("vulnerabilities", [])
        baseline_keys = frozenset(
            (v.get("id", ""), v.get("package_name", ""), v.get("version", ""))
            for v in baseline_vulns
        )
    elif baseline_info and baseline_info.get("status") == "success":
        # baseline_keys stays None here, so downstream: manifests_changed reports
        # every current finding as new, otherwise new_sca_vulns is forced to [].
        write_log(
            "[SAI] SCA baseline result present without a manifest-hash baseline; "
            + (
                "treating current dependency findings as newly introduced"
                if manifests_changed
                else "no manifest changes this cycle, so nothing will be reported as new"
            )
        )
    else:
        # A real hook-execution issue (baseline scan crashed, hung, or errored) --
        # not a benign case, so it belongs on stderr like other scan failures.
        # baseline_keys stays None here too, so the same downstream note applies.
        log_to_panel(
            f"[SAI] SCA baseline scan did not complete successfully "
            f"(status={baseline_info.get('status') if baseline_info else None}); "
            + (
                "treating current dependency findings as newly introduced"
                if manifests_changed
                else "no manifest changes this cycle, so nothing will be reported as new"
            )
        )

    sca_status = wait_for_sca_scan(workspace, log_fn=write_log)

    # Stale detection: re-scan if the result predates our last trigger.
    # Guards against scans that completed before npm install updated the lockfile.
    if sca_status == "success":
        sca_check = get_sca_completion_info(workspace)
        sca_started_at = (sca_check or {}).get("started_at", "")
        last_triggered_at = hashes.get("last_scan_triggered_at", "")
        sca_started_dt = parse_iso_timestamp(sca_started_at)
        last_triggered_dt = parse_iso_timestamp(last_triggered_at)
        if (
            sca_started_dt is not None
            and last_triggered_dt is not None
            and sca_started_dt < last_triggered_dt
        ):
            write_log("[SAI] SCA result predates last manifest trigger, re-scanning...")
            if trigger_sca_scan(workspace):
                save_manifest_hash_last_scan(workspace, MANIFEST_FILES, MANIFEST_SUFFIXES)
            sca_status = wait_for_sca_scan(workspace, log_fn=write_log)

    if sca_status == "success":
        sca_info = get_sca_completion_info(workspace)
        sca_duration = scan_duration_secs(sca_info) if sca_info else None
        sca_vulns = sca_info.get("vulnerabilities", []) if sca_info else []
        write_log(f"[SAI] SCA: {len(sca_vulns)} dependency vuln(s)")
        new_sca_vulns: List[Any]
        if not manifests_changed:
            new_sca_vulns = []
        elif baseline_keys is None:
            new_sca_vulns = sca_vulns
        else:
            new_sca_vulns = [
                v
                for v in sca_vulns
                if (v.get("id", ""), v.get("package_name", ""), v.get("version", ""))
                not in baseline_keys
            ]
        new_sca_vulns = [
            v for v in new_sca_vulns if _should_block_on_sca_severity(v.get("severity", ""))
        ]
        return ScaResult(
            new_sca_vulns=new_sca_vulns, duration=sca_duration, changed_manifests=changed_manifests
        )

    status, detail = _log_unscanned("SCA", sca_status, get_sca_completion_info(workspace))
    return ScaResult(
        unscanned_status=status, unscanned_detail=detail, changed_manifests=changed_manifests
    )


def _rearm_unscanned(workspace: str, sast: SastResult, sca: ScaResult) -> None:
    """Drop the done-files of engines that produced no results.

    wait_for_scan short-circuits on an existing done-file, so leaving a failed
    marker in place would make every later stop replay the same failure instead
    of retrying it.
    """
    for result, clear in ((sast, clear_scan_state), (sca, clear_sca_scan_state)):
        if result.unscanned_status:
            clear(workspace)


def _unscanned_notice(
    sast: SastResult,
    sca: ScaResult,
    code_files: Dict[str, Dict[str, Any]],
    workspace: str,
) -> str:
    """The warning for a turn that was not fully scanned.

    Sole builder of these strings. Unlike Claude Code and Gemini CLI, Cursor's
    `stop` hook has no user-visible field that skips the model: `user_message`
    exists only on the permission-gating hooks, and `followup_message` is
    documented as "auto-continue with this message" -- it is resubmitted as the
    next user message, which is exactly the context cost this change removes.
    So this goes to the panel log. Kept ASCII for the log.
    """
    files = f"{len(code_files)} file(s) from this turn were not scanned"
    engines = (
        (
            sast,
            {
                "auth_required": f"not authenticated, {files} - run 'snyk auth' in a terminal",
                "snyk_not_found": (
                    f"CLI not found on PATH, {files} - install with 'npm install -g snyk'"
                ),
            },
            "code scan did not complete ({status}), " + files,
        ),
        (
            sca,
            {
                "auth_required": (
                    "dependency scan skipped, not authenticated - run 'snyk auth' in a terminal"
                ),
                "snyk_not_found": "dependency scan skipped, Snyk CLI not found",
            },
            "dependency scan did not complete ({status})",
        ),
    )

    clauses: List[str] = []
    detail = ""
    ran = False
    for result, preflight_clause, ran_clause in engines:
        status = result.unscanned_status
        if not status:
            continue
        # A status the pre-flight map does not name is one where snyk actually
        # ran, so it has stderr worth surfacing and a log worth pointing at.
        clause = preflight_clause.get(status)
        if clause is None:
            clause = ran_clause.format(status=status)
            ran = True
            detail = detail or _truncate(result.unscanned_detail, NOTICE_DETAIL_MAX_LEN)
        clauses.append(clause)

    if not clauses:
        return ""

    sentences = ["Snyk: " + "; ".join(clauses) + "."]
    if detail:
        sentences.append(detail.rstrip(".") + ".")
    if ran:
        # Only point at the log when it holds more than the clause above -- an
        # unauthenticated CLI has nothing extra to read. Name the path: a
        # warning that says "see the log" without saying which is a dead end.
        sentences.append(f"Full output: {resolve_log_file(workspace)}")
    return " ".join(sentences)


def handle_stop(data: Dict[str, Any], workspace: str) -> None:
    """Evaluate SAST + SCA scan results and emit a followup_message if new vulns introduced.

    A scan that could not run is no longer handed to the Snyk MCP tools: the
    MCP server is the same Snyk CLI that just failed, after already spending
    its network and auth retries. Instead the turn is allowed to end and the
    scan is re-armed for the next stop. Auth is the one exception worth a round
    trip: authenticating repairs the configstore every later scan reads, so it
    gets exactly one followup per session -- telling the user to run `snyk
    auth`, not telling the agent to scan.
    """
    early_response, ctx = _check_stop_preconditions(workspace)
    if early_response is not None:
        output_response(early_response)
        return

    state = ctx.state
    code_files = state.get("code_files", {})
    manifests_changed = bool(ctx.hash_changed_from_baseline)

    sast = _evaluate_sast(state, workspace, code_files)
    sca = _evaluate_sca(
        workspace,
        code_files,
        manifests_changed,
        ctx.hash_changed_from_baseline,
        ctx.hash_changed_from_last_scan,
        ctx.current_hashes,
        ctx.hashes,
    )

    write_log(
        f"[SAI] {len(sast.new_vulns)} new vuln(s), "
        f"{len(sca.new_sca_vulns)} SCA vuln(s), "
        f"{len(sast.clean_file_paths)} clean file(s), "
        f"{len(sast.unevaluated_file_paths)} unevaluated file(s)"
    )

    # An engine that reported nothing leaves a failed done-file behind, and
    # wait_for_scan short-circuits on one -- so drop it here or every later
    # stop replays this failure instead of retrying. No-op when both scanned.
    _rearm_unscanned(workspace, sast, sca)
    unscanned = bool(sast.unscanned_status or sca.unscanned_status)

    # Three outcomes, one handler each.
    if sast.new_vulns or sca.new_sca_vulns:
        _handle_new_vuln_stop(workspace, sast, sca, code_files, unscanned)
    elif not unscanned:
        _handle_clean_stop(workspace, sast, sca)
    else:
        _handle_unscanned_stop(workspace, sast, sca, code_files)


def _handle_new_vuln_stop(
    workspace: str,
    sast: SastResult,
    sca: ScaResult,
    code_files: Dict[str, Dict[str, Any]],
    unscanned: bool,
) -> None:
    """Findings to fix. They outrank an unscanned engine, which is logged
    rather than spending the followup."""
    with _mutate_state(workspace) as state:
        code = state.get("code_files", {})
        for fp in sast.clean_file_paths:
            code.pop(fp, None)
        state["code_files"] = code
        state["stop_cycles"] = state.get("stop_cycles", 0) + 1

    if not sast.unscanned_status and not sast.dirty_file_paths and not sast.unevaluated_file_paths:
        clear_scan_state(workspace)

    _log_stop_block(sast, sca)
    if unscanned:
        log_to_panel(_unscanned_notice(sast, sca, code_files, workspace))
    output_response(
        {"followup_message": _build_followup_message(sast.new_vulns, sca.new_sca_vulns, workspace)}
    )


def _handle_clean_stop(workspace: str, sast: SastResult, sca: ScaResult) -> None:
    """Everything scanned, nothing new."""
    with _mutate_state(workspace) as state:
        code = state.get("code_files", {})
        for fp in sast.clean_file_paths:
            code.pop(fp, None)
        state["code_files"] = code

    if not sast.dirty_file_paths and not sast.unevaluated_file_paths:
        clear_scan_state(workspace)

    _log_stop_allow(sast, sca)
    output_response({})


def _handle_unscanned_stop(
    workspace: str,
    sast: SastResult,
    sca: ScaResult,
    code_files: Dict[str, Dict[str, Any]],
) -> None:
    """No findings, but a scan could not run.

    code_files is deliberately left in place so the next stop re-evaluates this
    turn's files -- paired with the done-file drop in _rearm_unscanned, that is
    what makes "we will catch it next stop" true rather than a slogan.
    """
    statuses = (sast.unscanned_status, sca.unscanned_status)

    # One auth prompt per session: authenticating repairs the configstore the
    # CLI reads, so it is worth a round trip -- but only the first time.
    if "auth_required" in statuses:
        with _mutate_state(workspace) as state:
            first_prompt = not state.get("auth_prompted")
            if first_prompt:
                state["auth_prompted"] = True
                state["stop_cycles"] = state.get("stop_cycles", 0) + 1
        if first_prompt:
            reason = _auth_prompt_reason(
                sast.unscanned_status == "auth_required",
                sca.unscanned_status == "auth_required",
            )
            log_to_panel("Stop: BLOCK - Snyk not authenticated (one auth prompt per session)")
            output_response({"followup_message": reason})
            return

    log_to_panel(f"Stop: ALLOW (unscanned) - {_unscanned_notice(sast, sca, code_files, workspace)}")
    output_response({})


def _build_followup_message(
    new_vulns: List[Dict[str, Any]],
    new_sca_vulns: List[Dict[str, Any]],
    workspace: str,
) -> str:
    message_parts: List[str] = []

    if new_vulns:
        message_parts.append("/snyk-batch-fix")
        message_parts.append("")
        message_parts.append("## Vulnerabilities Found in Modified Code")
        message_parts.append("")
        message_parts.append(_format_vuln_table(new_vulns))
    if new_sca_vulns:
        if not new_vulns:
            message_parts.append("/snyk-batch-fix")
            message_parts.append("")
        message_parts.append("")
        message_parts.append("## Newly Introduced Dependency Vulnerabilities")
        message_parts.append("")
        message_parts.append(
            "Remediation guidance: because these dependency issues were introduced in this "
            "session, prefer reverting the introduced dependency change directly in the "
            "manifest/lockfile instead of researching upgrade versions. Only keep the "
            "dependency if the user explicitly asked for it, and in that case update it "
            "to a safe version without using shell commands."
        )
        message_parts.append("")
        new_sca_vulns_sorted = sorted(
            new_sca_vulns,
            key=lambda v: _SEVERITY_ORDER.get(v.get("severity", "low"), 4),
        )
        message_parts.append(_format_sca_vuln_table(new_sca_vulns_sorted))
    total_prevented = len(new_vulns) + len(new_sca_vulns)
    if total_prevented > 0:
        prevented_ids = _prevented_issue_ids(new_vulns, new_sca_vulns)
        prevented_ids_json = json.dumps(prevented_ids)
        prevented_by_severity_json = json.dumps(_severity_counts_dict(new_vulns + new_sca_vulns))
        message_parts.append("")
        message_parts.append(
            "Remediation order: fix the files above first. Do not search for MCP "
            "tool definitions, hook files, or project config before making the "
            "required file edits."
        )
        message_parts.append("")
        message_parts.append(
            f"After the file edits are complete, call snyk_send_feedback with "
            f"preventedIssuesCount={total_prevented}, "
            f"preventedIssueIds={prevented_ids_json}, "
            f"preventedIssuesBySeverity={prevented_by_severity_json}, "
            f"path={workspace}. "
            f"If your installed Snyk MCP rejects preventedIssueIds or "
            f"preventedIssuesBySeverity (older version), retry the call "
            f"without those arguments. If the feedback "
            f"tool is unavailable or stalls, skip it rather than delaying "
            f"remediation."
        )

    return "\n".join(message_parts)


def _log_stop_allow(sast: SastResult, sca: ScaResult) -> None:
    if sast.unevaluated_file_paths:
        write_log("=" * 70)
        write_log(
            "[Secure at Inception] Some files not yet evaluated. "
            "They will be checked on the next stop."
        )
        write_log("=" * 70)
        return

    write_log("=" * 70)
    write_log("[Secure at Inception] No new security issues found.")
    write_log("=" * 70)
    duration_parts = []
    sast_dur = scan_duration_secs(sast.scan_info)
    if sast_dur is not None:
        duration_parts.append(f"SAST {sast_dur:.1f}s")
    if sca.duration is not None:
        duration_parts.append(f"SCA {sca.duration:.1f}s")
    log_line = "Stop: ALLOW"
    if duration_parts:
        log_line += " — scans: " + " ".join(duration_parts)
    write_log(log_line)


def _log_stop_block(sast: SastResult, sca: ScaResult) -> None:
    write_log("=" * 70)
    write_log("[Secure at Inception] New security issues detected")
    write_log("=" * 70)
    if sast.new_vulns:
        write_log(f"  Code vulnerabilities: {len(sast.new_vulns)}")
        for v in sast.new_vulns:
            write_log(
                f"    - {v['severity'].upper()}: {v['title']} at {v['file_path']}:{v['start_line']}"
            )
    if sca.new_sca_vulns:
        write_log(f"  Dependency vulnerabilities: {len(sca.new_sca_vulns)}")
    if sast.dirty_file_paths:
        write_log(
            f"  Files with vulns (kept in state): {[Path(f).name for f in sast.dirty_file_paths]}"
        )
    if sast.unevaluated_file_paths:
        write_log(
            f"  Unevaluated files (kept in state): "
            f"{[Path(f).name for f in sast.unevaluated_file_paths]}"
        )
    if sca.changed_manifests:
        write_log(f"  Manifest files changed: {len(sca.changed_manifests)}")
    write_log("=" * 70)

    threshold = os.environ.get("SAI_MIN_BLOCK_SEVERITY", "medium")
    sast_dur = scan_duration_secs(sast.scan_info)
    block_parts: List[str] = []
    if sast.new_vulns:
        n = len(sast.new_vulns)
        block_parts.append(
            f"SAST {n} {'vuln' if n == 1 else 'vulns'} ({_severity_counts(sast.new_vulns)})"
        )
    if sca.new_sca_vulns:
        n = len(sca.new_sca_vulns)
        block_parts.append(
            f"SCA {n} {'vuln' if n == 1 else 'vulns'} ({_severity_counts(sca.new_sca_vulns)})"
        )
    block_parts.append(f"threshold: {threshold}")
    dur_parts: List[str] = []
    if sast_dur is not None:
        dur_parts.append(f"SAST {sast_dur:.1f}s")
    if sca.duration is not None:
        dur_parts.append(f"SCA {sca.duration:.1f}s")
    if dur_parts:
        block_parts.append("scans: " + " ".join(dur_parts))
    top_ids = _top_vuln_ids(list(sast.new_vulns) + list(sca.new_sca_vulns))
    if top_ids:
        block_parts.append(f"top vulns: {top_ids}")
    write_log("Stop: BLOCK — " + " | ".join(block_parts))


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================


def main() -> None:
    try:
        # utf-8-sig strips the UTF-8 BOM that Cursor on Windows prepends to hook input.
        input_data = sys.stdin.buffer.read().decode("utf-8-sig")
        data = json.loads(input_data) if input_data.strip() else {}
        debug_log(f"Hook data: {json.dumps(data, indent=2)[:500]}...")
    except json.JSONDecodeError as e:
        log_to_panel(f"[SAI] Error parsing hook input: {e}")
        output_response({"exit_code": 1})
        sys.exit(1)

    hook_event = data.get("hook_event_name", "")
    workspace = get_workspace(data)

    # Resolve the persistent log path once, now that the workspace is known.
    global _LOG_FILE
    _LOG_FILE = resolve_log_file(workspace)

    debug_log(f"Event: {hook_event}, Workspace: {workspace}")

    handlers = {
        "sessionStart": handle_session_start,
        "afterFileEdit": handle_after_file_edit,
        "afterShellExecution": handle_after_shell_execution,
        "stop": handle_stop,
    }

    handler = handlers.get(hook_event)
    if handler:
        handler(data, workspace)
    else:
        debug_log(f"Unknown hook event: {hook_event}")
        output_response({"exit_code": 0})


if __name__ == "__main__":
    main()
