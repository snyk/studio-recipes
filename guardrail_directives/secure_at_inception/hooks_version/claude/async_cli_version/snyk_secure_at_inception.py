#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# ///
"""
Claude Code Hook: Snyk Secure At Inception
============================================

Launches background Snyk CLI scans on file edit/write, tracks modified
line ranges, and blocks Claude from stopping if new vulnerabilities were
introduced in agent-modified code.

WORKFLOW:
  1. SessionStart -> verify auth + CLI, launch cache-warming scan
  2. PostToolUse (Edit|Write|Bash) -> track modified line ranges / manifest mutations, launch background scan
  3. Stop -> wait for scan, filter results to modified lines, block if new vulns

INSTALLATION:
  1. Copy this script and lib/ to .claude/hooks/
  2. chmod +x snyk_secure_at_inception.py
  3. Merge settings.json into .claude/settings.json

PREREQUISITES:
  - Python 3.8+
  - Snyk CLI (npm install -g snyk)
  - Snyk authentication (snyk auth)
"""

import json
import os
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
    wait_for_sca_baseline_scan,
    wait_for_sca_scan,
    wait_for_scan,
    write_early_status,
)

# =============================================================================
# CONFIGURATION
# =============================================================================

DEBUG = os.environ.get("CLAUDE_HOOK_DEBUG", "0") == "1"

# Resolved per-invocation in main() once the workspace is known (the hook is a
# short-lived process and the workspace comes from parsed stdin). Until then it
# is None and log_to_panel/debug_log degrade to stderr-only.
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

MANIFEST_SUFFIXES = {".csproj", ".lock", ".fsproj", ".vbproj"}

MAX_STOP_CYCLES = 3

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


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
    failed: bool = False
    fallback: str = ""
    scan_info: Optional[Dict[str, Any]] = None


@dataclass
class ScaResult:
    new_sca_vulns: List[Dict[str, Any]] = field(default_factory=list)
    fallback: str = ""
    duration: Optional[float] = None


def _severity_counts(vulns: List[Dict[str, Any]]) -> str:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for vuln in vulns:
        sev = vuln.get("severity", "").lower()
        if sev in counts:
            counts[sev] += 1
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


def output_response(response: Dict[str, Any]) -> None:
    print(json.dumps(response))


def get_state_file_path(workspace: str) -> str:
    return os.path.join(get_cache_dir(workspace), "state.json")


def get_invocation_marker_path(workspace: str) -> str:
    return os.path.join(get_cache_dir(workspace), "hook.invoked")


def get_workspace(data: Dict[str, Any]) -> str:
    return str(data.get("cwd", os.getcwd()))


def is_code_file(file_path: str) -> bool:
    return Path(file_path).suffix.lower() in CODE_EXTENSIONS


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
    """Filter scan results per tracked file to only new vulns on modified lines."""
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


def _should_block_on_sca_severity(severity: str) -> bool:
    threshold = os.environ.get("SAI_MIN_BLOCK_SEVERITY", "medium").lower()
    if threshold not in _SEVERITY_ORDER:
        threshold = "medium"
    return _SEVERITY_ORDER.get(severity.lower(), 4) <= _SEVERITY_ORDER[threshold]


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


# =============================================================================
# HOOK HANDLERS
# =============================================================================


def handle_session_start(data: Dict[str, Any], workspace: str) -> None:
    """Verify prerequisites and launch a cache-warming scan at session start.

    Checks Snyk auth and CLI presence. If either is missing, reports via
    additionalContext so Claude can inform the user. If all checks pass,
    launches a background scan to warm Snyk's internal analysis cache.
    """
    source = data.get("source", "startup")
    issues: List[str] = []

    # 1. Check Snyk auth
    if check_snyk_auth() is None:
        issues.append("auth")
        log_to_panel("[SAI] Snyk CLI not authenticated")

    # 2. Check Snyk CLI presence
    if check_snyk_cli() is None:
        issues.append("cli")
        log_to_panel("[SAI] Snyk CLI not found on PATH")

    # 3. Report issues via additionalContext and write early status
    if issues:
        context_parts: List[str] = []
        if "cli" in issues:
            context_parts.append(
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
            context_parts.append(
                "Snyk CLI is not authenticated. If the user asks you to write "
                "code, remind them that security scanning is unavailable until "
                "they run `snyk auth` in a terminal to authenticate."
            )
            write_early_status(
                workspace,
                "auth_required",
                "Snyk CLI is not authenticated. Run snyk auth.",
            )

        output_response(
            {
                "hookSpecificOutput": {
                    "hookEventName": "SessionStart",
                    "additionalContext": " ".join(context_parts),
                }
            }
        )
        return

    # 4. All checks passed -- clear stale state on fresh sessions
    log_to_panel("[SAI] Snyk authenticated, CLI found")
    if _LOG_FILE:
        _shared_log(f"SessionStart: studio v{STUDIO_VERSION}", _LOG_FILE)
    if source in ("startup", "clear"):
        clear_state(workspace)
        clear_baseline(workspace)

    # 5. Launch cache-warming scans (non-blocking, dedup built-in).
    if launch_background_scan(workspace):
        log_to_panel("[SAI] Cache-warming scan launched")
    else:
        debug_log("Cache-warm scan not launched (already running or complete)")

    # The SCA baseline scan result persists across Stop cycles — regular scans compare against it.
    if launch_background_sca_baseline_scan(workspace):
        log_to_panel("[SAI] Cache-warming SCA scan launched")
        save_manifest_hash_baseline(workspace, MANIFEST_FILES, MANIFEST_SUFFIXES)
    else:
        debug_log("Cache-warm SCA scan not launched (already running or complete)")

    output_response({})


def _trigger_sca_and_save(workspace: str, snapshot: Dict[str, str]) -> None:
    """Trigger an SCA scan and record snapshot as the new last-scan reference."""
    if trigger_sca_scan(workspace):
        log_to_panel("[SAI] Background SCA scan launched")
        save_manifest_hash_last_scan(workspace, MANIFEST_FILES, MANIFEST_SUFFIXES, hashes=snapshot)


def handle_post_tool_use(data: Dict[str, Any], workspace: str) -> None:
    """Track file edits and launch background scans."""
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    # Bash commands that mutate manifests (npm install, pip install, etc.) bypass
    # the Edit|Write file_path path. Detect them by checking whether any manifest
    # file actually changed on disk after the command ran.
    if tool_name == "Bash":
        log_to_panel("[SAI] Bash tool use encountered. Checking if manifests changed.")
        hashes = load_manifest_hashes(workspace) or {}
        # Before any scan has run this session, the only thing to compare against
        # is the session-start baseline; once last_scan is populated it's the
        # tighter reference for "is anything different since we last scanned?"
        compare_against = hashes.get("last_scan") or hashes.get("baseline", {})
        snapshot = snapshot_manifest_hashes(workspace, MANIFEST_FILES, MANIFEST_SUFFIXES)
        changed = diff_manifest_hashes(snapshot, compare_against)
        if changed:
            log_to_panel(
                f"[SAI] Manifest change detected: {', '.join(Path(f).name for f in changed)}"
            )
            _trigger_sca_and_save(workspace, snapshot)
        output_response({})
        return

    file_path = tool_input.get("file_path", "")
    if not file_path:
        output_response({})
        return

    is_code = is_code_file(file_path)
    is_manifest = is_manifest_file(file_path)
    if not is_code and not is_manifest:
        debug_log(f"File not scannable, ignoring: {file_path}")
        output_response({})
        return

    # Persistent invocation marker survives clear_state(); useful for diagnostics.
    try:
        ensure_cache_dirs(workspace)
        with open(get_invocation_marker_path(workspace), "a") as _mf:
            _mf.write(datetime.now().isoformat() + "\n")
    except OSError:
        pass

    if is_code:
        with _state_lock(workspace):
            state = read_state(workspace)

            if tool_name == "Edit":
                old_string = tool_input.get("old_string", "")
                new_string = tool_input.get("new_string", "")
                edits = [{"old_string": old_string, "new_string": new_string}]

                try:
                    file_content = Path(file_path).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    file_content = ""

                new_ranges = compute_modified_ranges(file_content, edits)
                code_files = state.get("code_files", {})
                existing = code_files.get(file_path, {}).get("modified_ranges", [])
                code_files[file_path] = {
                    "modified_ranges": _accumulate_ranges(existing, new_ranges),
                    "last_edit": datetime.now().isoformat(),
                }
                state["code_files"] = code_files

            elif tool_name == "Write":
                content = tool_input.get("content", "")
                line_count = content.count("\n") + 1 if content else 1
                code_files = state.get("code_files", {})
                code_files[file_path] = {
                    "modified_ranges": [{"start": 1, "end": line_count}],
                    "last_edit": datetime.now().isoformat(),
                }
                state["code_files"] = code_files

            state["last_edit_ts"] = datetime.now().isoformat()
            write_state(workspace, state)
            range_count = len(state["code_files"][file_path]["modified_ranges"])

        log_to_panel(f"[SAI] Tracked: {Path(file_path).name} ({range_count} range(s))")

        # Peek at cached scan status for early error detection.
        # If SessionStart or a prior scan_worker wrote an error status,
        # block immediately instead of waiting for the Stop hook.
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
                output_response({"decision": "block", "reason": reason})
                return

        if launch_background_scan(workspace):
            log_to_panel("[SAI] Background scan launched")

    # NOTE: keeping is_manifest for now. But SCA scans usually need
    # the package manager to have actually installed packages. So an agent
    # file edit will not result in an SCA-detectable vuln.
    if is_manifest:
        log_to_panel(f"[SAI] Manifest edit tracked: {Path(file_path).name}")
        snapshot = snapshot_manifest_hashes(workspace, MANIFEST_FILES, MANIFEST_SUFFIXES)
        _trigger_sca_and_save(workspace, snapshot)

    output_response({})


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
            debug_log("No pending changes")
            return {}, ctx

        stop_cycles = state.get("stop_cycles", 0)
        if stop_cycles >= MAX_STOP_CYCLES:
            log_to_panel(f"[SAI] Max cycles ({MAX_STOP_CYCLES}) reached, allowing stop")
            clear_state(workspace)
            # clear and reset the sca baseline to accept the current state
            clear_baseline(workspace)
            if launch_background_sca_baseline_scan(workspace):
                save_manifest_hash_baseline(workspace, MANIFEST_FILES, MANIFEST_SUFFIXES)
            return {}, ctx

        state["stop_cycles"] = stop_cycles + 1
        write_state(workspace, state)

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

    scan_status = wait_for_scan(workspace, log_fn=log_to_panel)
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
            log_to_panel("[SAI] Edits after scan started, re-scanning...")
            clear_scan_state(workspace)
            launch_background_scan(workspace)
            scan_status = wait_for_scan(workspace, log_fn=log_to_panel)
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
        for fp in code_files:
            file_vulns = per_file_results.get(fp)
            if file_vulns:
                dirty_file_paths.append(fp)
                new_vulns.extend(file_vulns)
            else:
                clean_file_paths.append(fp)

        new_vulns.sort(
            key=lambda v: (
                _SEVERITY_ORDER.get(v.get("severity", "low"), 4),
                v.get("file_path", ""),
                v.get("start_line", 0),
            )
        )

        log_to_panel(f"[SAI] {len(new_vulns)} new vuln(s), {len(clean_file_paths)} clean file(s)")
        return SastResult(
            new_vulns=new_vulns,
            clean_file_paths=clean_file_paths,
            dirty_file_paths=dirty_file_paths,
            scan_info=scan_info,
        )

    scan_info = get_scan_completion_info(workspace)
    error_detail = scan_info.get("error_detail", "") if scan_info else ""
    file_list = ", ".join(Path(f).name for f in code_files)

    if scan_status == "auth_required":
        log_to_panel(
            f"[SAI] Snyk CLI not authenticated: {error_detail}"
            if error_detail
            else "[SAI] Snyk CLI not authenticated"
        )
        fallback = (
            "The Snyk CLI is not authenticated. Run snyk_auth to authenticate, "
            "then run snyk_code_scan on the current directory to check for "
            f"vulnerabilities in: {file_list}. Fix only NEWLY INTRODUCED issues."
        )
    elif scan_status == "snyk_not_found":
        log_to_panel("[SAI] Snyk CLI not found, falling back to MCP")
        fallback = (
            "Security scan could not complete. "
            "Run snyk_code_scan on the current directory to check for vulnerabilities "
            f"in: {file_list}. Fix only NEWLY INTRODUCED issues."
        )
    else:
        log_to_panel(f"[SAI] Scan failed (status: {scan_status}), falling back to MCP")
        fallback = (
            "Security scan could not complete. "
            "Run snyk_code_scan on the current directory to check for vulnerabilities "
            f"in: {file_list}. Fix only NEWLY INTRODUCED issues."
        )

    return SastResult(failed=True, fallback=fallback, scan_info=scan_info)


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
    if not (code_files or manifests_changed):
        return ScaResult()

    manifest_list = ""
    baseline_keys = None

    if manifests_changed:
        manifest_list = ", ".join(Path(f).name for f in hash_changed_from_baseline)
        if hash_changed_from_baseline:
            debug_log(f"[SAI] Detected manifest change(s): {hash_changed_from_baseline}")

        # Re-run SCA only if manifests changed since the last scan
        if hash_changed_from_last_scan:
            log_to_panel("[SAI] Manifest changes detected — re-running SCA scan")
            if trigger_sca_scan(workspace):
                log_to_panel("[SAI] Background SCA scan launched")
                save_manifest_hash_last_scan(
                    workspace, MANIFEST_FILES, MANIFEST_SUFFIXES, hashes=current_hashes
                )

    # Ensure the session-start baseline is complete before comparing
    wait_for_sca_baseline_scan(workspace, log_fn=log_to_panel)
    baseline_info = get_sca_baseline_completion_info(workspace)
    if baseline_info and baseline_info.get("status") == "success":
        baseline_vulns = baseline_info.get("vulnerabilities", [])
        log_to_panel(f"[SAI] SCA: {len(baseline_vulns)} baseline dependency vuln(s)")
        baseline_keys = frozenset(
            (v.get("id", ""), v.get("package_name", ""), v.get("version", ""))
            for v in baseline_vulns
        )

    sca_status = wait_for_sca_scan(workspace, log_fn=log_to_panel)

    # Stale detection: re-scan if the result predates our last trigger.
    # Guards against scans that completed before npm install updated the lockfile.
    if sca_status == "success":
        sca_check = get_sca_completion_info(workspace)
        sca_started_at = (sca_check or {}).get("started_at", "")
        last_triggered_at = hashes.get("last_scan_triggered_at", "")
        if sca_started_at and last_triggered_at and sca_started_at < last_triggered_at:
            log_to_panel("[SAI] SCA result predates last manifest trigger, re-scanning...")
            if trigger_sca_scan(workspace):
                save_manifest_hash_last_scan(workspace, MANIFEST_FILES, MANIFEST_SUFFIXES)
            sca_status = wait_for_sca_scan(workspace, log_fn=log_to_panel)

    if sca_status == "success":
        sca_info = get_sca_completion_info(workspace)
        sca_duration = scan_duration_secs(sca_info) if sca_info else None
        sca_vulns = sca_info.get("vulnerabilities", []) if sca_info else []
        log_to_panel(f"[SAI] SCA: {len(sca_vulns)} dependency vuln(s)")
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
        log_to_panel(f"[SAI] SCA: {len(new_sca_vulns)} new dependency vuln(s)")
        return ScaResult(new_sca_vulns=new_sca_vulns, duration=sca_duration)

    if manifests_changed:
        if sca_status == "auth_required":
            log_to_panel("[SAI] SCA skipped: Snyk not authenticated (run `snyk auth`)")
            fallback = (
                "The Snyk CLI is not authenticated. Run snyk_auth to authenticate, "
                "then run snyk_sca_scan on the current directory to check for "
                f"dependency vulnerabilities in: {manifest_list}. Fix only NEWLY INTRODUCED issues."
            )
        else:
            log_to_panel(f"[SAI] SCA scan did not complete (status: {sca_status})")
            fallback = (
                "Security scan could not complete. "
                "Run snyk_sca_scan on the current directory to check for "
                f"dependency vulnerabilities in: {manifest_list}. Fix only NEWLY INTRODUCED issues."
            )
        return ScaResult(fallback=fallback)

    if sca_status == "auth_required":
        log_to_panel("[SAI] SCA skipped: Snyk not authenticated (run `snyk auth`)")
    elif sca_status == "snyk_not_found":
        log_to_panel("[SAI] SCA skipped: Snyk CLI not found on PATH")
    elif sca_status is None:
        log_to_panel("[SAI] SCA scan timed out, continuing with SAST results only")
    else:
        log_to_panel(f"[SAI] SCA scan did not complete (status: {sca_status})")

    return ScaResult()


def handle_stop(data: Dict[str, Any], workspace: str) -> None:
    """Evaluate scan results and block if new vulnerabilities were introduced."""
    early_response, ctx = _check_stop_preconditions(workspace)
    if early_response is not None:
        output_response(early_response)
        return

    state = ctx.state
    code_files = state.get("code_files", {})
    manifests_changed = bool(ctx.hash_changed_from_baseline) or bool(ctx.hashes.get("last_scan"))

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

    # --- Handle SAST scan failure early return ---
    if sast.failed:
        fallback = sast.fallback
        if sca.new_sca_vulns:
            fallback += "\n\n## Newly Introduced Dependency Vulnerabilities\n\n"
            fallback += _format_sca_vuln_table(sca.new_sca_vulns)
        elif sca.fallback:
            fallback += f"\n\n## Dependency Scan Unavailable\n\n{sca.fallback}"
        clear_state(workspace)
        output_response({"decision": "block", "reason": fallback})
        return

    # --- Update state and decide ---
    if not sast.new_vulns and not sca.new_sca_vulns and not sca.fallback:
        _log_stop_allow(sast, sca)
        clear_state(workspace)
        # Explicitly do NOT clear the baseline. This means we always compare to
        # the status as of session start, and ignore any possibly improvements
        # to SCA vulns beyond it.
        output_response({})
        return

    # Remove clean files in one locked write
    with _state_lock(workspace):
        state = read_state(workspace)
        code = state.get("code_files", {})
        for fp in sast.clean_file_paths:
            code.pop(fp, None)
        state["code_files"] = code
        write_state(workspace, state)

    if not sast.dirty_file_paths:
        clear_scan_state(workspace)

    reason = _build_block_reason(sast.new_vulns, sca.new_sca_vulns, sca.fallback, workspace)
    _log_stop_block(sast, sca)
    output_response({"decision": "block", "reason": reason})


def _build_block_reason(
    new_vulns: List[Dict[str, Any]],
    new_sca_vulns: List[Dict[str, Any]],
    sca_fallback: str,
    workspace: str,
) -> str:
    reason_parts = [
        "SECURITY ISSUES DETECTED in code you just wrote or modified. "
        "Fix the following newly introduced vulnerabilities before completing your task. "
        "Do NOT fix pre-existing issues -- only fix what you introduced."
    ]

    if new_vulns:
        reason_parts.append("\n## Vulnerabilities Found in Modified Code\n")
        reason_parts.append(_format_vuln_table(new_vulns))

    if new_sca_vulns:
        new_sca_vulns_sorted = sorted(
            new_sca_vulns, key=lambda v: _SEVERITY_ORDER.get(v.get("severity", "low"), 4)
        )
        reason_parts.append("\n## Newly Introduced Dependency Vulnerabilities\n")
        reason_parts.append(_format_sca_vuln_table(new_sca_vulns_sorted))
        reason_parts.append(
            "\nFix all of the new vulnerabilities above using minimal package upgrades "
            "(e.g., bump the packages to the nearest non-vulnerable versions). "
            "Pre-existing vulnerabilities in this workspace are out of scope — "
            "address only what you introduced in this session."
        )

    if sca_fallback:
        reason_parts.append(f"\n## Dependency Scan Unavailable\n\n{sca_fallback}")

    total_prevented = len(new_vulns) + len(new_sca_vulns)
    if total_prevented > 0:
        prevented_ids = _prevented_issue_ids(new_vulns, new_sca_vulns)
        prevented_ids_json = json.dumps(prevented_ids)
        reason_parts.append(
            f"\nAfter fixing all issues above, call snyk_send_feedback with "
            f"preventedIssuesCount={total_prevented}, "
            f"preventedIssueIds={prevented_ids_json}, "
            f"path={workspace}. "
            f"If your installed Snyk MCP rejects preventedIssueIds (older version), "
            f"retry the call without that argument."
        )
    reason_parts.append("\nThe security scan will run again automatically after fixing.")

    return "\n".join(reason_parts)


def _log_stop_allow(sast: SastResult, sca: ScaResult) -> None:
    duration_parts = []
    sast_dur = scan_duration_secs(sast.scan_info)
    if sast_dur is not None:
        duration_parts.append(f"SAST {sast_dur:.1f}s")
    if sca.duration is not None:
        duration_parts.append(f"SCA {sca.duration:.1f}s")
    log_line = "Stop: ALLOW"
    if duration_parts:
        log_line += " — scans: " + " ".join(duration_parts)
    log_to_panel(log_line)


def _log_stop_block(sast: SastResult, sca: ScaResult) -> None:
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
    duration_parts: List[str] = []
    if sast_dur is not None:
        duration_parts.append(f"SAST {sast_dur:.1f}s")
    if sca.duration is not None:
        duration_parts.append(f"SCA {sca.duration:.1f}s")
    if duration_parts:
        block_parts.append("scans: " + " ".join(duration_parts))
    top_ids = _top_vuln_ids(list(sast.new_vulns) + list(sca.new_sca_vulns))
    if top_ids:
        block_parts.append(f"top vulns: {top_ids}")
    log_to_panel("Stop: BLOCK — " + " | ".join(block_parts))


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================


def main() -> None:
    try:
        input_data = sys.stdin.read()
        data = json.loads(input_data) if input_data.strip() else {}
        debug_log(f"Hook data: {json.dumps(data, indent=2)[:500]}...")
    except json.JSONDecodeError as e:
        log_to_panel(f"[SAI] Error parsing hook input: {e}")
        output_response({})
        sys.exit(0)

    hook_event = data.get("hook_event_name", "")
    workspace = get_workspace(data)

    # Resolve the persistent log path once, now that the workspace is known.
    # log_to_panel/debug_log read this global; calls before this point (e.g.
    # stdin-parse errors above) degrade to stderr-only.
    global _LOG_FILE
    _LOG_FILE = resolve_log_file(workspace)

    debug_log(f"Event: {hook_event}, Workspace: {workspace}")

    handlers = {
        "SessionStart": handle_session_start,
        "PostToolUse": handle_post_tool_use,
        "Stop": handle_stop,
    }

    handler = handlers.get(hook_event)
    if handler:
        handler(data, workspace)
    else:
        debug_log(f"Unknown hook event: {hook_event}")
        output_response({})


if __name__ == "__main__":
    main()
