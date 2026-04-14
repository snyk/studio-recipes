#!/usr/bin/env python3
"""
GitHub Copilot Hook: Snyk Secure At Inception
===============================================

Launches background Snyk CLI scans on file edit/create, tracks modified
line ranges, and gates git commit/push operations if new vulnerabilities
were introduced in agent-modified code.

Unlike Claude Code and Cursor, Copilot's agentStop output is ignored.
Enforcement shifts to preToolUse on bash commands: git commit/push
operations are denied (once) with vulnerability details. The user can
then fix the issues or retry to proceed anyway.

WORKFLOW:
  1. postToolUse (edit|create) -> track modified line ranges, launch background scan
  2. preToolUse (bash, non-git) -> peek at scan results, notify once if new vulns found
  3. preToolUse (bash, git op) -> wait for scan, deny commit/push if new vulns
  4. agentStop -> audit logging only (output ignored by Copilot)

INSTALLATION:
  1. Copy this script and lib/ to .github/hooks/
  2. chmod +x snyk_secure_at_inception.py
  3. Copy hooks.json to .github/hooks/hooks.json
"""

import hashlib
import json
import os
import re
import sys
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:
    _HAS_FCNTL = False

SCRIPT_DIR = Path(__file__).parent.resolve()
LIB_DIR = SCRIPT_DIR / "lib"
sys.path.insert(0, str(LIB_DIR))

from scan_runner import (
    check_snyk_auth,
    is_scan_complete,
    launch_background_scan,
    wait_for_scan,
    write_early_status,
    get_cache_dir,
    ensure_cache_dirs,
    clear_scan_state,
    get_scan_completion_info,
)


# =============================================================================
# CONFIGURATION
# =============================================================================

DEBUG = os.environ.get("COPILOT_HOOK_DEBUG", "0") == "1"

CODE_EXTENSIONS = {
    '.js', '.jsx', '.mjs', '.cjs',
    '.ts', '.tsx',
    '.py',
    '.java',
    '.kt', '.kts',
    '.go',
    '.rb',
    '.php',
    '.cs',
    '.vb',
    '.swift',
    '.m', '.mm',
    '.scala',
    '.rs',
    '.c', '.cpp', '.cc', '.h', '.hpp',
    '.cls', '.trigger',
    '.ex', '.exs',
    '.groovy',
    '.dart',
}

MANIFEST_FILES = {
    'package.json', 'package-lock.json', 'npm-shrinkwrap.json',
    'yarn.lock', 'pnpm-lock.yaml',
    'requirements.txt', 'setup.py', 'pyproject.toml',
    'Pipfile', 'Pipfile.lock', 'poetry.lock',
    'pom.xml', 'build.gradle', 'build.gradle.kts', 'gradle.lockfile',
    'Gemfile', 'Gemfile.lock',
    'go.mod', 'go.sum',
    'Cargo.toml', 'Cargo.lock',
    'packages.config', 'packages.lock.json',
    'composer.json', 'composer.lock',
    'Podfile', 'Podfile.lock',
    'Package.swift', 'Package.resolved',
    'mix.exs', 'mix.lock',
    'pubspec.yaml', 'pubspec.lock',
}

MANIFEST_SUFFIXES = {'.csproj'}

# preToolUse wait timeout (leave buffer for JSON output within 30s hook timeout)
PRE_TOOL_SCAN_WAIT_TIMEOUT = 25

# Regex patterns for git VCS operations that should be gated
GIT_VCS_PATTERNS = [
    re.compile(r'\bgit\s+commit\b'),
    re.compile(r'\bgit\s+push\b'),
    re.compile(r'\bgh\s+pr\s+create\b'),
    re.compile(r'\bgh\s+pr\s+merge\b'),
]


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def debug_log(message: str) -> None:
    if DEBUG:
        print(f"[DEBUG] {message}", file=sys.stderr)


def log_to_panel(message: str) -> None:
    print(message, file=sys.stderr)


def output_allow() -> None:
    """Output JSON that allows the tool call to proceed."""
    print(json.dumps({}))


def output_deny(reason: str) -> None:
    """Output JSON that denies the tool call with a reason shown to the agent."""
    print(json.dumps({
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }))


def get_state_file_path(workspace: str) -> str:
    return os.path.join(get_cache_dir(workspace), "state.json")


def get_workspace(data: Dict[str, Any]) -> str:
    return data.get("cwd", os.getcwd())


def is_code_file(file_path: str) -> bool:
    return Path(file_path).suffix.lower() in CODE_EXTENSIONS


def is_manifest_file(file_path: str) -> bool:
    name = Path(file_path).name
    return name in MANIFEST_FILES or Path(file_path).suffix.lower() in MANIFEST_SUFFIXES


def is_git_vcs_operation(command: str) -> bool:
    """Check if a bash command contains a git commit/push/PR operation."""
    for pattern in GIT_VCS_PATTERNS:
        if pattern.search(command):
            return True
    return False


def _compute_vuln_fingerprint(vulns: List[Dict[str, Any]]) -> str:
    """Compute a hash fingerprint of vulnerability IDs for cycle tracking."""
    vuln_ids = sorted(set(
        f"{v.get('id', '')}:{v.get('file_path', '')}:{v.get('start_line', 0)}"
        for v in vulns
    ))
    return hashlib.sha256("|".join(vuln_ids).encode()).hexdigest()[:16]


# =============================================================================
# LINE TRACKING (computes which lines the agent modified)
# =============================================================================

def compute_modified_ranges(
    file_content: str, edits: List[Dict[str, str]]
) -> List[Dict[str, int]]:
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
            start_line = file_content[:idx].count('\n') + 1
            end_line = start_line + new_str.count('\n')
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

def _normalize_path(path: str) -> str:
    while path.startswith("./"):
        path = path[2:]
    return path.lstrip("/")


def _paths_match(path_a: str, path_b: str) -> bool:
    """Segment-aware suffix comparison."""
    norm_a = _normalize_path(path_a)
    norm_b = _normalize_path(path_b)
    if norm_a == norm_b:
        return True
    parts_a = norm_a.split("/")
    parts_b = norm_b.split("/")
    shorter, longer = sorted([parts_a, parts_b], key=len)
    return longer[-len(shorter):] == shorter


def _find_vulns_for_file(
    file_path: str,
    results_by_file: Dict[str, List[Dict[str, Any]]],
) -> Optional[List[Dict[str, Any]]]:
    if file_path in results_by_file:
        return results_by_file[file_path]
    normalized = _normalize_path(file_path)
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
        v for v in vulns
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


# =============================================================================
# STATE MANAGEMENT
# =============================================================================

@contextmanager
def _state_lock(workspace: str):
    """Exclusive file lock for state.json read-modify-write operations.
    Falls back to no-op on platforms without fcntl (Windows)."""
    if not _HAS_FCNTL:
        yield
        return
    ensure_cache_dirs(workspace)
    lock_path = get_state_file_path(workspace) + ".lock"
    fd = open(lock_path, "w")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        fd.close()


def read_state(workspace: str) -> Dict[str, Any]:
    state_file = get_state_file_path(workspace)
    try:
        if os.path.exists(state_file):
            with open(state_file, "r") as f:
                return json.load(f)
    except (json.JSONDecodeError, IOError):
        pass
    return {
        "code_files": {},
        "manifest_files": [],
        "deny_cycles": 0,
        "last_denial_fingerprint": "",
        "notified_scan_fingerprint": "",
        "last_update": None,
    }


def write_state(workspace: str, state: Dict[str, Any]) -> None:
    ensure_cache_dirs(workspace)
    state_file = get_state_file_path(workspace)
    state["last_update"] = datetime.now().isoformat()
    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)


def clear_state(workspace: str) -> None:
    state_file = get_state_file_path(workspace)
    if os.path.exists(state_file):
        try:
            os.remove(state_file)
        except OSError:
            pass
    clear_scan_state(workspace)


def has_pending_changes(state: Dict[str, Any]) -> bool:
    return bool(state.get("code_files")) or bool(state.get("manifest_files"))


# =============================================================================
# SCAN EVALUATION (shared by early notification and git gating)
# =============================================================================

def _evaluate_completed_scan(
    workspace: str,
    code_files: Dict[str, Dict[str, Any]],
) -> tuple:
    """Evaluate completed scan results against tracked files.

    Returns: (new_vulns, clean_file_paths, dirty_file_paths)
    Assumes scan.done exists and has status 'success'.
    """
    scan_info = get_scan_completion_info(workspace)
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

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    new_vulns.sort(key=lambda v: (
        severity_order.get(v.get("severity", "low"), 4),
        v.get("file_path", ""),
        v.get("start_line", 0),
    ))

    return new_vulns, clean_file_paths, dirty_file_paths


def _maybe_notify_vulns(workspace: str, command: str) -> None:
    """Non-blocking check for completed scan vulns; notify once per result set.

    Peeks at scan.done without waiting. If vulns are found and the agent
    hasn't been notified about this exact set yet, denies the current bash
    command with /snyk-batch-fix instructions and includes the original
    command so the agent can re-run it after fixing.
    """
    state = read_state(workspace)
    code_files = state.get("code_files", {})
    if not code_files:
        output_allow()
        return

    # Non-blocking: only peek at scan.done, don't wait
    if not is_scan_complete(workspace):
        output_allow()
        return

    scan_info = get_scan_completion_info(workspace)
    if not scan_info or scan_info.get("status") != "success":
        output_allow()
        return

    new_vulns, _, _ = _evaluate_completed_scan(workspace, code_files)

    if not new_vulns:
        output_allow()
        return

    # Check if we already notified about these exact vulns
    current_fp = _compute_vuln_fingerprint(new_vulns)
    if current_fp == state.get("notified_scan_fingerprint", ""):
        output_allow()
        return

    # First time seeing these vulns — notify and include original command
    with _state_lock(workspace):
        state = read_state(workspace)
        state["notified_scan_fingerprint"] = current_fp
        write_state(workspace, state)

    reason_parts: List[str] = ["/snyk-batch-fix", ""]
    reason_parts.append("## Vulnerabilities Found in Modified Code")
    reason_parts.append("")
    reason_parts.append(_format_vuln_table(new_vulns))
    reason_parts.append("")
    reason_parts.append("After fixing the above issues, re-run your original command:")
    reason_parts.append(f"`{command}`")

    log_to_panel(f"[SAI] Early notification: {len(new_vulns)} vuln(s) found")
    output_deny("\n".join(reason_parts))


# =============================================================================
# HOOK HANDLERS
# =============================================================================

def handle_post_tool_use(data: Dict[str, Any], workspace: str) -> None:
    """Track file edits and launch background scans.
    Output is ignored by Copilot -- this is fire-and-forget."""
    tool_name = data.get("toolName", "")

    if tool_name not in ("edit", "create"):
        debug_log(f"Ignoring postToolUse for tool: {tool_name}")
        output_allow()
        return

    tool_args = data.get("toolArgs", {})
    if isinstance(tool_args, str):
        try:
            tool_args = json.loads(tool_args)
        except json.JSONDecodeError:
            tool_args = {}

    file_path = tool_args.get("filePath", tool_args.get("file_path", ""))
    if not file_path:
        output_allow()
        return

    if is_code_file(file_path):
        with _state_lock(workspace):
            state = read_state(workspace)

            if tool_name == "edit":
                # Try to extract edit content for line tracking.
                # Copilot may provide content differently -- fall back to full file.
                new_content = tool_args.get("content", tool_args.get("newContent", ""))
                old_content = tool_args.get("oldContent", "")

                if new_content and old_content:
                    # We have both old and new -- compute ranges from new content
                    edits = [{"new_string": new_content}]
                    try:
                        file_content = Path(file_path).read_text(
                            encoding="utf-8", errors="replace"
                        )
                    except (IOError, OSError):
                        file_content = new_content
                    new_ranges = compute_modified_ranges(file_content, edits)
                elif new_content:
                    edits = [{"new_string": new_content}]
                    try:
                        file_content = Path(file_path).read_text(
                            encoding="utf-8", errors="replace"
                        )
                    except (IOError, OSError):
                        file_content = new_content
                    new_ranges = compute_modified_ranges(file_content, edits)
                else:
                    # Fall back: mark entire file as modified
                    try:
                        file_content = Path(file_path).read_text(
                            encoding="utf-8", errors="replace"
                        )
                        line_count = file_content.count('\n') + 1
                    except (IOError, OSError):
                        line_count = 1
                    new_ranges = [{"start": 1, "end": line_count}]

                code_files = state.get("code_files", {})
                existing = code_files.get(file_path, {}).get("modified_ranges", [])
                code_files[file_path] = {
                    "modified_ranges": _accumulate_ranges(existing, new_ranges),
                    "last_edit": datetime.now().isoformat(),
                }
                state["code_files"] = code_files

            elif tool_name == "create":
                # New file -- mark entire file as modified
                content = tool_args.get("content", "")
                line_count = content.count('\n') + 1 if content else 1
                if not content:
                    try:
                        file_content = Path(file_path).read_text(
                            encoding="utf-8", errors="replace"
                        )
                        line_count = file_content.count('\n') + 1
                    except (IOError, OSError):
                        pass
                code_files = state.get("code_files", {})
                code_files[file_path] = {
                    "modified_ranges": [{"start": 1, "end": line_count}],
                    "last_edit": datetime.now().isoformat(),
                }
                state["code_files"] = code_files

            state["last_edit_ts"] = datetime.now().isoformat()
            state["notified_scan_fingerprint"] = ""
            write_state(workspace, state)
            range_count = len(state["code_files"][file_path]["modified_ranges"])

        log_to_panel(f"[SAI] Tracked: {Path(file_path).name} ({range_count} range(s))")

        # Check Snyk auth before launching background scan
        token = check_snyk_auth()
        if token is None:
            log_to_panel("[SAI] Snyk not authenticated -- skipping background scan")
            write_early_status(
                workspace,
                "auth_required",
                "Snyk CLI is not authenticated. Run snyk_auth to authenticate.",
            )
        elif launch_background_scan(workspace):
            log_to_panel("[SAI] Background scan launched")

    elif is_manifest_file(file_path):
        with _state_lock(workspace):
            state = read_state(workspace)
            manifests = state.get("manifest_files", [])
            if file_path not in manifests:
                manifests.append(file_path)
            state["manifest_files"] = manifests
            write_state(workspace, state)
        log_to_panel(f"[SAI] Manifest tracked: {Path(file_path).name}")

    else:
        debug_log(f"File not scannable, ignoring: {file_path}")

    output_allow()


def handle_pre_tool_use(data: Dict[str, Any], workspace: str) -> None:
    """Gate bash commands based on scan results.

    Two paths:
    - Non-git bash: non-blocking peek at scan results, notify once per vuln set
      via _maybe_notify_vulns (includes original command for re-run after fix)
    - Git operations: blocking wait for scan, deny with /snyk-batch-fix,
      notify-then-allow (retry proceeds)
    """
    tool_name = data.get("toolName", "")

    if tool_name != "bash":
        output_allow()
        return

    tool_args = data.get("toolArgs", {})
    if isinstance(tool_args, str):
        try:
            tool_args = json.loads(tool_args)
        except json.JSONDecodeError:
            tool_args = {}

    command = tool_args.get("command", "")

    if not is_git_vcs_operation(command):
        _maybe_notify_vulns(workspace, command)
        return

    debug_log(f"Git VCS operation detected: {command[:100]}")

    # --- Read state and check preconditions ---
    with _state_lock(workspace):
        state = read_state(workspace)

        if not has_pending_changes(state):
            debug_log("No pending changes, allowing git operation")
            output_allow()
            return

        deny_cycles = state.get("deny_cycles", 0)
        last_fingerprint = state.get("last_denial_fingerprint", "")

    code_files = state.get("code_files", {})
    manifest_files = state.get("manifest_files", [])

    new_vulns: List[Dict[str, Any]] = []
    clean_file_paths: List[str] = []
    dirty_file_paths: List[str] = []

    # --- Wait for scan and evaluate results ---
    if code_files:
        scan_status = wait_for_scan(
            workspace, timeout=PRE_TOOL_SCAN_WAIT_TIMEOUT, log_fn=log_to_panel
        )
        scan_succeeded = (scan_status == "success")
        scan_info = None

        # Stale detection: re-scan if edits happened after scan started
        if scan_succeeded:
            scan_info = get_scan_completion_info(workspace)
            last_edit_ts = state.get("last_edit_ts", "")
            started_at = (
                (scan_info.get("started_at") or scan_info.get("completed_at", ""))
                if scan_info else ""
            )

            if last_edit_ts and started_at and last_edit_ts > started_at:
                log_to_panel("[SAI] Edits after scan started, re-scanning...")
                clear_scan_state(workspace)
                launch_background_scan(workspace)
                scan_status = wait_for_scan(
                    workspace, timeout=PRE_TOOL_SCAN_WAIT_TIMEOUT, log_fn=log_to_panel
                )
                scan_succeeded = (scan_status == "success")
                scan_info = None

        if scan_succeeded:
            new_vulns, clean_file_paths, dirty_file_paths = \
                _evaluate_completed_scan(workspace, code_files)

            log_to_panel(
                f"[SAI] {len(new_vulns)} new vuln(s), "
                f"{len(clean_file_paths)} clean file(s)"
            )
        else:
            # Scan failed -- build fallback message
            scan_info = get_scan_completion_info(workspace)
            error_detail = scan_info.get("error_detail", "") if scan_info else ""
            file_list = ", ".join(Path(f).name for f in code_files)

            if scan_status == "auth_required":
                log_to_panel(
                    f"[SAI] Snyk CLI not authenticated: {error_detail}"
                    if error_detail else "[SAI] Snyk CLI not authenticated"
                )
                fallback = (
                    "The Snyk CLI is not authenticated. Run snyk_auth to authenticate, "
                    "then run snyk_code_scan on the current directory to check for "
                    f"vulnerabilities in: {file_list}. Fix only NEWLY INTRODUCED issues."
                )
            elif scan_status == "snyk_not_found":
                log_to_panel("[SAI] Snyk CLI not found, falling back to MCP")
                fallback = (
                    "Security scan could not complete (Snyk CLI not found). "
                    "Run snyk_code_scan on the current directory to check for vulnerabilities "
                    f"in: {file_list}. Fix only NEWLY INTRODUCED issues."
                )
            elif scan_status is None:
                log_to_panel("[SAI] Scan timed out, denying git operation")
                output_deny(
                    "Security scan is still in progress. "
                    "Please wait a moment and retry the commit."
                )
                return
            else:
                log_to_panel(f"[SAI] Scan failed (status: {scan_status}), falling back to MCP")
                fallback = (
                    "Security scan could not complete. "
                    "Run snyk_code_scan on the current directory to check for vulnerabilities "
                    f"in: {file_list}. Fix only NEWLY INTRODUCED issues."
                )

            if manifest_files:
                manifest_list = ", ".join(Path(f).name for f in manifest_files)
                fallback += (
                    f" Also run snyk_sca_scan to check dependencies. "
                    f"Modified manifests: {manifest_list}."
                )

            clear_state(workspace)
            output_deny(fallback)
            return

    # --- No vulns and no manifests: allow ---
    if not new_vulns and not manifest_files:
        log_to_panel("[SAI] No new security issues found.")
        clear_state(workspace)
        output_allow()
        return

    # --- Check notify-then-allow: if same vulns seen before, allow through ---
    current_fingerprint = _compute_vuln_fingerprint(new_vulns) if new_vulns else ""

    if deny_cycles > 0 and current_fingerprint and current_fingerprint == last_fingerprint:
        log_to_panel(
            f"[SAI] User chose to proceed (retry with same vulns, cycle {deny_cycles})"
        )
        clear_state(workspace)
        output_allow()
        return

    # --- First denial: show vulns and suggest fix or retry ---
    with _state_lock(workspace):
        state = read_state(workspace)
        # Remove clean files from tracking
        code = state.get("code_files", {})
        for fp in clean_file_paths:
            code.pop(fp, None)
        state["code_files"] = code
        if manifest_files:
            state["manifest_files"] = []
        # Track denial cycle
        state["deny_cycles"] = deny_cycles + 1
        state["last_denial_fingerprint"] = current_fingerprint
        write_state(workspace, state)

    if not dirty_file_paths:
        clear_scan_state(workspace)

    # --- Build /snyk-batch-fix denial reason ---
    reason_parts: List[str] = ["/snyk-batch-fix"]

    if new_vulns:
        reason_parts.append("")
        reason_parts.append("## Vulnerabilities Found in Modified Code")
        reason_parts.append("")
        reason_parts.append(_format_vuln_table(new_vulns))

    if manifest_files:
        reason_parts.append("")
        reason_parts.append("## Manifest Files Changed (SCA scan needed)")
        for mf in manifest_files:
            reason_parts.append(f"- {Path(mf).name}")

    if not new_vulns and manifest_files:
        reason_parts.insert(0, "/snyk-batch-fix")

    reason_parts.append("")
    reason_parts.append(
        "To proceed without fixing: retry the commit without changes."
    )

    log_to_panel(f"[SAI] Denying git operation: {len(new_vulns)} vuln(s) found")
    output_deny("\n".join(reason_parts))


def handle_agent_stop(data: Dict[str, Any], workspace: str) -> None:
    """Audit logging only -- agentStop output is ignored by Copilot."""
    state = read_state(workspace)
    if has_pending_changes(state):
        code_files = list(state.get("code_files", {}).keys())
        manifest_files = state.get("manifest_files", [])
        log_to_panel(
            f"[SAI] Session ended with pending changes: "
            f"{len(code_files)} code file(s), {len(manifest_files)} manifest(s)"
        )
    else:
        log_to_panel("[SAI] Session ended clean")
    output_allow()


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
        output_allow()
        sys.exit(0)

    # Determine hook event: try stdin field first, fall back to env var
    hook_event = data.get("hookEvent", data.get("hook_event_name", ""))
    if not hook_event:
        hook_event = os.environ.get("SAI_HOOK_EVENT", "")

    workspace = get_workspace(data)
    debug_log(f"Event: {hook_event}, Workspace: {workspace}")

    handlers = {
        "postToolUse": handle_post_tool_use,
        "preToolUse": handle_pre_tool_use,
        "agentStop": handle_agent_stop,
    }

    handler = handlers.get(hook_event)
    if handler:
        handler(data, workspace)
    else:
        debug_log(f"Unknown hook event: {hook_event}")
        output_allow()


if __name__ == "__main__":
    main()
