#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# ///
"""
GitHub Copilot Hook: Snyk Secure At Inception
===============================================

Launches background Snyk CLI scans on file edit/create, tracks modified
line ranges, and blocks Copilot from finishing if new vulnerabilities
were introduced in agent-modified code.


WORKFLOW:
  1. postToolUse (any file edit/create tool) -> track ranges, launch background scan
  2. agentStop -> wait for scan, filter results to modified lines, block if new vulns

INSTALLATION:
  1. Copy this script and lib/ to ~/.copilot/hooks/
  2. chmod +x snyk_secure_at_inception.py
  3. Merge hooks.json into ~/.copilot/hooks.json

PREREQUISITES:
  - Python 3.8+
  - Snyk CLI (npm install -g snyk)
  - Snyk authentication (snyk auth)
"""

import json
import os
import sys
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, cast

SCRIPT_DIR = Path(__file__).parent.resolve()
LIB_DIR = SCRIPT_DIR / "lib"
sys.path.insert(0, str(LIB_DIR))

from platform_utils import file_lock, normalize_path  # noqa: E402
from scan_runner import (  # noqa: E402
    check_snyk_auth,
    check_snyk_cli,
    clear_sca_scan_state,
    clear_scan_state,
    detect_manifest_changes,
    ensure_cache_dirs,
    get_cache_dir,
    get_sca_completion_info,
    get_scan_completion_info,
    launch_background_sca_scan,
    launch_background_scan,
    snapshot_manifest_hashes,
    wait_for_sca_scan,
    wait_for_scan,
    write_early_status,
)

# =============================================================================
# CONFIGURATION
# =============================================================================

DEBUG = os.environ.get("COPILOT_HOOK_DEBUG", "0") == "1"

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
    "pyproject.toml",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
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
# UTILITY FUNCTIONS
# =============================================================================


def debug_log(message: str) -> None:
    if DEBUG:
        print(f"[DEBUG] {message}", file=sys.stderr)


def log_to_panel(message: str) -> None:
    print(message, file=sys.stderr)


def output_response(response: Dict[str, Any]) -> None:
    print(json.dumps(response))


def output_block(reason: str, data: Dict[str, Any]) -> None:
    """Emit a 'block' decision that keeps the turn open and re-prompts the agent.

    Works on both Copilot surfaces. The Copilot CLI reads a top-level
    {"decision":"block","reason":...}; the GitHub Copilot Chat extension reads
    it nested under hookSpecificOutput keyed by hookEventName. Emit both -- each
    host ignores the field it doesn't use."""
    output_response(
        {
            "decision": "block",
            "reason": reason,
            "hookSpecificOutput": {
                "hookEventName": data.get("hook_event_name") or "Stop",
                "decision": "block",
                "reason": reason,
            },
        }
    )


def get_state_file_path(workspace: str) -> str:
    return os.path.join(get_cache_dir(workspace), "state.json")


def get_workspace(data: Dict[str, Any]) -> str:
    return str(data.get("cwd", os.getcwd()))


def is_code_file(file_path: str) -> bool:
    return Path(file_path).suffix.lower() in CODE_EXTENSIONS


def _parse_tool_args(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


# File-modifying tool names across both Copilot surfaces. The Copilot CLI sends
# edit/write/create; the Copilot Chat extension sends replace_string_in_file /
# multi_replace_string_in_file / insert_edit_into_file / create_file / apply_patch.
# Matching is case-insensitive.
_CREATE_TOOLS = {"write", "create", "create_file"}
_EDIT_TOOLS = {
    "edit",
    "multiedit",
    "str_replace_editor",
    "replace_string_in_file",
    "multi_replace_string_in_file",
    "insert_edit_into_file",
    "apply_patch",
}


def _classify_edit_tool(tool_name: str) -> Optional[str]:
    """Map a Copilot tool name (CLI or Chat extension) to 'edit' or 'create', or
    None if the tool does not modify file contents (and the edit is ignored)."""
    name = (tool_name or "").lower()
    if name in _CREATE_TOOLS:
        return "create"
    if name in _EDIT_TOOLS:
        return "edit"
    return None


# =============================================================================
# LINE TRACKING
# =============================================================================


def compute_modified_ranges(file_content: str, edits: List[Dict[str, str]]) -> List[Dict[str, int]]:
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
# VULNERABILITY FILTERING
# =============================================================================


def _paths_match(path_a: str, path_b: str) -> bool:
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
    Cross-platform via platform_utils.file_lock (no-op where unsupported)."""
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
        "manifest_baseline": {},
        "stop_cycles": 0,
        "session_initialized": False,
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
    clear_sca_scan_state(workspace)


def has_pending_changes(state: Dict[str, Any]) -> bool:
    return bool(state.get("code_files"))


# =============================================================================
# HOOK HANDLERS
# =============================================================================


def _initialize_session(workspace: str, state: Dict[str, Any]) -> None:
    """Cache-warming scan + manifest-baseline snapshot. Called from sessionStart
    and also (idempotently) on the first postToolUse if sessionStart never
    fired (Copilot has known sessionStart bugs in resume / -p / some paths)."""
    if state.get("session_initialized"):
        return

    if check_snyk_cli() is None:
        write_early_status(workspace, "snyk_not_found", "Snyk CLI not found on PATH.")
        log_to_panel("[SAI] Snyk CLI not found on PATH")
        state["session_initialized"] = True
        return
    if check_snyk_auth() is None:
        write_early_status(workspace, "auth_required", "Snyk CLI is not authenticated.")
        log_to_panel("[SAI] Snyk CLI not authenticated")
        state["session_initialized"] = True
        return

    if launch_background_scan(workspace):
        log_to_panel("[SAI] Cache-warming scan launched")
    if launch_background_sca_scan(workspace):
        log_to_panel("[SAI] Cache-warming SCA scan launched")

    state["manifest_baseline"] = snapshot_manifest_hashes(
        workspace, MANIFEST_FILES, MANIFEST_SUFFIXES
    )
    state["session_initialized"] = True


def handle_session_start(data: Dict[str, Any], workspace: str) -> None:
    """Warm Snyk's cache and snapshot manifest hashes on a fresh session.

    Copilot delivers `source` as one of startup/resume/new. On startup/new we
    clear any stale state so a previous session's pending vulns don't carry
    over; on resume we keep state intact."""
    source = data.get("source") or data.get("Source") or "startup"
    if source in ("startup", "new"):
        clear_state(workspace)

    with _state_lock(workspace):
        state = read_state(workspace)
        _initialize_session(workspace, state)
        write_state(workspace, state)

    output_response({})


def handle_post_tool_use(data: Dict[str, Any], workspace: str) -> None:
    """Track file edits and launch background scans. Output ignored."""
    # Field names differ by surface: the Copilot CLI sends toolName/toolArgs;
    # the Copilot Chat extension sends the Claude-style tool_name/tool_input.
    raw_tool_name = data.get("tool_name") or data.get("toolName") or ""
    raw_tool_args = data.get("tool_input")
    if raw_tool_args is None:
        raw_tool_args = data.get("toolArgs", {})

    edit_kind = _classify_edit_tool(raw_tool_name)
    if edit_kind is None:
        debug_log(f"Ignoring postToolUse for tool: {raw_tool_name}")
        output_response({})
        return

    tool_args = _parse_tool_args(raw_tool_args)
    file_path = tool_args.get("filePath") or tool_args.get("file_path") or tool_args.get("path", "")
    if not file_path:
        debug_log(f"No file path in tool args (keys: {list(tool_args.keys())})")
        output_response({})
        return

    if not is_code_file(file_path):
        debug_log(f"File not scannable, ignoring: {file_path}")
        output_response({})
        return

    with _state_lock(workspace):
        state = read_state(workspace)
        _initialize_session(workspace, state)

        if edit_kind == "edit":
            new_content = (
                tool_args.get("content")
                or tool_args.get("newContent")
                or tool_args.get("new_string")
                or tool_args.get("newString")  # Copilot Chat replace_string_in_file
                or tool_args.get("code", "")  # Copilot Chat insert_edit_into_file
            )
            if new_content:
                try:
                    file_content = Path(file_path).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    file_content = new_content
                new_ranges = compute_modified_ranges(file_content, [{"new_string": new_content}])
                if not new_ranges:
                    line_count = file_content.count("\n") + 1 if file_content else 1
                    new_ranges = [{"start": 1, "end": line_count}]
            else:
                try:
                    file_content = Path(file_path).read_text(encoding="utf-8", errors="replace")
                    line_count = file_content.count("\n") + 1
                except OSError:
                    line_count = 1
                new_ranges = [{"start": 1, "end": line_count}]

            code_files = state.get("code_files", {})
            existing = code_files.get(file_path, {}).get("modified_ranges", [])
            code_files[file_path] = {
                "modified_ranges": _accumulate_ranges(existing, new_ranges),
                "last_edit": datetime.now().isoformat(),
            }
            state["code_files"] = code_files
        else:  # write / create
            content = tool_args.get("content", "")
            if not content:
                try:
                    content = Path(file_path).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    content = ""
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

    # Early error detection: if a prior scan failed for auth/cli reasons,
    # surface it now so the agent stops introducing more code.
    scan_info = get_scan_completion_info(workspace)
    if scan_info:
        cached_status = scan_info.get("status")
        if cached_status in ("auth_required", "snyk_not_found"):
            log_to_panel(f"[SAI] Prerequisite issue detected: {cached_status}")
            clear_scan_state(workspace)
            if cached_status == "auth_required":
                reason = (
                    "Snyk CLI is not authenticated. Security scanning cannot run. "
                    "Run `snyk auth` in a terminal to authenticate, then continue editing."
                )
            else:
                reason = (
                    "Snyk CLI is not installed or not on PATH. Install it with "
                    "`npm install -g snyk` and authenticate with `snyk auth`."
                )
            output_block(reason, data)
            return

    if launch_background_scan(workspace):
        log_to_panel("[SAI] Background scan launched")

    output_response({})


def handle_agent_stop(data: Dict[str, Any], workspace: str) -> None:
    """Evaluate scan results and block if new vulnerabilities were introduced."""

    with _state_lock(workspace):
        state = read_state(workspace)

        if not has_pending_changes(state):
            debug_log("No pending changes")
            output_response({})
            return

        stop_cycles = state.get("stop_cycles", 0)
        if stop_cycles >= MAX_STOP_CYCLES:
            log_to_panel(f"[SAI] Max cycles ({MAX_STOP_CYCLES}) reached, allowing stop")
            clear_state(workspace)
            output_response({})
            return

        state["stop_cycles"] = stop_cycles + 1
        write_state(workspace, state)

    code_files = state.get("code_files", {})

    new_vulns: List[Dict[str, Any]] = []
    new_sca_vulns: List[Dict[str, Any]] = []
    clean_file_paths: List[str] = []
    dirty_file_paths: List[str] = []
    sast_failed = False
    sast_fallback = ""
    sca_fallback = ""
    changed_manifests: List[str] = []

    if code_files:
        scan_status = wait_for_scan(workspace, log_fn=log_to_panel)
        scan_succeeded = scan_status == "success"
        scan_info = None

        if scan_succeeded:
            scan_info = get_scan_completion_info(workspace)
            last_edit_ts = state.get("last_edit_ts", "")
            started_at = (
                (scan_info.get("started_at") or scan_info.get("completed_at", ""))
                if scan_info
                else ""
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
            log_to_panel(
                f"[SAI] {len(new_vulns)} new vuln(s), {len(clean_file_paths)} clean file(s)"
            )
        else:
            sast_failed = True
            scan_info = get_scan_completion_info(workspace)
            error_detail = scan_info.get("error_detail", "") if scan_info else ""
            file_list = ", ".join(Path(f).name for f in code_files)

            if scan_status == "auth_required":
                log_to_panel(
                    f"[SAI] Snyk CLI not authenticated: {error_detail}"
                    if error_detail
                    else "[SAI] Snyk CLI not authenticated"
                )
                sast_fallback = (
                    "The Snyk CLI is not authenticated. Run snyk_auth to authenticate, "
                    "then run snyk_code_scan on the current directory to check for "
                    f"vulnerabilities in: {file_list}. Fix only NEWLY INTRODUCED issues."
                )
            elif scan_status == "snyk_not_found":
                log_to_panel("[SAI] Snyk CLI not found, falling back to MCP")
                sast_fallback = (
                    "Security scan could not complete. "
                    "Run snyk_code_scan on the current directory to check for vulnerabilities "
                    f"in: {file_list}. Fix only NEWLY INTRODUCED issues."
                )
            else:
                log_to_panel(f"[SAI] Scan failed (status: {scan_status}), falling back to MCP")
                sast_fallback = (
                    "Security scan could not complete. "
                    "Run snyk_code_scan on the current directory to check for vulnerabilities "
                    f"in: {file_list}. Fix only NEWLY INTRODUCED issues."
                )

    baseline_keys = None
    if code_files:
        changed_manifests = detect_manifest_changes(
            workspace, state.get("manifest_baseline", {}), MANIFEST_FILES, MANIFEST_SUFFIXES
        )
        if changed_manifests:
            log_to_panel("[SAI] Manifest changes detected — re-running SCA scan")
            baseline_info = get_sca_completion_info(workspace)
            if baseline_info and baseline_info.get("status") == "success":
                baseline_vulns = baseline_info.get("vulnerabilities", [])
                baseline_keys = frozenset(
                    (v.get("id", ""), v.get("package_name", ""), v.get("version", ""))
                    for v in baseline_vulns
                )
            clear_sca_scan_state(workspace)

        sca_status = wait_for_sca_scan(workspace, log_fn=log_to_panel)
        if sca_status == "success":
            sca_info = get_sca_completion_info(workspace)
            sca_vulns = sca_info.get("vulnerabilities", []) if sca_info else []
            log_to_panel(f"[SAI] SCA: {len(sca_vulns)} dependency vuln(s)")
            if not changed_manifests:
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
        elif changed_manifests:
            manifest_list = ", ".join(Path(f).name for f in changed_manifests)
            if sca_status == "auth_required":
                log_to_panel("[SAI] SCA skipped: Snyk not authenticated")
                sca_fallback = (
                    "The Snyk CLI is not authenticated. Run snyk_auth to authenticate, "
                    "then run snyk_sca_scan on the current directory to check for "
                    f"dependency vulnerabilities in: {manifest_list}. Fix only NEWLY INTRODUCED issues."
                )
            else:
                log_to_panel(f"[SAI] SCA scan did not complete (status: {sca_status})")
                sca_fallback = (
                    "Security scan could not complete. "
                    "Run snyk_sca_scan on the current directory to check for "
                    f"dependency vulnerabilities in: {manifest_list}. Fix only NEWLY INTRODUCED issues."
                )

    if sast_failed:
        if new_sca_vulns:
            sast_fallback += "\n\n## Newly Introduced Dependency Vulnerabilities\n\n"
            sast_fallback += _format_sca_vuln_table(new_sca_vulns)
        elif sca_fallback:
            sast_fallback += f"\n\n## Dependency Scan Unavailable\n\n{sca_fallback}"
        clear_state(workspace)
        output_block(sast_fallback, data)
        return

    if not new_vulns and not new_sca_vulns and not sca_fallback:
        log_to_panel("[SAI] No new security issues found.")
        clear_state(workspace)
        output_response({})
        return

    with _state_lock(workspace):
        state = read_state(workspace)
        code = state.get("code_files", {})
        for fp in clean_file_paths:
            code.pop(fp, None)
        state["code_files"] = code
        write_state(workspace, state)

    if not dirty_file_paths:
        clear_scan_state(workspace)
    clear_sca_scan_state(workspace)

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
            "\nFix the highest-priority new vulnerability above using a minimal package upgrade. "
            "Pre-existing vulnerabilities are out of scope — address only what you introduced."
        )

    if sca_fallback:
        reason_parts.append(f"\n## Dependency Scan Unavailable\n\n{sca_fallback}")

    reason_parts.append("\nAfter fixing, the security scan will run again automatically.")

    log_to_panel(f"[SAI] Blocking: {len(new_vulns)} SAST + {len(new_sca_vulns)} SCA vuln(s)")
    output_block("\n".join(reason_parts), data)


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================


def main() -> None:
    # Copilot does NOT include the event name in the stdin payload — it must
    # be passed as argv[1] from hooks.json's `bash` command.
    hook_event = sys.argv[1] if len(sys.argv) > 1 else ""

    try:
        input_data = sys.stdin.read()
        data = json.loads(input_data) if input_data.strip() else {}
        debug_log(f"Event={hook_event} data={json.dumps(data)[:500]}")
    except json.JSONDecodeError as e:
        log_to_panel(f"[SAI] Error parsing hook input: {e}")
        output_response({})
        sys.exit(0)

    workspace = get_workspace(data)

    handlers = {
        "sessionStart": handle_session_start,
        "SessionStart": handle_session_start,
        "postToolUse": handle_post_tool_use,
        "agentStop": handle_agent_stop,
    }

    handler = handlers.get(hook_event)
    if handler:
        handler(data, workspace)
    else:
        debug_log(f"Unknown hook event: {hook_event}")
        output_response({})


if __name__ == "__main__":
    main()
