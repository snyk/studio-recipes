#!/usr/bin/env python3
"""
Gemini Code Hook: Snyk Secure At Inception
============================================

Launches background Snyk CLI scans on file edit/write, tracks modified
line ranges, and blocks Gemini from stopping if new vulnerabilities were
introduced in agent-modified code.

WORKFLOW:
  1. Startup -> Runs auth check and an initial scan to warm cache
  2. AfterTool (write_file|replace) -> Scans file code changes
  2. Stop -> wait for scan, filter results to modified lines, block if new vulns

INSTALLATION:
  1. Copy this script and lib/ to .gemini/hooks/
  2. chmod +x snyk_secure_at_inception.py
  3. Merge settings.json into .gemini/settings.json
"""

import json
import os
import sys
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).parent.resolve()
LIB_DIR = SCRIPT_DIR / "lib"
sys.path.insert(0, str(LIB_DIR))

from platform_utils import file_lock, normalize_path  # noqa: E402 — imports follow sys.path setup
from scan_runner import (  # noqa: E402 — imports follow sys.path setup
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

DEBUG = os.environ.get("GEMINI_HOOK_DEBUG", "0") == "1"

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
# UTILITY FUNCTIONS
# =============================================================================


def debug_log(message: str) -> None:
    if DEBUG:
        print(f"[DEBUG] {message}", file=sys.stderr)


def log_to_panel(message: str) -> None:
    print(message, file=sys.stderr)


def output_response(response: Dict[str, Any]) -> None:
    print(json.dumps(response), file=sys.stdout)


def get_state_file_path(workspace: str) -> str:
    return os.path.join(get_cache_dir(workspace), "state.json")


def get_workspace(data: Dict[str, Any]) -> str:
    return data.get("cwd", os.getcwd())


def is_code_file(file_path: str) -> bool:
    return Path(file_path).suffix.lower() in CODE_EXTENSIONS


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
    return longer[-len(shorter) :] == shorter


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
def _state_lock(workspace: str):
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
                return json.load(f)
    except (OSError, json.JSONDecodeError):
        pass
    return {"code_files": {}, "manifest_baseline": {}, "stop_cycles": 0, "last_update": None}


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


def handle_session_start(data: Dict[str, Any], workspace: str) -> None:
    """Verify prerequisites and launch a cache-warming scan at session start.

    Checks Snyk auth and CLI presence. If either is missing, reports via
    additionalContext so Gemini can inform the user. If all checks pass,
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
        user_messages: List[str] = []
        if "cli" in issues:
            context_parts.append(
                "Snyk CLI is not installed or not on PATH. Security scanning "
                "requires the Snyk CLI. Install it with `npm install -g snyk` "
                "and authenticate with `snyk auth`."
            )
            user_messages.append("Snyk CLI")
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
            user_messages.append("Snyk auth")
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
                },
            }
        )
        return

    # 4. All checks passed -- clear stale state on fresh sessions
    log_to_panel("[SAI] Snyk authenticated, CLI found")
    if source in ("startup", "clear"):
        clear_state(workspace)

    # 5. Launch cache-warming scans (non-blocking, dedup built-in)
    if launch_background_scan(workspace):
        log_to_panel("[SAI] Cache-warming scan launched")
    else:
        debug_log("Cache-warm scan not launched (already running or complete)")

    if launch_background_sca_scan(workspace):
        log_to_panel("[SAI] Cache-warming SCA scan launched")
    else:
        debug_log("Cache-warm SCA scan not launched (already running or complete)")

    # 6. Snapshot manifest hashes for hash-diff SCA triggering at AfterAgent
    with _state_lock(workspace):
        state = read_state(workspace)
        state["manifest_baseline"] = snapshot_manifest_hashes(
            workspace, MANIFEST_FILES, MANIFEST_SUFFIXES
        )
        write_state(workspace, state)
    debug_log(f"Manifest baseline: {len(state['manifest_baseline'])} files snapshotted")

    output_response({})


def handle_after_tool(data: Dict[str, Any], workspace: str) -> None:
    """Track file edits and launch background scans."""
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    file_path = tool_input.get("file_path", "")
    if not file_path:
        output_response({})
        return

    if is_code_file(file_path):
        with _state_lock(workspace):
            state = read_state(workspace)

            if tool_name == "replace":
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

            elif tool_name == "write_file":
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

        if launch_background_scan(workspace):
            log_to_panel("[SAI] Background scan launched")

    else:
        debug_log(f"File not scannable, ignoring: {file_path}")

    output_response({})


def handle_after_agent(data: Dict[str, Any], workspace: str) -> None:
    """Evaluate scan results and block if new vulnerabilities were introduced."""

    # --- Read state and check preconditions ---
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

    # --- Wait for SAST scan and evaluate results ---
    if code_files:
        scan_status = wait_for_scan(workspace, log_fn=log_to_panel)
        scan_succeeded = scan_status == "success"
        scan_info = None

        # Stale detection: re-scan if edits happened after scan started
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

            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            new_vulns.sort(
                key=lambda v: (
                    severity_order.get(v.get("severity", "low"), 4),
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

    # --- Detect manifest changes and conditionally clear stale SCA state ---
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
                log_to_panel("[SAI] SCA skipped: Snyk not authenticated (run `snyk auth`)")
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
        else:
            if sca_status == "auth_required":
                log_to_panel("[SAI] SCA skipped: Snyk not authenticated (run `snyk auth`)")
            elif sca_status == "snyk_not_found":
                log_to_panel("[SAI] SCA skipped: Snyk CLI not found on PATH")
            elif sca_status is None:
                log_to_panel("[SAI] SCA scan timed out, continuing with SAST results only")
            else:
                log_to_panel(f"[SAI] SCA scan did not complete (status: {sca_status})")

    # --- Handle SAST scan failure early return ---
    if sast_failed:
        if new_sca_vulns:
            sast_fallback += "\n\n## Newly Introduced Dependency Vulnerabilities\n\n"
            sast_fallback += _format_sca_vuln_table(new_sca_vulns)
        elif sca_fallback:
            sast_fallback += f"\n\n## Dependency Scan Unavailable\n\n{sca_fallback}"
        clear_state(workspace)
        log_to_panel(str({"decision": "deny", "reason": sast_fallback, "continue": True}))
        sys.exit(2)

    # --- Update state and decide ---
    if not new_vulns and not new_sca_vulns and not sca_fallback:
        log_to_panel("[SAI] No new security issues found.")
        clear_state(workspace)
        output_response({})
        return

    # Remove clean files in one locked write
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

    # --- Build block reason ---
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
            "\nFix the highest-priority new vulnerability above using a minimal package upgrade "
            "(e.g., bump the package to the nearest non-vulnerable version). "
            "Pre-existing vulnerabilities in this workspace are out of scope — "
            "address only what you introduced in this session."
        )

    if sca_fallback:
        reason_parts.append(f"\n## Dependency Scan Unavailable\n\n{sca_fallback}")

    reason_parts.append("\nAfter fixing, the security scan will run again automatically.")

    log_to_panel(f"[SAI] Blocking: {len(new_vulns)} SAST + {len(new_sca_vulns)} SCA vuln(s)")

    # blocking response should be sent to stderr
    log_to_panel(str({"decision": "deny", "reason": "\n".join(reason_parts), "continue": True}))

    # gemini only retries with feedback prompt on exit code 2
    sys.exit(2)


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

    debug_log(f"Event: {hook_event}, Workspace: {workspace}")

    handlers = {
        "SessionStart": handle_session_start,
        "AfterTool": handle_after_tool,
        "AfterAgent": handle_after_agent,
    }

    handler = handlers.get(hook_event)
    if handler:
        handler(data, workspace)
    else:
        debug_log(f"Unknown hook event: {hook_event}")
        output_response({})


if __name__ == "__main__":
    main()
