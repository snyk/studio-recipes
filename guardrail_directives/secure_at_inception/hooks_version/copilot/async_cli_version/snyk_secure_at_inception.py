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
  1. postToolUse (file edit/create tool) -> track ranges, launch background scan
  2. postToolUse (shell tool) -> detect manifest mutations, launch background SCA scan
  3. agentStop -> wait for scan, filter results to modified lines, block if new vulns

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

from platform_utils import (  # noqa: E402
    STUDIO_VERSION,
    file_lock,
    normalize_path,
    parse_iso_timestamp,
    resolve_log_file,
    scan_duration_secs,
)
from platform_utils import log as _shared_log  # noqa: E402
from scan_runner import (  # noqa: E402
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

DEBUG = os.environ.get("COPILOT_HOOK_DEBUG", "0") == "1"

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

# Per Copilot's hooks docs: startup, resume, new.
KNOWN_SESSION_START_SOURCES = {"startup", "resume", "new"}

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
    unscanned_status: str = ""
    unscanned_detail: str = ""
    scan_info: Optional[Dict[str, Any]] = None


@dataclass
class ScaResult:
    new_sca_vulns: List[Dict[str, Any]] = field(default_factory=list)
    unscanned_status: str = ""
    unscanned_detail: str = ""
    duration: Optional[float] = None


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


def output_response(response: Dict[str, Any]) -> None:
    print(json.dumps(response))
    # Flush explicitly: under `uvw run --gui-script` (pythonw) on Windows stdout is
    # a fully-buffered pipe, so the findings JSON must be flushed to reach the ADE.
    sys.stdout.flush()


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


def get_invocation_marker_path(workspace: str) -> str:
    return os.path.join(get_cache_dir(workspace), "hook.invoked")


def get_workspace(data: Dict[str, Any]) -> str:
    return str(data.get("cwd", os.getcwd()))


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


def is_manifest_file(file_path: str) -> bool:
    p = Path(file_path)
    return p.name in MANIFEST_FILES or p.suffix.lower() in MANIFEST_SUFFIXES


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
# Shell-execution tool names across both Copilot surfaces (CLI sends "bash",
# the Chat extension sends "run_in_terminal"). Bash-driven manifest mutations
# (npm install, pip install, etc.) bypass the edit/write tool_name path entirely.
_SHELL_TOOLS = {"bash", "run_in_terminal"}


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

    if _LOG_FILE:
        _shared_log(f"SessionStart: studio v{STUDIO_VERSION}", _LOG_FILE)
    if launch_background_scan(workspace):
        log_to_panel("[SAI] Cache-warming scan launched")

    # The SCA baseline scan result persists across Stop cycles — regular scans compare against it.
    if launch_background_sca_baseline_scan(workspace):
        log_to_panel("[SAI] Cache-warming SCA scan launched")
        save_manifest_hash_baseline(workspace, MANIFEST_FILES, MANIFEST_SUFFIXES)

    state["session_initialized"] = True


def handle_session_start(data: Dict[str, Any], workspace: str) -> None:
    """Warm Snyk's cache and snapshot manifest hashes on a fresh session.

    Copilot delivers `source` as one of startup/resume/new. On startup/new we
    clear any stale state so a previous session's pending vulns don't carry
    over; on resume we keep state intact."""
    source = data.get("source") or data.get("Source") or ""
    log_to_panel(f"[SAI] SessionStart source={source!r}")
    if source not in KNOWN_SESSION_START_SOURCES:
        log_to_panel(f"[SAI] Unrecognized SessionStart source {source!r}, treating as resume")
    if source in ("startup", "new"):
        clear_state(workspace)
        clear_baseline(workspace)

    with _state_lock(workspace):
        state = read_state(workspace)
        _initialize_session(workspace, state)
        # One auth prompt per session, so a new session gets its prompt back.
        # startup/new already wiped state.json above; resume did not.
        # Unconditional rather than guarded on `source`: after clear_state() the
        # pop is a no-op, and an unrecognised future source cannot skip it.
        state.pop("auth_prompted", None)
        write_state(workspace, state)

    output_response({})


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

    The shell branch used to walk and hash the entire workspace on *every*
    command -- 43s and 11k files when the session was started from $HOME. This
    is only a fast path: the agentStop hook's hash diff is still the
    authoritative check, so a mutation this misses is caught at the end of the
    turn.
    """
    return bool(command) and bool(_PKG_COMMAND_RE.search(command))


def _trigger_sca_and_save(workspace: str, snapshot: Dict[str, str]) -> None:
    """Trigger an SCA scan and record snapshot as the new last-scan reference."""
    if trigger_sca_scan(workspace):
        log_to_panel("[SAI] Background SCA scan launched")
        save_manifest_hash_last_scan(workspace, MANIFEST_FILES, MANIFEST_SUFFIXES, hashes=snapshot)


def handle_post_tool_use(data: Dict[str, Any], workspace: str) -> None:
    """Track file edits and launch background scans. Output ignored."""
    # Field names differ by surface: the Copilot CLI sends toolName/toolArgs;
    # the Copilot Chat extension sends the Claude-style tool_name/tool_input.
    raw_tool_name = data.get("tool_name") or data.get("toolName") or ""
    raw_tool_args = data.get("tool_input")
    if raw_tool_args is None:
        raw_tool_args = data.get("toolArgs", {})

    # Shell commands that mutate manifests (npm install, pip install, etc.) bypass
    # the edit/write tool_name path. Detect them by checking whether any manifest
    # file actually changed on disk after the command ran.
    if (raw_tool_name or "").lower() in _SHELL_TOOLS:
        with _state_lock(workspace):
            state = read_state(workspace)
            _initialize_session(workspace, state)
            write_state(workspace, state)

        _shell_args = _parse_tool_args(raw_tool_args)
        command = str(_shell_args.get("command", ""))
        if not _may_touch_manifests(command):
            debug_log(f"Shell command cannot touch manifests, skipping walk: {command[:120]}")
            output_response({})
            return
        log_to_panel("[SAI] Package-manager command detected. Checking if manifests changed.")
        _hashes = load_manifest_hashes(workspace) or {}
        _compare_against = _hashes.get("last_scan") or _hashes.get("baseline", {})
        _snapshot = snapshot_manifest_hashes(workspace, MANIFEST_FILES, MANIFEST_SUFFIXES)
        changed = diff_manifest_hashes(_snapshot, _compare_against)
        if changed:
            log_to_panel(
                f"[SAI] Manifest change detected: {', '.join(Path(f).name for f in changed)}"
            )
            _trigger_sca_and_save(workspace, _snapshot)
        output_response({})
        return

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

    is_code = is_code_file(file_path)
    is_manifest = is_manifest_file(file_path)
    if not is_code and not is_manifest:
        debug_log(f"File not scannable, ignoring: {file_path}")
        output_response({})
        return

    if not _within_workspace(file_path, workspace):
        debug_log(f"File outside workspace, ignoring: {file_path}")
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
        # Tracked under separators unified so the same file edited via
        # backslash- vs forward-slash-separated paths (both reported by
        # Windows tooling across separate tool calls) accumulates into one
        # entry instead of silently splitting into two.
        file_key = file_path.replace("\\", "/")
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
                    new_ranges = compute_modified_ranges(
                        file_content, [{"new_string": new_content}]
                    )
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
                existing = code_files.get(file_key, {}).get("modified_ranges", [])
                code_files[file_key] = {
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
                code_files[file_key] = {
                    "modified_ranges": [{"start": 1, "end": line_count}],
                    "last_edit": datetime.now().isoformat(),
                }
                state["code_files"] = code_files

            state["last_edit_ts"] = datetime.now().isoformat()
            write_state(workspace, state)
            range_count = len(state["code_files"][file_key]["modified_ranges"])

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

    if is_manifest:
        with _state_lock(workspace):
            state = read_state(workspace)
            _initialize_session(workspace, state)
            write_state(workspace, state)

        log_to_panel(f"[SAI] Manifest edit tracked: {Path(file_path).name}")
        _snapshot = snapshot_manifest_hashes(workspace, MANIFEST_FILES, MANIFEST_SUFFIXES)
        _trigger_sca_and_save(workspace, _snapshot)

    output_response({})


def _check_stop_preconditions(workspace: str) -> Tuple[Optional[Dict[str, Any]], StopContext]:
    """Read state and handle the no-pending-changes and max-cycles-reached
    early exits. Runs under _state_lock.

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
            log_to_panel(
                f"[SAI] Stop: no pending changes (tracked files: {len(state.get('code_files', {}))}, "
                f"manifest hashes changed vs baseline: {len(hash_changed_from_baseline)})"
            )
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

    scan_status = wait_for_scan(workspace, log_fn=log_to_panel)
    scan_succeeded = scan_status == "success"
    scan_info: Optional[Dict[str, Any]] = None

    if scan_succeeded:
        scan_info = get_scan_completion_info(workspace)
        last_edit_ts = state.get("last_edit_ts", "")
        started_at = (
            (scan_info.get("started_at") or scan_info.get("completed_at", "")) if scan_info else ""
        )
        if last_edit_ts and started_at and last_edit_ts > started_at:
            log_to_panel("[SAI] Edits after scan started, re-scanning...")
            trigger_scan(workspace)
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
    """Wait for the SCA scan, re-scanning once if manifests changed, and diff
    dependency vulns against the session-start baseline."""
    if not manifests_changed:
        return ScaResult()

    baseline_keys = None
    if manifests_changed:
        if hash_changed_from_baseline:
            debug_log(f"[SAI] Detected manifest change(s): {hash_changed_from_baseline}")

        # Re-run SCA only if manifests changed since the last scan
        if hash_changed_from_last_scan:
            log_to_panel("[SAI] Manifest changes detected — re-running SCA scan")
            _trigger_sca_and_save(workspace, current_hashes)

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
        sca_started_dt = parse_iso_timestamp(sca_started_at)
        last_triggered_dt = parse_iso_timestamp(last_triggered_at)
        if (
            sca_started_dt is not None
            and last_triggered_dt is not None
            and sca_started_dt < last_triggered_dt
        ):
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

    status, detail = _log_unscanned("SCA", sca_status, get_sca_completion_info(workspace))
    return ScaResult(unscanned_status=status, unscanned_detail=detail)


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

    Sole builder of these strings. Unlike Claude Code and Gemini CLI, Copilot's
    agentStop hook has no user-visible, non-context field -- it accepts only
    decision/reason, both of which are fed to the agent -- so this goes to the
    panel log rather than the terminal. Routing it through `reason` instead
    would put a scan failure back in the model's context, which is the cost
    this change exists to remove. Kept ASCII for the log.
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


def handle_agent_stop(data: Dict[str, Any], workspace: str) -> None:
    """Evaluate scan results and block if new vulnerabilities were introduced.

    A scan that could not run is no longer handed to the Snyk MCP tools: the
    MCP server is the same Snyk CLI that just failed, after already spending
    its network and auth retries. Instead the turn is allowed to end and the
    scan is re-armed for the next stop. Auth is the one exception worth a round
    trip: authenticating repairs the configstore every later scan reads, so it
    gets exactly one block per session -- handed to the user, not to an MCP
    tool.
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

    # An engine that reported nothing leaves a failed done-file behind, and
    # wait_for_scan short-circuits on one -- so drop it here or every later
    # stop replays this failure instead of retrying. No-op when both scanned.
    _rearm_unscanned(workspace, sast, sca)
    unscanned = bool(sast.unscanned_status or sca.unscanned_status)

    # Three outcomes, one handler each.
    if sast.new_vulns or sca.new_sca_vulns:
        _handle_new_vuln_stop(data, workspace, sast, sca, code_files, unscanned)
    elif not unscanned:
        _handle_clean_stop(workspace, sast, sca)
    else:
        _handle_unscanned_stop(data, workspace, sast, sca, code_files)


def _handle_new_vuln_stop(
    data: Dict[str, Any],
    workspace: str,
    sast: SastResult,
    sca: ScaResult,
    code_files: Dict[str, Dict[str, Any]],
    unscanned: bool,
) -> None:
    """Findings to fix. They outrank an unscanned engine, which is logged
    rather than spending the block."""
    with _mutate_state(workspace) as state:
        code = state.get("code_files", {})
        for fp in sast.clean_file_paths:
            code.pop(fp, None)
        state["code_files"] = code
        state["stop_cycles"] = state.get("stop_cycles", 0) + 1

    if not sast.unscanned_status and not sast.dirty_file_paths:
        clear_scan_state(workspace)

    _log_stop_block(sast, sca)
    if unscanned:
        log_to_panel(_unscanned_notice(sast, sca, code_files, workspace))
    output_block(_build_block_reason(sast.new_vulns, sca.new_sca_vulns, workspace), data)


def _handle_clean_stop(workspace: str, sast: SastResult, sca: ScaResult) -> None:
    """Everything scanned, nothing new."""
    _log_stop_allow(sast, sca)
    clear_state(workspace)
    # Explicitly do NOT clear the baseline. This means we always compare to
    # the status as of session start, and ignore any possibly improvements
    # to SCA vulns beyond it.
    output_response({})


def _handle_unscanned_stop(
    data: Dict[str, Any],
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
            output_block(reason, data)
            return

    log_to_panel(f"Stop: ALLOW (unscanned) - {_unscanned_notice(sast, sca, code_files, workspace)}")
    output_response({})


def _build_block_reason(
    new_vulns: List[Dict[str, Any]],
    new_sca_vulns: List[Dict[str, Any]],
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

    total_prevented = len(new_vulns) + len(new_sca_vulns)
    if total_prevented > 0:
        prevented_ids = _prevented_issue_ids(new_vulns, new_sca_vulns)
        prevented_ids_json = json.dumps(prevented_ids)
        prevented_by_severity_json = json.dumps(_severity_counts_dict(new_vulns + new_sca_vulns))
        reason_parts.append(
            f"\nAfter fixing all issues above, call snyk_send_feedback with "
            f"preventedIssuesCount={total_prevented}, "
            f"preventedIssueIds={prevented_ids_json}, "
            f"preventedIssuesBySeverity={prevented_by_severity_json}, "
            f"path={workspace}. "
            f"If your installed Snyk MCP rejects preventedIssueIds or "
            f"preventedIssuesBySeverity (older version), retry the call "
            f"without those arguments."
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

    # Resolve the persistent log path once, now that the workspace is known.
    global _LOG_FILE
    _LOG_FILE = resolve_log_file(workspace)

    handlers = {
        "sessionStart": handle_session_start,
        "SessionStart": handle_session_start,
        "postToolUse": handle_post_tool_use,
        "PostToolUse": handle_post_tool_use,
        "agentStop": handle_agent_stop,
        "Stop": handle_agent_stop,
    }

    handler = handlers.get(hook_event)
    if handler:
        handler(data, workspace)
    else:
        debug_log(f"Unknown hook event: {hook_event}")
        output_response({})


if __name__ == "__main__":
    main()
