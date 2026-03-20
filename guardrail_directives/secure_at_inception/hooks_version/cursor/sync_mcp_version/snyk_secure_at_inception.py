#!/usr/bin/env python3
"""
Cursor Hook: Snyk Secure At Inception
======================================

This hook tracks file modifications during an agent session and conditionally
prompts for Snyk security scans (SAST and/or SCA) only when relevant files
were actually changed. It will NOT prompt for scans during planning, question,
or read-only sessions where no code was modified.

WORKFLOW:
---------
1. AI edits a code file (.py, .ts, etc.)  -> afterFileEdit records it as needing SAST
2. AI edits a manifest file (package.json) -> afterFileEdit records it as needing SCA
3. AI runs snyk_code_scan               -> beforeMCPExecution clears code file state
4. AI runs snyk_sca_scan                -> beforeMCPExecution clears manifest file state
5. Agent stops                          -> stop prompts for any remaining unscanned changes

SUPPORTED HOOK EVENTS:
----------------------
- afterFileEdit:       Records code/manifest file modifications to state file
- beforeMCPExecution:  Clears relevant state when a Snyk scan tool is invoked
- stop:                Prompts for scans via followup_message if unscanned changes exist

INSTALLATION:
-------------
1. Place this script in .cursor/hooks/ directory
2. Make executable: chmod +x snyk_secure_at_inception.py
3. Configure hooks.json (see example below)

HOOKS.JSON EXAMPLE:
-------------------
{
  "version": 1,
  "hooks": {
    "afterFileEdit": [
      {"command": "python3 \"$HOME/.cursor/hooks/snyk_secure_at_inception.py\""}
    ],
    "beforeMCPExecution": [
      {"command": "python3 \"$HOME/.cursor/hooks/snyk_secure_at_inception.py\""}
    ],
    "stop": [
      {"command": "python3 \"$HOME/.cursor/hooks/snyk_secure_at_inception.py\""}
    ]
  }
}

CONFIGURATION:
--------------
Environment variables (optional):
- CURSOR_HOOK_STATE_DIR: Directory for state files (default: /tmp)
- CURSOR_HOOK_DEBUG: Set to "1" for verbose logging

COMPATIBILITY:
--------------
- Cursor IDE 2.2.x+
- Python 3.8+
"""

import sys
import json
import os
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List


# =============================================================================
# CONFIGURATION
# =============================================================================

# State file location - uses workspace-specific hash to avoid collisions
STATE_DIR = os.environ.get("CURSOR_HOOK_STATE_DIR", "/tmp")
DEBUG = os.environ.get("CURSOR_HOOK_DEBUG", "0") == "1"

# SAST-scannable code file extensions (Snyk Code supported languages)
CODE_EXTENSIONS = {
    '.js', '.jsx', '.mjs', '.cjs',       # JavaScript
    '.ts', '.tsx',                         # TypeScript
    '.py',                                 # Python
    '.java',                               # Java
    '.kt', '.kts',                         # Kotlin
    '.go',                                 # Go
    '.rb',                                 # Ruby
    '.php',                                # PHP
    '.cs',                                 # C#
    '.vb',                                 # VB.NET
    '.swift',                              # Swift
    '.m', '.mm',                           # Objective-C
    '.scala',                              # Scala
    '.rs',                                 # Rust
    '.c', '.cpp', '.cc', '.h', '.hpp',    # C/C++
    '.cls', '.trigger',                    # Apex
    '.ex', '.exs',                         # Elixir
    '.groovy',                             # Groovy
    '.dart',                               # Dart
}

# SCA manifest and lock files (Snyk Open Source supported ecosystems)
MANIFEST_FILES = {
    'package.json', 'package-lock.json', 'npm-shrinkwrap.json',  # npm
    'yarn.lock',                                                   # Yarn
    'pnpm-lock.yaml',                                              # pnpm
    'requirements.txt', 'setup.py', 'pyproject.toml',             # pip/Poetry
    'Pipfile', 'Pipfile.lock', 'poetry.lock',                     # Pipenv/Poetry
    'pom.xml',                                                     # Maven
    'build.gradle', 'build.gradle.kts', 'gradle.lockfile',        # Gradle
    'Gemfile', 'Gemfile.lock',                                     # RubyGems
    'go.mod', 'go.sum',                                            # Go modules
    'Cargo.toml', 'Cargo.lock',                                   # Cargo/Rust
    'packages.config', 'packages.lock.json',                       # NuGet
    'composer.json', 'composer.lock',                              # Composer/PHP
    'Podfile', 'Podfile.lock',                                    # CocoaPods
    'Package.swift', 'Package.resolved',                           # Swift PM
    'mix.exs', 'mix.lock',                                        # Hex/Elixir
    'pubspec.yaml', 'pubspec.lock',                                # Pub/Dart
}

# File suffixes that indicate SCA manifest files (for patterns like *.csproj)
MANIFEST_SUFFIXES = {
    '.csproj',   # NuGet / .NET
}

# MCP tool names for clearing state
CODE_SCAN_TOOL = "snyk_code_scan"
SCA_SCAN_TOOL = "snyk_sca_scan"


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def debug_log(message: str) -> None:
    """Print debug message to stderr if DEBUG is enabled."""
    if DEBUG:
        print(f"[DEBUG] {message}", file=sys.stderr)


def get_state_file_path(workspace: str) -> str:
    """
    Generate a unique state file path for the workspace.
    Uses a hash of the workspace path to avoid collisions between projects.
    """
    workspace_hash = hashlib.sha256(workspace.encode()).hexdigest()[:8]
    return os.path.join(STATE_DIR, f"cursor-sai-{workspace_hash}.json")


def get_workspace(data: Dict[str, Any]) -> str:
    """Extract workspace path from hook input data."""
    workspace_roots = data.get("workspace_roots", [])
    if workspace_roots:
        return workspace_roots[0]

    # Fallback: try to determine from file_path
    file_path = data.get("file_path", "")
    if file_path:
        path = Path(file_path)
        for parent in path.parents:
            if (parent / ".cursor").exists():
                return str(parent)
            if (parent / ".git").exists():
                return str(parent)

    # Last resort: current working directory
    return os.getcwd()


def is_code_file(file_path: str) -> bool:
    """Check if the file is a SAST-scannable code file based on its extension."""
    return Path(file_path).suffix.lower() in CODE_EXTENSIONS


def is_manifest_file(file_path: str) -> bool:
    """Check if the file is an SCA-scannable manifest or lock file."""
    file_name = Path(file_path).name
    if file_name in MANIFEST_FILES:
        return True
    # Check suffix-based patterns (e.g. *.csproj)
    suffix = Path(file_path).suffix.lower()
    return suffix in MANIFEST_SUFFIXES


def read_state(workspace: str) -> Dict[str, Any]:
    """Read and return the current state from the state file."""
    state_file = get_state_file_path(workspace)
    try:
        if os.path.exists(state_file):
            with open(state_file, "r") as f:
                return json.load(f)
    except (json.JSONDecodeError, IOError):
        pass
    return {"code_files": [], "manifest_files": [], "last_update": None}


def write_state(workspace: str, state: Dict[str, Any]) -> None:
    """Write the state to the state file."""
    state_file = get_state_file_path(workspace)
    state["last_update"] = datetime.now().isoformat()
    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)
    debug_log(f"Wrote state file: {state_file}")


def clear_state(workspace: str) -> None:
    """Remove the state file entirely."""
    state_file = get_state_file_path(workspace)
    if os.path.exists(state_file):
        os.remove(state_file)
        debug_log(f"Cleared state file: {state_file}")


def has_pending_changes(state: Dict[str, Any]) -> bool:
    """Check if the state has any pending file changes to scan."""
    return bool(state.get("code_files")) or bool(state.get("manifest_files"))


def output_response(response: Dict[str, Any]) -> None:
    """Output JSON response to stdout."""
    print(json.dumps(response))


def log_to_panel(message: str) -> None:
    """Print message to stderr (visible in Cursor Hooks output panel)."""
    print(message, file=sys.stderr)


# =============================================================================
# HOOK HANDLERS
# =============================================================================

def handle_after_file_edit(data: Dict[str, Any], workspace: str) -> None:
    """
    Handler for afterFileEdit hook event.

    Records when code files or manifest files are modified. Tracks them
    separately so the stop hook can prompt for the appropriate scan type.

    Note: afterFileEdit is "fire-and-forget" - it cannot send messages
    back to the agent or block the edit.
    """
    file_path = data.get("file_path", "")

    if is_code_file(file_path):
        state = read_state(workspace)
        # Use a set-like behavior: avoid duplicates
        if file_path not in state["code_files"]:
            state["code_files"].append(file_path)
            write_state(workspace, state)

        log_to_panel(f"[SAI] Code file tracked: {Path(file_path).name}")

    elif is_manifest_file(file_path):
        state = read_state(workspace)
        if file_path not in state["manifest_files"]:
            state["manifest_files"].append(file_path)
            write_state(workspace, state)

        log_to_panel(f"[SAI] Manifest file tracked: {Path(file_path).name}")

    else:
        debug_log(f"File not scannable, ignoring: {file_path}")

    # Always return success (afterFileEdit cannot block)
    output_response({"exit_code": 0})


def handle_before_mcp_execution(data: Dict[str, Any], workspace: str) -> None:
    """
    Handler for beforeMCPExecution hook event.

    Clears the relevant portion of state when a Snyk scan tool is invoked:
    - snyk_code_scan  -> clears code_files
    - snyk_sca_scan   -> clears manifest_files

    This ensures the stop hook won't re-prompt for scans that have
    already been run, and naturally prevents infinite loops.
    """
    tool_name = data.get("tool_name", "")

    if CODE_SCAN_TOOL in tool_name.lower():
        state = read_state(workspace)
        if state.get("code_files"):
            cleared_files = state["code_files"]
            state["code_files"] = []

            # If no manifest files remain either, remove the file entirely
            if not state.get("manifest_files"):
                clear_state(workspace)
            else:
                write_state(workspace, state)

            log_to_panel("=" * 60)
            log_to_panel("[SAI] SAST SCAN INITIATED - CODE FILES CLEARED")
            log_to_panel("=" * 60)
            log_to_panel(f"Tool: {tool_name}")
            log_to_panel(f"Cleared {len(cleared_files)} tracked code file(s):")
            for f in cleared_files:
                log_to_panel(f"  - {f}")
            log_to_panel("=" * 60)

    elif SCA_SCAN_TOOL in tool_name.lower():
        state = read_state(workspace)
        if state.get("manifest_files"):
            cleared_files = state["manifest_files"]
            state["manifest_files"] = []

            # If no code files remain either, remove the file entirely
            if not state.get("code_files"):
                clear_state(workspace)
            else:
                write_state(workspace, state)

            log_to_panel("=" * 60)
            log_to_panel("[SAI] SCA SCAN INITIATED - MANIFEST FILES CLEARED")
            log_to_panel("=" * 60)
            log_to_panel(f"Tool: {tool_name}")
            log_to_panel(f"Cleared {len(cleared_files)} tracked manifest file(s):")
            for f in cleared_files:
                log_to_panel(f"  - {f}")
            log_to_panel("=" * 60)

    output_response({"exit_code": 0})


def handle_stop(data: Dict[str, Any], workspace: str) -> None:
    """
    Handler for stop hook event.

    Checks if any code or manifest files were modified but not yet scanned.
    If so, sends a followup_message prompting the agent to run the
    appropriate Snyk scan(s). If no files are pending, exits cleanly
    (no scan prompt for planning/question-only sessions).
    """
    state = read_state(workspace)

    if not has_pending_changes(state):
        debug_log("No pending changes, no scan needed")
        output_response({})
        return

    code_files = state.get("code_files", [])
    manifest_files = state.get("manifest_files", [])

    # Build the followup message based on what needs scanning
    message_parts: List[str] = []

    if code_files:
        file_list = ", ".join(Path(f).name for f in code_files)
        message_parts.append(
            f"Run snyk_code_scan on the current directory to check for "
            f"security vulnerabilities in the modified code files: {file_list}."
        )

    if manifest_files:
        file_list = ", ".join(Path(f).name for f in manifest_files)
        message_parts.append(
            f"Run snyk_sca_scan on the current directory to check for "
            f"vulnerable dependencies. Modified manifest files: {file_list}."
        )

    followup_message = " ".join(message_parts)

    # Log to panel
    log_to_panel("=" * 60)
    log_to_panel("[SAI] UNSCANNED CHANGES DETECTED")
    log_to_panel("=" * 60)
    if code_files:
        log_to_panel(f"  Code files ({len(code_files)}):")
        for f in code_files:
            log_to_panel(f"    - {f}")
    if manifest_files:
        log_to_panel(f"  Manifest files ({len(manifest_files)}):")
        for f in manifest_files:
            log_to_panel(f"    - {f}")
    log_to_panel("")
    log_to_panel("Prompting agent to run security scan(s).")
    log_to_panel("=" * 60)

    response = {
        "followup_message": followup_message,
    }
    output_response(response)


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main() -> None:
    """
    Main entry point for the hook script.

    Reads JSON input from stdin, determines the hook event type,
    and dispatches to the appropriate handler.
    """
    # Read and parse JSON input from stdin
    try:
        input_data = sys.stdin.read()
        data = json.loads(input_data) if input_data.strip() else {}
        debug_log(f"Received hook data: {json.dumps(data, indent=2)[:500]}...")
    except json.JSONDecodeError as e:
        log_to_panel(f"[SAI] Error parsing hook input: {e}")
        output_response({"exit_code": 1})
        sys.exit(1)

    # Extract hook event and workspace
    hook_event = data.get("hook_event_name", "")
    workspace = get_workspace(data)

    debug_log(f"Hook event: {hook_event}")
    debug_log(f"Workspace: {workspace}")

    # Dispatch to appropriate handler
    handlers = {
        "afterFileEdit": handle_after_file_edit,
        "beforeMCPExecution": handle_before_mcp_execution,
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
