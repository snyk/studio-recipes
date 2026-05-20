#!/usr/bin/env python3
"""
Cursor Hook: Enforce Security Scan on New Packages
===================================================

This hook enforces security scanning of package.json changes before allowing
dependency installations. It implements a "scan-before-install" security gate.

WORKFLOW:
---------
1. AI edits package.json → afterFileEdit records the change
2. AI attempts npm/yarn/pnpm install → beforeShellExecution BLOCKS it
3. AI runs snyk_package_health_check → beforeMCPExecution clears the block
4. AI can now run install commands

SUPPORTED HOOK EVENTS:
----------------------
- afterFileEdit: Records package.json modifications to state file
- beforeShellExecution: Blocks install commands until scan is complete
- beforeMCPExecution: Clears block when security scan is initiated
- stop: Final reminder if session ends without scanning

INSTALLATION:
-------------
1. Place this script in .cursor/hooks/ directory
2. Make executable: chmod +x enforce_security_scan_on_new_packages.py
3. Configure hooks.json (see example below)

HOOKS.JSON EXAMPLE:
-------------------
{
  "version": 1,
  "hooks": {
    "afterFileEdit": [
      {"command": "python3 hooks/enforce_security_scan_on_new_packages.py"}
    ],
    "beforeShellExecution": [
      {"command": "python3 hooks/enforce_security_scan_on_new_packages.py"}
    ],
    "beforeMCPExecution": [
      {"command": "python3 hooks/enforce_security_scan_on_new_packages.py"}
    ],
    "stop": [
      {"command": "python3 hooks/enforce_security_scan_on_new_packages.py"}
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
- Works with npm, yarn, pnpm
"""

import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

# =============================================================================
# CONFIGURATION
# =============================================================================

# State file location - uses workspace-specific hash to avoid collisions
STATE_DIR = os.environ.get("CURSOR_HOOK_STATE_DIR", "/tmp")
DEBUG = os.environ.get("CURSOR_HOOK_DEBUG", "0") == "1"

# Manifest files that trigger security scanning requirements
MONITORED_MANIFESTS = [
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
]

# Commands that should be blocked until scan is complete
INSTALL_COMMANDS = [
    "npm install",
    "npm i ",
    "npm i\n",
    "npm ci",
    "yarn install",
    "yarn add",
    "yarn\n",
    "pnpm install",
    "pnpm add",
    "pnpm i ",
]

# MCP tool that satisfy the security scan requirement
SCAN_TOOL = "snyk_package_health_check"


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
    workspace_hash = hashlib.md5(workspace.encode()).hexdigest()[:8]
    return os.path.join(STATE_DIR, f"cursor-pkg-scan-{workspace_hash}.state")


def get_workspace(data: Dict[str, Any]) -> str:
    """Extract workspace path from hook input data."""
    workspace_roots = data.get("workspace_roots", [])
    if workspace_roots:
        return workspace_roots[0]

    # Fallback: try to determine from file_path
    file_path = data.get("file_path", "")
    if file_path:
        # Walk up to find .cursor directory or use parent of package.json
        path = Path(file_path)
        for parent in path.parents:
            if (parent / ".cursor").exists():
                return str(parent)
            if (parent / "package.json").exists():
                return str(parent)

    # Last resort: current working directory
    return os.getcwd()


def is_manifest_file(file_path: str) -> bool:
    """Check if the file is a package manifest file (package.json, lockfiles, etc.)."""
    return any(manifest in file_path for manifest in MONITORED_MANIFESTS)


def is_install_command(command: str) -> bool:
    """Check if the command is a package installation command."""
    cmd_lower = command.lower()
    return any(install_cmd in cmd_lower for install_cmd in INSTALL_COMMANDS)


def is_scan_tool(tool_name: str) -> bool:
    """Check if the MCP tool is a security scan tool."""
    return SCAN_TOOL in tool_name.lower()


def state_file_exists(workspace: str) -> bool:
    """Check if the state file exists for this workspace."""
    return os.path.exists(get_state_file_path(workspace))


def read_state_file(workspace: str) -> str:
    """Read and return contents of the state file."""
    state_file = get_state_file_path(workspace)
    if os.path.exists(state_file):
        with open(state_file) as f:
            return f.read().strip()
    return ""


def write_state_file(workspace: str, content: str) -> None:
    """Append content to the state file."""
    state_file = get_state_file_path(workspace)
    with open(state_file, "a") as f:
        f.write(content + "\n")
    debug_log(f"Wrote to state file: {state_file}")


def clear_state_file(workspace: str) -> None:
    """Remove the state file."""
    state_file = get_state_file_path(workspace)
    if os.path.exists(state_file):
        os.remove(state_file)
        debug_log(f"Cleared state file: {state_file}")


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

    Records when monitored manifest files are modified, creating a state
    that will block subsequent install commands until a scan is performed.

    Note: afterFileEdit is "fire-and-forget" - it cannot send messages
    back to the agent or block the edit.
    """
    file_path = data.get("file_path", "")

    if is_manifest_file(file_path):
        # Record the modification
        timestamp = datetime.now().isoformat()
        write_state_file(workspace, f"{timestamp}: {file_path}")

        # Log to Hooks output panel
        log_to_panel("=" * 60)
        log_to_panel("DEPENDENCY MANIFEST MODIFIED")
        log_to_panel("=" * 60)
        log_to_panel(f"File: {file_path}")
        log_to_panel(f"Time: {timestamp}")
        log_to_panel("")
        log_to_panel("Install commands will be blocked until security scan.")
        log_to_panel("Run snyk_package_health_check before npm/yarn/pnpm install.")
        log_to_panel("=" * 60)

    # Always return success (afterFileEdit cannot block)
    output_response({"exit_code": 0})


def handle_before_shell_execution(data: Dict[str, Any], workspace: str) -> None:
    """
    Handler for beforeShellExecution hook event.

    Blocks package installation commands if manifest files were modified
    without a subsequent security scan. This enforces the security gate.

    Uses:
    - permission: "deny" to indicate the command should be blocked
    - agent_message: to inform the AI agent why the command was blocked
    - user_message: to show the user a notification
    - exit code 2: to signal blocking to Cursor
    """
    command = data.get("command", "")

    # Only check install commands
    if not is_install_command(command):
        debug_log(f"Command '{command[:50]}...' is not an install command, allowing")
        output_response({"exit_code": 0})
        return

    # Check if there are pending scans
    if not state_file_exists(workspace):
        debug_log("No pending scans, allowing install command")
        output_response({"exit_code": 0})
        return

    # BLOCK the install command
    changes = read_state_file(workspace)

    log_to_panel("=" * 60)
    log_to_panel("INSTALL COMMAND BLOCKED")
    log_to_panel("=" * 60)
    log_to_panel("")
    log_to_panel("Dependency manifests were modified without security scan:")
    log_to_panel(changes)
    log_to_panel("")
    log_to_panel(f"Blocked command: {command}")
    log_to_panel("")
    log_to_panel("RESOLUTION:")
    log_to_panel(f"  1. Run: snyk_package_health_check on {workspace}")
    log_to_panel("  2. Review and address any vulnerabilities")
    log_to_panel("  3. Retry the install command")
    log_to_panel("=" * 60)

    # Return blocking response with messages for agent and user
    response = {
        "permission": "deny",
        "user_message": (
            f"Install blocked: Security scan required. "
            f"Run snyk_package_health_check on {workspace} first."
        ),
        "agent_message": (
            f"INSTALL BLOCKED: Dependency manifests were modified but not scanned. "
            f"You MUST run snyk_package_health_check on {workspace} before running install commands. "
            f"Modified files: {changes}"
        ),
    }
    output_response(response)

    # Exit with code 2 to block the action
    sys.exit(2)


def handle_before_mcp_execution(data: Dict[str, Any], workspace: str) -> None:
    """
    Handler for beforeMCPExecution hook event.

    Clears the security gate when a scan tool is invoked, allowing
    subsequent install commands to proceed.

    Also provides warnings if non-scan MCP tools are called while
    manifest changes are pending.
    """
    tool_name = data.get("tool_name", "unknown")

    # If calling a scan tool, clear the pending state
    if is_scan_tool(tool_name):
        if state_file_exists(workspace):
            changes = read_state_file(workspace)
            clear_state_file(workspace)

            log_to_panel("=" * 60)
            log_to_panel("SECURITY SCAN INITIATED")
            log_to_panel("=" * 60)
            log_to_panel(f"Tool: {tool_name}")
            log_to_panel(f"Scanned changes: {changes}")
            log_to_panel("")
            log_to_panel("Install commands are now allowed.")
            log_to_panel("=" * 60)

    output_response({"exit_code": 0})


def handle_stop(data: Dict[str, Any], workspace: str) -> None:
    """
    Handler for stop hook event.

    Provides a final reminder if the session ends with unscanned
    manifest changes. Uses followup_message which is more reliable
    than agent_message in Cursor.
    """
    if not state_file_exists(workspace):
        output_response({})
        return

    changes = read_state_file(workspace)
    clear_state_file(workspace)

    log_to_panel("=" * 60)
    log_to_panel("SESSION ENDED WITH UNSCANNED CHANGES")
    log_to_panel("=" * 60)
    log_to_panel("")
    log_to_panel("The following manifest changes were not scanned:")
    log_to_panel(changes)
    log_to_panel("")
    log_to_panel(f"Please run: snyk_package_health_check on {workspace}")
    log_to_panel("=" * 60)

    # Use followup_message which works reliably in the stop hook
    response = {
        "followup_message": (
            f"SECURITY ALERT: Dependency manifests were modified but not scanned "
            f"during this session. Please run snyk_package_health_check on {workspace} to check "
            f"for vulnerabilities before deploying."
        ),
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
        log_to_panel(f"Error parsing hook input: {e}")
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
        "beforeShellExecution": handle_before_shell_execution,
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
