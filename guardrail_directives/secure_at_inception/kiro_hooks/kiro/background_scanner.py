#!/usr/bin/env python3
"""
Background Scanner - Kiro Hook
==============================

A Kiro agent hook that triggers background security scans when files are saved.
Uses debouncing to avoid scanning on every keystroke during rapid saves.

Hook Events:
- afterFileEdit: Queue SAST scan for code files, SCA scan for package.json

Debouncing:
- Waits 2 seconds after last file save before scanning
- Uses a state file to track pending scans

Notifications:
- Displays toast notification when vulnerabilities are found
- Uses Kiro's user_message for notifications

Usage:
    Configured via kiro/hooks.json to run on afterFileEdit
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# =============================================================================
# CONFIGURATION
# =============================================================================

# Debounce delay in seconds
DEBOUNCE_SECONDS = 2.0

# State file for tracking pending scans
STATE_DIR = os.environ.get("SNYK_HOOK_STATE_DIR", "/tmp")

# Scannable file extensions
CODE_EXTENSIONS = {
    '.ts', '.tsx', '.js', '.jsx',  # JavaScript/TypeScript
    '.py',                          # Python
    '.java', '.kt',                 # Java/Kotlin
    '.go',                          # Go
    '.rb',                          # Ruby
    '.php',                         # PHP
    '.cs',                          # C#
    '.swift',                       # Swift
    '.c', '.cpp', '.h', '.hpp',    # C/C++
}

# Package manifest files
MANIFEST_FILES = {
    'package.json',
    'package-lock.json',
    'yarn.lock',
    'pnpm-lock.yaml',
    'requirements.txt',
    'Pipfile',
    'pyproject.toml',
    'pom.xml',
    'build.gradle',
    'Gemfile',
    'composer.json',
}


# =============================================================================
# UTILITIES
# =============================================================================

def get_workspace_hash(workspace: str) -> str:
    """Generate a unique hash for the workspace."""
    import hashlib
    return hashlib.md5(workspace.encode()).hexdigest()[:8]


def get_state_file(workspace: str) -> Path:
    """Get path to state file for this workspace."""
    workspace_hash = get_workspace_hash(workspace)
    return Path(STATE_DIR) / f"snyk-bg-scanner-{workspace_hash}.json"


def get_debounce_file(workspace: str) -> Path:
    """Get path to debounce tracking file."""
    workspace_hash = get_workspace_hash(workspace)
    return Path(STATE_DIR) / f"snyk-debounce-{workspace_hash}.json"


def log_to_panel(message: str) -> None:
    """Print to Kiro Hooks output panel (stderr)."""
    print(message, file=sys.stderr)


def is_code_file(file_path: str) -> bool:
    """Check if file is a scannable code file."""
    return Path(file_path).suffix.lower() in CODE_EXTENSIONS


def is_manifest_file(file_path: str) -> bool:
    """Check if file is a package manifest."""
    return Path(file_path).name in MANIFEST_FILES


def get_workspace(data: Dict[str, Any]) -> str:
    """Extract workspace path from hook input."""
    workspace_roots = data.get("workspace_roots", [])
    if workspace_roots:
        return workspace_roots[0]
    
    # Fallback
    file_path = data.get("file_path", "")
    if file_path:
        path = Path(file_path)
        for parent in path.parents:
            if (parent / ".git").exists():
                return str(parent)
    
    return os.getcwd()


def output_response(response: Dict[str, Any]) -> None:
    """Output JSON response to stdout."""
    print(json.dumps(response))


# =============================================================================
# DEBOUNCE LOGIC
# =============================================================================

class DebounceTracker:
    """
    Tracks files that need scanning and implements debouncing.
    
    When a file is saved:
    1. Record the file and timestamp
    2. Schedule a scan after DEBOUNCE_SECONDS
    3. If another save comes in, reset the timer
    """
    
    def __init__(self, workspace: str):
        self.workspace = workspace
        self.state_file = get_debounce_file(workspace)
    
    def read_state(self) -> Dict[str, Any]:
        """Read current debounce state."""
        try:
            if self.state_file.exists():
                with open(self.state_file, 'r') as f:
                    return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            pass
        return {"pending_files": {}, "pending_packages": False, "last_update": None}
    
    def write_state(self, state: Dict[str, Any]) -> None:
        """Write debounce state."""
        state["last_update"] = datetime.now().isoformat()
        with open(self.state_file, 'w') as f:
            json.dump(state, f)
    
    def add_file(self, file_path: str) -> None:
        """Add a file to pending scan list."""
        state = self.read_state()
        state["pending_files"][file_path] = datetime.now().isoformat()
        self.write_state(state)
    
    def add_packages(self) -> None:
        """Mark packages as needing scan."""
        state = self.read_state()
        state["pending_packages"] = True
        state["package_trigger_time"] = datetime.now().isoformat()
        self.write_state(state)
    
    def get_files_to_scan(self) -> List[str]:
        """
        Get files that should be scanned (debounce expired).
        
        Returns files where DEBOUNCE_SECONDS have passed since last save.
        """
        state = self.read_state()
        now = datetime.now()
        ready = []
        still_pending = {}
        
        for file_path, timestamp_str in state.get("pending_files", {}).items():
            timestamp = datetime.fromisoformat(timestamp_str)
            if (now - timestamp).total_seconds() >= DEBOUNCE_SECONDS:
                ready.append(file_path)
            else:
                still_pending[file_path] = timestamp_str
        
        # Update state to remove files we're scanning
        state["pending_files"] = still_pending
        self.write_state(state)
        
        return ready
    
    def should_scan_packages(self) -> bool:
        """Check if package scan should run (debounce expired)."""
        state = self.read_state()
        if not state.get("pending_packages"):
            return False
        
        trigger_time = state.get("package_trigger_time")
        if not trigger_time:
            return False
        
        trigger = datetime.fromisoformat(trigger_time)
        now = datetime.now()
        
        if (now - trigger).total_seconds() >= DEBOUNCE_SECONDS:
            # Clear the pending flag
            state["pending_packages"] = False
            state["package_trigger_time"] = None
            self.write_state(state)
            return True
        
        return False
    
    def clear(self) -> None:
        """Clear all pending scans."""
        self.state_file.unlink(missing_ok=True)


# =============================================================================
# BACKGROUND SCAN LAUNCHER
# =============================================================================

def launch_background_scan(workspace: str, scan_type: str, target: str) -> None:
    """
    Launch a background scan worker.
    
    The worker runs detached from this process and writes results to cache.
    """
    script_dir = Path(__file__).parent.parent / "git" / "lib"
    worker_script = script_dir / "scan_worker.py"
    
    if not worker_script.exists():
        log_to_panel(f"[ERROR] Scan worker not found: {worker_script}")
        return
    
    # Launch detached subprocess
    cmd = [
        sys.executable,
        str(worker_script),
        "--type", scan_type,
        "--target", target,
        "--workspace", workspace
    ]
    
    try:
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,  # Detach from parent
            cwd=workspace
        )
        log_to_panel(f"[SCAN] Queued {scan_type} scan for: {target}")
    except Exception as e:
        log_to_panel(f"[ERROR] Failed to launch scan: {e}")


def check_and_launch_pending_scans(workspace: str) -> List[str]:
    """
    Check for pending scans that have passed debounce and launch them.
    
    Returns list of files/packages being scanned.
    """
    tracker = DebounceTracker(workspace)
    launched = []
    
    # Check for files ready to scan
    files_to_scan = tracker.get_files_to_scan()
    for file_path in files_to_scan:
        launch_background_scan(workspace, "sast", file_path)
        launched.append(f"sast:{file_path}")
    
    # Check for packages ready to scan
    if tracker.should_scan_packages():
        launch_background_scan(workspace, "sca", workspace)
        launched.append("sca:packages")
    
    return launched


# =============================================================================
# HOOK HANDLERS
# =============================================================================

def handle_after_file_edit(data: Dict[str, Any], workspace: str) -> Dict[str, Any]:
    """
    Handle afterFileEdit hook event.
    
    1. Check if file is scannable
    2. Add to debounce queue
    3. Launch any pending scans that have passed debounce
    """
    file_path = data.get("file_path", "")
    tracker = DebounceTracker(workspace)
    
    # Determine what kind of file was edited
    if is_code_file(file_path):
        # Add to pending SAST scans
        tracker.add_file(file_path)
        log_to_panel(f"[QUEUE] Code file queued for scan: {Path(file_path).name}")
    
    elif is_manifest_file(file_path):
        # Trigger SCA scan
        tracker.add_packages()
        log_to_panel(f"[QUEUE] Package manifest changed, SCA scan queued")
    
    else:
        # Not a scannable file
        return {"exit_code": 0}
    
    # Check and launch any scans that have passed debounce
    launched = check_and_launch_pending_scans(workspace)
    
    if launched:
        log_to_panel(f"[SCAN] Launched {len(launched)} background scan(s)")
    
    return {"exit_code": 0}


def handle_scan_complete(data: Dict[str, Any], workspace: str) -> Dict[str, Any]:
    """
    Handle notification when a background scan completes.
    
    Called by the scan worker via a follow-up hook invocation.
    """
    scan_type = data.get("scan_type", "")
    target = data.get("target", "")
    vuln_count = data.get("vuln_count", 0)
    high_count = data.get("high_count", 0)
    critical_count = data.get("critical_count", 0)
    
    if vuln_count == 0:
        log_to_panel(f"[✓] {scan_type.upper()} scan complete: {target} - No vulnerabilities")
        return {"exit_code": 0}
    
    # Build notification message
    severity_parts = []
    if critical_count > 0:
        severity_parts.append(f"{critical_count} critical")
    if high_count > 0:
        severity_parts.append(f"{high_count} high")
    
    severity_str = ", ".join(severity_parts) if severity_parts else f"{vuln_count} issues"
    
    target_name = Path(target).name if scan_type == "sast" else "dependencies"
    
    log_to_panel("=" * 50)
    log_to_panel(f"⚠️  SECURITY SCAN FOUND ISSUES")
    log_to_panel("=" * 50)
    log_to_panel(f"  Target: {target_name}")
    log_to_panel(f"  Found: {severity_str}")
    log_to_panel("")
    log_to_panel("  These will be flagged on commit.")
    log_to_panel("=" * 50)
    
    # Show notification to user (toast)
    user_message = f"🔒 Security scan: {severity_str} found in {target_name}"
    
    return {
        "exit_code": 0,
        "user_message": user_message
    }


# =============================================================================
# MAIN
# =============================================================================

def main() -> None:
    """Main entry point for the hook."""
    # Read JSON input from stdin
    try:
        input_data = sys.stdin.read()
        data = json.loads(input_data) if input_data.strip() else {}
    except json.JSONDecodeError as e:
        log_to_panel(f"[ERROR] Failed to parse hook input: {e}")
        output_response({"exit_code": 1})
        sys.exit(1)
    
    # Get hook event and workspace
    hook_event = data.get("hook_event_name", "")
    workspace = get_workspace(data)
    
    # Dispatch to handler
    if hook_event == "afterFileEdit":
        response = handle_after_file_edit(data, workspace)
    elif hook_event == "scanComplete":
        # Custom event from scan worker
        response = handle_scan_complete(data, workspace)
    else:
        response = {"exit_code": 0}
    
    output_response(response)


if __name__ == "__main__":
    main()

