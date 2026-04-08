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
STATE_DIR = os.environ.get("SNYK_HOOK_STATE_DIR", "/tmp").replace('..','') 

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

def safe_open_within_base(file_path: Path, base_dir: Path, mode: str = 'r'):
    """
    Safely open a file after validating it's within the base directory.
    
    Prevents path traversal attacks by ensuring the resolved path
    stays within the allowed base directory.
    
    Args:
        file_path: The path to the file to open
        base_dir: The base directory that file_path must be within
        mode: File open mode (default: 'r')
        
    Returns:
        File handle
        
    Raises:
        ValueError: If path would escape the base directory
    """
    # For write modes, we need to validate the parent directory exists
    # and that the path would be within base_dir
    resolved_base = base_dir.resolve()
    
    # If file doesn't exist yet (write mode), validate parent directory
    if not file_path.exists() and 'w' in mode:
        # Ensure parent directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)
        # Validate the intended path is within base_dir
        try:
            file_path.resolve().relative_to(resolved_base)
        except ValueError:
            raise ValueError(f"Path traversal detected: {file_path} resolves outside of {resolved_base}")
    else:
        # For existing files or read mode, resolve and validate
        resolved_path = file_path.resolve()
        try:
            resolved_path.relative_to(resolved_base)
        except ValueError:
            raise ValueError(f"Path traversal detected: {file_path} resolves outside of {resolved_base}")
    
    # Path is validated - safe to open
    return open(file_path, mode)  # noqa: SIM115

def get_workspace_hash(workspace: str) -> str:
    """Generate a unique hash for the workspace."""
    import hashlib
    # Security fix: Use SHA-256 instead of MD5 for better security
    return hashlib.sha256(workspace.encode()).hexdigest()[:8]


def get_state_file(workspace: str) -> Path:
    """Get path to state file for this workspace."""
    workspace_hash = get_workspace_hash(workspace)
    return Path(STATE_DIR) / f"snyk-bg-scanner-{workspace_hash}.json"


def open_debounce_file(workspace: str, mode:str ='r'):
    """Get path to debounce tracking file."""
    workspace_hash = get_workspace_hash(workspace)
    workspace_path = Path(STATE_DIR) / f"snyk-debounce-{workspace_hash}.json"
    return safe_open_within_base(workspace_path, Path(STATE_DIR), mode)


def get_debounce_file(workspace: str):
    """Get path to debounce tracking file."""
    workspace_hash = get_workspace_hash(workspace)
    return Path(STATE_DIR)/ f"snyk-debounce-{workspace_hash}.json"


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
                with open_debounce_file(self.workspace) as f:
                    return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            pass
        return {"pending_files": {}, "pending_packages": False, "last_update": None}
    
    def write_state(self, state: Dict[str, Any]) -> None:
        """Write debounce state."""
        state["last_update"] = datetime.now().isoformat()
        with open_debounce_file(self.workspace, 'w') as f:
            json.dump(state, f)
    
    def add_file(self, file_path: str) -> None:
        """Add a file to pending scan list."""
        # Normalize path to be relative to workspace for consistent cache keys
        file_path = self._normalize_path(file_path)
        state = self.read_state()
        state["pending_files"][file_path] = datetime.now().isoformat()
        self.write_state(state)
    
    def _normalize_path(self, file_path: str) -> str:
        """Normalize file path to be relative to workspace."""
        path = Path(file_path)
        workspace_path = Path(self.workspace)
        
        # Convert to absolute first
        if not path.is_absolute():
            path = workspace_path / path
        
        # Make relative to workspace
        try:
            return str(path.relative_to(workspace_path))
        except ValueError:
            # If outside workspace, use absolute
            return str(path.resolve())
    
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
    # Look for scan_worker.py in .git/hooks/lib/ where installer puts it
    git_hooks_lib = Path(workspace) / ".git" / "hooks" / "lib"
    worker_script = git_hooks_lib / "scan_worker.py"
    
    if not worker_script.exists():
        log_to_panel(f"[ERROR] Scan worker not found: {worker_script}")
        return
    
    # Normalize target path to be relative to workspace
    # This ensures cache keys match between background scans and commit-time checks
    if scan_type == "sast":
        target_path = Path(target)
        workspace_path = Path(workspace)
        
        # Convert to absolute first, then make relative to workspace
        if not target_path.is_absolute():
            target_path = workspace_path / target_path
        
        try:
            target = str(target_path.relative_to(workspace_path))
        except ValueError:
            # If target is outside workspace, use absolute path
            target = str(target_path.resolve())
    
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
    log_to_panel("=== KIRO BACKGROUND SCANNER STARTED ===")
    
    try:
        # Get workspace (current directory)
        workspace = os.getcwd()
        log_to_panel(f"Workspace: {workspace}")
        
        # Kiro hooks can receive file info via environment variables or args
        # Check common environment variables that Kiro might set
        file_path = None
        
        # Try to get file path from various sources
        if len(sys.argv) > 1:
            file_path = sys.argv[1]
            log_to_panel(f"File from args: {file_path}")
        elif 'KIRO_EDITED_FILE' in os.environ:
            file_path = os.environ['KIRO_EDITED_FILE']
            log_to_panel(f"File from KIRO_EDITED_FILE: {file_path}")
        elif 'KIRO_FILE_PATH' in os.environ:
            file_path = os.environ['KIRO_FILE_PATH']
            log_to_panel(f"File from KIRO_FILE_PATH: {file_path}")
        elif 'FILE_PATH' in os.environ:
            file_path = os.environ['FILE_PATH']
            log_to_panel(f"File from FILE_PATH: {file_path}")
        elif 'EDITED_FILE' in os.environ:
            file_path = os.environ['EDITED_FILE']
            log_to_panel(f"File from EDITED_FILE: {file_path}")
        
        # If no specific file, scan recently modified files
        if not file_path:
            log_to_panel("No specific file provided, scanning recently modified files")
            # Find recently modified code files (last 5 minutes)
            import time
            current_time = time.time()
            recent_files = []
            
            for ext in CODE_EXTENSIONS:
                for file in Path(workspace).rglob(f"*{ext}"):
                    if file.is_file() and (current_time - file.stat().st_mtime) < 300:  # 5 minutes
                        recent_files.append(str(file.relative_to(workspace)))
            
            if recent_files:
                file_path = recent_files[0]  # Scan the most recently modified
                log_to_panel(f"Found recent file: {file_path}")
        
        if not file_path:
            log_to_panel("No file to scan, exiting")
            return
        
        # Use debounce tracker for sophisticated handling
        tracker = DebounceTracker(workspace)
        
        # Normalize the current file path
        if is_code_file(file_path):
            normalized_path = tracker._normalize_path(file_path)
        else:
            normalized_path = file_path
        
        # FIRST: Check and launch any pending scans that have passed debounce
        # This must happen BEFORE we update timestamps for the current file
        launched = check_and_launch_pending_scans(workspace)
        if launched:
            log_to_panel(f"[SCAN] Launched {len(launched)} debounced scan(s)")
        
        # Check if the current file was just launched via debounce
        current_file_just_launched = any(normalized_path in item for item in launched)
        
        # THEN: Handle the current file edit
        if is_code_file(file_path):
            if current_file_just_launched:
                # File was just scanned via debounce, don't launch again
                log_to_panel(f"[SCAN] {Path(file_path).name} already scanned via debounce")
                # But add it back to tracker for next edit
                tracker.add_file(file_path)
            else:
                # Check if this file was already pending
                state = tracker.read_state()
                was_pending = normalized_path in state.get("pending_files", {})
                
                if was_pending:
                    # File was already queued, just update timestamp (debounce)
                    tracker.add_file(file_path)
                    log_to_panel(f"[DEBOUNCE] Scan delayed for: {Path(file_path).name}")
                else:
                    # First edit of this file - launch scan immediately
                    log_to_panel(f"[SCAN] Launching immediate scan for: {Path(file_path).name}")
                    launch_background_scan(workspace, "sast", normalized_path)
                    
                    # Also add to tracker for future debouncing
                    tracker.add_file(file_path)
                
        elif is_manifest_file(file_path):
            # Check if packages were already pending
            state = tracker.read_state()
            was_pending = state.get("pending_packages", False)
            
            if was_pending:
                # Already queued, just update timestamp
                tracker.add_packages()
                log_to_panel(f"[DEBOUNCE] SCA scan delayed")
            else:
                # First change - launch immediately
                log_to_panel(f"[SCAN] Launching immediate SCA scan")
                launch_background_scan(workspace, "sca", workspace)
                tracker.add_packages()
        else:
            # Not a scannable file
            log_to_panel(f"File not scannable: {file_path}")
            return
        
        log_to_panel("=== KIRO BACKGROUND SCANNER COMPLETED ===")
        
    except Exception as e:
        log_to_panel(f"ERROR: {e}")
        import traceback
        log_to_panel(f"Traceback: {traceback.format_exc()}")


if __name__ == "__main__":
    main()

