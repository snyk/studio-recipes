#!/usr/bin/env python3
"""
Scan Worker - Background Security Scanner
==========================================

A detached worker process that runs Snyk scans and caches results.
Launched by the Kiro background_scanner hook.

Features:
- Runs independently of parent process
- Caches results for fast pre-commit lookups
- Sends notifications via Kiro hook callback

Usage:
    python scan_worker.py --type sast --target server.ts --workspace /path/to/project
    python scan_worker.py --type sca --target /path/to/project --workspace /path/to/project
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add lib directory to path
SCRIPT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SCRIPT_DIR))

from cache import SnykCache, get_cache_dir
from run_snyk_scan import (
    run_sast_scan,
    run_sca_scan,
    SastScanResult,
    ScaScanResult
)


# =============================================================================
# CONFIGURATION
# =============================================================================

# Log file for debugging
LOG_DIR = os.environ.get("SNYK_HOOK_LOG_DIR", "/tmp")


# =============================================================================
# PATH VALIDATION
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
    resolved_path = file_path.resolve()
    resolved_base = base_dir.resolve()
    
    try:
        resolved_path.relative_to(resolved_base)
    except ValueError:
        raise ValueError(f"Path traversal detected: {file_path} resolves outside of {resolved_base}")
    
    # Path is validated via relative_to() check above - safe to open
    # deepcode ignore PT: path traversal prevented by relative_to() validation above
    return open(resolved_path, mode)  # noqa: SIM115


# =============================================================================
# LOGGING
# =============================================================================

def get_log_file() -> Path:
    """Get path to log file."""
    return Path(LOG_DIR) / "snyk-scan-worker.log"


def log(message: str) -> None:
    """Write to log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] {message}\n"
    
    try:
        with open(get_log_file(), 'a') as f:
            f.write(log_line)
    except Exception:
        pass  # Best effort logging


# =============================================================================
# NOTIFICATION
# =============================================================================

def send_notification(
    workspace: str,
    scan_type: str,
    target: str,
    vuln_count: int,
    high_count: int = 0,
    critical_count: int = 0
) -> None:
    """
    Send notification about scan completion.
    
    Uses osascript on macOS to show a notification since we can't
    directly call back into Kiro from a detached process.
    """
    if vuln_count == 0:
        return  # No need to notify for clean scans
    
    # Build notification message
    target_name = Path(target).name if scan_type == "sast" else "dependencies"
    
    severity_parts = []
    if critical_count > 0:
        severity_parts.append(f"{critical_count} critical")
    if high_count > 0:
        severity_parts.append(f"{high_count} high")
    
    severity_str = ", ".join(severity_parts) if severity_parts else f"{vuln_count} issues"
    
    title = "🔒 Snyk Security Scan"
    message = f"{severity_str} found in {target_name}"
    
    # Try to show system notification (macOS)
    try:
        subprocess.run(
            [
                "osascript", "-e",
                f'display notification "{message}" with title "{title}"'
            ],
            capture_output=True,
            timeout=5
        )
        log(f"Notification sent: {message}")
    except Exception as e:
        log(f"Could not send notification: {e}")
    
    # Also write to a notification file that Kiro can poll
    notify_file = Path(get_cache_dir(workspace)) / "notifications.json"
    try:
        notifications = []
        if notify_file.exists():
            with open(notify_file, 'r') as f:
                notifications = json.load(f)
        
        notifications.append({
            "timestamp": datetime.now().isoformat(),
            "scan_type": scan_type,
            "target": target,
            "vuln_count": vuln_count,
            "high_count": high_count,
            "critical_count": critical_count,
            "message": message,
            "read": False
        })
        
        # Keep only last 10 notifications
        notifications = notifications[-10:]
        
        notify_file.parent.mkdir(parents=True, exist_ok=True)
        with open(notify_file, 'w') as f:
            json.dump(notifications, f, indent=2)
            
    except Exception as e:
        log(f"Could not write notification file: {e}")


# =============================================================================
# SAST SCANNING
# =============================================================================

def scan_sast(file_path: str, workspace: str) -> Dict[str, Any]:
    """
    Run SAST scan on a single file and cache results.
    
    Returns scan summary.
    """
    log(f"Starting SAST scan for: {file_path}")
    
    # Initialize cache
    cache = SnykCache(cache_dir=get_cache_dir(workspace))
    
    # Check if already cached (race condition protection)
    cached = cache.get_sast_result(file_path)
    if cached:
        log(f"Already cached: {file_path}")
        return {
            "status": "cached",
            "file": file_path,
            "vuln_count": len(cached.vulnerabilities)
        }
    
    # Run the scan
    try:
        result = run_sast_scan(file_path)
    except Exception as e:
        log(f"SAST scan failed: {e}")
        return {"status": "error", "error": str(e)}
    
    if not result.success:
        log(f"SAST scan failed: {result.error_message}")
        return {"status": "error", "error": result.error_message}
    
    # Filter vulnerabilities for this specific file
    file_vulns = [
        v for v in result.vulnerabilities 
        if Path(v.file_path).name == Path(file_path).name or 
           v.file_path.endswith(file_path) or
           file_path.endswith(v.file_path)
    ]
    
    # Convert to cacheable format
    vuln_dicts = [
        {
            "id": v.id,
            "title": v.title,
            "severity": v.severity,
            "cwe": v.cwe,
            "start_line": v.start_line,
            "end_line": v.end_line,
            "message": v.message
        }
        for v in file_vulns
    ]
    
    # Cache the results
    cache.set_sast_result(file_path, vuln_dicts)
    log(f"Cached SAST result for {file_path}: {len(vuln_dicts)} vulnerabilities")
    
    # Count severities
    critical_count = sum(1 for v in file_vulns if v.severity.lower() == "critical")
    high_count = sum(1 for v in file_vulns if v.severity.lower() == "high")
    
    # Send notification if issues found
    send_notification(
        workspace=workspace,
        scan_type="sast",
        target=file_path,
        vuln_count=len(vuln_dicts),
        high_count=high_count,
        critical_count=critical_count
    )
    
    return {
        "status": "success",
        "file": file_path,
        "vuln_count": len(vuln_dicts),
        "critical": critical_count,
        "high": high_count
    }


# =============================================================================
# SCA SCANNING
# =============================================================================

def scan_sca(workspace: str) -> Dict[str, Any]:
    """
    Run SCA scan and cache results per package.
    
    Returns scan summary.
    """
    log(f"Starting SCA scan for: {workspace}")
    
    # Initialize cache
    cache = SnykCache(cache_dir=get_cache_dir(workspace))
    
    # Run the scan
    try:
        result = run_sca_scan(workspace)
    except Exception as e:
        log(f"SCA scan failed: {e}")
        return {"status": "error", "error": str(e)}
    
    if not result.success:
        log(f"SCA scan failed: {result.error_message}")
        return {"status": "error", "error": result.error_message}
    
    # Group vulnerabilities by TOP-LEVEL package (first in dependency path)
    # This captures the full dependency tree for each top-level package
    packages: Dict[str, Dict[str, Any]] = {}
    
    # First, initialize entries for all top-level packages from package.json
    # This ensures we cache even packages with 0 vulnerabilities
    try:
        workspace_path = Path(workspace).resolve()
        pkg_json_path = workspace_path / "package.json"
        
        if pkg_json_path.exists():
            with safe_open_within_base(pkg_json_path, workspace_path) as f:
                pkg_json = json.load(f)
                deps = pkg_json.get("dependencies", {})
                
                # Get actual installed versions from node_modules
                for pkg_name in deps:
                    try:
                        # Validate package name doesn't contain path traversal
                        if ".." in pkg_name or pkg_name.startswith("/"):
                            log(f"Skipping suspicious package name: {pkg_name}")
                            continue
                        
                        pkg_path = workspace_path / "node_modules" / pkg_name / "package.json"
                        
                        if pkg_path.exists():
                            with safe_open_within_base(pkg_path, workspace_path) as pf:
                                pkg_info = json.load(pf)
                                version = pkg_info.get("version")
                                if version:
                                    key = f"{pkg_name}@{version}"
                                    packages[key] = {
                                        "package": pkg_name,
                                        "version": version,
                                        "vulnerabilities": [],
                                        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}
                                    }
                    except ValueError as e:
                        log(f"Path validation error for {pkg_name}: {e}")
                    except Exception:
                        pass
    except ValueError as e:
        log(f"Path validation error: {e}")
    except Exception:
        pass
    
    # Now add vulnerabilities to the appropriate packages
    for v in result.vulnerabilities:
        # Find the top-level package from dependency path
        if len(v.dependency_path) >= 2:
            top_level = v.dependency_path[1]  # e.g., 'express@4.14.1'
            
            if '@' in top_level:
                parts = top_level.rsplit('@', 1)
                if len(parts) == 2:
                    pkg, version = parts
                    key = f"{pkg}@{version}"
                    
                    if key not in packages:
                        packages[key] = {
                            "package": pkg,
                            "version": version,
                            "vulnerabilities": [],
                            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}
                        }
                    
                    packages[key]["vulnerabilities"].append({
                        "id": v.id,
                        "title": v.title,
                        "severity": v.severity,
                        "fixed_version": v.fixed_version,
                        "cve": v.cve,
                        "package_name": v.package_name,
                        "installed_version": v.installed_version,
                        "dependency_path": v.dependency_path
                    })
                    
                    sev = v.severity.lower()
                    if sev in packages[key]["severity_counts"]:
                        packages[key]["severity_counts"][sev] += 1
    
    # Cache each package
    total_vulns = 0
    total_critical = 0
    total_high = 0
    
    for key, pkg_data in packages.items():
        cache.set_sca_result(
            package=pkg_data["package"],
            version=pkg_data["version"],
            vulnerabilities=pkg_data["vulnerabilities"],
            severity_counts=pkg_data["severity_counts"]
        )
        
        total_vulns += len(pkg_data["vulnerabilities"])
        total_critical += pkg_data["severity_counts"]["critical"]
        total_high += pkg_data["severity_counts"]["high"]
    
    log(f"Cached SCA results for {len(packages)} packages: {total_vulns} total vulnerabilities")
    
    # Send notification if issues found
    if total_vulns > 0:
        send_notification(
            workspace=workspace,
            scan_type="sca",
            target=workspace,
            vuln_count=total_vulns,
            high_count=total_high,
            critical_count=total_critical
        )
    
    return {
        "status": "success",
        "packages_scanned": len(packages),
        "vuln_count": total_vulns,
        "critical": total_critical,
        "high": total_high
    }


# =============================================================================
# MAIN
# =============================================================================

def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Snyk background scan worker')
    parser.add_argument('--type', choices=['sast', 'sca'], required=True,
                        help='Type of scan to run')
    parser.add_argument('--target', required=True,
                        help='Target file (SAST) or directory (SCA)')
    parser.add_argument('--workspace', required=True,
                        help='Workspace root directory')
    
    args = parser.parse_args()
    
    log(f"Worker started: type={args.type}, target={args.target}")
    
    # Change to workspace directory
    os.chdir(args.workspace)
    
    # Run appropriate scan
    if args.type == 'sast':
        result = scan_sast(args.target, args.workspace)
    else:
        result = scan_sca(args.workspace)
    
    log(f"Worker completed: {json.dumps(result)}")
    
    # Exit cleanly
    sys.exit(0 if result.get("status") == "success" else 1)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(f"Worker crashed: {e}")
        import traceback
        log(traceback.format_exc())
        sys.exit(1)
