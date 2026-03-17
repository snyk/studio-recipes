#!/usr/bin/env python3
"""
Snyk Scanner Module
===================

Runs targeted Snyk scans using the CLI:
- SAST (snyk code test) for code vulnerabilities
- SCA (snyk test) for dependency vulnerabilities

Parses JSON output to extract vulnerability details.

Requirements:
- Snyk CLI must be installed globally: npm install -g snyk
- Must be authenticated: snyk auth

Usage:
    from run_snyk_scan import run_sast_scan, run_sca_scan
"""

import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any


@dataclass
class CodeVulnerability:
    """A code (SAST) vulnerability from Snyk."""
    id: str                      # e.g., "javascript/PT", "python/SQLi"
    title: str                   # e.g., "Path Traversal"
    severity: str               # "critical", "high", "medium", "low"
    cwe: Optional[str]          # e.g., "CWE-22"
    file_path: str              # e.g., "src/server.ts"
    start_line: int             # Line number where vulnerability starts
    end_line: int               # Line number where vulnerability ends
    message: str                # Detailed description
    
    @property
    def severity_rank(self) -> int:
        """Numeric rank for severity comparison (higher = more severe)."""
        ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        return ranks.get(self.severity.lower(), 0)
    
    def __repr__(self) -> str:
        return f"{self.severity.upper()}: {self.title} at {self.file_path}:{self.start_line}"


@dataclass
class DependencyVulnerability:
    """A dependency (SCA) vulnerability from Snyk."""
    id: str                      # Snyk ID, e.g., "SNYK-JS-LODASH-1018905"
    title: str                   # e.g., "Prototype Pollution"
    severity: str               # "critical", "high", "medium", "low"
    package_name: str           # e.g., "lodash"
    installed_version: str      # e.g., "4.17.15"
    fixed_version: Optional[str]  # e.g., "4.17.21" or None if no fix
    cve: Optional[str]          # e.g., "CVE-2021-23337"
    cvss_score: Optional[float] # e.g., 7.2
    is_direct: bool             # True if direct dependency, False if transitive
    dependency_path: List[str]  # Path from root to vulnerable package
    
    @property
    def severity_rank(self) -> int:
        """Numeric rank for severity comparison (higher = more severe)."""
        ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        return ranks.get(self.severity.lower(), 0)
    
    def __repr__(self) -> str:
        return f"{self.severity.upper()}: {self.title} in {self.package_name}@{self.installed_version}"


@dataclass
class SastScanResult:
    """Results from a SAST (code) scan."""
    success: bool
    vulnerabilities: List[CodeVulnerability] = field(default_factory=list)
    error_message: Optional[str] = None
    
    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity.lower() == "critical")
    
    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity.lower() == "high")
    
    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity.lower() == "medium")
    
    @property
    def low_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity.lower() == "low")


@dataclass
class ScaScanResult:
    """Results from an SCA (dependency) scan."""
    success: bool
    vulnerabilities: List[DependencyVulnerability] = field(default_factory=list)
    error_message: Optional[str] = None
    
    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity.lower() == "critical")
    
    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity.lower() == "high")
    
    def get_vulns_for_package_tree(self, package_name: str) -> List[DependencyVulnerability]:
        """
        Get all vulnerabilities for a package and its transitive dependencies.
        
        Includes vulnerabilities where the package appears anywhere in the dependency path.
        For example, if package_name is "express", this returns:
        - Direct express vulnerabilities
        - Vulnerabilities in qs (if express depends on qs)
        - Vulnerabilities in fresh (if express depends on fresh)
        etc.
        """
        return [
            v for v in self.vulnerabilities 
            if any(package_name in dep for dep in v.dependency_path)
        ]
    
    def count_severity_for_package_tree(self, package_name: str) -> Dict[str, int]:
        """Count vulnerabilities by severity for a package and its transitive dependencies."""
        vulns = self.get_vulns_for_package_tree(package_name)
        return {
            "critical": sum(1 for v in vulns if v.severity.lower() == "critical"),
            "high": sum(1 for v in vulns if v.severity.lower() == "high"),
            "medium": sum(1 for v in vulns if v.severity.lower() == "medium"),
            "low": sum(1 for v in vulns if v.severity.lower() == "low"),
        }


def run_snyk_cli(args: List[str], timeout: int = 300) -> tuple[int, str, str]:
    """
    Run snyk CLI command and return exit code, stdout, stderr.
    
    Args:
        args: Arguments to pass to snyk (e.g., ['code', 'test', '--json'])
        timeout: Timeout in seconds (default 5 minutes)
    
    Returns:
        Tuple of (exit_code, stdout, stderr)
    """
    try:
        result = subprocess.run(
            ['snyk'] + args,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Snyk scan timed out"
    except FileNotFoundError:
        return -1, "", "Snyk CLI not found. Please install: npm install -g snyk"


def parse_sast_json(output: str) -> List[CodeVulnerability]:
    """Parse Snyk Code (SAST) JSON output into vulnerability objects."""
    vulnerabilities = []
    
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return vulnerabilities
    
    # Handle different Snyk Code output formats
    runs = data.get('runs', [])
    
    for run in runs:
        results = run.get('results', [])
        
        for result in results:
            rule_id = result.get('ruleId', 'unknown')
            message = result.get('message', {}).get('text', '')
            
            # Get severity from rule metadata
            level = result.get('level', 'warning')
            severity_map = {
                'error': 'high',
                'warning': 'medium', 
                'note': 'low'
            }
            severity = severity_map.get(level, 'medium')
            
            # Extract location info
            locations = result.get('locations', [])
            for loc in locations:
                phys_loc = loc.get('physicalLocation', {})
                artifact = phys_loc.get('artifactLocation', {})
                region = phys_loc.get('region', {})
                
                file_path = artifact.get('uri', 'unknown')
                start_line = region.get('startLine', 0)
                end_line = region.get('endLine', start_line)
                
                # Try to get CWE from properties
                properties = result.get('properties', {})
                cwe_list = properties.get('cwe', [])
                cwe = cwe_list[0] if cwe_list else None
                
                # Get severity from properties if available
                if 'priorityScore' in properties:
                    score = properties['priorityScore']
                    if score >= 700:
                        severity = 'critical'
                    elif score >= 500:
                        severity = 'high'
                    elif score >= 300:
                        severity = 'medium'
                    else:
                        severity = 'low'
                
                vulnerabilities.append(CodeVulnerability(
                    id=rule_id,
                    title=rule_id.replace('/', ' - ').replace('_', ' ').title(),
                    severity=severity,
                    cwe=cwe,
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    message=message
                ))
    
    return vulnerabilities


def parse_sca_json(output: str) -> List[DependencyVulnerability]:
    """Parse Snyk SCA JSON output into vulnerability objects."""
    vulnerabilities = []
    
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return vulnerabilities
    
    # Handle both single project and multi-project output
    if isinstance(data, list):
        projects = data
    else:
        projects = [data]
    
    for project in projects:
        vulns = project.get('vulnerabilities', [])
        
        for vuln in vulns:
            # Build dependency path
            from_path = vuln.get('from', [])
            
            # Safely extract fixed_version and CVE from potentially empty lists
            fixed_in = vuln.get('fixedIn', [])
            fixed_version = fixed_in[0] if fixed_in else None
            
            identifiers = vuln.get('identifiers', {})
            cve_list = identifiers.get('CVE', []) if identifiers else []
            cve = cve_list[0] if cve_list else None
            
            vulnerabilities.append(DependencyVulnerability(
                id=vuln.get('id', 'unknown'),
                title=vuln.get('title', 'Unknown vulnerability'),
                severity=vuln.get('severity', 'medium'),
                package_name=vuln.get('packageName', vuln.get('name', 'unknown')),
                installed_version=vuln.get('version', 'unknown'),
                fixed_version=fixed_version,
                cve=cve,
                cvss_score=vuln.get('cvssScore'),
                is_direct=len(from_path) <= 2,  # project > package = direct
                dependency_path=from_path
            ))
    
    return vulnerabilities


def run_sast_scan(target_path: str = ".") -> SastScanResult:
    """
    Run Snyk Code (SAST) scan on target path.
    
    Args:
        target_path: Path to scan (file or directory)
    
    Returns:
        SastScanResult with vulnerabilities or error
    """
    args = ['code', 'test', target_path, '--json']
    
    exit_code, stdout, stderr = run_snyk_cli(args)
    
    # Exit code 0 = no vulns, 1 = vulns found, 2+ = error
    if exit_code < 0 or exit_code > 1:
        return SastScanResult(
            success=False,
            error_message=stderr or "Snyk code scan failed"
        )
    
    vulnerabilities = parse_sast_json(stdout)
    
    return SastScanResult(
        success=True,
        vulnerabilities=vulnerabilities
    )


def run_sca_scan(target_path: str = ".") -> ScaScanResult:
    """
    Run Snyk SCA scan on target path.
    
    Args:
        target_path: Path to scan (directory with package.json, requirements.txt, etc.)
    
    Returns:
        ScaScanResult with vulnerabilities or error
    """
    args = ['test', target_path, '--json']
    
    exit_code, stdout, stderr = run_snyk_cli(args)
    
    # Exit code 0 = no vulns, 1 = vulns found, 2+ = error
    if exit_code < 0 or exit_code > 1:
        # Check for common errors
        if "not authenticated" in stderr.lower():
            return ScaScanResult(
                success=False,
                error_message="Snyk not authenticated. Run: snyk auth"
            )
        return ScaScanResult(
            success=False,
            error_message=stderr or "Snyk test failed"
        )
    
    vulnerabilities = parse_sca_json(stdout)
    
    return ScaScanResult(
        success=True,
        vulnerabilities=vulnerabilities
    )


def run_sca_scan_for_package(package_name: str, version: str) -> ScaScanResult:
    """
    Run Snyk test on a specific package version.
    
    Useful for comparing vulnerability counts between versions.
    
    Args:
        package_name: npm package name
        version: Specific version to test
    
    Returns:
        ScaScanResult for that package version
    """
    args = ['test', f'{package_name}@{version}', '--json']
    
    exit_code, stdout, stderr = run_snyk_cli(args, timeout=60)
    
    if exit_code < 0 or exit_code > 1:
        return ScaScanResult(
            success=False,
            error_message=stderr or f"Failed to scan {package_name}@{version}"
        )
    
    vulnerabilities = parse_sca_json(stdout)
    
    return ScaScanResult(
        success=True,
        vulnerabilities=vulnerabilities
    )


# CLI interface for testing
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Run Snyk scans')
    parser.add_argument('--sast', action='store_true', help='Run SAST scan')
    parser.add_argument('--sca', action='store_true', help='Run SCA scan')
    parser.add_argument('--path', default='.', help='Target path')
    
    args = parser.parse_args()
    
    if args.sast:
        print("=== Snyk SAST Scan ===")
        result = run_sast_scan(args.path)
        if not result.success:
            print(f"Error: {result.error_message}")
        else:
            print(f"Found {len(result.vulnerabilities)} code vulnerabilities:")
            print(f"  Critical: {result.critical_count}")
            print(f"  High: {result.high_count}")
            print(f"  Medium: {result.medium_count}")
            print(f"  Low: {result.low_count}")
            for v in result.vulnerabilities:
                print(f"  - {v}")
    
    if args.sca:
        print("\n=== Snyk SCA Scan ===")
        result = run_sca_scan(args.path)
        if not result.success:
            print(f"Error: {result.error_message}")
        else:
            print(f"Found {len(result.vulnerabilities)} dependency vulnerabilities:")
            print(f"  Critical: {result.critical_count}")
            print(f"  High: {result.high_count}")
            for v in result.vulnerabilities:
                print(f"  - {v}")

