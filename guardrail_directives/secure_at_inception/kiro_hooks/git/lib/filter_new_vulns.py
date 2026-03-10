#!/usr/bin/env python3
"""
Vulnerability Filter Module
===========================

Filters Snyk scan results to identify only NEW vulnerabilities
introduced by the staged changes.

Logic:
- SAST: A vulnerability is NEW if its file:line falls within modified ranges
- SCA: A vulnerability is concerning if the changed package version has
       MORE critical/high vulnerabilities than the previous version

Usage:
    from filter_new_vulns import filter_new_sast_vulns, evaluate_sca_changes
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from analyze_diff import StagedChanges, PackageChange
from run_snyk_scan import (
    CodeVulnerability, 
    DependencyVulnerability,
    SastScanResult,
    ScaScanResult,
    run_sca_scan_for_package
)


@dataclass
class NewCodeVulnerability:
    """A code vulnerability confirmed to be introduced by staged changes."""
    vulnerability: CodeVulnerability
    introduced_in_line_range: str  # e.g., "lines 45-52"
    
    def __repr__(self) -> str:
        return f"NEW: {self.vulnerability} (introduced at {self.introduced_in_line_range})"


@dataclass
class PackageSecurityDelta:
    """
    Security comparison between old and new versions of a package.
    
    Tracks whether the change improves or degrades security posture.
    """
    package_name: str
    old_version: Optional[str]
    new_version: Optional[str]
    
    # Vulnerability counts for old version
    old_critical: int = 0
    old_high: int = 0
    
    # Vulnerability counts for new version
    new_critical: int = 0
    new_high: int = 0
    
    # List of new vulnerabilities in the new version
    new_vulnerabilities: List[DependencyVulnerability] = field(default_factory=list)
    
    @property
    def is_regression(self) -> bool:
        """
        Check if this change is a security regression.
        
        A regression is when:
        - Critical count increased, OR
        - High count increased (if critical count didn't decrease)
        
        Acceptable trade-offs:
        - Replacing a critical with a high (net improvement)
        - Same or fewer criticals AND same or fewer highs
        """
        # More criticals = always bad
        if self.new_critical > self.old_critical:
            return True
        
        # If criticals improved or stayed same, check highs
        # But allow trading criticals for highs (net improvement)
        # e.g., old: 1 crit, 0 high → new: 0 crit, 2 high = acceptable
        
        # Calculate "weighted score" where critical = 2 points, high = 1 point
        old_score = (self.old_critical * 2) + self.old_high
        new_score = (self.new_critical * 2) + self.new_high
        
        return new_score > old_score
    
    @property
    def is_new_package(self) -> bool:
        """Check if this is a newly added package."""
        return self.old_version is None
    
    @property
    def summary(self) -> str:
        """Human-readable summary of the change."""
        if self.is_new_package:
            base = f"NEW PACKAGE: {self.new_critical} critical, {self.new_high} high"
            
            # Add info about transitive dependencies with high/critical vulns
            transitive_vulns = [v for v in self.new_vulnerabilities if not v.is_direct]
            if transitive_vulns:
                # Group by package
                by_package = {}
                for v in transitive_vulns:
                    if v.severity.lower() in ["critical", "high"]:
                        pkg = v.package_name
                        if pkg not in by_package:
                            by_package[pkg] = {"critical": 0, "high": 0}
                        by_package[pkg][v.severity.lower()] += 1
                
                if by_package:
                    transitive_parts = []
                    for pkg, counts in sorted(by_package.items()):
                        if counts["critical"] > 0 or counts["high"] > 0:
                            transitive_parts.append(f"{pkg} ({counts['critical']}C/{counts['high']}H)")
                    
                    if transitive_parts:
                        base += f" (from: {', '.join(transitive_parts)})"
            
            return base
        
        crit_delta = self.new_critical - self.old_critical
        high_delta = self.new_high - self.old_high
        
        parts = []
        if crit_delta != 0:
            sign = "+" if crit_delta > 0 else ""
            parts.append(f"critical: {sign}{crit_delta}")
        if high_delta != 0:
            sign = "+" if high_delta > 0 else ""
            parts.append(f"high: {sign}{high_delta}")
        
        if not parts:
            return "no significant change"
        
        return ", ".join(parts)
    
    def __repr__(self) -> str:
        action = "REGRESSION" if self.is_regression else "OK"
        ver_change = f"{self.old_version or 'new'} → {self.new_version}"
        return f"[{action}] {self.package_name} ({ver_change}): {self.summary}"


@dataclass
class FilterResult:
    """Complete result of filtering vulnerabilities against staged changes."""
    
    # NEW code vulnerabilities (in modified lines)
    new_code_vulns: List[NewCodeVulnerability] = field(default_factory=list)
    
    # Existing code vulnerabilities (not in modified lines)
    existing_code_vulns: List[CodeVulnerability] = field(default_factory=list)
    
    # Package security deltas
    package_deltas: List[PackageSecurityDelta] = field(default_factory=list)
    
    # Packages that are regressions
    @property
    def package_regressions(self) -> List[PackageSecurityDelta]:
        return [p for p in self.package_deltas if p.is_regression]
    
    # Packages that are improvements or neutral
    @property
    def package_improvements(self) -> List[PackageSecurityDelta]:
        return [p for p in self.package_deltas if not p.is_regression]
    
    @property
    def should_block_commit(self) -> bool:
        """Determine if commit should be blocked based on findings."""
        # Block if ANY new code vulnerabilities
        if self.new_code_vulns:
            return True
        
        # Block if ANY package regressions (more critical/high vulns)
        if self.package_regressions:
            return True
        
        return False
    
    @property
    def block_reason(self) -> str:
        """Human-readable reason for blocking."""
        reasons = []
        
        if self.new_code_vulns:
            count = len(self.new_code_vulns)
            reasons.append(f"{count} new code vulnerabilit{'y' if count == 1 else 'ies'}")
        
        if self.package_regressions:
            count = len(self.package_regressions)
            pkgs = ", ".join(p.package_name for p in self.package_regressions)
            reasons.append(f"{count} package{'s' if count > 1 else ''} with security regressions: {pkgs}")
        
        return "; ".join(reasons) if reasons else "No issues"


def filter_new_sast_vulns(
    sast_result: SastScanResult,
    staged_changes: StagedChanges
) -> Tuple[List[NewCodeVulnerability], List[CodeVulnerability]]:
    """
    Filter SAST vulnerabilities to separate NEW from EXISTING.
    
    A vulnerability is NEW if:
    1. The file is staged, AND
    2. The vulnerability's line number falls within a modified range
    
    Args:
        sast_result: Results from Snyk SAST scan
        staged_changes: Parsed git staged changes
    
    Returns:
        Tuple of (new_vulns, existing_vulns)
    """
    new_vulns: List[NewCodeVulnerability] = []
    existing_vulns: List[CodeVulnerability] = []
    
    for vuln in sast_result.vulnerabilities:
        # Normalize path (remove leading ./ or /)
        vuln_path = vuln.file_path.lstrip('./')
        
        # Check if this file is in our staged changes
        file_changes = None
        for staged_path, fc in staged_changes.files.items():
            # Normalize staged path too
            normalized_staged = staged_path.lstrip('./')
            if normalized_staged == vuln_path or vuln_path.endswith(normalized_staged):
                file_changes = fc
                break
        
        if file_changes is None:
            # File not in staged changes - this is an existing vulnerability
            existing_vulns.append(vuln)
            continue
        
        # File is staged - check if vulnerability line is in modified ranges
        if file_changes.is_new:
            # Entire file is new - all vulnerabilities are new
            new_vulns.append(NewCodeVulnerability(
                vulnerability=vuln,
                introduced_in_line_range="new file"
            ))
        elif file_changes.line_in_changes(vuln.start_line):
            # Vulnerability line is in a modified range
            matching_range = next(
                (r for r in file_changes.modified_ranges if r.contains(vuln.start_line)),
                None
            )
            range_str = str(matching_range) if matching_range else f"line {vuln.start_line}"
            
            new_vulns.append(NewCodeVulnerability(
                vulnerability=vuln,
                introduced_in_line_range=range_str
            ))
        else:
            # File is staged but vulnerability is not in modified lines
            existing_vulns.append(vuln)
    
    return new_vulns, existing_vulns


def evaluate_package_change(
    package_change: PackageChange,
    current_scan: ScaScanResult
) -> PackageSecurityDelta:
    """
    Evaluate security impact of a single package version change.
    
    Compares vulnerability counts between old and new versions.
    Includes transitive dependencies for both new and updated packages.
    
    Args:
        package_change: The package change from git diff
        current_scan: Current SCA scan result (has new version vulns)
    
    Returns:
        PackageSecurityDelta with comparison
    """
    pkg_name = package_change.name
    
    # Get vulnerabilities for new version INCLUDING transitive dependencies
    new_vulns = current_scan.get_vulns_for_package_tree(pkg_name)
    new_counts = current_scan.count_severity_for_package_tree(pkg_name)
    
    delta = PackageSecurityDelta(
        package_name=pkg_name,
        old_version=package_change.old_version,
        new_version=package_change.new_version,
        new_critical=new_counts["critical"],
        new_high=new_counts["high"],
        new_vulnerabilities=new_vulns
    )
    
    if package_change.old_version is None:
        # New package - no old version to compare
        # For new packages, any critical/high is a "regression" from zero
        delta.old_critical = 0
        delta.old_high = 0
    else:
        # Get vulnerabilities for old version via separate scan
        # This is expensive but accurate
        old_scan = run_sca_scan_for_package(pkg_name, package_change.old_version.lstrip('^~'))
        
        if old_scan.success:
            old_counts = old_scan.count_severity_for_package(pkg_name)
            delta.old_critical = old_counts["critical"]
            delta.old_high = old_counts["high"]
        else:
            # If we can't scan old version, assume it was clean
            # (conservative - won't block unless new version definitely has issues)
            delta.old_critical = 0
            delta.old_high = 0
    
    return delta


def evaluate_sca_changes(
    sca_result: ScaScanResult,
    staged_changes: StagedChanges,
    skip_old_version_scan: bool = False
) -> List[PackageSecurityDelta]:
    """
    Evaluate security impact of all package changes.
    
    Args:
        sca_result: Current SCA scan result
        staged_changes: Parsed git staged changes
        skip_old_version_scan: If True, skip scanning old versions (faster but less accurate)
    
    Returns:
        List of PackageSecurityDelta for each changed package
    """
    deltas: List[PackageSecurityDelta] = []
    
    for pkg_name, pkg_change in staged_changes.packages.items():
        # Skip removed packages (can't introduce new vulns)
        if pkg_change.new_version is None:
            continue
        
        if skip_old_version_scan:
            # Quick mode: only check if new version has critical/high
            new_counts = sca_result.count_severity_for_package(pkg_name)
            
            delta = PackageSecurityDelta(
                package_name=pkg_name,
                old_version=pkg_change.old_version,
                new_version=pkg_change.new_version,
                old_critical=0,  # Assume clean (won't block improvements)
                old_high=0,
                new_critical=new_counts["critical"],
                new_high=new_counts["high"],
                new_vulnerabilities=sca_result.get_vulns_for_package(pkg_name)
            )
        else:
            # Full mode: compare with old version
            delta = evaluate_package_change(pkg_change, sca_result)
        
        deltas.append(delta)
    
    return deltas


def analyze_staged_changes(
    staged_changes: StagedChanges,
    sast_result: Optional[SastScanResult] = None,
    sca_result: Optional[ScaScanResult] = None,
    quick_mode: bool = False
) -> FilterResult:
    """
    Main entry point: Analyze staged changes against Snyk scan results.
    
    Args:
        staged_changes: Parsed git staged changes
        sast_result: SAST scan result (None to skip code analysis)
        sca_result: SCA scan result (None to skip dependency analysis)
        quick_mode: Skip old version comparison for SCA (faster)
    
    Returns:
        FilterResult with categorized vulnerabilities
    """
    result = FilterResult()
    
    # Analyze code vulnerabilities
    if sast_result and sast_result.success:
        new_code, existing_code = filter_new_sast_vulns(sast_result, staged_changes)
        result.new_code_vulns = new_code
        result.existing_code_vulns = existing_code
    
    # Analyze package vulnerabilities
    if sca_result and sca_result.success and staged_changes.has_package_changes:
        result.package_deltas = evaluate_sca_changes(
            sca_result, 
            staged_changes,
            skip_old_version_scan=quick_mode
        )
    
    return result


# CLI interface for testing
if __name__ == '__main__':
    from analyze_diff import get_staged_changes
    from run_snyk_scan import run_sast_scan, run_sca_scan
    
    print("=== Analyzing Staged Changes ===\n")
    
    # Get staged changes
    staged = get_staged_changes()
    print(f"Code files changed: {len(staged.changed_code_files)}")
    print(f"Packages changed: {len(staged.packages)}\n")
    
    sast_result = None
    sca_result = None
    
    # Run SAST if code changed
    if staged.has_code_changes:
        print("Running SAST scan...")
        sast_result = run_sast_scan(".")
        if sast_result.success:
            print(f"  Found {len(sast_result.vulnerabilities)} total code vulnerabilities")
    
    # Run SCA if packages changed
    if staged.has_package_changes:
        print("Running SCA scan...")
        sca_result = run_sca_scan(".")
        if sca_result.success:
            print(f"  Found {len(sca_result.vulnerabilities)} total dependency vulnerabilities")
    
    # Analyze
    print("\n=== Filtering NEW Vulnerabilities ===\n")
    result = analyze_staged_changes(staged, sast_result, sca_result, quick_mode=True)
    
    print(f"NEW code vulnerabilities: {len(result.new_code_vulns)}")
    for v in result.new_code_vulns:
        print(f"  - {v}")
    
    print(f"\nExisting code vulnerabilities: {len(result.existing_code_vulns)}")
    
    print(f"\nPackage security changes: {len(result.package_deltas)}")
    for d in result.package_deltas:
        print(f"  - {d}")
    
    print(f"\n=== Decision ===")
    if result.should_block_commit:
        print(f"BLOCK: {result.block_reason}")
    else:
        print("ALLOW: No new security issues introduced")

