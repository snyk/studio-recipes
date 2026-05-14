#!/usr/bin/env python3
"""
Cache-Aware Scanner Module
==========================

Wraps run_snyk_scan with cache lookup/population logic for both SAST and SCA scans.

- get_sast_with_cache: returns SAST results, serving from cache where available
- get_sca_with_cache:  returns SCA results, serving from cache where available
- resolve_installed_version: resolves actual installed version from package-lock.json

Usage:
    from scanner import get_sast_with_cache, get_sca_with_cache

    sast_result, hits, misses = get_sast_with_cache(staged, cache, debug=True)
    sca_result,  hits, misses = get_sca_with_cache(staged,  cache, debug=True)
"""

import json
from pathlib import Path
from typing import Dict, List, Tuple

from analyze_diff import StagedChanges
from cache import SnykCache
from run_snyk_scan import (
    CodeVulnerability,
    DependencyVulnerability,
    SastScanResult,
    ScaScanResult,
    run_sast_scan,
    run_sca_scan,
)


def resolve_installed_version(package_name: str, semver_range: str) -> str:
    """
    Resolve the actual installed version from package-lock.json.
    Falls back to the semver range if resolution fails.
    """
    try:
        lock_file = Path("package-lock.json")
        if not lock_file.exists():
            return semver_range.lstrip("^~>=<")

        with open(lock_file) as f:
            lock_data = json.load(f)

        # lockfileVersion 2+
        if "packages" in lock_data:
            pkg_key = f"node_modules/{package_name}"
            if pkg_key in lock_data["packages"]:
                return lock_data["packages"][pkg_key].get("version", semver_range.lstrip("^~>=<"))

        # lockfileVersion 1
        if "dependencies" in lock_data and package_name in lock_data["dependencies"]:
            return lock_data["dependencies"][package_name].get(
                "version", semver_range.lstrip("^~>=<")
            )

    except Exception:
        pass

    return semver_range.lstrip("^~>=<")


def get_sast_with_cache(
    staged: StagedChanges,
    cache: SnykCache,
    no_cache: bool = False,
    debug: bool = False,
) -> Tuple[SastScanResult, int, int]:
    """
    Get SAST results using cache where available.

    Returns:
        Tuple of (SastScanResult, cache_hits, cache_misses)
    """
    all_vulns: List[CodeVulnerability] = []
    cache_hits = 0
    cache_misses = 0
    uncached_files: List[str] = []

    for file_path in staged.changed_code_files:
        file_hash = cache.compute_file_hash(file_path)
        if debug:
            print(f"  DEBUG: Looking up cache for {file_path}, hash={file_hash}")
        cached = cache.get_sast_result(file_path)
        if debug:
            print(f"  DEBUG: Cache result: {cached is not None}, no_cache={no_cache}")

        if cached and not no_cache:
            cache_hits += 1
            for v in cached.vulnerabilities:
                all_vulns.append(
                    CodeVulnerability(
                        id=v.get("id", "unknown"),
                        title=v.get("title", "Unknown"),
                        severity=v.get("severity", "medium"),
                        cwe=v.get("cwe"),
                        file_path=file_path,
                        start_line=v.get("start_line", 0),
                        end_line=v.get("end_line", 0),
                        message=v.get("message", ""),
                    )
                )
        else:
            cache_misses += 1
            uncached_files.append(file_path)

    if uncached_files:
        fresh_result = run_sast_scan(".")

        if fresh_result.success:
            for v in fresh_result.vulnerabilities:
                for uncached in uncached_files:
                    if (
                        v.file_path == uncached
                        or v.file_path.endswith(uncached)
                        or uncached.endswith(v.file_path)
                        or Path(v.file_path).name == Path(uncached).name
                    ):
                        all_vulns.append(v)
                        break

            for file_path in uncached_files:
                file_vulns = [
                    {
                        "id": v.id,
                        "title": v.title,
                        "severity": v.severity,
                        "cwe": v.cwe,
                        "start_line": v.start_line,
                        "end_line": v.end_line,
                        "message": v.message,
                    }
                    for v in fresh_result.vulnerabilities
                    if (
                        v.file_path == file_path
                        or v.file_path.endswith(file_path)
                        or file_path.endswith(v.file_path)
                        or Path(v.file_path).name == Path(file_path).name
                    )
                ]
                cache.set_sast_result(file_path, file_vulns)

    return SastScanResult(success=True, vulnerabilities=all_vulns), cache_hits, cache_misses


def get_sca_with_cache(
    staged: StagedChanges,
    cache: SnykCache,
    no_cache: bool = False,
    debug: bool = False,
) -> Tuple[ScaScanResult, int, int]:
    """
    Get SCA results using cache where available.

    Returns:
        Tuple of (ScaScanResult, cache_hits, cache_misses)
    """
    all_vulns: List[DependencyVulnerability] = []
    cache_hits = 0
    cache_misses = 0
    need_fresh_scan = False

    for pkg_name, pkg_change in staged.packages.items():
        if pkg_change.new_version is None:
            continue  # Skip removed packages

        version = resolve_installed_version(pkg_name, pkg_change.new_version)
        cached = cache.get_sca_result(pkg_name, version)

        if cached and not no_cache:
            cache_hits += 1
            for v in cached.vulnerabilities:
                all_vulns.append(
                    DependencyVulnerability(
                        id=v.get("id", "unknown"),
                        title=v.get("title", "Unknown"),
                        severity=v.get("severity", "medium"),
                        package_name=v.get("package_name", pkg_name),
                        installed_version=v.get("installed_version", version),
                        fixed_version=v.get("fixed_version"),
                        cve=v.get("cve"),
                        cvss_score=None,
                        is_direct=v.get("package_name") == pkg_name,
                        dependency_path=v.get("dependency_path", []),
                    )
                )
        else:
            cache_misses += 1
            need_fresh_scan = True

    if need_fresh_scan:
        fresh_result = run_sca_scan(".")

        if fresh_result.success:
            cached_ids = {v.id for v in all_vulns}

            for v in fresh_result.vulnerabilities:
                if v.id not in cached_ids:
                    all_vulns.append(v)

            # Cache results per top-level package with their full dependency trees.
            # Group vulnerabilities by the first package in the dependency path
            # (i.e. the direct dependency of the project that pulls in the vuln).
            packages_cached: Dict[str, Dict] = {}

            for v in fresh_result.vulnerabilities:
                if len(v.dependency_path) >= 2:
                    # dependency_path: ['snyk-test-repo@1.0.0', 'express@4.14.1', ...]
                    top_level = v.dependency_path[1]

                    if "@" in top_level:
                        parts = top_level.rsplit("@", 1)
                        if len(parts) == 2:
                            top_pkg_name, top_pkg_version = parts
                            key = f"{top_pkg_name}@{top_pkg_version}"

                            if key not in packages_cached:
                                packages_cached[key] = {
                                    "package": top_pkg_name,
                                    "version": top_pkg_version,
                                    "vulnerabilities": [],
                                }

                            packages_cached[key]["vulnerabilities"].append(
                                {
                                    "id": v.id,
                                    "title": v.title,
                                    "severity": v.severity,
                                    "fixed_version": v.fixed_version,
                                    "cve": v.cve,
                                    "package_name": v.package_name,
                                    "installed_version": v.installed_version,
                                    "dependency_path": v.dependency_path,
                                }
                            )

            if debug:
                print(f"Caching {len(packages_cached)} top-level packages")
                for key in packages_cached:
                    print(
                        f"  {key}: {len(packages_cached[key]['vulnerabilities'])} vulnerabilities"
                    )

            for _key, data in packages_cached.items():
                cache.set_sca_result(data["package"], data["version"], data["vulnerabilities"])

    return ScaScanResult(success=True, vulnerabilities=all_vulns), cache_hits, cache_misses
