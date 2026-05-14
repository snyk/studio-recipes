#!/usr/bin/env python3
"""
Diff Analyzer Module
====================

Analyzes git staged changes to extract:
- Modified file:line ranges (for SAST vulnerability matching)
- Package dependency changes (for SCA vulnerability matching)

Usage:
    from analyze_diff import get_staged_changes
    changes = get_staged_changes()
"""

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class LineRange:
    """Represents a range of modified lines in a file."""

    start: int
    end: int

    def contains(self, line: int) -> bool:
        """Check if a line number falls within this range."""
        return self.start <= line <= self.end

    def __repr__(self) -> str:
        if self.start == self.end:
            return f"line {self.start}"
        return f"lines {self.start}-{self.end}"


@dataclass
class FileChanges:
    """Represents changes to a single file."""

    path: str
    modified_ranges: List[LineRange] = field(default_factory=list)
    is_new: bool = False
    is_deleted: bool = False

    def line_in_changes(self, line: int) -> bool:
        """Check if a specific line was modified."""
        if self.is_new:
            return True  # All lines in new files are "changed"
        return any(r.contains(line) for r in self.modified_ranges)


@dataclass
class PackageChange:
    """Represents a change to a single package dependency."""

    name: str
    old_version: Optional[str]  # None if package was added
    new_version: Optional[str]  # None if package was removed
    is_dev: bool = False

    @property
    def change_type(self) -> str:
        if self.old_version is None:
            return "added"
        if self.new_version is None:
            return "removed"
        return "changed"


@dataclass
class StagedChanges:
    """Complete summary of all staged changes."""

    files: Dict[str, FileChanges] = field(default_factory=dict)
    packages: Dict[str, PackageChange] = field(default_factory=dict)

    @property
    def has_code_changes(self) -> bool:
        """Check if any code files (non-manifest) were changed."""
        code_extensions = {
            ".ts",
            ".tsx",
            ".js",
            ".jsx",
            ".py",
            ".java",
            ".go",
            ".rb",
            ".php",
            ".cs",
            ".swift",
        }
        for path in self.files:
            if Path(path).suffix.lower() in code_extensions:
                return True
        return False

    @property
    def has_package_changes(self) -> bool:
        """Check if any package dependencies were changed."""
        return len(self.packages) > 0

    @property
    def changed_code_files(self) -> List[str]:
        """Get list of changed code files (for targeted SAST scan)."""
        code_extensions = {
            ".ts",
            ".tsx",
            ".js",
            ".jsx",
            ".py",
            ".java",
            ".go",
            ".rb",
            ".php",
            ".cs",
            ".swift",
        }
        return [p for p in self.files if Path(p).suffix.lower() in code_extensions]


def run_git_command(args: List[str]) -> str:
    """Run a git command and return stdout."""
    result = subprocess.run(["git"] + args, capture_output=True, text=True, check=False)
    if result.returncode != 0 and result.stderr:
        # Some git commands return non-zero but still have useful output
        pass
    return result.stdout


def parse_diff_hunks(diff_output: str) -> Dict[str, FileChanges]:
    """
    Parse git diff output to extract modified line ranges per file.

    Handles the unified diff format:
    @@ -old_start,old_count +new_start,new_count @@
    """
    files: Dict[str, FileChanges] = {}
    current_file: Optional[str] = None

    # Match file paths in diff header
    file_pattern = re.compile(r"^diff --git a/.+ b/(.+)$")
    # Match new file mode
    new_file_pattern = re.compile(r"^new file mode")
    # Match deleted file mode
    deleted_pattern = re.compile(r"^deleted file mode")
    # Match hunk headers: @@ -start,count +start,count @@
    hunk_pattern = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

    for line in diff_output.split("\n"):
        # Check for new file
        file_match = file_pattern.match(line)
        if file_match:
            current_file = file_match.group(1)
            files[current_file] = FileChanges(path=current_file)
            continue

        if current_file:
            # Check for new/deleted file markers
            if new_file_pattern.match(line):
                files[current_file].is_new = True
                continue

            if deleted_pattern.match(line):
                files[current_file].is_deleted = True
                continue

            # Parse hunk header for line ranges
            hunk_match = hunk_pattern.match(line)
            if hunk_match:
                start = int(hunk_match.group(1))
                count = int(hunk_match.group(2)) if hunk_match.group(2) else 1

                if count > 0:  # Only add if there are added/modified lines
                    end = start + count - 1
                    files[current_file].modified_ranges.append(LineRange(start=start, end=end))

    return files


def parse_package_json_diff() -> Dict[str, PackageChange]:
    """
    Parse changes to package.json to identify added/changed/removed packages.

    Compares staged version against HEAD to find dependency changes.
    """
    packages: Dict[str, PackageChange] = {}

    # Check if package.json is staged
    staged_files = run_git_command(["diff", "--staged", "--name-only"]).strip().split("\n")
    if "package.json" not in staged_files:
        return packages

    try:
        # Get old package.json (HEAD)
        old_content = run_git_command(["show", "HEAD:package.json"])
        old_json = json.loads(old_content) if old_content.strip() else {}
    except (json.JSONDecodeError, subprocess.CalledProcessError):
        old_json = {}

    try:
        # Get new package.json (staged)
        new_content = run_git_command(["show", ":package.json"])
        new_json = json.loads(new_content) if new_content.strip() else {}
    except (json.JSONDecodeError, subprocess.CalledProcessError):
        new_json = {}

    # Extract dependencies
    old_deps = {**old_json.get("dependencies", {})}
    old_dev_deps = {**old_json.get("devDependencies", {})}
    new_deps = {**new_json.get("dependencies", {})}
    new_dev_deps = {**new_json.get("devDependencies", {})}

    # Find changes in regular dependencies
    all_dep_names = set(old_deps.keys()) | set(new_deps.keys())
    for name in all_dep_names:
        old_ver = old_deps.get(name)
        new_ver = new_deps.get(name)

        if old_ver != new_ver:
            packages[name] = PackageChange(
                name=name, old_version=old_ver, new_version=new_ver, is_dev=False
            )

    # Find changes in dev dependencies
    all_dev_names = set(old_dev_deps.keys()) | set(new_dev_deps.keys())
    for name in all_dev_names:
        old_ver = old_dev_deps.get(name)
        new_ver = new_dev_deps.get(name)

        if old_ver != new_ver:
            packages[name] = PackageChange(
                name=name, old_version=old_ver, new_version=new_ver, is_dev=True
            )

    return packages


def get_staged_changes() -> StagedChanges:
    """
    Main entry point: Get complete summary of all staged changes.

    Returns:
        StagedChanges object with file changes and package changes
    """
    # Get file changes with line-level detail
    diff_output = run_git_command(["diff", "--staged", "--unified=0"])
    files = parse_diff_hunks(diff_output)

    # Get package changes
    packages = parse_package_json_diff()

    return StagedChanges(files=files, packages=packages)


def get_staged_file_list() -> List[str]:
    """Get simple list of staged files (for quick checks)."""
    output = run_git_command(["diff", "--staged", "--name-only"])
    return [f for f in output.strip().split("\n") if f]


# CLI interface for testing
if __name__ == "__main__":
    changes = get_staged_changes()

    print("=== Staged Changes Analysis ===\n")

    print(f"Code files changed: {changes.has_code_changes}")
    print(f"Packages changed: {changes.has_package_changes}\n")

    if changes.files:
        print("--- File Changes ---")
        for path, fc in changes.files.items():
            status = "[NEW]" if fc.is_new else "[DEL]" if fc.is_deleted else "[MOD]"
            print(f"  {status} {path}")
            if fc.modified_ranges:
                ranges = ", ".join(str(r) for r in fc.modified_ranges)
                print(f"        Modified: {ranges}")
        print()

    if changes.packages:
        print("--- Package Changes ---")
        for name, pc in changes.packages.items():
            if pc.change_type == "added":
                print(f"  [+] {name}@{pc.new_version}")
            elif pc.change_type == "removed":
                print(f"  [-] {name}@{pc.old_version}")
            else:
                print(f"  [~] {name}: {pc.old_version} → {pc.new_version}")
        print()
