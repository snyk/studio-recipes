#!/usr/bin/env python3
"""
Output Formatting Module
========================

Terminal output helpers for the Snyk pre-commit hook:
- Colored text and status symbols
- Vulnerability and package delta tables
- Fix command generation

Usage:
    from output import print_header, print_success, print_error, print_warning
    from output import print_info, print_cache_status, colored, Colors
    from output import format_code_vuln_table, format_package_table
    from output import generate_detailed_fix_instructions
"""

import sys
from pathlib import Path
from typing import List

from filter_new_vulns import FilterResult, NewCodeVulnerability, PackageSecurityDelta

# =============================================================================
# COLORS
# =============================================================================


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def colored(text: str, color: str) -> str:
    """Apply color to text if terminal supports it."""
    if sys.stdout.isatty():
        return f"{color}{text}{Colors.RESET}"
    return text


# =============================================================================
# STATUS PRINTERS
# =============================================================================


def print_header(text: str) -> None:
    print(colored(f"\n{'=' * 60}", Colors.CYAN))
    print(colored(f"  {text}", Colors.BOLD))
    print(colored(f"{'=' * 60}", Colors.CYAN))


def print_success(text: str) -> None:
    print(colored(f"✓ {text}", Colors.GREEN))


def print_error(text: str) -> None:
    print(colored(f"✗ {text}", Colors.RED))


def print_warning(text: str) -> None:
    print(colored(f"⚠ {text}", Colors.YELLOW))


def print_info(text: str) -> None:
    print(colored(f"ℹ {text}", Colors.BLUE))


def print_cache_status(hit: bool, target: str) -> None:
    if hit:
        print(colored(f"  ✓ {target}", Colors.GREEN) + colored(" (cached)", Colors.WHITE))
    else:
        print(colored(f"  ○ {target}", Colors.YELLOW) + colored(" (scanning...)", Colors.WHITE))


# =============================================================================
# TABLE FORMATTERS
# =============================================================================


def format_code_vuln_table(vulns: List[NewCodeVulnerability]) -> str:
    """Format code vulnerabilities as a table."""
    lines = []
    lines.append("┌─────────────┬────────────────────────────────┬──────────────────────┐")
    lines.append("│ Severity    │ Vulnerability                  │ Location             │")
    lines.append("├─────────────┼────────────────────────────────┼──────────────────────┤")

    for v in vulns:
        sev = v.vulnerability.severity.upper().ljust(11)
        title = v.vulnerability.title[:30].ljust(30)
        loc = f"{Path(v.vulnerability.file_path).name}:{v.vulnerability.start_line}"[:20].ljust(20)

        if v.vulnerability.severity.lower() == "critical":
            sev = colored(sev, Colors.RED + Colors.BOLD)
        elif v.vulnerability.severity.lower() == "high":
            sev = colored(sev, Colors.RED)
        elif v.vulnerability.severity.lower() == "medium":
            sev = colored(sev, Colors.YELLOW)
        else:
            sev = colored(sev, Colors.WHITE)

        lines.append(f"│ {sev} │ {title} │ {loc} │")

    lines.append("└─────────────┴────────────────────────────────┴──────────────────────┘")
    return "\n".join(lines)


def format_package_table(deltas: List[PackageSecurityDelta]) -> str:
    """Format package security deltas as a table."""
    lines = []
    lines.append("┌────────────────────┬──────────────────────┬─────────────────────────┐")
    lines.append("│ Package            │ Version Change       │ Security Impact         │")
    lines.append("├────────────────────┼──────────────────────┼─────────────────────────┤")

    for d in deltas:
        pkg = d.package_name[:18].ljust(18)

        if d.is_new_package:
            ver = f"NEW → {d.new_version}"[:20].ljust(20)
        else:
            ver = f"{d.old_version} → {d.new_version}"[:20].ljust(20)

        impact = d.summary[:23].ljust(23)

        if d.is_regression:
            impact = colored(impact, Colors.RED)
        else:
            impact = colored(impact, Colors.GREEN)

        lines.append(f"│ {pkg} │ {ver} │ {impact} │")

    lines.append("└────────────────────┴──────────────────────┴─────────────────────────┘")
    return "\n".join(lines)


# =============================================================================
# FIX INSTRUCTIONS
# =============================================================================


def generate_fix_command(result: FilterResult) -> str:
    """Generate the /snyk-fix-batch command with vulnerability IDs."""
    vuln_ids = []

    for v in result.new_code_vulns:
        vuln_id = v.vulnerability.id
        file_hint = Path(v.vulnerability.file_path).name
        line = v.vulnerability.start_line
        vuln_ids.append(f"{vuln_id}@{file_hint}:{line}")

    for d in result.package_regressions:
        vuln_ids.append(f"sca:{d.package_name}")

    if not vuln_ids:
        return ""

    return f"/snyk-fix-batch {', '.join(vuln_ids)}"


def generate_detailed_fix_instructions(result: FilterResult) -> str:
    """Generate detailed instructions for fixing the issues."""
    lines = []

    lines.append(
        colored(
            "\n╔══════════════════════════════════════════════════════════════╗", Colors.MAGENTA
        )
    )
    lines.append(
        colored("║           HOW TO FIX THESE ISSUES                            ║", Colors.MAGENTA)
    )
    lines.append(
        colored("╚══════════════════════════════════════════════════════════════╝", Colors.MAGENTA)
    )

    lines.append("")
    lines.append(colored("Copy and paste this command into your AI assistant:", Colors.BOLD))
    lines.append("")

    fix_cmd = generate_fix_command(result)
    lines.append(
        colored("┌────────────────────────────────────────────────────────────────┐", Colors.CYAN)
    )
    lines.append(colored(f"│  {fix_cmd.ljust(62)} │", Colors.CYAN + Colors.BOLD))
    lines.append(
        colored("└────────────────────────────────────────────────────────────────┘", Colors.CYAN)
    )

    lines.append("")
    lines.append("Or fix individually:")

    if result.new_code_vulns:
        lines.append("")
        lines.append(colored("  Code vulnerabilities:", Colors.YELLOW))
        for v in result.new_code_vulns:
            file_path = v.vulnerability.file_path
            line = v.vulnerability.start_line
            vuln_id = v.vulnerability.id
            lines.append(f"    /snyk-fix code {vuln_id} {file_path}:{line}")

    if result.package_regressions:
        lines.append("")
        lines.append(colored("  Dependency vulnerabilities:", Colors.YELLOW))
        for d in result.package_regressions:
            lines.append(f"    /snyk-fix sca {d.package_name}")

    lines.append("")
    lines.append(colored("After fixing, stage your changes and commit again.", Colors.WHITE))
    lines.append(colored("To bypass this check: git commit --no-verify", Colors.WHITE))

    return "\n".join(lines)
