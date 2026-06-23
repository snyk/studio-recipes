#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# ///
"""
Snyk Secure At Commit
=====================

Run Snyk Code (SAST) and Snyk Open Source (SCA) against a workspace and
report findings.

MODES:
  --staged       Pre-commit mode. Only files in the index ("git diff --cached")
                 are considered: SAST findings are filtered to those files,
                 SCA findings are filtered to the staged manifests, and the
                 footer points at `git commit --no-verify` as the bypass.
                 This is how the installer wires the script into the
                 pre-commit hook (`.git/hooks/pre-commit`, `.husky/pre-commit`,
                 or `.pre-commit-config.yaml`).
  (default)      Full-repo mode. Every code file is in scope for SAST and
                 every dependency manifest is in scope for SCA. Useful when
                 a developer wants an on-demand audit of the workspace.

EXIT CODES:
  0  no issues
  1  vulnerabilities found
  2  prerequisite failure — fail-closed. Snyk not installed, snyk not
     authenticated, --staged used outside a git repository, or the
     ``git diff --cached`` subprocess failed for any reason (a locked
     index, OS error, …). A security hook must never let a commit through
     when it can't reason about what's staged.

ENVIRONMENT:
  SAC_MIN_BLOCK_SEVERITY  min severity reported / blocking (default: medium)
  SAC_HOOK_DEBUG=1        verbose logging to stderr
"""

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# =============================================================================
# CONFIGURATION
# =============================================================================

SNYK_STUDIO_VERSION = "1.0.6"
DEBUG = os.environ.get("SAC_HOOK_DEBUG", "0") == "1"
_IS_WINDOWS = sys.platform == "win32"


def _supports_color() -> bool:
    """ANSI colors on stderr when it's a real terminal and NO_COLOR isn't set.

    Honours the NO_COLOR convention (no-color.org) so CI logs and piped
    output stay plain. Re-checked each call so tests can patch ``isatty``.
    """
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(sys.stderr, "isatty") and sys.stderr.isatty()


CODE_EXTENSIONS = {
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".py",
    ".java",
    ".kt",
    ".kts",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".vb",
    ".swift",
    ".m",
    ".mm",
    ".scala",
    ".rs",
    ".c",
    ".cpp",
    ".cc",
    ".h",
    ".hpp",
    ".cls",
    ".trigger",
    ".ex",
    ".exs",
    ".groovy",
    ".dart",
}

MANIFEST_FILES = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
    "build.sbt",
    "Gemfile",
    "Gemfile.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "packages.config",
    "packages.lock.json",
    "composer.json",
    "composer.lock",
    "Podfile",
    "Podfile.lock",
    "Package.swift",
    "Package.resolved",
    "mix.exs",
    "mix.lock",
    "pubspec.yaml",
    "pubspec.lock",
}

MANIFEST_SUFFIXES = {".csproj", ".lock", ".fsproj", ".vbproj"}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

EXIT_OK = 0
EXIT_BLOCK = 1
EXIT_PREREQ = 2


# =============================================================================
# LOGGING
# =============================================================================


def log(message: str) -> None:
    """User-visible log line on stderr (pre-commit hook output)."""
    print(f"[SAC] {message}", file=sys.stderr)


def debug(message: str) -> None:
    if DEBUG:
        print(f"[SAC DEBUG] {message}", file=sys.stderr)


def _norm(p: str) -> str:
    """Normalize a path for cross-platform / cross-tool comparison.

    Converts backslashes to forward slashes (Snyk on Windows may report
    backslashed paths; git always uses forward slashes) and strips a
    leading ``./`` relative-path marker if present.

    We deliberately do NOT use ``str.lstrip("./")`` here: ``lstrip`` takes
    a *character set*, not a literal prefix, so it would eat any leading
    ``.`` or ``/``. A dotfile in the repo root (``.env``, ``.gitignore``,
    ``.eslintrc``) would be normalised to ``env`` / ``gitignore`` /
    ``eslintrc`` and produce false-positive vulnerability matches against
    unrelated files. The explicit ``startswith("./")`` check below preserves
    leading dots while still stripping the relative-path marker.
    """
    p = p.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


# =============================================================================
# GIT INTEGRATION
# =============================================================================


def find_repo_root(start: Path) -> Optional[Path]:
    """Walk up from start looking for a .git entry (dir or worktree file)."""
    try:
        cur = start.resolve()
    except OSError:
        return None
    for parent in [cur, *cur.parents]:
        if (parent / ".git").exists():
            return parent
    return None


def get_staged_files(repo_root: Path) -> Optional[List[str]]:
    """Return paths (relative to *repo_root*) staged for commit, or ``None``
    if we couldn't determine the staged set.

    Uses ``git diff --cached --name-only --diff-filter=ACMR -z`` so deleted
    and untracked files are excluded and paths are NUL-separated to handle
    spaces and other special characters.

    A ``None`` return distinguishes "git diff failed" (transient OS error,
    a locked index, git not on PATH, …) from "no files staged" (an empty
    list). The caller fail-closes on ``None`` and exits with
    ``EXIT_PREREQ``: a security hook must NOT silently let a commit through
    when it can't reason about what's about to land. The cost of a false
    positive (a developer who legitimately has no staged files) is much
    lower than a false negative (a real vulnerability sneaking past
    because git was temporarily broken).
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
            capture_output=True,
            text=True,
            cwd=repo_root,
            check=False,
        )
    except OSError as e:
        log(f"git diff failed: {e}")
        return None
    if result.returncode != 0:
        log(f"git diff exited {result.returncode}: {result.stderr.strip()}")
        return None
    return [p for p in result.stdout.split("\0") if p]


def classify_staged(staged: List[str]) -> Tuple[List[str], List[str]]:
    """Split staged files into (code_files, manifest_files)."""
    code: List[str] = []
    manifests: List[str] = []
    for path in staged:
        name = Path(path).name
        suffix = Path(path).suffix.lower()
        if suffix in CODE_EXTENSIONS:
            code.append(path)
        if name in MANIFEST_FILES or suffix in MANIFEST_SUFFIXES:
            manifests.append(path)
    return code, manifests


# =============================================================================
# VULNERABILITY FILTERING
# =============================================================================


def _staged_set(staged: List[str]) -> Set[str]:
    return {_norm(p) for p in staged}


def _vuln_path_matches(vuln_path: str, staged_norm: Set[str]) -> bool:
    """Match a Snyk-reported file path against the set of staged files.

    Both ``git diff --cached`` (the staged-file source) and the Snyk scans
    run with ``cwd=repo_root``, so both produce repo-root-relative paths.
    Compare them as exact normalised strings. We intentionally do NOT
    suffix-match: in monorepos with duplicate basenames (e.g.
    ``pkg/api/main.go`` vs ``cmd/api/main.go``) a suffix match would treat a
    vulnerability in the unstaged copy as belonging to the staged one and
    block the commit on a false positive.
    """
    return _norm(vuln_path) in staged_norm


def filter_sast_vulns(
    vulns: List[Dict[str, Any]], staged: Optional[List[str]]
) -> List[Dict[str, Any]]:
    """Keep only SAST vulns whose file_path matches a staged file.

    Passing ``staged=None`` disables the filter — every vuln is returned.
    That's the full-repo mode the script uses when invoked without
    ``--staged``. An *empty* list still means "filter to nothing".
    """
    if staged is None:
        return list(vulns)
    if not staged:
        return []
    staged_norm = _staged_set(staged)
    return [v for v in vulns if _vuln_path_matches(v.get("file_path", ""), staged_norm)]


def _severity_blocks(severity: str) -> bool:
    threshold = os.environ.get("SAC_MIN_BLOCK_SEVERITY", "medium").lower()
    if threshold not in _SEVERITY_ORDER:
        threshold = "medium"
    return _SEVERITY_ORDER.get(severity.lower(), 4) <= _SEVERITY_ORDER[threshold]


def filter_sca_vulns(
    vulns: List[Dict[str, Any]], staged_manifests: Optional[List[str]]
) -> List[Dict[str, Any]]:
    """Keep SCA vulns whose ``target_file`` matches a staged manifest.

    Snyk reports a per-project ``targetFile`` (e.g. ``package.json``,
    ``services/auth/go.mod``) — in a monorepo that lets us drop vulns from
    projects whose manifest wasn't staged. Without this filter, staging a
    manifest for Project A could surface unrelated existing vulns from
    Project B, inconsistent with how SAST is filtered to staged files.
    The severity gate still applies on top.

    Passing ``staged_manifests=None`` disables the manifest filter — every
    project's vulns become eligible — but the severity gate still applies.
    That's the full-repo mode the script uses without ``--staged``.
    """
    if staged_manifests is None:
        return [v for v in vulns if _severity_blocks(v.get("severity", ""))]
    if not staged_manifests:
        return []
    staged_norm = _staged_set(staged_manifests)
    return [
        v
        for v in vulns
        if _norm(v.get("target_file", "")) in staged_norm
        and _severity_blocks(v.get("severity", ""))
    ]


# =============================================================================
# SNYK CLI DISCOVERY
# =============================================================================
#
# When git is invoked from a GUI tool (GitHub Desktop, SourceTree, JetBrains
# IDEs) the inherited PATH may not include the directory holding the snyk
# binary (e.g. an nvm-managed node, ~/.volta/bin, /opt/homebrew/bin). We probe
# the usual install locations and prepend the first hit to PATH so the
# subsequent ``snyk`` invocations resolve.

_SNYK_BINARY_NAMES = ["snyk.cmd", "snyk.exe", "snyk"] if _IS_WINDOWS else ["snyk"]


def _snyk_search_paths_unix(env: Dict[str, str]) -> List[str]:
    candidates: List[str] = []
    nvm_dir = env.get("NVM_DIR", os.path.expanduser("~/.nvm"))
    candidates.extend(
        sorted(
            glob.glob(os.path.join(nvm_dir, "versions", "node", "*", "bin")),
            reverse=True,
        )
    )
    candidates.append(os.path.expanduser("~/.volta/bin"))
    candidates.extend(["/usr/local/bin", "/opt/homebrew/bin"])
    return candidates


def _snyk_search_paths_windows(env: Dict[str, str]) -> List[str]:
    candidates: List[str] = []
    appdata = env.get("APPDATA", os.environ.get("APPDATA", ""))
    if appdata:
        nvm_root = os.path.join(appdata, "nvm")
        candidates.extend(sorted(glob.glob(os.path.join(nvm_root, "v*")), reverse=True))
        candidates.append(os.path.join(appdata, "npm"))
    local_appdata = env.get("LOCALAPPDATA", os.environ.get("LOCALAPPDATA", ""))
    if local_appdata:
        candidates.append(os.path.join(local_appdata, "Volta", "bin"))
    userprofile = env.get("USERPROFILE", os.environ.get("USERPROFILE", ""))
    if userprofile:
        candidates.append(os.path.join(userprofile, "scoop", "shims"))
    choco = env.get("ChocolateyInstall", os.environ.get("ChocolateyInstall", ""))
    if choco:
        candidates.append(os.path.join(choco, "bin"))
    program_files = env.get("ProgramFiles", os.environ.get("ProgramFiles", ""))
    if program_files:
        candidates.append(os.path.join(program_files, "Snyk"))
    return candidates


def _augment_path_for_snyk(env: Dict[str, str]) -> None:
    if shutil.which("snyk", path=env.get("PATH", "")):
        return
    search = _snyk_search_paths_windows(env) if _IS_WINDOWS else _snyk_search_paths_unix(env)
    for bin_dir in search:
        for name in _SNYK_BINARY_NAMES:
            if os.path.isfile(os.path.join(bin_dir, name)):
                env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
                return


def find_snyk_binary() -> Optional[str]:
    env = os.environ.copy()
    _augment_path_for_snyk(env)
    for name in _SNYK_BINARY_NAMES:
        found = shutil.which(name, path=env.get("PATH", ""))
        if found:
            return str(found)
    return None


def _snyk_config_path() -> str:
    """Resolve the path to Snyk's ``configstore`` JSON file.

    The Snyk CLI uses the npm ``configstore`` package, which honours
    ``$XDG_CONFIG_HOME`` and falls back to ``~/.config/`` on every platform
    (Linux, macOS, **and Windows** — configstore deliberately uses the
    XDG-style layout under ``%USERPROFILE%\\.config\\`` on Windows too).
    Reading the env var explicitly here keeps us correct for users who
    relocate their XDG config home, and surfaces intent more clearly than
    hardcoding the Unix-looking default.
    """
    config_dir = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )
    return os.path.join(config_dir, "configstore", "snyk.json")


def check_snyk_auth() -> Optional[str]:
    """Returns the API token (or oauth sentinel) when authed, else None."""
    token = os.environ.get("SNYK_TOKEN")
    if token:
        return token
    try:
        with open(_snyk_config_path()) as f:
            config = json.load(f)
    except (OSError, json.JSONDecodeError, FileNotFoundError):
        return None
    api_key = config.get("api")
    if api_key and isinstance(api_key, str):
        return api_key
    if config.get("INTERNAL_OAUTH_TOKEN_STORAGE"):
        return "__oauth__"
    return None


# =============================================================================
# SARIF / SNYK-TEST JSON PARSING
# =============================================================================


def parse_sast_results(json_output: str) -> List[Dict[str, Any]]:
    """Parse Snyk Code SARIF JSON output into a list of vuln dicts."""
    vulnerabilities: List[Dict[str, Any]] = []
    try:
        data = json.loads(json_output)
    except json.JSONDecodeError:
        return vulnerabilities

    for run in data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            message = result.get("message", {}).get("text", "")

            level = result.get("level", "warning")
            severity = {"error": "high", "warning": "medium", "note": "low"}.get(level, "medium")

            properties = result.get("properties", {})
            if "priorityScore" in properties:
                score = properties["priorityScore"]
                if score >= 700:
                    severity = "critical"
                elif score >= 500:
                    severity = "high"
                elif score >= 300:
                    severity = "medium"
                else:
                    severity = "low"

            cwe_list = properties.get("cwe", [])
            cwe = cwe_list[0] if cwe_list else None

            for loc in result.get("locations", []):
                phys_loc = loc.get("physicalLocation", {})
                artifact = phys_loc.get("artifactLocation", {})
                region = phys_loc.get("region", {})
                vulnerabilities.append(
                    {
                        "id": rule_id,
                        "title": rule_id.replace("/", " - ").replace("_", " ").title(),
                        "severity": severity,
                        "cwe": cwe,
                        "file_path": artifact.get("uri", "unknown"),
                        "start_line": region.get("startLine", 0),
                        "start_column": region.get("startColumn", 0),
                        "end_line": region.get("endLine", region.get("startLine", 0)),
                        "message": message,
                    }
                )
    return vulnerabilities


def parse_sca_results(json_output: str) -> List[Dict[str, Any]]:
    """Parse ``snyk test --json`` output (single project or monorepo array).

    Each vuln carries its project's ``target_file`` (the path to the manifest
    Snyk resolved for that project, e.g. ``package.json`` or
    ``services/auth/go.mod``) so downstream filtering can keep only vulns
    whose manifest is in the staged set. Dedup includes ``target_file`` so
    the same package vuln in two projects of a monorepo stays as two
    entries — each can be matched against its own staged manifest.
    """
    vulnerabilities: List[Dict[str, Any]] = []
    try:
        data = json.loads(json_output)
    except json.JSONDecodeError:
        return vulnerabilities

    projects = data if isinstance(data, list) else [data]
    seen: Set[Tuple[str, str, str, str]] = set()
    for project in projects:
        if not isinstance(project, dict):
            continue
        target_file = project.get("displayTargetFile") or project.get("targetFile") or ""
        for vuln in project.get("vulnerabilities", []):
            pkg_name = vuln.get("packageName", "")
            version = vuln.get("version", "")
            vuln_id = vuln.get("id", "")
            dedup_key = (vuln_id, pkg_name, version, target_file)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            identifiers = vuln.get("identifiers") or {}
            cve_list = identifiers.get("CVE", [])
            cve = cve_list[0] if cve_list else None

            fixed_in = vuln.get("fixedIn", [])
            fix_available = bool(vuln.get("isUpgradable") or vuln.get("isPatchable") or fixed_in)

            # Snyk's `from` array walks the dep tree from the project root
            # down to the vulnerable package. Strip the root (first entry,
            # the project itself) and the leaf (last entry, the vulnerable
            # package — already shown in the main line) so what remains is
            # exactly the chain of intermediate hops that introduced the
            # vuln. For a direct dependency this leaves an empty list,
            # which the formatter uses to suppress the `via:` annotation.
            from_chain = vuln.get("from") or []
            intro_chain = [str(hop) for hop in from_chain[1:-1]]

            vulnerabilities.append(
                {
                    "id": vuln_id,
                    "title": vuln.get("title", vuln_id),
                    "package_name": pkg_name,
                    "version": version,
                    "severity": vuln.get("severity", "unknown"),
                    "cve": cve,
                    "fix_available": fix_available,
                    "target_file": target_file,
                    "intro_chain": intro_chain,
                }
            )
    return vulnerabilities


# =============================================================================
# SNYK INVOCATIONS
# =============================================================================


_AUTH_ERROR_PATTERNS = (
    "missingapitokenerror",
    "not authenticated",
    "authentication required",
    "snyk-0005",
)


def _snyk_env() -> Dict[str, str]:
    env = os.environ.copy()
    _augment_path_for_snyk(env)
    env["SNYK_INTEGRATION_NAME"] = "STUDIO"
    env["SNYK_INTEGRATION_VERSION"] = SNYK_STUDIO_VERSION
    env["SNYK_INTEGRATION_ENVIRONMENT"] = "git_precommit"
    env["SNYK_INTEGRATION_ENVIRONMENT_VERSION"] = SNYK_STUDIO_VERSION
    try:
        _device_id = os.path.join(os.path.expanduser("~"), ".snyk-studio", "device-id")
        _machine_id = open(_device_id, encoding="utf-8-sig").read().strip()
        if _machine_id:
            env["INTERNAL_SNYK_CLIENT_MACHINE_ID"] = _machine_id
    except Exception:
        pass

    return env


def _classify_snyk_failure(stderr: str, stdout: str) -> str:
    combined = (stderr + stdout).lower()
    if any(p in combined for p in _AUTH_ERROR_PATTERNS):
        return "auth_required"
    return "error"


def run_sast_scan(workspace: Path, snyk_bin: str) -> Tuple[str, List[Dict[str, Any]]]:
    log("running snyk code test...")
    try:
        result = subprocess.run(
            [snyk_bin, "code", "test", ".", "--json"],
            capture_output=True,
            text=True,
            cwd=workspace,
            env=_snyk_env(),
            check=False,
        )
    except OSError as e:
        log(f"snyk code test failed to launch: {e}")
        return "error", []
    if result.returncode > 1:
        status = _classify_snyk_failure(result.stderr, result.stdout)
        debug(f"snyk code test exit={result.returncode}, stderr={result.stderr[:300]}")
        return status, []
    return "success", parse_sast_results(result.stdout)


def run_sca_scan(workspace: Path, snyk_bin: str) -> Tuple[str, List[Dict[str, Any]]]:
    log("running snyk test...")
    try:
        result = subprocess.run(
            [snyk_bin, "test", ".", "--json"],
            capture_output=True,
            text=True,
            cwd=workspace,
            env=_snyk_env(),
            check=False,
        )
    except OSError as e:
        log(f"snyk test failed to launch: {e}")
        return "error", []
    if result.returncode > 1:
        status = _classify_snyk_failure(result.stderr, result.stdout)
        debug(f"snyk test exit={result.returncode}, stderr={result.stderr[:300]}")
        return status, []
    return "success", parse_sca_results(result.stdout)


# =============================================================================
# REPORT FORMATTING
# =============================================================================


# Compiler-style output: one line per finding, no headers, parseable by
# editors that recognise the MSVC `file(line,column)` diagnostic form
# (including VS Code's Problems panel and most editor lint integrations).
# Colors are applied only when stderr is an interactive terminal.

_ANSI_RESET = "\033[0m"
_SEVERITY_ANSI = {
    "critical": "\033[1;31m",  # bold red
    "high": "\033[31m",  # red
    "medium": "\033[33m",  # yellow
    "low": "\033[36m",  # cyan
}


def _colorize_severity(severity: str, color: bool) -> str:
    if not color:
        return severity
    ansi = _SEVERITY_ANSI.get(severity.lower())
    return f"{ansi}{severity}{_ANSI_RESET}" if ansi else severity


def _fmt_sast_finding_only(v: Dict[str, Any], color: bool) -> str:
    """Bracketed tokens for one SAST finding — no location prefix.

    Used as the leaf of a per-location group so we don't repeat
    ``file(line,column):`` when multiple rules flag the same expression.
    """
    return (
        f"[{_colorize_severity(v.get('severity', '?'), color)}] "
        f"[{v.get('id', '?')}] "
        f"[{v.get('cwe') or '-'}] "
        f"[{v.get('title', '?')}]"
    )


def _fmt_sast_group(
    file_path: str,
    line: int,
    column: int,
    findings: List[Dict[str, Any]],
    color: bool,
) -> str:
    """Render every finding tied to a single ``(file, line, column)``.

    Layout mirrors the SCA group form for consistency:

      - 1 finding:
            ``file(line,col): [sev] [id] [cwe] [title]``
        (compact single-line MSVC-style diagnostic, parseable by editors)

      - N findings at the same location:
            ``file(line,col):``
            ``  [sev] [id] [cwe] [title]``  (sorted by severity, worst first)
            ``  ...``

    Multiple findings at the same (file, line, column) typically mean several
    rules flagged the same expression — collapsing them under one header
    keeps the report scannable.
    """
    header = f"{file_path}({line},{column}):"
    if len(findings) == 1:
        return f"{header} {_fmt_sast_finding_only(findings[0], color)}"
    findings_sorted = sorted(
        findings, key=lambda v: _SEVERITY_ORDER.get(v.get("severity", "low"), 4)
    )
    lines = [header]
    for v in findings_sorted:
        lines.append(f"  {_fmt_sast_finding_only(v, color)}")
    return "\n".join(lines)


def _fmt_sca_finding_only(v: Dict[str, Any], color: bool) -> str:
    """Bracketed tokens for one SCA finding — no location prefix.

    Used as the leaf of a per-package group so we don't repeat the
    ``manifest(pkg@version):`` header for every CVE attached to the same
    vulnerable package.
    """
    fix = "fix available" if v.get("fix_available") else "no fix"
    return (
        f"[{_colorize_severity(v.get('severity', '?'), color)}] "
        f"[{v.get('id', '?')}] "
        f"[{v.get('cve') or '-'}] "
        f"[{v.get('title', '?')}] "
        f"[{fix}]"
    )


def _fmt_sca_group(
    target_file: str,
    package_name: str,
    version: str,
    findings: List[Dict[str, Any]],
    color: bool,
) -> str:
    """Render every finding tied to a single vulnerable ``package@version``.

    Layout — chosen to keep direct-dependency reports terse while still
    expressing how an indirect vuln was introduced:

      - 1 direct finding (no intro chain):
            ``manifest(pkg@ver): [sev] [id] [cve] [title] [fix-info]``
        (single line, scannable in compiler-style output)

      - any other case — multiple findings OR a non-empty intro chain:
            ``manifest(pkg@ver):``
            ``  via: A > B``                  (one per distinct chain)
            ``    [sev] [id] [cve] [title] [fix-info]``  (findings under it)

    Findings sharing a chain are collapsed under one ``via:`` line so the
    chain isn't repeated for every CVE in the same package. Direct findings
    in a multi-finding group sit under the header with no ``via:`` prefix.
    """
    header = f"{target_file}({package_name}@{version}):"

    # Compact single-line form for the common case: 1 finding, direct dep.
    if len(findings) == 1 and not findings[0].get("intro_chain"):
        return f"{header} {_fmt_sca_finding_only(findings[0], color)}"

    by_chain: Dict[Tuple[str, ...], List[Dict[str, Any]]] = {}
    for v in findings:
        chain_key = tuple(v.get("intro_chain") or [])
        by_chain.setdefault(chain_key, []).append(v)

    # Direct findings (empty chain) print under the header first; then
    # chains by length then alphabetically for stable ordering.
    chain_order = sorted(by_chain.keys(), key=lambda c: (len(c), c))

    lines = [header]
    for chain in chain_order:
        chain_findings = sorted(
            by_chain[chain], key=lambda v: _SEVERITY_ORDER.get(v.get("severity", "low"), 4)
        )
        if chain:
            lines.append(f"  via: {' > '.join(chain)}")
            for v in chain_findings:
                lines.append(f"    {_fmt_sca_finding_only(v, color)}")
        else:
            for v in chain_findings:
                lines.append(f"  {_fmt_sca_finding_only(v, color)}")
    return "\n".join(lines)


def _print_block_reason(
    sast_vulns: List[Dict[str, Any]],
    sca_vulns: List[Dict[str, Any]],
    sast_fallback: str,
    sca_fallback: str,
    staged_mode: bool = True,
) -> None:
    color = _supports_color()

    # Group SAST findings by their exact source location so multiple rules
    # flagging the same expression collapse under one ``file(line,col):``
    # header. Group order, in priority:
    #   1. worst severity in the group (asc rank — critical first).
    #   2. group size (desc) — locations with the most findings rise so
    #      hotspots surface near the top of the report.
    #   3. file_path, line, column — stable tiebreakers.
    sast_groups: Dict[Tuple[str, int, int], List[Dict[str, Any]]] = {}
    for v in sast_vulns:
        key = (
            v.get("file_path", ""),
            v.get("start_line", 0),
            v.get("start_column", 0),
        )
        sast_groups.setdefault(key, []).append(v)
    sorted_sast_keys = sorted(
        sast_groups.keys(),
        key=lambda k: (
            min(_SEVERITY_ORDER.get(v.get("severity", "low"), 4) for v in sast_groups[k]),
            -len(sast_groups[k]),
            k[0],
            k[1],
            k[2],
        ),
    )
    for key in sorted_sast_keys:
        file_path, line, column = key
        print(_fmt_sast_group(file_path, line, column, sast_groups[key], color), file=sys.stderr)

    # Group SCA findings by the vulnerable (target_file, package@version) so
    # the same header isn't repeated for every CVE attached to the same
    # vulnerable package. Group order, in priority:
    #   1. dependency depth (asc) — direct deps come first because the dev
    #      can actually upgrade them; deeply nested transitives come last
    #      since they usually wait on an upstream release.
    #   2. worst severity in the group (asc rank — critical first).
    #   3. group size (desc) — packages with more findings rise so the
    #      most-leveraged upgrades surface near the top of the report.
    #   4. manifest path, then package name — stable tiebreakers so the
    #      same input always produces the same output.
    sca_groups: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    for v in sca_vulns:
        key = (
            v.get("target_file", ""),
            v.get("package_name", "?"),
            v.get("version", "?"),
        )
        sca_groups.setdefault(key, []).append(v)
    sorted_keys = sorted(
        sca_groups.keys(),
        key=lambda k: (
            min(len(v.get("intro_chain") or []) for v in sca_groups[k]),
            min(_SEVERITY_ORDER.get(v.get("severity", "low"), 4) for v in sca_groups[k]),
            -len(sca_groups[k]),
            k[0],
            k[1],
        ),
    )
    for key in sorted_keys:
        target_file, pkg, ver = key
        print(_fmt_sca_group(target_file, pkg, ver, sca_groups[key], color), file=sys.stderr)

    if sast_fallback:
        print(sast_fallback, file=sys.stderr)
    if sca_fallback:
        print(sca_fallback, file=sys.stderr)

    total = len(sast_vulns) + len(sca_vulns)
    if total:
        if staged_mode:
            print(
                f"snyk: {total} issue(s) blocking commit; bypass with `git commit --no-verify`",
                file=sys.stderr,
            )
        else:
            print(f"snyk: {total} issue(s) found", file=sys.stderr)


# =============================================================================
# MAIN
# =============================================================================


def parse_cli_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """CLI argument parser.

    The single flag is ``--staged``, which switches the script from the
    full-repo audit mode (default) to the pre-commit filtering mode the
    installer wires up.
    """
    parser = argparse.ArgumentParser(
        prog="snyk_secure_at_commit",
        description=(
            "Run Snyk Code (SAST) and Snyk Open Source (SCA) against a workspace "
            "and report findings."
        ),
        epilog=(
            "Without --staged, the entire workspace is scanned. With --staged "
            "(the form the installer wires into pre-commit), findings are "
            "filtered to files staged for commit."
        ),
    )
    parser.add_argument(
        "--staged",
        action="store_true",
        help=(
            "pre-commit mode: only report findings in files staged for commit "
            "(SAST filtered to staged code files, SCA filtered to staged manifests)"
        ),
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_cli_args(argv)
    cwd = Path.cwd()

    # In --staged mode we *must* be inside a git repo (it's where the staged
    # file list comes from). In full-repo mode we walk up looking for one
    # but fall back to cwd so the script also works on ad-hoc folders.
    repo_root = find_repo_root(cwd)
    if args.staged:
        # Fail-closed on every prerequisite needed to compute the staged
        # set: a security gate must NOT let a commit through silently
        # because git was unreachable or the repo couldn't be found.
        if repo_root is None:
            log("--staged requested but not inside a git repository")
            return EXIT_PREREQ
        staged = get_staged_files(repo_root)
        debug(f"staged files: {staged}")
        if staged is None:
            log("could not determine staged files; blocking commit (fail-closed)")
            return EXIT_PREREQ
        if not staged:
            log("no staged files, skipping scan")
            return EXIT_OK
        staged_code: Optional[List[str]]
        staged_manifests: Optional[List[str]]
        staged_code, staged_manifests = classify_staged(staged)
        debug(f"staged code: {staged_code}")
        debug(f"staged manifests: {staged_manifests}")
        if not staged_code and not staged_manifests:
            log("no scannable files staged, skipping scan")
            return EXIT_OK
    else:
        if repo_root is None:
            repo_root = cwd
        # None signals "no filter" to filter_sast_vulns / filter_sca_vulns.
        staged_code = None
        staged_manifests = None

    snyk_bin = find_snyk_binary()
    if snyk_bin is None:
        log("Snyk CLI not found on PATH — install with `npm install -g snyk`")
        return EXIT_PREREQ
    if check_snyk_auth() is None:
        log("Snyk CLI not authenticated — run `snyk auth`")
        return EXIT_PREREQ

    if args.staged:
        log(
            f"--staged: scanning {len(staged_code or [])} code file(s)"
            + (f", {len(staged_manifests)} manifest file(s)" if staged_manifests else "")
        )
    else:
        log(f"scanning workspace {repo_root}")

    sast_vulns: List[Dict[str, Any]] = []
    sca_vulns: List[Dict[str, Any]] = []
    sast_fallback = ""
    sca_fallback = ""

    # In --staged mode we skip scans whose staged-set is empty (no staged
    # code → no need to run SAST; no staged manifest → no need to run SCA).
    # In full-repo mode the staged_* lists are None so both scans run.
    should_run_sast = staged_code is None or len(staged_code) > 0
    should_run_sca = staged_manifests is None or len(staged_manifests) > 0

    # SAST and SCA shell out to independent Snyk CLI invocations, so we fan
    # them out across two threads. The threads sit blocked in subprocess
    # wait() — CPython releases the GIL there, so the two snyk processes run
    # in true parallel and the latency is max(SAST, SCA) rather than SAST + SCA.
    with ThreadPoolExecutor(max_workers=2) as executor:
        sast_future = (
            executor.submit(run_sast_scan, repo_root, snyk_bin) if should_run_sast else None
        )
        sca_future = executor.submit(run_sca_scan, repo_root, snyk_bin) if should_run_sca else None

        if sast_future is not None:
            status, all_vulns = sast_future.result()
            if status == "success":
                sast_vulns = filter_sast_vulns(all_vulns, staged_code)
                log(f"SAST: {len(sast_vulns)} issue(s)")
            elif status == "auth_required":
                sast_fallback = "Snyk CLI is not authenticated. Run `snyk auth` and re-run."
            else:
                sast_fallback = "Snyk Code scan did not complete. Run `snyk code test` manually."

        if sca_future is not None:
            status, all_vulns = sca_future.result()
            if status == "success":
                sca_vulns = filter_sca_vulns(all_vulns, staged_manifests)
                log(f"SCA: {len(sca_vulns)} issue(s)")
            elif status == "auth_required":
                sca_fallback = "Snyk CLI is not authenticated. Run `snyk auth` and re-run."
            else:
                sca_fallback = "Snyk Open Source scan did not complete. Run `snyk test` manually."

    if not (sast_vulns or sca_vulns or sast_fallback or sca_fallback):
        log("no vulnerabilities found")
        return EXIT_OK

    _print_block_reason(sast_vulns, sca_vulns, sast_fallback, sca_fallback, staged_mode=args.staged)
    return EXIT_BLOCK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("interrupted")
        sys.exit(EXIT_BLOCK)
