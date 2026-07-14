#!/usr/bin/env python3
"""
Snyk Studio Recipes Installer
==============================

Cross-platform installer for Snyk security recipes.
Installs skills, hooks, rules, commands, and MCP configs
into Cursor, Claude Code, and/or Gemini Code global directories.

Usage:
    python snyk-studio-installer.py [options]

Options:
    --profile <name>                           Installation profile (default, minimal, experimental)
    --ade <cursor|claude|gemini|windsurf|kiro> Target specific ADE (auto-detect if omitted)
    --workspace <path>                         Workspace root for workspace-scoped recipes
                                               (defaults to the enclosing git repo; skipped if neither)
    --dry-run                                  Show what would be installed without making changes
    --uninstall                                Remove Snyk recipes from detected ADEs
    --verify                                   Verify installed files and merged configs match manifest
    --read-only                                With --verify, only report prerequisite versions instead
                                               of offering to install/upgrade them
    --list                                     List available recipes and profiles
    --no-latest-deps                           Install pinned manifest dependency versions,
                                               upgrading only if missing or older than the pin
    --control-identifier <id>                  Machine/control identifier to record
    --diag-dump                                Create a diagnostic zip for Snyk support and print its path.
    --out-file <path>                          Output path for the diagnostic zip (default: timestamped zip in cwd).
    --days N                                   Include logs from workspaces active in the last N days (default: 1, minimum: 1).
    -y, --yes                                  Skip confirmation prompts
    -h, --help                                 Show this help message
"""

import argparse
import contextlib
import filecmp
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from subprocess import run
from typing import Any, Dict, Iterator, List, Optional, Tuple, cast

# When set (by generated install.sh / install.ps1 / install.py), manifest and recipe sources
# live under this directory (flat layout from the release zip).
BUNDLE_ENV = "SNYK_STUDIO_BUNDLE_ROOT"

GLOBAL = "global"
WORKSPACE = "workspace"

_IS_WINDOWS = sys.platform == "win32"

# Windows-only setup:
# - CREATE_NO_WINDOW suppresses the console window that would otherwise pop up
#   when the installer (running inside a GUI ADE with no attached console)
#   spawns a subprocess via shell=True. Elsewhere the flag is 0 (no-op).
# - stdout/stderr reconfigure: when stdout isn't a console (e.g. piped by a CI
#   runner), Python defaults to the active code page (cp1252 on most locales),
#   which can't encode the box-drawing chars in the banner and separators.
#   UTF-8 covers every char we emit; the try/except keeps unusual stream
#   replacements (test doubles, GUI wrappers) safe.
_CREATE_NO_WINDOW = 0
if _IS_WINDOWS:
    _CREATE_NO_WINDOW = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="backslashreplace")  # type: ignore[union-attr]
        except Exception:
            pass


# =============================================================================
# COLOR OUTPUT
# =============================================================================


class Color:
    """ANSI color codes with auto-detection of terminal support."""

    def __init__(self):
        self.enabled = self._detect()

    def _detect(self) -> bool:
        if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
            return False
        if _IS_WINDOWS:
            try:
                import ctypes

                kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
                handle = kernel32.GetStdHandle(-11)
                mode = ctypes.c_ulong()
                kernel32.GetConsoleMode(handle, ctypes.byref(mode))
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
                return True
            except Exception:
                return False
        return True

    def _w(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def red(self, t: str) -> str:
        return self._w("0;31", t)

    def green(self, t: str) -> str:
        return self._w("0;32", t)

    def yellow(self, t: str) -> str:
        return self._w("1;33", t)

    def cyan(self, t: str) -> str:
        return self._w("0;36", t)

    def bold(self, t: str) -> str:
        return self._w("1", t)

    def dim(self, t: str) -> str:
        return self._w("2", t)

    def underline(self, t: str) -> str:
        return self._w("4", t)


C = Color()


# =============================================================================
# ARGUMENT PARSING
# =============================================================================


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="snyk-studio-installer",
        description="Snyk Studio Recipes Installer",
    )
    parser.add_argument(
        "--profile", default="default", help="Installation profile (default: 'default')"
    )
    parser.add_argument(
        "--ade",
        choices=[
            "cursor",
            "claude",
            "gemini",
            "kiro",
            "codex",
            "windsurf",
            "copilot-cli",
            "copilot-vscode",
        ],
        default=None,
        help="Target specific ADE (auto-detect if omitted)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be installed without making changes"
    )
    parser.add_argument(
        "--uninstall", action="store_true", help="Remove Snyk recipes from detected ADEs"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify installed files and merged configs match manifest",
    )
    parser.add_argument(
        "--read-only",
        action="store_true",
        dest="read_only",
        help=(
            "With --verify, only report prerequisite versions instead of "
            "offering to install/upgrade them. Guarantees --verify never "
            "makes changes."
        ),
    )
    parser.add_argument(
        "--list", action="store_true", dest="list_mode", help="List available recipes and profiles"
    )
    parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompts")
    parser.add_argument(
        "--no-latest-deps",
        action="store_true",
        help=(
            "Install the dependency versions from the manifest prerequisites, "
            "upgrading only dependencies that are missing or older."
        ),
    )
    parser.add_argument(
        "--workspace",
        default=None,
        help=(
            "Workspace root for workspace-scoped recipes (e.g. sac-hooks). "
            "If omitted, the installer walks up from the current directory looking "
            "for a git repository; if none is found, workspace-scoped recipes are "
            "skipped."
        ),
    )
    parser.add_argument(
        "--control-identifier",
        default=None,
        dest="control_identifier",
        help=("Machine/control identifier to record."),
    )
    parser.add_argument(
        "--diag-dump",
        action="store_true",
        dest="diag_dump",
        help="Create a diagnostic zip for Snyk support and print its path.",
    )
    parser.add_argument(
        "--out-file",
        default=None,
        dest="out_file",
        metavar="PATH",
        help="Output path for the diagnostic zip (default: timestamped zip in cwd).",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=1,
        metavar="N",
        help="Include logs from workspaces active in the last N days (default: 1, minimum: 1).",
    )
    return parser.parse_args(argv)


# =============================================================================
# PAYLOAD CONTEXT
# =============================================================================


class PayloadContext:
    """Manages the payload directory — repo checkout (dev) or extracted zip (dist)."""

    def __init__(self):
        self.payload_dir = Path()
        self.repo_root = Path()

    def setup(self) -> None:
        bundle = os.environ.get(BUNDLE_ENV, "").strip()
        if bundle:
            root = Path(bundle).resolve()
            if not root.is_dir():
                print(f"Error: {BUNDLE_ENV} is not a directory: {root}", file=sys.stderr)
                sys.exit(1)
            self.payload_dir = root
            self.repo_root = root
            return
        self.payload_dir = Path(__file__).resolve().parent
        self.repo_root = self.payload_dir.parent

    def cleanup(self) -> None:
        """Reserved for future temp-bundle cleanup; tests may call after setup."""

    @property
    def manifest_path(self) -> Path:
        return self.payload_dir / "manifest.json"

    def resolve_src(self, src_relative: str) -> Path:
        if not str(src_relative).strip():
            print("Error: empty source path in manifest.", file=sys.stderr)
            sys.exit(1)
        rel = Path(src_relative)
        if rel.is_absolute():
            print(f"Error: absolute source path not allowed: {src_relative!r}", file=sys.stderr)
            sys.exit(1)
        root = self.repo_root.resolve()
        candidate = (root / rel).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            print(
                f"Error: manifest source path escapes bundle root: {src_relative!r}",
                file=sys.stderr,
            )
            sys.exit(1)
        return candidate


# =============================================================================
# MANIFEST
# =============================================================================


def jsonc_loads(text: str) -> Any:
    """Parse JSONC (JSON-with-comments) as used by VS Code / Cursor settings files.

    Strips ``/* ... */`` block comments and trailing commas before delegating to
    :func:`json.loads`. Used consistently on both the conflict-detection (read)
    and conflict-resolution (write) paths so a JSONC settings file that is
    flagged as conflicting can also be updated.
    """
    # Strip block comments
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    # Strip trailing commas before closing braces/brackets
    text = re.sub(r",\s*([\]}])", r"\1", text)
    return json.loads(text)


class Manifest:
    """Parsed manifest.json with profile resolution."""

    EXECUTION_FREQUENCY = "snyk.securityAtInception.executionFrequency"

    def __init__(self, path: Path):
        with open(path) as f:
            self.data = json.load(f)
        self.recipes: Dict[str, Any] = self.data["recipes"]
        self.profiles: Dict[str, Any] = self.data.get("profiles", {})
        self.conflicting_resources: Dict[str, Any] = self.data.get("conflicting-resources", {})

    def resolve_recipes(self, profile: str) -> List[str]:
        if profile not in self.profiles:
            print(f"Unknown profile: {profile}", file=sys.stderr)
            print(f"Available: {list(self.profiles.keys())}", file=sys.stderr)
            sys.exit(1)

        profile_recipes = self.profiles[profile]["recipes"]
        all_ids = list(self.recipes.keys())

        active = set(all_ids) if "*" in profile_recipes else set(profile_recipes)
        active = {r for r in active if self.recipes[r].get("enabled", True)}

        # Honour each enabled recipe's `conflicts_with` list. Iterating in
        # manifest declaration order (rather than set iteration order, which
        # is non-deterministic) makes conflict resolution stable: when a
        # later-declared recipe lists an earlier-declared one as a conflict,
        # the later recipe wins. This lets a profile add an override recipe
        # by simply declaring it after the one it replaces.
        for rid in all_ids:
            if rid not in active:
                continue
            for conflict in self.recipes.get(rid, {}).get("conflicts_with", []):
                if conflict in active:
                    print(f"  {C.yellow('NOTE')} skipping {conflict}: incompatible with {rid}")
                active.discard(conflict)

        return [r for r in all_ids if r in active]

    def is_workspace_scoped(self, recipe_id: str) -> bool:
        return bool(self.recipes.get(recipe_id, {}).get("scope") == "workspace")

    def get_sources(self, recipe_id: str, ade: str) -> Dict[str, Any]:
        return cast(Dict[str, Any], self.recipes.get(recipe_id, {}).get("sources", {}).get(ade, {}))

    def all_recipe_ids(self) -> List[str]:
        return list(self.recipes.keys())

    def prerequisite_version(self, name: str) -> Optional[str]:
        """Return the pinned version string for a prerequisite, or None if unset."""
        value = self.data.get("prerequisites", {}).get(name)
        return str(value) if value else None

    def detect_stale_conflicts(self, active_recipes: List[str]) -> List[Tuple[str, str, str]]:
        """Return ``(active, conflicted, ade)`` triples for stale on-disk installs.

        ``conflicts_with`` is normally a build-time concern: it just keeps a
        profile from listing two incompatible recipes at once. But if a user
        previously installed the conflicted recipe (e.g. via
        ``--profile default`` installing ``sai-hooks-async``) and then runs
        the experimental profile (which installs ``sac-hooks`` declaring a
        conflict with SAI), the old files stay on disk and double-fire
        alongside the new install. This walks every ADE the conflicted
        recipe ships sources for and reports the ones whose first file is
        actually present, so the installer can surface a warning + offer to
        clean up before the new install proceeds.
        """
        stale: List[Tuple[str, str, str]] = []
        for active_rid in active_recipes:
            conflicts = self.recipes.get(active_rid, {}).get("conflicts_with", [])
            for conflicted_rid in conflicts:
                # Workspace-scoped conflicted recipes would need a different
                # path resolver; today the only declared conflict is sac
                # against sai (ADE-scoped) so we only handle that case.
                if self.is_workspace_scoped(conflicted_rid):
                    continue
                # Check every ADE the conflicted recipe ships sources for —
                # SAI installed across several ADEs needs to be surfaced on
                # each one so a user with multi-ADE installs sees the full
                # cleanup picture, not just the first match.
                for ade in self.recipes.get(conflicted_rid, {}).get("sources", {}):
                    files = self.get_sources(conflicted_rid, ade).get("files", [])
                    if any(resolve_ade_path(ade, f["dest"]).exists() for f in files):
                        stale.append((active_rid, conflicted_rid, ade))
        return stale

    def list_recipes(self) -> None:
        print("  Available Recipes:")
        print("  " + "\u2500" * 54)
        for rid, recipe in self.recipes.items():
            status = "+" if recipe.get("enabled", True) else "-"
            rtype = recipe["type"]
            desc = recipe["description"]
            ades = ", ".join(recipe.get("sources", {}).keys())
            print(f"  {status} {rid:<35} [{rtype:<7}] ({ades})")
            print(f"    {desc}")
        print()
        print("  Profiles:")
        print("  " + "\u2500" * 54)
        for pid, pdata in self.profiles.items():
            recipes = pdata["recipes"]
            label = "all recipes" if "*" in recipes else f"{len(recipes)} recipes"
            print(f"  * {pid:<15} {label}")

    def conflicting_rule_scopes(self, ade: str) -> List[str]:
        """Return the scopes (``global``/``workspace``) that actually contain
        conflicting Snyk rule directives for ``ade``.

        Only locations whose file exists AND contains the Snyk rule tags count —
        so an ADE with both global and workspace rule paths reports only the
        scope(s) where a conflict is really present, not every configured path.
        """

        rule_start_tag = "<!--# BEGIN SNYK GLOBAL RULE -->"
        rule_end_tag = "<!--# END SNYK GLOBAL RULE -->"
        scopes: List[str] = []

        for rule in self.conflicting_resources.get(ade, {}).get("rules", []):
            rule_location = _safe_conflict_path(ade, rule)
            if rule_location is None or not rule_location.exists():
                continue

            try:
                # check for existence of start/end tags in the rules file
                content = rule_location.read_text(encoding="utf-8")
            except Exception:
                continue

            if rule_start_tag in content and rule_end_tag in content:
                scope = GLOBAL if rule.get(GLOBAL) else WORKSPACE
                if scope not in scopes:
                    scopes.append(scope)

        return scopes

    def conflicting_skill_scopes(self, ade: str) -> List[str]:
        """Return the scopes (``global``/``workspace``) that actually contain
        conflicting Snyk skills for ``ade`` (only locations whose file exists)."""

        scopes: List[str] = []

        for skill in self.conflicting_resources.get(ade, {}).get("skills", []):
            skill_location = _safe_conflict_path(ade, skill)
            if skill_location is None or not skill_location.exists():
                continue
            scope = GLOBAL if skill.get(GLOBAL) else WORKSPACE
            if scope not in scopes:
                scopes.append(scope)

        return scopes

    def are_rules_conflicting(self, ade: str) -> bool:
        """Whether any existing rules would conflict when adding the SAI hooks."""
        return bool(self.conflicting_rule_scopes(ade))

    def are_skills_conflicting(self, ade: str) -> bool:
        """Whether any existing skills would conflict when adding the SAI hooks."""
        return bool(self.conflicting_skill_scopes(ade))

    def get_conflicting_resource_scope(self, ade: str, resource_type: str) -> List[str]:
        """Return the scopes where ``resource_type`` (``rules``/``skills``) actually
        conflicts for ``ade`` — only scopes with a real conflict, so callers never
        act on a scope that has none."""
        if resource_type == "rules":
            return self.conflicting_rule_scopes(ade)
        if resource_type == "skills":
            return self.conflicting_skill_scopes(ade)
        return []

    def get_extension_settings_path(self, ade: str) -> List[Path]:
        """Get the paths to the extension settings files for the given ADE based on OS"""
        home = Path.home()
        path_prefix: Path
        settings_paths = []

        # set path prefix paths depending on OS
        if _IS_WINDOWS:
            path_prefix = Path(os.environ.get("APPDATA", str(home / "AppData/Roaming")))
        elif sys.platform == "darwin":
            path_prefix = Path(home / "Library/Application Support")
        else:  # Linux
            path_prefix = Path(os.environ.get("XDG_CONFIG_HOME", str(home / ".config")))

        for setting in self.conflicting_resources.get(ade, {}).get("extension-settings", []):
            setting_path = Path(setting.get("src"))
            setting_path = Path(path_prefix, setting_path) if setting.get(GLOBAL) else setting_path

            settings_paths.append(setting_path)

        return settings_paths

    def are_extension_settings_conflicting(self, ade: str) -> List[str]:
        """Return every settings file (across all scopes) whose Snyk extension SAI
        configuration conflicts with installing the hooks.

        Each scope (global user settings, workspace ``.vscode/settings.json``) is
        evaluated independently instead of being merged hierarchically: a
        ``Manual`` override in one scope must not mask a live conflict in another,
        and every conflicting file must be reported so it can be resolved.

        A file conflicts when its ``executionFrequency`` is set to anything other
        than ``"Manual"``. ``autoConfigureSnykMcpServer`` is intentionally ignored
        — the extension runs SAI whenever the frequency is non-Manual regardless
        of that flag.
        """

        home = Path.home()
        conflicting_paths = []
        settings_paths = self.get_extension_settings_path(ade)

        for path in settings_paths:
            try:
                # 1. Basic validation: must exist and be named settings.json
                if not path.exists() or ".." in str(path):
                    raise ValueError(
                        f"Error parsing manifest: conflicting-resources/${ade}/extension-settings has a path with .. which is not allowed: ${path} "
                    )

                # 2. Resolve to absolute path to find the real location on disk
                safe_path = path.resolve()

                # 3. Security validation: must be a file and strictly named settings.json
                if not safe_path.is_file() or safe_path.name != "settings.json":
                    continue

                # 4. Check that it is within home or workspace to satisfy SAST
                safe_path_abs = os.path.abspath(safe_path)
                allowed_bases = [os.path.abspath(home), os.path.abspath(os.getcwd())]

                is_safe = False
                for base in allowed_bases:
                    try:
                        if os.path.commonpath([base, safe_path_abs]) == base:
                            is_safe = True
                            break
                    except (ValueError, Exception):
                        continue

                if not is_safe:
                    continue

                # 5. Open the validated absolute path
                with open(safe_path_abs, encoding="utf-8") as f:
                    content = f.read()

                content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
                # Strip trailing commas before closing braces/brackets
                content = re.sub(r",\s*([\]}])", r"\1", content)
                settings_data = json.loads(content)

                # Evaluate each scope independently — do not merge across scopes.
                if settings_data.get(self.EXECUTION_FREQUENCY, "Manual") != "Manual":
                    conflicting_paths.append(safe_path_abs)
            except Exception:
                continue

        return conflicting_paths

    def resolve_extension_conflicts(self, settings_paths: List[str]) -> List[str]:
        """Resolve conflicting extension settings in each of the given paths and
        return the list of paths that were successfully updated.

        Every path returned by ``are_extension_settings_conflicting`` is a scope
        that individually conflicts, so each is fixed in place. The conflict is
        the extension running SAI on its own schedule, so we pin
        ``executionFrequency`` back to ``Manual``. Settings are parsed as JSONC so
        VS Code / Cursor files with comments still update.
        """

        home = Path.home()
        updated_paths: List[str] = []

        for raw_path in settings_paths:
            try:
                # Re-validate inline at the sink: these paths originate from
                # environment variables, so the sanitizing checks must be
                # adjacent to the open() sink rather than trusting the caller.
                path = Path(raw_path)
                # 1. Must exist and contain no traversal segments.
                if not path.exists() or ".." in str(path):
                    print(
                        f"  {C.red('ERROR')} Skipping unsafe or missing settings path: {raw_path}"
                    )
                    continue

                # 2. Resolve symlinks to the real location on disk.
                safe_path = path.resolve()

                # 3. Must be a regular file strictly named settings.json.
                if not safe_path.is_file() or safe_path.name != "settings.json":
                    print(
                        f"  {C.red('ERROR')} Skipping unsafe or missing settings path: {raw_path}"
                    )
                    continue

                # 4. Confine to the home directory or the current workspace.
                safe_path_abs = os.path.abspath(safe_path)
                allowed_bases = [os.path.abspath(home), os.path.abspath(os.getcwd())]
                is_safe = False
                for base in allowed_bases:
                    try:
                        if os.path.commonpath([base, safe_path_abs]) == base:
                            is_safe = True
                            break
                    except (ValueError, Exception):
                        continue
                if not is_safe:
                    print(
                        f"  {C.red('ERROR')} Skipping unsafe or missing settings path: {raw_path}"
                    )
                    continue

                # 5. Open the validated absolute path for writing. Parse as JSONC
                # so files with comments/trailing commas still update.
                with open(safe_path_abs, "r+", encoding="utf-8") as f:
                    settings_data = jsonc_loads(f.read())

                    settings_data[self.EXECUTION_FREQUENCY] = "Manual"
                    f.seek(0)
                    json.dump(settings_data, f, indent=4)
                    f.truncate()
                updated_paths.append(safe_path_abs)
            except Exception as e:
                print(f"  {C.red('ERROR')} Failed to update settings file {raw_path}: {e}")

        return updated_paths


# =============================================================================
# WINDOWS COMPATIBILITY
# =============================================================================


def _find_win_npm_executable(name: str) -> Optional[str]:
    """Search nvm-windows npm global paths for an executable not found by shutil.which.

    nvm-windows stores global npm packages (snyk, npm, etc.) in %APPDATA%\\npm by default.
    This directory is sometimes absent from the PATH inherited by Python subprocesses.
    """
    if not _IS_WINDOWS:
        return None
    search_dirs: List[Path] = []
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        search_dirs.append(Path(appdata) / "npm")
    nvm_home = os.environ.get("NVM_HOME", "")
    if nvm_home:
        search_dirs.append(Path(nvm_home))
    # NVM_SYMLINK is where nvm-windows places node.exe and npm.cmd for the active version
    nvm_symlink = os.environ.get("NVM_SYMLINK", "")
    if nvm_symlink:
        search_dirs.append(Path(nvm_symlink))
    for dir_path in search_dirs:
        for ext in (".cmd", ".exe", ""):
            candidate = dir_path / f"{name}{ext}"
            if candidate.is_file():
                return str(candidate)
    return None


# =============================================================================
# PREREQUISITES
# =============================================================================


# nvm installs Node under $NVM_DIR (default ~/.nvm). The release to pin when
# nvm is absent comes from the manifest's ``prerequisites.nvm`` entry — see
# ``_nvm_install_tag`` / ``_nvm_install_url``.


def _nvm_install_tag(nvm_version: Optional[str]) -> str:
    """Return the git tag for the nvm release to install.

    The manifest stores a bare version (e.g. ``0.40.3``) for consistency with
    the other prerequisites; nvm's release tags are ``v``-prefixed, so prepend
    it when absent. A ``v``-prefixed manifest value is accepted as-is.
    """
    version = (nvm_version or "").strip() or "0.40.3"
    return version if version.startswith("v") else f"v{version}"


def _nvm_install_url(nvm_version: Optional[str]) -> str:
    """Return the install.sh URL for the pinned nvm release."""
    tag = _nvm_install_tag(nvm_version)
    return f"https://raw.githubusercontent.com/nvm-sh/nvm/{tag}/install.sh"


def _nvm_dir() -> Path:
    """Return the nvm install directory: ``$NVM_DIR`` if set, else ``~/.nvm``."""
    nvm_dir = os.environ.get("NVM_DIR", "").strip()
    return Path(nvm_dir) if nvm_dir else Path.home() / ".nvm"


def _nvm_latest_node_bin_dir() -> Optional[str]:
    """Return the ``bin`` dir of the newest Node version nvm has installed, or None.

    nvm places each installed Node under ``$NVM_DIR/versions/node/v<X.Y.Z>/bin``.
    After an install we prepend this to the current process PATH so
    ``node``/``npm`` resolve immediately, without sourcing a shell profile. When
    several versions are installed only the newest is added — whichever dir comes
    first on PATH wins, so adding the older ones would just be shadowed.
    """
    versions = _nvm_dir() / "versions" / "node"
    if not versions.is_dir():
        return None

    best_dir: Optional[Path] = None
    best_key: Tuple[int, ...] = (-1, -1, -1)
    for d in versions.iterdir():
        if not (d / "bin").is_dir():
            continue
        m = re.match(r"v?(\d+)\.(\d+)\.(\d+)", d.name)
        if m is None:
            # Not a vX.Y.Z version dir (e.g. a temp/metadata folder) — skip it
            # so it can never be picked and add a bogus dir to PATH.
            continue
        key = tuple(int(x) for x in m.groups())
        if key > best_key:
            best_key = key
            best_dir = d

    return str(best_dir / "bin") if best_dir is not None else None


def _get_node_install_cmds_nvm(
    node_version: Optional[str] = None, nvm_version: Optional[str] = None
) -> List[List[str]]:
    """Return the Node.js install command for macOS/Linux via nvm.

    The returned command is a single ``sh -c`` invocation that installs nvm
    (pinned to ``nvm_version`` from the manifest) if it isn't already present,
    sources it, then installs the requested Node version (or the latest LTS when
    no version is given) and marks it the default for the user's future shells.
    nvm can install an exact upstream version, so the manifest's pinned Node
    version is honoured directly.
    """
    if node_version:
        install_sel, alias_sel, label = node_version, node_version, node_version
    else:
        install_sel, alias_sel, label = "--lts", "lts/*", "the latest LTS"

    print(f"  {C.cyan('INFO')} Installing Node.js {label} via nvm.")

    # The script is a constant and POSIX-compatible, so it runs under the
    # minimal /bin/sh that stripped-down distros (e.g. Alpine) ship as well as
    # under bash — hence ``sh -c`` rather than a hardcoded ``bash``. The install
    # URL and version selectors are passed as positional parameters ($1-$3)
    # rather than interpolated into the command text, so no value is ever
    # shell-interpreted. NVM_DIR is resolved by the script from its own
    # (inherited) environment rather than read in Python and passed in. The nvm
    # installer is piped to bash when present, falling back to sh. $0 is a label
    # for diagnostics.
    script = (
        "set -e; "
        'export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"; '
        'if [ ! -s "$NVM_DIR/nvm.sh" ]; then '
        'echo "Installing nvm..."; '
        "if command -v bash >/dev/null 2>&1; then nvm_sh=bash; else nvm_sh=sh; fi; "
        'if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" | "$nvm_sh"; '
        'elif command -v wget >/dev/null 2>&1; then wget -qO- "$1" | "$nvm_sh"; '
        'else echo "Neither curl nor wget is available to download nvm." >&2; exit 1; fi; '
        "fi; "
        '. "$NVM_DIR/nvm.sh"; '
        'nvm install "$2"; '
        'nvm alias default "$3"'
    )
    return [
        [
            "sh",
            "-c",
            script,
            "snyk-nvm-install",
            _nvm_install_url(nvm_version),
            install_sel,
            alias_sel,
        ]
    ]


def _get_node_install_cmds_windows(
    auto_yes: bool, node_version: Optional[str] = None
) -> List[List[str]]:
    """Return the Node.js install command(s) for Windows, closest to ``node_version``.

    winget and choco both support pinning an exact version, so when a target is
    given we request it directly (``OpenJS.NodeJS --version <v>`` / ``nodejs
    --version=<v>``). With no target, install the current LTS.
    """
    if node_version:
        print(f"  {C.cyan('INFO')} Targeting Node.js {node_version}.")

    if shutil.which("winget"):
        if node_version:
            return [
                [
                    "winget",
                    "install",
                    "OpenJS.NodeJS",
                    "--version",
                    node_version,
                    "--silent",
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                ]
            ]
        return [
            [
                "winget",
                "install",
                "OpenJS.NodeJS.LTS",
                "--silent",
                "--accept-package-agreements",
                "--accept-source-agreements",
            ]
        ]

    # choco: pin the exact version against the `nodejs` package, else track LTS.
    choco_cmd = (
        ["choco", "install", "nodejs", f"--version={node_version}", "-y"]
        if node_version
        else ["choco", "install", "nodejs-lts", "-y"]
    )
    if shutil.which("choco"):
        return [choco_cmd]

    print(f"  {C.yellow('WARNING')} Neither winget nor chocolatey found.")
    if not auto_yes:
        reply = input("  Install Chocolatey? (y/n) ").strip().lower()
        if reply not in ("y", "yes"):
            return []

    print(f"  {C.cyan('INFO')} Installing Chocolatey...")
    try:
        choco_install_cmd = "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
        run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                choco_install_cmd,
            ],
            check=True,
        )
        return [choco_cmd]
    except Exception as e:
        print(f"  {C.red('ERROR')} Failed to install Chocolatey: {e}")
        return []


def _update_process_path_for_nodejs(base_paths: Optional[List[str]] = None) -> None:
    """Add standard Node.js and npm installation paths to the current process's PATH.

    This enables the installer to use node/npm immediately after installation
    without requiring a shell restart.
    """
    new_paths = []

    if base_paths:
        new_paths.extend(base_paths)
    else:
        if _IS_WINDOWS:
            new_paths.append("C:\\Program Files\\nodejs")
            appdata = os.environ.get("APPDATA")
            if appdata:
                new_paths.append(os.path.join(appdata, "npm"))
            # nvm-windows install root: some setups keep globally installed CLIs
            # (snyk) here. Mirror _find_win_npm_executable so shell-based PATH
            # discovery can run what that helper is able to find.
            nvm_home = os.environ.get("NVM_HOME", "")
            if nvm_home:
                new_paths.append(nvm_home)
            # nvm-windows: NVM_SYMLINK points to the active Node.js version directory
            nvm_symlink = os.environ.get("NVM_SYMLINK", "")
            if nvm_symlink:
                new_paths.append(nvm_symlink)
        else:  # macOS and Linux: Node is installed via nvm
            latest_node_bin = _nvm_latest_node_bin_dir()
            if latest_node_bin:
                new_paths.append(latest_node_bin)

    current_path = os.environ.get("PATH", "")
    path_sep = ";" if _IS_WINDOWS else ":"
    existing_paths = set(current_path.split(path_sep))

    added = []
    for p in new_paths:
        if p and p not in existing_paths and os.path.isdir(p):
            added.append(p)

    if added:
        os.environ["PATH"] = path_sep.join(added) + path_sep + current_path


def _build_node_install_cmds(
    auto_yes: bool, node_version: Optional[str] = None, nvm_version: Optional[str] = None
) -> List[List[str]]:
    """Return the platform-appropriate Node.js install command(s), or [] if none can be built.

    Shared by the missing-Node install path and the outdated-Node upgrade path.
    ``node_version`` is the target version from the manifest. On Windows it is
    an exact pin via winget/choco; on macOS and Linux it is installed via nvm,
    which honours the exact upstream version directly. ``nvm_version`` is the
    pinned nvm release from the manifest, used only on the macOS/Linux path.
    """
    sys_os = platform.system().lower()

    if sys_os == "windows":
        return _get_node_install_cmds_windows(auto_yes, node_version)
    # macOS and Linux both install Node via nvm.
    return _get_node_install_cmds_nvm(node_version, nvm_version)


def _run_node_install(cmds: List[List[str]]) -> bool:
    """Run the given Node.js install command(s) and refresh PATH for the current process."""
    print(f"  {C.cyan('INFO')} Installing Node.js...")
    try:
        for cmd in cmds:
            run(cmd, check=True)

        # Attempt to refresh PATH for the current process
        _update_process_path_for_nodejs()

        if shutil.which("node") and shutil.which("npm"):
            print(f"  {C.green('OK')} Node.js installed and available in current process.")
            return True

        # Re-check PATH or assume success if run() didn't fail
        print(
            f"  {C.yellow('WARNING')} Node.js installed but not found on PATH yet. You may need to restart your terminal."
        )
        return True
    except Exception as e:
        print(f"  {C.red('ERROR')} Installation failed: {e}")
        return False


def _run_node_install_with_fallback(
    auto_yes: bool,
    primary: List[List[str]],
    node_version: Optional[str],
    nvm_version: Optional[str] = None,
) -> bool:
    """Run the version-pinned install; on failure, retry with the unpinned default build.

    The exact-version pin (e.g. winget ``--version 24.11.1`` or ``nvm install
    24.11.1``) can fail when that build isn't published. Falling back to the
    default — LTS on Windows, the latest LTS via nvm on macOS/Linux — keeps the
    install best-effort rather than hard-failing on an unavailable pin.
    """
    if _run_node_install(primary):
        return True
    if not node_version:
        return False
    fallback = _build_node_install_cmds(auto_yes, None, nvm_version)
    if not fallback or fallback == primary:
        return False
    print(
        f"  {C.yellow('WARNING')} Pinned Node.js {node_version} install failed; "
        f"falling back to the package manager's default build."
    )
    return _run_node_install(fallback)


def _get_node_version() -> Optional[tuple[int, ...]]:
    """Return the installed Node.js version as a (major, minor, patch) tuple, or None if undetectable."""
    # Presence guard only: never pass the resolved (env-derived) path into run().
    # Invoke the literal "node" — mirrors the Snyk version probe below.
    if not shutil.which("node"):
        # Node may exist only in a location not yet on PATH (e.g. an NVM dir).
        # Refresh PATH so the literal "node" below resolves; bail if still absent.
        if not _find_win_npm_executable("node"):
            return None
        _update_process_path_for_nodejs()
        if not shutil.which("node"):
            return None
    try:
        r = run(
            ["node", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            shell=_IS_WINDOWS,
            creationflags=_CREATE_NO_WINDOW,
        )
    except Exception:
        return None
    match = re.match(r"v?(\d+)\.(\d+)\.(\d+)", (r.stdout or "").strip())
    if not match:
        return None
    return tuple(int(x) for x in match.groups())


def _warn_if_node_outdated(
    auto_yes: bool, node_version: Optional[str], nvm_version: Optional[str] = None
) -> None:
    """When Node is present but older than the manifest minimum, warn and offer to upgrade.

    Best-effort: if the version can't be parsed/detected we stay quiet rather than
    block, mirroring how a soft prerequisite should behave.
    """
    if not node_version:
        return
    try:
        minimum = tuple(map(int, node_version.split(".")))
    except ValueError:
        return
    current = _get_node_version()
    if current is None or current >= minimum:
        return

    cur_str = ".".join(map(str, current))
    print(f"  {C.yellow('WARNING')} Node.js {cur_str} is outdated (min: {node_version}).")

    cmds = _build_node_install_cmds(auto_yes, node_version, nvm_version)
    if not cmds:
        return
    if not auto_yes:
        reply = input(f"  Upgrade Node.js to {node_version}? (y/n) ").strip().lower()
        if reply not in ("y", "yes"):
            return
    _run_node_install_with_fallback(auto_yes, cmds, node_version, nvm_version) or sys.exit(1)


def ensure_node_installed(
    auto_yes: bool, node_version: Optional[str] = None, nvm_version: Optional[str] = None
) -> bool:
    """Confirm that Node.js and npm are installed and configured.

    ``node_version`` is the target Node version from the manifest prerequisites.
    It doubles as the minimum: when Node is present but older, the user is warned
    and offered an upgrade. When Node is missing it is installed via nvm on
    macOS/Linux (pinned to ``nvm_version`` from the manifest) and via
    winget/choco on Windows — in every case targeting ``node_version``.

    The installer never uses sudo. On macOS/Linux an existing Node on PATH is
    accepted only when its global npm prefix is user-writable, so a later
    ``npm install -g`` (e.g. the Snyk CLI) needs no elevation. A root-owned
    system Node would force sudo for global installs, so instead a per-user Node
    is installed via nvm — which also lands the Snyk CLI in a directory the
    recipes already search on PATH.
    """
    if shutil.which("node") and shutil.which("npm"):
        # On Windows, ensure %APPDATA%\npm (global npm packages like snyk) is also on PATH
        # even when node/npm themselves are already found via NVM_SYMLINK or similar.
        if _IS_WINDOWS:
            _update_process_path_for_nodejs()
            _warn_if_node_outdated(auto_yes, node_version, nvm_version)
            return True
        # macOS/Linux: only accept the existing Node when global installs don't
        # need root; otherwise fall through to install a per-user Node via nvm.
        if _npm_global_prefix_writable():
            _warn_if_node_outdated(auto_yes, node_version, nvm_version)
            return True
        print(
            f"  {C.yellow('WARNING')} Node.js is installed but its global package "
            "directory is not writable; installing a per-user Node via nvm."
        )
    # On Windows with nvm-windows, node/npm may live in paths not yet on PATH
    elif _IS_WINDOWS and _find_win_npm_executable("node") and _find_win_npm_executable("npm"):
        _update_process_path_for_nodejs()
        _warn_if_node_outdated(auto_yes, node_version, nvm_version)
        return True
    else:
        print(f"  {C.yellow('WARNING')} Node.js and/or npm not found on system PATH.")

    cmds = _build_node_install_cmds(auto_yes, node_version, nvm_version)
    if not cmds:
        return False

    if not auto_yes:
        reply = input("  Install Node.js now? (y/n) ").strip().lower()
        if reply not in ("y", "yes"):
            return False

    return _run_node_install_with_fallback(auto_yes, cmds, node_version, nvm_version)


def _npm_global_prefix_writable() -> bool:
    """Return True if the current user can write to npm's global install prefix.

    Node installed via nvm lives under the user's home, so its global prefix is
    writable and ``npm install -g`` works directly. A pre-existing system-wide
    Node (e.g. ``/usr/bin/node``) usually has a root-owned prefix where a global
    install would fail with EACCES. Probing the prefix lets ensure_node_installed
    decide whether the existing Node is usable or a per-user Node must be
    installed via nvm — the installer never escalates privileges.

    Errs on the side of "writable" when the prefix can't be determined, so a
    transient ``npm`` hiccup never triggers an unnecessary nvm install.
    """
    try:
        r = run(
            ["npm", "prefix", "-g"],
            capture_output=True,
            text=True,
            timeout=10,
            shell=_IS_WINDOWS,
            creationflags=_CREATE_NO_WINDOW,
        )
    except Exception:
        return True
    stdout = getattr(r, "stdout", None)
    prefix = stdout.strip() if isinstance(stdout, str) else ""
    if not prefix:
        return True
    # npm creates lib/node_modules and bin under the prefix on demand, so test
    # write access at the nearest existing ancestor of the prefix.
    path = Path(prefix)
    while not path.exists() and path != path.parent:
        path = path.parent
    return os.access(path, os.W_OK)


def run_command(cmd: list[str], warn: str) -> int:
    """Run the given command and return the exit code (increments warning count in check_prerequisites)."""
    try:
        run(cmd, check=True, shell=_IS_WINDOWS, creationflags=_CREATE_NO_WINDOW)
        return 0
    except Exception:
        print(warn)
        return 1


def check_prerequisites(
    auto_yes: bool,
    snyk_version: Optional[str] = None,
    node_version: Optional[str] = None,
    no_latest_deps: bool = False,
    nvm_version: Optional[str] = None,
) -> None:
    """Check that the required prerequisites are installed and configured. If not, attempt to install them.

    ``snyk_version`` is the pinned Snyk CLI version from the manifest
    prerequisites; it doubles as the minimum-acceptable version. In
    ``no_latest_deps`` the installer does not upgrade to the latest dependency version when the dependency is
    missing or older.
    """

    warnings = 0

    def get_npm_install_cmd(pkg: str) -> List[str]:
        # Assumes node was installed per-user.
        return ["npm", "install", "-g", pkg]

    def snyk_pkg(latest_label: str) -> str:
        """Package spec to install: the manifest version if not installing latest, else the latest label."""
        if no_latest_deps and snyk_version:
            return f"snyk@{snyk_version}"
        return latest_label

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
    print(f"  {C.green('OK')} Python {py_ver}")

    def get_snyk_path():
        return shutil.which("snyk") or _find_win_npm_executable("snyk")

    if not ensure_node_installed(auto_yes, node_version, nvm_version) and get_snyk_path():
        print(f"  {C.red('ERROR')} Node.js is required to install Snyk CLI.")
        warnings += 1

    def parse_version(x):
        return tuple(map(int, x.split(".")))

    minimum_snyk_version = parse_version(snyk_version) if snyk_version else None

    # Probe the installed Snyk version. get_snyk_path() only confirms that a
    # `snyk` entry resolves on PATH; actually executing it can still fail (a
    # stale/broken shim, or a bin dir that became invalid after the Node/PATH
    # refresh) with FileNotFoundError. Treat any such failure as "Snyk not
    # usable" and fall through to (re)install it, mirroring how _get_node_version
    # guards its own probe — never let the exception crash the installer.
    snyk_ver_str: Optional[str] = None
    if get_snyk_path():
        try:
            r = run(
                ["snyk", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                shell=_IS_WINDOWS,
                creationflags=_CREATE_NO_WINDOW,
            )
            snyk_ver_str = r.stdout.strip().splitlines()[0] if r.stdout else "unknown"
        except Exception:
            snyk_ver_str = None

    if snyk_ver_str is not None:
        match = re.match(r"(\d+\.\d+\.\d+)", snyk_ver_str)
        if match:
            current_version = parse_version(match.group(1))
            # Only (re)install when the installed Snyk is older than the
            # pin/minimum; an equal-or-newer build is left untouched in both
            # global and default mode.
            if minimum_snyk_version is not None and current_version < minimum_snyk_version:
                target = "pinned" if no_latest_deps else "latest"
                print(
                    f"  {C.yellow('WARNING')} Snyk CLI {snyk_ver_str} is outdated "
                    f"(min: {snyk_version}). Upgrade to {target}?"
                )
                if not auto_yes:
                    reply = input("  (y/n) ").strip().lower()
                    if reply not in ("y", "yes"):
                        sys.exit(1)
                warnings += run_command(
                    get_npm_install_cmd(snyk_pkg("snyk@latest")),
                    f"  {C.yellow('WARNING')} Failed to upgrade Snyk CLI to {target} via npm",
                )
            else:
                print(f"  {C.green('OK')} Snyk CLI {snyk_ver_str}")
    else:
        target = "pinned" if no_latest_deps and snyk_version else "latest"
        print(f"  {C.yellow('WARNING')} Snyk CLI not found, install {target} version?")
        if not auto_yes:
            reply = input("  (y/n) ").strip().lower()
            if reply not in ("y", "yes"):
                sys.exit(1)
        warnings += run_command(
            get_npm_install_cmd(snyk_pkg("snyk")),
            f"  {C.yellow('WARNING')} Failed to install Snyk CLI via npm",
        )

    if warnings > 0 and not auto_yes:
        reply = input("\n  Continue with warnings? (y/n) ").strip().lower()
        if reply not in ("y", "yes"):
            sys.exit(1)


def print_prerequisite_versions(
    snyk_version: Optional[str] = None, node_version: Optional[str] = None
) -> None:
    """Print Python/Node/Snyk CLI versions, flagging any older than the manifest pins.

    Read-only: never installs, upgrades, or prompts — unlike
    ``check_prerequisites``. Used by ``--verify``, which must stay
    side-effect-free.
    """

    def parse_version(x: str) -> tuple[int, ...]:
        return tuple(map(int, x.split(".")))

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
    print(f"  {C.green('OK')} Python {py_ver}")

    node_ver = _get_node_version()
    if node_ver is None:
        print(f"  {C.yellow('WARNING')} Node.js not found")
    elif node_version and node_ver < parse_version(node_version):
        print(
            f"  {C.yellow('WARNING')} Node.js {'.'.join(map(str, node_ver))} "
            f"is outdated (min: {node_version})"
        )
    else:
        print(f"  {C.green('OK')} Node.js {'.'.join(map(str, node_ver))}")

    snyk_path = shutil.which("snyk") or _find_win_npm_executable("snyk")
    snyk_ver_str: Optional[str] = None
    if snyk_path:
        try:
            r = run(
                ["snyk", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                shell=_IS_WINDOWS,
                creationflags=_CREATE_NO_WINDOW,
            )
            snyk_ver_str = r.stdout.strip().splitlines()[0] if r.stdout else None
        except Exception:
            snyk_ver_str = None

    if not snyk_ver_str:
        print(f"  {C.yellow('WARNING')} Snyk CLI not found")
        return

    match = re.match(r"(\d+\.\d+\.\d+)", snyk_ver_str)
    if snyk_version and match and parse_version(match.group(1)) < parse_version(snyk_version):
        print(f"  {C.yellow('WARNING')} Snyk CLI {snyk_ver_str} is outdated (min: {snyk_version})")
    else:
        print(f"  {C.green('OK')} Snyk CLI {snyk_ver_str}")


# =============================================================================
# ADE DETECTION
# =============================================================================

ADE_HOMES = {
    "cursor": ".cursor",
    "claude": ".claude",
    "gemini": ".gemini",
    "kiro": ".kiro",
    "codex": ".codex",
    "windsurf": ".codeium/windsurf",
    "copilot-cli": ".copilot",
    "copilot-vscode": "User",
}

# Mapping from installer ADE name to the value `snyk mcp configure --tool` expects.
SNYK_MCP_TOOL_NAMES = {
    "cursor": "cursor",
    "claude": "claude-cli",
    "gemini": "gemini-cli",
    "kiro": "kiro-cli",
    "windsurf": "windsurf",
    "copilot-vscode": "vs_code",
}

# ADES that run in the CLI (not via GUI)
CLI_ADES = ["claude", "gemini", "copilot-cli", "copilot-vscode"]


def _vscode_user_dir() -> Path:
    """Return the platform-specific user-data root that hosts VS Code's `Code/User` dir.

    Env values are accepted only when absolute and traversal-free; otherwise
    the platform default rooted at Path.home() is used.
    """
    home = Path.home()

    if _IS_WINDOWS:
        return _join_path_to_env_var("APPDATA", home / "AppData" / "Roaming", "Code")
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "Code"
    return _join_path_to_env_var("XDG_CONFIG_HOME", home / ".config", "Code")


def _join_path_to_env_var(var_name: str, default: Path, *rel: str) -> Path:
    """Return env-supplied base dir (or default) joined with the given rel segments.

    The env-var read, validation, and concatenation all happen in this helper.
    The returned Path is reconstructed from its individual parts so that
    SAST taint tracking does not propagate the env-var input to downstream
    callers; any path-component check has already happened here.
    """
    raw = os.environ.get(var_name)
    base_parts = default.parts
    if raw and "\x00" not in raw:
        candidate = Path(raw)
        if candidate.is_absolute() and ".." not in candidate.parts:
            base_parts = candidate.parts
    return Path(*base_parts, *rel)


def get_ade_home(ade: str) -> Path:
    base = _vscode_user_dir() if ade == "copilot-vscode" else Path.home()
    return base / ADE_HOMES[ade]


def _safe_conflict_path(ade: str, entry: Dict[str, Any]) -> Optional[Path]:
    """Resolve a manifest conflicting-resources entry to an absolute Path under a trusted base.

    Returns None if `src` is missing, contains traversal segments, or escapes the
    expected base after resolution. Trusted bases are Path.home() (for most ADEs),
    `_vscode_user_dir()` (for copilot-vscode globals), and the current workspace
    (cwd) for non-global entries.
    """
    raw = entry.get("src")
    if not raw or not isinstance(raw, str):
        return None
    rel = Path(raw)
    if rel.is_absolute() or ".." in rel.parts:
        return None

    if entry.get(GLOBAL):
        base = get_ade_home(ade) if ade == "copilot-vscode" else Path.home()
    else:
        base = Path.cwd()

    base_resolved = base.resolve()
    candidate = (base_resolved / rel).resolve()
    try:
        candidate.relative_to(base_resolved)
    except ValueError:
        return None
    return candidate


def find_git_root(start: Path) -> Optional[Path]:
    """Walk up from *start* looking for a ``.git`` entry (dir or worktree file).

    Returns the first ancestor that contains ``.git``, or None when none does.
    """
    try:
        cur = start.resolve()
    except OSError:
        return None
    for parent in [cur, *cur.parents]:
        if (parent / ".git").exists():
            return parent
    return None


def resolve_workspace(workspace_arg: Optional[str]) -> Optional[Path]:
    """Resolve the workspace root used for workspace-scoped recipes.

    Priority:
      1. ``--workspace <path>`` if supplied — must exist and be a directory.
      2. Otherwise the enclosing git repo (walked up from cwd).
      3. Otherwise None, meaning workspace-scoped recipes get skipped.

    Exits with a clear error when ``--workspace`` is supplied but invalid;
    falling back silently in that case would install into the wrong place.
    """
    if workspace_arg:
        path = Path(workspace_arg).expanduser()
        if not path.exists():
            print(
                f"  {C.red('ERROR')} --workspace path does not exist: {path}",
                file=sys.stderr,
            )
            sys.exit(1)
        if not path.is_dir():
            print(
                f"  {C.red('ERROR')} --workspace path is not a directory: {path}",
                file=sys.stderr,
            )
            sys.exit(1)
        return path.resolve()

    return find_git_root(Path.cwd())


def resolve_install_path(workspace: Path, dest: str) -> Path:
    """Resolve a manifest ``dest`` path under *workspace* with a containment check.

    The dest comes from a trusted manifest entry, but we still verify the
    composed path stays inside the resolved workspace root before returning
    it. That serves two purposes:
      1. defends against accidental escape via odd manifest entries (e.g. a
         dest starting with ``../``)
      2. acts as an explicit sanitizer for static analysis — *workspace* may
         have arrived via ``--workspace`` (CLI input), and the
         ``relative_to`` check launders the taint for downstream file ops.
    """
    rel = Path(dest)
    if rel.is_absolute():
        print(
            f"  {C.red('ERROR')} manifest dest must be workspace-relative: {dest!r}",
            file=sys.stderr,
        )
        sys.exit(1)

    base = workspace.resolve()
    candidate = (base / rel).resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        print(
            f"  {C.red('ERROR')} manifest dest escapes workspace: {dest!r}",
            file=sys.stderr,
        )
        sys.exit(1)
    return candidate


def _display_path(p: Path, workspace: Path) -> str:
    """Render *p* relative to *workspace* when *p* lives inside, else absolute.

    Keeps post-install verification output compact for the entries that
    actually belong to the workspace.
    """
    try:
        return str(p.resolve().relative_to(workspace.resolve()))
    except (OSError, ValueError):
        return str(p)


def expand_install_tokens(s: str, workspace: Path) -> str:
    """Replace ``$WORKSPACE`` with the absolute workspace path.

    Used when materialising a ``pre_commit_integration.command`` string so the
    shim doesn't depend on shell variable expansion at git-hook time. The SAC
    recipe doesn't use ``$WORKSPACE`` (its command is workspace-relative so
    the resulting `.pre-commit-config.yaml` / `.husky/pre-commit` stays
    portable when committed), but the helper is kept for any future recipe
    that needs an absolute path baked in.
    """
    return s.replace("$WORKSPACE", str(workspace.resolve()))


def resolve_ade_path(ade: str, dest: str) -> Path:
    """Resolve a manifest dest path under the appropriate home dir for the given ADE.

    Special case: copilot-vscode dests that target `.copilot/...` resolve under
    `$HOME`, not the VS Code user-data dir. Both Copilot surfaces share
    `~/.copilot/hooks/` for SAI hook files, so the copilot-vscode SAI recipe
    points at the same paths as copilot-cli."""
    if ade == "copilot-vscode" and (dest == ".copilot" or dest.startswith(".copilot/")):
        return Path.home() / dest
    base = get_ade_home(ade) if ade == "copilot-vscode" else Path.home()
    return base / dest


def _cursor_app_bundle_exists() -> bool:
    if sys.platform != "darwin":
        return False
    home = Path.home()
    for path in (Path("/Applications/Cursor.app"), home / "Applications" / "Cursor.app"):
        if path.is_dir():
            return True
    return False


def _cursor_process_running() -> bool:
    """True only if a process is named exactly Cursor (any case) — -x, not substring."""
    try:
        r = run(
            ["pgrep", "-xiq", "cursor"],
            capture_output=True,
            timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def detect_ades() -> List[str]:
    detected = []
    home = Path.home()

    if (
        (home / ".cursor").is_dir()
        or _cursor_app_bundle_exists()
        or not _IS_WINDOWS
        and _cursor_process_running()
    ):
        detected.append("cursor")

    if (home / ".claude").is_dir() or shutil.which("claude"):
        detected.append("claude")

    if (home / ".gemini").is_dir() or shutil.which("gemini"):
        detected.append("gemini")

    if (home / ".kiro").is_dir() or shutil.which("kiro"):
        detected.append("kiro")

    if (home / ".codex").is_dir():
        detected.append("codex")
    elif shutil.which("codex"):
        detected.append("codex")

    if (home / ".codeium" / "windsurf").is_dir():
        detected.append("windsurf")
    elif (home / ".windsurf").is_dir():
        detected.append("windsurf")
    elif shutil.which("windsurf"):
        detected.append("windsurf")

    if (home / ".copilot").is_dir() or shutil.which("copilot"):
        detected.append("copilot-cli")

    if get_ade_home("copilot-vscode").is_dir() or shutil.which("code"):
        detected.append("copilot-vscode")

    return detected


def get_target_ades(
    target_ade: Optional[str],
    auto_yes: bool,
) -> List[str]:
    if target_ade:
        return [target_ade]

    detected = detect_ades()
    if detected:
        return detected

    if auto_yes or not hasattr(sys.stdin, "isatty") or not sys.stdin.isatty():
        print(
            "  Error: no ADE detected; pass --ade to run non-interactively.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"  {C.yellow('WARNING')} No supported ADE detected")
    print()
    print("  Which ADE(s) would you like to install for?")
    print("  1) Cursor")
    print("  2) Claude Code")
    print("  3) Gemini Code")
    print("  4) Kiro")
    print("  5) Codex CLI")
    print("  6) Windsurf")
    print("  7) GitHub Copilot CLI")
    print("  8) GitHub Copilot in VS Code")
    print("  9) All")
    print()
    reply = input("  Choose (1/2/3/4/5/6/7/8/9): ").strip()
    choices = {
        "1": ["cursor"],
        "2": ["claude"],
        "3": ["gemini"],
        "4": ["kiro"],
        "5": ["codex"],
        "6": ["windsurf"],
        "7": ["copilot-cli"],
        "8": ["copilot-vscode"],
        "9": [
            "cursor",
            "claude",
            "gemini",
            "kiro",
            "codex",
            "windsurf",
            "copilot-cli",
            "copilot-vscode",
        ],
    }
    if reply in choices:
        return choices[reply]
    print(C.red("Invalid choice"))
    sys.exit(1)


# =============================================================================
# HOOK-COMMAND PATH EXPANSION (install-time)
# =============================================================================
#
# Hook command strings in source files use ``$HOME``/``$env:USERPROFILE``
# placeholders for human readability. The runtime shell each ADE picks on
# each OS varies (bash, zsh, PowerShell, cmd, Git Bash, WSL), and not all of
# them expand the same variables — so leaving placeholders in the installed
# file is fragile. Instead we expand placeholders to an absolute path *at
# install time*, sidestepping every per-shell expansion difference.
#
# Strategies whose source file carries hook commands needing expansion:

_HOOK_EXPAND_STRATEGIES: frozenset[str] = frozenset(
    {
        "cursor_hooks",
        "claude_settings",
        "gemini_settings",
        "kiro_settings",
        "codex_config",
        "copilot_cli_hooks",
    }
)

# Strategies whose source file carries hook commands the Windows installer
# rewrites from ``uv run`` to ``uvw run --gui-script`` to suppress the console
# window ``uv run`` would otherwise pop up under graphical ADEs. Includes the
# Copilot CLI strategy, which on Windows needs both the GUI rewrite and
# install-time $HOME expansion (its hooks run with Windows-native paths, not a
# bash shell that would expand $HOME at hook time).
_HOOK_GUI_STRATEGIES: frozenset[str] = frozenset(
    {
        "cursor_hooks",
        "claude_settings",
        "gemini_settings",
        "kiro_settings",
        "codex_config",
        "copilot_cli_hooks",
    }
)


def _should_expand_source(strategy: str) -> bool:
    """True iff the source file for ``strategy`` carries hook commands we
    should pre-expand before passing to the merge layer.

    Skipped for ``unmerge_*`` strategies — those handle dual-form (raw vs
    expanded) matching internally so they can clean up entries written by
    older installer versions that still contain ``$HOME``.
    """
    if not any(s in strategy for s in _HOOK_EXPAND_STRATEGIES):
        return False
    return not strategy.startswith("unmerge_")


def _should_gui_transform(strategy: str) -> bool:
    """True iff the source file for ``strategy`` carries ``uv run`` hook
    commands the Windows installer should rewrite to ``uvw run --gui-script``.

    Applies on Windows only. Runs for both ``merge_*`` and ``unmerge_*``
    strategies so the unmerge source matches the on-disk form the installer
    wrote.
    """
    if not _IS_WINDOWS:
        return False
    return any(s in strategy for s in _HOOK_GUI_STRATEGIES)


@contextlib.contextmanager
def _expand_source(strategy: str, source: Path) -> Iterator[Path]:
    """Context manager yielding a path to source data with home-dir tokens expanded.

    For strategies that pass ``_should_expand_source``, parses the source,
    runs every string through ``expand_hook_command_paths``, writes the
    result to a temp file, and yields its path. On Windows, strategies that
    pass ``_should_gui_transform`` also have ``uv run`` rewritten to
    ``uvw run --gui-script``. Otherwise yields ``source`` unchanged.
    ``delete=False`` is required on Windows because the file cannot be read
    while still open.
    """
    needs_expand = _should_expand_source(strategy)
    needs_gui = _should_gui_transform(strategy)
    if not needs_expand and not needs_gui:
        yield source
        return

    is_toml = source.suffix.lower() == ".toml"
    if is_toml:
        vendor_dir = str(Path(__file__).resolve().parent / "lib" / "_vendor")
        if vendor_dir not in sys.path:
            sys.path.insert(0, vendor_dir)
        try:
            import tomllib as _toml_read  # Python 3.11+
        except ImportError:  # pragma: no cover
            import tomli as _toml_read
        import tomli_w as _toml_write

        with open(source, "rb") as f:
            data = _toml_read.load(f)
    else:
        with open(source) as f:
            data = json.load(f)

    lib_dir = str(Path(__file__).resolve().parent / "lib")
    if lib_dir not in sys.path:
        sys.path.insert(0, lib_dir)
    import merge_json

    if needs_expand:
        data = merge_json.expand_hook_command_paths(data)
    if needs_gui:
        data = merge_json.transform_uvw_gui_script(data)

    suffix = ".toml" if is_toml else ".json"
    mode = "wb" if is_toml else "w"
    tmp = tempfile.NamedTemporaryFile(mode=mode, suffix=suffix, delete=False)
    tmp_path = Path(tmp.name)
    try:
        if is_toml:
            _toml_write.dump(data, tmp)
        else:
            json.dump(data, tmp, indent=2)
            tmp.write("\n")
        tmp.close()
        yield tmp_path
    finally:
        with contextlib.suppress(OSError):
            tmp_path.unlink()


# =============================================================================
# FILE OPERATIONS
# =============================================================================


def copy_file(src: Path, dest: Path, dry_run: bool) -> None:
    if dry_run:
        print(f"    {C.dim('[dry-run] copy: ' + str(dest))}")
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and filecmp.cmp(str(src), str(dest), shallow=False):
        print(f"    {C.dim('unchanged: ' + str(dest))}")
        return
    shutil.copy2(str(src), str(dest))
    print(f"    {C.green('installed:')} {dest}")


def apply_transform(
    transform_type: str, src: Path, dest: Path, payload: PayloadContext, dry_run: bool
) -> None:
    if dry_run:
        print(f"    {C.dim(f'[dry-run] transform ({transform_type}): {dest}')}")
        return
    # Import transform module from payload lib/
    lib_dir = str(payload.payload_dir / "lib")
    if lib_dir not in sys.path:
        sys.path.insert(0, lib_dir)
    import transform as transform_mod

    if transform_type not in transform_mod.TRANSFORMS:
        print(f"    {C.red(f'Unknown transform: {transform_type}')}")
        return
    transform_mod.TRANSFORMS[transform_type](str(src), str(dest))
    print(f"    {C.green('transformed:')} {dest}")


def merge_config(
    strategy: str, target: Path, source: Path, payload: "PayloadContext", dry_run: bool
) -> None:
    if dry_run:
        print(f"    {C.dim(f'[dry-run] merge ({strategy}): {target}')}")
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    with _expand_source(strategy, source) as resolved_path:
        lib_dir = str(payload.payload_dir / "lib")
        if lib_dir not in sys.path:
            sys.path.insert(0, lib_dir)
        import merge_json

        if strategy not in merge_json.STRATEGIES:
            print(f"    {C.red(f'Unknown strategy: {strategy}')}")
            return
        try:
            merge_json.STRATEGIES[strategy](str(target), str(resolved_path))
        except ValueError as e:
            print(
                f"    {C.red('ERROR')} Cannot update configuration, parse error in file {target}. Please fix the error: {e}"
            )
            return
        print(f"    {C.green('merged:')} {target}")


def cleanup_legacy_config_merge(
    cm: Dict[str, Any], ade: str, payload: "PayloadContext", dry_run: bool
) -> None:
    """Strip Snyk entries from superseded config_merge locations.

    Older installer versions wrote Copilot hooks to ``~/.copilot/hooks.json``,
    but Copilot reads ``~/.copilot/hooks/hooks.json``. Each ``dest`` listed
    under the config_merge's ``legacy_targets`` is unmerged with the same
    strategy as the live target, then deleted (with its ``.bak``) once no entries
    remain — so an upgrade or uninstall doesn't leave dead config at the old path.
    Only Snyk-owned entries are removed, so a file a user added other hooks to is
    left in place. Idempotent.
    """
    for rel in cm.get("legacy_targets", []):
        target = resolve_ade_path(ade, rel)
        if not target.is_file():
            continue
        strategy = cm["strategy"].replace("merge_", "unmerge_", 1)
        if dry_run:
            print(f"    {C.dim(f'[dry-run] clean legacy ({strategy}): {target}')}")
            continue
        with _expand_source(strategy, payload.resolve_src(cm["source"])) as resolved_path:
            lib_dir = str(payload.payload_dir / "lib")
            if lib_dir not in sys.path:
                sys.path.insert(0, lib_dir)
            import merge_json

            if strategy not in merge_json.STRATEGIES:
                continue
            try:
                merge_json.STRATEGIES[strategy](str(target), str(resolved_path))
            except ValueError:
                continue
        _remove_if_no_hooks(target, dry_run)


def _remove_if_no_hooks(target: Path, dry_run: bool) -> None:
    """Delete a hooks.json (and its .bak) left with no remaining hook entries."""
    try:
        data = json.loads(target.read_text())
    except (OSError, ValueError):
        return
    if data.get("hooks"):
        return
    remove_file(target, dry_run)
    remove_file(Path(str(target) + ".bak"), dry_run)


def remove_file(path: Path, dry_run: bool) -> None:
    if not path.exists():
        return
    if dry_run:
        print(f"    {C.dim(f'[dry-run] remove: {path}')}")
        return
    path.unlink()
    print(f"    {C.green('removed:')} {path}")


def remove_pycache_under(root: Path, dry_run: bool) -> None:
    if not root.is_dir():
        return
    # Recursive: hook scripts live several levels below the install root
    # (e.g. .snyk-studio/components/scripts/), so any __pycache__ they produce
    # is nested. A non-recursive glob would miss it and leave the directory
    # non-empty, blocking remove_empty_parents from pruning the tree.
    for d in root.rglob("__pycache__"):
        if d.is_dir():
            if dry_run:
                print(f"    {C.dim(f'[dry-run] remove: {d}/')}")
            else:
                shutil.rmtree(d)
                print(f"    {C.green('removed:')} {d}/")


def remove_empty_parents(directory: Path, stop: Path, dry_run: bool) -> None:
    current = directory
    while current != stop and current.is_dir():
        try:
            if any(current.iterdir()):
                break
        except PermissionError:
            break
        if dry_run:
            print(f"    {C.dim(f'[dry-run] rmdir: {current}/')}")
            current = current.parent
            continue
        current.rmdir()
        print(f"    {C.green('removed:')} {current}/")
        current = current.parent


def remove_legacy_workspace_files(sources: Dict[str, Any], workspace: Path, dry_run: bool) -> None:
    """Remove workspace files written by older installer versions at locations
    we no longer use (declared as ``legacy_files`` in the manifest), and prune
    their emptied parents + ``__pycache__``.

    Run from both install and uninstall: on install it migrates an older layout
    (e.g. ``.snyk/studio/...``, which collided with a repo's existing ``.snyk``
    policy file) by deleting the stale copy after the current one is written; on
    uninstall it guarantees cleanup is complete regardless of which version
    performed the original install. ``remove_empty_parents`` stops at any
    non-empty directory, so a sibling ``.snyk`` policy file (or any other user
    content) is preserved — only the empty tree we created is removed.
    """
    legacy_files = sources.get("legacy_files", [])
    if not legacy_files:
        return

    for f in legacy_files:
        remove_file(resolve_install_path(workspace, f["dest"]), dry_run)

    install_roots = set()
    for f in legacy_files:
        dest = resolve_install_path(workspace, f["dest"])
        try:
            rel = dest.relative_to(workspace.resolve())
        except ValueError:
            continue
        if rel.parts:
            install_roots.add(workspace / rel.parts[0])
    for root in install_roots:
        if root.is_dir():
            remove_pycache_under(root, dry_run)
    for f in legacy_files:
        dest = resolve_install_path(workspace, f["dest"])
        remove_empty_parents(dest.parent, workspace, dry_run)


def chmod_python_files(ade_home: Path, dry_run: bool) -> None:
    if _IS_WINDOWS or dry_run:
        return
    for py_file in ade_home.rglob("*.py"):
        rel = str(py_file.relative_to(ade_home))
        if "snyk" in rel or "hooks" in str(py_file.parent.name):
            try:
                py_file.chmod(0o755)
            except OSError:
                pass


# =============================================================================
# INSTALL / VERIFY / UNINSTALL
# =============================================================================


def _load_git_hooks(payload: PayloadContext) -> Any:
    """Import the installer's ``git_hooks`` module from the payload ``lib/``."""
    lib_dir = str(payload.payload_dir / "lib")
    if lib_dir not in sys.path:
        sys.path.insert(0, lib_dir)
    import git_hooks

    return git_hooks


def install_workspace_recipe(
    recipe_id: str,
    manifest: Manifest,
    payload: PayloadContext,
    workspace: Path,
    dry_run: bool,
) -> None:
    """Install a recipe whose sources live under the synthetic ``workspace`` key.

    Files are copied relative to *workspace* and any ``pre_commit_integration``
    block is wired up via the detected hook manager (pre-commit framework,
    Husky, or git native).
    """
    sources = manifest.recipes.get(recipe_id, {}).get("sources", {}).get("workspace", {})
    if not sources:
        return

    print(f"  {C.bold(f'[workspace] {recipe_id}')} -> {workspace}/")

    for f in sources.get("files", []):
        src = payload.resolve_src(f["src"])
        dest = resolve_install_path(workspace, f["dest"])
        copy_file(src, dest, dry_run)

    for t in sources.get("transforms", []):
        src = payload.resolve_src(t["src"])
        dest = resolve_install_path(workspace, t["dest"])
        apply_transform(t["type"], src, dest, payload, dry_run)

    pci = sources.get("pre_commit_integration")
    if pci:
        command = expand_install_tokens(pci["command"], workspace)
        tag = pci.get("tag", "snyk-secure-at-commit")
        if dry_run:
            print(f"    {C.dim(f'[dry-run] pre-commit integrate ({tag}): {command}')}")
        else:
            git_hooks = _load_git_hooks(payload)
            spec = git_hooks.HookSpec(tag=tag, command=command)
            try:
                manager, installed, path = git_hooks.install_hook(workspace, spec)
            except FileNotFoundError as e:
                print(f"    {C.red('ERROR')} pre-commit integration skipped: {e}")
            else:
                label = f"{manager} -> {path}"
                if installed:
                    print(f"    {C.green('hook installed')} {label}")
                else:
                    print(f"    {C.dim('hook unchanged: ' + label)}")

    # chmod +x on Python files (covers both workspace-local and user-data dests)
    for f in sources.get("files", []):
        dest = resolve_install_path(workspace, f["dest"])
        if dest.suffix == ".py" and dest.exists() and not _IS_WINDOWS and not dry_run:
            try:
                dest.chmod(0o755)
            except OSError:
                pass

    # Migrate away from older layouts: the current files are in place and the
    # hook shim (replaced by tag, so it now points at the new path) is wired —
    # delete any stale copy an older installer version left behind.
    remove_legacy_workspace_files(sources, workspace, dry_run)


def verify_workspace_recipe(
    recipe_id: str,
    manifest: Manifest,
    payload: PayloadContext,
    workspace: Path,
) -> bool:
    sources = manifest.recipes.get(recipe_id, {}).get("sources", {}).get("workspace", {})
    if not sources:
        return True

    print(f"  {C.bold(f'[workspace] {recipe_id}')}")
    ok = True

    for f in sources.get("files", []):
        dest = resolve_install_path(workspace, f["dest"])
        label = _display_path(dest, workspace)
        if dest.exists():
            print(f"    {C.green('OK')} {label}")
        else:
            print(f"    {C.red('MISSING')} {label}")
            ok = False

    pci = sources.get("pre_commit_integration")
    if pci:
        git_hooks = _load_git_hooks(payload)
        command = expand_install_tokens(pci["command"], workspace)
        spec = git_hooks.HookSpec(tag=pci.get("tag", "snyk-secure-at-commit"), command=command)
        manager, found, path = git_hooks.verify_hook(workspace, spec)
        if found:
            shim_label = _display_path(Path(path), workspace)
            print(f"    {C.green('OK')} pre-commit shim present ({manager}: {shim_label})")
        else:
            print(f"    {C.red('MISSING')} pre-commit shim ({manager})")
            ok = False
    return ok


def uninstall_workspace_recipe(
    recipe_id: str,
    manifest: Manifest,
    payload: PayloadContext,
    workspace: Path,
    dry_run: bool,
) -> None:
    """Uninstall a workspace-scoped recipe symmetrically.

    Removes the pre-commit integration plus every workspace-local file the
    recipe installed, then cleans up `__pycache__` directories and empty
    parents under each top-level install root.
    """
    sources = manifest.recipes.get(recipe_id, {}).get("sources", {}).get("workspace", {})
    if not sources:
        return

    print(f"  {C.bold(f'[workspace] {recipe_id}')}")

    pci = sources.get("pre_commit_integration")
    if pci:
        tag = pci.get("tag", "snyk-secure-at-commit")
        if dry_run:
            print(f"    {C.dim(f'[dry-run] pre-commit unintegrate ({tag})')}")
        else:
            git_hooks = _load_git_hooks(payload)
            command = expand_install_tokens(pci["command"], workspace)
            spec = git_hooks.HookSpec(tag=tag, command=command)
            manager, removed, path = git_hooks.uninstall_hook(workspace, spec)
            if removed:
                print(f"    {C.green('hook removed:')} {manager} -> {path}")

    files = sources.get("files", [])
    transforms = sources.get("transforms", [])

    for f in files:
        remove_file(resolve_install_path(workspace, f["dest"]), dry_run)
    for t in transforms:
        remove_file(resolve_install_path(workspace, t["dest"]), dry_run)

    # Remove pycache + empty parents under each top-level install root within
    # the workspace.
    install_roots = set()
    for f in files:
        dest = resolve_install_path(workspace, f["dest"])
        try:
            rel = dest.relative_to(workspace.resolve())
        except ValueError:
            continue
        if rel.parts:
            install_roots.add(workspace / rel.parts[0])
    for root in install_roots:
        if root.is_dir():
            remove_pycache_under(root, dry_run)
    for f in files:
        dest = resolve_install_path(workspace, f["dest"])
        remove_empty_parents(dest.parent, workspace, dry_run)

    # Also clear any tree left by an older installer version (different dest).
    remove_legacy_workspace_files(sources, workspace, dry_run)


def install_recipe(
    recipe_id: str, ade: str, manifest: Manifest, payload: PayloadContext, dry_run: bool
) -> None:
    sources = manifest.get_sources(recipe_id, ade)
    if not sources:
        return

    ade_home = get_ade_home(ade)
    print(f"  {C.bold(f'[{ade}] {recipe_id}')}")

    # Copy files
    for f in sources.get("files", []):
        src = payload.resolve_src(f["src"])
        dest = resolve_ade_path(ade, f["dest"])
        copy_file(src, dest, dry_run)

    # Apply transforms
    for t in sources.get("transforms", []):
        src = payload.resolve_src(t["src"])
        dest = resolve_ade_path(ade, t["dest"])
        apply_transform(t["type"], src, dest, payload, dry_run)

    # Merge config
    cm = sources.get("config_merge")
    if cm:
        target = resolve_ade_path(ade, cm["target"])
        source = payload.resolve_src(cm["source"])
        if sys.platform == "darwin" and ade not in CLI_ADES and source.name == ".mcp.json":
            source = payload.resolve_src("mcp/.mcp.mac.json")

        merge_config(cm["strategy"], target, source, payload, dry_run)
        cleanup_legacy_config_merge(cm, ade, payload, dry_run)

    # chmod +x on Python files
    chmod_python_files(ade_home, dry_run)


def verify_recipe(recipe_id: str, ade: str, manifest: Manifest, payload: PayloadContext) -> bool:
    sources = manifest.get_sources(recipe_id, ade)
    if not sources:
        return True

    print(f"  {C.bold(f'[{ade}] {recipe_id}')}")
    ok = True

    # Check files
    for f in sources.get("files", []):
        dest = resolve_ade_path(ade, f["dest"])
        if dest.exists():
            print(f"    {C.green('OK')} {f['dest']}")
        else:
            print(f"    {C.red('MISSING')} {f['dest']}")
            ok = False

    # Check transforms
    for t in sources.get("transforms", []):
        dest = resolve_ade_path(ade, t["dest"])
        if dest.exists():
            print(f"    {C.green('OK')} {t['dest']}")
        else:
            print(f"    {C.red('MISSING')} {t['dest']}")
            ok = False

    # Verify config merge
    cm = sources.get("config_merge")
    if cm:
        strategy = cm["strategy"].replace("merge_", "verify_", 1)
        target = resolve_ade_path(ade, cm["target"])
        with _expand_source(strategy, payload.resolve_src(cm["source"])) as resolved_path:
            lib_dir = str(payload.payload_dir / "lib")
            if lib_dir not in sys.path:
                sys.path.insert(0, lib_dir)
            import merge_json

            try:
                if (
                    sys.platform == "darwin"
                    and ade not in CLI_ADES
                    and resolved_path.name == ".mcp.json"
                ):
                    resolved_path = payload.resolve_src("mcp/.mcp.mac.json")

                merge_json.STRATEGIES[strategy](str(target), str(resolved_path))
                print(f"    {C.green('OK')} hooks registered in {cm['target']}")
            except (SystemExit, KeyError):
                print(f"    {C.red('MISSING')} hooks in {cm['target']}")
                ok = False
            except ValueError as e:
                print(
                    f"    {C.red('ERROR')} Cannot update configuration, parse error in file {cm['target']}. Please fix the error: {e}"
                )
                ok = False

    return ok


def uninstall_ade_recipe(
    recipe_id: str,
    ade: str,
    manifest: Manifest,
    payload: PayloadContext,
    dry_run: bool,
) -> None:
    """Uninstall a single ADE-scoped recipe for a single ADE.

    Extracted from ``uninstall()`` so a stale-conflict cleanup step (the
    fix for the "dirty install" PR feedback) can target a single
    ``(recipe, ADE)`` pair without sweeping the full ADE list. Skips
    workspace-scoped recipes — those need ``uninstall_workspace_recipe``.
    """
    sources = manifest.get_sources(recipe_id, ade)
    if not sources:
        return

    ade_home = get_ade_home(ade)
    print(f"  {C.bold(f'[{ade}] {recipe_id}')}")

    for f in sources.get("files", []):
        remove_file(resolve_ade_path(ade, f["dest"]), dry_run)

    for t in sources.get("transforms", []):
        remove_file(resolve_ade_path(ade, t["dest"]), dry_run)

    hooks_dir = ade_home / "hooks"
    if hooks_dir.is_dir():
        remove_pycache_under(hooks_dir, dry_run)
        lib_dir = hooks_dir / "lib"
        if lib_dir.is_dir():
            remove_pycache_under(lib_dir, dry_run)

    for f in sources.get("files", []):
        dest = resolve_ade_path(ade, f["dest"])
        remove_empty_parents(dest.parent, ade_home, dry_run)
    for t in sources.get("transforms", []):
        dest = resolve_ade_path(ade, t["dest"])
        remove_empty_parents(dest.parent, ade_home, dry_run)

    cm = sources.get("config_merge")
    if cm:
        strategy = cm["strategy"].replace("merge_", "unmerge_", 1)
        target = resolve_ade_path(ade, cm["target"])
        if dry_run:
            print(f"    {C.dim(f'[dry-run] unmerge ({strategy}): {target}')}")
        else:
            with _expand_source(  # nosec B324 — manifest-supplied source path validated by payload.resolve_src
                strategy, payload.resolve_src(cm["source"])
            ) as resolved_path:
                merge_lib_dir = str(payload.payload_dir / "lib")
                if merge_lib_dir not in sys.path:
                    sys.path.insert(0, merge_lib_dir)
                import merge_json

                if strategy in merge_json.STRATEGIES:
                    merge_json.STRATEGIES[strategy](str(target), str(resolved_path))
                    print(f"    {C.green('unmerged:')} {target}")
        cleanup_legacy_config_merge(cm, ade, payload, dry_run)


def uninstall(
    ades: List[str],
    manifest: Manifest,
    payload: PayloadContext,
    workspace: Optional[Path],
    dry_run: bool,
) -> None:
    print(f"  {C.bold('Uninstalling Snyk recipes...')}")
    print()

    for ade in ades:
        ade_home = get_ade_home(ade)
        print(f"  {C.bold(ade)} ({ade_home}/):")

        for recipe_id in manifest.all_recipe_ids():
            if manifest.is_workspace_scoped(recipe_id):
                continue
            uninstall_ade_recipe(recipe_id, ade, manifest, payload, dry_run)

        print()

    # Workspace-scoped recipes are installed once per workspace regardless of
    # how many ADEs were targeted, so uninstall them once too — after the
    # per-ADE pass so a single ADE picked at install time is enough to clean up.
    workspace_recipes = [
        rid for rid in manifest.all_recipe_ids() if manifest.is_workspace_scoped(rid)
    ]
    if workspace_recipes:
        if workspace is None:
            print(
                f"  {C.yellow('NOTE')} no workspace resolved "
                "(pass --workspace or run inside a git repo); "
                f"skipping workspace-scoped recipes: {', '.join(workspace_recipes)}"
            )
        else:
            print(f"  {C.bold('workspace')} ({workspace}/):")
            for recipe_id in workspace_recipes:
                uninstall_workspace_recipe(recipe_id, manifest, payload, workspace, dry_run)
            print()


# =============================================================================
# DISPLAY HELPERS
# =============================================================================


def print_banner() -> None:
    print(C.cyan(C.bold("")))
    print(C.cyan("  " + "\u2554" + "\u2550" * 56 + "\u2557"))
    print(C.cyan("  " + "\u2551" + "        SNYK STUDIO RECIPES INSTALLER".ljust(56) + "\u2551"))
    print(C.cyan("  " + "\u255a" + "\u2550" * 56 + "\u255d"))
    print()


def show_plan(
    ades: List[str],
    recipes: List[str],
    profile: str,
    manifest: Manifest,
    workspace: Optional[Path],
) -> None:
    print(f"  {C.bold('Installation Plan')}")
    print("  " + "\u2500" * 54)
    print(f"  Profile:  {C.cyan(profile)}")
    print(f"  ADEs:     {C.cyan(' '.join(ades))}")
    if workspace is not None:
        print(f"  Workspace:{C.cyan(' ' + str(workspace))}")
    print()

    for ade in ades:
        ade_home = get_ade_home(ade)
        print(f"  {C.bold(ade)} -> {ade_home}/")

        for recipe_id in recipes:
            if manifest.is_workspace_scoped(recipe_id):
                continue
            sources = manifest.get_sources(recipe_id, ade)
            if sources.get("files") or sources.get("config_merge") or sources.get("transforms"):
                desc = manifest.recipes[recipe_id]["description"]
                print(f"    * {C.green(recipe_id)}: {desc}")
        print()

    workspace_recipes = [r for r in recipes if manifest.is_workspace_scoped(r)]
    if not workspace_recipes:
        return
    if workspace is None:
        print(
            f"  {C.yellow('NOTE')} no workspace resolved "
            "(pass --workspace or run inside a git repo); "
            f"skipping workspace-scoped recipes: {', '.join(workspace_recipes)}"
        )
        print()
        return
    print(f"  {C.bold('workspace')} -> {workspace}/")
    for recipe_id in workspace_recipes:
        desc = manifest.recipes[recipe_id]["description"]
        print(f"    * {C.green(recipe_id)}: {desc}")
    print()


def print_summary(ades: List[str], recipes: List[str], dry_run: bool) -> None:
    status = "[DRY RUN] " if dry_run else ""
    print()
    print(f"  {C.bold(f'{status}Installation complete')}")
    print("  " + "\u2500" * 54)
    print(f"  Recipes: {len(recipes)}")
    print(f"  ADEs:    {', '.join(ades)}")
    print()


# =============================================================================
# CONTROL IDENTIFIER (device-id)
# =============================================================================


def device_id_path() -> Path:
    """Path of the snyk-studio device-id file."""
    return Path.home() / ".snyk-studio" / "device-id"


def write_control_identifier(identifier: str, dry_run: bool) -> None:
    """Record the control identifier in the device-id file the recipes read."""
    path = device_id_path()
    print(f"  {C.bold('Control identifier')}")
    if dry_run:
        print(f"    [DRY RUN] would write device-id to {path}")
        print()
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Plain UTF-8 (no BOM); recipes read with utf-8-sig + .strip(), so a
        # trailing newline is harmless and keeps the file editor-friendly.
        path.write_text(identifier + "\n", encoding="utf-8")
        print(f"    {C.green('OK')} wrote device-id to {path}")
    except OSError as exc:
        # A device-id write failure only degrades telemetry (recipes tolerate
        # its absence), so warn but don't abort the recipe install.
        print(
            f"    {C.yellow('WARNING')} could not write device-id to {path}: {exc}",
            file=sys.stderr,
        )
    print()


# =============================================================================
# MAIN
# =============================================================================


def main() -> None:
    args = parse_args()

    if args.diag_dump:
        lib_dir = str(Path(__file__).resolve().parent / "lib")
        if lib_dir not in sys.path:
            sys.path.insert(0, lib_dir)
        import diag

        output_path = Path(args.out_file) if args.out_file else None
        diag.run(
            output_path=output_path,
            log_days=max(1, args.days),
            installer_path=Path(__file__).resolve(),
            ade_homes={ade: get_ade_home(ade) for ade in ADE_HOMES},
        )
        return

    payload = PayloadContext()
    payload.setup()
    manifest = Manifest(payload.manifest_path)

    # List mode
    if args.list_mode:
        manifest.list_recipes()
        return

    # Everything below can prompt for confirmation (prerequisites, ADE
    # selection, install/uninstall). On a non-interactive stdin those reads
    # would block forever, so fail fast unless -y was given (which skips them).
    # --verify is only exempt when --read-only is also set: that combination
    # (used internally by diag_dump) never prompts, but plain --verify still
    # falls through to check_prerequisites()'s prompts below.
    if (
        not args.yes
        and not (args.verify and args.read_only)
        and not args.list_mode
        and (not hasattr(sys.stdin, "isatty") or not sys.stdin.isatty())
    ):
        print(
            "  Error: interactive input required; re-run with -y (and flags such as "
            "--ade/--profile) to run non-interactively.",
            file=sys.stderr,
        )
        sys.exit(1)

    print_banner()

    # Record the control identifier (the ADS installer passes
    # --control-identifier) before anything that can fail, so the device-id is
    # provisioned even if a later step (verify, prerequisites, ADE selection)
    # does not complete.
    if args.control_identifier:
        write_control_identifier(args.control_identifier, args.dry_run)

    # Verify mode runs before the ADE-selection preamble below, but its
    # prerequisites step branches on --read-only: by default a user gets the
    # original check_prerequisites() experience (prompts, offers to
    # upgrade), while --read-only (passed by ``diag_dump``'s internal
    # ``--verify`` call) gets the side-effect-free print_prerequisite_versions()
    # so it never installs/upgrades/prompts as part of a diagnostic dump.
    if args.verify:
        print(f"  {C.bold('Prerequisites')}")
        if args.read_only:
            print_prerequisite_versions(
                snyk_version=manifest.prerequisite_version("snyk"),
                node_version=manifest.prerequisite_version("node"),
            )
        else:
            check_prerequisites(
                args.yes,
                snyk_version=manifest.prerequisite_version("snyk"),
                node_version=manifest.prerequisite_version("node"),
                no_latest_deps=args.no_latest_deps,
                nvm_version=manifest.prerequisite_version("nvm"),
            )
        print()
        ades = get_target_ades(args.ade, args.yes)
        workspace = resolve_workspace(args.workspace)
        recipes = manifest.resolve_recipes(args.profile)
        all_ok = True
        for ade in ades:
            for recipe_id in recipes:
                if manifest.is_workspace_scoped(recipe_id):
                    continue
                if not verify_recipe(recipe_id, ade, manifest, payload):
                    all_ok = False
        for recipe_id in recipes:
            if not manifest.is_workspace_scoped(recipe_id):
                continue
            if workspace is None:
                print(
                    f"  {C.yellow('NOTE')} skipping workspace-scoped {recipe_id}: "
                    "no workspace (pass --workspace or run inside a git repo)"
                )
                continue
            if not verify_workspace_recipe(recipe_id, manifest, payload, workspace):
                all_ok = False
        if all_ok:
            print(f"\n  {C.green('All checks passed.')}")
        else:
            print(f"\n  {C.red('Some checks failed.')}")
            sys.exit(1)
        return

    # Prerequisites
    print(f"  {C.bold('Prerequisites')}")
    check_prerequisites(
        args.yes,
        snyk_version=manifest.prerequisite_version("snyk"),
        node_version=manifest.prerequisite_version("node"),
        no_latest_deps=args.no_latest_deps,
        nvm_version=manifest.prerequisite_version("nvm"),
    )
    print()

    # ADE detection
    ades = get_target_ades(args.ade, args.yes)

    # Workspace resolution for workspace-scoped recipes (e.g. sac-hooks).
    # Explicit --workspace overrides everything; otherwise walk up from cwd
    # looking for a git repo; otherwise None (we'll skip workspace recipes
    # with a visible notice rather than guessing).
    workspace = resolve_workspace(args.workspace)

    # Uninstall mode
    if args.uninstall:
        uninstall(ades, manifest, payload, workspace, args.dry_run)
        print(f"  {C.green('Uninstall complete.')}")
        return

    # if auto configure is turned on and manual, need to remove rules
    def remove_legacy_SAI_directives(ade: str, scope: str) -> None:
        mcp_tool_name = SNYK_MCP_TOOL_NAMES[ade]
        print(f"    Cleaning up {scope} skills for {ade}...")
        run(
            [
                "snyk",
                "mcp",
                "configure",
                "--tool",
                mcp_tool_name,
                "--rm",
                "--rules-scope",
                scope,
                "--rule-type",
                "always-apply",
                "--workspace",
                ".",
                "--configure-mcp=false",
                "--configure-rules=true",
            ],
            timeout=10,
            shell=_IS_WINDOWS,
            creationflags=_CREATE_NO_WINDOW,
        )

    # Normal installation
    recipes = manifest.resolve_recipes(args.profile)
    show_plan(ades, recipes, args.profile, manifest, workspace)

    # Detect stale on-disk installs of recipes that are mutually exclusive
    # with what's about to be installed. Without this check, switching
    # profiles (e.g. default → experimental) would leave the old SAI files
    # behind so both SAI and SAC fire at once. Warn before the user commits
    # to the install so they can opt into cleanup with one prompt.
    stale_conflicts = manifest.detect_stale_conflicts(recipes)
    if stale_conflicts:
        print()
        print(f"  {C.yellow('WARNING')} Conflicting recipes are still installed on disk:")
        for active, conflicted, ade in stale_conflicts:
            print(f"    - [{ade}] {conflicted} conflicts with {active}")
        print("    Leaving them in place will cause both systems to fire at once.")
        clean_stale = False
        if args.dry_run:
            print(f"    {C.dim('[dry-run] would prompt to uninstall conflicting recipes')}")
        elif args.yes:
            clean_stale = True
        else:
            reply = (
                input("  Uninstall conflicting recipes before installing? (y/n) ").strip().lower()
            )
            clean_stale = reply in ("y", "yes")
        if clean_stale:
            print()
            for _active, conflicted, ade in stale_conflicts:
                uninstall_ade_recipe(conflicted, ade, manifest, payload, args.dry_run)
        print()

    if not args.yes and not args.dry_run:
        reply = input("  Proceed with installation? (y/n) ").strip().lower()
        if reply not in ("y", "yes"):
            print("  Cancelled.")
            return

    # ADE conflict detection after user has confirmed installation.
    #
    # Policy: only *workspace*-scoped rule/skill conflicts prompt for consent —
    # those live in the user's project and may be deliberate. Global rules/skills
    # and Snyk extension settings are auto-resolved with a warning, since they
    # are the shared defaults the installer manages.
    def resolve_directive_conflicts(ade: str, resource_type: str, label: str) -> None:
        # get_conflicting_resource_scope returns only the scopes where a conflict
        # was actually found, so we never prompt for a workspace cleanup on a
        # global-only conflict, or auto-run a global cleanup for a workspace-only
        # one.
        for scope in manifest.get_conflicting_resource_scope(ade, resource_type):
            if args.dry_run:
                print(f"    {C.dim(f'[dry-run] would remove conflicting {scope} {label}')}")
                continue
            if scope == WORKSPACE and not args.yes:
                reply = (
                    input(
                        f"  Run 'snyk mcp configure' to remove the conflicting workspace {label} for {ade}? (y/n) "
                    )
                    .strip()
                    .lower()
                )
                if reply not in ("y", "yes"):
                    continue
            remove_legacy_SAI_directives(ade, scope)

    for ade in ades:
        # Snyk extension settings: auto-resolve with a warning (no prompt).
        conflicting_paths = manifest.are_extension_settings_conflicting(ade)
        if conflicting_paths:
            print(f"  {C.yellow('WARNING')} Conflicting Snyk extension setting(s) found for: {ade}")
            if args.dry_run:
                print(f"    {C.dim('[dry-run] would set executionFrequency to Manual in:')}")
                for path in conflicting_paths:
                    print(f"    {C.dim('- ' + path)}")
            else:
                updated = manifest.resolve_extension_conflicts(conflicting_paths)
                if updated:
                    print(f"    Set executionFrequency to Manual for {ade}")

        # Global rules auto-resolve with a warning; workspace rules prompt.
        if manifest.are_rules_conflicting(ade):
            print(f"  {C.yellow('WARNING')} Conflicting rule(s) found for: {ade}")
            resolve_directive_conflicts(ade, "rules", "rule(s)")

        # Same policy for skills.
        if manifest.are_skills_conflicting(ade):
            print(f"  {C.yellow('WARNING')} Conflicting skill(s) found for: {ade}")
            resolve_directive_conflicts(ade, "skills", "skill(s)")

    # Install
    for ade in ades:
        for recipe_id in recipes:
            if manifest.is_workspace_scoped(recipe_id):
                continue
            install_recipe(recipe_id, ade, manifest, payload, args.dry_run)
    for recipe_id in recipes:
        if not manifest.is_workspace_scoped(recipe_id):
            continue
        if workspace is None:
            # show_plan already printed the skip notice; don't repeat it here.
            continue
        install_workspace_recipe(recipe_id, manifest, payload, workspace, args.dry_run)

    # Post-install verification
    if not args.dry_run:
        print()
        print(f"  {C.bold('Verification')}")
        all_ok = True
        for ade in ades:
            for recipe_id in recipes:
                if manifest.is_workspace_scoped(recipe_id):
                    continue
                if not verify_recipe(recipe_id, ade, manifest, payload):
                    all_ok = False
        for recipe_id in recipes:
            if not manifest.is_workspace_scoped(recipe_id):
                continue
            if workspace is None:
                continue
            if not verify_workspace_recipe(recipe_id, manifest, payload, workspace):
                all_ok = False
        if not all_ok:
            print(f"\n  {C.yellow('Some verifications failed. Check output above.')}")

    print_summary(ades, recipes, args.dry_run)


if __name__ == "__main__":
    main()
