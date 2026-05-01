#!/usr/bin/env python3
"""
Snyk Studio Recipes Installer
==============================

Cross-platform installer for Snyk security recipes.
Installs skills, hooks, rules, commands, and MCP configs
into Cursor and/or Claude Code global directories.

Usage:
    python snyk-studio-installer.py [options]

Options:
    --profile <name>      Installation profile (default, minimal)
    --ade <cursor|claude>  Target specific ADE (auto-detect if omitted)
    --dry-run             Show what would be installed without making changes
    --uninstall           Remove Snyk recipes from detected ADEs
    --verify              Verify installed files and merged configs match manifest
    --list                List available recipes and profiles
    -y, --yes             Skip confirmation prompts
    -h, --help            Show this help message
"""

import argparse
import contextlib
import filecmp
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

# When set (by generated install.sh / install.ps1 / install.py), manifest and recipe sources
# live under this directory (flat layout from the release zip).
BUNDLE_ENV = "SNYK_STUDIO_BUNDLE_ROOT"

GLOBAL = "global"
WORKSPACE = "workspace"
SNYK_MINIMUM_VERSION = "1.1302.0"


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
        if sys.platform == "win32":
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

    def red(self, t: str) -> str: return self._w("0;31", t)
    def green(self, t: str) -> str: return self._w("0;32", t)
    def yellow(self, t: str) -> str: return self._w("1;33", t)
    def cyan(self, t: str) -> str: return self._w("0;36", t)
    def bold(self, t: str) -> str: return self._w("1", t)
    def dim(self, t: str) -> str: return self._w("2", t)
    def underline(self, t: str) -> str: return self._w("4", t)


C = Color()


# =============================================================================
# ARGUMENT PARSING
# =============================================================================

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="snyk-studio-installer",
        description="Snyk Studio Recipes Installer",
    )
    parser.add_argument("--profile", default="default",
                        help="Installation profile (default: 'default')")
    parser.add_argument("--ade", choices=["cursor", "claude"], default=None,
                        help="Target specific ADE (auto-detect if omitted)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be installed without making changes")
    parser.add_argument("--uninstall", action="store_true",
                        help="Remove Snyk recipes from detected ADEs")
    parser.add_argument("--verify", action="store_true",
                        help="Verify installed files and merged configs match manifest")
    parser.add_argument("--list", action="store_true", dest="list_mode",
                        help="List available recipes and profiles")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Skip confirmation prompts")
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

class Manifest:
    """Parsed manifest.json with profile resolution."""

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
        return [r for r in all_ids if r in active and self.recipes[r].get("enabled", True)]

    def get_sources(self, recipe_id: str, ade: str) -> Dict[str, Any]:
        return self.recipes.get(recipe_id, {}).get("sources", {}).get(ade, {})

    def all_recipe_ids(self) -> List[str]:
        return list(self.recipes.keys())

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

    def are_rules_conflicting(self, ade: str) -> bool:
        """Determine if there are existing rules that would conflict when adding the SAI hooks"""

        rule_start_tag = "<!--# BEGIN SNYK GLOBAL RULE -->"
        rule_end_tag = "<!--# END SNYK GLOBAL RULE -->"
        home = Path.home()
        rules_locations = self.conflicting_resources.get(ade, {}).get("rules", [])

        for rule in rules_locations:
            rule_location = Path(rule.get("src"))
            rule_location = Path(home, rule_location) if rule.get(GLOBAL) else rule_location

            if rule_location.exists():
                try:
                    # check for existence of start/end tags in the rules file
                    content = rule_location.read_text(encoding="utf-8")
                    if rule_start_tag in content and rule_end_tag in content:
                        return True
                except Exception:
                    pass

        return False

    def are_skills_conflicting(self, ade: str) -> bool:
        """Determine if there are existing skills that would conflict when adding the SAI hooks"""

        home = Path.home()
        skills_locations = self.conflicting_resources.get(ade, {}).get("skills", [])

        for skill in skills_locations:
            skill_location = Path(skill.get("src"))
            skill_location = Path(home, skill_location) if skill.get(GLOBAL) else skill_location
            if skill_location.exists():
                return True
        return False

    def get_conflicting_resource_scope(self, ade: str, resource_type:str) -> List[str]:
        """Determine if the given ADE's rule/skill exists at the global or workspace level"""
        resource_locations = self.conflicting_resources.get(ade, {}).get(resource_type, [])
        return list(map(lambda x: GLOBAL if x.get(GLOBAL) else WORKSPACE, resource_locations))

    def are_extension_settings_conflicting(self, ade: str) -> bool:
        """Determine if the Snyk extension setting has conflicting values that would override hooks installation"""

        home = Path.home()
        auto_configure = "snyk.securityAtInception.autoConfigureSnykMcpServer"
        execution_frequency = "snyk.securityAtInception.executionFrequency"
        path_prefix = ""
        settings_paths = []

        # set path prefix paths depending on OS
        if sys.platform == "win32":
            path_prefix = Path(os.environ.get("APPDATA", str(home / "AppData/Roaming")))
        elif sys.platform == "darwin":
            path_prefix = home / "Library/Application Support"
        else:  # Linux
            path_prefix = Path(os.environ.get("XDG_CONFIG_HOME", str(home / ".config")))

        for setting in self.conflicting_resources.get(ade, {}).get("extension-settings", []):
            setting_path = Path(setting.get("src"))
            setting_path = Path(path_prefix, setting_path) if setting.get(GLOBAL) else setting_path

            settings_paths.append(setting_path)

        # Merge settings hierarchically, workspace settings will overwrite global
        resolved_settings: Dict[str, Any] = {}

        for path in settings_paths:
            try:
                # 1. Basic validation: must exist and be named settings.json
                if not path.exists() or ".." in str(path):
                    raise ValueError(f"Error parsing manifest: conflicting-resources/${ade}/extension-settings has a path with .. which is not allowed: ${path} ")

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
                with open(safe_path_abs, "r", encoding="utf-8") as f:
                    content = f.read()

                content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
                # Strip trailing commas before closing braces/brackets
                content = re.sub(r",\s*([\]}])", r"\1", content)
                settings_data = json.loads(content)

                resolved_settings.update(settings_data)
            except Exception:
                continue

        # Check the final resolved state
        return (resolved_settings.get(auto_configure, False) and
            resolved_settings.get(execution_frequency, "Manual") != "Manual")


# =============================================================================
# PREREQUISITES
# =============================================================================

def check_prerequisites(auto_yes: bool) -> None:
    warnings = 0

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
    print(f"  {C.green('OK')} Python {py_ver}")

    snyk_path = shutil.which("snyk")

    parse_version = lambda v: tuple(map(int, v.split('.')))

    minimum_snyk_version = parse_version(SNYK_MINIMUM_VERSION)

    if snyk_path:
        try:
            r = subprocess.run(["snyk", "--version"], capture_output=True, text=True, timeout=10)
            ver_str = r.stdout.strip().splitlines()[0] if r.stdout else "unknown"

            try:
                # Snyk version can be "1.1302.0" or "1.1302.0 (standalone)"
                match = re.match(r"(\d+\.\d+\.\d+)", ver_str)
                if match:
                    current_version = parse_version(match.group(1))
                    if current_version < minimum_snyk_version:
                        print(f"  {C.yellow('WARNING')} Snyk CLI {ver_str} is outdated (min: {SNYK_MINIMUM_VERSION})")
                        warnings += 1
                    else:
                        print(f"  {C.green('OK')} Snyk CLI {ver_str}")
                else:
                    print(f"  {C.green('OK')} Snyk CLI {ver_str} (could not parse version)")
            except Exception:
                print(f"  {C.green('OK')} Snyk CLI {ver_str}")
        except Exception:
            print(f"  {C.green('OK')} Snyk CLI (version check failed)")
    else:
        print(f"  {C.yellow('WARNING')} Snyk CLI not found")
        print("    Install with: npm install -g snyk")
        warnings += 1

    if snyk_path:
        try:
            r = subprocess.run(["snyk", "whoami"], capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                print(f"  {C.green('OK')} Snyk authenticated")
            else:
                print(f"  {C.yellow('WARNING')} Snyk not authenticated")
                print("    Run: snyk auth")
                warnings += 1
        except Exception:
            print(f"  {C.yellow('WARNING')} Snyk auth check failed")
            warnings += 1

    if warnings > 0 and not auto_yes:
        reply = input("\n  Continue with warnings? (y/n) ").strip().lower()
        if reply not in ("y", "yes"):
            sys.exit(1)


# =============================================================================
# ADE DETECTION
# =============================================================================

ADE_HOMES = {"cursor": ".cursor", "claude": ".claude"}


def get_ade_home(ade: str) -> Path:
    return Path.home() / ADE_HOMES[ade]


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
        r = subprocess.run(
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

    if (home / ".cursor").is_dir():
        detected.append("cursor")
    elif _cursor_app_bundle_exists():
        detected.append("cursor")
    elif sys.platform != "win32" and _cursor_process_running():
        detected.append("cursor")

    if (home / ".claude").is_dir():
        detected.append("claude")
    elif shutil.which("claude"):
        detected.append("claude")

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

    print(f"  {C.yellow('WARNING')} No supported ADE detected")
    print()
    print("  Which ADE(s) would you like to install for?")
    print("  1) Cursor")
    print("  2) Claude Code")
    print("  3) Both")
    print()
    reply = input("  Choose (1/2/3): ").strip()
    choices = {"1": ["cursor"], "2": ["claude"], "3": ["cursor", "claude"]}
    if reply in choices:
        return choices[reply]
    print(C.red("Invalid choice"))
    sys.exit(1)


# =============================================================================
# PLATFORM-AWARE HOOK COMMAND REWRITING
# =============================================================================

_WIN32_REWRITE_STRATEGIES: frozenset[str] = frozenset({"cursor_hooks", "claude_settings"})


@contextlib.contextmanager
def _platform_source(strategy: str, source: Path) -> Iterator[Path]:
    """Context manager yielding a platform-rewritten source path for Windows hook/settings strategies.

    Source files use Unix commands (python3, $HOME) that silently fail on Windows; they must be
    rewritten to (py -3, %USERPROFILE%). Without a temp file, merge_json (which only accepts paths)
    would receive the original source and install the wrong commands on Windows.
    delete=False is required because Windows cannot read a file that is still open.
    """
    should_create_temp = sys.platform == "win32" and any(s in strategy for s in _WIN32_REWRITE_STRATEGIES)
    if not should_create_temp:
        yield source
        return
    with open(source) as f:
        data = json.load(f)
    data = rewrite_hook_commands_for_platform(data)
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    tmp_path = Path(tmp.name)
    try:
        json.dump(data, tmp, indent=2)
        tmp.write("\n")
        tmp.close()
        yield tmp_path
    finally:
        with contextlib.suppress(OSError):
            tmp_path.unlink()


def rewrite_hook_commands_for_platform(data: Dict[str, Any]) -> Dict[str, Any]:
    """On Windows, rewrite python3/$HOME hook commands to py -3/%USERPROFILE%."""
    if sys.platform != "win32":
        return data

    def _rewrite(cmd: str) -> str:
        if not cmd.startswith("python3 "):
            return cmd
        cmd = cmd.replace("python3 ", "py -3 ", 1)
        cmd = cmd.replace("$HOME/", "%USERPROFILE%\\", 1)
        cmd = cmd.replace('"$HOME/', '"%USERPROFILE%\\', 1)
        cmd = cmd.replace("/", "\\")
        return cmd

    def _walk(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: _walk(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_walk(item) for item in obj]
        if isinstance(obj, str) and obj.startswith("python3 "):
            return _rewrite(obj)
        return obj

    return _walk(data)


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


def apply_transform(transform_type: str, src: Path, dest: Path,
                    payload: PayloadContext, dry_run: bool) -> None:
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


def merge_config(strategy: str, target: Path, source: Path, payload: "PayloadContext", dry_run: bool) -> None:
    if dry_run:
        print(f"    {C.dim(f'[dry-run] merge ({strategy}): {target}')}")
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    with _platform_source(strategy, source) as resolved_path:
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
            print(f"    {C.red('ERROR')} Cannot update configuration, parse error in file {target}. Please fix the error: {e}")
            return
        print(f"    {C.green('merged:')} {target}")


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
    for d in root.glob("__pycache__"):
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


def chmod_python_files(ade_home: Path, dry_run: bool) -> None:
    if sys.platform == "win32" or dry_run:
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

def install_recipe(recipe_id: str, ade: str, manifest: Manifest,
                   payload: PayloadContext, dry_run: bool) -> None:
    sources = manifest.get_sources(recipe_id, ade)
    if not sources:
        return

    ade_home = get_ade_home(ade)
    print(f"  {C.bold(f'[{ade}] {recipe_id}')}")

    # Copy files
    for f in sources.get("files", []):
        src = payload.resolve_src(f["src"])
        dest = Path.home() / f["dest"]
        copy_file(src, dest, dry_run)

    # Apply transforms
    for t in sources.get("transforms", []):
        src = payload.resolve_src(t["src"])
        dest = Path.home() / t["dest"]
        apply_transform(t["type"], src, dest, payload, dry_run)

    # Merge config
    cm = sources.get("config_merge")
    if cm:
        target = Path.home() / cm["target"]
        source = payload.resolve_src(cm["source"])
        merge_config(cm["strategy"], target, source, payload, dry_run)

    # chmod +x on Python files
    chmod_python_files(ade_home, dry_run)


def verify_recipe(recipe_id: str, ade: str, manifest: Manifest,
                  payload: PayloadContext) -> bool:
    sources = manifest.get_sources(recipe_id, ade)
    if not sources:
        return True

    print(f"  {C.bold(f'[{ade}] {recipe_id}')}")
    ok = True

    # Check files
    for f in sources.get("files", []):
        dest = Path.home() / f["dest"]
        if dest.exists():
            print(f"    {C.green('OK')} {f['dest']}")
        else:
            print(f"    {C.red('MISSING')} {f['dest']}")
            ok = False

    # Check transforms
    for t in sources.get("transforms", []):
        dest = Path.home() / t["dest"]
        if dest.exists():
            print(f"    {C.green('OK')} {t['dest']}")
        else:
            print(f"    {C.red('MISSING')} {t['dest']}")
            ok = False

    # Verify config merge
    cm = sources.get("config_merge")
    if cm:
        strategy = cm["strategy"].replace("merge_", "verify_", 1)
        target = Path.home() / cm["target"]
        with _platform_source(strategy, payload.resolve_src(cm["source"])) as resolved_path:
            lib_dir = str(payload.payload_dir / "lib")
            if lib_dir not in sys.path:
                sys.path.insert(0, lib_dir)
            import merge_json

            try:
                merge_json.STRATEGIES[strategy](str(target), str(resolved_path))
                print(f"    {C.green('OK')} hooks registered in {cm['target']}")
            except (SystemExit, KeyError):
                print(f"    {C.red('MISSING')} hooks in {cm['target']}")
                ok = False
            except ValueError as e:
                print(f"    {C.red('ERROR')} Cannot update configuration, parse error in file {cm['target']}. Please fix the error: {e}")
                ok = False

    return ok


def uninstall(ades: List[str], manifest: Manifest,
              payload: PayloadContext, dry_run: bool) -> None:
    print(f"  {C.bold('Uninstalling Snyk recipes...')}")
    print()

    for ade in ades:
        ade_home = get_ade_home(ade)
        print(f"  {C.bold(ade)} ({ade_home}/):")

        for recipe_id in manifest.all_recipe_ids():
            sources = manifest.get_sources(recipe_id, ade)
            if not sources:
                continue

            print(f"  {C.bold(f'[{ade}] {recipe_id}')}")

            # Remove files
            for f in sources.get("files", []):
                remove_file(Path.home() / f["dest"], dry_run)

            # Remove transformed files
            for t in sources.get("transforms", []):
                remove_file(Path.home() / t["dest"], dry_run)

            # Remove pycache
            hooks_dir = ade_home / "hooks"
            if hooks_dir.is_dir():
                remove_pycache_under(hooks_dir, dry_run)
                lib_dir = hooks_dir / "lib"
                if lib_dir.is_dir():
                    remove_pycache_under(lib_dir, dry_run)

            # Clean up empty directories
            for f in sources.get("files", []):
                dest = Path.home() / f["dest"]
                remove_empty_parents(dest.parent, ade_home, dry_run)
            for t in sources.get("transforms", []):
                dest = Path.home() / t["dest"]
                remove_empty_parents(dest.parent, ade_home, dry_run)

            # Unmerge config
            cm = sources.get("config_merge")
            if cm:
                strategy = cm["strategy"].replace("merge_", "unmerge_", 1)
                target = Path.home() / cm["target"]
                if dry_run:
                    print(f"    {C.dim(f'[dry-run] unmerge ({strategy}): {target}')}")
                else:
                    with _platform_source(strategy, payload.resolve_src(cm["source"])) as resolved_path:
                        lib_dir = str(payload.payload_dir / "lib")
                        if lib_dir not in sys.path:
                            sys.path.insert(0, lib_dir)
                        import merge_json
                        if strategy in merge_json.STRATEGIES:
                            merge_json.STRATEGIES[strategy](str(target), str(resolved_path))
                            print(f"    {C.green('unmerged:')} {target}")

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


def show_plan(ades: List[str], recipes: List[str], profile: str,
              manifest: Manifest) -> None:
    print(f"  {C.bold('Installation Plan')}")
    print("  " + "\u2500" * 54)
    print(f"  Profile:  {C.cyan(profile)}")
    print(f"  ADEs:     {C.cyan(' '.join(ades))}")
    print()

    for ade in ades:
        ade_home = get_ade_home(ade)
        print(f"  {C.bold(ade)} -> {ade_home}/")

        for recipe_id in recipes:
            sources = manifest.get_sources(recipe_id, ade)
            if sources.get("files") or sources.get("config_merge") or sources.get("transforms"):
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
# MAIN
# =============================================================================

def main() -> None:
    args = parse_args()
    payload = PayloadContext()
    payload.setup()
    manifest = Manifest(payload.manifest_path)

    # List mode
    if args.list_mode:
        manifest.list_recipes()
        return

    print_banner()

    # Prerequisites
    print(f"  {C.bold('Prerequisites')}")
    check_prerequisites(args.yes)
    print()

    # ADE detection
    ades = get_target_ades(args.ade, args.yes)

    # Uninstall mode
    if args.uninstall:
        uninstall(ades, manifest, payload, args.dry_run)
        print(f"  {C.green('Uninstall complete.')}")
        return

    # if auto configure is turned on and manual, need to remove rules
    def remove_legacy_SAI_directives(ade: str, scope: str) -> None:
        mcp_tool_name = "claude-cli" if ade == "claude" else ade
        print(f"    Cleaning up {scope} skills for {ade}...")
        subprocess.run(["snyk", "mcp", "configure",
            "--tool", mcp_tool_name, "--rm", "--rules-scope",
            scope, "--rule-type", "always-apply",
            "--workspace", ".", "--configure-mcp=false",
            "--configure-rules=true"], timeout=10)

    # ADE conflict detection
    for ade in ades:
        # check if any of the ADEs have snyk extension settings and if there are conflicts
        if manifest.are_extension_settings_conflicting(ade):
            print(f"  {C.yellow('WARNING')} Conflicting Snyk extension settings found for: {ade} - Please remove conflict by setting 'Secure At Inception Execution Frequency' to 'Manual'")
            print(
                f"    See documentation for more details: {C.underline('https://docs.snyk.io/integrations/snyk-studio-agentic-integrations/quickstart-guides-for-snyk-studio/github-copilot-guide#updating-secure-at-inception-settings')}"
            )
            if not args.yes and not args.dry_run:
                reply = input(f"  Install anyway for {ade}? (y/n) ").strip().lower()
                if reply not in ("y", "yes"):
                    print("  Cancelled.")
                    return
        if manifest.are_rules_conflicting(ade):
            print(f"  {C.yellow('WARNING')} Conflicting rule(s) found for: {ade}")
            reply = input(f"  Run 'snyk mcp configure' to remove the conflicting rules for {ade}? (y/n) ").strip().lower()
            if reply in ("y", "yes"):
                for scope in manifest.get_conflicting_resource_scope(ade, "rules"):
                        remove_legacy_SAI_directives(ade, scope)
        if manifest.are_skills_conflicting(ade):
            print(f"  {C.yellow('WARNING')} Conflicting skill(s) found for: {ade}")
            reply = input(f"  Run 'snyk mcp configure' to remove the conflicting skills for {ade}? (y/n) ").strip().lower()
            if reply in ("y", "yes"):
                for scope in manifest.get_conflicting_resource_scope(ade, "skills"):
                    remove_legacy_SAI_directives(ade, scope)

    # Verify mode
    if args.verify:
        recipes = manifest.resolve_recipes(args.profile)
        all_ok = True
        for ade in ades:
            for recipe_id in recipes:
                if not verify_recipe(recipe_id, ade, manifest, payload):
                    all_ok = False
        if all_ok:
            print(f"\n  {C.green('All checks passed.')}")
        else:
            print(f"\n  {C.red('Some checks failed.')}")
            sys.exit(1)
        return

    # Normal installation
    recipes = manifest.resolve_recipes(args.profile)
    show_plan(ades, recipes, args.profile, manifest)

    if not args.yes and not args.dry_run:
        reply = input("  Proceed with installation? (y/n) ").strip().lower()
        if reply not in ("y", "yes"):
            print("  Cancelled.")
            return

    # Install
    for ade in ades:
        for recipe_id in recipes:
            install_recipe(recipe_id, ade, manifest, payload, args.dry_run)

    # Post-install verification
    if not args.dry_run:
        print()
        print(f"  {C.bold('Verification')}")
        all_ok = True
        for ade in ades:
            for recipe_id in recipes:
                if not verify_recipe(recipe_id, ade, manifest, payload):
                    all_ok = False
        if not all_ok:
            print(f"\n  {C.yellow('Some verifications failed. Check output above.')}")

    print_summary(ades, recipes, args.dry_run)


if __name__ == "__main__":
    main()
