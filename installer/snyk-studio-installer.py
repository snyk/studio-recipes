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
import base64
import filecmp
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

# Embedded payload — replaced by build_installer.py in distribution mode.
PAYLOAD: Optional[str] = None


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
        self._tmpdir: Optional[str] = None
        self.payload_dir = Path()
        self.repo_root = Path()

    def setup(self) -> None:
        if PAYLOAD is not None:
            self._tmpdir = tempfile.mkdtemp(prefix="snyk-installer-")
            payload_dir = Path(self._tmpdir) / "payload"
            payload_dir.mkdir()
            data = base64.b64decode(PAYLOAD)
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                zf.extractall(payload_dir)
            self.payload_dir = payload_dir
            self.repo_root = payload_dir
        else:
            self.payload_dir = Path(__file__).resolve().parent
            self.repo_root = self.payload_dir.parent

    def cleanup(self) -> None:
        if self._tmpdir and os.path.isdir(self._tmpdir):
            shutil.rmtree(self._tmpdir, ignore_errors=True)

    @property
    def manifest_path(self) -> Path:
        return self.payload_dir / "manifest.json"

    def resolve_src(self, src_relative: str) -> Path:
        return self.repo_root / src_relative


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


# =============================================================================
# PREREQUISITES
# =============================================================================

def check_prerequisites(auto_yes: bool) -> None:
    warnings = 0

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
    print(f"  {C.green('OK')} Python {py_ver}")

    snyk_path = shutil.which("snyk")
    if snyk_path:
        try:
            r = subprocess.run(["snyk", "--version"], capture_output=True, text=True, timeout=10)
            ver = r.stdout.strip().splitlines()[0] if r.stdout else "unknown"
            print(f"  {C.green('OK')} Snyk CLI {ver}")
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


def detect_ades() -> List[str]:
    detected = []
    home = Path.home()

    if (home / ".cursor").is_dir():
        detected.append("cursor")
    elif sys.platform != "win32":
        try:
            r = subprocess.run(["pgrep", "-qi", "cursor"],
                               capture_output=True, timeout=5)
            if r.returncode == 0:
                detected.append("cursor")
        except Exception:
            pass

    if (home / ".claude").is_dir():
        detected.append("claude")
    elif shutil.which("claude"):
        detected.append("claude")

    return detected


def get_target_ades(target_ade: Optional[str], auto_yes: bool) -> List[str]:
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


def merge_config(strategy: str, target: Path, source: Path, dry_run: bool) -> None:
    if dry_run:
        print(f"    {C.dim(f'[dry-run] merge ({strategy}): {target}')}")
        return
    target.parent.mkdir(parents=True, exist_ok=True)

    # If this is a hook/settings merge on Windows, rewrite the source data first
    if sys.platform == "win32" and strategy in ("merge_cursor_hooks", "merge_claude_settings"):
        with open(source) as f:
            source_data = json.load(f)
        source_data = rewrite_hook_commands_for_platform(source_data)
        # Write rewritten source to a temp file for merge_json
        tmp_source = source.parent / f".{source.name}.win_rewrite"
        with open(tmp_source, "w") as f:
            json.dump(source_data, f, indent=2)
            f.write("\n")
        source = tmp_source

    lib_dir = str(Path(__file__).resolve().parent / "lib")
    if lib_dir not in sys.path:
        sys.path.insert(0, lib_dir)
    import merge_json
    if strategy not in merge_json.STRATEGIES:
        print(f"    {C.red(f'Unknown strategy: {strategy}')}")
        return
    merge_json.STRATEGIES[strategy](str(target), str(source))
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
        merge_config(cm["strategy"], target, source, dry_run)

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
        source = payload.resolve_src(cm["source"])

        lib_dir = str(Path(__file__).resolve().parent / "lib")
        if lib_dir not in sys.path:
            sys.path.insert(0, lib_dir)
        import merge_json

        try:
            merge_json.STRATEGIES[strategy](str(target), str(source))
            print(f"    {C.green('OK')} hooks registered in {cm['target']}")
        except (SystemExit, KeyError):
            print(f"    {C.red('MISSING')} hooks in {cm['target']}")
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
                source = payload.resolve_src(cm["source"])
                if dry_run:
                    print(f"    {C.dim(f'[dry-run] unmerge ({strategy}): {target}')}")
                else:
                    lib_dir = str(Path(__file__).resolve().parent / "lib")
                    if lib_dir not in sys.path:
                        sys.path.insert(0, lib_dir)
                    import merge_json
                    if strategy in merge_json.STRATEGIES:
                        merge_json.STRATEGIES[strategy](str(target), str(source))
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

    try:
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

    finally:
        payload.cleanup()


if __name__ == "__main__":
    main()
