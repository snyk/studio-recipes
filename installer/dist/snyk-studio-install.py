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
PAYLOAD: Optional[str] = (
    "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"
    "2278dMHkhPT4iNLq4KQnR4fCf6aUHAk8V3fWHZ6i+UZFe8mVN5D1mPXKFGIem+GABIwvWh7lW+JW"
    "b6doUe7T8kz2bdmWIrSQBAQPKRcHokSVfsSsdMKRuzhJyC9G1xHmX+oqA77iOTvZyNXkSp2B1Dtp"
    "T/fbB0552BR2X5L1ax2buQVs7zPYvszlsPeH4zM2gpjnD/bhfPwS14Gx+rYGOvuNkpp7GxWvLoRY"
    "mEPnIX7XIE7pqo1VC5f9+l5p6Zt5dCA2j0O895PDmnQ+tFJvdn0Rf7WLiWrgg/XrB9hiXYmc7f/b"
    "3t58a1K48gpP1y1WvGrJd4QKSn7EQOBqiQYQf1BK4I0HYVsXHwsGkERgQyt/T0oqggn5rbgNYu61"
    "mebmRTjtfmSuwv2tBQnVJtbolt6SfzAgt3320RRNHzQEXY4VRdeidK52eNZvg4G4d10dtN6CwB/9"
    "MqOwDiY6t84KsIBai/ZtcNQX82S/4Y1skNxuhDK7a9KX6ec0u0sF33ibJk8wsNfDl+OIGWFI5+cw"
    "RO0IQ3lyFqrS+19QSwMEFAAAAAgAFnaGXMWKNQKLAAAAGQEAAFoAAABndWFyZHJhaWxfZGlyZWN0"
    "aXZlcy9zZWN1cmVfYXRfaW5jZXB0aW9uL2hvb2tzX3ZlcnNpb24vY3Vyc29yL2FzeW5jX2NsaV92"
    "ZXJzaW9uL2hvb2tzLmpzb269jcEKwjAQRO/5ihA8lgbx5r3iRfyAVkpIIw212ZBdhVD6725jv8HT"
    "zptZZhYhpfq4hB6COstjtfEIMCHTwsBonuTSxb9cM3hiuy223OPyYmGeTRg4VDHTCOEkO3W43m+N"
    "ru07ISRdSjWGPPXo2HO9od4H6yLxdh1zp9ReuJb7qH7zSBD/uCo2tYovUEsDBBQAAAAIAIZLhlzH"
    "eOGfAwgAAGwZAABlAAAAZ3VhcmRyYWlsX2RpcmVjdGl2ZXMvc2VjdXJlX2F0X2luY2VwdGlvbi9o"
    "b29rc192ZXJzaW9uL2N1cnNvci9hc3luY19jbGlfdmVyc2lvbi9saWIvcGxhdGZvcm1fdXRpbHMu"
    "cHm1WN1uIjkWvq+nOEMUqWiRSqb7LlJWwxB6gpqGCJLO9CRRyVQZ8KSwS7aBMLuz2ofYJ9wn2XNc"
    "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"
    "AMWC8yqz4TwgPzk/NzcxLwUopJRXUKGkAxNPLEoH6YpW0q1U0lFQKgZqc8hJLEktLgFxgSaDKF0w"
    "p7gkJTNfKRauNTWvDMkGkJ1+kd7xvs4B8QFB/m6ePq4gy1IrClKLMnNT80oSc5SgSmu5YGQtVy0X"
    "AFBLAQIUAxQAAAAIAAx5hlwRM6/maAMAAAkWAAANAAAAAAAAAAAAAACkgQAAAABtYW5pZmVzdC5q"
    "c29uUEsBAhQDFAAAAAgAoU6BXDvFGxUkCgAAiTEAABEAAAAAAAAAAAAAAO2BkwMAAGxpYi9tZXJn"
    "ZV9qc29uLnB5UEsBAhQDFAAAAAgAZ314XJNXipe7AgAAiwcAABAAAAAAAAAAAAAAAO2B5g0AAGxp"
    "Yi90cmFuc2Zvcm0ucHlQSwECFAMUAAAACADHoFRcaW6GtE0aAACoSQAAWAAAAAAAAAAAAAAApIHP"
    "EAAAY29tbWFuZF9kaXJlY3RpdmVzL3N5bmNocm9ub3VzX3JlbWVkaWF0aW9uL2NvbW1hbmQvc2lu"
    "Z2xlX2FsbF9pbl9vbmVfY29tbWFuZC9zbnlrLWZpeC5tZFBLAQIUAxQAAAAIAItDZlxINNtAuQ4A"
    "AHsjAABEAAAAAAAAAAAAAACkgZIrAABjb21tYW5kX2RpcmVjdGl2ZXMvc3luY2hyb25vdXNfcmVt"
    "ZWRpYXRpb24vY29tbWFuZC9zbnlrLWJhdGNoLWZpeC5tZFBLAQIUAxQAAAAIAGZ2dFzBU02R0AoA"
    "ANIZAABZAAAAAAAAAAAAAACkga06AABjb21tYW5kX2RpcmVjdGl2ZXMvc3luY2hyb25vdXNfcmVt"
    "ZWRpYXRpb24vc2tpbGxzL3NlY3VyZS1kZXBlbmRlbmN5LWhlYWx0aC1jaGVjay9TS0lMTC5tZFBL"
    "AQIUAxQAAAAIAHClYlyEVVJqjQkAAOIVAAB6AAAAAAAAAAAAAACkgfRFAABjb21tYW5kX2RpcmVj"
    "dGl2ZXMvc3luY2hyb25vdXNfcmVtZWRpYXRpb24vc2tpbGxzL3NlY3VyZS1kZXBlbmRlbmN5LWhl"
    "YWx0aC1jaGVjay9yZWZlcmVuY2VzL3BhY2thZ2UtZXZhbHVhdGlvbi1jcml0ZXJpYS5tZFBLAQIU"
    "AxQAAAAIAHxLhlzHeOGfAwgAAGwZAABlAAAAAAAAAAAAAACkgRlQAABndWFyZHJhaWxfZGlyZWN0"
    "aXZlcy9zZWN1cmVfYXRfaW5jZXB0aW9uL2hvb2tzX3ZlcnNpb24vY2xhdWRlL2FzeW5jX2NsaV92"
    "ZXJzaW9uL2xpYi9wbGF0Zm9ybV91dGlscy5weVBLAQIUAxQAAAAIABZ2hlyZY+8cVAwAALkqAABi"
    "AAAAAAAAAAAAAACkgZ9YAABndWFyZHJhaWxfZGlyZWN0aXZlcy9zZWN1cmVfYXRfaW5jZXB0aW9u"
    "L2hvb2tzX3ZlcnNpb24vY2xhdWRlL2FzeW5jX2NsaV92ZXJzaW9uL2xpYi9zY2FuX3J1bm5lci5w"
    "eVBLAQIUAxQAAAAIAAdIhlxv0rNjvwYAADYTAABiAAAAAAAAAAAAAACkgXNlAABndWFyZHJhaWxf"
    "ZGlyZWN0aXZlcy9zZWN1cmVfYXRfaW5jZXB0aW9uL2hvb2tzX3ZlcnNpb24vY2xhdWRlL2FzeW5j"
    "X2NsaV92ZXJzaW9uL2xpYi9zY2FuX3dvcmtlci5weVBLAQIUAxQAAAAIABZ2hlySW6EG5wAAAGcC"
    "AABdAAAAAAAAAAAAAACkgbJsAABndWFyZHJhaWxfZGlyZWN0aXZlcy9zZWN1cmVfYXRfaW5jZXB0"
    "aW9uL2hvb2tzX3ZlcnNpb24vY2xhdWRlL2FzeW5jX2NsaV92ZXJzaW9uL3NldHRpbmdzLmpzb25Q"
    "SwECFAMUAAAACAAWdoZcf22xXj4VAAB4TgAAawAAAAAAAAAAAAAApIEUbgAAZ3VhcmRyYWlsX2Rp"
    "cmVjdGl2ZXMvc2VjdXJlX2F0X2luY2VwdGlvbi9ob29rc192ZXJzaW9uL2NsYXVkZS9hc3luY19j"
    "bGlfdmVyc2lvbi9zbnlrX3NlY3VyZV9hdF9pbmNlcHRpb24ucHlQSwECFAMUAAAACAAWdoZcxYo1"
    "AosAAAAZAQAAWgAAAAAAAAAAAAAApIHbgwAAZ3VhcmRyYWlsX2RpcmVjdGl2ZXMvc2VjdXJlX2F0"
    "X2luY2VwdGlvbi9ob29rc192ZXJzaW9uL2N1cnNvci9hc3luY19jbGlfdmVyc2lvbi9ob29rcy5q"
    "c29uUEsBAhQDFAAAAAgAhkuGXMd44Z8DCAAAbBkAAGUAAAAAAAAAAAAAAKSB3oQAAGd1YXJkcmFp"
    "bF9kaXJlY3RpdmVzL3NlY3VyZV9hdF9pbmNlcHRpb24vaG9va3NfdmVyc2lvbi9jdXJzb3IvYXN5"
    "bmNfY2xpX3ZlcnNpb24vbGliL3BsYXRmb3JtX3V0aWxzLnB5UEsBAhQDFAAAAAgAFnaGXA/8OmZT"
    "DAAAuyoAAGIAAAAAAAAAAAAAAKSBZI0AAGd1YXJkcmFpbF9kaXJlY3RpdmVzL3NlY3VyZV9hdF9p"
    "bmNlcHRpb24vaG9va3NfdmVyc2lvbi9jdXJzb3IvYXN5bmNfY2xpX3ZlcnNpb24vbGliL3NjYW5f"
    "cnVubmVyLnB5UEsBAhQDFAAAAAgANUiGXG/Ss2O/BgAANhMAAGIAAAAAAAAAAAAAAKSBN5oAAGd1"
    "YXJkcmFpbF9kaXJlY3RpdmVzL3NlY3VyZV9hdF9pbmNlcHRpb24vaG9va3NfdmVyc2lvbi9jdXJz"
    "b3IvYXN5bmNfY2xpX3ZlcnNpb24vbGliL3NjYW5fd29ya2VyLnB5UEsBAhQDFAAAAAgAFnaGXHK7"
    "SxByFQAAaVEAAGsAAAAAAAAAAAAAAO2BdqEAAGd1YXJkcmFpbF9kaXJlY3RpdmVzL3NlY3VyZV9h"
    "dF9pbmNlcHRpb24vaG9va3NfdmVyc2lvbi9jdXJzb3IvYXN5bmNfY2xpX3ZlcnNpb24vc255a19z"
    "ZWN1cmVfYXRfaW5jZXB0aW9uLnB5UEsBAhQDFAAAAAgAZ314XOPjQgaIAAAAwwAAAA0AAAAAAAAA"
    "AAAAAKSBcbcAAG1jcC8ubWNwLmpzb25QSwUGAAAAABIAEgDFCAAAJLgAAAAA"
)


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
