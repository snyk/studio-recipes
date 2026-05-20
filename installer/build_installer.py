#!/usr/bin/env python3
"""
Build script for the Snyk Studio recipes installer.



Usage:
    python3 build_installer.py
"""

import base64
import io
import json
import os
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import List, Tuple

# Marker line after shell logic; payload is base64 lines until end (sh) or #> (ps1).
BUNDLE_MARKER = "__SNYK_STUDIO_BUNDLE_B64__"

# Shared by generated installers; must match snyk-studio-installer.BUNDLE_ENV.
BUNDLE_ENV = "SNYK_STUDIO_BUNDLE_ROOT"


def main() -> None:
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent
    dist_dir = script_dir / "dist"
    dist_dir.mkdir(exist_ok=True)

    tpl_readme = script_dir / "templates" / "README.md"
    if not tpl_readme.is_file():
        print(f"Error: {tpl_readme} not found", file=sys.stderr)
        sys.exit(1)
    shutil.copy2(tpl_readme, dist_dir / "README.md")
    print(f"  Copied {tpl_readme.name} -> {dist_dir / 'README.md'}")

    installer_src = script_dir / "snyk-studio-installer.py"
    manifest_path = script_dir / "manifest.json"

    if not installer_src.exists():
        print(f"Error: {installer_src} not found", file=sys.stderr)
        sys.exit(1)
    if not manifest_path.exists():
        print(f"Error: {manifest_path} not found", file=sys.stderr)
        sys.exit(1)

    print("  Building installers...")
    print(f"  Repo root: {repo_root}")

    bundle_info, added, missing = collect_bundle_info(script_dir, repo_root, manifest_path)

    tar_bytes = build_tarball_bytes(bundle_info)
    tar_b64 = base64.b64encode(tar_bytes).decode("ascii")
    print(f"  Tar payload: {len(tar_bytes)} bytes ({added} members, {missing} missing)")
    print(f"  Tar base64:  {len(tar_b64)} chars")

    zip_bytes = build_zip_bytes(bundle_info)
    zip_b64 = base64.b64encode(zip_bytes).decode("ascii")
    print(f"  Zip payload: {len(zip_bytes)} bytes")
    print(f"  Zip base64:  {len(zip_b64)} chars")

    dst_bash_installer = dist_dir / "snyk-studio-install.sh"
    write_install_sh(dst_bash_installer, tar_b64)
    print(f"  Output:  {dst_bash_installer} ({(dst_bash_installer).stat().st_size} bytes)")

    dst_ps1_installer = dist_dir / "snyk-studio-install.ps1"
    write_install_ps1(dst_ps1_installer, zip_b64)
    print(f"  Output:  {dst_ps1_installer} ({(dst_ps1_installer).stat().st_size} bytes)")

    dst_py_installer = dist_dir / "snyk-studio-install.py"
    write_snyk_studio_install_py(dst_py_installer, tar_b64)
    print(f"  Output:  {dst_py_installer} ({dst_py_installer.stat().st_size} bytes)")

    print("  Done.")


def _installer_root() -> Path:
    return Path(__file__).resolve().parent


def _load_template(name: str) -> str:
    path = _installer_root() / "templates" / name
    if not path.is_file():
        print(f"Error: missing template {path}", file=sys.stderr)
        sys.exit(1)
    return path.read_text(encoding="utf-8")


def collect_bundle_info(
    script_dir: Path, repo_root: Path, manifest_path: Path
) -> Tuple[List[Tuple[str, Path]], int, int]:
    """Return (arcname, source_path) for each file in the bundle; (pairs, added, missing)."""
    with open(manifest_path) as f:
        manifest = json.load(f)

    src_paths: set[str] = set()
    for recipe in manifest["recipes"].values():
        for ade_sources in recipe.get("sources", {}).values():
            for file_entry in ade_sources.get("files", []):
                src_paths.add(file_entry["src"])
            cm = ade_sources.get("config_merge")
            if cm:
                src_paths.add(cm["source"])
            for t in ade_sources.get("transforms", []):
                src_paths.add(t["src"])

    pairs: List[Tuple[str, Path]] = []
    installer_src = script_dir / "snyk-studio-installer.py"
    missing = 0
    added = 0

    def add_or_mark_missing(arcname: str, source_path: Path) -> None:
        nonlocal added, missing
        if source_path.exists():
            pairs.append((arcname, source_path))
            added += 1
        else:
            print(f"  WARNING: Missing {arcname}", file=sys.stderr)
            missing += 1

    add_or_mark_missing("manifest.json", manifest_path)
    add_or_mark_missing("snyk-studio-installer.py", installer_src)

    # Optional platform-specific overrides not in manifest
    add_or_mark_missing("mcp/.mcp.mac.json", repo_root / "mcp" / ".mcp.mac.json")

    lib_dir = script_dir / "lib"
    if lib_dir.is_dir():
        # Bundle .py files plus LICENSE files for vendored deps under lib/_vendor/.
        # MIT-licensed third-party code must keep its license text in distributions.
        candidates = list(lib_dir.rglob("*.py")) + list(lib_dir.rglob("LICENSE"))
        for lib_path in sorted(
            candidates,
            key=lambda p: p.relative_to(lib_dir).as_posix(),
        ):
            rel = lib_path.relative_to(lib_dir)
            arcname = str(Path("lib") / rel).replace("\\", "/")
            add_or_mark_missing(arcname, lib_path)

    for src in sorted(src_paths):
        full_path = repo_root / src
        add_or_mark_missing(src, full_path)

    return pairs, added, missing


def build_tarball_bytes(pairs: List[Tuple[str, Path]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.GNU_FORMAT) as tf:
        for arcname, path in pairs:
            tf.add(str(path), arcname=arcname, recursive=False)
    return buf.getvalue()


def build_zip_bytes(pairs: List[Tuple[str, Path]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for arcname, path in pairs:
            zf.write(str(path), arcname)
    return buf.getvalue()


def _apply_template_placeholders(tpl: str, b64_body: str) -> str:
    return (
        tpl.replace("__BUNDLE_ENV__", BUNDLE_ENV)
        .replace("__MARKER__", BUNDLE_MARKER)
        .replace("__B64_BODY__", b64_body)
    )


def write_install_sh(dist_path: Path, payload_b64: str) -> None:
    lines = [payload_b64[i : i + 76] for i in range(0, len(payload_b64), 76)]
    b64_body = "\n".join(lines)
    tpl = _load_template("install.sh.template")
    content = _apply_template_placeholders(tpl, b64_body)
    dist_path.write_text(content, encoding="utf-8")
    os.chmod(str(dist_path), 0o755)


def write_install_ps1(dist_path: Path, payload_b64: str) -> None:
    lines = [payload_b64[i : i + 76] for i in range(0, len(payload_b64), 76)]
    b64_body = "\n".join(lines)
    tpl = _load_template("install.ps1.template")
    content = _apply_template_placeholders(tpl, b64_body)
    dist_path.write_text(content, encoding="utf-8")


def write_snyk_studio_install_py(dist_path: Path, payload_b64: str) -> None:
    lines = [payload_b64[i : i + 76] for i in range(0, len(payload_b64), 76)]
    b64_body = "\n".join(lines)
    tpl = _load_template("install.py.template")
    content = _apply_template_placeholders(tpl, b64_body)
    dist_path.write_text(content, encoding="utf-8")
    os.chmod(str(dist_path), 0o755)


if __name__ == "__main__":
    main()
