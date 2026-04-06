#!/usr/bin/env python3
"""
Build script for the cross-platform Snyk Studio installer.

Reads manifest.json, collects all referenced source files from the repo,
packages them into a zip archive, base64-encodes it, and embeds it into
snyk-studio-installer.py to produce dist/snyk-studio-install.py.

Usage:
    python build_installer.py
"""

import base64
import io
import json
import os
import sys
import zipfile
from pathlib import Path


def main() -> None:
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent
    dist_dir = script_dir / "dist"
    dist_dir.mkdir(exist_ok=True)

    installer_src = script_dir / "snyk-studio-installer.py"
    manifest_path = script_dir / "manifest.json"
    output_path = dist_dir / "snyk-studio-install.py"

    if not installer_src.exists():
        print(f"Error: {installer_src} not found", file=sys.stderr)
        sys.exit(1)
    if not manifest_path.exists():
        print(f"Error: {manifest_path} not found", file=sys.stderr)
        sys.exit(1)

    print(f"  Building cross-platform installer...")
    print(f"  Repo root: {repo_root}")

    # Collect source file paths from manifest
    with open(manifest_path) as f:
        manifest = json.load(f)

    src_paths: set = set()
    for recipe in manifest["recipes"].values():
        for ade_sources in recipe.get("sources", {}).values():
            for file_entry in ade_sources.get("files", []):
                src_paths.add(file_entry["src"])
            cm = ade_sources.get("config_merge")
            if cm:
                src_paths.add(cm["source"])
            for t in ade_sources.get("transforms", []):
                src_paths.add(t["src"])

    # Create zip archive in memory
    buf = io.BytesIO()
    missing = 0
    added = 0

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Add manifest
        zf.write(str(manifest_path), "manifest.json")
        added += 1

        # Add lib/ scripts
        for lib_file in ["merge_json.py", "transform.py"]:
            lib_path = script_dir / "lib" / lib_file
            if lib_path.exists():
                zf.write(str(lib_path), f"lib/{lib_file}")
                added += 1

        # Add all source files from repo
        for src in sorted(src_paths):
            full_path = repo_root / src
            if full_path.exists():
                zf.write(str(full_path), src)
                added += 1
            else:
                print(f"  WARNING: Missing {src}")
                missing += 1

    # Base64 encode
    payload_bytes = buf.getvalue()
    payload_b64 = base64.b64encode(payload_bytes).decode("ascii")

    print(f"  Payload: {len(payload_bytes)} bytes ({added} files, {missing} missing)")
    print(f"  Base64:  {len(payload_b64)} chars")

    # Read installer template and embed payload
    installer_content = installer_src.read_text()

    # Replace the PAYLOAD line
    marker = 'PAYLOAD: Optional[str] = None'
    if marker not in installer_content:
        print(f"Error: Payload marker not found in {installer_src}", file=sys.stderr)
        sys.exit(1)

    # Split the base64 string into 76-char lines for readability
    lines = [payload_b64[i:i+76] for i in range(0, len(payload_b64), 76)]
    payload_literal = '(\n    "' + '"\n    "'.join(lines) + '"\n)'
    replacement = f"PAYLOAD: Optional[str] = {payload_literal}"

    output_content = installer_content.replace(marker, replacement, 1)

    # Write output
    output_path.write_text(output_content)
    os.chmod(str(output_path), 0o755)

    output_size = output_path.stat().st_size
    print(f"  Output:  {output_path} ({output_size} bytes)")
    print(f"  Done.")


if __name__ == "__main__":
    main()
