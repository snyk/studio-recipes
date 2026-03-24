#!/usr/bin/env python3
"""Asset transforms for Snyk Studio Recipes installer.

Transforms:
  - mdc_to_md:        Strip YAML frontmatter from .mdc files for Claude rules
  - skill_to_command:  Strip YAML frontmatter from SKILL.md for Claude commands
"""

import os
import re
import sys


FRONTMATTER_RE = re.compile(r"^---\s*\n.*?\n---\s*\n", re.DOTALL)


def strip_frontmatter(content):
    """Remove YAML frontmatter (--- delimited block at start of file)."""
    return FRONTMATTER_RE.sub("", content, count=1)


def mdc_to_md(src_path, dest_path):
    """Convert .mdc rule file to .md by stripping YAML frontmatter."""
    with open(src_path, "r") as f:
        content = f.read()

    transformed = strip_frontmatter(content)

    os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
    with open(dest_path, "w") as f:
        f.write(transformed)


def skill_to_command(src_path, dest_path):
    """Convert SKILL.md to command .md by stripping YAML frontmatter."""
    with open(src_path, "r") as f:
        content = f.read()

    transformed = strip_frontmatter(content)

    os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
    with open(dest_path, "w") as f:
        f.write(transformed)


TRANSFORMS = {
    "mdc_to_md": mdc_to_md,
    "skill_to_command": skill_to_command,
}


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <transform> <src_path> <dest_path>", file=sys.stderr)
        print(f"Transforms: {', '.join(TRANSFORMS.keys())}", file=sys.stderr)
        sys.exit(1)

    transform_name = sys.argv[1]
    src_path = sys.argv[2]
    dest_path = sys.argv[3]

    if transform_name not in TRANSFORMS:
        print(f"Unknown transform: {transform_name}", file=sys.stderr)
        print(f"Available: {', '.join(TRANSFORMS.keys())}", file=sys.stderr)
        sys.exit(1)

    TRANSFORMS[transform_name](src_path, dest_path)


if __name__ == "__main__":
    main()
