#!/usr/bin/env python3
"""JSON config merging and verification for Snyk Studio Recipes installer.

Merge strategies (create .bak backup, write pretty-printed JSON, idempotent):
  - merge_cursor_hooks:    ~/.cursor/hooks.json
  - merge_claude_settings: ~/.claude/settings.json
  - merge_mcp_servers:     ~/.mcp.json or ~/.cursor/.mcp.json

Unmerge strategies (remove Snyk entries, idempotent):
  - unmerge_cursor_hooks, unmerge_claude_settings, unmerge_mcp_servers

Verify strategies (read-only, exit 1 if entries missing):
  - verify_cursor_hooks, verify_claude_settings, verify_mcp_servers
"""

import json
import os
import shutil
import sys


def _load_json(path):
    """Load JSON file, returning empty dict if file doesn't exist."""
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)


def _backup(path):
    """Create .bak backup of file if it exists."""
    if os.path.exists(path):
        shutil.copy2(path, path + ".bak")


def _write_json(path, data):
    """Write pretty-printed JSON to file."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def _is_snyk_command(command_str):
    """Check if a hook command is Snyk-related."""
    return "snyk" in command_str.lower()


def merge_cursor_hooks(target_path, source_path):
    """Merge Snyk hooks into Cursor's top-level hooks.json (~/.cursor/hooks.json).

    For each hook event in source, append entries to target array.
    Deduplicates by 'command' field. Preserves existing non-Snyk hooks.
    """
    _backup(target_path)
    target = _load_json(target_path)
    source = _load_json(source_path)

    # Ensure target has basic structure
    if "version" not in target:
        target["version"] = source.get("version", 1)
    if "hooks" not in target:
        target["hooks"] = {}

    source_hooks = source.get("hooks", {})
    for event, entries in source_hooks.items():
        if event not in target["hooks"]:
            target["hooks"][event] = []

        # Collect existing commands for dedup
        existing_commands = {
            e.get("command") for e in target["hooks"][event] if "command" in e
        }

        for entry in entries:
            cmd = entry.get("command", "")
            if cmd not in existing_commands:
                target["hooks"][event].append(entry)
                existing_commands.add(cmd)

    _write_json(target_path, target)


def merge_claude_settings(target_path, source_path):
    """Merge Snyk hooks into Claude settings.json.

    For each hook event (PostToolUse, Stop), find matching matcher group.
    Append hook entries within matching groups, deduplicate by 'command'.
    If no matching group exists, append entire group.
    Preserves existing non-Snyk settings.
    """
    _backup(target_path)
    target = _load_json(target_path)
    source = _load_json(source_path)

    if "hooks" not in target:
        target["hooks"] = {}

    source_hooks = source.get("hooks", {})
    for event, groups in source_hooks.items():
        if event not in target["hooks"]:
            target["hooks"][event] = []

        for src_group in groups:
            src_matcher = src_group.get("matcher")
            merged = False

            # Try to find a matching group in target
            for tgt_group in target["hooks"][event]:
                if tgt_group.get("matcher") == src_matcher:
                    # Merge hooks within this group
                    if "hooks" not in tgt_group:
                        tgt_group["hooks"] = []

                    existing_commands = {
                        h.get("command")
                        for h in tgt_group["hooks"]
                        if "command" in h
                    }

                    for hook in src_group.get("hooks", []):
                        cmd = hook.get("command", "")
                        if cmd not in existing_commands:
                            tgt_group["hooks"].append(hook)
                            existing_commands.add(cmd)

                    merged = True
                    break

            if not merged:
                # No matching group found, append the entire group
                target["hooks"][event].append(src_group)

    _write_json(target_path, target)


def merge_mcp_servers(target_path, source_path):
    """Merge Snyk MCP server config into .mcp.json.

    Add/update Snyk server entry. Preserve all non-Snyk servers.
    """
    _backup(target_path)
    target = _load_json(target_path)
    source = _load_json(source_path)

    if "mcpServers" not in target:
        target["mcpServers"] = {}

    source_servers = source.get("mcpServers", {})
    for name, config in source_servers.items():
        target["mcpServers"][name] = config

    _write_json(target_path, target)


def unmerge_cursor_hooks(target_path, source_path):
    """Remove Snyk hooks from Cursor's hooks.json.

    For each event in source, remove entries from target whose command
    matches any command in source. Cleans up empty event arrays.
    Idempotent — safe if entries already removed.
    """
    target = _load_json(target_path)
    source = _load_json(source_path)

    source_hooks = source.get("hooks", {})
    if not source_hooks or "hooks" not in target:
        return

    _backup(target_path)

    for event, entries in source_hooks.items():
        if event not in target["hooks"]:
            continue

        # Collect commands to remove
        remove_commands = {e.get("command") for e in entries if "command" in e}

        target["hooks"][event] = [
            e for e in target["hooks"][event]
            if e.get("command") not in remove_commands
        ]

        # Clean up empty event arrays
        if not target["hooks"][event]:
            del target["hooks"][event]

    _write_json(target_path, target)


def unmerge_claude_settings(target_path, source_path):
    """Remove Snyk hooks from Claude settings.json.

    For each event in source, for each matcher group in source, find the
    matching group in target (by matcher value), then remove hooks whose
    command matches. Cleans up empty groups and event arrays.
    Preserves all non-Snyk entries and non-hooks settings.
    Idempotent — safe if entries already removed.
    """
    target = _load_json(target_path)
    source = _load_json(source_path)

    source_hooks = source.get("hooks", {})
    if not source_hooks or "hooks" not in target:
        return

    _backup(target_path)

    for event, src_groups in source_hooks.items():
        if event not in target["hooks"]:
            continue

        for src_group in src_groups:
            src_matcher = src_group.get("matcher")
            remove_commands = {
                h.get("command") for h in src_group.get("hooks", []) if "command" in h
            }

            for tgt_group in target["hooks"][event]:
                if tgt_group.get("matcher") != src_matcher:
                    continue

                tgt_group["hooks"] = [
                    h for h in tgt_group.get("hooks", [])
                    if h.get("command") not in remove_commands
                ]

        # Remove groups with empty hooks
        target["hooks"][event] = [
            g for g in target["hooks"][event]
            if g.get("hooks")
        ]

        # Clean up empty event arrays
        if not target["hooks"][event]:
            del target["hooks"][event]

    _write_json(target_path, target)


def unmerge_mcp_servers(target_path, source_path):
    """Remove Snyk MCP server entries from .mcp.json.

    Removes server entries whose key matches any key in source.
    Preserves all non-Snyk servers. Idempotent.
    """
    target = _load_json(target_path)
    source = _load_json(source_path)

    source_servers = source.get("mcpServers", {})
    if not source_servers or "mcpServers" not in target:
        return

    _backup(target_path)

    for name in source_servers:
        target["mcpServers"].pop(name, None)

    _write_json(target_path, target)


def verify_cursor_hooks(target_path, source_path):
    """Verify that all Snyk hooks from source exist in Cursor's hooks.json.

    Prints missing entries to stderr. Exits with code 1 if anything is missing.
    Read-only — does not modify any files.
    """
    target = _load_json(target_path)
    source = _load_json(source_path)

    missing = []
    source_hooks = source.get("hooks", {})
    target_hooks = target.get("hooks", {})

    for event, entries in source_hooks.items():
        if event not in target_hooks:
            missing.append(f"  event '{event}' not found in {target_path}")
            continue

        existing_commands = {
            e.get("command") for e in target_hooks[event] if "command" in e
        }
        for entry in entries:
            cmd = entry.get("command", "")
            if cmd and cmd not in existing_commands:
                missing.append(f"  hook command missing from '{event}': {cmd}")

    if missing:
        for m in missing:
            print(m, file=sys.stderr)
        sys.exit(1)


def verify_claude_settings(target_path, source_path):
    """Verify that all Snyk hooks from source exist in Claude settings.json.

    For each hook event + matcher group in source, checks the matching group
    exists in target and contains the expected hook commands.
    Prints missing entries to stderr. Exits with code 1 if anything is missing.
    Read-only — does not modify any files.
    """
    target = _load_json(target_path)
    source = _load_json(source_path)

    missing = []
    source_hooks = source.get("hooks", {})
    target_hooks = target.get("hooks", {})

    for event, src_groups in source_hooks.items():
        if event not in target_hooks:
            missing.append(f"  event '{event}' not found in {target_path}")
            continue

        for src_group in src_groups:
            src_matcher = src_group.get("matcher")
            # Find matching group in target
            tgt_group = None
            for g in target_hooks[event]:
                if g.get("matcher") == src_matcher:
                    tgt_group = g
                    break

            if tgt_group is None:
                matcher_label = f"matcher='{src_matcher}'" if src_matcher else "no matcher"
                missing.append(f"  group ({matcher_label}) missing from '{event}'")
                continue

            existing_commands = {
                h.get("command") for h in tgt_group.get("hooks", []) if "command" in h
            }
            for hook in src_group.get("hooks", []):
                cmd = hook.get("command", "")
                if cmd and cmd not in existing_commands:
                    missing.append(f"  hook command missing from '{event}': {cmd}")

    if missing:
        for m in missing:
            print(m, file=sys.stderr)
        sys.exit(1)


def verify_mcp_servers(target_path, source_path):
    """Verify that all Snyk MCP servers from source exist in target.

    Read-only — does not modify any files.
    """
    target = _load_json(target_path)
    source = _load_json(source_path)

    missing = []
    source_servers = source.get("mcpServers", {})
    target_servers = target.get("mcpServers", {})

    for name in source_servers:
        if name not in target_servers:
            missing.append(f"  MCP server '{name}' missing from {target_path}")

    if missing:
        for m in missing:
            print(m, file=sys.stderr)
        sys.exit(1)


STRATEGIES = {
    "merge_cursor_hooks": merge_cursor_hooks,
    "merge_claude_settings": merge_claude_settings,
    "merge_mcp_servers": merge_mcp_servers,
    "unmerge_cursor_hooks": unmerge_cursor_hooks,
    "unmerge_claude_settings": unmerge_claude_settings,
    "unmerge_mcp_servers": unmerge_mcp_servers,
    "verify_cursor_hooks": verify_cursor_hooks,
    "verify_claude_settings": verify_claude_settings,
    "verify_mcp_servers": verify_mcp_servers,
}


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <strategy> <target_path> <source_path>", file=sys.stderr)
        print(f"Strategies: {', '.join(STRATEGIES.keys())}", file=sys.stderr)
        sys.exit(1)

    strategy_name = sys.argv[1]
    target_path = sys.argv[2]
    source_path = sys.argv[3]

    if strategy_name not in STRATEGIES:
        print(f"Unknown strategy: {strategy_name}", file=sys.stderr)
        print(f"Available: {', '.join(STRATEGIES.keys())}", file=sys.stderr)
        sys.exit(1)

    STRATEGIES[strategy_name](target_path, source_path)


if __name__ == "__main__":
    main()
