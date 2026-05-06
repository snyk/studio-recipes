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
import shlex
import shutil
import sys

LEGACY_LAUNCHERS = frozenset({"python", "python3"})

# Tokens that start shell redirection / piping; truncate argv before these for script identity.
_REDIR_PIPE_TOKENS = frozenset({
    ">>", ">", "<", "|", "2>", "2>>", "&>", "&>>", "2>&1", "<&", ">&", ">>&",
})


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


def _split_command_argv(command_str):
    """Split a hook command like a shell line; return argv list or None."""
    if not isinstance(command_str, str) or not command_str.strip():
        return None

    for posix in (True, False):
        try:
            parsed = shlex.split(command_str, posix=posix)
        except ValueError:
            continue
        if parsed:
            return parsed
    return None


def _strip_outer_quotes(token: str) -> str:
    s = token.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    return s


def _is_redirect_or_pipe_token(token: str) -> bool:
    if not token:
        return False
    if token in _REDIR_PIPE_TOKENS:
        return True
    # e.g. 2>, 1>>, &>file (if ever unsplit)
    if token[0].isdigit() and ">" in token:
        return True
    return False


def _strip_shell_redirects(tokens):
    """Drop redirect/pipe suffix (e.g. `>> log`) so the hook executable argv remains."""
    out = []
    for t in tokens:
        if _is_redirect_or_pipe_token(t):
            break
        out.append(t)
    return out


def _pick_script_index_and_key(effective_tokens):
    """Choose script token index and normalized path key for dedup/migration.

    Prefer the last token ending in ``.py`` (option 2); else last token (option 1).
    """
    if not effective_tokens:
        return None, None

    n = len(effective_tokens)
    for i in range(n - 1, -1, -1):
        norm = _strip_outer_quotes(effective_tokens[i])
        if norm.lower().endswith(".py"):
            return i, norm or None
    last = _strip_outer_quotes(effective_tokens[-1])
    return n - 1, last or None


def _command_script_key(command_str):
    """Return a stable script path key for dedup and migration.

    Parses like a shell command (quoting honored). Strips shell redirections
    (``>>``, ``>``, etc.) before resolving the script. The script is the last
    ``*.py`` token when present; otherwise the last argv token of the command
    portion (options 1 and 2).
    """
    args = _split_command_argv(command_str)
    if not args:
        return None

    effective = _strip_shell_redirects(args)
    _, key = _pick_script_index_and_key(effective)
    return key


def _command_launcher(command_str):
    """Return the launcher argv (everything before the chosen script token)."""
    args = _split_command_argv(command_str)
    if not args:
        return None

    effective = _strip_shell_redirects(args)
    if not effective:
        return ""

    idx, _ = _pick_script_index_and_key(effective)
    if idx is None:
        return ""
    if idx == 0:
        return ""
    return " ".join(effective[:idx]).strip()


def _merge_command_entries(target_entries, source_entries):
    """Merge source command entries into target entries.

    Matching priority:
      1. Same script key (after stripping redirects / pipes; last ``*.py`` token
         when present) and target launcher in LEGACY_LAUNCHERS (e.g. python,
         python3): replace target entry with source entry.
      2. Same command string: dedupe (skip append).
      3. Otherwise: append source entry.
    """
    command_to_idx = {}
    script_to_idx = {}

    for idx, entry in enumerate(target_entries):
        cmd = entry.get("command")
        if isinstance(cmd, str):
            command_to_idx[cmd] = idx
            script_key = _command_script_key(cmd)
            if script_key and script_key not in script_to_idx:
                script_to_idx[script_key] = idx

    for src_entry in source_entries:
        cmd = src_entry.get("command")
        if not isinstance(cmd, str):
            target_entries.append(src_entry)
            continue

        script_key = _command_script_key(cmd)
        if script_key and script_key in script_to_idx:
            idx = script_to_idx[script_key]
            old_cmd = target_entries[idx].get("command")
            old_launcher = _command_launcher(old_cmd)

            # Only migrate launcher for known legacy launchers.
            if old_launcher in LEGACY_LAUNCHERS:
                target_entries[idx] = src_entry

                if isinstance(old_cmd, str) and command_to_idx.get(old_cmd) == idx:
                    del command_to_idx[old_cmd]
                command_to_idx[cmd] = idx
                script_to_idx[script_key] = idx
                continue

        if cmd in command_to_idx:
            continue

        target_entries.append(src_entry)
        idx = len(target_entries) - 1
        command_to_idx[cmd] = idx
        if script_key and script_key not in script_to_idx:
            script_to_idx[script_key] = idx


def merge_cursor_hooks(target_path, source_path):
    """Merge Snyk hooks into Cursor's top-level hooks.json (~/.cursor/hooks.json).

    For each hook event in source, append entries to target array.
    Deduplicates by 'command' field. Preserves existing non-Snyk hooks.
    """
    _backup(target_path)
    source = _load_json(source_path)

    try:
        target = _load_json(target_path)
    except Exception:
        raise ValueError(f"Invalid JSON in file: {target_path}")

    # Ensure target has basic structure
    if "version" not in target:
        target["version"] = source.get("version", 1)
    if "hooks" not in target:
        target["hooks"] = {}

    source_hooks = source.get("hooks", {})
    for event, entries in source_hooks.items():
        if event not in target["hooks"]:
            target["hooks"][event] = []

        _merge_command_entries(target["hooks"][event], entries)

    _write_json(target_path, target)


def merge_claude_settings(target_path, source_path):
    """Merge Snyk hooks into Claude settings.json.

    For each hook event (PostToolUse, Stop), find matching matcher group.
    Append hook entries within matching groups, deduplicate by 'command'.
    If no matching group exists, append entire group.
    Preserves existing non-Snyk settings.
    """
    _backup(target_path)
    source = _load_json(source_path)

    try:
        target = _load_json(target_path)
    except Exception:
        raise ValueError(f"Invalid JSON in file: {target_path}")

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

                    _merge_command_entries(
                        tgt_group["hooks"], src_group.get("hooks", [])
                    )

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
