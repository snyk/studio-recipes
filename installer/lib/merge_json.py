#!/usr/bin/env python3
"""Config merging and verification for Snyk Studio Recipes installer.

JSON merge strategies (create .bak backup, write pretty-printed JSON, idempotent):
  - merge_cursor_hooks:    ~/.cursor/hooks.json
  - merge_claude_settings: ~/.claude/settings.json
  - merge_gemini_settings: ~/.gemini/settings.json
  - merge_mcp_servers:     ~/.mcp.json or ~/.cursor/.mcp.json

TOML merge strategies (~/.codex/config.toml, single file used for all of
[features], [[hooks.*]], and [mcp_servers.*]):
  - merge_codex_config

Unmerge strategies (remove Snyk entries, idempotent):
  - unmerge_cursor_hooks, unmerge_claude_settings, unmerge_gemini_settings,
    unmerge_mcp_servers, unmerge_codex_config

Verify strategies (read-only, exit 1 if entries missing):
  - verify_cursor_hooks, verify_claude_settings, verify_gemini_settings,
    verify_mcp_servers, verify_codex_config
"""

# Defer annotation evaluation (PEP 563) so builtin-generic hints like
# ``list[Any]`` don't get evaluated at runtime — required for Python 3.8/3.9,
# which the tomllib fallback below also supports.
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import sys
from pathlib import Path
from typing import Any

# Token used by the Windows installer to suppress the cmd.exe window `uv run`
# pops up under graphical ADEs. The installed-on-Windows form of every SAI
# hook command is `uvw run --gui-script <path>`; everywhere else the source
# form `uv run <path>` is preserved. Matching/dedup is by script file name
# (see _command_script_names), so the rewritten launcher needs no special
# handling there.
_UVW_GUI_TOKEN = "uvw run --gui-script"
_UV_RUN_RE = re.compile(r"(?<![\w./-])uv run(?!\S)")

# Home-directory variable tokens we substitute at install time so that the
# command string in the installed config no longer depends on shell expansion.
# Each pattern captures an optional path continuation after the token so the
# whole path can be re-joined with the platform's native separator (see
# expand_hook_command_paths); without that, $HOME/foo on Windows would expand
# to e.g. ``C:\Users\me/foo`` (mixed separators).
#
# Path-name characters: allowed inside a single path segment. Excluded:
#   - whitespace, quotes, common shell metas (``>``, ``<``, ``|``, ``;``,
#     ``&``, parens): end-of-path markers
#   - the path separators themselves (``/``, ``\``): segment boundaries
#   - ``$``, `` ` ``, ``{``, ``}``: start a shell variable / command
#     substitution. Stopping the continuation before these keeps a following
#     reference like ``$HOOK_VAR`` out of the substitution span; otherwise
#     ``$HOME/$HOOK_VAR`` on Windows would become ``C:\Users\me\$HOOK_VAR``
#     and the leading backslash would escape the ``$`` in a POSIX shell.
#
# A path continuation is one or more (separator + name+) segments. ``$HOME/``
# alone (no name chars after the separator) is intentionally NOT absorbed —
# we want the trailing ``/`` left in place so cases like ``$HOME/$VAR`` keep
# their forward slash for the shell to consume.
#
# %USERPROFILE% uses explicit non-word lookbehind/lookahead instead of \b so
# the token is only expanded when it isn't embedded in surrounding identifier
# characters (matching the safety semantics of the \b anchors on the other
# patterns; \b around %...% doesn't work because % itself is non-word).
_PATH_NAME_CHARS = r"[^\s\"'<>|;&()$`{}\\/]"
_PATH_CONTINUATION = rf"((?:[/\\]{_PATH_NAME_CHARS}+)*)"
_HOME_PATTERNS = (
    re.compile(r"\$\{HOME\}" + _PATH_CONTINUATION),
    re.compile(r"\$HOME" + _PATH_CONTINUATION + r"(?=\W|$)"),
    re.compile(r"\$env:USERPROFILE" + _PATH_CONTINUATION + r"(?=\W|$)", re.IGNORECASE),
    re.compile(r"(?<!\w)%USERPROFILE%" + _PATH_CONTINUATION + r"(?!\w)", re.IGNORECASE),
)


def expand_hook_command_paths(data, home=None):
    """Substitute home-dir variables with an absolute home path throughout ``data``.

    Recursively walks dicts/lists; on each string value, replaces ``$HOME``, ``${HOME}``
    ``$env:USERPROFILE``, and ``%USERPROFILE%`` (case-insensitive for the
    Windows variants) with ``home``. Other strings pass through untouched.

    ``home`` defaults to ``os.path.expanduser("~")``. The token AND its
    immediately-following path continuation are consumed together and rejoined
    via :class:`pathlib.Path`, so the result uses the platform-native separator
    end-to-end (no mixed ``C:\\Users\\me/foo`` on Windows).
    """
    if home is None:
        home = os.path.expanduser("~")

    def _replace(match):
        suffix = match.group(1) or ""
        parts = [p for p in re.split(r"[/\\]+", suffix) if p]
        if not parts:
            return home
        return str(Path(home, *parts))

    def _expand(s):
        for pat in _HOME_PATTERNS:
            s = pat.sub(_replace, s)
        return s

    def _walk(obj):
        if isinstance(obj, dict):
            return {k: _walk(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_walk(item) for item in obj]
        if isinstance(obj, str):
            return _expand(obj)
        return obj

    return _walk(data)


def transform_uvw_gui_script(data):
    """Rewrite ``uv run`` to ``uvw run --gui-script`` in every string in ``data``.

    Walks dicts/lists recursively; on each string, substitutes the literal
    launcher ``uv run`` (word-boundary anchored so ``uvx run`` and similar
    do not match). Idempotent — strings already using the new form pass
    through unchanged.

    Used by the installer on Windows to suppress the console window that
    ``uv run`` would otherwise pop up under graphical ADEs.
    """

    def _walk(obj):
        if isinstance(obj, dict):
            return {k: _walk(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_walk(item) for item in obj]
        if isinstance(obj, str):
            return _UV_RUN_RE.sub(_UVW_GUI_TOKEN, obj)
        return obj

    return _walk(data)


def _command_script_names(command_str):
    """Return the set of ``*.py`` script file base names that ``command_str`` runs.

    The command is tokenized with shell-quoting rules (``shlex``, non-POSIX so
    Windows backslash paths and quoted paths containing spaces stay intact);
    every token whose base name (after the final ``/`` or ``\\``) ends in
    ``.py`` is collected. Returning the *set* of scripts — rather than a single
    "the" script — lets callers match a hook by intersection with our known
    script names, so an entry is recognized as ours whenever it runs one of our
    scripts regardless of the runner (``python`` vs ``uv run``), the path in
    front of it, the separator, shell redirections, or any extra script-valued
    arguments it carries (e.g. ``snyk.py --config setup.py``). This is the only
    notion of "is this our hook?" used by the strategies below.
    """
    if not isinstance(command_str, str) or not command_str.strip():
        return set()
    try:
        tokens = shlex.split(command_str, posix=False)
    except ValueError:
        tokens = command_str.split()
    names = set()
    for token in tokens:
        base = re.split(r"[\\/]", token.strip("\"'"))[-1]
        if base.lower().endswith(".py"):
            names.add(base)
    return names


def _entries_script_names(entries, field="command"):
    """Union of ``*.py`` script base names referenced across ``entries`` (dicts only)."""
    out = set()
    for e in entries:
        if isinstance(e, dict):
            out |= _command_script_names(e.get(field))
    return out


def _entry_matches_scripts(entry, script_names, field="command"):
    """True if ``entry`` is a hook dict running one of ``script_names``."""
    if not isinstance(entry, dict):
        return False
    return bool(_command_script_names(entry.get(field)) & script_names)


# TOML support: stdlib tomllib on 3.11+, vendored tomli as fallback.
# Writer (tomli_w) is always vendored — TOML has no stdlib writer.
_VENDOR_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_vendor")
if _VENDOR_DIR not in sys.path:
    sys.path.insert(0, _VENDOR_DIR)
try:
    import tomllib as _toml_reader  # Python 3.11+
except ImportError:  # pragma: no cover - 3.8/3.9/3.10 fallback
    import tomli as _toml_reader
import tomli_w as _toml_writer  # noqa: E402


def _load_json(path):
    """Load JSON file, returning empty dict if file doesn't exist."""
    if not os.path.exists(path):
        return {}
    with open(path) as f:
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


def _merge_command_entries(target_entries, source_entries, field="command"):
    """Merge source hook entries into target entries.

    An existing target entry is treated as *ours* when it runs one of the hook
    scripts the source declares (matched by file name, e.g.
    ``snyk_secure_at_inception.py``). Every such entry is dropped — collapsing
    any duplicates that differ only in runner (``python`` vs ``uv run``), path,
    separator, home-variable spelling, or trailing arguments — and the source
    entries are inserted where the first one stood, so a reinstall refreshes in
    place rather than reordering the file. Entries that run none of our scripts
    are preserved; source entries are deduped against the kept entries (and each
    other) by exact ``field`` value. Non-dict list items are passed through
    untouched.
    """
    source_scripts = _entries_script_names(source_entries, field)

    insert_at = None
    kept: list[Any] = []
    for entry in target_entries:
        if _entry_matches_scripts(entry, source_scripts, field):
            if insert_at is None:
                insert_at = len(kept)
            continue
        kept.append(entry)
    if insert_at is None:
        insert_at = len(kept)

    kept_values = {
        e.get(field) for e in kept if isinstance(e, dict) and isinstance(e.get(field), str)
    }
    new_entries = []
    seen = set()
    for src in source_entries:
        value = src.get(field) if isinstance(src, dict) else None
        if isinstance(value, str):
            if value in kept_values or value in seen:
                continue
            seen.add(value)
        new_entries.append(src)

    target_entries[:] = kept[:insert_at] + new_entries + kept[insert_at:]


def _load_toml(path):
    """Load TOML file, returning empty dict if file doesn't exist."""
    if not os.path.exists(path):
        return {}
    with open(path, "rb") as f:
        return _toml_reader.load(f)


def _write_toml(path, data):
    """Write TOML to file with trailing newline."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        _toml_writer.dump(data, f)


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
        raise ValueError(f"Invalid JSON in file: {target_path}") from None

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
        raise ValueError(f"Invalid JSON in file: {target_path}") from None

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

                    _merge_command_entries(tgt_group["hooks"], src_group.get("hooks", []))

                    merged = True
                    break

            if not merged:
                # No matching group found, append the entire group
                target["hooks"][event].append(src_group)

    _write_json(target_path, target)


def merge_gemini_settings(target_path, source_path):
    """Merge Snyk hooks into Gemini settings.json.

    Gemini's hooks schema mirrors Claude's: hooks -> event -> list of
    {matcher, hooks: [...]} groups. The merge logic is identical — match groups
    by `matcher`, deduplicate hook entries by `command`.
    """
    merge_claude_settings(target_path, source_path)


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


def merge_copilot_cli_mcp(target_path, source_path):
    """Merge Snyk MCP server config into Copilot CLI's mcp-config.json.

    Copilot CLI uses `mcpServers` with each entry requiring `type: local` for
    stdio command-based servers.
    """
    _backup(target_path)
    target = _load_json(target_path)
    source = _load_json(source_path)

    if "mcpServers" not in target:
        target["mcpServers"] = {}

    for name, config in source.get("mcpServers", {}).items():
        entry = dict(config)
        entry["type"] = "local"
        target["mcpServers"][name] = entry

    _write_json(target_path, target)


def merge_vscode_mcp(target_path, source_path):
    """Merge Snyk MCP server config into VS Code Copilot's mcp.json.

    VS Code uses the `servers` key (not `mcpServers`) with each entry requiring
    `type: stdio` for stdio command-based servers.
    """
    _backup(target_path)
    target = _load_json(target_path)
    source = _load_json(source_path)

    if "servers" not in target:
        target["servers"] = {}

    for name, config in source.get("mcpServers", {}).items():
        entry = dict(config)
        entry["type"] = "stdio"
        target["servers"][name] = entry

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

        # Match by hook script file name so this unmerge cleans up entries
        # written by any installer version regardless of runner, path, or
        # home-variable spelling.
        remove_scripts = _entries_script_names(entries)

        target["hooks"][event] = [
            e for e in target["hooks"][event] if not _entry_matches_scripts(e, remove_scripts)
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
            # Match by hook script file name (runner / path / spelling agnostic).
            remove_scripts = _entries_script_names(src_group.get("hooks", []))

            for tgt_group in target["hooks"][event]:
                if tgt_group.get("matcher") != src_matcher:
                    continue

                tgt_group["hooks"] = [
                    h
                    for h in tgt_group.get("hooks", [])
                    if not _entry_matches_scripts(h, remove_scripts)
                ]

        # Remove groups with empty hooks
        target["hooks"][event] = [g for g in target["hooks"][event] if g.get("hooks")]

        # Clean up empty event arrays
        if not target["hooks"][event]:
            del target["hooks"][event]

    _write_json(target_path, target)


def unmerge_gemini_settings(target_path, source_path):
    """Remove Snyk hooks from Gemini settings.json (mirrors Claude's schema)."""
    unmerge_claude_settings(target_path, source_path)


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


def unmerge_copilot_cli_mcp(target_path, source_path):
    """Remove Snyk MCP server entries from Copilot CLI mcp-config.json."""
    target = _load_json(target_path)
    source = _load_json(source_path)

    source_servers = source.get("mcpServers", {})
    if not source_servers or "mcpServers" not in target:
        return

    _backup(target_path)
    for name in source_servers:
        target["mcpServers"].pop(name, None)
    _write_json(target_path, target)


def unmerge_vscode_mcp(target_path, source_path):
    """Remove Snyk MCP server entries from VS Code mcp.json (servers key)."""
    target = _load_json(target_path)
    source = _load_json(source_path)

    source_servers = source.get("mcpServers", {})
    if not source_servers or "servers" not in target:
        return

    _backup(target_path)
    for name in source_servers:
        target["servers"].pop(name, None)
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

        existing_scripts = _entries_script_names(target_hooks[event])
        for entry in entries:
            want = _command_script_names(entry.get("command"))
            if want and not (want & existing_scripts):
                missing.append(f"  hook script missing from '{event}': {', '.join(sorted(want))}")

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

            existing_scripts = _entries_script_names(tgt_group.get("hooks", []))
            for hook in src_group.get("hooks", []):
                want = _command_script_names(hook.get("command"))
                if want and not (want & existing_scripts):
                    missing.append(
                        f"  hook script missing from '{event}': {', '.join(sorted(want))}"
                    )

    if missing:
        for m in missing:
            print(m, file=sys.stderr)
        sys.exit(1)


def verify_gemini_settings(target_path, source_path):
    """Verify Snyk hooks in Gemini settings.json (mirrors Claude's schema)."""
    verify_claude_settings(target_path, source_path)


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


def verify_copilot_cli_mcp(target_path, source_path):
    """Verify all Snyk MCP servers from source exist in Copilot CLI mcp-config.json."""
    target = _load_json(target_path)
    source = _load_json(source_path)

    missing = []
    target_servers = target.get("mcpServers", {})
    for name in source.get("mcpServers", {}):
        if name not in target_servers:
            missing.append(f"  MCP server '{name}' missing from {target_path}")

    if missing:
        for m in missing:
            print(m, file=sys.stderr)
        sys.exit(1)


def verify_vscode_mcp(target_path, source_path):
    """Verify all Snyk MCP servers from source exist in VS Code mcp.json (servers key)."""
    target = _load_json(target_path)
    source = _load_json(source_path)

    missing = []
    target_servers = target.get("servers", {})
    for name in source.get("mcpServers", {}):
        if name not in target_servers:
            missing.append(f"  MCP server '{name}' missing from {target_path}")

    if missing:
        for m in missing:
            print(m, file=sys.stderr)
        sys.exit(1)


def merge_codex_config(target_path, source_path):
    """Merge Snyk entries into Codex's ~/.codex/config.toml.

    Handles three top-level concerns the source TOML may declare:
      - ``[features]``:        shallow-merge (source overrides target keys)
      - ``[hooks.<event>]``:   matcher-aware append, dedupe by ``command``
      - ``[mcp_servers.X]``:   add or overwrite by server name

    Preserves all unrelated keys, tables, and comments-bearing layout the
    user already has (within the limits of TOML round-tripping).
    """
    _backup(target_path)
    source = _load_toml(source_path)

    try:
        target = _load_toml(target_path)
    except Exception as e:
        raise ValueError(f"Invalid TOML in file: {target_path}: {e}") from e

    # 1. features
    if source.get("features"):
        target.setdefault("features", {})
        if not isinstance(target["features"], dict):
            target["features"] = {}
        for key, value in source["features"].items():
            target["features"][key] = value

    # 2. hooks (matcher-aware merge mirroring merge_claude_settings)
    src_hooks = source.get("hooks", {})
    if src_hooks:
        target.setdefault("hooks", {})
        if not isinstance(target["hooks"], dict):
            target["hooks"] = {}
        for event, src_groups in src_hooks.items():
            target["hooks"].setdefault(event, [])
            if not isinstance(target["hooks"][event], list):
                target["hooks"][event] = []

            for src_group in src_groups:
                src_matcher = src_group.get("matcher")
                merged = False

                for tgt_group in target["hooks"][event]:
                    if tgt_group.get("matcher") == src_matcher:
                        tgt_group.setdefault("hooks", [])
                        _merge_command_entries(tgt_group["hooks"], src_group.get("hooks", []))
                        merged = True
                        break

                if not merged:
                    target["hooks"][event].append(src_group)

    # 3. mcp_servers
    src_mcp = source.get("mcp_servers", {})
    if src_mcp:
        target.setdefault("mcp_servers", {})
        if not isinstance(target["mcp_servers"], dict):
            target["mcp_servers"] = {}
        for name, cfg in src_mcp.items():
            target["mcp_servers"][name] = cfg

    _write_toml(target_path, target)


def unmerge_codex_config(target_path, source_path):
    """Remove Snyk entries from Codex's config.toml. Idempotent.

    For features:    deletes only the keys our source declared.
    For hooks:       removes hook entries whose command matches ours; cleans
                     up emptied groups and emptied event arrays.
    For mcp_servers: removes server entries whose key matches our source.
    """
    if not os.path.exists(target_path):
        return
    source = _load_toml(source_path)
    target = _load_toml(target_path)
    if not target:
        return

    _backup(target_path)

    # 1. features: delete keys we own
    src_features = source.get("features", {})
    tgt_features = target.get("features", {})
    if src_features and tgt_features:
        for key in src_features:
            tgt_features.pop(key, None)
        if not tgt_features:
            target.pop("features", None)

    # 2. hooks: matcher-aware removal mirroring unmerge_claude_settings
    src_hooks = source.get("hooks", {})
    tgt_hooks = target.get("hooks", {})
    if src_hooks and tgt_hooks:
        for event, src_groups in src_hooks.items():
            if event not in tgt_hooks:
                continue
            for src_group in src_groups:
                src_matcher = src_group.get("matcher")
                # Match by hook script file name (runner / path / spelling agnostic).
                remove_scripts = _entries_script_names(src_group.get("hooks", []))
                for tgt_group in tgt_hooks[event]:
                    if tgt_group.get("matcher") != src_matcher:
                        continue
                    tgt_group["hooks"] = [
                        h
                        for h in tgt_group.get("hooks", [])
                        if not _entry_matches_scripts(h, remove_scripts)
                    ]
            tgt_hooks[event] = [g for g in tgt_hooks[event] if g.get("hooks")]
            if not tgt_hooks[event]:
                del tgt_hooks[event]
        if not tgt_hooks:
            target.pop("hooks", None)

    # 3. mcp_servers: drop our entries
    src_mcp = source.get("mcp_servers", {})
    tgt_mcp = target.get("mcp_servers", {})
    if src_mcp and tgt_mcp:
        for name in src_mcp:
            tgt_mcp.pop(name, None)
        if not tgt_mcp:
            target.pop("mcp_servers", None)

    if target:
        _write_toml(target_path, target)
    else:
        # File would round-trip to empty — remove rather than leaving a stub.
        try:
            os.remove(target_path)
        except OSError:
            pass


def verify_codex_config(target_path, source_path):
    """Verify Snyk entries are present in Codex's config.toml.

    Read-only. Exits with code 1 if anything from source is missing in target.
    """
    target = _load_toml(target_path)
    source = _load_toml(source_path)

    missing = []

    # features
    src_features = source.get("features", {})
    tgt_features = target.get("features", {})
    for key, expected in src_features.items():
        if tgt_features.get(key) != expected:
            missing.append(f"  features.{key} = {expected!r} missing from {target_path}")

    # hooks (mirrors verify_claude_settings)
    src_hooks = source.get("hooks", {})
    tgt_hooks = target.get("hooks", {})
    for event, src_groups in src_hooks.items():
        if event not in tgt_hooks:
            missing.append(f"  hook event '{event}' not found in {target_path}")
            continue
        for src_group in src_groups:
            src_matcher = src_group.get("matcher")
            tgt_group = next(
                (g for g in tgt_hooks[event] if g.get("matcher") == src_matcher),
                None,
            )
            if tgt_group is None:
                label = f"matcher='{src_matcher}'" if src_matcher else "no matcher"
                missing.append(f"  group ({label}) missing from hooks.{event}")
                continue
            existing_scripts = _entries_script_names(tgt_group.get("hooks", []))
            for hook in src_group.get("hooks", []):
                want = _command_script_names(hook.get("command"))
                if want and not (want & existing_scripts):
                    missing.append(
                        f"  hook script missing from hooks.{event}: {', '.join(sorted(want))}"
                    )

    # mcp_servers
    src_mcp = source.get("mcp_servers", {})
    tgt_mcp = target.get("mcp_servers", {})
    for name in src_mcp:
        if name not in tgt_mcp:
            missing.append(f"  mcp_servers.{name} missing from {target_path}")

    if missing:
        for m in missing:
            print(m, file=sys.stderr)
        sys.exit(1)


def merge_copilot_cli_hooks(target_path, source_path):
    """Merge Snyk hooks into Copilot CLI's hooks.json (~/.copilot/hooks.json).

    Same shape as Cursor's hooks.json ({version, hooks: {event: [entries]}}),
    but each entry uses the `bash` field instead of `command`. Matches existing
    entries by the hook script file name so a reinstall refreshes the entry in
    place across runner / path / spelling changes rather than duplicating it.
    """
    _backup(target_path)
    source = _load_json(source_path)
    try:
        target = _load_json(target_path)
    except Exception:
        raise ValueError(f"Invalid JSON in file: {target_path}") from None

    if "version" not in target:
        target["version"] = source.get("version", 1)
    if "hooks" not in target:
        target["hooks"] = {}

    for event, entries in source.get("hooks", {}).items():
        if event not in target["hooks"]:
            target["hooks"][event] = []
        _merge_command_entries(target["hooks"][event], entries, field="bash")

    _write_json(target_path, target)


def unmerge_copilot_cli_hooks(target_path, source_path):
    """Remove Snyk hooks from Copilot CLI's hooks.json. Idempotent.

    Matches the ``bash`` field by hook script file name, so entries written by
    any installer version — or by hand — get removed regardless of runner,
    path, or home-variable spelling.
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
        remove_scripts = _entries_script_names(entries, field="bash")
        target["hooks"][event] = [
            e
            for e in target["hooks"][event]
            if not _entry_matches_scripts(e, remove_scripts, field="bash")
        ]
        if not target["hooks"][event]:
            del target["hooks"][event]
    _write_json(target_path, target)


def verify_copilot_cli_hooks(target_path, source_path):
    """Verify Snyk hooks from source exist in Copilot CLI's hooks.json.

    Matches the ``bash`` field by hook script file name, so a target hooks.json
    written with a different runner / path / spelling than the source still
    verifies as installed.
    """
    target = _load_json(target_path)
    source = _load_json(source_path)
    missing = []
    target_hooks = target.get("hooks", {})
    for event, entries in source.get("hooks", {}).items():
        if event not in target_hooks:
            missing.append(f"  event '{event}' not found in {target_path}")
            continue
        existing_scripts = _entries_script_names(target_hooks[event], field="bash")
        for entry in entries:
            want = _command_script_names(entry.get("bash"))
            if want and not (want & existing_scripts):
                missing.append(f"  hook script missing from '{event}': {', '.join(sorted(want))}")
    if missing:
        for m in missing:
            print(m, file=sys.stderr)
        sys.exit(1)


STRATEGIES = {
    "merge_cursor_hooks": merge_cursor_hooks,
    "merge_claude_settings": merge_claude_settings,
    "merge_gemini_settings": merge_gemini_settings,
    "merge_mcp_servers": merge_mcp_servers,
    "merge_copilot_cli_mcp": merge_copilot_cli_mcp,
    "merge_copilot_cli_hooks": merge_copilot_cli_hooks,
    "merge_vscode_mcp": merge_vscode_mcp,
    "merge_codex_config": merge_codex_config,
    "unmerge_cursor_hooks": unmerge_cursor_hooks,
    "unmerge_claude_settings": unmerge_claude_settings,
    "unmerge_gemini_settings": unmerge_gemini_settings,
    "unmerge_mcp_servers": unmerge_mcp_servers,
    "unmerge_copilot_cli_mcp": unmerge_copilot_cli_mcp,
    "unmerge_copilot_cli_hooks": unmerge_copilot_cli_hooks,
    "unmerge_vscode_mcp": unmerge_vscode_mcp,
    "unmerge_codex_config": unmerge_codex_config,
    "verify_cursor_hooks": verify_cursor_hooks,
    "verify_claude_settings": verify_claude_settings,
    "verify_gemini_settings": verify_gemini_settings,
    "verify_mcp_servers": verify_mcp_servers,
    "verify_copilot_cli_mcp": verify_copilot_cli_mcp,
    "verify_copilot_cli_hooks": verify_copilot_cli_hooks,
    "verify_vscode_mcp": verify_vscode_mcp,
    "verify_codex_config": verify_codex_config,
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
