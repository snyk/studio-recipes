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

import json
import os
import re
import shlex
import shutil
import sys
from pathlib import Path

LEGACY_LAUNCHERS = frozenset({"python", "python3"})

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


def _fold_path_separators_in_home_spans(s, home):
    """Fold ``\\`` to ``/`` only within path-like spans anchored at ``home``.

    Anchoring on the home prefix limits the fold to substrings that are
    actually paths. Backslashes outside such spans — shell escapes, literal
    arguments, regex patterns — are preserved, so two commands that differ
    only in a non-path backslash do NOT collide on the canonical key.

    The home prefix itself is matched separator-agnostically so a legacy
    Windows entry like ``C:\\Users\\me/foo/bar.py`` (token replaced verbatim,
    forward slashes from the source surviving) collapses to the same key as
    a current install's native ``C:\\Users\\me\\foo\\bar.py``.
    """
    if not home:
        return s
    home_segments = re.split(r"[\\/]", home)
    home_re = r"[\\/]".join(re.escape(seg) for seg in home_segments)
    span_re = re.compile(home_re + rf"(?:[/\\]{_PATH_NAME_CHARS}+)*")
    return span_re.sub(lambda m: m.group(0).replace("\\", "/"), s)


def _canonicalize_command(cmd):
    """Return the canonical (home-expanded, separator-folded) form of a hook command.

    All known home-dir variable spellings (``$HOME``, ``${HOME}``,
    ``$env:USERPROFILE``, ``%USERPROFILE%``) collapse to the same absolute
    path. Within path spans anchored at the home prefix, separators are
    folded (``\\`` -> ``/``) so that entries written by older installer
    versions with mixed separators (e.g. on Windows
    ``C:\\Users\\me/foo\\bar.py``) match entries written by the current
    installer with native separators (``C:\\Users\\me\\foo\\bar.py``).
    The folded form is comparison-only — on-disk writes use the native form
    produced by ``expand_hook_command_paths``. Non-string inputs pass through.
    """
    if not isinstance(cmd, str):
        return cmd
    home = os.path.expanduser("~")
    expanded = expand_hook_command_paths({"_": cmd}, home=home)["_"]
    return _fold_path_separators_in_home_spans(expanded, home)


def _canonical_command_set(entries, field="command"):
    """Return the set of canonical hook command strings declared by ``entries``.

    Used by ``unmerge_*`` strategies as the remove-set when normalizing-on-
    compare: every entry in source AND every candidate in target is
    canonicalized with ``_canonicalize_command`` before set membership is
    checked. This cleans up entries written by older installer versions
    regardless of which home-dir variable spelling they used.
    """
    out = set()
    for e in entries:
        if not isinstance(e, dict):
            continue
        cmd = e.get(field)
        canonical = _canonicalize_command(cmd)
        if isinstance(canonical, str):
            out.add(canonical)
    return out


# Tokens that start shell redirection / piping; truncate argv before these for script identity.
_REDIR_PIPE_TOKENS = frozenset(
    {
        ">>",
        ">",
        "<",
        "|",
        "2>",
        "2>>",
        "&>",
        "&>>",
        "2>&1",
        "<&",
        ">&",
        ">>&",
    }
)

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

    The returned key is home-canonicalized so a target written by the legacy
    installer with ``$HOME/...`` matches a source written by the current
    installer with the already-expanded absolute path.
    """
    if not effective_tokens:
        return None, None

    n = len(effective_tokens)
    for i in range(n - 1, -1, -1):
        norm = _strip_outer_quotes(effective_tokens[i])
        if norm.lower().endswith(".py"):
            return i, _canonicalize_command(norm) or None
    last = _strip_outer_quotes(effective_tokens[-1])
    return n - 1, _canonicalize_command(last) or None


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

            # Migrate by replacement when either:
            #   - target uses a legacy launcher (python/python3), or
            #   - target and source commands are equal once home-dir tokens are
            #     canonicalized (same hook, differing only in $HOME-style vs
            #     install-time-expanded absolute path).
            same_after_canonical = isinstance(old_cmd, str) and _canonicalize_command(
                old_cmd
            ) == _canonicalize_command(cmd)
            if old_launcher in LEGACY_LAUNCHERS or same_after_canonical:
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

        # Normalize-on-compare: collapse every home-dir variable spelling
        # (and the already-expanded absolute path) to a single canonical
        # form on both sides, so this unmerge cleans up entries written by
        # any installer version regardless of which spelling was used.
        remove_commands = _canonical_command_set(entries)

        target["hooks"][event] = [
            e
            for e in target["hooks"][event]
            if _canonicalize_command(e.get("command")) not in remove_commands
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
            # Normalize-on-compare so every home-dir variable spelling
            # (and the install-time expanded path) collapses to one form.
            remove_commands = _canonical_command_set(src_group.get("hooks", []))

            for tgt_group in target["hooks"][event]:
                if tgt_group.get("matcher") != src_matcher:
                    continue

                tgt_group["hooks"] = [
                    h
                    for h in tgt_group.get("hooks", [])
                    if _canonicalize_command(h.get("command")) not in remove_commands
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

        existing_commands = {
            _canonicalize_command(e.get("command")) for e in target_hooks[event] if "command" in e
        }
        for entry in entries:
            cmd = entry.get("command", "")
            if cmd and _canonicalize_command(cmd) not in existing_commands:
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
                _canonicalize_command(h.get("command"))
                for h in tgt_group.get("hooks", [])
                if "command" in h
            }
            for hook in src_group.get("hooks", []):
                cmd = hook.get("command", "")
                if cmd and _canonicalize_command(cmd) not in existing_commands:
                    missing.append(f"  hook command missing from '{event}': {cmd}")

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
                        existing_commands = {
                            h.get("command") for h in tgt_group["hooks"] if "command" in h
                        }
                        for hook in src_group.get("hooks", []):
                            cmd = hook.get("command", "")
                            if cmd not in existing_commands:
                                tgt_group["hooks"].append(hook)
                                existing_commands.add(cmd)
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
                # Normalize-on-compare: collapse every home-dir variable
                # spelling to a single canonical form on both sides.
                remove_commands = _canonical_command_set(src_group.get("hooks", []))
                for tgt_group in tgt_hooks[event]:
                    if tgt_group.get("matcher") != src_matcher:
                        continue
                    tgt_group["hooks"] = [
                        h
                        for h in tgt_group.get("hooks", [])
                        if _canonicalize_command(h.get("command")) not in remove_commands
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
            existing_commands = {
                _canonicalize_command(h.get("command"))
                for h in tgt_group.get("hooks", [])
                if "command" in h
            }
            for hook in src_group.get("hooks", []):
                cmd = hook.get("command", "")
                if cmd and _canonicalize_command(cmd) not in existing_commands:
                    missing.append(f"  hook command missing from hooks.{event}: {cmd}")

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
    but each entry uses the `bash` field instead of `command`. Dedupes by the
    canonicalized `bash` value so an entry previously written with one
    home-dir variable spelling ($HOME, %USERPROFILE%, an expanded absolute
    path, etc.) is not duplicated by a reinstall using a different spelling.
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
        existing = _canonical_command_set(target["hooks"][event], field="bash")
        for entry in entries:
            canonical = _canonicalize_command(entry.get("bash"))
            if isinstance(canonical, str) and canonical in existing:
                continue
            target["hooks"][event].append(entry)
            if isinstance(canonical, str):
                existing.add(canonical)

    _write_json(target_path, target)


def unmerge_copilot_cli_hooks(target_path, source_path):
    """Remove Snyk hooks from Copilot CLI's hooks.json. Idempotent.

    Compares the ``bash`` field after canonicalizing home-dir variable
    spellings ($HOME, ${HOME}, %USERPROFILE%, $env:USERPROFILE, and the
    already-expanded absolute path), so entries written by any installer
    version — or by hand — get removed regardless of which spelling they
    used.
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
        remove_bash = _canonical_command_set(entries, field="bash")
        target["hooks"][event] = [
            e
            for e in target["hooks"][event]
            if _canonicalize_command(e.get("bash")) not in remove_bash
        ]
        if not target["hooks"][event]:
            del target["hooks"][event]
    _write_json(target_path, target)


def verify_copilot_cli_hooks(target_path, source_path):
    """Verify Snyk hooks from source exist in Copilot CLI's hooks.json.

    Compares the ``bash`` field after canonicalizing home-dir variable
    spellings, so a target hooks.json written with a different spelling
    than the source still verifies as installed.
    """
    target = _load_json(target_path)
    source = _load_json(source_path)
    missing = []
    target_hooks = target.get("hooks", {})
    for event, entries in source.get("hooks", {}).items():
        if event not in target_hooks:
            missing.append(f"  event '{event}' not found in {target_path}")
            continue
        existing = _canonical_command_set(target_hooks[event], field="bash")
        for entry in entries:
            b = entry.get("bash", "")
            if b and _canonicalize_command(b) not in existing:
                missing.append(f"  hook bash command missing from '{event}': {b}")
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
