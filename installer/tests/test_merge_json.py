"""Unit tests for installer/lib/merge_json.py."""

import json
import os

import pytest
from helpers import read_json
from merge_json import (
    STRATEGIES,
    _backup,
    _command_script_names,
    _is_snyk_command,
    _load_json,
    _load_toml,
    _write_json,
    _write_toml,
    expand_hook_command_paths,
    main,
    merge_claude_settings,
    merge_codex_config,
    merge_copilot_cli_hooks,
    merge_cursor_hooks,
    merge_gemini_settings,
    merge_mcp_servers,
    unmerge_claude_settings,
    unmerge_codex_config,
    unmerge_copilot_cli_hooks,
    unmerge_cursor_hooks,
    unmerge_gemini_settings,
    unmerge_mcp_servers,
    verify_claude_settings,
    verify_codex_config,
    verify_copilot_cli_hooks,
    verify_cursor_hooks,
    verify_gemini_settings,
    verify_mcp_servers,
)

# ═══════════════════════════════════════════════════════════════════════════
# Helper functions
# ═══════════════════════════════════════════════════════════════════════════


class TestExpandHookCommandPaths:
    """expand_hook_command_paths substitutes $HOME / $env:USERPROFILE / %USERPROFILE%."""

    HOME = "/Users/test"

    def test_substitutes_unix_home(self):
        out = expand_hook_command_paths({"cmd": 'uv run "$HOME/.x/hook.py"'}, home=self.HOME)
        assert out == {"cmd": 'uv run "/Users/test/.x/hook.py"'}

    def test_substitutes_braced_unix_home(self):
        out = expand_hook_command_paths({"cmd": 'uv run "${HOME}/.x/hook.py"'}, home=self.HOME)
        assert out == {"cmd": 'uv run "/Users/test/.x/hook.py"'}

    def test_substitutes_powershell_userprofile(self):
        # Backslash path continuation is rejoined with the platform separator
        # (forward slashes on POSIX, where the tests run).
        out = expand_hook_command_paths(
            {"cmd": 'uv run "$env:USERPROFILE\\.x\\hook.py"'}, home=self.HOME
        )
        assert out == {"cmd": 'uv run "/Users/test/.x/hook.py"'}

    def test_substitutes_cmd_userprofile(self):
        out = expand_hook_command_paths(
            {"cmd": 'uv run "%USERPROFILE%\\.x\\hook.py"'}, home=self.HOME
        )
        assert out == {"cmd": 'uv run "/Users/test/.x/hook.py"'}

    def test_word_boundary_protects_lookalike(self):
        # $HOMEY should NOT be substituted because E\b doesn't match before Y.
        out = expand_hook_command_paths({"cmd": "echo $HOMEY"}, home=self.HOME)
        assert out == {"cmd": "echo $HOMEY"}

    def test_recursive_walk(self):
        data = {
            "hooks": {
                "PostToolUse": [
                    {"command": 'python3 "$HOME/a.py"'},
                    {"nested": {"deeper": 'uv run "$HOME/b.py"'}},
                ]
            },
            "version": 1,
        }
        out = expand_hook_command_paths(data, home=self.HOME)
        assert out["hooks"]["PostToolUse"][0]["command"] == 'python3 "/Users/test/a.py"'
        assert out["hooks"]["PostToolUse"][1]["nested"]["deeper"] == 'uv run "/Users/test/b.py"'
        assert out["version"] == 1

    def test_no_op_on_strings_without_tokens(self):
        out = expand_hook_command_paths({"command": "eslint --fix"}, home=self.HOME)
        assert out == {"command": "eslint --fix"}

    def test_home_with_backslashes_safe(self):
        # On Windows home is C:\Users\foo — backslashes must not be interpreted as re backrefs.
        out = expand_hook_command_paths({"cmd": 'uv run "$HOME/x.py"'}, home="C:\\Users\\foo")
        assert out == {"cmd": 'uv run "C:\\Users\\foo/x.py"'}

    def test_default_home_uses_expanduser(self, monkeypatch):
        monkeypatch.setenv("HOME", "/tmp/fakehome")
        out = expand_hook_command_paths({"cmd": '"$HOME/x"'})
        assert "/tmp/fakehome" in out["cmd"]

    def test_case_insensitive_userprofile(self):
        out = expand_hook_command_paths({"cmd": "%userprofile%\\x"}, home=self.HOME)
        assert out == {"cmd": "/Users/test/x"}

    def test_path_continuation_uses_native_separator(self):
        # $HOME/foo/bar.py: the continuation is consumed together with the
        # token and rejoined via pathlib so the result has no mixed separators.
        # On POSIX the joiner produces forward slashes throughout.
        out = expand_hook_command_paths(
            {"cmd": 'python3 "$HOME/.snyk/hook.py"'}, home="/Users/test"
        )
        assert out == {"cmd": 'python3 "/Users/test/.snyk/hook.py"'}

    def test_path_continuation_normalizes_mixed_separators(self):
        # Source string mixes / and \ in the continuation. Both are absorbed
        # into Path components and rejoined with the native separator.
        out = expand_hook_command_paths(
            {"cmd": 'python3 "$HOME/.snyk\\hook.py"'}, home="/Users/test"
        )
        assert out == {"cmd": 'python3 "/Users/test/.snyk/hook.py"'}

    def test_path_continuation_stops_at_quote(self):
        # The optional continuation must not eat past a closing quote.
        out = expand_hook_command_paths({"cmd": 'echo "$HOME/foo" bar'}, home="/Users/test")
        assert out == {"cmd": 'echo "/Users/test/foo" bar'}

    def test_path_continuation_stops_at_space(self):
        # Bare (unquoted) token followed by whitespace: continuation ends at space.
        out = expand_hook_command_paths({"cmd": "echo $HOME/foo bar"}, home="/Users/test")
        assert out == {"cmd": "echo /Users/test/foo bar"}

    def test_path_continuation_stops_at_shell_meta(self):
        # Shell metas like '|' terminate the continuation.
        out = expand_hook_command_paths({"cmd": "cat $HOME/foo|wc -l"}, home="/Users/test")
        assert out == {"cmd": "cat /Users/test/foo|wc -l"}

    def test_path_continuation_preserves_following_unbraced_shell_variable(self):
        # $HOME/$HOOK_VAR/script.py: the continuation must NOT absorb the
        # following shell variable as a path component. If it did, Path
        # joining on Windows would yield C:\Users\me\$HOOK_VAR\script.py and
        # the leading backslash would escape the $ in a POSIX shell — breaking
        # variable expansion at runtime.
        out = expand_hook_command_paths(
            {"cmd": 'uv run "$HOME/$HOOK_VAR/script.py"'}, home="/Users/test"
        )
        assert out == {"cmd": 'uv run "/Users/test/$HOOK_VAR/script.py"'}

    def test_path_continuation_preserves_following_braced_shell_variable(self):
        # ${VAR} expansion: continuation must stop at the opening brace.
        out = expand_hook_command_paths(
            {"cmd": 'uv run "$HOME/${HOOK_VAR}/script.py"'}, home="/Users/test"
        )
        assert out == {"cmd": 'uv run "/Users/test/${HOOK_VAR}/script.py"'}

    def test_path_continuation_stops_at_partial_segment_with_variable(self):
        # $HOME/foo${VAR}/bar — only /foo is absorbed; the rest is left for
        # the shell to expand. The slash before $ is preserved as forward slash.
        out = expand_hook_command_paths({"cmd": 'uv run "$HOME/foo${VAR}/bar"'}, home="/Users/test")
        assert out == {"cmd": 'uv run "/Users/test/foo${VAR}/bar"'}

    def test_path_continuation_stops_at_backtick(self):
        # Backtick starts a command substitution — must not be absorbed.
        out = expand_hook_command_paths({"cmd": "echo $HOME/`date +%s`"}, home="/Users/test")
        assert out == {"cmd": "echo /Users/test/`date +%s`"}

    def test_userprofile_not_substituted_when_embedded_in_word(self):
        # %USERPROFILE% embedded in surrounding identifier characters is not a
        # shell-variable reference (mirrors the \b protection on $HOME).
        out = expand_hook_command_paths({"cmd": "echo abc%USERPROFILE%def"}, home=self.HOME)
        assert out == {"cmd": "echo abc%USERPROFILE%def"}


class TestCommandScriptNames:
    """_command_script_names collects every *.py script a command runs, by base
    name — ignoring the runner, the path in front, the separator, trailing args,
    and shell redirections. Matching a hook by intersection with this set is the
    sole basis for identifying "our" hooks."""

    def test_extracts_basename_from_quoted_path(self):
        cmd = 'uv run "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'
        assert _command_script_names(cmd) == {"snyk_secure_at_inception.py"}

    def test_ignores_runner(self):
        for runner in ("uv run", "python", "python3", "cat"):
            cmd = f'{runner} "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'
            assert _command_script_names(cmd) == {"snyk_secure_at_inception.py"}

    def test_ignores_path_and_separator(self):
        names = (
            _command_script_names('uv run "$HOME/.cursor/hooks/snyk_secure_at_inception.py"')
            | _command_script_names('uv run "C:\\Users\\me\\hooks\\snyk_secure_at_inception.py"')
            | _command_script_names('uv run "/Users/me/.cursor/hooks/snyk_secure_at_inception.py"')
            | _command_script_names('uv run "%USERPROFILE%/hooks/snyk_secure_at_inception.py"')
        )
        assert names == {"snyk_secure_at_inception.py"}

    def test_collects_every_py_token(self):
        # A second, script-valued argument is also collected, so matching by
        # intersection with our known scripts still identifies the hook even if
        # the argument's name changes between installer versions.
        cmd = 'python "$HOME/hooks/snyk_secure_at_inception.py" --config setup.py'
        assert _command_script_names(cmd) == {"snyk_secure_at_inception.py", "setup.py"}

    def test_handles_quoted_path_with_spaces(self):
        # shlex keeps the quoted path intact despite the space in the directory.
        cmd = 'python "/Users/My Name/.snyk/snyk_secure_at_inception.py"'
        assert _command_script_names(cmd) == {"snyk_secure_at_inception.py"}

    def test_ignores_trailing_args(self):
        cmd = 'uv run "$HOME/.copilot/hooks/snyk_secure_at_inception.py" agentStop'
        assert _command_script_names(cmd) == {"snyk_secure_at_inception.py"}

    def test_ignores_redirect_to_log(self):
        cmd = (
            'python3 "$HOME/.cursor/hooks/snyk_secure_at_inception.py" '
            '>> "$HOME/.cursor/hooks/snyk_secure_at_inception.log"'
        )
        assert _command_script_names(cmd) == {"snyk_secure_at_inception.py"}

    def test_empty_when_no_py_script(self):
        assert _command_script_names("eslint --fix") == set()

    def test_empty_for_non_string(self):
        assert _command_script_names(None) == set()


class TestTransformUvwGuiScript:
    """transform_uvw_gui_script rewrites `uv run` to `uvw run --gui-script` in strings."""

    def test_substitutes_uv_run_in_command_string(self):
        from merge_json import transform_uvw_gui_script

        out = transform_uvw_gui_script({"command": 'uv run "$HOME/x.py"'})
        assert out == {"command": 'uvw run --gui-script "$HOME/x.py"'}

    def test_does_not_match_uvx(self):
        from merge_json import transform_uvw_gui_script

        out = transform_uvw_gui_script({"command": "uvx run something"})
        assert out == {"command": "uvx run something"}

    def test_does_not_match_my_uv_run(self):
        # Bare-word check prevents corrupting unrelated tokens that happen to
        # end in "uv run". The pattern requires a non-identifier prefix.
        from merge_json import transform_uvw_gui_script

        out = transform_uvw_gui_script({"command": "my-uv run something"})
        assert out == {"command": "my-uv run something"}

    def test_idempotent_on_already_transformed(self):
        from merge_json import transform_uvw_gui_script

        already = {"command": 'uvw run --gui-script "$HOME/x.py"'}
        assert transform_uvw_gui_script(already) == already

    def test_walks_nested_structure(self):
        from merge_json import transform_uvw_gui_script

        data = {
            "hooks": {
                "PostToolUse": [
                    {"command": 'uv run "$HOME/a.py"'},
                    {"nested": {"deeper": 'uv run "$HOME/b.py"'}},
                ]
            },
            "version": 1,
        }
        out = transform_uvw_gui_script(data)
        assert out["hooks"]["PostToolUse"][0]["command"] == 'uvw run --gui-script "$HOME/a.py"'
        assert (
            out["hooks"]["PostToolUse"][1]["nested"]["deeper"]
            == 'uvw run --gui-script "$HOME/b.py"'
        )
        # Non-string values pass through.
        assert out["version"] == 1

    def test_no_op_on_strings_without_uv_run(self):
        from merge_json import transform_uvw_gui_script

        out = transform_uvw_gui_script({"command": "eslint --fix"})
        assert out == {"command": "eslint --fix"}


class TestLoadJson:
    def test_returns_dict_from_valid_file(self, tmp_path):
        p = tmp_path / "data.json"
        p.write_text('{"key": "value"}')
        assert _load_json(str(p)) == {"key": "value"}

    def test_returns_empty_dict_for_missing_file(self, tmp_path):
        assert _load_json(str(tmp_path / "nope.json")) == {}

    def test_raises_on_invalid_json(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("not json{{{")
        with pytest.raises(json.JSONDecodeError):
            _load_json(str(p))


class TestBackup:
    def test_creates_bak_file(self, tmp_path):
        p = tmp_path / "file.json"
        p.write_text('{"a": 1}')
        _backup(str(p))
        bak = tmp_path / "file.json.bak"
        assert bak.exists()
        assert bak.read_text() == '{"a": 1}'

    def test_noop_for_missing_file(self, tmp_path):
        _backup(str(tmp_path / "nope.json"))
        assert not (tmp_path / "nope.json.bak").exists()

    def test_overwrites_existing_bak(self, tmp_path):
        p = tmp_path / "file.json"
        p.write_text("original")
        _backup(str(p))
        p.write_text("updated")
        _backup(str(p))
        assert (tmp_path / "file.json.bak").read_text() == "updated"


class TestWriteJson:
    def test_pretty_prints_with_trailing_newline(self, tmp_path):
        p = str(tmp_path / "out.json")
        _write_json(p, {"a": 1})
        raw = open(p).read()
        assert raw == '{\n  "a": 1\n}\n'

    def test_creates_parent_directories(self, tmp_path):
        p = str(tmp_path / "a" / "b" / "c" / "out.json")
        _write_json(p, {"x": True})
        assert os.path.isfile(p)

    def test_overwrites_existing(self, tmp_path):
        p = str(tmp_path / "out.json")
        _write_json(p, {"first": True})
        _write_json(p, {"second": True})
        assert read_json(p) == {"second": True}


class TestIsSnykCommand:
    def test_positive(self):
        assert _is_snyk_command("python3 snyk_hook.py") is True

    def test_case_insensitive(self):
        assert _is_snyk_command("SNYK_TOOL") is True

    def test_negative(self):
        assert _is_snyk_command("eslint --fix") is False

    def test_empty_string(self):
        assert _is_snyk_command("") is False


class TestMergeRedirectEntries:
    """Entries that pipe the hook script's output to a log file are still
    matched by the script name, so a reinstall refreshes them in place."""

    def test_merge_replaces_legacy_when_target_has_redirect(self, write_json, snyk_cursor_source):
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "afterFileEdit": [
                        {
                            "command": (
                                'python3 "$HOME/.cursor/hooks/snyk_secure_at_inception.py" '
                                '>> "$HOME/.cursor/hooks/snyk_secure_at_inception.log"'
                            )
                        }
                    ]
                },
            },
        )
        merge_cursor_hooks(target, snyk_cursor_source)
        after_edit = read_json(target)["hooks"]["afterFileEdit"]
        assert len(after_edit) == 1
        assert after_edit[0]["command"] == (
            'uv run "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'
        )


# ═══════════════════════════════════════════════════════════════════════════
# merge_cursor_hooks
# ═══════════════════════════════════════════════════════════════════════════


class TestMergeCursorHooks:
    def test_merge_into_empty_target(self, empty_target, snyk_cursor_source):
        merge_cursor_hooks(empty_target, snyk_cursor_source)
        result = read_json(empty_target)
        assert result["version"] == 1
        assert len(result["hooks"]["afterFileEdit"]) == 1
        assert len(result["hooks"]["stop"]) == 1

    def test_merge_preserves_existing_hooks(self, existing_cursor_target, snyk_cursor_source):
        merge_cursor_hooks(existing_cursor_target, snyk_cursor_source)
        result = read_json(existing_cursor_target)
        commands = [e["command"] for e in result["hooks"]["afterFileEdit"]]
        assert "eslint --fix" in commands
        assert any("snyk" in c for c in commands)

    def test_merge_is_idempotent(self, empty_target, snyk_cursor_source):
        merge_cursor_hooks(empty_target, snyk_cursor_source)
        merge_cursor_hooks(empty_target, snyk_cursor_source)
        result = read_json(empty_target)
        assert len(result["hooks"]["afterFileEdit"]) == 1
        assert len(result["hooks"]["stop"]) == 1

    def test_merge_preserves_existing_version(self, write_json, snyk_cursor_source):
        target = write_json("target.json", {"version": 2, "hooks": {}})
        merge_cursor_hooks(target, snyk_cursor_source)
        assert read_json(target)["version"] == 2

    def test_merge_adds_new_event_types(self, write_json, snyk_cursor_source):
        target = write_json(
            "target.json",
            {"version": 1, "hooks": {"beforeCommand": [{"command": "echo hi"}]}},
        )
        merge_cursor_hooks(target, snyk_cursor_source)
        result = read_json(target)
        assert "beforeCommand" in result["hooks"]
        assert "afterFileEdit" in result["hooks"]
        assert "stop" in result["hooks"]

    def test_merge_creates_backup(self, existing_cursor_target, snyk_cursor_source):
        merge_cursor_hooks(existing_cursor_target, snyk_cursor_source)
        assert os.path.isfile(existing_cursor_target + ".bak")

    def test_merge_with_empty_source(self, write_json, existing_cursor_target):
        source = write_json("source.json", {})
        original = read_json(existing_cursor_target)
        merge_cursor_hooks(existing_cursor_target, source)
        result = read_json(existing_cursor_target)
        assert result["hooks"] == original["hooks"]

    def test_merge_dedup_by_command_only(self, write_json, snyk_cursor_source):
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "afterFileEdit": [
                        {
                            "command": 'uv run "$HOME/.cursor/hooks/snyk_secure_at_inception.py"',
                            "extra_field": "different",
                        }
                    ]
                },
            },
        )
        merge_cursor_hooks(target, snyk_cursor_source)
        assert len(read_json(target)["hooks"]["afterFileEdit"]) == 1

    def test_merge_replaces_legacy_launcher(self, write_json, snyk_cursor_source):
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "afterFileEdit": [
                        {"command": 'python "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'}
                    ]
                },
            },
        )
        merge_cursor_hooks(target, snyk_cursor_source)
        after_edit = read_json(target)["hooks"]["afterFileEdit"]
        assert len(after_edit) == 1
        assert after_edit[0]["command"] == (
            'uv run "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'
        )

    def test_merge_replaces_legacy_python3_launcher(self, write_json, snyk_cursor_source):
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "afterFileEdit": [
                        {"command": 'python3 "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'}
                    ]
                },
            },
        )
        merge_cursor_hooks(target, snyk_cursor_source)
        after_edit = read_json(target)["hooks"]["afterFileEdit"]
        assert len(after_edit) == 1
        assert after_edit[0]["command"] == (
            'uv run "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'
        )

    def test_merge_replaces_uv_run_with_uvw_gui_script(self, write_json, tmp_path):
        """Windows upgrade path: an older installer wrote `uv run ...` to the
        target. The current Windows installer now writes `uvw run --gui-script ...`.
        Same script (matched by file name) -> the old entry must be replaced in
        place, not appended alongside."""
        source = write_json(
            "source/cursor_hooks.json",
            {
                "version": 1,
                "hooks": {
                    "afterFileEdit": [
                        {
                            "command": (
                                "uvw run --gui-script "
                                '"$HOME/.cursor/hooks/snyk_secure_at_inception.py"'
                            )
                        }
                    ]
                },
            },
        )
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "afterFileEdit": [
                        {"command": 'uv run "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'}
                    ]
                },
            },
        )
        merge_cursor_hooks(target, source)
        after_edit = read_json(target)["hooks"]["afterFileEdit"]
        assert len(after_edit) == 1
        assert after_edit[0]["command"] == (
            'uvw run --gui-script "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'
        )

    def test_merge_replaces_any_runner_of_same_script(self, write_json, snyk_cursor_source):
        # Matching is by script name, so even an unusual runner that points at
        # our hook script is treated as ours and refreshed in place — never
        # left behind as a duplicate.
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "afterFileEdit": [
                        {"command": 'cat "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'}
                    ]
                },
            },
        )
        merge_cursor_hooks(target, snyk_cursor_source)
        after_edit = read_json(target)["hooks"]["afterFileEdit"]
        commands = [e["command"] for e in after_edit]
        assert commands == ['uv run "$HOME/.cursor/hooks/snyk_secure_at_inception.py"']

    def test_merge_collapses_multiple_existing_entries_for_same_script(
        self, write_json, snyk_cursor_source
    ):
        # Two stale entries that run the same script (different runners) must
        # collapse to a single refreshed entry — never leave a duplicate behind.
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "afterFileEdit": [
                        {"command": 'python "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'},
                        {"command": 'uv run "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'},
                    ]
                },
            },
        )
        merge_cursor_hooks(target, snyk_cursor_source)
        after_edit = read_json(target)["hooks"]["afterFileEdit"]
        assert [e["command"] for e in after_edit] == [
            'uv run "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'
        ]

    def test_merge_preserves_position_of_existing_hook(self, write_json, snyk_cursor_source):
        # A stale hook entry is refreshed in place — the user's own hook that
        # followed it keeps its relative order.
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "afterFileEdit": [
                        {"command": 'python "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'},
                        {"command": "eslint --fix"},
                    ]
                },
            },
        )
        merge_cursor_hooks(target, snyk_cursor_source)
        commands = [e["command"] for e in read_json(target)["hooks"]["afterFileEdit"]]
        assert commands == [
            'uv run "$HOME/.cursor/hooks/snyk_secure_at_inception.py"',
            "eslint --fix",
        ]

    def test_merge_skips_non_dict_entries(self, write_json, snyk_cursor_source):
        # A malformed config with a non-dict list item must not crash the merge.
        target = write_json(
            "target.json",
            {"version": 1, "hooks": {"afterFileEdit": ["not-a-dict", {"command": "eslint --fix"}]}},
        )
        merge_cursor_hooks(target, snyk_cursor_source)
        entries = read_json(target)["hooks"]["afterFileEdit"]
        assert "not-a-dict" in entries
        assert {"command": "eslint --fix"} in entries
        assert any(
            isinstance(e, dict) and "snyk_secure_at_inception" in e.get("command", "")
            for e in entries
        )

    def test_merge_replaces_raw_home_when_source_is_expanded(self, write_json, tmp_path):
        """Upgrade path: target was installed when source used $HOME; current source
        ships an install-time-expanded absolute path. The two must collapse to one
        entry (no duplicate)."""
        home = os.path.expanduser("~")
        expanded = f'uv run "{home}/.cursor/hooks/snyk_secure_at_inception.py"'
        source = write_json(
            "source/cursor_hooks.json",
            {
                "version": 1,
                "hooks": {
                    "afterFileEdit": [{"command": expanded}],
                    "stop": [{"command": expanded}],
                },
            },
        )
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "afterFileEdit": [
                        {"command": 'uv run "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'}
                    ]
                },
            },
        )
        merge_cursor_hooks(target, source)
        after_edit = read_json(target)["hooks"]["afterFileEdit"]
        assert len(after_edit) == 1
        # Target should have migrated to the install-time-expanded form.
        assert after_edit[0]["command"] == expanded

    def test_merge_dedupes_mixed_separator_legacy_entry(self, write_json, monkeypatch):
        """Upgrade path: a Windows install of a previous installer version wrote
        the home-expanded path with mixed separators (the $HOME token was
        replaced literally so forward slashes from the source survived next to
        the backslashes from the home prefix). The current installer writes
        all-native-separator paths via Path. Merge must recognize the legacy
        mixed-separator entry as the same hook and replace it — never append a
        duplicate."""
        # Simulate a Windows home so canonicalization anchors at the same
        # prefix the test data uses. POSIX expanduser honors $HOME.
        monkeypatch.setenv("HOME", "C:\\Users\\me")
        # Mixed-separator legacy form (what a Windows install of the old
        # installer produced).
        legacy_mixed = 'uv run "C:\\Users\\me/.cursor/hooks/snyk_secure_at_inception.py"'
        # Native-separator form (what a Windows install of the new installer
        # produces). Constructed explicitly so the test does not depend on the
        # platform running the test.
        new_native = 'uv run "C:\\Users\\me\\.cursor\\hooks\\snyk_secure_at_inception.py"'
        source = write_json(
            "source/cursor_hooks.json",
            {"version": 1, "hooks": {"afterFileEdit": [{"command": new_native}]}},
        )
        target = write_json(
            "target.json",
            {"version": 1, "hooks": {"afterFileEdit": [{"command": legacy_mixed}]}},
        )
        merge_cursor_hooks(target, source)
        after_edit = read_json(target)["hooks"]["afterFileEdit"]
        assert len(after_edit) == 1
        assert after_edit[0]["command"] == new_native

    def test_merge_dedupes_forward_slash_when_source_is_native(self, write_json, monkeypatch):
        """Upgrade path variant: target carries an all-forward-slash expanded
        path (e.g. a Windows install that always used '/' in the past), source
        is the new all-backslash native form. Single entry after merge."""
        monkeypatch.setenv("HOME", "C:\\Users\\me")
        forward_slash = 'uv run "C:/Users/me/.cursor/hooks/snyk_secure_at_inception.py"'
        new_native = 'uv run "C:\\Users\\me\\.cursor\\hooks\\snyk_secure_at_inception.py"'
        source = write_json(
            "source/cursor_hooks.json",
            {"version": 1, "hooks": {"afterFileEdit": [{"command": new_native}]}},
        )
        target = write_json(
            "target.json",
            {"version": 1, "hooks": {"afterFileEdit": [{"command": forward_slash}]}},
        )
        merge_cursor_hooks(target, source)
        after_edit = read_json(target)["hooks"]["afterFileEdit"]
        assert len(after_edit) == 1
        assert after_edit[0]["command"] == new_native

    def test_merge_is_idempotent_for_native_separator_source(self, write_json, monkeypatch):
        """Re-running merge with the same native-separator source must not
        accumulate duplicate entries — the second pass must dedupe by canonical
        comparison even though the on-disk form has backslashes."""
        monkeypatch.setenv("HOME", "C:\\Users\\me")
        new_native = 'uv run "C:\\Users\\me\\.cursor\\hooks\\snyk_secure_at_inception.py"'
        source = write_json(
            "source/cursor_hooks.json",
            {"version": 1, "hooks": {"afterFileEdit": [{"command": new_native}]}},
        )
        target = write_json(
            "target.json",
            {"version": 1, "hooks": {"afterFileEdit": []}},
        )
        merge_cursor_hooks(target, source)
        merge_cursor_hooks(target, source)
        after_edit = read_json(target)["hooks"]["afterFileEdit"]
        assert len(after_edit) == 1

    def test_merge_no_backup_for_new_target(self, empty_target, snyk_cursor_source):
        merge_cursor_hooks(empty_target, snyk_cursor_source)
        assert not os.path.isfile(empty_target + ".bak")

    def test_merge_fails_on_invalid_json(self, tmp_path, snyk_cursor_source):
        target = tmp_path / "target.json"
        target.write_text("{ invalid }")
        with pytest.raises(ValueError, match="Invalid JSON in file"):
            merge_cursor_hooks(str(target), snyk_cursor_source)


# ═══════════════════════════════════════════════════════════════════════════
# merge_claude_settings
# ═══════════════════════════════════════════════════════════════════════════


class TestMergeClaudeSettings:
    def test_merge_into_empty_target(self, empty_target, snyk_claude_source):
        merge_claude_settings(empty_target, snyk_claude_source)
        result = read_json(empty_target)
        assert "PostToolUse" in result["hooks"]
        assert "Stop" in result["hooks"]

    def test_merge_into_matching_group(self, existing_claude_target, snyk_claude_source):
        merge_claude_settings(existing_claude_target, snyk_claude_source)
        result = read_json(existing_claude_target)
        # The Edit|Write group should have both prettier and snyk hooks
        groups = result["hooks"]["PostToolUse"]
        edit_write_group = next(g for g in groups if g.get("matcher") == "Edit|Write")
        commands = [h["command"] for h in edit_write_group["hooks"]]
        assert "prettier --write" in commands
        assert any("snyk" in c for c in commands)

    def test_merge_appends_new_group(self, write_json, snyk_claude_source):
        target = write_json(
            "target.json",
            {
                "hooks": {
                    "PostToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "logger"}],
                        }
                    ]
                }
            },
        )
        merge_claude_settings(target, snyk_claude_source)
        result = read_json(target)
        matchers = [g.get("matcher") for g in result["hooks"]["PostToolUse"]]
        assert "Bash" in matchers
        assert "Edit|Write" in matchers

    def test_merge_is_idempotent(self, empty_target, snyk_claude_source):
        merge_claude_settings(empty_target, snyk_claude_source)
        merge_claude_settings(empty_target, snyk_claude_source)
        result = read_json(empty_target)
        edit_group = result["hooks"]["PostToolUse"][0]
        assert len(edit_group["hooks"]) == 1

    def test_merge_handles_no_matcher_group(self, empty_target, snyk_claude_source):
        merge_claude_settings(empty_target, snyk_claude_source)
        result = read_json(empty_target)
        # Stop event has a group with no matcher key
        stop_groups = result["hooks"]["Stop"]
        assert len(stop_groups) == 1
        assert "matcher" not in stop_groups[0]

    def test_merge_preserves_non_hooks_settings(self, existing_claude_target, snyk_claude_source):
        merge_claude_settings(existing_claude_target, snyk_claude_source)
        result = read_json(existing_claude_target)
        assert result["allowedTools"] == ["Read", "Write"]

    def test_merge_multiple_events(self, empty_target, snyk_claude_source):
        merge_claude_settings(empty_target, snyk_claude_source)
        result = read_json(empty_target)
        assert "PostToolUse" in result["hooks"]
        assert "Stop" in result["hooks"]

    def test_merge_creates_backup(self, existing_claude_target, snyk_claude_source):
        merge_claude_settings(existing_claude_target, snyk_claude_source)
        assert os.path.isfile(existing_claude_target + ".bak")

    def test_merge_replaces_matching_script_hook_launcher(self, write_json, snyk_claude_source):
        target = write_json(
            "target.json",
            {
                "hooks": {
                    "PostToolUse": [
                        {
                            "matcher": "Edit|Write",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": 'python "$HOME/.claude/hooks/snyk_secure_at_inception.py"',
                                    "statusMessage": "old",
                                }
                            ],
                        }
                    ]
                }
            },
        )
        merge_claude_settings(target, snyk_claude_source)
        hooks = read_json(target)["hooks"]["PostToolUse"][0]["hooks"]
        assert len(hooks) == 1
        assert hooks[0]["command"] == ('uv run "$HOME/.claude/hooks/snyk_secure_at_inception.py"')
        assert hooks[0]["statusMessage"] == "Tracking code changes for security scan..."

    def test_merge_replaces_legacy_python3_hook_launcher(self, write_json, snyk_claude_source):
        target = write_json(
            "target.json",
            {
                "hooks": {
                    "PostToolUse": [
                        {
                            "matcher": "Edit|Write",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": 'python3 "$HOME/.claude/hooks/snyk_secure_at_inception.py"',
                                    "statusMessage": "old",
                                }
                            ],
                        }
                    ]
                }
            },
        )
        merge_claude_settings(target, snyk_claude_source)
        hooks = read_json(target)["hooks"]["PostToolUse"][0]["hooks"]
        assert len(hooks) == 1
        assert hooks[0]["command"] == ('uv run "$HOME/.claude/hooks/snyk_secure_at_inception.py"')

    def test_merge_fails_on_invalid_json(self, tmp_path, snyk_claude_source):
        target = tmp_path / "target.json"
        target.write_text("{ invalid }")
        with pytest.raises(ValueError, match="Invalid JSON in file"):
            merge_claude_settings(str(target), snyk_claude_source)


# ═══════════════════════════════════════════════════════════════════════════
# merge_mcp_servers
# ═══════════════════════════════════════════════════════════════════════════


class TestMergeMcpServers:
    def test_merge_into_empty_target(self, empty_target, snyk_mcp_source):
        merge_mcp_servers(empty_target, snyk_mcp_source)
        result = read_json(empty_target)
        assert "Snyk" in result["mcpServers"]
        assert result["mcpServers"]["Snyk"]["command"] == "npx"

    def test_merge_preserves_non_snyk_servers(self, existing_mcp_target, snyk_mcp_source):
        merge_mcp_servers(existing_mcp_target, snyk_mcp_source)
        result = read_json(existing_mcp_target)
        assert "GitHub" in result["mcpServers"]
        assert "Snyk" in result["mcpServers"]

    def test_merge_overwrites_existing_snyk(self, write_json, snyk_mcp_source):
        target = write_json(
            "target.json",
            {
                "mcpServers": {
                    "Snyk": {"command": "old-snyk", "args": ["--old"]},
                }
            },
        )
        merge_mcp_servers(target, snyk_mcp_source)
        result = read_json(target)
        assert result["mcpServers"]["Snyk"]["command"] == "npx"
        assert result["mcpServers"]["Snyk"]["args"] == [
            "-y",
            "snyk@latest",
            "mcp",
            "-t",
            "stdio",
        ]

    def test_merge_multiple_snyk_servers(self, empty_target, multi_snyk_mcp_source):
        merge_mcp_servers(empty_target, multi_snyk_mcp_source)
        result = read_json(empty_target)
        assert "Snyk" in result["mcpServers"]
        assert "SnykCode" in result["mcpServers"]

    def test_merge_multiple_with_preexisting(self, existing_mcp_target, multi_snyk_mcp_source):
        merge_mcp_servers(existing_mcp_target, multi_snyk_mcp_source)
        result = read_json(existing_mcp_target)
        assert "GitHub" in result["mcpServers"]
        assert "Snyk" in result["mcpServers"]
        assert "SnykCode" in result["mcpServers"]

    def test_merge_is_idempotent(self, existing_mcp_target, snyk_mcp_source):
        merge_mcp_servers(existing_mcp_target, snyk_mcp_source)
        first = read_json(existing_mcp_target)
        merge_mcp_servers(existing_mcp_target, snyk_mcp_source)
        second = read_json(existing_mcp_target)
        assert first == second

    def test_merge_creates_backup(self, existing_mcp_target, snyk_mcp_source):
        merge_mcp_servers(existing_mcp_target, snyk_mcp_source)
        assert os.path.isfile(existing_mcp_target + ".bak")

    def test_merge_preserves_full_server_config(self, empty_target, snyk_mcp_source):
        merge_mcp_servers(empty_target, snyk_mcp_source)
        snyk = read_json(empty_target)["mcpServers"]["Snyk"]
        assert snyk["command"] == "npx"
        assert snyk["args"] == ["-y", "snyk@latest", "mcp", "-t", "stdio"]
        assert snyk["env"] == {"SNYK_MCP_PROFILE": "experimental"}


# ═══════════════════════════════════════════════════════════════════════════
# unmerge_cursor_hooks
# ═══════════════════════════════════════════════════════════════════════════


class TestUnmergeCursorHooks:
    def test_removes_matching_commands(self, write_json, snyk_cursor_source):
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "afterFileEdit": [
                        {"command": "eslint --fix"},
                        {"command": 'uv run "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'},
                    ],
                    "stop": [
                        {"command": 'uv run "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'},
                    ],
                },
            },
        )
        unmerge_cursor_hooks(target, snyk_cursor_source)
        result = read_json(target)
        assert len(result["hooks"]["afterFileEdit"]) == 1
        assert result["hooks"]["afterFileEdit"][0]["command"] == "eslint --fix"

    def test_removes_uvw_gui_form_using_uv_run_source(self, write_json, snyk_cursor_source):
        """Cross-launcher uninstall: target was written by the Windows installer
        with `uvw run --gui-script ...`, source still uses the canonical
        `uv run ...`. Matching is by script file name so the entry is recognized
        and removed regardless of launcher."""
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "afterFileEdit": [
                        {
                            "command": (
                                "uvw run --gui-script "
                                '"$HOME/.cursor/hooks/snyk_secure_at_inception.py"'
                            )
                        }
                    ],
                    "stop": [
                        {
                            "command": (
                                "uvw run --gui-script "
                                '"$HOME/.cursor/hooks/snyk_secure_at_inception.py"'
                            )
                        }
                    ],
                },
            },
        )
        unmerge_cursor_hooks(target, snyk_cursor_source)
        result = read_json(target)
        assert "afterFileEdit" not in result.get("hooks", {})
        assert "stop" not in result.get("hooks", {})

    def test_removes_entry_with_extra_script_argument(self, write_json, snyk_cursor_source):
        # The installed hook carries an extra script-valued argument
        # (--config setup.py). It must still be recognized as ours and removed
        # — the argument's name must not break identification / idempotency.
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "afterFileEdit": [
                        {"command": "eslint --fix"},
                        {
                            "command": (
                                'uv run "$HOME/.cursor/hooks/snyk_secure_at_inception.py" '
                                '--config "$HOME/.cursor/hooks/setup.py"'
                            )
                        },
                    ],
                },
            },
        )
        unmerge_cursor_hooks(target, snyk_cursor_source)
        result = read_json(target)
        assert [e["command"] for e in result["hooks"]["afterFileEdit"]] == ["eslint --fix"]

    def test_cleans_empty_events(self, write_json, snyk_cursor_source):
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "stop": [
                        {"command": 'uv run "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'},
                    ],
                },
            },
        )
        unmerge_cursor_hooks(target, snyk_cursor_source)
        result = read_json(target)
        assert "stop" not in result["hooks"]

    def test_noop_missing_target(self, tmp_path, snyk_cursor_source):
        target = str(tmp_path / "nope.json")
        unmerge_cursor_hooks(target, snyk_cursor_source)
        assert not os.path.exists(target)

    def test_noop_commands_absent(self, write_json, snyk_cursor_source):
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {"afterFileEdit": [{"command": "eslint --fix"}]},
            },
        )
        original = read_json(target)
        unmerge_cursor_hooks(target, snyk_cursor_source)
        result = read_json(target)
        assert result["hooks"] == original["hooks"]

    def test_removes_expanded_path_form(self, write_json, snyk_cursor_source):
        # Target carries the install-time expanded path (no $HOME). Unmerge
        # must still recognize and remove it, matching the source by its
        # expanded form (Q3 from the cross-platform refactor plan).
        home = os.path.expanduser("~")
        expanded = f'uv run "{home}/.cursor/hooks/snyk_secure_at_inception.py"'
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "afterFileEdit": [
                        {"command": "eslint --fix"},
                        {"command": expanded},
                    ],
                    "stop": [{"command": expanded}],
                },
            },
        )
        unmerge_cursor_hooks(target, snyk_cursor_source)
        result = read_json(target)
        assert len(result["hooks"]["afterFileEdit"]) == 1
        assert result["hooks"]["afterFileEdit"][0]["command"] == "eslint --fix"
        assert "stop" not in result["hooks"]

    def test_removes_mixed_separator_legacy_entry(self, write_json, monkeypatch):
        """Uninstall on Windows must clear out entries written by the legacy
        installer with mixed separators (token replaced verbatim, slashes
        from the source survived next to the home prefix's backslashes).
        Canonicalization folds separators so the entry is recognized."""
        monkeypatch.setenv("HOME", "C:\\Users\\me")
        # Source ships the new all-native form (what the new installer would
        # write after expansion via Path).
        new_native = 'uv run "C:\\Users\\me\\.cursor\\hooks\\snyk_secure_at_inception.py"'
        source = write_json(
            "source/cursor_hooks.json",
            {"version": 1, "hooks": {"afterFileEdit": [{"command": new_native}]}},
        )
        # Target was written by an older installer: mixed separators.
        legacy_mixed = 'uv run "C:\\Users\\me/.cursor/hooks/snyk_secure_at_inception.py"'
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "afterFileEdit": [
                        {"command": "eslint --fix"},
                        {"command": legacy_mixed},
                    ],
                },
            },
        )
        unmerge_cursor_hooks(target, source)
        after_edit = read_json(target)["hooks"]["afterFileEdit"]
        assert len(after_edit) == 1
        assert after_edit[0]["command"] == "eslint --fix"

    def test_removes_forward_slash_legacy_entry_when_source_is_native(
        self, write_json, monkeypatch
    ):
        """Inverse direction: target carries a forward-slash form; source ships
        the native-backslash form. Folding-on-compare matches both ways."""
        monkeypatch.setenv("HOME", "C:\\Users\\me")
        forward_slash = 'uv run "C:/Users/me/.cursor/hooks/snyk_secure_at_inception.py"'
        new_native = 'uv run "C:\\Users\\me\\.cursor\\hooks\\snyk_secure_at_inception.py"'
        source = write_json(
            "source/cursor_hooks.json",
            {"version": 1, "hooks": {"afterFileEdit": [{"command": new_native}]}},
        )
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {"afterFileEdit": [{"command": forward_slash}]},
            },
        )
        unmerge_cursor_hooks(target, source)
        # Whole event array should be cleaned up since the only entry matched.
        assert "afterFileEdit" not in read_json(target).get("hooks", {})

    def test_removes_cross_spelling_braced_vs_unbraced(self, write_json, tmp_path):
        # Source uses one spelling (e.g. ${HOME}); target was installed with
        # the other (e.g. $HOME). Normalize-on-compare must collapse both
        # to the same canonical form so the entry is still removed.
        source = write_json(
            "source/cursor_braced.json",
            {
                "hooks": {
                    "afterFileEdit": [
                        {"command": 'uv run "${HOME}/.cursor/hooks/snyk_secure_at_inception.py"'}
                    ]
                },
            },
        )
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "afterFileEdit": [
                        {"command": "eslint --fix"},
                        # Old-installer entry, unbraced spelling
                        {"command": 'uv run "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'},
                    ],
                },
            },
        )
        unmerge_cursor_hooks(target, source)
        result = read_json(target)
        assert len(result["hooks"]["afterFileEdit"]) == 1
        assert result["hooks"]["afterFileEdit"][0]["command"] == "eslint --fix"

    def test_noop_no_hooks_key(self, write_json, snyk_cursor_source):
        target = write_json("target.json", {"version": 1})
        unmerge_cursor_hooks(target, snyk_cursor_source)
        assert read_json(target) == {"version": 1}

    def test_noop_empty_source(self, write_json, existing_cursor_target):
        source = write_json("source.json", {})
        original = read_json(existing_cursor_target)
        unmerge_cursor_hooks(existing_cursor_target, source)
        assert read_json(existing_cursor_target) == original

    def test_preserves_other_events(self, write_json, snyk_cursor_source):
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "afterFileEdit": [
                        {"command": 'uv run "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'},
                    ],
                    "beforeCommand": [{"command": "echo hi"}],
                },
            },
        )
        unmerge_cursor_hooks(target, snyk_cursor_source)
        result = read_json(target)
        assert "beforeCommand" in result["hooks"]
        assert len(result["hooks"]["beforeCommand"]) == 1


# ═══════════════════════════════════════════════════════════════════════════
# unmerge_claude_settings
# ═══════════════════════════════════════════════════════════════════════════


class TestUnmergeClaudeSettings:
    def _merged_target(self, write_json, snyk_claude_source):
        """Helper: create a target with both prettier and snyk hooks merged."""
        target = write_json(
            "target.json",
            {
                "allowedTools": ["Read"],
                "hooks": {
                    "PostToolUse": [
                        {
                            "matcher": "Edit|Write",
                            "hooks": [
                                {"type": "command", "command": "prettier --write"},
                                {
                                    "type": "command",
                                    "command": 'uv run "$HOME/.claude/hooks/snyk_secure_at_inception.py"',
                                },
                            ],
                        }
                    ],
                    "Stop": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": 'uv run "$HOME/.claude/hooks/snyk_secure_at_inception.py"',
                                }
                            ]
                        }
                    ],
                },
            },
        )
        return target

    def test_removes_matching_commands(self, write_json, snyk_claude_source):
        target = self._merged_target(write_json, snyk_claude_source)
        unmerge_claude_settings(target, snyk_claude_source)
        result = read_json(target)
        group = result["hooks"]["PostToolUse"][0]
        assert len(group["hooks"]) == 1
        assert group["hooks"][0]["command"] == "prettier --write"

    def test_removes_empty_groups(self, write_json, snyk_claude_source):
        target = write_json(
            "target.json",
            {
                "hooks": {
                    "PostToolUse": [
                        {
                            "matcher": "Edit|Write",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": 'uv run "$HOME/.claude/hooks/snyk_secure_at_inception.py"',
                                }
                            ],
                        }
                    ],
                }
            },
        )
        unmerge_claude_settings(target, snyk_claude_source)
        result = read_json(target)
        # The Edit|Write group should be removed since its hooks are empty
        assert "PostToolUse" not in result["hooks"]

    def test_removes_empty_events(self, write_json, snyk_claude_source):
        target = write_json(
            "target.json",
            {
                "hooks": {
                    "Stop": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": 'uv run "$HOME/.claude/hooks/snyk_secure_at_inception.py"',
                                }
                            ]
                        }
                    ]
                }
            },
        )
        unmerge_claude_settings(target, snyk_claude_source)
        result = read_json(target)
        assert "Stop" not in result["hooks"]

    def test_noop_missing_target(self, tmp_path, snyk_claude_source):
        target = str(tmp_path / "nope.json")
        unmerge_claude_settings(target, snyk_claude_source)
        assert not os.path.exists(target)

    def test_noop_commands_absent(self, write_json, snyk_claude_source):
        target = write_json(
            "target.json",
            {
                "hooks": {
                    "PostToolUse": [
                        {
                            "matcher": "Edit|Write",
                            "hooks": [{"type": "command", "command": "prettier --write"}],
                        }
                    ]
                }
            },
        )
        read_json(target)
        unmerge_claude_settings(target, snyk_claude_source)
        # prettier should still be there
        result = read_json(target)
        assert len(result["hooks"]["PostToolUse"][0]["hooks"]) == 1

    def test_preserves_non_hooks_settings(self, write_json, snyk_claude_source):
        target = self._merged_target(write_json, snyk_claude_source)
        unmerge_claude_settings(target, snyk_claude_source)
        result = read_json(target)
        assert result["allowedTools"] == ["Read"]

    def test_handles_no_matcher_group(self, write_json, snyk_claude_source):
        """Stop event has groups with no matcher — unmerge should match on None."""
        target = write_json(
            "target.json",
            {
                "hooks": {
                    "Stop": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": 'uv run "$HOME/.claude/hooks/snyk_secure_at_inception.py"',
                                },
                                {"type": "command", "command": "echo done"},
                            ]
                        }
                    ]
                }
            },
        )
        unmerge_claude_settings(target, snyk_claude_source)
        result = read_json(target)
        group = result["hooks"]["Stop"][0]
        assert len(group["hooks"]) == 1
        assert group["hooks"][0]["command"] == "echo done"

    def test_noop_empty_source(self, write_json, existing_claude_target):
        source = write_json("source.json", {})
        original = read_json(existing_claude_target)
        unmerge_claude_settings(existing_claude_target, source)
        assert read_json(existing_claude_target) == original

    def test_removes_expanded_path_form(self, write_json, snyk_claude_source):
        # Target carries the install-time expanded path; unmerge must still
        # recognize it via the dual-form match (Q3).
        home = os.path.expanduser("~")
        expanded = f'uv run "{home}/.claude/hooks/snyk_secure_at_inception.py"'
        target = write_json(
            "target.json",
            {
                "hooks": {
                    "PostToolUse": [
                        {
                            "matcher": "Edit|Write",
                            "hooks": [
                                {"type": "command", "command": "prettier --write"},
                                {"type": "command", "command": expanded},
                            ],
                        }
                    ],
                    "Stop": [{"hooks": [{"type": "command", "command": expanded}]}],
                },
            },
        )
        unmerge_claude_settings(target, snyk_claude_source)
        result = read_json(target)
        # Snyk entries removed; user's prettier hook preserved.
        group = result["hooks"]["PostToolUse"][0]
        assert len(group["hooks"]) == 1
        assert group["hooks"][0]["command"] == "prettier --write"
        assert "Stop" not in result["hooks"]

    def test_removes_mixed_separator_legacy_entry(self, write_json, monkeypatch):
        """Uninstall on Windows must clean up legacy mixed-separator entries
        (token replaced verbatim by an older installer)."""
        monkeypatch.setenv("HOME", "C:\\Users\\me")
        legacy_mixed = 'uv run "C:\\Users\\me/.claude/hooks/snyk_secure_at_inception.py"'
        new_native = 'uv run "C:\\Users\\me\\.claude\\hooks\\snyk_secure_at_inception.py"'
        source = write_json(
            "source/claude_settings.json",
            {
                "hooks": {
                    "PostToolUse": [
                        {
                            "matcher": "Edit|Write",
                            "hooks": [{"type": "command", "command": new_native}],
                        }
                    ],
                },
            },
        )
        target = write_json(
            "target.json",
            {
                "hooks": {
                    "PostToolUse": [
                        {
                            "matcher": "Edit|Write",
                            "hooks": [
                                {"type": "command", "command": "prettier --write"},
                                {"type": "command", "command": legacy_mixed},
                            ],
                        }
                    ],
                },
            },
        )
        unmerge_claude_settings(target, source)
        group = read_json(target)["hooks"]["PostToolUse"][0]
        assert len(group["hooks"]) == 1
        assert group["hooks"][0]["command"] == "prettier --write"


# ═══════════════════════════════════════════════════════════════════════════
# unmerge_mcp_servers
# ═══════════════════════════════════════════════════════════════════════════


class TestUnmergeMcpServers:
    def test_removes_matching_servers(self, write_json, snyk_mcp_source):
        target = write_json(
            "target.json",
            {
                "mcpServers": {
                    "GitHub": {"command": "gh", "args": ["mcp"]},
                    "Snyk": {"command": "npx", "args": ["snyk@latest"]},
                }
            },
        )
        unmerge_mcp_servers(target, snyk_mcp_source)
        result = read_json(target)
        assert "GitHub" in result["mcpServers"]
        assert "Snyk" not in result["mcpServers"]

    def test_removes_multiple_snyk_servers(self, write_json, multi_snyk_mcp_source):
        target = write_json(
            "target.json",
            {
                "mcpServers": {
                    "GitHub": {"command": "gh"},
                    "Snyk": {"command": "npx"},
                    "SnykCode": {"command": "npx"},
                }
            },
        )
        unmerge_mcp_servers(target, multi_snyk_mcp_source)
        result = read_json(target)
        assert "GitHub" in result["mcpServers"]
        assert "Snyk" not in result["mcpServers"]
        assert "SnykCode" not in result["mcpServers"]

    def test_noop_missing_target(self, tmp_path, snyk_mcp_source):
        target = str(tmp_path / "nope.json")
        unmerge_mcp_servers(target, snyk_mcp_source)
        assert not os.path.exists(target)

    def test_noop_server_absent(self, existing_mcp_target, snyk_mcp_source):
        original = read_json(existing_mcp_target)
        unmerge_mcp_servers(existing_mcp_target, snyk_mcp_source)
        result = read_json(existing_mcp_target)
        assert result == original

    def test_noop_no_mcpservers_key(self, write_json, snyk_mcp_source):
        target = write_json("target.json", {"other": "data"})
        unmerge_mcp_servers(target, snyk_mcp_source)
        assert read_json(target) == {"other": "data"}

    def test_preserves_non_snyk_servers(self, write_json, multi_snyk_mcp_source):
        target = write_json(
            "target.json",
            {
                "mcpServers": {
                    "GitHub": {"command": "gh"},
                    "Copilot": {"command": "copilot-mcp"},
                    "Snyk": {"command": "npx"},
                    "SnykCode": {"command": "npx"},
                }
            },
        )
        unmerge_mcp_servers(target, multi_snyk_mcp_source)
        result = read_json(target)
        assert set(result["mcpServers"].keys()) == {"GitHub", "Copilot"}

    def test_noop_empty_source(self, write_json, existing_mcp_target):
        source = write_json("source.json", {})
        original = read_json(existing_mcp_target)
        unmerge_mcp_servers(existing_mcp_target, source)
        assert read_json(existing_mcp_target) == original


# ═══════════════════════════════════════════════════════════════════════════
# merge_gemini_settings / unmerge / verify
# ═══════════════════════════════════════════════════════════════════════════


SNYK_GEMINI_SETTINGS = {
    "hooks": {
        "AfterTool": [
            {
                "matcher": "write_file|replace",
                "hooks": [
                    {
                        "name": "snyk_secure_at_inception_after_tool_edit",
                        "type": "command",
                        "command": 'python3 "$HOME/.gemini/hooks/snyk_secure_at_inception.py"',
                        "description": "Scans code changes for vulnerabilities using Snyk",
                    }
                ],
            }
        ],
        "AfterAgent": [
            {
                "matcher": "*",
                "hooks": [
                    {
                        "name": "snyk_secure_at_inception_after_agent",
                        "type": "command",
                        "command": 'python3 "$HOME/.gemini/hooks/snyk_secure_at_inception.py"',
                        "description": "Evaluate Snyk scan results before agent completes",
                    }
                ],
            }
        ],
    }
}


class TestGeminiSettingsStrategies:
    @pytest.fixture
    def snyk_gemini_source(self, write_json):
        return write_json("source/gemini_settings.json", SNYK_GEMINI_SETTINGS)

    def test_merge_into_empty_target(self, empty_target, snyk_gemini_source):
        merge_gemini_settings(empty_target, snyk_gemini_source)
        result = read_json(empty_target)
        assert "AfterTool" in result["hooks"]
        assert "AfterAgent" in result["hooks"]

    def test_merge_preserves_unrelated_top_level_keys(self, write_json, snyk_gemini_source):
        target = write_json("target.json", {"theme": "dark", "hooks": {}})
        merge_gemini_settings(target, snyk_gemini_source)
        result = read_json(target)
        assert result["theme"] == "dark"
        assert "AfterTool" in result["hooks"]

    def test_merge_is_idempotent(self, empty_target, snyk_gemini_source):
        merge_gemini_settings(empty_target, snyk_gemini_source)
        merge_gemini_settings(empty_target, snyk_gemini_source)
        result = read_json(empty_target)
        for groups in result["hooks"].values():
            for group in groups:
                commands = [h["command"] for h in group["hooks"]]
                assert len(commands) == len(set(commands))

    def test_unmerge_removes_snyk_hooks(self, empty_target, snyk_gemini_source):
        merge_gemini_settings(empty_target, snyk_gemini_source)
        unmerge_gemini_settings(empty_target, snyk_gemini_source)
        result = read_json(empty_target)
        assert "AfterTool" not in result.get("hooks", {})
        assert "AfterAgent" not in result.get("hooks", {})

    def test_verify_passes_after_merge(self, empty_target, snyk_gemini_source):
        merge_gemini_settings(empty_target, snyk_gemini_source)
        # Should not raise
        verify_gemini_settings(empty_target, snyk_gemini_source)

    def test_verify_fails_when_missing(self, empty_target, snyk_gemini_source):
        with pytest.raises(SystemExit):
            verify_gemini_settings(empty_target, snyk_gemini_source)

    def test_strategies_registered(self):
        assert "merge_gemini_settings" in STRATEGIES
        assert "unmerge_gemini_settings" in STRATEGIES
        assert "verify_gemini_settings" in STRATEGIES


# ═══════════════════════════════════════════════════════════════════════════
# main() CLI dispatch
# ═══════════════════════════════════════════════════════════════════════════


class TestMain:
    def test_dispatches_correctly(self, monkeypatch, empty_target, snyk_mcp_source):
        monkeypatch.setattr(
            "sys.argv",
            ["merge_json.py", "merge_mcp_servers", empty_target, snyk_mcp_source],
        )
        main()
        result = read_json(empty_target)
        assert "Snyk" in result["mcpServers"]

    def test_exits_wrong_argc(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["merge_json.py", "only_one_arg"])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    def test_exits_unknown_strategy(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "sys.argv",
            ["merge_json.py", "bogus", str(tmp_path / "t"), str(tmp_path / "s")],
        )
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1


# ═══════════════════════════════════════════════════════════════════════════
# verify_claude_settings
# ═══════════════════════════════════════════════════════════════════════════


class TestVerifyClaudeSettings:
    def test_passes_when_hooks_present(self, write_json, snyk_claude_source):
        """Verify succeeds when all expected hooks are in target."""
        target = write_json("target.json", {"model": "opus[1m]"})
        merge_claude_settings(target, snyk_claude_source)
        # Should not raise SystemExit
        verify_claude_settings(target, snyk_claude_source)

    def test_fails_when_hooks_missing(self, write_json, snyk_claude_source):
        """Verify fails when target has no hooks at all."""
        target = write_json("target.json", {"model": "opus[1m]"})
        with pytest.raises(SystemExit) as exc_info:
            verify_claude_settings(target, snyk_claude_source)
        assert exc_info.value.code == 1

    def test_fails_when_event_missing(self, write_json, snyk_claude_source):
        """Verify fails when target has PostToolUse but not Stop."""
        target = write_json(
            "target.json",
            {
                "hooks": {
                    "PostToolUse": [
                        {
                            "matcher": "Edit|Write",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": 'uv run "$HOME/.claude/hooks/snyk_secure_at_inception.py"',
                                }
                            ],
                        }
                    ]
                }
            },
        )
        with pytest.raises(SystemExit) as exc_info:
            verify_claude_settings(target, snyk_claude_source)
        assert exc_info.value.code == 1

    def test_fails_when_command_missing(self, write_json, snyk_claude_source):
        """Verify fails when matcher group exists but command is different."""
        target = write_json(
            "target.json",
            {
                "hooks": {
                    "PostToolUse": [
                        {
                            "matcher": "Edit|Write",
                            "hooks": [{"type": "command", "command": "prettier --write"}],
                        }
                    ],
                    "Stop": [{"hooks": [{"type": "command", "command": "echo done"}]}],
                }
            },
        )
        with pytest.raises(SystemExit) as exc_info:
            verify_claude_settings(target, snyk_claude_source)
        assert exc_info.value.code == 1

    def test_passes_with_extra_hooks(self, write_json, snyk_claude_source):
        """Verify passes when target has expected hooks plus extras."""
        target = write_json("target.json", {"model": "opus[1m]"})
        merge_claude_settings(target, snyk_claude_source)
        # Add extra hooks
        data = read_json(target)
        data["hooks"]["PostToolUse"][0]["hooks"].append(
            {"type": "command", "command": "prettier --write"}
        )
        _write_json(target, data)
        verify_claude_settings(target, snyk_claude_source)

    def test_fails_on_missing_file(self, tmp_path, snyk_claude_source):
        """Verify fails when target file doesn't exist."""
        target = str(tmp_path / "nope.json")
        with pytest.raises(SystemExit) as exc_info:
            verify_claude_settings(target, snyk_claude_source)
        assert exc_info.value.code == 1


# ═══════════════════════════════════════════════════════════════════════════
# verify_cursor_hooks
# ═══════════════════════════════════════════════════════════════════════════


class TestVerifyCursorHooks:
    def test_passes_when_hooks_present(self, write_json, snyk_cursor_source):
        target = write_json("target.json", {})
        merge_cursor_hooks(target, snyk_cursor_source)
        verify_cursor_hooks(target, snyk_cursor_source)

    def test_fails_when_hooks_missing(self, write_json, snyk_cursor_source):
        target = write_json("target.json", {"version": 1, "hooks": {}})
        with pytest.raises(SystemExit) as exc_info:
            verify_cursor_hooks(target, snyk_cursor_source)
        assert exc_info.value.code == 1

    def test_fails_on_missing_file(self, tmp_path, snyk_cursor_source):
        target = str(tmp_path / "nope.json")
        with pytest.raises(SystemExit) as exc_info:
            verify_cursor_hooks(target, snyk_cursor_source)
        assert exc_info.value.code == 1

    def test_passes_when_target_uses_raw_home_and_source_is_expanded(self, write_json):
        """Legacy install wrote $HOME-form command; current source ships the
        install-time-expanded absolute path. Verification must treat them as
        equivalent (no false-negative missing-hook report)."""
        home = os.path.expanduser("~")
        source = write_json(
            "source/cursor_hooks.json",
            {
                "version": 1,
                "hooks": {
                    "afterFileEdit": [
                        {"command": f'uv run "{home}/.cursor/hooks/snyk_secure_at_inception.py"'}
                    ],
                    "stop": [
                        {"command": f'uv run "{home}/.cursor/hooks/snyk_secure_at_inception.py"'}
                    ],
                },
            },
        )
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "afterFileEdit": [
                        {"command": 'uv run "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'}
                    ],
                    "stop": [
                        {"command": 'uv run "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'}
                    ],
                },
            },
        )
        verify_cursor_hooks(target, source)  # must not SystemExit


# ═══════════════════════════════════════════════════════════════════════════
# verify_mcp_servers
# ═══════════════════════════════════════════════════════════════════════════


class TestVerifyMcpServers:
    def test_passes_when_servers_present(self, write_json, snyk_mcp_source):
        target = write_json("target.json", {})
        merge_mcp_servers(target, snyk_mcp_source)
        verify_mcp_servers(target, snyk_mcp_source)

    def test_fails_when_servers_missing(self, write_json, snyk_mcp_source):
        target = write_json("target.json", {"mcpServers": {}})
        with pytest.raises(SystemExit) as exc_info:
            verify_mcp_servers(target, snyk_mcp_source)
        assert exc_info.value.code == 1

    def test_fails_on_missing_file(self, tmp_path, snyk_mcp_source):
        target = str(tmp_path / "nope.json")
        with pytest.raises(SystemExit) as exc_info:
            verify_mcp_servers(target, snyk_mcp_source)
        assert exc_info.value.code == 1


# ═══════════════════════════════════════════════════════════════════════════
# Codex TOML config: merge / unmerge / verify
# ═══════════════════════════════════════════════════════════════════════════


def _read_toml(path):
    """Helper: read a TOML file into a dict (uses the same reader as merge_json)."""
    return _load_toml(path)


class TestLoadToml:
    def test_returns_dict_from_valid_file(self, tmp_path):
        p = tmp_path / "data.toml"
        p.write_text('key = "value"\n')
        assert _load_toml(str(p)) == {"key": "value"}

    def test_returns_empty_dict_for_missing_file(self, tmp_path):
        assert _load_toml(str(tmp_path / "nope.toml")) == {}


class TestWriteToml:
    def test_writes_round_trippable_content(self, tmp_path):
        p = str(tmp_path / "out.toml")
        _write_toml(p, {"a": 1, "nested": {"b": True}})
        assert _load_toml(p) == {"a": 1, "nested": {"b": True}}

    def test_creates_parent_directories(self, tmp_path):
        p = str(tmp_path / "a" / "b" / "c" / "out.toml")
        _write_toml(p, {"x": True})
        assert os.path.exists(p)


class TestMergeCodexConfig:
    """merge_codex_config handles features, hooks, and mcp_servers concerns."""

    def test_creates_target_when_missing(self, tmp_path, snyk_codex_hooks_source):
        target = str(tmp_path / "config.toml")
        merge_codex_config(target, snyk_codex_hooks_source)
        data = _read_toml(target)
        assert data["features"]["hooks"] is True
        assert "SessionStart" in data["hooks"]
        assert "PostToolUse" in data["hooks"]
        assert "Stop" in data["hooks"]

    def test_preserves_existing_user_keys(self, existing_codex_target, snyk_codex_hooks_source):
        merge_codex_config(existing_codex_target, snyk_codex_hooks_source)
        data = _read_toml(existing_codex_target)
        # User's top-level scalar preserved
        assert data["model"] == "gpt-5"
        # User's other [features] flag preserved alongside ours
        assert data["features"]["my_other_flag"] is True
        assert data["features"]["hooks"] is True
        # User's MCP server preserved
        assert data["mcp_servers"]["GitHub"]["command"] == "gh"

    def test_creates_backup_file(self, existing_codex_target, snyk_codex_hooks_source):
        merge_codex_config(existing_codex_target, snyk_codex_hooks_source)
        assert os.path.exists(existing_codex_target + ".bak")

    def test_merges_mcp_servers_alongside_hooks(
        self, existing_codex_target, snyk_codex_hooks_source, snyk_codex_mcp_source
    ):
        merge_codex_config(existing_codex_target, snyk_codex_hooks_source)
        merge_codex_config(existing_codex_target, snyk_codex_mcp_source)
        data = _read_toml(existing_codex_target)
        assert data["mcp_servers"]["Snyk"]["command"] == "npx"
        assert data["mcp_servers"]["GitHub"]["command"] == "gh"
        assert data["features"]["hooks"] is True
        assert "PostToolUse" in data["hooks"]

    def test_idempotent_dedupes_by_command(self, tmp_path, snyk_codex_hooks_source):
        target = str(tmp_path / "config.toml")
        merge_codex_config(target, snyk_codex_hooks_source)
        merge_codex_config(target, snyk_codex_hooks_source)
        data = _read_toml(target)
        # Each event has exactly one matcher group with exactly one hook entry
        for event in ("SessionStart", "PostToolUse", "Stop"):
            assert len(data["hooks"][event]) == 1
            assert len(data["hooks"][event][0]["hooks"]) == 1

    def test_appends_when_existing_hook_has_different_matcher(
        self, write_toml, snyk_codex_hooks_source
    ):
        # Pre-existing PostToolUse with a different matcher must coexist with ours.
        target = write_toml(
            "config.toml",
            """
[[hooks.PostToolUse]]
matcher = "^(eslint|prettier)$"
[[hooks.PostToolUse.hooks]]
type = "command"
command = "echo lint"
""",
        )
        merge_codex_config(target, snyk_codex_hooks_source)
        data = _read_toml(target)
        matchers = sorted(g.get("matcher", "") for g in data["hooks"]["PostToolUse"])
        assert matchers == ["^(apply_patch|Edit|Write)$", "^(eslint|prettier)$"]

    def test_dedupes_within_same_matcher_group(self, write_toml, snyk_codex_hooks_source):
        # Existing PostToolUse with the SAME matcher and a different command:
        # ours appends without removing theirs.
        target = write_toml(
            "config.toml",
            """
[[hooks.PostToolUse]]
matcher = "^(apply_patch|Edit|Write)$"
[[hooks.PostToolUse.hooks]]
type = "command"
command = "echo other-tool"
""",
        )
        merge_codex_config(target, snyk_codex_hooks_source)
        data = _read_toml(target)
        groups = data["hooks"]["PostToolUse"]
        assert len(groups) == 1  # Same matcher → single group
        commands = [h["command"] for h in groups[0]["hooks"]]
        assert "echo other-tool" in commands
        assert any("snyk_secure_at_inception" in c for c in commands)

    def test_invalid_toml_raises_value_error(self, tmp_path, snyk_codex_hooks_source):
        target = tmp_path / "bad.toml"
        target.write_text("this is not [valid toml = \n")
        with pytest.raises(ValueError, match="Invalid TOML"):
            merge_codex_config(str(target), snyk_codex_hooks_source)


class TestUnmergeCodexConfig:
    """unmerge_codex_config removes Snyk entries while preserving user content."""

    def test_round_trip_preserves_user_content(
        self, existing_codex_target, snyk_codex_hooks_source, snyk_codex_mcp_source
    ):
        merge_codex_config(existing_codex_target, snyk_codex_hooks_source)
        merge_codex_config(existing_codex_target, snyk_codex_mcp_source)
        unmerge_codex_config(existing_codex_target, snyk_codex_mcp_source)
        unmerge_codex_config(existing_codex_target, snyk_codex_hooks_source)
        data = _read_toml(existing_codex_target)
        assert data == {
            "model": "gpt-5",
            "features": {"my_other_flag": True},
            "mcp_servers": {"GitHub": {"command": "gh", "args": ["mcp"]}},
        }

    def test_removes_target_file_when_only_snyk_entries_present(
        self, tmp_path, snyk_codex_hooks_source
    ):
        target = str(tmp_path / "config.toml")
        merge_codex_config(target, snyk_codex_hooks_source)
        unmerge_codex_config(target, snyk_codex_hooks_source)
        # Empty result file is removed entirely (not left as a stub)
        assert not os.path.exists(target)

    def test_idempotent_when_already_unmerged(self, existing_codex_target, snyk_codex_hooks_source):
        unmerge_codex_config(existing_codex_target, snyk_codex_hooks_source)
        unmerge_codex_config(existing_codex_target, snyk_codex_hooks_source)
        # User content untouched after a no-op double unmerge
        data = _read_toml(existing_codex_target)
        assert data["model"] == "gpt-5"

    def test_noop_for_missing_target(self, tmp_path, snyk_codex_hooks_source):
        target = str(tmp_path / "absent.toml")
        unmerge_codex_config(target, snyk_codex_hooks_source)
        assert not os.path.exists(target)

    def test_preserves_hook_entries_we_did_not_install(
        self, existing_codex_target, snyk_codex_hooks_source
    ):
        merge_codex_config(existing_codex_target, snyk_codex_hooks_source)
        # Manually add an unrelated hook under the same matcher
        data = _read_toml(existing_codex_target)
        data["hooks"]["PostToolUse"][0]["hooks"].append(
            {"type": "command", "command": "echo my-own-hook"}
        )
        _write_toml(existing_codex_target, data)
        # Unmerge: ours should be removed, the user's preserved
        unmerge_codex_config(existing_codex_target, snyk_codex_hooks_source)
        data = _read_toml(existing_codex_target)
        commands = [h["command"] for h in data["hooks"]["PostToolUse"][0]["hooks"]]
        assert commands == ["echo my-own-hook"]

    def test_removes_expanded_path_form(self, write_toml, snyk_codex_hooks_source):
        # Target carries the install-time expanded path; dual-form match (Q3).
        home = os.path.expanduser("~")
        expanded = f'uv run "{home}/.codex/hooks/snyk_secure_at_inception.py"'
        target = write_toml(
            "config.toml",
            f"""
[features]
hooks = true

[[hooks.SessionStart]]
[[hooks.SessionStart.hooks]]
type = "command"
command = '{expanded}'

[[hooks.PostToolUse]]
matcher = "^(apply_patch|Edit|Write)$"
[[hooks.PostToolUse.hooks]]
type = "command"
command = '{expanded}'

[[hooks.Stop]]
[[hooks.Stop.hooks]]
type = "command"
command = '{expanded}'
""",
        )
        unmerge_codex_config(target, snyk_codex_hooks_source)
        # All snyk entries gone → empty hooks → file removed.
        assert not os.path.exists(target)


class TestVerifyCodexConfig:
    """verify_codex_config exits 1 on missing entries; returns silently on success."""

    def test_passes_after_merge(self, existing_codex_target, snyk_codex_hooks_source):
        merge_codex_config(existing_codex_target, snyk_codex_hooks_source)
        verify_codex_config(existing_codex_target, snyk_codex_hooks_source)  # no SystemExit

    def test_fails_when_features_flag_missing(self, tmp_path, snyk_codex_hooks_source):
        target = str(tmp_path / "config.toml")
        with pytest.raises(SystemExit) as exc_info:
            verify_codex_config(target, snyk_codex_hooks_source)
        assert exc_info.value.code == 1

    def test_fails_when_hook_event_missing(self, write_toml, snyk_codex_hooks_source, capsys):
        target = write_toml("config.toml", "[features]\nhooks = true\n")
        with pytest.raises(SystemExit):
            verify_codex_config(target, snyk_codex_hooks_source)
        err = capsys.readouterr().err
        assert "SessionStart" in err

    def test_fails_when_mcp_server_missing(self, tmp_path, snyk_codex_mcp_source):
        target = str(tmp_path / "config.toml")
        with pytest.raises(SystemExit) as exc_info:
            verify_codex_config(target, snyk_codex_mcp_source)
        assert exc_info.value.code == 1

    def test_fails_when_hook_command_missing(self, write_toml, snyk_codex_hooks_source, capsys):
        # Same matcher group exists but with the wrong command.
        target = write_toml(
            "config.toml",
            """
[features]
hooks = true

[[hooks.SessionStart]]
[[hooks.SessionStart.hooks]]
type = "command"
command = "echo wrong"

[[hooks.PostToolUse]]
matcher = "^(apply_patch|Edit|Write)$"
[[hooks.PostToolUse.hooks]]
type = "command"
command = "echo wrong"

[[hooks.Stop]]
[[hooks.Stop.hooks]]
type = "command"
command = "echo wrong"
""",
        )
        with pytest.raises(SystemExit):
            verify_codex_config(target, snyk_codex_hooks_source)
        err = capsys.readouterr().err
        assert "snyk_secure_at_inception" in err


# ═══════════════════════════════════════════════════════════════════════════
# Copilot CLI hooks strategies (hooks.json keyed by `bash`, not `command`)
# ═══════════════════════════════════════════════════════════════════════════


SNYK_COPILOT_BASH = 'uv run "$HOME/.copilot/hooks/snyk_secure_at_inception.py" agentStop'


class TestMergeCopilotCliHooks:
    def test_merge_into_empty_target(self, empty_target, snyk_copilot_source):
        merge_copilot_cli_hooks(empty_target, snyk_copilot_source)
        result = read_json(empty_target)
        assert result["version"] == 1
        assert len(result["hooks"]["sessionStart"]) == 1
        assert len(result["hooks"]["postToolUse"]) == 1
        assert len(result["hooks"]["agentStop"]) == 1

    def test_merge_preserves_user_hooks(self, existing_copilot_target, snyk_copilot_source):
        merge_copilot_cli_hooks(existing_copilot_target, snyk_copilot_source)
        result = read_json(existing_copilot_target)
        bashes = [e["bash"] for e in result["hooks"]["postToolUse"]]
        assert "echo user-hook" in bashes
        assert any("snyk_secure_at_inception" in b for b in bashes)

    def test_merge_is_idempotent(self, empty_target, snyk_copilot_source):
        merge_copilot_cli_hooks(empty_target, snyk_copilot_source)
        merge_copilot_cli_hooks(empty_target, snyk_copilot_source)
        result = read_json(empty_target)
        for event in ("sessionStart", "postToolUse", "agentStop"):
            assert len(result["hooks"][event]) == 1, event

    def test_merge_dedupes_by_bash_field(self, write_json, snyk_copilot_source):
        # Same bash string already present with extra fields — should not duplicate.
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "agentStop": [{"type": "command", "bash": SNYK_COPILOT_BASH, "timeoutSec": 999}]
                },
            },
        )
        merge_copilot_cli_hooks(target, snyk_copilot_source)
        assert len(read_json(target)["hooks"]["agentStop"]) == 1

    def test_merge_dedupes_across_home_var_spellings(self, write_json, snyk_copilot_source):
        # Source uses $HOME; target was previously written with %USERPROFILE%
        # (or an expanded absolute path). After canonicalization both refer
        # to the same hook, so merge must not double-register.
        home = os.path.expanduser("~")
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "sessionStart": [
                        {
                            "type": "command",
                            "bash": (
                                'uv run "%USERPROFILE%/.copilot/hooks/'
                                'snyk_secure_at_inception.py" sessionStart'
                            ),
                        }
                    ],
                    "postToolUse": [
                        {
                            "type": "command",
                            "bash": (
                                f'uv run "{home}/.copilot/hooks/'
                                'snyk_secure_at_inception.py" postToolUse'
                            ),
                        }
                    ],
                },
            },
        )
        merge_copilot_cli_hooks(target, snyk_copilot_source)
        result = read_json(target)
        # Each event still has exactly one entry — the existing stale-spelling
        # one is preserved, no duplicate is appended.
        assert len(result["hooks"]["sessionStart"]) == 1
        assert len(result["hooks"]["postToolUse"]) == 1

    def test_merge_creates_backup(self, existing_copilot_target, snyk_copilot_source):
        merge_copilot_cli_hooks(existing_copilot_target, snyk_copilot_source)
        assert os.path.isfile(existing_copilot_target + ".bak")

    def test_merge_no_backup_for_new_target(self, empty_target, snyk_copilot_source):
        merge_copilot_cli_hooks(empty_target, snyk_copilot_source)
        assert not os.path.isfile(empty_target + ".bak")

    def test_merge_fails_on_invalid_json(self, tmp_path, snyk_copilot_source):
        target = tmp_path / "target.json"
        target.write_text("{ invalid }")
        with pytest.raises(ValueError, match="Invalid JSON in file"):
            merge_copilot_cli_hooks(str(target), snyk_copilot_source)


class TestUnmergeCopilotCliHooks:
    def test_removes_snyk_entries(self, write_json, snyk_copilot_source):
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "postToolUse": [
                        {"type": "command", "bash": "echo user-hook"},
                        {
                            "type": "command",
                            "bash": (
                                'uv run "$HOME/.copilot/hooks/snyk_secure_at_inception.py" '
                                "postToolUse"
                            ),
                        },
                    ],
                    "agentStop": [{"type": "command", "bash": SNYK_COPILOT_BASH}],
                },
            },
        )
        unmerge_copilot_cli_hooks(target, snyk_copilot_source)
        result = read_json(target)
        assert len(result["hooks"]["postToolUse"]) == 1
        assert result["hooks"]["postToolUse"][0]["bash"] == "echo user-hook"
        assert "agentStop" not in result["hooks"]

    def test_unmerge_is_idempotent(self, write_json, snyk_copilot_source):
        target = write_json("target.json", {"version": 1, "hooks": {}})
        unmerge_copilot_cli_hooks(target, snyk_copilot_source)
        unmerge_copilot_cli_hooks(target, snyk_copilot_source)
        assert read_json(target) == {"version": 1, "hooks": {}}

    def test_noop_missing_target(self, tmp_path, snyk_copilot_source):
        target = str(tmp_path / "nope.json")
        unmerge_copilot_cli_hooks(target, snyk_copilot_source)
        assert not os.path.exists(target)

    def test_removes_cross_spelling_userprofile(self, write_json, snyk_copilot_source):
        # Source uses $HOME; target was installed with %USERPROFILE% (e.g. a
        # prior Windows install). Normalize-on-compare must collapse both to
        # the same canonical form so the stale entry is removed.
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "agentStop": [
                        {"type": "command", "bash": "echo user-hook"},
                        {
                            "type": "command",
                            "bash": (
                                'uv run "%USERPROFILE%/.copilot/hooks/'
                                'snyk_secure_at_inception.py" agentStop'
                            ),
                        },
                    ],
                },
            },
        )
        unmerge_copilot_cli_hooks(target, snyk_copilot_source)
        result = read_json(target)
        assert len(result["hooks"]["agentStop"]) == 1
        assert result["hooks"]["agentStop"][0]["bash"] == "echo user-hook"

    def test_removes_absolute_path_written_by_newer_installer(
        self, write_json, snyk_copilot_source
    ):
        # Newer installer expands $HOME to an absolute path at install time.
        # An old uninstaller (source still uses $HOME) must still remove it.
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "agentStop": [
                        {
                            "type": "command",
                            "bash": (
                                f'uv run "{os.path.expanduser("~")}/.copilot/hooks/'
                                'snyk_secure_at_inception.py" agentStop'
                            ),
                        },
                    ],
                },
            },
        )
        unmerge_copilot_cli_hooks(target, snyk_copilot_source)
        result = read_json(target)
        assert "agentStop" not in result["hooks"]


class TestVerifyCopilotCliHooks:
    def test_passes_after_merge(self, empty_target, snyk_copilot_source):
        merge_copilot_cli_hooks(empty_target, snyk_copilot_source)
        verify_copilot_cli_hooks(empty_target, snyk_copilot_source)

    def test_fails_when_event_missing(self, write_json, snyk_copilot_source):
        target = write_json("target.json", {"version": 1, "hooks": {}})
        with pytest.raises(SystemExit) as exc_info:
            verify_copilot_cli_hooks(target, snyk_copilot_source)
        assert exc_info.value.code == 1

    def test_fails_when_bash_entry_missing(self, write_json, snyk_copilot_source, capsys):
        # Has the events but with foreign bash commands only.
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "sessionStart": [{"type": "command", "bash": "echo other"}],
                    "postToolUse": [{"type": "command", "bash": "echo other"}],
                    "agentStop": [{"type": "command", "bash": "echo other"}],
                },
            },
        )
        with pytest.raises(SystemExit):
            verify_copilot_cli_hooks(target, snyk_copilot_source)
        err = capsys.readouterr().err
        assert "snyk_secure_at_inception" in err

    def test_strategies_registered(self):
        assert "merge_copilot_cli_hooks" in STRATEGIES
        assert "unmerge_copilot_cli_hooks" in STRATEGIES
        assert "verify_copilot_cli_hooks" in STRATEGIES

    def test_passes_when_target_uses_different_home_spelling(self, write_json, snyk_copilot_source):
        # Source ships with $HOME, target was installed by a newer installer
        # that expanded $HOME to the absolute path. verify must canonicalize
        # both sides and report no missing hooks.
        home = os.path.expanduser("~")
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "sessionStart": [
                        {
                            "type": "command",
                            "bash": (
                                f'uv run "{home}/.copilot/hooks/'
                                'snyk_secure_at_inception.py" sessionStart'
                            ),
                        }
                    ],
                    "postToolUse": [
                        {
                            "type": "command",
                            "bash": (
                                f'uv run "{home}/.copilot/hooks/'
                                'snyk_secure_at_inception.py" postToolUse'
                            ),
                        }
                    ],
                    "agentStop": [
                        {
                            "type": "command",
                            "bash": (
                                f'uv run "{home}/.copilot/hooks/'
                                'snyk_secure_at_inception.py" agentStop'
                            ),
                        }
                    ],
                },
            },
        )
        # Should not raise SystemExit
        verify_copilot_cli_hooks(target, snyk_copilot_source)
