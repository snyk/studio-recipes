"""Unit tests for installer/lib/merge_json.py."""

import json
import os

import pytest

from merge_json import (
    _backup,
    _is_snyk_command,
    _load_json,
    _write_json,
    main,
    merge_claude_settings,
    merge_cursor_hooks,
    merge_mcp_servers,
    unmerge_claude_settings,
    unmerge_cursor_hooks,
    unmerge_mcp_servers,
    verify_claude_settings,
    verify_cursor_hooks,
    verify_mcp_servers,
)

from helpers import read_json


# ═══════════════════════════════════════════════════════════════════════════
# Helper functions
# ═══════════════════════════════════════════════════════════════════════════


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

    def test_merge_preserves_existing_hooks(
        self, existing_cursor_target, snyk_cursor_source
    ):
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
                            "command": 'python3 "$HOME/.cursor/hooks/snyk_secure_at_inception.py"',
                            "extra_field": "different",
                        }
                    ]
                },
            },
        )
        merge_cursor_hooks(target, snyk_cursor_source)
        assert len(read_json(target)["hooks"]["afterFileEdit"]) == 1

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

    def test_merge_into_matching_group(
        self, existing_claude_target, snyk_claude_source
    ):
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

    def test_merge_preserves_non_hooks_settings(
        self, existing_claude_target, snyk_claude_source
    ):
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

    def test_merge_preserves_non_snyk_servers(
        self, existing_mcp_target, snyk_mcp_source
    ):
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

    def test_merge_multiple_with_preexisting(
        self, existing_mcp_target, multi_snyk_mcp_source
    ):
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
                        {
                            "command": 'python3 "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'
                        },
                    ],
                    "stop": [
                        {
                            "command": 'python3 "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'
                        },
                    ],
                },
            },
        )
        unmerge_cursor_hooks(target, snyk_cursor_source)
        result = read_json(target)
        assert len(result["hooks"]["afterFileEdit"]) == 1
        assert result["hooks"]["afterFileEdit"][0]["command"] == "eslint --fix"

    def test_cleans_empty_events(self, write_json, snyk_cursor_source):
        target = write_json(
            "target.json",
            {
                "version": 1,
                "hooks": {
                    "stop": [
                        {
                            "command": 'python3 "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'
                        },
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
                        {
                            "command": 'python3 "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'
                        },
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
                                    "command": 'python3 "$HOME/.claude/hooks/snyk_secure_at_inception.py"',
                                },
                            ],
                        }
                    ],
                    "Stop": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": 'python3 "$HOME/.claude/hooks/snyk_secure_at_inception.py"',
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
                                    "command": 'python3 "$HOME/.claude/hooks/snyk_secure_at_inception.py"',
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
                                    "command": 'python3 "$HOME/.claude/hooks/snyk_secure_at_inception.py"',
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
                            "hooks": [
                                {"type": "command", "command": "prettier --write"}
                            ],
                        }
                    ]
                }
            },
        )
        original = read_json(target)
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
                                    "command": 'python3 "$HOME/.claude/hooks/snyk_secure_at_inception.py"',
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
# main() CLI dispatch
# ═══════════════════════════════════════════════════════════════════════════


class TestMain:
    def test_dispatches_correctly(
        self, monkeypatch, empty_target, snyk_mcp_source
    ):
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
                                    "command": 'python3 "$HOME/.claude/hooks/snyk_secure_at_inception.py"',
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
                            "hooks": [
                                {"type": "command", "command": "prettier --write"}
                            ],
                        }
                    ],
                    "Stop": [
                        {
                            "hooks": [
                                {"type": "command", "command": "echo done"}
                            ]
                        }
                    ],
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
