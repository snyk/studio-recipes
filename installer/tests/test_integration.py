"""Integration tests: full merge → unmerge lifecycle scenarios."""

import json
import os

from helpers import read_json
from merge_json import (
    main,
    merge_claude_settings,
    merge_cursor_hooks,
    merge_mcp_servers,
    unmerge_claude_settings,
    unmerge_cursor_hooks,
    unmerge_mcp_servers,
)


class TestCursorHooksLifecycle:
    def test_full_lifecycle(self, empty_target, snyk_cursor_source):
        # 1. Merge into fresh target
        merge_cursor_hooks(empty_target, snyk_cursor_source)
        result = read_json(empty_target)
        assert result["version"] == 1
        assert len(result["hooks"]["afterFileEdit"]) == 1
        assert len(result["hooks"]["stop"]) == 1

        # 2. Merge again — idempotent
        merge_cursor_hooks(empty_target, snyk_cursor_source)
        result2 = read_json(empty_target)
        assert result2 == result

        # 3. Unmerge — hooks removed, structure and version preserved
        unmerge_cursor_hooks(empty_target, snyk_cursor_source)
        result3 = read_json(empty_target)
        assert result3["version"] == 1
        assert "afterFileEdit" not in result3["hooks"]
        assert "stop" not in result3["hooks"]
        # File is still valid JSON
        assert isinstance(result3, dict)


class TestClaudeSettingsLifecycle:
    def test_full_lifecycle(self, existing_claude_target, snyk_claude_source):
        read_json(existing_claude_target)

        # 1. Merge snyk into target with existing prettier hooks
        merge_claude_settings(existing_claude_target, snyk_claude_source)
        result = read_json(existing_claude_target)
        assert result["allowedTools"] == ["Read", "Write"]
        # PostToolUse Edit|Write group has both prettier and snyk
        group = result["hooks"]["PostToolUse"][0]
        assert len(group["hooks"]) == 2
        # Stop event added
        assert "Stop" in result["hooks"]

        # 2. Merge again — idempotent
        merge_claude_settings(existing_claude_target, snyk_claude_source)
        assert read_json(existing_claude_target) == result

        # 3. Unmerge — only snyk removed
        unmerge_claude_settings(existing_claude_target, snyk_claude_source)
        result3 = read_json(existing_claude_target)
        assert result3["allowedTools"] == ["Read", "Write"]
        # Prettier hook survives
        group = result3["hooks"]["PostToolUse"][0]
        assert len(group["hooks"]) == 1
        assert group["hooks"][0]["command"] == "prettier --write"
        # Stop event cleaned up (was only snyk)
        assert "Stop" not in result3["hooks"]


class TestMcpServersLifecycle:
    def test_full_lifecycle(self, existing_mcp_target, snyk_mcp_source):
        # 1. Merge Snyk into target with GitHub
        merge_mcp_servers(existing_mcp_target, snyk_mcp_source)
        result = read_json(existing_mcp_target)
        assert set(result["mcpServers"].keys()) == {"GitHub", "Snyk"}

        # 2. Merge again — idempotent
        merge_mcp_servers(existing_mcp_target, snyk_mcp_source)
        assert read_json(existing_mcp_target) == result

        # 3. Unmerge — only Snyk removed
        unmerge_mcp_servers(existing_mcp_target, snyk_mcp_source)
        result3 = read_json(existing_mcp_target)
        assert set(result3["mcpServers"].keys()) == {"GitHub"}

    def test_multi_snyk_lifecycle(self, existing_mcp_target, multi_snyk_mcp_source):
        # 1. Merge Snyk + SnykCode into target with GitHub
        merge_mcp_servers(existing_mcp_target, multi_snyk_mcp_source)
        result = read_json(existing_mcp_target)
        assert set(result["mcpServers"].keys()) == {"GitHub", "Snyk", "SnykCode"}

        # 2. Unmerge — both Snyk servers removed, GitHub preserved
        unmerge_mcp_servers(existing_mcp_target, multi_snyk_mcp_source)
        result2 = read_json(existing_mcp_target)
        assert set(result2["mcpServers"].keys()) == {"GitHub"}


class TestAllStrategiesFreshFiles:
    def test_merge_and_unmerge_all(
        self, tmp_path, snyk_cursor_source, snyk_claude_source, snyk_mcp_source
    ):
        cursor_target = str(tmp_path / "cursor_hooks.json")
        claude_target = str(tmp_path / "claude_settings.json")
        mcp_target = str(tmp_path / "mcp.json")

        # Merge all three into empty targets
        merge_cursor_hooks(cursor_target, snyk_cursor_source)
        merge_claude_settings(claude_target, snyk_claude_source)
        merge_mcp_servers(mcp_target, snyk_mcp_source)

        # All files created and valid
        assert os.path.isfile(cursor_target)
        assert os.path.isfile(claude_target)
        assert os.path.isfile(mcp_target)
        assert read_json(cursor_target)["hooks"]["afterFileEdit"]
        assert read_json(claude_target)["hooks"]["PostToolUse"]
        assert read_json(mcp_target)["mcpServers"]["Snyk"]

        # Unmerge all three
        unmerge_cursor_hooks(cursor_target, snyk_cursor_source)
        unmerge_claude_settings(claude_target, snyk_claude_source)
        unmerge_mcp_servers(mcp_target, snyk_mcp_source)

        # Files still valid JSON but content removed
        cursor_result = read_json(cursor_target)
        assert "afterFileEdit" not in cursor_result.get("hooks", {})

        claude_result = read_json(claude_target)
        assert "PostToolUse" not in claude_result.get("hooks", {})
        assert "Stop" not in claude_result.get("hooks", {})

        mcp_result = read_json(mcp_target)
        assert "Snyk" not in mcp_result.get("mcpServers", {})


class TestBackupChain:
    def test_backup_reflects_state_before_each_merge(self, tmp_path, snyk_mcp_source):
        target = str(tmp_path / "mcp.json")

        # First merge — no target existed, so no .bak
        merge_mcp_servers(target, snyk_mcp_source)
        assert not os.path.isfile(target + ".bak")

        # Manually modify target
        data = read_json(target)
        data["mcpServers"]["ManualServer"] = {"command": "manual"}
        with open(target, "w") as f:
            json.dump(data, f, indent=2)

        # Second merge — .bak should capture the manual edit
        merge_mcp_servers(target, snyk_mcp_source)
        bak = read_json(target + ".bak")
        assert "ManualServer" in bak["mcpServers"]


class TestCliRoundTrip:
    def test_main_merge_then_unmerge(self, monkeypatch, tmp_path, snyk_mcp_source):
        target = str(tmp_path / "mcp.json")

        # Merge via CLI
        monkeypatch.setattr(
            "sys.argv",
            ["merge_json.py", "merge_mcp_servers", target, snyk_mcp_source],
        )
        main()
        assert "Snyk" in read_json(target)["mcpServers"]

        # Unmerge via CLI
        monkeypatch.setattr(
            "sys.argv",
            ["merge_json.py", "unmerge_mcp_servers", target, snyk_mcp_source],
        )
        main()
        assert "Snyk" not in read_json(target).get("mcpServers", {})
