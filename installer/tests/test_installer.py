"""Tests for snyk-studio-installer.py (cross-platform Python installer)."""

import contextlib
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add installer root to path
INSTALLER_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(INSTALLER_DIR))
sys.path.insert(0, str(INSTALLER_DIR / "lib"))

# Import with underscore since the filename has hyphens
import importlib
installer = importlib.import_module("snyk-studio-installer")


# ===========================================================================
# TestCheckPrerequisites
# ===========================================================================

class TestCheckPrerequisites:
    def test_all_ok(self, monkeypatch, capsys):
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None)

        def mock_run(cmd, **kwargs):
            m = MagicMock()
            if cmd[0] == "snyk" and cmd[1] == "--version":
                m.stdout = "1.1302.0\n"
                m.returncode = 0
            return m

        monkeypatch.setattr("subprocess.run", mock_run)

        # Should not raise SystemExit
        installer.check_prerequisites(auto_yes=True)
        captured = capsys.readouterr()
        assert "OK Snyk CLI 1.1302.0" in captured.out

    def test_outdated_snyk_warning(self, monkeypatch, capsys):
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None)

        def mock_run(cmd, **kwargs):
            m = MagicMock()
            if cmd[0] == "snyk" and cmd[1] == "--version":
                m.stdout = "1.1301.0\n"
                m.returncode = 0
            return m

        monkeypatch.setattr("subprocess.run", mock_run)

        # With auto_yes=True, it should just print warning and continue
        installer.check_prerequisites(auto_yes=True)
        captured = capsys.readouterr()
        assert "WARNING Snyk CLI 1.1301.0 is outdated" in captured.out

    def test_outdated_snyk_cancel(self, monkeypatch, capsys):
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None)

        def mock_run(cmd, **kwargs):
            m = MagicMock()
            if cmd[0] == "snyk" and cmd[1] == "--version":
                m.stdout = "1.1301.0\n"
                m.returncode = 0
            return m

        monkeypatch.setattr("subprocess.run", mock_run)
        monkeypatch.setattr("builtins.input", lambda _: "n")

        with pytest.raises(SystemExit):
            installer.check_prerequisites(auto_yes=False)

        captured = capsys.readouterr()
        assert "WARNING Snyk CLI 1.1301.0 is outdated" in captured.out

    def test_snyk_not_found(self, monkeypatch, capsys):
        monkeypatch.setattr("shutil.which", lambda cmd: None)

        # Mock input to say 'y' to continue
        monkeypatch.setattr("builtins.input", lambda _: "y")

        installer.check_prerequisites(auto_yes=False)
        captured = capsys.readouterr()
        assert "WARNING Snyk CLI not found" in captured.out

    def test_version_parse_edge_case(self, monkeypatch, capsys):
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None)

        def mock_run(cmd, **kwargs):
            m = MagicMock()
            if cmd[0] == "snyk" and cmd[1] == "--version":
                m.stdout = "1.1302.0 (standalone)\n"
                m.returncode = 0
            return m

        monkeypatch.setattr("subprocess.run", mock_run)

        installer.check_prerequisites(auto_yes=True)
        captured = capsys.readouterr()
        assert "OK Snyk CLI 1.1302.0 (standalone)" in captured.out
        assert "is outdated" not in captured.out

    def test_version_malformed_no_error(self, monkeypatch, capsys):
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None)

        def mock_run(cmd, **kwargs):
            m = MagicMock()
            if cmd[0] == "snyk" and cmd[1] == "--version":
                m.stdout = "development-version\n"
                m.returncode = 0
            return m

        monkeypatch.setattr("subprocess.run", mock_run)

        installer.check_prerequisites(auto_yes=True)
        captured = capsys.readouterr()
        assert "OK Snyk CLI development-version (could not parse version)" in captured.out


# ===========================================================================
# TestParseArgs
# ===========================================================================

class TestParseArgs:
    def test_defaults(self):
        args = installer.parse_args([])
        assert args.profile == "default"
        assert args.ade is None
        assert args.dry_run is False
        assert args.uninstall is False
        assert args.verify is False
        assert args.list_mode is False
        assert args.yes is False

    def test_all_flags(self):
        args = installer.parse_args([
            "--profile", "minimal",
            "--ade", "cursor",
            "--dry-run",
            "--verify",
            "--list",
            "-y",
        ])
        assert args.profile == "minimal"
        assert args.ade == "cursor"
        assert args.dry_run is True
        assert args.verify is True
        assert args.list_mode is True
        assert args.yes is True

    def test_invalid_ade_rejected(self):
        with pytest.raises(SystemExit):
            installer.parse_args(["--ade", "vscode"])

    def test_gemini_ade_accepted(self):
        args = installer.parse_args(["--ade", "gemini"])
        assert args.ade == "gemini"

    def test_kiro_ade_accepted(self):
        args = installer.parse_args(["--ade", "kiro"])
        assert args.ade == "kiro"


# ===========================================================================
# TestColor
# ===========================================================================

class TestColor:
    def test_disabled_returns_plain_text(self):
        c = installer.Color()
        c.enabled = False
        assert c.red("hello") == "hello"
        assert c.green("world") == "world"
        assert c.bold("test") == "test"

    def test_enabled_wraps_with_ansi(self):
        c = installer.Color()
        c.enabled = True
        result = c.red("error")
        assert "\033[" in result
        assert "error" in result


# ===========================================================================
# TestDetectAdes
# ===========================================================================

class TestDetectAdes:
    def test_detects_cursor_from_directory(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        (tmp_path / ".cursor").mkdir()
        result = installer.detect_ades()
        assert "cursor" in result

    def test_detects_claude_from_directory(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        (tmp_path / ".claude").mkdir()
        result = installer.detect_ades()
        assert "claude" in result

    def test_detects_gemini_from_directory(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        (tmp_path / ".gemini").mkdir()
        result = installer.detect_ades()
        assert "gemini" in result

    def test_detects_gemini_from_cli(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/gemini" if cmd == "gemini" else None)
        result = installer.detect_ades()
        assert "gemini" in result

    def test_detects_kiro_from_directory(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        (tmp_path / ".kiro").mkdir()
        result = installer.detect_ades()
        assert "kiro" in result

    def test_detects_kiro_from_cli(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/kiro" if cmd == "kiro" else None)
        result = installer.detect_ades()
        assert "kiro" in result

    def test_detects_both(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        
        (tmp_path / ".cursor").mkdir()
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".gemini").mkdir()
        result = installer.detect_ades()
        assert result == ["cursor", "claude", "gemini"]

    def test_detects_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        monkeypatch.setattr(installer, "_cursor_app_bundle_exists", lambda: False)
        # Mock pgrep to not find cursor process
        mock_run = MagicMock(return_value=MagicMock(returncode=1))
        monkeypatch.setattr("subprocess.run", mock_run)
        result = installer.detect_ades()
        assert result == []
        # Exact process name (case-insensitive): pgrep -xi, not substring match
        for call in mock_run.call_args_list:
            args, kwargs = call
            assert args[0] == ["pgrep", "-xiq", "cursor"]

    def test_detects_cursor_from_macos_app_bundle_without_dot_cursor(
        self, tmp_path, monkeypatch
    ):
        """When ~/.cursor is absent, macOS Cursor.app implies cursor (no pgrep)."""

        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        monkeypatch.setattr("sys.platform", "darwin")
        monkeypatch.setattr(installer, "_cursor_app_bundle_exists", lambda: True)

        pgrep_calls: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            pgrep_calls.append(list(cmd))
            m = MagicMock()
            m.returncode = 1
            return m

        monkeypatch.setattr("subprocess.run", fake_run)
        assert installer.detect_ades() == ["cursor"]
        assert pgrep_calls == []

    def test_detects_cursor_from_pgrep_exact_process_name(self, tmp_path, monkeypatch):
        """When ~/.cursor and Cursor.app are absent, pgrep -xiq cursor (exact name) detects cursor."""

        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        monkeypatch.setattr(installer, "_cursor_app_bundle_exists", lambda: False)
        monkeypatch.setattr("sys.platform", "linux")

        pgrep_calls: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            pgrep_calls.append(list(cmd))
            m = MagicMock()
            m.returncode = 0 if cmd == ["pgrep", "-xiq", "cursor"] else 1
            return m

        monkeypatch.setattr("subprocess.run", fake_run)
        assert installer.detect_ades() == ["cursor"]
        assert pgrep_calls == [["pgrep", "-xiq", "cursor"]]

    def test_cursor_not_detected_for_substring_process_names(self, tmp_path, monkeypatch):
        """Regression: only an exact process name Cursor counts (pgrep -x).

        Older substring-style matching could treat unrelated processes whose names
        contained 'cursor' as the Cursor IDE. pgrep -xiq cursor exits 1 when no
        command is named exactly 'cursor' (case-insensitive), e.g. only
        'cursor-indexer' or 'my-cursor-helper' is running.
        """

        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        monkeypatch.setattr(installer, "_cursor_app_bundle_exists", lambda: False)
        monkeypatch.setattr("sys.platform", "linux")

        def fake_run(cmd, **kwargs):
            assert list(cmd) == ["pgrep", "-xiq", "cursor"]
            m = MagicMock()
            m.returncode = 1
            return m

        monkeypatch.setattr("subprocess.run", fake_run)
        assert installer.detect_ades() == []

    def test_detects_claude_from_cli(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/claude" if cmd == "claude" else None)
        result = installer.detect_ades()
        assert "claude" in result


# ===========================================================================
# TestManifest
# ===========================================================================

class TestManifest:
    @pytest.fixture
    def manifest(self):
        return installer.Manifest(INSTALLER_DIR / "manifest.json")

    def test_resolve_default_profile(self, manifest):
        recipes = manifest.resolve_recipes("default")
        assert "sai-hooks-async" in recipes
        assert "snyk-fix-command" in recipes
        assert len(recipes) == 5

    def test_resolve_minimal_profile(self, manifest):
        recipes = manifest.resolve_recipes("minimal")
        assert "sai-hooks-async" in recipes
        assert "mcp-config" in recipes
        assert "snyk-fix-command" not in recipes

    def test_unknown_profile_exits(self, manifest):
        with pytest.raises(SystemExit):
            manifest.resolve_recipes("nonexistent")

    def test_get_sources_cursor(self, manifest):
        sources = manifest.get_sources("sai-hooks-async", "cursor")
        assert "files" in sources
        assert "config_merge" in sources

    def test_get_sources_gemini(self, manifest):
        sources = manifest.get_sources("sai-hooks-async", "gemini")
        assert "files" in sources
        assert sources["config_merge"]["strategy"] == "merge_gemini_settings"
        assert sources["config_merge"]["target"] == ".gemini/settings.json"

    def test_get_sources_kiro(self, manifest):
        sources = manifest.get_sources("mcp-config", "kiro")
        assert sources["config_merge"]["strategy"] == "merge_mcp_servers"
        assert sources["config_merge"]["target"] == ".kiro/settings/mcp.json"

    def test_gemini_sources_for_all_default_recipes(self, manifest):
        for recipe_id in manifest.resolve_recipes("default"):
            sources = manifest.get_sources(recipe_id, "gemini")
            assert sources, f"missing gemini sources for {recipe_id}"

    def test_kiro_sources_for_all_default_recipes_except_hooks(self, manifest):
        for recipe_id in manifest.resolve_recipes("default"):
            if recipe_id == "sai-hooks-async":
                continue
            sources = manifest.get_sources(recipe_id, "kiro")
            assert sources, f"missing kiro sources for {recipe_id}"

    def test_get_sources_missing_ade(self, manifest):
        sources = manifest.get_sources("sai-hooks-async", "vscode")
        assert sources == {}

    def test_are_rules_conflicting_no_conflict(self, manifest, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.chdir(tmp_path)
        assert manifest.are_rules_conflicting("cursor") is False

    def test_are_rules_conflicting_file_exists_no_tags(self, manifest, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.chdir(tmp_path)
        rule_path = tmp_path / ".cursor/rules/snyk_rules.mdc"
        rule_path.parent.mkdir(parents=True)
        rule_path.write_text("some random content")
        assert manifest.are_rules_conflicting("cursor") is False

    def test_are_rules_conflicting_with_tags(self, manifest, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.chdir(tmp_path)
        rule_path = tmp_path / ".cursor/rules/snyk_rules.mdc"
        rule_path.parent.mkdir(parents=True)
        rule_path.write_text("<!--# BEGIN SNYK GLOBAL RULE -->\ncontent\n<!--# END SNYK GLOBAL RULE -->")
        assert manifest.are_rules_conflicting("cursor") is True

    def test_are_rules_conflicting_global(self, manifest, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        # windsurf has a global rule: .codeium/windsurf/memories/global_rules.md
        rule_path = tmp_path / ".codeium/windsurf/memories/global_rules.md"
        rule_path.parent.mkdir(parents=True)
        rule_path.write_text("<!--# BEGIN SNYK GLOBAL RULE -->\ncontent\n<!--# END SNYK GLOBAL RULE -->")
        assert manifest.are_rules_conflicting("windsurf") is True

    def test_are_skills_conflicting_no_conflict(self, manifest, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.chdir(tmp_path)
        assert manifest.are_skills_conflicting("cursor") is False

    def test_are_skills_conflicting_exists(self, manifest, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.chdir(tmp_path)
        # cursor has a global skill: .cursor/skills/snyk-rules/SKILL.md
        skill_path = tmp_path / ".cursor/skills/snyk-rules/SKILL.md"
        skill_path.parent.mkdir(parents=True)
        skill_path.touch()
        assert manifest.are_skills_conflicting("cursor") is True

    def test_are_rules_conflicting_unknown_ade(self, manifest):
        assert manifest.are_rules_conflicting("nonexistent") is False

    def test_are_skills_conflicting_unknown_ade(self, manifest):
        assert manifest.are_skills_conflicting("nonexistent") is False

    def test_get_conflicting_resource_scope(self, manifest):
        # cursor has 1 rule (workspace) and 1 skill (global) in manifest.json
        # "cursor" :{ "rules": [{"global": false, ...}], "skills": [{"global": true, ...}] }
        assert manifest.get_conflicting_resource_scope("cursor", "rules") == ["workspace"]
        assert manifest.get_conflicting_resource_scope("cursor", "skills") == ["global"]
        assert manifest.get_conflicting_resource_scope("nonexistent", "rules") == []


# ===========================================================================
# TestCopyFile
# ===========================================================================

class TestCopyFile:
    def test_copies_new_file(self, tmp_path):
        src = tmp_path / "src.txt"
        src.write_text("hello")
        dest = tmp_path / "sub" / "dest.txt"
        installer.copy_file(src, dest, dry_run=False)
        assert dest.read_text() == "hello"

    def test_skips_identical_file(self, tmp_path, capsys):
        src = tmp_path / "src.txt"
        src.write_text("hello")
        dest = tmp_path / "dest.txt"
        dest.write_text("hello")
        installer.copy_file(src, dest, dry_run=False)
        captured = capsys.readouterr()
        assert "unchanged" in captured.out

    def test_dry_run_no_write(self, tmp_path, capsys):
        src = tmp_path / "src.txt"
        src.write_text("hello")
        dest = tmp_path / "dest.txt"
        installer.copy_file(src, dest, dry_run=True)
        assert not dest.exists()
        captured = capsys.readouterr()
        assert "dry-run" in captured.out


# ===========================================================================
# TestRewriteHookCommands
# ===========================================================================

class TestRewriteHookCommands:
    def test_noop_on_unix(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "darwin")
        data = {"hooks": {"PostToolUse": [{"command": 'python3 "$HOME/.claude/hooks/test.py"'}]}}
        result = installer.rewrite_hook_commands_for_platform(data)
        assert result == data

    def test_rewrites_on_windows(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "win32")
        data = {"hooks": {"PostToolUse": [
            {"matcher": "Edit|Write", "hooks": [
                {"type": "command", "command": 'python3 "$HOME/.claude/hooks/snyk_secure_at_inception.py"'}
            ]}
        ]}}
        result = installer.rewrite_hook_commands_for_platform(data)
        cmd = result["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
        assert cmd.startswith("py -3")
        assert "%USERPROFILE%" in cmd

    def test_ignores_non_python_commands(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "win32")
        data = {"hooks": {"PostToolUse": [{"command": "eslint --fix"}]}}
        result = installer.rewrite_hook_commands_for_platform(data)
        assert result["hooks"]["PostToolUse"][0]["command"] == "eslint --fix"


# ===========================================================================
# TestPlatformSource
# ===========================================================================

class TestPlatformSource:
    def test_non_windows_passthrough(self, tmp_path, monkeypatch):
        monkeypatch.setattr("sys.platform", "darwin")
        source = tmp_path / "hooks.json"
        source.write_text('{"hooks": {}}')
        with installer._platform_source("merge_cursor_hooks", source) as resolved_path:
            assert resolved_path == source

    def test_windows_matching_strategy_rewrites_and_cleans_up(self, tmp_path, monkeypatch):
        monkeypatch.setattr("sys.platform", "win32")
        source = tmp_path / "hooks.json"
        source.write_text('{"command": "python3 $HOME/test.py"}')
        tmp_file_path = None
        with installer._platform_source("merge_cursor_hooks", source) as resolved_path:
            assert resolved_path != source
            tmp_file_path = resolved_path
            assert tmp_file_path.exists()
        assert tmp_file_path is not None
        assert not tmp_file_path.exists()

    def test_windows_non_matching_strategy_passthrough(self, tmp_path, monkeypatch):
        monkeypatch.setattr("sys.platform", "win32")
        source = tmp_path / "data.json"
        source.write_text('{"key": "value"}')
        with installer._platform_source("copy_files", source) as resolved_path:
            assert resolved_path == source

    def test_windows_cleans_up_on_exception(self, tmp_path, monkeypatch):
        monkeypatch.setattr("sys.platform", "win32")
        source = tmp_path / "hooks.json"
        source.write_text('{"hooks": {}}')
        tmp_file_path = None
        with pytest.raises(RuntimeError):
            with installer._platform_source("merge_claude_settings", source) as resolved_path:
                tmp_file_path = resolved_path
                raise RuntimeError("boom")
        assert tmp_file_path is not None
        assert not tmp_file_path.exists()


# ===========================================================================
# TestMergeConfig
# ===========================================================================

class TestMergeConfig:
    def test_dry_run(self, tmp_path, capsys):
        source = tmp_path / "source.json"
        source.write_text('{}')
        target = tmp_path / "target.json"
        payload = MagicMock()
        installer.merge_config("merge_cursor_hooks", target, source, payload, dry_run=True)
        assert not target.exists()
        assert "dry-run" in capsys.readouterr().out

    def test_unknown_strategy(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(sys, "path", list(sys.path))
        source = tmp_path / "source.json"
        source.write_text('{}')
        target = tmp_path / "target.json"
        payload = installer.PayloadContext()
        payload.setup()
        try:
            installer.merge_config("no_such_strategy_xyz", target, source, payload, dry_run=False)
        finally:
            payload.cleanup()
        assert "Unknown strategy" in capsys.readouterr().out
        assert not target.exists()

    def test_valid_strategy(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(sys, "path", list(sys.path))
        payload = installer.PayloadContext()
        payload.setup()
        try:
            manifest = installer.Manifest(payload.manifest_path)
            sources = manifest.get_sources("sai-hooks-async", "claude")
            cm = sources.get("config_merge")
            assert cm is not None, "expected config_merge for sai-hooks-async/claude"
            source = payload.resolve_src(cm["source"])
            strategy = cm["strategy"]
            target = tmp_path / "settings.json"
            installer.merge_config(strategy, target, source, payload, dry_run=False)
        finally:
            payload.cleanup()
        assert "merged:" in capsys.readouterr().out

    def test_merge_invalid_json(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(sys, "path", list(sys.path))
        payload = installer.PayloadContext()
        payload.setup()
        try:
            source = tmp_path / "source.json"
            source.write_text('{"hooks": {}}')
            target = tmp_path / "target.json"
            target.write_text("{ invalid }")

            installer.merge_config("merge_cursor_hooks", target, source, payload, dry_run=False)
        finally:
            payload.cleanup()

        assert "Cannot update configuration, parse error in file" in capsys.readouterr().out


# ===========================================================================
# TestLifecycle
# ===========================================================================

class TestLifecycle:
    """Integration test: install -> verify -> uninstall with temp HOME."""

    @pytest.fixture
    def fake_home(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".cursor").mkdir()
        (tmp_path / ".gemini").mkdir()
        return tmp_path

    @pytest.fixture
    def payload(self):
        ctx = installer.PayloadContext()
        ctx.setup()
        yield ctx
        ctx.cleanup()

    @pytest.fixture
    def manifest(self, payload):
        return installer.Manifest(payload.manifest_path)

    def test_install_verify_uninstall(self, fake_home, payload, manifest):
        ades = ["claude"]
        recipes = manifest.resolve_recipes("default")

        # Install
        for ade in ades:
            for recipe_id in recipes:
                installer.install_recipe(recipe_id, ade, manifest, payload, dry_run=False)

        # Verify files exist
        assert (fake_home / ".claude" / "hooks" / "snyk_secure_at_inception.py").exists()
        assert (fake_home / ".claude" / "hooks" / "lib" / "scan_runner.py").exists()
        assert (fake_home / ".claude" / "hooks" / "lib" / "platform_utils.py").exists()
        assert (fake_home / ".claude" / "commands" / "snyk-fix.md").exists()

        # Verify via installer
        for ade in ades:
            for recipe_id in recipes:
                assert installer.verify_recipe(recipe_id, ade, manifest, payload)

        # Uninstall
        installer.uninstall(ades, manifest, payload, dry_run=False)

        # Verify files removed
        assert not (fake_home / ".claude" / "hooks" / "snyk_secure_at_inception.py").exists()

    def test_install_verify_uninstall_gemini(self, fake_home, payload, manifest):
        ades = ["gemini"]
        recipes = manifest.resolve_recipes("default")

        for ade in ades:
            for recipe_id in recipes:
                installer.install_recipe(recipe_id, ade, manifest, payload, dry_run=False)

        gemini_settings = fake_home / ".gemini" / "settings.json"
        assert (fake_home / ".gemini" / "hooks" / "snyk_secure_at_inception.py").exists()
        assert (fake_home / ".gemini" / "hooks" / "lib" / "scan_runner.py").exists()
        assert (fake_home / ".gemini" / "commands" / "snyk-fix.md").exists()
        assert gemini_settings.exists()

        settings_after_install = json.loads(gemini_settings.read_text())
        assert settings_after_install.get("hooks"), "expected hooks merged into gemini settings.json"
        assert settings_after_install.get("mcpServers", {}).get("Snyk"), \
            "expected MCP server merged into gemini settings.json"

        for ade in ades:
            for recipe_id in recipes:
                assert installer.verify_recipe(recipe_id, ade, manifest, payload)

        installer.uninstall(ades, manifest, payload, dry_run=False)

        assert not (fake_home / ".gemini" / "hooks" / "snyk_secure_at_inception.py").exists()
        assert not (fake_home / ".gemini" / "commands" / "snyk-fix.md").exists()

        settings_after_uninstall = json.loads(gemini_settings.read_text())
        assert not settings_after_uninstall.get("hooks"), \
            "unmerge_gemini_settings should remove Snyk hooks from settings.json"
        assert "Snyk" not in settings_after_uninstall.get("mcpServers", {}), \
            "unmerge_mcp_servers should remove the Snyk MCP server from settings.json"

    def test_install_verify_uninstall_kiro(self, fake_home, payload, manifest):
        ades = ["kiro"]
        recipes = manifest.resolve_recipes("default")

        for ade in ades:
            for recipe_id in recipes:
                installer.install_recipe(recipe_id, ade, manifest, payload, dry_run=False)

        kiro_mcp_settings = fake_home / ".kiro" / "settings" / "mcp.json"
        assert (fake_home / ".kiro" / "steering" / "snyk-fix.md").exists()
        assert (fake_home / ".kiro" / "steering" / "snyk-batch-fix.md").exists()
        assert (fake_home / ".kiro" / "skills" / "secure-dependency-health-check" / "SKILL.md").exists()
        assert kiro_mcp_settings.exists()

        settings_after_install = json.loads(kiro_mcp_settings.read_text())
        assert settings_after_install.get("mcpServers", {}).get("Snyk"), \
            "expected MCP server merged into .kiro/settings/mcp.json"

        for ade in ades:
            for recipe_id in recipes:
                # verify_recipe will return True for sai-hooks-async because it has no sources for kiro
                assert installer.verify_recipe(recipe_id, ade, manifest, payload)

        installer.uninstall(ades, manifest, payload, dry_run=False)

        assert not (fake_home / ".kiro" / "steering" / "snyk-fix.md").exists()

        settings_after_uninstall = json.loads(kiro_mcp_settings.read_text())
        assert "Snyk" not in settings_after_uninstall.get("mcpServers", {}), \
            "unmerge_mcp_servers should remove the Snyk MCP server from .kiro/settings/mcp.json"

    def test_dry_run_makes_no_changes(self, fake_home, payload, manifest):
        recipes = manifest.resolve_recipes("default")
        for recipe_id in recipes:
            installer.install_recipe(recipe_id, "claude", manifest, payload, dry_run=True)

        assert not (fake_home / ".claude" / "hooks" / "snyk_secure_at_inception.py").exists()


# ===========================================================================
# TestVerifyRecipe
# ===========================================================================

class TestVerifyRecipe:
    def test_verify_recipe_invalid_json(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        payload = installer.PayloadContext()
        payload.setup()
        manifest = installer.Manifest(payload.manifest_path)

        # Create an invalid JSON file at the target location for claude settings
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text("{ invalid }")

        # sai-hooks-async for claude uses merge_claude_settings
        result = installer.verify_recipe("sai-hooks-async", "claude", manifest, payload)

        assert result is False
        assert "Cannot update configuration, parse error in file" in capsys.readouterr().out


# ===========================================================================
# TestVSCodeSettingsConflict
# ===========================================================================

class TestVSCodeSettingsConflict:

    @pytest.fixture
    def manifest(self):
        """Fixture to provide a Manifest instance using the real manifest.json."""
        return installer.Manifest(INSTALLER_DIR / "manifest.json")

    @pytest.fixture
    def vscode_env(self, tmp_path, monkeypatch):
        """Sets up a mock environment with home and workspace directories."""
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setattr(Path, "home", lambda: home)
        monkeypatch.chdir(tmp_path)
        # Default to non-windows for consistent testing
        monkeypatch.setattr(sys, "platform", "darwin")

        # Paths must align with entries in manifest.json:
        # global: Cursor/User/settings.json (on Darwin, prefixed with Library/Application Support)
        # local: .vscode/settings.json
        return {
            "home": home,
            "workspace": tmp_path,
            "global_dir": home / "Library" / "Application Support" / "Cursor" / "User",
            "workspace_dir": tmp_path / ".vscode"
        }

    def test_no_settings_files(self, manifest, vscode_env):
        assert not manifest.are_extension_settings_conflicting("cursor")

    def test_workspace_conflict(self, manifest, vscode_env):
        ws_dir = vscode_env["workspace_dir"]
        ws_dir.mkdir(parents=True)
        (ws_dir / "settings.json").write_text(json.dumps({
            "snyk.securityAtInception.autoConfigureSnykMcpServer": True,
            "snyk.securityAtInception.executionFrequency": "On Code Generation"
        }))
        assert manifest.are_extension_settings_conflicting("cursor")

    def test_workspace_no_conflict_global_conflict(self, manifest, vscode_env):
        # Global has it enabled
        global_dir = vscode_env["global_dir"]
        global_dir.mkdir(parents=True)
        (global_dir / "settings.json").write_text(json.dumps({
            "snyk.securityAtInception.autoConfigureSnykMcpServer": True,
            "snyk.securityAtInception.executionFrequency": "On Code Generation"
        }))

        # Workspace has it explicitly disabled - this SHOULD NOT conflict as it overrides global.
        # Note: Both keys must be present for the installer to update its resolved settings.
        ws_dir = vscode_env["workspace_dir"]
        ws_dir.mkdir(parents=True)
        (ws_dir / "settings.json").write_text(json.dumps({
            "snyk.securityAtInception.autoConfigureSnykMcpServer": False,
            "snyk.securityAtInception.executionFrequency": "On Code Generation"
        }))

        assert not manifest.are_extension_settings_conflicting("cursor")

    def test_workspace_manual_frequency_is_no_conflict(self, manifest, vscode_env):
        ws_dir = vscode_env["workspace_dir"]
        ws_dir.mkdir(parents=True)
        (ws_dir / "settings.json").write_text(json.dumps({
            "snyk.securityAtInception.autoConfigureSnykMcpServer": True,
            "snyk.securityAtInception.executionFrequency": "Manual"
        }))
        assert not manifest.are_extension_settings_conflicting("cursor")

    def test_unset_execution_frequency_defaults_to_manual_no_conflict(self, manifest, vscode_env):
        ws_dir = vscode_env["workspace_dir"]
        ws_dir.mkdir(parents=True)
        (ws_dir / "settings.json").write_text(json.dumps({
            "snyk.securityAtInception.autoConfigureSnykMcpServer": True,
        }))
        assert not manifest.are_extension_settings_conflicting("cursor")

    def test_windows_global_path(self, manifest, vscode_env, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        appdata = vscode_env["home"] / "AppData" / "Roaming"
        monkeypatch.setitem(os.environ, "APPDATA", str(appdata))

        win_global_dir = appdata / "Cursor" / "User"
        win_global_dir.mkdir(parents=True)
        (win_global_dir / "settings.json").write_text(json.dumps({
            "snyk.securityAtInception.autoConfigureSnykMcpServer": True,
            "snyk.securityAtInception.executionFrequency": "On Code Generation"
        }))

        assert manifest.are_extension_settings_conflicting("cursor")

    def test_invalid_json_skips(self, manifest, vscode_env):
        ws_dir = vscode_env["workspace_dir"]
        ws_dir.mkdir(parents=True)
        (ws_dir / "settings.json").write_text("{ invalid json")
        assert not manifest.are_extension_settings_conflicting("cursor")

    def test_skips_check_if_ade_not_configured_in_manifest(self, manifest, vscode_env):
        # Global has conflict values
        global_dir = vscode_env["global_dir"]
        global_dir.mkdir(parents=True)
        (global_dir / "settings.json").write_text(json.dumps({
            "snyk.securityAtInception.autoConfigureSnykMcpServer": True,
            "snyk.securityAtInception.executionFrequency": "On Code Generation"
        }))
        # 'claude' has no extension-settings entries in manifest.json, so it should return False.
        assert not manifest.are_extension_settings_conflicting("claude")

    def test_resolve_extension_conflicts(self, manifest, vscode_env):
        ws_dir = vscode_env["workspace_dir"]
        ws_dir.mkdir(parents=True)
        settings_file = ws_dir / "settings.json"
        original_data = {
            "snyk.securityAtInception.autoConfigureSnykMcpServer": True,
            "snyk.securityAtInception.executionFrequency": "On Code Generation",
            "other.setting": "value"
        }
        settings_file.write_text(json.dumps(original_data))

        manifest.resolve_extension_conflicts([str(settings_file)])

        # Check that settings were updated
        updated_data = json.loads(settings_file.read_text())
        assert updated_data["snyk.securityAtInception.autoConfigureSnykMcpServer"] is False
        assert updated_data["snyk.securityAtInception.executionFrequency"] == "Manual"
        assert updated_data["other.setting"] == "value"

# ===========================================================================
# TestConflictResolution
# ===========================================================================

class TestConflictResolution:
    @pytest.fixture
    def manifest(self):
        return installer.Manifest(INSTALLER_DIR / "manifest.json")

    def test_get_extension_settings_path_darwin(self, manifest, monkeypatch, tmp_path):
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        paths = manifest.get_extension_settings_path("cursor")
        # Global path on Darwin for cursor: ~/Library/Application Support/Cursor/User/settings.json
        expected_global = tmp_path / "Library/Application Support/Cursor/User/settings.json"
        assert expected_global in paths

    def test_get_extension_settings_path_linux(self, manifest, monkeypatch, tmp_path):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setitem(os.environ, "XDG_CONFIG_HOME", str(tmp_path / ".config"))

        paths = manifest.get_extension_settings_path("cursor")
        # Global path on Linux for cursor: ~/.config/Cursor/User/settings.json
        expected_global = tmp_path / ".config/Cursor/User/settings.json"
        assert expected_global in paths

    def test_resolve_extension_conflicts_write_error(self, manifest, tmp_path, capsys):
        # Setup a file that exists but we can't write to (mocking open failure)
        settings_file = tmp_path / "settings.json"
        settings_file.write_text("{}")

        with patch("builtins.open", side_effect=IOError("Permission denied")):
            manifest.resolve_extension_conflicts([str(settings_file)])

        assert "Failed to update settings file" in capsys.readouterr().out

# ===========================================================================
# TestMacMcpLogic
# ===========================================================================

class TestMacMcpLogic:
    @pytest.fixture
    def payload(self):
        ctx = installer.PayloadContext()
        ctx.setup()
        yield ctx
        ctx.cleanup()

    @pytest.fixture
    def manifest(self, payload):
        return installer.Manifest(payload.manifest_path)

    def test_install_recipe_mac_gui_ade_uses_mac_mcp(self, monkeypatch, payload, manifest):
        monkeypatch.setattr("sys.platform", "darwin")

        mock_merge = MagicMock()
        monkeypatch.setattr(installer, "merge_config", mock_merge)

        # Cursor is NOT in CLI_ADES
        installer.install_recipe("mcp-config", "cursor", manifest, payload, dry_run=False)

        # Check that merge_config was called with the mac source
        args, _ = mock_merge.call_args
        # args[2] is the source Path
        assert args[2].name == ".mcp.mac.json"

    def test_install_recipe_mac_cli_ade_uses_regular_mcp(self, monkeypatch, payload, manifest):
        monkeypatch.setattr("sys.platform", "darwin")

        mock_merge = MagicMock()
        monkeypatch.setattr(installer, "merge_config", mock_merge)

        # Claude IS in CLI_ADES
        installer.install_recipe("mcp-config", "claude", manifest, payload, dry_run=False)

        # Check that merge_config was called with the regular source
        args, _ = mock_merge.call_args
        assert args[2].name == ".mcp.json"

    def test_verify_recipe_mac_gui_ade_uses_mac_mcp(self, monkeypatch, payload, manifest, tmp_path):
        monkeypatch.setattr("sys.platform", "darwin")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        import merge_json
        mock_verify_strategy = MagicMock()
        monkeypatch.setitem(merge_json.STRATEGIES, "verify_mcp_servers", mock_verify_strategy)

        # Mock _platform_source to just return the path (avoiding Windows rewrite logic)
        @contextlib.contextmanager
        def mock_platform_source(strategy, source):
            yield source
        monkeypatch.setattr(installer, "_platform_source", mock_platform_source)

        installer.verify_recipe("mcp-config", "cursor", manifest, payload)

        args, _ = mock_verify_strategy.call_args
        # args[1] is the resolved_path string
        assert Path(args[1]).name == ".mcp.mac.json"

    def test_verify_recipe_mac_cli_ade_uses_regular_mcp(self, monkeypatch, payload, manifest, tmp_path):
        monkeypatch.setattr("sys.platform", "darwin")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        import merge_json
        mock_verify_strategy = MagicMock()
        monkeypatch.setitem(merge_json.STRATEGIES, "verify_mcp_servers", mock_verify_strategy)

        # Mock _platform_source to just return the path
        @contextlib.contextmanager
        def mock_platform_source(strategy, source):
            yield source
        monkeypatch.setattr(installer, "_platform_source", mock_platform_source)

        installer.verify_recipe("mcp-config", "claude", manifest, payload)

        args, _ = mock_verify_strategy.call_args
        assert Path(args[1]).name == ".mcp.json"
