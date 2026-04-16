"""Tests for snyk-studio-installer.py (cross-platform Python installer)."""

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

    def test_detects_both(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        (tmp_path / ".cursor").mkdir()
        (tmp_path / ".claude").mkdir()
        result = installer.detect_ades()
        assert result == ["cursor", "claude"]

    def test_detects_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        # Mock pgrep to not find cursor process
        mock_run = MagicMock(return_value=MagicMock(returncode=1))
        monkeypatch.setattr("subprocess.run", mock_run)
        result = installer.detect_ades()
        assert result == []

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

    def test_get_sources_missing_ade(self, manifest):
        sources = manifest.get_sources("sai-hooks-async", "vscode")
        assert sources == {}


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
# TestLifecycle
# ===========================================================================

class TestLifecycle:
    """Integration test: install -> verify -> uninstall with temp HOME."""

    @pytest.fixture
    def fake_home(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".cursor").mkdir()
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

    def test_dry_run_makes_no_changes(self, fake_home, payload, manifest):
        recipes = manifest.resolve_recipes("default")
        for recipe_id in recipes:
            installer.install_recipe(recipe_id, "claude", manifest, payload, dry_run=True)

        assert not (fake_home / ".claude" / "hooks" / "snyk_secure_at_inception.py").exists()
