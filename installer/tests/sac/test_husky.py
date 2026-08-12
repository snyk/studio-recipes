"""Husky pre-commit integration: marked-block install/uninstall into an
existing .husky/pre-commit, and real-commit firing."""

import os
import subprocess
from pathlib import Path

import pytest

from tests.sac.conftest import (
    SPEC,
    _commit_tracked_file,
    _configure_git_identity,
    _runtime_hook_spec,
    git_hooks,
    git_native,
    requires_git,
    requires_hooks_path_support,
)


@requires_git
@requires_hooks_path_support
class TestHusky:
    @pytest.fixture
    def husky_workspace(self, workspace):
        subprocess.run(
            ["git", "-C", str(workspace), "config", "core.hooksPath", ".husky"],
            check=True,
        )
        (workspace / ".husky").mkdir()
        (workspace / ".husky" / "pre-commit").write_text("#!/usr/bin/env sh\necho husky-stage\n")
        return workspace

    def test_install_appends_and_preserves_existing(self, husky_workspace):
        manager, installed, path = git_hooks.install_hook(husky_workspace, SPEC)
        assert manager == "husky"
        assert installed is True
        text = Path(path).read_text()
        assert "echo husky-stage" in text
        assert SPEC.command in text

    def test_uninstall_leaves_existing_step(self, husky_workspace):
        git_hooks.install_hook(husky_workspace, SPEC)
        _, removed, _ = git_hooks.uninstall_hook(husky_workspace, SPEC)
        assert removed is True
        text = (husky_workspace / ".husky" / "pre-commit").read_text()
        assert "echo husky-stage" in text
        assert SPEC.begin_marker not in text

    def test_verify_and_uninstall_ignore_non_utf8_existing_hook(self, husky_workspace):
        hook = husky_workspace / ".husky" / "pre-commit"
        original = b"\xff\xfe\x00"
        hook.write_bytes(original)

        _, ok, _, _ = git_hooks.verify_hook(husky_workspace, SPEC)
        assert ok is False
        _, removed, _ = git_hooks.uninstall_hook(husky_workspace, SPEC)
        assert removed is False
        assert hook.read_bytes() == original

    @requires_git
    def test_install_cleans_stale_git_config_without_removing_husky_hooks_path(self, workspace):
        subprocess.run(
            ["git", "-C", str(workspace), "config", "core.hooksPath", ".husky"],
            check=True,
        )
        (workspace / ".husky").mkdir()
        hook = workspace / ".husky" / "pre-commit"
        hook.write_text("#!/usr/bin/env sh\necho husky-stage\n", encoding="utf-8")
        config_strategy = git_native.ConfigBasedHookStrategy()
        config_strategy.install(workspace, SPEC)

        manager, installed, _ = git_hooks.install_hook(workspace, SPEC)

        config_ok, _, _ = config_strategy.is_installed(workspace, SPEC)
        text = hook.read_text(encoding="utf-8")
        assert manager == "husky"
        assert installed is True
        assert config_ok is False
        assert "echo husky-stage" in text
        assert SPEC.begin_marker in text

    @requires_git
    @pytest.mark.skipif(os.name == "nt", reason="Husky pre-commit scripts are POSIX shell scripts")
    def test_installed_husky_hook_runs_with_existing_husky_v9_style_script(self, workspace):
        _configure_git_identity(workspace)
        subprocess.run(
            ["git", "-C", str(workspace), "config", "core.hooksPath", ".husky/_"],
            check=True,
        )
        (workspace / ".husky" / "_").mkdir(parents=True)
        (workspace / ".husky" / "_" / "husky.sh").write_text("# no-op compatibility shim\n")
        dispatcher = workspace / ".husky" / "_" / "pre-commit"
        dispatcher.write_text(
            '#!/usr/bin/env sh\n. "$(dirname "$0")/husky.sh"\nsh "$(dirname "$0")/../pre-commit"',
            encoding="utf-8",
        )
        dispatcher.chmod(0o755)
        (workspace / ".husky" / "pre-commit").write_text(
            '#!/usr/bin/env sh\n. "$(dirname "$0")/_/husky.sh"\nprintf existing > .husky-existing',
            encoding="utf-8",
        )

        manager, installed, _ = git_hooks.install_hook(
            workspace, _runtime_hook_spec(workspace, ".husky-snyk")
        )

        assert manager == "husky"
        assert installed is True
        _commit_tracked_file(workspace, "husky hook")
        assert (workspace / ".husky-existing").read_text(encoding="utf-8") == "existing"
        assert (workspace / ".husky-snyk").read_text(encoding="utf-8") == "ok"

    @requires_git
    @pytest.mark.skipif(os.name == "nt", reason="POSIX git hooks only")
    def test_stale_husky_hook_falls_through_to_git_native_and_runs(self, workspace, monkeypatch):
        _configure_git_identity(workspace)
        subprocess.run(
            ["git", "-C", str(workspace), "config", "core.hooksPath", "custom-hooks"],
            check=True,
        )
        (workspace / ".husky").mkdir()
        stale_husky_hook = workspace / ".husky" / "pre-commit"
        stale_husky_hook.write_text("#!/usr/bin/env sh\necho stale-husky\n", encoding="utf-8")
        monkeypatch.setattr(
            git_native.ConfigBasedHookStrategy, "check_prerequisite", lambda self, ws: False
        )

        manager, installed, path = git_hooks.install_hook(
            workspace, _runtime_hook_spec(workspace, ".native-snyk")
        )

        assert manager == "git-native"
        assert installed is True
        assert Path(path) == workspace / "custom-hooks" / "pre-commit"
        assert SPEC.begin_marker not in stale_husky_hook.read_text(encoding="utf-8")
        verify_manager, ok, verify_path, _reason = git_hooks.verify_hook(
            workspace, _runtime_hook_spec(workspace, ".native-snyk")
        )
        assert verify_manager == "git-native"
        assert ok is True
        assert Path(verify_path) == workspace / "custom-hooks" / "pre-commit"

        _commit_tracked_file(workspace, "stale husky falls through")
        assert (workspace / ".native-snyk").read_text(encoding="utf-8") == "ok"

    @requires_git
    @pytest.mark.skipif(os.name == "nt", reason="Husky pre-commit scripts are POSIX shell scripts")
    def test_first_blocking_recipe_is_not_masked_by_a_second_passing_one(self, workspace):
        """secure-at-commit and secrets-precommit-hook are both workspace-scoped and can both
        append their own command block to the same .husky/pre-commit. Without
        `|| exit $?`, a failing first block's exit status gets silently
        overwritten by whatever the second (unrelated, later-appended) block
        exits with -- here, a passing one -- and the commit wrongly succeeds."""
        _configure_git_identity(workspace)
        subprocess.run(
            ["git", "-C", str(workspace), "config", "core.hooksPath", ".husky"],
            check=True,
        )
        (workspace / ".husky").mkdir()
        (workspace / ".husky" / "pre-commit").write_text("#!/usr/bin/env sh\n")

        blocking_spec = git_hooks.HookSpec(
            tag="fake-blocking-recipe",
            command='python3 -c "import sys; sys.exit(1)"',
            name="Fake Blocking Recipe",
        )
        git_hooks.install_hook(workspace, blocking_spec)
        # Appended after the blocking block -- always exits 0.
        manager, installed, _ = git_hooks.install_hook(workspace, _runtime_hook_spec(workspace))
        assert manager == "husky"
        assert installed is True

        result = subprocess.run(
            ["git", "-C", str(workspace), "commit", "--allow-empty", "-m", "test"],
            cwd=workspace,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0

    @requires_git
    @pytest.mark.skipif(os.name == "nt", reason="Husky pre-commit scripts are POSIX shell scripts")
    def test_second_blocking_recipe_still_blocks_after_a_passing_first_one(self, workspace):
        """Mirror of the case above: the first (passing) block must not
        prevent a failing second block from blocking the commit."""
        _configure_git_identity(workspace)
        subprocess.run(
            ["git", "-C", str(workspace), "config", "core.hooksPath", ".husky"],
            check=True,
        )
        (workspace / ".husky").mkdir()
        (workspace / ".husky" / "pre-commit").write_text("#!/usr/bin/env sh\n")

        manager, installed, _ = git_hooks.install_hook(workspace, _runtime_hook_spec(workspace))
        assert manager == "husky"
        assert installed is True
        blocking_spec = git_hooks.HookSpec(
            tag="fake-blocking-recipe",
            command='python3 -c "import sys; sys.exit(1)"',
            name="Fake Blocking Recipe",
        )
        git_hooks.install_hook(workspace, blocking_spec)

        result = subprocess.run(
            ["git", "-C", str(workspace), "commit", "--allow-empty", "-m", "test"],
            cwd=workspace,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert (workspace / ".hook-fired").read_text(encoding="utf-8") == "ok"

    @requires_git
    @pytest.mark.skipif(os.name == "nt", reason="Husky pre-commit scripts are POSIX shell scripts")
    def test_blocking_command_with_trailing_comment_is_not_masked_by_a_later_passing_hook(
        self, workspace
    ):
        """A trailing comment used to swallow `|| exit $?`. A lone hook
        "works" by accident even with the bug -- needs a second hook to
        actually catch the masking."""
        _configure_git_identity(workspace)
        subprocess.run(
            ["git", "-C", str(workspace), "config", "core.hooksPath", ".husky"],
            check=True,
        )
        (workspace / ".husky").mkdir()
        (workspace / ".husky" / "pre-commit").write_text("#!/usr/bin/env sh\n")

        blocking_spec = git_hooks.HookSpec(
            tag="fake-blocking-recipe-with-comment",
            command='python3 -c "import sys; sys.exit(1)"  # trailing comment',
            name="Fake Blocking Recipe With Comment",
        )
        git_hooks.install_hook(workspace, blocking_spec)
        # Appended after the blocking block -- always exits 0.
        manager, installed, _ = git_hooks.install_hook(workspace, _runtime_hook_spec(workspace))
        assert manager == "husky"
        assert installed is True

        result = subprocess.run(
            ["git", "-C", str(workspace), "commit", "--allow-empty", "-m", "test"],
            cwd=workspace,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0

    @requires_git
    @pytest.mark.skipif(os.name == "nt", reason="Husky pre-commit scripts are POSIX shell scripts")
    def test_installed_husky_hook_runs_on_real_commit(self, workspace):
        _configure_git_identity(workspace)
        subprocess.run(
            ["git", "-C", str(workspace), "config", "core.hooksPath", ".husky"],
            check=True,
        )
        (workspace / ".husky").mkdir()
        (workspace / ".husky" / "pre-commit").write_text("#!/usr/bin/env sh\n")

        manager, installed, _ = git_hooks.install_hook(workspace, _runtime_hook_spec(workspace))
        assert manager == "husky"
        assert installed is True

        _commit_tracked_file(workspace, "test husky hook")

        assert (workspace / ".hook-fired").read_text(encoding="utf-8") == "ok"
