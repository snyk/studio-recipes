"""Git-native pre-commit strategies: version-gated selection between
declarative git config hooks (git >= 2.54) and a file-based shim that
writes to core.hooksPath if set, else .git/hooks/pre-commit -- plus the
marker-stripping safety net shared by every file-based strategy."""

import os
import subprocess
from pathlib import Path
from typing import List, Optional

import pytest

from tests.sac.conftest import (
    SPEC,
    _commit_tracked_file,
    _configure_git_identity,
    _init_git_repo,
    _runtime_hook_spec,
    git_hooks,
    git_native,
    husky,
    marked_files,
    pre_commit,
    requires_git,
)


class TestHookStrategySelection:
    def _selected_integration_kind(self, workspace: Path) -> str:
        return git_hooks._select_strategy(workspace, git_hooks.HOOK_STRATEGIES).integration_kind

    def test_detects_pre_commit_framework(self, workspace):
        (workspace / ".pre-commit-config.yaml").write_text("repos: []\n")
        assert self._selected_integration_kind(workspace) == "pre-commit"

    def test_detects_pre_commit_framework_yml(self, workspace):
        (workspace / ".pre-commit-config.yml").write_text("repos: []\n")
        assert self._selected_integration_kind(workspace) == "pre-commit"

    @requires_git
    def test_detects_husky(self, workspace):
        subprocess.run(
            ["git", "-C", str(workspace), "config", "core.hooksPath", ".husky"],
            check=True,
        )
        (workspace / ".husky").mkdir()
        (workspace / ".husky" / "pre-commit").write_text("#!/usr/bin/env sh\n")
        assert self._selected_integration_kind(workspace) == "husky"

    @requires_git
    def test_detects_husky_v9_hooks_path(self, workspace):
        subprocess.run(
            ["git", "-C", str(workspace), "config", "core.hooksPath", ".husky/_"],
            check=True,
        )
        (workspace / ".husky").mkdir()
        (workspace / ".husky" / "pre-commit").write_text("#!/usr/bin/env sh\n")
        assert self._selected_integration_kind(workspace) == "husky"

    @requires_git
    def test_detects_husky_with_normalized_hooks_path(self, workspace):
        (workspace / ".husky").mkdir()
        (workspace / ".husky" / "pre-commit").write_text("#!/usr/bin/env sh\n")

        for hooks_path in (
            "./.husky",
            str(workspace / ".husky"),
            "./.husky/_",
            str(workspace / ".husky" / "_"),
        ):
            subprocess.run(
                ["git", "-C", str(workspace), "config", "core.hooksPath", hooks_path],
                check=True,
            )
            assert self._selected_integration_kind(workspace) == "husky"

    @requires_git
    def test_stale_husky_file_with_unset_hooks_path_is_git_native(self, workspace):
        (workspace / ".husky").mkdir()
        (workspace / ".husky" / "pre-commit").write_text("#!/usr/bin/env sh\n")
        assert self._selected_integration_kind(workspace) == "git-native"

    @requires_git
    def test_stale_husky_file_with_other_hooks_path_is_git_native(self, workspace):
        subprocess.run(
            ["git", "-C", str(workspace), "config", "core.hooksPath", "custom-hooks"],
            check=True,
        )
        (workspace / ".husky").mkdir()
        (workspace / ".husky" / "pre-commit").write_text("#!/usr/bin/env sh\n")
        assert self._selected_integration_kind(workspace) == "git-native"

    @requires_git
    def test_prefers_precommit_over_husky(self, workspace):
        subprocess.run(
            ["git", "-C", str(workspace), "config", "core.hooksPath", ".husky"],
            check=True,
        )
        (workspace / ".pre-commit-config.yaml").write_text("repos: []\n")
        (workspace / ".husky").mkdir()
        (workspace / ".husky" / "pre-commit").write_text("#!/usr/bin/env sh\n")
        assert self._selected_integration_kind(workspace) == "pre-commit"

    def test_falls_back_to_git_native(self, workspace):
        assert self._selected_integration_kind(workspace) == "git-native"


class TestSelfPropagatingBlock:
    """Covers the shared exit-propagation wrapper."""

    def test_normal_command_is_wrapped_in_a_brace_group(self):
        block = marked_files._self_propagating_block("echo hi")
        assert block == "{\necho hi\n} || exit $?"

    def test_trailing_shell_comment_cannot_swallow_the_exit_check(self):
        block = marked_files._self_propagating_block("python3 foo.py  # a note")
        lines = block.splitlines()
        assert lines[-1] == "} || exit $?"
        assert "#" not in lines[-1]


class TestWriteHookTextForcesLfNewlines:
    """Windows regression: text file writes with newline=None
    translates \\n to os.linesep -- \\r\\n on native Windows Python. That
    would corrupt _self_propagating_block's brace-group syntax (a bare
    "{"/"}" with a trailing \\r isn't a valid shell reserved word;
    confirmed by literally running such a script under sh). Hook files
    are never git-tracked, so nothing else normalizes this. os.linesep
    is already "\\n" on the platform running this test, so the raw
    bytes look identical either way -- this asserts newline="\\n" is
    passed explicitly rather than relying on that happening to be true
    here."""

    @staticmethod
    def _spy_newline_kwarg(monkeypatch) -> List[Optional[str]]:
        recorded: List[Optional[str]] = []
        real_open = Path.open

        def spy(self: Path, *args: object, **kwargs: object) -> object:
            mode = str(args[0] if args else kwargs.get("mode", "r"))
            if "w" in mode or "a" in mode:
                recorded.append(kwargs.get("newline"))  # type: ignore[arg-type]
            return real_open(self, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(Path, "open", spy)
        return recorded

    def test_install_forces_lf(self, tmp_path, monkeypatch):
        path = tmp_path / "hook"
        path.write_text("#!/usr/bin/env sh\n")
        recorded = self._spy_newline_kwarg(monkeypatch)

        marked_files._install_marked_file(
            path,
            SPEC,
            marked_files._self_propagating_block(SPEC.command),
            marked_files.MarkedFilePolicy(label="hook", missing_error="missing"),
        )
        assert recorded
        assert all(n == "\n" for n in recorded)

    def test_uninstall_forces_lf(self, tmp_path, monkeypatch):
        path = tmp_path / "hook"
        path.write_text(
            f"#!/usr/bin/env sh\n{SPEC.begin_marker}\nbody\n{SPEC.end_marker}\nkeep-me\n"
        )
        recorded = self._spy_newline_kwarg(monkeypatch)

        marked_files._uninstall_marked_file(
            path, SPEC, marked_files.MarkedFilePolicy(label="hook", missing_error="missing")
        )
        assert recorded
        assert all(n == "\n" for n in recorded)


class TestStripBlockMalformedSafety:
    """PR feedback: the previous non-greedy ``.*?`` in ``_strip_block``
    would span across a duplicated begin marker, silently consuming the
    orphan and every line up to the next end. The tempered pattern now in
    place refuses to match when an intervening begin marker is present,
    so a corrupted file preserves user content instead of losing it."""

    SPEC = git_hooks.HookSpec(
        tag="snyk-secure-at-commit", command="fake", name="Snyk Secure At Commit"
    )

    def test_well_formed_block_is_still_removed(self):
        """Regression: a single well-formed block must still be stripped."""
        text = f"before\n{self.SPEC.begin_marker}\nin block\n{self.SPEC.end_marker}\nafter\n"
        result = marked_files._strip_block(text, self.SPEC)
        assert "in block" not in result
        assert "before\n" in result
        assert "after\n" in result

    def test_two_independent_well_formed_blocks_both_removed(self):
        """Regression: two separate, well-formed blocks are both stripped —
        tempering must not regress the common multi-install case."""
        text = (
            f"{self.SPEC.begin_marker}\nblock1\n{self.SPEC.end_marker}\n"
            "middle\n"
            f"{self.SPEC.begin_marker}\nblock2\n{self.SPEC.end_marker}\n"
        )
        result = marked_files._strip_block(text, self.SPEC)
        assert "block1" not in result
        assert "block2" not in result
        assert "middle" in result

    def test_orphan_begin_does_not_swallow_adjacent_user_content(self):
        """The bug shape: BEGIN1 ... BEGIN2 ... END (orphan begin from a
        failed manual edit). The OLD regex would have matched from BEGIN1
        all the way to the END and silently deleted BEGIN2 plus every
        line between them — destroying any user content sitting between
        the orphan begin and the next begin marker. The tempered regex
        refuses to span across BEGIN2 from BEGIN1's match attempt, so the
        adjacent user content (between BEGIN1 and BEGIN2) is preserved.

        The isolated BEGIN2-END pair still looks well-formed in itself
        and gets removed — that's the right call: well-formed pairs are
        assumed to be a previous SAC install we're cleaning up. The user
        is then left with the orphan BEGIN1 still in the file so they
        can see the broken state and decide what to do."""
        text = (
            "before\n"
            f"{self.SPEC.begin_marker}\n"
            "user content adjacent to the orphan begin\n"
            f"{self.SPEC.begin_marker}\n"
            "content inside the well-formed inner pair\n"
            f"{self.SPEC.end_marker}\n"
            "after\n"
        )
        result = marked_files._strip_block(text, self.SPEC)
        # The critical bit: data adjacent to the orphan survives. Without
        # the tempered match the old regex would have eaten this.
        assert "user content adjacent to the orphan begin" in result
        # The orphan BEGIN itself is still in the file — visible enough
        # that a user will notice and clean it up manually.
        assert self.SPEC.begin_marker in result
        # The isolated well-formed inner pair gets removed as a normal
        # SAC-block cleanup. Its content was always within our markers.
        assert "content inside the well-formed inner pair" not in result

    def test_orphan_begin_without_end_is_left_intact(self):
        """A begin marker with no closing end: nothing to strip; the file
        is left unchanged. Don't try to clever-recover a malformed file."""
        text = (
            "before\n"
            f"{self.SPEC.begin_marker}\n"
            "trailing content with no closing end marker\n"
            "after\n"
        )
        result = marked_files._strip_block(text, self.SPEC)
        assert "trailing content with no closing end marker" in result
        assert self.SPEC.begin_marker in result

    def test_isolated_pair_after_orphan_is_still_removed(self):
        """Mixed shape: an orphan BEGIN followed by adjacent user content,
        then two normal BEGIN-END pairs. The orphan's adjacent content
        survives; the two isolated pairs (assumed to be previous SAC
        installs) are still cleaned. Partial cleanup is the right call —
        refusing to strip ANY blocks just because one orphan exists would
        make a single corrupted file derail every subsequent install."""
        text = (
            f"{self.SPEC.begin_marker}\n"  # orphan BEGIN1
            "adjacent-to-orphan body\n"
            f"{self.SPEC.begin_marker}\n"  # opens isolated pair
            "first isolated pair body\n"
            f"{self.SPEC.end_marker}\n"  # closes isolated pair
            "between blocks\n"
            f"{self.SPEC.begin_marker}\n"  # opens second isolated pair
            "second isolated pair body\n"
            f"{self.SPEC.end_marker}\n"
        )
        result = marked_files._strip_block(text, self.SPEC)
        # Orphan-adjacent user content survives.
        assert "adjacent-to-orphan body" in result
        # Both isolated well-formed pairs get cleaned.
        assert "first isolated pair body" not in result
        assert "second isolated pair body" not in result
        # Material between the cleaned blocks survives.
        assert "between blocks" in result
        # Exactly one BEGIN marker (the orphan) remains so the user can
        # see and repair the broken state.
        assert result.count(self.SPEC.begin_marker) == 1

    def test_unrelated_marker_tag_is_untouched(self):
        """Markers from a different tag don't match this spec — installs
        for unrelated tools must coexist without interference."""
        other_begin = "# >>> other-tool >>>"
        other_end = "# <<< other-tool <<<"
        text = f"before\n{other_begin}\ncontent\n{other_end}\nafter\n"
        result = marked_files._strip_block(text, self.SPEC)
        assert result == text


class TestGitNative:
    @pytest.fixture(autouse=True)
    def _force_pre_2_54_shim(self, monkeypatch):
        """This suite exercises the file-based shim (``FileShimStrategy``)
        specifically — force ``ConfigBasedHookStrategy``'s prerequisite off so
        these tests aren't sensitive to whether the machine running them
        happens to have Git 2.54+ installed. Config-based hooks get their own
        dedicated coverage separately.
        """
        monkeypatch.setattr(
            git_native.ConfigBasedHookStrategy, "check_prerequisite", lambda self, workspace: False
        )

    def test_install_creates_hook_with_default_header(self, workspace):
        manager, installed, path = git_hooks.install_hook(workspace, SPEC)
        assert manager == "git-native"
        assert installed is True
        content = Path(path).read_text()
        assert SPEC.begin_marker in content
        assert SPEC.command in content
        assert SPEC.end_marker in content
        assert content.startswith("#!/usr/bin/env sh")

    def test_install_appends_to_existing_hook(self, workspace):
        hook = workspace / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/usr/bin/env bash\nexisting-step\n")
        _, installed, _ = git_hooks.install_hook(workspace, SPEC)
        assert installed is True
        text = hook.read_text()
        assert "existing-step" in text
        assert SPEC.command in text

    def test_install_is_idempotent(self, workspace):
        git_hooks.install_hook(workspace, SPEC)
        _, second, _ = git_hooks.install_hook(workspace, SPEC)
        assert second is False  # nothing changed
        hook = workspace / ".git" / "hooks" / "pre-commit"
        # Only one tagged block remains.
        assert hook.read_text().count(SPEC.begin_marker) == 1

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits only")
    def test_install_sets_executable_bit(self, workspace):
        _, _, path = git_hooks.install_hook(workspace, SPEC)
        mode = Path(path).stat().st_mode
        assert mode & 0o111, f"hook not executable: {oct(mode)}"

    def test_uninstall_round_trips(self, workspace):
        git_hooks.install_hook(workspace, SPEC)
        _, removed, _ = git_hooks.uninstall_hook(workspace, SPEC)
        assert removed is True
        # Default header was all we wrote, so the file is dropped entirely.
        assert not (workspace / ".git" / "hooks" / "pre-commit").exists()

    def test_uninstall_preserves_other_steps(self, workspace):
        hook = workspace / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/usr/bin/env sh\necho other\n")
        git_hooks.install_hook(workspace, SPEC)
        git_hooks.uninstall_hook(workspace, SPEC)
        text = hook.read_text()
        assert "echo other" in text
        assert SPEC.begin_marker not in text

    def test_verify_reflects_installed_state(self, workspace):
        _, ok, _ = git_hooks.verify_hook(workspace, SPEC)
        assert ok is False
        git_hooks.install_hook(workspace, SPEC)
        _, ok, _ = git_hooks.verify_hook(workspace, SPEC)
        assert ok is True

    def test_verify_and_uninstall_ignore_non_utf8_existing_hook(self, workspace):
        hook = workspace / ".git" / "hooks" / "pre-commit"
        original = b"\xff\xfe\x00"
        hook.write_bytes(original)

        _, ok, _ = git_hooks.verify_hook(workspace, SPEC)
        assert ok is False
        _, removed, _ = git_hooks.uninstall_hook(workspace, SPEC)
        assert removed is False
        assert hook.read_bytes() == original

    def test_install_without_git_raises(self, tmp_path):
        # No .git/ at all.
        with pytest.raises(FileNotFoundError):
            git_hooks.install_hook(tmp_path, SPEC)

    @requires_git
    @pytest.mark.skipif(os.name == "nt", reason="POSIX git hooks only")
    def test_existing_native_hook_without_trailing_newline_runs_with_installed_block(
        self, workspace
    ):
        _configure_git_identity(workspace)
        hook = workspace / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/usr/bin/env sh\nprintf existing > .native-existing", encoding="utf-8")

        _, installed, _ = git_hooks.install_hook(
            workspace, _runtime_hook_spec(workspace, ".native-snyk")
        )

        assert installed is True
        _commit_tracked_file(workspace, "native hook")
        assert (workspace / ".native-existing").read_text(encoding="utf-8") == "existing"
        assert (workspace / ".native-snyk").read_text(encoding="utf-8") == "ok"

    @requires_git
    @pytest.mark.skipif(os.name == "nt", reason="POSIX git hooks only")
    def test_hooks_path_existing_hook_runs_with_installed_block(self, workspace):
        _configure_git_identity(workspace)
        hooks_dir = workspace / "custom-hooks"
        hooks_dir.mkdir()
        hook = hooks_dir / "pre-commit"
        hook.write_text("#!/usr/bin/env sh\nprintf hooks-path > .hooks-path-existing\n")
        subprocess.run(
            ["git", "-C", str(workspace), "config", "core.hooksPath", "custom-hooks"],
            check=True,
        )

        _, installed, path = git_hooks.install_hook(
            workspace, _runtime_hook_spec(workspace, ".hooks-path-snyk")
        )

        assert installed is True
        assert path.endswith(str(Path("custom-hooks") / "pre-commit"))
        assert not (workspace / ".git" / "hooks" / "pre-commit").exists()
        _commit_tracked_file(workspace, "hooks path")
        assert (workspace / ".hooks-path-existing").read_text(encoding="utf-8") == "hooks-path"
        assert (workspace / ".hooks-path-snyk").read_text(encoding="utf-8") == "ok"

    @requires_git
    @pytest.mark.skipif(os.name == "nt", reason="POSIX git hooks only")
    def test_first_blocking_recipe_is_not_masked_by_a_second_passing_one(self, workspace):
        """secure-at-commit and secrets-precommit-hook are both workspace-scoped and can both
        append their own command block to the same .git/hooks/pre-commit --
        if it already existed (e.g. from another tool) without `set -e`
        (only seeded when we create the file from scratch), a failing first
        block's exit status must not get silently overwritten by a later,
        unrelated passing block. See install_husky's identical concern."""
        _configure_git_identity(workspace)
        hook = workspace / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/usr/bin/env sh\n")  # pre-existing, no set -e

        blocking_spec = git_hooks.HookSpec(
            tag="fake-blocking-recipe",
            command='python3 -c "import sys; sys.exit(1)"',
            name="Fake Blocking Recipe",
        )
        git_hooks.install_hook(workspace, blocking_spec)
        # Appended after the blocking block -- always exits 0.
        manager, installed, _ = git_hooks.install_hook(workspace, _runtime_hook_spec(workspace))
        assert manager == "git-native"
        assert installed is True

        result = subprocess.run(
            ["git", "-C", str(workspace), "commit", "--allow-empty", "-m", "test"],
            cwd=workspace,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0

    @requires_git
    @pytest.mark.skipif(os.name == "nt", reason="POSIX git hooks only")
    def test_second_blocking_recipe_still_blocks_after_a_passing_first_one(self, workspace):
        """Mirror of the case above: the first (passing) block must not
        prevent a failing second block from blocking the commit."""
        _configure_git_identity(workspace)
        hook = workspace / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/usr/bin/env sh\n")  # pre-existing, no set -e

        manager, installed, _ = git_hooks.install_hook(workspace, _runtime_hook_spec(workspace))
        assert manager == "git-native"
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
    @pytest.mark.skipif(os.name == "nt", reason="POSIX git hooks only")
    def test_blocking_command_with_trailing_comment_is_not_masked_by_a_later_passing_hook(
        self, workspace
    ):
        """A trailing comment used to swallow `|| exit $?`. A lone hook
        "works" by accident even with the bug -- needs a second hook to
        actually catch the masking."""
        _configure_git_identity(workspace)
        hook = workspace / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/usr/bin/env sh\n")  # pre-existing, no set -e

        blocking_spec = git_hooks.HookSpec(
            tag="fake-blocking-recipe-with-comment",
            command='python3 -c "import sys; sys.exit(1)"  # trailing comment',
            name="Fake Blocking Recipe With Comment",
        )
        git_hooks.install_hook(workspace, blocking_spec)
        # Appended after the blocking block -- always exits 0.
        manager, installed, _ = git_hooks.install_hook(workspace, _runtime_hook_spec(workspace))
        assert manager == "git-native"
        assert installed is True

        result = subprocess.run(
            ["git", "-C", str(workspace), "commit", "--allow-empty", "-m", "test"],
            cwd=workspace,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0


class TestConfigBasedHookStrategy:
    pytestmark = requires_git

    """Direct coverage of ConfigBasedHookStrategy's git-config storage.

    Calls the strategy's own methods (not the check_prerequisite-gated
    dispatch) since config read/write works against any real git version —
    no version shim needed here.
    """

    def _set_config(self, workspace: Path, key: str, value: str) -> None:
        subprocess.run(
            ["git", "-C", str(workspace), "config", "--local", "--replace-all", key, value],
            check=True,
        )

    def _get_config(self, workspace: Path, key: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", "-C", str(workspace), "config", "--get", key],
            capture_output=True,
            text=True,
        )

    def test_install_uninstall_round_trip(self, workspace):
        strategy = git_native.ConfigBasedHookStrategy()
        installed, path = strategy.install(workspace, SPEC)
        assert installed is True
        assert "hook." in path

        ok, _ = strategy.is_installed(workspace, SPEC)
        assert ok is True

        removed, _ = strategy.safe_uninstall(workspace, SPEC)
        assert removed is True
        ok, _ = strategy.is_installed(workspace, SPEC)
        assert ok is False

    def test_reinstall_after_git_upgrade_replaces_file_shim_with_config_hook(
        self, workspace, monkeypatch
    ):
        git_native.FileShimStrategy().install(workspace, SPEC)
        file_hook = workspace / ".git" / "hooks" / "pre-commit"
        assert SPEC.begin_marker in file_hook.read_text(encoding="utf-8")
        monkeypatch.setattr(
            git_native.ConfigBasedHookStrategy, "check_prerequisite", lambda self, ws: True
        )

        manager, installed, path = git_hooks.install_hook(workspace, SPEC)

        strategy = git_native.ConfigBasedHookStrategy()
        config_ok, _ = strategy.is_installed(workspace, SPEC)
        assert manager == "git-native"
        assert installed is True
        assert path == f"{strategy._section(SPEC)} (git config)"
        assert config_ok is True
        if file_hook.exists():
            assert SPEC.begin_marker not in file_hook.read_text(encoding="utf-8")

    def test_reinstall_with_config_hook_already_ok_removes_stale_file_shim(
        self, workspace, monkeypatch
    ):
        strategy = git_native.ConfigBasedHookStrategy()
        strategy.install(workspace, SPEC)
        git_native.FileShimStrategy().install(workspace, SPEC)
        file_hook = workspace / ".git" / "hooks" / "pre-commit"
        assert SPEC.begin_marker in file_hook.read_text(encoding="utf-8")
        monkeypatch.setattr(
            git_native.ConfigBasedHookStrategy, "check_prerequisite", lambda self, ws: True
        )

        manager, installed, path = git_hooks.install_hook(workspace, SPEC)

        config_ok, _ = strategy.is_installed(workspace, SPEC)
        assert manager == "git-native"
        assert installed is True
        assert path == f"{strategy._section(SPEC)} (git config)"
        assert config_ok is True
        if file_hook.exists():
            assert SPEC.begin_marker not in file_hook.read_text(encoding="utf-8")

    def test_reinstall_after_git_downgrade_replaces_config_hook_with_file_shim(
        self, workspace, monkeypatch
    ):
        strategy = git_native.ConfigBasedHookStrategy()
        strategy.install(workspace, SPEC)
        monkeypatch.setattr(
            git_native.ConfigBasedHookStrategy, "check_prerequisite", lambda self, ws: False
        )

        manager, installed, path = git_hooks.install_hook(workspace, SPEC)

        config_ok, _ = strategy.is_installed(workspace, SPEC)
        file_hook = workspace / ".git" / "hooks" / "pre-commit"
        assert manager == "git-native"
        assert installed is True
        assert path == str(file_hook)
        assert config_ok is False
        assert SPEC.begin_marker in file_hook.read_text(encoding="utf-8")

    def test_install_replaces_config_based_hook_with_old_command(self, workspace):
        strategy = git_native.ConfigBasedHookStrategy()
        section = strategy._section(SPEC)
        self._set_config(workspace, f"{section}.event", "pre-commit")
        self._set_config(
            workspace,
            f"{section}.command",
            "uv run .snyk/studio/components/scripts/snyk_secure_at_commit.py --staged",
        )

        installed, _ = strategy.install(workspace, SPEC)

        command = self._get_config(workspace, f"{section}.command")
        assert installed is True
        assert command.stdout.strip() == SPEC.command

    def test_safe_uninstall_removes_config_based_hook_with_old_command(self, workspace):
        strategy = git_native.ConfigBasedHookStrategy()
        section = strategy._section(SPEC)
        self._set_config(workspace, f"{section}.event", "pre-commit")
        self._set_config(
            workspace,
            f"{section}.command",
            "uv run .snyk/studio/components/scripts/snyk_secure_at_commit.py --staged",
        )

        removed, _ = strategy.safe_uninstall(workspace, SPEC)

        assert removed is True
        assert self._get_config(workspace, f"{section}.event").returncode != 0
        assert self._get_config(workspace, f"{section}.command").returncode != 0

    def test_safe_uninstall_cleans_up_orphaned_event_with_no_command(self, workspace):
        """Regression test for a partial install: if `.event` got written but
        `.command` never did (e.g. the second git-config call failed), the
        orphaned `.event` key must still be cleaned up by safe_uninstall —
        it must not check `.command` presence alone to decide there's
        nothing to remove, since that leaves a stale `hook.<tag>.event`
        entry with no corresponding command, invisible to every future
        install/uninstall call.
        """
        strategy = git_native.ConfigBasedHookStrategy()
        section = strategy._section(SPEC)
        self._set_config(workspace, f"{section}.event", "pre-commit")

        removed, _ = strategy.safe_uninstall(workspace, SPEC)

        leftover = self._get_config(workspace, f"{section}.event")
        assert removed is True, "safe_uninstall must report removing the orphaned .event key"
        assert leftover.returncode != 0, (
            f"orphaned {section}.event survived safe_uninstall: {leftover.stdout!r}"
        )

    def test_distinct_tags_do_not_collide_in_config_section(self):
        """Regression test: _config_safe_tag must not map two different tags
        to the same git config section — otherwise a second hook (tag
        differing only in punctuation) would silently overwrite the first
        hook's .command/.event on install.
        """
        tag_a = git_native.ConfigBasedHookStrategy._config_safe_tag("foo!bar")
        tag_b = git_native.ConfigBasedHookStrategy._config_safe_tag("foo?bar")
        assert tag_a != tag_b, (
            f"'foo!bar' and 'foo?bar' both normalize to {tag_a!r} — "
            "two distinct hook tags would collide into the same config section"
        )

    def test_distinct_tags_do_not_collide_via_variable_width_hex(self):
        """Regression test for a subtler collision: escaping each unsafe
        character with a *variable*-width hex ordinal (e.g. plain ``ord()``)
        is ambiguous, since hex digits are themselves passthrough characters
        — a single high-codepoint escape (``chr(0x1234)`` -> ``_1234``) is
        indistinguishable from a short escape followed by passthrough digits
        (``chr(0x12)`` + literal ``"34"`` -> also ``_1234``). Every escape
        must be a fixed width (one ``_XX`` per UTF-8 byte) so this can't
        happen.
        """
        tag_a = git_native.ConfigBasedHookStrategy._config_safe_tag(chr(0x1234))
        tag_b = git_native.ConfigBasedHookStrategy._config_safe_tag(chr(0x12) + "34")
        assert tag_a != tag_b, (
            f"chr(0x1234) and chr(0x12)+'34' both normalize to {tag_a!r} — "
            "variable-width hex escaping collides across codepoint boundaries"
        )

    def test_run_git_throws_raises_real_error_with_real_stderr(self, workspace):
        with pytest.raises(subprocess.CalledProcessError) as excinfo:
            git_native._run_git_throws(workspace, ["config", "--get", "no.such.key"])
        assert excinfo.value.returncode != 0

    def test_run_git_throws_returns_completed_process_on_success(self, workspace):
        result = git_native._run_git_throws(workspace, ["config", "--local", "foo.bar", "baz"])
        assert isinstance(result, subprocess.CompletedProcess)
        assert result.returncode == 0

    def test_install_propagates_real_exception_and_rolls_back(self, workspace, monkeypatch):
        """If `.command` fails after `.event` already wrote for real, the real
        exception (not a generic message) must propagate, and the partial
        `.event` write must be rolled back rather than left orphaned."""
        strategy = git_native.ConfigBasedHookStrategy()
        section = strategy._section(SPEC)
        real_run_git_throws = git_native._run_git_throws
        calls = []

        def fake_run_git_throws(ws, args, timeout=5.0):
            calls.append(args)
            if len(calls) == 1:
                return real_run_git_throws(ws, args, timeout)
            raise subprocess.CalledProcessError(1, args, output="", stderr="disk full (simulated)")

        monkeypatch.setattr(git_native, "_run_git_throws", fake_run_git_throws)

        # CalledProcessError.__str__ doesn't include .stderr — assert on the
        # real attribute, not the exception's string form.
        with pytest.raises(subprocess.CalledProcessError) as excinfo:
            strategy.install(workspace, SPEC)
        assert "disk full" in excinfo.value.stderr

        leftover = subprocess.run(
            ["git", "-C", str(workspace), "config", "--get", f"{section}.event"],
            capture_output=True,
            text=True,
        )
        assert leftover.returncode != 0, "partial .event write must be rolled back on failure"

    def test_install_hook_falls_back_on_real_native_failure(self, workspace, monkeypatch, caplog):
        """A real failure in the highest-precedence strategy's install() must
        fall back to the next eligible strategy, with the real error visible
        (not silently swallowed)."""
        monkeypatch.setattr(
            git_native.ConfigBasedHookStrategy, "check_prerequisite", lambda self, ws: True
        )

        def boom(self, ws, spec):
            raise subprocess.CalledProcessError(
                1, ["git", "config"], stderr="simulated config failure"
            )

        monkeypatch.setattr(git_native.ConfigBasedHookStrategy, "install", boom)

        with caplog.at_level("WARNING", logger="git_hooks"):
            manager, installed, path = git_hooks.install_hook(workspace, SPEC)

        assert manager == "git-native"
        assert installed is True
        assert "(git config)" not in path  # fell back to a file-based strategy
        assert any("simulated config failure" in record.message for record in caplog.records)

    def test_verify_hook_finds_existing_file_shim_when_config_strategy_is_preferred(
        self, workspace, monkeypatch
    ):
        git_native.FileShimStrategy().install(workspace, SPEC)
        monkeypatch.setattr(
            git_native.ConfigBasedHookStrategy, "check_prerequisite", lambda self, ws: True
        )

        manager, ok, path = git_hooks.verify_hook(workspace, SPEC)

        assert manager == "git-native"
        assert ok is True
        assert path.endswith(str(Path(".git") / "hooks" / "pre-commit"))

    def test_verify_hook_finds_stale_native_shim_when_precommit_is_preferred_but_unintegrated(
        self, workspace
    ):
        """A ``.pre-commit-config.yaml`` existing makes
        ``PreCommitFrameworkStrategy`` the primary selection, but a stale
        git-native shim from an earlier install must still count as
        verified protection - a broken/missing pre-commit integration must
        not report MISSING when the repo is still genuinely protected by an
        older mechanism."""
        git_native.FileShimStrategy().install(workspace, SPEC)
        (workspace / ".pre-commit-config.yaml").write_text("repos: []\n", encoding="utf-8")

        manager, ok, path = git_hooks.verify_hook(workspace, SPEC)

        assert manager == "git-native"
        assert ok is True
        assert path.endswith(str(Path(".git") / "hooks" / "pre-commit"))


class TestFallbackEligibleDefaults:
    """``fallback_eligible`` is what the dispatcher uses to decide whether a
    failed strategy can be retried with a sibling (see ``_install_candidates``
    and ``verify_hook`` in ``git_hooks.py``) - pin the defaults directly so a
    future strategy can't silently end up in the wrong group."""

    def test_base_hook_strategy_defaults_to_false(self):
        assert git_hooks.HookStrategy.fallback_eligible is False

    def test_git_native_strategies_are_fallback_eligible(self):
        assert git_native.GitNativeStrategy.fallback_eligible is True
        assert git_native.ConfigBasedHookStrategy.fallback_eligible is True
        assert git_native.FileShimStrategy.fallback_eligible is True

    def test_pre_commit_and_husky_are_not_fallback_eligible(self):
        assert pre_commit.PreCommitFrameworkStrategy.fallback_eligible is False
        assert husky.HuskyStrategy.fallback_eligible is False


class TestFileShimStrategyFallbackSafety:
    """``FileShimStrategy`` is the only file-based git-native mechanism left
    - if ``ConfigBasedHookStrategy`` fails and it fails too, there is
    nothing left to fall back to. A failure here must raise, never be
    swallowed by silently doing nothing."""

    def test_install_hook_raises_real_last_native_error_when_all_fail(self, workspace, monkeypatch):
        monkeypatch.setattr(
            git_native.ConfigBasedHookStrategy, "check_prerequisite", lambda self, ws: True
        )

        def config_boom(self, ws, spec):
            raise subprocess.CalledProcessError(1, ["git", "config"], stderr="config-fail")

        def shim_boom(self, ws, spec):
            raise OSError("shim-fail")

        monkeypatch.setattr(git_native.ConfigBasedHookStrategy, "install", config_boom)
        monkeypatch.setattr(git_native.FileShimStrategy, "install", shim_boom)

        with pytest.raises(OSError, match="shim-fail"):
            git_hooks.install_hook(workspace, SPEC)

        assert not (workspace / ".git" / "hooks" / "pre-commit").exists()

    def test_install_hook_raises_runtime_error_when_no_candidate_remains_eligible(
        self, workspace, monkeypatch
    ):
        """``_select_strategy`` and ``_install_candidates`` each re-check
        ``check_prerequisite`` independently; if a strategy passes the
        first check but fails the second, there are no candidates left to
        attempt at all - the dispatcher must raise rather than silently
        doing nothing."""
        calls = {"n": 0}

        def flaky_check(self, ws):
            calls["n"] += 1
            return calls["n"] == 1  # eligible only the first time it's asked

        monkeypatch.setattr(git_native.ConfigBasedHookStrategy, "check_prerequisite", flaky_check)
        monkeypatch.setattr(
            git_native.FileShimStrategy, "check_prerequisite", lambda self, ws: False
        )

        with pytest.raises(RuntimeError, match="no hook strategy could be attempted"):
            git_hooks.install_hook(workspace, SPEC)

    @requires_git
    def test_install_hook_raises_instead_of_writing_to_git_hooks_dir_when_override_set_and_shim_fails(
        self, workspace, monkeypatch
    ):
        """git ignores ``.git/hooks/pre-commit`` whenever ``core.hooksPath``
        points elsewhere, so a failed write to the override location must
        never be papered over by writing there anyway."""
        override = workspace / "custom-hooks"
        override.mkdir()
        subprocess.run(
            ["git", "-C", str(workspace), "config", "core.hooksPath", str(override)],
            check=True,
        )
        monkeypatch.setattr(
            git_native.ConfigBasedHookStrategy, "check_prerequisite", lambda self, ws: False
        )

        def shim_boom(self, ws, spec):
            raise OSError("permission denied writing override hook")

        monkeypatch.setattr(git_native.FileShimStrategy, "install", shim_boom)

        with pytest.raises(OSError, match="permission denied"):
            git_hooks.install_hook(workspace, SPEC)

        assert not (workspace / ".git" / "hooks" / "pre-commit").exists()
        assert list(override.iterdir()) == []


class TestWorktreeAndSubmoduleGitdirFile:
    """``.git`` may be a file with a ``gitdir:`` pointer instead of a
    directory (worktrees and submodules). A submodule's gitdir is its own
    standalone repo, so the pointer target is used as-is. A worktree's
    gitdir is private to that worktree and has no hooks of its own - git
    always runs hooks from the *common* gitdir every worktree shares,
    identified by a ``commondir`` file inside the private gitdir - so
    ``_git_hook_default_path`` must follow that file back to the common
    dir instead of using the worktree's private gitdir directly (which
    would silently install a hook git never executes)."""

    def test_submodule_style_absolute_pointer_with_no_commondir_is_used_as_is(self, tmp_path):
        workspace = tmp_path / "submodule"
        workspace.mkdir()
        external = tmp_path / "external-gitdir"
        external.mkdir()
        (workspace / ".git").write_text(f"gitdir: {external}\n")

        resolved = git_native._git_hook_default_path(workspace)

        assert resolved == external / "hooks" / "pre-commit"

    def test_submodule_style_relative_pointer_is_resolved_against_workspace(self, tmp_path):
        workspace = tmp_path / "submodule"
        workspace.mkdir()
        (tmp_path / "external-gitdir").mkdir()
        (workspace / ".git").write_text("gitdir: ../external-gitdir\n")

        resolved = git_native._git_hook_default_path(workspace)

        assert resolved == (tmp_path / "external-gitdir" / "hooks" / "pre-commit")

    def test_worktree_style_pointer_with_commondir_resolves_to_common_gitdir(self, tmp_path):
        common_dir = tmp_path / "main" / ".git"
        private_gitdir = common_dir / "worktrees" / "wt"
        private_gitdir.mkdir(parents=True)
        (private_gitdir / "commondir").write_text("../..\n")

        workspace = tmp_path / "wt"
        workspace.mkdir()
        (workspace / ".git").write_text(f"gitdir: {private_gitdir}\n")

        resolved = git_native._git_hook_default_path(workspace)

        assert resolved == common_dir / "hooks" / "pre-commit"

    def test_commondir_preserves_spaces_in_path(self, tmp_path):
        common_dir = tmp_path / "common git "
        common_dir.mkdir()
        private_gitdir = tmp_path / "private-gitdir"
        private_gitdir.mkdir()
        (private_gitdir / "commondir").write_text("../common git \n")

        workspace = tmp_path / "wt"
        workspace.mkdir()
        (workspace / ".git").write_text(f"gitdir: {private_gitdir}\n")

        resolved = git_native._git_hook_default_path(workspace)

        assert resolved == common_dir / "hooks" / "pre-commit"

    @requires_git
    def test_install_and_commit_in_a_real_worktree(self, tmp_path, monkeypatch):
        """End-to-end: a real ``git worktree add`` checkout, hook installed
        via ``FileShimStrategy``, fires on a real commit made from
        the worktree - pins the commondir resolution above against git's
        actual hook-lookup behaviour, not just a hand-built fixture."""
        main_repo = tmp_path / "main"
        _init_git_repo(main_repo)
        _configure_git_identity(main_repo)
        subprocess.run(
            ["git", "-C", str(main_repo), "commit", "--allow-empty", "-q", "-m", "init"],
            check=True,
        )
        worktree = tmp_path / "wt"
        subprocess.run(
            ["git", "-C", str(main_repo), "worktree", "add", str(worktree), "-b", "feature"],
            check=True,
        )
        monkeypatch.setattr(
            git_native.ConfigBasedHookStrategy, "check_prerequisite", lambda self, ws: False
        )

        manager, installed, path = git_hooks.install_hook(worktree, _runtime_hook_spec(worktree))

        assert manager == "git-native"
        assert installed is True
        assert not (worktree / ".git").is_dir()  # confirms this is really the gitdir-file case
        assert Path(path) == main_repo / ".git" / "hooks" / "pre-commit"

        _commit_tracked_file(worktree, "worktree hook")
        assert (worktree / ".hook-fired").read_text(encoding="utf-8") == "ok"
