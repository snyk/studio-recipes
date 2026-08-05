"""What happens to an *already-installed* hook when ``core.hooksPath``
changes *after* install (as opposed to ``test_hooks_path_scope.py``, which
covers an override already in place *before* install).

- Precedence: local beats global beats system - normal git config
  behavior, not something we control.
- The gap: ``FileShimStrategy`` doesn't pin ``core.hooksPath`` to stay
  where it landed. If a later change (another tool, the user, Husky)
  points it elsewhere, our hook goes silently dead. Inherent to any
  plain-hookdir-file tool; not fixed by the scope fix, which only covers
  the reverse ordering. We deliberately don't pin a local override to
  close this - that would silently disable any other hook mechanism
  protecting the repo.
- What we do fix: ``FileShimStrategy.is_installed`` detects the drift and
  reports missing (with a reason) instead of a false positive.
- The escape hatch: Git >= 2.54's declarative hook config is immune to
  all of this - orthogonal to ``core.hooksPath``, additive across scopes.
- Also verified against real Git: ``core.hooksPath`` itself didn't exist
  before 2.9.0, so ``_hooks_path_supported`` ignores any override on
  older git. ``TestHooksPathUnsupportedOnVeryOldGit`` below adapts to
  whatever git is really installed; confirmed against a from-source
  Git 2.5.3 build (see ``conftest.py``'s ``_installed_git_version``).
"""

import os
import subprocess
from pathlib import Path

import pytest

from tests.sac.conftest import (
    _configure_git_identity,
    _runtime_hook_spec,
    git_native,
    requires_git,
    requires_hooks_path_support,
)


def _set_config(scope_flag: str, workspace, key: str, value: str) -> None:
    subprocess.run(["git", "-C", str(workspace), "config", scope_flag, key, value], check=True)


@requires_git
@requires_hooks_path_support
class TestCoreHooksPathPrecedence:
    """Plain git config precedence - documented here because the rest of
    this module's behavior all follows from it. Requires git >= 2.9.0 -
    see ``TestHooksPathUnsupportedOnVeryOldGit`` for what these same
    questions look like below that."""

    def test_local_beats_global(self, workspace, monkeypatch, tmp_path_factory):
        global_config = tmp_path_factory.mktemp("global") / "gitconfig"
        global_config.write_text("[core]\n\thooksPath = /global/hooks\n", encoding="utf-8")
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
        _set_config("--local", workspace, "core.hooksPath", "/local/hooks")

        assert git_native.resolve_core_hooks_path(workspace) == Path("/local/hooks")

    def test_global_beats_system(self, workspace, monkeypatch, tmp_path_factory):
        global_config = tmp_path_factory.mktemp("global") / "gitconfig"
        global_config.write_text("[core]\n\thooksPath = /global/hooks\n", encoding="utf-8")
        system_config = tmp_path_factory.mktemp("system") / "gitconfig"
        system_config.write_text("[core]\n\thooksPath = /system/hooks\n", encoding="utf-8")
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
        monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(system_config))
        monkeypatch.delenv("GIT_CONFIG_NOSYSTEM", raising=False)

        assert git_native.resolve_core_hooks_path(workspace) == Path("/global/hooks")


@requires_git
@requires_hooks_path_support
class TestFileShimGoesDeadWhenHooksPathChangesAfterInstall:
    """Installing while core.hooksPath is unset doesn't pin it there, so
    a later change by anything else silently stops our hook running -
    not re-checked by ``install_hook`` after the fact. Requires git >=
    2.9.0 (see ``TestHooksPathUnsupportedOnVeryOldGit`` for older git,
    where the "later override" is never honored anyway).

    What *is* fixed: ``verify_hook`` detects the drift and reports
    missing with a reason instead of a false positive."""

    def test_a_later_global_override_silences_our_already_installed_hook(
        self, workspace, monkeypatch, tmp_path_factory
    ):
        _configure_git_identity(workspace)
        spec = _runtime_hook_spec(workspace, ".our-hook-fired")
        installed, path = git_native.FileShimStrategy().install(workspace, spec)
        assert installed is True
        assert Path(path) == workspace / ".git" / "hooks" / "pre-commit"

        subprocess.run(
            ["git", "-C", str(workspace), "commit", "--allow-empty", "-q", "-m", "before"],
            check=True,
        )
        assert (workspace / ".our-hook-fired").exists(), "sanity: our hook must fire before"
        (workspace / ".our-hook-fired").unlink()

        # Something else sets a global core.hooksPath after our install.
        elsewhere_hooks = tmp_path_factory.mktemp("someone-elses-global-hooks")
        global_config = tmp_path_factory.mktemp("global-config") / "gitconfig"
        global_config.write_text(
            f"[core]\n\thooksPath = {elsewhere_hooks.as_posix()}\n", encoding="utf-8"
        )
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))

        subprocess.run(
            ["git", "-C", str(workspace), "commit", "--allow-empty", "-q", "-m", "after"],
            check=True,
        )

        assert not (workspace / ".our-hook-fired").exists(), (
            "documents the current gap: our hook is silently no longer executed once "
            "core.hooksPath changes underneath it"
        )

    def test_verify_hook_detects_the_drift_instead_of_falsely_reporting_present(
        self, workspace, monkeypatch, tmp_path_factory
    ):
        """Marker text is still physically present, but core.hooksPath no
        longer points there - verify_hook must report missing (with a
        reason), not a false positive."""
        from tests.sac.conftest import SPEC, git_hooks

        _configure_git_identity(workspace)
        assert git_native.FileShimStrategy().install(workspace, SPEC)[0] is True

        elsewhere_hooks = tmp_path_factory.mktemp("someone-elses-global-hooks")
        global_config = tmp_path_factory.mktemp("global-config") / "gitconfig"
        global_config.write_text(
            f"[core]\n\thooksPath = {elsewhere_hooks.as_posix()}\n", encoding="utf-8"
        )
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
        # Config-based hooks are only reachable on real git >= 2.54; force
        # off so this test doesn't depend on the host's git version.
        monkeypatch.setattr(
            git_native.ConfigBasedHookStrategy, "check_prerequisite", lambda self, ws: False
        )

        verification = git_hooks.verify_hook(workspace, SPEC)

        assert verification.found is False
        assert verification.path == str(workspace / ".git" / "hooks" / "pre-commit")
        assert str(elsewhere_hooks) in verification.reason

    def test_a_later_local_override_moves_where_we_look_and_correctly_reports_missing(
        self, workspace, monkeypatch
    ):
        """A subtly different case from global/system drift: a *local*
        override always wins (see TestCoreHooksPathPrecedence), so once
        one is set, ``_hook_path`` itself follows it to the new location
        - there's no mismatch between "where we look" and "where git
        looks" to report as a `reason`, just a genuine "nothing has been
        installed at the new local target yet". Confirms verify_hook
        doesn't get confused and keeps reporting the *old* location's
        (now-orphaned) content as if it still counted."""
        from tests.sac.conftest import SPEC, git_hooks

        _configure_git_identity(workspace)
        old_path = git_native.FileShimStrategy().install(workspace, SPEC)[1]
        assert Path(old_path) == workspace / ".git" / "hooks" / "pre-commit"

        elsewhere_hooks = workspace.parent / "elsewhere-local-hooks"
        elsewhere_hooks.mkdir()
        _set_config("--local", workspace, "core.hooksPath", str(elsewhere_hooks))
        monkeypatch.setattr(
            git_native.ConfigBasedHookStrategy, "check_prerequisite", lambda self, ws: False
        )

        verification = git_hooks.verify_hook(workspace, SPEC)

        assert verification.found is False
        assert verification.path == str(elsewhere_hooks / "pre-commit")
        assert not (elsewhere_hooks / "pre-commit").exists()

    def test_a_later_system_override_also_silences_our_hook(
        self, workspace, monkeypatch, tmp_path_factory
    ):
        from tests.sac.conftest import SPEC, git_hooks

        _configure_git_identity(workspace)
        assert git_native.FileShimStrategy().install(workspace, SPEC)[0] is True

        elsewhere_hooks = tmp_path_factory.mktemp("someone-elses-system-hooks")
        system_config = tmp_path_factory.mktemp("system-config") / "gitconfig"
        system_config.write_text(
            f"[core]\n\thooksPath = {elsewhere_hooks.as_posix()}\n", encoding="utf-8"
        )
        monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(system_config))
        monkeypatch.delenv("GIT_CONFIG_NOSYSTEM", raising=False)
        monkeypatch.setattr(
            git_native.ConfigBasedHookStrategy, "check_prerequisite", lambda self, ws: False
        )

        verification = git_hooks.verify_hook(workspace, SPEC)

        assert verification.found is False
        assert str(elsewhere_hooks) in verification.reason

    def test_verify_hook_recovers_once_the_drift_is_undone(
        self, workspace, monkeypatch, tmp_path_factory
    ):
        """Not cached - re-evaluated fresh on every call, in both
        directions. Fixing the override (or removing it) must make
        verify_hook report the hook as genuinely protected again,
        without touching the file we originally wrote."""
        from tests.sac.conftest import SPEC, git_hooks

        _configure_git_identity(workspace)
        install_path = git_native.FileShimStrategy().install(workspace, SPEC)[1]
        monkeypatch.setattr(
            git_native.ConfigBasedHookStrategy, "check_prerequisite", lambda self, ws: False
        )

        elsewhere_hooks = tmp_path_factory.mktemp("someone-elses-global-hooks")
        global_config = tmp_path_factory.mktemp("global-config") / "gitconfig"
        global_config.write_text(
            f"[core]\n\thooksPath = {elsewhere_hooks.as_posix()}\n", encoding="utf-8"
        )
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
        assert git_hooks.verify_hook(workspace, SPEC).found is False, "sanity: drift detected"

        # The override is removed (or fixed) - our original, untouched
        # file is exactly what git looks at again.
        empty_config = tmp_path_factory.mktemp("empty-global-config") / "gitconfig"
        empty_config.write_text("", encoding="utf-8")
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(empty_config))

        verification = git_hooks.verify_hook(workspace, SPEC)

        assert verification.found is True
        assert verification.path == install_path
        assert verification.reason is None

    def test_verify_hook_surfaces_a_legacy_file_shims_drift_reason_even_once_config_based_is_preferred(
        self, workspace, monkeypatch, tmp_path_factory
    ):
        """A repo installed a FileShimStrategy hook before upgrading to a
        Git >= 2.54 machine (or ConfigBasedHookStrategy just isn't
        installed here yet). ``_select_strategy`` now prefers
        ConfigBasedHookStrategy, which has no reason of its own (it's
        just "not installed") - but the legacy file shim below it has a
        specific, more useful diagnosis (hooksPath drift). verify_hook
        must surface that instead of a bare, unexplained MISSING."""
        from tests.sac.conftest import SPEC, git_hooks

        _configure_git_identity(workspace)
        monkeypatch.setattr(
            git_native.ConfigBasedHookStrategy, "check_prerequisite", lambda self, ws: False
        )
        git_native.FileShimStrategy().install(workspace, SPEC)

        elsewhere_hooks = tmp_path_factory.mktemp("someone-elses-global-hooks")
        global_config = tmp_path_factory.mktemp("global-config") / "gitconfig"
        global_config.write_text(
            f"[core]\n\thooksPath = {elsewhere_hooks.as_posix()}\n", encoding="utf-8"
        )
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))

        # Now simulate upgrading to Git >= 2.54 - ConfigBasedHookStrategy
        # becomes the selected strategy, but was never actually installed.
        monkeypatch.setattr(
            git_native.ConfigBasedHookStrategy, "check_prerequisite", lambda self, ws: True
        )

        verification = git_hooks.verify_hook(workspace, SPEC)

        assert verification.found is False
        assert verification.kind == "git-native"
        assert verification.path == str(workspace / ".git" / "hooks" / "pre-commit")
        assert verification.reason is not None
        assert str(elsewhere_hooks) in verification.reason


def _requires_real_git_2_54(workspace) -> None:
    version = git_native._git_version(workspace)
    if version is None or version < (2, 54, 0):
        pytest.skip("requires a real Git >= 2.54 (declarative hooks); this machine has less")


@requires_git
class TestConfigBasedHookIsImmuneToHooksPathChangesAfterInstall:
    """No version shim in this class - declarative hooks only really
    behave this way on an actually-installed Git >= 2.54, so these skip
    cleanly on older real git rather than asserting something a shim can't
    make genuinely true."""

    def test_survives_a_later_global_hookspath_change(
        self, workspace, monkeypatch, tmp_path_factory
    ):
        _requires_real_git_2_54(workspace)
        _configure_git_identity(workspace)
        spec = _runtime_hook_spec(workspace, ".our-hook-fired")
        installed, _path = git_native.ConfigBasedHookStrategy().install(workspace, spec)
        assert installed is True

        elsewhere_hooks = tmp_path_factory.mktemp("someone-elses-global-hooks")
        global_config = tmp_path_factory.mktemp("global-config") / "gitconfig"
        global_config.write_text(
            f"[core]\n\thooksPath = {elsewhere_hooks.as_posix()}\n", encoding="utf-8"
        )
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))

        subprocess.run(
            ["git", "-C", str(workspace), "commit", "--allow-empty", "-q", "-m", "after"],
            check=True,
        )

        assert (workspace / ".our-hook-fired").exists(), (
            "declarative hooks must keep firing regardless of a later core.hooksPath change"
        )

    def test_coexists_with_a_later_global_declarative_hook_from_another_tool(
        self, workspace, monkeypatch, tmp_path_factory
    ):
        _requires_real_git_2_54(workspace)
        _configure_git_identity(workspace)
        spec = _runtime_hook_spec(workspace, ".our-hook-fired")
        git_native.ConfigBasedHookStrategy().install(workspace, spec)

        other_tool_script = workspace / "other_tool_hook.py"
        other_tool_script.write_text(
            "from pathlib import Path\nPath('.other-tool-fired').write_text('ok')\n",
            encoding="utf-8",
        )
        global_config = tmp_path_factory.mktemp("global-config") / "gitconfig"
        global_config.write_text(
            '[hook "other-tool"]\n'
            "\tevent = pre-commit\n"
            f"\tcommand = python3 {other_tool_script.name}\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))

        subprocess.run(
            ["git", "-C", str(workspace), "commit", "--allow-empty", "-q", "-m", "after"],
            check=True,
        )

        assert (workspace / ".our-hook-fired").exists(), "our hook must still fire"
        assert (workspace / ".other-tool-fired").exists(), (
            "the other tool's hook must also fire - declarative hooks are additive across "
            "scopes, not last-one-wins like core.hooksPath"
        )

    def test_same_hook_name_defined_globally_afterward_does_not_override_ours(
        self, workspace, monkeypatch, tmp_path_factory
    ):
        """Edge case: another tool reuses our exact hook name at a lower-
        precedence (global) scope. Normal git config precedence (local
        beats global) means our command still wins for that name."""
        _requires_real_git_2_54(workspace)
        _configure_git_identity(workspace)
        spec = _runtime_hook_spec(workspace, ".ours-fired")
        git_native.ConfigBasedHookStrategy().install(workspace, spec)

        their_script = workspace / "their_hook.py"
        their_script.write_text(
            "from pathlib import Path\nPath('.theirs-fired').write_text('ok')\n",
            encoding="utf-8",
        )
        global_config = tmp_path_factory.mktemp("global-config") / "gitconfig"
        global_config.write_text(
            f'[hook "{spec.tag}"]\n\tevent = pre-commit\n\tcommand = python3 {their_script.name}\n',
            encoding="utf-8",
        )
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))

        subprocess.run(
            ["git", "-C", str(workspace), "commit", "--allow-empty", "-q", "-m", "after"],
            check=True,
        )

        assert (workspace / ".ours-fired").exists(), "our (local) command must still run"
        assert not (workspace / ".theirs-fired").exists(), (
            "a same-named global hook must not silently replace our local one"
        )


@requires_git
class TestHooksPathUnsupportedOnVeryOldGit:
    """No ``requires_hooks_path_support`` - these adapt to whatever git
    is really on PATH via ``_hooks_path_supported`` instead of assuming.
    Confirmed against a from-source Git 2.5.3 build (see conftest.py's
    ``_installed_git_version``)."""

    def test_resolve_ignores_any_override_when_this_git_cannot_honor_it(self, workspace):
        override = workspace / "custom-hooks"
        override.mkdir()
        _set_config("--local", workspace, "core.hooksPath", "custom-hooks")

        resolved = git_native.resolve_core_hooks_path(workspace, local_only=True)

        if git_native._hooks_path_supported(workspace):
            assert resolved == override.resolve()
        else:
            assert resolved is None

    @pytest.mark.skipif(os.name == "nt", reason="POSIX git hooks + real commit only")
    def test_file_shim_writes_to_wherever_this_git_will_really_execute_a_hook(self, workspace):
        """Ground truth: a real commit proving the hook fires from
        wherever this git genuinely looks."""
        _configure_git_identity(workspace)
        override = workspace / "custom-hooks"
        override.mkdir()
        _set_config("--local", workspace, "core.hooksPath", "custom-hooks")
        spec = _runtime_hook_spec(workspace, ".hook-fired")

        installed, path = git_native.FileShimStrategy().install(workspace, spec)
        assert installed is True

        default_path = workspace / ".git" / "hooks" / "pre-commit"
        expected_path = (
            override / "pre-commit" if git_native._hooks_path_supported(workspace) else default_path
        )
        assert Path(path) == expected_path

        subprocess.run(
            ["git", "-C", str(workspace), "commit", "--allow-empty", "-q", "-m", "test"],
            check=True,
        )
        assert (workspace / ".hook-fired").read_text(encoding="utf-8") == "ok"
