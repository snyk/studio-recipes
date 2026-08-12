"""install_workspace_recipe/verify_workspace_recipe warn when a local
secrets-precommit-hook install would double-fire with an active
secrets-precommit-hook-global, without ever altering what gets installed."""

import pytest

from tests.sac.conftest import _configure_git_identity, _set_home, git_hooks, git_native, installer

LOCAL_RECIPE_ID = "secrets-precommit-hook"
GLOBAL_RECIPE_ID = "secrets-precommit-hook-global"
TAG = "snyk-secrets-at-commit"


@pytest.fixture(autouse=True)
def _force_git_2_54(git_version_shim_factory):
    """Both recipes are gated on git >= 2.54 - shim it for determinism."""
    git_version_shim_factory("2.54.0")


@pytest.fixture
def home(tmp_path, monkeypatch):
    home_dir = tmp_path / "fake-home"
    home_dir.mkdir()
    _set_home(monkeypatch, home_dir)
    return home_dir


def _install_global(manifest, payload):
    installer.install_git_global_recipe(GLOBAL_RECIPE_ID, manifest, payload, dry_run=False)


def _spec():
    return git_hooks.HookSpec(tag=TAG, command="true", name="test")


class TestNoWarningWhenGlobalHookIsNotActive:
    """Baseline: no false positives when there's nothing to double-fire with."""

    def test_install_prints_no_warning(self, home, workspace, manifest, payload, capsys):
        _configure_git_identity(workspace)
        installer.install_workspace_recipe(
            LOCAL_RECIPE_ID, manifest, payload, workspace, dry_run=False
        )
        assert "WARNING" not in capsys.readouterr().out

    def test_verify_prints_no_warning(self, home, workspace, manifest, payload, capsys):
        _configure_git_identity(workspace)
        installer.install_workspace_recipe(
            LOCAL_RECIPE_ID, manifest, payload, workspace, dry_run=False
        )
        capsys.readouterr()
        installer.verify_workspace_recipe(LOCAL_RECIPE_ID, manifest, payload, workspace)
        assert "WARNING" not in capsys.readouterr().out

    def test_helper_reports_false(self, home, workspace, manifest, payload):
        _configure_git_identity(workspace)
        installer.install_workspace_recipe(
            LOCAL_RECIPE_ID, manifest, payload, workspace, dry_run=False
        )
        assert git_hooks.local_install_double_fires_with_global(workspace, _spec()) is False


class TestSameTagShadowsGlobalForFree:
    """Local resolves to ConfigBasedHookStrategy - same declarative
    subsystem as the global hook, so local config wins. No warning."""

    def test_helper_reports_false_when_local_would_use_declarative_config(
        self, home, workspace, manifest, payload
    ):
        _configure_git_identity(workspace)
        _install_global(manifest, payload)
        assert git_hooks.local_install_shadows_global_for_free(workspace, _spec()) is True
        assert git_hooks.local_install_double_fires_with_global(workspace, _spec()) is False

    def test_install_prints_no_warning_when_global_already_active(
        self, home, workspace, manifest, payload, capsys
    ):
        _configure_git_identity(workspace)
        _install_global(manifest, payload)

        installer.install_workspace_recipe(
            LOCAL_RECIPE_ID, manifest, payload, workspace, dry_run=False
        )

        out = capsys.readouterr().out
        assert "WARNING" not in out
        assert "hook installed" in out or "hook unchanged" in out

    def test_verify_prints_no_warning_when_global_already_active(
        self, home, workspace, manifest, payload, capsys
    ):
        _configure_git_identity(workspace)
        _install_global(manifest, payload)
        installer.install_workspace_recipe(
            LOCAL_RECIPE_ID, manifest, payload, workspace, dry_run=False
        )
        capsys.readouterr()

        ok = installer.verify_workspace_recipe(LOCAL_RECIPE_ID, manifest, payload, workspace)

        out = capsys.readouterr().out
        assert ok is True
        assert "WARNING" not in out
        assert "OK" in out

    def test_uninstalling_local_reports_hook_missing_but_global_recipe_still_reports_ok(
        self, home, workspace, manifest, payload, capsys
    ):
        """Local and global commands differ even for the same tag, so
        removing the local override correctly reports MISSING locally,
        while the global recipe's own verify still reports OK."""
        _configure_git_identity(workspace)
        _install_global(manifest, payload)
        installer.install_workspace_recipe(
            LOCAL_RECIPE_ID, manifest, payload, workspace, dry_run=False
        )
        installer.uninstall_workspace_recipe(
            LOCAL_RECIPE_ID, manifest, payload, workspace, dry_run=False
        )
        capsys.readouterr()

        local_ok = installer.verify_workspace_recipe(LOCAL_RECIPE_ID, manifest, payload, workspace)
        local_out = capsys.readouterr().out

        global_ok = installer.verify_git_global_recipe(GLOBAL_RECIPE_ID, manifest, payload)

        assert local_ok is False
        assert "MISSING pre-commit shim" in local_out
        assert "WARNING" not in local_out
        assert global_ok is True


class TestDoubleFireWhenLocalIsNotDeclarative:
    """Local resolves to Husky/pre-commit-framework/file-shim - a separate
    git subsystem, so both fire. Install still proceeds; only warns."""

    @pytest.fixture(autouse=True)
    def _force_local_to_file_shim(self, monkeypatch):
        monkeypatch.setattr(
            git_native.ConfigBasedHookStrategy, "check_prerequisite", lambda self, workspace: False
        )

    def test_helper_reports_true(self, home, workspace, manifest, payload):
        _configure_git_identity(workspace)
        _install_global(manifest, payload)
        assert git_hooks.local_install_shadows_global_for_free(workspace, _spec()) is False
        assert git_hooks.local_install_double_fires_with_global(workspace, _spec()) is True

    def test_install_still_installs_the_real_local_hook_and_warns(
        self, home, workspace, manifest, payload, capsys
    ):
        _configure_git_identity(workspace)
        _install_global(manifest, payload)

        installer.install_workspace_recipe(
            LOCAL_RECIPE_ID, manifest, payload, workspace, dry_run=False
        )

        out = capsys.readouterr().out
        assert "hook installed" in out or "hook unchanged" in out
        assert "WARNING" in out
        assert "global hook" in out

        hook_file = workspace / ".git" / "hooks" / "pre-commit"
        assert hook_file.exists()
        assert TAG in hook_file.read_text(encoding="utf-8")

    def test_verify_still_reports_ok_and_warns(self, home, workspace, manifest, payload, capsys):
        _configure_git_identity(workspace)
        _install_global(manifest, payload)
        installer.install_workspace_recipe(
            LOCAL_RECIPE_ID, manifest, payload, workspace, dry_run=False
        )
        capsys.readouterr()

        ok = installer.verify_workspace_recipe(LOCAL_RECIPE_ID, manifest, payload, workspace)

        out = capsys.readouterr().out
        assert ok is True
        assert "WARNING" in out

    def test_warns_regardless_of_whether_global_was_installed_in_the_same_run_or_earlier(
        self, home, workspace, manifest, payload, capsys
    ):
        """Both a prior-run global install and a same-run one warn - both
        reduce to the same live check."""
        _configure_git_identity(workspace)

        _install_global(manifest, payload)
        capsys.readouterr()
        installer.install_workspace_recipe(
            LOCAL_RECIPE_ID, manifest, payload, workspace, dry_run=False
        )
        assert "WARNING" in capsys.readouterr().out

        installer.uninstall_workspace_recipe(
            LOCAL_RECIPE_ID, manifest, payload, workspace, dry_run=False
        )
        capsys.readouterr()
        _install_global(manifest, payload)
        installer.install_workspace_recipe(
            LOCAL_RECIPE_ID, manifest, payload, workspace, dry_run=False
        )
        assert "WARNING" in capsys.readouterr().out

    def test_documented_limitation_local_installed_before_global_is_not_retroactively_warned_at_install_time(
        self, home, workspace, manifest, payload, capsys
    ):
        """install_workspace_recipe only warns at the moment it runs; a
        later verify (a live check) does catch the global hook showing up
        afterward."""
        _configure_git_identity(workspace)

        installer.install_workspace_recipe(
            LOCAL_RECIPE_ID, manifest, payload, workspace, dry_run=False
        )
        assert "WARNING" not in capsys.readouterr().out

        _install_global(manifest, payload)
        capsys.readouterr()

        installer.verify_workspace_recipe(LOCAL_RECIPE_ID, manifest, payload, workspace)
        assert "WARNING" in capsys.readouterr().out

    def test_uninstalling_local_removes_the_local_hook_but_global_still_protects(
        self, home, workspace, manifest, payload, capsys
    ):
        _configure_git_identity(workspace)
        _install_global(manifest, payload)
        installer.install_workspace_recipe(
            LOCAL_RECIPE_ID, manifest, payload, workspace, dry_run=False
        )

        installer.uninstall_workspace_recipe(
            LOCAL_RECIPE_ID, manifest, payload, workspace, dry_run=False
        )

        hook_file = workspace / ".git" / "hooks" / "pre-commit"
        assert not hook_file.exists() or TAG not in hook_file.read_text(encoding="utf-8")
        assert git_hooks.is_global_hook_active_for_tag(TAG) is True


class TestShadowCheckUsesTheActuallyActiveStrategy:
    """A stale local file-shim install (from before this machine's git was
    upgraded to >= 2.54) must still be recognized as double-firing with the
    global hook - the "shadows for free" property only holds for the
    declarative strategy that's actually active, not whichever one a fresh
    install would pick today."""

    def test_stale_file_shim_still_double_fires_even_though_config_is_now_preferred(
        self, home, workspace, manifest, payload
    ):
        _configure_git_identity(workspace)
        spec = _spec()
        # Simulates a file shim installed before this machine's git was
        # upgraded to >= 2.54 (the autouse shim reports 2.54 for every
        # check from here on) - now stale, but still the actually-active
        # mechanism regardless of what a fresh install would pick today.
        git_native.FileShimStrategy().install(workspace, spec)

        assert git_hooks.local_install_shadows_global_for_free(workspace, spec) is False
        _install_global(manifest, payload)
        assert git_hooks.local_install_double_fires_with_global(workspace, spec) is True
