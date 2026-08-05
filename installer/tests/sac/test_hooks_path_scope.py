"""Integration coverage for the ``core.hooksPath`` scope leak. Every test
drives the real installer entry points against real git repos - nothing
is mocked except the Snyk CLI itself (a fake that always reports "no
findings"), so a real commit can genuinely execute the installed hook
script without network access or a real auth token.

The bug: ``git config --get core.hooksPath`` resolves the effective value
across system/global/local scope. If a user has
``git config --global core.hooksPath ~/.git-hooks`` set, writing "wherever
git will execute a file hook" means writing repo-specific content into a
file shared across every repo on the machine - a scope leak, and a
cross-repo breakage risk if another repo lacks the referenced
``.snyk-studio/...`` files.

The fix: ``FileShimStrategy`` only honors a ``core.hooksPath`` set in the
repo's own local/worktree config, falling back to the repo's own default
hooks directory otherwise. Git >= 2.54's declarative hook config is
immune to this whole class of bug (see ``test_git_version_gate.py``), so
every test here forces it off to exercise the file-based shim specifically.

Residual limitation (see ``test_hooks_path_precedence.py``): if an
override is already in effect at install time, the repo-local file we
write is never actually executed by git. We don't paper over that with a
false success - ``install_hook`` re-verifies what it wrote and raises
``HookIntegrationSkipped`` (a loud installer ``ERROR``) instead. The
write isn't rolled back, so the repo ends up with an inert-but-confined
hook file plus an honest error, never a silent "hook installed".
"""

import os
import subprocess
from pathlib import Path

import pytest

from tests.sac.conftest import (
    SPEC,
    _configure_git_identity,
    _set_global_hooks_path,
    _set_system_hooks_path,
    _snapshot_tree,
    git_hooks,
    git_native,
    installer,
    requires_git,
    requires_hooks_path_support,
)

RECIPE_ID = "secrets-precommit-hook"
SCRIPT_DEST = Path(".snyk-studio") / "components" / "scripts" / "snyk_secrets_at_commit.py"
TAG = "snyk-secrets-at-commit"


def _install_secrets_recipe(workspace: Path, manifest, payload) -> None:
    installer.install_workspace_recipe(RECIPE_ID, manifest, payload, workspace, dry_run=False)


@pytest.fixture(autouse=True)
def _force_pre_2_54_shim(monkeypatch):
    """Pin the file-based shim path specifically - see module docstring."""
    monkeypatch.setattr(
        git_native.ConfigBasedHookStrategy, "check_prerequisite", lambda self, workspace: False
    )


@requires_git
@requires_hooks_path_support
class TestResolveCoreHooksPathScope:
    """Direct coverage of the ``local_only`` resolution mode, against a
    real repo. Requires git >= 2.9.0 (core.hooksPath support) - see
    ``test_hooks_path_precedence.py::TestHooksPathUnsupportedOnVeryOldGit``
    for older git."""

    def test_local_only_ignores_global_override(self, workspace, monkeypatch, tmp_path_factory):
        shared_global_hooks = tmp_path_factory.mktemp("shared-global-hooks")
        _set_global_hooks_path(monkeypatch, tmp_path_factory, shared_global_hooks)

        assert git_native.resolve_core_hooks_path(workspace) == shared_global_hooks
        assert git_native.resolve_core_hooks_path(workspace, local_only=True) is None

    def test_local_only_ignores_system_override(self, workspace, monkeypatch, tmp_path_factory):
        shared_system_hooks = tmp_path_factory.mktemp("shared-system-hooks")
        _set_system_hooks_path(monkeypatch, tmp_path_factory, shared_system_hooks)

        assert git_native.resolve_core_hooks_path(workspace) == shared_system_hooks
        assert git_native.resolve_core_hooks_path(workspace, local_only=True) is None

    def test_local_only_honors_explicit_local_override(self, workspace):
        override = workspace / "custom-hooks"
        override.mkdir()
        subprocess.run(
            ["git", "-C", str(workspace), "config", "--local", "core.hooksPath", "custom-hooks"],
            check=True,
        )

        assert git_native.resolve_core_hooks_path(workspace, local_only=True) == override.resolve()

    def test_local_only_prefers_local_over_global_when_both_set(
        self, workspace, monkeypatch, tmp_path_factory
    ):
        shared_global_hooks = tmp_path_factory.mktemp("shared-global-hooks")
        _set_global_hooks_path(monkeypatch, tmp_path_factory, shared_global_hooks)
        local_override = workspace / "local-hooks"
        local_override.mkdir()
        subprocess.run(
            ["git", "-C", str(workspace), "config", "--local", "core.hooksPath", "local-hooks"],
            check=True,
        )

        assert (
            git_native.resolve_core_hooks_path(workspace, local_only=True)
            == local_override.resolve()
        )

    def test_unset_returns_none_in_both_modes(self, workspace):
        assert git_native.resolve_core_hooks_path(workspace) is None
        assert git_native.resolve_core_hooks_path(workspace, local_only=True) is None


@requires_git
class TestInstallHookOnlyReportsSuccessWhenVerified:
    """Direct, library-level contract for ``git_hooks.install_hook`` -
    the exact guarantee this module's install-time behavior rests on:
    it must never return successfully unless it has confirmed git will
    actually execute what it just wrote."""

    def test_raises_when_a_global_override_prevents_the_write_from_firing(
        self, workspace, monkeypatch, tmp_path_factory
    ):
        shared_global_hooks = tmp_path_factory.mktemp("shared-global-hooks")
        _set_global_hooks_path(monkeypatch, tmp_path_factory, shared_global_hooks)

        with pytest.raises(git_hooks.HookIntegrationSkipped, match="cannot confirm"):
            git_hooks.install_hook(workspace, SPEC)

        # Not rolled back - still physically present, just not claimed as
        # a working install.
        hook = workspace / ".git" / "hooks" / "pre-commit"
        assert hook.is_file()
        assert list(shared_global_hooks.iterdir()) == []

    def test_message_says_found_not_wrote_when_a_prior_install_is_the_one_now_drifting(
        self, workspace, monkeypatch, tmp_path_factory
    ):
        """A second install_hook call against an already-installed, still
        word-for-word-identical hook doesn't rewrite anything - the error
        must say so, not claim it just wrote a file it actually left
        untouched."""
        git_hooks.install_hook(workspace, SPEC)

        shared_global_hooks = tmp_path_factory.mktemp("shared-global-hooks")
        _set_global_hooks_path(monkeypatch, tmp_path_factory, shared_global_hooks)

        with pytest.raises(git_hooks.HookIntegrationSkipped, match="found an existing"):
            git_hooks.install_hook(workspace, SPEC)

    def test_succeeds_normally_with_no_override_at_all(self, workspace):
        manager, installed, path = git_hooks.install_hook(workspace, SPEC)

        assert manager == "git-native"
        assert installed is True
        assert Path(path) == workspace / ".git" / "hooks" / "pre-commit"

    def test_succeeds_normally_with_a_genuine_local_override(self, workspace):
        override = workspace / "custom-hooks"
        override.mkdir()
        subprocess.run(
            ["git", "-C", str(workspace), "config", "--local", "core.hooksPath", "custom-hooks"],
            check=True,
        )

        manager, installed, path = git_hooks.install_hook(workspace, SPEC)

        assert manager == "git-native"
        assert installed is True
        assert Path(path) == override / "pre-commit"


@requires_git
class TestSecretsRecipeInstallIgnoresGlobalHooksPath:
    """End to end through the real installer entry points for the actual
    ``secrets-precommit-hook`` recipe - the exact surface a customer's
    install run exercises, not a synthetic ``HookSpec``."""

    def test_install_reports_an_error_instead_of_false_success_under_global_override(
        self, workspace, manifest, payload, monkeypatch, tmp_path_factory, capsys
    ):
        """Can't confirm git will run what we're about to write (a global
        override already active), so the installer must surface a loud
        error, not a false "hook installed". The write still happens and
        stays confined to the repo - just honestly reported as unverified."""
        shared_global_hooks = tmp_path_factory.mktemp("shared-global-hooks")
        _set_global_hooks_path(monkeypatch, tmp_path_factory, shared_global_hooks)
        before = _snapshot_tree(workspace.parent)

        _install_secrets_recipe(workspace, manifest, payload)

        out = capsys.readouterr().out
        assert "hook installed" not in out
        assert "ERROR" in out
        assert "pre-commit integration skipped" in out
        assert "cannot confirm git will actually execute it" in out

        script = workspace / SCRIPT_DEST
        assert script.is_file()
        hook = workspace / ".git" / "hooks" / "pre-commit"
        assert hook.is_file()
        text = hook.read_text(encoding="utf-8")
        assert TAG in text
        # Command references the workspace-local script, not an absolute
        # path or anything under the shared global hooks directory.
        assert SCRIPT_DEST.as_posix() in text
        assert str(shared_global_hooks) not in text
        assert list(shared_global_hooks.iterdir()) == []

        # Sweep the *entire* shared temp root (repo + simulated global
        # hooks dir together): every new path introduced by the install
        # must live under the repo, never under the global hooks dir.
        after = _snapshot_tree(workspace.parent)
        new_paths = after - before
        assert new_paths, "install should have created at least one new file"
        assert all(workspace.name in path.parts for path in new_paths), (
            f"install wrote outside the repo: {new_paths}"
        )

    def test_install_reports_an_error_instead_of_false_success_under_system_override(
        self, workspace, manifest, payload, monkeypatch, tmp_path_factory, capsys
    ):
        shared_system_hooks = tmp_path_factory.mktemp("shared-system-hooks")
        _set_system_hooks_path(monkeypatch, tmp_path_factory, shared_system_hooks)

        _install_secrets_recipe(workspace, manifest, payload)

        out = capsys.readouterr().out
        assert "hook installed" not in out
        assert "ERROR" in out
        assert "cannot confirm git will actually execute it" in out
        hook = workspace / ".git" / "hooks" / "pre-commit"
        assert hook.is_file()
        assert list(shared_system_hooks.iterdir()) == []

    @requires_hooks_path_support
    def test_install_still_honors_explicit_local_override(self, workspace, manifest, payload):
        """Not a leak risk - an override set directly on this repo (not
        inherited from global/system) is exactly what the repo owner asked
        for, and stays repo-specific by construction."""
        override = workspace / "custom-hooks"
        override.mkdir()
        subprocess.run(
            ["git", "-C", str(workspace), "config", "--local", "core.hooksPath", "custom-hooks"],
            check=True,
        )

        _install_secrets_recipe(workspace, manifest, payload)

        hook = override / "pre-commit"
        assert hook.is_file()
        assert TAG in hook.read_text(encoding="utf-8")

    @requires_hooks_path_support
    def test_verify_honestly_reports_missing_when_a_global_override_prevents_firing(
        self, workspace, manifest, payload, monkeypatch, tmp_path_factory, capsys
    ):
        """The residual limitation: the file shim we wrote to the repo's
        default location is never actually executed by git under an
        active global override, so verify must say MISSING, not OK -
        and the printed reason must name the actual redirected path,
        not just repeat where we looked."""
        shared_global_hooks = tmp_path_factory.mktemp("shared-global-hooks")
        _set_global_hooks_path(monkeypatch, tmp_path_factory, shared_global_hooks)
        _install_secrets_recipe(workspace, manifest, payload)
        capsys.readouterr()  # discard install output

        ok = installer.verify_workspace_recipe(RECIPE_ID, manifest, payload, workspace)

        assert ok is False
        out = capsys.readouterr().out
        assert "MISSING pre-commit shim (git-native)" in out
        assert str(workspace / ".git" / "hooks" / "pre-commit") in out
        assert "core.hooksPath now points to" in out
        assert "git won't run this file" in out

    def test_uninstall_removes_local_hook_and_leaves_global_path_untouched(
        self, workspace, manifest, payload, monkeypatch, tmp_path_factory
    ):
        shared_global_hooks = tmp_path_factory.mktemp("shared-global-hooks")
        _set_global_hooks_path(monkeypatch, tmp_path_factory, shared_global_hooks)
        _install_secrets_recipe(workspace, manifest, payload)

        installer.uninstall_workspace_recipe(RECIPE_ID, manifest, payload, workspace, dry_run=False)

        assert not (workspace / SCRIPT_DEST).exists()
        hook = workspace / ".git" / "hooks" / "pre-commit"
        if hook.exists():
            assert TAG not in hook.read_text(encoding="utf-8")
        assert list(shared_global_hooks.iterdir()) == []

    @requires_hooks_path_support
    @pytest.mark.skipif(os.name == "nt", reason="POSIX git hooks + real commit only")
    def test_real_commit_confirms_the_hook_does_not_actually_run_under_global_override(
        self, workspace, manifest, payload, monkeypatch, tmp_path_factory, fake_snyk_env
    ):
        """Ground truth: with a global override in effect, a real commit
        must not invoke the installed hook script at all - git is looking
        at the (empty) global hooks directory, not ours."""
        _configure_git_identity(workspace)
        shared_global_hooks = tmp_path_factory.mktemp("shared-global-hooks")
        _set_global_hooks_path(monkeypatch, tmp_path_factory, shared_global_hooks)
        _install_secrets_recipe(workspace, manifest, payload)

        (workspace / "app.py").write_text("print('hello')\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(workspace), "add", "app.py"], check=True)
        # fake_snyk_env snapshotted os.environ before the override above was
        # set - graft the (monkeypatch-updated) live GIT_CONFIG_GLOBAL back
        # in so the commit subprocess genuinely sees the override.
        env = {**fake_snyk_env, "GIT_CONFIG_GLOBAL": os.environ["GIT_CONFIG_GLOBAL"]}
        result = subprocess.run(
            ["git", "-C", str(workspace), "commit", "-m", "test"],
            cwd=workspace,
            env=env,
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, result.stderr
        assert "Scanning" not in result.stderr, (
            f"the hook must not have run at all: {result.stderr!r}"
        )
        assert list(shared_global_hooks.iterdir()) == []

        ok = installer.verify_workspace_recipe(RECIPE_ID, manifest, payload, workspace)
        assert ok is False, "verify must agree: this repo is not actually protected right now"


@requires_git
class TestCrossRepoIsolationUnderSharedGlobalHooksPath:
    """One machine, one global ``core.hooksPath``, two unrelated repos.
    Repo A's install must never end up somewhere repo B's commits would
    also execute, and repo B (never installed into) must be completely
    unaffected."""

    @pytest.fixture
    def two_repos(self, tmp_path, monkeypatch, tmp_path_factory):
        shared_global_hooks = tmp_path_factory.mktemp("shared-global-hooks")
        _set_global_hooks_path(monkeypatch, tmp_path_factory, shared_global_hooks)

        repo_a = tmp_path / "repo-a"
        repo_b = tmp_path / "repo-b"
        for repo in (repo_a, repo_b):
            repo.mkdir()
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            _configure_git_identity(repo)
        return repo_a, repo_b, shared_global_hooks

    def test_installing_into_one_repo_never_touches_a_sibling_repo(
        self, two_repos, manifest, payload
    ):
        repo_a, repo_b, shared_global_hooks = two_repos

        _install_secrets_recipe(repo_a, manifest, payload)

        # Repo B never got the recipe - it must have none of repo A's
        # installed assets, and a real commit in repo B must succeed
        # exactly as if the recipe had never been installed anywhere.
        assert not (repo_b / SCRIPT_DEST).exists()
        assert not (repo_b / ".git" / "hooks" / "pre-commit").exists()
        result = subprocess.run(
            ["git", "-C", str(repo_b), "commit", "--allow-empty", "-m", "untouched"],
            cwd=repo_b,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        assert list(shared_global_hooks.iterdir()) == []

    def test_each_repo_gets_its_own_isolated_local_hook_and_assets(
        self, two_repos, manifest, payload
    ):
        repo_a, repo_b, shared_global_hooks = two_repos

        _install_secrets_recipe(repo_a, manifest, payload)
        _install_secrets_recipe(repo_b, manifest, payload)

        hook_a = repo_a / ".git" / "hooks" / "pre-commit"
        hook_b = repo_b / ".git" / "hooks" / "pre-commit"
        assert hook_a.is_file()
        assert hook_b.is_file()
        assert hook_a.resolve() != hook_b.resolve()
        assert (repo_a / SCRIPT_DEST).is_file()
        assert (repo_b / SCRIPT_DEST).is_file()
        # The one thing both repos' configs "agree" on is never actually
        # written to.
        assert list(shared_global_hooks.iterdir()) == []

    def test_uninstalling_one_repo_never_touches_the_other(self, two_repos, manifest, payload):
        repo_a, repo_b, _shared_global_hooks = two_repos
        _install_secrets_recipe(repo_a, manifest, payload)
        _install_secrets_recipe(repo_b, manifest, payload)

        installer.uninstall_workspace_recipe(RECIPE_ID, manifest, payload, repo_a, dry_run=False)

        assert not (repo_a / SCRIPT_DEST).exists()
        # Repo B's install is untouched by repo A's uninstall.
        assert (repo_b / SCRIPT_DEST).is_file()
        repo_b_hook = repo_b / ".git" / "hooks" / "pre-commit"
        assert repo_b_hook.is_file()
        assert TAG in repo_b_hook.read_text(encoding="utf-8")


@requires_git
@requires_hooks_path_support
class TestHuskyDetectionUnaffectedByGlobalHooksPath:
    """Husky is a "less affected" path per the bug report - it always
    writes to the repo-local ``.husky/pre-commit`` regardless of where
    ``core.hooksPath`` is scoped, so a *legitimate* company-wide global
    Husky setup must keep working exactly as before.

    Requires git >= 2.9.0 - Husky itself only works via core.hooksPath,
    which doesn't exist at all below that."""

    def test_husky_still_selected_and_installs_locally_under_global_override(
        self, workspace, manifest, payload, monkeypatch, tmp_path_factory
    ):
        _set_global_hooks_path(monkeypatch, tmp_path_factory, workspace / ".husky")
        (workspace / ".husky").mkdir()
        (workspace / ".husky" / "pre-commit").write_text("#!/usr/bin/env sh\n", encoding="utf-8")

        _install_secrets_recipe(workspace, manifest, payload)

        husky_hook = workspace / ".husky" / "pre-commit"
        assert TAG in husky_hook.read_text(encoding="utf-8")
        native_hook = workspace / ".git" / "hooks" / "pre-commit"
        if native_hook.exists():
            assert TAG not in native_hook.read_text(encoding="utf-8")
