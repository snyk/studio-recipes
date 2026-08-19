"""Do the pre-commit framework and Husky strategies have any of the
``core.hooksPath`` scope-leak exposure ``FileShimStrategy`` had? Verified
against real git, not assumed:

- Pre-commit framework: never reads ``core.hooksPath`` - only edits
  ``<workspace>/.pre-commit-config.yaml``, so there's no code path to
  write anywhere but inside the repo.
- Husky: always writes to the hardcoded ``<workspace>/.husky/pre-commit``.
  It reads the effective ``core.hooksPath`` only to *detect* whether
  Husky is active, and that detection is itself anchored to this
  workspace (only matches ``<this workspace>/.husky[/_]``), so a shared
  global/system value can never cause a false match against some
  unrelated location.
"""

import subprocess
from pathlib import Path

import pytest

from tests.sac.conftest import (
    _set_global_hooks_path,
    _set_system_hooks_path,
    _snapshot_tree,
    git_hooks,
    git_native,
    husky,
    pre_commit,
    requires_git,
    requires_hooks_path_support,
)


def _is_relative_to(path: Path, other: Path) -> bool:
    """Path.is_relative_to requires Python 3.9+; back-port via relative_to."""
    try:
        path.relative_to(other)
    except ValueError:
        return False
    return True


@requires_git
class TestPreCommitFrameworkNeverTouchesHooksPath:
    """No amount of core.hooksPath tampering should change what this
    strategy does at all - it doesn't read that config key."""

    SPEC = git_hooks.HookSpec(tag="snyk-secrets-at-commit", command="echo hi", name="Snyk")

    def _make_yaml(self, workspace: Path) -> Path:
        path = workspace / ".pre-commit-config.yaml"
        path.write_text("repos: []\n", encoding="utf-8")
        return path

    @pytest.mark.parametrize("scope", ["global", "system", "none"])
    def test_install_verify_uninstall_unaffected_by_hookspath_scope(
        self, workspace, monkeypatch, tmp_path_factory, scope
    ):
        elsewhere = tmp_path_factory.mktemp("unrelated-hooks-dir")
        if scope == "global":
            _set_global_hooks_path(monkeypatch, tmp_path_factory, elsewhere)
        elif scope == "system":
            _set_system_hooks_path(monkeypatch, tmp_path_factory, elsewhere)

        yaml_path = self._make_yaml(workspace)
        strategy = pre_commit.PreCommitFrameworkStrategy()
        assert strategy.check_prerequisite(workspace) is True

        installed, path = strategy.install(workspace, self.SPEC)
        assert installed is True
        assert Path(path) == yaml_path
        assert self.SPEC.tag in yaml_path.read_text(encoding="utf-8")

        ok, _, _ = strategy.is_installed(workspace, self.SPEC)
        assert ok is True

        removed, _ = strategy.safe_uninstall(workspace, self.SPEC)
        assert removed is True
        assert self.SPEC.tag not in yaml_path.read_text(encoding="utf-8")

        # Nothing was ever written outside the repo, regardless of scope.
        assert list(elsewhere.iterdir()) == []

    def test_file_hook_path_is_always_inside_the_workspace(self, workspace):
        self._make_yaml(workspace)
        strategy = pre_commit.PreCommitFrameworkStrategy()
        path = strategy.file_hook_path(workspace)
        assert path is not None
        assert _is_relative_to(
            git_native.normalize_path(path), git_native.normalize_path(workspace)
        )


@requires_git
class TestHuskyOnlyEverActivatesForThisWorkspacesOwnHuskyDir:
    def _write_husky_file(self, workspace: Path) -> Path:
        husky_dir = workspace / ".husky"
        husky_dir.mkdir(exist_ok=True)
        path = husky_dir / "pre-commit"
        path.write_text("#!/usr/bin/env sh\necho existing-husky-step\n", encoding="utf-8")
        return path

    def test_unrelated_global_override_does_not_falsely_trigger_husky(
        self, workspace, monkeypatch, tmp_path_factory
    ):
        """A stale ``.husky/pre-commit`` left over from disuse must not be
        mistaken for "Husky is active" just because some unrelated global
        core.hooksPath is set."""
        self._write_husky_file(workspace)
        unrelated = tmp_path_factory.mktemp("unrelated-global-hooks")
        _set_global_hooks_path(monkeypatch, tmp_path_factory, unrelated)

        assert husky.HuskyStrategy().check_prerequisite(workspace) is False
        manager = git_hooks._select_strategy(workspace, git_hooks.HOOK_STRATEGIES).integration_kind
        assert manager != "husky"

    def test_unrelated_system_override_does_not_falsely_trigger_husky(
        self, workspace, monkeypatch, tmp_path_factory
    ):
        self._write_husky_file(workspace)
        unrelated = tmp_path_factory.mktemp("unrelated-system-hooks")
        _set_system_hooks_path(monkeypatch, tmp_path_factory, unrelated)

        assert husky.HuskyStrategy().check_prerequisite(workspace) is False

    @requires_hooks_path_support
    def test_legitimate_global_husky_override_writes_only_inside_the_workspace(
        self, workspace, monkeypatch, tmp_path_factory
    ):
        """A company-wide dotfiles setup with a relative global override -
        unlike an absolute one, this resolves independently per repo, so
        it never causes cross-repo leakage."""
        self._write_husky_file(workspace)
        global_config_dir = tmp_path_factory.mktemp("global-config")
        global_config = global_config_dir / "gitconfig"
        global_config.write_text("[core]\n\thooksPath = .husky\n", encoding="utf-8")
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
        before = _snapshot_tree(global_config_dir)

        assert husky.HuskyStrategy().check_prerequisite(workspace) is True

        manager, installed, path = git_hooks.install_hook(
            workspace,
            git_hooks.HookSpec(
                tag="snyk-secrets-at-commit", command="echo unique-marker", name="X"
            ),
        )

        assert manager == "husky"
        assert installed is True
        assert Path(path) == workspace / ".husky" / "pre-commit"
        assert "echo unique-marker" in Path(path).read_text(encoding="utf-8")

        # Nothing was written outside the repo.
        assert _snapshot_tree(global_config_dir) == before

    @requires_hooks_path_support
    def test_two_repos_sharing_a_global_relative_husky_override_stay_independent(
        self, tmp_path, monkeypatch, tmp_path_factory
    ):
        global_config = tmp_path_factory.mktemp("global-config") / "gitconfig"
        global_config.write_text("[core]\n\thooksPath = .husky\n", encoding="utf-8")
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))

        repo_a = tmp_path / "repo-a"
        repo_b = tmp_path / "repo-b"
        for repo in (repo_a, repo_b):
            repo.mkdir()
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            self._write_husky_file(repo)

        spec_a = git_hooks.HookSpec(tag="snyk-secrets-at-commit", command="echo A", name="X")
        spec_b = git_hooks.HookSpec(tag="snyk-secrets-at-commit", command="echo B", name="X")
        _manager_a, _installed_a, path_a = git_hooks.install_hook(repo_a, spec_a)
        _manager_b, _installed_b, path_b = git_hooks.install_hook(repo_b, spec_b)

        text_a = Path(path_a).read_text(encoding="utf-8")
        text_b = Path(path_b).read_text(encoding="utf-8")
        assert Path(path_a) == repo_a / ".husky" / "pre-commit"
        assert Path(path_b) == repo_b / ".husky" / "pre-commit"
        assert "echo A" in text_a
        assert "echo A" not in text_b
        assert "echo B" in text_b
        assert "echo B" not in text_a

    def test_husky_write_path_is_structurally_always_inside_the_workspace(self, workspace):
        """Even without any core.hooksPath at all, pin that Husky's write
        target can never resolve outside the repo - it's a hardcoded
        workspace-relative join, not derived from any config value."""
        path = husky.HuskyStrategy().file_hook_path(workspace)
        assert path is not None
        assert _is_relative_to(
            git_native.normalize_path(path), git_native.normalize_path(workspace)
        )
