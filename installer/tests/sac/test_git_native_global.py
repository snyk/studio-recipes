"""``GlobalConfigBasedHookStrategy``: git >= 2.54 declarative ``hook.<tag>.*``
config at ``--global`` scope, immune to a repo's local core.hooksPath."""

import subprocess
from pathlib import Path
from typing import Optional

import pytest

from tests.sac.conftest import (
    SPEC,
    _configure_git_identity,
    _runtime_hook_spec,
    git_hooks,
    git_native,
    requires_git,
)


def _requires_real_git_2_54(workspace: Optional[Path] = None) -> None:
    """Skip on real git < 2.54; the version shim can't fake the real git on PATH."""
    version = git_native._git_version(workspace or Path.cwd())
    if version is None or version < (2, 54, 0):
        pytest.skip("requires a real Git >= 2.54 (declarative hooks); this machine has less")


@requires_git
class TestGlobalConfigBasedHookStrategy:
    """Isolated from the real ``~/.gitconfig`` by conftest's autouse fixture."""

    def test_install_uninstall_round_trip(self):
        strategy = git_native.GlobalConfigBasedHookStrategy()

        installed, path = strategy.install(SPEC)
        assert installed is True
        assert "hook." in path
        assert "global git config" in path

        check = strategy.is_installed(SPEC)
        assert check.installed is True

        removed, _ = strategy.safe_uninstall(SPEC)
        assert removed is True
        check = strategy.is_installed(SPEC)
        assert check.installed is False

    def test_install_is_idempotent(self):
        strategy = git_native.GlobalConfigBasedHookStrategy()

        first_installed, _ = strategy.install(SPEC)
        second_installed, _ = strategy.install(SPEC)

        assert first_installed is True
        assert second_installed is False  # already matched, nothing changed

    def test_uninstall_when_never_installed_is_a_safe_noop(self):
        removed, _ = git_native.GlobalConfigBasedHookStrategy().safe_uninstall(SPEC)
        assert removed is False

    @pytest.mark.parametrize(
        ("version", "expected"),
        [((2, 54, 0), True), ((2, 53, 99), False), ((2, 9, 0), False), ((3, 0, 0), True)],
    )
    def test_check_prerequisite_gates_at_2_54(self, git_version_shim_factory, version, expected):
        git_version_shim_factory(".".join(str(part) for part in version))
        assert git_native.GlobalConfigBasedHookStrategy().check_prerequisite() is expected

    def test_check_prerequisite_matches_real_git_ground_truth(self, workspace):
        """No shim - cross-checks against this machine's real git."""
        real_version = git_native._git_version(workspace)
        assert real_version is not None
        expected = real_version >= (2, 54, 0)
        assert git_native.GlobalConfigBasedHookStrategy().check_prerequisite() is expected


@requires_git
class TestGlobalHookIsImmuneToLocalOverride:
    """The property this whole mechanism exists for. No version shim; skips on older real git."""

    def test_fires_despite_a_local_core_hooks_path_override(self, workspace, monkeypatch):
        """Repo adopts Husky (local core.hooksPath) - global hook still fires."""
        _requires_real_git_2_54(workspace)
        _configure_git_identity(workspace)
        spec = _runtime_hook_spec(workspace, ".global-hook-fired")
        installed, _path = git_native.GlobalConfigBasedHookStrategy().install(spec)
        assert installed is True

        husky_dir = workspace / ".husky"
        husky_dir.mkdir()
        subprocess.run(
            ["git", "-C", str(workspace), "config", "--local", "core.hooksPath", ".husky"],
            check=True,
        )
        assert not (husky_dir / "pre-commit").exists()

        subprocess.run(
            ["git", "-C", str(workspace), "commit", "--allow-empty", "-q", "-m", "test"],
            check=True,
        )

        assert (workspace / ".global-hook-fired").exists(), (
            "the global hook must fire regardless of a local core.hooksPath override"
        )

    def test_coexists_with_a_later_local_declarative_hook_of_a_different_tag(
        self, workspace, monkeypatch
    ):
        """Declarative hooks are additive across scopes for different tags."""
        _requires_real_git_2_54(workspace)
        _configure_git_identity(workspace)
        global_spec = git_hooks.HookSpec(
            tag="snyk-secrets-at-commit",
            command="python3 global_script.py",
            name="Global",
        )
        (workspace / "global_script.py").write_text(
            "from pathlib import Path\nPath('.global-fired').write_text('ok')\n",
            encoding="utf-8",
        )
        git_native.GlobalConfigBasedHookStrategy().install(global_spec)

        local_spec = git_hooks.HookSpec(
            tag="snyk-secure-at-commit",
            command="python3 local_script.py",
            name="Local",
        )
        (workspace / "local_script.py").write_text(
            "from pathlib import Path\nPath('.local-fired').write_text('ok')\n",
            encoding="utf-8",
        )
        git_native.ConfigBasedHookStrategy().install(workspace, local_spec)

        subprocess.run(
            ["git", "-C", str(workspace), "commit", "--allow-empty", "-q", "-m", "test"],
            check=True,
        )

        assert (workspace / ".global-fired").exists()
        assert (workspace / ".local-fired").exists()


@requires_git
class TestGlobalHookDispatcher:
    """Same contract as the local dispatcher, but with no fallback."""

    def test_install_verify_uninstall_round_trip(self):
        _requires_real_git_2_54()
        kind, installed, path = git_hooks.install_global_hook(SPEC)
        assert kind == "git-native-global"
        assert installed is True
        assert path

        verification = git_hooks.verify_global_hook(SPEC)
        assert verification.kind == "git-native-global"
        assert verification.found is True

        kind, removed, _ = git_hooks.uninstall_global_hook(SPEC)
        assert kind == "git-native-global"
        assert removed is True

        verification = git_hooks.verify_global_hook(SPEC)
        assert verification.found is False

    def test_verify_when_never_installed_reports_not_found_with_no_crash(self):
        verification = git_hooks.verify_global_hook(SPEC)
        assert verification.found is False
        assert verification.kind == "git-native-global"

    def test_uninstall_when_never_installed_is_a_safe_noop(self):
        _kind, removed, _path = git_hooks.uninstall_global_hook(SPEC)
        assert removed is False

    def test_install_raises_hook_integration_skipped_when_no_mechanism_available(
        self, git_version_shim_factory
    ):
        git_version_shim_factory("2.53.0")
        with pytest.raises(git_hooks.HookIntegrationSkipped):
            git_hooks.install_global_hook(SPEC)

    def test_verify_reports_not_found_with_reason_when_no_mechanism_available(
        self, git_version_shim_factory
    ):
        git_version_shim_factory("2.53.0")
        verification = git_hooks.verify_global_hook(SPEC)
        assert verification.found is False
        assert verification.reason is not None

    def test_uninstall_is_a_safe_noop_when_no_mechanism_available(self, git_version_shim_factory):
        git_version_shim_factory("2.53.0")
        _kind, removed, _path = git_hooks.uninstall_global_hook(SPEC)
        assert removed is False


class TestLocalDispatcherUnaffectedByGlobalHookStrategies:
    """The local dispatcher never calls into the global one."""

    def test_local_verify_of_an_unrelated_tag_is_unaffected_by_a_global_install(self, workspace):
        _requires_real_git_2_54(workspace)
        git_hooks.install_global_hook(SPEC)
        try:
            unrelated_spec = git_hooks.HookSpec(
                tag="totally-unrelated-tag", command="true", name="Unrelated"
            )
            local_verification = git_hooks.verify_hook(workspace, unrelated_spec)
            assert local_verification.found is False
        finally:
            git_hooks.uninstall_global_hook(SPEC)

    def test_local_verify_of_the_same_tag_sees_a_global_install_too(self, workspace):
        """``ConfigBasedHookStrategy.is_installed`` reads config unscoped, so
        it also sees a tag installed only globally - true here only because
        the command matches exactly; see
        ``git_hooks.is_global_hook_active_for_tag`` for the command-agnostic
        check the shadow-aware warning actually relies on."""
        _requires_real_git_2_54(workspace)
        git_hooks.install_global_hook(SPEC)
        try:
            local_verification = git_hooks.verify_hook(workspace, SPEC)
            assert local_verification.found is True
            assert local_verification.kind == "git-native"
        finally:
            git_hooks.uninstall_global_hook(SPEC)
