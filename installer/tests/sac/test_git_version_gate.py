"""Validates the Git >= 2.54 declarative-hook version gate
(``ConfigBasedHookStrategy.check_prerequisite``).

Three layers, most to least synthetic:

1. ``_git_version`` parsing against real-but-version-shimmed output,
   including the classic pitfall a *string* comparison would get wrong
   (``"2.9" > "2.54"`` lexically, but ``2.9.0 < 2.54.0`` must hold).
2. The real dispatcher at and around the 2.54.0 boundary, using the same
   shim so every actual git operation still happens for real.
3. No shim: cross-checks ``check_prerequisite()`` against what Git
   actually does on the machine running the suite (a real declarative
   hook write plus a real commit), self-validating against ground truth
   regardless of the host's Git version.
"""

import os
import re
import subprocess
from pathlib import Path

import pytest

from tests.sac.conftest import (
    SPEC,
    _configure_git_identity,
    _runtime_hook_spec,
    git_hooks,
    git_native,
    requires_git,
)


@requires_git
class TestGitVersionParsing:
    """``git_native._git_version`` against real (version-shimmed) git,
    plus a real, non-shimmed check against an actual Apple-bundled git
    binary where one is available - see that test for why the shimmed
    cases below are a *weaker* form of evidence than they might look."""

    def test_parses_standard_triple(self, workspace, git_version_shim_factory):
        git_version_shim_factory("2.54.0")
        assert git_native._git_version(workspace) == (2, 54, 0)

    def test_parses_low_minor_version_correctly(self, workspace, git_version_shim_factory):
        """String comparison would say "2.9" > "2.54"; must parse to a
        real int tuple so ordering is correct."""
        git_version_shim_factory("2.9.0")
        assert git_native._git_version(workspace) == (2, 9, 0)
        assert (2, 9, 0) < (2, 54, 0)

    def test_parses_version_with_windows_style_suffix(self, workspace, git_version_shim_factory):
        """Not verified against a real Windows git in this suite (no
        Windows machine available here) - this pins the documented
        git-for-windows format (``X.Y.Z.windows.N``) so the regex is at
        least known to handle it, but treat this as weaker evidence than
        the real-binary tests elsewhere in this class."""
        git_version_shim_factory("2.43.0.windows.1")
        assert git_native._git_version(workspace) == (2, 43, 0)

    def test_parses_synthetic_apple_git_style_string(self, workspace, git_version_shim_factory):
        """A fabricated-but-realistic string, kept as a deterministic
        pin independent of what happens to be installed on the machine
        running the suite. See ``test_parses_real_apple_bundled_git``
        below for the same format confirmed against a genuine binary."""
        git_version_shim_factory("2.39.3 (Apple Git-146)")
        assert git_native._git_version(workspace) == (2, 39, 3)

    def test_parses_real_apple_bundled_git(self, workspace, monkeypatch):
        """No shim at all - runs directly against the real Apple Git CLT
        binary at ``/usr/bin/git`` (distinct from a Homebrew/MacPorts git
        that might otherwise win PATH resolution), when this machine has
        one. Confirmed on the machine this test was written on: real
        output was ``git version 2.50.1 (Apple Git-155)``, correctly
        parsed to ``(2, 50, 1)``. Skips cleanly everywhere else (Linux,
        Windows, or a mac without Xcode CLT installed)."""
        apple_git = Path("/usr/bin/git")
        if not apple_git.is_file():
            pytest.skip("no /usr/bin/git on this machine")
        raw = subprocess.run(
            [str(apple_git), "--version"], capture_output=True, text=True
        ).stdout.strip()
        if "Apple Git" not in raw:
            pytest.skip(f"/usr/bin/git here isn't Apple's build: {raw!r}")
        match = re.search(r"(\d+)\.(\d+)\.(\d+)", raw)
        assert match, f"couldn't even parse the real version string by hand: {raw!r}"
        expected = tuple(int(part) for part in match.groups())

        # Put /usr/bin first so PATH resolution picks Apple's git even if
        # a Homebrew/MacPorts git normally wins.
        monkeypatch.setenv("PATH", f"{apple_git.parent}{os.pathsep}{os.environ.get('PATH', '')}")

        assert git_native._git_version(workspace) == expected

    def test_unparseable_version_output_returns_none(self, workspace, git_version_shim_factory):
        git_version_shim_factory("not-a-version-string")
        assert git_native._git_version(workspace) is None


@requires_git
class TestConfigBasedHookStrategyVersionGate:
    """Crossing 2.54.0 must actually change which strategy runs and what
    ends up on disk, not just what the raw comparison returns."""

    @staticmethod
    def _assert_used_file_shim(workspace: Path, path: str) -> None:
        assert Path(path) == workspace / ".git" / "hooks" / "pre-commit"
        assert Path(path).is_file()

    @staticmethod
    def _assert_used_config_based(workspace: Path, path: str) -> None:
        assert "(git config)" in path
        assert not (workspace / ".git" / "hooks" / "pre-commit").exists()

    @pytest.mark.parametrize(
        "version",
        ["2.9.0", "2.53.0", "2.53.99", "2.53.999"],
    )
    def test_below_threshold_uses_file_shim(self, workspace, git_version_shim_factory, version):
        git_version_shim_factory(version)
        assert git_native.ConfigBasedHookStrategy().check_prerequisite(workspace) is False

        manager, installed, path = git_hooks.install_hook(workspace, SPEC)

        assert manager == "git-native"
        assert installed is True
        self._assert_used_file_shim(workspace, path)

    @pytest.mark.parametrize(
        "version",
        ["2.54.0", "2.54.1", "2.55.0", "3.0.0", "10.0.0"],
    )
    def test_at_or_above_threshold_uses_config_based(
        self, workspace, git_version_shim_factory, version
    ):
        git_version_shim_factory(version)
        assert git_native.ConfigBasedHookStrategy().check_prerequisite(workspace) is True

        manager, installed, path = git_hooks.install_hook(workspace, SPEC)

        assert manager == "git-native"
        assert installed is True
        self._assert_used_config_based(workspace, path)

    def test_reinstall_across_the_boundary_switches_mechanism_on_disk(
        self, workspace, git_version_shim_factory
    ):
        """The same repo, Git upgraded from just-under to just-at 2.54.0:
        the old file-shim content must be cleaned up, not left alongside
        the new config-based hook (both would otherwise fire)."""
        git_version_shim_factory("2.53.99")
        git_hooks.install_hook(workspace, SPEC)
        file_hook = workspace / ".git" / "hooks" / "pre-commit"
        assert SPEC.begin_marker in file_hook.read_text(encoding="utf-8")

        git_version_shim_factory("2.54.0")
        manager, installed, path = git_hooks.install_hook(workspace, SPEC)

        assert manager == "git-native"
        assert installed is True
        self._assert_used_config_based(workspace, path)
        if file_hook.exists():
            assert SPEC.begin_marker not in file_hook.read_text(encoding="utf-8")


@requires_git
class TestVersionGateMatchesRealGitBehavior:
    """No version shim - cross-checks against what the real, installed
    Git binary actually does, so this holds on any machine."""

    def test_check_prerequisite_agrees_with_a_real_declarative_hook_firing(self, workspace):
        _configure_git_identity(workspace)
        real_version = git_native._git_version(workspace)
        assert real_version is not None
        expected_supported = real_version >= (2, 54, 0)

        reported = git_native.ConfigBasedHookStrategy().check_prerequisite(workspace)
        assert reported is expected_supported

        # Ground truth: write the declarative config block for real and
        # see whether a real commit actually executes it.
        spec = _runtime_hook_spec(workspace, ".version-gate-fired")
        git_native.ConfigBasedHookStrategy().install(workspace, spec)
        subprocess.run(
            ["git", "-C", str(workspace), "commit", "--allow-empty", "-q", "-m", "test"],
            check=True,
        )
        actually_fired = (workspace / ".version-gate-fired").exists()
        assert actually_fired is expected_supported
