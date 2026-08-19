"""End-to-end installer wiring for the git-global-scoped
``secrets-precommit-hook-global`` recipe: install/verify/uninstall, plus
the path helper they depend on."""

import shutil
import subprocess

import pytest

from tests.sac.conftest import _set_home, git_hooks, git_native, installer

GLOBAL_RECIPE_ID = "secrets-precommit-hook-global"
GLOBAL_SCRIPT_DEST = "secrets_at_commit/snyk_secrets_at_commit.py"


@pytest.fixture(autouse=True)
def _force_git_2_54(git_version_shim_factory):
    """No fallback below git 2.54 - shim the version for determinism."""
    git_version_shim_factory("2.54.0")


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Isolates ``Path.home()`` from the real ``~/.snyk-studio``."""
    home_dir = tmp_path / "fake-home"
    home_dir.mkdir()
    _set_home(monkeypatch, home_dir)
    return home_dir


class TestInstallGitGlobalRecipe:
    def test_install_copies_script_under_root_and_wires_hook(self, home, manifest, payload):
        installer.install_git_global_recipe(GLOBAL_RECIPE_ID, manifest, payload, dry_run=False)

        script = home / ".snyk-studio" / GLOBAL_SCRIPT_DEST
        assert script.is_file()

        # $HOME is expanded to an absolute path at install time.
        section = git_native._hook_config_section(
            git_hooks.HookSpec(tag="snyk-secrets-at-commit", command="", name="")
        )
        result = subprocess.run(
            ["git", "config", "--global", "--get", f"{section}.command"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "$HOME" not in result.stdout
        assert str(script) in result.stdout

    def test_install_is_idempotent(self, home, manifest, payload):
        installer.install_git_global_recipe(GLOBAL_RECIPE_ID, manifest, payload, dry_run=False)
        installer.install_git_global_recipe(GLOBAL_RECIPE_ID, manifest, payload, dry_run=False)

        script = home / ".snyk-studio" / GLOBAL_SCRIPT_DEST
        assert script.is_file()

    def test_dry_run_writes_nothing(self, home, manifest, payload):
        installer.install_git_global_recipe(GLOBAL_RECIPE_ID, manifest, payload, dry_run=True)

        script = home / ".snyk-studio" / GLOBAL_SCRIPT_DEST
        assert not script.exists()

    def test_dry_run_message_names_the_real_config_section(self, home, manifest, payload, capsys):
        installer.install_git_global_recipe(GLOBAL_RECIPE_ID, manifest, payload, dry_run=True)

        out = capsys.readouterr().out
        assert "hook.snyk-secrets-at-commit.*" in out
        assert "hook.hook." not in out


class TestVerifyGitGlobalRecipe:
    def test_verify_after_install_passes(self, home, manifest, payload):
        installer.install_git_global_recipe(GLOBAL_RECIPE_ID, manifest, payload, dry_run=False)
        assert installer.verify_git_global_recipe(GLOBAL_RECIPE_ID, manifest, payload) is True

    def test_verify_without_install_fails(self, home, manifest, payload):
        assert installer.verify_git_global_recipe(GLOBAL_RECIPE_ID, manifest, payload) is False

    def test_verify_reports_missing_files_and_missing_hook_separately(
        self, home, manifest, payload, capsys
    ):
        ok = installer.verify_git_global_recipe(GLOBAL_RECIPE_ID, manifest, payload)
        out = capsys.readouterr().out
        assert ok is False
        assert "MISSING" in out


class TestUninstallGitGlobalRecipe:
    def test_uninstall_removes_files_and_hook(self, home, manifest, payload):
        installer.install_git_global_recipe(GLOBAL_RECIPE_ID, manifest, payload, dry_run=False)
        script = home / ".snyk-studio" / GLOBAL_SCRIPT_DEST
        assert script.is_file()

        installer.uninstall_git_global_recipe(GLOBAL_RECIPE_ID, manifest, payload, dry_run=False)

        assert not script.exists()
        assert installer.verify_git_global_recipe(GLOBAL_RECIPE_ID, manifest, payload) is False

    def test_uninstall_without_install_is_a_safe_noop(self, home, manifest, payload):
        installer.uninstall_git_global_recipe(GLOBAL_RECIPE_ID, manifest, payload, dry_run=False)

    def test_uninstall_removes_the_whole_recipe_directory_when_empty(self, home, manifest, payload):
        """Product-scoped dest paths mean uninstall leaves no trace under
        ~/.snyk-studio, without touching unrelated files (e.g. device-id)."""
        installer.install_git_global_recipe(GLOBAL_RECIPE_ID, manifest, payload, dry_run=False)
        installer.uninstall_git_global_recipe(GLOBAL_RECIPE_ID, manifest, payload, dry_run=False)

        assert not (home / ".snyk-studio" / "secrets_at_commit").exists()


class TestGitGlobalPathHelpers:
    def test_resolve_studio_install_path_stays_under_root(self, home):
        p = installer.resolve_studio_install_path("subdir/file.py")
        assert p == (home / ".snyk-studio" / "subdir" / "file.py").resolve()

    def test_resolve_studio_install_path_rejects_absolute_dest(self, home):
        with pytest.raises(installer.ManifestDestError):
            installer.resolve_studio_install_path("/etc/passwd")

    def test_resolve_studio_install_path_rejects_escape(self, home):
        with pytest.raises(installer.ManifestDestError):
            installer.resolve_studio_install_path("../sibling/file.py")


class TestRecipeSelectionEligibility:
    """secrets-precommit-hook-global is installed by the ADS or experimental profile."""

    def test_selectable_under_experimental(self, manifest):
        installer.validate_recipe_selection(manifest, "experimental", [GLOBAL_RECIPE_ID])

    def test_selectable_under_ads(self, manifest):
        installer.validate_recipe_selection(manifest, "ads", [GLOBAL_RECIPE_ID])

    def test_rejected_under_default_profile(self, manifest, capsys):
        with pytest.raises(SystemExit) as excinfo:
            installer.validate_recipe_selection(manifest, "default", [GLOBAL_RECIPE_ID])
        assert excinfo.value.code != 0
        assert (
            "--recipes cannot be used with --profile default or --profile minimal"
            in capsys.readouterr().err
        )

    def test_installed_by_bare_experimental_profile(self, manifest):
        assert GLOBAL_RECIPE_ID in manifest.resolve_recipes("experimental")

    def test_installed_by_bare_ads_profile(self, manifest):
        assert GLOBAL_RECIPE_ID in manifest.resolve_recipes("ads")

    def test_installed_when_explicitly_named(self, manifest):
        assert manifest.resolve_recipes("ads", [GLOBAL_RECIPE_ID]) == [GLOBAL_RECIPE_ID]

    def test_is_git_global_scoped(self, manifest):
        assert manifest.is_git_global_scoped(GLOBAL_RECIPE_ID) is True
        assert manifest.is_git_global_scoped("secrets-precommit-hook") is False
        assert manifest.is_workspace_scoped(GLOBAL_RECIPE_ID) is False


class TestVerifyAutoDetectsGitGlobalInstall:
    """``--verify`` (bare, no ``--recipes``) must still catch a real global
    install even though the recipe is not in the default profile - mirrors the existing
    auto-detection for the workspace-scoped secrets hook."""

    def test_verify_includes_existing_global_hook_without_a_selection(
        self, home, manifest, payload
    ):
        recipes = installer.resolve_verify_recipes(manifest, payload, "default", workspace=None)
        assert GLOBAL_RECIPE_ID not in recipes

        installer.install_git_global_recipe(GLOBAL_RECIPE_ID, manifest, payload, dry_run=False)

        recipes = installer.resolve_verify_recipes(manifest, payload, "default", workspace=None)
        assert GLOBAL_RECIPE_ID in recipes

    def test_verify_includes_existing_global_hook_when_files_are_missing(
        self, home, manifest, payload
    ):
        installer.install_git_global_recipe(GLOBAL_RECIPE_ID, manifest, payload, dry_run=False)
        shutil.rmtree(home / ".snyk-studio" / "secrets_at_commit")

        recipes = installer.resolve_verify_recipes(manifest, payload, "default", workspace=None)
        assert GLOBAL_RECIPE_ID in recipes
        assert installer.verify_git_global_recipe(GLOBAL_RECIPE_ID, manifest, payload) is False
