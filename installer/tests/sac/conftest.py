"""Shared fixtures/helpers for the secure-at-commit test package.

Split out of a single 3300+ line ``test_secure_at_commit.py`` into one file
per concern - see the sibling ``test_*.py`` modules for what each covers.
"""

import importlib
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

import pytest

INSTALLER_DIR = Path(__file__).resolve().parent.parent.parent
REPO_ROOT = INSTALLER_DIR.parent.parent
SAC_HOOK_DIR = REPO_ROOT / "recipes" / "guardrail_directives" / "secure_at_commit"
sys.path.insert(0, str(INSTALLER_DIR))
sys.path.insert(0, str(INSTALLER_DIR / "lib"))
sys.path.insert(0, str(SAC_HOOK_DIR))

installer = importlib.import_module("snyk-studio-installer")
import git_hooks  # noqa: E402
import snyk_secure_at_commit as sac_hook  # noqa: E402
from git_hooks_impl import git_native, husky, marked_files, pre_commit  # noqa: E402

GIT = shutil.which("git")
requires_git = pytest.mark.skipif(GIT is None, reason="git not installed")

SAC_DEST = Path(".snyk-studio") / "components" / "scripts" / "snyk_secure_at_commit.py"
LEGACY_SAC_DEST = Path(".snyk") / "studio" / "components" / "scripts" / "snyk_secure_at_commit.py"

SPEC = git_hooks.HookSpec(
    tag="snyk-secure-at-commit",
    command='uv run "/tmp/sac/snyk_secure_at_commit.py"',
    name="Snyk Secure At Commit",
)


# ============================================================================
# Helpers
# ============================================================================


def _init_git_repo(path: Path) -> None:
    """Create a real git repository at *path*.

    A real ``git init`` is required (not just a faked ``.git/hooks/``
    directory) — git_hooks.py now shells out to git for the git-native
    strategies (version detection, config-based hooks, core.hooksPath
    resolution), so it needs an actual repo to operate against.
    """
    path.mkdir(parents=True, exist_ok=True)
    if GIT is None:
        pytest.skip("git not installed")
    subprocess.run([GIT, "init", "-q"], cwd=path, check=True)


def _init_hook_workspace(path: Path) -> None:
    """Create a workspace suitable for hook file tests.

    Most installer tests only need a ``.git/hooks`` directory so
    ``FileShimStrategy`` has somewhere to write. CircleCI's docker
    unit-test image does not include git, so keep those tests runnable with a
    lightweight fake repo and let real git subprocess tests opt into
    ``requires_git``.
    """
    if GIT is not None:
        _init_git_repo(path)
        return
    (path / ".git" / "hooks").mkdir(parents=True, exist_ok=True)


def _configure_git_identity(path: Path) -> None:
    if GIT is None:
        pytest.skip("git not installed")
    subprocess.run([GIT, "-C", str(path), "config", "user.email", "test@example.com"], check=True)
    subprocess.run([GIT, "-C", str(path), "config", "user.name", "Test User"], check=True)


def _write_runtime_hook_script(path: Path, sentinel: str = ".hook-fired") -> Path:
    script = path / ".hook_runtime.py"
    script.write_text(
        f"from pathlib import Path\nPath({sentinel!r}).write_text('ok', encoding='utf-8')\n",
        encoding="utf-8",
    )
    return script


def _runtime_hook_spec(workspace: Path, sentinel: str = ".hook-fired") -> git_hooks.HookSpec:
    script = _write_runtime_hook_script(workspace, sentinel)
    return git_hooks.HookSpec(
        tag="snyk-secure-at-commit",
        command=f"python3 {script.name}",
        name="Snyk Secure At Commit",
    )


def _commit_tracked_file(
    workspace: Path, message: str = "test hook", env: Optional[dict] = None
) -> None:
    if GIT is None:
        pytest.skip("git not installed")
    (workspace / "file.txt").write_text("x\n", encoding="utf-8")
    subprocess.run([GIT, "-C", str(workspace), "add", "file.txt"], check=True)
    subprocess.run(
        [GIT, "-C", str(workspace), "commit", "-m", message],
        cwd=workspace,
        env=env,
        check=True,
    )


def _set_home(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    """Overrides expanduser("~") on every platform -- Windows needs
    USERPROFILE set too, not just HOME."""
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))


def _validate_with_precommit_cli(workspace: Path, config_path: Path) -> None:
    import os

    env = os.environ.copy()
    env["PRE_COMMIT_HOME"] = str(workspace / ".pre-commit-cache")
    subprocess.run(
        ["pre-commit", "validate-config", str(config_path)],
        cwd=workspace,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.fixture(autouse=True)
def _isolate_git_config(tmp_path_factory, monkeypatch):
    """Prevent git subprocess calls made by git_hooks.py from reading the
    real machine's global/system git config.

    Without this, a developer machine with e.g. ``core.hooksPath`` set
    globally (as ggshield does) would leak into every test's git config
    resolution, since ``git config --get`` walks system -> global -> local
    by default. Tests must only ever see config they set up explicitly.

    Deliberately does NOT touch ``HOME`` — these env vars fully redirect
    git's own config resolution on their own, and overriding ``HOME`` would
    also affect unrelated code under test that calls
    ``os.path.expanduser("~")`` / ``Path.home()`` (it broke
    ``TestSnykEnv.test_machine_id_from_home`` the first time around).
    """
    empty_config = tmp_path_factory.mktemp("git-config") / "gitconfig-empty"
    empty_config.write_text("", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(empty_config))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(empty_config))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """A clean workspace cwd for hook tests."""
    _init_hook_workspace(tmp_path)
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def manifest():
    return installer.Manifest(INSTALLER_DIR / "manifest.json")


@pytest.fixture
def payload():
    pl = installer.PayloadContext()
    pl.setup()
    return pl
