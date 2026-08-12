"""Shared fixtures/helpers for the secure-at-commit test package.

Split out of a single 3300+ line ``test_secure_at_commit.py`` into one file
per concern - see the sibling ``test_*.py`` modules for what each covers.
"""

import importlib
import os
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Callable, Optional

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
from git_hooks_impl import git_native, husky, marked_files, pre_commit, types  # noqa: E402

GIT = shutil.which("git")
requires_git = pytest.mark.skipif(GIT is None, reason="git not installed")


def _installed_git_version() -> Optional[tuple]:
    """Version of whatever ``git`` resolves to on ``PATH`` - independent of
    ``git_native._git_version`` (the code under test) so a bug there can't
    hide from this gate.

    To verify against a real old git (e.g. Git 2.5.3, pre-dates
    core.hooksPath), build one and put it first on PATH before running:

        curl -sL -o git.tar.gz https://github.com/git/git/archive/refs/tags/v2.5.3.tar.gz
        tar xzf git.tar.gz && cd git-2.5.3
        make NO_GETTEXT=1 NO_TCLTK=1 NO_PYTHON=1 NO_OPENSSL=1 \\
            prefix="$PWD/../install" -j4 install
        export PATH="$PWD/../install/bin:$PATH"
        uv run pytest tests/sac/   # from recipes/installer/
    """
    if GIT is None:
        return None
    result = subprocess.run([GIT, "--version"], capture_output=True, text=True, timeout=5.0)
    if result.returncode != 0:
        return None
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", result.stdout)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


_installed_version = _installed_git_version()
requires_hooks_path_support = pytest.mark.skipif(
    _installed_version is None or _installed_version < git_native._HOOKS_PATH_MIN_VERSION,
    reason=(
        f"core.hooksPath requires git >= {git_native._HOOKS_PATH_MIN_VERSION}; "
        f"this PATH's git reports {_installed_version}"
    ),
)

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


def _snapshot_tree(root: Path) -> set:
    """Every path under *root*, relative to it - for asserting an install
    touched only expected files anywhere under a shared temp root."""
    if not root.exists():
        return set()
    return {p.relative_to(root) for p in root.rglob("*")}


def _set_global_hooks_path(monkeypatch, tmp_path_factory, target: Path) -> Path:
    """Simulate ``git config --global core.hooksPath <target>`` via
    ``GIT_CONFIG_GLOBAL``, without touching the real ``~/.gitconfig``."""
    config = tmp_path_factory.mktemp("customer-global-config") / "gitconfig"
    config.write_text(f"[core]\n\thooksPath = {target.as_posix()}\n", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    return config


def _set_system_hooks_path(monkeypatch, tmp_path_factory, target: Path) -> Path:
    """Simulate ``git config --system core.hooksPath <target>`` via
    ``GIT_CONFIG_SYSTEM``, undoing the suite's own ``GIT_CONFIG_NOSYSTEM=1``
    isolation just for this call so the simulated value is actually read."""
    config = tmp_path_factory.mktemp("customer-system-config") / "gitconfig"
    config.write_text(f"[core]\n\thooksPath = {target.as_posix()}\n", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(config))
    monkeypatch.delenv("GIT_CONFIG_NOSYSTEM", raising=False)
    return config


@pytest.fixture
def manifest():
    return installer.Manifest(INSTALLER_DIR / "manifest.json")


@pytest.fixture
def payload():
    pl = installer.PayloadContext()
    pl.setup()
    return pl


@pytest.fixture
def git_version_shim_factory(tmp_path: Path, monkeypatch) -> Callable[[str], None]:
    """Factory: ``git_version_shim_factory(version)`` puts a ``git`` shim
    reporting a fake ``--version`` string first on ``PATH``. Every other
    invocation forwards to the real binary, so real git operations still
    happen for real - only version detection is fooled.
    """
    real_git = shutil.which("git")
    if real_git is None:
        pytest.skip("git not installed")
    bin_dir = tmp_path / "git-version-shim-bin"
    bin_dir.mkdir(exist_ok=True)

    def _make(version: str) -> None:
        if os.name == "nt":
            shim_path = bin_dir / "git.bat"
            shim_path.write_text(
                "@echo off\r\n"
                "setlocal enabledelayedexpansion\r\n"
                "for %%a in (%*) do (\r\n"
                '  if "%%a"=="--version" (\r\n'
                f"    echo git version {version}\r\n"
                "    exit /b 0\r\n"
                "  )\r\n"
                ")\r\n"
                f'"{real_git}" %*\r\n',
                encoding="utf-8",
            )
        else:
            shim_path = bin_dir / "git"
            shim_path.write_text(
                "#!/usr/bin/env bash\n"
                'for arg in "$@"; do\n'
                '  if [ "$arg" = "--version" ]; then\n'
                f'    echo "git version {version}"\n'
                "    exit 0\n"
                "  fi\n"
                "done\n"
                f'exec "{real_git}" "$@"\n',
                encoding="utf-8",
            )
            shim_path.chmod(0o755)
        monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))

    return _make


@pytest.fixture
def fake_snyk_env(tmp_path: Path) -> dict:
    """Hermetic env with a fake ``snyk`` on ``PATH`` that always reports
    "no findings" - lets a real commit execute the installed hook script
    without a real Snyk CLI, auth, or network access."""
    bin_dir = tmp_path / "fake-snyk-bin"
    bin_dir.mkdir(exist_ok=True)
    fake = bin_dir / ("snyk.cmd" if os.name == "nt" else "snyk")
    fake_py = bin_dir / "fake_snyk.py"
    fake_py.write_text(
        textwrap.dedent(
            """
            import json
            print(json.dumps({"runs": [{"results": []}]}))
            """
        ).lstrip(),
        encoding="utf-8",
    )
    if os.name == "nt":
        fake.write_text(f'@echo off\r\n"{sys.executable}" "{fake_py}" %*\r\n')
    else:
        fake.write_text(f"#!{sys.executable}\nexec(open({str(fake_py)!r}).read())\n")
        fake.chmod(0o755)

    env = os.environ.copy()
    env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
    env["SNYK_TOKEN"] = "fake-token"
    env["SECRETS_SCAN_TIMEOUT"] = "5"
    return env
