"""Tests for the check_prerequisites bash function in template.sh.

Uses fake snyk/npm scripts on PATH to exercise each branch of the
Snyk CLI detection, version-check, install, and upgrade logic.
"""

import os
import stat
import subprocess
import textwrap

import pytest

TEMPLATE_SH = os.path.join(
    os.path.dirname(__file__), "..", "template.sh",
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fake_bin(bin_dir, name, script_body):
    """Create a fake executable shell script in bin_dir."""
    bin_dir = str(bin_dir)
    os.makedirs(bin_dir, exist_ok=True)
    path = os.path.join(bin_dir, name)
    with open(path, "w") as f:
        f.write("#!/bin/bash\n" + script_body + "\n")
    os.chmod(path, stat.S_IRWXU)


def _setup_isolated_path(tmp_path):
    """Create a bin dir with only essential system tools (no snyk/npm).

    Symlinks python3, head, sed, etc. into the fake bin dir so the bash
    wrapper works, but snyk/npm are absent unless explicitly added by tests.
    """
    bin_dir = str(tmp_path / "bin")
    os.makedirs(bin_dir, exist_ok=True)

    # Tools the wrapper and check_prerequisites need
    import shutil
    for tool in ["python3", "head", "sed", "bash", "cat", "tail", "rm",
                 "mkdir", "cp", "chmod", "echo", "printf", "read"]:
        real = shutil.which(tool)
        if real:
            link = os.path.join(bin_dir, tool)
            if not os.path.exists(link):
                os.symlink(real, link)
    return bin_dir


def _run_check(tmp_path, env_overrides=None, stdin_input=None):
    """Run check_prerequisites from template.sh with a controlled PATH.

    Returns (stdout, stderr, returncode).
    """
    bin_dir = _setup_isolated_path(tmp_path)

    # We need a minimal wrapper that sources the color vars and function,
    # then calls it.  We extract just what we need from template.sh.
    wrapper = textwrap.dedent(f"""\
        #!/bin/bash
        set -uo pipefail
        GREEN='\\033[0;32m'
        RED='\\033[0;31m'
        YELLOW='\\033[1;33m'
        NC='\\033[0m'
        AUTO_YES="${{AUTO_YES:-false}}"
        DISABLE_UPGRADES="${{DISABLE_UPGRADES:-false}}"

        # Source only the check_prerequisites function
        eval "$(sed -n '/^check_prerequisites()/,/^}}/p' '{TEMPLATE_SH}')"

        check_prerequisites
    """)
    wrapper_path = str(tmp_path / "wrapper.sh")
    with open(wrapper_path, "w") as f:
        f.write(wrapper)
    os.chmod(wrapper_path, stat.S_IRWXU)

    env = os.environ.copy()
    # Isolated PATH: only our fake bin dir — no system snyk/npm leak
    env["PATH"] = bin_dir
    if env_overrides:
        env.update(env_overrides)

    result = subprocess.run(
        ["bash", wrapper_path],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
        input=stdin_input,
    )
    return result.stdout, result.stderr, result.returncode


# ---------------------------------------------------------------------------
# Tests: Snyk CLI installed and up to date
# ---------------------------------------------------------------------------

class TestSnykInstalled:

    def test_snyk_current_version(self, tmp_path):
        """Snyk installed + npm reports same version -> green check, no prompt."""
        _make_fake_bin(tmp_path / "bin", "snyk", 'echo "1.1294.0"')
        _make_fake_bin(tmp_path / "bin", "npm", """
            if [[ "$1" == "view" && "$2" == "snyk" ]]; then
                echo "1.1294.0"
            fi
        """)
        stdout, _, rc = _run_check(tmp_path)
        assert rc == 0
        assert "Snyk CLI 1.1294.0" in stdout
        assert "Upgrade" not in stdout
        assert "not found" not in stdout

    def test_snyk_installed_no_npm(self, tmp_path):
        """Snyk installed but npm not available -> shows version, no upgrade check."""
        _make_fake_bin(tmp_path / "bin", "snyk", 'echo "1.1290.0"')
        # No npm mock — so `command -v npm` fails
        stdout, _, rc = _run_check(tmp_path)
        assert rc == 0
        assert "Snyk CLI 1.1290.0" in stdout
        assert "Upgrade" not in stdout


# ---------------------------------------------------------------------------
# Tests: Snyk CLI installed but outdated
# ---------------------------------------------------------------------------

class TestSnykOutdated:

    def test_outdated_decline_upgrade(self, tmp_path):
        """Snyk outdated, user declines upgrade -> shows version with update note."""
        _make_fake_bin(tmp_path / "bin", "snyk", 'echo "1.1290.0"')
        _make_fake_bin(tmp_path / "bin", "npm", """
            if [[ "$1" == "view" && "$2" == "snyk" ]]; then
                echo "1.1294.0"
            fi
        """)
        stdout, _, rc = _run_check(tmp_path, stdin_input="n\nn\n")
        assert rc == 0
        assert "1.1290.0" in stdout
        assert "latest: 1.1294.0" in stdout
        assert "update available" in stdout

    def test_outdated_auto_yes_upgrades(self, tmp_path):
        """Snyk outdated + AUTO_YES -> runs npm install automatically."""
        _make_fake_bin(tmp_path / "bin", "snyk", 'echo "1.1294.0"')
        _make_fake_bin(tmp_path / "bin", "npm", """
            if [[ "$1" == "view" && "$2" == "snyk" ]]; then
                echo "1.1294.0"
            elif [[ "$1" == "install" ]]; then
                echo "installed snyk@1.1294.0"
            fi
        """)
        # First run with old version, but after "upgrade" snyk reports new version
        # We simulate this by having snyk always return the new version
        _make_fake_bin(tmp_path / "bin", "npm", """
            if [[ "$1" == "view" && "$2" == "snyk" ]]; then
                echo "1.1295.0"
            elif [[ "$1" == "install" ]]; then
                echo "installed snyk@1.1295.0"
                exit 0
            fi
        """)
        _make_fake_bin(tmp_path / "bin", "snyk", 'echo "1.1294.0"')
        stdout, _, rc = _run_check(
            tmp_path, env_overrides={"AUTO_YES": "true"},
        )
        assert rc == 0
        assert "Installing snyk@latest" in stdout

    def test_npm_view_fails_gracefully(self, tmp_path):
        """npm view fails (offline) -> just shows installed version."""
        _make_fake_bin(tmp_path / "bin", "snyk", 'echo "1.1290.0"')
        _make_fake_bin(tmp_path / "bin", "npm", """
            if [[ "$1" == "view" ]]; then
                exit 1
            fi
        """)
        stdout, _, rc = _run_check(tmp_path)
        assert rc == 0
        assert "Snyk CLI 1.1290.0" in stdout
        assert "Upgrade" not in stdout


# ---------------------------------------------------------------------------
# Tests: Snyk CLI missing
# ---------------------------------------------------------------------------

class TestSnykMissing:

    def test_missing_no_npm(self, tmp_path):
        """Snyk missing + no npm -> warning with Node.js install guidance."""
        # No snyk, no npm in fake bin
        stdout, _, rc = _run_check(tmp_path, stdin_input="y\n")
        assert "not found" in stdout
        assert "Node.js/npm" in stdout

    def test_missing_npm_available_decline(self, tmp_path):
        """Snyk missing + npm available + user declines -> warning."""
        _make_fake_bin(tmp_path / "bin", "npm", "true")
        stdout, _, rc = _run_check(tmp_path, stdin_input="n\nn\n")
        assert "Snyk CLI not found" in stdout
        assert "Install later with" in stdout

    def test_missing_npm_available_auto_yes_installs(self, tmp_path):
        """Snyk missing + npm available + AUTO_YES -> runs npm install."""
        _make_fake_bin(tmp_path / "bin", "npm", """
            if [[ "$1" == "install" ]]; then
                echo "installed snyk@1.1294.0"
                exit 0
            fi
        """)
        # After install, snyk should be "found" — create it in the same bin dir
        # so the version check after install works
        _make_fake_bin(tmp_path / "bin", "snyk", 'echo "1.1294.0"')
        # But we need snyk to NOT be found initially, then found after install.
        # Trick: rename snyk to snyk-real, have npm "install" create it
        snyk_path = str(tmp_path / "bin" / "snyk")
        snyk_real = str(tmp_path / "bin" / "snyk-real")
        os.rename(snyk_path, snyk_real)

        _make_fake_bin(tmp_path / "bin", "npm", f"""
            if [[ "$1" == "install" ]]; then
                cp "{snyk_real}" "{snyk_path}"
                echo "installed snyk@1.1294.0"
                exit 0
            fi
        """)
        stdout, _, rc = _run_check(
            tmp_path, env_overrides={"AUTO_YES": "true"},
        )
        assert rc == 0
        assert "Installing snyk@latest" in stdout
        assert "Snyk CLI 1.1294.0" in stdout

    def test_missing_npm_install_fails(self, tmp_path):
        """Snyk missing + npm install fails -> error with manual instructions."""
        _make_fake_bin(tmp_path / "bin", "npm", """
            if [[ "$1" == "install" ]]; then
                echo "ERR! install failed" >&2
                exit 1
            fi
        """)
        stdout, _, rc = _run_check(
            tmp_path, env_overrides={"AUTO_YES": "true"},
        )
        assert "installation failed" in stdout
        assert "Try manually" in stdout


# ---------------------------------------------------------------------------
# Tests: --disable-upgrades flag
# ---------------------------------------------------------------------------

class TestDisableUpgrades:

    def test_installed_skips_version_check(self, tmp_path):
        """Snyk installed + disable-upgrades -> shows version, no npm call."""
        _make_fake_bin(tmp_path / "bin", "snyk", 'echo "1.1290.0"')
        _make_fake_bin(tmp_path / "bin", "npm", """
            if [[ "$1" == "view" ]]; then
                echo "1.1294.0"
            fi
        """)
        stdout, _, rc = _run_check(
            tmp_path, env_overrides={"DISABLE_UPGRADES": "true"},
        )
        assert rc == 0
        assert "Snyk CLI 1.1290.0" in stdout
        assert "upgrade check skipped" in stdout
        assert "Upgrade" not in stdout

    def test_missing_skips_install(self, tmp_path):
        """Snyk missing + disable-upgrades -> warning, no install prompt."""
        _make_fake_bin(tmp_path / "bin", "npm", "true")
        stdout, _, rc = _run_check(
            tmp_path,
            env_overrides={"DISABLE_UPGRADES": "true", "AUTO_YES": "true"},
        )
        assert "install/upgrade disabled" in stdout
        assert "Installing" not in stdout

    def test_disable_upgrades_with_auto_yes(self, tmp_path):
        """disable-upgrades takes precedence over auto-yes for upgrades."""
        _make_fake_bin(tmp_path / "bin", "snyk", 'echo "1.1290.0"')
        _make_fake_bin(tmp_path / "bin", "npm", """
            if [[ "$1" == "view" ]]; then
                echo "1.1294.0"
            elif [[ "$1" == "install" ]]; then
                echo "should not run"
                exit 0
            fi
        """)
        stdout, _, rc = _run_check(
            tmp_path,
            env_overrides={"DISABLE_UPGRADES": "true", "AUTO_YES": "true"},
        )
        assert rc == 0
        assert "upgrade check skipped" in stdout
        assert "should not run" not in stdout
