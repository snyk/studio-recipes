"""Tests for snyk-studio-installer.py (cross-platform Python installer)."""

from __future__ import annotations

import contextlib
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add installer root to path
INSTALLER_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(INSTALLER_DIR))
sys.path.insert(0, str(INSTALLER_DIR / "lib"))

# Import with underscore since the filename has hyphens
import importlib  # noqa: E402 — imports follow sys.path setup

installer = importlib.import_module("snyk-studio-installer")


def _is_snyk_version_cmd(cmd):
    return (
        isinstance(cmd, list)
        and len(cmd) == 2
        and cmd[1] == "--version"
        and Path(str(cmd[0])).name in {"snyk", "snyk.cmd", "snyk.exe"}
    )


def _make_executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _persist_selected_snyk_cli(selected: installer.SnykCliSelection | None) -> None:
    installer._sync_selected_snyk_cli_sidecars(selected, False)


def _cli_sidecar_values() -> tuple[str | None, str | None]:
    path_sidecar = installer.cli_path_sidecar()
    source_sidecar = installer.cli_source_sidecar()
    path_value = path_sidecar.read_text(encoding="utf-8").strip() if path_sidecar.exists() else None
    source_value = (
        source_sidecar.read_text(encoding="utf-8").strip() if source_sidecar.exists() else None
    )
    return path_value, source_value


def _set_npm_global_prefix_writable(monkeypatch, writable: bool) -> None:
    monkeypatch.setattr(
        installer.SnykCliResolver,
        "npm_global_prefix_writable",
        lambda self: writable,
    )


# ===========================================================================
# TestCheckPrerequisites
# ===========================================================================


class TestCheckPrerequisites:
    @pytest.fixture(autouse=True)
    def mock_node_installed(self, monkeypatch, tmp_path):
        monkeypatch.setattr(installer, "ensure_node_installed", lambda *_: True)
        sidecar_dir = tmp_path / "home" / ".snyk-studio"
        monkeypatch.setattr(installer, "cli_path_sidecar", lambda: sidecar_dir / "cli-path")
        monkeypatch.setattr(installer, "cli_source_sidecar", lambda: sidecar_dir / "cli-source")

    def test_all_ok(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None
        )

        def mock_run(cmd, **kwargs):
            m = MagicMock()
            if _is_snyk_version_cmd(cmd):
                m.stdout = "1.1302.0\n"
                m.returncode = 0
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        # Should not raise SystemExit
        selected = installer.check_prerequisites(auto_yes=True)
        captured = capsys.readouterr()
        assert "OK Snyk CLI 1.1302.0" in captured.out
        assert selected == installer.SnykCliSelection(
            "/usr/local/bin/snyk",
            "1.1302.0",
            installer.SNYK_CLI_SOURCE_PATH,
        )

    def test_path_snyk_is_path_managed_even_if_npm_global(self, monkeypatch, tmp_path):
        npm_cli = _make_executable(tmp_path / "npm" / "bin" / "snyk")
        monkeypatch.setattr("shutil.which", lambda cmd: str(npm_cli) if cmd == "snyk" else None)

        def mock_run(cmd, **kwargs):
            if cmd[:3] == ["npm", "prefix", "-g"]:
                raise AssertionError("PATH-managed Snyk should not probe npm ownership")
            m = MagicMock(returncode=0)
            if cmd == [str(npm_cli), "--version"]:
                m.stdout = "1.1306.0\n"
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        selected = installer.check_prerequisites(auto_yes=True, snyk_version="1.1306.0")
        _persist_selected_snyk_cli(selected)

        assert selected == installer.SnykCliSelection(
            str(npm_cli),
            "1.1306.0",
            installer.SNYK_CLI_SOURCE_PATH,
        )
        assert _cli_sidecar_values() == (None, None)

    def test_outdated_snyk_warning(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None
        )

        def mock_run(cmd, **kwargs):
            m = MagicMock()
            if _is_snyk_version_cmd(cmd):
                m.stdout = "1.1301.0\n"
                m.returncode = 0
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        # With auto_yes=True, an outdated PATH-managed Snyk opts into npm management.
        installer.check_prerequisites(auto_yes=True, snyk_version="1.1302.0")
        captured = capsys.readouterr()
        assert "WARNING Snyk CLI 1.1301.0 at /usr/local/bin/snyk is outdated" in captured.out

    def test_outdated_snyk_cancel(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None
        )

        def mock_run(cmd, **kwargs):
            m = MagicMock()
            if _is_snyk_version_cmd(cmd):
                m.stdout = "1.1301.0\n"
                m.returncode = 0
            return m

        monkeypatch.setattr(installer, "run", mock_run)
        monkeypatch.setattr("builtins.input", lambda _: "n")

        with pytest.raises(SystemExit):
            installer.check_prerequisites(auto_yes=False, snyk_version="1.1302.0")

        captured = capsys.readouterr()
        assert "WARNING Snyk CLI 1.1301.0 at /usr/local/bin/snyk is outdated" in captured.out

    def test_snyk_not_found(self, monkeypatch, capsys):
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        monkeypatch.setattr("sys.platform", "linux")

        cmds_run = []

        def mock_run(cmd, **kwargs):
            cmds_run.append(cmd)
            return MagicMock(returncode=0)

        monkeypatch.setattr(installer, "run", mock_run)

        # Mock input to say 'y' to continue
        monkeypatch.setattr("builtins.input", lambda _: "y")

        installer.check_prerequisites(auto_yes=False)
        assert ["npm", "install", "-g", "snyk"] in cmds_run
        captured = capsys.readouterr()
        assert "WARNING Snyk CLI not found" in captured.out

    def test_snyk_not_found_returns_npm_installed_selection(self, monkeypatch, tmp_path, capsys):
        npm_prefix = tmp_path / "npm"
        npm_cli = _make_executable(npm_prefix / "bin" / "snyk")
        installed = False

        monkeypatch.setattr("shutil.which", lambda cmd: None)

        cmds_run = []

        def mock_run(cmd, **kwargs):
            nonlocal installed
            cmds_run.append(cmd)
            m = MagicMock(returncode=0)
            if cmd[:3] == ["npm", "prefix", "-g"]:
                m.stdout = f"{npm_prefix}\n"
            elif cmd[:3] == ["npm", "install", "-g"]:
                installed = True
            elif cmd == [str(npm_cli), "--version"] and installed:
                m.stdout = "1.1306.0\n"
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        selected = installer.check_prerequisites(auto_yes=True)

        assert ["npm", "install", "-g", "snyk"] in cmds_run
        assert selected == installer.SnykCliSelection(
            str(npm_cli),
            "1.1306.0",
            installer.SNYK_CLI_SOURCE_NPM,
        )
        captured = capsys.readouterr()
        assert f"OK Snyk CLI 1.1306.0 ({npm_cli})" in captured.out

    def test_npm_install_succeeds_but_version_probe_fails_still_selects_cli(
        self, monkeypatch, tmp_path, capsys
    ):
        """A binary that npm just installed but that transiently fails to report
        a version must still be selected (and thus still pinned to the
        sidecar) -- not discarded as if npm's install itself had failed."""
        npm_prefix = tmp_path / "npm"
        npm_cli = _make_executable(npm_prefix / "bin" / "snyk")

        monkeypatch.setattr("shutil.which", lambda cmd: None)

        cmds_run = []

        def mock_run(cmd, **kwargs):
            cmds_run.append(cmd)
            m = MagicMock(returncode=0)
            if cmd[:3] == ["npm", "prefix", "-g"]:
                m.stdout = f"{npm_prefix}\n"
            elif cmd[:3] == ["npm", "install", "-g"]:
                pass
            elif cmd == [str(npm_cli), "--version"]:
                m.stdout = ""
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        selected = installer.check_prerequisites(auto_yes=True)

        assert ["npm", "install", "-g", "snyk"] in cmds_run
        assert selected == installer.SnykCliSelection(
            str(npm_cli),
            None,
            installer.SNYK_CLI_SOURCE_NPM,
        )
        captured = capsys.readouterr()
        assert f"installed via npm ({npm_cli}) but did not report a version" in captured.out

    def test_sidecar_user_specified_wins_over_path_without_npm_update(
        self, monkeypatch, tmp_path, capsys
    ):
        sidecar_cli = _make_executable(tmp_path / "user-specified" / "snyk")
        sidecar = tmp_path / "home" / ".snyk-studio" / "cli-path"
        sidecar.parent.mkdir(parents=True)
        sidecar.write_text(str(sidecar_cli), encoding="utf-8")
        (sidecar.parent / "cli-source").write_text(installer.SNYK_CLI_SOURCE_USER_SPECIFIED)

        monkeypatch.setattr(installer, "cli_path_sidecar", lambda: sidecar)
        monkeypatch.setattr(installer, "cli_source_sidecar", lambda: sidecar.parent / "cli-source")
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None
        )

        cmds_run = []

        def mock_run(cmd, **kwargs):
            cmds_run.append(cmd)
            m = MagicMock(returncode=0)
            if cmd[0] == str(sidecar_cli) and cmd[1] == "--version":
                m.stdout = "1.1301.0\n"
            elif cmd[0] == "/usr/local/bin/snyk" and cmd[1] == "--version":
                m.stdout = "1.1400.0\n"
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        selected = installer.check_prerequisites(auto_yes=True, snyk_version="1.1302.0")

        assert selected == installer.SnykCliSelection(
            str(sidecar_cli),
            "1.1301.0",
            installer.SNYK_CLI_SOURCE_USER_SPECIFIED,
        )
        assert not any(c[:3] == ["npm", "install", "-g"] for c in cmds_run)
        captured = capsys.readouterr()
        assert f"Snyk CLI 1.1301.0 at {sidecar_cli} is older" in captured.out

    def test_sidecar_npm_path_uses_sidecar_version_for_update(self, monkeypatch, tmp_path, capsys):
        npm_prefix = tmp_path / "npm"
        sidecar_cli = _make_executable(npm_prefix / "bin" / "snyk")
        sidecar = tmp_path / "home" / ".snyk-studio" / "cli-path"
        source_sidecar = sidecar.parent / "cli-source"
        sidecar.parent.mkdir(parents=True)
        sidecar.write_text(str(sidecar_cli), encoding="utf-8")
        source_sidecar.write_text(installer.SNYK_CLI_SOURCE_NPM, encoding="utf-8")
        installed = False

        monkeypatch.setattr(installer, "cli_path_sidecar", lambda: sidecar)
        monkeypatch.setattr(installer, "cli_source_sidecar", lambda: source_sidecar)
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None
        )
        monkeypatch.setattr("builtins.input", lambda _: "y")

        cmds_run = []

        def mock_run(cmd, **kwargs):
            nonlocal installed
            cmds_run.append(cmd)
            m = MagicMock(returncode=0)
            if cmd[:3] == ["npm", "prefix", "-g"]:
                m.stdout = f"{npm_prefix}\n"
            elif cmd[:3] == ["npm", "install", "-g"]:
                installed = True
            elif cmd[0] == str(sidecar_cli) and cmd[1] == "--version":
                m.stdout = "1.1306.0\n" if installed else "1.1301.0\n"
            elif cmd[0] == "/usr/local/bin/snyk" and cmd[1] == "--version":
                m.stdout = "1.1400.0\n"
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        selected = installer.check_prerequisites(auto_yes=False, snyk_version="1.1302.0")

        assert ["npm", "install", "-g", "snyk@latest"] in cmds_run
        assert selected == installer.SnykCliSelection(
            str(sidecar_cli),
            "1.1306.0",
            installer.SNYK_CLI_SOURCE_NPM,
        )
        captured = capsys.readouterr()
        assert "WARNING Snyk CLI 1.1301.0 is outdated" in captured.out
        assert "Snyk CLI 1.1400.0 is outdated" not in captured.out

    def test_outdated_snyk_auto_upgrade(self, monkeypatch, tmp_path, capsys):
        npm_prefix = tmp_path / "npm"
        npm_cli = _make_executable(npm_prefix / "bin" / "snyk")
        installed = False

        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None
        )

        cmds_run = []

        def mock_run(cmd, **kwargs):
            nonlocal installed
            cmds_run.append(cmd)
            m = MagicMock()
            if cmd[:3] == ["npm", "prefix", "-g"]:
                m.stdout = f"{npm_prefix}\n"
            elif cmd[:3] == ["npm", "install", "-g"]:
                installed = True
            elif cmd == ["/usr/local/bin/snyk", "--version"]:
                m.stdout = "1.1301.0\n"
            elif cmd == [str(npm_cli), "--version"] and installed:
                m.stdout = "1.1306.0\n"
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        selected = installer.check_prerequisites(auto_yes=True, snyk_version="1.1302.0")

        # Verify that npm install was called
        assert ["npm", "install", "-g", "snyk@latest"] in cmds_run
        assert selected == installer.SnykCliSelection(
            str(npm_cli),
            "1.1306.0",
            installer.SNYK_CLI_SOURCE_NPM,
        )
        captured = capsys.readouterr()
        assert "WARNING Snyk CLI 1.1301.0 at /usr/local/bin/snyk is outdated" in captured.out

    def test_global_pins_snyk_on_upgrade(self, monkeypatch, capsys):
        """In --no-latest-deps mode an outdated Snyk upgrades to the pinned version, not latest."""
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None
        )
        monkeypatch.setattr("sys.platform", "linux")

        cmds_run = []

        def mock_run(cmd, **kwargs):
            cmds_run.append(cmd)
            m = MagicMock()
            if _is_snyk_version_cmd(cmd):
                m.stdout = "1.1301.0\n"
                m.returncode = 0
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        installer.check_prerequisites(auto_yes=True, snyk_version="1.1304.0", no_latest_deps=True)

        assert ["npm", "install", "-g", "snyk@1.1304.0"] in cmds_run
        assert ["npm", "install", "-g", "snyk@latest"] not in cmds_run

    def test_global_pins_snyk_when_missing(self, monkeypatch, capsys):
        """In --no-latest-deps mode a missing Snyk installs exactly the pinned version."""
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        monkeypatch.setattr("sys.platform", "linux")

        cmds_run = []

        def mock_run(cmd, **kwargs):
            cmds_run.append(cmd)
            return MagicMock(returncode=0)

        monkeypatch.setattr(installer, "run", mock_run)
        monkeypatch.setattr("builtins.input", lambda _: "y")

        installer.check_prerequisites(auto_yes=True, snyk_version="1.1304.0", no_latest_deps=True)

        assert ["npm", "install", "-g", "snyk@1.1304.0"] in cmds_run

    def test_global_skips_snyk_when_newer_than_pin(self, monkeypatch, capsys):
        """In --no-latest-deps mode an installed Snyk newer than the pin is left untouched."""
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None
        )
        monkeypatch.setattr("sys.platform", "linux")

        cmds_run = []

        def mock_run(cmd, **kwargs):
            cmds_run.append(cmd)
            m = MagicMock()
            if _is_snyk_version_cmd(cmd):
                m.stdout = "1.1310.0\n"
                m.returncode = 0
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        installer.check_prerequisites(auto_yes=True, snyk_version="1.1304.0", no_latest_deps=True)

        assert not any(c[:2] == ["npm", "install"] for c in cmds_run)
        captured = capsys.readouterr()
        assert "OK Snyk CLI 1.1310.0" in captured.out

    def test_version_parse_edge_case(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None
        )

        def mock_run(cmd, **kwargs):
            m = MagicMock()
            if _is_snyk_version_cmd(cmd):
                m.stdout = "1.1302.0 (custom)\n"
                m.returncode = 0
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        installer.check_prerequisites(auto_yes=True)
        captured = capsys.readouterr()
        assert "OK Snyk CLI 1.1302.0 (custom)" in captured.out
        assert "is outdated" not in captured.out

    def test_version_malformed_no_error(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None
        )

        def mock_run(cmd, **kwargs):
            m = MagicMock()
            if _is_snyk_version_cmd(cmd):
                m.stdout = "development-version\n"
                m.returncode = 0
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        installer.check_prerequisites(auto_yes=True)

    def test_snyk_on_path_but_not_executable_installs_instead_of_crashing(
        self, monkeypatch, capsys
    ):
        """snyk resolves via `which` but exec raises FileNotFoundError — install, don't crash."""
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None
        )
        monkeypatch.setattr(installer, "ensure_node_installed", lambda *_: True)

        cmds_run = []

        def mock_run(cmd, **kwargs):
            # The version probe (the literal "snyk") fails like the real crash.
            if _is_snyk_version_cmd(cmd):
                raise FileNotFoundError(2, "No such file or directory", "snyk")
            cmds_run.append(cmd)
            return MagicMock(returncode=0)

        monkeypatch.setattr(installer, "run", mock_run)

        # Must not raise; falls through to (re)install Snyk.
        installer.check_prerequisites(auto_yes=True)
        assert ["npm", "install", "-g", "snyk"] in cmds_run
        assert "Snyk CLI not found" in capsys.readouterr().out

    def test_outdated_path_snyk_without_npm_does_not_run_npm_install(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None
        )
        monkeypatch.setattr(installer, "ensure_node_installed", lambda *_: False)
        inputs = iter(["y", "y"])
        monkeypatch.setattr("builtins.input", lambda _: next(inputs))

        cmds_run = []

        def mock_run(cmd, **kwargs):
            cmds_run.append(cmd)
            m = MagicMock(returncode=0)
            if cmd == ["/usr/local/bin/snyk", "--version"]:
                m.stdout = "1.1301.0\n"
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        selected = installer.check_prerequisites(auto_yes=False, snyk_version="1.1302.0")

        assert selected == installer.SnykCliSelection(
            "/usr/local/bin/snyk",
            "1.1301.0",
            installer.SNYK_CLI_SOURCE_PATH,
        )
        assert not any(c[:3] == ["npm", "install", "-g"] for c in cmds_run)
        captured = capsys.readouterr()
        assert "Node.js/npm is required to upgrade Snyk CLI via npm" in captured.out

    def test_missing_snyk_without_npm_does_not_run_npm_install(self, monkeypatch, capsys):
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        monkeypatch.setattr(installer, "ensure_node_installed", lambda *_: False)
        inputs = iter(["y", "y"])
        monkeypatch.setattr("builtins.input", lambda _: next(inputs))

        cmds_run = []

        def mock_run(cmd, **kwargs):
            cmds_run.append(cmd)
            return MagicMock(returncode=0)

        monkeypatch.setattr(installer, "run", mock_run)

        selected = installer.check_prerequisites(auto_yes=False)

        assert selected is None
        assert not any(c[:3] == ["npm", "install", "-g"] for c in cmds_run)
        captured = capsys.readouterr()
        assert "Node.js/npm is required to install Snyk CLI via npm" in captured.out

    def test_path_source_clears_sidecar(self, tmp_path, monkeypatch):
        sidecar = tmp_path / "home" / ".snyk-studio" / "cli-path"
        source_sidecar = sidecar.parent / "cli-source"
        sidecar.parent.mkdir(parents=True)
        sidecar.write_text("/old/snyk", encoding="utf-8")
        source_sidecar.write_text(installer.SNYK_CLI_SOURCE_NPM, encoding="utf-8")
        monkeypatch.setattr(installer, "cli_path_sidecar", lambda: sidecar)
        monkeypatch.setattr(installer, "cli_source_sidecar", lambda: source_sidecar)

        installer._sync_selected_snyk_cli_sidecars(
            installer.SnykCliSelection(
                "/usr/local/bin/snyk",
                "1.1306.0",
                installer.SNYK_CLI_SOURCE_PATH,
            ),
            False,
        )

        assert not sidecar.exists()
        assert not source_sidecar.exists()

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX file mode bits")
    def test_sync_sidecars_writes_owner_only_permissions(self, tmp_path, monkeypatch):
        sidecar = tmp_path / "home" / ".snyk-studio" / "cli-path"
        source_sidecar = sidecar.parent / "cli-source"
        monkeypatch.setattr(installer, "cli_path_sidecar", lambda: sidecar)
        monkeypatch.setattr(installer, "cli_source_sidecar", lambda: source_sidecar)

        installer._sync_selected_snyk_cli_sidecars(
            installer.SnykCliSelection(
                "/usr/local/bin/snyk",
                "1.1306.0",
                installer.SNYK_CLI_SOURCE_NPM,
            ),
            False,
        )

        assert (sidecar.stat().st_mode & 0o777) == 0o600
        assert (source_sidecar.stat().st_mode & 0o777) == 0o600

    def test_reinstall_path_managed_cli_remains_dynamic(self, monkeypatch, capsys):
        current_path_snyk = "/usr/local/bin/snyk"
        versions = {
            "/usr/local/bin/snyk": "1.1306.0\n",
            "/opt/homebrew/bin/snyk": "1.1307.0\n",
        }
        sidecar = installer.cli_path_sidecar()
        source_sidecar = installer.cli_source_sidecar()
        sidecar.parent.mkdir(parents=True)
        sidecar.write_text("/stale/npm/snyk", encoding="utf-8")
        source_sidecar.write_text(installer.SNYK_CLI_SOURCE_NPM, encoding="utf-8")

        def mock_which(cmd):
            return current_path_snyk if cmd == "snyk" else None

        def mock_run(cmd, **kwargs):
            m = MagicMock(returncode=0)
            if isinstance(cmd, list) and cmd == [current_path_snyk, "--version"]:
                m.stdout = versions[current_path_snyk]
            return m

        monkeypatch.setattr("shutil.which", mock_which)
        monkeypatch.setattr(installer, "run", mock_run)

        first = installer.check_prerequisites(auto_yes=True, snyk_version="1.1306.0")
        _persist_selected_snyk_cli(first)

        assert first == installer.SnykCliSelection(
            "/usr/local/bin/snyk",
            "1.1306.0",
            installer.SNYK_CLI_SOURCE_PATH,
        )
        assert _cli_sidecar_values() == (None, None)

        current_path_snyk = "/opt/homebrew/bin/snyk"
        second = installer.check_prerequisites(auto_yes=True, snyk_version="1.1306.0")
        _persist_selected_snyk_cli(second)

        assert second == installer.SnykCliSelection(
            "/opt/homebrew/bin/snyk",
            "1.1307.0",
            installer.SNYK_CLI_SOURCE_PATH,
        )
        assert _cli_sidecar_values() == (None, None)
        assert "OK Snyk CLI 1.1307.0" in capsys.readouterr().out

    def test_reinstall_npm_managed_cli_uses_sidecar_not_newer_path(
        self, monkeypatch, tmp_path, capsys
    ):
        npm_prefix = tmp_path / "npm"
        npm_cli = _make_executable(npm_prefix / "bin" / "snyk")
        npm_version = "1.1302.0"
        path_snyk: str | None = None
        npm_installs: list[list[str]] = []

        def mock_which(cmd):
            return path_snyk if cmd == "snyk" else None

        def mock_run(cmd, **kwargs):
            nonlocal npm_version
            m = MagicMock(returncode=0)
            if cmd[:3] == ["npm", "prefix", "-g"]:
                m.stdout = f"{npm_prefix}\n"
            elif cmd[:3] == ["npm", "install", "-g"]:
                npm_installs.append(cmd)
                npm_version = "1.1307.0" if cmd[3] == "snyk@latest" else "1.1302.0"
            elif cmd == [str(npm_cli), "--version"]:
                m.stdout = f"{npm_version}\n"
            elif path_snyk and cmd == [path_snyk, "--version"]:
                m.stdout = "1.1400.0\n"
            return m

        monkeypatch.setattr("shutil.which", mock_which)
        monkeypatch.setattr(installer, "run", mock_run)

        first = installer.check_prerequisites(auto_yes=True, snyk_version="1.1302.0")
        _persist_selected_snyk_cli(first)

        assert first == installer.SnykCliSelection(
            str(npm_cli),
            "1.1302.0",
            installer.SNYK_CLI_SOURCE_NPM,
        )
        assert _cli_sidecar_values() == (str(npm_cli), installer.SNYK_CLI_SOURCE_NPM)

        # A later install should read the npm-managed sidecar's version. Even
        # if the user now has a newer unrelated Snyk on PATH, the installer
        # should update the npm-managed CLI it previously selected.
        path_snyk = "/usr/local/bin/snyk"
        second = installer.check_prerequisites(auto_yes=True, snyk_version="1.1306.0")
        _persist_selected_snyk_cli(second)

        assert npm_installs == [
            ["npm", "install", "-g", "snyk"],
            ["npm", "install", "-g", "snyk@latest"],
        ]
        assert second == installer.SnykCliSelection(
            str(npm_cli),
            "1.1307.0",
            installer.SNYK_CLI_SOURCE_NPM,
        )
        assert _cli_sidecar_values() == (str(npm_cli), installer.SNYK_CLI_SOURCE_NPM)
        captured = capsys.readouterr()
        assert "WARNING Snyk CLI 1.1302.0 is outdated" in captured.out
        assert "Snyk CLI 1.1400.0 is outdated" not in captured.out

    def test_reinstall_user_specified_cli_stays_strict(self, monkeypatch, tmp_path, capsys):
        user_cli = _make_executable(tmp_path / "user" / "snyk")
        cmds_run = []

        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None
        )

        def mock_run(cmd, **kwargs):
            cmds_run.append(cmd)
            m = MagicMock(returncode=0)
            if cmd == [str(user_cli), "--version"]:
                m.stdout = "1.1301.0\n"
            elif cmd == ["/usr/local/bin/snyk", "--version"]:
                m.stdout = "1.1400.0\n"
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        first = installer.check_prerequisites(
            auto_yes=True,
            snyk_version="1.1306.0",
            cli_path=str(user_cli),
        )
        _persist_selected_snyk_cli(first)

        assert _cli_sidecar_values() == (
            str(user_cli),
            installer.SNYK_CLI_SOURCE_USER_SPECIFIED,
        )

        second = installer.check_prerequisites(auto_yes=True, snyk_version="1.1306.0")
        _persist_selected_snyk_cli(second)

        assert (
            first
            == second
            == installer.SnykCliSelection(
                str(user_cli),
                "1.1301.0",
                installer.SNYK_CLI_SOURCE_USER_SPECIFIED,
            )
        )
        assert _cli_sidecar_values() == (
            str(user_cli),
            installer.SNYK_CLI_SOURCE_USER_SPECIFIED,
        )
        assert not any(c[:3] == ["npm", "install", "-g"] for c in cmds_run)
        captured = capsys.readouterr()
        assert f"Snyk CLI 1.1301.0 at {user_cli} is older" in captured.out
        assert "Snyk CLI 1.1400.0 is outdated" not in captured.out

    def test_reinstall_legacy_path_only_sidecar_becomes_user_specified(
        self, monkeypatch, tmp_path, capsys
    ):
        legacy_cli = _make_executable(tmp_path / "legacy" / "snyk")
        sidecar = installer.cli_path_sidecar()
        sidecar.parent.mkdir(parents=True)
        sidecar.write_text(str(legacy_cli), encoding="utf-8")

        cmds_run = []

        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None
        )

        def mock_run(cmd, **kwargs):
            cmds_run.append(cmd)
            m = MagicMock(returncode=0)
            if cmd == [str(legacy_cli), "--version"]:
                m.stdout = "1.1301.0\n"
            elif cmd == ["/usr/local/bin/snyk", "--version"]:
                m.stdout = "1.1400.0\n"
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        selected = installer.check_prerequisites(auto_yes=True, snyk_version="1.1306.0")
        _persist_selected_snyk_cli(selected)

        assert selected == installer.SnykCliSelection(
            str(legacy_cli),
            "1.1301.0",
            installer.SNYK_CLI_SOURCE_USER_SPECIFIED,
        )
        assert _cli_sidecar_values() == (
            str(legacy_cli),
            installer.SNYK_CLI_SOURCE_USER_SPECIFIED,
        )
        assert not any(c[:3] == ["npm", "install", "-g"] for c in cmds_run)
        assert f"Snyk CLI 1.1301.0 at {legacy_cli} is older" in capsys.readouterr().out

    def test_reinstall_ignores_stale_path_source_sidecar(self, monkeypatch, tmp_path):
        stale_path_cli = _make_executable(tmp_path / "old-path" / "snyk")
        current_path_cli = "/usr/local/bin/snyk"
        sidecar = installer.cli_path_sidecar()
        source_sidecar = installer.cli_source_sidecar()
        sidecar.parent.mkdir(parents=True)
        sidecar.write_text(str(stale_path_cli), encoding="utf-8")
        source_sidecar.write_text(installer.SNYK_CLI_SOURCE_PATH, encoding="utf-8")

        monkeypatch.setattr("shutil.which", lambda cmd: current_path_cli if cmd == "snyk" else None)

        def mock_run(cmd, **kwargs):
            m = MagicMock(returncode=0)
            if cmd == [str(stale_path_cli), "--version"]:
                m.stdout = "1.1200.0\n"
            elif cmd == [current_path_cli, "--version"]:
                m.stdout = "1.1306.0\n"
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        selected = installer.check_prerequisites(auto_yes=True, snyk_version="1.1306.0")
        _persist_selected_snyk_cli(selected)

        assert selected == installer.SnykCliSelection(
            current_path_cli,
            "1.1306.0",
            installer.SNYK_CLI_SOURCE_PATH,
        )
        assert _cli_sidecar_values() == (None, None)

    def test_relative_sidecar_path_is_ignored(self, monkeypatch, tmp_path):
        cwd_cli = _make_executable(tmp_path / "cwd" / "snyk")
        sidecar = installer.cli_path_sidecar()
        source_sidecar = installer.cli_source_sidecar()
        sidecar.parent.mkdir(parents=True)
        sidecar.write_text(cwd_cli.name, encoding="utf-8")
        source_sidecar.write_text(installer.SNYK_CLI_SOURCE_NPM, encoding="utf-8")
        monkeypatch.chdir(cwd_cli.parent)

        current_path_cli = "/usr/local/bin/snyk"
        monkeypatch.setattr("shutil.which", lambda cmd: current_path_cli if cmd == "snyk" else None)

        def mock_run(cmd, **kwargs):
            m = MagicMock(returncode=0)
            if cmd == [current_path_cli, "--version"]:
                m.stdout = "1.1306.0\n"
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        selected = installer.check_prerequisites(auto_yes=True, snyk_version="1.1306.0")

        assert selected == installer.SnykCliSelection(
            current_path_cli,
            "1.1306.0",
            installer.SNYK_CLI_SOURCE_PATH,
        )

    def test_invalid_encoded_sidecar_path_is_ignored(self, monkeypatch):
        sidecar = installer.cli_path_sidecar()
        source_sidecar = installer.cli_source_sidecar()
        sidecar.parent.mkdir(parents=True)
        sidecar.write_bytes(b"\xff")
        source_sidecar.write_text(installer.SNYK_CLI_SOURCE_NPM, encoding="utf-8")

        current_path_cli = "/usr/local/bin/snyk"
        monkeypatch.setattr("shutil.which", lambda cmd: current_path_cli if cmd == "snyk" else None)

        def mock_run(cmd, **kwargs):
            m = MagicMock(returncode=0)
            if cmd == [current_path_cli, "--version"]:
                m.stdout = "1.1306.0\n"
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        selected = installer.check_prerequisites(auto_yes=True, snyk_version="1.1306.0")

        assert selected == installer.SnykCliSelection(
            current_path_cli,
            "1.1306.0",
            installer.SNYK_CLI_SOURCE_PATH,
        )

    def test_invalid_encoded_sidecar_source_defaults_to_user_specified(
        self, monkeypatch, tmp_path, capsys
    ):
        sidecar_cli = _make_executable(tmp_path / "sidecar" / "snyk")
        sidecar = installer.cli_path_sidecar()
        source_sidecar = installer.cli_source_sidecar()
        sidecar.parent.mkdir(parents=True)
        sidecar.write_text(str(sidecar_cli), encoding="utf-8")
        source_sidecar.write_bytes(b"\xff")

        current_path_cli = "/usr/local/bin/snyk"
        cmds_run = []
        monkeypatch.setattr("shutil.which", lambda cmd: current_path_cli if cmd == "snyk" else None)

        def mock_run(cmd, **kwargs):
            cmds_run.append(cmd)
            m = MagicMock(returncode=0)
            if cmd == [str(sidecar_cli), "--version"]:
                m.stdout = "1.1301.0\n"
            elif cmd == [current_path_cli, "--version"]:
                m.stdout = "1.1400.0\n"
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        selected = installer.check_prerequisites(auto_yes=True, snyk_version="1.1306.0")

        assert selected == installer.SnykCliSelection(
            str(sidecar_cli),
            "1.1301.0",
            installer.SNYK_CLI_SOURCE_USER_SPECIFIED,
        )
        assert not any(c[:3] == ["npm", "install", "-g"] for c in cmds_run)
        assert f"Snyk CLI 1.1301.0 at {sidecar_cli} is older" in capsys.readouterr().out


# ===========================================================================
# TestReadOnlySelectedSnykCli
# ===========================================================================


class TestReadOnlySelectedSnykCli:
    def test_cli_path_wins_unconditionally(self, monkeypatch, tmp_path):
        cli = _make_executable(tmp_path / "user" / "snyk")

        selected = installer._read_only_selected_snyk_cli(str(cli))

        assert selected == installer.SnykCliSelection(
            str(cli), None, installer.SNYK_CLI_SOURCE_USER_SPECIFIED
        )

    def test_broken_path_snyk_is_rejected_like_check_prerequisites(self, monkeypatch, tmp_path):
        """A PATH `snyk` that can't report a version must be treated as
        unusable here too, matching check_prerequisites's require_version=True
        probe -- otherwise --verify --read-only could see a PATH selection
        that a real install would have routed to npm instead."""
        home = tmp_path / "home"
        monkeypatch.setattr(installer, "cli_path_sidecar", lambda: home / ".snyk-studio/cli-path")
        monkeypatch.setattr(
            installer, "cli_source_sidecar", lambda: home / ".snyk-studio/cli-source"
        )
        broken = _make_executable(tmp_path / "path" / "snyk")
        monkeypatch.setattr("shutil.which", lambda cmd: str(broken) if cmd == "snyk" else None)
        monkeypatch.setattr(installer, "run", lambda *a, **kw: MagicMock(returncode=1, stdout=""))

        assert installer._read_only_selected_snyk_cli(None) is None

    def test_working_path_snyk_is_selected(self, monkeypatch, tmp_path):
        home = tmp_path / "home"
        monkeypatch.setattr(installer, "cli_path_sidecar", lambda: home / ".snyk-studio/cli-path")
        monkeypatch.setattr(
            installer, "cli_source_sidecar", lambda: home / ".snyk-studio/cli-source"
        )
        path_cli = _make_executable(tmp_path / "path" / "snyk")
        monkeypatch.setattr("shutil.which", lambda cmd: str(path_cli) if cmd == "snyk" else None)

        def mock_run(cmd, **kwargs):
            if cmd == [str(path_cli), "--version"]:
                return MagicMock(returncode=0, stdout="1.1306.0\n")
            return MagicMock(returncode=0, stdout="")

        monkeypatch.setattr(installer, "run", mock_run)

        assert installer._read_only_selected_snyk_cli(None) == installer.SnykCliSelection(
            str(path_cli), "1.1306.0", installer.SNYK_CLI_SOURCE_PATH
        )


# ===========================================================================
# TestPrintPrerequisiteVersions
# ===========================================================================


class TestPrintPrerequisiteVersions:
    def test_prints_versions_without_prompting(self, monkeypatch, capsys):
        monkeypatch.setattr(installer, "_get_node_version", lambda: (24, 12, 0))
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None
        )

        def mock_run(cmd, **kwargs):
            m = MagicMock()
            if _is_snyk_version_cmd(cmd):
                m.stdout = "1.1302.0\n"
                m.returncode = 0
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        def _no_input(*_a, **_kw):
            raise AssertionError("print_prerequisite_versions must not prompt")

        monkeypatch.setattr("builtins.input", _no_input)

        # Must not raise (and must not call input()).
        installer.print_prerequisite_versions()

        captured = capsys.readouterr()
        py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"
        assert f"OK Python {py_ver}" in captured.out
        assert "OK Node.js 24.12.0" in captured.out
        assert "OK Snyk CLI 1.1302.0" in captured.out


# ===========================================================================
# TestParseArgs
# ===========================================================================


class TestParseArgs:
    def test_defaults(self):
        args = installer.parse_args([])
        assert args.profile == "default"
        assert args.ade is None
        assert args.dry_run is False
        assert args.uninstall is False
        assert args.verify is False
        assert args.read_only is False
        assert args.list_mode is False
        assert args.yes is False
        assert args.no_latest_deps is False
        assert args.recipes is None
        assert args.control_identifier is None

    def test_all_flags(self):
        args = installer.parse_args(
            [
                "--profile",
                "minimal",
                "--ade",
                "cursor",
                "--dry-run",
                "--verify",
                "--read-only",
                "--list",
                "-y",
                "--no-latest-deps",
                "--recipes",
                "secure-at-commit",
                "--control-identifier",
                "machine-123",
            ]
        )
        assert args.profile == "minimal"
        assert args.ade == "cursor"
        assert args.dry_run is True
        assert args.verify is True
        assert args.read_only is True
        assert args.list_mode is True
        assert args.yes is True
        assert args.no_latest_deps is True
        assert args.recipes == ["secure-at-commit"]
        assert args.control_identifier == "machine-123"

    def test_no_latest_deps_explicit(self):
        args = installer.parse_args(["--no-latest-deps"])
        assert args.no_latest_deps is True

    def test_removed_secrets_precommit_hook_flag_rejected(self):
        with pytest.raises(SystemExit):
            installer.parse_args(["--secrets-precommit-hook"])

    def test_recipes_single_name(self):
        args = installer.parse_args(["--recipes", "secrets-precommit-hook"])
        assert args.recipes == ["secrets-precommit-hook"]

    def test_recipes_multiple_names(self):
        args = installer.parse_args(["--recipes", "secure-at-commit,secrets-precommit-hook"])
        assert args.recipes == ["secure-at-commit", "secrets-precommit-hook"]

    def test_recipes_strips_surrounding_whitespace(self):
        args = installer.parse_args(["--recipes", " secure-at-commit , secrets-precommit-hook "])
        assert args.recipes == ["secure-at-commit", "secrets-precommit-hook"]

    def test_recipes_collapses_duplicates(self):
        args = installer.parse_args(["--recipes", "secure-at-commit,secure-at-commit"])
        assert args.recipes == ["secure-at-commit"]

    def test_recipes_accepts_empty_value_as_empty_selection(self):
        args = installer.parse_args(["--recipes", ""])
        assert args.recipes == []

        equals_args = installer.parse_args(["--recipes="])
        assert equals_args.recipes == []

    def test_recipes_rejects_empty_element(self):
        with pytest.raises(SystemExit):
            installer.parse_args(["--recipes", "secure-at-commit,,secrets-precommit-hook"])

    def test_recipes_rejects_repeated_flag(self):
        with pytest.raises(SystemExit):
            installer.parse_args(
                ["--recipes", "secure-at-commit", "--recipes", "secrets-precommit-hook"]
            )

    def test_recipes_preserves_case_for_exact_matching(self):
        args = installer.parse_args(["--recipes", "Secure-At-Commit"])
        assert args.recipes == ["Secure-At-Commit"]

    def test_invalid_ade_rejected(self):
        with pytest.raises(SystemExit):
            installer.parse_args(["--ade", "vscode"])

    def test_gemini_ade_accepted(self):
        args = installer.parse_args(["--ade", "gemini"])
        assert args.ade == "gemini"

    def test_kiro_ade_accepted(self):
        args = installer.parse_args(["--ade", "kiro"])
        assert args.ade == "kiro"

    def test_codex_ade_accepted(self):
        args = installer.parse_args(["--ade", "codex"])
        assert args.ade == "codex"

    def test_windsurf_ade_accepted(self):
        args = installer.parse_args(["--ade", "windsurf"])
        assert args.ade == "windsurf"

    def test_copilot_cli_ade_accepted(self):
        args = installer.parse_args(["--ade", "copilot-cli"])
        assert args.ade == "copilot-cli"

    def test_copilot_vscode_ade_accepted(self):
        args = installer.parse_args(["--ade", "copilot-vscode"])
        assert args.ade == "copilot-vscode"


# ===========================================================================
# TestControlIdentifier
# ===========================================================================


class TestControlIdentifier:
    def test_device_id_path_under_home(self, monkeypatch, tmp_path):
        monkeypatch.setattr(installer.Path, "home", classmethod(lambda cls: tmp_path))
        assert installer.device_id_path() == tmp_path / ".snyk-studio" / "device-id"

    def test_write_creates_file_with_identifier(self, monkeypatch, tmp_path):
        target = tmp_path / ".snyk-studio" / "device-id"
        monkeypatch.setattr(installer, "device_id_path", lambda: target)

        installer.write_control_identifier("machine-123", dry_run=False)

        # Recipes read with .strip(), so a trailing newline is fine; the
        # identifier itself must round-trip exactly.
        assert target.read_text(encoding="utf-8").strip() == "machine-123"

    def test_write_overwrites_existing_file(self, monkeypatch, tmp_path):
        target = tmp_path / ".snyk-studio" / "device-id"
        target.parent.mkdir(parents=True)
        target.write_text("old-id\n", encoding="utf-8")
        monkeypatch.setattr(installer, "device_id_path", lambda: target)

        installer.write_control_identifier("new-id", dry_run=False)

        assert target.read_text(encoding="utf-8").strip() == "new-id"

    def test_write_dry_run_does_not_create_file(self, monkeypatch, tmp_path):
        target = tmp_path / ".snyk-studio" / "device-id"
        monkeypatch.setattr(installer, "device_id_path", lambda: target)

        installer.write_control_identifier("machine-123", dry_run=True)

        assert not target.exists()

    def test_write_failure_warns_but_does_not_raise(self, monkeypatch, tmp_path, capsys):
        target = tmp_path / ".snyk-studio" / "device-id"
        monkeypatch.setattr(installer, "device_id_path", lambda: target)

        def boom(*_args, **_kwargs):
            raise OSError("permission denied")

        monkeypatch.setattr(installer.Path, "write_text", boom)

        installer.write_control_identifier("machine-123", dry_run=False)

        err = capsys.readouterr().err
        assert "WARNING" in err
        assert "permission denied" in err


# ===========================================================================
# TestColor
# ===========================================================================


class TestColor:
    def test_disabled_returns_plain_text(self):
        c = installer.Color()
        c.enabled = False
        assert c.red("hello") == "hello"
        assert c.green("world") == "world"
        assert c.bold("test") == "test"

    def test_enabled_wraps_with_ansi(self):
        c = installer.Color()
        c.enabled = True
        result = c.red("error")
        assert "\033[" in result
        assert "error" in result


class TestNonInteractiveGuard:
    def test_install_fails_fast_without_tty(self, monkeypatch, capsys):
        # Non-interactive stdin + no -y: main() must fail fast, not block on a prompt.
        monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
        monkeypatch.setattr(
            installer,
            "parse_args",
            lambda: MagicMock(list_mode=False, yes=False, diag_dump=False, verify=False),
        )
        monkeypatch.setattr(installer, "PayloadContext", lambda: MagicMock())
        monkeypatch.setattr(installer, "Manifest", lambda *a, **k: MagicMock())
        with pytest.raises(SystemExit):
            installer.main()
        assert "interactive input required" in capsys.readouterr().err

    def test_list_mode_allowed_without_tty(self, monkeypatch):
        # --list never prompts, so it must work on a non-interactive stdin.
        monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
        monkeypatch.setattr(
            installer, "parse_args", lambda: MagicMock(list_mode=True, yes=False, diag_dump=False)
        )
        monkeypatch.setattr(installer, "PayloadContext", lambda: MagicMock())
        listed = MagicMock()
        monkeypatch.setattr(installer, "Manifest", lambda *a, **k: listed)
        installer.main()  # returns without SystemExit
        listed.list_recipes.assert_called_once()


# ===========================================================================
# TestEnsureNodeInstalled
# ===========================================================================


class TestEnsureNodeInstalled:
    def test_node_npm_already_installed(self, monkeypatch):
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/bin/cmd" if cmd in ("node", "npm") else None
        )
        _set_npm_global_prefix_writable(monkeypatch, True)
        assert installer.ensure_node_installed(auto_yes=True) is True

    def test_node_meets_minimum_no_warning(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/bin/cmd" if cmd in ("node", "npm") else None
        )
        _set_npm_global_prefix_writable(monkeypatch, True)
        monkeypatch.setattr(installer, "_get_node_version", lambda: (24, 12, 0))
        assert installer.ensure_node_installed(auto_yes=True, node_version="24.11.1") is True
        assert "is outdated" not in capsys.readouterr().out

    def test_outdated_node_warns_and_upgrades(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/bin/cmd" if cmd in ("node", "npm", "brew") else None
        )
        _set_npm_global_prefix_writable(monkeypatch, True)
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        monkeypatch.setattr(installer, "_get_node_version", lambda: (18, 0, 0))

        cmds_run = []
        monkeypatch.setattr(
            installer, "run", lambda cmd, **k: cmds_run.append(cmd) or MagicMock(returncode=0)
        )

        assert installer.ensure_node_installed(auto_yes=True, node_version="24.11.1") is True
        captured = capsys.readouterr()
        assert "WARNING Node.js 18.0.0 is outdated (min: 24.11.1)" in captured.out
        # macOS installs the exact version via nvm (no brew). The version is an
        # argv parameter, not interpolated into the shell script text.
        assert any(c[0] == "sh" and "nvm install" in c[2] and "24.11.1" in c for c in cmds_run), (
            cmds_run
        )

    def test_outdated_node_failed_upgrade_exits(self, monkeypatch, capsys):
        """A failed upgrade of an outdated Node must not silently proceed — it exits."""
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/bin/cmd" if cmd in ("node", "npm", "brew") else None
        )
        _set_npm_global_prefix_writable(monkeypatch, True)
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        monkeypatch.setattr(installer, "_get_node_version", lambda: (18, 0, 0))
        # Every install command (pin + fallback) fails.
        monkeypatch.setattr(
            installer, "run", lambda cmd, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        )

        with pytest.raises(SystemExit):
            installer.ensure_node_installed(auto_yes=True, node_version="24.11.1")
        out = capsys.readouterr().out
        assert "is outdated" in out
        # _run_node_install / fallback already printed the install failure before exit.
        assert "Installation failed" in out

    def test_outdated_node_declined_upgrade_returns_true(self, monkeypatch, capsys):
        """Declining the upgrade is an informed choice — proceed (warning already shown)."""
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/bin/cmd" if cmd in ("node", "npm", "brew") else None
        )
        _set_npm_global_prefix_writable(monkeypatch, True)
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        monkeypatch.setattr(installer, "_get_node_version", lambda: (18, 0, 0))
        monkeypatch.setattr("builtins.input", lambda prompt: "n")
        monkeypatch.setattr(
            installer, "run", lambda cmd, **k: (_ for _ in ()).throw(AssertionError("no install"))
        )

        assert installer.ensure_node_installed(auto_yes=False, node_version="24.11.1") is True

    def test_darwin_installs_exact_version_via_nvm(self, monkeypatch):
        """On macOS a target version installs that exact version via nvm."""
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        cmds = installer._build_node_install_cmds(auto_yes=True, node_version="24.11.1")
        assert len(cmds) == 1
        cmd = cmds[0]
        assert cmd[0] == "sh"
        assert cmd[1] == "-c"
        # The script is constant; the version is passed as an argv parameter.
        assert "nvm install" in cmd[2]
        assert "nvm alias default" in cmd[2]
        assert "24.11.1" in cmd

    def test_windows_winget_pins_exact_version(self, monkeypatch):
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "C:\\winget.exe" if cmd == "winget" else None
        )
        monkeypatch.setattr("platform.system", lambda: "Windows")
        cmds = installer._build_node_install_cmds(auto_yes=True, node_version="24.11.1")
        assert cmds == [
            [
                "winget",
                "install",
                "OpenJS.NodeJS",
                "--version",
                "24.11.1",
                "--silent",
                "--accept-package-agreements",
                "--accept-source-agreements",
            ]
        ]

    def test_windows_choco_pins_exact_version(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda cmd: "C:\\choco.exe" if cmd == "choco" else None)
        monkeypatch.setattr("platform.system", lambda: "Windows")
        cmds = installer._build_node_install_cmds(auto_yes=True, node_version="24.11.1")
        assert cmds == [["choco", "install", "nodejs", "--version=24.11.1", "-y"]]

    def test_windows_pinned_failure_falls_back_to_lts(self, monkeypatch, capsys):
        """When the exact-version winget pin fails, retry with the default LTS package."""
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "C:\\cmd.exe" if cmd in ("node", "npm", "winget") else None
        )
        monkeypatch.setattr("platform.system", lambda: "Windows")
        monkeypatch.setattr(installer, "_get_node_version", lambda: (18, 0, 0))

        attempted = []

        def mock_run(cmd, **k):
            attempted.append(cmd)
            # The exact-version pin fails; the LTS fallback succeeds.
            if "--version" in cmd and "24.11.1" in cmd:
                raise RuntimeError("No applicable installer version found")
            return MagicMock(returncode=0)

        monkeypatch.setattr(installer, "run", mock_run)

        assert installer.ensure_node_installed(auto_yes=True, node_version="24.11.1") is True
        captured = capsys.readouterr()
        # Pinned attempt happened first, then the fallback to the LTS package.
        assert any("--version" in c and "24.11.1" in c for c in attempted)
        assert [
            "winget",
            "install",
            "OpenJS.NodeJS.LTS",
            "--silent",
            "--accept-package-agreements",
            "--accept-source-agreements",
        ] in attempted
        assert "falling back to the package manager's default build" in captured.out

    def test_pinned_failure_no_fallback_when_unversioned(self, monkeypatch, capsys):
        """Without a target version there's nothing to fall back from; failure stays a failure."""
        monkeypatch.setattr("shutil.which", lambda cmd: "/bin/brew" if cmd == "brew" else None)
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        monkeypatch.setattr(
            installer, "run", lambda cmd, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        )
        assert installer.ensure_node_installed(auto_yes=True) is False
        assert "falling back" not in capsys.readouterr().out

    def test_linux_installs_exact_version_via_nvm(self, monkeypatch, capsys):
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        monkeypatch.setattr("platform.system", lambda: "Linux")
        cmds = installer._build_node_install_cmds(auto_yes=True, node_version="24.11.1")
        assert len(cmds) == 1
        cmd = cmds[0]
        assert cmd[0] == "sh"
        assert cmd[1] == "-c"
        # nvm honours the exact upstream version directly — no distro pkg.
        assert "nvm install" in cmd[2]
        assert "24.11.1" in cmd
        assert "via nvm" in capsys.readouterr().out

    def test_nvm_install_tag_normalizes_version(self):
        # Manifest stores a bare version; the release tag is v-prefixed.
        assert installer._nvm_install_tag("0.40.3") == "v0.40.3"
        assert installer._nvm_install_tag("v0.40.3") == "v0.40.3"
        # Falls back to a sane default when the manifest omits the pin.
        assert installer._nvm_install_tag(None) == "v0.40.3"
        assert installer._nvm_install_tag("") == "v0.40.3"

    def test_nvm_version_from_manifest_pins_install_url(self, monkeypatch):
        """The nvm release pinned by the manifest drives the install.sh URL."""
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        monkeypatch.setattr("platform.system", lambda: "Linux")
        cmds = installer._build_node_install_cmds(
            auto_yes=True, node_version="24.11.1", nvm_version="0.39.7"
        )
        # The install.sh URL is passed as an argv parameter to the shell script.
        cmd = cmds[0]
        assert any("nvm-sh/nvm/v0.39.7/install.sh" in str(a) for a in cmd)

    def test_outdated_node_user_declines_upgrade(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/bin/cmd" if cmd in ("node", "npm", "brew") else None
        )
        _set_npm_global_prefix_writable(monkeypatch, True)
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        monkeypatch.setattr(installer, "_get_node_version", lambda: (18, 0, 0))
        monkeypatch.setattr("builtins.input", lambda prompt: "n")

        runs = []
        monkeypatch.setattr(
            installer, "run", lambda cmd, **k: runs.append(cmd) or MagicMock(returncode=0)
        )

        # Declining the upgrade still leaves Node usable, so the prereq passes.
        assert installer.ensure_node_installed(auto_yes=False, node_version="24.11.1") is True
        captured = capsys.readouterr()
        assert "WARNING Node.js 18.0.0 is outdated" in captured.out
        assert runs == []  # no upgrade attempted

    def test_node_version_undetectable_stays_quiet(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/bin/cmd" if cmd in ("node", "npm") else None
        )
        _set_npm_global_prefix_writable(monkeypatch, True)
        monkeypatch.setattr(installer, "_get_node_version", lambda: None)
        assert installer.ensure_node_installed(auto_yes=True, node_version="24.11.1") is True
        assert "is outdated" not in capsys.readouterr().out

    def test_get_node_version_parses_v_prefix(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda cmd: "/bin/node" if cmd == "node" else None)
        monkeypatch.setattr(installer, "run", lambda cmd, **k: MagicMock(stdout="v24.11.1\n"))
        assert installer._get_node_version() == (24, 11, 1)

    def test_get_node_version_refreshes_path_for_nvm_node(self, monkeypatch):
        """Node reachable only via an un-indexed (NVM) dir: PATH is refreshed before probing."""
        on_path = {"node": False}
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/nvm/node" if cmd == "node" and on_path["node"] else None
        )
        monkeypatch.setattr(installer, "_find_win_npm_executable", lambda name: "C:\\nvm\\node.exe")

        def fake_refresh(*a, **k):
            on_path["node"] = True  # simulate the NVM dir being added to PATH

        monkeypatch.setattr(installer, "_update_process_path_for_nodejs", fake_refresh)

        probed = []

        def mock_run(cmd, **k):
            probed.append(cmd)
            return MagicMock(stdout="v24.11.1\n")

        monkeypatch.setattr(installer, "run", mock_run)

        assert installer._get_node_version() == (24, 11, 1)
        # The literal "node" is invoked (never the env-derived path), after the refresh.
        assert probed == [["node", "--version"]]

    def test_get_node_version_none_when_node_absent_after_refresh(self, monkeypatch):
        """If Node still isn't resolvable after the PATH refresh, return None without probing."""
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        monkeypatch.setattr(installer, "_find_win_npm_executable", lambda name: "C:\\nvm\\node.exe")
        monkeypatch.setattr(installer, "_update_process_path_for_nodejs", lambda *a, **k: None)

        def fail_run(*a, **k):
            raise AssertionError("run() must not be called when node is unresolvable")

        monkeypatch.setattr(installer, "run", fail_run)
        assert installer._get_node_version() is None

    def test_darwin_nvm_install(self, monkeypatch, capsys):
        """On macOS a missing Node is installed via nvm (no brew)."""

        monkeypatch.setattr("shutil.which", lambda cmd: None)
        monkeypatch.setattr("platform.system", lambda: "Darwin")

        cmds_run = []

        def mock_run(cmd, **kwargs):
            cmds_run.append(cmd)
            # simulate node being available after the nvm install
            monkeypatch.setattr(
                "shutil.which", lambda c: "/bin/cmd" if c in ("node", "npm") else None
            )
            return MagicMock(returncode=0)

        monkeypatch.setattr(installer, "run", mock_run)
        assert installer.ensure_node_installed(auto_yes=True) is True
        assert any(c[0] == "sh" and "nvm install" in c[2] for c in cmds_run), cmds_run

    def test_windows_winget_install(self, monkeypatch, capsys):
        def mock_which(cmd):
            if cmd == "winget":
                return "C:\\winget.exe"
            return None

        monkeypatch.setattr("shutil.which", mock_which)
        monkeypatch.setattr("platform.system", lambda: "Windows")

        cmds_run = []

        def mock_run(cmd, **kwargs):
            cmds_run.append(cmd)
            monkeypatch.setattr(
                "shutil.which", lambda c: "/bin/cmd" if c in ("node", "npm") else mock_which(c)
            )
            return MagicMock(returncode=0)

        monkeypatch.setattr(installer, "run", mock_run)
        assert installer.ensure_node_installed(auto_yes=True) is True
        assert [
            "winget",
            "install",
            "OpenJS.NodeJS.LTS",
            "--silent",
            "--accept-package-agreements",
            "--accept-source-agreements",
        ] in cmds_run

    def test_linux_nvm_install(self, monkeypatch, capsys):
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        monkeypatch.setattr("platform.system", lambda: "Linux")

        cmds_run = []

        def mock_run(cmd, **kwargs):
            cmds_run.append(cmd)
            monkeypatch.setattr(
                "shutil.which", lambda c: "/bin/cmd" if c in ("node", "npm") else None
            )
            return MagicMock(returncode=0)

        monkeypatch.setattr(installer, "run", mock_run)
        assert installer.ensure_node_installed(auto_yes=True) is True
        # nvm install, never apt-get.
        assert any(c[0] == "sh" and "nvm install" in c[2] for c in cmds_run), cmds_run

    def test_user_declines_install(self, monkeypatch, capsys):
        monkeypatch.setattr(installer.shutil, "which", lambda cmd: None)
        monkeypatch.setattr(installer.platform, "system", lambda: "Darwin")

        input_prompts = []

        def mock_input(prompt):
            input_prompts.append(prompt)
            return "n"

        monkeypatch.setattr("builtins.input", mock_input)

        assert installer.ensure_node_installed(auto_yes=False) is False
        assert any("Install Node.js" in p for p in input_prompts)

    def test_path_refresh_after_install(self, monkeypatch, tmp_path):
        """Verify that _update_process_path correctly updates os.environ['PATH']."""
        # Mock platform and directories
        monkeypatch.setattr("sys.platform", "linux")
        fake_bin = tmp_path / "usr" / "local" / "bin"
        fake_bin.mkdir(parents=True)
        (fake_bin / "node").touch()
        (fake_bin / "npm").touch()

        # Initial state: PATH does not contain fake_bin
        orig_path = "/usr/bin"
        monkeypatch.setitem(os.environ, "PATH", orig_path)

        # Mock shutil.which to only find things in fake_bin if fake_bin is in PATH
        def mock_which(cmd, path=None):
            if path is None:
                path = os.environ.get("PATH", "")
            search_dirs = path.split(":")
            if str(fake_bin) in search_dirs:
                return str(fake_bin / cmd)
            return None

        monkeypatch.setattr(installer.shutil, "which", mock_which)

        # Before refresh, node is not found
        assert installer.shutil.which("node") is None

        # Execute refresh (pass fake_bin explicitly to avoid dependency on host OS folders)
        installer._update_process_path_for_nodejs(base_paths=[str(fake_bin)])

        # Now node should be found
        assert str(fake_bin) in os.environ["PATH"]
        assert installer.shutil.which("node") == str(fake_bin / "node")

    def test_nvm_latest_picks_highest_version(self, monkeypatch, tmp_path):
        """The newest installed Node version's bin dir is returned."""
        node_root = tmp_path / "versions" / "node"
        for v in ("v18.20.4", "v20.11.0", "v24.11.1"):
            (node_root / v / "bin").mkdir(parents=True)
        monkeypatch.setattr(installer, "_nvm_dir", lambda: tmp_path)
        assert installer._nvm_latest_node_bin_dir() == str(node_root / "v24.11.1" / "bin")

    def test_nvm_latest_skips_non_version_dirs(self, monkeypatch, tmp_path):
        """A non-vX.Y.Z dir (e.g. metadata) is never chosen, even with a bin/ child."""
        node_root = tmp_path / "versions" / "node"
        (node_root / "v18.20.4" / "bin").mkdir(parents=True)
        # A junk directory that has a bin/ child but no parseable version.
        (node_root / "cache" / "bin").mkdir(parents=True)
        monkeypatch.setattr(installer, "_nvm_dir", lambda: tmp_path)
        assert installer._nvm_latest_node_bin_dir() == str(node_root / "v18.20.4" / "bin")

    def test_nvm_latest_none_when_only_non_version_dirs(self, monkeypatch, tmp_path):
        """With no parseable version dir, returns None rather than a bogus path."""
        node_root = tmp_path / "versions" / "node"
        (node_root / "cache" / "bin").mkdir(parents=True)
        monkeypatch.setattr(installer, "_nvm_dir", lambda: tmp_path)
        assert installer._nvm_latest_node_bin_dir() is None

    def test_system_node_not_writable_forces_nvm_never_sudo(self, monkeypatch, capsys):
        """A system Node with a root-owned global prefix triggers a per-user nvm install — never sudo."""
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/bin/" + cmd if cmd in ("node", "npm") else None
        )
        monkeypatch.setattr("platform.system", lambda: "Linux")
        _set_npm_global_prefix_writable(monkeypatch, False)

        cmds_run = []
        monkeypatch.setattr(
            installer, "run", lambda cmd, **k: cmds_run.append(cmd) or MagicMock(returncode=0)
        )

        assert installer.ensure_node_installed(auto_yes=True, node_version="24.11.1") is True
        assert "not writable" in capsys.readouterr().out
        # Installs a per-user Node via nvm; never escalates with sudo.
        assert any(c[0] == "sh" and "nvm install" in c[2] for c in cmds_run), cmds_run
        assert not any(c and c[0] == "sudo" for c in cmds_run)

    def test_snyk_install_never_uses_sudo(self, monkeypatch):
        """The Snyk CLI global install is always a plain `npm install -g`, never sudo."""
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(installer, "ensure_node_installed", lambda *_: True)

        cmds_run = []
        monkeypatch.setattr(
            installer, "run", lambda cmd, **k: cmds_run.append(cmd) or MagicMock(returncode=0)
        )
        monkeypatch.setattr("builtins.input", lambda _: "y")

        installer.check_prerequisites(auto_yes=True)
        assert ["npm", "install", "-g", "snyk"] in cmds_run
        assert not any(c and c[0] == "sudo" for c in cmds_run)

    def test_resolver_probes_npm_prefix_writable(self, monkeypatch, tmp_path):
        """A writable prefix reported by `npm prefix -g` yields True; an exception yields True."""
        monkeypatch.setattr(
            installer, "run", lambda *a, **k: MagicMock(stdout=str(tmp_path) + "\n")
        )
        assert installer._snyk_cli_resolver().npm_global_prefix_writable() is True

        def boom(*a, **k):
            raise RuntimeError("npm missing")

        monkeypatch.setattr(installer, "run", boom)
        assert installer._snyk_cli_resolver().npm_global_prefix_writable() is True


# ===========================================================================
# TestWinCompatibility
# ===========================================================================


class TestWinCompatibility:
    def test_find_win_npm_executable_returns_none_on_non_windows(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        assert installer._find_win_npm_executable("snyk") is None

    def test_should_gui_transform_only_on_windows(self, monkeypatch):
        monkeypatch.setattr(installer, "_IS_WINDOWS", False)
        assert installer._should_gui_transform("merge_cursor_hooks") is False
        monkeypatch.setattr(installer, "_IS_WINDOWS", True)
        assert installer._should_gui_transform("merge_cursor_hooks") is False
        assert installer._should_gui_transform("unmerge_cursor_hooks") is False
        assert installer._should_gui_transform("merge_copilot_cli_hooks") is True
        assert installer._should_gui_transform("merge_mcp_servers") is False

    def test_expand_source_preserves_cursor_uv_run_on_windows(self, monkeypatch, tmp_path):
        monkeypatch.setattr(installer, "_IS_WINDOWS", True)
        monkeypatch.setattr(
            installer.os.path, "expanduser", lambda p: "/home/me" if p == "~" else p
        )
        src = tmp_path / "hooks.json"
        src.write_text(
            json.dumps(
                {
                    "version": 1,
                    "hooks": {
                        "afterFileEdit": [
                            {"command": 'uv run "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'}
                        ]
                    },
                }
            )
        )
        with installer._expand_source("merge_cursor_hooks", src) as resolved:
            data = json.loads(Path(resolved).read_text())
        cmd = data["hooks"]["afterFileEdit"][0]["command"]
        assert cmd.startswith("uv run ")
        assert "uvw run --gui-script" not in cmd
        assert "$HOME" not in cmd

    def test_expand_source_preserves_uv_run_off_windows(self, monkeypatch, tmp_path):
        monkeypatch.setattr(installer, "_IS_WINDOWS", False)
        monkeypatch.setattr(
            installer.os.path, "expanduser", lambda p: "/home/me" if p == "~" else p
        )
        src = tmp_path / "hooks.json"
        src.write_text(
            json.dumps(
                {
                    "version": 1,
                    "hooks": {
                        "afterFileEdit": [
                            {"command": 'uv run "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'}
                        ]
                    },
                }
            )
        )
        with installer._expand_source("merge_cursor_hooks", src) as resolved:
            data = json.loads(Path(resolved).read_text())
        cmd = data["hooks"]["afterFileEdit"][0]["command"]
        assert "uvw" not in cmd
        assert cmd.startswith("uv run ")

    def test_expand_source_rewrites_copilot_cli_hooks_on_windows(self, monkeypatch, tmp_path):
        # On Windows, copilot_cli_hooks needs BOTH the GUI rewrite and install-time
        # $HOME expansion (hooks run with Windows-native paths, not a bash shell
        # that would expand $HOME at hook time).
        monkeypatch.setattr(installer, "_IS_WINDOWS", True)
        monkeypatch.setattr(
            installer.os.path, "expanduser", lambda p: "/home/me" if p == "~" else p
        )
        src = tmp_path / "hooks.json"
        src.write_text(
            json.dumps(
                {
                    "version": 1,
                    "hooks": {
                        "sessionStart": [
                            {
                                "bash": 'uv run "$HOME/.copilot/hooks/snyk_secure_at_inception.py" sessionStart'
                            }
                        ]
                    },
                }
            )
        )
        with installer._expand_source("merge_copilot_cli_hooks", src) as resolved:
            data = json.loads(Path(resolved).read_text())
        bash_cmd = data["hooks"]["sessionStart"][0]["bash"]
        assert bash_cmd.startswith("uvw run --gui-script ")
        # $HOME should be expanded to an absolute path (copilot is in the expand set).
        assert "$HOME" not in bash_cmd
        assert "/home/me/.copilot/hooks/snyk_secure_at_inception.py" in bash_cmd


# ===========================================================================
# TestDetectAdes
# ===========================================================================


class TestDetectAdes:
    def test_detects_cursor_from_directory(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        (tmp_path / ".cursor").mkdir()
        result = installer.detect_ades()
        assert "cursor" in result

    def test_detects_claude_from_directory(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        (tmp_path / ".claude").mkdir()
        result = installer.detect_ades()
        assert "claude" in result

    def test_detects_gemini_from_directory(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        (tmp_path / ".gemini").mkdir()
        result = installer.detect_ades()
        assert "gemini" in result

    def test_detects_gemini_from_cli(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/bin/gemini" if cmd == "gemini" else None
        )
        result = installer.detect_ades()
        assert "gemini" in result

    def test_detects_kiro_from_directory(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        (tmp_path / ".kiro").mkdir()
        result = installer.detect_ades()
        assert "kiro" in result

    def test_detects_kiro_from_cli(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/kiro" if cmd == "kiro" else None)
        result = installer.detect_ades()
        assert "kiro" in result

    def test_detects_both(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("shutil.which", lambda cmd: None)

        (tmp_path / ".cursor").mkdir()
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".gemini").mkdir()
        result = installer.detect_ades()
        assert result == ["cursor", "claude", "gemini"]

    def test_detects_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        monkeypatch.setattr(installer, "_cursor_app_bundle_exists", lambda: False)
        # Mock pgrep to not find cursor process
        mock_run = MagicMock(return_value=MagicMock(returncode=1))
        monkeypatch.setattr(installer, "run", mock_run)
        result = installer.detect_ades()
        assert result == []
        # Exact process name (case-insensitive): pgrep -xi, not substring match
        for call in mock_run.call_args_list:
            args, kwargs = call
            assert args[0] == ["pgrep", "-xiq", "cursor"]

    def test_detects_cursor_from_macos_app_bundle_without_dot_cursor(self, tmp_path, monkeypatch):
        """When ~/.cursor is absent, macOS Cursor.app implies cursor (no pgrep)."""

        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        monkeypatch.setattr("sys.platform", "darwin")
        monkeypatch.setattr(installer, "_cursor_app_bundle_exists", lambda: True)

        pgrep_calls: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            pgrep_calls.append(list(cmd))
            m = MagicMock()
            m.returncode = 1
            return m

        monkeypatch.setattr(installer, "run", fake_run)
        assert installer.detect_ades() == ["cursor"]
        assert pgrep_calls == []

    def test_detects_cursor_from_pgrep_exact_process_name(self, tmp_path, monkeypatch):
        """When ~/.cursor and Cursor.app are absent, pgrep -xiq cursor (exact name) detects cursor."""

        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        monkeypatch.setattr(installer, "_cursor_app_bundle_exists", lambda: False)
        monkeypatch.setattr("sys.platform", "linux")

        pgrep_calls: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            pgrep_calls.append(list(cmd))
            m = MagicMock()
            m.returncode = 0 if cmd == ["pgrep", "-xiq", "cursor"] else 1
            return m

        monkeypatch.setattr(installer, "run", fake_run)
        assert installer.detect_ades() == ["cursor"]
        assert pgrep_calls == [["pgrep", "-xiq", "cursor"]]

    def test_cursor_not_detected_for_substring_process_names(self, tmp_path, monkeypatch):
        """Regression: only an exact process name Cursor counts (pgrep -x).

        Older substring-style matching could treat unrelated processes whose names
        contained 'cursor' as the Cursor IDE. pgrep -xiq cursor exits 1 when no
        command is named exactly 'cursor' (case-insensitive), e.g. only
        'cursor-indexer' or 'my-cursor-helper' is running.
        """

        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        monkeypatch.setattr(installer, "_cursor_app_bundle_exists", lambda: False)
        monkeypatch.setattr("sys.platform", "linux")

        def fake_run(cmd, **kwargs):
            assert list(cmd) == ["pgrep", "-xiq", "cursor"]
            m = MagicMock()
            m.returncode = 1
            return m

        monkeypatch.setattr(installer, "run", fake_run)
        assert installer.detect_ades() == []

    def test_detects_claude_from_cli(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/bin/claude" if cmd == "claude" else None
        )
        result = installer.detect_ades()
        assert "claude" in result

    def test_detects_codex_from_directory(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        (tmp_path / ".codex").mkdir()
        result = installer.detect_ades()
        assert "codex" in result

    def test_detects_codex_from_cli(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr(installer, "_cursor_app_bundle_exists", lambda: False)
        mock_run = MagicMock(return_value=MagicMock(returncode=1))
        monkeypatch.setattr("subprocess.run", mock_run)
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/bin/codex" if cmd == "codex" else None
        )
        result = installer.detect_ades()
        assert "codex" in result

    def test_detects_windsurf_from_codeium_directory(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        (tmp_path / ".codeium" / "windsurf").mkdir(parents=True)
        result = installer.detect_ades()
        assert "windsurf" in result

    def test_detects_windsurf_from_windsurf_directory(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        (tmp_path / ".windsurf").mkdir()
        result = installer.detect_ades()
        assert "windsurf" in result

    def test_detects_windsurf_from_cli(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/bin/windsurf" if cmd == "windsurf" else None
        )
        result = installer.detect_ades()
        assert "windsurf" in result

    def test_detects_copilot_cli_from_directory(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        (tmp_path / ".copilot").mkdir()
        result = installer.detect_ades()
        assert "copilot-cli" in result

    def test_detects_copilot_vscode_from_code_cli(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/code" if cmd == "code" else None)
        result = installer.detect_ades()
        assert "copilot-vscode" in result

    def test_detects_more(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        (tmp_path / ".cursor").mkdir()
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".codex").mkdir()
        result = installer.detect_ades()
        assert "codex" in result
        assert len(result) > 1


# ===========================================================================
# TestGetTargetAdes
# ===========================================================================


class TestGetTargetAdes:
    def test_auto_yes_exits_when_no_ade_detected(self, monkeypatch, capsys):
        monkeypatch.setattr(installer, "detect_ades", lambda: [])

        def _no_input(*_a, **_kw):
            raise AssertionError("get_target_ades must not prompt when auto_yes is True")

        monkeypatch.setattr("builtins.input", _no_input)

        with pytest.raises(SystemExit):
            installer.get_target_ades(None, auto_yes=True)
        assert "no ADE detected" in capsys.readouterr().err

    def test_not_required_returns_empty_list_instead_of_exiting(self, monkeypatch, capsys):
        monkeypatch.setattr(installer, "detect_ades", lambda: [])

        assert installer.get_target_ades(None, auto_yes=True, required=False) == []
        assert "no ADE detected" in capsys.readouterr().out

    def test_non_tty_stdin_exits_even_without_auto_yes(self, monkeypatch, capsys):
        # Non-interactive stdin + no ADE detected/specified: must fail fast,
        # not block on input(), even when auto_yes is False (e.g. --verify
        # invoked with a piped/closed stdin).
        monkeypatch.setattr(installer, "detect_ades", lambda: [])
        monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)

        def _no_input(*_a, **_kw):
            raise AssertionError("get_target_ades must not prompt on non-tty stdin")

        monkeypatch.setattr("builtins.input", _no_input)

        with pytest.raises(SystemExit):
            installer.get_target_ades(None, auto_yes=False)
        assert "no ADE detected" in capsys.readouterr().err


# ===========================================================================
# TestManifest
# ===========================================================================


class TestManifest:
    @pytest.fixture
    def manifest(self):
        return installer.Manifest(INSTALLER_DIR / "manifest.json")

    def test_resolve_default_profile(self, manifest):
        recipes = manifest.resolve_recipes("default")
        assert "sai-hooks-async" in recipes
        assert "secrets-precommit-hook" not in recipes
        assert "snyk-fix-command" in recipes
        assert len(recipes) == 6

    def test_ads_profile_is_a_superset_of_default_with_global_secrets(self, manifest):
        default = set(manifest.resolve_recipes("default"))
        ads = set(manifest.resolve_recipes("ads"))

        assert default <= ads
        assert "secrets-precommit-hook-global" in ads

    def test_resolve_minimal_profile(self, manifest):
        recipes = manifest.resolve_recipes("minimal")
        assert recipes == ["sai-hooks-async", "mcp-config"]

    def test_resolve_experimental_profile(self, manifest):
        recipes = manifest.resolve_recipes("experimental")
        assert "secure-at-commit" in recipes
        assert "sai-hooks-async" not in recipes
        assert "secrets-precommit-hook" not in recipes
        assert "secrets-precommit-hook-global" in recipes
        assert len(recipes) == 7

    def test_selection_replaces_profile_list(self, manifest):
        recipes = manifest.resolve_recipes("experimental", ["secrets-precommit-hook"])
        assert recipes == ["secrets-precommit-hook"]

    def test_empty_selection_replaces_profile_list(self, manifest):
        assert manifest.resolve_recipes("ads", []) == []

    def test_selection_of_both_commit_hooks_follows_manifest_order(self, manifest):
        # Typed in the opposite order to the manifest's declaration order.
        recipes = manifest.resolve_recipes(
            "experimental", ["secrets-precommit-hook", "secure-at-commit"]
        )
        assert recipes == ["secure-at-commit", "secrets-precommit-hook"]

    def test_sorted_by_scope_orders_git_global_before_ade_before_workspace(self, manifest):
        result = manifest.sorted_by_scope(
            ["secure-at-commit", "mcp-config", "secrets-precommit-hook-global"]
        )
        assert result == ["secrets-precommit-hook-global", "mcp-config", "secure-at-commit"]

    def test_resolve_recipes_orders_by_scope_regardless_of_selection_order(self, manifest):
        # Typed workspace, git-global, ADE - output must still come out
        # git-global -> ADE -> workspace.
        recipes = manifest.resolve_recipes(
            "experimental",
            ["secure-at-commit", "secrets-precommit-hook-global", "mcp-config"],
        )
        assert recipes == ["secrets-precommit-hook-global", "mcp-config", "secure-at-commit"]

    def test_all_recipe_ids_orders_git_global_before_workspace(self, manifest):
        ids = manifest.all_recipe_ids()
        assert ids.index("secrets-precommit-hook-global") < ids.index("secure-at-commit")

    def test_selection_narrows_the_profile_to_one_member(self, manifest):
        assert manifest.resolve_recipes("experimental", ["secure-at-commit"]) == [
            "secure-at-commit"
        ]

    def test_unprofiled_recipes_is_pinned(self, manifest):
        # A recipe left out of every profile silently becomes user-selectable,
        # so adding one has to be a deliberate decision rather than an omission.
        assert manifest.unprofiled_recipes() == ["secrets-precommit-hook"]

    def test_unprofiled_recipes_empty_when_a_profile_lists_everything(self, manifest, monkeypatch):
        monkeypatch.setitem(manifest.profiles, "everything", {"recipes": ["*"]})
        assert manifest.unprofiled_recipes() == []

    def test_nameable_recipes_under_experimental(self, manifest):
        # Every recipe but the Secure at Inception hooks: the profile's own
        # members plus the unprofiled local secrets hook.
        assert manifest.nameable_recipes("experimental") == [
            "snyk-fix-command",
            "snyk-batch-fix-command",
            "snyk-fix-skill",
            "mcp-config",
            "secure-at-commit",
            "secrets-precommit-hook",
            "secrets-precommit-hook-global",
            "secure-dependency-health-check-skill",
        ]

    def test_nameable_recipes_excludes_disabled(self, manifest, monkeypatch):
        monkeypatch.setitem(
            manifest.recipes, "secrets-precommit-hook", {"type": "hooks", "enabled": False}
        )
        assert "secrets-precommit-hook" not in manifest.nameable_recipes("experimental")

    def test_unknown_profile_exits(self, manifest):
        with pytest.raises(SystemExit):
            manifest.resolve_recipes("nonexistent")

    def test_get_sources_cursor(self, manifest):
        sources = manifest.get_sources("sai-hooks-async", "cursor")
        assert "files" in sources
        assert "config_merge" in sources

    def test_get_sources_gemini(self, manifest):
        sources = manifest.get_sources("sai-hooks-async", "gemini")
        assert "files" in sources
        assert sources["config_merge"]["strategy"] == "merge_gemini_settings"
        assert sources["config_merge"]["target"] == ".gemini/settings.json"

    def test_get_sources_kiro(self, manifest):
        sources = manifest.get_sources("mcp-config", "kiro")
        assert sources["config_merge"]["strategy"] == "merge_mcp_servers"
        assert sources["config_merge"]["target"] == ".kiro/settings/mcp.json"

    def test_gemini_sources_for_all_default_recipes(self, manifest):
        # snyk-fix-skill is limited to command-less platforms (codex, copilot-cli);
        # workspace-scoped recipes (e.g. secrets-precommit-hook) have no per-ADE sources.
        skill_only_recipes = {"snyk-fix-skill"}
        for recipe_id in manifest.resolve_recipes("default"):
            if recipe_id in skill_only_recipes or manifest.is_workspace_scoped(recipe_id):
                continue
            sources = manifest.get_sources(recipe_id, "gemini")
            assert sources, f"missing gemini sources for {recipe_id}"

    def test_kiro_sources_for_all_default_recipes_except_hooks(self, manifest):
        # snyk-fix-skill is limited to command-less platforms (codex, copilot-cli);
        # workspace-scoped recipes (e.g. secrets-precommit-hook) have no per-ADE sources.
        skill_only_recipes = {"snyk-fix-skill"}
        for recipe_id in manifest.resolve_recipes("default"):
            if recipe_id in (
                "sai-hooks-async",
                *skill_only_recipes,
            ) or manifest.is_workspace_scoped(recipe_id):
                continue
            sources = manifest.get_sources(recipe_id, "kiro")
            assert sources, f"missing kiro sources for {recipe_id}"

    def test_get_sources_missing_ade(self, manifest):
        sources = manifest.get_sources("sai-hooks-async", "vscode")
        assert sources == {}

    def test_codex_sources_for_sai_hooks(self, manifest):
        sources = manifest.get_sources("sai-hooks-async", "codex")
        assert "files" in sources
        assert "config_merge" in sources
        # Hook scripts go to ~/.codex/hooks/, config to ~/.codex/config.toml
        dests = {f["dest"] for f in sources["files"]}
        assert ".codex/hooks/snyk_secure_at_inception.py" in dests
        assert sources["config_merge"]["target"] == ".codex/config.toml"
        assert sources["config_merge"]["strategy"] == "merge_codex_config"

    def test_codex_sources_for_mcp_use_same_config_toml(self, manifest):
        sources = manifest.get_sources("mcp-config", "codex")
        # MCP servers go in the SAME ~/.codex/config.toml as hooks (Codex convention)
        assert sources["config_merge"]["target"] == ".codex/config.toml"
        assert sources["config_merge"]["strategy"] == "merge_codex_config"

    def test_codex_skill_uses_dot_agents_path(self, manifest):
        sources = manifest.get_sources("secure-dependency-health-check-skill", "codex")
        dests = [f["dest"] for f in sources["files"]]
        # Codex skills convention is ~/.agents/skills/, not ~/.codex/skills/
        assert all(d.startswith(".agents/skills/snyk/") for d in dests), dests

    def test_codex_snyk_fix_skill_uses_dot_agents_path(self, manifest):
        sources = manifest.get_sources("snyk-fix-skill", "codex")
        dests = [f["dest"] for f in sources["files"]]
        # Codex skills convention is ~/.agents/skills/, not ~/.codex/skills/
        assert all(d.startswith(".agents/skills/snyk/") for d in dests), dests

    def test_copilot_cli_snyk_fix_skill_uses_dot_copilot_path(self, manifest):
        sources = manifest.get_sources("snyk-fix-skill", "copilot-cli")
        dests = [f["dest"] for f in sources["files"]]
        assert all(d.startswith(".copilot/skills/") for d in dests), dests

    def test_windsurf_uses_global_workflows_for_commands(self, manifest):
        for recipe_id in ("snyk-fix-command", "snyk-batch-fix-command"):
            sources = manifest.get_sources(recipe_id, "windsurf")
            dests = [f["dest"] for f in sources["files"]]
            assert all(".codeium/windsurf/global_workflows/" in d for d in dests), dests

    def test_windsurf_skill_uses_dot_agents_path(self, manifest):
        sources = manifest.get_sources("secure-dependency-health-check-skill", "windsurf")
        dests = [f["dest"] for f in sources["files"]]
        assert all(d.startswith(".agents/skills/") for d in dests), dests

    def test_windsurf_mcp_config_target(self, manifest):
        sources = manifest.get_sources("mcp-config", "windsurf")
        assert sources["config_merge"]["target"] == ".codeium/windsurf/mcp_config.json"
        assert sources["config_merge"]["strategy"] == "merge_mcp_servers"

    def test_codex_has_no_slash_command_recipes(self, manifest):
        # Codex does not support user-defined slash commands.
        for recipe_id in ("snyk-fix-command", "snyk-batch-fix-command"):
            assert manifest.get_sources(recipe_id, "codex") == {}, recipe_id

    def test_are_rules_conflicting_no_conflict(self, manifest, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.chdir(tmp_path)
        assert manifest.are_rules_conflicting("cursor") is False

    def test_are_rules_conflicting_file_exists_no_tags(self, manifest, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.chdir(tmp_path)
        rule_path = tmp_path / ".cursor/rules/snyk_rules.mdc"
        rule_path.parent.mkdir(parents=True)
        rule_path.write_text("some random content")
        assert manifest.are_rules_conflicting("cursor") is False

    def test_are_rules_conflicting_with_tags(self, manifest, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.chdir(tmp_path)
        rule_path = tmp_path / ".cursor/rules/snyk_rules.mdc"
        rule_path.parent.mkdir(parents=True)
        rule_path.write_text(
            "<!--# BEGIN SNYK GLOBAL RULE -->\ncontent\n<!--# END SNYK GLOBAL RULE -->"
        )
        assert manifest.are_rules_conflicting("cursor") is True

    def test_are_rules_conflicting_global(self, manifest, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        # windsurf has a global rule: .codeium/windsurf/memories/global_rules.md
        rule_path = tmp_path / ".codeium/windsurf/memories/global_rules.md"
        rule_path.parent.mkdir(parents=True)
        rule_path.write_text(
            "<!--# BEGIN SNYK GLOBAL RULE -->\ncontent\n<!--# END SNYK GLOBAL RULE -->"
        )
        assert manifest.are_rules_conflicting("windsurf") is True

    def test_are_skills_conflicting_no_conflict(self, manifest, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.chdir(tmp_path)
        assert manifest.are_skills_conflicting("cursor") is False

    def test_are_skills_conflicting_exists(self, manifest, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.chdir(tmp_path)
        # cursor has a global skill: .cursor/skills/snyk-rules/SKILL.md
        skill_path = tmp_path / ".cursor/skills/snyk-rules/SKILL.md"
        skill_path.parent.mkdir(parents=True)
        skill_path.touch()
        assert manifest.are_skills_conflicting("cursor") is True

    def test_are_rules_conflicting_unknown_ade(self, manifest):
        assert manifest.are_rules_conflicting("nonexistent") is False

    def test_are_skills_conflicting_unknown_ade(self, manifest):
        assert manifest.are_skills_conflicting("nonexistent") is False

    _RULE_TAGS = "<!--# BEGIN SNYK GLOBAL RULE -->\nx\n<!--# END SNYK GLOBAL RULE -->"

    def test_conflicting_rule_scopes_none(self, manifest, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.chdir(tmp_path)
        assert manifest.conflicting_rule_scopes("windsurf") == []

    def test_conflicting_rule_scopes_workspace_only(self, manifest, tmp_path, monkeypatch):
        # windsurf: global .codeium/windsurf/memories/global_rules.md + workspace
        # .windsurf/rules/snyk_rules.md. Only the workspace file has tags.
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.chdir(tmp_path)
        ws = tmp_path / ".windsurf/rules/snyk_rules.md"
        ws.parent.mkdir(parents=True)
        ws.write_text(self._RULE_TAGS)
        assert manifest.conflicting_rule_scopes("windsurf") == ["workspace"]

    def test_conflicting_rule_scopes_global_only(self, manifest, tmp_path, monkeypatch):
        # Only the global file has tags -> must not report workspace.
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.chdir(tmp_path)
        gl = tmp_path / ".codeium/windsurf/memories/global_rules.md"
        gl.parent.mkdir(parents=True)
        gl.write_text(self._RULE_TAGS)
        assert manifest.conflicting_rule_scopes("windsurf") == ["global"]

    def test_conflicting_rule_scopes_file_without_tags_ignored(
        self, manifest, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.chdir(tmp_path)
        ws = tmp_path / ".windsurf/rules/snyk_rules.md"
        ws.parent.mkdir(parents=True)
        ws.write_text("no tags here")
        assert manifest.conflicting_rule_scopes("windsurf") == []

    def test_conflicting_skill_scopes(self, manifest, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.chdir(tmp_path)
        assert manifest.conflicting_skill_scopes("cursor") == []
        # cursor has a global skill: .cursor/skills/snyk-rules/SKILL.md
        skill = tmp_path / ".cursor/skills/snyk-rules/SKILL.md"
        skill.parent.mkdir(parents=True)
        skill.touch()
        assert manifest.conflicting_skill_scopes("cursor") == ["global"]

    def test_conflicting_scopes_unknown_ade(self, manifest):
        assert manifest.conflicting_rule_scopes("nonexistent") == []
        assert manifest.conflicting_skill_scopes("nonexistent") == []


# ===========================================================================
# TestDisplayHelpers
# ===========================================================================


class TestDisplayHelpers:
    @pytest.fixture
    def manifest(self):
        return installer.Manifest(INSTALLER_DIR / "manifest.json")

    def test_workspace_only_plan_omits_ades(self, manifest, tmp_path, capsys):
        installer.show_plan(
            ["cursor", "claude"],
            ["secrets-precommit-hook"],
            "experimental",
            manifest,
            tmp_path,
        )

        output = capsys.readouterr().out
        assert "ADEs:" not in output
        assert "Workspace:" in output
        assert "workspace ->" in output

    def test_workspace_only_summary_omits_ades(self, manifest, capsys):
        installer.print_summary(["cursor"], ["secrets-precommit-hook"], False, manifest)

        output = capsys.readouterr().out
        assert "Recipes: 1" in output
        assert "ADEs:" not in output

    def test_ade_summary_keeps_only_ade_targets_with_sources(self, manifest, capsys):
        installer.print_summary(["cursor", "kiro"], ["sai-hooks-async"], False, manifest)

        output = capsys.readouterr().out
        assert "ADEs:    cursor" in output
        assert "kiro" not in output

    def test_ade_plan_omits_missing_source_targets(self, manifest, capsys):
        installer.show_plan(["kiro"], ["sai-hooks-async"], "default", manifest, None)

        output = capsys.readouterr().out
        assert "ADEs:" not in output
        assert "kiro ->" not in output

    def test_ade_plan_omits_sources_with_no_installable_entries(
        self, manifest, capsys, monkeypatch
    ):
        monkeypatch.setattr(manifest, "is_workspace_scoped", lambda _: False)
        monkeypatch.setattr(
            manifest,
            "get_sources",
            lambda _, __: {"legacy_files": [{"dest": "old-config.json"}]},
        )

        installer.show_plan(["cursor"], ["fixture-recipe"], "default", manifest, None)

        output = capsys.readouterr().out
        assert "ADEs:" not in output
        assert "cursor ->" not in output


# ===========================================================================
# TestValidateRecipeSelection
# ===========================================================================


class TestValidateRecipeSelection:
    @pytest.fixture
    def manifest(self):
        return installer.Manifest(INSTALLER_DIR / "manifest.json")

    def _validate(self, manifest, profile, selection):
        with pytest.raises(SystemExit) as excinfo:
            installer.validate_recipe_selection(manifest, profile, selection)
        assert excinfo.value.code != 0

    def test_no_selection_is_always_accepted(self, manifest):
        installer.validate_recipe_selection(manifest, "default", None)
        installer.validate_recipe_selection(manifest, "experimental", None)
        installer.validate_recipe_selection(manifest, "ads", None)

    def test_empty_selection_is_accepted_for_selection_profiles(self, manifest):
        installer.validate_recipe_selection(manifest, "experimental", [])
        installer.validate_recipe_selection(manifest, "ads", [])

    def test_empty_selection_still_requires_a_selection_profile(self, manifest, capsys):
        self._validate(manifest, "default", [])
        assert (
            "cannot be used with --profile default or --profile minimal" in capsys.readouterr().err
        )

    def test_eligible_selection_is_accepted(self, manifest):
        installer.validate_recipe_selection(
            manifest, "experimental", ["secure-at-commit", "secrets-precommit-hook"]
        )

    @pytest.mark.parametrize("profile", ["default", "minimal"])
    def test_static_profile_rejects_selection(self, manifest, profile, capsys):
        self._validate(manifest, profile, ["secure-at-commit"])
        assert (
            "--recipes cannot be used with --profile default or --profile minimal"
            in capsys.readouterr().err
        )

    def test_gate_precedes_eligibility(self, manifest, capsys):
        # secrets-precommit-hook belongs to no profile, so it satisfies the
        # eligibility rule everywhere; only the gate can reject it here.
        self._validate(manifest, "default", ["secrets-precommit-hook"])
        err = capsys.readouterr().err
        assert "--recipes cannot be used with --profile default or --profile minimal" in err
        assert "not selectable" not in err

    def test_future_profile_accepts_selection(self, manifest):
        manifest.profiles["future"] = {"recipes": ["mcp-config"]}

        installer.validate_recipe_selection(manifest, "future", ["mcp-config"])

    def test_profile_member_is_accepted(self, manifest):
        installer.validate_recipe_selection(manifest, "experimental", ["mcp-config"])

    def test_ads_profile_member_is_accepted(self, manifest):
        installer.validate_recipe_selection(manifest, "ads", ["secrets-precommit-hook-global"])

    def test_sai_hooks_not_nameable_under_experimental(self, manifest, capsys):
        # sai-hooks-async belongs to default and minimal but not experimental,
        # which makes it the only name the eligibility rule rejects.
        self._validate(manifest, "experimental", ["sai-hooks-async"])
        err = capsys.readouterr().err
        assert "not selectable under profile 'experimental'" in err
        assert "sai-hooks-async" not in err.split("Selectable under 'experimental': ")[1]

    def test_unknown_name_rejected_with_nameable_listed(self, manifest, capsys):
        self._validate(manifest, "experimental", ["not-a-real-recipe"])
        err = capsys.readouterr().err
        assert "unknown recipe" in err
        listing = err.split("Selectable under 'experimental': ")[1]
        assert "secure-at-commit" in listing
        assert "secrets-precommit-hook" in listing

    def test_superseded_name_rejected(self, manifest, capsys):
        self._validate(manifest, "experimental", ["sac-hooks"])
        assert "unknown recipe" in capsys.readouterr().err

    def test_case_mismatch_rejected(self, manifest, capsys):
        self._validate(manifest, "experimental", ["Secure-At-Commit"])
        assert "unknown recipe" in capsys.readouterr().err

    def test_disabled_name_rejected(self, manifest, capsys, monkeypatch):
        monkeypatch.setitem(
            manifest.recipes, "secrets-precommit-hook", {"type": "hooks", "enabled": False}
        )
        self._validate(manifest, "experimental", ["secrets-precommit-hook"])
        assert "recipe is disabled" in capsys.readouterr().err

    def test_explicitly_named_conflicting_pair_rejected(self, manifest, capsys, monkeypatch):
        # The shipped manifest's only conflicts_with edge touches
        # sai-hooks-async, which is not nameable under experimental, so the
        # edge has to be synthesised between two nameable recipes.
        conflicting = dict(manifest.recipes["secrets-precommit-hook"])
        conflicting["conflicts_with"] = ["secure-at-commit"]
        monkeypatch.setitem(manifest.recipes, "secrets-precommit-hook", conflicting)
        self._validate(manifest, "experimental", ["secure-at-commit", "secrets-precommit-hook"])
        err = capsys.readouterr().err
        assert "secrets-precommit-hook" in err
        assert "secure-at-commit" in err
        assert "incompatible" in err

    def test_conflict_detected_in_either_direction(self, manifest, capsys, monkeypatch):
        conflicting = dict(manifest.recipes["secure-at-commit"])
        conflicting["conflicts_with"] = ["secrets-precommit-hook"]
        monkeypatch.setitem(manifest.recipes, "secure-at-commit", conflicting)
        self._validate(manifest, "experimental", ["secrets-precommit-hook", "secure-at-commit"])
        assert "incompatible" in capsys.readouterr().err

    def test_profile_list_conflict_still_prunes_with_a_warning(self, manifest, capsys):
        manifest.profiles["both-hooks"] = {"recipes": ["sai-hooks-async", "secure-at-commit"]}
        recipes = manifest.resolve_recipes("both-hooks")
        assert recipes == ["secure-at-commit"]
        assert "skipping sai-hooks-async" in capsys.readouterr().out


# ===========================================================================
# TestRecipeSelectionInMain
# ===========================================================================


class TestRecipeSelectionInMain:
    """main()'s install-path guards and the notice for modes that ignore --recipes."""

    @pytest.fixture
    def manifest(self):
        return installer.Manifest(INSTALLER_DIR / "manifest.json")

    @pytest.fixture(autouse=True)
    def _isolated_home(self, monkeypatch, tmp_path):
        """Isolate Path.home() so --verify's git-global auto-detection can't
        read this machine's real ~/.snyk-studio state and git config."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

    @staticmethod
    def _args(**overrides):
        args = MagicMock(
            list_mode=False,
            yes=True,
            dry_run=False,
            read_only=False,
            control_identifier=None,
            uninstall=False,
            verify=False,
            diag_dump=False,
            ade="claude",
            profile="experimental",
            workspace=None,
            no_latest_deps=False,
            cli_path=None,
            recipes=None,
        )
        for name, value in overrides.items():
            setattr(args, name, value)
        return args

    def _stub_main(self, monkeypatch, manifest, args, workspace=None):
        monkeypatch.setattr(installer, "parse_args", lambda: args)
        monkeypatch.setattr(installer, "PayloadContext", lambda: MagicMock())
        monkeypatch.setattr(installer, "Manifest", lambda *a, **kw: manifest)
        monkeypatch.setattr(installer, "check_prerequisites", lambda *a, **kw: None)
        monkeypatch.setattr(installer, "_sync_selected_snyk_cli_sidecars", lambda *a, **kw: None)
        monkeypatch.setattr(installer, "get_target_ades", lambda *a, **kw: ["claude"])
        monkeypatch.setattr(installer, "resolve_workspace", lambda *a, **kw: workspace)
        monkeypatch.setattr(installer, "print_banner", lambda: None)
        monkeypatch.setattr(installer, "install_recipe", lambda *a, **kw: None)
        monkeypatch.setattr(installer, "install_workspace_recipe", lambda *a, **kw: None)
        monkeypatch.setattr(installer, "install_git_global_recipe", lambda *a, **kw: None)
        monkeypatch.setattr(installer, "verify_recipe", lambda *a, **kw: True)
        monkeypatch.setattr(installer, "verify_workspace_recipe", lambda *a, **kw: True)
        monkeypatch.setattr(installer, "verify_git_global_recipe", lambda *a, **kw: True)
        monkeypatch.setattr(installer, "_has_installed_git_global_hook_files", lambda *a: False)
        monkeypatch.setattr(
            installer, "_has_installed_git_global_hook_integration", lambda *a: False
        )
        # The ADE conflict sweeps read the real home directory and shell out to
        # the Snyk CLI; neither is under test here.
        monkeypatch.setattr(manifest, "are_extension_settings_conflicting", lambda ade: [])
        monkeypatch.setattr(manifest, "are_rules_conflicting", lambda ade: False)
        monkeypatch.setattr(manifest, "are_skills_conflicting", lambda ade: False)
        monkeypatch.setattr(manifest, "detect_stale_conflicts", lambda recipes: [])

    def test_main_writes_selected_cli_path_to_sidecar(self, monkeypatch, manifest):
        args = self._args()
        self._stub_main(monkeypatch, manifest, args)
        selected = installer.SnykCliSelection(
            "/tmp/npm/bin/snyk",
            "1.1306.0",
            installer.SNYK_CLI_SOURCE_NPM,
        )
        sync_calls = []

        monkeypatch.setattr(installer, "check_prerequisites", lambda *a, **kw: selected)
        monkeypatch.setattr(
            installer,
            "_sync_selected_snyk_cli_sidecars",
            lambda selected_snyk_cli, dry_run: sync_calls.append((selected_snyk_cli, dry_run)),
        )

        def stop_after_sidecar(*_args, **_kwargs):
            raise SystemExit(0)

        monkeypatch.setattr(installer, "get_target_ades", stop_after_sidecar)

        with pytest.raises(SystemExit) as excinfo:
            installer.main()

        assert excinfo.value.code == 0
        assert sync_calls == [(selected, False)]

    def test_main_passes_selected_cli_to_install_and_verify(self, monkeypatch, manifest):
        args = self._args(profile="minimal")
        self._stub_main(monkeypatch, manifest, args)
        monkeypatch.setattr(manifest, "resolve_recipes", lambda *a, **kw: ["mcp-config"])
        selected = installer.SnykCliSelection(
            "/tmp/npm/bin/snyk",
            "1.1306.0",
            installer.SNYK_CLI_SOURCE_NPM,
        )
        install_calls = []
        verify_calls = []

        monkeypatch.setattr(installer, "check_prerequisites", lambda *a, **kw: selected)
        monkeypatch.setattr(
            installer,
            "install_recipe",
            lambda *a, **kw: install_calls.append(kw),
        )
        monkeypatch.setattr(
            installer,
            "verify_recipe",
            lambda *a, **kw: verify_calls.append(kw) or True,
        )

        installer.main()

        assert install_calls
        assert verify_calls
        assert install_calls[0]["selected_snyk_cli"] == selected
        assert verify_calls[0]["selected_snyk_cli"] == selected

    def test_read_only_verify_passes_selected_cli_to_verify(self, monkeypatch, manifest):
        args = self._args(verify=True, read_only=True, profile="minimal")
        self._stub_main(monkeypatch, manifest, args)
        monkeypatch.setattr(manifest, "resolve_recipes", lambda *a, **kw: ["mcp-config"])
        selected = installer.SnykCliSelection(
            "/tmp/npm/bin/snyk",
            "1.1306.0",
            installer.SNYK_CLI_SOURCE_NPM,
        )
        verify_calls = []

        monkeypatch.setattr(installer, "print_prerequisite_versions", lambda *a, **kw: None)
        monkeypatch.setattr(installer, "_read_only_selected_snyk_cli", lambda cli_path: selected)
        monkeypatch.setattr(
            installer,
            "verify_recipe",
            lambda *a, **kw: verify_calls.append(kw) or True,
        )

        installer.main()

        assert verify_calls
        assert verify_calls[0]["selected_snyk_cli"] == selected

    def test_workspace_only_selection_without_a_workspace_exits(
        self, monkeypatch, manifest, capsys
    ):
        args = self._args(recipes=["secrets-precommit-hook"])
        self._stub_main(monkeypatch, manifest, args)

        with pytest.raises(SystemExit) as excinfo:
            installer.main()

        assert excinfo.value.code != 0
        assert "every selected recipe is workspace-scoped" in capsys.readouterr().err

    def test_selection_of_both_hooks_without_a_workspace_exits(self, monkeypatch, manifest, capsys):
        args = self._args(recipes=["secure-at-commit", "secrets-precommit-hook"])
        self._stub_main(monkeypatch, manifest, args)

        with pytest.raises(SystemExit) as excinfo:
            installer.main()

        assert excinfo.value.code != 0
        assert "every selected recipe is workspace-scoped" in capsys.readouterr().err

    def test_empty_resolution_exits_with_its_own_message(self, monkeypatch, manifest, capsys):
        # Every shipped profile resolves to something, and a disabled name is
        # rejected by the validator before resolution, so the only way to reach
        # this guard is a profile that lists nothing.
        monkeypatch.setitem(manifest.profiles, "_empty", {"recipes": []})
        self._stub_main(monkeypatch, manifest, self._args(profile="_empty"))

        with pytest.raises(SystemExit) as excinfo:
            installer.main()

        assert excinfo.value.code != 0
        err = capsys.readouterr().err
        assert "produced no recipes" in err
        assert "workspace-scoped" not in err

    def test_explicit_empty_selection_installs_no_recipes(self, monkeypatch, manifest, capsys):
        args = self._args(profile="ads", recipes=[])
        self._stub_main(monkeypatch, manifest, args)

        monkeypatch.setattr(
            installer,
            "get_target_ades",
            lambda *a, **kw: pytest.fail("empty selection must not detect ADEs"),
        )

        installer.main()

        assert "No recipes selected; nothing to install." in capsys.readouterr().out

    def test_aborted_run_leaves_a_stale_conflict_in_place(self, monkeypatch, manifest, capsys):
        # Under -y the stale-conflict block uninstalls without prompting, so the
        # guards above have to fire before it ever runs.
        self._stub_main(monkeypatch, manifest, self._args(recipes=["secure-at-commit"]))
        monkeypatch.setattr(
            manifest,
            "detect_stale_conflicts",
            lambda recipes: [("secure-at-commit", "sai-hooks-async", "claude")],
        )
        removed: list = []
        monkeypatch.setattr(
            installer, "uninstall_ade_recipe", lambda *a, **kw: removed.append(a) or None
        )

        with pytest.raises(SystemExit):
            installer.main()

        assert removed == []

    def test_mixed_scope_resolution_without_a_workspace_still_succeeds(
        self, monkeypatch, manifest, capsys
    ):
        # The experimental profile pairs the workspace-scoped secure-at-commit
        # with globally-scoped recipes, so a bare profile reaches this path.
        self._stub_main(monkeypatch, manifest, self._args())

        installer.main()

        assert "skipping workspace-scoped recipes: secure-at-commit" in capsys.readouterr().out

    @pytest.mark.parametrize("profile", ["experimental", "ads"])
    def test_git_global_only_selection_does_not_require_an_ade(
        self, monkeypatch, manifest, profile
    ):
        """A pure git-global recipe selection must install even when this
        machine has no ADE and none was passed - get_target_ades must never
        even be called."""
        args = self._args(profile=profile, recipes=["secrets-precommit-hook-global"], ade=None)
        self._stub_main(monkeypatch, manifest, args)

        def _must_not_be_called(*_a, **_kw):
            raise AssertionError(
                "get_target_ades must not be called for a git-global-only selection"
            )

        monkeypatch.setattr(installer, "get_target_ades", _must_not_be_called)
        monkeypatch.setattr(installer, "install_git_global_recipe", lambda *a, **kw: None)
        monkeypatch.setattr(installer, "verify_git_global_recipe", lambda *a, **kw: True)

        installer.main()

    def test_verify_notes_the_unused_selection_without_validating_it(
        self, monkeypatch, manifest, capsys
    ):
        args = self._args(verify=True, profile="default", recipes=["not-a-real-recipe"])
        self._stub_main(monkeypatch, manifest, args)

        installer.main()

        out = capsys.readouterr().out
        assert "--verify does not use --recipes" in out
        assert "All checks passed" in out

    def test_uninstall_notes_the_unused_selection_without_validating_it(
        self, monkeypatch, manifest, capsys
    ):
        args = self._args(uninstall=True, profile="default", recipes=["not-a-real-recipe"])
        self._stub_main(monkeypatch, manifest, args)
        swept: list = []
        monkeypatch.setattr(installer, "uninstall", lambda *a, **kw: swept.append(a) or None)

        installer.main()

        out = capsys.readouterr().out
        assert "--uninstall does not use --recipes" in out
        assert "Uninstall complete" in out
        assert len(swept) == 1

    def test_uninstall_does_not_require_an_ade(self, monkeypatch, manifest, capsys):
        """--uninstall must still run (git-global/workspace cleanup) when no
        ADE is detected or passed - only the ADE-scoped part is skipped."""
        real_get_target_ades = installer.get_target_ades
        args = self._args(uninstall=True, ade=None)
        self._stub_main(monkeypatch, manifest, args)
        monkeypatch.setattr(installer, "get_target_ades", real_get_target_ades)
        monkeypatch.setattr(installer, "detect_ades", lambda: [])
        captured: dict = {}
        monkeypatch.setattr(
            installer, "uninstall", lambda ades, *a, **kw: captured.setdefault("ades", ades)
        )

        installer.main()

        assert captured["ades"] == []
        assert "Uninstall complete" in capsys.readouterr().out

    def test_list_notes_the_unused_selection(self, monkeypatch, manifest, capsys):
        args = self._args(list_mode=True, profile="default", recipes=["bogus"])
        self._stub_main(monkeypatch, manifest, args)

        installer.main()

        assert "--list does not use --recipes" in capsys.readouterr().out

    def test_no_notice_without_a_selection(self, monkeypatch, manifest, capsys):
        args = self._args(list_mode=True, profile="default")
        self._stub_main(monkeypatch, manifest, args)

        installer.main()

        assert "--recipes" not in capsys.readouterr().out

    @pytest.mark.parametrize("mode", ["diag_dump", "list_mode", "verify", "uninstall"])
    def test_every_mode_returning_before_resolution_notes_the_selection(self, mode, capsys):
        args = self._args(recipes=["secure-at-commit"], **{mode: True})
        installer.notify_unused_recipe_selection(args)
        assert "does not use --recipes" in capsys.readouterr().out

    def test_install_path_gets_no_notice(self, capsys):
        installer.notify_unused_recipe_selection(self._args(recipes=["secure-at-commit"]))
        assert capsys.readouterr().out == ""


# ===========================================================================
# TestCopyFile
# ===========================================================================


class TestCopyFile:
    def test_copies_new_file(self, tmp_path):
        src = tmp_path / "src.txt"
        src.write_text("hello")
        dest = tmp_path / "sub" / "dest.txt"
        installer.copy_file(src, dest, dry_run=False)
        assert dest.read_text() == "hello"

    def test_skips_identical_file(self, tmp_path, capsys):
        src = tmp_path / "src.txt"
        src.write_text("hello")
        dest = tmp_path / "dest.txt"
        dest.write_text("hello")
        installer.copy_file(src, dest, dry_run=False)
        captured = capsys.readouterr()
        assert "unchanged" in captured.out

    def test_dry_run_no_write(self, tmp_path, capsys):
        src = tmp_path / "src.txt"
        src.write_text("hello")
        dest = tmp_path / "dest.txt"
        installer.copy_file(src, dest, dry_run=True)
        assert not dest.exists()
        captured = capsys.readouterr()
        assert "dry-run" in captured.out


# ===========================================================================
# TestExpandInstallTokens — $HOME/$WORKSPACE substitution in command strings
# ===========================================================================


class TestExpandInstallTokens:
    def test_expands_home_and_workspace(self, tmp_path, monkeypatch):
        monkeypatch.setattr(installer.Path, "home", lambda: tmp_path)
        result = installer.expand_install_tokens('uv run "$HOME/a.py" "$WORKSPACE/b.py"', tmp_path)
        assert result == f'uv run "{tmp_path}/a.py" "{tmp_path}/b.py"'

    def test_rejects_home_with_embedded_quote(self, monkeypatch):
        monkeypatch.setattr(installer.Path, "home", lambda: Path('"/evil"'))
        with pytest.raises(RuntimeError, match="\\$HOME"):
            installer.expand_install_tokens('uv run "$HOME/a.py"', None)

    def test_rejects_workspace_with_embedded_quote(self, tmp_path):
        evil = tmp_path / '"evil"'
        with pytest.raises(RuntimeError, match="\\$WORKSPACE"):
            installer.expand_install_tokens('uv run "$WORKSPACE/a.py"', evil)


# ===========================================================================
# TestExpandSource — install-time $HOME expansion via temp-file context manager
# ===========================================================================


class TestExpandSource:
    def test_matching_strategy_expands_and_cleans_up(self, tmp_path):
        source = tmp_path / "hooks.json"
        source.write_text('{"command": "uv run \\"$HOME/test.py\\""}')
        tmp_file_path = None
        with installer._expand_source("merge_cursor_hooks", source) as resolved_path:
            assert resolved_path != source
            tmp_file_path = resolved_path
            assert tmp_file_path.exists()
            content = tmp_file_path.read_text()
            assert "$HOME" not in content
            assert os.path.expanduser("~") in content
        assert tmp_file_path is not None
        assert not tmp_file_path.exists()

    def test_non_matching_strategy_passthrough(self, tmp_path):
        source = tmp_path / "data.json"
        source.write_text('{"key": "value"}')
        with installer._expand_source("copy_files", source) as resolved_path:
            assert resolved_path == source

    def test_unmerge_strategy_passthrough(self, tmp_path):
        # Unmerge handles dual-form (raw vs expanded) matching itself, so it
        # must receive the raw source — not the expanded one.
        source = tmp_path / "hooks.json"
        source.write_text('{"command": "uv run \\"$HOME/test.py\\""}')
        with installer._expand_source("unmerge_cursor_hooks", source) as resolved_path:
            assert resolved_path == source

    def test_verify_strategy_expands(self, tmp_path):
        source = tmp_path / "hooks.json"
        source.write_text('{"command": "uv run \\"$HOME/test.py\\""}')
        with installer._expand_source("verify_cursor_hooks", source) as resolved_path:
            assert resolved_path != source
            assert "$HOME" not in resolved_path.read_text()

    def test_cleans_up_on_exception(self, tmp_path):
        source = tmp_path / "hooks.json"
        source.write_text('{"hooks": {}}')
        tmp_file_path = None
        with pytest.raises(RuntimeError):  # noqa: PT012 — exception must propagate through context manager __exit__
            with installer._expand_source("merge_claude_settings", source) as resolved_path:
                tmp_file_path = resolved_path
                raise RuntimeError("boom")
        assert tmp_file_path is not None
        assert not tmp_file_path.exists()

    def test_toml_strategy_expands(self, tmp_path):
        source = tmp_path / "config.toml"
        source.write_text('[hooks]\ncommand = "uv run \\"$HOME/.codex/hooks/test.py\\""\n')
        with installer._expand_source("merge_codex_config", source) as resolved_path:
            assert resolved_path != source
            assert resolved_path.suffix == ".toml"
            content = resolved_path.read_text()
            assert "$HOME" not in content
            assert os.path.expanduser("~") in content


# ===========================================================================
# TestMergeConfig
# ===========================================================================


class TestMergeConfig:
    def test_dry_run(self, tmp_path, capsys):
        source = tmp_path / "source.json"
        source.write_text("{}")
        target = tmp_path / "target.json"
        payload = MagicMock()
        installer.merge_config("merge_cursor_hooks", target, source, payload, dry_run=True)
        assert not target.exists()
        assert "dry-run" in capsys.readouterr().out

    def test_unknown_strategy(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(sys, "path", list(sys.path))
        source = tmp_path / "source.json"
        source.write_text("{}")
        target = tmp_path / "target.json"
        payload = installer.PayloadContext()
        payload.setup()
        try:
            installer.merge_config("no_such_strategy_xyz", target, source, payload, dry_run=False)
        finally:
            payload.cleanup()
        assert "Unknown strategy" in capsys.readouterr().out
        assert not target.exists()

    def test_valid_strategy(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(sys, "path", list(sys.path))
        payload = installer.PayloadContext()
        payload.setup()
        try:
            manifest = installer.Manifest(payload.manifest_path)
            sources = manifest.get_sources("sai-hooks-async", "claude")
            cm = sources.get("config_merge")
            assert cm is not None, "expected config_merge for sai-hooks-async/claude"
            source = payload.resolve_src(cm["source"])
            strategy = cm["strategy"]
            target = tmp_path / "settings.json"
            installer.merge_config(strategy, target, source, payload, dry_run=False)
        finally:
            payload.cleanup()
        assert "merged:" in capsys.readouterr().out

    def test_merge_invalid_json(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(sys, "path", list(sys.path))
        payload = installer.PayloadContext()
        payload.setup()
        try:
            source = tmp_path / "source.json"
            source.write_text('{"hooks": {}}')
            target = tmp_path / "target.json"
            target.write_text("{ invalid }")

            installer.merge_config("merge_cursor_hooks", target, source, payload, dry_run=False)
        finally:
            payload.cleanup()

        assert "Cannot update configuration, parse error in file" in capsys.readouterr().out


# ===========================================================================
# TestLifecycle
# ===========================================================================


class TestLifecycle:
    """Integration test: install -> verify -> uninstall with temp HOME."""

    @pytest.fixture
    def fake_home(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".cursor").mkdir()
        (tmp_path / ".gemini").mkdir()
        return tmp_path

    @pytest.fixture
    def payload(self):
        ctx = installer.PayloadContext()
        ctx.setup()
        yield ctx
        ctx.cleanup()

    @pytest.fixture
    def manifest(self, payload):
        return installer.Manifest(payload.manifest_path)

    def test_install_verify_uninstall(self, fake_home, payload, manifest):
        ades = ["claude"]
        recipes = manifest.resolve_recipes("default")

        # Install
        for ade in ades:
            for recipe_id in recipes:
                installer.install_recipe(recipe_id, ade, manifest, payload, dry_run=False)

        # Verify files exist
        assert (fake_home / ".claude" / "hooks" / "snyk_secure_at_inception.py").exists()
        assert (fake_home / ".claude" / "hooks" / "lib" / "scan_runner.py").exists()
        assert (fake_home / ".claude" / "hooks" / "lib" / "platform_utils.py").exists()
        assert (fake_home / ".claude" / "commands" / "snyk-fix.md").exists()

        # Verify via installer
        for ade in ades:
            for recipe_id in recipes:
                assert installer.verify_recipe(recipe_id, ade, manifest, payload)

        # Uninstall
        installer.uninstall(ades, manifest, payload, workspace=None, dry_run=False)

        # Verify files removed
        assert not (fake_home / ".claude" / "hooks" / "snyk_secure_at_inception.py").exists()

    def test_install_verify_uninstall_gemini(self, fake_home, payload, manifest):
        ades = ["gemini"]
        recipes = manifest.resolve_recipes("default")

        for ade in ades:
            for recipe_id in recipes:
                installer.install_recipe(recipe_id, ade, manifest, payload, dry_run=False)

        gemini_settings = fake_home / ".gemini" / "settings.json"
        assert (fake_home / ".gemini" / "hooks" / "snyk_secure_at_inception.py").exists()
        assert (fake_home / ".gemini" / "hooks" / "lib" / "scan_runner.py").exists()
        assert (fake_home / ".gemini" / "commands" / "snyk-fix.md").exists()
        assert gemini_settings.exists()

        settings_after_install = json.loads(gemini_settings.read_text())
        assert settings_after_install.get("hooks"), (
            "expected hooks merged into gemini settings.json"
        )
        assert settings_after_install.get("mcpServers", {}).get("Snyk"), (
            "expected MCP server merged into gemini settings.json"
        )

        for ade in ades:
            for recipe_id in recipes:
                assert installer.verify_recipe(recipe_id, ade, manifest, payload)

        installer.uninstall(ades, manifest, payload, workspace=None, dry_run=False)

        assert not (fake_home / ".gemini" / "hooks" / "snyk_secure_at_inception.py").exists()
        assert not (fake_home / ".gemini" / "commands" / "snyk-fix.md").exists()

        settings_after_uninstall = json.loads(gemini_settings.read_text())
        assert not settings_after_uninstall.get("hooks"), (
            "unmerge_gemini_settings should remove Snyk hooks from settings.json"
        )
        assert "Snyk" not in settings_after_uninstall.get("mcpServers", {}), (
            "unmerge_mcp_servers should remove the Snyk MCP server from settings.json"
        )

    def test_install_verify_uninstall_kiro(self, fake_home, payload, manifest):
        ades = ["kiro"]
        recipes = manifest.resolve_recipes("default")

        for ade in ades:
            for recipe_id in recipes:
                installer.install_recipe(recipe_id, ade, manifest, payload, dry_run=False)

        kiro_mcp_settings = fake_home / ".kiro" / "settings" / "mcp.json"
        assert (fake_home / ".kiro" / "steering" / "snyk-fix.md").exists()
        assert (fake_home / ".kiro" / "steering" / "snyk-batch-fix.md").exists()
        assert (
            fake_home / ".kiro" / "skills" / "secure-dependency-health-check" / "SKILL.md"
        ).exists()
        assert kiro_mcp_settings.exists()

        settings_after_install = json.loads(kiro_mcp_settings.read_text())
        assert settings_after_install.get("mcpServers", {}).get("Snyk"), (
            "expected MCP server merged into .kiro/settings/mcp.json"
        )

        for ade in ades:
            for recipe_id in recipes:
                # verify_recipe will return True for sai-hooks-async because it has no sources for kiro
                assert installer.verify_recipe(recipe_id, ade, manifest, payload)

        installer.uninstall(ades, manifest, payload, workspace=None, dry_run=False)

        assert not (fake_home / ".kiro" / "steering" / "snyk-fix.md").exists()

        settings_after_uninstall = json.loads(kiro_mcp_settings.read_text())
        assert "Snyk" not in settings_after_uninstall.get("mcpServers", {}), (
            "unmerge_mcp_servers should remove the Snyk MCP server from .kiro/settings/mcp.json"
        )

    def test_dry_run_makes_no_changes(self, fake_home, payload, manifest):
        recipes = manifest.resolve_recipes("default")
        for recipe_id in recipes:
            installer.install_recipe(recipe_id, "claude", manifest, payload, dry_run=True)

        assert not (fake_home / ".claude" / "hooks" / "snyk_secure_at_inception.py").exists()

    def test_codex_install_verify_uninstall(self, tmp_path, payload, manifest, monkeypatch):
        # Codex doesn't get all recipes (no slash commands), so use a fresh fake_home
        # without claude/cursor pre-created so we exercise the codex-only path.
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        recipes = manifest.resolve_recipes("default")

        # Install codex recipes
        for recipe_id in recipes:
            installer.install_recipe(recipe_id, "codex", manifest, payload, dry_run=False)

        # Hook scripts and lib live under ~/.codex/
        assert (tmp_path / ".codex" / "hooks" / "snyk_secure_at_inception.py").exists()
        assert (tmp_path / ".codex" / "hooks" / "lib" / "scan_runner.py").exists()
        # Skill files live under ~/.agents/skills/snyk/ (NOT ~/.codex/)
        assert (
            tmp_path / ".agents" / "skills" / "snyk" / "secure-dependency-health-check" / "SKILL.md"
        ).exists()
        assert (tmp_path / ".agents" / "skills" / "snyk" / "snyk-fix" / "SKILL.md").exists()
        # Hooks + MCP both merged into a single config.toml
        config_toml = (tmp_path / ".codex" / "config.toml").read_text()
        assert "hooks = true" in config_toml
        assert "[mcp_servers.Snyk]" in config_toml
        assert "PostToolUse" in config_toml

        # Slash-command recipes have no codex source, so they should produce no files
        assert not (tmp_path / ".codex" / "commands" / "snyk-fix.md").exists()

        # Verify
        for recipe_id in recipes:
            assert installer.verify_recipe(recipe_id, "codex", manifest, payload)

        # Uninstall removes our entries; user content (none here) is preserved
        installer.uninstall(["codex"], manifest, payload, workspace=None, dry_run=False)
        assert not (tmp_path / ".codex" / "hooks" / "snyk_secure_at_inception.py").exists()
        # config.toml itself is removed when only Snyk content was present
        assert not (tmp_path / ".codex" / "config.toml").exists()
        # .bak file from the merge backup is left behind (intentional, matches claude behavior)
        assert (tmp_path / ".codex" / "config.toml.bak").exists()

    def test_copilot_cli_install_verify_uninstall(self, tmp_path, payload, manifest, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        recipes = manifest.resolve_recipes("default")

        for recipe_id in recipes:
            installer.install_recipe(recipe_id, "copilot-cli", manifest, payload, dry_run=False)

        assert (
            tmp_path / ".copilot" / "skills" / "secure-dependency-health-check" / "SKILL.md"
        ).exists()
        assert (tmp_path / ".copilot" / "skills" / "snyk-fix" / "SKILL.md").exists()
        # sai-hooks-async should drop scripts and merge ~/.copilot/hooks/hooks.json
        assert (tmp_path / ".copilot" / "hooks" / "snyk_secure_at_inception.py").exists()
        assert (tmp_path / ".copilot" / "hooks" / "lib" / "scan_runner.py").exists()
        hooks_cfg = json.loads((tmp_path / ".copilot" / "hooks" / "hooks.json").read_text())
        for event in ("sessionStart", "postToolUse", "agentStop"):
            assert any(
                "snyk_secure_at_inception" in e.get("bash", "") for e in hooks_cfg["hooks"][event]
            ), event

        for recipe_id in recipes:
            assert installer.verify_recipe(recipe_id, "copilot-cli", manifest, payload)

        installer.uninstall(["copilot-cli"], manifest, payload, workspace=None, dry_run=False)
        assert not (tmp_path / ".copilot" / "skills" / "snyk-fix" / "SKILL.md").exists()
        assert not (tmp_path / ".copilot" / "hooks" / "snyk_secure_at_inception.py").exists()

    def test_copilot_vscode_sai_installs_under_dot_copilot_hooks(
        self, tmp_path, payload, manifest, monkeypatch
    ):
        """copilot-vscode SAI files must land in ~/.copilot/hooks/ (shared with the
        CLI), not in the VS Code user-data dir — that's what resolve_ade_path's
        special case enables."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        # Point the VS Code user dir somewhere distinct from $HOME so we can
        # tell whether the SAI files leaked there.
        vscode_user = tmp_path / "vscode-userdata" / "Code"
        monkeypatch.setattr(installer, "_vscode_user_dir", lambda: vscode_user)

        installer.install_recipe(
            "sai-hooks-async", "copilot-vscode", manifest, payload, dry_run=False
        )

        # SAI hooks live under $HOME/.copilot/, not under the VS Code user dir.
        assert (tmp_path / ".copilot" / "hooks" / "snyk_secure_at_inception.py").exists()
        assert (tmp_path / ".copilot" / "hooks" / "hooks.json").exists()
        assert not (vscode_user / "User" / ".copilot").exists()

        assert installer.verify_recipe("sai-hooks-async", "copilot-vscode", manifest, payload)

        installer.uninstall(["copilot-vscode"], manifest, payload, workspace=None, dry_run=False)
        assert not (tmp_path / ".copilot" / "hooks" / "snyk_secure_at_inception.py").exists()

    def _seed_legacy_copilot_hooks(self, tmp_path, extra_events=None):
        """Write a pre-AG-299 ~/.copilot/hooks.json (wrong location) the way the
        buggy installer would have, plus any extra non-Snyk entries."""
        hooks = {
            "sessionStart": [
                {
                    "type": "command",
                    "bash": 'uv run "$HOME/.copilot/hooks/snyk_secure_at_inception.py" sessionStart',
                    "timeoutSec": 10,
                }
            ]
        }
        hooks.update(extra_events or {})
        legacy = tmp_path / ".copilot" / "hooks.json"
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text(json.dumps({"version": 1, "hooks": hooks}))
        return legacy

    def test_install_removes_legacy_copilot_hooks_file_when_empty(
        self, tmp_path, payload, manifest, monkeypatch
    ):
        """Upgrading from the buggy version (hooks merged into ~/.copilot/hooks.json)
        should strip Snyk entries from the old file and delete it once nothing else
        remains, so no dead config is left at the wrong path."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        legacy = self._seed_legacy_copilot_hooks(tmp_path)

        installer.install_recipe("sai-hooks-async", "copilot-cli", manifest, payload, dry_run=False)

        # Old location is gone; hooks now live at the correct path.
        assert not legacy.exists()
        assert not (tmp_path / ".copilot" / "hooks.json.bak").exists()
        assert (tmp_path / ".copilot" / "hooks" / "hooks.json").exists()

    def test_install_preserves_user_entries_in_legacy_file(
        self, tmp_path, payload, manifest, monkeypatch
    ):
        """A legacy ~/.copilot/hooks.json that also holds a user's own hook must keep
        that hook — only Snyk-owned entries are stripped, and the file survives."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        user_entry = {"type": "command", "bash": "echo my-own-hook", "timeoutSec": 5}
        legacy = self._seed_legacy_copilot_hooks(
            tmp_path, extra_events={"preToolUse": [user_entry]}
        )

        installer.install_recipe("sai-hooks-async", "copilot-cli", manifest, payload, dry_run=False)

        remaining = json.loads(legacy.read_text())
        assert "sessionStart" not in remaining["hooks"]  # Snyk entry stripped
        assert remaining["hooks"]["preToolUse"] == [user_entry]  # user entry kept

    def test_uninstall_cleans_legacy_copilot_hooks_file(
        self, tmp_path, payload, manifest, monkeypatch
    ):
        """Uninstall must also clean the old location for users who never re-ran a
        fixed install before removing Snyk."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        legacy = self._seed_legacy_copilot_hooks(tmp_path)

        installer.uninstall(["copilot-cli"], manifest, payload, workspace=None, dry_run=False)

        assert not legacy.exists()

    def test_install_verify_uninstall_windsurf(self, tmp_path, payload, manifest, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        (tmp_path / ".codeium" / "windsurf").mkdir(parents=True)
        recipes = manifest.resolve_recipes("default")

        for recipe_id in recipes:
            installer.install_recipe(recipe_id, "windsurf", manifest, payload, dry_run=False)

        # Workflow files go under .codeium/windsurf/global_workflows/
        assert (tmp_path / ".codeium" / "windsurf" / "global_workflows" / "snyk-fix.md").exists()
        assert (
            tmp_path / ".codeium" / "windsurf" / "global_workflows" / "snyk-batch-fix.md"
        ).exists()
        # Skills go under .agents/skills/ (not under the windsurf ADE home)
        assert (
            tmp_path / ".agents" / "skills" / "secure-dependency-health-check" / "SKILL.md"
        ).exists()
        # MCP config merged into .codeium/windsurf/mcp_config.json
        mcp_config = tmp_path / ".codeium" / "windsurf" / "mcp_config.json"
        assert mcp_config.exists()
        assert json.loads(mcp_config.read_text()).get("mcpServers", {}).get("Snyk"), (
            "expected MCP server merged into .codeium/windsurf/mcp_config.json"
        )

        for recipe_id in recipes:
            assert installer.verify_recipe(recipe_id, "windsurf", manifest, payload)

        installer.uninstall(["windsurf"], manifest, payload, workspace=None, dry_run=False)

        assert not (
            tmp_path / ".codeium" / "windsurf" / "global_workflows" / "snyk-fix.md"
        ).exists()
        assert "Snyk" not in json.loads(mcp_config.read_text()).get("mcpServers", {}), (
            "unmerge_mcp_servers should remove the Snyk MCP server from mcp_config.json"
        )


# ===========================================================================
# TestResolveAdePath
# ===========================================================================


class TestResolveAdePath:
    def test_home_based_ade(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        assert installer.resolve_ade_path("claude", ".claude/hooks/x.py") == (
            tmp_path / ".claude/hooks/x.py"
        )

    def test_copilot_vscode_non_copilot_path_uses_vscode_user_dir(self, tmp_path, monkeypatch):
        vscode_user = tmp_path / "vscode-userdata" / "Code"
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr(installer, "_vscode_user_dir", lambda: vscode_user)
        # Non-.copilot dest resolves under the VS Code user-data dir (User subdir).
        assert installer.resolve_ade_path("copilot-vscode", "prompts/snyk-fix.prompt.md") == (
            vscode_user / "User" / "prompts" / "snyk-fix.prompt.md"
        )

    def test_copilot_vscode_dot_copilot_path_uses_home(self, tmp_path, monkeypatch):
        vscode_user = tmp_path / "vscode-userdata" / "Code"
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr(installer, "_vscode_user_dir", lambda: vscode_user)
        # .copilot/... dest is special-cased to resolve under $HOME so SAI files
        # land where Copilot CLI also reads them from.
        assert installer.resolve_ade_path(
            "copilot-vscode", ".copilot/hooks/snyk_secure_at_inception.py"
        ) == (tmp_path / ".copilot" / "hooks" / "snyk_secure_at_inception.py")
        assert installer.resolve_ade_path("copilot-vscode", ".copilot/hooks.json") == (
            tmp_path / ".copilot" / "hooks.json"
        )

    def test_copilot_vscode_lookalike_prefix_not_matched(self, tmp_path, monkeypatch):
        """A dest that merely starts with the literal string `.copilot` (e.g.
        `.copilot-other/...`) should NOT trigger the special case."""
        vscode_user = tmp_path / "vscode-userdata" / "Code"
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr(installer, "_vscode_user_dir", lambda: vscode_user)
        result = installer.resolve_ade_path("copilot-vscode", ".copilot-other/x.json")
        # Should resolve under the VS Code user dir, not $HOME
        assert result == vscode_user / "User" / ".copilot-other" / "x.json"


# ===========================================================================
# TestVerifyRecipe
# ===========================================================================


class TestVerifyRecipe:
    def test_verify_recipe_invalid_json(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        payload = installer.PayloadContext()
        payload.setup()
        manifest = installer.Manifest(payload.manifest_path)

        # Create an invalid JSON file at the target location for claude settings
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text("{ invalid }")

        # sai-hooks-async for claude uses merge_claude_settings
        result = installer.verify_recipe("sai-hooks-async", "claude", manifest, payload)

        assert result is False
        assert "Cannot update configuration, parse error in file" in capsys.readouterr().out


# ===========================================================================
# TestVSCodeSettingsConflict
# ===========================================================================


class TestVSCodeSettingsConflict:
    @pytest.fixture
    def manifest(self):
        """Fixture to provide a Manifest instance using the real manifest.json."""
        return installer.Manifest(INSTALLER_DIR / "manifest.json")

    @pytest.fixture
    def vscode_env(self, tmp_path, monkeypatch):
        """Sets up a mock environment with home and workspace directories."""
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setattr(Path, "home", lambda: home)
        monkeypatch.chdir(tmp_path)
        # Default to non-windows for consistent testing
        monkeypatch.setattr(sys, "platform", "darwin")

        # Paths must align with entries in manifest.json:
        # global: Cursor/User/settings.json (on Darwin, prefixed with Library/Application Support)
        # local: .vscode/settings.json
        return {
            "home": home,
            "workspace": tmp_path,
            "global_dir": home / "Library" / "Application Support" / "Cursor" / "User",
            "workspace_dir": tmp_path / ".vscode",
        }

    def test_no_settings_files(self, manifest, vscode_env):
        assert not manifest.are_extension_settings_conflicting("cursor")

    def test_workspace_conflict(self, manifest, vscode_env):
        ws_dir = vscode_env["workspace_dir"]
        ws_dir.mkdir(parents=True)
        (ws_dir / "settings.json").write_text(
            json.dumps(
                {
                    "snyk.securityAtInception.autoConfigureSnykMcpServer": True,
                    "snyk.securityAtInception.executionFrequency": "On Code Generation",
                }
            )
        )
        assert manifest.are_extension_settings_conflicting("cursor")

    def test_global_conflict_not_masked_by_manual_workspace(self, manifest, vscode_env):
        # Global has SAI running on code generation.
        global_dir = vscode_env["global_dir"]
        global_dir.mkdir(parents=True)
        global_settings = global_dir / "settings.json"
        global_settings.write_text(
            json.dumps(
                {
                    "snyk.securityAtInception.executionFrequency": "On Code Generation",
                }
            )
        )

        # Workspace pins it to Manual. Scopes are evaluated independently, so the
        # workspace override must NOT hide the live global conflict.
        ws_dir = vscode_env["workspace_dir"]
        ws_dir.mkdir(parents=True)
        (ws_dir / "settings.json").write_text(
            json.dumps(
                {
                    "snyk.securityAtInception.executionFrequency": "Manual",
                }
            )
        )

        conflicts = manifest.are_extension_settings_conflicting("cursor")
        assert conflicts == [str(global_settings.resolve())]

    def test_all_conflicting_scopes_reported(self, manifest, vscode_env):
        # Both global and workspace have SAI running non-Manual -> both reported.
        global_dir = vscode_env["global_dir"]
        global_dir.mkdir(parents=True)
        global_settings = global_dir / "settings.json"
        global_settings.write_text(
            json.dumps({"snyk.securityAtInception.executionFrequency": "On Code Generation"})
        )

        ws_dir = vscode_env["workspace_dir"]
        ws_dir.mkdir(parents=True)
        ws_settings = ws_dir / "settings.json"
        ws_settings.write_text(
            json.dumps({"snyk.securityAtInception.executionFrequency": "On Save"})
        )

        conflicts = manifest.are_extension_settings_conflicting("cursor")
        assert set(conflicts) == {
            str(global_settings.resolve()),
            str(ws_settings.resolve()),
        }

    def test_conflict_detected_without_auto_configure_flag(self, manifest, vscode_env):
        # autoConfigureSnykMcpServer is intentionally ignored: a non-Manual
        # executionFrequency alone is a conflict.
        ws_dir = vscode_env["workspace_dir"]
        ws_dir.mkdir(parents=True)
        (ws_dir / "settings.json").write_text(
            json.dumps(
                {
                    "snyk.securityAtInception.executionFrequency": "On Code Generation",
                }
            )
        )
        assert manifest.are_extension_settings_conflicting("cursor")

    def test_workspace_manual_frequency_is_no_conflict(self, manifest, vscode_env):
        ws_dir = vscode_env["workspace_dir"]
        ws_dir.mkdir(parents=True)
        (ws_dir / "settings.json").write_text(
            json.dumps(
                {
                    "snyk.securityAtInception.executionFrequency": "Manual",
                }
            )
        )
        assert not manifest.are_extension_settings_conflicting("cursor")

    def test_unset_execution_frequency_defaults_to_manual_no_conflict(self, manifest, vscode_env):
        ws_dir = vscode_env["workspace_dir"]
        ws_dir.mkdir(parents=True)
        (ws_dir / "settings.json").write_text(
            json.dumps(
                {
                    "snyk.securityAtInception.autoConfigureSnykMcpServer": True,
                }
            )
        )
        assert not manifest.are_extension_settings_conflicting("cursor")

    def test_windows_global_path(self, manifest, vscode_env, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(installer, "_IS_WINDOWS", True)
        appdata = vscode_env["home"] / "AppData" / "Roaming"
        monkeypatch.setitem(os.environ, "APPDATA", str(appdata))

        win_global_dir = appdata / "Cursor" / "User"
        win_global_dir.mkdir(parents=True)
        (win_global_dir / "settings.json").write_text(
            json.dumps(
                {
                    "snyk.securityAtInception.autoConfigureSnykMcpServer": True,
                    "snyk.securityAtInception.executionFrequency": "On Code Generation",
                }
            )
        )

        assert manifest.are_extension_settings_conflicting("cursor")

    def test_invalid_json_skips(self, manifest, vscode_env):
        ws_dir = vscode_env["workspace_dir"]
        ws_dir.mkdir(parents=True)
        (ws_dir / "settings.json").write_text("{ invalid json")
        assert not manifest.are_extension_settings_conflicting("cursor")

    def test_skips_check_if_ade_not_configured_in_manifest(self, manifest, vscode_env):
        # Global has conflict values
        global_dir = vscode_env["global_dir"]
        global_dir.mkdir(parents=True)
        (global_dir / "settings.json").write_text(
            json.dumps(
                {
                    "snyk.securityAtInception.autoConfigureSnykMcpServer": True,
                    "snyk.securityAtInception.executionFrequency": "On Code Generation",
                }
            )
        )
        # 'claude' has no extension-settings entries in manifest.json, so it should return False.
        assert not manifest.are_extension_settings_conflicting("claude")

    def test_resolve_extension_conflicts(self, manifest, vscode_env):
        ws_dir = vscode_env["workspace_dir"]
        ws_dir.mkdir(parents=True)
        settings_file = ws_dir / "settings.json"
        original_data = {
            "snyk.securityAtInception.autoConfigureSnykMcpServer": True,
            "snyk.securityAtInception.executionFrequency": "On Code Generation",
            "other.setting": "value",
        }
        settings_file.write_text(json.dumps(original_data))

        updated = manifest.resolve_extension_conflicts([str(settings_file)])

        # executionFrequency is pinned to Manual; unrelated settings (including
        # autoConfigureSnykMcpServer, which we no longer touch) are preserved.
        updated_data = json.loads(settings_file.read_text())
        assert updated_data["snyk.securityAtInception.executionFrequency"] == "Manual"
        assert updated_data["snyk.securityAtInception.autoConfigureSnykMcpServer"] is True
        assert updated_data["other.setting"] == "value"
        assert updated == [str(settings_file.resolve())]

    def test_resolve_extension_conflicts_jsonc(self, manifest, vscode_env):
        # A JSONC settings file (block comment + trailing comma) that was flagged
        # as conflicting must also update — not silently fail on strict json.load.
        ws_dir = vscode_env["workspace_dir"]
        ws_dir.mkdir(parents=True)
        settings_file = ws_dir / "settings.json"
        settings_file.write_text(
            """{
            /* Snyk config */
            "snyk.securityAtInception.executionFrequency": "On Code Generation",
            "other.setting": "value",
        }"""
        )

        # Confirm it is detected, then resolved.
        assert manifest.are_extension_settings_conflicting("cursor")
        updated = manifest.resolve_extension_conflicts([str(settings_file)])

        assert updated == [str(settings_file.resolve())]
        updated_data = json.loads(settings_file.read_text())
        assert updated_data["snyk.securityAtInception.executionFrequency"] == "Manual"
        assert updated_data["other.setting"] == "value"
        # And it is no longer flagged as conflicting.
        assert not manifest.are_extension_settings_conflicting("cursor")

    def test_json_with_comments_and_trailing_commas(self, manifest, vscode_env):
        ws_dir = vscode_env["workspace_dir"]
        ws_dir.mkdir(parents=True)
        # JSON with comments and trailing commas - valid after regex cleanup
        json_content = """{
            /* Block comment */
            "snyk.securityAtInception.autoConfigureSnykMcpServer": true,
            "snyk.securityAtInception.executionFrequency": "On Code Generation",
            "trailing": "comma",
        }"""
        (ws_dir / "settings.json").write_text(json_content)
        assert manifest.are_extension_settings_conflicting("cursor")

    def test_path_outside_home_or_workspace_security(self, manifest, vscode_env, monkeypatch):
        # Create a settings file in a "malicious" location outside home and workspace
        import tempfile

        with tempfile.TemporaryDirectory() as tmp_dir:
            malicious_file = Path(tmp_dir) / "settings.json"
            malicious_file.write_text(
                json.dumps(
                    {
                        "snyk.securityAtInception.autoConfigureSnykMcpServer": True,
                        "snyk.securityAtInception.executionFrequency": "On Code Generation",
                    }
                )
            )

            # Mock get_extension_settings_path to return this file
            monkeypatch.setattr(
                manifest, "get_extension_settings_path", lambda ade: [malicious_file]
            )

            # are_extension_settings_conflicting should ignore it and return False
            assert not manifest.are_extension_settings_conflicting("cursor")


# ===========================================================================
# TestConflictResolution
# ===========================================================================


class TestConflictResolution:
    @pytest.fixture
    def manifest(self):
        return installer.Manifest(INSTALLER_DIR / "manifest.json")

    def test_get_extension_settings_path_darwin(self, manifest, monkeypatch, tmp_path):
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        paths = manifest.get_extension_settings_path("cursor")
        # Global path on Darwin for cursor: ~/Library/Application Support/Cursor/User/settings.json
        expected_global = tmp_path / "Library/Application Support/Cursor/User/settings.json"
        assert expected_global in paths

    def test_get_extension_settings_path_linux(self, manifest, monkeypatch, tmp_path):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setitem(os.environ, "XDG_CONFIG_HOME", str(tmp_path / ".config"))

        paths = manifest.get_extension_settings_path("cursor")
        # Global path on Linux for cursor: ~/.config/Cursor/User/settings.json
        expected_global = tmp_path / ".config/Cursor/User/settings.json"
        assert expected_global in paths

    def test_get_extension_settings_path_windsurf(self, manifest, monkeypatch, tmp_path):
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        paths = manifest.get_extension_settings_path("windsurf")
        expected_global = tmp_path / "Library/Application Support/Windsurf/User/settings.json"
        expected_workspace = Path(".vscode/settings.json")
        assert expected_global in paths
        assert expected_workspace in paths

    def test_get_extension_settings_path_copilot_vscode(self, manifest, monkeypatch, tmp_path):
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        paths = manifest.get_extension_settings_path("copilot-vscode")
        expected_global = tmp_path / "Library/Application Support/Code/User/settings.json"
        expected_workspace = Path(".vscode/settings.json")
        assert expected_global in paths
        assert expected_workspace in paths

    def test_resolve_extension_conflicts_write_error(self, manifest, tmp_path, capsys, monkeypatch):
        # File must live under an allowed base (home) to pass sink validation,
        # then the mocked open() failure exercises the write-error branch.
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        settings_file = tmp_path / "settings.json"
        settings_file.write_text("{}")

        with patch("builtins.open", side_effect=OSError("Permission denied")):
            manifest.resolve_extension_conflicts([str(settings_file)])

        assert "Failed to update settings file" in capsys.readouterr().out


# ===========================================================================
# TestConflictPromptAutoYes
# ===========================================================================


class TestConflictPromptAutoYes:
    """The -y flag must auto-accept the rule/skill conflict prompts."""

    @staticmethod
    def _args():
        return MagicMock(
            list_mode=False,
            yes=True,
            dry_run=False,
            control_identifier=None,
            uninstall=False,
            verify=False,
            diag_dump=False,
            ade=None,
            profile="default",
            workspace=None,
            no_latest_deps=False,
            cli_path=None,
            recipes=None,
        )

    def _stub_main(self, monkeypatch, manifest, ade="cursor"):
        monkeypatch.setattr(installer, "parse_args", lambda: self._args())
        monkeypatch.setattr(installer, "PayloadContext", lambda: MagicMock())
        monkeypatch.setattr(installer, "Manifest", lambda *a, **kw: manifest)
        monkeypatch.setattr(installer, "check_prerequisites", lambda *a, **kw: None)
        monkeypatch.setattr(installer, "_sync_selected_snyk_cli_sidecars", lambda *a, **kw: None)
        monkeypatch.setattr(installer, "get_target_ades", lambda *a, **kw: [ade])
        monkeypatch.setattr(installer, "resolve_workspace", lambda *a, **kw: None)
        monkeypatch.setattr(installer, "show_plan", lambda *a, **kw: None)
        monkeypatch.setattr(installer, "install_recipe", lambda *a, **kw: None)
        monkeypatch.setattr(installer, "install_workspace_recipe", lambda *a, **kw: None)
        monkeypatch.setattr(installer, "verify_recipe", lambda *a, **kw: True)
        monkeypatch.setattr(installer, "print_banner", lambda: None)

        def boom(*_a, **_kw):
            raise AssertionError("input() must not be called when -y is set")

        monkeypatch.setattr("builtins.input", boom)

    @staticmethod
    def _base_manifest():
        m = MagicMock()
        # Non-empty and ADE-scoped: main() aborts on an empty resolution and on a
        # workspace-only one with no workspace, neither of which these tests exercise.
        m.resolve_recipes.return_value = ["mcp-config"]
        m.detect_stale_conflicts.return_value = []
        m.are_extension_settings_conflicting.return_value = []
        m.are_rules_conflicting.return_value = False
        m.are_skills_conflicting.return_value = False
        m.get_conflicting_resource_scope.return_value = []
        m.is_workspace_scoped.return_value = False
        m.is_git_global_scoped.return_value = False
        return m

    def test_rules_conflict_auto_accepts_under_yes(self, monkeypatch, capsys):
        manifest = self._base_manifest()
        manifest.are_rules_conflicting.return_value = True
        manifest.get_conflicting_resource_scope.return_value = ["workspace"]
        self._stub_main(monkeypatch, manifest)

        cmds: list = []
        monkeypatch.setattr(
            installer,
            "run",
            lambda cmd, **kw: cmds.append(cmd) or MagicMock(returncode=0),
        )

        installer.main()

        assert any(isinstance(c, list) and c[:3] == ["snyk", "mcp", "configure"] for c in cmds), (
            f"expected snyk mcp configure invocation, got {cmds}"
        )

    def test_rules_conflict_uses_selected_snyk_cli_for_cleanup(self, monkeypatch, capsys):
        manifest = self._base_manifest()
        manifest.are_rules_conflicting.return_value = True
        manifest.get_conflicting_resource_scope.return_value = ["workspace"]
        selected = installer.SnykCliSelection(
            "/tmp/npm/bin/snyk",
            "1.1306.0",
            installer.SNYK_CLI_SOURCE_NPM,
        )
        self._stub_main(monkeypatch, manifest)
        monkeypatch.setattr(installer, "check_prerequisites", lambda *a, **kw: selected)

        cmds: list = []
        monkeypatch.setattr(
            installer,
            "run",
            lambda cmd, **kw: cmds.append(cmd) or MagicMock(returncode=0),
        )

        installer.main()

        assert any(
            isinstance(c, list) and c[:3] == [selected.path, "mcp", "configure"] for c in cmds
        ), f"expected selected Snyk CLI cleanup invocation, got {cmds}"

    def test_skills_conflict_auto_accepts_under_yes(self, monkeypatch, capsys):
        manifest = self._base_manifest()
        manifest.are_skills_conflicting.return_value = True
        manifest.get_conflicting_resource_scope.return_value = ["global"]
        self._stub_main(monkeypatch, manifest)

        cmds: list = []
        monkeypatch.setattr(
            installer,
            "run",
            lambda cmd, **kw: cmds.append(cmd) or MagicMock(returncode=0),
        )

        installer.main()

        assert any(isinstance(c, list) and c[:3] == ["snyk", "mcp", "configure"] for c in cmds), (
            f"expected snyk mcp configure invocation, got {cmds}"
        )

    def test_extension_settings_conflict_auto_resolves_under_yes(self, monkeypatch, capsys):
        manifest = self._base_manifest()
        manifest.are_extension_settings_conflicting.return_value = ["/tmp/settings.json"]
        self._stub_main(monkeypatch, manifest)

        installer.main()

        manifest.resolve_extension_conflicts.assert_called_once_with(["/tmp/settings.json"])


class TestConflictResolutionPolicy:
    """Only workspace-scoped rule/skill conflicts prompt; global rules/skills and
    extension settings are auto-resolved with a warning."""

    @staticmethod
    def _args(yes=False):
        return MagicMock(
            list_mode=False,
            yes=yes,
            dry_run=False,
            control_identifier=None,
            uninstall=False,
            verify=False,
            diag_dump=False,
            ade=None,
            profile="default",
            workspace=None,
            no_latest_deps=False,
            cli_path=None,
            recipes=None,
        )

    @staticmethod
    def _base_manifest():
        m = MagicMock()
        # Non-empty and ADE-scoped: main() aborts on an empty resolution and on a
        # workspace-only one with no workspace, neither of which these tests exercise.
        m.resolve_recipes.return_value = ["mcp-config"]
        m.detect_stale_conflicts.return_value = []
        m.are_extension_settings_conflicting.return_value = []
        m.are_rules_conflicting.return_value = False
        m.are_skills_conflicting.return_value = False
        m.get_conflicting_resource_scope.return_value = []
        m.is_workspace_scoped.return_value = False
        m.is_git_global_scoped.return_value = False
        return m

    def _stub_main(self, monkeypatch, manifest, prompt_answers, ade="cursor"):
        monkeypatch.setattr(installer, "PayloadContext", lambda: MagicMock())
        monkeypatch.setattr(installer, "Manifest", lambda *a, **kw: manifest)
        monkeypatch.setattr(installer, "check_prerequisites", lambda *a, **kw: None)
        monkeypatch.setattr(installer, "_sync_selected_snyk_cli_sidecars", lambda *a, **kw: None)
        monkeypatch.setattr(installer, "get_target_ades", lambda *a, **kw: [ade])
        monkeypatch.setattr(installer, "resolve_workspace", lambda *a, **kw: None)
        monkeypatch.setattr(installer, "show_plan", lambda *a, **kw: None)
        monkeypatch.setattr(installer, "install_recipe", lambda *a, **kw: None)
        monkeypatch.setattr(installer, "install_workspace_recipe", lambda *a, **kw: None)
        monkeypatch.setattr(installer, "verify_recipe", lambda *a, **kw: True)
        monkeypatch.setattr(installer, "print_banner", lambda: None)
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

        self.prompts: list = []

        def fake_input(prompt=""):
            self.prompts.append(prompt)
            if "Proceed with installation" in prompt:
                return "y"
            return prompt_answers.pop(0) if prompt_answers else "n"

        monkeypatch.setattr("builtins.input", fake_input)

    def test_global_rule_conflict_auto_resolves_without_prompt(self, monkeypatch):
        manifest = self._base_manifest()
        manifest.are_rules_conflicting.return_value = True
        manifest.get_conflicting_resource_scope.return_value = ["global"]
        monkeypatch.setattr(installer, "parse_args", lambda: self._args(yes=False))
        self._stub_main(monkeypatch, manifest, prompt_answers=[])

        cmds: list = []
        monkeypatch.setattr(
            installer, "run", lambda cmd, **kw: cmds.append(cmd) or MagicMock(returncode=0)
        )

        installer.main()

        # No resolve prompt was shown for the global rule (only the install prompt).
        assert not any("remove the conflicting" in p for p in self.prompts)
        # It was auto-resolved.
        assert any(isinstance(c, list) and c[:3] == ["snyk", "mcp", "configure"] for c in cmds)

    def test_workspace_rule_conflict_prompts_and_resolves_on_accept(self, monkeypatch):
        manifest = self._base_manifest()
        manifest.are_rules_conflicting.return_value = True
        manifest.get_conflicting_resource_scope.return_value = ["workspace"]
        monkeypatch.setattr(installer, "parse_args", lambda: self._args(yes=False))
        self._stub_main(monkeypatch, manifest, prompt_answers=["y"])

        cmds: list = []
        monkeypatch.setattr(
            installer, "run", lambda cmd, **kw: cmds.append(cmd) or MagicMock(returncode=0)
        )

        installer.main()

        assert any("remove the conflicting workspace" in p for p in self.prompts)
        assert any(isinstance(c, list) and c[:3] == ["snyk", "mcp", "configure"] for c in cmds)

    def test_workspace_rule_conflict_declined_is_not_resolved(self, monkeypatch):
        manifest = self._base_manifest()
        manifest.are_rules_conflicting.return_value = True
        manifest.get_conflicting_resource_scope.return_value = ["workspace"]
        monkeypatch.setattr(installer, "parse_args", lambda: self._args(yes=False))
        self._stub_main(monkeypatch, manifest, prompt_answers=["n"])

        cmds: list = []
        monkeypatch.setattr(
            installer, "run", lambda cmd, **kw: cmds.append(cmd) or MagicMock(returncode=0)
        )

        installer.main()

        assert any("remove the conflicting workspace" in p for p in self.prompts)
        assert not cmds

    def test_extension_settings_auto_resolves_without_prompt(self, monkeypatch):
        manifest = self._base_manifest()
        manifest.are_extension_settings_conflicting.return_value = ["/tmp/settings.json"]
        monkeypatch.setattr(installer, "parse_args", lambda: self._args(yes=False))
        self._stub_main(monkeypatch, manifest, prompt_answers=[])

        installer.main()

        manifest.resolve_extension_conflicts.assert_called_once_with(["/tmp/settings.json"])
        assert not any("executionFrequency" in p for p in self.prompts)

    def test_extension_settings_no_success_message_when_update_fails(self, monkeypatch, capsys):
        manifest = self._base_manifest()
        manifest.are_extension_settings_conflicting.return_value = ["/tmp/settings.json"]
        # Resolution failed to update any file (e.g. write error) -> empty list.
        manifest.resolve_extension_conflicts.return_value = []
        monkeypatch.setattr(installer, "parse_args", lambda: self._args(yes=False))
        self._stub_main(monkeypatch, manifest, prompt_answers=[])

        installer.main()

        assert "Set executionFrequency to Manual" not in capsys.readouterr().out


# ===========================================================================
# TestMcpConfigSelection
# ===========================================================================


class TestMcpConfigSelection:
    @pytest.fixture
    def payload(self):
        ctx = installer.PayloadContext()
        ctx.setup()
        yield ctx
        ctx.cleanup()

    @pytest.fixture
    def manifest(self, payload):
        return installer.Manifest(payload.manifest_path)

    @staticmethod
    def _selection(path, source):
        return installer.SnykCliSelection(path, "1.1306.0", source)

    def _capture_install_source(self, monkeypatch):
        captured = {}

        def capture_merge(strategy, target, source, payload, dry_run):
            captured["strategy"] = strategy
            captured["name"] = source.name
            if source.name.endswith(".mcp-codex.toml"):
                captured["text"] = source.read_text(encoding="utf-8")
            else:
                captured["json"] = json.loads(source.read_text(encoding="utf-8"))

        monkeypatch.setattr(installer, "merge_config", capture_merge)
        monkeypatch.setattr(installer, "cleanup_legacy_config_merge", lambda *a, **kw: None)
        monkeypatch.setattr(installer, "chmod_python_files", lambda *a, **kw: None)
        return captured

    def test_install_recipe_npm_selection_uses_selected_mcp_command(
        self, monkeypatch, payload, manifest, tmp_path
    ):
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        captured = self._capture_install_source(monkeypatch)
        selected = self._selection("/tmp/npm/bin/snyk", installer.SNYK_CLI_SOURCE_NPM)

        installer.install_recipe(
            "mcp-config",
            "cursor",
            manifest,
            payload,
            dry_run=False,
            selected_snyk_cli=selected,
        )

        assert captured["json"]["mcpServers"]["Snyk"] == {
            "command": "/tmp/npm/bin/snyk",
            "args": ["mcp", "-t", "stdio"],
        }

    def test_install_recipe_user_specified_selection_uses_selected_mcp_command(
        self, monkeypatch, payload, manifest, tmp_path
    ):
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        captured = self._capture_install_source(monkeypatch)
        selected = self._selection(
            "/tmp/user/bin/snyk",
            installer.SNYK_CLI_SOURCE_USER_SPECIFIED,
        )

        installer.install_recipe(
            "mcp-config",
            "cursor",
            manifest,
            payload,
            dry_run=False,
            selected_snyk_cli=selected,
        )

        assert captured["json"]["mcpServers"]["Snyk"] == {
            "command": "/tmp/user/bin/snyk",
            "args": ["mcp", "-t", "stdio"],
        }

    def test_install_recipe_path_selection_uses_dynamic_snyk_command(
        self, monkeypatch, payload, manifest, tmp_path
    ):
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        captured = self._capture_install_source(monkeypatch)
        selected = self._selection("/usr/local/bin/snyk", installer.SNYK_CLI_SOURCE_PATH)

        installer.install_recipe(
            "mcp-config",
            "cursor",
            manifest,
            payload,
            dry_run=False,
            selected_snyk_cli=selected,
        )

        assert captured["json"]["mcpServers"]["Snyk"] == {
            "command": "snyk",
            "args": ["mcp", "-t", "stdio"],
        }

    def test_install_recipe_path_selection_mac_gui_uses_login_shell_snyk(
        self, monkeypatch, payload, manifest, tmp_path
    ):
        monkeypatch.setattr("sys.platform", "darwin")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        captured = self._capture_install_source(monkeypatch)
        selected = self._selection("/usr/local/bin/snyk", installer.SNYK_CLI_SOURCE_PATH)

        installer.install_recipe(
            "mcp-config",
            "cursor",
            manifest,
            payload,
            dry_run=False,
            selected_snyk_cli=selected,
        )

        assert captured["json"]["mcpServers"]["Snyk"] == {
            "command": "sh",
            "args": ["-l", "-c", "snyk mcp -t stdio"],
        }

    def test_install_recipe_codex_npm_selection_uses_selected_toml_command(
        self, monkeypatch, payload, manifest, tmp_path
    ):
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        captured = self._capture_install_source(monkeypatch)
        selected = self._selection("/tmp/npm/bin/snyk", installer.SNYK_CLI_SOURCE_NPM)

        installer.install_recipe(
            "mcp-config",
            "codex",
            manifest,
            payload,
            dry_run=False,
            selected_snyk_cli=selected,
        )

        assert 'command = "/tmp/npm/bin/snyk"' in captured["text"]
        assert 'args = ["mcp", "-t", "stdio"]' in captured["text"]

    def test_install_recipe_non_mcp_source_ignores_selected_snyk_cli(
        self, monkeypatch, payload, manifest, tmp_path
    ):
        """A non-MCP config_merge (e.g. sai-hooks-async's settings.json) must
        never be substituted for a Snyk command, even with a selection present."""
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        captured = {}

        def capture_merge(strategy, target, source, payload, dry_run):
            captured["source"] = source

        monkeypatch.setattr(installer, "merge_config", capture_merge)
        monkeypatch.setattr(installer, "cleanup_legacy_config_merge", lambda *a, **kw: None)
        monkeypatch.setattr(installer, "chmod_python_files", lambda *a, **kw: None)
        selected = self._selection("/tmp/npm/bin/snyk", installer.SNYK_CLI_SOURCE_NPM)

        cm = manifest.get_sources("sai-hooks-async", "claude")["config_merge"]
        expected_source = payload.resolve_src(cm["source"])

        installer.install_recipe(
            "sai-hooks-async",
            "claude",
            manifest,
            payload,
            dry_run=False,
            selected_snyk_cli=selected,
        )

        assert captured["source"] == expected_source

    def test_verify_recipe_npm_selection_checks_selected_mcp_command(
        self, monkeypatch, payload, manifest, tmp_path
    ):
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        selected = self._selection("/tmp/npm/bin/snyk", installer.SNYK_CLI_SOURCE_NPM)
        captured = {}

        import merge_json

        def verify_strategy(target, source):
            captured["source"] = json.loads(Path(source).read_text(encoding="utf-8"))

        monkeypatch.setitem(merge_json.STRATEGIES, "verify_mcp_servers", verify_strategy)

        @contextlib.contextmanager
        def mock_expand_source(strategy, source):
            yield source

        monkeypatch.setattr(installer, "_expand_source", mock_expand_source)

        assert installer.verify_recipe(
            "mcp-config",
            "cursor",
            manifest,
            payload,
            selected_snyk_cli=selected,
        )
        assert captured["source"]["mcpServers"]["Snyk"] == {
            "command": "/tmp/npm/bin/snyk",
            "args": ["mcp", "-t", "stdio"],
        }

    def test_install_recipe_mac_gui_ade_uses_mac_mcp(self, monkeypatch, payload, manifest):
        monkeypatch.setattr("sys.platform", "darwin")

        mock_merge = MagicMock()
        monkeypatch.setattr(installer, "merge_config", mock_merge)

        # Cursor is NOT in CLI_ADES
        installer.install_recipe("mcp-config", "cursor", manifest, payload, dry_run=False)

        # Check that merge_config was called with the mac source
        args, _ = mock_merge.call_args
        # args[2] is the source Path
        assert args[2].name == ".mcp.mac.json"

    def test_install_recipe_mac_cli_ade_uses_regular_mcp(self, monkeypatch, payload, manifest):
        monkeypatch.setattr("sys.platform", "darwin")

        mock_merge = MagicMock()
        monkeypatch.setattr(installer, "merge_config", mock_merge)

        # Claude IS in CLI_ADES
        installer.install_recipe("mcp-config", "claude", manifest, payload, dry_run=False)

        # Check that merge_config was called with the regular source
        args, _ = mock_merge.call_args
        assert args[2].name == ".mcp.json"

    def test_verify_recipe_mac_gui_ade_uses_mac_mcp(self, monkeypatch, payload, manifest, tmp_path):
        monkeypatch.setattr("sys.platform", "darwin")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        import merge_json

        mock_verify_strategy = MagicMock()
        monkeypatch.setitem(merge_json.STRATEGIES, "verify_mcp_servers", mock_verify_strategy)

        # Mock _expand_source to just return the path (skip $HOME expansion)
        @contextlib.contextmanager
        def mock_expand_source(strategy, source):
            yield source

        monkeypatch.setattr(installer, "_expand_source", mock_expand_source)

        installer.verify_recipe("mcp-config", "cursor", manifest, payload)

        args, _ = mock_verify_strategy.call_args
        # args[1] is the resolved_path string
        assert Path(args[1]).name == ".mcp.mac.json"

    def test_verify_recipe_mac_cli_ade_uses_regular_mcp(
        self, monkeypatch, payload, manifest, tmp_path
    ):
        monkeypatch.setattr("sys.platform", "darwin")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        import merge_json

        mock_verify_strategy = MagicMock()
        monkeypatch.setitem(merge_json.STRATEGIES, "verify_mcp_servers", mock_verify_strategy)

        # Mock _expand_source to just return the path
        @contextlib.contextmanager
        def mock_expand_source(strategy, source):
            yield source

        monkeypatch.setattr(installer, "_expand_source", mock_expand_source)

        installer.verify_recipe("mcp-config", "claude", manifest, payload)

        args, _ = mock_verify_strategy.call_args
        assert Path(args[1]).name == ".mcp.json"
