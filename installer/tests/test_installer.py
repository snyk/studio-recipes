"""Tests for snyk-studio-installer.py (cross-platform Python installer)."""

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


# ===========================================================================
# TestCheckPrerequisites
# ===========================================================================


class TestCheckPrerequisites:
    @pytest.fixture(autouse=True)
    def mock_node_installed(self, monkeypatch):
        monkeypatch.setattr(installer, "ensure_node_installed", lambda *_: True)

    def test_all_ok(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None
        )

        def mock_run(cmd, **kwargs):
            m = MagicMock()
            if cmd[0] == "snyk" and cmd[1] == "--version":
                m.stdout = "1.1302.0\n"
                m.returncode = 0
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        # Should not raise SystemExit
        installer.check_prerequisites(auto_yes=True)
        captured = capsys.readouterr()
        assert "OK Snyk CLI 1.1302.0" in captured.out

    def test_outdated_snyk_warning(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None
        )

        def mock_run(cmd, **kwargs):
            m = MagicMock()
            if cmd[0] == "snyk" and cmd[1] == "--version":
                m.stdout = "1.1301.0\n"
                m.returncode = 0
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        # With auto_yes=True, it should just print warning and continue
        installer.check_prerequisites(auto_yes=True, snyk_version="1.1302.0")
        captured = capsys.readouterr()
        assert "WARNING Snyk CLI 1.1301.0 is outdated" in captured.out

    def test_outdated_snyk_cancel(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None
        )

        def mock_run(cmd, **kwargs):
            m = MagicMock()
            if cmd[0] == "snyk" and cmd[1] == "--version":
                m.stdout = "1.1301.0\n"
                m.returncode = 0
            return m

        monkeypatch.setattr(installer, "run", mock_run)
        monkeypatch.setattr("builtins.input", lambda _: "n")

        with pytest.raises(SystemExit):
            installer.check_prerequisites(auto_yes=False, snyk_version="1.1302.0")

        captured = capsys.readouterr()
        assert "WARNING Snyk CLI 1.1301.0 is outdated" in captured.out

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

    def test_outdated_snyk_auto_upgrade(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None
        )
        monkeypatch.setattr("sys.platform", "linux")

        cmds_run = []

        def mock_run(cmd, **kwargs):
            cmds_run.append(cmd)
            m = MagicMock()
            if cmd[0] == "snyk" and cmd[1] == "--version":
                m.stdout = "1.1301.0\n"
                m.returncode = 0
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        installer.check_prerequisites(auto_yes=True, snyk_version="1.1302.0")

        # Verify that npm install was called
        assert ["npm", "install", "-g", "snyk@latest"] in cmds_run
        captured = capsys.readouterr()
        assert "WARNING Snyk CLI 1.1301.0 is outdated" in captured.out

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
            if cmd[0] == "snyk" and cmd[1] == "--version":
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
            if cmd[0] == "snyk" and cmd[1] == "--version":
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
            if cmd[0] == "snyk" and cmd[1] == "--version":
                m.stdout = "1.1302.0 (standalone)\n"
                m.returncode = 0
            return m

        monkeypatch.setattr(installer, "run", mock_run)

        installer.check_prerequisites(auto_yes=True)
        captured = capsys.readouterr()
        assert "OK Snyk CLI 1.1302.0 (standalone)" in captured.out
        assert "is outdated" not in captured.out

    def test_version_malformed_no_error(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/usr/local/bin/snyk" if cmd == "snyk" else None
        )

        def mock_run(cmd, **kwargs):
            m = MagicMock()
            if cmd[0] == "snyk" and cmd[1] == "--version":
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
            if cmd[:2] == ["snyk", "--version"]:
                raise FileNotFoundError(2, "No such file or directory", "snyk")
            cmds_run.append(cmd)
            return MagicMock(returncode=0)

        monkeypatch.setattr(installer, "run", mock_run)

        # Must not raise; falls through to (re)install Snyk.
        installer.check_prerequisites(auto_yes=True)
        assert ["npm", "install", "-g", "snyk"] in cmds_run
        assert "Snyk CLI not found" in capsys.readouterr().out


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
            if cmd[0] == "snyk" and cmd[1] == "--version":
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
        assert args.control_identifier == "machine-123"

    def test_no_latest_deps_explicit(self):
        args = installer.parse_args(["--no-latest-deps"])
        assert args.no_latest_deps is True

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
        monkeypatch.setattr(installer, "_npm_global_prefix_writable", lambda: True)
        assert installer.ensure_node_installed(auto_yes=True) is True

    def test_node_meets_minimum_no_warning(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/bin/cmd" if cmd in ("node", "npm") else None
        )
        monkeypatch.setattr(installer, "_npm_global_prefix_writable", lambda: True)
        monkeypatch.setattr(installer, "_get_node_version", lambda: (24, 12, 0))
        assert installer.ensure_node_installed(auto_yes=True, node_version="24.11.1") is True
        assert "is outdated" not in capsys.readouterr().out

    def test_outdated_node_warns_and_upgrades(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "shutil.which", lambda cmd: "/bin/cmd" if cmd in ("node", "npm", "brew") else None
        )
        monkeypatch.setattr(installer, "_npm_global_prefix_writable", lambda: True)
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
        monkeypatch.setattr(installer, "_npm_global_prefix_writable", lambda: True)
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
        monkeypatch.setattr(installer, "_npm_global_prefix_writable", lambda: True)
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
        monkeypatch.setattr(installer, "_npm_global_prefix_writable", lambda: True)
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
        monkeypatch.setattr(installer, "_npm_global_prefix_writable", lambda: True)
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
        monkeypatch.setattr(installer, "_npm_global_prefix_writable", lambda: False)

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

    def test_npm_global_prefix_writable_probes_npm_prefix(self, monkeypatch, tmp_path):
        """A writable prefix reported by `npm prefix -g` yields True; an exception yields True."""
        monkeypatch.setattr(
            installer, "run", lambda *a, **k: MagicMock(stdout=str(tmp_path) + "\n")
        )
        assert installer._npm_global_prefix_writable() is True

        def boom(*a, **k):
            raise RuntimeError("npm missing")

        monkeypatch.setattr(installer, "run", boom)
        assert installer._npm_global_prefix_writable() is True


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
        assert installer._should_gui_transform("merge_cursor_hooks") is True
        assert installer._should_gui_transform("unmerge_cursor_hooks") is True
        assert installer._should_gui_transform("merge_copilot_cli_hooks") is True
        assert installer._should_gui_transform("merge_mcp_servers") is False

    def test_expand_source_rewrites_uv_run_on_windows(self, monkeypatch, tmp_path):
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
        assert "uvw run --gui-script" in cmd
        assert "uv run" not in cmd.replace("uvw run", "")

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
        assert "snyk-fix-command" in recipes
        assert len(recipes) == 6

    def test_resolve_minimal_profile(self, manifest):
        recipes = manifest.resolve_recipes("minimal")
        assert "sai-hooks-async" in recipes
        assert "mcp-config" in recipes
        assert "snyk-fix-command" not in recipes

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
        # snyk-fix-skill is intentionally limited to command-less platforms (codex, copilot-cli)
        skill_only_recipes = {"snyk-fix-skill"}
        for recipe_id in manifest.resolve_recipes("default"):
            if recipe_id in skill_only_recipes:
                continue
            sources = manifest.get_sources(recipe_id, "gemini")
            assert sources, f"missing gemini sources for {recipe_id}"

    def test_kiro_sources_for_all_default_recipes_except_hooks(self, manifest):
        # snyk-fix-skill is intentionally limited to command-less platforms (codex, copilot-cli)
        skill_only_recipes = {"snyk-fix-skill"}
        for recipe_id in manifest.resolve_recipes("default"):
            if recipe_id in ("sai-hooks-async", *skill_only_recipes):
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
        # Codex CLI does not support user-defined slash commands.
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

    def test_get_conflicting_resource_scope(self, manifest):
        # cursor has 1 rule (workspace) and 1 skill (global) in manifest.json
        # "cursor" :{ "rules": [{"global": false, ...}], "skills": [{"global": true, ...}] }
        assert manifest.get_conflicting_resource_scope("cursor", "rules") == ["workspace"]
        assert manifest.get_conflicting_resource_scope("cursor", "skills") == ["global"]
        assert manifest.get_conflicting_resource_scope("nonexistent", "rules") == []


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

    def test_workspace_no_conflict_global_conflict(self, manifest, vscode_env):
        # Global has it enabled
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

        # Workspace has it explicitly disabled - this SHOULD NOT conflict as it overrides global.
        # Note: Both keys must be present for the installer to update its resolved settings.
        ws_dir = vscode_env["workspace_dir"]
        ws_dir.mkdir(parents=True)
        (ws_dir / "settings.json").write_text(
            json.dumps(
                {
                    "snyk.securityAtInception.autoConfigureSnykMcpServer": False,
                    "snyk.securityAtInception.executionFrequency": "On Code Generation",
                }
            )
        )

        assert not manifest.are_extension_settings_conflicting("cursor")

    def test_workspace_manual_frequency_is_no_conflict(self, manifest, vscode_env):
        ws_dir = vscode_env["workspace_dir"]
        ws_dir.mkdir(parents=True)
        (ws_dir / "settings.json").write_text(
            json.dumps(
                {
                    "snyk.securityAtInception.autoConfigureSnykMcpServer": True,
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

        manifest.resolve_extension_conflicts([str(settings_file)])

        # Check that settings were updated
        updated_data = json.loads(settings_file.read_text())
        assert updated_data["snyk.securityAtInception.autoConfigureSnykMcpServer"] is False
        assert updated_data["snyk.securityAtInception.executionFrequency"] == "Manual"
        assert updated_data["other.setting"] == "value"

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

    def test_resolve_extension_conflicts_write_error(self, manifest, tmp_path, capsys):
        # Setup a file that exists but we can't write to (mocking open failure)
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
        )

    def _stub_main(self, monkeypatch, manifest, ade="cursor"):
        monkeypatch.setattr(installer, "parse_args", lambda: self._args())
        monkeypatch.setattr(installer, "PayloadContext", lambda: MagicMock())
        monkeypatch.setattr(installer, "Manifest", lambda *a, **kw: manifest)
        monkeypatch.setattr(installer, "check_prerequisites", lambda *a, **kw: None)
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
        m.resolve_recipes.return_value = []
        m.detect_stale_conflicts.return_value = []
        m.are_extension_settings_conflicting.return_value = []
        m.are_rules_conflicting.return_value = False
        m.are_skills_conflicting.return_value = False
        m.is_workspace_scoped.return_value = False
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

        manifest.get_conflicting_resource_scope.assert_any_call("cursor", "rules")
        assert any(isinstance(c, list) and c[:3] == ["snyk", "mcp", "configure"] for c in cmds), (
            f"expected snyk mcp configure invocation, got {cmds}"
        )

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

        manifest.get_conflicting_resource_scope.assert_any_call("cursor", "skills")
        assert any(isinstance(c, list) and c[:3] == ["snyk", "mcp", "configure"] for c in cmds), (
            f"expected snyk mcp configure invocation, got {cmds}"
        )


# ===========================================================================
# TestMacMcpLogic
# ===========================================================================


class TestMacMcpLogic:
    @pytest.fixture
    def payload(self):
        ctx = installer.PayloadContext()
        ctx.setup()
        yield ctx
        ctx.cleanup()

    @pytest.fixture
    def manifest(self, payload):
        return installer.Manifest(payload.manifest_path)

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
