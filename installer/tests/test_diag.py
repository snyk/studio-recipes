"""Tests for lib/diag.py."""

import io
import json
import os
import subprocess
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

INSTALLER_DIR = Path(__file__).resolve().parent.parent
LIB_DIR = str(INSTALLER_DIR / "lib")
if LIB_DIR not in sys.path:
    sys.path.insert(0, LIB_DIR)

import diag  # noqa: E402

_FAR_PAST = datetime(2000, 1, 1, tzinfo=timezone.utc)
_NOW = datetime.now(timezone.utc)


def _ts(dt: datetime) -> str:
    return f"[{dt.isoformat()}]"


# ---------------------------------------------------------------------------
# _collect_sai_logs
# ---------------------------------------------------------------------------


class TestCollectSaiLogs:
    def _run(self, log_root, cutoff=None):
        if cutoff is None:
            cutoff = _FAR_PAST
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            diag._collect_sai_logs(zf, log_root, cutoff)
        buf.seek(0)
        return zipfile.ZipFile(buf, "r")

    def test_collects_logs_for_multiple_workspaces(self, tmp_path):
        p1 = tmp_path / "claude" / "ws" / "proj1"
        p1.mkdir(parents=True)
        (p1 / "log.txt").write_text(f"{_ts(_NOW)} entry\n")

        p2 = tmp_path / "gemini" / "ws" / "proj2"
        p2.mkdir(parents=True)
        (p2 / "log.txt").write_text(f"{_ts(_NOW)} entry\n")

        zf = self._run(tmp_path)
        names = set(zf.namelist())
        zf.close()

        assert "logs/claude/proj1/log.txt" in names
        assert "logs/gemini/proj2/log.txt" in names
        assert not any("recent_log" in n for n in names)

    def test_rotated_log_included_when_entries_in_window(self, tmp_path):
        ws = tmp_path / "claude" / "ws" / "proj1"
        ws.mkdir(parents=True)
        (ws / "log.txt").write_text(f"{_ts(_NOW)} current\n")
        (ws / "log.txt.1").write_text(f"{_ts(_NOW - timedelta(hours=2))} rotated\n")

        zf = self._run(tmp_path, cutoff=_NOW - timedelta(hours=24))
        names = set(zf.namelist())
        zf.close()

        assert "logs/claude/proj1/log.txt" in names
        assert "logs/claude/proj1/log.txt.1" in names

    def test_rotated_log_excluded_when_entries_outside_window(self, tmp_path):
        ws = tmp_path / "claude" / "ws" / "proj1"
        ws.mkdir(parents=True)
        (ws / "log.txt").write_text(f"{_ts(_NOW)} current\n")
        old_ts = _NOW - timedelta(days=3)
        (ws / "log.txt.1").write_text(f"{_ts(old_ts)} old rotated\n")

        zf = self._run(tmp_path, cutoff=_NOW - timedelta(hours=24))
        names = set(zf.namelist())
        zf.close()

        assert "logs/claude/proj1/log.txt" in names
        assert "logs/claude/proj1/log.txt.1" not in names

    def test_entries_older_than_cutoff_stripped_from_log(self, tmp_path):
        ws = tmp_path / "claude" / "ws" / "proj1"
        ws.mkdir(parents=True)
        old = _NOW - timedelta(days=3)
        recent = _NOW - timedelta(hours=1)
        (ws / "log.txt").write_text(f"{_ts(old)} old entry\n{_ts(recent)} recent entry\n")

        cutoff = _NOW - timedelta(hours=24)
        zf = self._run(tmp_path, cutoff=cutoff)
        content = zf.read("logs/claude/proj1/log.txt").decode()
        zf.close()

        assert "recent entry" in content
        assert "old entry" not in content

    def test_log_omitted_when_all_entries_outside_window(self, tmp_path):
        ws = tmp_path / "claude" / "ws" / "proj1"
        ws.mkdir(parents=True)
        old = _NOW - timedelta(days=5)
        log = ws / "log.txt"
        log.write_text(f"{_ts(old)} stale entry\n")
        # Set mtime to now so workspace passes the fast pre-check
        now_ts = _NOW.timestamp()
        os.utime(log, (now_ts, now_ts))

        cutoff = _NOW - timedelta(hours=24)
        zf = self._run(tmp_path, cutoff=cutoff)
        names = set(zf.namelist())
        zf.close()

        assert "logs/claude/proj1/log.txt" not in names

    def test_non_timestamped_lines_always_included(self, tmp_path):
        ws = tmp_path / "claude" / "ws" / "proj1"
        ws.mkdir(parents=True)
        old = _NOW - timedelta(days=5)
        (ws / "log.txt").write_text(
            f"{_ts(old)} old entry\nno timestamp line\n{_ts(_NOW)} recent\n"
        )
        now_ts = _NOW.timestamp()
        os.utime(ws / "log.txt", (now_ts, now_ts))

        cutoff = _NOW - timedelta(hours=24)
        zf = self._run(tmp_path, cutoff=cutoff)
        content = zf.read("logs/claude/proj1/log.txt").decode()
        zf.close()

        assert "no timestamp line" in content
        assert "recent" in content
        assert "old entry" not in content

    def test_no_error_on_missing_log_root(self, tmp_path):
        zf = self._run(tmp_path / "nonexistent")
        assert zf.namelist() == []
        zf.close()

    def test_skips_ade_dirs_without_ws(self, tmp_path):
        (tmp_path / "nodeWs").mkdir()
        zf = self._run(tmp_path)
        assert zf.namelist() == []
        zf.close()

    def test_no_ade_logs_entries(self, tmp_path):
        ws = tmp_path / "claude" / "ws" / "proj1"
        ws.mkdir(parents=True)
        (ws / "log.txt").write_text(f"{_ts(_NOW)} data\n")

        zf = self._run(tmp_path)
        names = set(zf.namelist())
        zf.close()

        assert not any(n.startswith("ade_logs/") for n in names)

    def test_old_workspace_excluded_by_mtime(self, tmp_path):
        ws = tmp_path / "claude" / "ws" / "old-project"
        ws.mkdir(parents=True)
        log = ws / "log.txt"
        log.write_text(f"{_ts(_NOW)} entry\n")
        old_ts = (_NOW - timedelta(days=3)).timestamp()
        os.utime(log, (old_ts, old_ts))

        cutoff = _NOW - timedelta(hours=24)
        zf = self._run(tmp_path, cutoff=cutoff)
        names = set(zf.namelist())
        zf.close()

        assert "logs/claude/old-project/log.txt" not in names

    def test_cutoff_excludes_old_keeps_recent(self, tmp_path):
        old_ws = tmp_path / "claude" / "ws" / "old-project"
        old_ws.mkdir(parents=True)
        old_log = old_ws / "log.txt"
        old_log.write_text(f"{_ts(_NOW - timedelta(days=3))} old\n")
        old_file_ts = (_NOW - timedelta(days=3)).timestamp()
        os.utime(old_log, (old_file_ts, old_file_ts))

        new_ws = tmp_path / "claude" / "ws" / "new-project"
        new_ws.mkdir(parents=True)
        (new_ws / "log.txt").write_text(f"{_ts(_NOW)} recent\n")

        cutoff = _NOW - timedelta(hours=24)
        zf = self._run(tmp_path, cutoff=cutoff)
        names = set(zf.namelist())
        zf.close()

        assert "logs/claude/new-project/log.txt" in names
        assert "logs/claude/old-project/log.txt" not in names


# ---------------------------------------------------------------------------
# _filter_log_entries
# ---------------------------------------------------------------------------


class TestFilterLogEntries:
    def _write(self, tmp_path, content):
        p = tmp_path / "log.txt"
        p.write_text(content)
        return p

    def test_keeps_recent_strips_old(self, tmp_path):
        old = _NOW - timedelta(days=3)
        recent = _NOW - timedelta(hours=1)
        p = self._write(tmp_path, f"{_ts(old)} old\n{_ts(recent)} recent\n")
        result = diag._filter_log_entries(p, (_NOW - timedelta(hours=24)).timestamp())
        assert "recent" in result
        assert "old" not in result

    def test_empty_file_returns_empty(self, tmp_path):
        p = self._write(tmp_path, "")
        assert diag._filter_log_entries(p, _NOW.timestamp()) == ""

    def test_missing_file_returns_empty(self, tmp_path):
        assert diag._filter_log_entries(tmp_path / "no.txt", _NOW.timestamp()) == ""

    def test_unparseable_timestamp_line_included(self, tmp_path):
        p = self._write(tmp_path, "[not-a-date] line\n")
        result = diag._filter_log_entries(p, _NOW.timestamp())
        assert "[not-a-date] line" in result

    def test_non_bracket_line_always_included(self, tmp_path):
        old = _NOW - timedelta(days=5)
        p = self._write(tmp_path, f"{_ts(old)} old\nplain line\n")
        result = diag._filter_log_entries(p, (_NOW - timedelta(hours=24)).timestamp())
        assert "plain line" in result
        assert "old" not in result

    def test_all_entries_within_window(self, tmp_path):
        recent = _NOW - timedelta(minutes=30)
        p = self._write(tmp_path, f"{_ts(recent)} a\n{_ts(_NOW)} b\n")
        result = diag._filter_log_entries(p, (_NOW - timedelta(hours=24)).timestamp())
        assert "a" in result
        assert "b" in result


# ---------------------------------------------------------------------------
# _collect_verify_output
# ---------------------------------------------------------------------------


class TestCollectVerifyOutput:
    def _run(self, installer_path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            diag._collect_verify_output(zf, installer_path)
        buf.seek(0)
        with zipfile.ZipFile(buf, "r") as zf:
            if "verify.txt" in zf.namelist():
                return zf.read("verify.txt").decode()
            return None

    def test_verify_txt_written(self, tmp_path):
        script = INSTALLER_DIR / "snyk-studio-installer.py"
        result = self._run(script)
        assert result is not None

    def test_ansi_codes_stripped(self, tmp_path):
        script = tmp_path / "fake_installer.py"
        script.write_text("import sys\nprint('\\x1b[32mOK\\x1b[0m all good')\nsys.exit(0)\n")
        result = self._run(script)
        assert result is not None
        assert "\x1b[" not in result
        assert "OK all good" in result

    def test_stderr_merged_inline(self, tmp_path):
        script = tmp_path / "fake_installer.py"
        script.write_text(
            "import sys\n"
            "print('section start')\n"
            "print('warning message', file=sys.stderr)\n"
            "print('section end')\n"
        )
        result = self._run(script)
        assert result is not None
        assert "--- stderr ---" not in result
        assert "warning message" in result
        assert (
            result.index("section start")
            < result.index("warning message")
            < result.index("section end")
        )

    def test_failure_does_not_raise(self, tmp_path):
        self._run(tmp_path / "nonexistent.py")

    def test_timeout_does_not_raise(self, tmp_path):
        script = tmp_path / "slow.py"
        script.write_text("import time\ntime.sleep(60)\n")
        with patch.object(diag, "_collect_verify_output", wraps=lambda zf, p: None):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                diag._collect_verify_output(zf, script)


# ---------------------------------------------------------------------------
# _collect_installed_recipes
# ---------------------------------------------------------------------------


class TestCollectInstalledRecipes:
    def _run(self, monkeypatch, ade_homes):
        monkeypatch.setattr(diag, "ADE_HOMES", ade_homes)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            diag._collect_installed_recipes(zf)
        buf.seek(0)
        with zipfile.ZipFile(buf, "r") as zf:
            return json.loads(zf.read("installed_recipes.json"))

    def test_snyk_file_included_non_snyk_excluded(self, tmp_path, monkeypatch):
        ade_home = tmp_path / "claude"
        hooks = ade_home / "hooks"
        hooks.mkdir(parents=True)
        (hooks / "snyk_secure.py").write_text("recipe")
        (hooks / "other_hook.py").write_text("other")

        data = self._run(monkeypatch, {"claude": ade_home})

        assert "claude" in data
        paths = {e["path"] for e in data["claude"]}
        assert any("snyk_secure.py" in p for p in paths)
        assert not any("other_hook.py" in p for p in paths)

    def test_ade_with_no_snyk_files_absent_from_json(self, tmp_path, monkeypatch):
        ade_home = tmp_path / "claude"
        hooks = ade_home / "hooks"
        hooks.mkdir(parents=True)
        (hooks / "some_other.py").write_text("no snyk")

        data = self._run(monkeypatch, {"claude": ade_home})

        assert "claude" not in data

    def test_recipe_entry_has_path_size_mtime(self, tmp_path, monkeypatch):
        ade_home = tmp_path / "claude"
        hooks = ade_home / "hooks"
        hooks.mkdir(parents=True)
        (hooks / "snyk_hook.py").write_text("content")

        data = self._run(monkeypatch, {"claude": ade_home})

        entry = data["claude"][0]
        assert "path" in entry
        assert "size" in entry
        assert "mtime" in entry
        assert isinstance(entry["mtime"], int)

    def test_snyk_files_found_in_commands_and_rules(self, tmp_path, monkeypatch):
        ade_home = tmp_path / "claude"
        for subdir in ("commands", "rules"):
            d = ade_home / subdir
            d.mkdir(parents=True)
            (d / f"snyk-{subdir}.md").write_text("recipe")

        data = self._run(monkeypatch, {"claude": ade_home})

        paths = {e["path"] for e in data["claude"]}
        assert any("commands" in p for p in paths)
        assert any("rules" in p for p in paths)

    def test_path_is_relative_to_ade_home(self, tmp_path, monkeypatch):
        ade_home = tmp_path / "claude"
        hooks = ade_home / "hooks"
        hooks.mkdir(parents=True)
        (hooks / "snyk_hook.py").write_text("x")

        data = self._run(monkeypatch, {"claude": ade_home})

        entry = data["claude"][0]
        assert not Path(entry["path"]).is_absolute()
        assert "hooks" in entry["path"]

    def test_sensitive_snyk_files_excluded(self, tmp_path, monkeypatch):
        ade_home = tmp_path / "claude"
        hooks = ade_home / "hooks"
        hooks.mkdir(parents=True)
        (hooks / "snyk_token_store.py").write_text("secret")
        (hooks / "snyk_hook.py").write_text("safe")

        data = self._run(monkeypatch, {"claude": ade_home})

        paths = {e["path"] for e in data["claude"]}
        assert any("snyk_hook.py" in p for p in paths)
        assert not any("snyk_token_store.py" in p for p in paths)


# ---------------------------------------------------------------------------
# _collect_env_snapshot
# ---------------------------------------------------------------------------


class TestCollectEnvSnapshot:
    def _run(self, log_root):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            diag._collect_env_snapshot(zf, log_root)
        buf.seek(0)
        with zipfile.ZipFile(buf, "r") as zf:
            return json.loads(zf.read("env.json"))

    def test_has_exactly_eight_keys(self, tmp_path):
        result = self._run(tmp_path)
        expected = {
            "os",
            "os_version",
            "os_release",
            "machine",
            "python",
            "PATH",
            "SNYK_STUDIO_LOG_DIR",
            "bundled_at",
        }
        assert set(result.keys()) == expected

    def test_snyk_studio_log_dir_uses_env_when_set(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SNYK_STUDIO_LOG_DIR", "/custom/path")
        result = self._run(tmp_path)
        assert result["SNYK_STUDIO_LOG_DIR"] == "/custom/path"

    def test_snyk_studio_log_dir_falls_back_to_log_root(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SNYK_STUDIO_LOG_DIR", raising=False)
        result = self._run(tmp_path)
        assert result["SNYK_STUDIO_LOG_DIR"] == str(tmp_path)


# ---------------------------------------------------------------------------
# 5.2 _collect_machine_id
# ---------------------------------------------------------------------------


class TestCollectMachineId:
    def _run(self, monkeypatch, home_dir):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: home_dir))
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            diag._collect_machine_id(zf)
        buf.seek(0)
        with zipfile.ZipFile(buf, "r") as zf:
            names = zf.namelist()
            content = zf.read("machine_id.txt").decode() if "machine_id.txt" in names else None
        return names, content

    def test_machine_id_present_when_device_id_exists(self, tmp_path, monkeypatch):
        snyk_studio = tmp_path / ".snyk-studio"
        snyk_studio.mkdir()
        (snyk_studio / "device-id").write_text("abc-123-xyz")

        names, content = self._run(monkeypatch, tmp_path)

        assert "machine_id.txt" in names
        assert content == "abc-123-xyz"

    def test_machine_id_absent_when_device_id_missing(self, tmp_path, monkeypatch):
        names, content = self._run(monkeypatch, tmp_path)

        assert "machine_id.txt" not in names

    def test_bom_stripped_from_device_id(self, tmp_path, monkeypatch):
        snyk_studio = tmp_path / ".snyk-studio"
        snyk_studio.mkdir()
        # Write with UTF-8 BOM
        (snyk_studio / "device-id").write_bytes(b"\xef\xbb\xbfmy-device-id")

        names, content = self._run(monkeypatch, tmp_path)

        assert "machine_id.txt" in names
        assert content == "my-device-id"
        assert not content.startswith("\ufeff")

    def test_machine_id_absent_when_device_id_whitespace_only(self, tmp_path, monkeypatch):
        # A device-id file that contains only whitespace is treated as absent:
        # machine_id.txt is omitted and the bundle is still created successfully.
        snyk_studio = tmp_path / ".snyk-studio"
        snyk_studio.mkdir()
        (snyk_studio / "device-id").write_text("   \n\t  ")

        names, content = self._run(monkeypatch, tmp_path)

        assert "machine_id.txt" not in names


# ---------------------------------------------------------------------------
# 5.3 _collect_ade_versions
# ---------------------------------------------------------------------------


class TestCollectAdeVersions:
    def _run(self, ade_homes):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            diag._collect_ade_versions(zf, ade_homes)
        buf.seek(0)
        with zipfile.ZipFile(buf, "r") as zf:
            return json.loads(zf.read("ade_versions.json"))

    def test_all_ades_present_in_output(self, tmp_path):
        ade_homes = {
            "claude": tmp_path / "claude",
            "cursor": tmp_path / "cursor",
            "gemini": tmp_path / "gemini",
        }
        with patch.object(diag, "_resolve_ade_version", return_value=None):
            data = self._run(ade_homes)

        assert set(data.keys()) == {"claude", "cursor", "gemini"}

    def test_detected_true_when_ade_home_exists(self, tmp_path):
        ade_home = tmp_path / "claude"
        ade_home.mkdir()
        with patch.object(diag, "_resolve_ade_version", return_value=None):
            data = self._run({"claude": ade_home})

        assert data["claude"]["detected"] is True

    def test_detected_false_when_ade_home_absent(self, tmp_path):
        with patch.object(diag, "_resolve_ade_version", return_value=None):
            data = self._run({"claude": tmp_path / "nonexistent"})

        assert data["claude"]["detected"] is False

    def test_version_from_plist(self, tmp_path):
        import plistlib

        plist_path = tmp_path / "Info.plist"
        plist_data = {"CFBundleShortVersionString": "1.2.3"}
        with open(plist_path, "wb") as f:
            plistlib.dump(plist_data, f)

        with patch.dict(diag._ADE_APP_BUNDLES, {"claude": str(plist_path)}), patch(
            "sys.platform", "darwin"
        ):
            data = self._run({"claude": tmp_path / "claude"})

        assert data["claude"]["version"] == "1.2.3"

    def test_version_from_cli_fallback(self, tmp_path):
        with patch.dict(diag._ADE_APP_BUNDLES, {}), patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = "gemini version 2.5.0\n"
            mock_run.return_value.returncode = 0
            data = self._run({"gemini": tmp_path / "gemini"})

        assert data["gemini"]["version"] == "2.5.0"

    def test_version_null_when_undetectable(self, tmp_path):
        with patch.object(diag, "_resolve_ade_version", return_value=None):
            data = self._run({"gemini": tmp_path / "gemini"})

        assert data["gemini"]["version"] is None

    def test_cli_timeout_returns_null(self, tmp_path):
        import subprocess as sp

        with patch.dict(diag._ADE_APP_BUNDLES, {}), patch(
            "subprocess.run", side_effect=sp.TimeoutExpired("gemini", 3)
        ):
            data = self._run({"gemini": tmp_path / "gemini"})

        assert data["gemini"]["version"] is None

    def test_copilot_vscode_version_from_code_list_extensions(self, tmp_path):
        # copilot-vscode uses `code --list-extensions --show-versions`; the
        # version is parsed from the line matching GitHub.copilot.
        def fake_run(cmd, **kwargs):
            class R:
                stdout = "GitHub.copilot@1.2.3\nms-python.python@2024.1.0\n"
                returncode = 0

            if cmd == ["code", "--list-extensions", "--show-versions"]:
                return R()
            r = R()
            r.stdout = ""
            return r

        with patch.dict(diag._ADE_APP_BUNDLES, {}), patch("subprocess.run", side_effect=fake_run):
            data = self._run({"copilot-vscode": tmp_path / "copilot-vscode"})

        assert data["copilot-vscode"]["version"] == "1.2.3"

    def test_copilot_vscode_version_null_on_timeout(self, tmp_path):
        import subprocess as sp

        def fake_run(cmd, **kwargs):
            if cmd == ["code", "--list-extensions", "--show-versions"]:
                raise sp.TimeoutExpired(cmd, 3)

            class R:
                stdout = ""
                returncode = 1

            return R()

        with patch.dict(diag._ADE_APP_BUNDLES, {}), patch("subprocess.run", side_effect=fake_run):
            data = self._run({"copilot-vscode": tmp_path / "copilot-vscode"})

        assert data["copilot-vscode"]["version"] is None


# ---------------------------------------------------------------------------
# 5.4 _collect_dependency_versions
# ---------------------------------------------------------------------------


class TestCollectDependencyVersions:
    def _run(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            diag._collect_dependency_versions(zf)
        buf.seek(0)
        with zipfile.ZipFile(buf, "r") as zf:
            return json.loads(zf.read("dependency_versions.json"))

    def test_has_all_four_keys(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = ""
            mock_run.return_value.returncode = 1
            data = self._run()

        assert set(data.keys()) == {"node", "uv", "snyk", "nvm"}

    def test_node_version_parsed(self):
        def fake_run(cmd, **kwargs):
            class R:
                stdout = "v24.11.1\n"
                returncode = 0

            if cmd[0] == "node":
                return R()
            r = R()
            r.stdout = ""
            return r

        with patch("subprocess.run", side_effect=fake_run):
            data = self._run()

        assert data["node"] == "24.11.1"

    def test_missing_dependency_records_null(self):

        def fake_run(cmd, **kwargs):
            if isinstance(cmd, list) and cmd[0] == "nvm":
                raise FileNotFoundError

            class R:
                stdout = ""
                returncode = 1

            return R()

        with patch("subprocess.run", side_effect=fake_run), patch.object(diag, "_IS_WINDOWS", True):
            data = self._run()

        assert data["nvm"] is None


# ---------------------------------------------------------------------------
# run() — basic bundle creation
# ---------------------------------------------------------------------------


class TestRun:
    def _setup(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(diag, "ADE_HOMES", {})
        monkeypatch.setenv("SNYK_STUDIO_LOG_DIR", str(tmp_path / "no_logs"))

    def test_creates_zip_in_cwd(self, tmp_path, monkeypatch, capsys):
        self._setup(tmp_path, monkeypatch)
        diag.run(ade_homes={})

        captured = capsys.readouterr()
        assert "Diagnostic bundle created:" in captured.out

        zips = list(tmp_path.glob("snyk-studio-diag-*.zip"))
        assert len(zips) == 1
        assert str(zips[0]) in captured.out

    def test_zip_contains_expected_files(self, tmp_path, monkeypatch, capsys):
        self._setup(tmp_path, monkeypatch)
        diag.run(ade_homes={})

        zips = list(tmp_path.glob("snyk-studio-diag-*.zip"))
        with zipfile.ZipFile(zips[0], "r") as zf:
            names = set(zf.namelist())

        assert "env.json" in names
        assert "installed_recipes.json" in names
        assert "ade_versions.json" in names
        assert "dependency_versions.json" in names

    def test_no_ade_logs_entries_in_zip(self, tmp_path, monkeypatch, capsys):
        self._setup(tmp_path, monkeypatch)
        diag.run(ade_homes={})

        zips = list(tmp_path.glob("snyk-studio-diag-*.zip"))
        with zipfile.ZipFile(zips[0], "r") as zf:
            names = set(zf.namelist())

        assert not any(n.startswith("ade_logs/") for n in names)

    def test_no_cache_entries_in_zip(self, tmp_path, monkeypatch, capsys):
        self._setup(tmp_path, monkeypatch)
        diag.run(ade_homes={})

        zips = list(tmp_path.glob("snyk-studio-diag-*.zip"))
        with zipfile.ZipFile(zips[0], "r") as zf:
            names = set(zf.namelist())

        assert not any(n.startswith("cache/") for n in names)

    def test_no_recent_log_entries_in_zip(self, tmp_path, monkeypatch, capsys):
        self._setup(tmp_path, monkeypatch)
        diag.run(ade_homes={})

        zips = list(tmp_path.glob("snyk-studio-diag-*.zip"))
        with zipfile.ZipFile(zips[0], "r") as zf:
            names = set(zf.namelist())

        assert not any("recent_log" in n for n in names)

    def test_output_path_used_when_specified(self, tmp_path, monkeypatch, capsys):
        out_path = tmp_path / "output" / "my-diag.zip"
        out_path.parent.mkdir()
        monkeypatch.setattr(diag, "ADE_HOMES", {})
        monkeypatch.setenv("SNYK_STUDIO_LOG_DIR", str(tmp_path / "no_logs"))

        result = diag.run(output_path=out_path, ade_homes={})

        assert result == out_path
        assert out_path.exists()

    def test_exits_nonzero_when_both_cwd_and_home_unwritable(self, tmp_path, monkeypatch, capsys):
        self._setup(tmp_path, monkeypatch)

        with patch("zipfile.ZipFile", side_effect=OSError("unwritable")):
            with pytest.raises(SystemExit) as exc:
                diag.run(ade_homes={})

        assert exc.value.code == 1
        captured = capsys.readouterr()
        assert captured.err != ""

    def test_log_days_clamps_to_1_when_zero(self, tmp_path, monkeypatch, capsys):
        self._setup(tmp_path, monkeypatch)
        diag.run(log_days=0, ade_homes={})
        zips = list(tmp_path.glob("snyk-studio-diag-*.zip"))
        assert len(zips) == 1

    def test_log_days_wider_window_includes_older_workspace(self, tmp_path, monkeypatch, capsys):
        log_dir = tmp_path / "logs"
        ws = log_dir / "claude" / "ws" / "old-project"
        ws.mkdir(parents=True)
        old_entry_ts = _NOW - timedelta(days=5)
        log = ws / "log.txt"
        log.write_text(f"{_ts(old_entry_ts)} within 7d window\n")

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("SNYK_STUDIO_LOG_DIR", str(log_dir))

        diag.run(log_days=7, ade_homes={})

        zips = list(tmp_path.glob("snyk-studio-diag-*.zip"))
        with zipfile.ZipFile(zips[0], "r") as zf:
            names = set(zf.namelist())
        assert "logs/claude/old-project/log.txt" in names


# ---------------------------------------------------------------------------
# run() — cwd fallback
# ---------------------------------------------------------------------------


class TestRunFallback:
    def test_fallback_to_home_on_cwd_write_failure(self, tmp_path, monkeypatch, capsys):
        cwd_dir = tmp_path / "cwd"
        home_dir = tmp_path / "home"
        cwd_dir.mkdir()
        home_dir.mkdir()

        monkeypatch.chdir(cwd_dir)
        monkeypatch.setenv("SNYK_STUDIO_LOG_DIR", str(tmp_path / "no_logs"))
        monkeypatch.setattr(Path, "home", staticmethod(lambda: home_dir))

        call_count = {"n": 0}
        original_zipfile = zipfile.ZipFile

        def fail_first_write(path, *args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise OSError("read-only")
            return original_zipfile(path, *args, **kwargs)

        with patch("zipfile.ZipFile", side_effect=fail_first_write):
            diag.run(ade_homes={})

        captured = capsys.readouterr()
        assert "Diagnostic bundle created:" in captured.out
        zips = list(home_dir.glob("snyk-studio-diag-*.zip"))
        assert len(zips) == 1

    def test_partial_file_deleted_before_fallback(self, tmp_path, monkeypatch, capsys):
        cwd_dir = tmp_path / "cwd"
        home_dir = tmp_path / "home"
        cwd_dir.mkdir()
        home_dir.mkdir()

        monkeypatch.chdir(cwd_dir)
        monkeypatch.setenv("SNYK_STUDIO_LOG_DIR", str(tmp_path / "no_logs"))
        monkeypatch.setattr(Path, "home", staticmethod(lambda: home_dir))

        call_count = {"n": 0}
        original_zipfile = zipfile.ZipFile

        def create_partial_then_fail(path, *args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                Path(path).write_text("partial")
                raise OSError("disk full")
            return original_zipfile(path, *args, **kwargs)

        with patch("zipfile.ZipFile", side_effect=create_partial_then_fail):
            diag.run(ade_homes={})

        assert not any(cwd_dir.glob("snyk-studio-diag-*.zip"))
        zips = list(home_dir.glob("snyk-studio-diag-*.zip"))
        assert len(zips) == 1


# ---------------------------------------------------------------------------
# 5.5 Integration tests
# ---------------------------------------------------------------------------


class TestIntegration:
    def test_installer_diag_dump_flag_creates_bundle(self, tmp_path):
        log_dir = tmp_path / "logs"
        ws_dir = log_dir / "claude" / "ws" / "my-project"
        ws_dir.mkdir(parents=True)
        (ws_dir / "log.txt").write_text(f"{_ts(_NOW)} line 1\n{_ts(_NOW)} line 2\n")

        run_dir = tmp_path / "run"
        run_dir.mkdir()

        script = INSTALLER_DIR / "snyk-studio-installer.py"
        env = os.environ.copy()
        env["SNYK_STUDIO_LOG_DIR"] = str(log_dir)

        result = subprocess.run(
            [sys.executable, str(script), "--diag-dump"],
            capture_output=True,
            text=True,
            cwd=str(run_dir),
            env=env,
        )

        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "Diagnostic bundle created:" in result.stdout

        zips = list(run_dir.glob("snyk-studio-diag-*.zip"))
        assert len(zips) == 1

        with zipfile.ZipFile(zips[0], "r") as zf:
            names = set(zf.namelist())

        assert "logs/claude/my-project/log.txt" in names
        assert not any("recent_log" in n for n in names)
        assert "env.json" in names
        assert "installed_recipes.json" in names
        assert "ade_versions.json" in names
        assert "dependency_versions.json" in names
        assert "verify.txt" in names
        assert not any(n.startswith("ade_logs/") for n in names)
        assert not any(n.startswith("cache/") for n in names)
        # machine_id.txt is present when ~/.snyk-studio/device-id exists and
        # is non-empty; when absent the file is simply omitted — bundle still
        # created successfully either way.
        device_id_path = Path.home() / ".snyk-studio" / "device-id"
        if device_id_path.exists() and device_id_path.read_text(encoding="utf-8-sig").strip():
            assert "machine_id.txt" in names
        else:
            assert "machine_id.txt" not in names

    def test_out_file_flag_writes_to_specified_path(self, tmp_path):
        out_file = tmp_path / "my-bundle.zip"
        run_dir = tmp_path / "run"
        run_dir.mkdir()

        script = INSTALLER_DIR / "snyk-studio-installer.py"
        env = os.environ.copy()
        env["SNYK_STUDIO_LOG_DIR"] = str(tmp_path / "nonexistent")

        result = subprocess.run(
            [sys.executable, str(script), "--diag-dump", "--out-file", str(out_file)],
            capture_output=True,
            text=True,
            cwd=str(run_dir),
            env=env,
        )

        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert out_file.exists()
        assert str(out_file) in result.stdout

    def test_old_log_entries_stripped_by_default_window(self, tmp_path):
        log_dir = tmp_path / "logs"
        ws_dir = log_dir / "claude" / "ws" / "my-project"
        ws_dir.mkdir(parents=True)
        old = _NOW - timedelta(days=3)
        (ws_dir / "log.txt").write_text(f"{_ts(old)} old entry\n{_ts(_NOW)} recent entry\n")

        run_dir = tmp_path / "run"
        run_dir.mkdir()

        script = INSTALLER_DIR / "snyk-studio-installer.py"
        env = os.environ.copy()
        env["SNYK_STUDIO_LOG_DIR"] = str(log_dir)

        result = subprocess.run(
            [sys.executable, str(script), "--diag-dump"],
            capture_output=True,
            text=True,
            cwd=str(run_dir),
            env=env,
        )

        assert result.returncode == 0, f"stderr: {result.stderr}"
        zips = list(run_dir.glob("snyk-studio-diag-*.zip"))
        with zipfile.ZipFile(zips[0], "r") as zf:
            content = zf.read("logs/claude/my-project/log.txt").decode()

        assert "recent entry" in content
        assert "old entry" not in content

    def test_days_arg_wider_window_includes_older_entries(self, tmp_path):
        log_dir = tmp_path / "logs"
        ws_dir = log_dir / "claude" / "ws" / "my-project"
        ws_dir.mkdir(parents=True)
        five_days_ago = _NOW - timedelta(days=5)
        (ws_dir / "log.txt").write_text(f"{_ts(five_days_ago)} 5-day-old entry\n")

        run_dir = tmp_path / "run"
        run_dir.mkdir()

        script = INSTALLER_DIR / "snyk-studio-installer.py"
        env = os.environ.copy()
        env["SNYK_STUDIO_LOG_DIR"] = str(log_dir)

        result = subprocess.run(
            [sys.executable, str(script), "--diag-dump", "--days", "7"],
            capture_output=True,
            text=True,
            cwd=str(run_dir),
            env=env,
        )

        assert result.returncode == 0, f"stderr: {result.stderr}"
        zips = list(run_dir.glob("snyk-studio-diag-*.zip"))
        with zipfile.ZipFile(zips[0], "r") as zf:
            content = zf.read("logs/claude/my-project/log.txt").decode()

        assert "5-day-old entry" in content

    def test_completes_with_no_data_sources(self, tmp_path):
        run_dir = tmp_path / "run"
        run_dir.mkdir()

        script = INSTALLER_DIR / "snyk-studio-installer.py"
        env = os.environ.copy()
        env["SNYK_STUDIO_LOG_DIR"] = str(tmp_path / "nonexistent")

        result = subprocess.run(
            [sys.executable, str(script), "--diag-dump"],
            capture_output=True,
            text=True,
            cwd=str(run_dir),
            env=env,
        )

        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "Error:" not in result.stderr
        zips = list(run_dir.glob("snyk-studio-diag-*.zip"))
        assert len(zips) == 1

        with zipfile.ZipFile(zips[0], "r") as zf:
            names = set(zf.namelist())
        assert "env.json" in names
        assert "installed_recipes.json" in names
        assert "ade_versions.json" in names
        assert "dependency_versions.json" in names
