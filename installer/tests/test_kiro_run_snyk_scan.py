"""Snyk CLI selection for Kiro's legacy git-hook scanner wrapper."""

import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "guardrail_directives"
    / "secure_at_inception"
    / "kiro_hooks"
    / "git"
    / "lib"
    / "run_snyk_scan.py"
)


@pytest.fixture
def kiro_snyk():
    spec = importlib.util.spec_from_file_location("kiro_run_snyk_scan_under_test", MODULE_PATH)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _make_executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _write_sidecar(home: Path, cli_path: Path) -> None:
    sidecar = home / ".snyk-studio" / "cli-path"
    sidecar.parent.mkdir(parents=True)
    sidecar.write_text(str(cli_path), encoding="utf-8")


def test_check_snyk_cli_prefers_sidecar_over_path(kiro_snyk, monkeypatch, tmp_path):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    pinned = _make_executable(tmp_path / "pin" / "snyk")
    path_cli = _make_executable(tmp_path / "path" / "snyk")
    _write_sidecar(home, pinned)
    monkeypatch.setattr(
        kiro_snyk.shutil,
        "which",
        lambda cmd: str(path_cli) if cmd == "snyk" else None,
    )

    assert kiro_snyk.check_snyk_cli() == str(pinned)


def test_check_snyk_cli_falls_back_to_path_when_unpinned(kiro_snyk, monkeypatch, tmp_path):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    path_cli = _make_executable(tmp_path / "path" / "snyk")
    monkeypatch.setattr(
        kiro_snyk.shutil,
        "which",
        lambda cmd: str(path_cli) if cmd == "snyk" else None,
    )

    assert kiro_snyk.check_snyk_cli() == str(path_cli)


def test_check_snyk_cli_falls_back_to_path_when_sidecar_stale(kiro_snyk, monkeypatch, tmp_path):
    """A sidecar pointing at a since-removed/non-executable binary is ignored,
    not trusted -- the pin must still resolve to a usable executable."""
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    stale_target = tmp_path / "pin" / "snyk"  # never created
    path_cli = _make_executable(tmp_path / "path" / "snyk")
    _write_sidecar(home, stale_target)
    monkeypatch.setattr(
        kiro_snyk.shutil,
        "which",
        lambda cmd: str(path_cli) if cmd == "snyk" else None,
    )

    assert kiro_snyk.check_snyk_cli() == str(path_cli)


def test_check_snyk_cli_falls_back_to_path_when_sidecar_relative(kiro_snyk, monkeypatch, tmp_path):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    path_cli = _make_executable(tmp_path / "path" / "snyk")
    sidecar = home / ".snyk-studio" / "cli-path"
    sidecar.parent.mkdir(parents=True)
    sidecar.write_text("bin/snyk", encoding="utf-8")
    monkeypatch.setattr(
        kiro_snyk.shutil,
        "which",
        lambda cmd: str(path_cli) if cmd == "snyk" else None,
    )

    assert kiro_snyk.check_snyk_cli() == str(path_cli)


def test_check_snyk_cli_falls_back_to_path_when_sidecar_undecodable(
    kiro_snyk, monkeypatch, tmp_path
):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    path_cli = _make_executable(tmp_path / "path" / "snyk")
    sidecar = home / ".snyk-studio" / "cli-path"
    sidecar.parent.mkdir(parents=True)
    sidecar.write_bytes(b"\xff\xfe\x00")
    monkeypatch.setattr(
        kiro_snyk.shutil,
        "which",
        lambda cmd: str(path_cli) if cmd == "snyk" else None,
    )

    assert kiro_snyk.check_snyk_cli() == str(path_cli)


def test_sidecar_rejection_logs_reason_under_debug_flag(kiro_snyk, monkeypatch, tmp_path, capsys):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("SNYK_HOOK_DEBUG", "1")
    sidecar = home / ".snyk-studio" / "cli-path"
    sidecar.parent.mkdir(parents=True)
    sidecar.write_text("bin/snyk", encoding="utf-8")
    monkeypatch.setattr(kiro_snyk.shutil, "which", lambda cmd: None)

    assert kiro_snyk._snyk_cli_from_sidecar() is None

    assert "not an absolute path" in capsys.readouterr().err


def test_sidecar_rejection_silent_without_debug_flag(kiro_snyk, monkeypatch, tmp_path, capsys):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("SNYK_HOOK_DEBUG", raising=False)
    sidecar = home / ".snyk-studio" / "cli-path"
    sidecar.parent.mkdir(parents=True)
    sidecar.write_text("bin/snyk", encoding="utf-8")
    monkeypatch.setattr(kiro_snyk.shutil, "which", lambda cmd: None)

    assert kiro_snyk._snyk_cli_from_sidecar() is None

    assert capsys.readouterr().err == ""


def test_run_snyk_cli_uses_selected_binary(kiro_snyk, monkeypatch, tmp_path):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    pinned = _make_executable(tmp_path / "pin" / "snyk")
    _write_sidecar(home, pinned)
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["env"] = kwargs["env"]
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(kiro_snyk.subprocess, "run", fake_run)

    assert kiro_snyk.run_snyk_cli(["code", "test", ".", "--json"]) == (0, "{}", "")
    assert captured["cmd"] == [str(pinned), "code", "test", ".", "--json"]
    assert captured["env"]["PATH"].split(os.pathsep)[0] == str(pinned.parent)


def test_run_snyk_cli_returns_not_found_when_unresolved(kiro_snyk, monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr(kiro_snyk.shutil, "which", lambda cmd: None)

    code, stdout, stderr = kiro_snyk.run_snyk_cli(["test"])

    assert code == -1
    assert stdout == ""
    assert "Snyk CLI not found" in stderr
    assert "npm install" not in stderr
