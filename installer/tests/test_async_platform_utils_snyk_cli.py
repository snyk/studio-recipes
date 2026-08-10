"""Sidecar Snyk CLI discovery shared by async CLI hooks."""

import importlib.util
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

HOOKS_ROOT = (
    Path(__file__).resolve().parents[2]
    / "guardrail_directives"
    / "secure_at_inception"
    / "hooks_version"
)

ASYNC_CLI_IDES = ("claude", "gemini", "codex", "copilot", "cursor")
ASYNC_WORKERS = (
    ("scan_worker.py", ["code", "test", ".", "--json"], '{"runs":[]}'),
    ("sca_scan_worker.py", ["test", ".", "--json"], "{}"),
)


def _make_executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _load_platform_utils(ade: str):
    module_path = HOOKS_ROOT / ade / "async_cli_version" / "lib" / "platform_utils.py"
    spec = importlib.util.spec_from_file_location(f"{ade}_platform_utils_under_test", module_path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _load_worker(ide: str, worker_name: str, monkeypatch):
    lib_dir = HOOKS_ROOT / ide / "async_cli_version" / "lib"
    sys.modules.pop("platform_utils", None)
    sys.modules.pop("scan_runner", None)
    monkeypatch.syspath_prepend(str(lib_dir))
    module_path = lib_dir / worker_name
    spec = importlib.util.spec_from_file_location(
        f"{ide}_{Path(worker_name).stem}_under_test",
        module_path,
    )
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("ade", ASYNC_CLI_IDES)
def test_snyk_cli_from_sidecar_returns_absolute_executable(ade, monkeypatch, tmp_path):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    platform_utils = _load_platform_utils(ade)
    pinned = _make_executable(tmp_path / "pin" / "snyk")
    sidecar = home / ".snyk-studio" / "cli-path"
    sidecar.parent.mkdir(parents=True)
    sidecar.write_text(str(pinned), encoding="utf-8")

    assert platform_utils.snyk_cli_from_sidecar() == str(pinned)


@pytest.mark.parametrize("ade", ASYNC_CLI_IDES)
def test_snyk_cli_from_sidecar_rejects_relative_path(ade, monkeypatch, tmp_path):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)
    platform_utils = _load_platform_utils(ade)
    _make_executable(tmp_path / "relative" / "snyk")
    sidecar = home / ".snyk-studio" / "cli-path"
    sidecar.parent.mkdir(parents=True)
    sidecar.write_text("relative/snyk", encoding="utf-8")

    assert platform_utils.snyk_cli_from_sidecar() is None


@pytest.mark.parametrize("ade", ASYNC_CLI_IDES)
def test_snyk_cli_from_sidecar_accepts_utf8_bom(ade, monkeypatch, tmp_path):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    platform_utils = _load_platform_utils(ade)
    pinned = _make_executable(tmp_path / "pin" / "snyk")
    sidecar = home / ".snyk-studio" / "cli-path"
    sidecar.parent.mkdir(parents=True)
    sidecar.write_bytes(b"\xef\xbb\xbf" + str(pinned).encode("utf-8"))

    assert platform_utils.snyk_cli_from_sidecar() == str(pinned)


@pytest.mark.parametrize("ade", ASYNC_CLI_IDES)
def test_snyk_cli_from_sidecar_returns_none_when_missing(ade, monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    platform_utils = _load_platform_utils(ade)

    assert platform_utils.snyk_cli_from_sidecar() is None


@pytest.mark.parametrize("ade", ASYNC_CLI_IDES)
def test_snyk_cli_from_sidecar_rejects_non_executable_target(ade, monkeypatch, tmp_path):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    platform_utils = _load_platform_utils(ade)
    not_executable = tmp_path / "pin" / "snyk"
    not_executable.parent.mkdir(parents=True)
    not_executable.write_text("#!/bin/sh\n", encoding="utf-8")
    sidecar = home / ".snyk-studio" / "cli-path"
    sidecar.parent.mkdir(parents=True)
    sidecar.write_text(str(not_executable), encoding="utf-8")

    assert platform_utils.snyk_cli_from_sidecar() is None


@pytest.mark.parametrize("ade", ASYNC_CLI_IDES)
def test_snyk_cli_from_sidecar_returns_none_on_bad_encoding(ade, monkeypatch, tmp_path):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    platform_utils = _load_platform_utils(ade)
    sidecar = home / ".snyk-studio" / "cli-path"
    sidecar.parent.mkdir(parents=True)
    sidecar.write_bytes(b"\xff\xfe\x00")

    assert platform_utils.snyk_cli_from_sidecar() is None


@pytest.mark.parametrize("ade", ASYNC_CLI_IDES)
@pytest.mark.parametrize(("worker_name", "expected_args", "stdout"), ASYNC_WORKERS)
def test_async_worker_uses_sidecar_cli_and_prepends_path(
    ade,
    worker_name,
    expected_args,
    stdout,
    monkeypatch,
    tmp_path,
):
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    cache_dir = tmp_path / "cache"
    workspace.mkdir()
    cache_dir.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", str(tmp_path / "path"))
    monkeypatch.setenv("SNYK_TOKEN", "token")
    monkeypatch.setenv("SAI_WORKSPACE", str(workspace))
    monkeypatch.setenv("SAI_CACHE_DIR", str(cache_dir))
    monkeypatch.setenv("SAI_LIB_DIR", str(HOOKS_ROOT / ade / "async_cli_version" / "lib"))
    pinned = _make_executable(tmp_path / "pin" / "snyk")
    sidecar = home / ".snyk-studio" / "cli-path"
    sidecar.parent.mkdir(parents=True)
    sidecar.write_text(str(pinned), encoding="utf-8")
    worker = _load_worker(ade, worker_name, monkeypatch)
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["env"] = kwargs["env"]
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(worker.subprocess, "run", fake_run)

    try:
        worker.main()
    finally:
        lib_dir = str(HOOKS_ROOT / ade / "async_cli_version" / "lib")
        while lib_dir in sys.path:
            sys.path.remove(lib_dir)

    assert captured["cmd"] == [str(pinned), *expected_args]
    assert captured["env"]["PATH"].split(os.pathsep)[0] == str(pinned.parent)
