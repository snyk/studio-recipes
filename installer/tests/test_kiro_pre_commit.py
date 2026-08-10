"""Kiro's legacy git-hook pre-commit script: prerequisite gate messaging."""

import importlib.machinery
import importlib.util
import sys
from pathlib import Path

import pytest

MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "guardrail_directives"
    / "secure_at_inception"
    / "kiro_hooks"
    / "git"
    / "pre-commit"
)


@pytest.fixture
def kiro_pre_commit(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    loader = importlib.machinery.SourceFileLoader("kiro_pre_commit_under_test", str(MODULE_PATH))
    spec = importlib.util.spec_from_file_location(
        "kiro_pre_commit_under_test", MODULE_PATH, loader=loader
    )
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    lib_dir = str(MODULE_PATH.parent / "lib")
    monkeypatch.syspath_prepend(lib_dir)
    try:
        spec.loader.exec_module(module)
    finally:
        while lib_dir in sys.path:
            sys.path.remove(lib_dir)
    return module


def _staged_changes(module):
    analyze_diff = sys.modules["analyze_diff"]
    return analyze_diff.StagedChanges(files={"src/app.py": object()})


def test_auth_hint_uses_resolved_cli_not_bare_snyk(kiro_pre_commit, monkeypatch, capsys):
    """The pin is only useful if a non-PATH `snyk` still gets a runnable hint."""
    sidecar_cli = "/opt/snyk-studio/bin/snyk"
    monkeypatch.setattr(
        kiro_pre_commit, "get_staged_changes", lambda: _staged_changes(kiro_pre_commit)
    )
    monkeypatch.setattr(kiro_pre_commit, "check_snyk_cli", lambda: sidecar_cli)
    monkeypatch.setattr(kiro_pre_commit, "check_snyk_auth", lambda: None)

    result = kiro_pre_commit.run_hook()

    assert result == 1
    out = capsys.readouterr().out
    assert f"run `{sidecar_cli} auth`" in out
    assert "run `snyk auth`" not in out
