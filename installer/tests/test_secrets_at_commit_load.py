"""Manual load probes for the Secrets At Commit pre-commit hook.

These tests answer: how does staged-file count affect commit-time scan
latency? They deliberately use the real hook installed into a real temporary
Git repository and a real Snyk Secrets scan. They are opt-in only:

    SECRETS_LOAD_TEST=1 uv run pytest -s -v -m secrets_load \
        recipes/installer/tests/test_secrets_at_commit_load.py

Use SECRETS_LOAD_COUNTS=50,100,500,1000 to override the default matrix.
Use SECRETS_LOAD_PAYLOAD=synthetic to measure with generated benign files
that mirror the repo's tracked-file size profile without copying repo content.
Run with `-k ruamel_vendor_tree` to measure the full vendored ruamel tree as
one staged commit.
Results are printed and appended as JSON lines to
tmp/test-results/secrets-load-results.jsonl.

Set SECRETS_LOAD_FAKE_SNYK=1 for a safer local-only plumbing/overhead
measurement. Fake mode still exercises `git commit`, the installed hook,
staged-index snapshotting, file argument passing, and SARIF parsing, but it
does not run Snyk's detector or send file contents to Snyk.
"""

from __future__ import annotations

import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

import pytest

INSTALLER_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = INSTALLER_DIR.parent.parent
RESULTS_DIR = REPO_ROOT / "tmp" / "test-results"
RESULTS_PATH = RESULTS_DIR / "secrets-load-results.jsonl"
SUMMARY_PATH = RESULTS_DIR / "secrets-load-summary.md"
SECRETS_DEST = Path(".snyk-studio/components/scripts/snyk_secrets_at_commit.py")
RUAMEL_VENDOR_ROOT = Path("recipes/installer/lib/_vendor/ruamel")
RUAMEL_PAYLOAD_MODE = "ruamel-vendor"

GIT = shutil.which("git")
UV = shutil.which("uv")
SNYK = shutil.which("snyk")

sys.path.insert(0, str(INSTALLER_DIR))
installer = importlib.import_module("snyk-studio-installer")

pytestmark = [
    pytest.mark.manual,
    pytest.mark.slow,
    pytest.mark.e2e,
    pytest.mark.integration,
    pytest.mark.secrets_load,
    pytest.mark.skipif(
        os.environ.get("SECRETS_LOAD_TEST") != "1",
        reason="manual load test; set SECRETS_LOAD_TEST=1 to run",
    ),
]


@dataclass(frozen=True)
class LoadPayload:
    staged_paths: list[str]
    total_bytes: int
    source_file_count: int
    synthetic_file_count: int


@dataclass(frozen=True)
class TimingResult:
    scan_mode: str
    payload_mode: str
    file_count: int
    total_bytes: int
    source_file_count: int
    synthetic_file_count: int
    git_commit_wall_seconds: float
    hook_total_seconds: float
    scan_seconds: float
    hook_overhead_seconds: float
    outcome: str
    result_path: str


def _load_counts() -> list[int]:
    raw = os.environ.get("SECRETS_LOAD_COUNTS", "50,100,500,1000")
    counts: list[int] = []
    for piece in raw.split(","):
        piece = piece.strip()
        if not piece:
            continue
        try:
            count = int(piece)
        except ValueError as e:
            raise ValueError(f"invalid SECRETS_LOAD_COUNTS value: {piece!r}") from e
        if count <= 0:
            raise ValueError(f"SECRETS_LOAD_COUNTS values must be positive: {piece!r}")
        counts.append(count)
    if not counts:
        raise ValueError("SECRETS_LOAD_COUNTS did not contain any counts")
    return counts


def _load_count_params() -> list[int]:
    if os.environ.get("SECRETS_LOAD_TEST") != "1":
        return [50]
    return _load_counts()


def _run(
    args: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout: float = 120.0,
    check: bool = True,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        cwd=cwd,
        env=env,
        input=input_text,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
        check=check,
    )


def _init_repo(repo: Path, env: dict[str, str]) -> None:
    if GIT is None:
        pytest.skip("git not installed")
    repo.mkdir(parents=True, exist_ok=True)
    _run([GIT, "init", "-q"], cwd=repo, env=env)
    _run([GIT, "config", "user.email", "secrets-load@example.com"], cwd=repo, env=env)
    _run([GIT, "config", "user.name", "secrets-load"], cwd=repo, env=env)
    _run([GIT, "commit", "--allow-empty", "-q", "-m", "initial"], cwd=repo, env=env)


def _git_env(tmp_path: Path) -> dict[str, str]:
    """Keep Git global hooks/config out, while preserving HOME for Snyk auth.

    Snyk OAuth/API-token auth often lives under the real HOME. Since this is a
    manual local load test, preserving HOME is more useful than a perfectly
    hermetic hook log path.
    """
    empty_config = tmp_path / "gitconfig-empty"
    empty_config.write_text("", encoding="utf-8")
    env = os.environ.copy()
    env.update(
        {
            "GIT_CONFIG_GLOBAL": str(empty_config),
            "GIT_CONFIG_SYSTEM": str(empty_config),
            "GIT_CONFIG_NOSYSTEM": "1",
            "NO_UPDATE_NOTIFIER": "1",
            "SNYK_DISABLE_CLI_SELF_UPDATE": "1",
            "BROWSER": "none",
            "SECRETS_HOOK_DEBUG": "1",
            "SECRETS_SCAN_TIMEOUT": os.environ.get("SECRETS_LOAD_SCAN_TIMEOUT", "300"),
        }
    )
    return env


def _use_fake_snyk() -> bool:
    return os.environ.get("SECRETS_LOAD_FAKE_SNYK") == "1"


def _payload_mode() -> str:
    mode = os.environ.get("SECRETS_LOAD_PAYLOAD", "repo").strip().lower()
    if mode not in {"repo", "synthetic"}:
        raise ValueError("SECRETS_LOAD_PAYLOAD must be either 'repo' or 'synthetic'")
    return mode


def _scan_mode() -> str:
    return "fake" if _use_fake_snyk() else "real"


def _artifact_slug(scan_mode: str | None = None, payload_mode: str | None = None) -> str:
    return f"{scan_mode or _scan_mode()}-{payload_mode or _payload_mode()}"


def _scoped_results_path(scan_mode: str | None = None, payload_mode: str | None = None) -> Path:
    return RESULTS_DIR / f"secrets-load-results-{_artifact_slug(scan_mode, payload_mode)}.jsonl"


def _scoped_summary_path(scan_mode: str | None = None, payload_mode: str | None = None) -> Path:
    return RESULTS_DIR / f"secrets-load-summary-{_artifact_slug(scan_mode, payload_mode)}.md"


def _install_fake_snyk(tmp_path: Path, env: dict[str, str]) -> None:
    bin_dir = tmp_path / "fake-snyk-bin"
    bin_dir.mkdir()
    fake = bin_dir / ("snyk.cmd" if os.name == "nt" else "snyk")
    fake_py = bin_dir / "fake_snyk.py"
    fake_py.write_text(
        """
import json
import sys
from pathlib import Path

inputs = [arg for arg in sys.argv[3:] if arg != "--json"]
total_bytes = 0
for input_path in inputs:
    path = Path(input_path)
    candidates = path.rglob("*") if path.is_dir() else [path]
    for filename in candidates:
        if not filename.is_file():
            continue
        try:
            total_bytes += len(filename.read_bytes())
        except OSError:
            pass
print(json.dumps({"runs": [{"results": []}], "fakeBytesRead": total_bytes}))
""".lstrip(),
        encoding="utf-8",
    )
    if os.name == "nt":
        fake.write_text(f'@echo off\r\n"{sys.executable}" "{fake_py}" %*\r\n')
    else:
        fake.write_text(f"#!{sys.executable}\nexec(open({str(fake_py)!r}).read())\n")
        fake.chmod(0o755)

    env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
    env["SNYK_TOKEN"] = "fake-token"


def _tracked_source_files(root: Path | None = None) -> list[str]:
    if GIT is None:
        pytest.skip("git not installed")
    args = [GIT, "ls-files", "-z"]
    if root is not None:
        args.append(str(root))
    result = _run(args, cwd=REPO_ROOT)
    files = [p for p in result.stdout.split("\0") if p]
    # Keep this representative of the repo while avoiding special files that
    # do not copy or scan as ordinary file payload.
    return [p for p in files if (REPO_ROOT / p).is_file()]


def _copy_file(source_rel: str, dest_repo: Path, dest_rel: str) -> int:
    source = REPO_ROOT / source_rel
    dest = dest_repo / dest_rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, dest)
    return dest.stat().st_size


def _materialize_repo_payload(dest_repo: Path, file_count: int) -> LoadPayload:
    source_files = _tracked_source_files()
    if not source_files:
        pytest.skip("source repo has no tracked files to copy")

    staged_paths: list[str] = []
    total_bytes = 0
    for source_rel in source_files[:file_count]:
        staged_paths.append(source_rel)
        total_bytes += _copy_file(source_rel, dest_repo, source_rel)

    duplicate_index = 0
    while len(staged_paths) < file_count:
        source_rel = source_files[duplicate_index % len(source_files)]
        dest_rel = f"load-duplicates/{duplicate_index:04d}/{source_rel}"
        staged_paths.append(dest_rel)
        total_bytes += _copy_file(source_rel, dest_repo, dest_rel)
        duplicate_index += 1

    return LoadPayload(
        staged_paths=staged_paths,
        total_bytes=total_bytes,
        source_file_count=min(file_count, len(source_files)),
        synthetic_file_count=max(0, file_count - len(source_files)),
    )


def _write_synthetic_file(dest: Path, size: int, index: int) -> int:
    dest.parent.mkdir(parents=True, exist_ok=True)
    header = (
        f"# synthetic secrets-load file {index}\nSAFE_IDENTIFIER_{index} = 'not-a-secret-{index}'\n"
    ).encode()
    filler = (
        f"# benign generated content for load testing {index}\n"
        "def stable_value():\n"
        f"    return {index}\n\n"
    ).encode()
    if size <= len(header):
        dest.write_bytes(header[:size])
    else:
        repeats = ((size - len(header)) // len(filler)) + 1
        dest.write_bytes((header + filler * repeats)[:size])
    return dest.stat().st_size


def _materialize_synthetic_payload(dest_repo: Path, file_count: int) -> LoadPayload:
    source_files = _tracked_source_files()
    if not source_files:
        pytest.skip("source repo has no tracked files to model")

    staged_paths: list[str] = []
    total_bytes = 0
    for index in range(file_count):
        source_rel = source_files[index % len(source_files)]
        source_size = max(1, (REPO_ROOT / source_rel).stat().st_size)
        dest_rel = f"synthetic-load/file_{index:04d}.py"
        staged_paths.append(dest_rel)
        total_bytes += _write_synthetic_file(dest_repo / dest_rel, source_size, index)

    return LoadPayload(
        staged_paths=staged_paths,
        total_bytes=total_bytes,
        source_file_count=0,
        synthetic_file_count=file_count,
    )


def _materialize_ruamel_vendor_payload(dest_repo: Path) -> LoadPayload:
    source_files = _tracked_source_files(RUAMEL_VENDOR_ROOT)
    if not source_files:
        pytest.skip(f"no tracked files found under {RUAMEL_VENDOR_ROOT}")

    staged_paths: list[str] = []
    total_bytes = 0
    for source_rel in source_files:
        staged_paths.append(source_rel)
        total_bytes += _copy_file(source_rel, dest_repo, source_rel)

    return LoadPayload(
        staged_paths=staged_paths,
        total_bytes=total_bytes,
        source_file_count=len(source_files),
        synthetic_file_count=0,
    )


def _materialize_payload(dest_repo: Path, file_count: int, payload_mode: str) -> LoadPayload:
    if payload_mode == "synthetic":
        return _materialize_synthetic_payload(dest_repo, file_count)
    return _materialize_repo_payload(dest_repo, file_count)


def _stage_many(repo: Path, paths: Sequence[str], env: dict[str, str]) -> None:
    # Avoid command-line length limits for the 1000-file case.
    pathspecs = "".join(f"{p}\0" for p in paths)
    _run(
        [GIT or "git", "add", "-f", "--pathspec-from-file=-", "--pathspec-file-nul"],
        cwd=repo,
        env=env,
        input_text=pathspecs,
        timeout=120.0,
    )


def _install_secrets_hook(repo: Path) -> None:
    manifest = installer.Manifest(INSTALLER_DIR / "manifest.json")
    payload = installer.PayloadContext()
    payload.setup()
    installer.install_workspace_recipe("secrets-hooks", manifest, payload, repo, dry_run=False)
    assert (repo / SECRETS_DEST).is_file()


def _parse_timing(stderr: str) -> tuple[float, float]:
    total_match = re.search(r"done in ([\d.]+)s -- ", stderr)
    scan_match = re.search(r"\[debug\] scan took ([\d.]+)s \(total ([\d.]+)s\)", stderr)
    if not total_match:
        raise AssertionError(f"hook summary timing was not present in stderr:\n{stderr}")
    if not scan_match:
        raise AssertionError(f"hook debug scan timing was not present in stderr:\n{stderr}")
    return float(total_match.group(1)), float(scan_match.group(1))


def _assert_scan_ran(result: subprocess.CompletedProcess[str], file_count: int) -> None:
    stderr = result.stderr
    assert f"Scanning {file_count} staged files for secrets" in stderr, stderr
    assert "Snyk CLI not found" not in stderr, stderr
    assert "Snyk CLI not authenticated" not in stderr, stderr
    assert "scan timed out" not in stderr, stderr
    assert "scan did not complete" not in stderr, stderr
    assert "could not snapshot staged content" not in stderr, stderr


def _measure_staged_commit(
    repo: Path,
    env: dict[str, str],
    payload: LoadPayload,
    *,
    payload_mode: str,
    commit_message: str,
) -> TimingResult:
    file_count = len(payload.staged_paths)
    _stage_many(repo, payload.staged_paths, env)

    timeout = float(os.environ.get("SECRETS_LOAD_COMMIT_TIMEOUT", "420"))
    start = time.monotonic()
    result = _run(
        [GIT or "git", "commit", "-m", commit_message],
        cwd=repo,
        env=env,
        timeout=timeout,
        check=False,
    )
    wall_seconds = time.monotonic() - start

    _assert_scan_ran(result, file_count)
    hook_total_seconds, scan_seconds = _parse_timing(result.stderr)
    outcome = "committed" if result.returncode == 0 else "blocked"
    assert result.returncode in (0, 1), (
        f"unexpected git commit exit {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    scan_mode = _scan_mode()
    return TimingResult(
        scan_mode=scan_mode,
        payload_mode=payload_mode,
        file_count=file_count,
        total_bytes=payload.total_bytes,
        source_file_count=payload.source_file_count,
        synthetic_file_count=payload.synthetic_file_count,
        git_commit_wall_seconds=round(wall_seconds, 3),
        hook_total_seconds=hook_total_seconds,
        scan_seconds=scan_seconds,
        hook_overhead_seconds=round(max(0.0, hook_total_seconds - scan_seconds), 3),
        outcome=outcome,
        result_path=str(_scoped_results_path(scan_mode, payload_mode)),
    )


def _record_result(timing: TimingResult) -> None:
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(timing.__dict__, sort_keys=True) + "\n"
    for path in (RESULTS_PATH, Path(timing.result_path)):
        with path.open("a", encoding="utf-8") as f:
            f.write(line)


def _read_results() -> list[TimingResult]:
    if not RESULTS_PATH.exists():
        return []
    rows: list[TimingResult] = []
    for line in RESULTS_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rows.append(TimingResult(**json.loads(line)))
    return sorted(rows, key=lambda row: (row.scan_mode, row.payload_mode, row.file_count))


def _format_summary(rows: Sequence[TimingResult], *, results_path: Path) -> str:
    if not rows:
        return "No secrets load timing results were recorded."
    lines = [
        "# Secrets Load Timing",
        "",
        "| Scan | Payload | Files | Bytes | Source | Synthetic | Outcome | Hook Total | Scan Time | Hook Overhead | Git Commit Wall |",
        "|---|---|---:|---:|---:|---:|---|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            "| "
            f"{row.scan_mode} | "
            f"{row.payload_mode} | "
            f"{row.file_count} | "
            f"{row.total_bytes} | "
            f"{row.source_file_count} | "
            f"{row.synthetic_file_count} | "
            f"{row.outcome} | "
            f"{row.hook_total_seconds:.1f}s | "
            f"{row.scan_seconds:.1f}s | "
            f"{row.hook_overhead_seconds:.3f}s | "
            f"{row.git_commit_wall_seconds:.3f}s |"
        )
    lines.extend(
        [
            "",
            f"Raw JSONL: `{results_path}`",
        ]
    )
    return "\n".join(lines) + "\n"


def _print_timing(timing: TimingResult) -> None:
    print(
        "\n[secrets-load] "
        f"mode={timing.scan_mode} "
        f"payload={timing.payload_mode} "
        f"files={timing.file_count} bytes={timing.total_bytes} "
        f"source_files={timing.source_file_count} synthetic_files={timing.synthetic_file_count} "
        f"outcome={timing.outcome}"
    )
    print(
        "[secrets-load] "
        f"git_commit_wall={timing.git_commit_wall_seconds:.3f}s "
        f"hook_total={timing.hook_total_seconds:.1f}s "
        f"scan={timing.scan_seconds:.1f}s "
        f"hook_overhead={timing.hook_overhead_seconds:.3f}s"
    )
    print(f"[secrets-load] results={RESULTS_PATH}")


@pytest.fixture(scope="session", autouse=True)
def _load_timing_summary() -> None:
    if os.environ.get("SECRETS_LOAD_TEST") == "1":
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        for path in RESULTS_DIR.glob("secrets-load-results*.jsonl"):
            path.unlink(missing_ok=True)
        for path in RESULTS_DIR.glob("secrets-load-summary*.md"):
            path.unlink(missing_ok=True)
    yield
    if os.environ.get("SECRETS_LOAD_TEST") != "1":
        return
    rows = _read_results()
    if not rows:
        return
    summary = _format_summary(rows, results_path=RESULTS_PATH)
    SUMMARY_PATH.write_text(summary, encoding="utf-8")
    scoped_summary_paths: list[Path] = []
    grouped_rows: dict[tuple[str, str], list[TimingResult]] = {}
    for row in rows:
        grouped_rows.setdefault((row.scan_mode, row.payload_mode), []).append(row)
    for (scan_mode, payload_mode), group in sorted(grouped_rows.items()):
        scoped_summary_path = _scoped_summary_path(scan_mode, payload_mode)
        scoped_summary = _format_summary(
            group,
            results_path=_scoped_results_path(scan_mode, payload_mode),
        )
        scoped_summary_path.write_text(scoped_summary, encoding="utf-8")
        scoped_summary_paths.append(scoped_summary_path)
    print("\n[secrets-load] summary")
    print(summary)
    print(f"[secrets-load] summary_file={SUMMARY_PATH}")
    for path in scoped_summary_paths:
        print(f"[secrets-load] scoped_summary_file={path}")


@pytest.mark.parametrize("file_count", _load_count_params())
def test_secrets_precommit_load_timing(file_count: int, tmp_path: Path) -> None:
    """Measure real hook latency for staged commits of different sizes."""
    if UV is None:
        pytest.skip("uv not installed; installed hook command uses `uv run`")
    fake_snyk = _use_fake_snyk()
    payload_mode = _payload_mode()
    if not fake_snyk and SNYK is None:
        pytest.skip("snyk CLI not installed; load test needs a real secrets scan")

    env = _git_env(tmp_path)
    if fake_snyk:
        _install_fake_snyk(tmp_path, env)
    repo = tmp_path / f"load-{file_count}"
    _init_repo(repo, env)
    _install_secrets_hook(repo)
    payload = _materialize_payload(repo, file_count, payload_mode)
    timing = _measure_staged_commit(
        repo,
        env,
        payload,
        payload_mode=payload_mode,
        commit_message=f"load {file_count} files",
    )
    _record_result(timing)
    _print_timing(timing)


def test_secrets_precommit_load_ruamel_vendor_tree(tmp_path: Path) -> None:
    """Measure one commit containing the full tracked vendored ruamel tree."""
    if UV is None:
        pytest.skip("uv not installed; installed hook command uses `uv run`")
    fake_snyk = _use_fake_snyk()
    if not fake_snyk and SNYK is None:
        pytest.skip("snyk CLI not installed; load test needs a real secrets scan")

    env = _git_env(tmp_path)
    if fake_snyk:
        _install_fake_snyk(tmp_path, env)
    repo = tmp_path / "load-ruamel-vendor"
    _init_repo(repo, env)
    _install_secrets_hook(repo)
    payload = _materialize_ruamel_vendor_payload(repo)
    timing = _measure_staged_commit(
        repo,
        env,
        payload,
        payload_mode=RUAMEL_PAYLOAD_MODE,
        commit_message="load ruamel vendor tree",
    )
    _record_result(timing)
    _print_timing(timing)
