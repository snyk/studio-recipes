"""Tests for the secrets-only pre-commit hook recipe: manifest wiring,
the pure-Python diff/finding logic in `secrets_at_commit/lib/`, and the
entry script's fail-open/fail-closed contract."""

from __future__ import annotations

import dataclasses
import importlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
from contextlib import contextmanager
from io import BytesIO
from pathlib import Path

import pytest

INSTALLER_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = INSTALLER_DIR.parent.parent
SECRETS_HOOK_DIR = REPO_ROOT / "recipes" / "guardrail_directives" / "secrets_at_commit"
SECRETS_DEST = Path(".snyk-studio/components/scripts/snyk_secrets_at_commit.py")

# Some CI images don't have git installed; every real-repo test below goes
# through _init_git_repo first, so gating there is enough to skip them all.
GIT = shutil.which("git")

sys.path.insert(0, str(INSTALLER_DIR))
sys.path.insert(0, str(INSTALLER_DIR / "lib"))
# Inserted last so it's sys.path[0] -- `lib` must resolve to
# secrets_at_commit/lib, not e.g. recipes/installer/lib.
sys.path.insert(0, str(SECRETS_HOOK_DIR))

installer = importlib.import_module("snyk-studio-installer")
secrets_hook = importlib.import_module("snyk_secrets_at_commit")
from lib import (  # noqa: E402
    baseline,
    deprecated_flags,
    diff_scope,
    findings,
    git_ops,
    index_snapshot,
    persistent_log,
    proc,
    report,
    snyk_cli,
    timing,
)
from lib.index_snapshot import SnapshotError, ref_snapshot, staged_snapshot  # noqa: E402


def _init_git_repo(path: Path) -> None:
    if GIT is None:
        pytest.skip("git not installed")
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run([GIT, "init", "-q"], cwd=path, check=True)
    subprocess.run([GIT, "config", "user.email", "t@example.com"], cwd=path, check=True)
    subprocess.run([GIT, "config", "user.name", "t"], cwd=path, check=True)


@pytest.fixture(autouse=True)
def _isolate_git_config(tmp_path_factory, monkeypatch):
    empty_config = tmp_path_factory.mktemp("git-config") / "gitconfig-empty"
    empty_config.write_text("", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(empty_config))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(empty_config))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    # SECRETS_DIFF_STRATEGY is a removed flag -- don't let a real shell env
    # with it set leak in and add an unexpected deprecation-warning line to
    # tests that assert on exact stderr output.
    monkeypatch.delenv("SECRETS_DIFF_STRATEGY", raising=False)


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path_factory, monkeypatch):
    """Redirect os.path.expanduser("~") to a per-test fake home dir --
    otherwise the always-on persistent log (lib/persistent_log.py) would
    write to the real developer/CI machine's home directory."""
    fake_home = tmp_path_factory.mktemp("home")
    monkeypatch.setattr(os.path, "expanduser", lambda p: p.replace("~", str(fake_home)))


@pytest.fixture
def repo(tmp_path):
    """A real git repo with one commit, so HEAD exists."""
    _init_git_repo(tmp_path)
    subprocess.run(["git", "commit", "-q", "--allow-empty", "-m", "init"], cwd=tmp_path, check=True)
    return tmp_path


@pytest.fixture
def manifest():
    return installer.Manifest(INSTALLER_DIR / "manifest.json")


@pytest.fixture
def payload():
    pl = installer.PayloadContext()
    pl.setup()
    return pl


def _stage(repo: Path, name: str, content: str) -> None:
    (repo / name).write_text(content)
    subprocess.run(["git", "add", name], cwd=repo, check=True)


# ============================================================================
# 1. Manifest plumbing
# ============================================================================


class TestManifest:
    def test_workspace_scoped(self, manifest):
        assert manifest.is_workspace_scoped("secrets-precommit-hook") is True

    def test_excluded_from_default_and_experimental_profiles_by_default(self, manifest):
        assert "secrets-precommit-hook" not in manifest.resolve_recipes("default")
        assert "secrets-precommit-hook" not in manifest.resolve_recipes("experimental")

    def test_selection_replaces_the_profile_with_the_secrets_hook(self, manifest):
        assert manifest.resolve_recipes("experimental", ["secrets-precommit-hook"]) == [
            "secrets-precommit-hook"
        ]

    def test_profile_can_include_secrets_hook_without_a_selection(self, manifest):
        manifest.profiles["with-secrets"] = {"recipes": ["mcp-config", "secrets-precommit-hook"]}
        assert "secrets-precommit-hook" in manifest.resolve_recipes("with-secrets")

    def test_coexists_with_secure_at_commit(self, manifest):
        # Secrets At Commit scans secrets only, so it can be selected alongside
        # the other commit-time hook.
        recipes = manifest.resolve_recipes(
            "experimental", ["secure-at-commit", "secrets-precommit-hook"]
        )
        assert "secure-at-commit" in recipes
        assert "secrets-precommit-hook" in recipes

    def test_pre_commit_integration_command_has_no_flags(self, manifest):
        # There's only one mode (audit mode was removed), so the installed
        # command line is just the bare script invocation -- no --staged.
        ws = manifest.recipes["secrets-precommit-hook"]["sources"]["workspace"]
        cmd = ws["pre_commit_integration"]["command"]
        assert cmd.split()[-1].endswith("snyk_secrets_at_commit.py")
        assert ws["pre_commit_integration"]["tag"] == "snyk-secrets-at-commit"

    def test_source_files_exist(self, manifest, payload):
        for f in manifest.recipes["secrets-precommit-hook"]["sources"]["workspace"]["files"]:
            assert payload.resolve_src(f["src"]).is_file(), f["src"]

    def test_every_py_file_on_disk_is_in_manifest(self, manifest):
        """The reverse of test_source_files_exist: a new lib/*.py module
        that's imported but never added here installs nothing and only
        fails at hook runtime (ModuleNotFoundError), which no unit test
        catches since those import straight from the source tree."""
        listed = {
            f["src"]
            for f in manifest.recipes["secrets-precommit-hook"]["sources"]["workspace"]["files"]
        }
        on_disk = {
            p.relative_to(SECRETS_HOOK_DIR.parent.parent).as_posix()
            for p in SECRETS_HOOK_DIR.rglob("*.py")
        }
        missing = on_disk - listed
        assert not missing, f"present on disk but missing from manifest.json: {missing}"

    def test_every_py_file_on_disk_is_in_global_manifest(self, manifest):
        """Same check as test_every_py_file_on_disk_is_in_manifest, but for
        the global-install variant's own file list -- the two lists are
        maintained separately, so a module added to one and not the other
        installs nothing for global installs (ModuleNotFoundError at
        runtime, not caught by any test that only exercises the workspace
        variant)."""
        listed = {
            f["src"]
            for f in manifest.recipes["secrets-precommit-hook-global"]["sources"]["git-global"][
                "files"
            ]
        }
        on_disk = {
            p.relative_to(SECRETS_HOOK_DIR.parent.parent).as_posix()
            for p in SECRETS_HOOK_DIR.rglob("*.py")
        }
        missing = on_disk - listed
        assert not missing, f"present on disk but missing from global manifest.json: {missing}"

    def test_default_profile_does_not_install_secrets_hook_by_default(
        self, repo, manifest, payload
    ):
        recipes = manifest.resolve_recipes("default")
        for recipe_id in recipes:
            if manifest.is_workspace_scoped(recipe_id):
                installer.install_workspace_recipe(
                    recipe_id, manifest, payload, repo, dry_run=False
                )

        assert not (repo / SECRETS_DEST).exists()
        hook = repo / ".git" / "hooks" / "pre-commit"
        if hook.exists():
            assert "snyk-secrets-at-commit" not in hook.read_text(encoding="utf-8")

    def test_selection_installs_secrets_hook_files_and_integration(self, repo, manifest, payload):
        recipes = manifest.resolve_recipes("experimental", ["secrets-precommit-hook"])
        for recipe_id in recipes:
            if manifest.is_workspace_scoped(recipe_id):
                installer.install_workspace_recipe(
                    recipe_id, manifest, payload, repo, dry_run=False
                )

        assert (repo / SECRETS_DEST).is_file()
        assert (
            installer.verify_workspace_recipe("secrets-precommit-hook", manifest, payload, repo)
            is True
        )

    def test_narrowed_install_verifies_clean(self, repo, manifest, payload):
        # A selection narrower than the profile must verify against what it
        # actually resolved, not against the profile's own list.
        recipes = manifest.resolve_recipes("experimental", ["secrets-precommit-hook"])
        for recipe_id in recipes:
            installer.install_workspace_recipe(recipe_id, manifest, payload, repo, dry_run=False)

        assert all(
            installer.verify_workspace_recipe(recipe_id, manifest, payload, repo)
            for recipe_id in recipes
        )

    def test_verify_includes_existing_secrets_hook_without_a_selection(
        self, repo, manifest, payload
    ):
        recipes = installer.resolve_verify_recipes(manifest, payload, "default", workspace=repo)
        assert "secrets-precommit-hook" not in recipes

        installer.install_workspace_recipe(
            "secrets-precommit-hook", manifest, payload, repo, dry_run=False
        )

        recipes = installer.resolve_verify_recipes(manifest, payload, "default", workspace=repo)
        assert "secrets-precommit-hook" in recipes

    def test_verify_includes_existing_secrets_hook_when_files_are_missing(
        self, repo, manifest, payload
    ):
        installer.install_workspace_recipe(
            "secrets-precommit-hook", manifest, payload, repo, dry_run=False
        )
        shutil.rmtree(repo / ".snyk-studio")

        recipes = installer.resolve_verify_recipes(manifest, payload, "default", workspace=repo)
        assert "secrets-precommit-hook" in recipes
        assert (
            installer.verify_workspace_recipe("secrets-precommit-hook", manifest, payload, repo)
            is False
        )

    def test_uninstall_removes_secrets_hook_even_when_default_profile_excludes_it(
        self, repo, manifest, payload
    ):
        installer.install_workspace_recipe(
            "secrets-precommit-hook", manifest, payload, repo, dry_run=False
        )
        assert (repo / SECRETS_DEST).is_file()

        installer.uninstall([], manifest, payload, workspace=repo, dry_run=False)

        assert not (repo / SECRETS_DEST).exists()
        assert (
            installer.verify_workspace_recipe("secrets-precommit-hook", manifest, payload, repo)
            is False
        )

    def test_uninstall_after_a_narrowed_install_ignores_unselected_recipes(
        self, repo, manifest, payload
    ):
        for recipe_id in manifest.resolve_recipes("experimental", ["secrets-precommit-hook"]):
            installer.install_workspace_recipe(recipe_id, manifest, payload, repo, dry_run=False)

        installer.uninstall([], manifest, payload, workspace=repo, dry_run=False)

        assert not (repo / SECRETS_DEST).exists()


# ============================================================================
# 2. lib/diff_scope.py
# ============================================================================


class TestParseAddedLineRanges:
    def test_new_file(self):
        diff = "diff --git a/new.py b/new.py\n+++ b/new.py\n@@ -0,0 +1,3 @@\n"
        assert diff_scope.parse_added_line_ranges(diff) == {"new.py": [(1, 3)]}

    def test_pure_modification_single_line(self):
        diff = "+++ b/app.py\n@@ -5 +5 @@\n"
        assert diff_scope.parse_added_line_ranges(diff) == {"app.py": [(5, 5)]}

    def test_pure_deletion_yields_no_ranges(self):
        diff = "+++ b/app.py\n@@ -10,3 +9,0 @@\n"
        assert diff_scope.parse_added_line_ranges(diff) == {}

    def test_rename_only_no_content_change_yields_no_ranges(self):
        # git emits no +++/@@ lines at all for a pure rename with no diff.
        diff = "diff --git a/old.py b/new.py\nsimilarity index 100%\nrename from old.py\nrename to new.py\n"
        assert diff_scope.parse_added_line_ranges(diff) == {}

    def test_multiple_hunks_one_file(self):
        diff = "+++ b/app.py\n@@ -1,0 +1,2 @@\n@@ -20,0 +25,1 @@\n"
        assert diff_scope.parse_added_line_ranges(diff) == {"app.py": [(1, 2), (25, 25)]}

    def test_multiple_files(self):
        diff = "+++ b/a.py\n@@ -0,0 +1,1 @@\n+++ b/b.py\n@@ -0,0 +1,2 @@\n"
        assert diff_scope.parse_added_line_ranges(diff) == {"a.py": [(1, 1)], "b.py": [(1, 2)]}

    def test_quoted_filename_with_embedded_quote_and_space(self):
        # Real git output for a staged file named `weird "quote".txt`:
        # C-quoted (embedded " always forces quoting, regardless of
        # core.quotePath) with a trailing tab appended for the space.
        diff = '+++ "b/weird \\"quote\\".txt"\t\n@@ -0,0 +1,2 @@\n'
        assert diff_scope.parse_added_line_ranges(diff) == {'weird "quote".txt': [(1, 2)]}

    def test_quoted_filename_not_first_does_not_leak_into_previous_file(self):
        # Regression: a quoted +++ line that failed to parse used to leave
        # current_file pointing at the previous file, misattributing this
        # hunk to normal.py instead of dropping/attributing it correctly.
        diff = '+++ b/normal.py\n@@ -2,0 +3,1 @@\n+++ "b/weird \\"name\\".txt"\t\n@@ -0,0 +1,2 @@\n'
        assert diff_scope.parse_added_line_ranges(diff) == {
            "normal.py": [(3, 3)],
            'weird "name".txt': [(1, 2)],
        }


class TestUnquoteGitPath:
    def test_unquoted_passthrough(self):
        assert diff_scope._unquote_git_path("b/plain.py") == "b/plain.py"

    def test_embedded_double_quote(self):
        assert diff_scope._unquote_git_path('"b/weird \\"quote\\".txt"') == 'b/weird "quote".txt'

    def test_embedded_backslash(self):
        assert diff_scope._unquote_git_path('"b/weird\\\\path.txt"') == "b/weird\\path.txt"

    def test_named_control_escapes(self):
        assert diff_scope._unquote_git_path('"b/tab\\there.txt"') == "b/tab\there.txt"

    def test_octal_escape_fallback(self):
        # \NNN is only emitted by core.quotePath=true (non-ASCII bytes);
        # this hook always sets it false, but the decoder handles it
        # defensively anyway.
        assert diff_scope._unquote_git_path('"b/\\303\\251.txt"') == "b/\u00e9.txt"

    def test_not_quoted_even_with_internal_looking_quote_char(self):
        # Doesn't start AND end with a quote -- not actually quoted form.
        assert diff_scope._unquote_git_path('b/weird"name.txt') == 'b/weird"name.txt'


class TestSplitAddedVsPreExisting:
    @staticmethod
    def _finding(path="app.py", line=1):
        return findings.Finding(file_path=path, start_line=line)

    def test_line_inside_range_is_added(self):
        added, pre, _ = diff_scope.split_added_vs_pre_existing(
            [self._finding(line=5)], {"app.py": [(1, 10)]}
        )
        assert added == [self._finding(line=5)]
        assert pre == []

    def test_line_outside_range_is_pre_existing(self):
        added, pre, _ = diff_scope.split_added_vs_pre_existing(
            [self._finding(line=50)], {"app.py": [(1, 10)]}
        )
        assert added == []
        assert pre == [self._finding(line=50)]

    def test_file_with_no_ranges_is_all_pre_existing(self):
        added, pre, _ = diff_scope.split_added_vs_pre_existing([self._finding()], {})
        assert added == []
        assert len(pre) == 1

    def test_backslash_path_from_finding_still_matches_forward_slash_range(self):
        finding = findings.Finding(file_path="src\\app.py", start_line=5)
        added, pre, _ = diff_scope.split_added_vs_pre_existing([finding], {"src/app.py": [(1, 10)]})
        assert added == [finding]
        assert pre == []

    def test_multiline_finding_is_added_when_only_its_end_overlaps_a_range(self):
        # A multi-line match (e.g. a PEM block) whose start_line sits above
        # an edit but whose end_line falls inside it must still count as
        # added -- checking start_line alone would miss this.
        finding = findings.Finding(file_path="app.py", start_line=8, end_line=12)
        added, pre, _ = diff_scope.split_added_vs_pre_existing([finding], {"app.py": [(10, 15)]})
        assert added == [finding]
        assert pre == []

    def test_multiline_finding_spanning_entirely_over_a_range_is_added(self):
        # Neither endpoint falls literally inside the range, but the range
        # is fully contained within the finding's span.
        finding = findings.Finding(file_path="app.py", start_line=1, end_line=20)
        added, pre, _ = diff_scope.split_added_vs_pre_existing([finding], {"app.py": [(10, 12)]})
        assert added == [finding]
        assert pre == []

    def test_missing_start_line_is_added_not_silently_pre_existing(self):
        # A finding with no usable position (e.g. SARIF omitted startLine,
        # so it defaults to 0) must never be classified as pre-existing --
        # that would silently let a blocking finding through as pre-existing.
        finding = findings.Finding(file_path="app.py", start_line=0)
        added, pre, _ = diff_scope.split_added_vs_pre_existing([finding], {"app.py": [(1, 10)]})
        assert added == [finding]
        assert pre == []

    def test_missing_start_line_is_added_even_with_no_ranges_for_file(self):
        finding = findings.Finding(file_path="app.py", start_line=0)
        added, pre, _ = diff_scope.split_added_vs_pre_existing([finding], {})
        assert added == [finding]
        assert pre == []


# ============================================================================
# 3. lib/index_snapshot.py
# ============================================================================


class TestStagedSnapshot:
    def test_no_files_checks_out_empty_directory(self, repo):
        with staged_snapshot(repo, []) as snap:
            assert list(snap.iterdir()) == []

    def test_success_checks_out_index_content(self, repo):
        _stage(repo, "app.py", "one\n")
        with staged_snapshot(repo, ["app.py"]) as snap:
            assert (snap / "app.py").read_text() == "one\n"

    def test_unstaged_edit_not_reflected_in_snapshot(self, repo):
        """The whole point: snapshot reflects the index, not the working tree."""
        _stage(repo, "app.py", "staged content\n")
        (repo / "app.py").write_text("unstaged edit on top\n")
        with staged_snapshot(repo, ["app.py"]) as snap:
            assert (snap / "app.py").read_text() == "staged content\n"

    def test_failure_raises_with_stderr_snippet(self, repo, monkeypatch):
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **kw: subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="<GIT_CHECKOUT_INDEX_ERROR>"
            ),
        )
        with pytest.raises(SnapshotError, match="<GIT_CHECKOUT_INDEX_ERROR>"):
            with staged_snapshot(repo, ["app.py"]):
                pass

    def test_hung_checkout_index_raises_timeout_detail(self, repo, monkeypatch):
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **kw: (_ for _ in ()).throw(
                subprocess.TimeoutExpired(cmd="git", timeout=kw.get("timeout"))
            ),
        )
        with pytest.raises(SnapshotError, match="timed out"):
            with staged_snapshot(repo, ["app.py"]):
                pass

    def test_scratch_dir_creation_failure_is_actionable(self, repo, monkeypatch, tmp_path_factory):
        fake_tmp = tmp_path_factory.mktemp("fake-tmp-root")
        monkeypatch.setattr(tempfile, "gettempdir", lambda: str(fake_tmp))
        monkeypatch.setattr(
            tempfile,
            "mkdtemp",
            lambda *a, **kw: (_ for _ in ()).throw(OSError(28, "No space left on device")),
        )
        with pytest.raises(SnapshotError) as exc_info:
            with staged_snapshot(repo, ["app.py"]):
                pass
        assert str(fake_tmp) in str(exc_info.value)
        assert "No space left on device" in str(exc_info.value)

    def test_temp_dir_cleaned_up_on_checkout_index_failure(self, repo, monkeypatch):
        captured: list[Path] = []
        real_mkdtemp = tempfile.mkdtemp

        def _tracking_mkdtemp(*a, **kw):
            d = Path(real_mkdtemp(*a, **kw))
            captured.append(d)
            return str(d)

        monkeypatch.setattr(tempfile, "mkdtemp", _tracking_mkdtemp)
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **kw: subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr=""
            ),
        )
        with pytest.raises(SnapshotError):
            with staged_snapshot(repo, ["app.py"]):
                pass
        assert not captured[0].exists()

    def test_temp_dir_cleaned_up_even_on_exception(self, repo):
        _stage(repo, "app.py", "one\n")
        captured: list[Path] = []

        def _raise_inside_snapshot():
            with staged_snapshot(repo, ["app.py"]) as snap:
                captured.append(snap)
                raise RuntimeError("<TEST_EXCEPTION_INSIDE_STAGED_SNAPSHOT_CONTEXT>")

        with pytest.raises(RuntimeError):
            _raise_inside_snapshot()
        assert not captured[0].exists()


class TestRefSnapshot:
    def test_no_files_yields_none(self, repo):
        with ref_snapshot(repo, "HEAD", []) as (snap, existing, failed):
            assert snap is None
            assert existing == set()
            assert failed is False

    def test_extracts_correct_ref_content(self, repo):
        _stage(repo, "app.py", "one\n")
        subprocess.run(["git", "commit", "-q", "-m", "add app"], cwd=repo, check=True)
        with ref_snapshot(repo, "HEAD", ["app.py"]) as (snap, existing, failed):
            assert existing == {"app.py"}
            assert (snap / "app.py").read_text() == "one\n"
            assert failed is False

    def test_brand_new_file_gracefully_excluded(self, repo):
        # app.py is staged but not yet committed -- doesn't exist at HEAD.
        _stage(repo, "app.py", "one\n")
        with ref_snapshot(repo, "HEAD", ["app.py"]) as (snap, existing, failed):
            assert snap is None
            assert existing == set()
            assert failed is False

    def test_mix_of_existing_and_new_files(self, repo):
        # A new file alongside an existing one must not lose baseline
        # coverage for the existing one.
        _stage(repo, "existing.py", "one\n")
        subprocess.run(["git", "commit", "-q", "-m", "add existing"], cwd=repo, check=True)
        _stage(repo, "brand_new.py", "two\n")
        with ref_snapshot(repo, "HEAD", ["existing.py", "brand_new.py"]) as (
            snap,
            existing,
            failed,
        ):
            assert existing == {"existing.py"}
            assert (snap / "existing.py").read_text() == "one\n"
            assert not (snap / "brand_new.py").exists()
            assert failed is False

    def test_bad_ref_yields_none(self, repo):
        _stage(repo, "app.py", "one\n")
        subprocess.run(["git", "commit", "-q", "-m", "add app"], cwd=repo, check=True)
        with ref_snapshot(repo, "not-a-real-ref", ["app.py"]) as (snap, existing, failed):
            assert snap is None
            assert existing == set()
            assert failed is False

    def test_hung_git_archive_times_out_instead_of_hanging(self, repo, monkeypatch):
        _stage(repo, "app.py", "one\n")
        subprocess.run(["git", "commit", "-q", "-m", "add app"], cwd=repo, check=True)
        real_run = subprocess.run

        def fake_run(args, *a, **kw):
            if "archive" in args:
                raise subprocess.TimeoutExpired(cmd="git", timeout=kw.get("timeout"))
            return real_run(args, *a, **kw)

        monkeypatch.setattr(subprocess, "run", fake_run)
        with ref_snapshot(repo, "HEAD", ["app.py"]) as (snap, existing, failed):
            assert snap is None
            assert existing == set()
            # A hung git archive is a real, attempted failure -- distinct
            # from "nothing exists at ref" -- so callers can say so.
            assert failed is True

    def test_deadline_exhausted_after_files_confirmed_is_flagged(self, repo, monkeypatch):
        # Files were confirmed to exist at `ref` and a scratch dir was
        # created -- running out of shared budget before `git archive`
        # could run is a real, attempted failure, not "nothing to do."
        # The deadline check inside `_existing_at_ref` must still succeed
        # (real budget for that call); only the later check, after
        # existence is confirmed, should see it exhausted.
        _stage(repo, "app.py", "one\n")
        subprocess.run(["git", "commit", "-q", "-m", "add app"], cwd=repo, check=True)
        real_bounded_git_timeout = index_snapshot.bounded_git_timeout
        calls = []

        def _fake_bounded_git_timeout(deadline):
            calls.append(deadline)
            return real_bounded_git_timeout(None) if len(calls) == 1 else None

        monkeypatch.setattr(index_snapshot, "bounded_git_timeout", _fake_bounded_git_timeout)
        with ref_snapshot(repo, "HEAD", ["app.py"], deadline=0.0) as (snap, existing, failed):
            assert snap is None
            assert existing == set()
            assert failed is True

    def test_archive_extraction_failure_is_flagged(self, repo, monkeypatch):
        _stage(repo, "app.py", "one\n")
        subprocess.run(["git", "commit", "-q", "-m", "add app"], cwd=repo, check=True)
        monkeypatch.setattr(index_snapshot, "_extract_archive", lambda *a, **kw: False)
        with ref_snapshot(repo, "HEAD", ["app.py"]) as (snap, existing, failed):
            assert snap is None
            assert existing == set()
            assert failed is True

    def test_scratch_dir_creation_failure_is_flagged_not_raised(self, repo, monkeypatch):
        _stage(repo, "app.py", "one\n")
        subprocess.run(["git", "commit", "-q", "-m", "add app"], cwd=repo, check=True)

        def _raise(*a, **kw):
            raise index_snapshot.SnapshotError("disk full")

        monkeypatch.setattr(index_snapshot, "_create_scratch_dir", _raise)
        with ref_snapshot(repo, "HEAD", ["app.py"]) as (snap, existing, failed):
            assert snap is None
            assert existing == set()
            assert failed is True

    def test_temp_dir_cleaned_up_even_on_exception(self, repo):
        _stage(repo, "app.py", "one\n")
        subprocess.run(["git", "commit", "-q", "-m", "add app"], cwd=repo, check=True)
        captured: list[Path] = []

        def _raise_inside_snapshot():
            with ref_snapshot(repo, "HEAD", ["app.py"]) as (snap, _existing, _failed):
                captured.append(snap)
                raise RuntimeError("<TEST_EXCEPTION_INSIDE_REF_SNAPSHOT_CONTEXT>")

        with pytest.raises(RuntimeError):
            _raise_inside_snapshot()
        assert not captured[0].exists()


class TestExtractDefensively:
    """Exercised directly, regardless of which Python runs these tests."""

    @staticmethod
    def _make_tar(members: list[tuple[tarfile.TarInfo, bytes | None]]) -> tarfile.TarFile:
        buf = BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for info, data in members:
                tar.addfile(info, BytesIO(data) if data is not None else None)
        buf.seek(0)
        return tarfile.open(fileobj=buf, mode="r")

    def test_normal_file_extracts_fine(self, tmp_path):
        info = tarfile.TarInfo("app.py")
        info.size = 5
        with self._make_tar([(info, b"hello")]) as tar:
            index_snapshot._extract_defensively(tar, tmp_path)
        assert (tmp_path / "app.py").read_bytes() == b"hello"

    def test_path_traversal_is_rejected(self, tmp_path):
        info = tarfile.TarInfo("../evil.txt")
        info.size = 4
        with self._make_tar([(info, b"evil")]) as tar:
            with pytest.raises(tarfile.TarError):
                index_snapshot._extract_defensively(tar, tmp_path)
        assert not (tmp_path.parent / "evil.txt").exists()

    def test_symlink_is_rejected(self, tmp_path):
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        with self._make_tar([(info, None)]) as tar:
            with pytest.raises(tarfile.TarError):
                index_snapshot._extract_defensively(tar, tmp_path)
        assert not (tmp_path / "link").exists()

    def test_setuid_bit_is_stripped(self, tmp_path):
        info = tarfile.TarInfo("app.sh")
        info.size = 2
        info.mode = 0o4755
        with self._make_tar([(info, b"hi")]) as tar:
            index_snapshot._extract_defensively(tar, tmp_path)
        mode = (tmp_path / "app.sh").stat().st_mode
        assert not mode & stat.S_ISUID

    def test_directory_uses_sanitized_permissions(self, tmp_path):
        info = tarfile.TarInfo("private")
        info.type = tarfile.DIRTYPE
        info.mode = 0o4750
        with self._make_tar([(info, None)]) as tar:
            index_snapshot._extract_defensively(tar, tmp_path)
        mode = (tmp_path / "private").stat().st_mode
        assert mode & 0o777 == 0o750
        assert not mode & stat.S_ISUID

    def test_failed_copy_leaves_no_partial_target(self, monkeypatch, tmp_path):
        info = tarfile.TarInfo("app.py")
        info.size = 5

        def fail_copy(source, output):
            output.write(source.read(2))
            raise OSError("simulated copy failure")

        monkeypatch.setattr(index_snapshot.shutil, "copyfileobj", fail_copy)
        with self._make_tar([(info, b"hello")]) as tar:
            with pytest.raises(OSError, match="simulated copy failure"):
                index_snapshot._extract_defensively(tar, tmp_path)

        assert not (tmp_path / "app.py").exists()
        assert list(tmp_path.iterdir()) == []

    def test_extract_archive_end_to_end_rejects_traversal(self, tmp_path):
        buf = BytesIO()
        info = tarfile.TarInfo("../evil.txt")
        info.size = 4
        with tarfile.open(fileobj=buf, mode="w") as tar:
            tar.addfile(info, BytesIO(b"evil"))
        assert index_snapshot._extract_archive(buf.getvalue(), tmp_path) is False

    def test_pax_header_member_is_skipped_not_rejected(self, tmp_path):
        # git archive's pax_global_header record is real tar metadata, not
        # suspicious content -- Bugbot flagged this on PR #156. tarfile
        # itself absorbs pax members before getmembers() ever sees them
        # (confirmed against real git archive output), so this can't be
        # exercised via a real archive round-trip; a fake tar object is
        # the only way to reach the code path directly.
        pax_member = tarfile.TarInfo("pax_global_header")
        pax_member.type = tarfile.XGLTYPE
        file_member = tarfile.TarInfo("app.py")
        file_member.size = 5

        class _FakeTar:
            def getmembers(self) -> list[tarfile.TarInfo]:
                return [pax_member, file_member]

            def extractfile(self, member: tarfile.TarInfo) -> BytesIO:
                if member is file_member:
                    return BytesIO(b"hello")
                raise AssertionError("PAX headers must not be extracted")

        index_snapshot._extract_defensively(_FakeTar(), tmp_path)  # type: ignore[arg-type]
        assert (tmp_path / "app.py").read_bytes() == b"hello"


# ============================================================================
# 4. lib/findings.py
# ============================================================================


class TestFinding:
    def test_omitted_end_line_and_column_default_to_start(self):
        f = findings.Finding(start_line=5, start_column=3)
        assert f.end_line == 5
        assert f.end_column == 3

    def test_explicit_end_line_and_column_are_preserved(self):
        f = findings.Finding(start_line=5, start_column=3, end_line=8, end_column=1)
        assert f.end_line == 8
        assert f.end_column == 1


class TestParseSecretsResults:
    def test_parses_sarif_result_with_cwe(self):
        payload = json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "generic/aws_key",
                                "level": "error",
                                "message": {"text": "AWS key"},
                                "properties": {"cwe": ["CWE-798"]},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {
                                                "startLine": 3,
                                                "startColumn": 5,
                                                "endLine": 3,
                                                "endColumn": 25,
                                            },
                                        }
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        )
        out = findings.parse_secrets_results(payload)
        assert out == [
            findings.Finding(
                id="generic/aws_key",
                title="Generic - Aws Key",
                severity="high",
                cwe="CWE-798",
                file_path="app.py",
                start_line=3,
                start_column=5,
                end_line=3,
                end_column=25,
            )
        ]

    def test_extracts_finding_id_from_real_cli_sample(self):
        # Verbatim shape from a real `snyk secrets test --json` run --
        # confirms the exact key: fingerprints["snyk/asset/finding/v1"]
        # (singular "asset" -- Snyk Code's own docs use "assets" at the
        # same key name for that product, don't assume they're the same).
        payload = json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "aws-access-token",
                                "level": "error",
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "demo/config.py"},
                                            "region": {
                                                "startLine": 2,
                                                "startColumn": 22,
                                                "endLine": 2,
                                                "endColumn": 42,
                                            },
                                        }
                                    }
                                ],
                                "fingerprints": {
                                    "identity": "UNDEFINED-1c283a56-23de-4478-bef3-e8ad6cb80e7a",
                                    "snyk/asset/finding/v1": (
                                        "UNDEFINED-1c283a56-23de-4478-bef3-e8ad6cb80e7a"
                                    ),
                                },
                            }
                        ]
                    }
                ]
            }
        )
        out = findings.parse_secrets_results(payload)
        assert out[0].finding_id == "UNDEFINED-1c283a56-23de-4478-bef3-e8ad6cb80e7a"

    def test_finding_id_absent_without_fingerprints(self):
        payload = json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "x",
                                "level": "error",
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {"startLine": 1, "startColumn": 1},
                                        }
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        )
        out = findings.parse_secrets_results(payload)
        assert out[0].finding_id is None

    def test_malformed_fingerprint_value_degrades_to_no_finding_id(self):
        # An unexpected shape (e.g. a non-string) must not abort the whole
        # scan over a hint-only field -- degrade to no ignore hint instead.
        payload = json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "x",
                                "level": "error",
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {"startLine": 1, "startColumn": 1},
                                        }
                                    }
                                ],
                                "fingerprints": {"snyk/asset/finding/v1": 12345},
                            }
                        ]
                    }
                ]
            }
        )
        out = findings.parse_secrets_results(payload)
        assert out is not None
        assert out[0].finding_id is None

    def test_malformed_fingerprints_shape_degrades_to_no_finding_id(self):
        # "fingerprints" itself can be present but not an object (e.g. a
        # producer that emits JSON null) -- same hint-only degradation as
        # a malformed value inside it, not a whole-scan parse failure.
        payload = json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "x",
                                "level": "error",
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {"startLine": 1, "startColumn": 1},
                                        }
                                    }
                                ],
                                "fingerprints": None,
                            }
                        ]
                    }
                ]
            }
        )
        out = findings.parse_secrets_results(payload)
        assert out is not None
        assert out[0].finding_id is None

    def test_accepted_suppression_marks_finding_ignored(self):
        # Verbatim shape from a real `snyk secrets test --json` run after
        # `snyk ignore create --remote-repo-url=...` against that finding.
        payload = json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "aws-access-token",
                                "level": "error",
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "demo/untouched.py"},
                                            "region": {
                                                "startLine": 3,
                                                "startColumn": 22,
                                                "endLine": 3,
                                                "endColumn": 42,
                                            },
                                        }
                                    }
                                ],
                                "fingerprints": {
                                    "identity": "d02aa386-ed36-5df1-8c33-e0cc97271bbe",
                                    "snyk/asset/finding/v1": "d02aa386-ed36-5df1-8c33-e0cc97271bbe",
                                },
                                "suppressions": [
                                    {
                                        "guid": "90d5da9a-01bf-4f9b-b6c4-a533aca9d9d4",
                                        "status": "accepted",
                                        "justification": "testing",
                                        "kind": "external",
                                        "properties": {
                                            "category": "not-vulnerable",
                                            "ignoredOn": "2026-08-12T16:26:44Z",
                                            "ignoredBy": {
                                                "name": "Jacob",
                                                "email": "jacob.boerma@snyk.io",
                                            },
                                        },
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        )
        out = findings.parse_secrets_results(payload)
        assert out is not None
        assert len(out) == 1
        assert out[0].suppression == "accepted"
        assert out[0].is_ignored is True

    def _finding_with_suppression_status(self, status):
        payload = json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "aws-access-token",
                                "level": "error",
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {"startLine": 1, "startColumn": 1},
                                        }
                                    }
                                ],
                                "suppressions": [{"status": status}],
                            }
                        ]
                    }
                ]
            }
        )
        out = findings.parse_secrets_results(payload)
        assert out is not None
        assert len(out) == 1
        return out[0]

    def test_under_review_suppression_is_not_ignored_but_is_flagged(self):
        finding = self._finding_with_suppression_status("underReview")
        assert finding.suppression == "underReview"
        assert finding.is_ignored is False
        assert finding.is_under_review is True

    def test_rejected_suppression_is_not_ignored_but_is_flagged(self):
        finding = self._finding_with_suppression_status("rejected")
        assert finding.suppression == "rejected"
        assert finding.is_ignored is False
        assert finding.is_rejected is True

    def test_missing_status_on_suppression_defaults_to_accepted(self):
        # SARIF 2.1: suppression.status defaults to "accepted" when absent.
        payload = json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "aws-access-token",
                                "level": "error",
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {"startLine": 1, "startColumn": 1},
                                        }
                                    }
                                ],
                                "suppressions": [{"guid": "abc123"}],
                            }
                        ]
                    }
                ]
            }
        )
        out = findings.parse_secrets_results(payload)
        assert out is not None
        assert len(out) == 1
        assert out[0].suppression == "accepted"
        assert out[0].is_ignored is True

    def test_no_suppression_is_none_status(self):
        payload = json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "x",
                                "level": "error",
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {"startLine": 1, "startColumn": 1},
                                        }
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        )
        out = findings.parse_secrets_results(payload)
        assert out is not None
        assert out[0].suppression == "none"

    def test_accepted_wins_over_under_review_on_same_result(self):
        # A result carrying more than one suppression entry shouldn't be
        # possible in practice, but if it happens, accepted must win.
        payload = json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "x",
                                "level": "error",
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {"startLine": 1, "startColumn": 1},
                                        }
                                    }
                                ],
                                "suppressions": [{"status": "underReview"}, {"status": "accepted"}],
                            }
                        ]
                    }
                ]
            }
        )
        out = findings.parse_secrets_results(payload)
        assert out is not None
        assert out[0].suppression == "accepted"

    def test_defaults_end_line_column_to_start_when_absent(self):
        # A SARIF producer that omits endLine/endColumn shouldn't yield an
        # ill-defined (0, 0) span.
        payload = json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "x",
                                "level": "error",
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "a.py"},
                                            "region": {"startLine": 7, "startColumn": 2},
                                        }
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        )
        out = findings.parse_secrets_results(payload)
        assert out[0].end_line == 7
        assert out[0].end_column == 2

    def test_missing_start_line_still_blocks_end_to_end(self):
        # A SARIF result with no region.startLine parses to start_line=0;
        # that finding must still make it through classification as
        # "added" (blocking), not get silently dropped as pre-existing.
        payload = json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "x",
                                "level": "error",
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {},
                                        }
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        )
        parsed = findings.parse_secrets_results(payload)
        assert parsed[0].start_line == 0
        added, pre, _ = diff_scope.split_added_vs_pre_existing(parsed, {"app.py": [(1, 10)]})
        assert added == parsed
        assert pre == []

    def test_priority_score_overrides_level_severity(self):
        payload = json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "x",
                                "level": "warning",
                                "properties": {"priorityScore": 900},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "a.py"},
                                            "region": {"startLine": 1},
                                        }
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        )
        out = findings.parse_secrets_results(payload)
        assert out[0].severity == "critical"

    def test_malformed_json_returns_none(self):
        # None (not []) -- callers must treat this as a scan failure, since
        # both would otherwise look identical to "genuinely zero findings".
        assert findings.parse_secrets_results("not json") is None

    def test_valid_json_wrong_top_level_type_returns_none(self):
        assert findings.parse_secrets_results("[]") is None
        assert findings.parse_secrets_results("null") is None
        assert findings.parse_secrets_results("42") is None

    def test_runs_not_a_list_of_objects_returns_none(self):
        assert findings.parse_secrets_results(json.dumps({"runs": "not-a-list"})) is None
        assert findings.parse_secrets_results(json.dumps({"runs": ["not-a-dict"]})) is None

    @pytest.mark.parametrize(
        "payload",
        [
            {"runs": [{"results": "not-a-list"}]},
            {"runs": [{"results": [{"ruleId": 123, "locations": []}]}]},
            {"runs": [{"results": [{"properties": {"priorityScore": True}, "locations": []}]}]},
            {"runs": [{"results": [{"properties": {"cwe": [123]}, "locations": []}]}]},
            {"runs": [{"results": [{"locations": ["not-a-location"]}]}]},
            {
                "runs": [
                    {
                        "results": [
                            {"locations": [{"physicalLocation": {"region": {"startLine": True}}}]}
                        ]
                    }
                ]
            },
        ],
    )
    def test_malformed_nested_sarif_shape_returns_none(self, payload):
        assert findings.parse_secrets_results(json.dumps(payload)) is None

    def test_well_formed_but_empty_results_is_a_real_empty_list(self):
        # Distinguishes "parsed fine, genuinely nothing to report" (a real
        # empty list) from the malformed-input cases above (None).
        assert findings.parse_secrets_results(json.dumps({"runs": []})) == []


class TestDeprecatedFlagWarnings:
    """Exercised against an isolated, synthetic registry -- real entries
    (SECRETS_FALLBACK_TO_WORKING_DIR onward) are swapped out for the
    duration of these tests so they can't leak in from a real shell env."""

    FAKE = deprecated_flags.DeprecatedFlag(
        name="SECRETS_TOTALLY_FAKE_FLAG", message="see the docs for what replaced it"
    )

    @pytest.fixture(autouse=True)
    def _isolated_registry(self, monkeypatch):
        monkeypatch.setattr(deprecated_flags, "_DEPRECATED_FLAGS", {self.FAKE.name: self.FAKE})

    def test_unset_flag_produces_no_warning(self, monkeypatch):
        monkeypatch.delenv(self.FAKE.name, raising=False)
        assert deprecated_flags.get_deprecated_flag_warnings() == []

    def test_set_flag_produces_one_warning_with_message(self, monkeypatch):
        monkeypatch.setenv(self.FAKE.name, "1")
        out = deprecated_flags.get_deprecated_flag_warnings()
        assert len(out) == 1
        assert self.FAKE.name in out[0]
        assert self.FAKE.message in out[0]

    def test_set_to_any_value_still_warns(self, monkeypatch):
        monkeypatch.setenv(self.FAKE.name, "0")
        assert len(deprecated_flags.get_deprecated_flag_warnings()) == 1

    def test_registration_order_is_preserved(self, monkeypatch):
        other = deprecated_flags.DeprecatedFlag(name="SECRETS_ANOTHER_FAKE_FLAG", message="x")
        monkeypatch.setattr(
            deprecated_flags, "_DEPRECATED_FLAGS", {self.FAKE.name: self.FAKE, other.name: other}
        )
        monkeypatch.setenv(self.FAKE.name, "1")
        monkeypatch.setenv(other.name, "1")
        out = deprecated_flags.get_deprecated_flag_warnings()
        assert [self.FAKE.name in line for line in out] == [True, False]


class TestRealDeprecatedFlags:
    """The actual registry -- one test per removed flag, added alongside
    the removal PR that registers it."""

    def test_fallback_to_working_dir_is_registered(self, monkeypatch):
        monkeypatch.setenv("SECRETS_FALLBACK_TO_WORKING_DIR", "1")
        out = deprecated_flags.get_deprecated_flag_warnings()
        assert any("SECRETS_FALLBACK_TO_WORKING_DIR" in line for line in out)

    def test_ignore_paths_is_registered(self, monkeypatch):
        monkeypatch.setenv("SECRETS_IGNORE_PATHS", "app.py")
        out = deprecated_flags.get_deprecated_flag_warnings()
        assert any(
            "SECRETS_IGNORE_PATHS" in line and "ignore request command" in line for line in out
        )

    def test_diff_strategy_is_registered(self, monkeypatch):
        monkeypatch.setenv("SECRETS_DIFF_STRATEGY", "line")
        out = deprecated_flags.get_deprecated_flag_warnings()
        assert any("SECRETS_DIFF_STRATEGY" in line for line in out)

    def test_min_block_severity_is_registered(self, monkeypatch):
        monkeypatch.setenv("SECRETS_MIN_BLOCK_SEVERITY", "high")
        out = deprecated_flags.get_deprecated_flag_warnings()
        assert any("SECRETS_MIN_BLOCK_SEVERITY" in line for line in out)


# ============================================================================
# 5. lib/snyk_cli.py
# ============================================================================


class TestNeedsShell:
    def test_cmd_needs_a_shell_on_windows(self, monkeypatch):
        monkeypatch.setattr(proc, "IS_WINDOWS", True)
        assert proc.needs_shell(r"C:\snyk\snyk.cmd")

    def test_bat_needs_a_shell_on_windows(self, monkeypatch):
        monkeypatch.setattr(proc, "IS_WINDOWS", True)
        assert proc.needs_shell(r"C:\snyk\snyk.bat")

    def test_case_insensitive_extension_match(self, monkeypatch):
        monkeypatch.setattr(proc, "IS_WINDOWS", True)
        assert proc.needs_shell(r"C:\snyk\SNYK.CMD")

    def test_exe_never_needs_a_shell_even_on_windows(self, monkeypatch):
        monkeypatch.setattr(proc, "IS_WINDOWS", True)
        assert not proc.needs_shell(r"C:\snyk\snyk.exe")

    def test_extensionless_never_needs_a_shell_even_on_windows(self, monkeypatch):
        monkeypatch.setattr(proc, "IS_WINDOWS", True)
        assert not proc.needs_shell("/usr/local/bin/snyk")

    def test_cmd_never_needs_a_shell_off_windows(self, monkeypatch):
        monkeypatch.setattr(proc, "IS_WINDOWS", False)
        assert not proc.needs_shell("/usr/local/bin/snyk.cmd")


class TestFindSnykBinary:
    """The sidecar lives under `~`, which the autouse `_isolate_home` fixture
    redirects -- so these write to the fake home rather than patch a path."""

    @staticmethod
    def _fake_cli(path: Path, *, executable: bool = True) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
        path.chmod(0o755 if executable else 0o644)
        return path

    @classmethod
    def _fake_cli_on_path(cls, bin_dir: Path) -> Path:
        # shutil.which() on Windows only matches PATHEXT suffixes, so an
        # extensionless `snyk` there would never be discovered.
        return cls._fake_cli(bin_dir / ("snyk.cmd" if os.name == "nt" else "snyk"))

    @staticmethod
    def _pin(target: str, *, encoding: str = "utf-8") -> Path:
        sidecar = Path(os.path.expanduser("~")) / ".snyk-studio" / "cli-path"
        sidecar.parent.mkdir(parents=True, exist_ok=True)
        sidecar.write_text(target, encoding=encoding)
        return sidecar

    def test_sidecar_pin_wins_over_path(self, monkeypatch, tmp_path):
        pinned = self._fake_cli(tmp_path / "standalone" / "snyk")
        self._pin(str(pinned))
        on_path = self._fake_cli_on_path(tmp_path / "npm-bin")
        monkeypatch.setenv("PATH", str(on_path.parent))
        assert snyk_cli.find_snyk_binary() == str(pinned)

    def test_bom_and_trailing_newline_in_sidecar_are_tolerated(self, monkeypatch, tmp_path):
        pinned = self._fake_cli(tmp_path / "standalone" / "snyk")
        self._pin(f"{pinned}\n", encoding="utf-8-sig")
        monkeypatch.setenv("PATH", "")
        assert snyk_cli.find_snyk_binary() == str(pinned)

    def test_missing_sidecar_falls_back_to_path(self, monkeypatch, tmp_path):
        on_path = self._fake_cli_on_path(tmp_path / "npm-bin")
        monkeypatch.setenv("PATH", str(on_path.parent))
        assert snyk_cli.find_snyk_binary() == str(on_path)

    def test_non_file_sidecar_does_not_fall_back_to_path(self, monkeypatch, tmp_path):
        sidecar = Path(os.path.expanduser("~")) / ".snyk-studio" / "cli-path"
        sidecar.parent.mkdir(parents=True, exist_ok=True)
        sidecar.mkdir()
        on_path = self._fake_cli_on_path(tmp_path / "npm-bin")
        monkeypatch.setenv("PATH", str(on_path.parent))
        assert snyk_cli.find_snyk_binary() is None

    def test_missing_pinned_cli_wins_over_path(self, monkeypatch, tmp_path):
        pinned = tmp_path / "uninstalled" / "snyk"
        self._pin(str(pinned))
        on_path = self._fake_cli_on_path(tmp_path / "npm-bin")
        monkeypatch.setenv("PATH", str(on_path.parent))
        assert snyk_cli.find_snyk_binary() == str(pinned)

    @pytest.mark.skipif(os.name == "nt", reason="X_OK is not meaningful on Windows")
    def test_non_executable_pin_wins_over_path(self, monkeypatch, tmp_path):
        pinned = self._fake_cli(tmp_path / "standalone" / "snyk", executable=False)
        self._pin(str(pinned))
        on_path = self._fake_cli_on_path(tmp_path / "npm-bin")
        monkeypatch.setenv("PATH", str(on_path.parent))
        assert snyk_cli.find_snyk_binary() == str(pinned)

    def test_relative_pin_is_resolved_from_the_hook_working_directory(self, monkeypatch, tmp_path):
        pinned = self._fake_cli(tmp_path / "cwd" / "snyk")
        monkeypatch.chdir(tmp_path / "cwd")
        self._pin("snyk")
        on_path = self._fake_cli_on_path(tmp_path / "npm-bin")
        monkeypatch.setenv("PATH", str(on_path.parent))
        assert snyk_cli.find_snyk_binary() == str(pinned)

    def test_pin_containing_shell_metacharacter_is_selected_for_a_cmd_on_windows(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setattr(proc, "IS_WINDOWS", True)
        pinned = self._fake_cli(tmp_path / "std&alone" / "snyk.cmd")
        self._pin(str(pinned))
        on_path = self._fake_cli_on_path(tmp_path / "npm-bin")
        monkeypatch.setenv("PATH", str(on_path.parent))
        assert snyk_cli.find_snyk_binary() == str(pinned)

    def test_pin_containing_shell_metacharacter_is_allowed_for_a_native_exe(
        self, monkeypatch, tmp_path
    ):
        # A native .exe never reaches a shell, even on Windows -- no
        # metacharacter in its path is unsafe.
        monkeypatch.setattr(proc, "IS_WINDOWS", True)
        pinned = self._fake_cli(tmp_path / "std&alone" / "snyk.exe")
        self._pin(str(pinned))
        assert snyk_cli.find_snyk_binary() == str(pinned)

    def test_path_resolved_cmd_binary_with_shell_metacharacter_is_rejected_on_windows(
        self, monkeypatch, tmp_path
    ):
        # A PATH-resolved .cmd reaches a shell=True subprocess call on
        # Windows -- only there is a metacharacter actually unsafe. Force
        # the candidate name list since it's normally frozen at import
        # time from the real platform, not the monkeypatched one.
        monkeypatch.setattr(proc, "IS_WINDOWS", True)
        monkeypatch.setattr(snyk_cli, "_SNYK_BINARY_NAMES", ["snyk.cmd"])
        monkeypatch.delenv("PATH", raising=False)
        on_path = self._fake_cli(tmp_path / "npm&bin" / "snyk.cmd")
        monkeypatch.setenv("PATH", str(on_path.parent))
        assert snyk_cli.find_snyk_binary() is None

    def test_path_resolved_cmd_binary_with_semicolon_is_rejected_on_windows(
        self, monkeypatch, tmp_path
    ):
        # cmd.exe treats ';' as an argument delimiter (like space or ','),
        # even though it's a legal character in a Windows directory name --
        # only a .cmd/.bat target reaches that shell (see needs_shell).
        monkeypatch.setattr(proc, "IS_WINDOWS", True)
        monkeypatch.setattr(snyk_cli, "_SNYK_BINARY_NAMES", ["snyk.cmd"])
        monkeypatch.delenv("PATH", raising=False)
        on_path = self._fake_cli(tmp_path / "npm;bin" / "snyk.cmd")
        monkeypatch.setenv("PATH", str(on_path.parent))
        assert snyk_cli.find_snyk_binary() is None

    def test_path_resolved_exe_binary_with_shell_metacharacter_is_allowed_on_windows(
        self, monkeypatch, tmp_path
    ):
        # A native .exe never reaches a shell, even on Windows.
        monkeypatch.setattr(proc, "IS_WINDOWS", True)
        monkeypatch.setattr(snyk_cli, "_SNYK_BINARY_NAMES", ["snyk.exe"])
        monkeypatch.delenv("PATH", raising=False)
        on_path = self._fake_cli(tmp_path / "npm&bin" / "snyk.exe")
        monkeypatch.setenv("PATH", str(on_path.parent))
        assert snyk_cli.find_snyk_binary() == str(on_path)

    def test_path_resolved_binary_with_shell_metacharacter_is_allowed_off_windows(
        self, monkeypatch, tmp_path
    ):
        # shell=False off Windows -- a `&` in the path is a literal, safe
        # character, not shell syntax, so it must not be rejected there.
        monkeypatch.setattr(proc, "IS_WINDOWS", False)
        monkeypatch.delenv("PATH", raising=False)
        on_path = self._fake_cli_on_path(tmp_path / "npm&bin")
        monkeypatch.setenv("PATH", str(on_path.parent))
        assert snyk_cli.find_snyk_binary() == str(on_path)

    def test_pinned_dir_is_prepended_to_scan_env_path(self, tmp_path):
        pinned = self._fake_cli(tmp_path / "standalone" / "snyk")
        self._pin(str(pinned))
        env = {"PATH": "/usr/bin"}
        snyk_cli._augment_path_for_snyk(env)
        assert env["PATH"].split(os.pathsep)[0] == str(pinned.parent)

    def test_pinned_dir_already_on_path_is_moved_to_the_front(self, tmp_path):
        # Merely being on PATH isn't enough: an npm dir ahead of it would still
        # win for a `snyk` the CLI shells out to.
        pinned = self._fake_cli(tmp_path / "standalone" / "snyk")
        self._pin(str(pinned))
        env = {"PATH": os.pathsep.join(["/usr/bin", str(pinned.parent)])}
        snyk_cli._augment_path_for_snyk(env)
        entries = env["PATH"].split(os.pathsep)
        assert entries[0] == str(pinned.parent)
        assert entries.count(str(pinned.parent)) == 1

    def test_empty_path_gains_no_trailing_separator(self, tmp_path):
        # A trailing separator leaves an empty entry, which means cwd on
        # POSIX -- during a scan that is the snapshot being committed.
        pinned = self._fake_cli(tmp_path / "standalone" / "snyk")
        self._pin(str(pinned))
        env = {}
        snyk_cli._augment_path_for_snyk(env)
        assert env["PATH"] == str(pinned.parent)

    def test_probed_dir_prepend_leaves_no_empty_path_entry(self, monkeypatch, tmp_path):
        probed = self._fake_cli_on_path(tmp_path / "probed-bin")
        monkeypatch.setattr(snyk_cli, "_search_paths_unix", lambda env: [str(probed.parent)])
        monkeypatch.setattr(snyk_cli, "_search_paths_windows", lambda env: [str(probed.parent)])
        env = {"PATH": ""}
        snyk_cli._augment_path_for_snyk(env)
        assert env["PATH"] == str(probed.parent)

    def test_scan_env_carries_pinned_dir(self, monkeypatch, tmp_path):
        pinned = self._fake_cli(tmp_path / "standalone" / "snyk")
        self._pin(str(pinned))
        monkeypatch.setenv("PATH", "/usr/bin")
        assert snyk_cli.build_snyk_env()["PATH"].split(os.pathsep)[0] == str(pinned.parent)

    def test_discovered_cli_dir_is_prepended_to_scan_env(self, monkeypatch, tmp_path):
        earlier = self._fake_cli(tmp_path / "earlier" / "snyk")
        discovered = self._fake_cli(tmp_path / "selected" / "snyk")
        monkeypatch.setenv("PATH", os.pathsep.join([str(earlier.parent), "/usr/bin"]))
        env = snyk_cli.build_snyk_env(str(discovered))
        assert env["PATH"].split(os.pathsep)[0] == str(discovered.parent)

    def test_stale_sidecar_is_named_in_the_not_found_message(self, tmp_path):
        missing = tmp_path / "uninstalled" / "snyk"
        sidecar = self._pin(str(missing))
        message = secrets_hook._cli_not_found_message()
        assert str(sidecar) in message
        # The pinned value too, so the user doesn't have to cat the file to
        # learn which of the three unusable cases they hit.
        assert str(missing) in message
        assert "npm install" not in message

    def test_empty_sidecar_message_reads_without_a_pinned_value(self, tmp_path):
        sidecar = self._pin("  \n")
        message = secrets_hook._cli_not_found_message()
        assert f"{sidecar} is empty or unreadable" in message

    def test_unreadable_sidecar_is_reported_under_debug(self, monkeypatch, capsys):
        # Undecodable bytes stand in for any unreadable sidecar (EACCES too):
        # silently falling back to PATH runs the CLI the user opted out of.
        self._pin("")
        (Path(os.path.expanduser("~")) / ".snyk-studio" / "cli-path").write_bytes(b"\xff\xfe/snyk")
        monkeypatch.setenv("SECRETS_HOOK_DEBUG", "1")
        assert snyk_cli._snyk_cli_from_sidecar() is None
        assert "could not be read" in capsys.readouterr().err

    def test_unreadable_sidecar_does_not_augment_path(self, monkeypatch, tmp_path):
        self._pin("")
        sidecar = Path(os.path.expanduser("~")) / ".snyk-studio" / "cli-path"
        sidecar.write_bytes(b"\xff\xfe/snyk")
        monkeypatch.setattr(snyk_cli, "_search_paths_unix", lambda _env: [str(tmp_path)])
        env = {"PATH": ""}
        snyk_cli._augment_path_for_snyk(env)
        assert env["PATH"] == ""

    def test_interior_empty_path_entry_is_dropped(self, tmp_path):
        pinned = self._fake_cli(tmp_path / "standalone" / "snyk")
        self._pin(str(pinned))
        env = {"PATH": os.pathsep.join(["/usr/bin", "", "/bin"])}
        snyk_cli._augment_path_for_snyk(env)
        assert "" not in env["PATH"].split(os.pathsep)

    def test_pin_problem_names_the_failed_check(self, tmp_path):
        missing = tmp_path / "gone" / "snyk"
        assert snyk_cli._pin_problem(str(missing)) == f'pins "{missing}", which does not exist'
        assert snyk_cli._pin_problem("") == "is empty or unreadable"
        assert snyk_cli._pin_problem(str(self._fake_cli(tmp_path / "ok" / "snyk"))) is None

    def test_pin_problem_accepts_a_relative_path(self, monkeypatch, tmp_path):
        pinned = self._fake_cli(tmp_path / "bin" / "snyk")
        monkeypatch.chdir(pinned.parent)
        assert snyk_cli._pin_problem("snyk") is None

    def test_pin_problem_allows_shell_characters(self, tmp_path):
        pinned = self._fake_cli(tmp_path / "std&alone" / "snyk.cmd")
        assert snyk_cli._pin_problem(str(pinned)) is None

    @pytest.mark.skipif(os.name == "nt", reason="X_OK is not meaningful on Windows")
    def test_pin_problem_reports_a_non_executable_pin(self, tmp_path):
        pinned = self._fake_cli(tmp_path / "standalone" / "snyk", executable=False)
        assert snyk_cli._pin_problem(str(pinned)) == f'pins "{pinned}", which is not executable'

    def test_windows_style_pin_is_not_backslash_escaped(self):
        # repr() would double the separators, leaving a path the user can't
        # paste back into --cli-path. Not absolute on POSIX, so still stale.
        pinned = r"C:\Program Files\Snyk\snyk.exe"
        self._pin(pinned)
        assert pinned in secrets_hook._cli_not_found_message()

    def test_stale_message_does_not_claim_path_was_checked(self, tmp_path):
        self._pin(str(tmp_path / "uninstalled" / "snyk"))
        message = secrets_hook._cli_not_found_message()
        assert "delete" not in message
        assert "no snyk on PATH either" not in message
        assert "contact your Snyk administrator" in message

    def test_not_found_message_without_a_sidecar_suggests_npm(self):
        assert "npm install -g snyk" in secrets_hook._cli_not_found_message()


class TestCheckSnykAuth:
    @staticmethod
    def _write_config(config_home: Path, payload: str, *, encoding: str = "utf-8") -> None:
        config_dir = config_home / "configstore"
        config_dir.mkdir(parents=True)
        (config_dir / "snyk.json").write_text(payload, encoding=encoding)

    def test_snyk_token_env_var_takes_precedence(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SNYK_TOKEN", "env-token")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        assert snyk_cli.check_snyk_auth() == "env-token"

    def test_reads_api_key_from_config_file(self, monkeypatch, tmp_path):
        monkeypatch.delenv("SNYK_TOKEN", raising=False)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        self._write_config(tmp_path, json.dumps({"api": "file-token"}))
        assert snyk_cli.check_snyk_auth() == "file-token"

    def test_oauth_marker_without_api_key_returns_sentinel(self, monkeypatch, tmp_path):
        monkeypatch.delenv("SNYK_TOKEN", raising=False)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        self._write_config(tmp_path, json.dumps({"INTERNAL_OAUTH_TOKEN_STORAGE": "present"}))
        assert snyk_cli.check_snyk_auth() == "__oauth__"

    def test_missing_config_file_returns_none(self, monkeypatch, tmp_path):
        monkeypatch.delenv("SNYK_TOKEN", raising=False)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        assert snyk_cli.check_snyk_auth() is None

    def test_relative_xdg_config_home_is_rejected(self, monkeypatch, tmp_path):
        monkeypatch.delenv("SNYK_TOKEN", raising=False)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("XDG_CONFIG_HOME", "controlled-config")
        config_dir = tmp_path / "controlled-config" / "configstore"
        config_dir.mkdir(parents=True)
        (config_dir / "snyk.json").write_text('{"api": "untrusted-token"}')
        with pytest.raises(snyk_cli.InvalidConfigError, match="must be an absolute path"):
            snyk_cli.check_snyk_auth()

    def test_malformed_config_json_returns_none(self, monkeypatch, tmp_path):
        monkeypatch.delenv("SNYK_TOKEN", raising=False)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        self._write_config(tmp_path, "not json")
        assert snyk_cli.check_snyk_auth() is None

    def test_bom_prefixed_config_file_still_parses(self, monkeypatch, tmp_path):
        # Some Windows tooling writes a UTF-8 BOM; plain utf-8 decoding
        # would leave it in the string and break json.load, silently
        # reporting "not authenticated" even with a real token present.
        monkeypatch.delenv("SNYK_TOKEN", raising=False)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        self._write_config(tmp_path, json.dumps({"api": "file-token"}), encoding="utf-8-sig")
        assert snyk_cli.check_snyk_auth() == "file-token"


class TestRunSecretsScan:
    def test_passes_timeout_to_subprocess(self, monkeypatch, tmp_path):
        captured = {}

        def fake_run(*args, **kwargs):
            captured.update(kwargs)
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="{}", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        snyk_cli.run_secrets_scan(tmp_path, snyk_cli.ScanInvocation(), timeout=3.5)
        assert captured["timeout"] == 3.5

    def test_scan_uses_workspace_root_as_single_snyk_input(self, monkeypatch, tmp_path):
        """Also the "no remote_url" case: ScanInvocation.remote_url
        defaults to None, and the argv has no --remote-repo-url flag."""
        captured = {}
        clean_sarif = json.dumps({"runs": [{"results": []}]})

        def fake_run(*args, **kwargs):
            captured["args"] = args[0]
            return subprocess.CompletedProcess(args=[], returncode=0, stdout=clean_sarif, stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        status, out = snyk_cli.run_secrets_scan(tmp_path, snyk_cli.ScanInvocation(), timeout=1)
        assert status == "success"
        assert out == []
        assert captured["args"] == ["snyk", "secrets", "test", ".", "--json"]

    def test_includes_remote_repo_url_flag_when_set(self, monkeypatch, tmp_path):
        captured = {}

        def fake_run(*args, **kwargs):
            captured["args"] = args[0]
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="{}", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        invocation = snyk_cli.ScanInvocation(remote_url="git@github.com:acme/repo.git")
        snyk_cli.run_secrets_scan(tmp_path, invocation, timeout=1)
        assert captured["args"] == [
            "snyk",
            "secrets",
            "test",
            ".",
            "--json",
            "--remote-repo-url=git@github.com:acme/repo.git",
        ]

    def test_timeout_expired_yields_timeout_status(self, monkeypatch, tmp_path):
        def fake_run(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd="snyk", timeout=1)

        monkeypatch.setattr(subprocess, "run", fake_run)
        status, out = snyk_cli.run_secrets_scan(tmp_path, snyk_cli.ScanInvocation(), timeout=1)
        assert status == "timeout"
        assert out == []

    def test_auth_error_pattern_classified(self, monkeypatch, tmp_path):
        def fake_run(*args, **kwargs):
            return subprocess.CompletedProcess(
                args=[], returncode=2, stdout="", stderr="MissingApiTokenError: run snyk auth"
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(snyk_cli.AuthRequiredError):
            snyk_cli.run_secrets_scan(tmp_path, snyk_cli.ScanInvocation(), timeout=1)

    def test_auth_error_pattern_classified_for_real_cli_message(self, monkeypatch, tmp_path):
        # The actual message this CLI version emits when unauthenticated
        # (confirmed by running it directly) -- didn't match any pre-existing
        # pattern, so this pins the fix down.
        def fake_run(*args, **kwargs):
            return subprocess.CompletedProcess(
                args=[],
                returncode=2,
                stdout="",
                stderr='{"ok": false, "error": "Use `snyk auth` to authenticate.", "path": "."}',
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(snyk_cli.AuthRequiredError) as exc_info:
            snyk_cli.run_secrets_scan(tmp_path, snyk_cli.ScanInvocation(), timeout=1)
        assert exc_info.value.message == "Use `snyk auth` to authenticate."

    def test_not_entitled_pattern_captures_cli_message(self, monkeypatch, tmp_path):
        def fake_run(*args, **kwargs):
            return subprocess.CompletedProcess(
                args=[],
                returncode=2,
                stdout=(
                    '{"ok": false, "error": "Snyk Secrets is not supported for org '
                    'abc: enable it in Settings > Snyk Secrets", "path": "."}'
                ),
                stderr="",
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(snyk_cli.NotEntitledError) as exc_info:
            snyk_cli.run_secrets_scan(tmp_path, snyk_cli.ScanInvocation(), timeout=1)
        assert exc_info.value.message == (
            "Snyk Secrets is not supported for org abc: enable it in Settings > Snyk Secrets"
        )

    def test_not_entitled_message_unescapes_json_html_chars(self, monkeypatch, tmp_path):
        # Go's encoding/json HTML-escapes < > & by default -- the CLI's raw
        # `--json` output literally contains ">", not a real ">".
        # Real JSON parsing must undo that.
        def fake_run(*args, **kwargs):
            return subprocess.CompletedProcess(
                args=[],
                returncode=2,
                stdout=(
                    '{"ok": false, "error": "Snyk Secrets is not supported for org '
                    'abc: enable it in Settings \\u003e Snyk Secrets", "path": "."}'
                ),
                stderr="",
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(snyk_cli.NotEntitledError) as exc_info:
            snyk_cli.run_secrets_scan(tmp_path, snyk_cli.ScanInvocation(), timeout=1)
        assert exc_info.value.message == (
            "Snyk Secrets is not supported for org abc: enable it in Settings > Snyk Secrets"
        )

    def test_not_entitled_pattern_without_valid_json_raises_with_no_message(
        self, monkeypatch, tmp_path
    ):
        def fake_run(*args, **kwargs):
            return subprocess.CompletedProcess(
                args=[],
                returncode=2,
                stdout="Snyk Secrets is not supported for org -- not valid json",
                stderr="",
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(snyk_cli.NotEntitledError) as exc_info:
            snyk_cli.run_secrets_scan(tmp_path, snyk_cli.ScanInvocation(), timeout=1)
        assert exc_info.value.message is None

    def test_entitlement_check_failed_pattern_raises(self, monkeypatch, tmp_path):
        def fake_run(*args, **kwargs):
            return subprocess.CompletedProcess(
                args=[],
                returncode=2,
                stdout=(
                    '{"ok": false, "error": "Workflow execution failed: Unable to '
                    'check if the Secrets feature is enabled.: some cause", "path": "."}'
                ),
                stderr="",
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(snyk_cli.EntitlementCheckFailedError) as exc_info:
            snyk_cli.run_secrets_scan(tmp_path, snyk_cli.ScanInvocation(), timeout=1)
        assert exc_info.value.message == (
            "Workflow execution failed: Unable to check if the Secrets feature is enabled.: "
            "some cause"
        )

    def test_no_supported_files_pattern_raises_permanent_failure(self, monkeypatch, tmp_path):
        def fake_run(*args, **kwargs):
            return subprocess.CompletedProcess(
                args=[],
                returncode=2,
                stdout='{"ok": false, "error": "No supported files found.", "path": "."}',
                stderr="",
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(snyk_cli.PermanentScanFailureError) as exc_info:
            snyk_cli.run_secrets_scan(tmp_path, snyk_cli.ScanInvocation(), timeout=1)
        assert exc_info.value.message == "No supported files found."
        assert exc_info.value.fallback == (
            "Snyk couldn't detect any supported files to scan; confirm you are committing "
            "the intended files"
        )

    def test_file_count_limit_pattern_raises_permanent_failure(self, monkeypatch, tmp_path):
        def fake_run(*args, **kwargs):
            return subprocess.CompletedProcess(
                args=[],
                returncode=2,
                stdout=(
                    '{"ok": false, "error": "File count limit reached: too many files: '
                    '550 exceeds limit of 500", "path": "."}'
                ),
                stderr="",
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(snyk_cli.PermanentScanFailureError) as exc_info:
            snyk_cli.run_secrets_scan(tmp_path, snyk_cli.ScanInvocation(), timeout=1)
        assert exc_info.value.fallback == (
            "this commit has more files than Snyk Secrets can scan at once -- try "
            "committing in smaller batches"
        )

    def test_size_limit_pattern_raises_permanent_failure(self, monkeypatch, tmp_path):
        def fake_run(*args, **kwargs):
            return subprocess.CompletedProcess(
                args=[],
                returncode=2,
                stdout=(
                    '{"ok": false, "error": "file big.bin size 900000000 exceeds limit '
                    'of 800000000 bytes", "path": "."}'
                ),
                stderr="",
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(snyk_cli.PermanentScanFailureError) as exc_info:
            snyk_cli.run_secrets_scan(tmp_path, snyk_cli.ScanInvocation(), timeout=1)
        assert exc_info.value.fallback == (
            "a file (or the total commit) is too large for Snyk Secrets to scan"
        )

    def test_invalid_remote_url_pattern_raises_permanent_failure(self, monkeypatch, tmp_path):
        def fake_run(*args, **kwargs):
            return subprocess.CompletedProcess(
                args=[],
                returncode=2,
                stdout=(
                    '{"ok": false, "error": "Invalid --remote-repo-url: must be a valid '
                    'git URL (e.g., ...)", "path": "."}'
                ),
                stderr="",
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(snyk_cli.PermanentScanFailureError) as exc_info:
            snyk_cli.run_secrets_scan(tmp_path, snyk_cli.ScanInvocation(), timeout=1)
        assert exc_info.value.fallback == (
            "the detected git remote URL isn't valid for Snyk Secrets -- check "
            "`git remote get-url origin`"
        )

    def test_no_org_pattern_raises_permanent_failure(self, monkeypatch, tmp_path):
        def fake_run(*args, **kwargs):
            return subprocess.CompletedProcess(
                args=[],
                returncode=2,
                stdout='{"ok": false, "error": "No org provided.", "path": "."}',
                stderr="",
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(snyk_cli.PermanentScanFailureError) as exc_info:
            snyk_cli.run_secrets_scan(tmp_path, snyk_cli.ScanInvocation(), timeout=1)
        assert exc_info.value.fallback == (
            "Snyk couldn't determine which org to scan against -- run "
            "`snyk config set org=<your-org-id>`, or ask your Snyk administrator"
        )

    def test_malformed_stdout_on_success_exit_code_is_an_error_not_a_clean_scan(
        self, monkeypatch, tmp_path
    ):
        """A 0/1 exit code with unparseable stdout (e.g. output truncated,
        or a stray warning mixed into stdout ahead of the JSON) must not be
        treated the same as a real, clean scan -- that would silently let
        an unscanned commit through."""

        def fake_run(*args, **kwargs):
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="not json", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        status, out = snyk_cli.run_secrets_scan(tmp_path, snyk_cli.ScanInvocation(), timeout=1)
        assert status == "unparseable"
        assert out == []

    def test_never_uses_a_shell(self, monkeypatch, tmp_path):
        captured = {}

        def fake_run(*args, **kwargs):
            captured.update(kwargs)
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="{}", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        snyk_cli.run_secrets_scan(tmp_path, snyk_cli.ScanInvocation(needs_shell=True), timeout=1)
        assert captured["shell"] is False
        assert captured["creationflags"] == proc.CREATE_NO_WINDOW

    def test_windows_uses_an_explicit_cmd_launcher(self, monkeypatch, tmp_path):
        captured = {}

        def fake_run(*args, **kwargs):
            captured["args"] = args[0]
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="{}", stderr="")

        monkeypatch.setattr(proc, "IS_WINDOWS", True)
        monkeypatch.setattr(subprocess, "run", fake_run)
        snyk_cli.run_secrets_scan(tmp_path, snyk_cli.ScanInvocation(needs_shell=True), timeout=1)
        assert captured["args"][:3] == ["cmd.exe", "/d", "/s"]

    def test_windows_drops_an_unsafe_remote_url(self, monkeypatch, tmp_path):
        captured = {}

        def fake_run(*args, **kwargs):
            captured["args"] = args[0]
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="{}", stderr="")

        monkeypatch.setattr(proc, "IS_WINDOWS", True)
        monkeypatch.setattr(subprocess, "run", fake_run)
        invocation = snyk_cli.ScanInvocation(remote_url="https://example.test/repo&calc.exe")
        snyk_cli.run_secrets_scan(tmp_path, invocation, timeout=1)
        assert "--remote-repo-url" not in captured["args"][-1]


class TestRunSecretsScanWithRetries:
    def test_retries_transient_error_then_succeeds(self, monkeypatch, tmp_path):
        results = [("error", []), ("error", []), ("success", [])]

        def fake_scan(workspace, invocation, timeout):
            return results.pop(0)

        monkeypatch.setattr(snyk_cli, "run_secrets_scan", fake_scan)
        invocation = snyk_cli.ScanInvocation()
        attempt = snyk_cli.run_secrets_scan_with_retries(
            tmp_path, invocation, time.monotonic() + 30
        )
        assert (attempt.status, attempt.attempts) == ("success", 3)

    def test_gives_up_after_max_attempts(self, monkeypatch, tmp_path):
        calls = []

        def fake_scan(workspace, invocation, timeout):
            calls.append(1)
            return "error", []

        monkeypatch.setattr(snyk_cli, "run_secrets_scan", fake_scan)
        invocation = snyk_cli.ScanInvocation()
        attempt = snyk_cli.run_secrets_scan_with_retries(
            tmp_path, invocation, time.monotonic() + 30
        )
        assert (attempt.status, attempt.attempts) == (
            "retries_exhausted",
            snyk_cli.MAX_SCAN_ATTEMPTS,
        )
        assert len(calls) == snyk_cli.MAX_SCAN_ATTEMPTS

    def test_no_new_attempt_once_deadline_has_passed(self, monkeypatch, tmp_path):
        calls = []

        def fake_scan(workspace, invocation, timeout):
            calls.append(1)
            return "error", []

        monkeypatch.setattr(snyk_cli, "run_secrets_scan", fake_scan)
        invocation = snyk_cli.ScanInvocation()
        attempt = snyk_cli.run_secrets_scan_with_retries(tmp_path, invocation, time.monotonic() - 1)
        assert (attempt.status, attempt.attempts) == ("timeout", 0)
        assert calls == []

    def test_unparseable_is_not_retried(self, monkeypatch, tmp_path):
        calls = []

        def fake_scan(workspace, invocation, timeout):
            calls.append(1)
            return "unparseable", []

        monkeypatch.setattr(snyk_cli, "run_secrets_scan", fake_scan)
        invocation = snyk_cli.ScanInvocation()
        attempt = snyk_cli.run_secrets_scan_with_retries(
            tmp_path, invocation, time.monotonic() + 30
        )
        assert (attempt.status, attempt.attempts) == ("unparseable", 1)
        assert len(calls) == 1

    def test_auth_required_is_not_retried(self, monkeypatch, tmp_path):
        calls = []

        def fake_scan(workspace, invocation, timeout):
            calls.append(1)
            raise snyk_cli.AuthRequiredError("abc")

        monkeypatch.setattr(snyk_cli, "run_secrets_scan", fake_scan)
        invocation = snyk_cli.ScanInvocation()
        with pytest.raises(snyk_cli.AuthRequiredError):
            snyk_cli.run_secrets_scan_with_retries(tmp_path, invocation, time.monotonic() + 30)
        assert len(calls) == 1

    def test_not_entitled_is_not_retried(self, monkeypatch, tmp_path):
        calls = []

        def fake_scan(workspace, invocation, timeout):
            calls.append(1)
            raise snyk_cli.NotEntitledError("abc")

        monkeypatch.setattr(snyk_cli, "run_secrets_scan", fake_scan)
        invocation = snyk_cli.ScanInvocation()
        with pytest.raises(snyk_cli.NotEntitledError):
            snyk_cli.run_secrets_scan_with_retries(tmp_path, invocation, time.monotonic() + 30)
        assert len(calls) == 1

    def test_entitlement_check_failed_is_not_retried(self, monkeypatch, tmp_path):
        calls = []

        def fake_scan(workspace, invocation, timeout):
            calls.append(1)
            raise snyk_cli.EntitlementCheckFailedError()

        monkeypatch.setattr(snyk_cli, "run_secrets_scan", fake_scan)
        invocation = snyk_cli.ScanInvocation()
        with pytest.raises(snyk_cli.EntitlementCheckFailedError):
            snyk_cli.run_secrets_scan_with_retries(tmp_path, invocation, time.monotonic() + 30)
        assert len(calls) == 1

    def test_permanent_scan_failure_is_not_retried(self, monkeypatch, tmp_path):
        calls = []

        def fake_scan(workspace, invocation, timeout):
            calls.append(1)
            raise snyk_cli.PermanentScanFailureError("fallback wording", "abc")

        monkeypatch.setattr(snyk_cli, "run_secrets_scan", fake_scan)
        invocation = snyk_cli.ScanInvocation()
        with pytest.raises(snyk_cli.PermanentScanFailureError):
            snyk_cli.run_secrets_scan_with_retries(tmp_path, invocation, time.monotonic() + 30)
        assert len(calls) == 1

    def test_passes_invocation_through_to_run_secrets_scan(self, monkeypatch, tmp_path):
        received = []

        def fake_scan(workspace, invocation, timeout):
            received.append(invocation)
            return "success", []

        monkeypatch.setattr(snyk_cli, "run_secrets_scan", fake_scan)
        invocation = snyk_cli.ScanInvocation(remote_url="git@github.com:acme/repo.git")
        snyk_cli.run_secrets_scan_with_retries(tmp_path, invocation, time.monotonic() + 30)
        assert received == [invocation]


class TestRunConcurrentScans:
    def test_both_scans_invoked_with_their_own_workspace(self, monkeypatch, tmp_path):
        calls = []

        def fake_run_secrets_scan(workspace, invocation, timeout):
            calls.append(workspace)
            return "success", []

        monkeypatch.setattr(snyk_cli, "run_secrets_scan", fake_run_secrets_scan)
        current_dir, baseline_dir = tmp_path / "current", tmp_path / "baseline"
        invocation = snyk_cli.ScanInvocation()
        snyk_cli.run_concurrent_scans(current_dir, baseline_dir, invocation, time.monotonic() + 5)
        assert current_dir in calls
        assert baseline_dir in calls

    def test_both_lanes_receive_the_same_invocation(self, monkeypatch, tmp_path):
        """Both lanes are snapshots of the same real repo, so both must
        resolve to the same --remote-repo-url -- not two independently
        computed values that could drift apart."""
        received = {}

        def fake_run_secrets_scan(workspace, invocation, timeout):
            received[str(workspace)] = invocation
            return "success", []

        monkeypatch.setattr(snyk_cli, "run_secrets_scan", fake_run_secrets_scan)
        current_dir, baseline_dir = tmp_path / "current", tmp_path / "baseline"
        invocation = snyk_cli.ScanInvocation(remote_url="git@github.com:acme/repo.git")
        snyk_cli.run_concurrent_scans(current_dir, baseline_dir, invocation, time.monotonic() + 5)
        assert received[str(current_dir)] == invocation
        assert received[str(baseline_dir)] == invocation

    def test_results_returned_in_current_baseline_order(self, monkeypatch, tmp_path):
        def fake_run_secrets_scan(workspace, invocation, timeout):
            return ("success", []) if "current" in str(workspace) else ("timeout", [])

        monkeypatch.setattr(snyk_cli, "run_secrets_scan", fake_run_secrets_scan)
        invocation = snyk_cli.ScanInvocation()
        (current_result, baseline_result) = snyk_cli.run_concurrent_scans(
            tmp_path / "current", tmp_path / "baseline", invocation, time.monotonic() + 5
        )
        assert (current_result.status, current_result.findings) == ("success", [])
        assert (baseline_result.status, baseline_result.findings) == ("timeout", [])

    def test_runs_concurrently_not_sequentially(self, monkeypatch, tmp_path):
        # Sequential would take >= 2x the sleep; concurrent ~= 1x.
        sleep_seconds = 0.2

        def fake_run_secrets_scan(workspace, invocation, timeout):
            time.sleep(sleep_seconds)
            return "success", []

        monkeypatch.setattr(snyk_cli, "run_secrets_scan", fake_run_secrets_scan)
        invocation = snyk_cli.ScanInvocation()
        start = time.monotonic()
        snyk_cli.run_concurrent_scans(
            tmp_path / "current", tmp_path / "baseline", invocation, time.monotonic() + 5
        )
        elapsed = time.monotonic() - start
        assert elapsed < sleep_seconds * 1.75

    def test_bounded_even_if_a_lane_ignores_its_own_deadline(self, monkeypatch, tmp_path):
        """A lane's own subprocess.run(timeout=...) is what actually kills
        a hung `snyk` process in production -- this proves the *wrapper*
        around both lanes doesn't hang even if a lane's thread somehow
        never returns, by never actually respecting the shrinking
        `remaining` timeout it's given."""
        hang_seconds = 0.3

        def _ignores_its_own_timeout(workspace, invocation, timeout):
            time.sleep(hang_seconds)
            return "success", []

        monkeypatch.setattr(snyk_cli, "run_secrets_scan", _ignores_its_own_timeout)
        monkeypatch.setattr(snyk_cli, "RESULT_GRACE_SECONDS", 0.05)
        deadline = time.monotonic() + 0.05

        start = time.monotonic()
        invocation = snyk_cli.ScanInvocation()
        current, baseline = snyk_cli.run_concurrent_scans(
            tmp_path / "current", tmp_path / "baseline", invocation, deadline
        )
        elapsed = time.monotonic() - start

        assert elapsed < hang_seconds  # returned well before the hang finished
        assert current.status == "timeout"
        assert baseline.status == "timeout"
        # Real attempt count is unknown (the thread never returned), but it
        # was actively scanning -- report 1, not a misleading 0.
        assert current.attempts == 1
        assert baseline.attempts == 1

    def test_expected_exceptions_propagate_unwrapped(self, monkeypatch, tmp_path):
        def fake_run_secrets_scan(workspace, invocation, timeout):
            raise snyk_cli.NotEntitledError("org not entitled")

        monkeypatch.setattr(snyk_cli, "run_secrets_scan", fake_run_secrets_scan)
        invocation = snyk_cli.ScanInvocation()
        with pytest.raises(snyk_cli.NotEntitledError) as exc_info:
            snyk_cli.run_concurrent_scans(
                tmp_path / "current", tmp_path / "baseline", invocation, time.monotonic() + 5
            )
        assert exc_info.value.message == "org not entitled"

    def test_baseline_expected_exception_falls_back_to_an_error_result(self, monkeypatch, tmp_path):
        current_workspace = tmp_path / "current"
        baseline_workspace = tmp_path / "baseline"

        def fake_run_secrets_scan(workspace, invocation, timeout):
            if workspace == baseline_workspace:
                raise snyk_cli.PermanentScanFailureError("too many files")
            return "success", []

        monkeypatch.setattr(snyk_cli, "run_secrets_scan", fake_run_secrets_scan)
        current, baseline = snyk_cli.run_concurrent_scans(
            current_workspace,
            baseline_workspace,
            snyk_cli.ScanInvocation(),
            time.monotonic() + 5,
        )
        assert current.status == "success"
        assert baseline.status == "error"

    def test_baseline_exception_propagates_when_current_scan_failed(self, monkeypatch, tmp_path):
        current_workspace = tmp_path / "current"
        baseline_workspace = tmp_path / "baseline"

        def fake_run_secrets_scan(workspace, invocation, timeout):
            if workspace == baseline_workspace:
                raise snyk_cli.AuthRequiredError("authenticate")
            return "error", []

        monkeypatch.setattr(snyk_cli, "run_secrets_scan", fake_run_secrets_scan)
        with pytest.raises(snyk_cli.AuthRequiredError):
            snyk_cli.run_concurrent_scans(
                current_workspace,
                baseline_workspace,
                snyk_cli.ScanInvocation(),
                time.monotonic() + 5,
            )

    def test_unexpected_exception_is_wrapped(self, monkeypatch, tmp_path):
        def fake_run_secrets_scan(workspace, invocation, timeout):
            raise RuntimeError("boom")

        monkeypatch.setattr(snyk_cli, "run_secrets_scan", fake_run_secrets_scan)
        invocation = snyk_cli.ScanInvocation()
        with pytest.raises(snyk_cli.UnexpectedScanError) as exc_info:
            snyk_cli.run_concurrent_scans(
                tmp_path / "current", tmp_path / "baseline", invocation, time.monotonic() + 5
            )
        assert str(exc_info.value) == "RuntimeError: boom"
        assert isinstance(exc_info.value.__cause__, RuntimeError)


# ============================================================================
# 6. lib/report.py
# ============================================================================


class TestPrintFindings:
    def test_prints_compiler_style_diagnostic_line(self, capsys):
        report.print_findings(
            [
                findings.Finding(
                    id="x",
                    title="X",
                    severity="high",
                    file_path="a.py",
                    start_line=1,
                    start_column=1,
                )
            ]
        )
        err = capsys.readouterr().err
        assert "  - a.py(1,1):" in err
        assert "[high]" in err
        assert "bypass" not in err

    def test_empty_findings_prints_nothing(self, capsys):
        report.print_findings([])
        assert capsys.readouterr().err == ""

    def test_prints_ready_to_run_ignore_command_when_id_and_remote_present(self, capsys):
        report.print_findings(
            [
                findings.Finding(
                    id="x",
                    title="X",
                    severity="high",
                    file_path="a.py",
                    start_line=1,
                    start_column=1,
                    finding_id="abc123-def456",
                )
            ],
            remote_url="git@github.com:acme/repo.git",
        )
        err = capsys.readouterr().err
        assert (
            "snyk ignore create --finding-id=abc123-def456 "
            "--remote-repo-url=git@github.com:acme/repo.git" in err
        )

    def test_ignore_command_quotes_a_remote_url_with_spaces(self, capsys):
        # A local filesystem remote can contain spaces -- the command must
        # stay copy-pasteable (its whole reason for never being wrapped).
        report.print_findings(
            [
                findings.Finding(
                    id="x",
                    title="X",
                    severity="high",
                    file_path="a.py",
                    start_line=1,
                    start_column=1,
                    finding_id="abc123-def456",
                )
            ],
            remote_url="/Users/me/my repo/.git",
        )
        err = capsys.readouterr().err
        assert "--remote-repo-url='/Users/me/my repo/.git'" in err

    def test_ignore_command_neutralizes_shell_metacharacters_in_remote_url(self, capsys):
        # remote_url comes from `git config --get remote.origin.url` --
        # not trusted input. A double-quote wrap alone doesn't stop
        # $(...) from executing on paste; real shell quoting does.
        report.print_findings(
            [
                findings.Finding(
                    id="x",
                    title="X",
                    severity="high",
                    file_path="a.py",
                    start_line=1,
                    start_column=1,
                    finding_id="abc123-def456",
                )
            ],
            remote_url="https://x.example/$(touch pwned)",
        )
        err = capsys.readouterr().err
        # Single-quoted: the whole thing is one shell word, so $(...)
        # is inert literal text rather than executable substitution.
        assert "--remote-repo-url='https://x.example/$(touch pwned)'" in err

    def test_ignore_command_quoting_is_not_gated_on_is_windows(self, monkeypatch, capsys):
        # Quoting must stay POSIX-style even when IS_WINDOWS is True.
        monkeypatch.setattr(proc, "IS_WINDOWS", True)
        report.print_findings(
            [
                findings.Finding(
                    id="x",
                    title="X",
                    severity="high",
                    file_path="a.py",
                    start_line=1,
                    start_column=1,
                    finding_id="abc123-def456",
                )
            ],
            remote_url="https://x.example/$(touch pwned)",
        )
        err = capsys.readouterr().err
        assert "--remote-repo-url='https://x.example/$(touch pwned)'" in err

    def test_no_ignore_command_line_for_undefined_prefixed_id(self, capsys):
        # Confirmed against a real `snyk ignore create` run: the CLI rejects
        # an UNDEFINED-<uuid> fingerprint outright as an invalid UUID, so
        # it's never usable -- omit the command rather than show one
        # guaranteed to fail.
        report.print_findings(
            [
                findings.Finding(
                    id="x",
                    title="X",
                    severity="high",
                    file_path="a.py",
                    start_line=1,
                    start_column=1,
                    finding_id="UNDEFINED-abc123",
                )
            ],
            remote_url="git@github.com:acme/repo.git",
        )
        assert "snyk ignore create" not in capsys.readouterr().err

    def test_no_ignore_command_line_without_finding_id(self, capsys):
        report.print_findings(
            [
                findings.Finding(
                    id="x",
                    title="X",
                    severity="high",
                    file_path="a.py",
                    start_line=1,
                    start_column=1,
                )
            ],
            remote_url="git@github.com:acme/repo.git",
        )
        assert "snyk ignore create" not in capsys.readouterr().err

    def test_no_ignore_command_line_without_remote_url(self, capsys):
        report.print_findings(
            [
                findings.Finding(
                    id="x",
                    title="X",
                    severity="high",
                    file_path="a.py",
                    start_line=1,
                    start_column=1,
                    finding_id="abc123",
                )
            ],
            remote_url=None,
        )
        assert "snyk ignore create" not in capsys.readouterr().err

    def test_under_review_finding_shows_tag_and_no_ignore_command(self, capsys):
        report.print_findings(
            [
                findings.Finding(
                    id="x",
                    title="X",
                    severity="high",
                    file_path="a.py",
                    start_line=1,
                    start_column=1,
                    finding_id="abc123",
                    suppression="underReview",
                )
            ],
            remote_url="git@github.com:acme/repo.git",
        )
        err = capsys.readouterr().err
        assert "(ignore request pending review)" in err
        assert "snyk ignore create" not in err

    def test_rejected_finding_shows_tag_and_still_shows_ignore_command(self, capsys):
        report.print_findings(
            [
                findings.Finding(
                    id="x",
                    title="X",
                    severity="high",
                    file_path="a.py",
                    start_line=1,
                    start_column=1,
                    finding_id="abc123",
                    suppression="rejected",
                )
            ],
            remote_url="git@github.com:acme/repo.git",
        )
        err = capsys.readouterr().err
        assert "(a previous ignore request was rejected)" in err
        assert "snyk ignore create --finding-id=abc123" in err

    def test_ignored_finding_shows_tag_and_no_ignore_command(self, capsys):
        report.print_findings(
            [
                findings.Finding(
                    id="x",
                    title="X",
                    severity="high",
                    file_path="a.py",
                    start_line=1,
                    start_column=1,
                    finding_id="abc123",
                    suppression="accepted",
                )
            ],
            remote_url="git@github.com:acme/repo.git",
        )
        err = capsys.readouterr().err
        assert "(already ignored)" in err
        assert "snyk ignore create" not in err

    def test_multi_finding_group_shows_each_findings_own_command(self, capsys):
        report.print_findings(
            [
                findings.Finding(
                    id="x",
                    title="X",
                    severity="high",
                    file_path="a.py",
                    start_line=1,
                    start_column=1,
                    finding_id="id-1",
                ),
                findings.Finding(
                    id="y",
                    title="Y",
                    severity="medium",
                    file_path="a.py",
                    start_line=1,
                    start_column=1,
                    finding_id="id-2",
                ),
            ],
            remote_url="git@github.com:acme/repo.git",
        )
        err = capsys.readouterr().err
        assert "snyk ignore create --finding-id=id-1" in err
        assert "snyk ignore create --finding-id=id-2" in err

    def test_color_off_when_not_a_tty(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        assert report.supports_color() is False

    def test_color_off_when_no_color_set(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert report.supports_color() is False

    def test_suppression_tag_colors_by_status(self):
        under_review = findings.Finding(
            id="x", file_path="a.py", start_line=1, suppression="underReview"
        )
        rejected = findings.Finding(id="x", file_path="a.py", start_line=1, suppression="rejected")
        ignored = findings.Finding(id="x", file_path="a.py", start_line=1, suppression="accepted")

        assert report._suppression_tag(under_review, color=True) == (
            " \033[33m(ignore request pending review)\033[0m"
        )
        assert report._suppression_tag(rejected, color=True) == (
            " \033[31m(a previous ignore request was rejected)\033[0m"
        )
        assert report._suppression_tag(ignored, color=True) == " \033[2m(already ignored)\033[0m"

    def test_suppression_tag_uncolored_when_color_off(self):
        under_review = findings.Finding(
            id="x", file_path="a.py", start_line=1, suppression="underReview"
        )
        tag = report._suppression_tag(under_review, color=False)
        assert tag == " (ignore request pending review)"
        assert "\033" not in tag

    def test_dim_group_wraps_whole_line_not_just_the_tag(self, monkeypatch, capsys):
        # dim=True must override per-severity coloring too -- otherwise a
        # "not blocking" group still has a red/yellow severity word
        # fighting the gray, un-blocking signal.
        monkeypatch.setattr(report, "supports_color", lambda: True)
        finding = findings.Finding(
            id="x",
            title="X",
            severity="critical",
            file_path="a.py",
            start_line=1,
            start_column=1,
            suppression="accepted",
        )
        report.print_findings([finding], remote_url="git@github.com:acme/repo.git", dim=True)
        err = capsys.readouterr().err
        assert err.startswith(report._ANSI_DIM)
        assert err.rstrip("\n").endswith(report._ANSI_RESET)
        # No nested color codes inside -- severity/tag coloring is
        # suppressed when the whole line is already being dimmed.
        assert err.count("\033") == 2


# ============================================================================
# 7. lib/timing.py
# ============================================================================


class TestTimer:
    def test_segment_ms_nonnegative_and_ordered(self):
        t = timing.Timer()
        t.mark("a")
        t.mark("b")
        assert t.segment_ms("start", "a") is not None
        assert t.segment_ms("start", "a") >= 0
        assert t.total_ms() >= t.segment_ms("start", "a")

    def test_segment_ms_unknown_mark_is_none(self):
        t = timing.Timer()
        assert t.segment_ms("start", "nope") is None


class TestSummaryLine:
    """The closing "done in ..." line for a *successful* scan -- a scan
    failure's own message (see _handle_scan_failure/_fail_open_or_block in
    snyk_secrets_at_commit.py) is a complete statement on its own and never
    goes through this function. The bypass hint lives on the caller's
    opening "Scanning..." line instead, so it never appears here."""

    def test_clean_success_says_no_secrets_found(self):
        line = timing.summary_line(timing.Timer(), 0)
        assert line.endswith("no secrets found")

    def test_blocking_omits_bypass(self):
        line = timing.summary_line(timing.Timer(), 1)
        assert "1 finding blocking commit" in line
        assert "bypass" not in line

    def test_blocking_pluralizes(self):
        line = timing.summary_line(timing.Timer(), 2)
        assert "2 findings blocking commit" in line

    def test_added_ignored_count_zero_is_unchanged(self):
        # The default -- no already-ignored findings mixed in -- must
        # produce exactly today's wording, byte for byte.
        line = timing.summary_line(timing.Timer(), 3, under_review_count=1)
        assert line.endswith("3 findings blocking commit (1 already under review)")

    def test_added_ignored_count_reconciles_with_the_printed_list(self):
        # 3 blocking + 1 already-ignored means 4 findings were actually
        # introduced -- say so, instead of a bare "3 blocking" that reads
        # as inconsistent next to 4 printed lines.
        line = timing.summary_line(timing.Timer(), 3, under_review_count=1, added_ignored_count=1)
        assert line.endswith(
            "4 new findings introduced, 3 blocking (1 already under review), 1 already ignored"
        )

    def test_added_ignored_count_without_under_review(self):
        line = timing.summary_line(timing.Timer(), 1, added_ignored_count=1)
        assert line.endswith("2 new findings introduced, 1 blocking, 1 already ignored")

    def test_added_ignored_count_reconciles_even_when_nothing_blocks(self):
        # Nothing is blocking, but a new finding was still introduced (and
        # covered by an existing ignore) -- "no secrets found" would
        # contradict that.
        line = timing.summary_line(timing.Timer(), 0, added_ignored_count=1)
        assert line.endswith("1 new finding introduced, 0 blocking, 1 already ignored")
        assert "no secrets found" not in line

    def test_summary_line_omits_pre_existing_detail(self):
        # Detail belongs to history_line; the headline stays consistent.
        line = timing.summary_line(timing.Timer(), 0, pre_existing_count=1)
        assert line.endswith("no blocking secrets found")
        assert "pre-existing" not in line

    def test_summary_line_removed_count_also_avoids_no_secrets_found(self):
        # A cleanup-only run still has history to report.
        line = timing.summary_line(timing.Timer(), 0, removed_count=1)
        assert line.endswith("no blocking secrets found")

    def test_summary_line_truly_nothing_says_no_secrets_found(self):
        line = timing.summary_line(timing.Timer(), 0, pre_existing_count=0, removed_count=0)
        assert line.endswith("no secrets found")

    def test_highlight_blocking_colors_only_the_blocking_clause(self):
        line = timing.summary_line(timing.Timer(), 2, highlight_blocking=True)
        colored = f"{timing._ANSI_BOLD_RED}2 findings blocking{timing._ANSI_RESET}"
        assert line.endswith(f"{colored} commit")

    def test_highlight_blocking_is_absent_when_nothing_blocks(self):
        line = timing.summary_line(
            timing.Timer(), 0, added_ignored_count=1, highlight_blocking=True
        )
        assert "\033[" not in line


class TestHistoryLine:
    def test_nothing_to_report_is_empty(self):
        assert timing.history_line(0, 0) == ""

    def test_pre_existing_only_singular(self):
        assert timing.history_line(1, 0) == "history: 1 pre-existing finding"

    def test_pre_existing_only_plural(self):
        assert timing.history_line(2, 0) == "history: 2 pre-existing findings"

    def test_removed_only_singular(self):
        assert timing.history_line(0, 1) == "history: 1 secret cleaned up"

    def test_removed_only_plural(self):
        assert timing.history_line(0, 2) == "history: 2 secrets cleaned up"

    def test_both_combined(self):
        assert timing.history_line(1, 1) == "history: 1 pre-existing finding, 1 secret cleaned up"


# ============================================================================
# 8. lib/git_ops.py (re-exported by the entry script -- see its imports)
# + fail-open/fail-closed contract
# ============================================================================


class TestGetStagedFiles:
    def test_returns_none_on_subprocess_oserror(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            proc.subprocess, "run", lambda *a, **kw: (_ for _ in ()).throw(OSError("x"))
        )
        assert secrets_hook.get_staged_files(tmp_path) is None

    def test_returns_none_on_subprocess_timeout(self, monkeypatch, tmp_path):
        # A hung git process (stale lock, slow/network filesystem, ...)
        # must not hang the whole commit -- see proc.GIT_TIMEOUT.
        monkeypatch.setattr(
            proc.subprocess,
            "run",
            lambda *a, **kw: (_ for _ in ()).throw(
                subprocess.TimeoutExpired(cmd="git", timeout=kw.get("timeout"))
            ),
        )
        assert secrets_hook.get_staged_files(tmp_path) is None

    def test_git_calls_are_bounded_by_git_timeout(self, monkeypatch, tmp_path):
        captured = {}

        def fake_run(*args, **kwargs):
            captured.update(kwargs)
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        monkeypatch.setattr(proc.subprocess, "run", fake_run)
        secrets_hook.get_staged_files(tmp_path)
        assert captured["timeout"] == proc.GIT_TIMEOUT

    def test_no_deadline_left_skips_the_call_entirely(self, monkeypatch, tmp_path):
        # Proves the shared-deadline budget actually gates git calls, not
        # just the scan subprocess: no time left means no process spawned.
        called = []
        monkeypatch.setattr(proc.subprocess, "run", lambda *a, **kw: called.append(1))
        already_passed = time.monotonic() - 1
        assert git_ops.get_staged_files(tmp_path, already_passed) is None
        assert called == []

    def test_deadline_shrinks_the_subprocess_timeout_below_git_timeout(self, monkeypatch, tmp_path):
        captured = {}

        def fake_run(*args, **kwargs):
            captured.update(kwargs)
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        monkeypatch.setattr(proc.subprocess, "run", fake_run)
        short_deadline = time.monotonic() + 2.0  # well under GIT_TIMEOUT
        git_ops.get_staged_files(tmp_path, short_deadline)
        assert captured["timeout"] < proc.GIT_TIMEOUT
        assert captured["timeout"] <= 2.0

    def test_returns_none_on_nonzero_exit(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            proc.subprocess,
            "run",
            lambda *a, **kw: subprocess.CompletedProcess(
                args=[], returncode=128, stdout="", stderr="fatal"
            ),
        )
        assert secrets_hook.get_staged_files(tmp_path) is None

    def test_real_repo_lists_staged_file(self, repo):
        _stage(repo, "app.py", "x\n")
        assert secrets_hook.get_staged_files(repo) == ["app.py"]

    def test_empty_repo_no_head_yet(self, tmp_path):
        """First commit ever: no HEAD, git diff --cached still works (empty-tree diff)."""
        _init_git_repo(tmp_path)
        _stage(tmp_path, "app.py", "x\n")
        assert secrets_hook.get_staged_files(tmp_path) == ["app.py"]


class TestGetAddedLineRanges:
    def test_returns_none_on_nonzero_exit(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            proc.subprocess,
            "run",
            lambda *a, **kw: subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="fatal"
            ),
        )
        assert secrets_hook.get_added_line_ranges(tmp_path) is None

    def test_real_repo_new_file_is_whole_file_range(self, repo):
        _stage(repo, "app.py", "one\ntwo\n")
        ranges, binary_files = secrets_hook.get_added_line_ranges(repo)
        assert ranges == {"app.py": [(1, 2)]}
        assert binary_files == []

    def test_empty_repo_no_head_yet(self, tmp_path):
        _init_git_repo(tmp_path)
        _stage(tmp_path, "app.py", "one\n")
        ranges, binary_files = secrets_hook.get_added_line_ranges(tmp_path)
        assert ranges == {"app.py": [(1, 1)]}
        assert binary_files == []

    def test_new_binary_file_gets_sentinel_range(self, repo):
        (repo / "secret.bin").write_bytes(b"\x00\x01AKIA_FAKE\x02\x03")
        subprocess.run(["git", "add", "secret.bin"], cwd=repo, check=True)
        ranges, binary_files = secrets_hook.get_added_line_ranges(repo)
        assert ranges["secret.bin"] == [diff_scope.BINARY_SENTINEL_RANGE]
        assert binary_files == ["secret.bin"]


class TestGetBinaryFiles:
    """Real git repos throughout -- pins down git's actual --numstat -z
    output shape rather than a guess at it."""

    def test_new_binary_file_is_detected(self, repo):
        (repo / "secret.bin").write_bytes(b"\x00\x01binary\x02\x03")
        subprocess.run(["git", "add", "secret.bin"], cwd=repo, check=True)
        assert git_ops.get_binary_files(repo) == {"secret.bin"}

    def test_binary_file_modified_in_place_is_detected(self, repo):
        (repo / "secret.bin").write_bytes(b"\x00\x01one\x02\x03")
        subprocess.run(["git", "add", "secret.bin"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "add binary"], cwd=repo, check=True)
        (repo / "secret.bin").write_bytes(b"\x00\x01two\x02\x03")
        subprocess.run(["git", "add", "secret.bin"], cwd=repo, check=True)
        assert git_ops.get_binary_files(repo) == {"secret.bin"}

    def test_text_file_is_not_flagged(self, repo):
        _stage(repo, "app.py", "one\ntwo\n")
        assert git_ops.get_binary_files(repo) == set()

    def test_pure_rename_of_binary_file_is_still_flagged(self, repo):
        # Confirmed against real git: the binary marker is about content
        # *type*, not whether bytes changed -- a byte-identical rename of
        # a binary file still reports "-"/"-" in numstat. That's fine:
        # BINARY_SENTINEL_RANGE then treats the whole file as added,
        # which can only ever over-block (a pre-existing secret in an
        # untouched rename), never under-block -- consistent with this
        # hook's conservative-only design.
        (repo / "a.bin").write_bytes(b"\x00\x01same\x02\x03")
        subprocess.run(["git", "add", "a.bin"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "add a"], cwd=repo, check=True)
        subprocess.run(["git", "mv", "a.bin", "b.bin"], cwd=repo, check=True)
        assert git_ops.get_binary_files(repo) == {"b.bin"}

    def test_pure_rename_of_text_file_is_not_flagged(self, repo):
        _stage(repo, "a.py", "line1\nline2\n")
        subprocess.run(["git", "commit", "-q", "-m", "add a"], cwd=repo, check=True)
        subprocess.run(["git", "mv", "a.py", "b.py"], cwd=repo, check=True)
        assert git_ops.get_binary_files(repo) == set()

    def test_renamed_and_edited_binary_is_detected_under_new_path(self, repo):
        (repo / "a.bin").write_bytes(b"\x00\x01one\x02\x03")
        subprocess.run(["git", "add", "a.bin"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "add a"], cwd=repo, check=True)
        subprocess.run(["git", "mv", "a.bin", "b.bin"], cwd=repo, check=True)
        (repo / "b.bin").write_bytes(b"\x00\x01two\x02\x03")
        subprocess.run(["git", "add", "b.bin"], cwd=repo, check=True)
        assert git_ops.get_binary_files(repo) == {"b.bin"}

    def test_git_failure_fails_soft_to_empty_set(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            proc.subprocess,
            "run",
            lambda *a, **kw: subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="fatal"
            ),
        )
        assert git_ops.get_binary_files(tmp_path) == set()

    @pytest.mark.skipif(os.name == "nt", reason="chmod +x has no effect on Windows")
    def test_mode_only_change_is_not_flagged_as_binary(self, repo):
        # A mode-only change has zero content lines to count, so numstat
        # reports 0/0 -- not the "-"/"-" binary marker.
        _stage(repo, "script.sh", "echo hi\n")
        subprocess.run(["git", "commit", "-q", "-m", "add script"], cwd=repo, check=True)
        (repo / "script.sh").chmod(0o755)
        subprocess.run(["git", "add", "script.sh"], cwd=repo, check=True)
        assert git_ops.get_binary_files(repo) == set()
        ranges, binary_files = secrets_hook.get_added_line_ranges(repo)
        assert ranges == {}
        assert binary_files == []


class TestGetRenameMap:
    """Real git repos throughout, not mocked output -- pins down git's
    actual similarity-detection behavior."""

    def test_pure_rename_no_content_change(self, repo):
        _stage(repo, "a.py", "line1\nline2\nline3\n")
        subprocess.run(["git", "commit", "-q", "-m", "add a"], cwd=repo, check=True)
        subprocess.run(["git", "mv", "a.py", "b.py"], cwd=repo, check=True)
        assert secrets_hook.get_rename_map(repo) == {"b.py": "a.py"}

    def test_renamed_and_edited_elsewhere_still_detected(self, repo):
        # One extra line on five unchanged stays well above git's 50%
        # similarity threshold for --find-renames.
        _stage(repo, "a.py", "line1\nline2\nline3\nline4\nline5\n")
        subprocess.run(["git", "commit", "-q", "-m", "add a"], cwd=repo, check=True)
        subprocess.run(["git", "mv", "a.py", "b.py"], cwd=repo, check=True)
        (repo / "b.py").write_text("line1\nline2\nline3\nline4\nline5\nextra line\n")
        subprocess.run(["git", "add", "b.py"], cwd=repo, check=True)
        assert secrets_hook.get_rename_map(repo) == {"b.py": "a.py"}

    def test_renamed_below_similarity_threshold_is_not_detected(self, repo):
        # Rewriting virtually all the content drops similarity below 50%,
        # so git itself stops calling this a rename -- no entry in the map.
        _stage(repo, "a.py", "line1\nline2\nline3\nline4\nline5\n")
        subprocess.run(["git", "commit", "-q", "-m", "add a"], cwd=repo, check=True)
        subprocess.run(["git", "mv", "a.py", "b.py"], cwd=repo, check=True)
        (repo / "b.py").write_text(
            "totally different content\nnothing shared\nwith the original at all\n"
        )
        subprocess.run(["git", "add", "b.py"], cwd=repo, check=True)
        assert secrets_hook.get_rename_map(repo) == {}

    def test_multiple_simultaneous_renames(self, repo):
        _stage(repo, "a.py", "content a\n")
        _stage(repo, "c.py", "content c\n")
        subprocess.run(["git", "commit", "-q", "-m", "add a and c"], cwd=repo, check=True)
        subprocess.run(["git", "mv", "a.py", "b.py"], cwd=repo, check=True)
        subprocess.run(["git", "mv", "c.py", "d.py"], cwd=repo, check=True)
        assert secrets_hook.get_rename_map(repo) == {"b.py": "a.py", "d.py": "c.py"}

    def test_no_renames_staged_yields_empty_map(self, repo):
        _stage(repo, "a.py", "one\n")
        assert secrets_hook.get_rename_map(repo) == {}

    def test_git_failure_yields_empty_map_not_prereq_failure(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            proc.subprocess,
            "run",
            lambda *a, **kw: subprocess.CompletedProcess(
                args=[], returncode=128, stdout="", stderr="fatal"
            ),
        )
        assert secrets_hook.get_rename_map(tmp_path) == {}


class TestGetRemoteUrl:
    """Real git repos throughout -- this is the value later passed as
    --remote-repo-url to the scan and to `snyk ignore create`, so it must
    reflect the real repo's origin, not the scan's scratch workspace.

    get_remote_url() itself never judges shell-safety -- that depends on
    which Snyk binary ends up resolved, not known yet at this point (see
    is_safe_for_shell, applied once needs_shell is known)."""

    def test_no_origin_remote_yields_unavailable(self, repo):
        decision = git_ops.get_remote_url(repo)
        assert decision.url is None
        assert decision.status == "unavailable"

    def test_returns_origin_remote_url(self, repo):
        subprocess.run(
            ["git", "remote", "add", "origin", "git@github.com:acme/repo.git"],
            cwd=repo,
            check=True,
        )
        decision = git_ops.get_remote_url(repo)
        assert decision.url == "git@github.com:acme/repo.git"
        assert decision.status == "ok"

    def test_exhausted_deadline_yields_unavailable_not_unbounded_wait(self, repo):
        subprocess.run(
            ["git", "remote", "add", "origin", "git@github.com:acme/repo.git"],
            cwd=repo,
            check=True,
        )
        already_passed = time.monotonic() - 1
        decision = git_ops.get_remote_url(repo, already_passed)
        assert decision.url is None
        assert decision.status == "unavailable"

    @pytest.mark.parametrize(
        "url",
        [
            "https://github.com/acme/repo.git",
            "git@github.com:acme/repo.git",
            "ssh://git@host.example.com:2222/acme/repo.git",
            "file:///Users/me/repos/repo.git",
        ],
    )
    def test_realistic_remote_url_forms_pass_through(self, repo, url):
        subprocess.run(["git", "remote", "add", "origin", url], cwd=repo, check=True)
        assert git_ops.get_remote_url(repo).url == url

    @pytest.mark.parametrize(
        "url",
        [
            "https://example.com&calc.exe",
            "https://example.com|whoami",
            "https://example.com^whoami",
            "https://example.com;rm -rf /",
            "https://example.com`whoami`",
            "https://example.com$(whoami)",
        ],
    )
    def test_shell_unsafe_urls_still_pass_through_raw(self, repo, url):
        # get_remote_url() doesn't reject on characters -- see
        # TestIsSafeForShell below for the actual safety check, applied
        # only once a shell is known to be involved.
        subprocess.run(["git", "remote", "add", "origin", url], cwd=repo, check=True)
        assert git_ops.get_remote_url(repo).url == url


class TestIsSafeForShell:
    @pytest.mark.parametrize(
        "url",
        [
            "https://github.com/acme/repo.git",
            "git@github.com:acme/repo.git",
            "ssh://git@host.example.com:2222/acme/repo.git",
            "file:///Users/me/repos/repo.git",
        ],
    )
    def test_realistic_remote_url_forms_are_safe(self, url):
        assert git_ops.is_safe_for_shell(url)

    @pytest.mark.parametrize(
        "url",
        [
            "https://example.com&calc.exe",
            "https://example.com|whoami",
            "https://example.com^whoami",
            "https://example.com;rm -rf /",
            "https://example.com`whoami`",
            "https://example.com$(whoami)",
        ],
    )
    def test_shell_metacharacters_are_unsafe(self, url):
        # This value flows into run_secrets_scan's argv, which runs with
        # shell=True when the resolved Snyk CLI is a .cmd/.bat -- cmd.exe
        # would interpret these characters rather than treat them as a
        # literal URL.
        assert not git_ops.is_safe_for_shell(url)


class TestRemoteUrlDecision:
    def test_unavailable_has_no_url(self):
        decision = git_ops.RemoteUrlDecision.unavailable()
        assert decision.url is None
        assert decision.status == "unavailable"

    def test_ok_carries_the_url(self):
        decision = git_ops.RemoteUrlDecision.ok("git@github.com:acme/repo.git")
        assert decision.url == "git@github.com:acme/repo.git"
        assert decision.status == "ok"

    def test_rejected_downgrades_ok_to_no_url(self):
        decision = git_ops.RemoteUrlDecision.ok("https://example.com&calc.exe").rejected()
        assert decision.url is None
        assert decision.status == "rejected_unsafe"


class TestResolveScanScope:
    def test_outside_git_repo_is_prereq_failure(self, tmp_path):
        scope, early_exit = secrets_hook.resolve_scan_scope(tmp_path, time.monotonic() + 90)
        assert scope is None
        assert early_exit == secrets_hook.EXIT_PREREQ

    def test_populates_files_and_ranges(self, repo):
        _stage(repo, "app.py", "one\ntwo\n")
        scope, early_exit = secrets_hook.resolve_scan_scope(repo, time.monotonic() + 90)
        assert early_exit is None
        assert scope.files == ["app.py"]
        assert scope.ranges == {"app.py": [(1, 2)]}

    def test_renames_empty_by_default(self, repo):
        _stage(repo, "app.py", "one\n")
        scope, _ = secrets_hook.resolve_scan_scope(repo, time.monotonic() + 90)
        assert scope.renames == {}

    def test_remote_url_unavailable_without_origin(self, repo):
        _stage(repo, "app.py", "one\n")
        scope, _ = secrets_hook.resolve_scan_scope(repo, time.monotonic() + 90)
        assert scope.remote_url.url is None
        assert scope.remote_url.status == "unavailable"

    def test_remote_url_populated_from_origin(self, repo):
        subprocess.run(
            ["git", "remote", "add", "origin", "git@github.com:acme/repo.git"],
            cwd=repo,
            check=True,
        )
        _stage(repo, "app.py", "one\n")
        scope, _ = secrets_hook.resolve_scan_scope(repo, time.monotonic() + 90)
        assert scope.remote_url.url == "git@github.com:acme/repo.git"

    def test_needs_renames_false_skips_the_extra_git_call(self, repo, monkeypatch):
        _stage(repo, "app.py", "one\n")
        called = []
        monkeypatch.setattr(secrets_hook, "get_rename_map", lambda *a, **kw: called.append(1) or {})
        secrets_hook.resolve_scan_scope(repo, time.monotonic() + 90, needs_renames=False)
        assert called == []

    def test_needs_renames_true_populates_renames(self, repo):
        _stage(repo, "a.py", "one\ntwo\n")
        subprocess.run(["git", "commit", "-q", "-m", "add a"], cwd=repo, check=True)
        subprocess.run(["git", "mv", "a.py", "b.py"], cwd=repo, check=True)
        scope, early_exit = secrets_hook.resolve_scan_scope(
            repo, time.monotonic() + 90, needs_renames=True
        )
        assert early_exit is None
        assert scope.renames == {"b.py": "a.py"}

    def test_exhausted_deadline_is_prereq_failure_not_unbounded_wait(self, repo):
        # Proves resolve_scan_scope's git calls actually share the same
        # budget as the scan step, not their own separate GIT_TIMEOUT --
        # an already-exhausted deadline fails closed immediately.
        _stage(repo, "app.py", "one\n")
        already_passed = time.monotonic() - 1
        scope, early_exit = secrets_hook.resolve_scan_scope(repo, already_passed)
        assert scope is None
        assert early_exit == secrets_hook.EXIT_PREREQ


class TestMainFailClosed:
    def test_outside_git_repo_is_prereq_failure(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)  # not a git repo
        assert secrets_hook.main([]) == secrets_hook.EXIT_PREREQ

    def test_git_diff_failure_is_prereq_failure(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        monkeypatch.setattr(secrets_hook, "get_staged_files", lambda *a, **kw: None)
        assert secrets_hook.main([]) == secrets_hook.EXIT_PREREQ

    def test_added_line_range_failure_is_prereq_failure(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        monkeypatch.setattr(secrets_hook, "get_staged_files", lambda *a, **kw: ["app.py"])
        monkeypatch.setattr(secrets_hook, "get_added_line_ranges", lambda *a, **kw: None)
        assert secrets_hook.main([]) == secrets_hook.EXIT_PREREQ

    def test_no_staged_files_is_ok(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        monkeypatch.setattr(secrets_hook, "get_staged_files", lambda *a, **kw: [])
        assert secrets_hook.main([]) == secrets_hook.EXIT_OK


class TestScanFailureDefaultsToFailClosed:
    @pytest.fixture(autouse=True)
    def _stub_prereqs(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        monkeypatch.setattr(secrets_hook, "find_repo_root", lambda _: tmp_path)
        monkeypatch.setattr(secrets_hook, "get_staged_files", lambda *a, **kw: ["app.py"])
        monkeypatch.setattr(secrets_hook, "get_added_line_ranges", lambda *a, **kw: ({}, []))
        monkeypatch.setattr(secrets_hook, "find_snyk_binary", lambda: "/usr/bin/snyk")
        monkeypatch.setattr(secrets_hook, "check_snyk_auth", lambda: "token")
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan_with_retries",
            lambda *a, **kw: snyk_cli.ScanAttempt("timeout", [], 1),
        )
        snapshot_dir = tmp_path / "staged-snapshot"
        snapshot_dir.mkdir()

        @contextmanager
        def _fake_snapshot(repo_root, files, deadline=None):
            yield snapshot_dir

        monkeypatch.setattr(
            secrets_hook, "staged_snapshot", lambda *a, **kw: _fake_snapshot(*a, **kw)
        )

    def test_default_blocks_commit(self, monkeypatch):
        monkeypatch.delenv("SECRETS_BLOCK_ON_SCAN_FAILURE", raising=False)
        assert secrets_hook.main([]) == secrets_hook.EXIT_BLOCK

    def test_opt_out_allows_commit(self, monkeypatch):
        monkeypatch.setenv("SECRETS_BLOCK_ON_SCAN_FAILURE", "0")
        assert secrets_hook.main([]) == secrets_hook.EXIT_OK


class TestScanTimeoutParsing:
    def test_default(self, monkeypatch):
        monkeypatch.delenv("SECRETS_SCAN_TIMEOUT", raising=False)
        assert secrets_hook._scan_timeout() == secrets_hook.DEFAULT_SCAN_TIMEOUT

    def test_custom(self, monkeypatch):
        monkeypatch.setenv("SECRETS_SCAN_TIMEOUT", "12.5")
        assert secrets_hook._scan_timeout() == 12.5

    def test_invalid_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("SECRETS_SCAN_TIMEOUT", "not-a-number")
        assert secrets_hook._scan_timeout() == secrets_hook.DEFAULT_SCAN_TIMEOUT

    def test_zero_clamped_to_minimum(self, monkeypatch):
        monkeypatch.setenv("SECRETS_SCAN_TIMEOUT", "0")
        assert secrets_hook._scan_timeout() == secrets_hook.MIN_SCAN_TIMEOUT

    def test_negative_one_means_no_timeout(self, monkeypatch):
        monkeypatch.setenv("SECRETS_SCAN_TIMEOUT", "-1")
        assert secrets_hook._scan_timeout() is None

    def test_other_negative_values_clamped_to_minimum(self, monkeypatch):
        # Only the exact sentinel -1 means "no timeout" -- any other
        # negative value is just clamped like 0 already is.
        monkeypatch.setenv("SECRETS_SCAN_TIMEOUT", "-5")
        assert secrets_hook._scan_timeout() == secrets_hook.MIN_SCAN_TIMEOUT


class TestBlocksOnlyOnAddedFindings:
    """End-to-end within main(): a pre-existing secret (outside the added
    line ranges) must not block; one inside the range must."""

    @pytest.fixture(autouse=True)
    def _stub_prereqs(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        monkeypatch.setattr(secrets_hook, "find_repo_root", lambda _: tmp_path)
        monkeypatch.setattr(secrets_hook, "get_staged_files", lambda *a, **kw: ["app.py"])
        monkeypatch.setattr(secrets_hook, "find_snyk_binary", lambda: "/usr/bin/snyk")
        monkeypatch.setattr(secrets_hook, "check_snyk_auth", lambda: "token")
        snapshot_dir = tmp_path / "staged-snapshot"
        snapshot_dir.mkdir()

        # Plain local helper: `staticmethod` objects aren't directly callable
        # until Python 3.10, and this isn't a class attribute anyway.
        def _fake_snapshot(repo_root, files, deadline=None):
            from contextlib import contextmanager

            @contextmanager
            def _cm():
                yield snapshot_dir

            return _cm()

        monkeypatch.setattr(
            secrets_hook, "staged_snapshot", lambda *a, **kw: _fake_snapshot(*a, **kw)
        )

    def test_pre_existing_only_does_not_block(self, monkeypatch):
        monkeypatch.setattr(
            secrets_hook, "get_added_line_ranges", lambda *a, **kw: ({"app.py": [(10, 10)]}, [])
        )
        finding = findings.Finding(
            id="x", title="X", severity="high", file_path="app.py", start_line=1, start_column=1
        )
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan_with_retries",
            lambda *a, **kw: snyk_cli.ScanAttempt("success", [finding], 1),
        )
        assert secrets_hook.main([]) == secrets_hook.EXIT_OK

    def test_added_finding_blocks(self, monkeypatch):
        monkeypatch.setattr(
            secrets_hook, "get_added_line_ranges", lambda *a, **kw: ({"app.py": [(1, 1)]}, [])
        )
        finding = findings.Finding(
            id="x", title="X", severity="high", file_path="app.py", start_line=1, start_column=1
        )
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan_with_retries",
            lambda *a, **kw: snyk_cli.ScanAttempt("success", [finding], 1),
        )
        assert secrets_hook.main([]) == secrets_hook.EXIT_BLOCK


class TestParseCliArgs:
    def test_no_flags_needed(self):
        secrets_hook.parse_cli_args([])  # must not raise

    def test_unknown_flag_raises(self):
        # A stale hook install still passing --staged must fail fast, not
        # silently behave differently.
        with pytest.raises(SystemExit):
            secrets_hook.parse_cli_args(["--staged"])


# ============================================================================
# 9. lib/baseline.py -- the "content" DiffStrategy
# ============================================================================


def _write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n")


class TestExtractFindingText:
    def test_extracts_single_line_substring(self, tmp_path):
        _write_lines(tmp_path / "app.py", ['x = "hello world"'])
        finding = findings.Finding(
            file_path="app.py", start_line=1, start_column=6, end_line=1, end_column=17
        )
        assert baseline.extract_finding_text(tmp_path, "app.py", finding) == "hello world"

    def test_none_for_missing_file(self, tmp_path):
        finding = findings.Finding(
            file_path="missing.py", start_line=1, start_column=1, end_line=1, end_column=5
        )
        assert baseline.extract_finding_text(tmp_path, "missing.py", finding) is None

    def test_none_for_out_of_bounds_line(self, tmp_path):
        _write_lines(tmp_path / "app.py", ["one line only"])
        finding = findings.Finding(
            file_path="app.py", start_line=5, start_column=1, end_line=5, end_column=4
        )
        assert baseline.extract_finding_text(tmp_path, "app.py", finding) is None

    def test_none_for_out_of_bounds_column(self, tmp_path):
        _write_lines(tmp_path / "app.py", ["short"])
        finding = findings.Finding(
            file_path="app.py", start_line=1, start_column=1, end_line=1, end_column=99
        )
        assert baseline.extract_finding_text(tmp_path, "app.py", finding) is None

    def test_none_for_absolute_file_path_outside_snapshot(self, tmp_path):
        # Path("/snapshot") / "/etc/passwd" == Path("/etc/passwd") in
        # pathlib -- an absolute file_path must not escape the snapshot dir.
        secret_file = tmp_path / "outside-snapshot-secret.txt"
        secret_file.write_text('KEY = "abc123"')
        snapshot_dir = tmp_path / "snapshot"
        snapshot_dir.mkdir()
        finding = findings.Finding(
            file_path=str(secret_file), start_line=1, start_column=7, end_line=1, end_column=15
        )
        assert baseline.extract_finding_text(snapshot_dir, str(secret_file), finding) is None

    def test_none_for_dot_dot_escaping_snapshot(self, tmp_path):
        (tmp_path / "outside.py").write_text('KEY = "abc123"')
        snapshot_dir = tmp_path / "snapshot"
        snapshot_dir.mkdir()
        finding = findings.Finding(
            file_path="../outside.py", start_line=1, start_column=7, end_line=1, end_column=15
        )
        assert baseline.extract_finding_text(snapshot_dir, "../outside.py", finding) is None

    def test_lookup_path_can_differ_from_findings_own_path(self, tmp_path):
        # The rename-translated (old) path case: the finding's own
        # file_path is the current/new one, but baseline-side extraction
        # needs to read from the old path in the baseline snapshot.
        _write_lines(tmp_path / "old_name.py", ['KEY = "abc123"'])
        finding = findings.Finding(
            file_path="new_name.py", start_line=1, start_column=7, end_line=1, end_column=15
        )
        assert baseline.extract_finding_text(tmp_path, "old_name.py", finding) == '"abc123"'


class TestClassifyByContent:
    @staticmethod
    def _ctx(**overrides):
        defaults = dict(
            findings=[],
            ranges={},
            current_snapshot_dir=Path("."),
            baseline_findings=[],
            baseline_snapshot_dir=None,
            baseline_files=set(),
            renames={},
        )
        defaults.update(overrides)
        return diff_scope.ClassificationContext(**defaults)

    def test_touched_line_with_unchanged_secret_is_pre_existing(self, tmp_path):
        # A trailing comment touches the secret's line, so line-diff alone
        # would call it "added" even though the matched text is unchanged.
        current_dir, baseline_dir = tmp_path / "current", tmp_path / "baseline"
        current_dir.mkdir()
        baseline_dir.mkdir()
        _write_lines(current_dir / "app.py", ['KEY = "abc123"  # rotated soon'])
        _write_lines(baseline_dir / "app.py", ['KEY = "abc123"'])

        current_finding = findings.Finding(
            id="generic-secret",
            file_path="app.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=14,
        )
        baseline_finding = findings.Finding(
            id="generic-secret",
            file_path="app.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=14,
        )
        ctx = self._ctx(
            findings=[current_finding],
            ranges={"app.py": [(1, 1)]},  # git's diff marks this line changed
            current_snapshot_dir=current_dir,
            baseline_findings=[baseline_finding],
            baseline_snapshot_dir=baseline_dir,
            baseline_files={"app.py"},
        )
        added, pre_existing, _ = baseline.classify_by_content(ctx)
        assert added == []
        assert pre_existing == [current_finding]

    def test_genuinely_new_secret_is_added(self, tmp_path):
        current_dir, baseline_dir = tmp_path / "current", tmp_path / "baseline"
        current_dir.mkdir()
        baseline_dir.mkdir()
        _write_lines(current_dir / "app.py", ['KEY = "new-value-999"'])
        _write_lines(baseline_dir / "app.py", ['KEY = "old-value-111"'])

        current_finding = findings.Finding(
            id="generic-secret",
            file_path="app.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=22,
        )
        baseline_finding = findings.Finding(
            id="generic-secret",
            file_path="app.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=22,
        )
        ctx = self._ctx(
            findings=[current_finding],
            ranges={"app.py": [(1, 1)]},
            current_snapshot_dir=current_dir,
            baseline_findings=[baseline_finding],
            baseline_snapshot_dir=baseline_dir,
            baseline_files={"app.py"},
        )
        added, pre_existing, _ = baseline.classify_by_content(ctx)
        assert added == [current_finding]
        assert pre_existing == []

    def test_secret_removed_from_file_is_removed(self, tmp_path):
        current_dir, baseline_dir = tmp_path / "current", tmp_path / "baseline"
        current_dir.mkdir()
        baseline_dir.mkdir()
        _write_lines(current_dir / "app.py", ["KEY = 'clean now'"])
        _write_lines(baseline_dir / "app.py", ['KEY = "abc123"'])

        baseline_finding = findings.Finding(
            id="generic-secret",
            file_path="app.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=14,
        )
        ctx = self._ctx(
            findings=[],
            ranges={},
            current_snapshot_dir=current_dir,
            baseline_findings=[baseline_finding],
            baseline_snapshot_dir=baseline_dir,
            baseline_files={"app.py"},
        )
        added, pre_existing, removed = baseline.classify_by_content(ctx)
        assert (added, pre_existing) == ([], [])
        assert removed == [baseline_finding]

    def test_removed_finding_retains_its_ignored_flag(self, tmp_path):
        current_dir, baseline_dir = tmp_path / "current", tmp_path / "baseline"
        current_dir.mkdir()
        baseline_dir.mkdir()
        _write_lines(current_dir / "app.py", ["KEY = 'clean now'"])
        _write_lines(baseline_dir / "app.py", ['KEY = "abc123"'])

        baseline_finding = findings.Finding(
            id="generic-secret",
            file_path="app.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=14,
            suppression="accepted",
        )
        ctx = self._ctx(
            current_snapshot_dir=current_dir,
            baseline_findings=[baseline_finding],
            baseline_snapshot_dir=baseline_dir,
            baseline_files={"app.py"},
        )
        _, _, removed = baseline.classify_by_content(ctx)
        assert removed == [baseline_finding]
        assert removed[0].is_ignored is True

    def test_not_removed_when_a_same_rule_current_finding_falls_back(self, tmp_path):
        # The current finding for the same secret has a malformed location
        # (extraction fails), so it's classified via the line-range
        # fallback instead of by text -- it may be the very secret the
        # baseline finding matches, so baseline mustn't be called
        # "removed" just because it's invisible to the text index.
        current_dir, baseline_dir = tmp_path / "current", tmp_path / "baseline"
        current_dir.mkdir()
        baseline_dir.mkdir()
        _write_lines(current_dir / "app.py", ['KEY = "abc123"'])
        _write_lines(baseline_dir / "app.py", ['KEY = "abc123"'])

        baseline_finding = findings.Finding(
            id="generic-secret",
            file_path="app.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=14,
        )
        # Malformed: end_column < start_column makes extract_finding_text
        # return None for the current finding.
        current_finding = findings.Finding(
            id="generic-secret",
            file_path="app.py",
            start_line=1,
            start_column=14,
            end_line=1,
            end_column=7,
        )
        ctx = self._ctx(
            findings=[current_finding],
            ranges={"app.py": [(1, 1)]},
            current_snapshot_dir=current_dir,
            baseline_findings=[baseline_finding],
            baseline_snapshot_dir=baseline_dir,
            baseline_files={"app.py"},
        )
        _, _, removed = baseline.classify_by_content(ctx)
        assert removed == []

    def test_no_baseline_snapshot_yields_no_removed(self, tmp_path):
        # Nothing to compare against -- must not report removed at all.
        current_dir = tmp_path / "current"
        current_dir.mkdir()
        baseline_finding = findings.Finding(id="generic-secret", file_path="app.py", start_line=1)
        ctx = self._ctx(
            current_snapshot_dir=current_dir,
            baseline_findings=[baseline_finding],
            baseline_snapshot_dir=None,
        )
        _, _, removed = baseline.classify_by_content(ctx)
        assert removed == []

    def test_new_file_falls_back_to_line_range(self, tmp_path):
        current_dir = tmp_path / "current"
        current_dir.mkdir()
        _write_lines(current_dir / "new.py", ['KEY = "abc123"'])
        current_finding = findings.Finding(
            id="generic-secret",
            file_path="new.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=14,
        )
        ctx = self._ctx(
            findings=[current_finding],
            ranges={"new.py": [(1, 1)]},  # whole new file: line-heuristic says "added"
            current_snapshot_dir=current_dir,
            baseline_files=set(),  # new.py has no baseline coverage at all
        )
        added, pre_existing, _ = baseline.classify_by_content(ctx)
        assert added == [current_finding]
        assert pre_existing == []

    def test_pure_rename_preserves_pre_existing_classification(self, tmp_path):
        current_dir, baseline_dir = tmp_path / "current", tmp_path / "baseline"
        current_dir.mkdir()
        baseline_dir.mkdir()
        _write_lines(current_dir / "new_name.py", ['KEY = "abc123"'])
        _write_lines(baseline_dir / "old_name.py", ['KEY = "abc123"'])

        current_finding = findings.Finding(
            id="generic-secret",
            file_path="new_name.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=14,
        )
        baseline_finding = findings.Finding(
            id="generic-secret",
            file_path="old_name.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=14,
        )
        ctx = self._ctx(
            findings=[current_finding],
            ranges={},  # pure rename: git emits no hunks at all
            current_snapshot_dir=current_dir,
            baseline_findings=[baseline_finding],
            baseline_snapshot_dir=baseline_dir,
            baseline_files={"old_name.py"},
            renames={"new_name.py": "old_name.py"},
        )
        added, pre_existing, _ = baseline.classify_by_content(ctx)
        assert added == []
        assert pre_existing == [current_finding]

    def test_renamed_and_edited_elsewhere_still_preserves_pre_existing(self, tmp_path):
        # Composite case: file renamed AND its secret's line touched by an
        # unrelated edit -- both the rename lookup and content match have
        # to work together.
        current_dir, baseline_dir = tmp_path / "current", tmp_path / "baseline"
        current_dir.mkdir()
        baseline_dir.mkdir()
        _write_lines(current_dir / "new_name.py", ['KEY = "abc123"  # TODO rotate'])
        _write_lines(baseline_dir / "old_name.py", ['KEY = "abc123"'])

        current_finding = findings.Finding(
            id="generic-secret",
            file_path="new_name.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=14,
        )
        baseline_finding = findings.Finding(
            id="generic-secret",
            file_path="old_name.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=14,
        )
        ctx = self._ctx(
            findings=[current_finding],
            ranges={"new_name.py": [(1, 1)]},  # git's diff marks this line changed
            current_snapshot_dir=current_dir,
            baseline_findings=[baseline_finding],
            baseline_snapshot_dir=baseline_dir,
            baseline_files={"old_name.py"},
            renames={"new_name.py": "old_name.py"},
        )
        added, pre_existing, _ = baseline.classify_by_content(ctx)
        assert added == []
        assert pre_existing == [current_finding]

    def test_renamed_file_with_secret_itself_changed_is_added(self, tmp_path):
        current_dir, baseline_dir = tmp_path / "current", tmp_path / "baseline"
        current_dir.mkdir()
        baseline_dir.mkdir()
        _write_lines(current_dir / "new_name.py", ['KEY = "rotated-value"'])
        _write_lines(baseline_dir / "old_name.py", ['KEY = "original-value"'])

        current_finding = findings.Finding(
            id="generic-secret",
            file_path="new_name.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=21,
        )
        baseline_finding = findings.Finding(
            id="generic-secret",
            file_path="old_name.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=23,
        )
        ctx = self._ctx(
            findings=[current_finding],
            ranges={"new_name.py": [(1, 1)]},
            current_snapshot_dir=current_dir,
            baseline_findings=[baseline_finding],
            baseline_snapshot_dir=baseline_dir,
            baseline_files={"old_name.py"},
            renames={"new_name.py": "old_name.py"},
        )
        added, pre_existing, _ = baseline.classify_by_content(ctx)
        assert added == [current_finding]
        assert pre_existing == []

    def test_unresolved_rename_falls_back_to_line_range(self, tmp_path):
        # Simulates a below-threshold rename git didn't detect (empty
        # renames dict) -- falls back to line-range classification, same
        # as a genuinely new file.
        current_dir = tmp_path / "current"
        current_dir.mkdir()
        _write_lines(current_dir / "new_name.py", ['KEY = "abc123"'])
        current_finding = findings.Finding(
            id="generic-secret",
            file_path="new_name.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=14,
        )
        ctx = self._ctx(
            findings=[current_finding],
            ranges={"new_name.py": [(1, 1)]},
            current_snapshot_dir=current_dir,
            baseline_files={"old_name.py"},  # exists, but nothing maps to it
            renames={},
        )
        added, pre_existing, _ = baseline.classify_by_content(ctx)
        assert added == [current_finding]
        assert pre_existing == []


# ============================================================================
# 10a. Terminal-width word-wrap
# ============================================================================


class TestWrapForPrefix:
    def test_short_message_is_not_wrapped(self):
        assert secrets_hook._wrap_for_prefix(
            "scan timed out after 1 attempt; blocking commit", ""
        ) == ["scan timed out after 1 attempt; blocking commit"]

    def test_long_message_wraps_at_width(self):
        lines = secrets_hook._wrap_for_prefix(
            "set SECRETS_BLOCK_ON_SCAN_FAILURE=0 to allow the commit through scan failures instead",
            "",
            width=80,
        )
        assert len(lines) > 1
        assert all(len(line) <= 80 for line in lines)
        # Re-joining with spaces reconstructs the original words in order.
        assert (
            " ".join(lines).split()
            == (
                "set SECRETS_BLOCK_ON_SCAN_FAILURE=0 to allow the commit through scan "
                "failures instead"
            ).split()
        )

    def test_backtick_command_never_split_even_if_it_alone_exceeds_width(self):
        long_command = "`" + "x" * 90 + "`"
        lines = secrets_hook._wrap_for_prefix(f"run {long_command} manually", "", width=80)
        assert any(long_command in line for line in lines)

    def test_punctuation_attached_to_a_command_stays_attached(self):
        # No space between the closing backtick and ")" -- the wrap must not
        # introduce one.
        lines = secrets_hook._wrap_for_prefix("bypass with `git commit --no-verify`) now", "")
        assert "`git commit --no-verify`)" in " ".join(lines)

    def test_long_url_is_never_split_even_when_forced_narrower_than_itself(self, capsys):
        # A bare long token (no backticks needed -- it just has no
        # whitespace to split on) must stay intact even at a width many
        # times narrower than the token itself, instead of being sliced
        # mid-hostname/mid-path the way plain textwrap defaults would.
        url = "https://docs.snyk.io/scan-fix-and-prevent/prevent/policies/security-policies"
        message = f"see {url} for details"
        lines = secrets_hook._wrap_for_prefix(message, "  ", width=20)
        with capsys.disabled():
            print("\n----- long URL forced onto one line (width=20) -----")
            for line in lines:
                print(f"[{line}]  len={len(line)}")
        assert any(line.strip() == url for line in lines)

    def test_preexisting_placeholder_byte_does_not_corrupt_output(self):
        # A literal null byte (the internal space-protection sentinel)
        # already in the input must not survive as a real character, and
        # must not silently swallow a real space either.
        lines = secrets_hook._wrap_for_prefix("weird\x00input `a command` here", "")
        joined = " ".join(lines)
        assert "\x00" not in joined
        assert "`a command`" in joined

    def test_preexisting_placeholder_byte_becomes_a_real_word_boundary(self):
        # A pre-existing placeholder byte must be defused to a space before
        # wrapping decides where words break, not after -- otherwise the
        # wrapper treats it as one unbreakable token instead of two words.
        assert secrets_hook._wrap_for_prefix("weird\x00input", "", width=6) == [
            "weird",
            "    input",
        ]

    def test_embedded_newlines_are_preserved_as_separate_lines(self):
        # A real multi-line message (e.g. an exception with its own line
        # breaks) must keep its original line structure -- each line is
        # wrapped independently, not reflowed into one paragraph.
        lines = secrets_hook._wrap_for_prefix("first line\nsecond line", "", width=80)
        assert lines == ["first line", "    second line"]

    def test_long_line_within_a_multiline_message_still_wraps(self):
        lines = secrets_hook._wrap_for_prefix(
            "short first line\n"
            "set SECRETS_BLOCK_ON_SCAN_FAILURE=0 to allow the commit through scan "
            "failures instead",
            "",
            width=80,
        )
        assert lines[0] == "short first line"
        assert len(lines) > 2
        assert all(len(line) <= 80 for line in lines)

    def test_printed_line_including_prefix_stays_within_width(self, monkeypatch, capsys):
        # The prefix ("[snyk] " or the continuation indent) counts against
        # the 80-column budget too, not just the wrapped message text.
        long_message = (
            "set SECRETS_BLOCK_ON_SCAN_FAILURE=0 to allow the commit through scan "
            "failures instead, a fairly long sentence on purpose"
        )
        secrets_hook.log(long_message)
        secrets_hook.log_cont(long_message)
        printed = capsys.readouterr().err
        for line in printed.splitlines():
            assert len(line) <= secrets_hook._WRAP_WIDTH, line

    def test_continuation_line_uses_its_own_wider_budget(self):
        # log()'s "[snyk] " prefix (7 chars) leaves less room than the
        # continuation indent does -- a continuation line shouldn't be
        # capped to the first line's tighter width just because they
        # share one wrap call. This message needs 3 lines if every line
        # were capped at the (narrower) first-line width, but only 2 once
        # the continuation line gets its own (wider) budget.
        words = [
            "alpha",
            "beta",
            "gamma",
            "delta",
            "epsilon",
            "zeta",
            "eta",
            "theta",
            "iota",
            "kappa",
            "lambda",
            "mu",
            "nu",
            "xi",
            "omicron",
            "pi",
        ]
        message_words: list[str] = []
        length = 0
        for i in range(40):
            w = words[i % len(words)]
            message_words.append(w)
            length += len(w) + 1
            if length >= 180:
                break
        message = " ".join(message_words)
        first_width = secrets_hook._WRAP_WIDTH - len(secrets_hook._LOG_PREFIX)

        # Uniform-width baseline: as if every line, including the first,
        # were capped to the (narrower) first-line budget.
        old_uniform = secrets_hook._wrap_for_prefix(message, "", width=first_width)
        new = secrets_hook._wrap_for_prefix(message, secrets_hook._LOG_PREFIX)

        assert len(new) < len(old_uniform)
        assert all(len(line) <= secrets_hook._WRAP_WIDTH for line in new)

    def test_colored_span_stays_intact_when_wrapped(self):
        colored = f"{timing._ANSI_BOLD_RED}1 blocking{timing._ANSI_RESET}"
        lines = secrets_hook._wrap_for_prefix(f"before {colored} after", "", width=20)
        assert any(line.strip() == colored for line in lines)


class TestLogColor:
    """`color=` is a display-only concern: it wraps the printed line, but
    the persisted log line (via _LOG_FILE) always stays plain."""

    def test_color_applied_to_display_line_when_supported(self, monkeypatch, capsys):
        monkeypatch.setattr(secrets_hook, "supports_color", lambda: True)
        secrets_hook.log("hello", color=secrets_hook._ANSI_GREEN)
        err = capsys.readouterr().err
        assert err == f"{secrets_hook._ANSI_GREEN}[snyk] hello{secrets_hook._ANSI_RESET}\n"

    def test_no_color_when_not_supported(self, monkeypatch, capsys):
        monkeypatch.setattr(secrets_hook, "supports_color", lambda: False)
        secrets_hook.log("hello", color=secrets_hook._ANSI_GREEN)
        err = capsys.readouterr().err
        assert err == "[snyk] hello\n"
        assert "\033" not in err

    def test_persisted_log_line_is_never_colored(self, monkeypatch, capsys, tmp_path):
        monkeypatch.setattr(secrets_hook, "supports_color", lambda: True)
        log_file = str(tmp_path / "log.txt")
        monkeypatch.setattr(secrets_hook, "_LOG_FILE", log_file)
        secrets_hook.log_cont("hello", color=secrets_hook._ANSI_GREEN)
        persisted = Path(log_file).read_text()
        assert "\033" not in persisted
        assert "hello" in persisted

    def test_embedded_color_is_not_persisted(self, monkeypatch, tmp_path):
        log_file = str(tmp_path / "log.txt")
        monkeypatch.setattr(secrets_hook, "_LOG_FILE", log_file)
        message = f"1 {timing._ANSI_BOLD_RED}blocking{timing._ANSI_RESET} finding"
        secrets_hook.log_cont(message)
        persisted = Path(log_file).read_text()
        assert "\033" not in persisted
        assert persisted.endswith("1 blocking finding\n")


# ============================================================================
# 11. Output scenarios -- each asserts on and prints the hook's actual
# stderr (via capsys.disabled(), so it shows without -s, even on pass).
#
# Run just this class to see every scenario's real output in one pass:
#   uv run pytest recipes/installer/tests/test_secrets_at_commit.py::TestOutputScenarios -v
# ============================================================================


class TestOutputScenarios:
    """Every cross-cutting concern outside `DiffStrategy.classify` itself --
    classification differences are covered by `TestClassifyByContent` and
    `TestContentStrategyEndToEnd`."""

    SYNTHETIC_SCAN_EXCEPTION = (
        "<UNEXPECTED_SCAN_ERROR_FROM_RUN_SECRETS_SCAN: real exception message would appear here>"
    )
    # Fake org id, UUID-shaped only to match what the real CLI would emit --
    # not a credential, but named explicitly so it doesn't read as one.
    FAKE_ORG_ID = "13d16b4e-9c09-46e6-92ca-57aa867a1075"
    NEW_FINDING = findings.Finding(
        id="aws-access-token",
        title="Aws-Access-Token",
        severity="high",
        file_path="config.py",
        start_line=1,
        start_column=22,
    )
    # No entry for "old.py" in the default _stub_prereqs ranges below, so
    # this is always classified pre-existing regardless of what's staged.
    PRE_EXISTING_FINDING = findings.Finding(
        id="generic-secret",
        title="Generic-Secret",
        severity="medium",
        file_path="old.py",
        start_line=5,
        start_column=1,
    )

    @pytest.fixture(autouse=True)
    def _stub_prereqs(self, monkeypatch, tmp_path):
        """A working setup by default -- individual tests override just the
        pieces that change for their scenario (snyk_bin, auth, scan
        result)."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        monkeypatch.delenv("SECRETS_BLOCK_ON_SCAN_FAILURE", raising=False)
        monkeypatch.delenv("SECRETS_FALLBACK_TO_WORKING_DIR", raising=False)
        monkeypatch.setattr(secrets_hook, "DEBUG", False)
        monkeypatch.setattr(secrets_hook, "find_repo_root", lambda _: tmp_path)
        monkeypatch.setattr(secrets_hook, "get_staged_files", lambda *a, **kw: ["config.py"])
        monkeypatch.setattr(
            secrets_hook, "get_added_line_ranges", lambda *a, **kw: ({"config.py": [(1, 1)]}, [])
        )
        monkeypatch.setattr(secrets_hook, "find_snyk_binary", lambda: "/usr/bin/snyk")
        monkeypatch.setattr(secrets_hook, "check_snyk_auth", lambda: "token")
        self.current_snapshot_dir = tmp_path / "staged-snapshot"
        self.current_snapshot_dir.mkdir()
        self.baseline_snapshot_dir = tmp_path / "baseline-snapshot"
        self.baseline_snapshot_dir.mkdir()

        # Defaults to a successful snapshot; the snapshot failure tests
        # below override this to exercise that prerequisite path instead.
        @contextmanager
        def _fake_snapshot(repo_root, files, deadline=None):
            yield self.current_snapshot_dir

        monkeypatch.setattr(
            secrets_hook, "staged_snapshot", lambda *a, **kw: _fake_snapshot(*a, **kw)
        )

        # No real files under tmp_path, so classify_by_content can't
        # extract text and falls back to line-range classification for
        # every finding.
        monkeypatch.setattr(secrets_hook, "get_rename_map", lambda *a, **kw: {})

        @contextmanager
        def _fake_ref_snapshot(repo_root, ref, files, deadline=None):
            yield self.baseline_snapshot_dir, set(), False

        monkeypatch.setattr(
            secrets_hook, "ref_snapshot", lambda *a, **kw: _fake_ref_snapshot(*a, **kw)
        )

        def _fake_concurrent(current_ws, baseline_ws, invocation, deadline):
            # Delegates to whatever run_secrets_scan_with_retries a test
            # method below mocks, looked up fresh each call.
            status, current_findings = secrets_hook.run_secrets_scan_with_retries(
                current_ws, invocation, deadline
            )
            return (
                snyk_cli.ScanAttempt(status, current_findings, 1),
                snyk_cli.ScanAttempt("success", [], 1),
            )

        monkeypatch.setattr(secrets_hook, "run_concurrent_scans", _fake_concurrent)

    def _run(self, capsys, header: str, argv: list[str]):
        rc = secrets_hook.main(argv)
        err = capsys.readouterr().err
        with capsys.disabled():
            print(f"\n----- {header} (exit={rc}) -----")
            print(err, end="" if err.endswith("\n") else "\n")
        return rc, err

    @staticmethod
    def _dewrap(text: str) -> str:
        """Collapses word-wrap continuation breaks back into one line, for
        substring assertions that must not depend on exactly where a
        message happened to wrap -- variable-length content earlier in the
        same message (e.g. a tmp path, different length in CI than
        locally) shifts the wrap point for everything after it."""
        return re.sub(r"\n {4}", " ", text)

    @staticmethod
    def _persisted_log_text(tmp_path) -> str:
        """Reads back whatever this run persisted."""
        log_file = persistent_log.resolve_log_file(str(tmp_path))
        if not os.path.exists(log_file):
            return ""
        return Path(log_file).read_text(encoding="utf-8")

    def test_clean_commit(self, monkeypatch, capsys, tmp_path):
        monkeypatch.setattr(
            secrets_hook, "run_secrets_scan_with_retries", lambda *a, **kw: ("success", [])
        )
        rc, err = self._run(capsys, "clean commit", [])
        assert rc == secrets_hook.EXIT_OK
        assert "[snyk] Scanning 1 staged file for secrets... (bypass with" in err
        assert "`git commit --no-verify`)" in err
        assert re.search(r"^  done in [\d.]+s -- no secrets found$", err, re.M)

        # Same lines as stderr, minus the "[snyk] "/"  " prefixes, plus a
        # leading timestamp.
        log_text = self._persisted_log_text(tmp_path)
        assert re.search(
            r"^\[[\d\-T:.]+\] Scanning 1 staged file for secrets\.\.\. "
            r"\(bypass with `git commit --no-verify`\)$",
            log_text,
            re.M,
        )
        assert re.search(r"^\[[\d\-T:.]+\] done in [\d.]+s -- no secrets found$", log_text, re.M)

    def test_clean_commit_with_no_timeout_configured(self, monkeypatch, capsys):
        # SECRETS_SCAN_TIMEOUT=-1 means no deadline at all -- confirm both
        # the message and the actual deadline passed downstream reflect it.
        monkeypatch.setenv("SECRETS_SCAN_TIMEOUT", "-1")
        seen_deadlines = []

        def fake_run_secrets_scan(*a, **kw):
            seen_deadlines.append(a[-1] if a else kw.get("deadline"))
            return ("success", [])

        monkeypatch.setattr(secrets_hook, "run_secrets_scan_with_retries", fake_run_secrets_scan)
        rc, err = self._run(capsys, "clean commit, no timeout configured", [])
        assert rc == secrets_hook.EXIT_OK
        assert "[snyk] Scanning 1 staged file for secrets... (bypass with" in err
        assert "`git commit --no-verify`)" in err
        assert seen_deadlines == [None]

    def test_clean_commit_with_pre_existing(self, monkeypatch, capsys):
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan_with_retries",
            lambda *a, **kw: ("success", [self.PRE_EXISTING_FINDING]),
        )
        rc, err = self._run(capsys, "clean commit, pre-existing secret", [])
        assert rc == secrets_hook.EXIT_OK
        assert re.search(
            r"^  done in [\d.]+s -- no blocking secrets found$",
            err,
            re.M,
        )
        assert re.search(r"^  history: 1 pre-existing finding$", err, re.M)

    def _fake_classify(self, monkeypatch, added=(), pre_existing=(), removed=()):
        """Bypasses classify_by_content's real matching -- these tests are
        about the message per category, not the matching logic itself
        (covered by TestClassifyByContent)."""
        monkeypatch.setattr(
            secrets_hook, "run_secrets_scan_with_retries", lambda *a, **kw: ("success", [])
        )
        monkeypatch.setitem(
            secrets_hook._DIFF_STRATEGIES,
            "content",
            secrets_hook.DiffStrategy(
                name="content",
                needs_baseline_scan=True,
                classify=lambda ctx: (list(added), list(pre_existing), list(removed)),
            ),
        )

    def test_added_and_ignored_does_not_block(self, monkeypatch, capsys):
        finding = findings.Finding(id="x", file_path="app.py", start_line=1, suppression="accepted")
        self._fake_classify(monkeypatch, added=[finding])
        rc, err = self._run(capsys, "added finding already ignored", [])
        assert rc == secrets_hook.EXIT_OK
        assert "1 new finding introduced, 0 blocking, 1 already ignored" in err

    def test_added_and_ignored_is_not_itemized(self, monkeypatch, capsys):
        # Only blocking findings need file/line detail.
        finding = findings.Finding(
            id="aws-access-token",
            title="Aws-Access-Token",
            severity="high",
            file_path="config.py",
            start_line=1,
            start_column=1,
            suppression="accepted",
        )
        self._fake_classify(monkeypatch, added=[finding])
        rc, err = self._run(capsys, "added finding already ignored, with position", [])
        assert rc == secrets_hook.EXIT_OK
        assert "config.py(1,1):" not in err
        assert "snyk ignore create" not in err

    def test_blocking_and_added_ignored_together_only_itemizes_blocking(self, monkeypatch, capsys):
        blocking_finding = findings.Finding(
            id="aws-access-token",
            title="Aws-Access-Token",
            severity="high",
            file_path="new_secret.py",
            start_line=3,
            start_column=1,
        )
        ignored_finding = findings.Finding(
            id="generic-secret",
            title="Generic-Secret",
            severity="high",
            file_path="config.py",
            start_line=12,
            start_column=1,
            suppression="accepted",
        )
        self._fake_classify(monkeypatch, added=[blocking_finding, ignored_finding])
        rc, err = self._run(capsys, "blocking and added-ignored together", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert "done in 0.0s -- 2 new findings introduced, 1 blocking, 1 already ignored" in err
        assert "new_secret.py" in err
        assert "config.py" not in err

    def test_pre_existing_ignored_collapses_into_history(self, monkeypatch, capsys):
        finding = findings.Finding(id="x", file_path="app.py", start_line=1, suppression="accepted")
        self._fake_classify(monkeypatch, pre_existing=[finding])
        rc, err = self._run(capsys, "pre-existing finding already ignored", [])
        assert rc == secrets_hook.EXIT_OK
        assert re.search(r"^  history: 1 pre-existing finding$", err, re.M)

    def test_removed_finding_shows_history_line(self, monkeypatch, capsys):
        finding = findings.Finding(id="x", file_path="app.py", start_line=1)
        self._fake_classify(monkeypatch, removed=[finding])
        rc, err = self._run(capsys, "pre-existing secret removed", [])
        assert rc == secrets_hook.EXIT_OK
        assert re.search(r"^  history: 1 secret cleaned up$", err, re.M)

    def test_removed_ignored_finding_also_counts_toward_history(self, monkeypatch, capsys):
        finding = findings.Finding(id="x", file_path="app.py", start_line=1, suppression="accepted")
        self._fake_classify(monkeypatch, removed=[finding])
        rc, err = self._run(capsys, "previously-ignored secret removed", [])
        assert rc == secrets_hook.EXIT_OK
        assert re.search(r"^  history: 1 secret cleaned up$", err, re.M)

    def test_under_review_added_finding_still_blocks_but_is_flagged(self, monkeypatch, capsys):
        finding = findings.Finding(
            id="aws-access-token",
            title="Aws-Access-Token",
            severity="high",
            file_path="config.py",
            start_line=1,
            start_column=1,
            suppression="underReview",
        )
        self._fake_classify(monkeypatch, added=[finding])
        rc, err = self._run(capsys, "added finding under review", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert "(ignore request pending review)" in err
        assert re.search(
            r"^  done in [\d.]+s -- 1 finding blocking commit \(1 already under review\)$",
            err,
            re.M,
        )

    def test_rejected_added_finding_blocks_without_under_review_parenthetical(
        self, monkeypatch, capsys
    ):
        finding = findings.Finding(
            id="aws-access-token",
            title="Aws-Access-Token",
            severity="high",
            file_path="config.py",
            start_line=1,
            start_column=1,
            suppression="rejected",
        )
        self._fake_classify(monkeypatch, added=[finding])
        rc, err = self._run(capsys, "added finding previously rejected", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert "(a previous ignore request was rejected)" in err
        assert re.search(
            r"^  done in [\d.]+s -- 1 finding blocking commit$",
            err,
            re.M,
        )

    def test_pre_existing_under_review_collapses_into_history(self, monkeypatch, capsys):
        finding = findings.Finding(
            id="x", file_path="app.py", start_line=1, suppression="underReview"
        )
        self._fake_classify(monkeypatch, pre_existing=[finding])
        rc, err = self._run(capsys, "pre-existing finding under review", [])
        assert rc == secrets_hook.EXIT_OK
        assert re.search(r"^  history: 1 pre-existing finding$", err, re.M)

    def test_blocking_no_pre_existing(self, monkeypatch, capsys, tmp_path):
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan_with_retries",
            lambda *a, **kw: ("success", [self.NEW_FINDING]),
        )
        rc, err = self._run(capsys, "blocking, no pre-existing", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert re.search(r"^  done in [\d.]+s -- 1 finding blocking commit$", err, re.M)
        assert "  - config.py(1,22): [high] [aws-access-token] [-] [Aws-Access-Token]" in err
        # NEW_FINDING has no finding_id, so no ignore command is shown at all
        # (no fallback text either -- see test_blocking_with_finding_id_but_no_remote_shows_no_ignore_command).
        assert "snyk ignore create" not in err

        # The blocking summary is persisted; the raw finding list
        # (print_findings, above) deliberately is not -- see
        # lib/persistent_log.py's module docstring.
        log_text = self._persisted_log_text(tmp_path)
        assert re.search(
            r"^\[[\d\-T:.]+\] done in [\d.]+s -- 1 finding blocking commit$", log_text, re.M
        )
        assert "snyk ignore create" not in log_text
        assert "config.py(1,22)" not in log_text

    def test_blocking_with_finding_id_shows_ready_command_not_generic_hint(
        self, monkeypatch, capsys, tmp_path
    ):
        finding_with_id = dataclasses.replace(self.NEW_FINDING, finding_id="abc123-def456")
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan_with_retries",
            lambda *a, **kw: ("success", [finding_with_id]),
        )
        monkeypatch.setattr(
            secrets_hook,
            "get_remote_url",
            lambda *a, **kw: git_ops.RemoteUrlDecision.ok("git@github.com:acme/repo.git"),
        )
        rc, err = self._run(capsys, "blocking, finding id available", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert (
            "snyk ignore create --finding-id=abc123-def456 "
            "--remote-repo-url=git@github.com:acme/repo.git" in err
        )

        # The ready-to-run command lives inside print_findings' output, which
        # is never persisted (same as the finding list itself).
        log_text = self._persisted_log_text(tmp_path)
        assert "snyk ignore create" not in log_text

    def test_blocking_with_finding_id_but_no_remote_shows_no_ignore_command(
        self, monkeypatch, capsys
    ):
        # No fallback text either -- a command we know is incomplete isn't
        # worth suggesting the user reconstruct by hand.
        finding_with_id = dataclasses.replace(self.NEW_FINDING, finding_id="abc123-def456")
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan_with_retries",
            lambda *a, **kw: ("success", [finding_with_id]),
        )
        monkeypatch.setattr(
            secrets_hook, "get_remote_url", lambda *a, **kw: git_ops.RemoteUrlDecision.unavailable()
        )
        rc, err = self._run(capsys, "blocking, finding id but no origin remote", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert "snyk ignore create" not in err

    def test_blocking_with_undefined_prefixed_id_shows_no_ignore_command(self, monkeypatch, capsys):
        # Confirmed against a real run: the CLI rejects UNDEFINED-<uuid>
        # outright, so a remote being available doesn't help here either.
        finding_with_id = dataclasses.replace(self.NEW_FINDING, finding_id="UNDEFINED-abc123")
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan_with_retries",
            lambda *a, **kw: ("success", [finding_with_id]),
        )
        monkeypatch.setattr(
            secrets_hook,
            "get_remote_url",
            lambda *a, **kw: git_ops.RemoteUrlDecision.ok("git@github.com:acme/repo.git"),
        )
        rc, err = self._run(capsys, "blocking, undefined-prefixed finding id", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert "snyk ignore create" not in err

    def test_blocking_with_pre_existing(self, monkeypatch, capsys):
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan_with_retries",
            lambda *a, **kw: ("success", [self.NEW_FINDING, self.PRE_EXISTING_FINDING]),
        )
        rc, err = self._run(capsys, "blocking, with pre-existing also present", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert re.search(
            r"^  done in [\d.]+s -- 1 finding blocking commit$",
            err,
            re.M,
        )
        assert re.search(r"^  history: 1 pre-existing finding$", err, re.M)

    def test_snyk_cli_not_found(self, monkeypatch, capsys):
        monkeypatch.setattr(secrets_hook, "find_snyk_binary", lambda: None)
        rc, err = self._run(capsys, "Snyk CLI not found (fail-closed, default)", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert "Snyk CLI not found on PATH -- install with `npm install -g snyk`;" in err
        assert "blocking commit" in err
        assert "set SECRETS_BLOCK_ON_SCAN_FAILURE=0 to allow the commit" in err

    def test_snyk_cli_not_authenticated(self, monkeypatch, capsys):
        monkeypatch.setattr(secrets_hook, "check_snyk_auth", lambda: None)
        rc, err = self._run(capsys, "Snyk CLI not authenticated (fail-closed, default)", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert "Snyk CLI not authenticated; blocking commit" in err
        assert "run `/usr/bin/snyk auth`" in err
        assert "if that doesn't work, contact your Snyk administrator" in err
        assert "set SECRETS_BLOCK_ON_SCAN_FAILURE=0 to allow the commit" in err

    def test_relative_xdg_config_path_is_actionable(self, monkeypatch, capsys):
        monkeypatch.setattr(
            secrets_hook,
            "check_snyk_auth",
            lambda: (_ for _ in ()).throw(
                secrets_hook.InvalidConfigError(
                    "XDG_CONFIG_HOME must be an absolute path; unset it or set it to an absolute directory"
                )
            ),
        )
        rc, err = self._run(capsys, "relative XDG config path", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert "XDG_CONFIG_HOME must be an absolute path" in err
        assert "blocking commit" in err

    def test_scan_auth_failure_hint_names_the_resolved_binary(self, monkeypatch, capsys):
        # A standalone-pin user may have no `snyk` on PATH to run at all.
        monkeypatch.setattr(secrets_hook, "find_snyk_binary", lambda: "/opt/snyk/snyk")

        def _raise_auth_required(*a, **kw):
            raise secrets_hook.AuthRequiredError()

        monkeypatch.setattr(secrets_hook, "run_secrets_scan_with_retries", _raise_auth_required)
        rc, err = self._run(capsys, "scan reported auth required (fail-closed, default)", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert re.search(
            r"^  Snyk CLI not authenticated; blocking commit$",
            err,
            re.M,
        )
        assert re.search(r"^  run `/opt/snyk/snyk auth`$", err, re.M)
        assert re.search(r"^  if that doesn't work, contact your Snyk administrator$", err, re.M)

    def test_scan_error_hint_names_the_resolved_binary(self, monkeypatch, capsys):
        monkeypatch.setattr(secrets_hook, "find_snyk_binary", lambda: "/opt/snyk/snyk")
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan_with_retries",
            lambda *a, **kw: ("retries_exhausted", []),
        )
        rc, err = self._run(capsys, "scan did not complete (fail-closed, default)", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert "run `/opt/snyk/snyk secrets test` manually to check" in err

    def test_unparseable_scan_output_reports_distinct_message(self, monkeypatch, capsys):
        monkeypatch.setattr(
            secrets_hook, "run_secrets_scan_with_retries", lambda *a, **kw: ("unparseable", [])
        )
        rc, err = self._run(capsys, "scan output could not be parsed (fail-closed, default)", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert "scan output could not be parsed; blocking commit" in err

    def test_not_entitled_passes_cli_message_through(self, monkeypatch, capsys):
        monkeypatch.setenv("SECRETS_BLOCK_ON_SCAN_FAILURE", "1")
        cli_message = (
            f"Snyk Secrets is not supported for org {self.FAKE_ORG_ID}: "
            "enable it in Settings > Snyk Secrets"
        )

        def _raise_not_entitled(*a, **kw):
            raise secrets_hook.NotEntitledError(cli_message)

        monkeypatch.setattr(secrets_hook, "run_secrets_scan_with_retries", _raise_not_entitled)
        rc, err = self._run(capsys, "org not entitled to Snyk Secrets", [])
        assert rc == secrets_hook.EXIT_OK
        expected = cli_message.replace(
            "Settings > Snyk Secrets", "Settings\u00a0>\u00a0Snyk\u00a0Secrets"
        )
        assert f"{expected} -- allowing commit without scanning" in self._dewrap(err)
        # The non-breaking spaces keep this phrase from being split across a
        # wrapped line -- confirm it actually lands on one printed line.
        assert any("Settings > Snyk Secrets" in line for line in err.splitlines())

    def test_auth_required_passes_cli_message_through(self, monkeypatch, capsys):
        # Unlike NotEntitledError, auth failures still respect
        # SECRETS_BLOCK_ON_SCAN_FAILURE (blocks by default) -- a fresh
        # `snyk auth` fixes this, so it's not an unconditional allow.
        cli_message = "Use `snyk auth` to authenticate."

        def _raise_auth_required(*a, **kw):
            raise secrets_hook.AuthRequiredError(cli_message)

        monkeypatch.setattr(secrets_hook, "run_secrets_scan_with_retries", _raise_auth_required)
        rc, err = self._run(capsys, "auth failure passes CLI message through", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert f"{cli_message}; blocking commit" in err
        assert "run `/usr/bin/snyk auth`" in err
        assert "if that doesn't work, contact your Snyk administrator" in err

    def test_permanent_scan_failure_passes_cli_message_through(self, monkeypatch, capsys):
        cli_message = "No supported files found."

        def _raise_permanent_failure(*a, **kw):
            raise secrets_hook.PermanentScanFailureError(
                "no files in this commit are eligible to scan", cli_message
            )

        monkeypatch.setattr(secrets_hook, "run_secrets_scan_with_retries", _raise_permanent_failure)
        rc, err = self._run(capsys, "permanent scan failure passes CLI message through", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert f"{cli_message}; blocking commit" in err
        assert "run `/usr/bin/snyk secrets test` manually to check" in err

    def test_permanent_scan_failure_falls_back_when_no_cli_message(self, monkeypatch, capsys):
        def _raise_permanent_failure(*a, **kw):
            raise secrets_hook.PermanentScanFailureError(
                "this commit has more files than Snyk Secrets can scan at once"
            )

        monkeypatch.setattr(secrets_hook, "run_secrets_scan_with_retries", _raise_permanent_failure)
        rc, err = self._run(capsys, "permanent scan failure falls back", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert (
            "this commit has more files than Snyk Secrets can scan at once; blocking commit" in err
        )

    def test_not_entitled_without_a_message_falls_back_to_generic_wording(
        self, monkeypatch, capsys
    ):
        def _raise_not_entitled(*a, **kw):
            raise secrets_hook.NotEntitledError(None)

        monkeypatch.setattr(secrets_hook, "run_secrets_scan_with_retries", _raise_not_entitled)
        rc, err = self._run(capsys, "org not entitled, no message parsed", [])
        assert rc == secrets_hook.EXIT_OK
        assert (
            "org is not entitled to Snyk Secrets -- allowing commit without scanning"
            in self._dewrap(err)
        )

    def test_entitlement_check_failed_always_allows_even_with_block_on_failure(
        self, monkeypatch, capsys
    ):
        monkeypatch.setenv("SECRETS_BLOCK_ON_SCAN_FAILURE", "1")

        def _raise_check_failed(*a, **kw):
            raise secrets_hook.EntitlementCheckFailedError()

        monkeypatch.setattr(secrets_hook, "run_secrets_scan_with_retries", _raise_check_failed)
        rc, err = self._run(capsys, "couldn't confirm Snyk Secrets entitlement", [])
        assert rc == secrets_hook.EXIT_OK
        assert (
            "couldn't confirm whether Snyk Secrets is enabled for this Snyk Org -- allowing "
            "commit without scanning" in self._dewrap(err)
        )

    def test_entitlement_check_failed_passes_cli_message_through(self, monkeypatch, capsys):
        cli_message = "Workflow execution failed: Unable to check if the Secrets feature is enabled.: network error"

        def _raise_check_failed(*a, **kw):
            raise secrets_hook.EntitlementCheckFailedError(cli_message)

        monkeypatch.setattr(secrets_hook, "run_secrets_scan_with_retries", _raise_check_failed)
        rc, err = self._run(capsys, "entitlement check failed, CLI message passed through", [])
        assert rc == secrets_hook.EXIT_OK
        assert f"{cli_message} -- allowing commit without scanning" in self._dewrap(err)

    def test_exhausted_retries_message_reports_real_attempt_count(self, monkeypatch, capsys):
        def fake_concurrent(current_ws, baseline_ws, invocation, deadline):
            return (
                snyk_cli.ScanAttempt("retries_exhausted", [], 3),
                snyk_cli.ScanAttempt("success", [], 1),
            )

        monkeypatch.setattr(secrets_hook, "run_concurrent_scans", fake_concurrent)
        rc, err = self._run(capsys, "scan errored after exhausting retries", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert "scan did not complete after 3 attempts" in err

    def test_unusable_pinned_cli_is_a_prerequisite_failure(self, monkeypatch, capsys):
        sidecar = Path(os.path.expanduser("~")) / ".snyk-studio" / "cli-path"
        sidecar.parent.mkdir(parents=True, exist_ok=True)
        sidecar.write_text("/gone/snyk", encoding="utf-8")
        monkeypatch.setattr(secrets_hook, "find_snyk_binary", lambda: "/gone/snyk")
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan_with_retries",
            lambda *args: pytest.fail("scan should not start"),
        )

        rc, err = self._run(capsys, "unusable pinned CLI", [])

        assert rc == secrets_hook.EXIT_BLOCK
        assert str(sidecar) in err
        assert "does not exist" in err
        assert "scan did not complete" not in err

    def test_no_sidecar_emits_no_stale_pin_warning(self, monkeypatch, capsys):
        monkeypatch.setattr(
            secrets_hook, "run_secrets_scan_with_retries", lambda *a, **kw: ("success", [])
        )
        _, err = self._run(capsys, "no sidecar, no warning", [])
        assert "cli-path" not in err

    def test_hint_quotes_a_binary_path_with_spaces(self, monkeypatch, capsys):
        # _search_paths_windows probes C:\Program Files\Snyk, so a resolved
        # path with spaces is routine -- the hint has to stay runnable.
        monkeypatch.setattr(
            secrets_hook, "find_snyk_binary", lambda: r"C:\Program Files\Snyk\snyk.exe"
        )
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan_with_retries",
            lambda *a, **kw: ("retries_exhausted", []),
        )
        _, err = self._run(capsys, "scan did not complete, spaced binary path", [])
        assert r"run `'C:\Program Files\Snyk\snyk.exe' secrets test`" in err

    def test_scan_timeout_fail_closed_by_default(self, monkeypatch, capsys):
        monkeypatch.setattr(
            secrets_hook, "run_secrets_scan_with_retries", lambda *a, **kw: ("timeout", [])
        )
        rc, err = self._run(capsys, "scan timeout, fail-closed (default)", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert re.search(r"^  scan timed out after 1 attempt; blocking commit$", err, re.M)
        assert "run `/usr/bin/snyk secrets test` manually to check" in err
        assert "increase SECRETS_SCAN_TIMEOUT or set it to -1 for no timeout" in err
        assert "set SECRETS_BLOCK_ON_SCAN_FAILURE=0 to allow the commit" in err

    def test_scan_timeout_allows_when_opted_out(self, monkeypatch, capsys):
        monkeypatch.setenv("SECRETS_BLOCK_ON_SCAN_FAILURE", "0")
        monkeypatch.setattr(
            secrets_hook, "run_secrets_scan_with_retries", lambda *a, **kw: ("timeout", [])
        )
        rc, err = self._run(capsys, "scan timeout, opted out (SECRETS_BLOCK_ON_SCAN_FAILURE=0)", [])
        assert rc == secrets_hook.EXIT_OK
        assert re.search(r"^  scan timed out after 1 attempt; allowing commit$", err, re.M)
        assert "run `/usr/bin/snyk secrets test` manually to check" in err
        assert "increase SECRETS_SCAN_TIMEOUT or set it to -1 for no timeout" in err
        assert "SECRETS_BLOCK_ON_SCAN_FAILURE=0 to allow the commit" not in err

    def test_scan_timeout_message_reports_real_attempt_count(self, monkeypatch, capsys):
        def fake_concurrent(current_ws, baseline_ws, invocation, deadline):
            return (
                snyk_cli.ScanAttempt("timeout", [], 2),
                snyk_cli.ScanAttempt("success", [], 1),
            )

        monkeypatch.setattr(secrets_hook, "run_concurrent_scans", fake_concurrent)
        rc, err = self._run(capsys, "scan timeout after 2 attempts", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert "scan timed out after 2 attempts" in err

    def test_scan_timeout_before_any_attempt_gets_its_own_message(self, monkeypatch, capsys):
        # attempts==0 means the deadline was already gone before a scan
        # ever launched (e.g. git operations used the whole budget) --
        # "timed out after 0 attempts" would misleadingly imply one ran.
        def fake_concurrent(current_ws, baseline_ws, invocation, deadline):
            return (
                snyk_cli.ScanAttempt("timeout", [], 0),
                snyk_cli.ScanAttempt("success", [], 1),
            )

        monkeypatch.setattr(secrets_hook, "run_concurrent_scans", fake_concurrent)
        rc, err = self._run(capsys, "scan timeout before any attempt", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert "scan timed out before it could start" in err
        assert "0 attempts" not in err

    def test_hints_each_land_on_their_own_line_not_crammed_together(self, monkeypatch, capsys):
        monkeypatch.setattr(
            secrets_hook, "run_secrets_scan_with_retries", lambda *a, **kw: ("timeout", [])
        )
        rc, err = self._run(capsys, "scan timeout, hints on separate lines", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert re.search(r"^  scan timed out after 1 attempt; blocking commit$", err, re.M)
        assert re.search(r"^  run `/usr/bin/snyk secrets test` manually to check$", err, re.M)
        assert re.search(
            r"^  increase SECRETS_SCAN_TIMEOUT or set it to -1 for no timeout$", err, re.M
        )
        # None of the hints is parenthesized or semicolon-joined onto the
        # problem line anymore.
        assert "(run" not in err
        assert "check;" not in err

    def test_unexpected_crash_fails_closed_by_default(self, monkeypatch, capsys):
        # A bug we didn't anticipate must still respect the fail-closed
        # default -- Python's own uncaught-exception exit code would
        # otherwise coincidentally already be EXIT_BLOCK.
        def _raise_unexpected_scan_error(*a, **kw):
            raise RuntimeError(self.SYNTHETIC_SCAN_EXCEPTION)

        monkeypatch.setattr(
            secrets_hook, "run_secrets_scan_with_retries", _raise_unexpected_scan_error
        )
        rc, err = self._run(capsys, "unexpected crash, fail-closed (default)", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert "[snyk] internal error: RuntimeError:" in err
        assert self.SYNTHETIC_SCAN_EXCEPTION[:20] in err
        assert "blocking" in err
        assert "set SECRETS_BLOCK_ON_SCAN_FAILURE=0 to allow the commit" in err

    def test_unexpected_crash_with_multiline_message_preserves_newlines(self, monkeypatch, capsys):
        # An exception's own embedded newline must survive as a real,
        # separately-indented continuation line -- not get reflowed into
        # one paragraph the way word-wrapping would otherwise do.
        multiline_message = (
            "connection reset while talking to the Snyk backend\n"
            "retrying was not attempted because SECRETS_SCAN_TIMEOUT=-1"
        )

        def _raise_unexpected_scan_error(*a, **kw):
            raise RuntimeError(multiline_message)

        monkeypatch.setattr(
            secrets_hook, "run_secrets_scan_with_retries", _raise_unexpected_scan_error
        )
        rc, err = self._run(capsys, "unexpected crash, multi-line exception message", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert re.search(
            r"^\[snyk\] internal error: RuntimeError: connection reset while talking to the Snyk "
            r"backend$",
            err,
            re.M,
        )
        assert re.search(
            r"^    retrying was not attempted because SECRETS_SCAN_TIMEOUT=-1; blocking commit$",
            err,
            re.M,
        )

    def test_unexpected_crash_allows_when_opted_out(self, monkeypatch, capsys):
        monkeypatch.setenv("SECRETS_BLOCK_ON_SCAN_FAILURE", "0")

        def _raise_unexpected_scan_error(*a, **kw):
            raise RuntimeError(self.SYNTHETIC_SCAN_EXCEPTION)

        monkeypatch.setattr(
            secrets_hook, "run_secrets_scan_with_retries", _raise_unexpected_scan_error
        )
        rc, err = self._run(
            capsys, "unexpected crash, opted out (SECRETS_BLOCK_ON_SCAN_FAILURE=0)", []
        )
        assert rc == secrets_hook.EXIT_OK
        assert "[snyk] internal error: RuntimeError:" in err
        assert self.SYNTHETIC_SCAN_EXCEPTION[:20] in err
        assert "allowing commit" in err

    def test_unexpected_crash_with_no_message_still_reports_the_exception_type(
        self, monkeypatch, capsys
    ):
        def _raise_unexpected_scan_error_without_message(*a, **kw):
            raise ValueError

        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan_with_retries",
            _raise_unexpected_scan_error_without_message,
        )
        rc, err = self._run(capsys, "unexpected crash with no message", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert "[snyk] internal error: ValueError; blocking commit" in err

    def test_debug_mode(self, monkeypatch, capsys, tmp_path):
        monkeypatch.setattr(secrets_hook, "DEBUG", True)
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan_with_retries",
            lambda *a, **kw: ("success", [self.PRE_EXISTING_FINDING]),
        )
        rc, err = self._run(capsys, "debug mode, clean + pre-existing", [])
        assert rc == secrets_hook.EXIT_OK
        dewrapped = self._dewrap(err)
        assert re.search(r"^  \[debug\] diff strategy: content$", err, re.M)
        assert re.search(r"^  \[debug\] scan scope: 1 file, 0 binary files$", err, re.M)
        assert (
            "[debug] remote-repo-url: (none -- no origin remote configured)" in dewrapped
        )  # no origin remote in this fake repo fixture
        assert f"[debug] scan workspace: {self.current_snapshot_dir} (staged snapshot)" in dewrapped
        assert (
            f"[debug] baseline scan workspace: {self.baseline_snapshot_dir} (0 files)" in dewrapped
        )
        assert "[debug] running concurrent scans:" in err
        assert f"current_workspace={self.current_snapshot_dir}" in err
        assert f"baseline_workspace={self.baseline_snapshot_dir}" in err
        assert "target=." in dewrapped
        assert re.search(r"^  \[debug\] scan took [\d.]+s \(total [\d.]+s\)$", err, re.M)
        log_text = self._persisted_log_text(tmp_path)
        assert "[debug] scan scope: 1 file, 0 binary files" in log_text
        assert f"[debug] scan workspace: {self.current_snapshot_dir} (staged snapshot)" in log_text
        assert re.search(r"^  history: 1 pre-existing finding$", err, re.M)
        assert re.search(
            r"^  done in [\d.]+s -- no blocking secrets found$",
            err,
            re.M,
        )

    def test_debug_mode_shows_configured_remote_url(self, monkeypatch, capsys):
        """Direct visibility that the value fed into the scan (not just the
        post-scan ignore hint) is the real repo's origin remote."""
        monkeypatch.setattr(secrets_hook, "DEBUG", True)
        monkeypatch.setattr(
            secrets_hook,
            "get_remote_url",
            lambda *a, **kw: git_ops.RemoteUrlDecision.ok("git@github.com:acme/repo.git"),
        )
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan_with_retries",
            lambda *a, **kw: ("success", [self.PRE_EXISTING_FINDING]),
        )
        rc, err = self._run(capsys, "debug mode, remote configured", [])
        assert rc == secrets_hook.EXIT_OK
        assert "[debug] remote-repo-url: git@github.com:acme/repo.git" in err

    def test_unsafe_remote_url_is_rejected_when_resolved_cli_is_a_cmd(self, monkeypatch, capsys):
        monkeypatch.setattr(secrets_hook, "find_snyk_binary", lambda: r"C:\snyk\snyk.cmd")
        monkeypatch.setattr(proc, "IS_WINDOWS", True)
        monkeypatch.setattr(
            secrets_hook,
            "get_remote_url",
            lambda *a, **kw: git_ops.RemoteUrlDecision.ok("https://example.com&calc.exe"),
        )
        captured = {}
        monkeypatch.setattr(
            secrets_hook,
            "build_snyk_env",
            lambda discovered: captured.update(snyk_bin=discovered) or {"PATH": ""},
        )

        def fake_retries(workspace, invocation, deadline):
            captured["invocation"] = invocation
            return "success", [self.PRE_EXISTING_FINDING]

        monkeypatch.setattr(secrets_hook, "run_secrets_scan_with_retries", fake_retries)
        monkeypatch.setattr(secrets_hook, "DEBUG", True)
        rc, err = self._run(capsys, "cmd-resolved CLI, unsafe remote", [])
        assert rc == secrets_hook.EXIT_OK
        assert captured["snyk_bin"] == r"C:\snyk\snyk.cmd"
        assert captured["invocation"].remote_url is None
        assert captured["invocation"].needs_shell is True
        assert "[debug] remote-repo-url: (none -- origin remote unsafe" in err

    def test_unsafe_remote_url_is_rejected_for_windows_native_exe(self, monkeypatch, capsys):
        # Every Windows scan uses cmd.exe.
        monkeypatch.setattr(secrets_hook, "find_snyk_binary", lambda: r"C:\snyk\snyk.exe")
        monkeypatch.setattr(proc, "IS_WINDOWS", True)
        monkeypatch.setattr(
            secrets_hook,
            "get_remote_url",
            lambda *a, **kw: git_ops.RemoteUrlDecision.ok("https://example.com&calc.exe"),
        )
        captured = {}

        def fake_retries(workspace, invocation, deadline):
            captured["invocation"] = invocation
            return "success", [self.PRE_EXISTING_FINDING]

        monkeypatch.setattr(secrets_hook, "run_secrets_scan_with_retries", fake_retries)
        rc, _ = self._run(capsys, "exe-resolved CLI, unsafe remote", [])
        assert rc == secrets_hook.EXIT_OK
        assert captured["invocation"].remote_url is None
        assert captured["invocation"].needs_shell is False

    def test_empty_commit_skips_scan_entirely(self, monkeypatch, capsys):
        """An empty commit must skip the scan outright, not fall through
        to scanning something else (e.g. the whole workspace)."""
        monkeypatch.setattr(secrets_hook, "get_staged_files", lambda *a, **kw: [])
        rc, err = self._run(capsys, "empty commit, nothing staged", [])
        assert rc == secrets_hook.EXIT_OK
        assert "[snyk] no staged files, skipping scan" in err
        assert "Scanning" not in err  # no scan of any kind should start

    def test_deprecated_flag_warning_shown_even_on_early_exit(self, monkeypatch, capsys, tmp_path):
        """A deprecated flag is a pure os.environ check with no repo
        dependency -- it must still warn even when the scan itself never
        starts (e.g. an empty commit), so a user doesn't keep a
        deprecated env var set without ever seeing the notice. It must
        also still be persisted to the per-repo log like any other
        warning (requires _LOG_FILE to already be set when it's checked)."""
        fake_flag = deprecated_flags.DeprecatedFlag(
            name="SECRETS_TEMP_TEST_FLAG", message="test message"
        )
        monkeypatch.setitem(deprecated_flags._DEPRECATED_FLAGS, fake_flag.name, fake_flag)
        monkeypatch.setenv(fake_flag.name, "1")
        monkeypatch.setattr(secrets_hook, "get_staged_files", lambda *a, **kw: [])
        rc, err = self._run(capsys, "deprecated flag warned on early exit", [])
        assert rc == secrets_hook.EXIT_OK
        assert "SECRETS_TEMP_TEST_FLAG is no longer supported" in err
        log_text = self._persisted_log_text(tmp_path)
        assert "SECRETS_TEMP_TEST_FLAG is no longer supported" in log_text

    # A realistic checkout-index failure message -- same shape staged_snapshot's
    # real code produces for a permission error, so this scenario's printed
    # output (visible with `-s`) is representative, not a placeholder marker.
    REALISTIC_CHECKOUT_INDEX_FAILURE = (
        "could not snapshot staged content (git checkout-index failed): "
        "error: unable to create file config.py (Permission denied)"
    )

    @classmethod
    def _stub_failing_snapshot(cls, monkeypatch, detail=None):
        detail = detail or cls.REALISTIC_CHECKOUT_INDEX_FAILURE

        @contextmanager
        def _failing_snapshot(repo_root, files, deadline=None):
            raise SnapshotError(detail)
            yield  # pragma: no cover -- unreachable, satisfies the generator protocol

        monkeypatch.setattr(
            secrets_hook, "staged_snapshot", lambda *a, **kw: _failing_snapshot(*a, **kw)
        )

    def test_snapshot_failure_respects_fail_closed_default(self, monkeypatch, capsys):
        # A snapshot failure is a runtime/environment problem (disk full,
        # git subprocess issue), not a "don't know what to scan" case --
        # it respects SECRETS_BLOCK_ON_SCAN_FAILURE like any other scan
        # failure instead of always hard-blocking.
        called = []
        self._stub_failing_snapshot(monkeypatch)
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan_with_retries",
            lambda *a, **kw: called.append(1) or ("success", []),
        )

        rc, err = self._run(capsys, "index snapshot failed, fail-closed default", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert called == []
        dewrapped = self._dewrap(err)
        assert "could not snapshot staged content (git checkout-index failed):" in dewrapped
        assert "unable to create file config.py (Permission denied)" in dewrapped

    def test_snapshot_failure_allows_when_opted_out(self, monkeypatch, capsys):
        called = []
        self._stub_failing_snapshot(monkeypatch)
        monkeypatch.setenv("SECRETS_BLOCK_ON_SCAN_FAILURE", "0")
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan_with_retries",
            lambda *a, **kw: called.append(1) or ("success", []),
        )

        rc, err = self._run(capsys, "index snapshot failed, opted out", [])
        assert rc == secrets_hook.EXIT_OK
        assert called == []
        dewrapped = self._dewrap(err)
        assert "could not snapshot staged content (git checkout-index failed):" in dewrapped
        assert "unable to create file config.py (Permission denied)" in dewrapped

    def test_scratch_dir_creation_failure_respects_fail_closed_default(
        self, monkeypatch, capsys, tmp_path
    ):
        """Real staged_snapshot/_create_scratch_dir code path (only
        tempfile.mkdtemp itself is mocked) -- shows the actual message for a
        disk-full/permission scratch-dir failure, not a stand-in. _stub_prereqs
        replaces staged_snapshot with a fixed fake by default; restore the
        real one so the mocked tempfile.mkdtemp actually gets exercised."""
        monkeypatch.setattr(secrets_hook, "staged_snapshot", staged_snapshot)
        monkeypatch.setattr(tempfile, "gettempdir", lambda: "/private/tmp")
        monkeypatch.setattr(
            tempfile,
            "mkdtemp",
            lambda *a, **kw: (_ for _ in ()).throw(OSError(28, "No space left on device")),
        )
        called = []
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan_with_retries",
            lambda *a, **kw: called.append(1) or ("success", []),
        )

        rc, err = self._run(capsys, "scratch dir creation failed, disk full", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert called == []
        assert "/private/tmp" in err
        assert "No space left on" in err
        assert "device" in err
        assert "TMPDIR" in err

    def test_fallback_flag_no_longer_changes_behavior(self, monkeypatch, capsys):
        """SECRETS_FALLBACK_TO_WORKING_DIR is removed: setting it does not
        restore the old fallback -- the snapshot failure still respects
        SECRETS_BLOCK_ON_SCAN_FAILURE like any other scan failure, and a
        deprecation warning is printed."""
        called = []
        self._stub_failing_snapshot(monkeypatch)
        monkeypatch.setenv("SECRETS_FALLBACK_TO_WORKING_DIR", "1")
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan_with_retries",
            lambda *a, **kw: called.append(1) or ("success", []),
        )

        rc, err = self._run(capsys, "fallback flag set but ignored", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert called == []
        assert "SECRETS_FALLBACK_TO_WORKING_DIR is no longer supported" in err

    def test_snapshot_returning_repo_root_blocks(self, monkeypatch, capsys):
        @contextmanager
        def _repo_root_snapshot(repo_root, files, deadline=None):
            yield repo_root

        monkeypatch.setattr(
            secrets_hook, "staged_snapshot", lambda *a, **kw: _repo_root_snapshot(*a, **kw)
        )
        called = []
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan_with_retries",
            lambda *a, **kw: called.append(1) or ("success", []),
        )

        rc, err = self._run(capsys, "snapshot returned repo root", [])
        assert rc == secrets_hook.EXIT_PREREQ
        assert called == []
        assert (
            "refusing to scan the repository working tree directly; "
            "scan workspace must be a prepared snapshot" in self._dewrap(err)
        )

    def test_binary_file_warning_and_blocks(self, monkeypatch, capsys):
        """A binary file has no line-level diff to check (see
        BINARY_SENTINEL_RANGE), so any finding in it counts as added; the
        user is told why via a visible (non-debug) warning."""
        monkeypatch.setattr(
            secrets_hook,
            "get_added_line_ranges",
            # "config.py" is just the default staged filename _stub_prereqs
            # already wires NEW_FINDING to -- not implying anything about
            # the extension, since binary-ness comes from binary_files here.
            lambda *a, **kw: ({"config.py": [diff_scope.BINARY_SENTINEL_RANGE]}, ["config.py"]),
        )
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan_with_retries",
            lambda *a, **kw: ("success", [self.NEW_FINDING]),
        )
        rc, err = self._run(capsys, "binary file staged, finding blocks", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert "1 binary file staged; can't diff line-by-line, treating the whole file" in err
        assert "scope" in err
        assert re.search(r"^  done in [\d.]+s -- 1 finding blocking commit$", err, re.M)


# ============================================================================
# 12. Subprocess integration: real git plumbing + fake Snyk CLI
# ============================================================================


class TestHookScriptSubprocessWithFakeSnyk:
    """Runs the hook script as a subprocess against a real git repo.

    The Snyk CLI is faked at the executable boundary, so these tests cover
    repo discovery, staged-file/range detection, checkout-index snapshots,
    SARIF parsing, classification, and stderr output without depending on
    auth, network, or detector backend behavior.
    """

    @pytest.fixture
    def fake_snyk_env(self, tmp_path):
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        fake = bin_dir / ("snyk.cmd" if os.name == "nt" else "snyk")
        fake_py = bin_dir / "fake_snyk.py"
        fake_py.write_text(
            textwrap.dedent(
                """
                import json
                import os
                import sys
                from pathlib import Path

                argv_log = os.environ.get("FAKE_SNYK_ARGV_LOG")
                if argv_log:
                    with open(argv_log, "a", encoding="utf-8") as f:
                        f.write(json.dumps(sys.argv[1:]) + "\\n")

                # Any flag (not just --json) must be excluded from the file list --
                # a real --remote-repo-url=... would otherwise be treated as a scan
                # target and blow up trying to stat it.
                files = [arg for arg in sys.argv[3:] if not arg.startswith("--")]
                results = []
                for target in files:
                    target_path = Path(target)
                    candidates = (
                        sorted(p for p in target_path.rglob("*") if p.is_file())
                        if target_path.is_dir()
                        else [target_path]
                    )
                    for path in candidates:
                        filename = path.as_posix()
                        try:
                            lines = path.read_text(encoding="utf-8").splitlines()
                        except OSError:
                            lines = []
                        for line_no, line in enumerate(lines, 1):
                            if "FAKE_SECRET" not in line:
                                continue
                            column = line.index("FAKE_SECRET") + 1
                            results.append(
                                {
                                    "ruleId": "fake/secret",
                                    "level": "error",
                                    "properties": {"priorityScore": 700, "cwe": ["CWE-798"]},
                                    "locations": [
                                        {
                                            "physicalLocation": {
                                                "artifactLocation": {"uri": filename},
                                                "region": {
                                                    "startLine": line_no,
                                                    "startColumn": column,
                                                },
                                            }
                                        }
                                    ],
                                }
                            )
                print(json.dumps({"runs": [{"results": results}]}))
                sys.exit(1 if results else 0)
                """
            ).lstrip(),
            encoding="utf-8",
        )
        if os.name == "nt":
            fake.write_text(f'@echo off\r\n"{sys.executable}" "{fake_py}" %*\r\n')
        else:
            fake.write_text(f"#!{sys.executable}\nexec(open({str(fake_py)!r}).read())\n")
            fake.chmod(0o755)

        home = tmp_path / "home"
        home.mkdir()
        env = os.environ.copy()
        env.update(
            {
                "HOME": str(home),
                "PATH": str(bin_dir) + os.pathsep + env.get("PATH", ""),
                "SNYK_TOKEN": "fake-token",
                "SECRETS_SCAN_TIMEOUT": "5",
            }
        )
        return env

    @staticmethod
    def _run_hook(repo: Path, env: dict) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SECRETS_HOOK_DIR / "snyk_secrets_at_commit.py")],
            cwd=repo,
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
        )

    def test_added_secret_blocks(self, repo, fake_snyk_env):
        _stage(repo, "config.py", 'TOKEN = "FAKE_SECRET"\n')

        result = self._run_hook(repo, fake_snyk_env)

        assert result.returncode == secrets_hook.EXIT_BLOCK
        assert "1 finding blocking commit" in result.stderr
        assert "config.py(1,10): [critical] [fake/secret] [CWE-798]" in result.stderr

    def test_untouched_secret_in_staged_file_warns_as_pre_existing(self, repo, fake_snyk_env):
        _stage(repo, "config.py", 'TOKEN = "FAKE_SECRET"\n')
        subprocess.run(["git", "commit", "-q", "-m", "add old secret"], cwd=repo, check=True)
        (repo / "config.py").write_text('TOKEN = "FAKE_SECRET"\nprint("unrelated")\n')
        subprocess.run(["git", "add", "config.py"], cwd=repo, check=True)

        result = self._run_hook(repo, fake_snyk_env)

        assert result.returncode == secrets_hook.EXIT_OK
        assert "history: 1 pre-existing finding" in result.stderr
        assert "done in " in result.stderr
        assert "no blocking secrets found" in result.stderr

    def test_unstaged_secret_is_not_scanned(self, repo, fake_snyk_env):
        _stage(repo, "config.py", 'TOKEN = "clean"\n')
        (repo / "config.py").write_text('TOKEN = "FAKE_SECRET"\n')

        result = self._run_hook(repo, fake_snyk_env)

        assert result.returncode == secrets_hook.EXIT_OK
        assert "no secrets found" in result.stderr
        assert "FAKE_SECRET" not in result.stderr

    def test_passes_remote_repo_url_to_real_snyk_argv_when_origin_configured(
        self, repo, fake_snyk_env, tmp_path
    ):
        """Proves the real scan invocation (not just the post-scan ignore
        hint) carries --remote-repo-url, so scan and ignore resolve to the
        same finding identity."""
        subprocess.run(
            ["git", "remote", "add", "origin", "git@github.com:acme/repo.git"],
            cwd=repo,
            check=True,
        )
        argv_log = tmp_path / "argv_log.jsonl"
        fake_snyk_env = dict(fake_snyk_env, FAKE_SNYK_ARGV_LOG=str(argv_log))
        _stage(repo, "config.py", 'TOKEN = "FAKE_SECRET"\n')

        result = self._run_hook(repo, fake_snyk_env)

        assert result.returncode == secrets_hook.EXIT_BLOCK
        logged_argvs = [json.loads(line) for line in argv_log.read_text().splitlines()]
        assert logged_argvs, "fake snyk was never invoked"
        for argv in logged_argvs:
            assert "--remote-repo-url=git@github.com:acme/repo.git" in argv

    def test_no_remote_repo_url_flag_when_no_origin_configured(self, repo, fake_snyk_env, tmp_path):
        argv_log = tmp_path / "argv_log.jsonl"
        fake_snyk_env = dict(fake_snyk_env, FAKE_SNYK_ARGV_LOG=str(argv_log))
        _stage(repo, "config.py", 'TOKEN = "FAKE_SECRET"\n')

        result = self._run_hook(repo, fake_snyk_env)

        assert result.returncode == secrets_hook.EXIT_BLOCK
        logged_argvs = [json.loads(line) for line in argv_log.read_text().splitlines()]
        assert logged_argvs, "fake snyk was never invoked"
        for argv in logged_argvs:
            assert not any(arg.startswith("--remote-repo-url=") for arg in argv)

    def test_unsafe_looking_remote_url_reaches_snyk_argv_literally_without_a_shell(
        self, repo, fake_snyk_env, tmp_path
    ):
        # The fake snyk here is a plain executable, not a .cmd/.bat, so
        # needs_shell() is False -- shell=False means this value is never
        # parsed by anything, just delivered as one literal argv element.
        # The real proof of safety: it arrives unmangled, not split into
        # separate shell-interpreted tokens (see lib.proc.needs_shell).
        subprocess.run(
            ["git", "remote", "add", "origin", "https://example.com&calc.exe"],
            cwd=repo,
            check=True,
        )
        argv_log = tmp_path / "argv_log.jsonl"
        fake_snyk_env = dict(fake_snyk_env, FAKE_SNYK_ARGV_LOG=str(argv_log))
        _stage(repo, "config.py", 'TOKEN = "FAKE_SECRET"\n')

        result = self._run_hook(repo, fake_snyk_env)

        assert result.returncode == secrets_hook.EXIT_BLOCK
        logged_argvs = [json.loads(line) for line in argv_log.read_text().splitlines()]
        assert logged_argvs, "fake snyk was never invoked"
        for argv in logged_argvs:
            assert "--remote-repo-url=https://example.com&calc.exe" in argv


# ============================================================================
# 13. End-to-end: the "content" diff strategy. Real git repos throughout
# (real commits/mv/edits/snapshots) -- only the Snyk scan itself is mocked.
# ============================================================================


class TestContentStrategyEndToEnd:
    @pytest.fixture(autouse=True)
    def _stub_snyk(self, monkeypatch):
        monkeypatch.setattr(secrets_hook, "find_snyk_binary", lambda: "/usr/bin/snyk")
        monkeypatch.setattr(secrets_hook, "check_snyk_auth", lambda: "token")

    # The touched-line/unchanged-secret scenario itself is covered by
    # TestLineStrategyKnownLimitation below.

    def test_genuinely_new_secret_still_blocks(self, repo, monkeypatch):
        _stage(repo, "app.py", "def add(a, b):\n    return a + b\n")
        subprocess.run(["git", "commit", "-q", "-m", "add app"], cwd=repo, check=True)
        (repo / "app.py").write_text(
            'def add(a, b):\n    return a + b\n\nKEY = "brand-new-secret"\n'
        )
        subprocess.run(["git", "add", "app.py"], cwd=repo, check=True)

        current_finding = findings.Finding(
            id="generic-secret",
            severity="high",
            file_path="app.py",
            start_line=4,
            start_column=7,
            end_line=4,
            end_column=25,
        )

        def fake_run_concurrent_scans(current_ws, baseline_ws, invocation, deadline):
            return (
                snyk_cli.ScanAttempt("success", [current_finding], 1),
                snyk_cli.ScanAttempt("success", [], 1),
            )

        monkeypatch.setattr(secrets_hook, "run_concurrent_scans", fake_run_concurrent_scans)
        monkeypatch.chdir(repo)
        assert secrets_hook.main([]) == secrets_hook.EXIT_BLOCK

    def test_only_modified_file_is_scanned_when_repo_has_many_baseline_secrets(
        self, repo, monkeypatch
    ):
        for index in range(8):
            _stage(repo, f"config_{index}.py", f'KEY = "baseline-{index}"\n')
        subprocess.run(["git", "commit", "-q", "-m", "add baseline secrets"], cwd=repo, check=True)

        (repo / "config_3.py").write_text('KEY = "baseline-3"\nNEW_KEY = "brand-new-secret"\n')
        subprocess.run(["git", "add", "config_3.py"], cwd=repo, check=True)

        current_existing = findings.Finding(
            id="generic-secret",
            severity="high",
            file_path="config_3.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=19,
        )
        current_new = findings.Finding(
            id="generic-secret",
            severity="high",
            file_path="config_3.py",
            start_line=2,
            start_column=11,
            end_line=2,
            end_column=29,
        )
        baseline_existing = findings.Finding(
            id="generic-secret",
            severity="high",
            file_path="config_3.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=19,
        )

        def _workspace_files(workspace: Path) -> list[str]:
            return sorted(
                p.relative_to(workspace).as_posix() for p in workspace.rglob("*") if p.is_file()
            )

        def fake_run_concurrent_scans(current_ws, baseline_ws, invocation, deadline):
            assert _workspace_files(current_ws) == ["config_3.py"]
            assert _workspace_files(baseline_ws) == ["config_3.py"]
            assert "brand-new-secret" in (current_ws / "config_3.py").read_text(encoding="utf-8")
            assert "brand-new-secret" not in (baseline_ws / "config_3.py").read_text(
                encoding="utf-8"
            )
            return (
                snyk_cli.ScanAttempt("success", [current_existing, current_new], 1),
                snyk_cli.ScanAttempt("success", [baseline_existing], 1),
            )

        monkeypatch.setattr(secrets_hook, "run_concurrent_scans", fake_run_concurrent_scans)
        monkeypatch.chdir(repo)
        assert secrets_hook.main([]) == secrets_hook.EXIT_BLOCK

    def test_real_rename_with_pre_existing_secret_does_not_block(self, repo, monkeypatch):
        _stage(repo, "old_name.py", 'KEY = "abc123"\n')
        subprocess.run(["git", "commit", "-q", "-m", "add old_name"], cwd=repo, check=True)
        subprocess.run(["git", "mv", "old_name.py", "new_name.py"], cwd=repo, check=True)

        current_finding = findings.Finding(
            id="generic-secret",
            severity="high",
            file_path="new_name.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=14,
        )
        baseline_finding = findings.Finding(
            id="generic-secret",
            severity="high",
            file_path="old_name.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=14,
        )

        def fake_run_concurrent_scans(current_ws, baseline_ws, invocation, deadline):
            return (
                snyk_cli.ScanAttempt("success", [current_finding], 1),
                snyk_cli.ScanAttempt("success", [baseline_finding], 1),
            )

        monkeypatch.setattr(secrets_hook, "run_concurrent_scans", fake_run_concurrent_scans)
        monkeypatch.chdir(repo)
        assert secrets_hook.main([]) == secrets_hook.EXIT_OK

    def test_baseline_scan_failure_falls_back_gracefully(self, repo, monkeypatch, capsys):
        # app.py must exist at HEAD, so this tests the baseline scan
        # itself timing out, not the no-baseline-content fast path.
        _stage(repo, "app.py", 'KEY = "abc123"\n')
        subprocess.run(["git", "commit", "-q", "-m", "add app"], cwd=repo, check=True)
        (repo / "app.py").write_text('KEY = "abc123"  # rotated soon\n')
        subprocess.run(["git", "add", "app.py"], cwd=repo, check=True)

        current_finding = findings.Finding(
            id="generic-secret",
            severity="high",
            file_path="app.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=14,
        )

        def fake_run_concurrent_scans(current_ws, baseline_ws, invocation, deadline):
            return (
                snyk_cli.ScanAttempt("success", [current_finding], 1),
                snyk_cli.ScanAttempt("timeout", [], 1),
            )

        monkeypatch.setattr(secrets_hook, "run_concurrent_scans", fake_run_concurrent_scans)
        monkeypatch.chdir(repo)
        # Falls back to line-diff, which blocks on the touched line since
        # it can't know the secret text itself is unchanged.
        assert secrets_hook.main([]) == secrets_hook.EXIT_BLOCK
        err = capsys.readouterr().err
        # A degraded-detection run must be visible without SECRETS_HOOK_DEBUG --
        # dewrapped since the message is long enough to word-wrap.
        assert "baseline scan timeout; falling back to line-diff classification" in re.sub(
            r"\n\s+", " ", err
        )

    def test_ref_snapshot_failure_falls_back_gracefully_and_is_visible(
        self, repo, monkeypatch, capsys
    ):
        # Distinct from the test above: here ref_snapshot itself fails
        # (e.g. git archive/extraction broke), not the baseline scan run
        # against an already-successful snapshot. Both must be equally
        # visible, not just the latter.
        _stage(repo, "app.py", 'KEY = "abc123"\n')
        subprocess.run(["git", "commit", "-q", "-m", "add app"], cwd=repo, check=True)
        (repo / "app.py").write_text('KEY = "abc123"  # rotated soon\n')
        subprocess.run(["git", "add", "app.py"], cwd=repo, check=True)

        current_finding = findings.Finding(
            id="generic-secret",
            severity="high",
            file_path="app.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=14,
        )

        @contextmanager
        def _failed_ref_snapshot(repo_root, ref, files, deadline=None):
            yield None, set(), True

        monkeypatch.setattr(secrets_hook, "ref_snapshot", _failed_ref_snapshot)
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan_with_retries",
            lambda *a, **kw: snyk_cli.ScanAttempt("success", [current_finding], 1),
        )
        monkeypatch.chdir(repo)
        assert secrets_hook.main([]) == secrets_hook.EXIT_BLOCK
        err = capsys.readouterr().err
        assert "baseline scan unavailable; falling back to line-diff classification" in re.sub(
            r"\n\s+", " ", err
        )

    def test_get_rename_map_failure_does_not_abort_commit(self, repo, monkeypatch):
        # An empty rename map (as on git failure) must not fail-closed
        # the whole commit.
        _stage(repo, "app.py", 'KEY = "abc123"\n')
        subprocess.run(["git", "commit", "-q", "-m", "add app"], cwd=repo, check=True)
        (repo / "app.py").write_text('KEY = "abc123"\nEXTRA = 1\n')
        subprocess.run(["git", "add", "app.py"], cwd=repo, check=True)

        monkeypatch.setattr(secrets_hook, "get_rename_map", lambda *a, **kw: {})
        monkeypatch.setattr(
            secrets_hook,
            "run_concurrent_scans",
            lambda *a, **kw: (
                snyk_cli.ScanAttempt("success", [], 1),
                snyk_cli.ScanAttempt("success", [], 1),
            ),
        )
        monkeypatch.chdir(repo)
        assert secrets_hook.main([]) == secrets_hook.EXIT_OK


# ============================================================================
# 13. "line" vs. "content", same scenario: xfail(strict=True) for "line"
# (a known limitation) and a genuine pass for "content" (the fix). strict
# turns an unexpected "line" pass into a hard failure, so this can't go
# silently stale if the limitation is ever actually fixed.
# ============================================================================


class TestLineStrategyKnownLimitation:
    """The line-diff heuristic (still used internally whenever there's no
    real baseline to compare against -- see lib/baseline.py's module
    docstring) blocks on any touched line, even when the secret's own
    matched text is unchanged. The "content" strategy, which has a real
    baseline here, does not have this limitation."""

    @pytest.fixture(autouse=True)
    def _stub_snyk(self, monkeypatch):
        monkeypatch.setattr(secrets_hook, "find_snyk_binary", lambda: "/usr/bin/snyk")
        monkeypatch.setattr(secrets_hook, "check_snyk_auth", lambda: "token")

    def test_touched_line_with_unchanged_secret_does_not_block(self, repo, monkeypatch):
        _stage(repo, "app.py", 'KEY = "abc123"\n')
        subprocess.run(["git", "commit", "-q", "-m", "add app"], cwd=repo, check=True)
        (repo / "app.py").write_text('KEY = "abc123"  # rotated soon\n')
        subprocess.run(["git", "add", "app.py"], cwd=repo, check=True)

        current_finding = findings.Finding(
            id="generic-secret",
            severity="high",
            file_path="app.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=14,
        )
        baseline_finding = findings.Finding(
            id="generic-secret",
            severity="high",
            file_path="app.py",
            start_line=1,
            start_column=7,
            end_line=1,
            end_column=14,
        )

        def fake_run_concurrent_scans(current_ws, baseline_ws, invocation, deadline):
            return (
                snyk_cli.ScanAttempt("success", [current_finding], 1),
                snyk_cli.ScanAttempt("success", [baseline_finding], 1),
            )

        monkeypatch.setattr(secrets_hook, "run_concurrent_scans", fake_run_concurrent_scans)
        monkeypatch.chdir(repo)

        assert secrets_hook.main([]) == secrets_hook.EXIT_OK


# ============================================================================
# 14. lib/persistent_log.py -- the always-on, per-repo log, adopted verbatim
# from the SAI hooks' own ~/.snyk-studio/.../ws/<name>/log.txt framework
# (see secure_at_inception's platform_utils.py). Non-configurable by design:
# no env override, no opt-out.
# ============================================================================


class TestPersistentLog:
    def test_path_under_home_snyk_studio(self, tmp_path, monkeypatch):
        # The "secrets-hooks" component deliberately keeps the pre-rename
        # spelling of the recipe id so logs already on disk stay discoverable by
        # the diagnostic bundle. Renaming it here and in persistent_log.py
        # together would leave the suite green while orphaning those logs.
        monkeypatch.setattr(os.path, "expanduser", lambda p: p.replace("~", str(tmp_path)))
        path = persistent_log.resolve_log_file("/home/user/my-repo")
        expected = os.path.join(
            str(tmp_path),
            ".snyk-studio",
            "git-hooks",
            "secrets-hooks",
            "ws",
            "my-repo",
            "log.txt",
        )
        assert path == expected

    def test_basename_sanitizes_non_alphanumerics(self):
        assert persistent_log._safe_workspace_name("/repos/My Repo! (v2)") == "My-Repo---v2-"

    def test_basename_falls_back_when_empty(self):
        assert persistent_log._safe_workspace_name("/") == "workspace"

    def test_append_creates_parent_dir_and_file_with_restrictive_perms(self, tmp_path):
        log_file = str(tmp_path / "ws" / "repo" / "log.txt")
        persistent_log.append_log("hello", log_file)

        assert Path(log_file).is_file()
        content = Path(log_file).read_text(encoding="utf-8")
        assert content.endswith("hello\n")
        assert re.match(r"^\[\d{4}-\d{2}-\d{2}T[\d:.]+\] hello\n$", content)

        if sys.platform != "win32":
            parent_mode = Path(log_file).parent.stat().st_mode & 0o777
            file_mode = Path(log_file).stat().st_mode & 0o777
            assert parent_mode == 0o700
            assert file_mode == 0o600

    def test_append_appends_across_calls(self, tmp_path):
        log_file = str(tmp_path / "log.txt")
        persistent_log.append_log("first", log_file)
        persistent_log.append_log("second", log_file)
        lines = Path(log_file).read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
        assert lines[0].endswith("first")
        assert lines[1].endswith("second")

    def test_rotates_at_max_bytes(self, tmp_path, monkeypatch):
        monkeypatch.setattr(persistent_log, "LOG_MAX_BYTES", 10)
        log_file = str(tmp_path / "log.txt")
        persistent_log.append_log("first message, well over ten bytes", log_file)
        persistent_log.append_log("second", log_file)

        assert Path(log_file + ".1").is_file()
        assert "first message" in Path(log_file + ".1").read_text(encoding="utf-8")
        assert Path(log_file).read_text(encoding="utf-8").strip().endswith("second")

    def test_missing_log_file_is_a_no_op(self):
        persistent_log.append_log("hello", "")  # must not raise

    @pytest.mark.skipif(sys.platform == "win32", reason="posix flock only")
    def test_unix_lock_gives_up_instead_of_hanging_forever(self, tmp_path, monkeypatch):
        import fcntl

        monkeypatch.setattr(persistent_log, "_LOCK_TIMEOUT_SECONDS", 0.2)
        monkeypatch.setattr(persistent_log, "_LOCK_POLL_INTERVAL_SECONDS", 0.01)
        lock_path = str(tmp_path / "log.txt.lock")

        # Simulates a stuck sibling process holding the lock indefinitely.
        blocker_fd = open(lock_path, "w")
        fcntl.flock(blocker_fd, fcntl.LOCK_EX)
        try:
            start = time.monotonic()
            with persistent_log.file_lock(lock_path):
                pass
            assert time.monotonic() - start < 2.0
        finally:
            fcntl.flock(blocker_fd, fcntl.LOCK_UN)
            blocker_fd.close()

    @pytest.mark.skipif(sys.platform == "win32", reason="posix flock only")
    def test_unix_lock_gives_up_immediately_on_non_retryable_error(self, tmp_path, monkeypatch):
        import fcntl

        # A non-contention OSError (e.g. flock unsupported on this
        # filesystem) will never clear -- must not be retried for the
        # full timeout like real lock contention is.
        monkeypatch.setattr(persistent_log, "_LOCK_TIMEOUT_SECONDS", 5.0)

        def _always_unsupported(*a, **kw):
            raise OSError("Operation not supported")

        monkeypatch.setattr(fcntl, "flock", _always_unsupported)
        lock_path = str(tmp_path / "log.txt.lock")

        start = time.monotonic()
        with persistent_log.file_lock(lock_path):
            pass
        assert time.monotonic() - start < 1.0

    def test_unwritable_path_does_not_raise(self, tmp_path):
        # A file where a parent dir needs to be created makes os.makedirs
        # fail reliably, cross-platform.
        blocker = tmp_path / "not-a-dir"
        blocker.write_text("x", encoding="utf-8")
        persistent_log.append_log("hello", str(blocker / "sub" / "log.txt"))
