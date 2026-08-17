"""Tests for the secrets-only pre-commit hook recipe: manifest wiring,
the pure-Python diff/finding logic in `secrets_at_commit/lib/`, and the
entry script's fail-open/fail-closed contract."""

from __future__ import annotations

import importlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import textwrap
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
from lib.index_snapshot import ref_snapshot, staged_snapshot, working_tree_snapshot  # noqa: E402


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
    # Most tests are written against the default "line" strategy -- don't
    # let a real shell env with SECRETS_DIFF_STRATEGY=content set leak in
    # and change behavior out from under them. Tests that specifically
    # exercise the "content" strategy set this themselves.
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
        added, pre = diff_scope.split_added_vs_pre_existing(
            [self._finding(line=5)], {"app.py": [(1, 10)]}
        )
        assert added == [self._finding(line=5)]
        assert pre == []

    def test_line_outside_range_is_pre_existing(self):
        added, pre = diff_scope.split_added_vs_pre_existing(
            [self._finding(line=50)], {"app.py": [(1, 10)]}
        )
        assert added == []
        assert pre == [self._finding(line=50)]

    def test_file_with_no_ranges_is_all_pre_existing(self):
        added, pre = diff_scope.split_added_vs_pre_existing([self._finding()], {})
        assert added == []
        assert len(pre) == 1

    def test_backslash_path_from_finding_still_matches_forward_slash_range(self):
        finding = findings.Finding(file_path="src\\app.py", start_line=5)
        added, pre = diff_scope.split_added_vs_pre_existing([finding], {"src/app.py": [(1, 10)]})
        assert added == [finding]
        assert pre == []

    def test_multiline_finding_is_added_when_only_its_end_overlaps_a_range(self):
        # A multi-line match (e.g. a PEM block) whose start_line sits above
        # an edit but whose end_line falls inside it must still count as
        # added -- checking start_line alone would miss this.
        finding = findings.Finding(file_path="app.py", start_line=8, end_line=12)
        added, pre = diff_scope.split_added_vs_pre_existing([finding], {"app.py": [(10, 15)]})
        assert added == [finding]
        assert pre == []

    def test_multiline_finding_spanning_entirely_over_a_range_is_added(self):
        # Neither endpoint falls literally inside the range, but the range
        # is fully contained within the finding's span.
        finding = findings.Finding(file_path="app.py", start_line=1, end_line=20)
        added, pre = diff_scope.split_added_vs_pre_existing([finding], {"app.py": [(10, 12)]})
        assert added == [finding]
        assert pre == []

    def test_missing_start_line_is_added_not_silently_pre_existing(self):
        # A finding with no usable position (e.g. SARIF omitted startLine,
        # so it defaults to 0) must never be classified as pre-existing --
        # that would silently let a blocking finding through as pre-existing.
        finding = findings.Finding(file_path="app.py", start_line=0)
        added, pre = diff_scope.split_added_vs_pre_existing([finding], {"app.py": [(1, 10)]})
        assert added == [finding]
        assert pre == []

    def test_missing_start_line_is_added_even_with_no_ranges_for_file(self):
        finding = findings.Finding(file_path="app.py", start_line=0)
        added, pre = diff_scope.split_added_vs_pre_existing([finding], {})
        assert added == [finding]
        assert pre == []


# ============================================================================
# 3. lib/index_snapshot.py
# ============================================================================


class TestStagedSnapshot:
    def test_no_files_yields_none(self, repo):
        with staged_snapshot(repo, []) as snap:
            assert snap is None

    def test_success_checks_out_index_content(self, repo):
        _stage(repo, "app.py", "one\n")
        with staged_snapshot(repo, ["app.py"]) as snap:
            assert snap is not None
            assert (snap / "app.py").read_text() == "one\n"

    def test_unstaged_edit_not_reflected_in_snapshot(self, repo):
        """The whole point: snapshot reflects the index, not the working tree."""
        _stage(repo, "app.py", "staged content\n")
        (repo / "app.py").write_text("unstaged edit on top\n")
        with staged_snapshot(repo, ["app.py"]) as snap:
            assert (snap / "app.py").read_text() == "staged content\n"

    def test_failure_yields_none(self, repo, monkeypatch):
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **kw: subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="<GIT_CHECKOUT_INDEX_ERROR>"
            ),
        )
        with staged_snapshot(repo, ["app.py"]) as snap:
            assert snap is None

    def test_hung_checkout_index_times_out_instead_of_hanging(self, repo, monkeypatch):
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **kw: (_ for _ in ()).throw(
                subprocess.TimeoutExpired(cmd="git", timeout=kw.get("timeout"))
            ),
        )
        with staged_snapshot(repo, ["app.py"]) as snap:
            assert snap is None

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


class TestWorkingTreeSnapshot:
    def test_no_files_yields_none(self, repo):
        with working_tree_snapshot(repo, []) as snap:
            assert snap is None

    def test_copies_only_requested_working_tree_files(self, repo):
        _stage(repo, "app.py", "staged content\n")
        (repo / "app.py").write_text("working tree content\n")
        (repo / "ignored.py").write_text("do not copy me\n")

        with working_tree_snapshot(repo, ["app.py"]) as snap:
            assert snap is not None
            assert snap != repo
            assert (snap / "app.py").read_text() == "working tree content\n"
            assert not (snap / "ignored.py").exists()

    def test_missing_file_yields_none(self, repo):
        with working_tree_snapshot(repo, ["missing.py"]) as snap:
            assert snap is None

    def test_rejects_paths_outside_repo(self, repo):
        with working_tree_snapshot(repo, ["../outside.py"]) as snap:
            assert snap is None

    def test_temp_dir_cleaned_up_even_on_exception(self, repo):
        _stage(repo, "app.py", "one\n")
        captured: list[Path] = []

        def _raise_inside_snapshot():
            with working_tree_snapshot(repo, ["app.py"]) as snap:
                assert snap is not None
                captured.append(snap)
                raise RuntimeError("<TEST_EXCEPTION_INSIDE_WORKING_TREE_SNAPSHOT_CONTEXT>")

        with pytest.raises(RuntimeError):
            _raise_inside_snapshot()
        assert not captured[0].exists()


class TestRefSnapshot:
    def test_no_files_yields_none(self, repo):
        with ref_snapshot(repo, "HEAD", []) as (snap, existing):
            assert snap is None
            assert existing == set()

    def test_extracts_correct_ref_content(self, repo):
        _stage(repo, "app.py", "one\n")
        subprocess.run(["git", "commit", "-q", "-m", "add app"], cwd=repo, check=True)
        with ref_snapshot(repo, "HEAD", ["app.py"]) as (snap, existing):
            assert existing == {"app.py"}
            assert (snap / "app.py").read_text() == "one\n"

    def test_brand_new_file_gracefully_excluded(self, repo):
        # app.py is staged but not yet committed -- doesn't exist at HEAD.
        _stage(repo, "app.py", "one\n")
        with ref_snapshot(repo, "HEAD", ["app.py"]) as (snap, existing):
            assert snap is None
            assert existing == set()

    def test_mix_of_existing_and_new_files(self, repo):
        # A new file alongside an existing one must not lose baseline
        # coverage for the existing one.
        _stage(repo, "existing.py", "one\n")
        subprocess.run(["git", "commit", "-q", "-m", "add existing"], cwd=repo, check=True)
        _stage(repo, "brand_new.py", "two\n")
        with ref_snapshot(repo, "HEAD", ["existing.py", "brand_new.py"]) as (snap, existing):
            assert existing == {"existing.py"}
            assert (snap / "existing.py").read_text() == "one\n"
            assert not (snap / "brand_new.py").exists()

    def test_bad_ref_yields_none(self, repo):
        _stage(repo, "app.py", "one\n")
        subprocess.run(["git", "commit", "-q", "-m", "add app"], cwd=repo, check=True)
        with ref_snapshot(repo, "not-a-real-ref", ["app.py"]) as (snap, existing):
            assert snap is None
            assert existing == set()

    def test_hung_git_archive_times_out_instead_of_hanging(self, repo, monkeypatch):
        _stage(repo, "app.py", "one\n")
        subprocess.run(["git", "commit", "-q", "-m", "add app"], cwd=repo, check=True)
        real_run = subprocess.run

        def fake_run(args, *a, **kw):
            if "archive" in args:
                raise subprocess.TimeoutExpired(cmd="git", timeout=kw.get("timeout"))
            return real_run(args, *a, **kw)

        monkeypatch.setattr(subprocess, "run", fake_run)
        with ref_snapshot(repo, "HEAD", ["app.py"]) as (snap, existing):
            assert snap is None
            assert existing == set()

    def test_temp_dir_cleaned_up_even_on_exception(self, repo):
        _stage(repo, "app.py", "one\n")
        subprocess.run(["git", "commit", "-q", "-m", "add app"], cwd=repo, check=True)
        captured: list[Path] = []

        def _raise_inside_snapshot():
            with ref_snapshot(repo, "HEAD", ["app.py"]) as (snap, _existing):
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

    def test_extract_archive_end_to_end_rejects_traversal(self, tmp_path, monkeypatch):
        # Forces the pre-3.12 fallback path regardless of the actual interpreter.
        monkeypatch.setattr(index_snapshot.sys, "version_info", (3, 8, 0))
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

            def extract(self, member: tarfile.TarInfo, path: Path) -> None:
                if member is file_member:
                    (Path(path) / member.name).write_bytes(b"hello")

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
        added, pre = diff_scope.split_added_vs_pre_existing(parsed, {"app.py": [(1, 10)]})
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


class TestFilterBySeverity:
    @staticmethod
    def _finding(severity):
        return findings.Finding(id=severity, severity=severity)

    def test_default_threshold_is_medium(self, monkeypatch):
        monkeypatch.delenv("SECRETS_MIN_BLOCK_SEVERITY", raising=False)
        out = findings.filter_by_severity([self._finding("low"), self._finding("medium")])
        assert [f.id for f in out] == ["medium"]

    def test_custom_threshold(self, monkeypatch):
        monkeypatch.setenv("SECRETS_MIN_BLOCK_SEVERITY", "critical")
        out = findings.filter_by_severity([self._finding("high"), self._finding("critical")])
        assert [f.id for f in out] == ["critical"]

    def test_invalid_threshold_falls_back_to_medium(self, monkeypatch):
        monkeypatch.setenv("SECRETS_MIN_BLOCK_SEVERITY", "not-a-severity")
        out = findings.filter_by_severity([self._finding("low"), self._finding("high")])
        assert [f.id for f in out] == ["high"]


# ============================================================================
# 5. lib/snyk_cli.py
# ============================================================================


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

    def test_stale_sidecar_pin_falls_back_to_path(self, monkeypatch, tmp_path):
        self._pin(str(tmp_path / "uninstalled" / "snyk"))
        on_path = self._fake_cli_on_path(tmp_path / "npm-bin")
        monkeypatch.setenv("PATH", str(on_path.parent))
        assert snyk_cli.find_snyk_binary() == str(on_path)

    @pytest.mark.skipif(os.name == "nt", reason="X_OK is not meaningful on Windows")
    def test_non_executable_pin_falls_back_to_path(self, monkeypatch, tmp_path):
        self._pin(str(self._fake_cli(tmp_path / "standalone" / "snyk", executable=False)))
        on_path = self._fake_cli_on_path(tmp_path / "npm-bin")
        monkeypatch.setenv("PATH", str(on_path.parent))
        assert snyk_cli.find_snyk_binary() == str(on_path)

    def test_relative_pin_is_ignored(self, monkeypatch, tmp_path):
        # A relative pin would resolve against the scan workspace -- a
        # snapshot of the content being committed -- not the install dir.
        self._fake_cli(tmp_path / "cwd" / "snyk")
        monkeypatch.chdir(tmp_path / "cwd")
        self._pin("snyk")
        on_path = self._fake_cli_on_path(tmp_path / "npm-bin")
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
        assert snyk_cli._snyk_env()["PATH"].split(os.pathsep)[0] == str(pinned.parent)

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

    def test_interior_empty_path_entry_is_dropped(self, tmp_path):
        pinned = self._fake_cli(tmp_path / "standalone" / "snyk")
        self._pin(str(pinned))
        env = {"PATH": os.pathsep.join(["/usr/bin", "", "/bin"])}
        snyk_cli._augment_path_for_snyk(env)
        assert "" not in env["PATH"].split(os.pathsep)

    def test_pin_problem_names_the_failed_check(self, tmp_path):
        missing = tmp_path / "gone" / "snyk"
        assert snyk_cli._pin_problem(str(missing)) == f'pins "{missing}", which does not exist'
        assert snyk_cli._pin_problem("snyk") == 'pins "snyk", which is not an absolute path'
        assert snyk_cli._pin_problem("") == "is empty or unreadable"
        assert snyk_cli._pin_problem(str(self._fake_cli(tmp_path / "ok" / "snyk"))) is None

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

    def test_stale_message_does_not_suggest_falling_back_to_path(self, tmp_path):
        # find_snyk_binary() probes PATH before this message is reached, so
        # deleting the sidecar to "fall back to PATH" is a guaranteed no-op.
        self._pin(str(tmp_path / "uninstalled" / "snyk"))
        message = secrets_hook._cli_not_found_message()
        assert "delete" not in message
        assert "no snyk on PATH either" in message

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


class TestResolveScanFiles:
    def test_no_ignore_patterns_passthrough(self, monkeypatch):
        monkeypatch.delenv("SECRETS_IGNORE_PATHS", raising=False)
        assert snyk_cli.resolve_scan_files(["a.py", "b.py"]) == ["a.py", "b.py"]

    def test_excludes_matching_glob(self, monkeypatch):
        monkeypatch.setenv("SECRETS_IGNORE_PATHS", "fixtures/*,*.lock")
        out = snyk_cli.resolve_scan_files(["fixtures/x.py", "app.py", "yarn.lock"])
        assert out == ["app.py"]

    def test_multiple_patterns_are_comma_separated_and_trimmed(self, monkeypatch):
        monkeypatch.setenv("SECRETS_IGNORE_PATHS", " a.py , b.py ")
        out = snyk_cli.resolve_scan_files(["a.py", "b.py", "c.py"])
        assert out == ["c.py"]


class TestRunSecretsScan:
    def test_passes_timeout_to_subprocess(self, monkeypatch, tmp_path):
        captured = {}

        def fake_run(*args, **kwargs):
            captured.update(kwargs)
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="{}", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        snyk_cli.run_secrets_scan(tmp_path, "snyk", timeout=3.5)
        assert captured["timeout"] == 3.5

    def test_scan_uses_workspace_root_as_single_snyk_input(self, monkeypatch, tmp_path):
        captured = {}
        clean_sarif = json.dumps({"runs": [{"results": []}]})

        def fake_run(*args, **kwargs):
            captured["args"] = args[0]
            return subprocess.CompletedProcess(args=[], returncode=0, stdout=clean_sarif, stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        status, out = snyk_cli.run_secrets_scan(tmp_path, "snyk", timeout=1)
        assert status == "success"
        assert out == []
        assert captured["args"] == ["snyk", "secrets", "test", ".", "--json"]

    def test_timeout_expired_yields_timeout_status(self, monkeypatch, tmp_path):
        def fake_run(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd="snyk", timeout=1)

        monkeypatch.setattr(subprocess, "run", fake_run)
        status, out = snyk_cli.run_secrets_scan(tmp_path, "snyk", timeout=1)
        assert status == "timeout"
        assert out == []

    def test_auth_error_pattern_classified(self, monkeypatch, tmp_path):
        def fake_run(*args, **kwargs):
            return subprocess.CompletedProcess(
                args=[], returncode=2, stdout="", stderr="MissingApiTokenError: run snyk auth"
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        status, _ = snyk_cli.run_secrets_scan(tmp_path, "snyk", timeout=1)
        assert status == "auth_required"

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
        status, out = snyk_cli.run_secrets_scan(tmp_path, "snyk", timeout=1)
        assert status == "error"
        assert out == []

    def test_shell_and_creationflags_match_platform(self, monkeypatch, tmp_path):
        captured = {}

        def fake_run(*args, **kwargs):
            captured.update(kwargs)
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="{}", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        snyk_cli.run_secrets_scan(tmp_path, "snyk", timeout=1)
        assert captured["shell"] == proc.IS_WINDOWS
        assert captured["creationflags"] == proc.CREATE_NO_WINDOW


class TestRunConcurrentScans:
    def test_both_scans_invoked_with_their_own_workspace(self, monkeypatch, tmp_path):
        calls = []

        def fake_run_secrets_scan(workspace, snyk_bin, timeout):
            calls.append(workspace)
            return "success", []

        monkeypatch.setattr(snyk_cli, "run_secrets_scan", fake_run_secrets_scan)
        current_dir, baseline_dir = tmp_path / "current", tmp_path / "baseline"
        snyk_cli.run_concurrent_scans(current_dir, baseline_dir, "snyk", timeout=5)
        assert current_dir in calls
        assert baseline_dir in calls

    def test_results_returned_in_current_baseline_order(self, monkeypatch, tmp_path):
        def fake_run_secrets_scan(workspace, snyk_bin, timeout):
            return ("success", []) if "current" in str(workspace) else ("timeout", [])

        monkeypatch.setattr(snyk_cli, "run_secrets_scan", fake_run_secrets_scan)
        (current_result, baseline_result) = snyk_cli.run_concurrent_scans(
            tmp_path / "current", tmp_path / "baseline", "snyk", timeout=5
        )
        assert current_result == ("success", [])
        assert baseline_result == ("timeout", [])

    def test_runs_concurrently_not_sequentially(self, monkeypatch, tmp_path):
        # Sequential would take >= 2x the sleep; concurrent ~= 1x.
        import time

        sleep_seconds = 0.2

        def fake_run_secrets_scan(workspace, snyk_bin, timeout):
            time.sleep(sleep_seconds)
            return "success", []

        monkeypatch.setattr(snyk_cli, "run_secrets_scan", fake_run_secrets_scan)
        start = time.monotonic()
        snyk_cli.run_concurrent_scans(
            tmp_path / "current", tmp_path / "baseline", "snyk", timeout=5
        )
        elapsed = time.monotonic() - start
        assert elapsed < sleep_seconds * 1.75


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

    def test_color_off_when_not_a_tty(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        assert report.supports_color() is False

    def test_color_off_when_no_color_set(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert report.supports_color() is False


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

    def test_pre_existing_notice_singular(self):
        assert (
            timing.pre_existing_notice(1)
            == "1 finding classified as pre-existing; not blocking this commit"
        )

    def test_pre_existing_notice_plural(self):
        assert (
            timing.pre_existing_notice(2)
            == "2 findings classified as pre-existing; not blocking this commit"
        )

    def test_summary_line_omits_pre_existing_notice(self):
        line = timing.summary_line(timing.Timer(), 0, pre_existing_count=1)
        assert line.endswith("no blocking secrets found")
        assert "pre-existing" not in line


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


class TestResolveScanScope:
    def test_outside_git_repo_is_prereq_failure(self, tmp_path):
        scope, early_exit = secrets_hook.resolve_scan_scope(tmp_path)
        assert scope is None
        assert early_exit == secrets_hook.EXIT_PREREQ

    def test_populates_files_and_ranges(self, repo):
        _stage(repo, "app.py", "one\ntwo\n")
        scope, early_exit = secrets_hook.resolve_scan_scope(repo)
        assert early_exit is None
        assert scope.files == ["app.py"]
        assert scope.ranges == {"app.py": [(1, 2)]}

    def test_ignored_files_leave_nothing_to_scan(self, repo, monkeypatch):
        monkeypatch.setenv("SECRETS_IGNORE_PATHS", "app.py")
        _stage(repo, "app.py", "one\n")
        scope, early_exit = secrets_hook.resolve_scan_scope(repo)
        assert scope is None
        assert early_exit == secrets_hook.EXIT_OK

    def test_renames_empty_by_default(self, repo):
        _stage(repo, "app.py", "one\n")
        scope, _ = secrets_hook.resolve_scan_scope(repo)
        assert scope.renames == {}

    def test_needs_renames_false_skips_the_extra_git_call(self, repo, monkeypatch):
        _stage(repo, "app.py", "one\n")
        called = []
        monkeypatch.setattr(secrets_hook, "get_rename_map", lambda *a, **kw: called.append(1) or {})
        secrets_hook.resolve_scan_scope(repo, needs_renames=False)
        assert called == []

    def test_needs_renames_true_populates_renames(self, repo):
        _stage(repo, "a.py", "one\ntwo\n")
        subprocess.run(["git", "commit", "-q", "-m", "add a"], cwd=repo, check=True)
        subprocess.run(["git", "mv", "a.py", "b.py"], cwd=repo, check=True)
        scope, early_exit = secrets_hook.resolve_scan_scope(repo, needs_renames=True)
        assert early_exit is None
        assert scope.renames == {"b.py": "a.py"}


class TestMainFailClosed:
    def test_outside_git_repo_is_prereq_failure(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)  # not a git repo
        assert secrets_hook.main([]) == secrets_hook.EXIT_PREREQ

    def test_git_diff_failure_is_prereq_failure(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        monkeypatch.setattr(secrets_hook, "get_staged_files", lambda _: None)
        assert secrets_hook.main([]) == secrets_hook.EXIT_PREREQ

    def test_added_line_range_failure_is_prereq_failure(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        monkeypatch.setattr(secrets_hook, "get_staged_files", lambda _: ["app.py"])
        monkeypatch.setattr(secrets_hook, "get_added_line_ranges", lambda _: None)
        assert secrets_hook.main([]) == secrets_hook.EXIT_PREREQ

    def test_no_staged_files_is_ok(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        monkeypatch.setattr(secrets_hook, "get_staged_files", lambda _: [])
        assert secrets_hook.main([]) == secrets_hook.EXIT_OK


class TestScanFailureDefaultsToFailOpen:
    @pytest.fixture(autouse=True)
    def _stub_prereqs(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        monkeypatch.setattr(secrets_hook, "find_repo_root", lambda _: tmp_path)
        monkeypatch.setattr(secrets_hook, "get_staged_files", lambda _: ["app.py"])
        monkeypatch.setattr(secrets_hook, "get_added_line_ranges", lambda _: ({}, []))
        monkeypatch.setattr(secrets_hook, "find_snyk_binary", lambda: "/usr/bin/snyk")
        monkeypatch.setattr(secrets_hook, "check_snyk_auth", lambda: "token")
        monkeypatch.setattr(secrets_hook, "run_secrets_scan", lambda *a, **kw: ("timeout", []))
        snapshot_dir = tmp_path / "staged-snapshot"
        snapshot_dir.mkdir()

        @contextmanager
        def _fake_snapshot(repo_root, files):
            yield snapshot_dir

        monkeypatch.setattr(
            secrets_hook, "staged_snapshot", lambda *a, **kw: _fake_snapshot(*a, **kw)
        )

    def test_default_allows_commit(self, monkeypatch):
        monkeypatch.delenv("SECRETS_BLOCK_ON_SCAN_FAILURE", raising=False)
        assert secrets_hook.main([]) == secrets_hook.EXIT_OK

    def test_opt_in_blocks_commit(self, monkeypatch):
        monkeypatch.setenv("SECRETS_BLOCK_ON_SCAN_FAILURE", "1")
        assert secrets_hook.main([]) == secrets_hook.EXIT_BLOCK


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

    def test_negative_clamped_to_minimum(self, monkeypatch):
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
        monkeypatch.setattr(secrets_hook, "get_staged_files", lambda _: ["app.py"])
        monkeypatch.setattr(secrets_hook, "find_snyk_binary", lambda: "/usr/bin/snyk")
        monkeypatch.setattr(secrets_hook, "check_snyk_auth", lambda: "token")
        snapshot_dir = tmp_path / "staged-snapshot"
        snapshot_dir.mkdir()

        # Plain local helper: `staticmethod` objects aren't directly callable
        # until Python 3.10, and this isn't a class attribute anyway.
        def _fake_snapshot(repo_root, files):
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
            secrets_hook, "get_added_line_ranges", lambda _: ({"app.py": [(10, 10)]}, [])
        )
        finding = findings.Finding(
            id="x", title="X", severity="high", file_path="app.py", start_line=1, start_column=1
        )
        monkeypatch.setattr(
            secrets_hook, "run_secrets_scan", lambda *a, **kw: ("success", [finding])
        )
        assert secrets_hook.main([]) == secrets_hook.EXIT_OK

    def test_added_finding_blocks(self, monkeypatch):
        monkeypatch.setattr(
            secrets_hook, "get_added_line_ranges", lambda _: ({"app.py": [(1, 1)]}, [])
        )
        finding = findings.Finding(
            id="x", title="X", severity="high", file_path="app.py", start_line=1, start_column=1
        )
        monkeypatch.setattr(
            secrets_hook, "run_secrets_scan", lambda *a, **kw: ("success", [finding])
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
        added, pre_existing = baseline.classify_by_content(ctx)
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
        added, pre_existing = baseline.classify_by_content(ctx)
        assert added == [current_finding]
        assert pre_existing == []

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
        added, pre_existing = baseline.classify_by_content(ctx)
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
        added, pre_existing = baseline.classify_by_content(ctx)
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
        added, pre_existing = baseline.classify_by_content(ctx)
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
        added, pre_existing = baseline.classify_by_content(ctx)
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
        added, pre_existing = baseline.classify_by_content(ctx)
        assert added == [current_finding]
        assert pre_existing == []


# ============================================================================
# 10. Strategy resolution (SECRETS_DIFF_STRATEGY) -- the extensibility
# surface itself.
# ============================================================================


class TestResolveDiffStrategy:
    def test_default_is_line(self, monkeypatch):
        monkeypatch.delenv("SECRETS_DIFF_STRATEGY", raising=False)
        strategy = secrets_hook._resolve_diff_strategy()
        assert strategy.name == "line"
        assert strategy.needs_baseline_scan is False

    def test_content_selects_baseline_strategy(self, monkeypatch):
        monkeypatch.setenv("SECRETS_DIFF_STRATEGY", "content")
        strategy = secrets_hook._resolve_diff_strategy()
        assert strategy.name == "content"
        assert strategy.needs_baseline_scan is True

    def test_unknown_value_falls_back_to_line(self, monkeypatch):
        monkeypatch.setenv("SECRETS_DIFF_STRATEGY", "nonsense")
        strategy = secrets_hook._resolve_diff_strategy()
        assert strategy.name == "line"

    def test_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("SECRETS_DIFF_STRATEGY", "CONTENT")
        assert secrets_hook._resolve_diff_strategy().name == "content"

    def test_registering_a_third_strategy_requires_no_main_changes(self, monkeypatch):
        calls = []

        def _fake_classify(ctx):
            calls.append(ctx)
            return [], []

        fake_strategy = secrets_hook.DiffStrategy(
            "fake", needs_baseline_scan=False, classify=_fake_classify
        )
        monkeypatch.setitem(secrets_hook._DIFF_STRATEGIES, "fake", fake_strategy)
        monkeypatch.setenv("SECRETS_DIFF_STRATEGY", "fake")
        assert secrets_hook._resolve_diff_strategy() is fake_strategy


# ============================================================================
# 11. Output scenarios -- each asserts on and prints the hook's actual
# stderr (via capsys.disabled(), so it shows without -s, even on pass).
#
# Run just this class to see every scenario's real output in one pass:
#   uv run pytest recipes/installer/tests/test_secrets_at_commit.py::TestOutputScenarios -v
# ============================================================================


class TestOutputScenarios:
    """Every scenario runs under both diff strategies (see
    `_stub_prereqs`'s `params`) -- all cross-cutting concerns outside
    `DiffStrategy.classify`, so "content" must match "line" here.
    Classification differences are covered by `TestClassifyByContent` and
    `TestContentStrategyEndToEnd`."""

    SYNTHETIC_SCAN_EXCEPTION = (
        "<UNEXPECTED_SCAN_ERROR_FROM_RUN_SECRETS_SCAN: real exception message would appear here>"
    )
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

    @pytest.fixture(autouse=True, params=["line", "content"])
    def _stub_prereqs(self, request, monkeypatch, tmp_path):
        """A working setup by default -- individual tests override just the
        pieces that change for their scenario (snyk_bin, auth, scan
        result)."""
        self.strategy_name: str = request.param
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        monkeypatch.setenv("SECRETS_DIFF_STRATEGY", self.strategy_name)
        monkeypatch.delenv("SECRETS_BLOCK_ON_SCAN_FAILURE", raising=False)
        monkeypatch.delenv("SECRETS_FALLBACK_TO_WORKING_DIR", raising=False)
        monkeypatch.setattr(secrets_hook, "DEBUG", False)
        monkeypatch.setattr(secrets_hook, "find_repo_root", lambda _: tmp_path)
        monkeypatch.setattr(secrets_hook, "get_staged_files", lambda _: ["config.py"])
        monkeypatch.setattr(
            secrets_hook, "get_added_line_ranges", lambda _: ({"config.py": [(1, 1)]}, [])
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
        def _fake_snapshot(repo_root, files):
            yield self.current_snapshot_dir

        monkeypatch.setattr(
            secrets_hook, "staged_snapshot", lambda *a, **kw: _fake_snapshot(*a, **kw)
        )

        if self.strategy_name == "content":
            # No real files under tmp_path, so classify_by_content can't
            # extract text and falls back to the same line-range check
            # "line" uses -- the point being these tests assert the two
            # strategies agree on everything except classification.
            monkeypatch.setattr(secrets_hook, "get_rename_map", lambda _: {})

            @contextmanager
            def _fake_ref_snapshot(repo_root, ref, files):
                yield self.baseline_snapshot_dir, set()

            monkeypatch.setattr(
                secrets_hook, "ref_snapshot", lambda *a, **kw: _fake_ref_snapshot(*a, **kw)
            )

            def _fake_concurrent(current_ws, baseline_ws, snyk_bin, timeout):
                # Delegates to whatever run_secrets_scan a test method
                # below mocks, looked up fresh each call.
                current_result = secrets_hook.run_secrets_scan(current_ws, snyk_bin, timeout)
                return current_result, ("success", [])

            monkeypatch.setattr(secrets_hook, "run_concurrent_scans", _fake_concurrent)

    def _run(self, capsys, header: str, argv: list[str]):
        rc = secrets_hook.main(argv)
        err = capsys.readouterr().err
        with capsys.disabled():
            print(f"\n----- {header} [{self.strategy_name}] (exit={rc}) -----")
            print(err, end="" if err.endswith("\n") else "\n")
        return rc, err

    @staticmethod
    def _persisted_log_text(tmp_path) -> str:
        """Reads back whatever this run persisted."""
        log_file = persistent_log.resolve_log_file(str(tmp_path))
        if not os.path.exists(log_file):
            return ""
        return Path(log_file).read_text(encoding="utf-8")

    def test_clean_commit(self, monkeypatch, capsys, tmp_path):
        monkeypatch.setattr(secrets_hook, "run_secrets_scan", lambda *a, **kw: ("success", []))
        rc, err = self._run(capsys, "clean commit", [])
        assert rc == secrets_hook.EXIT_OK
        assert re.search(
            r"^\[snyk\] Scanning 1 staged file for secrets, up to \d+s\.\.\. "
            r"\(bypass with `git commit --no-verify`\)$",
            err,
            re.M,
        )
        assert re.search(r"^  done in [\d.]+s -- no secrets found$", err, re.M)

        # Same lines as stderr, minus the "[snyk] "/"  " prefixes, plus a
        # leading timestamp.
        log_text = self._persisted_log_text(tmp_path)
        assert re.search(
            r"^\[[\d\-T:.]+\] Scanning 1 staged file for secrets, up to \d+s\.\.\. "
            r"\(bypass with `git commit --no-verify`\)$",
            log_text,
            re.M,
        )
        assert re.search(r"^\[[\d\-T:.]+\] done in [\d.]+s -- no secrets found$", log_text, re.M)

    def test_clean_commit_with_pre_existing(self, monkeypatch, capsys):
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan",
            lambda *a, **kw: ("success", [self.PRE_EXISTING_FINDING]),
        )
        rc, err = self._run(capsys, "clean commit, pre-existing secret", [])
        assert rc == secrets_hook.EXIT_OK
        assert re.search(
            r"^  1 finding classified as pre-existing; not blocking this commit$",
            err,
            re.M,
        )
        assert re.search(
            r"^  done in [\d.]+s -- no blocking secrets found$",
            err,
            re.M,
        )

    def test_blocking_no_pre_existing(self, monkeypatch, capsys, tmp_path):
        monkeypatch.setattr(
            secrets_hook, "run_secrets_scan", lambda *a, **kw: ("success", [self.NEW_FINDING])
        )
        rc, err = self._run(capsys, "blocking, no pre-existing", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert re.search(r"^  done in [\d.]+s -- 1 finding blocking commit$", err, re.M)
        assert "  - config.py(1,22): [high] [aws-access-token] [-] [Aws-Access-Token]" in err

        # The blocking summary is persisted too; the raw finding list
        # (print_findings, above) deliberately is not -- see
        # lib/persistent_log.py's module docstring.
        log_text = self._persisted_log_text(tmp_path)
        assert re.search(
            r"^\[[\d\-T:.]+\] done in [\d.]+s -- 1 finding blocking commit$", log_text, re.M
        )
        assert "config.py(1,22)" not in log_text

    def test_blocking_with_pre_existing(self, monkeypatch, capsys):
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan",
            lambda *a, **kw: ("success", [self.NEW_FINDING, self.PRE_EXISTING_FINDING]),
        )
        rc, err = self._run(capsys, "blocking, with pre-existing also present", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert re.search(
            r"^  1 finding classified as pre-existing; not blocking this commit$",
            err,
            re.M,
        )
        assert re.search(
            r"^  done in [\d.]+s -- 1 finding blocking commit$",
            err,
            re.M,
        )

    def test_snyk_cli_not_found(self, monkeypatch, capsys):
        monkeypatch.setattr(secrets_hook, "find_snyk_binary", lambda: None)
        rc, err = self._run(capsys, "Snyk CLI not found (fail-open, default)", [])
        assert rc == secrets_hook.EXIT_OK
        assert (
            "[snyk] Snyk CLI not found on PATH -- install with `npm install -g snyk`; "
            "allowing commit (set SECRETS_BLOCK_ON_SCAN_FAILURE=1 to block instead)" in err
        )

    def test_snyk_cli_not_authenticated(self, monkeypatch, capsys):
        monkeypatch.setattr(secrets_hook, "check_snyk_auth", lambda: None)
        rc, err = self._run(capsys, "Snyk CLI not authenticated (fail-open, default)", [])
        assert rc == secrets_hook.EXIT_OK
        assert (
            "[snyk] Snyk CLI not authenticated -- run `/usr/bin/snyk auth`; "
            "allowing commit (set SECRETS_BLOCK_ON_SCAN_FAILURE=1 to block instead)" in err
        )

    def test_scan_auth_failure_hint_names_the_resolved_binary(self, monkeypatch, capsys):
        # A standalone-pin user may have no `snyk` on PATH to run at all.
        monkeypatch.setattr(secrets_hook, "find_snyk_binary", lambda: "/opt/snyk/snyk")
        monkeypatch.setattr(
            secrets_hook, "run_secrets_scan", lambda *a, **kw: ("auth_required", [])
        )
        rc, err = self._run(capsys, "scan reported auth_required (fail-open)", [])
        assert rc == secrets_hook.EXIT_OK
        assert re.search(
            r"^  Snyk CLI not authenticated -- run `/opt/snyk/snyk auth`; allowing commit ",
            err,
            re.M,
        )

    def test_scan_error_hint_names_the_resolved_binary(self, monkeypatch, capsys):
        monkeypatch.setattr(secrets_hook, "find_snyk_binary", lambda: "/opt/snyk/snyk")
        monkeypatch.setattr(secrets_hook, "run_secrets_scan", lambda *a, **kw: ("error", []))
        rc, err = self._run(capsys, "scan did not complete (fail-open)", [])
        assert rc == secrets_hook.EXIT_OK
        assert "run `/opt/snyk/snyk secrets test` manually to check" in err

    def test_stale_pin_falling_back_to_path_warns_outside_debug(self, monkeypatch, capsys):
        # Otherwise the user believes they're scanning with the pinned
        # standalone CLI while the hook quietly used the npm one.
        sidecar = Path(os.path.expanduser("~")) / ".snyk-studio" / "cli-path"
        sidecar.parent.mkdir(parents=True, exist_ok=True)
        sidecar.write_text("/gone/snyk", encoding="utf-8")
        monkeypatch.setattr(secrets_hook, "run_secrets_scan", lambda *a, **kw: ("success", []))
        rc, err = self._run(capsys, "stale pin, scanned with PATH fallback", [])
        assert rc == secrets_hook.EXIT_OK
        assert (
            f'[snyk] {sidecar} pins "/gone/snyk", which does not exist; '
            "scanning with /usr/bin/snyk instead" in err
        )

    def test_no_sidecar_emits_no_stale_pin_warning(self, monkeypatch, capsys):
        monkeypatch.setattr(secrets_hook, "run_secrets_scan", lambda *a, **kw: ("success", []))
        _, err = self._run(capsys, "no sidecar, no warning", [])
        assert "cli-path" not in err

    def test_hint_quotes_a_binary_path_with_spaces(self, monkeypatch, capsys):
        # _search_paths_windows probes C:\Program Files\Snyk, so a resolved
        # path with spaces is routine -- the hint has to stay runnable.
        monkeypatch.setattr(
            secrets_hook, "find_snyk_binary", lambda: r"C:\Program Files\Snyk\snyk.exe"
        )
        monkeypatch.setattr(secrets_hook, "run_secrets_scan", lambda *a, **kw: ("error", []))
        _, err = self._run(capsys, "scan did not complete, spaced binary path", [])
        assert r'run `"C:\Program Files\Snyk\snyk.exe" secrets test`' in err

    def test_scan_timeout_fail_open(self, monkeypatch, capsys):
        monkeypatch.setattr(secrets_hook, "run_secrets_scan", lambda *a, **kw: ("timeout", []))
        rc, err = self._run(capsys, "scan timeout, fail-open (default)", [])
        assert rc == secrets_hook.EXIT_OK
        assert re.search(
            r"^  scan timed out after \d+s; allowing commit \(run `/usr/bin/snyk secrets test` "
            r"manually to check; set SECRETS_BLOCK_ON_SCAN_FAILURE=1 to block instead\)$",
            err,
            re.M,
        )

    def test_scan_timeout_fail_closed(self, monkeypatch, capsys):
        monkeypatch.setenv("SECRETS_BLOCK_ON_SCAN_FAILURE", "1")
        monkeypatch.setattr(secrets_hook, "run_secrets_scan", lambda *a, **kw: ("timeout", []))
        rc, err = self._run(
            capsys, "scan timeout, fail-closed (SECRETS_BLOCK_ON_SCAN_FAILURE=1)", []
        )
        assert rc == secrets_hook.EXIT_BLOCK
        assert re.search(
            r"^  scan timed out after \d+s; blocking commit \(run `/usr/bin/snyk secrets test` "
            r"manually to check\)$",
            err,
            re.M,
        )

    def test_unexpected_crash_fails_open_by_default(self, monkeypatch, capsys):
        # A bug we didn't anticipate must still respect the fail-open
        # default -- Python's own uncaught-exception exit code would
        # otherwise coincide with EXIT_BLOCK and force-block every commit.
        def _raise_unexpected_scan_error(*a, **kw):
            raise RuntimeError(self.SYNTHETIC_SCAN_EXCEPTION)

        monkeypatch.setattr(secrets_hook, "run_secrets_scan", _raise_unexpected_scan_error)
        rc, err = self._run(capsys, "unexpected crash, fail-open (default)", [])
        assert rc == secrets_hook.EXIT_OK
        assert (
            f"[snyk] internal error: RuntimeError: {self.SYNTHETIC_SCAN_EXCEPTION}; "
            "allowing commit "
            "(set SECRETS_BLOCK_ON_SCAN_FAILURE=1 to block instead)" in err
        )

    def test_unexpected_crash_fails_closed_when_configured(self, monkeypatch, capsys):
        monkeypatch.setenv("SECRETS_BLOCK_ON_SCAN_FAILURE", "1")

        def _raise_unexpected_scan_error(*a, **kw):
            raise RuntimeError(self.SYNTHETIC_SCAN_EXCEPTION)

        monkeypatch.setattr(secrets_hook, "run_secrets_scan", _raise_unexpected_scan_error)
        rc, err = self._run(
            capsys, "unexpected crash, fail-closed (SECRETS_BLOCK_ON_SCAN_FAILURE=1)", []
        )
        assert rc == secrets_hook.EXIT_BLOCK
        assert (
            f"[snyk] internal error: RuntimeError: {self.SYNTHETIC_SCAN_EXCEPTION}; "
            "blocking commit" in err
        )

    def test_unexpected_crash_with_no_message_still_reports_the_exception_type(
        self, monkeypatch, capsys
    ):
        def _raise_unexpected_scan_error_without_message(*a, **kw):
            raise ValueError

        monkeypatch.setattr(
            secrets_hook, "run_secrets_scan", _raise_unexpected_scan_error_without_message
        )
        rc, err = self._run(capsys, "unexpected crash with no message", [])
        assert rc == secrets_hook.EXIT_OK
        assert "[snyk] internal error: ValueError; allowing commit" in err

    def test_debug_mode(self, monkeypatch, capsys, tmp_path):
        monkeypatch.setattr(secrets_hook, "DEBUG", True)
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan",
            lambda *a, **kw: ("success", [self.PRE_EXISTING_FINDING]),
        )
        rc, err = self._run(capsys, "debug mode, clean + pre-existing", [])
        assert rc == secrets_hook.EXIT_OK
        assert re.search(rf"^  \[debug\] diff strategy: {self.strategy_name}$", err, re.M)
        assert re.search(r"^  \[debug\] scan scope: 1 file, 0 binary files$", err, re.M)
        assert re.search(
            rf"^  \[debug\] scan workspace: {re.escape(str(self.current_snapshot_dir))} "
            r"\(staged snapshot\)$",
            err,
            re.M,
        )
        if self.strategy_name == "content":
            assert re.search(
                rf"^  \[debug\] baseline scan workspace: {re.escape(str(self.baseline_snapshot_dir))} "
                r"\(0 files\)$",
                err,
                re.M,
            )
            assert re.search(
                rf"^  \[debug\] running concurrent scans: "
                rf"current_workspace={re.escape(str(self.current_snapshot_dir))} "
                rf"baseline_workspace={re.escape(str(self.baseline_snapshot_dir))} target=\.$",
                err,
                re.M,
            )
        else:
            assert re.search(
                rf"^  \[debug\] running current scan: "
                rf"workspace={re.escape(str(self.current_snapshot_dir))} target=\.$",
                err,
                re.M,
            )
        assert re.search(r"^  \[debug\] scan took [\d.]+s \(total [\d.]+s\)$", err, re.M)
        log_text = self._persisted_log_text(tmp_path)
        assert "[debug] scan scope: 1 file, 0 binary files" in log_text
        assert f"[debug] scan workspace: {self.current_snapshot_dir} (staged snapshot)" in log_text
        assert re.search(
            r"^  1 finding classified as pre-existing; not blocking this commit$",
            err,
            re.M,
        )
        assert re.search(
            r"^  done in [\d.]+s -- no blocking secrets found$",
            err,
            re.M,
        )

    def test_empty_commit_skips_scan_entirely(self, monkeypatch, capsys):
        """An empty commit must skip the scan outright, not fall through
        to scanning something else (e.g. the whole workspace)."""
        monkeypatch.setattr(secrets_hook, "get_staged_files", lambda _: [])
        rc, err = self._run(capsys, "empty commit, nothing staged", [])
        assert rc == secrets_hook.EXIT_OK
        assert "[snyk] no staged files, skipping scan" in err
        assert "Scanning" not in err  # no scan of any kind should start

    @staticmethod
    def _stub_failing_snapshot(monkeypatch):
        @contextmanager
        def _failing_snapshot(repo_root, files):
            yield None

        monkeypatch.setattr(
            secrets_hook, "staged_snapshot", lambda *a, **kw: _failing_snapshot(*a, **kw)
        )

    def test_snapshot_failure_blocks_by_default(self, monkeypatch, capsys):
        called = []
        self._stub_failing_snapshot(monkeypatch)
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan",
            lambda *a, **kw: called.append(1) or ("success", []),
        )

        rc, err = self._run(capsys, "index snapshot failed, fail closed", [])
        assert rc == secrets_hook.EXIT_PREREQ
        assert called == []
        assert re.search(
            r"^  could not snapshot staged content \(git checkout-index failed\); "
            r"cannot safely scan staged changes$",
            err,
            re.M,
        )

    def test_snapshot_returning_repo_root_blocks(self, monkeypatch, capsys):
        @contextmanager
        def _repo_root_snapshot(repo_root, files):
            yield repo_root

        monkeypatch.setattr(
            secrets_hook, "staged_snapshot", lambda *a, **kw: _repo_root_snapshot(*a, **kw)
        )
        called = []
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan",
            lambda *a, **kw: called.append(1) or ("success", []),
        )

        rc, err = self._run(capsys, "snapshot returned repo root", [])
        assert rc == secrets_hook.EXIT_PREREQ
        assert called == []
        assert re.search(
            r"^  refusing to scan the repository working tree directly; "
            r"scan workspace must be a prepared snapshot$",
            err,
            re.M,
        )

    def test_snapshot_fallback_warning_when_explicitly_enabled(self, monkeypatch, capsys, tmp_path):
        """The accuracy caveat is visible whenever the legacy fallback is
        explicitly enabled."""
        self._stub_failing_snapshot(monkeypatch)
        monkeypatch.setenv("SECRETS_FALLBACK_TO_WORKING_DIR", "1")
        (tmp_path / "config.py").write_text("clean = True\n")
        monkeypatch.setattr(secrets_hook, "run_secrets_scan", lambda *a, **kw: ("success", []))

        rc, err = self._run(capsys, "index snapshot failed, explicit working-tree fallback", [])
        assert rc == secrets_hook.EXIT_OK
        assert re.search(
            r"^  could not snapshot staged content \(git checkout-index failed\); "
            r"scanning the working tree because SECRETS_FALLBACK_TO_WORKING_DIR=1 "
            r"-- results may not match what's staged$",
            err,
            re.M,
        )

    def test_snapshot_fallback_scans_filtered_copy_not_repo_root(
        self, monkeypatch, capsys, tmp_path
    ):
        self._stub_failing_snapshot(monkeypatch)
        monkeypatch.setenv("SECRETS_FALLBACK_TO_WORKING_DIR", "1")
        monkeypatch.setenv("SECRETS_IGNORE_PATHS", "ignored.py")
        monkeypatch.setattr(secrets_hook, "get_staged_files", lambda _: ["config.py", "ignored.py"])
        monkeypatch.setattr(
            secrets_hook,
            "get_added_line_ranges",
            lambda _: ({"config.py": [(1, 1)], "ignored.py": [(1, 1)]}, []),
        )
        (tmp_path / "config.py").write_text("clean = True\n")
        (tmp_path / "ignored.py").write_text('AWS_ACCESS_KEY_ID = "ignored"\n')
        scanned_workspaces = []

        def _scan(workspace, snyk_bin, timeout):
            scanned_workspaces.append(workspace)
            assert workspace != tmp_path
            assert (workspace / "config.py").read_text(encoding="utf-8") == "clean = True\n"
            assert not (workspace / "ignored.py").exists()
            return "success", []

        monkeypatch.setattr(secrets_hook, "run_secrets_scan", _scan)

        rc, err = self._run(capsys, "fallback copies filtered working tree", [])
        assert rc == secrets_hook.EXIT_OK
        assert scanned_workspaces
        assert "working tree because SECRETS_FALLBACK_TO_WORKING_DIR=1" in err

    def test_snapshot_fallback_copy_failure_blocks(self, monkeypatch, capsys):
        self._stub_failing_snapshot(monkeypatch)
        monkeypatch.setenv("SECRETS_FALLBACK_TO_WORKING_DIR", "1")
        called = []
        monkeypatch.setattr(
            secrets_hook,
            "run_secrets_scan",
            lambda *a, **kw: called.append(1) or ("success", []),
        )

        rc, err = self._run(capsys, "working-tree fallback copy failed", [])
        assert rc == secrets_hook.EXIT_PREREQ
        assert called == []
        assert re.search(
            r"^  could not snapshot working-tree fallback content; "
            r"cannot safely scan staged changes$",
            err,
            re.M,
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
            lambda _: ({"config.py": [diff_scope.BINARY_SENTINEL_RANGE]}, ["config.py"]),
        )
        monkeypatch.setattr(
            secrets_hook, "run_secrets_scan", lambda *a, **kw: ("success", [self.NEW_FINDING])
        )
        rc, err = self._run(capsys, "binary file staged, finding blocks", [])
        assert rc == secrets_hook.EXIT_BLOCK
        assert re.search(
            r"^  1 binary file staged; can't diff line-by-line, treating the whole file as in scope$",
            err,
            re.M,
        )
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
                import sys
                from pathlib import Path

                files = [arg for arg in sys.argv[3:] if arg != "--json"]
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
        assert "1 finding classified as pre-existing; not blocking this commit" in result.stderr
        assert "done in " in result.stderr
        assert "no blocking secrets found" in result.stderr

    def test_unstaged_secret_is_not_scanned(self, repo, fake_snyk_env):
        _stage(repo, "config.py", 'TOKEN = "clean"\n')
        (repo / "config.py").write_text('TOKEN = "FAKE_SECRET"\n')

        result = self._run_hook(repo, fake_snyk_env)

        assert result.returncode == secrets_hook.EXIT_OK
        assert "no secrets found" in result.stderr
        assert "FAKE_SECRET" not in result.stderr


# ============================================================================
# 13. End-to-end: the "content" diff strategy. Real git repos throughout
# (real commits/mv/edits/snapshots) -- only the Snyk scan itself is mocked.
# ============================================================================


class TestContentStrategyEndToEnd:
    @pytest.fixture(autouse=True)
    def _stub_snyk(self, monkeypatch):
        monkeypatch.setenv("SECRETS_DIFF_STRATEGY", "content")
        monkeypatch.setattr(secrets_hook, "find_snyk_binary", lambda: "/usr/bin/snyk")
        monkeypatch.setattr(secrets_hook, "check_snyk_auth", lambda: "token")

    # The touched-line/unchanged-secret scenario itself is covered by
    # TestLineStrategyKnownLimitation below, parametrized across both
    # strategies (xfail for "line", genuine pass for "content") rather
    # than duplicated here as a content-only test.

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

        def fake_run_concurrent_scans(current_ws, baseline_ws, snyk_bin, timeout):
            return ("success", [current_finding]), ("success", [])

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

        def fake_run_concurrent_scans(current_ws, baseline_ws, snyk_bin, timeout):
            assert _workspace_files(current_ws) == ["config_3.py"]
            assert _workspace_files(baseline_ws) == ["config_3.py"]
            assert "brand-new-secret" in (current_ws / "config_3.py").read_text(encoding="utf-8")
            assert "brand-new-secret" not in (baseline_ws / "config_3.py").read_text(
                encoding="utf-8"
            )
            return ("success", [current_existing, current_new]), (
                "success",
                [baseline_existing],
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

        def fake_run_concurrent_scans(current_ws, baseline_ws, snyk_bin, timeout):
            return ("success", [current_finding]), ("success", [baseline_finding])

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

        def fake_run_concurrent_scans(current_ws, baseline_ws, snyk_bin, timeout):
            return ("success", [current_finding]), ("timeout", [])

        monkeypatch.setattr(secrets_hook, "run_concurrent_scans", fake_run_concurrent_scans)
        monkeypatch.setattr(secrets_hook, "DEBUG", True)
        monkeypatch.chdir(repo)
        # Falls back to line-diff, which blocks on the touched line since
        # it can't know the secret text itself is unchanged.
        assert secrets_hook.main([]) == secrets_hook.EXIT_BLOCK
        err = capsys.readouterr().err
        assert "baseline scan timeout; using line-diff classification for this run" in err

    def test_get_rename_map_failure_does_not_abort_commit(self, repo, monkeypatch):
        # An empty rename map (as on git failure) must not fail-closed
        # the whole commit.
        _stage(repo, "app.py", 'KEY = "abc123"\n')
        subprocess.run(["git", "commit", "-q", "-m", "add app"], cwd=repo, check=True)
        (repo / "app.py").write_text('KEY = "abc123"\nEXTRA = 1\n')
        subprocess.run(["git", "add", "app.py"], cwd=repo, check=True)

        monkeypatch.setattr(secrets_hook, "get_rename_map", lambda _: {})
        monkeypatch.setattr(
            secrets_hook,
            "run_concurrent_scans",
            lambda *a, **kw: (("success", []), ("success", [])),
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
    @pytest.fixture(autouse=True)
    def _stub_snyk(self, monkeypatch):
        monkeypatch.setattr(secrets_hook, "find_snyk_binary", lambda: "/usr/bin/snyk")
        monkeypatch.setattr(secrets_hook, "check_snyk_auth", lambda: "token")

    @pytest.mark.parametrize(
        "strategy_name",
        [
            pytest.param(
                "line",
                marks=pytest.mark.xfail(
                    reason=(
                        "known limitation: the line-diff heuristic blocks on any "
                        "touched line, even when the secret's own matched text is "
                        "unchanged -- see lib/baseline.py's module docstring"
                    ),
                    strict=True,
                ),
            ),
            "content",
        ],
    )
    def test_touched_line_with_unchanged_secret_does_not_block(
        self, repo, monkeypatch, strategy_name
    ):
        monkeypatch.setenv("SECRETS_DIFF_STRATEGY", strategy_name)
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
        # Only one of these two actually gets called, depending on strategy_name.
        monkeypatch.setattr(
            secrets_hook, "run_secrets_scan", lambda *a, **kw: ("success", [current_finding])
        )

        def fake_run_concurrent_scans(current_ws, baseline_ws, snyk_bin, timeout):
            return ("success", [current_finding]), ("success", [baseline_finding])

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

    def test_unwritable_path_does_not_raise(self, tmp_path):
        # A file where a parent dir needs to be created makes os.makedirs
        # fail reliably, cross-platform.
        blocker = tmp_path / "not-a-dir"
        blocker.write_text("x", encoding="utf-8")
        persistent_log.append_log("hello", str(blocker / "sub" / "log.txt"))
