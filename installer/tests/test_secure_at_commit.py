"""Tests for the secure-at-commit recipe wiring.

Covers four concerns:

1. Manifest plumbing — sac-hooks is workspace-scoped, lives in the experimental
   profile, and declares a conflicts_with against the SAI recipe so listing
   both in a profile drops the SAI half. Conflict resolution iterates in
   manifest declaration order so the outcome is deterministic.
2. Hook-manager probe & integration (``lib/git_hooks.py``) — pre-commit
   framework, Husky, and git-native install/uninstall/verify round-trips.
3. End-to-end installer behaviour — workspace-scoped install + verify, and
   uninstall cleanup of both files and the pre-commit shim.
4. Hook-script semantics — exact (not suffix) path matching, per-manifest
   SCA filtering, and XDG-aware Snyk auth lookup.
"""

import importlib
import json
import os
import sys
from pathlib import Path

import pytest

INSTALLER_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = INSTALLER_DIR.parent.parent
SAC_HOOK_DIR = REPO_ROOT / "recipes" / "guardrail_directives" / "secure_at_commit"
sys.path.insert(0, str(INSTALLER_DIR))
sys.path.insert(0, str(INSTALLER_DIR / "lib"))
sys.path.insert(0, str(SAC_HOOK_DIR))

installer = importlib.import_module("snyk-studio-installer")
git_hooks = importlib.import_module("git_hooks")
sac_hook = importlib.import_module("snyk_secure_at_commit")


# ============================================================================
# Helpers
# ============================================================================


def _init_git_repo(path: Path) -> None:
    """Create a minimal git directory layout sufficient for the installer.

    We don't need a real ``git init`` — only the ``.git/hooks/`` path is
    actually inspected/written, and git_hooks.py doesn't shell out.
    """
    (path / ".git" / "hooks").mkdir(parents=True)


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """A clean workspace cwd that looks like a git repo to git_hooks."""
    _init_git_repo(tmp_path)
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def manifest():
    return installer.Manifest(INSTALLER_DIR / "manifest.json")


@pytest.fixture
def payload():
    pl = installer.PayloadContext()
    pl.setup()
    return pl


SAC_DEST = Path(".snyk-studio") / "components" / "scripts" / "snyk_secure_at_commit.py"
LEGACY_SAC_DEST = Path(".snyk") / "studio" / "components" / "scripts" / "snyk_secure_at_commit.py"


# ============================================================================
# 1. Manifest plumbing
# ============================================================================


class TestManifestSAC:
    def test_sac_hooks_is_workspace_scoped(self, manifest):
        assert manifest.is_workspace_scoped("sac-hooks") is True
        # Sanity: every other recipe stays ADE-scoped so the iteration loops
        # in main() don't accidentally run them in workspace mode.
        for rid in manifest.all_recipe_ids():
            if rid == "sac-hooks":
                continue
            assert manifest.is_workspace_scoped(rid) is False, rid

    def test_sac_hooks_workspace_sources(self, manifest):
        sources = manifest.recipes["sac-hooks"]["sources"]
        assert list(sources.keys()) == ["workspace"]
        ws = sources["workspace"]
        assert ws["files"], "sac-hooks must ship files"
        # All file dests are workspace-relative under .snyk-studio/components/scripts/
        # so the script ships inside the repo and any committed hook config
        # (e.g. .pre-commit-config.yaml) references it portably. The directory
        # is deliberately NOT under .snyk/, which can already exist as a Snyk
        # policy file in the repo.
        for f in ws["files"]:
            assert f["dest"].startswith(".snyk-studio/components/scripts/"), f
            assert not f["dest"].startswith("/"), f
        # Older installs lived under .snyk/studio/; uninstall still cleans those.
        assert ws["legacy_files"] == [
            {"dest": ".snyk/studio/components/scripts/snyk_secure_at_commit.py"}
        ]
        assert ws["pre_commit_integration"]["tag"] == "snyk-secure-at-commit"
        # The shim command is workspace-relative too — no absolute path or
        # token gets baked in, so a committed .pre-commit-config.yaml stays
        # portable across machines.
        cmd = ws["pre_commit_integration"]["command"]
        assert ".snyk-studio/components/scripts/snyk_secure_at_commit.py" in cmd
        assert "$WORKSPACE" not in cmd
        assert "$USER_DATA_HOME" not in cmd
        # The installer wires the pre-commit form with --staged so the hook
        # filters findings to files in the index; without it the script
        # would scan & report the whole workspace, which is the wrong
        # behaviour for a pre-commit gate.
        assert "--staged" in cmd.split()

    def test_experimental_profile_excludes_sai(self, manifest):
        recipes = manifest.resolve_recipes("experimental")
        assert "sac-hooks" in recipes
        assert "sai-hooks-async" not in recipes

    def test_default_profile_excludes_sac(self, manifest):
        recipes = manifest.resolve_recipes("default")
        assert "sai-hooks-async" in recipes
        assert "sac-hooks" not in recipes

    def test_conflicts_with_drops_sai_when_both_listed(self, manifest, monkeypatch):
        """If a profile happens to list both sac-hooks and sai-hooks-async,
        sai-hooks-async is dropped because of conflicts_with."""
        monkeypatch.setitem(
            manifest.profiles,
            "_both",
            {"recipes": ["sai-hooks-async", "sac-hooks", "mcp-config"]},
        )
        recipes = manifest.resolve_recipes("_both")
        assert "sac-hooks" in recipes
        assert "sai-hooks-async" not in recipes
        assert "mcp-config" in recipes

    def test_conflicts_with_no_op_when_only_sai(self, manifest, monkeypatch):
        """A profile that lists only SAI is unaffected by SAC's
        conflicts_with declaration (sac-hooks isn't in the active set)."""
        monkeypatch.setitem(manifest.profiles, "_only_sai", {"recipes": ["sai-hooks-async"]})
        recipes = manifest.resolve_recipes("_only_sai")
        assert recipes == ["sai-hooks-async"]

    def test_conflict_resolution_is_deterministic_in_manifest_order(self, manifest, monkeypatch):
        """Two recipes that mutually conflict must resolve the same way every
        time. We iterate `manifest.recipes` in insertion order, so a
        later-declared recipe wins over the earlier one it conflicts with."""
        # Inject a synthetic recipe declared AFTER sai-hooks-async (sai is
        # declared first in the manifest) and have it also claim sai as a
        # conflict. With deterministic iteration in manifest order, the
        # later-declared recipe (`_late_override`) wins.
        monkeypatch.setitem(
            manifest.recipes,
            "_late_override",
            {
                "type": "hooks",
                "scope": "workspace",
                "description": "synthetic override",
                "enabled": True,
                "conflicts_with": ["sai-hooks-async"],
                "sources": {"workspace": {"files": []}},
            },
        )
        monkeypatch.setitem(
            manifest.profiles,
            "_both",
            {"recipes": ["sai-hooks-async", "_late_override"]},
        )
        # Run repeatedly — outcome must not flip between calls.
        outcomes = {tuple(manifest.resolve_recipes("_both")) for _ in range(10)}
        assert len(outcomes) == 1
        recipes = manifest.resolve_recipes("_both")
        assert "_late_override" in recipes
        assert "sai-hooks-async" not in recipes

    def test_sac_source_files_exist_in_repo(self, manifest, payload):
        """Every src path declared on sac-hooks must resolve to a real file
        in the payload — protects against typos in manifest.json."""
        for f in manifest.recipes["sac-hooks"]["sources"]["workspace"]["files"]:
            src = payload.resolve_src(f["src"])
            assert src.is_file(), f["src"]


class TestDetectStaleConflicts:
    """PR feedback: when a user switches from a profile that installs SAI to
    one that installs SAC, the old SAI files stay on disk and both systems
    fire at once. ``Manifest.detect_stale_conflicts`` reports those triples
    so the installer can warn + offer cleanup before proceeding."""

    def test_no_stale_conflicts_when_nothing_on_disk(self, manifest, tmp_path, monkeypatch):
        """Clean baseline: no SAI files installed → no stale conflicts even
        when sac-hooks declares it conflicts with sai-hooks-async."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert manifest.detect_stale_conflicts(["sac-hooks"]) == []

    def test_reports_sai_files_present_for_each_affected_ade(self, manifest, tmp_path, monkeypatch):
        """SAI files exist for claude and cursor (from a prior install via
        the default profile). Installing sac-hooks must report both ADEs
        — the warning should cover every ADE where the stale install
        actually lives, not just the one being targeted now."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        # Drop a sentinel file at the location resolve_ade_path would
        # check for sai-hooks-async on each ADE.
        for ade in ("claude", "cursor"):
            src_dest = manifest.get_sources("sai-hooks-async", ade)["files"][0]["dest"]
            target = tmp_path / src_dest
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("# stale SAI hook\n")

        stale = manifest.detect_stale_conflicts(["sac-hooks"])
        triples = {(active, conflicted, ade) for active, conflicted, ade in stale}
        assert ("sac-hooks", "sai-hooks-async", "claude") in triples
        assert ("sac-hooks", "sai-hooks-async", "cursor") in triples

    def test_skips_workspace_scoped_conflicted_recipes(self, manifest, tmp_path, monkeypatch):
        """Workspace-scoped conflicted recipes need a different path
        resolver; the helper deliberately skips them. Today no recipe
        declares such a conflict — this test guards against a future
        misuse silently going undetected."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        # Fake an active recipe that "conflicts with" sac-hooks itself
        # (workspace-scoped). The detector must not crash and must not
        # report a stale conflict for sac-hooks.
        monkeypatch.setitem(
            manifest.recipes,
            "_pretend",
            {
                "type": "hooks",
                "description": "synthetic",
                "enabled": True,
                "conflicts_with": ["sac-hooks"],
                "sources": {},
            },
        )
        assert manifest.detect_stale_conflicts(["_pretend"]) == []

    def test_no_stale_conflict_when_active_recipe_has_no_conflicts_declaration(
        self, manifest, tmp_path, monkeypatch
    ):
        """An active recipe with no ``conflicts_with`` produces nothing,
        even if files happen to exist for some unrelated recipe."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        # snyk-fix-command doesn't declare conflicts_with anything.
        assert manifest.detect_stale_conflicts(["snyk-fix-command"]) == []


class TestUninstallAdeRecipeHelper:
    """Round-trips through ``uninstall_ade_recipe`` so the stale-conflict
    cleanup step actually removes what it claims to."""

    def test_uninstall_ade_recipe_removes_sai_files_for_one_ade(
        self, manifest, payload, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        # Install SAI for claude…
        installer.install_recipe("sai-hooks-async", "claude", manifest, payload, dry_run=False)
        sai_marker = tmp_path / ".claude" / "hooks" / "snyk_secure_at_inception.py"
        assert sai_marker.exists()

        # …then uninstall just that one (recipe, ADE) pair.
        installer.uninstall_ade_recipe(
            "sai-hooks-async", "claude", manifest, payload, dry_run=False
        )

        # SAI files gone for claude.
        assert not sai_marker.exists()
        assert not (tmp_path / ".claude" / "hooks").exists()


# ============================================================================
# 2. Hook-manager probe + install/uninstall/verify
# ============================================================================


SPEC = git_hooks.HookSpec(
    tag="snyk-secure-at-commit",
    command='uv run "/tmp/sac/snyk_secure_at_commit.py"',
)


class TestDetectHookManager:
    def test_detects_pre_commit_framework(self, workspace):
        (workspace / ".pre-commit-config.yaml").write_text("repos: []\n")
        assert git_hooks.detect_hook_manager(workspace) == "pre-commit"

    def test_detects_pre_commit_framework_yml(self, workspace):
        (workspace / ".pre-commit-config.yml").write_text("repos: []\n")
        assert git_hooks.detect_hook_manager(workspace) == "pre-commit"

    def test_detects_husky(self, workspace):
        (workspace / ".husky").mkdir()
        (workspace / ".husky" / "pre-commit").write_text("#!/usr/bin/env sh\n")
        assert git_hooks.detect_hook_manager(workspace) == "husky"

    def test_prefers_precommit_over_husky(self, workspace):
        (workspace / ".pre-commit-config.yaml").write_text("repos: []\n")
        (workspace / ".husky").mkdir()
        (workspace / ".husky" / "pre-commit").write_text("#!/usr/bin/env sh\n")
        assert git_hooks.detect_hook_manager(workspace) == "pre-commit"

    def test_falls_back_to_git_native(self, workspace):
        assert git_hooks.detect_hook_manager(workspace) == "git-native"


class TestStripBlockMalformedSafety:
    """PR feedback: the previous non-greedy ``.*?`` in ``_strip_block``
    would span across a duplicated begin marker, silently consuming the
    orphan and every line up to the next end. The tempered pattern now in
    place refuses to match when an intervening begin marker is present,
    so a corrupted file preserves user content instead of losing it."""

    SPEC = git_hooks.HookSpec(tag="snyk-secure-at-commit", command="fake")

    def test_well_formed_block_is_still_removed(self):
        """Regression: a single well-formed block must still be stripped."""
        text = f"before\n{self.SPEC.begin_marker}\nin block\n{self.SPEC.end_marker}\nafter\n"
        result = git_hooks._strip_block(text, self.SPEC)
        assert "in block" not in result
        assert "before\n" in result
        assert "after\n" in result

    def test_two_independent_well_formed_blocks_both_removed(self):
        """Regression: two separate, well-formed blocks are both stripped —
        tempering must not regress the common multi-install case."""
        text = (
            f"{self.SPEC.begin_marker}\nblock1\n{self.SPEC.end_marker}\n"
            "middle\n"
            f"{self.SPEC.begin_marker}\nblock2\n{self.SPEC.end_marker}\n"
        )
        result = git_hooks._strip_block(text, self.SPEC)
        assert "block1" not in result
        assert "block2" not in result
        assert "middle" in result

    def test_orphan_begin_does_not_swallow_adjacent_user_content(self):
        """The bug shape: BEGIN1 ... BEGIN2 ... END (orphan begin from a
        failed manual edit). The OLD regex would have matched from BEGIN1
        all the way to the END and silently deleted BEGIN2 plus every
        line between them — destroying any user content sitting between
        the orphan begin and the next begin marker. The tempered regex
        refuses to span across BEGIN2 from BEGIN1's match attempt, so the
        adjacent user content (between BEGIN1 and BEGIN2) is preserved.

        The isolated BEGIN2-END pair still looks well-formed in itself
        and gets removed — that's the right call: well-formed pairs are
        assumed to be a previous SAC install we're cleaning up. The user
        is then left with the orphan BEGIN1 still in the file so they
        can see the broken state and decide what to do."""
        text = (
            "before\n"
            f"{self.SPEC.begin_marker}\n"
            "user content adjacent to the orphan begin\n"
            f"{self.SPEC.begin_marker}\n"
            "content inside the well-formed inner pair\n"
            f"{self.SPEC.end_marker}\n"
            "after\n"
        )
        result = git_hooks._strip_block(text, self.SPEC)
        # The critical bit: data adjacent to the orphan survives. Without
        # the tempered match the old regex would have eaten this.
        assert "user content adjacent to the orphan begin" in result
        # The orphan BEGIN itself is still in the file — visible enough
        # that a user will notice and clean it up manually.
        assert self.SPEC.begin_marker in result
        # The isolated well-formed inner pair gets removed as a normal
        # SAC-block cleanup. Its content was always within our markers.
        assert "content inside the well-formed inner pair" not in result

    def test_orphan_begin_without_end_is_left_intact(self):
        """A begin marker with no closing end: nothing to strip; the file
        is left unchanged. Don't try to clever-recover a malformed file."""
        text = (
            "before\n"
            f"{self.SPEC.begin_marker}\n"
            "trailing content with no closing end marker\n"
            "after\n"
        )
        result = git_hooks._strip_block(text, self.SPEC)
        assert "trailing content with no closing end marker" in result
        assert self.SPEC.begin_marker in result

    def test_isolated_pair_after_orphan_is_still_removed(self):
        """Mixed shape: an orphan BEGIN followed by adjacent user content,
        then two normal BEGIN-END pairs. The orphan's adjacent content
        survives; the two isolated pairs (assumed to be previous SAC
        installs) are still cleaned. Partial cleanup is the right call —
        refusing to strip ANY blocks just because one orphan exists would
        make a single corrupted file derail every subsequent install."""
        text = (
            f"{self.SPEC.begin_marker}\n"  # orphan BEGIN1
            "adjacent-to-orphan body\n"
            f"{self.SPEC.begin_marker}\n"  # opens isolated pair
            "first isolated pair body\n"
            f"{self.SPEC.end_marker}\n"  # closes isolated pair
            "between blocks\n"
            f"{self.SPEC.begin_marker}\n"  # opens second isolated pair
            "second isolated pair body\n"
            f"{self.SPEC.end_marker}\n"
        )
        result = git_hooks._strip_block(text, self.SPEC)
        # Orphan-adjacent user content survives.
        assert "adjacent-to-orphan body" in result
        # Both isolated well-formed pairs get cleaned.
        assert "first isolated pair body" not in result
        assert "second isolated pair body" not in result
        # Material between the cleaned blocks survives.
        assert "between blocks" in result
        # Exactly one BEGIN marker (the orphan) remains so the user can
        # see and repair the broken state.
        assert result.count(self.SPEC.begin_marker) == 1

    def test_unrelated_marker_tag_is_untouched(self):
        """Markers from a different tag don't match this spec — installs
        for unrelated tools must coexist without interference."""
        other_begin = "# >>> other-tool >>>"
        other_end = "# <<< other-tool <<<"
        text = f"before\n{other_begin}\ncontent\n{other_end}\nafter\n"
        result = git_hooks._strip_block(text, self.SPEC)
        assert result == text


class TestGitNative:
    def test_install_creates_hook_with_default_header(self, workspace):
        manager, installed, path = git_hooks.install_hook(workspace, SPEC)
        assert manager == "git-native"
        assert installed is True
        content = Path(path).read_text()
        assert SPEC.begin_marker in content
        assert SPEC.command in content
        assert SPEC.end_marker in content
        assert content.startswith("#!/usr/bin/env sh")

    def test_install_appends_to_existing_hook(self, workspace):
        hook = workspace / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/usr/bin/env bash\nexisting-step\n")
        _, installed, _ = git_hooks.install_hook(workspace, SPEC)
        assert installed is True
        text = hook.read_text()
        assert "existing-step" in text
        assert SPEC.command in text

    def test_install_is_idempotent(self, workspace):
        git_hooks.install_hook(workspace, SPEC)
        _, second, _ = git_hooks.install_hook(workspace, SPEC)
        assert second is False  # nothing changed
        hook = workspace / ".git" / "hooks" / "pre-commit"
        # Only one tagged block remains.
        assert hook.read_text().count(SPEC.begin_marker) == 1

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits only")
    def test_install_sets_executable_bit(self, workspace):
        _, _, path = git_hooks.install_hook(workspace, SPEC)
        mode = Path(path).stat().st_mode
        assert mode & 0o111, f"hook not executable: {oct(mode)}"

    def test_uninstall_round_trips(self, workspace):
        git_hooks.install_hook(workspace, SPEC)
        _, removed, _ = git_hooks.uninstall_hook(workspace, SPEC)
        assert removed is True
        # Default header was all we wrote, so the file is dropped entirely.
        assert not (workspace / ".git" / "hooks" / "pre-commit").exists()

    def test_uninstall_preserves_other_steps(self, workspace):
        hook = workspace / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/usr/bin/env sh\necho other\n")
        git_hooks.install_hook(workspace, SPEC)
        git_hooks.uninstall_hook(workspace, SPEC)
        text = hook.read_text()
        assert "echo other" in text
        assert SPEC.begin_marker not in text

    def test_verify_reflects_installed_state(self, workspace):
        _, ok, _ = git_hooks.verify_hook(workspace, SPEC)
        assert ok is False
        git_hooks.install_hook(workspace, SPEC)
        _, ok, _ = git_hooks.verify_hook(workspace, SPEC)
        assert ok is True

    def test_install_without_git_raises(self, tmp_path):
        # No .git/ at all.
        with pytest.raises(FileNotFoundError):
            git_hooks.install_hook(tmp_path, SPEC)


class TestHusky:
    @pytest.fixture
    def husky_workspace(self, workspace):
        (workspace / ".husky").mkdir()
        (workspace / ".husky" / "pre-commit").write_text("#!/usr/bin/env sh\necho husky-stage\n")
        return workspace

    def test_install_appends_and_preserves_existing(self, husky_workspace):
        manager, installed, path = git_hooks.install_hook(husky_workspace, SPEC)
        assert manager == "husky"
        assert installed is True
        text = Path(path).read_text()
        assert "echo husky-stage" in text
        assert SPEC.command in text

    def test_uninstall_leaves_existing_step(self, husky_workspace):
        git_hooks.install_hook(husky_workspace, SPEC)
        _, removed, _ = git_hooks.uninstall_hook(husky_workspace, SPEC)
        assert removed is True
        text = (husky_workspace / ".husky" / "pre-commit").read_text()
        assert "echo husky-stage" in text
        assert SPEC.begin_marker not in text


class TestPreCommitFramework:
    @pytest.fixture
    def pc_workspace(self, workspace):
        (workspace / ".pre-commit-config.yaml").write_text(
            "repos:\n"
            "- repo: https://github.com/pre-commit/pre-commit-hooks\n"
            "  rev: v4.0.0\n"
            "  hooks:\n"
            "  - id: trailing-whitespace\n"
        )
        return workspace

    def test_install_appends_local_repo_entry(self, pc_workspace):
        manager, installed, path = git_hooks.install_hook(pc_workspace, SPEC)
        assert manager == "pre-commit"
        assert installed is True
        text = Path(path).read_text()
        assert "trailing-whitespace" in text  # original entry preserved
        assert "- repo: local" in text
        assert f"id: {SPEC.tag}" in text
        assert SPEC.command in text

    def test_uninstall_restores_original(self, pc_workspace):
        original = (pc_workspace / ".pre-commit-config.yaml").read_text()
        git_hooks.install_hook(pc_workspace, SPEC)
        git_hooks.uninstall_hook(pc_workspace, SPEC)
        # Trailing whitespace normalization may add a final newline; compare
        # whitespace-insensitively.
        after = (pc_workspace / ".pre-commit-config.yaml").read_text()
        assert SPEC.begin_marker not in after
        assert original.strip() in after


class TestPreCommitIndentSniff:
    """Reported bug: appending a zero-indent ``- repo:`` block to a config
    whose existing items sit at two-space indent triggers pre-commit's
    ``InvalidConfigError: did not find expected key`` because the new
    item parses as a top-level construct rather than a continuation of
    ``repos:``. We now sniff the existing items' indent and match it."""

    def test_detect_zero_indent(self):
        text = "repos:\n- repo: https://x\n  rev: 1\n"
        assert git_hooks._detect_repos_indent(text) == ""

    def test_detect_two_space_indent(self):
        text = "repos:\n  - repo: https://x\n    rev: 1\n"
        assert git_hooks._detect_repos_indent(text) == "  "

    def test_detect_four_space_indent(self):
        text = "repos:\n    - repo: https://x\n      rev: 1\n"
        assert git_hooks._detect_repos_indent(text) == "    "

    def test_detect_empty_repos_returns_empty_string(self):
        """An empty ``repos:`` list has no items to sniff; default to
        zero indent (the canonical pre-commit form)."""
        assert git_hooks._detect_repos_indent("repos:\n") == ""

    def test_detect_picks_first_item_when_multiple_present(self):
        """Sniff picks the *first* match deterministically. In a
        well-formed config every item shares an indent level, so any
        choice would be the same; in a malformed file the first-match
        rule keeps behaviour predictable."""
        text = "repos:\n  - repo: https://a\n  - repo: https://b\n"
        assert git_hooks._detect_repos_indent(text) == "  "

    def test_detect_tabs_preserved(self):
        """If the user's file uses tabs, match that. We don't translate
        between spaces and tabs — YAML treats them differently."""
        text = "repos:\n\t- repo: https://x\n"
        assert git_hooks._detect_repos_indent(text) == "\t"

    def test_block_body_uses_supplied_indent(self):
        spec = git_hooks.HookSpec(tag="snyk-secure-at-commit", command="fake")
        block = git_hooks._precommit_block(spec, indent="  ")
        # Every body line either starts with the indent + content or is
        # a marker comment (markers stay at column 0 so they're visible
        # at a glance regardless of file style).
        body_lines = block.split("\n")
        sequence_line = next(line for line in body_lines if line.lstrip().startswith("- repo:"))
        assert sequence_line == "  - repo: local"
        # The hook id line lands at the matching deeper indent.
        assert f"  - id: {spec.tag}" in block

    def test_install_into_two_space_indented_config_matches_existing_indent(self, workspace):
        """The exact shape reported by the affected user: items under
        ``repos:`` are two-space indented. The installed SAC block must
        land at the same level so YAML parses without complaint."""
        path = workspace / ".pre-commit-config.yaml"
        path.write_text(
            "repos:\n"
            "  - repo: https://github.com/astral-sh/ruff-pre-commit\n"
            "    rev: v0.15.12\n"
            "    hooks:\n"
            "      - id: ruff\n"
            "        args: [--fix]\n"
            "      - id: ruff-format\n"
        )
        manager, installed, _ = git_hooks.install_hook(workspace, SPEC)
        assert manager == "pre-commit"
        assert installed is True
        text = path.read_text()
        # The new sequence item lands at column 3 (after two spaces).
        assert "  - repo: local" in text
        # And the buggy zero-indent form is absent — that was the cause
        # of "did not find expected key".
        assert "\n- repo: local" not in text

    def test_install_into_two_space_indented_config_is_idempotent(self, workspace):
        """Second install must detect the existing (correctly indented)
        block and skip writing — otherwise we'd grow the file every
        time the installer ran."""
        path = workspace / ".pre-commit-config.yaml"
        path.write_text(
            "repos:\n"
            "  - repo: https://github.com/astral-sh/ruff-pre-commit\n"
            "    rev: v0.15.12\n"
            "    hooks:\n"
            "      - id: ruff\n"
        )
        git_hooks.install_hook(workspace, SPEC)
        _, second_installed, _ = git_hooks.install_hook(workspace, SPEC)
        assert second_installed is False

    def test_reinstall_self_corrects_previously_bad_indent(self, workspace):
        """If a previous (pre-fix) install wrote the block at column 0
        and the user has 2-space items, re-running the installer should
        clean up the bad block and re-emit it at the correct indent."""
        path = workspace / ".pre-commit-config.yaml"
        bad = (
            "repos:\n"
            "  - repo: https://github.com/astral-sh/ruff-pre-commit\n"
            "    rev: v0.15.12\n"
            "    hooks:\n"
            "      - id: ruff\n"
            f"{SPEC.begin_marker}\n"
            "- repo: local\n"  # column 0 — the bug
            "  hooks:\n"
            f"  - id: {SPEC.tag}\n"
            f"    entry: {SPEC.command}\n"
            f"{SPEC.end_marker}\n"
        )
        path.write_text(bad)
        _, installed, _ = git_hooks.install_hook(workspace, SPEC)
        assert installed is True
        text = path.read_text()
        # New block is at the correct two-space indent.
        assert "  - repo: local" in text
        # The buggy zero-indent line is gone.
        assert "\n- repo: local" not in text

    def test_install_into_empty_repos_uses_default_zero_indent(self, workspace):
        """Empty ``repos:`` list — no items to sniff. Default to zero
        indent, which is the canonical pre-commit form."""
        path = workspace / ".pre-commit-config.yaml"
        path.write_text("repos:\n")
        _, installed, _ = git_hooks.install_hook(workspace, SPEC)
        assert installed is True
        # `- repo: local` at column 0 follows the default.
        assert "\n- repo: local" in path.read_text()


# ============================================================================
# 3. End-to-end installer behaviour
# ============================================================================


class TestInstallWorkspaceRecipe:
    def test_install_copies_script_into_workspace_and_wires_hook(
        self, workspace, manifest, payload, capsys
    ):
        installer.install_workspace_recipe("sac-hooks", manifest, payload, workspace, dry_run=False)
        # Script lives at <workspace>/.snyk-studio/components/scripts/...
        script = workspace / SAC_DEST
        assert script.is_file()
        # Hook shim is present in the git-native pre-commit file.
        hook = workspace / ".git" / "hooks" / "pre-commit"
        text = hook.read_text()
        assert "snyk-secure-at-commit" in text
        # The shim references the workspace-relative path so a committed
        # .pre-commit-config.yaml / .husky/pre-commit stays portable across
        # machines — no absolute path, no env token.
        assert str(SAC_DEST) in text
        assert str(workspace.resolve()) not in text

    def test_install_is_idempotent(self, workspace, manifest, payload):
        installer.install_workspace_recipe("sac-hooks", manifest, payload, workspace, dry_run=False)
        installer.install_workspace_recipe("sac-hooks", manifest, payload, workspace, dry_run=False)
        hook = (workspace / ".git" / "hooks" / "pre-commit").read_text()
        assert hook.count("# >>> snyk-secure-at-commit >>>") == 1

    def test_verify_after_install_passes(self, workspace, manifest, payload):
        installer.install_workspace_recipe("sac-hooks", manifest, payload, workspace, dry_run=False)
        ok = installer.verify_workspace_recipe("sac-hooks", manifest, payload, workspace)
        assert ok is True

    def test_verify_without_install_fails(self, workspace, manifest, payload):
        ok = installer.verify_workspace_recipe("sac-hooks", manifest, payload, workspace)
        assert ok is False

    def test_verify_renders_workspace_entries_relative_to_workspace(
        self, workspace, manifest, payload, capsys
    ):
        """Both the script and the pre-commit shim live inside the workspace
        — verify output should render them relative, not as absolute paths."""
        installer.install_workspace_recipe("sac-hooks", manifest, payload, workspace, dry_run=False)
        capsys.readouterr()
        installer.verify_workspace_recipe("sac-hooks", manifest, payload, workspace)
        out = capsys.readouterr().out

        assert ".git/hooks/pre-commit" in out
        assert str(SAC_DEST) in out
        # The absolute workspace prefix should not appear anywhere in the
        # verification output for SAC entries.
        assert str(workspace.resolve()) not in out

    def test_uninstall_removes_script_and_workspace_integration(self, workspace, manifest, payload):
        installer.install_workspace_recipe("sac-hooks", manifest, payload, workspace, dry_run=False)
        assert (workspace / SAC_DEST).is_file()

        installer.uninstall_workspace_recipe(
            "sac-hooks", manifest, payload, workspace, dry_run=False
        )

        # The shim is gone…
        assert not (workspace / ".git" / "hooks" / "pre-commit").exists()
        # …and so is the workspace-local script tree.
        assert not (workspace / ".snyk-studio").exists()

    def test_install_over_legacy_rewrites_shim_and_migrates_script(
        self, workspace, manifest, payload
    ):
        # Simulate a legacy install: a git-native shim pointing at the old
        # .snyk/studio/ path, plus the old script committed on disk.
        legacy_cmd = "uv run .snyk/studio/components/scripts/snyk_secure_at_commit.py --staged"
        spec = git_hooks.HookSpec(tag="snyk-secure-at-commit", command=legacy_cmd)
        git_hooks.install_hook(workspace, spec)
        legacy = workspace / LEGACY_SAC_DEST
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text("# legacy script\n")

        # Re-run install (an upgrade).
        installer.install_workspace_recipe("sac-hooks", manifest, payload, workspace, dry_run=False)

        hook = (workspace / ".git" / "hooks" / "pre-commit").read_text()
        # The shim now points at the new location, with no duplicate block…
        assert ".snyk-studio/components/scripts/snyk_secure_at_commit.py" in hook
        assert ".snyk/studio/" not in hook
        assert hook.count("# >>> snyk-secure-at-commit >>>") == 1
        # …the new script is in place…
        assert (workspace / SAC_DEST).is_file()
        # …and the stale legacy tree is gone.
        assert not legacy.exists()
        assert not (workspace / ".snyk").exists()

    def test_install_coexists_with_existing_snyk_policy_file(self, workspace, manifest, payload):
        # A repo may already have a `.snyk` policy file. Installing under
        # `.snyk-studio/` must not collide with it (the old `.snyk/studio/`
        # layout did) and must leave the policy file untouched.
        policy = workspace / ".snyk"
        policy.write_text("version: v1.0.0\nignore: {}\n")
        installer.install_workspace_recipe("sac-hooks", manifest, payload, workspace, dry_run=False)
        assert (workspace / SAC_DEST).is_file()
        # The policy file is still a file with its original contents.
        assert policy.is_file()
        assert "version: v1.0.0" in policy.read_text()

    def test_uninstall_removes_legacy_snyk_studio_tree(self, workspace, manifest, payload):
        # Simulate an install done by an older installer version under
        # `.snyk/studio/...`. Uninstall must remove the legacy script and prune
        # its now-empty parents.
        legacy = workspace / LEGACY_SAC_DEST
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text("# legacy script\n")

        installer.uninstall_workspace_recipe(
            "sac-hooks", manifest, payload, workspace, dry_run=False
        )

        assert not legacy.exists()
        # The whole legacy tree, including `.snyk/`, is pruned since it is empty.
        assert not (workspace / ".snyk").exists()

    def test_uninstall_prunes_legacy_tree_with_nested_pycache(self, workspace, manifest, payload):
        # The script sits several levels deep, so any __pycache__ it generates
        # is nested (not directly under .snyk/). Cleanup must find and remove it
        # recursively — otherwise the directory stays non-empty and the legacy
        # tree can't be pruned.
        legacy = workspace / LEGACY_SAC_DEST
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text("# legacy script\n")
        pycache = legacy.parent / "__pycache__"
        pycache.mkdir()
        (pycache / "snyk_secure_at_commit.cpython-312.pyc").write_bytes(b"\x00")

        installer.uninstall_workspace_recipe(
            "sac-hooks", manifest, payload, workspace, dry_run=False
        )

        assert not pycache.exists()
        # With the nested __pycache__ gone, the whole legacy tree prunes away.
        assert not (workspace / ".snyk").exists()

    def test_uninstall_preserves_snyk_policy_file_during_legacy_cleanup(
        self, workspace, manifest, payload
    ):
        # Legacy cleanup must not touch a sibling `.snyk` *policy file* — only
        # the empty `.snyk/` directory tree it created is pruned. (Here `.snyk`
        # is a directory holding both the legacy tree and a user file, so the
        # directory itself stays because it is non-empty after cleanup.)
        legacy = workspace / LEGACY_SAC_DEST
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text("# legacy script\n")
        user_file = workspace / ".snyk" / "keep-me.txt"
        user_file.write_text("user data\n")

        installer.uninstall_workspace_recipe(
            "sac-hooks", manifest, payload, workspace, dry_run=False
        )

        assert not legacy.exists()
        # `.snyk/studio/` is gone but the user's file (and thus `.snyk/`) remains.
        assert not (workspace / ".snyk" / "studio").exists()
        assert user_file.is_file()

    def test_dry_run_makes_no_filesystem_changes(self, workspace, manifest, payload):
        installer.install_workspace_recipe("sac-hooks", manifest, payload, workspace, dry_run=True)
        assert not (workspace / SAC_DEST).exists()
        assert not (workspace / ".git" / "hooks" / "pre-commit").exists()

    def test_install_into_explicit_workspace_outside_cwd(
        self, tmp_path, manifest, payload, monkeypatch
    ):
        """`--workspace <path>` installs into the supplied dir even when cwd is unrelated."""
        target = tmp_path / "explicit"
        target.mkdir()
        _init_git_repo(target)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)

        installer.install_workspace_recipe("sac-hooks", manifest, payload, target, dry_run=False)
        # Files land under the explicit workspace, not under cwd.
        assert (target / SAC_DEST).is_file()
        assert not (elsewhere / ".snyk").exists()
        hook = target / ".git" / "hooks" / "pre-commit"
        assert hook.exists()
        # Shim is workspace-relative — same string regardless of which
        # workspace was targeted.
        assert str(SAC_DEST) in hook.read_text()


# ============================================================================
# 4. Workspace resolution (--workspace + git walk-up + skip)
# ============================================================================


class TestResolveWorkspace:
    def test_explicit_arg_wins(self, tmp_path, monkeypatch):
        # cwd is a git repo, but the explicit arg should take priority.
        cwd_repo = tmp_path / "cwd_repo"
        _init_git_repo(cwd_repo)
        monkeypatch.chdir(cwd_repo)
        explicit = tmp_path / "explicit"
        explicit.mkdir()
        resolved = installer.resolve_workspace(str(explicit))
        assert resolved == explicit.resolve()

    def test_explicit_arg_expands_user(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        sub = tmp_path / "sub"
        sub.mkdir()
        resolved = installer.resolve_workspace("~/sub")
        assert resolved == sub.resolve()

    def test_explicit_arg_missing_exits(self, tmp_path):
        missing = tmp_path / "does-not-exist"
        with pytest.raises(SystemExit):
            installer.resolve_workspace(str(missing))

    def test_explicit_arg_not_directory_exits(self, tmp_path):
        f = tmp_path / "afile"
        f.write_text("x")
        with pytest.raises(SystemExit):
            installer.resolve_workspace(str(f))

    def test_falls_back_to_enclosing_git_repo(self, tmp_path, monkeypatch):
        repo = tmp_path / "repo"
        _init_git_repo(repo)
        nested = repo / "subdir" / "deep"
        nested.mkdir(parents=True)
        monkeypatch.chdir(nested)
        resolved = installer.resolve_workspace(None)
        assert resolved == repo.resolve()

    def test_returns_none_when_no_workspace(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)  # not a git repo
        assert installer.resolve_workspace(None) is None

    def test_find_git_root_handles_worktree_file(self, tmp_path, monkeypatch):
        """`.git` may be a file (worktrees/submodules) — still counts as a repo root."""
        worktree = tmp_path / "wt"
        worktree.mkdir()
        (worktree / ".git").write_text("gitdir: /tmp/somewhere\n")
        monkeypatch.chdir(worktree)
        assert installer.find_git_root(worktree) == worktree.resolve()


class TestExpandInstallTokens:
    def test_expands_dollar_workspace(self, workspace):
        s = 'uv run "$WORKSPACE/.snyk/sac/script.py"'
        out = installer.expand_install_tokens(s, workspace)
        assert "$WORKSPACE" not in out
        assert str(workspace.resolve()) in out

    def test_passthrough_when_no_token(self, workspace):
        assert installer.expand_install_tokens("echo hi", workspace) == "echo hi"


# ============================================================================
# 5. resolve_install_path: containment under workspace
# ============================================================================


class TestResolveInstallPath:
    def test_relative_dest_anchors_under_workspace(self, workspace):
        p = installer.resolve_install_path(workspace, "subdir/file.py")
        assert p == (workspace / "subdir" / "file.py").resolve()

    def test_absolute_dest_is_rejected(self, workspace):
        with pytest.raises(SystemExit):
            installer.resolve_install_path(workspace, "/etc/passwd")

    def test_dest_escaping_workspace_is_rejected(self, workspace):
        # `..` segments resolve through the workspace boundary; the
        # containment check rejects the result.
        with pytest.raises(SystemExit):
            installer.resolve_install_path(workspace, "../sibling/file.py")


# ============================================================================
# 6. Hook-script semantics
# ============================================================================
#
# These exercise pure-Python helpers in snyk_secure_at_commit.py — no
# subprocess, no Snyk CLI. Goals:
#   * confirm exact (not suffix) path matching so monorepos with duplicate
#     basenames don't get false positives
#   * confirm SCA filtering keeps only vulns whose project's targetFile is
#     in the staged set (so staging Project A's manifest doesn't surface
#     unrelated Project B vulns)
#   * confirm parse_sca_results threads targetFile per vuln
#   * confirm check_snyk_auth honours XDG_CONFIG_HOME (platform portability)


class TestVulnPathMatching:
    def test_exact_match(self):
        assert sac_hook._vuln_path_matches("pkg/api/main.go", {"pkg/api/main.go"})

    def test_normalises_backslashes(self):
        # Snyk on Windows could emit backslashed paths; we still match.
        assert sac_hook._vuln_path_matches("pkg\\api\\main.go", {"pkg/api/main.go"})

    def test_normalises_leading_dot_slash(self):
        assert sac_hook._vuln_path_matches("./pkg/api/main.go", {"pkg/api/main.go"})

    def test_no_suffix_match_in_monorepo(self):
        """``pkg/api/main.go`` and ``cmd/api/main.go`` share the basename
        ``api/main.go``. Suffix matching would treat them as the same file
        and produce false positives. Exact-match must reject this case."""
        assert sac_hook._vuln_path_matches("pkg/api/main.go", {"cmd/api/main.go"}) is False

    def test_no_match_on_substring(self):
        assert sac_hook._vuln_path_matches("api/main.go", {"pkg/api/main.go"}) is False

    def test_dotfiles_preserve_leading_dot(self):
        """PR feedback: the previous ``lstrip("./")`` in ``_norm`` ate any
        leading ``.`` character, so ``.env`` was normalised to ``env`` and
        produced false-positive matches against unrelated files."""
        # A vuln in `.env` must not match the staged file `env`, and vice
        # versa — they're different files even if the dot looks
        # decorative.
        assert sac_hook._vuln_path_matches(".env", {"env"}) is False
        assert sac_hook._vuln_path_matches("env", {".env"}) is False
        # The legitimate match still works: `.env` matches itself.
        assert sac_hook._vuln_path_matches(".env", {".env"}) is True
        # Same story for any other dotfile a project would have at the
        # repo root.
        assert sac_hook._vuln_path_matches(".gitignore", {".gitignore"}) is True
        assert sac_hook._vuln_path_matches(".gitignore", {"gitignore"}) is False

    def test_norm_strips_only_relative_marker_not_arbitrary_dots(self):
        """Direct ``_norm`` coverage of the prefix-vs-character-set distinction."""
        # The relative-path marker IS stripped.
        assert sac_hook._norm("./src/app.py") == "src/app.py"
        # Multiple stacked markers (defensive — Snyk SARIF could in theory
        # emit nested forms) are all stripped.
        assert sac_hook._norm("././src/app.py") == "src/app.py"
        # A leading dot that is NOT part of a "./" prefix survives.
        assert sac_hook._norm(".env") == ".env"
        # A file literally named `..env` survives — lstrip would have
        # eaten the dots and produced "env".
        assert sac_hook._norm("..env") == "..env"
        # Backslash → forward slash, leading dot preserved.
        assert sac_hook._norm("pkg\\.env") == "pkg/.env"


class TestSASTFilter:
    @staticmethod
    def _vuln(path="src/app.py", vid="V"):
        return {"id": vid, "file_path": path}

    def test_empty_list_filters_to_nothing(self):
        assert sac_hook.filter_sast_vulns([self._vuln()], []) == []

    def test_list_keeps_only_matching_paths(self):
        out = sac_hook.filter_sast_vulns(
            [self._vuln(path="src/app.py", vid="A"), self._vuln(path="src/other.py", vid="B")],
            ["src/app.py"],
        )
        assert {v["id"] for v in out} == {"A"}

    def test_none_sentinel_disables_filter(self):
        """Full-repo mode: ``None`` returns every vuln untouched. The
        severity gate is SCA-only, so SAST has no extra filter here."""
        vulns = [self._vuln(path="a.py", vid="A"), self._vuln(path="b.py", vid="B")]
        out = sac_hook.filter_sast_vulns(vulns, None)
        assert {v["id"] for v in out} == {"A", "B"}


class TestSCAFilter:
    @staticmethod
    def _vuln(severity="high", target_file="package.json", vid="SNYK-X"):
        return {"id": vid, "severity": severity, "target_file": target_file}

    def test_drops_everything_when_no_manifests_staged(self):
        vulns = [self._vuln()]
        assert sac_hook.filter_sca_vulns(vulns, []) == []

    def test_keeps_vuln_for_staged_manifest(self):
        vulns = [self._vuln(target_file="package.json")]
        out = sac_hook.filter_sca_vulns(vulns, ["package.json"])
        assert len(out) == 1

    def test_drops_vuln_from_unstaged_sibling_project(self):
        """Monorepo: staging Project A's manifest must not surface
        Project B's vulns."""
        vulns = [
            self._vuln(target_file="services/a/package.json", vid="A"),
            self._vuln(target_file="services/b/package.json", vid="B"),
        ]
        out = sac_hook.filter_sca_vulns(vulns, ["services/a/package.json"])
        assert {v["id"] for v in out} == {"A"}

    def test_severity_threshold_still_applies(self, monkeypatch):
        monkeypatch.setenv("SAC_MIN_BLOCK_SEVERITY", "high")
        vulns = [
            self._vuln(severity="medium", target_file="package.json", vid="M"),
            self._vuln(severity="high", target_file="package.json", vid="H"),
        ]
        out = sac_hook.filter_sca_vulns(vulns, ["package.json"])
        assert {v["id"] for v in out} == {"H"}

    def test_none_sentinel_disables_manifest_filter(self, monkeypatch):
        """Passing ``None`` for staged_manifests is full-repo mode (script
        invoked without ``--staged``): every project's vulns become eligible,
        but the severity gate still applies."""
        monkeypatch.delenv("SAC_MIN_BLOCK_SEVERITY", raising=False)  # default medium
        vulns = [
            self._vuln(severity="medium", target_file="services/a/package.json", vid="A"),
            self._vuln(severity="medium", target_file="services/b/package.json", vid="B"),
            self._vuln(severity="low", target_file="services/c/package.json", vid="C"),
        ]
        out = sac_hook.filter_sca_vulns(vulns, None)
        # A and B (medium) survive both filters; C (low) drops on severity.
        assert {v["id"] for v in out} == {"A", "B"}


class TestParseSCAResults:
    def test_threads_target_file_per_project(self):
        payload = json.dumps(
            [
                {
                    "displayTargetFile": "services/a/package.json",
                    "vulnerabilities": [
                        {
                            "id": "SNYK-LEFTPAD-1",
                            "packageName": "leftpad",
                            "version": "1.0.0",
                            "severity": "high",
                        }
                    ],
                },
                {
                    "displayTargetFile": "services/b/package.json",
                    "vulnerabilities": [
                        {
                            "id": "SNYK-LEFTPAD-1",
                            "packageName": "leftpad",
                            "version": "1.0.0",
                            "severity": "high",
                        }
                    ],
                },
            ]
        )
        out = sac_hook.parse_sca_results(payload)
        # Same vuln in two projects survives dedup because target_file is part
        # of the dedup key — otherwise we'd lose the project context we need
        # for per-manifest filtering.
        assert {v["target_file"] for v in out} == {
            "services/a/package.json",
            "services/b/package.json",
        }

    def test_falls_back_to_target_file_when_display_missing(self):
        payload = json.dumps({"targetFile": "go.mod", "vulnerabilities": []})
        out = sac_hook.parse_sca_results(payload)
        # No vulns to inspect directly — parsing must still succeed (no
        # KeyError on the missing displayTargetFile field).
        assert out == []

    def test_indirect_dep_intro_chain_excludes_project_and_self(self):
        """Snyk's `from` walks project → intermediates → vulnerable leaf.
        We surface only the intermediates so the developer sees which
        direct dependency dragged the vuln in."""
        payload = json.dumps(
            {
                "targetFile": "package.json",
                "vulnerabilities": [
                    {
                        "id": "SNYK-LODASH",
                        "packageName": "lodash",
                        "version": "4.17.15",
                        "severity": "high",
                        "from": [
                            "my-project@1.0.0",
                            "express@4.17.1",
                            "body-parser@1.19.0",
                            "lodash@4.17.15",
                        ],
                    }
                ],
            }
        )
        out = sac_hook.parse_sca_results(payload)
        assert out[0]["intro_chain"] == ["express@4.17.1", "body-parser@1.19.0"]

    def test_direct_dep_intro_chain_is_empty(self):
        payload = json.dumps(
            {
                "targetFile": "package.json",
                "vulnerabilities": [
                    {
                        "id": "SNYK-LODASH",
                        "packageName": "lodash",
                        "version": "4.17.15",
                        "severity": "high",
                        "from": ["my-project@1.0.0", "lodash@4.17.15"],
                    }
                ],
            }
        )
        out = sac_hook.parse_sca_results(payload)
        assert out[0]["intro_chain"] == []

    def test_missing_from_field_yields_empty_chain(self):
        # Older snyk versions or sparse outputs may not include `from`.
        payload = json.dumps(
            {
                "targetFile": "package.json",
                "vulnerabilities": [
                    {
                        "id": "SNYK-LODASH",
                        "packageName": "lodash",
                        "version": "4.17.15",
                        "severity": "high",
                    }
                ],
            }
        )
        out = sac_hook.parse_sca_results(payload)
        assert out[0]["intro_chain"] == []


class TestSnykConfigPath:
    def test_honours_xdg_config_home(self, tmp_path, monkeypatch):
        custom = tmp_path / "xdg"
        monkeypatch.setenv("XDG_CONFIG_HOME", str(custom))
        path = sac_hook._snyk_config_path()
        assert path == str(custom / "configstore" / "snyk.json")

    def test_falls_back_to_home_dot_config(self, tmp_path, monkeypatch):
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path))
        path = sac_hook._snyk_config_path()
        assert path == str(tmp_path / ".config" / "configstore" / "snyk.json")


class TestSnykEnv:
    def test_machine_id_linux_path(self, monkeypatch):
        import builtins
        import io

        monkeypatch.setattr("sys.platform", "linux")
        real_open = builtins.open

        def mock_open(path, *args, **kwargs):
            if path == "/var/lib/snyk-studio/device-id":
                return io.StringIO("my-device-id")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", mock_open)
        env = sac_hook._snyk_env()
        assert env["SNYK_CLIENT_MACHINE_ID"] == "my-device-id"

    def test_machine_id_macos_path(self, monkeypatch):
        import builtins
        import io

        monkeypatch.setattr("sys.platform", "darwin")
        real_open = builtins.open

        def mock_open(path, *args, **kwargs):
            if path == "/Library/Application Support/snyk-studio/device-id":
                return io.StringIO("my-device-id")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", mock_open)
        env = sac_hook._snyk_env()
        assert env["SNYK_CLIENT_MACHINE_ID"] == "my-device-id"

    def test_machine_id_windows_path(self, monkeypatch):
        import builtins
        import io

        monkeypatch.setattr("sys.platform", "win32")
        monkeypatch.setattr("snyk_secure_at_commit.shutil.which", lambda *a, **kw: None)
        monkeypatch.setenv("ProgramData", "C:\\ProgramData")
        expected_path = os.path.join("C:\\ProgramData", "snyk-studio", "device-id")
        real_open = builtins.open

        def mock_open(path, *args, **kwargs):
            if path == expected_path:
                return io.StringIO("my-device-id")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", mock_open)
        env = sac_hook._snyk_env()
        assert env["SNYK_CLIENT_MACHINE_ID"] == "my-device-id"

    def test_machine_id_absent_when_file_missing(self, monkeypatch):
        import builtins

        monkeypatch.setattr("sys.platform", "linux")
        real_open = builtins.open

        def mock_open(path, *args, **kwargs):
            if path == "/var/lib/snyk-studio/device-id":
                raise FileNotFoundError(path)
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", mock_open)
        env = sac_hook._snyk_env()
        assert "SNYK_CLIENT_MACHINE_ID" not in env

    def test_machine_id_absent_when_file_empty(self, monkeypatch):
        import builtins
        import io

        monkeypatch.setattr("sys.platform", "linux")
        real_open = builtins.open

        def mock_open(path, *args, **kwargs):
            if path == "/var/lib/snyk-studio/device-id":
                return io.StringIO("   ")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", mock_open)
        env = sac_hook._snyk_env()
        assert "SNYK_CLIENT_MACHINE_ID" not in env


# ============================================================================
# 7. Compiler-style output formatting
# ============================================================================
#
# `_fmt_sast_line` follows the MSVC diagnostic shape `file(line,col):` so VS
# Code's Problems panel and most editor lint integrations recognise each
# finding as a clickable diagnostic. `_fmt_sca_line` adapts the same skeleton
# for dependency vulns (no line/column — the manifest + package@version
# stands in for the location). `_print_block_reason` emits one line per
# finding (no markdown header) plus a single trailing bypass hint.


class TestSastGroupFormat:
    @staticmethod
    def _vuln(**overrides):
        base = {
            "id": "python/SQLi",
            "title": "SQL Injection",
            "severity": "high",
            "cwe": "CWE-89",
            "file_path": "src/app.py",
            "start_line": 42,
            "start_column": 5,
        }
        base.update(overrides)
        return base

    def _render(self, *findings):
        v0 = findings[0]
        return sac_hook._fmt_sast_group(
            v0["file_path"],
            v0["start_line"],
            v0["start_column"],
            list(findings),
            color=False,
        )

    def test_single_finding_is_one_line_msvc_diagnostic(self):
        out = self._render(self._vuln())
        assert out == "src/app.py(42,5): [high] [python/SQLi] [CWE-89] [SQL Injection]"

    def test_missing_cwe_renders_as_dash(self):
        out = self._render(self._vuln(cwe=None))
        assert "[-]" in out

    def test_color_wraps_only_the_severity_token(self):
        out = self._render(self._vuln(severity="critical"))
        # On a colorless render the severity is plain text.
        assert sac_hook._SEVERITY_ANSI["critical"] not in out
        # Single-line shape preserves the editor-parseable diagnostic prefix.
        assert out.startswith("src/app.py(42,5): [")
        # Now the color path — render via the group helper directly to
        # bypass the test's color=False default.
        v = self._vuln(severity="critical")
        colored = sac_hook._fmt_sast_group(
            v["file_path"], v["start_line"], v["start_column"], [v], color=True
        )
        assert sac_hook._SEVERITY_ANSI["critical"] in colored
        assert sac_hook._ANSI_RESET in colored
        # The `file(line,col):` prefix must not be color-escaped — editors
        # parse that prefix to locate diagnostics in the buffer.
        assert colored.startswith("src/app.py(42,5): [")

    def test_multiple_findings_at_one_location_collapse_under_header(self):
        """Multiple rules flagging the same expression collapse under one
        ``file(line,col):`` header so the report doesn't re-state the
        location for every finding."""
        a = self._vuln(id="python/SQLi", severity="critical", title="SQLi")
        b = self._vuln(id="python/Taint", severity="high", title="Taint")
        c = self._vuln(id="python/InjFromInput", severity="medium", title="InjInput")
        out = self._render(a, b, c)
        lines = out.split("\n")
        assert lines[0] == "src/app.py(42,5):"
        # Findings indented under the single header, sorted worst-first.
        assert lines[1].startswith("  [critical] [python/SQLi]")
        assert lines[2].startswith("  [high] [python/Taint]")
        assert lines[3].startswith("  [medium] [python/InjFromInput]")
        # Location text appears exactly once.
        assert out.count("src/app.py(42,5)") == 1


class TestScaGroupFormat:
    @staticmethod
    def _vuln(**overrides):
        base = {
            "id": "SNYK-JS-LODASH-1018905",
            "title": "Prototype Pollution",
            "severity": "high",
            "package_name": "lodash",
            "version": "4.17.15",
            "cve": "CVE-2020-8203",
            "fix_available": True,
            "target_file": "package.json",
            "intro_chain": [],
        }
        base.update(overrides)
        return base

    def _render(self, *findings):
        v0 = findings[0]
        return sac_hook._fmt_sca_group(
            v0["target_file"],
            v0["package_name"],
            v0["version"],
            list(findings),
            color=False,
        )

    def test_single_direct_finding_is_one_line(self):
        out = self._render(self._vuln())
        assert out == (
            "package.json(lodash@4.17.15): [high] [SNYK-JS-LODASH-1018905] "
            "[CVE-2020-8203] [Prototype Pollution] [fix available]"
        )

    def test_no_fix_marker_when_not_upgradable(self):
        out = self._render(self._vuln(fix_available=False))
        assert out.endswith("[no fix]")

    def test_missing_cve_renders_as_dash(self):
        out = self._render(self._vuln(cve=None))
        assert "[-]" in out

    def test_single_indirect_finding_renders_header_via_finding(self):
        """One indirect finding: a header line, a ``via:`` line, and the
        bracketed finding indented under it — three lines total."""
        v = self._vuln(intro_chain=["express@4.17.1", "body-parser@1.19.0"])
        lines = self._render(v).split("\n")
        assert lines == [
            "package.json(lodash@4.17.15):",
            "  via: express@4.17.1 > body-parser@1.19.0",
            "    [high] [SNYK-JS-LODASH-1018905] [CVE-2020-8203] "
            "[Prototype Pollution] [fix available]",
        ]

    def test_multiple_findings_share_one_chain(self):
        """The reported case: several CVEs in the same vulnerable package
        introduced via the same chain. The chain isn't repeated per CVE —
        it appears once, with the findings stacked beneath it."""
        a = self._vuln(
            id="SNYK-JS-VM2-A",
            cve="CVE-2026-A",
            title="RCE A",
            severity="critical",
            package_name="vm2",
            version="3.9.11",
            intro_chain=["juicy-chat-bot@0.6.6"],
        )
        b = {**a, "id": "SNYK-JS-VM2-B", "cve": "CVE-2026-B", "title": "RCE B"}
        c = {**a, "id": "SNYK-JS-VM2-C", "cve": "CVE-2026-C", "title": "RCE C"}
        lines = self._render(a, b, c).split("\n")
        assert lines[0] == "package.json(vm2@3.9.11):"
        assert lines[1] == "  via: juicy-chat-bot@0.6.6"
        # 3 indented findings under the single chain header.
        assert lines[2].startswith("    [critical] [SNYK-JS-VM2-A]")
        assert lines[3].startswith("    [critical] [SNYK-JS-VM2-B]")
        assert lines[4].startswith("    [critical] [SNYK-JS-VM2-C]")
        # Chain text appears exactly once.
        assert sum(1 for line in lines if line.lstrip().startswith("via:")) == 1

    def test_findings_split_across_distinct_chains(self):
        """When the same vulnerable package is introduced by more than one
        path, we emit one ``via:`` section per chain with its own findings."""
        a = self._vuln(
            id="A",
            cve="CVE-A",
            title="T-A",
            severity="critical",
            package_name="vm2",
            version="3.9.11",
            intro_chain=["juicy-chat-bot@0.6.6"],
        )
        b = self._vuln(
            id="B",
            cve="CVE-B",
            title="T-B",
            severity="critical",
            package_name="vm2",
            version="3.9.11",
            intro_chain=["request@2.88.2"],
        )
        lines = self._render(a, b).split("\n")
        via_lines = [line for line in lines if line.lstrip().startswith("via:")]
        assert via_lines == ["  via: juicy-chat-bot@0.6.6", "  via: request@2.88.2"]
        # Each chain has exactly one finding under it (4-space indent).
        assert sum(1 for line in lines if line.startswith("    [critical]")) == 2

    def test_direct_findings_print_under_header_without_via_prefix(self):
        """A package with both a direct and an indirect finding emits the
        direct one under the header (no ``via:``) and the indirect one
        under its chain — but the package header appears just once."""
        direct = self._vuln(id="D", cve=None, title="direct", intro_chain=[])
        indirect = self._vuln(id="I", cve=None, title="indirect", intro_chain=["wrapper@1.0"])
        lines = self._render(direct, indirect).split("\n")
        assert lines[0] == "package.json(lodash@4.17.15):"
        # Direct findings come before chain groups; their indent is 2 spaces
        # (vs 4 for findings under a chain) so the structure is visually
        # distinct on a console.
        assert lines[1].startswith("  [high]")
        assert "[direct]" in lines[1]
        assert lines[2] == "  via: wrapper@1.0"
        assert lines[3].startswith("    [high]")
        assert "[indirect]" in lines[3]


class TestPrintBlockReason:
    def test_emits_one_line_per_finding_then_bypass_hint(self, capsys):
        sast = [
            {
                "id": "python/X",
                "title": "X",
                "severity": "high",
                "cwe": None,
                "file_path": "a.py",
                "start_line": 1,
                "start_column": 1,
            }
        ]
        sca = [
            {
                "id": "SNYK-1",
                "title": "Y",
                "severity": "medium",
                "package_name": "p",
                "version": "1.0",
                "cve": None,
                "fix_available": False,
                "target_file": "package.json",
            }
        ]
        sac_hook._print_block_reason(sast, sca, "", "")
        err = capsys.readouterr().err
        lines = err.strip().split("\n")
        # 2 findings + 1 trailing footer; no markdown header.
        assert len(lines) == 3
        assert lines[0].startswith("a.py(1,1):")
        assert lines[1].startswith("package.json(p@1.0):")
        assert lines[2].startswith("snyk: 2 issue(s) blocking commit")
        # No markdown leftovers.
        assert "##" not in err
        assert "|---" not in err

    def test_fallback_messages_print_as_plain_lines(self, capsys):
        sac_hook._print_block_reason([], [], "Snyk CLI not authenticated.", "")
        err = capsys.readouterr().err
        # No findings → no count footer; just the single fallback line.
        assert err.strip() == "Snyk CLI not authenticated."

    def test_findings_sort_by_severity_then_file(self, capsys):
        sast = [
            {
                "id": "low",
                "title": "L",
                "severity": "low",
                "cwe": None,
                "file_path": "z.py",
                "start_line": 1,
                "start_column": 1,
            },
            {
                "id": "crit",
                "title": "C",
                "severity": "critical",
                "cwe": None,
                "file_path": "a.py",
                "start_line": 1,
                "start_column": 1,
            },
        ]
        sac_hook._print_block_reason(sast, [], "", "")
        lines = capsys.readouterr().err.strip().split("\n")
        # critical comes first; the bypass footer is last.
        assert lines[0].startswith("a.py")
        assert "[critical]" in lines[0]
        assert lines[1].startswith("z.py")

    def test_sca_findings_collapse_into_per_package_groups(self, capsys):
        """Three CVEs in the same vulnerable package, all introduced by the
        same direct dependency, must render as one ``manifest(pkg@ver):``
        header + one ``via:`` line + three bracketed finding lines. The
        footer counts the underlying findings, not the groups."""
        sca = [
            {
                "id": "SNYK-A",
                "title": "A",
                "severity": "critical",
                "package_name": "vm2",
                "version": "3.9.11",
                "cve": "CVE-A",
                "fix_available": True,
                "target_file": "package.json",
                "intro_chain": ["juicy-chat-bot@0.6.6"],
            },
            {
                "id": "SNYK-B",
                "title": "B",
                "severity": "critical",
                "package_name": "vm2",
                "version": "3.9.11",
                "cve": "CVE-B",
                "fix_available": True,
                "target_file": "package.json",
                "intro_chain": ["juicy-chat-bot@0.6.6"],
            },
            {
                "id": "SNYK-C",
                "title": "C",
                "severity": "critical",
                "package_name": "vm2",
                "version": "3.9.11",
                "cve": "CVE-C",
                "fix_available": True,
                "target_file": "package.json",
                "intro_chain": ["juicy-chat-bot@0.6.6"],
            },
        ]
        sac_hook._print_block_reason([], sca, "", "")
        err = capsys.readouterr().err
        # One header, one via:, three findings, one footer.
        assert err.count("package.json(vm2@3.9.11):") == 1
        assert err.count("via: juicy-chat-bot@0.6.6") == 1
        for cve in ("CVE-A", "CVE-B", "CVE-C"):
            assert cve in err
        # Footer reports the underlying-finding count, not the group count.
        assert "snyk: 3 issue(s) blocking commit" in err

    def test_sca_groups_ordered_by_dependency_depth(self, capsys):
        """Top-level SCA group order is depth-first: direct deps before
        one-hop indirects before deeper transitives. Severity is only the
        tiebreaker within the same depth — so a medium-severity direct dep
        comes before a critical-severity indirect dep."""

        def vuln(pkg, severity, chain):
            return {
                "id": f"SNYK-{pkg}",
                "title": pkg,
                "severity": severity,
                "package_name": pkg,
                "version": "1.0.0",
                "cve": None,
                "fix_available": False,
                "target_file": "package.json",
                "intro_chain": chain,
            }

        sca = [
            vuln("deepvuln", "critical", ["a@1", "b@1", "c@1"]),  # depth 3
            vuln("onehop", "high", ["wrapper@1"]),  # depth 1
            vuln("direct", "medium", []),  # depth 0
            vuln("twohop", "critical", ["x@1", "y@1"]),  # depth 2
        ]
        sac_hook._print_block_reason([], sca, "", "")
        err = capsys.readouterr().err

        # Pull each package header's first-occurrence offset; sort gives the
        # rendered order.
        headers = [
            ("direct", err.find("package.json(direct@1.0.0)")),
            ("onehop", err.find("package.json(onehop@1.0.0)")),
            ("twohop", err.find("package.json(twohop@1.0.0)")),
            ("deepvuln", err.find("package.json(deepvuln@1.0.0)")),
        ]
        rendered_order = [pkg for pkg, _ in sorted(headers, key=lambda h: h[1])]
        assert rendered_order == ["direct", "onehop", "twohop", "deepvuln"]

    def test_sca_groups_direct_deps_precede_indirect_even_with_higher_severity(self, capsys):
        """Reproduces the form-data vs multer/sequelize/marsdb shape: depth
        wins over severity. A critical indirect dep must sort *after* every
        direct dep regardless of how bad its findings are."""

        def vuln(pkg, severity, chain, vid):
            return {
                "id": vid,
                "title": pkg,
                "severity": severity,
                "package_name": pkg,
                "version": "1.0.0",
                "cve": None,
                "fix_available": False,
                "target_file": "package-lock.json",
                "intro_chain": chain,
            }

        sca = [
            # depth 1, single critical finding — would have surfaced first
            # under the old (severity-then-alpha) sort because it sorts
            # alphabetically before m/m/s.
            vuln("form-data", "critical", ["request@2.88.2"], "F"),
            # depth 0 with mixed severities.
            vuln("marsdb", "critical", [], "M1"),
            vuln("multer", "critical", [], "MU1"),
            vuln("multer", "high", [], "MU2"),
            vuln("sequelize", "critical", [], "S1"),
            vuln("sequelize", "high", [], "S2"),
        ]
        sac_hook._print_block_reason([], sca, "", "")
        err = capsys.readouterr().err

        idx = {
            pkg: err.find(f"package-lock.json({pkg}@1.0.0)")
            for pkg in ("form-data", "marsdb", "multer", "sequelize")
        }
        # All three depth-0 packages must appear before the depth-1 one.
        assert max(idx["marsdb"], idx["multer"], idx["sequelize"]) < idx["form-data"]

    def test_sca_groups_with_same_depth_and_severity_break_ties_by_count(self, capsys):
        """At identical depth+severity, the group with more findings rises —
        a developer hunting for an upgrade with the biggest payoff sees
        densely vulnerable packages first."""

        def vuln(pkg, vid):
            return {
                "id": vid,
                "title": pkg,
                "severity": "critical",
                "package_name": pkg,
                "version": "1.0.0",
                "cve": None,
                "fix_available": False,
                "target_file": "package.json",
                "intro_chain": [],
            }

        # Both at depth 0 + critical: `big` has 3 findings, `small` has 1.
        sca = [
            vuln("small", "S1"),
            vuln("big", "B1"),
            vuln("big", "B2"),
            vuln("big", "B3"),
        ]
        sac_hook._print_block_reason([], sca, "", "")
        err = capsys.readouterr().err
        assert err.find("package.json(big@1.0.0)") < err.find("package.json(small@1.0.0)")

    def test_sast_findings_collapse_into_per_location_groups(self, capsys):
        """Two rules flagging the same expression render as one
        ``file(line,col):`` header plus two indented findings — not two
        separate top-level diagnostics."""
        sast = [
            {
                "id": "python/SQLi",
                "title": "SQLi",
                "severity": "critical",
                "cwe": "CWE-89",
                "file_path": "src/app.py",
                "start_line": 42,
                "start_column": 5,
            },
            {
                "id": "python/Taint",
                "title": "Taint",
                "severity": "high",
                "cwe": None,
                "file_path": "src/app.py",
                "start_line": 42,
                "start_column": 5,
            },
        ]
        sac_hook._print_block_reason(sast, [], "", "")
        err = capsys.readouterr().err
        # Header appears once; findings sit beneath it sorted worst-first.
        assert err.count("src/app.py(42,5)") == 1
        assert "src/app.py(42,5):\n" in err
        assert "  [critical] [python/SQLi]" in err
        assert "  [high] [python/Taint]" in err
        # Footer counts the underlying findings, not groups.
        assert "snyk: 2 issue(s) blocking commit" in err

    def test_sast_groups_ordered_by_severity_then_count_descending(self, capsys):
        """Top-level SAST group order: worst severity first; at equal
        severity the location with more findings rises so hotspots — likely
        a single buggy expression flagged by many rules — surface near
        the top."""

        def sast(file_, line, sev, vid):
            return {
                "id": vid,
                "title": vid,
                "severity": sev,
                "cwe": None,
                "file_path": file_,
                "start_line": line,
                "start_column": 1,
            }

        findings = [
            # 1 medium finding — should be last (worst severity loses).
            sast("c.py", 10, "medium", "C1"),
            # 1 critical finding — beats anything non-critical but loses
            # on count vs `b.py` below.
            sast("a.py", 10, "critical", "A1"),
            # 3 critical findings at one location — should win.
            sast("b.py", 5, "critical", "B1"),
            sast("b.py", 5, "critical", "B2"),
            sast("b.py", 5, "high", "B3"),
        ]
        sac_hook._print_block_reason(findings, [], "", "")
        err = capsys.readouterr().err
        positions = {
            "a.py": err.find("a.py(10,1)"),
            "b.py": err.find("b.py(5,1)"),
            "c.py": err.find("c.py(10,1)"),
        }
        # b.py wins (3 critical-or-better at one location), then a.py
        # (single critical), then c.py (medium).
        assert positions["b.py"] < positions["a.py"] < positions["c.py"]

    def test_full_repo_footer_omits_blocking_commit_language(self, capsys):
        """Without --staged the script is doing an audit, not gating a
        commit, so the footer drops the ``blocking commit`` phrasing and
        the ``--no-verify`` bypass hint that only makes sense in a
        pre-commit context."""
        sast = [
            {
                "id": "python/X",
                "title": "X",
                "severity": "high",
                "cwe": None,
                "file_path": "a.py",
                "start_line": 1,
                "start_column": 1,
            }
        ]
        sac_hook._print_block_reason(sast, [], "", "", staged_mode=False)
        err = capsys.readouterr().err.strip().split("\n")
        # Last line is the audit-mode footer; pre-commit language is absent.
        assert err[-1] == "snyk: 1 issue(s) found"
        assert "blocking commit" not in "\n".join(err)
        assert "--no-verify" not in "\n".join(err)


# ============================================================================
# 8. CLI argument parsing (--staged)
# ============================================================================


class TestParseCliArgs:
    def test_default_is_full_repo_mode(self):
        ns = sac_hook.parse_cli_args([])
        assert ns.staged is False

    def test_staged_flag_sets_pre_commit_mode(self):
        ns = sac_hook.parse_cli_args(["--staged"])
        assert ns.staged is True

    def test_help_describes_staged_flag(self, capsys):
        """``--help`` should mention --staged so anyone running the script
        manually discovers the pre-commit vs audit-mode distinction."""
        with pytest.raises(SystemExit):
            sac_hook.parse_cli_args(["--help"])
        out = capsys.readouterr().out
        assert "--staged" in out
        # The script's purpose appears in either the description or epilog.
        assert "Snyk Code" in out or "Snyk" in out


# ============================================================================
# 9. Fail-closed behavior on git failure (PR feedback: Security Bypass)
# ============================================================================
#
# Reviewer flagged that returning an empty list when ``git diff`` fails would
# let a transiently broken git environment silently pass commits through. We
# now return ``None`` to distinguish "unknown" from "empty"; main() turns
# that into EXIT_PREREQ so the commit is blocked.


class TestGetStagedFilesFailClosed:
    def test_returns_none_when_subprocess_oserror(self, monkeypatch, tmp_path):
        """OSError from subprocess (git not on PATH, etc.) yields ``None``,
        not ``[]``. The caller must be able to tell "git failed" from "no
        staged files"."""

        def raises(*_a, **_kw):
            raise OSError("git is unavailable")

        monkeypatch.setattr(sac_hook.subprocess, "run", raises)
        assert sac_hook.get_staged_files(tmp_path) is None

    def test_returns_none_when_git_exits_nonzero(self, monkeypatch, tmp_path):
        """A non-zero git exit (locked index, corrupt repo, etc.) yields
        ``None``. The reviewer's concern: an empty list here would look
        identical to a clean ``no staged files`` from main()'s perspective
        and let the commit slip through."""

        class FakeResult:
            returncode = 128
            stdout = ""
            stderr = "fatal: not a git repository"

        monkeypatch.setattr(sac_hook.subprocess, "run", lambda *a, **kw: FakeResult())
        assert sac_hook.get_staged_files(tmp_path) is None

    def test_returns_list_on_clean_success(self, monkeypatch, tmp_path):
        """Sanity: success path still returns the parsed file list."""

        class FakeResult:
            returncode = 0
            stdout = "src/app.py\0src/util.py\0"
            stderr = ""

        monkeypatch.setattr(sac_hook.subprocess, "run", lambda *a, **kw: FakeResult())
        assert sac_hook.get_staged_files(tmp_path) == ["src/app.py", "src/util.py"]


class TestMainFailClosed:
    def test_main_returns_exit_prereq_when_get_staged_files_returns_none(
        self, monkeypatch, tmp_path
    ):
        """End-to-end: with ``--staged``, a git failure (signalled by
        ``get_staged_files`` returning ``None``) must surface as
        EXIT_PREREQ. Returning EXIT_OK here would let the commit through
        — the exact bug the reviewer flagged."""
        (tmp_path / ".git").mkdir()
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sac_hook, "get_staged_files", lambda _: None)
        assert sac_hook.main(["--staged"]) == sac_hook.EXIT_PREREQ

    def test_main_returns_exit_prereq_when_staged_outside_git_repo(self, monkeypatch, tmp_path):
        """--staged outside a git repo can only happen via misuse (the
        pre-commit hook is always invoked with cwd inside the repo).
        Treat it as a prerequisite failure so the misuse is loud, not
        silently no-op."""
        monkeypatch.chdir(tmp_path)  # no .git here
        assert sac_hook.main(["--staged"]) == sac_hook.EXIT_PREREQ

    def test_main_returns_exit_ok_when_staged_set_is_empty(self, monkeypatch, tmp_path):
        """The reviewer's complaint was that ``[]`` and ``None`` looked
        identical. Now ``[]`` keeps its original "nothing to scan" meaning
        (EXIT_OK), while ``None`` is the fail-closed signal."""
        (tmp_path / ".git").mkdir()
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sac_hook, "get_staged_files", lambda _: [])
        assert sac_hook.main(["--staged"]) == sac_hook.EXIT_OK


class TestColorSupport:
    def test_off_when_no_color_set(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert sac_hook._supports_color() is False

    def test_off_when_stderr_is_not_a_tty(self, monkeypatch, capsys):
        monkeypatch.delenv("NO_COLOR", raising=False)
        # pytest captures stderr by default; its replacement is not a TTY.
        assert sac_hook._supports_color() is False

    def test_on_when_tty_and_no_color_unset(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setattr(sys.stderr, "isatty", lambda: True, raising=False)
        assert sac_hook._supports_color() is True
