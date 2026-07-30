"""Manifest plumbing for secure-at-commit: scope, profile membership, and
conflicts_with resolution against the SAI recipe."""

from pathlib import Path

from tests.sac.conftest import installer


class TestManifestSAC:
    def test_sac_hooks_is_workspace_scoped(self, manifest):
        assert manifest.is_workspace_scoped("secure-at-commit") is True
        # secrets-precommit-hook is the one other legitimate workspace-scoped recipe.
        for rid in manifest.all_recipe_ids():
            if rid in ("secure-at-commit", "secrets-precommit-hook"):
                continue
            assert manifest.is_workspace_scoped(rid) is False, rid

    def test_sac_hooks_workspace_sources(self, manifest):
        sources = manifest.recipes["secure-at-commit"]["sources"]
        assert list(sources.keys()) == ["workspace"]
        ws = sources["workspace"]
        assert ws["files"], "secure-at-commit must ship files"
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
        assert ws["pre_commit_integration"]["name"] == "Snyk Secure At Commit"
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

    def test_all_pre_commit_integrations_declare_display_name(self, manifest):
        missing = []
        for recipe_id, recipe in manifest.recipes.items():
            for scope, sources in recipe.get("sources", {}).items():
                pci = sources.get("pre_commit_integration")
                if pci is not None and not pci.get("name"):
                    missing.append(f"{recipe_id}:{scope}")

        assert missing == []

    def test_experimental_profile_excludes_sai(self, manifest):
        recipes = manifest.resolve_recipes("experimental")
        assert "secure-at-commit" in recipes
        assert "sai-hooks-async" not in recipes

    def test_default_profile_excludes_sac(self, manifest):
        recipes = manifest.resolve_recipes("default")
        assert "sai-hooks-async" in recipes
        assert "secure-at-commit" not in recipes

    def test_conflicts_with_drops_sai_when_both_listed(self, manifest, monkeypatch):
        """If a profile happens to list both secure-at-commit and sai-hooks-async,
        sai-hooks-async is dropped because of conflicts_with."""
        monkeypatch.setitem(
            manifest.profiles,
            "_both",
            {"recipes": ["sai-hooks-async", "secure-at-commit", "mcp-config"]},
        )
        recipes = manifest.resolve_recipes("_both")
        assert "secure-at-commit" in recipes
        assert "sai-hooks-async" not in recipes
        assert "mcp-config" in recipes

    def test_conflicts_with_no_op_when_only_sai(self, manifest, monkeypatch):
        """A profile that lists only SAI is unaffected by SAC's
        conflicts_with declaration (secure-at-commit isn't in the active set)."""
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
        """Every src path declared on secure-at-commit must resolve to a real file
        in the payload — protects against typos in manifest.json."""
        for f in manifest.recipes["secure-at-commit"]["sources"]["workspace"]["files"]:
            src = payload.resolve_src(f["src"])
            assert src.is_file(), f["src"]


class TestDetectStaleConflicts:
    """PR feedback: when a user switches from a profile that installs SAI to
    one that installs SAC, the old SAI files stay on disk and both systems
    fire at once. ``Manifest.detect_stale_conflicts`` reports those triples
    so the installer can warn + offer cleanup before proceeding."""

    def test_no_stale_conflicts_when_nothing_on_disk(self, manifest, tmp_path, monkeypatch):
        """Clean baseline: no SAI files installed → no stale conflicts even
        when secure-at-commit declares it conflicts with sai-hooks-async."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert manifest.detect_stale_conflicts(["secure-at-commit"]) == []

    def test_reports_sai_files_present_for_each_affected_ade(self, manifest, tmp_path, monkeypatch):
        """SAI files exist for claude and cursor (from a prior install via
        the default profile). Installing secure-at-commit must report both ADEs
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

        stale = manifest.detect_stale_conflicts(["secure-at-commit"])
        triples = {(active, conflicted, ade) for active, conflicted, ade in stale}
        assert ("secure-at-commit", "sai-hooks-async", "claude") in triples
        assert ("secure-at-commit", "sai-hooks-async", "cursor") in triples

    def test_skips_workspace_scoped_conflicted_recipes(self, manifest, tmp_path, monkeypatch):
        """Workspace-scoped conflicted recipes need a different path
        resolver; the helper deliberately skips them. Today no recipe
        declares such a conflict — this test guards against a future
        misuse silently going undetected."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        # Fake an active recipe that "conflicts with" secure-at-commit itself
        # (workspace-scoped). The detector must not crash and must not
        # report a stale conflict for secure-at-commit.
        monkeypatch.setitem(
            manifest.recipes,
            "_pretend",
            {
                "type": "hooks",
                "description": "synthetic",
                "enabled": True,
                "conflicts_with": ["secure-at-commit"],
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
