"""End-to-end installer wiring for the secure-at-commit workspace recipe: install
copies the script and wires whichever hook mechanism is detected, verify
reflects that state, uninstall cleans up files and the hook -- plus the
workspace/path-resolution helpers this wiring depends on."""

import subprocess

import pytest

from tests.sac.conftest import (
    GIT,
    LEGACY_SAC_DEST,
    SAC_DEST,
    SPEC,
    _init_hook_workspace,
    _set_home,
    git_hooks,
    git_native,
    husky,
    installer,
    pre_commit,
    types,
)


class TestInstallWorkspaceRecipe:
    @pytest.fixture(autouse=True)
    def _force_pre_2_54_shim(self, monkeypatch):
        """These tests assert against the file-based shim path specifically
        (``.git/hooks/pre-commit``) — force config-based hooks off so
        assertions aren't sensitive to the running machine's Git version.
        """
        monkeypatch.setattr(
            git_native.ConfigBasedHookStrategy, "check_prerequisite", lambda self, workspace: False
        )

    def test_install_copies_script_into_workspace_and_wires_hook(
        self, workspace, manifest, payload, capsys
    ):
        installer.install_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )
        # Script lives at <workspace>/.snyk-studio/components/scripts/...
        script = workspace / SAC_DEST
        assert script.is_file()
        # Hook shim is present in the git-native pre-commit file.
        hook = workspace / ".git" / "hooks" / "pre-commit"
        text = hook.read_text()
        assert "snyk-secure-at-commit" in text
        # Workspace-relative, no absolute path/env token. The manifest's
        # command string is always `/`-separated -- as_posix(), not str().
        assert SAC_DEST.as_posix() in text
        assert str(workspace.resolve()) not in text

    @pytest.mark.parametrize("manager", ["git-native", "pre-commit", "husky"])
    def test_install_is_idempotent_for_detected_manager(
        self, workspace, manifest, payload, manager
    ):
        target = workspace / ".git" / "hooks" / "pre-commit"
        if manager == "pre-commit":
            target = workspace / ".pre-commit-config.yaml"
            target.write_text("repos: []\n", encoding="utf-8")
        elif manager == "husky":
            if GIT is None:
                pytest.skip("git not installed")
            if not git_native._hooks_path_supported(workspace):
                pytest.skip("Husky requires core.hooksPath, added in git 2.9.0")
            subprocess.run(
                [GIT, "-C", str(workspace), "config", "core.hooksPath", ".husky"],
                check=True,
            )
            husky_dir = workspace / ".husky"
            husky_dir.mkdir()
            target = husky_dir / "pre-commit"
            target.write_text("#!/usr/bin/env sh\necho husky\n", encoding="utf-8")

        installer.install_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )
        installer.install_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )
        hook = target.read_text(encoding="utf-8")
        assert hook.count("# >>> snyk-secure-at-commit >>>") == 1
        if manager == "husky":
            assert "echo husky" in hook
        if manager != "git-native":
            native_hook = workspace / ".git" / "hooks" / "pre-commit"
            if native_hook.exists():
                assert SPEC.begin_marker not in native_hook.read_text(encoding="utf-8")

    def test_reinstall_after_precommit_appears_moves_from_git_native_to_precommit(
        self, workspace, manifest, payload
    ):
        installer.install_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )
        native_hook = workspace / ".git" / "hooks" / "pre-commit"
        assert SPEC.begin_marker in native_hook.read_text(encoding="utf-8")

        precommit_config = workspace / ".pre-commit-config.yaml"
        precommit_config.write_text("repos: []\n", encoding="utf-8")
        installer.install_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )

        precommit_text = precommit_config.read_text(encoding="utf-8")
        assert SPEC.begin_marker in precommit_text
        assert precommit_text.count(SPEC.begin_marker) == 1
        if native_hook.exists():
            assert SPEC.begin_marker not in native_hook.read_text(encoding="utf-8")

    def test_verify_after_install_passes(self, workspace, manifest, payload):
        installer.install_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )
        ok = installer.verify_workspace_recipe("secure-at-commit", manifest, payload, workspace)
        assert ok is True

    def test_verify_reports_ok_via_fallback_native_hook_when_precommit_yaml_is_unintegrated(
        self, workspace, manifest, payload
    ):
        """A native shim from an earlier install must still count as verified
        protection even when a newer .pre-commit-config.yaml exists but was
        never actually wired up with our hook - verify must not report
        missing when the repo is still genuinely protected another way."""
        installer.install_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )
        native_hook = workspace / ".git" / "hooks" / "pre-commit"
        assert SPEC.begin_marker in native_hook.read_text(encoding="utf-8")

        (workspace / ".pre-commit-config.yaml").write_text("repos: []\n", encoding="utf-8")

        ok = installer.verify_workspace_recipe("secure-at-commit", manifest, payload, workspace)
        assert ok is True

    def test_install_workspace_recipe_passes_manifest_display_name(
        self, workspace, manifest, payload, monkeypatch
    ):
        captured = {}

        def fake_install_hook(ws, spec):
            captured["workspace"] = ws
            captured["spec"] = spec
            return "git-native", True, str(ws / ".git" / "hooks" / "pre-commit")

        monkeypatch.setattr(git_hooks, "install_hook", fake_install_hook)

        installer.install_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )

        assert captured["workspace"] == workspace
        assert captured["spec"].name == "Snyk Secure At Commit"

    def test_pre_commit_integration_name_falls_back_for_older_manifest(self, workspace):
        tag, command, name = installer._pre_commit_integration_parts(
            {
                "tag": "snyk-secrets-at-commit",
                "command": "uv run .snyk-studio/components/scripts/hook.py",
            },
            workspace,
        )

        assert tag == "snyk-secrets-at-commit"
        assert command == "uv run .snyk-studio/components/scripts/hook.py"
        assert name == "Snyk Secrets At Commit"

    def test_install_workspace_recipe_skips_expected_hook_integration_errors(
        self, workspace, manifest, payload, monkeypatch, capsys
    ):
        def fake_install_hook(ws, spec):
            raise git_hooks.HookIntegrationSkipped("cannot safely parse .pre-commit-config.yaml")

        monkeypatch.setattr(git_hooks, "install_hook", fake_install_hook)

        installer.install_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )

        out = capsys.readouterr().out
        assert "pre-commit integration skipped" in out
        assert "cannot safely parse .pre-commit-config.yaml" in out

    def test_install_workspace_recipe_skips_malformed_precommit_yaml_without_rewriting(
        self, workspace, manifest, payload, capsys
    ):
        path = workspace / ".pre-commit-config.yaml"
        original = "repos: [\n"
        path.write_text(original, encoding="utf-8")

        installer.install_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )

        out = capsys.readouterr().out
        assert "pre-commit integration skipped" in out
        assert "cannot safely parse .pre-commit-config.yaml" in out
        assert path.read_text(encoding="utf-8") == original

    def test_reinstall_with_malformed_new_precommit_config_keeps_existing_native_hook(
        self, workspace, manifest, payload, capsys
    ):
        installer.install_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )
        native_hook = workspace / ".git" / "hooks" / "pre-commit"
        assert SPEC.begin_marker in native_hook.read_text(encoding="utf-8")

        path = workspace / ".pre-commit-config.yaml"
        original = "repos: [\n"
        path.write_text(original, encoding="utf-8")

        installer.install_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )

        out = capsys.readouterr().out
        assert "pre-commit integration skipped" in out
        assert path.read_text(encoding="utf-8") == original
        assert SPEC.begin_marker in native_hook.read_text(encoding="utf-8")

    def test_install_workspace_recipe_skips_non_utf8_precommit_yaml_without_rewriting(
        self, workspace, manifest, payload, capsys
    ):
        path = workspace / ".pre-commit-config.yaml"
        original = b"\xff\xfe\x00"
        path.write_bytes(original)

        installer.install_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )

        out = capsys.readouterr().out
        assert "pre-commit integration skipped" in out
        assert "cannot safely read .pre-commit-config.yaml" in out
        assert path.read_bytes() == original

    def test_install_workspace_recipe_still_skips_missing_hook_integration(
        self, workspace, manifest, payload, monkeypatch, capsys
    ):
        def fake_install_hook(ws, spec):
            raise FileNotFoundError(".pre-commit-config.yaml not found")

        monkeypatch.setattr(git_hooks, "install_hook", fake_install_hook)

        installer.install_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )

        out = capsys.readouterr().out
        assert "pre-commit integration skipped" in out
        assert ".pre-commit-config.yaml not found" in out

    @pytest.mark.parametrize("error", [ValueError("unexpected"), OSError("disk full")])
    def test_install_workspace_recipe_propagates_unexpected_hook_errors(
        self, workspace, manifest, payload, monkeypatch, error
    ):
        def fake_install_hook(ws, spec):
            raise error

        monkeypatch.setattr(git_hooks, "install_hook", fake_install_hook)

        with pytest.raises(type(error), match=str(error)):
            installer.install_workspace_recipe(
                "secure-at-commit", manifest, payload, workspace, dry_run=False
            )

    def test_verify_without_install_fails(self, workspace, manifest, payload):
        ok = installer.verify_workspace_recipe("secure-at-commit", manifest, payload, workspace)
        assert ok is False

    def test_verify_workspace_recipe_passes_manifest_display_name(
        self, workspace, manifest, payload, monkeypatch
    ):
        captured = {}

        def fake_verify_hook(ws, spec):
            captured["workspace"] = ws
            captured["spec"] = spec
            return types.HookVerification("git-native", False, "", None)

        monkeypatch.setattr(git_hooks, "verify_hook", fake_verify_hook)

        ok = installer.verify_workspace_recipe("secure-at-commit", manifest, payload, workspace)

        assert ok is False
        assert captured["workspace"] == workspace
        assert captured["spec"].name == "Snyk Secure At Commit"

    def test_verify_renders_workspace_entries_relative_to_workspace(
        self, workspace, manifest, payload, capsys
    ):
        """Both the script and the pre-commit shim live inside the workspace
        — verify output should render them relative, not as absolute paths."""
        installer.install_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )
        capsys.readouterr()
        installer.verify_workspace_recipe("secure-at-commit", manifest, payload, workspace)
        out = capsys.readouterr().out

        # _display_path renders with the native separator -- normalize
        # both sides to `/` so this test isn't platform-sensitive.
        out_posix = out.replace("\\", "/")
        assert ".git/hooks/pre-commit" in out_posix
        assert SAC_DEST.as_posix() in out_posix
        assert workspace.resolve().as_posix() not in out_posix

    def test_uninstall_removes_script_and_workspace_integration(self, workspace, manifest, payload):
        installer.install_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )
        assert (workspace / SAC_DEST).is_file()

        installer.uninstall_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )

        # The shim is gone…
        assert not (workspace / ".git" / "hooks" / "pre-commit").exists()
        # …and so is the workspace-local script tree.
        assert not (workspace / ".snyk-studio").exists()

    def test_uninstall_removes_legacy_shim_and_legacy_script_tree(
        self, workspace, manifest, payload
    ):
        # Older installs wrote the hook command and script under `.snyk/studio`.
        # Current uninstall must still own the marker block even though the
        # command now points at `.snyk-studio`.
        legacy_cmd = "uv run .snyk/studio/components/scripts/snyk_secure_at_commit.py --staged"
        git_hooks.install_hook(
            workspace,
            git_hooks.HookSpec(
                tag="snyk-secure-at-commit",
                command=legacy_cmd,
                name="Snyk Secure At Commit",
            ),
        )
        legacy = workspace / LEGACY_SAC_DEST
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text("# legacy script\n")

        installer.uninstall_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )

        assert not (workspace / ".git" / "hooks" / "pre-commit").exists()
        assert not legacy.exists()
        assert not (workspace / ".snyk").exists()

    def test_uninstall_scrubs_marked_blocks_from_inactive_managers(self, workspace):
        # Simulate a repo that changed hook integrations over time: old native and
        # Husky marker blocks remain, but pre-commit is now the active integration.
        git_native.FileShimStrategy().install(workspace, SPEC)
        native_hook = workspace / ".git" / "hooks" / "pre-commit"

        (workspace / ".husky").mkdir()
        husky_hook = workspace / ".husky" / "pre-commit"
        husky_hook.write_text("#!/usr/bin/env sh\necho husky\n", encoding="utf-8")
        husky.install_husky(workspace, SPEC)

        precommit_config = workspace / ".pre-commit-config.yaml"
        precommit_config.write_text("repos: []\n", encoding="utf-8")
        pre_commit.install_precommit_framework(workspace, SPEC)

        manager, removed, path = git_hooks.uninstall_hook(workspace, SPEC)

        assert manager == "pre-commit"
        assert removed is True
        assert path == str(precommit_config)
        assert SPEC.begin_marker not in precommit_config.read_text(encoding="utf-8")
        assert SPEC.begin_marker not in husky_hook.read_text(encoding="utf-8")
        assert not native_hook.exists()

    def test_install_over_legacy_rewrites_shim_and_migrates_script(
        self, workspace, manifest, payload
    ):
        # Simulate a legacy install: a git-native shim pointing at the old
        # .snyk/studio/ path, plus the old script committed on disk.
        legacy_cmd = "uv run .snyk/studio/components/scripts/snyk_secure_at_commit.py --staged"
        spec = git_hooks.HookSpec(
            tag="snyk-secure-at-commit",
            command=legacy_cmd,
            name="Snyk Secure At Commit",
        )
        git_hooks.install_hook(workspace, spec)
        legacy = workspace / LEGACY_SAC_DEST
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text("# legacy script\n")

        # Re-run install (an upgrade).
        installer.install_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )

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
        installer.install_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )
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
            "secure-at-commit", manifest, payload, workspace, dry_run=False
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
            "secure-at-commit", manifest, payload, workspace, dry_run=False
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
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )

        assert not legacy.exists()
        # `.snyk/studio/` is gone but the user's file (and thus `.snyk/`) remains.
        assert not (workspace / ".snyk" / "studio").exists()
        assert user_file.is_file()

    def test_dry_run_makes_no_filesystem_changes(self, workspace, manifest, payload):
        installer.install_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=True
        )
        assert not (workspace / SAC_DEST).exists()
        assert not (workspace / ".git" / "hooks" / "pre-commit").exists()

    def test_install_into_explicit_workspace_outside_cwd(
        self, tmp_path, manifest, payload, monkeypatch
    ):
        """`--workspace <path>` installs into the supplied dir even when cwd is unrelated."""
        target = tmp_path / "explicit"
        target.mkdir()
        _init_hook_workspace(target)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)

        installer.install_workspace_recipe(
            "secure-at-commit", manifest, payload, target, dry_run=False
        )
        # Files land under the explicit workspace, not under cwd.
        assert (target / SAC_DEST).is_file()
        assert not (elsewhere / ".snyk").exists()
        hook = target / ".git" / "hooks" / "pre-commit"
        assert hook.exists()
        # Shim is workspace-relative -- same string regardless of workspace.
        assert SAC_DEST.as_posix() in hook.read_text()


# ============================================================================
# 4. Workspace resolution (--workspace + git walk-up + skip)
# ============================================================================


class TestResolveWorkspace:
    def test_explicit_arg_wins(self, tmp_path, monkeypatch):
        # cwd is a git repo, but the explicit arg should take priority.
        cwd_repo = tmp_path / "cwd_repo"
        _init_hook_workspace(cwd_repo)
        monkeypatch.chdir(cwd_repo)
        explicit = tmp_path / "explicit"
        explicit.mkdir()
        resolved = installer.resolve_workspace(str(explicit))
        assert resolved == explicit.resolve()

    def test_explicit_arg_expands_user(self, tmp_path, monkeypatch):
        _set_home(monkeypatch, tmp_path)
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
        _init_hook_workspace(repo)
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
        with pytest.raises(installer.ManifestDestError):
            installer.resolve_install_path(workspace, "/etc/passwd")

    def test_dest_escaping_workspace_is_rejected(self, workspace):
        # `..` segments resolve through the workspace boundary; the
        # containment check rejects the result.
        with pytest.raises(installer.ManifestDestError):
            installer.resolve_install_path(workspace, "../sibling/file.py")


class TestBadManifestDestSkipsOnlyThatFile:
    """A bad manifest ``dest`` must not crash the whole install/verify run -
    only the offending file is skipped (with an ERROR printed); everything
    else in the same recipe still installs and verifies normally."""

    def _corrupt_one_file_dest(self, manifest, bad_dest: str) -> None:
        files = manifest.recipes["secure-at-commit"]["sources"]["workspace"]["files"]
        files.insert(0, {"src": files[0]["src"], "dest": bad_dest})

    def test_install_skips_the_bad_file_and_prints_error_without_crashing(
        self, workspace, manifest, payload, capsys
    ):
        self._corrupt_one_file_dest(manifest, "../escape.py")

        installer.install_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )

        assert "ERROR" in capsys.readouterr().out
        assert (workspace / SAC_DEST).is_file()

    def test_verify_reports_missing_for_the_bad_file_without_crashing(
        self, workspace, manifest, payload, capsys
    ):
        installer.install_workspace_recipe(
            "secure-at-commit", manifest, payload, workspace, dry_run=False
        )
        self._corrupt_one_file_dest(manifest, "/etc/passwd")
        capsys.readouterr()

        ok = installer.verify_workspace_recipe("secure-at-commit", manifest, payload, workspace)

        out = capsys.readouterr().out
        assert ok is False
        assert "ERROR" in out

    def test_has_installed_secrets_hook_files_still_finds_a_later_valid_file(
        self, workspace, manifest, payload
    ):
        """A bad dest in the *first* file entry must not abort the check
        before the rest of the (legitimately installed) files are seen."""
        installer.install_workspace_recipe(
            "secrets-precommit-hook", manifest, payload, workspace, dry_run=False
        )
        files = manifest.recipes["secrets-precommit-hook"]["sources"]["workspace"]["files"]
        files.insert(0, {"src": files[0]["src"], "dest": "/etc/passwd"})

        assert installer._has_installed_secrets_hook_files(manifest, workspace) is True
