"""pre-commit framework integration: managed-entry install/uninstall/verify
in .pre-commit-config.yaml via ruamel, including malformed/mangled-config
recovery and real pre-commit-CLI validation."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.sac.conftest import (
    SPEC,
    _commit_tracked_file,
    _configure_git_identity,
    _runtime_hook_spec,
    _validate_with_precommit_cli,
    git_hooks,
    pre_commit,
    requires_git,
)


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

    @requires_git
    @pytest.mark.skipif(shutil.which("pre-commit") is None, reason="pre-commit not installed")
    def test_installed_precommit_hook_runs_on_real_commit(self, workspace):
        _configure_git_identity(workspace)
        (workspace / ".pre-commit-config.yaml").write_text("repos: []\n", encoding="utf-8")

        manager, installed, _ = git_hooks.install_hook(workspace, _runtime_hook_spec(workspace))
        assert manager == "pre-commit"
        assert installed is True

        env = os.environ.copy()
        env["PRE_COMMIT_HOME"] = str(workspace / ".pre-commit-cache")
        subprocess.run(["pre-commit", "install"], cwd=workspace, env=env, check=True)

        _commit_tracked_file(workspace, "test pre-commit hook", env=env)

        assert (workspace / ".hook-fired").read_text(encoding="utf-8") == "ok"

    @requires_git
    @pytest.mark.skipif(shutil.which("pre-commit") is None, reason="pre-commit not installed")
    def test_ruamel_generated_precommit_config_runs_hook_on_real_commit(self, workspace):
        _configure_git_identity(workspace)
        (workspace / ".pre-commit-config.yaml").write_text(
            "minimum_pre_commit_version: '3.0.0'\n"
            "repos: [{repo: local, hooks: [{id: existing-flow, name: Existing Hook, "
            "entry: \"python3 -c 'print(1)'\", language: system, "
            "pass_filenames: false, always_run: true}]}]\n"
            "ci: {skip: [existing-flow]}\n",
            encoding="utf-8",
        )

        manager, installed, _ = git_hooks.install_hook(
            workspace, _runtime_hook_spec(workspace, ".ruamel-hook-fired")
        )
        assert manager == "pre-commit"
        assert installed is True

        env = os.environ.copy()
        env["PRE_COMMIT_HOME"] = str(workspace / ".pre-commit-cache")
        _validate_with_precommit_cli(workspace, workspace / ".pre-commit-config.yaml")
        subprocess.run(["pre-commit", "install"], cwd=workspace, env=env, check=True)
        _commit_tracked_file(workspace, "test ruamel pre-commit hook", env=env)

        assert (workspace / ".ruamel-hook-fired").read_text(encoding="utf-8") == "ok"

    def test_install_emits_managed_marker_block(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        path.write_text("repos: []\n", encoding="utf-8")
        git_hooks.install_hook(workspace, SPEC)

        text = path.read_text(encoding="utf-8")
        assert SPEC.begin_marker in text
        assert SPEC.end_marker in text
        assert f"id: {SPEC.tag}" in text

    def test_install_does_not_remove_same_id_from_non_local_repo(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        path.write_text(
            "repos:\n"
            "- repo: https://example.com/custom\n"
            "  rev: v1.0.0\n"
            "  hooks:\n"
            f"  - id: {SPEC.tag}\n"
            "    name: Customer Hook\n"
            '    entry: python3 -c "print(1)"\n'
            "    language: system\n"
        )
        _, installed, _ = git_hooks.install_hook(workspace, SPEC)
        assert installed is True
        text = path.read_text()
        assert "repo: https://example.com/custom" in text
        assert "name: Customer Hook" in text
        assert text.count(f"id: {SPEC.tag}") == 2

    def test_uninstall_precommit_is_noop_when_our_hook_absent_on_flow_style_config(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        original = (
            "repos: [{repo: https://github.com/pre-commit/pre-commit-hooks, "
            "rev: v4.0.0, hooks: [{id: trailing-whitespace}]}]\n"
        )
        path.write_text(original, encoding="utf-8")
        removed, _ = pre_commit.uninstall_precommit_framework(workspace, SPEC)
        assert removed is False
        assert path.read_text() == original

    def test_install_precommit_invalid_yaml_skips_and_preserves_file(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        original = "repos: [\n"
        path.write_text(original, encoding="utf-8")

        with pytest.raises(git_hooks.HookIntegrationSkipped):
            git_hooks.install_hook(workspace, SPEC)

        assert path.read_text(encoding="utf-8") == original
        _, found, _, _ = git_hooks.verify_hook(workspace, SPEC)
        assert found is False
        _, removed, _ = git_hooks.uninstall_hook(workspace, SPEC)
        assert removed is False
        assert path.read_text(encoding="utf-8") == original

    def test_install_precommit_non_utf8_yaml_skips_and_preserves_file(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        original = b"\xff\xfe\x00"
        path.write_bytes(original)

        with pytest.raises(git_hooks.HookIntegrationSkipped, match="cannot safely read"):
            git_hooks.install_hook(workspace, SPEC)

        _, found, _, _ = git_hooks.verify_hook(workspace, SPEC)
        assert found is False
        _, removed, _ = git_hooks.uninstall_hook(workspace, SPEC)
        assert removed is False
        assert path.read_bytes() == original

    def test_install_precommit_non_mapping_yaml_skips_and_preserves_file(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        original = "- repo: local\n"
        path.write_text(original, encoding="utf-8")

        with pytest.raises(git_hooks.HookIntegrationSkipped):
            git_hooks.install_hook(workspace, SPEC)

        assert path.read_text(encoding="utf-8") == original

    def test_install_precommit_repos_wrong_type_skips_and_preserves_file(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        original = "repos: not-a-list\n"
        path.write_text(original, encoding="utf-8")

        with pytest.raises(git_hooks.HookIntegrationSkipped):
            git_hooks.install_hook(workspace, SPEC)

        assert path.read_text(encoding="utf-8") == original

    def test_install_precommit_write_error_skips_and_preserves_file(self, workspace, monkeypatch):
        path = workspace / ".pre-commit-config.yaml"
        original = "repos: []\n"
        path.write_text(original, encoding="utf-8")
        real_open = Path.open

        def fail_target_write(self, *args, **kwargs):
            mode = str(args[0] if args else kwargs.get("mode", "r"))
            if self == path and ("w" in mode or "a" in mode):
                raise PermissionError("denied")
            return real_open(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", fail_target_write)

        with pytest.raises(git_hooks.HookIntegrationSkipped, match="cannot safely update"):
            git_hooks.install_hook(workspace, SPEC)

        assert path.read_text(encoding="utf-8") == original

    def test_unmarked_exact_local_repo_is_not_owned_on_install_verify_or_uninstall(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        original = (
            "repos:\n"
            "- repo: local\n"
            "  hooks:\n"
            f"  - id: {SPEC.tag}\n"
            f"    name: {SPEC.name}\n"
            f"    entry: {SPEC.command}\n"
            "    language: system\n"
            "    pass_filenames: false\n"
            "    always_run: true\n"
            "    verbose: true\n"
            "    stages: [pre-commit]\n"
        )
        path.write_text(original, encoding="utf-8")

        _, found, _, _ = git_hooks.verify_hook(workspace, SPEC)
        assert found is False
        _, removed, _ = git_hooks.uninstall_hook(workspace, SPEC)
        assert removed is False
        assert path.read_text(encoding="utf-8") == original

        _, installed, _ = git_hooks.install_hook(workspace, SPEC)

        assert installed is True
        text = path.read_text(encoding="utf-8")
        assert original.strip() in text
        assert SPEC.begin_marker in text
        assert text.count(f"id: {SPEC.tag}") == 2


PRECOMMIT_VALIDATE_CONFIG_CASES = [
    pytest.param("repos: []\n", id="empty-repos"),
    pytest.param(
        (
            "minimum_pre_commit_version: 3.0.0\n"
            "repos: []  # none yet\n"
            "default_language_version:\n"
            "  python: python3\n"
        ),
        id="empty-flow-repos-before-top-level-key",
    ),
    pytest.param(
        (
            "repos:\n"
            "  - repo: local\n"
            "    hooks:\n"
            "      - id: existing\n"
            "        name: Existing Hook\n"
            "        entry: echo existing\n"
            "        language: system\n"
            "\n"
            "# Keep this comment with the following top-level key.\n"
            "ci:\n"
            "  skip: [existing]\n"
        ),
        id="two-space-repos-before-commented-top-level-key",
    ),
    pytest.param(
        (
            "repos: [{repo: local, hooks: [{id: existing, name: Existing Hook, "
            "entry: echo existing, language: system}]}]\n"
            "default_stages: [pre-commit]\n"
        ),
        id="flow-repos-before-top-level-key",
    ),
    pytest.param(
        (
            "# Top-level comment should survive round-trip formatting.\n"
            "minimum_pre_commit_version: '3.0.0'\n"
            "default_language_version:\n"
            "  python: python3\n"
            "repos:\n"
            "  # Existing local hook with folded and literal scalars.\n"
            "  - repo: local\n"
            "    hooks:\n"
            "      - id: existing-gnarly\n"
            '        name: "Existing: Hook #1"\n'
            "        entry: >-\n"
            "          python -c \"print('existing, ok')\"\n"
            "        language: system\n"
            "        files: '\\.(py|js)$'\n"
            "        exclude: |\n"
            "          (?x)^(\n"
            "            docs/\n"
            "          )\n"
            "default_stages: [pre-commit]\n"
        ),
        id="comments-scalars-and-regex",
    ),
    pytest.param(
        (
            "default_stages: &precommit_stages [pre-commit]\n"
            "repos:\n"
            "- repo: local\n"
            "  hooks:\n"
            "  - id: existing-anchor\n"
            "    name: Existing Anchor Hook\n"
            "    entry: echo anchored\n"
            "    language: system\n"
            "    stages: *precommit_stages\n"
            "ci:\n"
            "  skip: [existing-anchor]\n"
        ),
        id="anchors-and-aliases",
    ),
    pytest.param(
        (
            "repos: [\n"
            "  {repo: local, hooks: [\n"
            '    {id: existing-flow, name: "Existing: # flow", '
            "entry: \"python -c 'print(1)'\", language: system, "
            'args: ["--flag=a,b", "[literal]"]}\n'
            "  ]}\n"
            "]\n"
            "ci: {skip: [existing-flow]}\n"
        ),
        id="nested-flow-style",
    ),
]


class TestPreCommitRuamelYaml:
    """Behavior-level coverage for ruamel-backed pre-commit config updates."""

    def _load_config(self, path: Path):
        return pre_commit.YAML().load(path.read_text(encoding="utf-8"))

    def _managed_repo(self, path: Path):
        data = self._load_config(path)
        matches = pre_commit._managed_precommit_repos(data["repos"], SPEC)
        assert len(matches) == 1
        return matches[0]

    def test_hookspec_name_is_required(self):
        with pytest.raises(TypeError):
            git_hooks.HookSpec(tag="snyk-secrets-at-commit", command="fake")

    def test_constructed_entry_uses_display_name_and_managed_markers(self):
        data = pre_commit.YAML().load("repos: []\n")
        repos = data["repos"]
        repos.fa.set_block_style()
        repos.append(pre_commit._new_precommit_repo_entry(SPEC))
        text = pre_commit._dump_yaml_text(pre_commit._new_yaml(), data)

        assert SPEC.begin_marker in text
        assert SPEC.end_marker in text
        assert f"name: {SPEC.name}" in text
        assert "verbose: true" in text
        assert "repo: local  # >>>" not in text
        assert "stages: [pre-commit]  # <<<" not in text
        lines = [line.strip() for line in text.splitlines()]
        assert lines.index(SPEC.begin_marker) < lines.index("- repo: local")
        assert lines.index("stages: [pre-commit]") < lines.index(SPEC.end_marker)
        loaded = pre_commit.YAML().load(text)
        assert len(pre_commit._managed_precommit_repos(loaded["repos"], SPEC)) == 1
        assert pre_commit._precommit_entry_present(loaded, SPEC) is True

    def test_install_into_two_space_indented_config_matches_existing_indent(self, workspace):
        """The exact shape reported by the affected user: items under
        ``repos:`` are two-space indented. The installed SAC block stays
        parseable and aligned with the existing sequence style."""
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
        assert "  - repo: local" in text
        assert "\n- repo: local" not in text
        self._managed_repo(path)

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

    def test_install_skips_invalid_yaml_with_malformed_managed_block(self, workspace):
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
        with pytest.raises(git_hooks.HookIntegrationSkipped):
            git_hooks.install_hook(workspace, SPEC)
        assert path.read_text() == bad

    def test_install_into_empty_repos_uses_default_zero_indent(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        path.write_text("repos:\n")
        _, installed, _ = git_hooks.install_hook(workspace, SPEC)
        assert installed is True
        self._managed_repo(path)

    def test_install_into_flow_style_empty_repos_remains_valid_yaml(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        path.write_text("repos: []\n")
        _, installed, _ = git_hooks.install_hook(workspace, SPEC)
        assert installed is True
        text = path.read_text()
        assert text.startswith("repos:\n")
        assert "repos: []" not in text
        assert self._managed_repo(path)["hooks"][0]["verbose"] is True

    def test_install_into_flow_style_empty_repos_with_inline_comment(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        path.write_text("minimum_pre_commit_version: 3.0.0\nrepos: []  # none yet\n")
        _, installed, _ = git_hooks.install_hook(workspace, SPEC)
        assert installed is True
        text = path.read_text()
        assert "minimum_pre_commit_version: 3.0.0" in text
        assert "# none yet" in text
        assert "\n[]\n" not in text
        self._managed_repo(path)

    def test_install_inserts_managed_block_before_following_top_level_key(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        path.write_text(
            "minimum_pre_commit_version: 3.0.0\n"
            "repos:\n"
            "- repo: https://github.com/pre-commit/pre-commit-hooks\n"
            "  rev: v4.0.0\n"
            "  hooks:\n"
            "  - id: trailing-whitespace\n"
            "default_language_version:\n"
            "  python: python3\n",
            encoding="utf-8",
        )

        _, installed, _ = git_hooks.install_hook(workspace, SPEC)

        assert installed is True
        text = path.read_text(encoding="utf-8")
        assert text.index(SPEC.begin_marker) < text.index("default_language_version:")
        self._managed_repo(path)

    def test_install_into_two_space_repos_before_following_top_level_key(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        path.write_text(
            "repos:\n"
            "  - repo: https://github.com/astral-sh/ruff-pre-commit\n"
            "    rev: v0.15.12\n"
            "    hooks:\n"
            "      - id: ruff\n"
            "\n"
            "# CI tuning belongs to the following key.\n"
            "ci:\n"
            "  skip: [ruff]\n",
            encoding="utf-8",
        )

        _, installed, _ = git_hooks.install_hook(workspace, SPEC)

        assert installed is True
        text = path.read_text(encoding="utf-8")
        assert "# CI tuning belongs to the following key." in text
        assert "  - repo: local" in text
        assert "\n- repo: local" not in text
        self._managed_repo(path)

    def test_install_into_empty_flow_repos_before_following_top_level_key(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        path.write_text("repos: []  # none yet\nci:\n  skip: [ruff]\n", encoding="utf-8")

        _, installed, _ = git_hooks.install_hook(workspace, SPEC)

        assert installed is True
        text = path.read_text(encoding="utf-8")
        assert text.index(SPEC.begin_marker) < text.index("ci:")
        assert "# none yet" in text
        assert "\n[]\n" not in text
        self._managed_repo(path)

    @pytest.mark.skipif(shutil.which("pre-commit") is None, reason="pre-commit not installed")
    @pytest.mark.parametrize("initial_config", PRECOMMIT_VALIDATE_CONFIG_CASES)
    def test_generated_yaml_validates_with_precommit_cli(self, workspace, initial_config):
        path = workspace / ".pre-commit-config.yaml"
        path.write_text(initial_config, encoding="utf-8")

        _, installed, _ = git_hooks.install_hook(workspace, SPEC)

        assert installed is True
        _validate_with_precommit_cli(workspace, path)

    def test_install_into_flow_style_nonempty_repos_preserves_existing_repo_semantics(
        self, workspace
    ):
        path = workspace / ".pre-commit-config.yaml"
        path.write_text(
            "repos: [{repo: https://github.com/pre-commit/pre-commit-hooks, "
            "rev: v4.0.0, hooks: [{id: trailing-whitespace}]}]\n"
        )
        _, installed, _ = git_hooks.install_hook(workspace, SPEC)
        assert installed is True
        text = path.read_text()
        assert text.startswith("repos:\n")
        assert "repos: [" not in text
        data = self._load_config(path)
        assert data["repos"][0]["repo"] == "https://github.com/pre-commit/pre-commit-hooks"
        assert data["repos"][0]["rev"] == "v4.0.0"
        assert data["repos"][0]["hooks"][0]["id"] == "trailing-whitespace"
        self._managed_repo(path)

    def test_install_into_multiline_flow_style_repos_normalizes_to_block_style(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        path.write_text(
            "repos: [\n"
            "  {repo: https://github.com/pre-commit/pre-commit-hooks,\n"
            "   rev: v4.0.0,\n"
            "   hooks: [{id: trailing-whitespace}]}\n"
            "]\n"
        )
        _, installed, _ = git_hooks.install_hook(workspace, SPEC)
        assert installed is True
        text = path.read_text()
        assert text.startswith("repos:\n")
        assert "repos: [" not in text
        data = self._load_config(path)
        assert data["repos"][0]["repo"] == "https://github.com/pre-commit/pre-commit-hooks"
        assert data["repos"][0]["rev"] == "v4.0.0"
        assert data["repos"][0]["hooks"][0]["id"] == "trailing-whitespace"
        self._managed_repo(path)

    def test_install_into_flow_style_repos_with_comment_and_two_items_does_not_crash(
        self, workspace
    ):
        path = workspace / ".pre-commit-config.yaml"
        path.write_text(
            "repos: [\n"
            "  {repo: https://github.com/pre-commit/pre-commit-hooks, hooks: [{id: a}]},\n"
            '  {repo: local, hooks: [{id: b, name: "# not a comment"}]}\n'
            "]  # existing hooks\n"
        )
        _, installed, _ = git_hooks.install_hook(workspace, SPEC)
        assert installed is True
        data = self._load_config(path)
        assert data["repos"][0]["repo"] == "https://github.com/pre-commit/pre-commit-hooks"
        assert data["repos"][1]["hooks"][0]["name"] == "# not a comment"
        self._managed_repo(path)

    def test_reinstall_updates_managed_entry_when_display_name_changes(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        path.write_text("repos: []\n")
        old_spec = git_hooks.HookSpec(
            tag=SPEC.tag,
            command=SPEC.command,
            name="Old Secure At Commit Name",
        )
        git_hooks.install_hook(workspace, old_spec)

        _, installed, _ = git_hooks.install_hook(workspace, SPEC)

        assert installed is True
        text = path.read_text(encoding="utf-8")
        assert "Old Secure At Commit Name" not in text
        assert f"name: {SPEC.name}" in text
        assert text.count(f"id: {SPEC.tag}") == 1

    def test_reinstall_consolidates_duplicate_managed_entries(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        old_spec = git_hooks.HookSpec(
            tag=SPEC.tag,
            command="uv run old-hook.py --staged",
            name=SPEC.name,
        )
        data = pre_commit.YAML().load("repos: []\n")
        repos = data["repos"]
        repos.fa.set_block_style()
        repos.append(pre_commit._new_precommit_repo_entry(old_spec))
        repos.append(pre_commit._new_precommit_repo_entry(SPEC))
        path.write_text(pre_commit._dump_yaml_text(pre_commit._new_yaml(), data), encoding="utf-8")

        _, installed, _ = git_hooks.install_hook(workspace, SPEC)

        text = path.read_text(encoding="utf-8")
        assert installed is True
        assert "old-hook.py" not in text
        assert text.count(f"id: {SPEC.tag}") == 1

    def test_reinstall_replaces_mangled_managed_block_after_reload(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        path.write_text("repos: []\n")
        git_hooks.install_hook(workspace, SPEC)
        data = self._load_config(path)
        managed_repo = pre_commit._managed_precommit_repos(data["repos"], SPEC)[0]
        hook = managed_repo["hooks"][0]
        hook["id"] = "mutated-snyk-hook"
        hook["entry"] = "echo broken"
        hook["args"] = ["--changed-inside-managed-block"]
        path.write_text(pre_commit._dump_yaml_text(pre_commit._new_yaml(), data), encoding="utf-8")

        _, installed, _ = git_hooks.install_hook(workspace, SPEC)

        text = path.read_text(encoding="utf-8")
        assert installed is True
        assert "mutated-snyk-hook" not in text
        assert "changed-inside-managed-block" not in text
        assert text.count(f"id: {SPEC.tag}") == 1

    def test_reinstall_replaces_only_mangled_managed_block_after_reload(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        path.write_text(
            "repos:\n"
            "- repo: local\n"
            "  hooks:\n"
            "  - id: customer-before-hook\n"
            "    name: Customer Before Hook\n"
            "    entry: echo before\n"
            "    language: system\n",
            encoding="utf-8",
        )
        git_hooks.install_hook(workspace, SPEC)
        data = self._load_config(path)
        managed_repo = pre_commit._managed_precommit_repos(data["repos"], SPEC)[0]
        managed_repo["repo"] = "other-installer-mutated-repo"
        managed_repo["hooks"][0]["id"] = "other-installer-mutated-hook"
        managed_repo["hooks"].append(
            pre_commit.YAML().load(
                "- id: inside-managed-customer-hook\n"
                "  name: Inside Managed Customer Hook\n"
                "  entry: echo inside\n"
                "  language: system\n"
            )[0]
        )
        data["repos"].append(
            pre_commit.YAML().load(
                "- repo: local\n"
                "  hooks:\n"
                "  - id: customer-after-hook\n"
                "    name: Customer After Hook\n"
                "    entry: echo after\n"
                "    language: system\n"
            )[0]
        )
        path.write_text(pre_commit._dump_yaml_text(pre_commit._new_yaml(), data), encoding="utf-8")

        _, installed, _ = git_hooks.install_hook(workspace, SPEC)

        text = path.read_text(encoding="utf-8")
        loaded = self._load_config(path)
        hook_ids = [hook["id"] for repo in loaded["repos"] for hook in repo.get("hooks", [])]
        assert installed is True
        assert hook_ids == ["customer-before-hook", "customer-after-hook", SPEC.tag]
        assert "other-installer-mutated" not in text
        assert "inside-managed-customer-hook" not in text
        assert len(pre_commit._managed_precommit_repos(loaded["repos"], SPEC)) == 1

    def test_uninstall_removes_managed_entry_using_ruamel_comments(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        path.write_text("repos: []\n")
        git_hooks.install_hook(workspace, SPEC)

        removed, _ = pre_commit.uninstall_precommit_framework(workspace, SPEC)

        assert removed is True
        text = path.read_text(encoding="utf-8")
        assert SPEC.begin_marker not in text
        assert SPEC.end_marker not in text
        assert self._load_config(path)["repos"] == []

    def test_uninstall_removes_everything_inside_managed_block(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        path.write_text(
            "repos:\n"
            "- repo: local\n"
            "  hooks:\n"
            "  - id: outside-customer-hook\n"
            "    name: Outside Customer Hook\n"
            "    entry: echo outside\n"
            "    language: system\n"
            f"{SPEC.begin_marker}\n"
            "- repo: local\n"
            "  hooks:\n"
            f"  - id: {SPEC.tag}\n"
            f"    name: {SPEC.name}\n"
            f"    entry: {SPEC.command}\n"
            "    language: system\n"
            "    pass_filenames: false\n"
            "    always_run: true\n"
            "    verbose: true\n"
            "    stages: [pre-commit]\n"
            "- repo: local\n"
            "  hooks:\n"
            "  - id: inside-second-repo-hook\n"
            "    name: Inside Second Repo Hook\n"
            "    entry: echo inside\n"
            "    language: system\n"
            f"{SPEC.end_marker}\n"
            "- repo: local\n"
            "  hooks:\n"
            "  - id: after-customer-hook\n"
            "    name: After Customer Hook\n"
            "    entry: echo after\n"
            "    language: system\n",
            encoding="utf-8",
        )

        removed, _ = pre_commit.uninstall_precommit_framework(workspace, SPEC)

        loaded = self._load_config(path)
        hook_ids = [repo["hooks"][0]["id"] for repo in loaded["repos"]]
        assert removed is True
        assert hook_ids == ["outside-customer-hook", "after-customer-hook"]
        assert "inside-second-repo-hook" not in path.read_text(encoding="utf-8")
        assert SPEC.begin_marker not in path.read_text(encoding="utf-8")
        assert SPEC.end_marker not in path.read_text(encoding="utf-8")

    def test_uninstall_removes_mangled_managed_block_after_reload(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        path.write_text("repos: []\n")
        git_hooks.install_hook(workspace, SPEC)
        data = self._load_config(path)
        managed_repo = pre_commit._managed_precommit_repos(data["repos"], SPEC)[0]
        managed_repo["repo"] = "mutated-local"
        managed_repo["hooks"][0]["id"] = "mutated-snyk-hook"
        path.write_text(pre_commit._dump_yaml_text(pre_commit._new_yaml(), data), encoding="utf-8")

        removed, _ = pre_commit.uninstall_precommit_framework(workspace, SPEC)

        assert removed is True
        assert self._load_config(path)["repos"] == []

    def test_install_after_uninstall_recreates_single_managed_entry(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        path.write_text("repos: []\n")
        git_hooks.install_hook(workspace, SPEC)
        pre_commit.uninstall_precommit_framework(workspace, SPEC)

        _, installed, _ = git_hooks.install_hook(workspace, SPEC)

        text = path.read_text(encoding="utf-8")
        assert installed is True
        assert text.count(f"id: {SPEC.tag}") == 1
        assert self._managed_repo(path)["hooks"][0]["entry"] == SPEC.command

    def test_marker_strings_in_yaml_values_are_not_owned(self, workspace):
        path = workspace / ".pre-commit-config.yaml"
        path.write_text(
            "repos:\n"
            "- repo: local\n"
            "  hooks:\n"
            f"  - id: {SPEC.tag}\n"
            f"    name: {SPEC.name}\n"
            f"    entry: {SPEC.command}\n"
            "    language: system\n"
            f"    args: ['{SPEC.begin_marker}', '{SPEC.end_marker}']\n",
            encoding="utf-8",
        )

        _, found, _, _ = git_hooks.verify_hook(workspace, SPEC)
        removed, _ = pre_commit.uninstall_precommit_framework(workspace, SPEC)
        _, installed, _ = git_hooks.install_hook(workspace, SPEC)

        text = path.read_text(encoding="utf-8")
        assert found is False
        assert removed is False
        assert installed is True
        assert text.count(f"id: {SPEC.tag}") == 2
