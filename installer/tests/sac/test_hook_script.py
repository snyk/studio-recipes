"""Hook-script semantics for snyk_secure_at_commit.py: exact (not suffix)
path matching, per-manifest SAST/SCA filtering and parsing, XDG-aware Snyk
auth/config lookup, CLI argument parsing, and fail-closed behaviour when
git itself misbehaves (PR feedback: Security Bypass)."""

import json
import os
import sys

import pytest

from tests.sac.conftest import _set_home, sac_hook


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
        _set_home(monkeypatch, tmp_path)
        path = sac_hook._snyk_config_path()
        assert path == str(tmp_path / ".config" / "configstore" / "snyk.json")


class TestSnykEnv:
    # The device-id is read from a single, platform-independent location:
    # ~/.snyk-studio/device-id (written by the installer's --control-identifier).
    _DEVICE_ID = os.path.join(os.path.expanduser("~"), ".snyk-studio", "device-id")

    def test_machine_id_from_home(self, monkeypatch):
        import builtins
        import io

        real_open = builtins.open

        def mock_open(path, *args, **kwargs):
            if path == self._DEVICE_ID:
                return io.StringIO("my-device-id")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", mock_open)
        env = sac_hook._snyk_env()
        assert env["INTERNAL_SNYK_CLIENT_MACHINE_ID"] == "my-device-id"

    def test_machine_id_absent_when_file_missing(self, monkeypatch):
        import builtins

        real_open = builtins.open

        def mock_open(path, *args, **kwargs):
            if path == self._DEVICE_ID:
                raise FileNotFoundError(path)
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", mock_open)
        env = sac_hook._snyk_env()
        assert "INTERNAL_SNYK_CLIENT_MACHINE_ID" not in env

    def test_machine_id_absent_when_file_empty(self, monkeypatch):
        import builtins
        import io

        real_open = builtins.open

        def mock_open(path, *args, **kwargs):
            if path == self._DEVICE_ID:
                return io.StringIO("   ")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", mock_open)
        env = sac_hook._snyk_env()
        assert "INTERNAL_SNYK_CLIENT_MACHINE_ID" not in env


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
