"""Compiler-style diagnostic output formatting for snyk_secure_at_commit.py.

`_fmt_sast_line` follows the MSVC diagnostic shape `file(line,col):` so VS
Code's Problems panel and most editor lint integrations recognise each
finding as a clickable diagnostic. `_fmt_sca_line` adapts the same skeleton
for dependency vulns (no line/column - the manifest + package@version
stands in for the location). `_print_block_reason` emits one line per
finding (no markdown header) plus a single trailing bypass hint.
"""

from tests.sac.conftest import sac_hook


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
