"""Unit tests for installer/lib/transform.py."""

import os

import pytest
from transform import main, mdc_to_md, skill_to_command, strip_frontmatter


class TestStripFrontmatter:
    def test_removes_yaml_block(self):
        content = "---\ntitle: Test\ndescription: foo\n---\nBody content here."
        assert strip_frontmatter(content) == "Body content here."

    def test_noop_without_frontmatter(self):
        content = "Just regular content\nwith multiple lines."
        assert strip_frontmatter(content) == content

    def test_only_removes_first_block(self):
        content = "---\ntitle: First\n---\nMiddle\n---\ntitle: Second\n---\nEnd"
        result = strip_frontmatter(content)
        assert result.startswith("Middle")
        assert "---" in result  # second block remains


class TestMdcToMd:
    def test_creates_output_with_frontmatter_stripped(self, tmp_path):
        src = tmp_path / "input.mdc"
        src.write_text("---\ntitle: Rule\n---\n# Rule Body\nContent here.")
        dest = str(tmp_path / "output" / "rule.md")
        mdc_to_md(str(src), dest)
        assert os.path.isfile(dest)
        result = open(dest).read()
        assert result == "# Rule Body\nContent here."
        assert "---" not in result


class TestSkillToCommand:
    def test_creates_output_with_frontmatter_stripped(self, tmp_path):
        src = tmp_path / "SKILL.md"
        src.write_text("---\nname: skill\n---\n# Skill Instructions\nDo stuff.")
        dest = str(tmp_path / "out" / "command.md")
        skill_to_command(str(src), dest)
        assert os.path.isfile(dest)
        result = open(dest).read()
        assert result == "# Skill Instructions\nDo stuff."


class TestTransformMain:
    def test_dispatches_correctly(self, monkeypatch, tmp_path):
        src = tmp_path / "input.md"
        src.write_text("---\nfoo: bar\n---\nBody")
        dest = str(tmp_path / "output.md")
        monkeypatch.setattr("sys.argv", ["transform.py", "mdc_to_md", str(src), dest])
        main()
        assert open(dest).read() == "Body"

    def test_exits_unknown_transform(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "sys.argv",
            ["transform.py", "bogus", str(tmp_path / "s"), str(tmp_path / "d")],
        )
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    def test_exits_wrong_argc(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["transform.py"])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
