"""Shared fixtures for installer tests."""

import json
import os
import sys

import pytest

# Add installer/lib and tests dir to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.insert(0, os.path.dirname(__file__))


@pytest.fixture
def write_json(tmp_path):
    """Factory fixture: write_json(filename, data) -> absolute path string."""
    def _write(filename, data):
        path = tmp_path / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2) + "\n")
        return str(path)
    return _write


@pytest.fixture
def empty_target(tmp_path):
    """Path to a non-existent file (for testing create-from-scratch)."""
    return str(tmp_path / "target.json")


# ---------------------------------------------------------------------------
# Cursor hooks fixtures
# ---------------------------------------------------------------------------

SNYK_CURSOR_HOOKS = {
    "version": 1,
    "hooks": {
        "afterFileEdit": [
            {"command": 'python3 "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'}
        ],
        "stop": [
            {"command": 'python3 "$HOME/.cursor/hooks/snyk_secure_at_inception.py"'}
        ],
    },
}


@pytest.fixture
def snyk_cursor_source(write_json):
    return write_json("source/cursor_hooks.json", SNYK_CURSOR_HOOKS)


@pytest.fixture
def existing_cursor_target(write_json):
    return write_json(
        "target/hooks.json",
        {
            "version": 1,
            "hooks": {
                "afterFileEdit": [{"command": "eslint --fix"}],
            },
        },
    )


# ---------------------------------------------------------------------------
# Claude settings fixtures
# ---------------------------------------------------------------------------

SNYK_CLAUDE_SETTINGS = {
    "hooks": {
        "PostToolUse": [
            {
                "matcher": "Edit|Write",
                "hooks": [
                    {
                        "type": "command",
                        "command": 'python3 "$HOME/.claude/hooks/snyk_secure_at_inception.py"',
                        "statusMessage": "Tracking code changes for security scan...",
                    }
                ],
            }
        ],
        "Stop": [
            {
                "hooks": [
                    {
                        "type": "command",
                        "command": 'python3 "$HOME/.claude/hooks/snyk_secure_at_inception.py"',
                        "statusMessage": "Evaluating security scan results...",
                    }
                ]
            }
        ],
    }
}


@pytest.fixture
def snyk_claude_source(write_json):
    return write_json("source/claude_settings.json", SNYK_CLAUDE_SETTINGS)


@pytest.fixture
def existing_claude_target(write_json):
    return write_json(
        "target/settings.json",
        {
            "allowedTools": ["Read", "Write"],
            "hooks": {
                "PostToolUse": [
                    {
                        "matcher": "Edit|Write",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "prettier --write",
                                "statusMessage": "Formatting...",
                            }
                        ],
                    }
                ],
            },
        },
    )


# ---------------------------------------------------------------------------
# MCP server fixtures
# ---------------------------------------------------------------------------

SNYK_MCP_CONFIG = {
    "mcpServers": {
        "Snyk": {
            "command": "npx",
            "args": ["-y", "snyk@latest", "mcp", "-t", "stdio"],
            "env": {"SNYK_MCP_PROFILE": "experimental"},
        }
    }
}

MULTI_SNYK_MCP_CONFIG = {
    "mcpServers": {
        "Snyk": {
            "command": "npx",
            "args": ["-y", "snyk@latest", "mcp", "-t", "stdio"],
            "env": {"SNYK_MCP_PROFILE": "experimental"},
        },
        "SnykCode": {
            "command": "npx",
            "args": ["-y", "snyk@latest", "code-mcp"],
            "env": {"SNYK_MCP_PROFILE": "code"},
        },
    }
}

GITHUB_MCP_CONFIG = {
    "mcpServers": {
        "GitHub": {
            "command": "gh",
            "args": ["mcp"],
        }
    }
}


@pytest.fixture
def snyk_mcp_source(write_json):
    return write_json("source/mcp.json", SNYK_MCP_CONFIG)


@pytest.fixture
def multi_snyk_mcp_source(write_json):
    return write_json("source/multi_mcp.json", MULTI_SNYK_MCP_CONFIG)


@pytest.fixture
def existing_mcp_target(write_json):
    return write_json("target/mcp.json", GITHUB_MCP_CONFIG)
