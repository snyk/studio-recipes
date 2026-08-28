#!/usr/bin/env python3
"""Self-check for the MCD registry enforcement hook.

Pipes real assistant payloads through the hook against temporary projects
with real .npmrc files and a controlled temporary $HOME, so the user-level
configuration branch is deterministic on any machine.

Run: python3 test_enforce_mcd_registry.py
"""

import json
import os
import subprocess
import sys
import tempfile

HOOK = os.path.join(
    os.path.dirname(__file__), "..", "hooks", "enforce_mcd_registry.py"
)
TENANT = "00000000-0000-4000-8000-000000000000"
MCD = f"https://api.snyk.io/hidden/tenants/{TENANT}/registry/npm/"
MCD_PYPI = MCD.replace("/npm/", "/pypi/") + "simple/"
NPMJS = "https://registry.npmjs.org/"


def run_hook(payload, env=None):
    e = os.environ.copy()
    e.update(env or {})
    p = subprocess.run(
        [sys.executable, HOOK], input=json.dumps(payload),
        capture_output=True, text=True, env=e, timeout=30,
    )
    return p.returncode, p.stdout


def claude(command, cwd):
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": command}, "cwd": cwd}


def cursor(command, cwd):
    return {"hook_event_name": "beforeShellExecution",
            "command": command, "cwd": cwd}


def npmrc_dir(registry):
    d = tempfile.mkdtemp()
    with open(os.path.join(d, ".npmrc"), "w") as f:
        f.write(f"registry={registry}\n")
    return d


def reason(out):
    return json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]


good, bad = npmrc_dir(MCD), npmrc_dir(NPMJS)
home_mcd, home_plain = npmrc_dir(MCD), tempfile.mkdtemp()

# npm install through MCD -> allow (exit 0, no deny output)
code, out = run_hook(claude("npm install left-pad", good), {"HOME": home_mcd})
assert code == 0 and "deny" not in out, (code, out)

# non-install command -> allow, even in the bad project
code, out = run_hook(claude("npm info left-pad", bad), {"HOME": home_plain})
assert code == 0 and not out.strip(), (code, out)

# --registry flag bypass in a compliant project -> deny + "remove the flag"
code, out = run_hook(claude(f"npm install evil --registry={NPMJS}", good),
                     {"HOME": home_mcd})
assert "remove the --registry override" in reason(out), out

# project .npmrc overrides a compliant user config -> deny + fix-the-project
code, out = run_hook(claude("npm install left-pad", bad), {"HOME": home_mcd})
assert "overrides it" in reason(out) and ".npmrc" in reason(out), out

# no MCD config anywhere -> deny + explicit stop-and-ask-the-user handoff
code, out = run_hook(claude("npm install left-pad", bad), {"HOME": home_plain})
assert "STOP" in reason(out) and "ask the user" in reason(out), out

# MCD_REGISTRY_URL surfaces the expected URL in the handoff message
code, out = run_hook(claude("npm install left-pad", bad),
                     {"HOME": home_plain, "MCD_REGISTRY_URL": MCD})
assert MCD in reason(out), out

# pip through MCD via env -> allow; to public PyPI with no fallback -> handoff
code, out = run_hook(claude("pip install requests", good),
                     {"PIP_INDEX_URL": MCD_PYPI, "HOME": home_plain})
assert code == 0 and "deny" not in out, (code, out)
code, out = run_hook(claude("pip install requests", good),
                     {"PIP_INDEX_URL": "https://pypi.org/simple/",
                      "HOME": home_plain})
assert "ask the user" in reason(out), out

# pip env var overriding a compliant pip.conf -> deny + "unset the var" hint
home_pip = tempfile.mkdtemp()
os.makedirs(os.path.join(home_pip, ".config", "pip"), exist_ok=True)
with open(os.path.join(home_pip, ".config", "pip", "pip.conf"), "w") as f:
    f.write(f"[global]\nindex-url = {MCD_PYPI}\n")
code, out = run_hook(claude("pip install requests", good),
                     {"PIP_INDEX_URL": "https://pypi.org/simple/",
                      "HOME": home_pip})
assert "Unset PIP_INDEX_URL" in reason(out), out

# Cursor payload -> snake_case deny contract + exit code 2
code, out = run_hook(cursor("pnpm add left-pad", bad), {"HOME": home_plain})
resp = json.loads(out)
assert code == 2 and resp["permission"] == "deny" and "STOP" in resp["agent_message"], out
code, out = run_hook(cursor("pnpm add left-pad", good), {"HOME": home_mcd})
assert code == 0, (code, out)

print("all checks passed")
