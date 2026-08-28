#!/usr/bin/env python3
"""
Studio Hook: Enforce the Malicious Code Defense registry on installs
=====================================================================

Blocks package-install commands unless the effective registry/index is the
Snyk Malicious Code Defense registry proxy, which screens npm and PyPI
packages for malicious code before serving them.

FEATURE AVAILABILITY
--------------------
Snyk Malicious Code Defense is in Experimental Preview. It requires a
feature flag enabled for your tenant by Snyk — contact your Snyk account
team to request access. Without it, the tenant registry URL this hook
enforces will not be available, and installs will be blocked.

HOW IT WORKS
------------
Stateless: no scan and no state file — a configuration check at intercept
time. One script serves two assistants, detected from the payload shape:

- Claude Code  PreToolUse (matcher: Bash)
    stdin:  {"hook_event_name":"PreToolUse","tool_name":"Bash",
             "tool_input":{"command":"..."},"cwd":"..."}
    deny:   {"hookSpecificOutput":{"hookEventName":"PreToolUse",
             "permissionDecision":"deny","permissionDecisionReason":"..."}}
- Cursor  beforeShellExecution
    stdin:  {"hook_event_name":"beforeShellExecution","command":"...", ...}
    deny:   {"permission":"deny","user_message":"...","agent_message":"..."}
            + exit code 2

Resolution order per ecosystem (first hit wins):
- npm family:  --registry flag on the command > `npm config list` run in the
               command's cwd (honors project/user .npmrc)
- PyPI family: --index-url/-i flag > PIP_INDEX_URL / UV_DEFAULT_INDEX /
               UV_INDEX_URL environment variables > `pip config get
               global.index-url`

Denial messages are agent-actionable and branch by failure mode:
- a command flag overriding compliant configuration -> remove the flag
- project configuration overriding compliant user configuration -> fix the
  project file (no credential changes needed; auth is host-scoped in the
  user configuration)
- no Malicious Code Defense configuration anywhere -> stop and hand off to
  the user, since setup requires a tenant URL and an auth token the agent
  cannot obtain

Fail-closed: if the effective registry cannot be determined for an install
command, the command is blocked.

CONFIGURATION (environment variables, all optional):
- MCD_REGISTRY_PATTERN  regex the registry URL must match
                        (default: the tenant registry path shape)
- MCD_REGISTRY_URL      exact expected URL, used in remediation messages
- MCD_HOOK_DEBUG        "1" for stderr debug logging

COMPATIBILITY: Python 3.8+; npm, pnpm, yarn (classic), bun, pip, uv.
"""

import json
import os
import re
import subprocess
import sys

# \*+ because npm 11 redacts UUID-shaped path segments in `npm config list`
MCD_PATTERN = re.compile(
    os.environ.get(
        "MCD_REGISTRY_PATTERN",
        r"/tenants/([0-9a-fA-F-]{36}|\*+)/registry/(npm|pypi)",
    )
)
DEBUG = os.environ.get("MCD_HOOK_DEBUG", "0") == "1"

NPM_INSTALL = re.compile(
    r"\b(?:npm|pnpm|bun)\s+(?:install|i|ci|add)\b|\byarn\s+(?:install|add)\b"
)
PIP_INSTALL = re.compile(
    r"\bpip3?\s+install\b|\bpython3?\s+-m\s+pip\s+install\b"
    r"|\buv\s+(?:pip\s+install|add|sync)\b"
)
REGISTRY_FLAG = re.compile(r"--registry[= ](\S+)")
INDEX_FLAG = re.compile(r"(?:--index-url|(?<=\s)-i)[= ](\S+)")
PIP_ENV_VARS = ("PIP_INDEX_URL", "UV_DEFAULT_INDEX", "UV_INDEX_URL")


def debug(msg):
    if DEBUG:
        print(f"[mcd-hook] {msg}", file=sys.stderr)


def run(cmd, cwd):
    try:
        out = subprocess.run(
            cmd, cwd=cwd or None, capture_output=True, text=True, timeout=10
        )
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def ok(url):
    return bool(url and MCD_PATTERN.search(url))


def npm_config_registries(cwd):
    """Return (effective, overridden_user_value) from `npm config list`.

    `npm config get registry` is a protected option in npm 11, so parse the
    list output: the effective value is the uncommented `registry = ` line;
    when a project .npmrc shadows the user config, npm also prints the
    shadowed value as `; registry = "..." ; overridden by project`.

    npm's resolution stands in for pnpm, yarn classic, and bun as well, since
    all of them read .npmrc. yarn berry (.yarnrc.yml) and bunfig.toml
    overrides are not resolved — see Limitations in the README.
    """
    effective, overridden = "", ""
    for line in run(["npm", "config", "list"], cwd).splitlines():
        m = re.match(r'^registry = "(.+)"', line)
        if m:
            effective = m.group(1)
        m = re.match(r'^; registry = "(.+)" ; overridden by', line)
        if m:
            overridden = m.group(1)
    return effective, overridden


def handoff():
    expected = os.environ.get("MCD_REGISTRY_URL")
    where = f" The expected registry is {expected}." if expected else ""
    return (
        "No Malicious Code Defense configuration was found on this machine."
        + where
        + " Do NOT attempt to configure the registry yourself: it requires a "
        "tenant-specific URL and an auth token that you cannot obtain. STOP "
        "and ask the user to run their Snyk Malicious Code Defense setup "
        "(Snyk authentication plus registry configuration), then retry the "
        "install. Note that Malicious Code Defense is in Experimental "
        "Preview and requires a feature flag enabled for the tenant by Snyk."
    )


def blocked(ecosystem, registry, hint):
    found = f"'{registry}'" if registry else "not determinable (failing closed)"
    return (
        f"INSTALL BLOCKED: packages must be installed through the Snyk "
        f"Malicious Code Defense registry proxy, which screens for malicious "
        f"packages before serving them. Effective {ecosystem} registry is "
        f"{found}. {hint}"
    )


def check_npm(command, cwd):
    flag = REGISTRY_FLAG.search(command)
    effective, overridden = npm_config_registries(cwd)
    registry = flag.group(1) if flag else effective
    debug(f"npm registry={registry!r} effective={effective!r} overridden={overridden!r}")
    if ok(registry):
        return None
    if flag and ok(effective):
        hint = (
            "The npm configuration for this project already points at the MCD "
            "proxy; remove the --registry override from the command and retry."
        )
    elif ok(overridden):
        project = os.path.join(cwd, ".npmrc") if cwd else "the project .npmrc"
        hint = (
            f"The user-level npm configuration already points at the MCD "
            f"proxy, but a project-level .npmrc ({project} or one above it) "
            f"overrides it with '{effective}'. Fix or remove the registry "
            f"line in that file, then retry the install. Do not touch auth: "
            f"the token is host-scoped in the user config and will apply "
            f"automatically once the registry line is corrected."
        )
    else:
        hint = handoff()
    return blocked("npm", registry, hint)


def check_pip(command, cwd):
    flag = INDEX_FLAG.search(command)
    env_var = next((v for v in PIP_ENV_VARS if os.environ.get(v)), None)
    env_url = os.environ.get(env_var, "") if env_var else ""
    cfg = run(
        [sys.executable, "-m", "pip", "config", "get", "global.index-url"], cwd
    ) or run(["pip", "config", "get", "global.index-url"], cwd)
    registry = flag.group(1) if flag else (env_url or cfg)
    debug(f"pip registry={registry!r} env={env_var}={env_url!r} cfg={cfg!r}")
    if ok(registry):
        return None
    if flag and ok(env_url or cfg):
        hint = (
            "The pip index is already MCD-configured; remove the "
            "--index-url/-i override from the command and retry."
        )
    elif env_url and ok(cfg):
        hint = (
            f"The pip configuration already points at the MCD proxy, but the "
            f"{env_var} environment variable overrides it with '{env_url}'. "
            f"Unset {env_var} (or run the install with it unset), then retry."
        )
    else:
        hint = handoff()
    return blocked("pypi", registry, hint)


def check(command, cwd):
    """Return None to allow, or a denial reason string to block."""
    if NPM_INSTALL.search(command):
        return check_npm(command, cwd)
    if PIP_INSTALL.search(command):
        return check_pip(command, cwd)
    return None


def main():
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)  # unparseable input: not an install we can vet, stay quiet

    is_claude = "tool_input" in data
    if is_claude:
        if data.get("tool_name") != "Bash":
            sys.exit(0)
        command = data.get("tool_input", {}).get("command", "")
    else:
        command = data.get("command", "")
    cwd = data.get("cwd", "") or data.get("workspace_roots", [""])[0]

    reason = check(command, cwd)
    if reason is None:
        sys.exit(0)

    if is_claude:
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }))
        sys.exit(0)

    print(json.dumps({
        "permission": "deny",
        "user_message": "Install blocked: registry is not the Snyk Malicious "
                        "Code Defense proxy. See the agent message for the fix.",
        "agent_message": reason,
    }))
    sys.exit(2)


if __name__ == "__main__":
    main()
