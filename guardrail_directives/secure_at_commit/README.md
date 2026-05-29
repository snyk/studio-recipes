# Secure At Commit (SAC)

Block git commits when newly introduced code or dependency vulnerabilities show
up in the files staged for commit. SAC is the **complement** of Secure At
Inception (SAI):

| | SAI | SAC |
| --- | --- | --- |
| When does it run? | Each agent edit / before the agent stops | At `git commit` time |
| What does it watch? | Lines the agent just edited | Files staged for commit |
| What blocks the operation? | Agent's `Stop` event | `git commit` (non-zero exit) |
| Installation surface | Per-ADE agent hooks | One in-repo script + one pre-commit shim per workspace |

SAI and SAC are not designed to run together — the installer treats them as
mutually exclusive. SAC is opted into via `--profile=experimental`.

## What gets scanned

On commit, SAC:

1. Asks git which files are staged (`git diff --cached --name-only`).
2. If any of them are code files, runs a Snyk Code (SAST) scan on the workspace
   and filters results to the staged files.
3. If any of them are dependency manifests (package.json, pom.xml, go.mod, …),
   runs a Snyk Open Source (SCA) scan on the workspace and filters results by
   severity threshold.
4. Prints a vulnerability report on stderr and exits non-zero — git aborts the
   commit. The user can bypass with `git commit --no-verify`.

If staging contains no code or manifest files (e.g. a docs-only commit), the
hook returns success immediately without invoking Snyk.

## Installation

The hook script is **installed inside the workspace** at
`.snyk/studio/components/scripts/snyk_secure_at_commit.py`. Hook-manager
configs that get committed (`.pre-commit-config.yaml`, `.husky/pre-commit`)
reference the script via that workspace-relative path, so cloning the repo
on a new machine — or running `pre-commit install` there — Just Works
without depending on any per-user install location.

The installer wires the script into whichever pre-commit machinery the
workspace already has, in this order:

- If `.pre-commit-config.yaml` exists → append a `local` repo entry.
- Else if `.husky/pre-commit` exists → append a single shim line.
- Else → write `.git/hooks/pre-commit`.

Each wire-up is wrapped in `# >>> snyk-secure-at-commit >>>` /
`# <<< snyk-secure-at-commit <<<` markers so the installer can later remove
the entry idempotently on uninstall. The shim command is a workspace-relative
path (`uv run .snyk/studio/components/scripts/snyk_secure_at_commit.py`) so
it stays portable when the file is committed.

The `.snyk/studio/components/scripts/` tree should be committed alongside
your `.pre-commit-config.yaml` / `.husky/pre-commit` so collaborators get
the same pre-commit behavior on `git pull`.

## Uninstall

`snyk-studio-install --uninstall` removes the pre-commit shim from the
workspace's hook config and deletes the installed script.

## Configuration

Environment variables read by the hook script at commit time:

- `SAC_MIN_BLOCK_SEVERITY` — minimum SCA severity that blocks commit (default `medium`).
- `SAC_HOOK_DEBUG=1` — verbose log lines on stderr.

The hook runs the Snyk CLI synchronously and waits for it to finish — no
timeout. Interrupt with Ctrl-C if a scan is taking too long.

## Layout

```
secure_at_commit/
  snyk_secure_at_commit.py   # entry point (git pre-commit hook); self-contained
  README.md
```

The hook is a single self-contained script: it shells out to `snyk code test`
and `snyk test`, parses their JSON output, filters the results against the
staged file set, and prints a markdown report on findings.
