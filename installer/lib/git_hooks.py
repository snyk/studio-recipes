#!/usr/bin/env python3
"""Git pre-commit hook integration for Snyk Studio Recipes installer.

Used by the workspace-scoped `sac-hooks` recipe. Probes the workspace for an
already-configured hook manager and installs (or removes) a tagged shim entry
that invokes the SAC python script.

Probe order:
  1. ``.pre-commit-config.yaml`` (or ``.yml``) → pre-commit framework
  2. ``.husky/pre-commit``                     → Husky
  3. Otherwise                                 → git native ``.git/hooks/pre-commit``

All three strategies are idempotent: installs are no-ops if the tagged block
already matches what we would write, and uninstall removes only the block
between our `# >>> snyk-secure-at-commit >>>` markers.
"""

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

PRE_COMMIT_YAML_NAMES = (".pre-commit-config.yaml", ".pre-commit-config.yml")
HUSKY_HOOK_PATH = Path(".husky") / "pre-commit"


def detect_hook_manager(workspace: Path) -> str:
    """Return ``"pre-commit"``, ``"husky"``, or ``"git-native"`` for *workspace*."""
    for name in PRE_COMMIT_YAML_NAMES:
        if (workspace / name).is_file():
            return "pre-commit"
    if (workspace / HUSKY_HOOK_PATH).is_file():
        return "husky"
    return "git-native"


@dataclass(frozen=True)
class HookSpec:
    """Resolved hook-integration parameters."""

    tag: str
    command: str

    @property
    def begin_marker(self) -> str:
        return f"# >>> {self.tag} >>>"

    @property
    def end_marker(self) -> str:
        return f"# <<< {self.tag} <<<"


# =============================================================================
# MARKER BLOCK UTILITIES
# =============================================================================


def _wrap_block(spec: HookSpec, body: str) -> str:
    """Return *body* sandwiched between this spec's begin/end markers."""
    return f"{spec.begin_marker}\n{body.rstrip()}\n{spec.end_marker}\n"


def _strip_block(text: str, spec: HookSpec) -> str:
    """Remove well-formed marker-delimited blocks belonging to *spec* from *text*.

    The inner ``(?:(?!BEGIN).)*?`` is a "tempered" non-greedy match: it
    consumes any character that is NOT the start of another begin marker.
    The whole pattern therefore matches only a begin/end pair with NO
    intervening begin marker between them. If a file is corrupted into
    BEGIN..BEGIN..END (e.g. an orphan begin left behind by a failed manual
    edit), a plain ``.*?`` would match from the first BEGIN to the END and
    silently delete the orphan begin plus every line between it and the
    closing end — destroying user configuration. The tempered version
    refuses to match at all in that case and leaves the malformed region
    intact so the user can see and fix it.

    Tolerates trailing newlines and CRLF line endings; collapses any
    chain of three or more newlines down to two so the file stays tidy on
    repeated install/uninstall cycles.
    """
    begin = re.escape(spec.begin_marker)
    end = re.escape(spec.end_marker)
    pattern = re.compile(
        rf"(?:\r?\n)?{begin}(?:(?!{begin}).)*?{end}(?:\r?\n)?",
        re.DOTALL,
    )
    cleaned = pattern.sub("\n", text)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _chmod_executable(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        mode = path.stat().st_mode
        path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass


def _normalize_existing(text: str) -> str:
    if not text:
        return ""
    if not text.endswith("\n"):
        text += "\n"
    return text


# =============================================================================
# PRE-COMMIT FRAMEWORK (.pre-commit-config.yaml)
# =============================================================================


def _precommit_yaml_path(workspace: Path) -> Optional[Path]:
    for name in PRE_COMMIT_YAML_NAMES:
        candidate = workspace / name
        if candidate.is_file():
            return candidate
    return None


_REPOS_ITEM_RE = re.compile(r"^(?P<indent>[ \t]*)-[ \t]+repo:", re.MULTILINE)


def _detect_repos_indent(text: str) -> str:
    """Return the leading whitespace used by ``- repo:`` items in *text*.

    YAML block sequences require every item to share an indent level. A
    file written with two-space-indented items under ``repos:`` (the
    common style produced by ``pre-commit autoupdate`` and most
    templates) will refuse to load if a new item is appended at column 0
    — pre-commit raises ``InvalidConfigError`` with "did not find expected
    key" pointing at our marker, because the parser stops treating the
    new line as part of the sequence and starts looking for a sibling
    mapping key. Sniffing the indent off the file's existing items lets
    the appended SAC block line up with whichever style the user has.

    Returns the leading whitespace of the first ``- repo:`` line found,
    or ``""`` when none exists (e.g. an empty ``repos:`` list — in that
    case the canonical zero-indent form is a safe default).
    """
    match = _REPOS_ITEM_RE.search(text)
    return match.group("indent") if match else ""


def _precommit_block(spec: HookSpec, indent: str = "") -> str:
    """Return the YAML fragment to append under ``repos:``.

    The fragment is one ``local`` repo entry with a single hook whose
    ``entry`` is the SAC command line. ``indent`` is the leading
    whitespace prepended to every body line so the appended block lines
    up with the user's existing ``- repo:`` items — pass the result of
    ``_detect_repos_indent`` against the current file contents.
    """
    body = "\n".join(
        [
            f"{indent}- repo: local",
            f"{indent}  hooks:",
            f"{indent}  - id: {spec.tag}",
            f"{indent}    name: Snyk Secure At Commit",
            f"{indent}    entry: {spec.command}",
            f"{indent}    language: system",
            f"{indent}    pass_filenames: false",
            f"{indent}    always_run: true",
            f"{indent}    stages: [pre-commit]",
        ]
    )
    return _wrap_block(spec, body)


def install_precommit_framework(workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
    """Append the SAC local hook to the existing ``.pre-commit-config.yaml``.

    Returns ``(installed, path_str)``. ``installed`` is False if the block was
    already present and the file was left untouched.

    The indent of the appended ``- repo:`` block is sniffed off the file
    so it matches whichever style the user already has (canonical
    zero-indent vs the very common two-space style). The sniff runs
    against the file with any prior SAC block stripped, so a previous
    install that wrote at the wrong column doesn't poison the next one
    — the new install reads the user's actual ``- repo:`` items and
    self-corrects.
    """
    yaml_path = _precommit_yaml_path(workspace)
    if yaml_path is None:
        raise FileNotFoundError(".pre-commit-config.yaml not found")

    text = _normalize_existing(_read_text(yaml_path))
    cleaned = _strip_block(text, spec)
    indent = _detect_repos_indent(cleaned)
    block = _precommit_block(spec, indent)
    if block.strip() in text:
        return False, str(yaml_path)
    if not cleaned.endswith("\n"):
        cleaned += "\n"
    yaml_path.write_text(cleaned + block, encoding="utf-8")
    return True, str(yaml_path)


def uninstall_precommit_framework(workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
    yaml_path = _precommit_yaml_path(workspace)
    if yaml_path is None:
        return False, ""
    text = _read_text(yaml_path)
    if spec.begin_marker not in text:
        return False, str(yaml_path)
    yaml_path.write_text(_strip_block(text, spec), encoding="utf-8")
    return True, str(yaml_path)


def verify_precommit_framework(workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
    yaml_path = _precommit_yaml_path(workspace)
    if yaml_path is None:
        return False, ""
    text = _read_text(yaml_path)
    return (spec.begin_marker in text and spec.end_marker in text and spec.command in text), str(
        yaml_path
    )


# =============================================================================
# HUSKY (.husky/pre-commit)
# =============================================================================


def _husky_path(workspace: Path) -> Path:
    return workspace / HUSKY_HOOK_PATH


def _husky_block(spec: HookSpec) -> str:
    return _wrap_block(spec, spec.command)


def install_husky(workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
    path = _husky_path(workspace)
    if not path.is_file():
        raise FileNotFoundError(".husky/pre-commit not found")
    text = _normalize_existing(_read_text(path))
    block = _husky_block(spec)
    if block.strip() in text:
        return False, str(path)
    cleaned = _strip_block(text, spec)
    if not cleaned.endswith("\n"):
        cleaned += "\n"
    path.write_text(cleaned + block, encoding="utf-8")
    _chmod_executable(path)
    return True, str(path)


def uninstall_husky(workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
    path = _husky_path(workspace)
    if not path.is_file():
        return False, ""
    text = _read_text(path)
    if spec.begin_marker not in text:
        return False, str(path)
    path.write_text(_strip_block(text, spec), encoding="utf-8")
    return True, str(path)


def verify_husky(workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
    path = _husky_path(workspace)
    if not path.is_file():
        return False, ""
    text = _read_text(path)
    return (spec.begin_marker in text and spec.end_marker in text and spec.command in text), str(
        path
    )


# =============================================================================
# GIT NATIVE (.git/hooks/pre-commit)
# =============================================================================


def _git_hook_path(workspace: Path) -> Optional[Path]:
    """Return ``.git/hooks/pre-commit`` resolved against *workspace*.

    Handles repositories where ``.git`` is a file (worktrees and submodules):
    the file's ``gitdir:`` line points at the real git dir.
    """
    git = workspace / ".git"
    if git.is_dir():
        return git / "hooks" / "pre-commit"
    if git.is_file():
        try:
            line = git.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        if line.startswith("gitdir:"):
            target = line[len("gitdir:") :].strip()
            git_dir = Path(target)
            if not git_dir.is_absolute():
                git_dir = (workspace / git_dir).resolve()
            return git_dir / "hooks" / "pre-commit"
    return None


_GIT_HOOK_HEADER = "#!/usr/bin/env sh\nset -e\n"


def _git_native_block(spec: HookSpec) -> str:
    return _wrap_block(spec, spec.command)


def install_git_native(workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
    hook_path = _git_hook_path(workspace)
    if hook_path is None:
        raise FileNotFoundError("not a git repository (.git not found)")
    _ensure_parent(hook_path)
    existing = _read_text(hook_path)
    if not existing:
        existing = _GIT_HOOK_HEADER
    existing = _normalize_existing(existing)
    block = _git_native_block(spec)
    if block.strip() in existing:
        _chmod_executable(hook_path)
        return False, str(hook_path)
    cleaned = _strip_block(existing, spec)
    if not cleaned.endswith("\n"):
        cleaned += "\n"
    hook_path.write_text(cleaned + block, encoding="utf-8")
    _chmod_executable(hook_path)
    return True, str(hook_path)


def uninstall_git_native(workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
    hook_path = _git_hook_path(workspace)
    if hook_path is None or not hook_path.is_file():
        return False, ""
    text = _read_text(hook_path)
    if spec.begin_marker not in text:
        return False, str(hook_path)
    cleaned = _strip_block(text, spec)
    # If the file is now just our default header (or empty), remove it so we
    # don't leave a stray shim behind that could confuse future tools.
    if cleaned.strip() in {"", _GIT_HOOK_HEADER.strip()}:
        hook_path.unlink()
    else:
        hook_path.write_text(cleaned, encoding="utf-8")
    return True, str(hook_path)


def verify_git_native(workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
    hook_path = _git_hook_path(workspace)
    if hook_path is None or not hook_path.is_file():
        return False, ""
    text = _read_text(hook_path)
    return (spec.begin_marker in text and spec.end_marker in text and spec.command in text), str(
        hook_path
    )


# =============================================================================
# DISPATCH
# =============================================================================


_INSTALL = {
    "pre-commit": install_precommit_framework,
    "husky": install_husky,
    "git-native": install_git_native,
}

_UNINSTALL = {
    "pre-commit": uninstall_precommit_framework,
    "husky": uninstall_husky,
    "git-native": uninstall_git_native,
}

_VERIFY = {
    "pre-commit": verify_precommit_framework,
    "husky": verify_husky,
    "git-native": verify_git_native,
}


def install_hook(workspace: Path, spec: HookSpec) -> Tuple[str, bool, str]:
    """Install the SAC shim using the auto-detected hook manager.

    Returns ``(manager, installed, path)``.
    """
    manager = detect_hook_manager(workspace)
    installed, path = _INSTALL[manager](workspace, spec)
    return manager, installed, path


def uninstall_hook(workspace: Path, spec: HookSpec) -> Tuple[str, bool, str]:
    """Remove the SAC shim from every manager that has a tagged block.

    Returns the *primary* manager (per detect_hook_manager) plus whether
    anything was removed and the affected path. Other managers are scrubbed
    silently so leftover shims don't fire after uninstall.
    """
    primary = detect_hook_manager(workspace)
    removed_any = False
    primary_path = ""
    for mgr in ("pre-commit", "husky", "git-native"):
        ok, path = _UNINSTALL[mgr](workspace, spec)
        if ok:
            removed_any = True
            if mgr == primary:
                primary_path = path
    return primary, removed_any, primary_path


def verify_hook(workspace: Path, spec: HookSpec) -> Tuple[str, bool, str]:
    """Check whether the SAC shim is present under the active hook manager."""
    manager = detect_hook_manager(workspace)
    ok, path = _VERIFY[manager](workspace, spec)
    return manager, ok, path
