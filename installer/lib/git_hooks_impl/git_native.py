import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import ClassVar, List, Optional, Tuple

from .marked_files import (
    _install_marked_file,
    _self_propagating_block,
    _uninstall_marked_file,
    _verify_marked_file,
)
from .types import HookIntegrationKind, HookSpec, HookStrategy, MarkedFilePolicy

_IS_WINDOWS = sys.platform == "win32"
_CREATE_NO_WINDOW = 0
if sys.platform == "win32":
    _CREATE_NO_WINDOW = subprocess.CREATE_NO_WINDOW


def _resolve_common_dir(git_dir: Path) -> Path:
    """Resolve a linked worktree's private gitdir to the common gitdir its
    ``commondir`` file points to.

    Git never runs hooks per-worktree - they always live in the *common*
    gitdir shared by every worktree - so using a worktree's own private
    gitdir (``.git/worktrees/<name>``) here would silently install a hook
    git never executes. Returns *git_dir* unchanged when there's no
    ``commondir`` file: a plain repo, or a submodule's own standalone
    gitdir (which really does own its hooks directory).
    """
    try:
        commondir = (git_dir / "commondir").read_text(encoding="utf-8").rstrip("\r\n")
    except OSError:
        return git_dir
    if not commondir:
        return git_dir
    common_dir = Path(commondir)
    if not common_dir.is_absolute():
        common_dir = git_dir / common_dir
    try:
        return common_dir.resolve(strict=False)
    except OSError:
        return common_dir.absolute()


def _git_hook_default_path(workspace: Path) -> Optional[Path]:
    """Return ``hooks/pre-commit`` under the common gitdir, ignoring
    ``core.hooksPath``.

    Handles ``.git``-as-a-file repos (worktrees/submodules) via the
    ``gitdir:`` pointer.
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
            git_dir = _resolve_common_dir(git_dir)
            return git_dir / "hooks" / "pre-commit"
    return None


_GIT_HOOK_HEADER = "#!/usr/bin/env sh\nset -e\n"

_GIT_NATIVE_SHIM_POLICY = MarkedFilePolicy(
    label="git pre-commit hook",
    missing_error="not a git repository (.git not found)",
    seed_when_empty=_GIT_HOOK_HEADER,
    create_parent=True,
    chmod_after_write=True,
    chmod_on_noop=True,
    report_path_when_missing=True,
    delete_when_cleaned_is=("", _GIT_HOOK_HEADER.strip()),
)


def _resolve_git() -> Tuple[str, bool]:
    """Returns (git command, needs_shell). On Windows, "git" can resolve
    to a non-.exe wrapper that CreateProcess can't launch directly --
    shell=True routes it through cmd.exe instead."""
    if not _IS_WINDOWS:
        return "git", False
    resolved = shutil.which("git")
    if resolved and not resolved.lower().endswith(".exe"):
        return resolved, True
    return "git", False


def _run_git_safe(
    workspace: Path, args: List[str], timeout: float = 5.0
) -> Optional["subprocess.CompletedProcess[str]"]:
    """Run ``git -C workspace <args>``, returning the result on success."""
    git_bin, needs_shell = _resolve_git()
    try:
        result = subprocess.run(
            [git_bin, "-C", str(workspace), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=needs_shell,
            creationflags=_CREATE_NO_WINDOW,
        )
    except Exception:
        return None
    if result.returncode != 0:
        return None
    return result


def _run_git_throws(
    workspace: Path, args: List[str], timeout: float = 5.0
) -> "subprocess.CompletedProcess[str]":
    """Like ``_run_git_safe``, but propagates subprocess/OS failures."""
    git_bin, needs_shell = _resolve_git()
    return subprocess.run(
        [git_bin, "-C", str(workspace), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=True,
        shell=needs_shell,
        creationflags=_CREATE_NO_WINDOW,
    )


_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def _git_version(workspace: Path) -> Optional[Tuple[int, int, int]]:
    """Return the installed git version as ``(major, minor, patch)``."""
    result = _run_git_safe(workspace, ["--version"])
    if result is None:
        return None
    match = _VERSION_RE.search(result.stdout)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def resolve_core_hooks_path(workspace: Path) -> Optional[Path]:
    """Return the effective ``core.hooksPath``, or ``None`` if unset."""
    result = _run_git_safe(workspace, ["config", "--get", "core.hooksPath"])
    value = result.stdout.strip() if result is not None else ""
    if not value:
        return None
    path = Path(value)
    if path.is_absolute():
        return path
    return (workspace / path).resolve()


class GitNativeStrategy(HookStrategy):
    """Interface for a single git-native hook install mechanism."""

    name = "base"
    integration_kind: ClassVar[HookIntegrationKind] = "git-native"
    fallback_eligible = True


_CONFIG_SAFE_PASSTHROUGH_RE = re.compile(r"[A-Za-z0-9-]")


class ConfigBasedHookStrategy(GitNativeStrategy):
    """Git >= 2.54 declarative ``hook.<tag>.event``/``hook.<tag>.command`` config."""

    name = "git-native-config"

    def check_prerequisite(self, workspace: Path) -> bool:
        version = _git_version(workspace)
        return version is not None and version >= (2, 54, 0)

    @staticmethod
    def _config_safe_tag(tag: str) -> str:
        """Return *tag* as a safe, collision-free git config subsection name."""
        chars = []
        for ch in tag:
            if _CONFIG_SAFE_PASSTHROUGH_RE.match(ch):
                chars.append(ch)
            else:
                chars.extend(f"_{byte:02x}" for byte in ch.encode("utf-8"))
        safe = "".join(chars)
        if not safe or not safe[0].isalnum():
            safe = f"h{safe}"
        return safe

    @classmethod
    def _section(cls, spec: HookSpec) -> str:
        return f"hook.{cls._config_safe_tag(spec.tag)}"

    def is_installed(self, workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
        section = self._section(spec)
        path = f"{section} (git config)"
        events_result = _run_git_safe(workspace, ["config", "--get-all", f"{section}.event"])
        command_result = _run_git_safe(workspace, ["config", "--get", f"{section}.command"])
        events = events_result.stdout if events_result is not None else ""
        command = command_result.stdout.strip() if command_result is not None else None
        ok = bool(events) and "pre-commit" in events.splitlines() and command == spec.command
        return ok, path

    def install(self, workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
        """Returns (changed, path): changed=True if this call wrote new config."""
        section = self._section(spec)
        path = f"{section} (git config)"
        already_ok, _ = self.is_installed(workspace, spec)
        if already_ok:
            return False, path
        try:
            _run_git_throws(
                workspace, ["config", "--local", "--replace-all", f"{section}.event", "pre-commit"]
            )
            _run_git_throws(workspace, ["config", "--local", f"{section}.command", spec.command])
        except (OSError, subprocess.SubprocessError):
            _run_git_safe(workspace, ["config", "--local", "--remove-section", section])
            raise
        return True, path

    def safe_uninstall(self, workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
        section = self._section(spec)
        path = f"{section} (git config)"
        result = _run_git_safe(workspace, ["config", "--local", "--remove-section", section])
        return result is not None, path


def _is_shim_installed_at(hook_path: Optional[Path], spec: HookSpec) -> Tuple[bool, str]:
    return _verify_marked_file(hook_path, spec, _GIT_NATIVE_SHIM_POLICY)


def _install_shim_at(hook_path: Optional[Path], spec: HookSpec) -> Tuple[bool, str]:
    """`set -e` is only seeded for a freshly-created hook file, not a
    pre-existing one -- same masking risk as install_husky() otherwise."""
    return _install_marked_file(
        hook_path,
        spec,
        _self_propagating_block(spec.command),
        _GIT_NATIVE_SHIM_POLICY,
    )


def _uninstall_shim_at(hook_path: Optional[Path], spec: HookSpec) -> Tuple[bool, str]:
    return _uninstall_marked_file(hook_path, spec, _GIT_NATIVE_SHIM_POLICY)


class FileShimStrategy(GitNativeStrategy):
    """File-based shim written to ``core.hooksPath`` if set, else the
    repo's own ``<gitdir>/hooks/pre-commit``.

    Always eligible: whichever location applies, it's the only correct
    place for a file-based hook to live, so there's no other file-based
    strategy left to fall back to if writing here fails.
    """

    name = "git-native-file-shim"

    def check_prerequisite(self, workspace: Path) -> bool:
        return True

    def _hook_path(self, workspace: Path) -> Optional[Path]:
        override = resolve_core_hooks_path(workspace)
        if override is not None:
            return override / "pre-commit"
        return _git_hook_default_path(workspace)

    def is_installed(self, workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
        return _is_shim_installed_at(self._hook_path(workspace), spec)

    def install(self, workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
        return _install_shim_at(self._hook_path(workspace), spec)

    def safe_uninstall(self, workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
        return _uninstall_shim_at(self._hook_path(workspace), spec)

    def file_hook_path(self, workspace: Path) -> Optional[Path]:
        return self._hook_path(workspace)
