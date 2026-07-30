from pathlib import Path
from typing import ClassVar, Optional, Tuple

from .git_native import resolve_core_hooks_path
from .marked_files import (
    _install_marked_file,
    _self_propagating_block,
    _uninstall_marked_file,
    _verify_marked_file,
)
from .types import HookIntegrationKind, HookSpec, HookStrategy, MarkedFilePolicy, normalize_path

HUSKY_HOOK_PATH = Path(".husky") / "pre-commit"
HUSKY_HOOKS_PATHS = (Path(".husky"), Path(".husky") / "_")

_HUSKY_MARKED_FILE_POLICY = MarkedFilePolicy(
    label=".husky/pre-commit",
    missing_error=".husky/pre-commit not found",
    require_existing=True,
    chmod_after_write=True,
)


def _husky_path(workspace: Path) -> Path:
    return workspace / HUSKY_HOOK_PATH


def _core_hooks_path_is_husky(workspace: Path) -> bool:
    hooks_path = resolve_core_hooks_path(workspace)
    if hooks_path is None:
        return False
    resolved_hooks_path = normalize_path(hooks_path)
    husky_hooks_paths = {normalize_path(workspace / path) for path in HUSKY_HOOKS_PATHS}
    return resolved_hooks_path in husky_hooks_paths


def install_husky(workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
    """Appends `spec.command` as its own marked block; can't rely on
    script-wide `set -e` since another recipe's block may follow ours."""
    return _install_marked_file(
        _husky_path(workspace),
        spec,
        _self_propagating_block(spec.command),
        _HUSKY_MARKED_FILE_POLICY,
    )


def uninstall_husky(workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
    return _uninstall_marked_file(_husky_path(workspace), spec, _HUSKY_MARKED_FILE_POLICY)


def verify_husky(workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
    return _verify_marked_file(_husky_path(workspace), spec, _HUSKY_MARKED_FILE_POLICY)


class HuskyStrategy(HookStrategy):
    name = "husky"
    integration_kind: ClassVar[HookIntegrationKind] = "husky"

    def check_prerequisite(self, workspace: Path) -> bool:
        return _husky_path(workspace).is_file() and _core_hooks_path_is_husky(workspace)

    def install(self, workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
        return install_husky(workspace, spec)

    def is_installed(self, workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
        return verify_husky(workspace, spec)

    def safe_uninstall(self, workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
        return uninstall_husky(workspace, spec)

    def file_hook_path(self, workspace: Path) -> Optional[Path]:
        return _husky_path(workspace)
