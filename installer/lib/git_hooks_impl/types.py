from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Literal, Optional, Tuple

HookIntegrationKind = Literal["pre-commit", "husky", "git-native"]


class HookIntegrationSkipped(Exception):
    """Raised when an existing hook config cannot be safely edited."""


@dataclass(frozen=True)
class HookSpec:
    """Resolved hook-integration parameters."""

    tag: str
    command: str
    name: str

    @property
    def begin_marker(self) -> str:
        return f"# >>> {self.tag} >>>"

    @property
    def end_marker(self) -> str:
        return f"# <<< {self.tag} <<<"


@dataclass(frozen=True)
class MarkedFilePolicy:
    """Hook-integration-specific behavior for marker-delimited text files."""

    label: str
    missing_error: str
    require_existing: bool = False
    seed_when_empty: str = ""
    create_parent: bool = False
    chmod_after_write: bool = False
    chmod_on_noop: bool = False
    report_path_when_missing: bool = False
    delete_when_cleaned_is: Tuple[str, ...] = ()


def normalize_path(path: Path) -> Path:
    """Resolve a path for equality checks without requiring it to exist."""
    try:
        return path.resolve(strict=False)
    except OSError:
        return path.absolute()


class HookStrategy:
    """Interface for one hook install target."""

    name: ClassVar[str] = "base"
    integration_kind: ClassVar[HookIntegrationKind]
    # True only for strategies interchangeable with each other (see GitNativeStrategy).
    fallback_eligible: ClassVar[bool] = False

    def check_prerequisite(self, workspace: Path) -> bool:
        raise NotImplementedError

    def install(self, workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
        raise NotImplementedError

    def is_installed(self, workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
        raise NotImplementedError

    def safe_uninstall(self, workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
        """Remove this strategy's install, if present. Never raises, and is
        always safe to call even if this strategy was never installed."""
        raise NotImplementedError

    def file_hook_path(self, workspace: Path) -> Optional[Path]:
        """Return the hook file this strategy manages, or None for config-only strategies."""
        return None
