"""Resolve and persist the Snyk CLI selected by the installer.

The installer records npm-managed and user-specified CLI selections in sidecar
files so installed hooks can use the same binary later. PATH-managed selections
intentionally clear the sidecar and remain dynamic: future runs should use the
current ``snyk`` found on PATH.
"""

import contextlib
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, NamedTuple, Optional

SNYK_CLI_SOURCE_NPM = "npm"
SNYK_CLI_SOURCE_PATH = "path"
SNYK_CLI_SOURCE_USER_SPECIFIED = "user-specified"
_SNYK_CLI_SOURCES = frozenset(
    {SNYK_CLI_SOURCE_NPM, SNYK_CLI_SOURCE_PATH, SNYK_CLI_SOURCE_USER_SPECIFIED}
)

_IS_WINDOWS = sys.platform == "win32"
_SNYK_BINARY_NAMES_WINDOWS = ("snyk.cmd", "snyk.exe", "snyk")
_SNYK_BINARY_NAMES_POSIX = ("snyk",)


class SnykCliSelection(NamedTuple):
    """A resolved Snyk CLI plus the installer contract for managing it."""

    path: str
    version: Optional[str]
    source: str


def absolute_cli_path(cli_path: str) -> str:
    return os.path.abspath(os.path.expanduser(cli_path))


def version_from_output(output: str | None) -> str | None:
    if not output:
        return None
    m = re.search(r"(\d+\.\d[\d.]*)", output.strip())
    if m:
        return m.group(1)
    return None


def cli_path_sidecar() -> Path:
    return Path.home() / ".snyk-studio" / "cli-path"


def cli_source_sidecar() -> Path:
    return Path.home() / ".snyk-studio" / "cli-source"


def _no_win_npm_executable(_name: str) -> Optional[str]:
    return None


@dataclass(frozen=True)
class SnykCliResolver:
    runner: Callable[..., Any] = subprocess.run
    is_windows: bool = _IS_WINDOWS
    creationflags: int = 0
    find_win_npm_executable: Callable[[str], Optional[str]] = _no_win_npm_executable
    cli_path_sidecar: Callable[[], Path] = cli_path_sidecar
    cli_source_sidecar: Callable[[], Path] = cli_source_sidecar

    def npm_global_prefix(self) -> Optional[Path]:
        try:
            result = self.runner(
                ["npm", "prefix", "-g"],
                capture_output=True,
                text=True,
                timeout=10,
                shell=self.is_windows,
                creationflags=self.creationflags,
            )
        except Exception:
            return None
        stdout = getattr(result, "stdout", None)
        prefix = stdout.strip() if isinstance(stdout, str) else ""
        return Path(prefix) if prefix else None

    def npm_global_prefix_writable(self) -> bool:
        """Return True if the current user can write to npm's global install prefix.

        Errs on the side of "writable" when the prefix can't be determined, so a
        transient ``npm`` hiccup never triggers an unnecessary nvm install.
        """
        prefix = self.npm_global_prefix()
        if prefix is None:
            return True
        # npm creates lib/node_modules and bin under the prefix on demand, so
        # test write access at the nearest existing ancestor of the prefix.
        while not prefix.exists() and prefix != prefix.parent:
            prefix = prefix.parent
        return os.access(prefix, os.W_OK)

    def snyk_cli_from_path(self) -> Optional[str]:
        return shutil.which("snyk") or self.find_win_npm_executable("snyk")

    def sync_cli_sidecars(self, cli_path: Optional[str], source: Optional[str]) -> None:
        sidecar = self.cli_path_sidecar()
        source_sidecar = self.cli_source_sidecar()
        if source == SNYK_CLI_SOURCE_PATH:
            cli_path = None
            source = None
        if cli_path:
            if source not in _SNYK_CLI_SOURCES:
                raise ValueError("valid source is required when writing Snyk CLI sidecars")
            # Owner-only: these files decide what binary hooks execute, so a
            # local user other than the owner must not be able to repoint them.
            sidecar.parent.mkdir(parents=True, exist_ok=True)
            sidecar.write_text(cli_path, encoding="utf-8")
            sidecar.chmod(0o600)
            source_sidecar.parent.mkdir(parents=True, exist_ok=True)
            source_sidecar.write_text(source, encoding="utf-8")
            source_sidecar.chmod(0o600)
        else:
            for path in (sidecar, source_sidecar):
                with contextlib.suppress(FileNotFoundError):
                    path.unlink()

    def read_cli_path_sidecar(self) -> Optional[str]:
        try:
            raw = self.cli_path_sidecar().read_text(encoding="utf-8-sig").strip()
        except (OSError, UnicodeDecodeError):
            return None
        if not raw:
            return None
        expanded = os.path.expanduser(raw)
        if not os.path.isabs(expanded):
            return None
        cli_path = os.path.abspath(expanded)
        if os.path.isfile(cli_path) and os.access(cli_path, os.X_OK):
            return cli_path
        return None

    def read_cli_source_sidecar(self) -> Optional[str]:
        try:
            raw = self.cli_source_sidecar().read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError):
            return None
        if raw in _SNYK_CLI_SOURCES:
            return raw
        return None

    def current_npm_global_bin_dirs(self) -> list[str]:
        prefix = self.npm_global_prefix()
        if prefix is None:
            return []
        if self.is_windows:
            return [absolute_cli_path(str(prefix))]
        return [absolute_cli_path(str(prefix / "bin"))]

    def sidecar_cli_source(self) -> str:
        """Return how the sidecar-pinned CLI should be managed.

        ``npm`` means a previous installer selected npm management. ``path``
        sidecars are ignored by selection callers: they mean the installer
        should defer back to the user's current PATH. Missing source metadata
        means a legacy ``--cli-path`` install, which is user-specified.
        """
        return self.read_cli_source_sidecar() or SNYK_CLI_SOURCE_USER_SPECIFIED

    def npm_global_snyk_cli(self) -> Optional[str]:
        """Return the Snyk executable path npm would update globally, if present."""
        bin_dirs = self.current_npm_global_bin_dirs()
        if not bin_dirs:
            return None
        binary_names = _SNYK_BINARY_NAMES_WINDOWS if self.is_windows else _SNYK_BINARY_NAMES_POSIX
        for bin_dir in bin_dirs:
            for name in binary_names:
                candidate = Path(bin_dir) / name
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    return str(candidate)
        return None

    def read_snyk_version(self, cli_path: str) -> Optional[str]:
        try:
            result = self.runner(
                [cli_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                shell=self.is_windows,
                creationflags=self.creationflags,
            )
        except Exception:
            return None
        stdout = getattr(result, "stdout", None)
        if not isinstance(stdout, str):
            return None
        lines = stdout.strip().splitlines()
        return lines[0] if lines else None

    def selected_snyk_cli(
        self,
        cli_path: str,
        source: str,
        require_version: bool = False,
    ) -> Optional[SnykCliSelection]:
        version = self.read_snyk_version(cli_path)
        if require_version and not version:
            return None
        return SnykCliSelection(absolute_cli_path(cli_path), version, source)

    def selected_snyk_cli_from_path(
        self, require_version: bool = False
    ) -> Optional[SnykCliSelection]:
        snyk_path = self.snyk_cli_from_path()
        if not snyk_path:
            return None
        return self.selected_snyk_cli(
            snyk_path,
            SNYK_CLI_SOURCE_PATH,
            require_version=require_version,
        )

    def selected_snyk_cli_from_sidecar(
        self, require_version: bool = False
    ) -> Optional[SnykCliSelection]:
        sidecar_path = self.read_cli_path_sidecar()
        if not sidecar_path:
            return None
        source = self.sidecar_cli_source()
        if source == SNYK_CLI_SOURCE_PATH:
            return None
        return self.selected_snyk_cli(
            sidecar_path,
            source,
            require_version=require_version,
        )

    def selected_snyk_cli_from_npm_global(
        self, require_version: bool = False
    ) -> Optional[SnykCliSelection]:
        snyk_path = self.npm_global_snyk_cli()
        if not snyk_path:
            return None
        return self.selected_snyk_cli(
            snyk_path,
            SNYK_CLI_SOURCE_NPM,
            require_version=require_version,
        )

    def command_version(self, cmd: list[str] | str, timeout: int = 5, **kwargs: Any) -> str | None:
        try:
            result = self.runner(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                **kwargs,
            )
        except Exception:
            return None
        return version_from_output(getattr(result, "stdout", None))

    def collect_sidecar_info(self) -> dict[str, Any]:
        sidecar_path = self.cli_path_sidecar()
        source_sidecar = self.cli_source_sidecar()
        source = self.read_cli_source_sidecar()
        info: dict[str, Any] = {
            "path_file": str(sidecar_path),
            "source_file": str(source_sidecar),
            "raw_path": None,
            "path": None,
            "source": source,
            "version": None,
            "valid": False,
            "error": None,
        }

        try:
            raw_path = sidecar_path.read_text(encoding="utf-8-sig").strip()
        except FileNotFoundError:
            info["error"] = "missing"
            return info
        except (OSError, UnicodeDecodeError):
            info["error"] = "unreadable"
            return info

        if not raw_path:
            info["error"] = "empty"
            return info

        info["raw_path"] = raw_path
        expanded_path = os.path.expanduser(raw_path)
        cli_path = os.path.abspath(expanded_path)
        info["path"] = cli_path

        if not os.path.isabs(expanded_path):
            info["error"] = "relative_path"
            return info
        if not os.path.isfile(cli_path):
            info["error"] = "missing_executable"
            return info
        if not os.access(cli_path, os.X_OK):
            info["error"] = "not_executable"
            return info

        info["valid"] = True
        info["source"] = self.sidecar_cli_source()
        info["version"] = self.read_snyk_version(cli_path)
        return info

    def collect_cli_info(self) -> dict[str, Any]:
        path_cli = self.snyk_cli_from_path()
        path_version = self.read_snyk_version(path_cli) if path_cli else None
        sidecar = self.collect_sidecar_info()

        if sidecar["valid"] and sidecar["source"] != SNYK_CLI_SOURCE_PATH:
            used_path = sidecar["path"]
            used_version = sidecar["version"]
            used_source = sidecar["source"]
        else:
            used_path = path_cli
            used_version = path_version
            used_source = SNYK_CLI_SOURCE_PATH if path_cli else None

        return {
            "used": {
                "path": used_path,
                "source": used_source,
                "version": used_version,
            },
            "from_user_path": {
                "path": path_cli,
                "version": path_version,
            },
            "sidecar": sidecar,
        }
