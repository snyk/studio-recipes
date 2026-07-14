import json
import os
import platform
import plistlib
import re
import shlex
import subprocess
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
_VERSION_RE = re.compile(r"(\d+\.\d[\d.]*)")

_SENSITIVE = frozenset({"token", "key", "secret", "credential", "password"})

_IS_WINDOWS = sys.platform == "win32"

ADE_HOMES: dict[str, Path] = {}

# macOS app bundle Info.plist paths per ADE (no subprocess needed)
_ADE_APP_BUNDLES: dict[str, str] = {
    "claude": "/Applications/Claude.app/Contents/Info.plist",
    "cursor": "/Applications/Cursor.app/Contents/Info.plist",
    "windsurf": "/Applications/Windsurf.app/Contents/Info.plist",
}

# CLI command to run `--version` for each ADE
_ADE_CLI_COMMANDS: dict[str, str] = {
    "claude": "claude",
    "cursor": "cursor",
    "gemini": "gemini",
    "codex": "codex",
    "windsurf": "windsurf",
    "kiro": "kiro",
}


def _is_sensitive(name: str) -> bool:
    name_lower = name.lower()
    return any(s in name_lower for s in _SENSITIVE)


def _filter_log_entries(path: Path, cutoff_ts: float) -> str:
    """Return only lines from path whose [timestamp] prefix is >= cutoff_ts.

    Lines that do not start with a parseable [ISO8601] prefix are always
    included (conservative: never silently drop unparseable content).
    Returns empty string on OSError.
    """
    lines = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("["):
                    bracket_end = line.find("]")
                    if bracket_end > 0:
                        try:
                            ts = datetime.fromisoformat(line[1:bracket_end]).timestamp()
                            if ts < cutoff_ts:
                                continue
                        except ValueError:
                            pass
                lines.append(line)
    except OSError:
        return ""
    return "".join(lines)


def _collect_sai_logs(zf: zipfile.ZipFile, log_root: Path, cutoff: datetime) -> None:
    cutoff_ts = cutoff.timestamp()
    try:
        ade_dirs = list(log_root.iterdir())
    except OSError:
        return
    for ade_dir in ade_dirs:
        ws_root = ade_dir / "ws"
        if not ws_root.is_dir():
            continue
        try:
            ws_dirs = list(ws_root.iterdir())
        except OSError:
            continue
        for ws_dir in ws_dirs:
            ade = re.sub(r"[^a-zA-Z0-9_\-.]", "_", Path(ade_dir.name).name)
            ws = re.sub(r"[^a-zA-Z0-9_\-.]", "_", Path(ws_dir.name).name)
            log_txt = ws_dir / "log.txt"
            log_txt1 = ws_dir / "log.txt.1"
            has_log = log_txt.exists()
            has_log1 = log_txt1.exists()

            if not has_log and not has_log1:
                continue

            # Fast pre-check: skip workspaces with no recent file activity.
            ref_file = log_txt if has_log else log_txt1
            try:
                if ref_file.stat().st_mtime < cutoff_ts:
                    continue
            except OSError:
                continue

            if has_log:
                content = _filter_log_entries(log_txt, cutoff_ts)
                if content:
                    try:
                        zf.writestr(f"logs/{ade}/{ws}/log.txt", content)
                    except OSError:
                        pass

            if has_log1:
                content1 = _filter_log_entries(log_txt1, cutoff_ts)
                if content1:
                    try:
                        zf.writestr(f"logs/{ade}/{ws}/log.txt.1", content1)
                    except OSError:
                        pass


def _collect_installed_recipes(
    zf: zipfile.ZipFile, ade_homes: dict[str, Path] | None = None
) -> None:
    homes = ade_homes if ade_homes is not None else ADE_HOMES
    recipes: dict[str, list[dict[str, Any]]] = {}
    for ade, ade_home in homes.items():
        ade_home = Path(ade_home)
        if not ade_home.is_dir():
            continue
        entries = []
        for subdir in ("hooks", "commands", "rules"):
            d = ade_home / subdir
            if not d.is_dir():
                continue
            try:
                for p in d.iterdir():
                    if not p.is_file():
                        continue
                    if "snyk" not in p.name.lower():
                        continue
                    if _is_sensitive(p.name):
                        continue
                    try:
                        stat = p.stat()
                        entries.append(
                            {
                                "path": str(p.relative_to(ade_home)),
                                "size": stat.st_size,
                                "mtime": int(stat.st_mtime * 1000),
                            }
                        )
                    except OSError:
                        pass
            except OSError:
                pass
        if entries:
            recipes[ade] = entries
    zf.writestr("installed_recipes.json", json.dumps(recipes))


def _collect_env_snapshot(zf: zipfile.ZipFile, log_root: Path) -> None:
    data = {
        "os": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "python": sys.version,
        # PATH is intentional: useful for diagnosing "command not found" issues; no credentials stored in PATH
        "PATH": os.environ.get("PATH", ""),
        "SNYK_STUDIO_LOG_DIR": os.environ.get("SNYK_STUDIO_LOG_DIR", str(log_root)),
        "bundled_at": datetime.now(timezone.utc).isoformat(),
    }
    zf.writestr("env.json", json.dumps(data))


def _collect_verify_output(zf: zipfile.ZipFile, installer_path: Path) -> None:
    try:
        result = subprocess.run(
            [sys.executable, "-u", str(installer_path), "--yes", "--read-only", "--verify"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=30,
        )
        output = _ANSI_ESCAPE.sub("", result.stdout)
        zf.writestr("verify.txt", output)
    except Exception:
        pass


def _collect_machine_id(zf: zipfile.ZipFile) -> None:
    device_id_path = Path.home() / ".snyk-studio" / "device-id"
    try:
        with open(device_id_path, encoding="utf-8-sig") as f:
            content = f.read().strip()
        if content:
            zf.writestr("machine_id.txt", content)
    except (OSError, UnicodeDecodeError):
        pass


def _resolve_ade_version(ade: str) -> str | None:
    """Try Info.plist (macOS only), then CLI --version. Returns None if both fail."""
    if sys.platform == "darwin" and ade in _ADE_APP_BUNDLES:
        try:
            with open(_ADE_APP_BUNDLES[ade], "rb") as f:
                plist = plistlib.load(f)
            version = plist.get("CFBundleShortVersionString")
            if version:
                return str(version)
        except Exception:
            pass

    if ade in _ADE_CLI_COMMANDS:
        try:
            out = subprocess.run(
                [_ADE_CLI_COMMANDS[ade], "--version"],
                capture_output=True,
                text=True,
                timeout=3,
            ).stdout.strip()
            m = _VERSION_RE.search(out)
            if m:
                return m.group(1)
        except Exception:
            pass

    if ade == "copilot-vscode":
        try:
            out = subprocess.run(
                ["code", "--list-extensions", "--show-versions"],
                capture_output=True,
                text=True,
                timeout=3,
            ).stdout
            for line in out.splitlines():
                if "github.copilot" in line.lower() and "@" in line:
                    m = re.search(r"@(\d[\d.]+)", line)
                    if m:
                        return m.group(1)
        except Exception:
            pass

    return None


def _collect_ade_versions(zf: zipfile.ZipFile, ade_homes: dict[str, Path] | None = None) -> None:
    homes = ade_homes if ade_homes is not None else ADE_HOMES
    result: dict[str, dict[str, Any]] = {}
    for ade, ade_home in homes.items():
        detected = Path(ade_home).exists()
        version: str | None = None
        try:
            version = _resolve_ade_version(ade)
        except Exception:
            pass
        result[ade] = {"detected": detected, "version": version}
    zf.writestr("ade_versions.json", json.dumps(result))


def _collect_dependency_versions(zf: zipfile.ZipFile) -> None:
    deps: dict[str, str | None] = {"node": None, "uv": None, "snyk": None, "nvm": None}

    for dep, cmd in [
        ("node", ["node", "--version"]),
        ("uv", ["uv", "--version"]),
        ("snyk", ["snyk", "--version"]),
    ]:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout.strip()
            m = _VERSION_RE.search(out)
            if m:
                deps[dep] = m.group(1)
        except Exception:
            pass

    # nvm is a shell function on Unix; use bash sourcing. On Windows, nvm-windows is a real binary.
    try:
        if _IS_WINDOWS:
            out = subprocess.run(
                ["nvm", "version"], capture_output=True, text=True, timeout=5
            ).stdout.strip()
        else:
            nvm_dir = os.environ.get("NVM_DIR", str(Path.home() / ".nvm"))
            out = subprocess.run(
                f"source {shlex.quote(nvm_dir + '/nvm.sh')} 2>/dev/null && nvm --version",
                shell=True,
                executable="/bin/bash",
                capture_output=True,
                text=True,
                timeout=5,
            ).stdout.strip()
        m = _VERSION_RE.search(out)
        if m:
            deps["nvm"] = m.group(1)
    except Exception:
        pass

    zf.writestr("dependency_versions.json", json.dumps(deps))


def run(
    output_path: Path | None = None,
    log_days: int = 1,
    installer_path: Path | None = None,
    ade_homes: dict[str, Path] | None = None,
) -> Path:
    log_days = max(1, log_days)
    log_root = Path(
        os.environ.get("SNYK_STUDIO_LOG_DIR", str(Path.home() / ".snyk-studio" / "ades"))
    )
    log_cutoff = datetime.now(timezone.utc) - timedelta(days=log_days)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"snyk-studio-diag-{ts}.zip"

    zip_path = output_path if output_path is not None else Path.cwd() / filename

    def _write(path: Path) -> None:
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            _collect_machine_id(zf)
            _collect_sai_logs(zf, log_root, log_cutoff)
            _collect_installed_recipes(zf, ade_homes)
            _collect_ade_versions(zf, ade_homes)
            _collect_dependency_versions(zf)
            _collect_env_snapshot(zf, log_root)
            if installer_path is not None:
                _collect_verify_output(zf, installer_path)

    try:
        _write(zip_path)
    except OSError:
        zip_path.unlink(missing_ok=True)
        zip_path = Path.home() / zip_path.name
        try:
            _write(zip_path)
        except OSError as e:
            print(f"Error: Could not write diagnostic bundle: {e}", file=sys.stderr)
            sys.exit(1)

    print(f"Diagnostic bundle created: {zip_path}")
    return zip_path
