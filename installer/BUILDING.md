# Building the Installer

Build from source to **tailor the bundle for your organization**, **audit the installer before deploying**, or **host it in a restricted environment**. For a vanilla install, use the pre-built installer — see [`README.md`](README.md).

---

## Prerequisites

- Python 3.8+
- A clone of [`snyk/studio-recipes`](https://github.com/snyk/studio-recipes)
- Go 1.18+ (optional — only needed to compile the Go installer binaries; install from [go.dev/dl](https://go.dev/dl/). The build skips them if `go` is not on `PATH`)

---

## Build

From the `installer/` directory of your clone:

```bash
python3 build_installer.py
```

This regenerates the installers from [`manifest.json`](manifest.json) and the recipe sources alongside it:

- `dist/snyk-studio-install.sh`, `dist/snyk-studio-install.ps1`, `dist/snyk-studio-install.py` — single self-extracting scripts with the recipe payload embedded as base64.
- `dist/snyk-studio-<os>-<arch>[.exe]` — Go installer binaries cross-compiled for macOS, Linux, and Windows (`macos`/`linux`/`windows` × `x86_64`/`arm64`). Invoke with the `install` subcommand, e.g. `snyk-studio-macos-arm64 install -y` (options after `install` are forwarded to the Python installer).

Distribute or host the contents of `dist/` — developers run them exactly the same way as the pre-built installer described in [`README.md`](README.md).

To build a single flavor, pass `--only` (repeatable):

```bash
python3 build_installer.py --only go        # just the Go binaries
python3 build_installer.py --only sh --only ps1
```

---

## Customize what gets bundled

Everything the installer ships is declared in [`manifest.json`](manifest.json). The two sections you'll edit most:

- **`recipes`** — each entry maps recipe sources to per-assistant destinations. Add new entries to bundle internal recipes, or set `"enabled": false` to drop ones you don't need.
- **`profiles`** — named bundles (`default`, `minimal`) that select which recipes get installed. Add your own profile, or change the membership of an existing one.

Rebuild with `python3 build_installer.py` after editing.

For lower-level changes (new recipe types, new assistants, custom merge strategies), the entry points are `snyk-studio-installer.py` and the modules under `lib/`.

---

## Test changes without rebuilding

```bash
python3 snyk-studio-installer.py --dry-run
```

This runs the same logic the build embeds into `dist/`, against the recipe sources in your checkout — the fastest way to validate manifest changes before producing a distributable.

---

## Host in a restricted environment

Once `dist/` is built, place `snyk-studio-install.sh` and `snyk-studio-install.ps1` wherever your developers can reach them — internal artifact server, S3 bucket, network share. The installers are self-extracting and embed the full recipe payload, so they don't fetch additional resources at install time except for any package-manager bootstraps (Node.js, `uv`, Snyk CLI) the user explicitly accepts.

---

## Tests

```bash
pytest
```

The Go installer has its own tests (they exercise the embedded-bundle extraction against whatever is currently staged in `go/bundle/`):

```bash
cd go && go test ./...
```
