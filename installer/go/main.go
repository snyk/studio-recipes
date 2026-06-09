// Snyk Studio Recipes — self-extracting installer (Go).
//
// This mirrors the bash, PowerShell, and Python installers: it ensures `uv`
// is available, extracts the bundled recipe payload to a temp directory, and
// hands off to snyk-studio-installer.py via `uv run`. Unlike the other
// installers, the payload is embedded natively with //go:embed instead of the
// tar/zip + base64 trick — `build_installer.py` stages the files into bundle/
// before compiling this binary.
package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// all: includes dotfiles (e.g. mcp/.mcp.json) and underscore-prefixed files
// (e.g. lib/_vendor/...) that a plain //go:embed bundle would skip.
//
//go:embed all:bundle
var bundleFS embed.FS

// Must match snyk-studio-installer.BUNDLE_ENV and build_installer.BUNDLE_ENV.
const bundleEnv = "SNYK_STUDIO_BUNDLE_ROOT"

// bundleRoot is the directory name embedded above; embed.FS paths are rooted here.
const bundleRoot = "bundle"

// installerScript is the Python entry point the bootstrap hands off to.
const installerScript = "snyk-studio-installer.py"

func main() {
	os.Exit(run(os.Args[1:]))
}

// run dispatches on the first positional argument as a subcommand. This lets
// the binary grow other behaviors (e.g. uninstall, version) alongside install.
func run(argv []string) int {
	if len(argv) == 0 {
		usage(os.Stderr)
		return 2
	}

	command, rest := argv[0], argv[1:]
	switch command {
	case "install":
		return runInstall(rest)
	case "-h", "--help", "help":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command %q\n\n", command)
		usage(os.Stderr)
		return 2
	}
}

// usage prints the top-level command listing.
func usage(w io.Writer) {
	fmt.Fprintln(w, "Snyk Studio Recipes installer")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage: snyk-studio <command> [options]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  install   Install Snyk Studio recipes (pass installer options after the command)")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Install options:")
	fmt.Fprintln(w, "  --global  Install pinned dependency versions (uv, snyk) instead of the latest")
}

// runInstall extracts the embedded bundle and hands off to the Python installer.
// installArgs are forwarded verbatim to snyk-studio-installer.py.
func runInstall(installArgs []string) int {
	ensureUvOnPath()
	// --global pins binary dependencies (uv here, snyk in the Python installer)
	// to the versions declared in the manifest's prerequisites, instead of
	// tracking the latest release. The flag stays in installArgs so it also
	// reaches the Python installer.
	globalMode := hasFlag(installArgs, "--global")
	pinnedUv := ""
	if globalMode {
		pinnedUv = pinnedVersion("uv")
	}
	if err := ensureUv(installArgs, globalMode, pinnedUv); err != nil {
		fmt.Fprintf(os.Stderr, "  Error: %s\n", err)
		return 1
	}

	workdir, err := os.MkdirTemp("", "snyk-studio-install.")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot create temp dir: %s\n", err)
		return 1
	}
	cleanup := func() { _ = os.RemoveAll(workdir) }
	defer cleanup()
	installSignalCleanup(cleanup)

	// Env key mirrors the other installers; the Python installer reads it.
	_ = os.Setenv(bundleEnv, workdir)

	if err := extractBundle(workdir); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to extract embedded bundle: %s\n", err)
		return 1
	}

	installer := filepath.Join(workdir, installerScript)
	if fi, err := os.Stat(installer); err != nil || fi.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: missing %s in bundle.\n", installerScript)
		return 1
	}
	// embed.FS does not carry file modes, so extracted files are 0o644. `uv run`
	// does not require the +x bit, but set it on the entry point for parity with
	// the script installers and in case it is ever invoked directly.
	if err := os.Chmod(installer, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not mark %s executable: %s\n", installerScript, err)
	}

	uvExe, err := exec.LookPath("uv")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: uv not found on PATH.")
		return 1
	}

	args := append([]string{"run", installer}, installArgs...)
	cmd := exec.Command(uvExe, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "Error: failed to run installer: %s\n", err)
		return 1
	}
	return 0
}

// ensureUvOnPath prepends ~/.local/bin so a user-installed uv is visible
// (astral.sh default install location).
func ensureUvOnPath() {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return
	}
	// filepath.Join builds the path with the OS-native separator. Only append
	// the existing PATH when it is non-empty, otherwise the trailing list
	// separator would leave an empty entry (interpreted as the current
	// directory on most shells).
	localBin := filepath.Join(home, ".local", "bin")
	if existing := os.Getenv("PATH"); existing != "" {
		os.Setenv("PATH", localBin+string(os.PathListSeparator)+existing)
	} else {
		os.Setenv("PATH", localBin)
	}
}

// ensureUv probes for uv and, if missing, offers to install it via the official
// script (mirrors install.sh / install.ps1 / install.py).
//
// In globalMode with a non-empty pinnedUv, an already-installed uv that is older
// than the pin is upgraded to it; an equal-or-newer uv (or any uv outside global
// mode) is accepted as-is. The version installed is the pin in global mode and
// the latest release otherwise.
func ensureUv(argv []string, globalMode bool, pinnedUv string) error {
	autoYes := hasFlag(argv, "-y", "--yes")

	if _, err := exec.LookPath("uv"); err == nil {
		cur, haveVer := uvInstalledVersion()
		// Outside global pinning, any installed uv is acceptable.
		if !globalMode || pinnedUv == "" {
			fmt.Printf("  OK uv %s\n", uvVersionLine())
			return nil
		}
		// Pinning: keep the installed uv only when we can confirm it is not
		// older than the pin. If we cannot read or compare the versions (e.g. a
		// malformed manifest pin or unexpected `uv --version` output), fall
		// through and (re)install the pin rather than acting on a guess.
		older, comparable := versionOlder(cur, pinnedUv)
		if haveVer && comparable && !older {
			fmt.Printf("  OK uv %s\n", uvVersionLine())
			return nil
		}
		switch {
		case !haveVer:
			fmt.Fprintf(os.Stderr, "  WARNING could not read uv version; reinstalling %s\n", pinnedUv)
		case !comparable:
			fmt.Fprintf(os.Stderr, "  WARNING could not compare uv %s against pinned %s; reinstalling %s\n", cur, pinnedUv, pinnedUv)
		default:
			fmt.Fprintf(os.Stderr, "  WARNING uv %s is older than the minimum supported %s\n", cur, pinnedUv)
		}
		// Fall through to (re)install the pinned version.
	} else {
		fmt.Fprintln(os.Stderr, "  WARNING uv not found")
	}

	// In global mode install the manifest pin; otherwise track the latest.
	installVersion := ""
	if globalMode {
		installVersion = pinnedUv
	}

	if runtime.GOOS == "windows" {
		fmt.Fprintf(os.Stderr, "    Install with: irm %s | iex\n", uvInstallURL("install.ps1", installVersion))
	} else {
		fmt.Fprintf(os.Stderr, "    Install with: curl -LsSf %s | sh\n", uvInstallURL("install.sh", installVersion))
	}

	if !autoYes {
		// Only prompt on an interactive terminal. In an automated environment
		// (stdin redirected from a pipe/file, or no TTY) Scanln could block
		// indefinitely, so fail fast with guidance instead of hanging.
		if !stdinIsInteractive() {
			return fmt.Errorf("uv is required; re-run with -y to install it without prompting.")
		}
		fmt.Print("\n  Install uv now? (y/n) ")
		var reply string
		// A read error (e.g. EOF on a closed stdin) leaves reply empty -> cancel.
		_, _ = fmt.Scanln(&reply)
		reply = strings.ToLower(strings.TrimSpace(reply))
		if reply != "y" && reply != "yes" {
			return fmt.Errorf("Cancelled: uv is required to run this installer.")
		}
	}

	if err := bootstrapUvInstall(installVersion); err != nil {
		return fmt.Errorf("uv install failed: %s", err)
	}

	ensureUvOnPath()
	if _, err := exec.LookPath("uv"); err != nil {
		return fmt.Errorf("uv was installed but is not on PATH. Add ~/.local/bin to PATH and retry.")
	}
	return nil
}

// hasFlag reports whether any of names appears verbatim in argv.
func hasFlag(argv []string, names ...string) bool {
	for _, a := range argv {
		for _, n := range names {
			if a == n {
				return true
			}
		}
	}
	return false
}

// pinnedVersion reads a pinned dependency version from the embedded manifest's
// "prerequisites" map. Returns "" if the manifest is absent or the key is unset
// — e.g. a dev build where only the bundle .gitkeep placeholder is embedded —
// in which case callers fall back to installing the latest release.
func pinnedVersion(dep string) string {
	data, err := bundleFS.ReadFile(bundleRoot + "/manifest.json")
	if err != nil {
		return ""
	}
	var m struct {
		Prerequisites map[string]string `json:"prerequisites"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return ""
	}
	return m.Prerequisites[dep]
}

// uvInstallURL returns the astral.sh install-script URL for uv. A non-empty
// version pins to that exact release (https://astral.sh/uv/<version>/<script>);
// otherwise it tracks the latest.
func uvInstallURL(script, version string) string {
	if version != "" {
		return "https://astral.sh/uv/" + version + "/" + script
	}
	return "https://astral.sh/uv/" + script
}

// uvInstalledVersion returns the numeric version reported by `uv --version`
// (e.g. "0.11.19"), and false if uv is absent or its output is unparseable.
func uvInstalledVersion() (string, bool) {
	out, err := exec.Command("uv", "--version").Output()
	if err != nil {
		return "", false
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return "", false
	}
	return fields[1], true
}

// parseVersion splits a dotted version like "0.11.19" into integer components,
// reading only the leading digits of each component so a trailing build suffix
// (e.g. "1.2.3-rc1") still parses. It returns ok=false when the string is empty
// or any component lacks a leading digit (e.g. "1..2", ".rc1", "1.2."), so a
// malformed manifest pin is surfaced rather than silently coerced to zeros and
// compared as if valid.
func parseVersion(s string) ([]int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	parts := strings.Split(s, ".")
	nums := make([]int, len(parts))
	for i, p := range parts {
		j := 0
		for j < len(p) && p[j] >= '0' && p[j] <= '9' {
			j++
		}
		if j == 0 {
			return nil, false
		}
		n, err := strconv.Atoi(p[:j])
		if err != nil {
			return nil, false // overflow or other malformed component
		}
		nums[i] = n
	}
	return nums, true
}

// versionOlder reports whether version a is strictly older than version b. ok is
// false when either version cannot be parsed, in which case older is meaningless
// and the caller must decide how to proceed rather than trusting the result.
func versionOlder(a, b string) (older bool, ok bool) {
	av, aok := parseVersion(a)
	bv, bok := parseVersion(b)
	if !aok || !bok {
		return false, false
	}
	n := len(av)
	if len(bv) > n {
		n = len(bv)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(av) {
			x = av[i]
		}
		if i < len(bv) {
			y = bv[i]
		}
		if x != y {
			return x < y, true
		}
	}
	return false, true
}

// stdinIsInteractive reports whether stdin is a terminal (character device),
// as opposed to a pipe, regular file, or closed stream.
func stdinIsInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func uvVersionLine() string {
	out, err := exec.Command("uv", "--version").Output()
	if err == nil {
		s := strings.TrimSpace(string(out))
		if s != "" {
			return strings.SplitN(s, "\n", 2)[0]
		}
	}
	return "present"
}

// bootstrapUvInstall runs the official uv installer. A non-empty version pins to
// that exact release; otherwise the latest is installed.
func bootstrapUvInstall(version string) error {
	if runtime.GOOS == "windows" {
		ps, err := exec.LookPath("powershell")
		if err != nil {
			ps, err = exec.LookPath("pwsh")
		}
		if err != nil {
			return fmt.Errorf("need PowerShell to install uv on Windows")
		}
		return runInherit(ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
			"Invoke-Expression (Invoke-RestMethod -Uri '"+uvInstallURL("install.ps1", version)+"')")
	}

	var shellCmd string
	if _, err := exec.LookPath("curl"); err == nil {
		shellCmd = "curl -LsSf " + uvInstallURL("install.sh", version) + " | sh"
	} else if _, err := exec.LookPath("wget"); err == nil {
		shellCmd = "wget -qO- " + uvInstallURL("install.sh", version) + " | sh"
	} else {
		return fmt.Errorf("need curl or wget to install uv")
	}
	return runInherit("sh", "-c", shellCmd)
}

func runInherit(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// extractBundle writes every embedded file out under workdir, stripping the
// leading "bundle/" prefix. embed.FS always uses forward-slash paths.
func extractBundle(workdir string) error {
	prefix := bundleRoot + "/"
	return fs.WalkDir(bundleFS, bundleRoot, func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == bundleRoot {
			return nil
		}
		rel := strings.TrimPrefix(name, prefix)
		dest := filepath.Join(workdir, filepath.FromSlash(rel))
		if d.IsDir() {
			return os.MkdirAll(dest, 0o755)
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		return writeEmbedded(name, dest)
	})
}

func writeEmbedded(name, dest string) error {
	in, err := bundleFS.Open(name)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func installSignalCleanup(cleanup func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		cleanup()
		os.Exit(130)
	}()
}
