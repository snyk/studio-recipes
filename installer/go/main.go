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
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
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
	os.Exit(run())
}

func run() int {
	ensureUvOnPath()
	if err := ensureUv(os.Args[1:]); err != nil {
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

	args := append([]string{"run", installer}, os.Args[1:]...)
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
func ensureUv(argv []string) error {
	autoYes := false
	for _, a := range argv {
		if a == "-y" || a == "--yes" {
			autoYes = true
			break
		}
	}

	if _, err := exec.LookPath("uv"); err == nil {
		fmt.Printf("  OK uv %s\n", uvVersionLine())
		return nil
	}

	fmt.Fprintln(os.Stderr, "  WARNING uv not found")
	if runtime.GOOS == "windows" {
		fmt.Fprintln(os.Stderr, "    Install with: irm https://astral.sh/uv/install.ps1 | iex")
	} else {
		fmt.Fprintln(os.Stderr, "    Install with: curl -LsSf https://astral.sh/uv/install.sh | sh")
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

	if err := bootstrapUvInstall(); err != nil {
		return fmt.Errorf("uv install failed: %s", err)
	}

	ensureUvOnPath()
	if _, err := exec.LookPath("uv"); err != nil {
		return fmt.Errorf("uv was installed but is not on PATH. Add ~/.local/bin to PATH and retry.")
	}
	return nil
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

func bootstrapUvInstall() error {
	if runtime.GOOS == "windows" {
		ps, err := exec.LookPath("powershell")
		if err != nil {
			ps, err = exec.LookPath("pwsh")
		}
		if err != nil {
			return fmt.Errorf("need PowerShell to install uv on Windows")
		}
		return runInherit(ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
			"Invoke-Expression (Invoke-RestMethod -Uri 'https://astral.sh/uv/install.ps1')")
	}

	var shellCmd string
	if _, err := exec.LookPath("curl"); err == nil {
		shellCmd = "curl -LsSf https://astral.sh/uv/install.sh | sh"
	} else if _, err := exec.LookPath("wget"); err == nil {
		shellCmd = "wget -qO- https://astral.sh/uv/install.sh | sh"
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
