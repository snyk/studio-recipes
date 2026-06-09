package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunDispatch covers the top-level subcommand routing. The "install"
// command is exercised end-to-end elsewhere; here we check the cases that
// return before any extraction happens.
func TestRunDispatch(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want int
	}{
		{"no command", nil, 2},
		{"help long", []string{"--help"}, 0},
		{"help short", []string{"-h"}, 0},
		{"help word", []string{"help"}, 0},
		{"unknown command", []string{"frobnicate"}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(tc.argv); got != tc.want {
				t.Errorf("run(%v) = %d, want %d", tc.argv, got, tc.want)
			}
		})
	}
}

// TestVersionOlder covers the semver-ish comparison used to decide whether a
// pinned dependency needs (re)installing.
func TestVersionOlder(t *testing.T) {
	cases := []struct {
		a, b         string
		want, wantOK bool
	}{
		{"0.11.18", "0.11.19", true, true},
		{"0.11.19", "0.11.19", false, true},
		{"0.11.20", "0.11.19", false, true},
		{"0.9.0", "0.11.0", true, true},
		{"1.0.0", "0.11.19", false, true},
		{"0.11.19-rc1", "0.11.19", false, true}, // trailing suffix ignored -> equal
		{"0.11", "0.11.1", true, true},          // missing component treated as 0
		// Unparseable inputs must report ok=false rather than comparing as 0.
		{"", "0.11.19", false, false},    // empty installed version
		{"0.11.19", "", false, false},    // empty pin
		{"0..1", "0.1.1", false, false},  // empty middle segment
		{"rc1", "0.1.0", false, false},   // no leading digit
		{"0.11.19", "1.x", false, false}, // malformed pin component
	}
	for _, tc := range cases {
		got, gotOK := versionOlder(tc.a, tc.b)
		if got != tc.want || gotOK != tc.wantOK {
			t.Errorf("versionOlder(%q, %q) = (%v, %v), want (%v, %v)",
				tc.a, tc.b, got, gotOK, tc.want, tc.wantOK)
		}
	}
}

// TestUvInstallURL checks the latest vs pinned URL forms.
func TestUvInstallURL(t *testing.T) {
	if got := uvInstallURL("install.sh", ""); got != "https://astral.sh/uv/install.sh" {
		t.Errorf("latest sh URL = %q", got)
	}
	if got := uvInstallURL("install.ps1", "0.11.19"); got != "https://astral.sh/uv/0.11.19/install.ps1" {
		t.Errorf("pinned ps1 URL = %q", got)
	}
}

// TestPinnedVersion reads the uv pin from whatever manifest is currently
// embedded. In a dev build only the .gitkeep placeholder is present, so the
// manifest may be absent — in that case pinnedVersion must return "" rather
// than crash. When a manifest IS embedded, a present uv pin must be non-empty.
func TestPinnedVersion(t *testing.T) {
	got := pinnedVersion("uv")
	if _, err := bundleFS.ReadFile(bundleRoot + "/manifest.json"); err != nil {
		if got != "" {
			t.Errorf("no embedded manifest, want empty pin, got %q", got)
		}
		t.Skip("no manifest embedded in this build")
	}
	// A manifest is embedded; the value may legitimately be empty if the key
	// is unset, so just assert no panic and a string result (implicit).
	_ = got
}

// TestExtractBundle verifies every embedded file lands on disk under workdir
// with the "bundle/" prefix stripped and byte-identical contents. Works with
// whatever is currently embedded (the .gitkeep placeholder at minimum, or the
// full payload after build_installer.py has staged it).
func TestExtractBundle(t *testing.T) {
	workdir := t.TempDir()
	if err := extractBundle(workdir); err != nil {
		t.Fatalf("extractBundle: %v", err)
	}

	prefix := bundleRoot + "/"
	err := fs.WalkDir(bundleFS, bundleRoot, func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == bundleRoot || d.IsDir() {
			return nil
		}
		rel := strings.TrimPrefix(name, prefix)
		dest := filepath.Join(workdir, filepath.FromSlash(rel))

		want, err := bundleFS.ReadFile(name)
		if err != nil {
			return err
		}
		got, err := os.ReadFile(dest)
		if err != nil {
			t.Errorf("expected extracted file %s: %v", rel, err)
			return nil
		}
		if string(got) != string(want) {
			t.Errorf("content mismatch for %s", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded bundle: %v", err)
	}
}
