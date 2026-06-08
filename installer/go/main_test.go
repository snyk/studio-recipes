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
