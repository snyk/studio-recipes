package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
