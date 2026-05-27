// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitRoot_MkdirError(t *testing.T) {
	t.Parallel()
	// /dev/null is a file — MkdirAll under it fails.
	if err := initRoot("/dev/null/cannot/path"); err == nil {
		t.Error("expected mkdir error")
	}
}

func TestInitRoot_RefusesOverwriteExistingKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Pre-create root.key so initRoot refuses.
	if err := os.WriteFile(filepath.Join(dir, "root.key"), []byte("existing"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	err := initRoot(dir)
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Errorf("err = %v", err)
	}
}

func TestIssueBeacon_NoRootFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Skip initRoot — issueBeacon should fail at loadRoot.
	if err := issueBeacon(dir, "host.example", dir); err == nil {
		t.Error("expected error when root files are missing")
	}
}

func TestIssueBeacon_MkdirError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := initRoot(dir); err != nil {
		t.Fatalf("initRoot: %v", err)
	}
	// outDir under /dev/null can't have its parent created.
	if err := issueBeacon(dir, "host", "/dev/null/cannot"); err == nil {
		t.Error("expected mkdir error")
	}
}
