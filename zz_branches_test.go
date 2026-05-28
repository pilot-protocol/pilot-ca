// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validRootCertPEM is a real self-signed PEM-encoded cert from initRoot,
// inlined for tests that need a parseable root.crt without re-running init.
// We don't need a corresponding key; tests use it to pin loadRoot's
// per-file error branches separately.

// TestLoadRoot_InvalidKeyPEM hits the "root.key: invalid PEM" branch:
// root.crt is a valid PEM cert but root.key contains no PEM block.
func TestLoadRoot_InvalidKeyPEM(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Build a real root via initRoot, then clobber root.key with junk.
	if err := initRoot(dir); err != nil {
		t.Fatalf("initRoot: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "root.key"), []byte("not pem at all"), 0o600); err != nil {
		t.Fatalf("clobber key: %v", err)
	}
	_, _, err := loadRoot(dir)
	if err == nil || !strings.Contains(err.Error(), "root.key: invalid PEM") {
		t.Errorf("err = %v; want 'root.key: invalid PEM'", err)
	}
}

// TestLoadRoot_KeyParseError hits the PKCS8 parse-failure branch:
// root.key is a syntactically valid PEM block but its bytes are not
// a valid PKCS8 private key.
func TestLoadRoot_KeyParseError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := initRoot(dir); err != nil {
		t.Fatalf("initRoot: %v", err)
	}
	garbageKey := "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
	if err := os.WriteFile(filepath.Join(dir, "root.key"), []byte(garbageKey), 0o600); err != nil {
		t.Fatalf("clobber key: %v", err)
	}
	_, _, err := loadRoot(dir)
	if err == nil || !strings.Contains(err.Error(), "root.key parse") {
		t.Errorf("err = %v; want 'root.key parse'", err)
	}
}

// TestLoadRoot_CertParseError hits the x509 parse-failure branch for the
// root cert: PEM block is well-formed but bytes are not a valid cert.
func TestLoadRoot_CertParseError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	garbageCert := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(filepath.Join(dir, "root.crt"), []byte(garbageCert), 0o644); err != nil {
		t.Fatalf("write crt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "root.key"), []byte("doesn't matter"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	_, _, err := loadRoot(dir)
	if err == nil || !strings.Contains(err.Error(), "root.crt parse") {
		t.Errorf("err = %v; want 'root.crt parse'", err)
	}
}

// TestVerifyChain_MissingLeafFile hits the os.ReadFile-leaf error branch.
func TestVerifyChain_MissingLeafFile(t *testing.T) {
	t.Parallel()
	rootDir := t.TempDir()
	if err := initRoot(rootDir); err != nil {
		t.Fatalf("initRoot: %v", err)
	}
	err := verifyChain(filepath.Join(rootDir, "root.crt"), "/nonexistent/leaf.crt")
	if err == nil || !strings.Contains(err.Error(), "read leaf cert") {
		t.Errorf("err = %v; want 'read leaf cert'", err)
	}
}

// TestVerifyChain_RootPEMAppendFails hits the AppendCertsFromPEM-false
// branch: root file exists and is readable but contains no valid cert PEM.
func TestVerifyChain_RootPEMAppendFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root.crt")
	leafPath := filepath.Join(dir, "leaf.crt")
	if err := os.WriteFile(rootPath, []byte("garbage with no PEM block"), 0o644); err != nil {
		t.Fatalf("write root: %v", err)
	}
	if err := os.WriteFile(leafPath, []byte("garbage"), 0o644); err != nil {
		t.Fatalf("write leaf: %v", err)
	}
	err := verifyChain(rootPath, leafPath)
	if err == nil || !strings.Contains(err.Error(), "root cert PEM parse failed") {
		t.Errorf("err = %v; want 'root cert PEM parse failed'", err)
	}
}

// TestVerifyChain_LeafParseError hits the x509.ParseCertificate branch:
// leaf PEM block is well-formed but cert bytes are bogus.
func TestVerifyChain_LeafParseError(t *testing.T) {
	t.Parallel()
	rootDir := t.TempDir()
	if err := initRoot(rootDir); err != nil {
		t.Fatalf("initRoot: %v", err)
	}
	leafPath := filepath.Join(t.TempDir(), "leaf.crt")
	garbageLeaf := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(leafPath, []byte(garbageLeaf), 0o644); err != nil {
		t.Fatalf("write leaf: %v", err)
	}
	err := verifyChain(filepath.Join(rootDir, "root.crt"), leafPath)
	if err == nil || !strings.Contains(err.Error(), "leaf parse") {
		t.Errorf("err = %v; want 'leaf parse'", err)
	}
}

// TestIssueBeacon_HostnameWithSlash_Rejected pins the path-traversal
// fix: hostnames containing '/' (and the parent-dir token '..') must
// be rejected before any filepath.Join touches outDir, so a leaf cert
// can never be written outside the operator-chosen directory.
func TestIssueBeacon_HostnameWithSlash_Rejected(t *testing.T) {
	t.Parallel()
	rootDir := t.TempDir()
	if err := initRoot(rootDir); err != nil {
		t.Fatalf("initRoot: %v", err)
	}
	outDir := t.TempDir()
	err := issueBeacon(rootDir, "evil/../host", outDir)
	if err == nil {
		t.Fatal("expected error for hostname with slash; got nil")
	}
	if !strings.Contains(err.Error(), "hostname") {
		t.Errorf("error = %q; want it to mention 'hostname'", err.Error())
	}
	// And no leaf files should have been created anywhere.
	entries, readErr := os.ReadDir(outDir)
	if readErr != nil {
		t.Fatalf("read outDir: %v", readErr)
	}
	if len(entries) != 0 {
		t.Errorf("outDir not empty after rejected hostname: %v", entries)
	}
}

// TestIssueBeacon_HostnameWithParentDir_Rejected explicitly covers a
// bare '..' traversal attempt — even with no slash present, '..' must
// be rejected because filepath.Join would resolve it relative to outDir.
func TestIssueBeacon_HostnameWithParentDir_Rejected(t *testing.T) {
	t.Parallel()
	rootDir := t.TempDir()
	if err := initRoot(rootDir); err != nil {
		t.Fatalf("initRoot: %v", err)
	}
	outDir := t.TempDir()
	for _, host := range []string{"..", "../escape", "foo/../bar", `evil\..\host`} {
		err := issueBeacon(rootDir, host, outDir)
		if err == nil {
			t.Errorf("hostname %q: expected error; got nil", host)
			continue
		}
		if !strings.Contains(err.Error(), "hostname") {
			t.Errorf("hostname %q: error = %q; want it to mention 'hostname'", host, err.Error())
		}
	}
	entries, readErr := os.ReadDir(outDir)
	if readErr != nil {
		t.Fatalf("read outDir: %v", readErr)
	}
	if len(entries) != 0 {
		t.Errorf("outDir not empty after rejected hostnames: %v", entries)
	}
}

// TestIssueBeacon_ValidHostname_Succeeds proves the happy path still
// works after the strict-allowlist validator landed — a normal DNS name
// produces both files in outDir.
func TestIssueBeacon_ValidHostname_Succeeds(t *testing.T) {
	t.Parallel()
	rootDir := t.TempDir()
	if err := initRoot(rootDir); err != nil {
		t.Fatalf("initRoot: %v", err)
	}
	outDir := t.TempDir()
	const host = "beacon-01.example.com"
	if err := issueBeacon(rootDir, host, outDir); err != nil {
		t.Fatalf("issueBeacon(%q): %v", host, err)
	}
	for _, name := range []string{host + ".key", host + ".crt"} {
		p := filepath.Join(outDir, name)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected %s to exist: %v", p, err)
		}
	}
}
