// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLoadRoot_MissingCert covers the os.ReadFile error branch.
func TestLoadRoot_MissingCert(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if _, _, err := loadRoot(dir); err == nil {
		t.Error("expected error when root.crt missing")
	}
}

// TestLoadRoot_MissingKey covers the missing-key branch.
func TestLoadRoot_MissingKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Write a valid root.crt but no root.key.
	if err := os.WriteFile(filepath.Join(dir, "root.crt"), []byte("-----BEGIN CERTIFICATE-----\nXXX\n-----END CERTIFICATE-----\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _, err := loadRoot(dir)
	if err == nil || !strings.Contains(err.Error(), "root.key") {
		t.Errorf("err = %v, want root.key error", err)
	}
}

// TestLoadRoot_InvalidCertPEM covers the "invalid PEM" branch.
func TestLoadRoot_InvalidCertPEM(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "root.crt"), []byte("not pem"), 0644); err != nil {
		t.Fatalf("write crt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "root.key"), []byte("not pem"), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	_, _, err := loadRoot(dir)
	if err == nil || !strings.Contains(err.Error(), "root.crt: invalid PEM") {
		t.Errorf("err = %v", err)
	}
}

// TestWritePEM_ToBadPath covers the OpenFile error branch.
func TestWritePEM_ToBadPath(t *testing.T) {
	t.Parallel()
	if err := writePEM("/no/such/dir/file.pem", "CERTIFICATE", []byte("x"), 0644); err == nil {
		t.Error("expected error on unwritable path")
	}
}

// TestWritePEM_HappyPath drives the encode-success branch.
func TestWritePEM_HappyPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "out.pem")
	if err := writePEM(path, "CERTIFICATE", []byte("ABCDEFG"), 0600); err != nil {
		t.Fatalf("writePEM: %v", err)
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "BEGIN CERTIFICATE") {
		t.Errorf("got %q", body)
	}
}

// TestMustMarshalPKCS8_PanicsOnInvalid covers the panic branch.
func TestMustMarshalPKCS8_PanicsOnInvalid(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on unsupported key type")
		}
	}()
	mustMarshalPKCS8(42) // int is not a private key
}

// TestMustMarshalPKCS8_HappyPath covers the success branch.
func TestMustMarshalPKCS8_HappyPath(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	body := mustMarshalPKCS8(priv)
	if len(body) == 0 {
		t.Error("empty PKCS8 body")
	}
}

// TestRandomSerial_NonZero covers the helper.
func TestRandomSerial_NonZero(t *testing.T) {
	t.Parallel()
	s, err := randomSerial()
	if err != nil {
		t.Fatalf("randomSerial: %v", err)
	}
	if s.Sign() == 0 {
		t.Error("serial should be non-zero")
	}
}

// TestLoadRoot_AfterInit drives initRoot + loadRoot end-to-end.
func TestLoadRoot_AfterInit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := initRoot(dir); err != nil {
		t.Fatalf("initRoot: %v", err)
	}
	crt, key, err := loadRoot(dir)
	if err != nil {
		t.Fatalf("loadRoot: %v", err)
	}
	if crt == nil || key == nil {
		t.Error("nil crt or key")
	}
}

// TestIssueBeacon_HappyPath drives initRoot + issueBeacon end-to-end.
func TestIssueBeacon_HappyPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := initRoot(dir); err != nil {
		t.Fatalf("initRoot: %v", err)
	}
	beaconDir := filepath.Join(dir, "beacon1")
	if err := os.MkdirAll(beaconDir, 0700); err != nil {
		t.Fatalf("mkdir beacon: %v", err)
	}
	if err := issueBeacon(dir, "beacon1.example", beaconDir); err != nil {
		t.Fatalf("issueBeacon: %v", err)
	}
	for _, name := range []string{"beacon1.example.crt", "beacon1.example.key"} {
		if _, err := os.Stat(filepath.Join(beaconDir, name)); err != nil {
			t.Errorf("%s missing: %v", name, err)
		}
	}
}

// TestLoadRoot_NotCA verifies loadRoot rejects a self-signed cert
// that does not have IsCA set. This is the PILOT-139 fix.
func TestLoadRoot_NotCA(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Generate a leaf-like self-signed cert (IsCA=false).
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    now,
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IsCA:         false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	// Also marshal the key — loadRoot needs both files.
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(filepath.Join(dir, "root.crt"), crtPEM, 0644); err != nil {
		t.Fatalf("write crt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "root.key"), keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	_, _, err = loadRoot(dir)
	if err == nil {
		t.Error("loadRoot should reject a non-CA root cert")
	}
	if err != nil && !strings.Contains(err.Error(), "IsCA") {
		t.Errorf("err = %v, want IsCA", err)
	}
}

// TestIssueBeacon_RequiresHostname covers the empty-hostname branch.
func TestIssueBeacon_RequiresHostname(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := issueBeacon(dir, "", dir); err == nil {
		t.Error("expected error on empty hostname")
	}
}
