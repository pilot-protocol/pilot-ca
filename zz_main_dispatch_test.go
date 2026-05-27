// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestMain re-enters the test binary as the real `pilot-ca` command
// when PILOTCA_TEST_MAIN=1 is set. This lets subprocess tests below
// drive every dispatch branch in main() / die() without modifying
// production code.
func TestMain(m *testing.M) {
	if os.Getenv("PILOTCA_TEST_MAIN") == "1" {
		// Strip the magic env so subprocesses we fork (if any) don't loop.
		os.Unsetenv("PILOTCA_TEST_MAIN")
		// Splice in synthetic argv for the real main().
		// Args are passed through PILOTCA_TEST_ARG_N (N = 0..count-1) env vars
		// because Go's os/exec forbids NUL in env strings, ruling out a
		// single null-separated env var.
		n, _ := strconv.Atoi(os.Getenv("PILOTCA_TEST_ARGC"))
		argv := []string{"pilot-ca"}
		for i := 0; i < n; i++ {
			argv = append(argv, os.Getenv(fmt.Sprintf("PILOTCA_TEST_ARG_%d", i)))
		}
		os.Args = argv
		main()
		return
	}
	os.Exit(m.Run())
}

// runMain re-execs the test binary with PILOTCA_TEST_MAIN=1 so main()
// runs against the synthetic argv. Returns combined output + exit code.
func runMain(t *testing.T, args ...string) (string, int) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	// -test.run=^$ matches no tests; the env-var check in TestMain hijacks
	// the process before m.Run() is reached, so the filter is just a safety net.
	cmd := exec.Command(exe, "-test.run=^$")
	env := append(os.Environ(),
		"PILOTCA_TEST_MAIN=1",
		"PILOTCA_TEST_ARGC="+strconv.Itoa(len(args)),
	)
	for i, a := range args {
		env = append(env, fmt.Sprintf("PILOTCA_TEST_ARG_%d=%s", i, a))
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			t.Fatalf("exec: %v (out=%q)", err, out)
		}
	}
	return string(out), exitCode
}

func TestMain_NoArgs_PrintsUsage(t *testing.T) {
	out, code := runMain(t)
	if code != 2 {
		t.Errorf("exit = %d; want 2 (flag.Usage)", code)
	}
	if !strings.Contains(out, "usage:") {
		t.Errorf("output missing usage line: %s", out)
	}
}

func TestMain_UnknownSubcommand(t *testing.T) {
	out, code := runMain(t, "nope")
	if code != 2 {
		t.Errorf("exit = %d; want 2", code)
	}
	if !strings.Contains(out, "usage:") {
		t.Errorf("output missing usage: %s", out)
	}
}

func TestMain_InitRoot_WrongArgCount(t *testing.T) {
	_, code := runMain(t, "init-root") // missing out-dir
	if code != 2 {
		t.Errorf("exit = %d; want 2", code)
	}
}

func TestMain_InitRoot_Happy(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "ca")
	out, code := runMain(t, "init-root", outDir)
	if code != 0 {
		t.Fatalf("exit = %d (out=%s)", code, out)
	}
	if _, err := os.Stat(filepath.Join(outDir, "root.crt")); err != nil {
		t.Errorf("root.crt missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "root.key")); err != nil {
		t.Errorf("root.key missing: %v", err)
	}
}

func TestMain_InitRoot_DieOnError(t *testing.T) {
	// /dev/null is a file, so MkdirAll fails -> initRoot returns an error -> die().
	out, code := runMain(t, "init-root", "/dev/null/cannot/path")
	if code != 1 {
		t.Errorf("exit = %d; want 1 (die)", code)
	}
	if !strings.Contains(out, "pilot-ca: init-root:") {
		t.Errorf("missing die prefix: %s", out)
	}
}

func TestMain_IssueBeacon_WrongArgCount(t *testing.T) {
	_, code := runMain(t, "issue-beacon", "only-one")
	if code != 2 {
		t.Errorf("exit = %d; want 2", code)
	}
}

func TestMain_IssueBeacon_Happy(t *testing.T) {
	rootDir := t.TempDir()
	leafDir := t.TempDir()
	if _, code := runMain(t, "init-root", rootDir); code != 0 {
		t.Fatalf("init-root failed")
	}
	out, code := runMain(t, "issue-beacon", rootDir, "host.example", leafDir)
	if code != 0 {
		t.Fatalf("exit = %d (out=%s)", code, out)
	}
	if _, err := os.Stat(filepath.Join(leafDir, "host.example.crt")); err != nil {
		t.Errorf("leaf cert missing: %v", err)
	}
}

func TestMain_IssueBeacon_DieOnError(t *testing.T) {
	emptyDir := t.TempDir() // no root.crt -> issueBeacon -> loadRoot -> err -> die
	out, code := runMain(t, "issue-beacon", emptyDir, "h.example", t.TempDir())
	if code != 1 {
		t.Errorf("exit = %d; want 1", code)
	}
	if !strings.Contains(out, "pilot-ca: issue-beacon:") {
		t.Errorf("missing die prefix: %s", out)
	}
}

func TestMain_Verify_WrongArgCount(t *testing.T) {
	_, code := runMain(t, "verify", "only-one")
	if code != 2 {
		t.Errorf("exit = %d; want 2", code)
	}
}

func TestMain_Verify_Happy(t *testing.T) {
	rootDir := t.TempDir()
	leafDir := t.TempDir()
	if _, code := runMain(t, "init-root", rootDir); code != 0 {
		t.Fatalf("init-root")
	}
	host := "verify.example"
	if _, code := runMain(t, "issue-beacon", rootDir, host, leafDir); code != 0 {
		t.Fatalf("issue-beacon")
	}
	out, code := runMain(t, "verify",
		filepath.Join(rootDir, "root.crt"),
		filepath.Join(leafDir, host+".crt"))
	if code != 0 {
		t.Fatalf("exit = %d (out=%s)", code, out)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("missing OK line: %s", out)
	}
}

func TestMain_Verify_DieOnError(t *testing.T) {
	out, code := runMain(t, "verify", "/nonexistent/root.crt", "/nonexistent/leaf.crt")
	if code != 1 {
		t.Errorf("exit = %d; want 1", code)
	}
	if !strings.Contains(out, "pilot-ca: verify:") {
		t.Errorf("missing die prefix: %s", out)
	}
}
