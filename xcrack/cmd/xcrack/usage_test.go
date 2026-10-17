package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

// captureStderr runs f with os.Stderr redirected and returns what it wrote.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	f()
	w.Close()
	os.Stderr = old
	b, _ := io.ReadAll(r)
	return string(b)
}

// TestUsageListsEverySubcommand guards against a subcommand being dispatched in
// run() but missing from the --help text (as thunder-gen once was). Every
// user-facing subcommand must appear in the usage output.
func TestUsageListsEverySubcommand(t *testing.T) {
	// The user-facing subcommands dispatched by run() (meta aliases --version/-v
	// and -h/--help are intentionally not separate usage lines).
	want := []string{
		"identify", "kp", "hashline", "export-challenge",
		"office-keyattack", "pdf-keyattack", "thunder-gen",
		"access-recover", "vba-recover", "wordlist", "version",
	}
	out := captureStderr(t, usage)
	for _, sub := range want {
		if !strings.Contains(out, "xcrack "+sub) {
			t.Errorf("usage() does not list the %q subcommand", sub)
		}
	}
}
