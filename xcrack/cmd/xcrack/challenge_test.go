package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xcrack/pkg/xcrack"
)

// TestChallengesForWinZip proves export-challenge probes a WinZip-AES zip and
// produces a crackable envelope for its encrypted entry.
func TestChallengesForWinZip(t *testing.T) {
	data, err := os.ReadFile("../../../samples/winzip-aes.zip")
	if err != nil {
		t.Skipf("sample not available: %v", err)
	}
	envs := challengesFor(xcrack.DefaultRegistry(), "winzip-aes.zip", data)
	if len(envs) == 0 {
		t.Fatal("no challenge envelopes produced")
	}
	e := envs[0]
	if e.Scheme != "winzip-aes-256" {
		t.Errorf("scheme = %q, want winzip-aes-256", e.Scheme)
	}
	if e.KDF.Algo != "pbkdf2-hmac-sha1" || e.KDF.Iterations != 1000 {
		t.Errorf("kdf = %+v, want pbkdf2-hmac-sha1/1000", e.KDF)
	}
	if e.KDF.SaltHex == "" || e.VerifierHex == "" {
		t.Errorf("envelope missing salt/verifier: %+v", e)
	}
}

// TestLoadRecoveredPasswords proves the --resume-from importer accepts both a
// single envelope and a JSON array, and rejects a bad version.
func TestLoadRecoveredPasswords(t *testing.T) {
	dir := t.TempDir()
	single := filepath.Join(dir, "one.json")
	if err := os.WriteFile(single, []byte(`{"xcrack_recovered_version":1,"password":"opensesame"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	arr := filepath.Join(dir, "arr.json")
	if err := os.WriteFile(arr, []byte(`[{"xcrack_recovered_version":1,"password":"a"},{"xcrack_recovered_version":1,"password":"b"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	pws, err := loadRecoveredPasswords([]string{single, arr})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	want := []string{"opensesame", "a", "b"}
	if len(pws) != len(want) {
		t.Fatalf("got %v, want %v", pws, want)
	}
	for i := range want {
		if pws[i] != want[i] {
			t.Fatalf("pw[%d] = %q, want %q", i, pws[i], want[i])
		}
	}

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"xcrack_recovered_version":99,"password":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRecoveredPasswords([]string{bad}); err == nil {
		t.Fatal("expected an error for an unsupported version")
	}
}
