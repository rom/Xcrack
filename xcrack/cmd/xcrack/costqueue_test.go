package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/xcrack/pkg/xcrack"
)

// TestCostOrderRanksFastFirst confirms the cost-aware queue attacks the weaker,
// faster scheme first: given a slow WinZip-AES file (PBKDF2, ~1000 iters) and a
// fast ZipCrypto file, in slow-first argument order, costOrder reorders so the
// ZipCrypto file is dispatched first. A plaintext file ranks last.
func TestCostOrderRanksFastFirst(t *testing.T) {
	winzip := "../../../samples/winzip-aes.zip"
	zipc := "../../../samples/zipcrypto.zip"
	for _, p := range []string{winzip, zipc} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("sample not available: %v", err)
		}
	}
	// A plaintext (non-encrypted) file should sort last.
	plain := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(plain, []byte("not encrypted\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	files := []string{winzip, zipc, plain} // slow, fast, plaintext
	order := costOrder(files, xcrack.DefaultRegistry(), 200*time.Millisecond)
	if len(order) != 3 {
		t.Fatalf("order len = %d, want 3", len(order))
	}
	// ZipCrypto (index 1) must come before WinZip-AES (index 0).
	posZip, posWinzip, posPlain := -1, -1, -1
	for pos, idx := range order {
		switch idx {
		case 0:
			posWinzip = pos
		case 1:
			posZip = pos
		case 2:
			posPlain = pos
		}
	}
	if posZip >= posWinzip {
		t.Errorf("ZipCrypto dispatched at %d, WinZip-AES at %d; want ZipCrypto first", posZip, posWinzip)
	}
	if posPlain != len(order)-1 {
		t.Errorf("plaintext file dispatched at %d; want last (%d)", posPlain, len(order)-1)
	}
}
