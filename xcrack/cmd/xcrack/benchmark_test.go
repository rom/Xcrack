package main

import (
	"os"
	"testing"
	"time"

	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrypto/candidates"
)

func TestCountKeyspace(t *testing.T) {
	n, capped := countKeyspace(candidates.Explicit("a", "b", "c"), 0)
	if n != 3 || capped {
		t.Fatalf("got (%d,%v), want (3,false)", n, capped)
	}
	n, capped = countKeyspace(candidates.Explicit("a", "b", "c", "d"), 2)
	if n != 2 || !capped {
		t.Fatalf("got (%d,%v), want (2,true)", n, capped)
	}
}

// TestFirstTargetWinZip proves the benchmark/estimate prober finds the encrypted
// entry of a WinZip-AES zip and returns a verifier that accepts the right
// password and rejects a wrong one.
func TestFirstTargetWinZip(t *testing.T) {
	data, err := os.ReadFile("../../../samples/winzip-aes.zip")
	if err != nil {
		t.Skipf("sample not available: %v", err)
	}
	label, verify, ok := firstTarget(xcrack.DefaultRegistry(), data)
	if !ok {
		t.Fatal("firstTarget did not find an encrypted target")
	}
	if label != "winzip-aes-256" {
		t.Errorf("label = %q, want winzip-aes-256", label)
	}
	if okv, err := verify([]byte("opensesame")); err != nil || !okv {
		t.Fatalf("verify(correct) = (%v,%v), want (true,nil)", okv, err)
	}
	if okv, _ := verify([]byte("definitely-wrong")); okv {
		t.Fatal("verify(wrong) = true, want false")
	}
}

func TestMeasureRatePositive(t *testing.T) {
	calls := 0
	verify := func([]byte) (bool, error) { calls++; return false, nil }
	rate := measureRate(verify, 40*time.Millisecond)
	if rate <= 0 || calls == 0 {
		t.Fatalf("rate=%v calls=%d, want a positive rate", rate, calls)
	}
}

func TestHumanRate(t *testing.T) {
	cases := map[float64]string{
		500:       "500",
		1500:      "1.50k",
		2_500_000: "2.50M",
		3.2e9:     "3.20G",
	}
	for in, want := range cases {
		if got := humanRate(in); got != want {
			t.Errorf("humanRate(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestRoundDur(t *testing.T) {
	// Spot-check the magnitude buckets and the overflow-safe large case.
	if got := roundDur(0); got != "0s" {
		t.Errorf("roundDur(0) = %q", got)
	}
	if got := roundDur(90 * time.Minute); got != "1h30m0s" {
		t.Errorf("roundDur(90m) = %q", got)
	}
	// A keyspace/rate that would overflow a naive nanosecond year constant.
	if got := roundDur(time.Duration(1 << 62)); got == "" {
		t.Errorf("roundDur(huge) returned empty")
	}
}
