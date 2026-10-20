package dmg

import (
	"bufio"
	"os"
	"strings"
	"testing"
	"time"
)

// TestJohnVectors cross-validates the DMG verifier against John the Ripper's
// own authoritative `dmg` test vectors (testdata/john_vectors.txt, extracted
// verbatim from JtR's dmg_common_plug.c). For each vector the correct password
// must verify and a wrong one must not — covering v1 (AES-128 3DES key-unwrap)
// and v2 (AES-128 and AES-256, with the per-chunk HMAC-SHA1 IV and the
// 8-consecutive-NUL plaintext test). Matching these proves the implementation
// is byte-for-byte compatible with the reference cracker.
func TestJohnVectors(t *testing.T) {
	f, err := os.Open("testdata/john_vectors.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20) // v2 lines are long
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			t.Fatalf("malformed testdata line (no tab): %.40q", line)
		}
		hash, pw := line[:tab], line[tab+1:]
		n++

		p, err := ParseJohn(hash)
		if err != nil {
			t.Fatalf("ParseJohn(v%s): %v", hash[5:6], err)
		}
		ok, err := Verify([]byte(pw), p)
		if err != nil {
			t.Fatalf("Verify(correct, v%d, pw=%q): %v", p.Version, pw, err)
		}
		if !ok {
			t.Errorf("Verify(correct) = false for v%d pw=%q (hash %.24s…)", p.Version, pw, hash)
		}
		if ok, _ := Verify([]byte(pw+"_wrong"), p); ok {
			t.Errorf("Verify(wrong) = true for v%d pw=%q (false accept)", p.Version, pw)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n < 13 {
		t.Fatalf("only %d vectors exercised, expected >= 13", n)
	}
	t.Logf("cross-validated %d John dmg vectors", n)
}

func TestParseJohnRejects(t *testing.T) {
	for _, bad := range []string{"", "notdmg", "$dmg$", "$dmg$9*1*ab", "$dmg$1*20*zz"} {
		if _, err := ParseJohn(bad); err == nil {
			t.Errorf("ParseJohn(%q) = nil error, want rejection", bad)
		}
	}
}

// TestVerifyRejectsOversizeIterations guards the PBKDF2 cost cap: the iteration
// count is read straight from the encrcdsa header (a uint32), so an implausible
// value must be refused promptly rather than running billions of rounds.
func TestVerifyRejectsOversizeIterations(t *testing.T) {
	p := Params{Version: 2, Iterations: 1 << 30, Salt: make([]byte, 20)}
	done := make(chan bool, 1)
	go func() { ok, _ := Verify([]byte("x"), p); done <- ok }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("Verify accepted an out-of-range iteration count")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Verify did not reject an oversize iteration count promptly (CPU DoS)")
	}
}
