package iwork

import (
	"os"
	"path/filepath"
	"testing"
)

// vectors are the real .iwpv2 verifiers from Pages/Numbers/Keynote 14.5; the
// passphrase for all three is "Password" (see testdata/ATTRIBUTION.md).
var vectors = []string{"pages.iwpv2", "numbers.iwpv2", "key.iwpv2"}

func load(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestVerifyKnownAnswer cross-validates against the real documents: the correct
// passphrase verifies and wrong ones do not.
func TestVerifyKnownAnswer(t *testing.T) {
	for _, name := range vectors {
		raw := load(t, name)
		p, err := Parse(raw)
		if err != nil {
			t.Fatalf("%s: Parse: %v", name, err)
		}
		if p.Format != 2 || p.Variant != 1 || p.Iterations != 100000 {
			t.Fatalf("%s: unexpected params %+v", name, p)
		}
		if !Verify(p, []byte("Password")) {
			t.Fatalf("%s: correct passphrase rejected", name)
		}
		for _, wrong := range []string{"password", "Password ", " Password", "Passw0rd", "", "Secret"} {
			if Verify(p, []byte(wrong)) {
				t.Fatalf("%s: wrong passphrase %q accepted", name, wrong)
			}
		}
	}
}

// TestVerifyRaw exercises the one-shot path.
func TestVerifyRaw(t *testing.T) {
	ok, err := VerifyRaw(load(t, "pages.iwpv2"), []byte("Password"))
	if err != nil || !ok {
		t.Fatalf("VerifyRaw: ok=%v err=%v", ok, err)
	}
	ok, err = VerifyRaw(load(t, "pages.iwpv2"), []byte("nope"))
	if err != nil || ok {
		t.Fatalf("VerifyRaw wrong: ok=%v err=%v", ok, err)
	}
}

// TestParseRejects checks malformed/unsupported inputs are rejected cleanly
// (never a panic, never mistaken for a valid verifier).
func TestParseRejects(t *testing.T) {
	good := load(t, "pages.iwpv2")
	cases := map[string][]byte{
		"empty":       nil,
		"short":       good[:40],
		"bad-format":  mutate(good, 0, 0x09),     // format != 2
		"bad-variant": mutate(good, 2, 0x09),     // variant != 1
		"zero-iters":  mutateU32(good, 4, 0),     // iterations == 0
		"huge-iters":  mutateU32(good, 4, 1<<30), // iterations > max
	}
	for name, in := range cases {
		if _, err := Parse(in); err == nil {
			t.Errorf("%s: Parse accepted an invalid verifier", name)
		}
	}
}

func mutate(b []byte, off int, v byte) []byte {
	c := append([]byte(nil), b...)
	c[off] = v
	return c
}

func mutateU32(b []byte, off int, v uint32) []byte {
	c := append([]byte(nil), b...)
	c[off] = byte(v)
	c[off+1] = byte(v >> 8)
	c[off+2] = byte(v >> 16)
	c[off+3] = byte(v >> 24)
	return c
}
