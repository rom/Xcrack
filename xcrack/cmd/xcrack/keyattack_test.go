package main

import (
	"context"
	"crypto/md5" //nolint:gosec // mirrors the MS-OFFCRYPTO trunc derivation under test
	"encoding/binary"
	"testing"

	"github.com/rom/xcrypto/prim"
	"github.com/rom/xcrypto/scheme/officebinary"
)

func TestResolveRange(t *testing.T) {
	max := officebinary.MaxRC4Trunc
	cases := []struct {
		shard      string
		start, max uint64
		wantLo     uint64
		wantHi     uint64
		wantErr    bool
	}{
		{"", 0, 0, 0, max, false},
		{"0/8", 0, 0, 0, max / 8, false},
		{"7/8", 0, 0, max / 8 * 7, max, false}, // last shard mops up to the end
		{"", 100, 50, 100, 150, false},
		{"0/4", 10, 0, 10, max / 4, false}, // start trims the shard's low end
		{"9/8", 0, 0, 0, 0, true},          // i >= N
		{"bad", 0, 0, 0, 0, true},
		{"1/0", 0, 0, 0, 0, true}, // N == 0
	}
	for _, c := range cases {
		lo, hi, err := resolveRange(c.shard, c.start, c.max, max)
		if c.wantErr {
			if err == nil {
				t.Errorf("resolveRange(%q,%d,%d): want error", c.shard, c.start, c.max)
			}
			continue
		}
		if err != nil {
			t.Errorf("resolveRange(%q,%d,%d): %v", c.shard, c.start, c.max, err)
			continue
		}
		if lo != c.wantLo || hi != c.wantHi {
			t.Errorf("resolveRange(%q,%d,%d) = [%d,%d); want [%d,%d)", c.shard, c.start, c.max, lo, hi, c.wantLo, c.wantHi)
		}
	}
}

// TestSweepKeyspaceRecovers drives the subcommand's attack over a small window
// containing the real key. The challenge is built from the KAT-validated RC4Key,
// so a recovered trunc confirms the extraction + range + sweep wiring.
func TestSweepKeyspaceRecovers(t *testing.T) {
	salt := []byte("0123456789abcdef")
	verifier := []byte("verifier--16byte")
	vh := md5.Sum(verifier) //nolint:gosec
	plain := append(append([]byte{}, verifier...), vh[:]...)
	key := officebinary.RC4Key([]byte("password1"), salt, 0)
	enc, err := prim.RC4(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	ch := officebinary.ChallengeRC4(salt, enc[:16], enc[16:32])
	if ch.Scheme != "mso-rc4" {
		t.Fatalf("challenge scheme = %q", ch.Scheme)
	}

	// Real trunc index (the subcommand's little-endian mapping).
	tr := md5.Sum(prim.UTF16LE([]byte("password1"))) //nolint:gosec
	idx := binary.LittleEndian.Uint64(append(append([]byte(nil), tr[:5]...), 0, 0, 0))
	lo := idx
	if lo >= 4 {
		lo -= 4
	} else {
		lo = 0
	}
	hi := idx + 4

	trunc, found, err := sweepKeyspace(context.Background(), ch, lo, hi, 2, false)
	if err != nil || !found {
		t.Fatalf("sweepKeyspace found=%v err=%v", found, err)
	}
	if ok, _ := officebinary.VerifyRC4Trunc(trunc, salt, enc[:16], enc[16:32]); !ok {
		t.Fatalf("recovered trunc %x does not verify", trunc)
	}
}
