//go:build opencl

package main

import (
	"context"
	"crypto/md5" //nolint:gosec // mirrors the MS-OFFCRYPTO trunc derivation under test
	"encoding/binary"
	"testing"

	"github.com/rom/xcrypto/prim"
	"github.com/rom/xcrypto/scheme/officebinary"
)

// TestSweepKeyspaceGPU drives the office-keyattack sweep through the GPU path
// (useGPU=true) on whatever OpenCL device is present (pocl locally), confirming
// the CLI wiring — OldOfficeKeySearch offload plus the authoritative CPU
// re-check — recovers the real trunc. Built only with -tags opencl.
func TestSweepKeyspaceGPU(t *testing.T) {
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

	tr := md5.Sum(prim.UTF16LE([]byte("password1"))) //nolint:gosec
	idx := binary.LittleEndian.Uint64(append(append([]byte(nil), tr[:5]...), 0, 0, 0))
	lo := idx
	if lo >= 4 {
		lo -= 4
	} else {
		lo = 0
	}
	hi := idx + 4

	trunc, found, err := sweepKeyspace(context.Background(), ch, lo, hi, 0, false, true)
	if err != nil {
		t.Fatalf("sweepKeyspace(gpu): %v", err)
	}
	if !found {
		t.Fatal("GPU sweep did not recover the trunc")
	}
	if ok, _ := officebinary.VerifyRC4Trunc(trunc, salt, enc[:16], enc[16:32]); !ok {
		t.Fatalf("GPU-recovered trunc %x does not verify", trunc)
	}
}
