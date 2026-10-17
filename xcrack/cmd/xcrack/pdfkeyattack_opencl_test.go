//go:build opencl

package main

import (
	"context"
	"crypto/md5" //nolint:gosec // the PDF Standard Security Handler mandates MD5
	"crypto/rc4" //nolint:gosec // the PDF Standard Security Handler mandates RC4
	"testing"

	"github.com/rom/xcrypto/scheme/pdf"
)

// pdfPad is the 32-byte PDF Standard Security Handler padding string (PDF spec
// Algorithm 2), used here to synthesize a /U verifier for a known file key.
var pdfPad = []byte{
	0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
	0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
}

// pdfRC4U reproduces /U for a 5-byte file key: it RC4s `input` `rounds` times,
// round r keyed by key5 XOR r. It mirrors pdf.Handler.computeU (R2: input=pad,
// rounds=1; R3/R4: input=MD5(pad||ID), rounds=20) without the pdf package.
func pdfRC4U(key5, input []byte, rounds int) []byte {
	buf := append([]byte(nil), input...)
	for r := 0; r < rounds; r++ {
		kr := make([]byte, 5)
		for i := range kr {
			kr[i] = key5[i] ^ byte(r)
		}
		c, _ := rc4.NewCipher(kr) //nolint:gosec
		c.XORKeyStream(buf, buf)
	}
	return buf
}

// TestSweepPDFKeyspaceGPU drives the pdf-keyattack sweep through the GPU path
// (useGPU=true) on whatever OpenCL device is present (pocl locally), confirming
// the CLI wiring — PDFRC4KeySearch offload plus the authoritative CPU re-check
// (VerifyFileKey) — recovers the real 40-bit file key for both the R2 and the
// 40-bit R3/R4 shapes. Built only with -tags opencl.
func TestSweepPDFKeyspaceGPU(t *testing.T) {
	id := []byte("pdf-id-16-bytes!")
	r34 := md5.Sum(append(append([]byte{}, pdfPad...), id...)) //nolint:gosec
	for _, tc := range []struct {
		name   string
		r      int
		input  []byte
		rounds int
	}{
		{"R2", 2, pdfPad, 1},
		{"R3R4", 3, r34[:], 20},
	} {
		idx := uint64(0x0100000007) // a non-trivial 40-bit index
		key5 := []byte{byte(idx), byte(idx >> 8), byte(idx >> 16), byte(idx >> 24), byte(idx >> 32)}
		u := pdfRC4U(key5, tc.input, tc.rounds)
		h := &pdf.Handler{R: tc.r, Length: 5, Cipher: pdf.CipherRC4, U: u, ID: id}
		if !h.VerifyFileKey(key5) {
			t.Fatalf("%s: constructed /U does not verify against the CPU reference", tc.name)
		}

		lo := idx - 4
		hi := idx + 4
		key, found, err := sweepPDFKeyspace(context.Background(), h, lo, hi, 0, false, true)
		if err != nil {
			t.Fatalf("%s: sweepPDFKeyspace(gpu): %v", tc.name, err)
		}
		if !found {
			t.Fatalf("%s: GPU sweep did not recover the file key", tc.name)
		}
		if !h.VerifyFileKey(key) {
			t.Fatalf("%s: GPU-recovered key %x does not verify", tc.name, key)
		}
	}
}
