//go:build opencl

package main

import (
	"bytes"
	"context"
	"crypto/rc4" //nolint:gosec // the PDF Standard Security Handler mandates RC4
	"testing"

	"github.com/rom/xcrack/pkg/accel"
	"github.com/rom/xcrypto/scheme/pdf"
)

// pdfPadConst is the 32-byte PDF Standard Security Handler padding string — the
// universal constant R2 encrypts to form /U (matches pdf.pad).
var pdfPadConst = []byte{
	0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
	0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
}

// TestThunderGenGPUMatchesCPU builds the same thunder table twice — once with the
// CPU walk, once with the GPU chain computer — and asserts the two are
// byte-identical (so a GPU-built table is inverted by the exact same CPU lookup),
// then confirms the GPU-built table actually recovers a covered R2 file key.
// Built only with -tags opencl; runs on pocl when no GPU is present.
func TestThunderGenGPUMatchesCPU(t *testing.T) {
	if err := accel.GPUSelfTest(); err != nil {
		t.Skipf("no usable OpenCL device / self-test failed: %v", err)
	}
	acc, err := accel.Detect()
	if err != nil {
		t.Skipf("accel.Detect: %v", err)
	}
	defer acc.Close()
	comp := gpuChainComputer(acc)
	if comp == nil {
		t.Skip("accelerator does not implement PDFThunderChainer")
	}

	base := pdf.TableParams{KeyspaceBits: 16, ChainLen: 128, Chains: 1024, Tables: 3}
	cpuTbl, err := pdf.GenerateTable(context.Background(), base)
	if err != nil {
		t.Fatalf("CPU GenerateTable: %v", err)
	}
	gpuParams := base
	gpuParams.Chain = comp
	gpuTbl, err := pdf.GenerateTable(context.Background(), gpuParams)
	if err != nil {
		t.Fatalf("GPU GenerateTable: %v", err)
	}

	var cb, gb bytes.Buffer
	if _, err := cpuTbl.WriteTo(&cb); err != nil {
		t.Fatalf("WriteTo(cpu): %v", err)
	}
	if _, err := gpuTbl.WriteTo(&gb); err != nil {
		t.Fatalf("WriteTo(gpu): %v", err)
	}
	if !bytes.Equal(cb.Bytes(), gb.Bytes()) {
		t.Fatalf("GPU-built table differs from CPU-built (%d vs %d bytes)", gb.Len(), cb.Len())
	}

	// The GPU-built table must recover a key it covers; find one via the CPU table
	// (identical), then look it up in the GPU table and verify.
	for idx := uint64(0); idx < (1 << 16); idx++ {
		u, rerr := r2UBytes(idx)
		if rerr != nil {
			t.Fatalf("r2U: %v", rerr)
		}
		if _, ok := cpuTbl.Lookup(u); !ok {
			continue
		}
		got, found := gpuTbl.Lookup(u)
		if !found {
			t.Fatalf("idx %#x: GPU-built table missed a key the identical CPU table covered", idx)
		}
		h := &pdf.Handler{R: 2, Length: 5, Cipher: pdf.CipherRC4, U: u}
		if !h.VerifyFileKey(got) {
			t.Fatalf("idx %#x: recovered key %x fails VerifyFileKey", idx, got)
		}
		return // one confirmed recovery is enough
	}
	t.Fatal("GPU-built table covered no key in [0, 2^16) — parameters too small")
}

// r2UBytes builds the R2 /U = RC4(key5, pad) for a key index — the value a V1/R2
// PDF stores and the thunder table's lookup input.
func r2UBytes(idx uint64) ([]byte, error) {
	key := []byte{byte(idx), byte(idx >> 8), byte(idx >> 16), byte(idx >> 24), byte(idx >> 32)}
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	u := make([]byte, len(pdfPadConst))
	c.XORKeyStream(u, pdfPadConst)
	return u, nil
}
