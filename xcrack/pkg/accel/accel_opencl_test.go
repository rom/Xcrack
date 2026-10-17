//go:build opencl

package accel

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // the PDF handler mandates MD5; building test inputs
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"

	"github.com/rom/xcrypto/prim"
	"github.com/rom/xcrypto/scheme/officebinary"
	"github.com/rom/xcrypto/scheme/pdf"
)

// TestGPUSelfTest validates the OpenCL PBKDF2-HMAC-SHA1 kernel against the Go
// reference on whatever OpenCL device is present (pocl CPU in CI-less local
// runs, a real GPU in production). Run with: go test -tags opencl ./pkg/accel/
func TestGPUSelfTest(t *testing.T) {
	if err := GPUSelfTest(); err != nil {
		t.Fatal(err)
	}
	a, err := Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	defer a.Close()
	if len(a.Devices()) == 0 {
		t.Fatal("no devices reported")
	}
	for _, d := range a.Devices() {
		t.Logf("device: %s / %s (%s, %d CU)", d.Vendor, d.Name, d.Type, d.ComputeUnits)
	}
}

// TestGPUOldOfficeKeySearch cross-validates the Office 97/2000 40-bit MD5+RC4
// key-search kernel against the CPU reference (officebinary.RC4KeyAttack): for a
// known trunc the device must recover exactly it, the CPU key-attack must find
// the same trunc over the same window, and officebinary.VerifyRC4Trunc must
// accept it. A window that excludes the trunc must return not-found.
func TestGPUOldOfficeKeySearch(t *testing.T) {
	a, err := Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	defer a.Close()
	ks, ok := a.(OldOfficeKeySearcher)
	if !ok {
		t.Skip("accelerator does not implement OldOfficeKeySearcher")
	}
	salt := []byte("0123456789abcdef")
	for _, idx := range []uint64{0, 7, 0x0102030405} {
		trunc := []byte{byte(idx), byte(idx >> 8), byte(idx >> 16), byte(idx >> 24), byte(idx >> 32)}
		encV, encVH := oldOfficeVerifier(trunc, salt)

		// CPU reference must accept this trunc.
		if okv, _ := officebinary.VerifyRC4Trunc(trunc, salt, encV, encVH); !okv {
			t.Fatalf("idx %#x: officebinary.VerifyRC4Trunc rejected the constructed verifier", idx)
		}
		start := uint64(0)
		if idx > 2048 {
			start = idx - 2048
		}
		// GPU sweep finds it.
		got, found, err := ks.OldOfficeKeySearch(salt, encV, encVH, start, 4096)
		if err != nil {
			t.Fatalf("idx %#x: OldOfficeKeySearch: %v", idx, err)
		}
		if !found || !bytes.Equal(got, trunc) {
			t.Fatalf("idx %#x: GPU got (%x, %v), want %x", idx, got, found, trunc)
		}
		// CPU key-attack over the same window finds the same trunc.
		cpu, cfound, err := officebinary.RC4KeyAttack(context.Background(), salt, encV, encVH, start, 4096)
		if err != nil {
			t.Fatalf("idx %#x: RC4KeyAttack: %v", idx, err)
		}
		if !cfound || !bytes.Equal(cpu, got) {
			t.Fatalf("idx %#x: CPU/GPU disagree: cpu (%x,%v) gpu %x", idx, cpu, cfound, got)
		}
		// A window that excludes the trunc must not match.
		if _, f2, _ := ks.OldOfficeKeySearch(salt, encV, encVH, idx+1000, 100); f2 {
			t.Fatalf("idx %#x: false positive on a non-containing window", idx)
		}
	}
}

// TestGPUPDFKeySearch cross-validates the PDF 40-bit RC4 file-key search kernel
// against the CPU reference (pdf.Handler.RC4KeyAttack) for both R2 and R3/R4
// (40-bit): for a known file key the device must recover exactly it, the CPU
// attack must find the same key over the same window, pdf.Handler.VerifyFileKey
// must accept it, and a non-containing window must return not-found.
func TestGPUPDFKeySearch(t *testing.T) {
	a, err := Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	defer a.Close()
	ks, ok := a.(PDFRC4KeySearcher)
	if !ok {
		t.Skip("accelerator does not implement PDFRC4KeySearcher")
	}
	id := []byte("pdf-id-16-bytes!")
	r34in := md5.Sum(append(append([]byte{}, pdfPad...), id...)) //nolint:gosec

	for _, tc := range []struct {
		name   string
		r      int
		input  []byte
		rounds int
	}{
		{"R2", 2, pdfPad, 1},
		{"R3R4", 3, r34in[:], 20},
	} {
		for _, idx := range []uint64{0, 9, 0x0102030405} {
			key5 := []byte{byte(idx), byte(idx >> 8), byte(idx >> 16), byte(idx >> 24), byte(idx >> 32)}
			u := pdfRC4U(key5, tc.input, tc.rounds)
			h := &pdf.Handler{R: tc.r, Length: 5, Cipher: pdf.CipherRC4, U: u, ID: id}
			input, rounds, cmpLen, uu, okp := h.RC4KeyAttackParams()
			if !okp {
				t.Fatalf("%s idx %#x: RC4KeyAttackParams not ok", tc.name, idx)
			}
			if !bytes.Equal(input, tc.input) || rounds != tc.rounds {
				t.Fatalf("%s: params mismatch input=%x rounds=%d", tc.name, input, rounds)
			}
			if !h.VerifyFileKey(key5) {
				t.Fatalf("%s idx %#x: VerifyFileKey rejected constructed /U", tc.name, idx)
			}
			start := uint64(0)
			if idx > 2048 {
				start = idx - 2048
			}
			got, found, err := ks.PDFRC4KeySearch(input, rounds, uu, cmpLen, start, 4096)
			if err != nil {
				t.Fatalf("%s idx %#x: PDFRC4KeySearch: %v", tc.name, idx, err)
			}
			if !found || !bytes.Equal(got, key5) {
				t.Fatalf("%s idx %#x: GPU got (%x,%v) want %x", tc.name, idx, got, found, key5)
			}
			cpu, cfound, err := h.RC4KeyAttack(context.Background(), start, 4096)
			if err != nil {
				t.Fatalf("%s idx %#x: CPU RC4KeyAttack: %v", tc.name, idx, err)
			}
			if !cfound || !bytes.Equal(cpu, got) {
				t.Fatalf("%s idx %#x: CPU/GPU disagree cpu (%x,%v) gpu %x", tc.name, idx, cpu, cfound, got)
			}
			if _, f2, _ := ks.PDFRC4KeySearch(input, rounds, uu, cmpLen, idx+1000, 100); f2 {
				t.Fatalf("%s idx %#x: false positive on a non-containing window", tc.name, idx)
			}
		}
	}
}

// TestGPUSaltedSHA1 cross-validates the salted SHA-1 batch kernel (hashcat-110 /
// VBA) against crypto/sha1 over (password || salt): every digest in the batch must
// match, across one- and two-block messages and an empty password, and a message
// longer than the kernel's bound must return ErrUnsupported (CPU fallback).
func TestGPUSaltedSHA1(t *testing.T) {
	a, err := Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	defer a.Close()
	sh, ok := a.(SaltedSHA1Hasher)
	if !ok {
		t.Skip("accelerator does not implement SaltedSHA1Hasher")
	}
	salt := []byte{0x01, 0x02, 0x03, 0x04} // 4-byte VBA key
	pws := [][]byte{}
	for _, s := range []string{"", "a", "Welcome1", "hashcat", "Σecretü", "x\x00y",
		"this-password-is-long-enough-to-need-a-second-sha1-compression-block"} {
		pws = append(pws, []byte(s))
	}
	got, err := sh.SaltedSHA1(pws, salt)
	if err != nil {
		t.Fatalf("SaltedSHA1: %v", err)
	}
	if len(got) != len(pws) {
		t.Fatalf("got %d results, want %d", len(got), len(pws))
	}
	for i, pw := range pws {
		want := sha1.Sum(append(append([]byte(nil), pw...), salt...))
		if !bytes.Equal(got[i], want[:]) {
			t.Errorf("pw %q:\n gpu %x\n cpu %x", pw, got[i], want[:])
		}
	}
	// A message past the kernel's bound must fall back, not silently truncate.
	if _, err := sh.SaltedSHA1([][]byte{make([]byte, 1024)}, salt); err != ErrUnsupported {
		t.Errorf("oversize message: err = %v, want ErrUnsupported", err)
	}
}

// TestGPUBatchMatchesReference derives a batch of distinct passwords against one
// salt and checks every result equals prim.PBKDF2 (WinZip-AES-256 parameters:
// 1000 iters, 66-byte derived key).
func TestGPUBatchMatchesReference(t *testing.T) {
	a, err := Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	defer a.Close()

	pws := [][]byte{}
	for _, s := range []string{"", "a", "hashcat", "Welcome1", "correct horse", "Σecretü", "x\x00y"} {
		pws = append(pws, []byte(s))
	}
	salt := []byte{0x7b, 0xb0, 0x0a, 0x58, 0xf7, 0x43, 0x4c, 0x99, 0xdc, 0x84, 0xe1, 0x49, 0x19, 0x01, 0x26, 0x3f}
	const iter, dk = 1000, 66

	got, err := a.PBKDF2SHA1(pws, salt, iter, dk)
	if err != nil {
		t.Fatalf("PBKDF2SHA1: %v", err)
	}
	if len(got) != len(pws) {
		t.Fatalf("got %d results, want %d", len(got), len(pws))
	}
	for i, pw := range pws {
		want, err := prim.PBKDF2(sha1.New, string(pw), salt, iter, dk)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got[i], want) {
			t.Errorf("pw %q:\n gpu %x\n cpu %x", pw, got[i], want)
		}
	}

	// A salt longer than the kernel's single-block bound must fall back (not
	// silently return a wrong answer).
	if _, err := a.PBKDF2SHA1(pws, make([]byte, 64), iter, dk); err != ErrUnsupported {
		t.Errorf("oversize salt: err = %v, want ErrUnsupported", err)
	}
}

// TestGPUBatchSHA256And512 checks the SHA-256 (RAR5-class) and SHA-512
// (SQLCipher-v4-class) batch kernels against the Go reference across a batch.
func TestGPUBatchSHA256And512(t *testing.T) {
	a, err := Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	defer a.Close()

	pws := [][]byte{}
	for _, s := range []string{"", "a", "hashcat", "Welcome1", "correct horse battery", "Σecretü"} {
		pws = append(pws, []byte(s))
	}
	variants := []struct {
		name string
		h    func() hash.Hash
		fn   func([][]byte, []byte, int, int) ([][]byte, error)
		salt []byte
		iter int
		dk   int
	}{
		{"sha256", sha256.New, a.PBKDF2SHA256, []byte("rar5saltrar5salt"), 2000, 32},
		{"sha512", sha512.New, a.PBKDF2SHA512, []byte("sqlcipher-v4-salt"), 1500, 64},
	}
	for _, v := range variants {
		got, err := v.fn(pws, v.salt, v.iter, v.dk)
		if err != nil {
			t.Fatalf("%s batch: %v", v.name, err)
		}
		for i, pw := range pws {
			want, _ := prim.PBKDF2(v.h, string(pw), v.salt, v.iter, v.dk)
			if !bytes.Equal(got[i], want) {
				t.Errorf("%s pw %q:\n gpu %x\n cpu %x", v.name, pw, got[i], want)
			}
		}
	}
}

// TestAutotuneBatch checks the accelerator advertises a sane, positive batch
// size via BatchTuner, and that a batch of that size still matches the
// reference (exercising the per-device runOne path at the tuned width).
func TestAutotuneBatch(t *testing.T) {
	a, err := Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	defer a.Close()
	bt, ok := a.(BatchTuner)
	if !ok {
		t.Fatal("OpenCL accelerator does not implement BatchTuner")
	}
	n := bt.OptimalBatch()
	if n <= 0 || n > 1<<20 {
		t.Fatalf("OptimalBatch() = %d; want a sane positive size", n)
	}
	t.Logf("autotuned batch = %d over %d device(s)", n, len(a.Devices()))

	salt := []byte("batch-ref-salt16")
	const iter, dk = 200, 32
	pws := make([][]byte, n)
	for i := range pws {
		pws[i] = []byte{byte(i), byte(i >> 8), byte(i >> 16), 'z'}
	}
	got, err := a.PBKDF2SHA1(pws, salt, iter, dk)
	if err != nil {
		t.Fatalf("PBKDF2SHA1(tuned batch): %v", err)
	}
	if len(got) != n {
		t.Fatalf("got %d results, want %d", len(got), n)
	}
	// Spot-check a sample of the batch against the reference.
	for _, i := range []int{0, n / 3, n / 2, n - 1} {
		want, _ := prim.PBKDF2(sha1.New, string(pws[i]), salt, iter, dk)
		if !bytes.Equal(got[i], want) {
			t.Fatalf("tuned-batch index %d mismatch", i)
		}
	}
}

func TestBuiltFlag(t *testing.T) {
	if !Built() {
		t.Error("Built() = false in an -tags opencl build")
	}
}
