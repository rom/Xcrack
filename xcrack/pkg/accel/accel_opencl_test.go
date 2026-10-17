//go:build opencl

package accel

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"

	"github.com/rom/xcrypto/prim"
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
