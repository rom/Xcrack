package xcrack

import (
	stdzip "archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"os"
	"sync/atomic"
	"testing"

	"github.com/rom/xcrack/pkg/accel"
	"github.com/rom/xcrypto/candidates"
	"github.com/rom/xcrypto/prim"
	"github.com/rom/xcrypto/scheme/winzipaes"
	"github.com/rom/xfileformats"
)

// stubAccel is a pure-Go stand-in for the OpenCL accelerator: it derives
// PBKDF2-HMAC-SHA1 keys with the CPU reference (prim.PBKDF2) — the exact
// function the real kernel is self-tested to match — so the engine's batched
// offload path can be exercised in CI without any GPU, cgo, or -tags opencl.
// It counts dispatches so a test can prove the GPU path (not the CPU fallback)
// did the work, and can be told to report ErrUnsupported to exercise fallback.
type stubAccel struct {
	calls       atomic.Int64 // successful PBKDF2SHA1 dispatches
	derived     atomic.Int64 // total passwords derived
	unsupported bool         // when true, always returns accel.ErrUnsupported
}

func (s *stubAccel) Devices() []accel.Device { return []accel.Device{{Name: "stub", Type: "CPU"}} }
func (s *stubAccel) Close() error            { return nil }

func (s *stubAccel) PBKDF2SHA1(passwords [][]byte, salt []byte, iter, dkLen int) ([][]byte, error) {
	return s.derive(sha1.New, passwords, salt, iter, dkLen)
}

func (s *stubAccel) PBKDF2SHA256(passwords [][]byte, salt []byte, iter, dkLen int) ([][]byte, error) {
	return s.derive(sha256.New, passwords, salt, iter, dkLen)
}

func (s *stubAccel) PBKDF2SHA512(passwords [][]byte, salt []byte, iter, dkLen int) ([][]byte, error) {
	return s.derive(sha512.New, passwords, salt, iter, dkLen)
}

func (s *stubAccel) derive(h func() hash.Hash, passwords [][]byte, salt []byte, iter, dkLen int) ([][]byte, error) {
	if s.unsupported {
		return nil, accel.ErrUnsupported
	}
	s.calls.Add(1)
	s.derived.Add(int64(len(passwords)))
	out := make([][]byte, len(passwords))
	for i, pw := range passwords {
		dk, err := prim.PBKDF2(h, string(pw), salt, iter, dkLen)
		if err != nil {
			return nil, err
		}
		out[i] = dk
	}
	return out, nil
}

// TestAccelDeriveDispatch checks accelDerive routes each PRF to the matching
// accelerator method (so the kernel output matches the reference for that hash),
// and that an unknown PRF reports ErrUnsupported (CPU fallback).
func TestAccelDeriveDispatch(t *testing.T) {
	stub := &stubAccel{}
	salt := []byte("0123456789abcdef")
	batch := [][]byte{[]byte("alpha"), []byte("beta")}
	const iter, dk = 64, 32
	cases := []struct {
		prf string
		h   func() hash.Hash
	}{
		{"", sha1.New},
		{"sha1", sha1.New},
		{"sha256", sha256.New},
		{"sha512", sha512.New},
	}
	for _, c := range cases {
		got, err := accelDerive(stub, &xfileformats.AccelKDF{PRF: c.prf, Salt: salt, Iter: iter, DKLen: dk}, batch)
		if err != nil {
			t.Fatalf("prf %q: %v", c.prf, err)
		}
		for i, pw := range batch {
			want, _ := prim.PBKDF2(c.h, string(pw), salt, iter, dk)
			if !bytes.Equal(got[i], want) {
				t.Errorf("prf %q pw %q: dispatched to the wrong HMAC variant", c.prf, pw)
			}
		}
	}
	if _, err := accelDerive(stub, &xfileformats.AccelKDF{PRF: "md5", Salt: salt, Iter: iter, DKLen: dk}, batch); err == nil {
		t.Error("unknown PRF: want error (CPU fallback), got nil")
	}
}

// --- WinZip-AES fixture (mirrors xfileformats/formats/zip test builder) ---

func deflate(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func aesExtra(p winzipaes.Params) []byte {
	e := make([]byte, 0, 11)
	e = binary.LittleEndian.AppendUint16(e, 0x9901)
	e = binary.LittleEndian.AppendUint16(e, 7)
	e = binary.LittleEndian.AppendUint16(e, p.VendorVer)
	e = binary.LittleEndian.AppendUint16(e, winzipaes.VendorAE)
	e = append(e, p.Strength)
	e = binary.LittleEndian.AppendUint16(e, p.ActualMethod)
	return e
}

func buildWinZipAES(t *testing.T, password []byte, strength byte, name string, plain []byte) []byte {
	t.Helper()
	p := winzipaes.Params{Strength: strength, ActualMethod: 8 /* deflate */, VendorVer: 2}
	salt := make([]byte, p.SaltLen())
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	raw, err := winzipaes.EncryptRaw(password, p, salt, deflate(t, plain))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	zw := stdzip.NewWriter(&b)
	fh := &stdzip.FileHeader{Name: name, Method: 99 /* methodAES */}
	fh.Flags |= 0x1
	fh.UncompressedSize64 = uint64(len(plain))
	fh.CompressedSize64 = uint64(len(raw))
	fh.Extra = aesExtra(p)
	w, err := zw.CreateRaw(fh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// findNode returns the first node whose password search concluded (decrypted or
// locked) for the given path suffix, or the root for whole-file targets.
func findDecrypted(root *Node) *Node {
	var hit *Node
	root.Walk(func(n *Node) {
		if hit == nil && n.Status == StatusDecrypted {
			hit = n
		}
	})
	return hit
}

// TestAccelWinZipAES proves the batched accelerator path cracks a WinZip-AES
// entry (the Entry.Accel seam) through the full engine, and that the stub
// accelerator — not the CPU fallback — is what found it.
func TestAccelWinZipAES(t *testing.T) {
	const password = "Welcome1"
	plain := bytes.Repeat([]byte("nested-secret-payload "), 64)
	for _, strength := range []byte{1, 3} { // AES-128 and AES-256
		data := buildWinZipAES(t, []byte(password), strength, "doc.bin", plain)
		src := candidates.Explicit("wrong1", "nope", password, "unused")

		stub := &stubAccel{}
		res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
			src, Options{Accelerator: stub})
		if err != nil {
			t.Fatalf("strength %d: Process: %v", strength, err)
		}
		n := findDecrypted(res.Root)
		if n == nil {
			t.Fatalf("strength %d: no node decrypted via accelerator", strength)
		}
		if n.Password != password {
			t.Fatalf("strength %d: password = %q, want %q", strength, n.Password, password)
		}
		if stub.calls.Load() == 0 {
			t.Fatalf("strength %d: accelerator was never dispatched (CPU fallback took over)", strength)
		}
	}
}

// TestAccelWinZipAESFallback proves that when the accelerator reports the
// parameters unsupported, the engine transparently falls back to the CPU search
// and still recovers the password (no candidates lost across the fallback).
func TestAccelWinZipAESFallback(t *testing.T) {
	const password = "Welcome1"
	plain := []byte("fallback content")
	data := buildWinZipAES(t, []byte(password), 3, "doc.bin", plain)
	src := candidates.Explicit("wrong1", "wrong2", password)

	stub := &stubAccel{unsupported: true}
	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		src, Options{Accelerator: stub})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	n := findDecrypted(res.Root)
	if n == nil || n.Password != password {
		t.Fatalf("CPU fallback did not recover the password (node=%+v)", n)
	}
}

// TestAccelParityNoMatch proves a no-match accelerator sweep does not falsely
// report a hit and leaves the entry locked — identical to the CPU outcome.
func TestAccelParityNoMatch(t *testing.T) {
	data := buildWinZipAES(t, []byte("Welcome1"), 3, "doc.bin", []byte("x"))
	src := candidates.Explicit("nope1", "nope2", "nope3")

	stub := &stubAccel{}
	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		src, Options{Accelerator: stub})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	var locked bool
	res.Root.Walk(func(n *Node) {
		if n.Status == StatusLocked {
			locked = true
		}
		if n.Status == StatusDecrypted {
			t.Fatalf("accelerator falsely decrypted a node with wrong-only candidates: %q", n.Password)
		}
	})
	if !locked {
		t.Fatal("expected the encrypted entry to be locked")
	}
	if stub.calls.Load() == 0 {
		t.Fatal("accelerator was never dispatched")
	}
}

// TestAccelDMGOnDisk proves the whole-file Accelerable path end to end: the real
// on-disk encrcdsa v2 fixtures (carved from genuine macOS AES-128/256 images,
// password "opensesame") are cracked through the engine via the batched
// accelerator, and a wrong-only candidate list leaves them locked.
func TestAccelDMGOnDisk(t *testing.T) {
	for _, f := range []string{"encrcdsa-aes256.dmg", "encrcdsa-aes128.dmg"} {
		data, err := os.ReadFile("../../../xfileformats/formats/dmg/testdata/" + f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		stub := &stubAccel{}
		src := candidates.Explicit("wrongpassword", "secret", "opensesame", "later")
		res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
			src, Options{Accelerator: stub})
		if err != nil {
			t.Fatalf("%s: Process: %v", f, err)
		}
		if res.Root.Status != StatusDecrypted || res.Root.Password != "opensesame" {
			t.Fatalf("%s: got status=%v password=%q, want decrypted/opensesame",
				f, res.Root.Status, res.Root.Password)
		}
		if stub.calls.Load() == 0 {
			t.Fatalf("%s: accelerator was never dispatched", f)
		}

		// Wrong-only candidates must leave it locked (no false positive).
		stub2 := &stubAccel{}
		res2, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
			candidates.Explicit("nope", "bad", "wrong"), Options{Accelerator: stub2})
		if err != nil {
			t.Fatalf("%s: Process(wrong): %v", f, err)
		}
		if res2.Root.Status != StatusLocked {
			t.Fatalf("%s: wrong-only candidates gave status %v, want locked", f, res2.Root.Status)
		}
	}
}

// TestAccelMatchesCPU proves parity: with and without the accelerator the engine
// recovers the same password for the same input, so the offload changes speed,
// never results.
func TestAccelMatchesCPU(t *testing.T) {
	data, err := os.ReadFile("../../../xfileformats/formats/dmg/testdata/encrcdsa-aes256.dmg")
	if err != nil {
		t.Fatal(err)
	}
	src := func() CandidateSource { return candidates.Explicit("a", "b", "opensesame") }

	cpu, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)), src(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	gpu, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)), src(),
		Options{Accelerator: &stubAccel{}})
	if err != nil {
		t.Fatal(err)
	}
	if cpu.Root.Password != gpu.Root.Password || cpu.Root.Status != gpu.Root.Status {
		t.Fatalf("CPU vs accelerator mismatch: cpu=(%v,%q) gpu=(%v,%q)",
			cpu.Root.Status, cpu.Root.Password, gpu.Root.Status, gpu.Root.Password)
	}
}
