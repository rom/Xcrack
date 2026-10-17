//go:build opencl

// This file is built only with `-tags opencl` (and only on a host with an
// OpenCL runtime). It proves the live crack loop genuinely offloads to the real
// GPU/OpenCL kernel — not just the pure-Go stub in accel_engine_test.go — by
// detecting a device, self-testing the kernel against the CPU reference, and
// then cracking real fixtures through the full engine with that device wired in
// as Options.Accelerator. It is never built by CI or the default `go build`.

package xcrack

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rom/xcrack/pkg/accel"
	"github.com/rom/xcrypto/candidates"
	fooxml "github.com/rom/xfileformats/formats/ooxml"
)

// realAccel detects a device and validates the kernel, skipping the test when
// no usable OpenCL device is present so the suite still passes on a bare host.
func realAccel(t *testing.T) accel.Accelerator {
	t.Helper()
	if err := accel.GPUSelfTest(); err != nil {
		t.Skipf("no usable OpenCL device / kernel self-test failed: %v", err)
	}
	a, err := accel.Detect()
	if err != nil {
		t.Skipf("accel.Detect: %v", err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

// TestOpenCLWinZipAESLive cracks a WinZip-AES entry through the engine with the
// real OpenCL accelerator doing the PBKDF2-HMAC-SHA1 sweep.
func TestOpenCLWinZipAESLive(t *testing.T) {
	acc := realAccel(t)
	const password = "Welcome1"
	plain := bytes.Repeat([]byte("gpu-path-payload "), 32)
	for _, strength := range []byte{1, 3} {
		data := buildWinZipAES(t, []byte(password), strength, "doc.bin", plain)
		res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
			candidates.Explicit("wrong", "nope", password), Options{Accelerator: acc})
		if err != nil {
			t.Fatalf("strength %d: Process: %v", strength, err)
		}
		n := findDecrypted(res.Root)
		if n == nil || n.Password != password {
			t.Fatalf("strength %d: GPU path did not recover the password (node=%+v)", strength, n)
		}
	}
}

// TestOpenCLDMGLive cracks the real on-disk encrcdsa fixtures through the engine
// with the OpenCL accelerator (the high-iteration DMG KDF is exactly the case a
// GPU tier exists to accelerate).
func TestOpenCLDMGLive(t *testing.T) {
	acc := realAccel(t)
	for _, f := range []string{"encrcdsa-aes256.dmg", "encrcdsa-aes128.dmg"} {
		data, err := os.ReadFile("../../../xfileformats/formats/dmg/testdata/" + f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
			candidates.Explicit("wrongpassword", "opensesame"), Options{Accelerator: acc})
		if err != nil {
			t.Fatalf("%s: Process: %v", f, err)
		}
		if res.Root.Status != StatusDecrypted || res.Root.Password != "opensesame" {
			t.Fatalf("%s: GPU path got (%v,%q), want decrypted/opensesame",
				f, res.Root.Status, res.Root.Password)
		}
	}
}

// TestOpenCLODFLive cracks the real LibreOffice ODF fixture through the engine
// with the OpenCL accelerator. ODF exercises the new PreHash path: the kernel
// runs PBKDF2-HMAC-SHA1 over SHA-256(password), not the raw password.
func TestOpenCLODFLive(t *testing.T) {
	acc := realAccel(t)
	data, err := os.ReadFile("../../../xfileformats/formats/odf/testdata/libreoffice-aes256cbc.odt")
	if err != nil {
		t.Fatalf("read ODF fixture: %v", err)
	}
	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit("wrong", "nope", "opensesame"), Options{Accelerator: acc})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if n := findDecrypted(res.Root); n == nil || n.Password != "opensesame" {
		t.Fatalf("GPU ODF path did not recover the password (node=%+v)", n)
	}
}

// TestOpenCLRAR5Live generates a RAR5 archive with the real `rar` tool and
// cracks it through the engine with the OpenCL accelerator doing the
// PBKDF2-HMAC-SHA256 sweep that produces the 8-byte password-check value.
func TestOpenCLRAR5Live(t *testing.T) {
	acc := realAccel(t)
	rarBin, err := exec.LookPath("rar")
	if err != nil {
		t.Skip("rar CLI not available")
	}
	dir := t.TempDir()
	payload := filepath.Join(dir, "msg.txt")
	if err := os.WriteFile(payload, []byte("rar5 gpu payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const pw = "Midsommar2024!"
	arc := filepath.Join(dir, "a.rar")
	if out, err := exec.Command(rarBin, "a", "-p"+pw, "-idq", arc, payload).CombinedOutput(); err != nil {
		t.Fatalf("rar a: %v\n%s", err, out)
	}
	data, err := os.ReadFile(arc)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit("wrong", "nope", pw), Options{Accelerator: acc})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if n := findDecrypted(res.Root); n == nil || n.Password != pw {
		t.Fatalf("GPU RAR5 path did not recover the password (node=%+v)", n)
	}
}

// TestOpenCLOfficeAgileLive cracks an agile OOXML (Office 2010+, SHA-512 spin)
// document through the engine with the OpenCL accelerator running the Office
// iterated-hash spin — the dominant cost of every modern Office document.
func TestOpenCLOfficeAgileLive(t *testing.T) {
	acc := realAccel(t)
	const password = "Secret-Office-99"
	pkg := bytes.Repeat([]byte("inner ooxml package bytes "), 64)
	data, err := fooxml.BuildEncryptedAgile([]byte(password), pkg, 4000)
	if err != nil {
		t.Fatalf("build agile OOXML: %v", err)
	}
	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit("wrong", "nope", password), Options{Accelerator: acc})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if n := findDecrypted(res.Root); n == nil || n.Password != password {
		t.Fatalf("GPU Office-agile path did not recover the password (node=%+v)", n)
	}
}
