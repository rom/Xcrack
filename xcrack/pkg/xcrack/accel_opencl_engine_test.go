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
	"testing"

	"github.com/rom/xcrack/pkg/accel"
	"github.com/rom/xcrypto/candidates"
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
