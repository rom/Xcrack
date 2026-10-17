package xcrack

import (
	"archive/tar"
	"bytes"
	"context"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/rom/xcrypto/candidates"
)

// TestRecurseEncryptedInsideTarZst is the end-to-end proof that a password-
// protected file wrapped in a modern codec is now reachable: a WinZip-AES ZIP
// is tarred and zstd-compressed into a .tar.zst, and the engine decompresses
// (zstd -> tar) down to the encrypted entry and cracks it — a chain that was
// impossible before the zstd codec was added.
func TestRecurseEncryptedInsideTarZst(t *testing.T) {
	const password = "Welcome1"
	plain := bytes.Repeat([]byte("the-decrypted-secret "), 32)
	zipBytes := buildWinZipAES(t, []byte(password), 3, "secret.bin", plain)

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	if err := tw.WriteHeader(&tar.Header{Name: "inner.zip", Mode: 0o600, Size: int64(len(zipBytes))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(zipBytes); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	var zb bytes.Buffer
	zw, err := zstd.NewWriter(&zb)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(tarBuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	data := zb.Bytes()

	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit("nope", "wrong", password), Options{})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	n := findDecrypted(res.Root)
	if n == nil || n.Password != password {
		t.Fatalf("encrypted file inside .tar.zst not cracked (node=%+v)", n)
	}
}
