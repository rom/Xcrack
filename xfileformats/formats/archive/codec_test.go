package archive

import (
	"archive/tar"
	"bytes"
	"io"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

func zstdCompress(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func lz4Compress(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := lz4.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestZstdLz4RoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte("encrypted-file-lives-here "), 200)
	// zstd
	{
		c := zstdCompress(t, payload)
		if conf, ok := (zstdFormat{}).Detect(c); !ok || conf == 0 {
			t.Fatal("zstd not detected")
		}
		es, err := (zstdFormat{}).Entries(bytes.NewReader(c), int64(len(c)))
		if err != nil || len(es) != 1 {
			t.Fatalf("zstd Entries: err=%v n=%d", err, len(es))
		}
		r, err := es[0].Open(nil)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(r)
		if !bytes.Equal(got, payload) {
			t.Fatal("zstd content mismatch")
		}
	}
	// lz4
	{
		c := lz4Compress(t, payload)
		if conf, ok := (lz4Format{}).Detect(c); !ok || conf == 0 {
			t.Fatal("lz4 not detected")
		}
		es, err := (lz4Format{}).Entries(bytes.NewReader(c), int64(len(c)))
		if err != nil || len(es) != 1 {
			t.Fatalf("lz4 Entries: err=%v n=%d", err, len(es))
		}
		r, err := es[0].Open(nil)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(r)
		if !bytes.Equal(got, payload) {
			t.Fatal("lz4 content mismatch")
		}
	}
}

// TestZstdWrappedTar proves the .tar.zst recursion path mechanically: a tar
// holding a file, compressed with zstd, decodes to the tar, which the tar
// format then unpacks — the chain the engine follows to reach an encrypted file.
func TestZstdWrappedTar(t *testing.T) {
	payload := []byte("the secret inner file content")
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	if err := tw.WriteHeader(&tar.Header{Name: "secret.bin", Mode: 0o600, Size: int64(len(payload))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	comp := zstdCompress(t, tarBuf.Bytes())

	if _, ok := (zstdFormat{}).Detect(comp); !ok {
		t.Fatal("zstd not detected")
	}
	es, err := (zstdFormat{}).Entries(bytes.NewReader(comp), int64(len(comp)))
	if err != nil || len(es) != 1 {
		t.Fatalf("zstd Entries: err=%v n=%d", err, len(es))
	}
	r, _ := es[0].Open(nil)
	inner, _ := io.ReadAll(r)
	if _, ok := (tarFormat{}).Detect(inner); !ok {
		t.Fatal("inner stream not detected as tar")
	}
	tes, err := (tarFormat{}).Entries(bytes.NewReader(inner), int64(len(inner)))
	if err != nil || len(tes) == 0 {
		t.Fatalf("tar Entries: err=%v n=%d", err, len(tes))
	}
	tr, _ := tes[0].Open(nil)
	got, _ := io.ReadAll(tr)
	if !bytes.Equal(got, payload) {
		t.Fatalf("tar.zst inner content mismatch: %q", got)
	}
}
