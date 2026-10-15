package archive

import (
	stdtar "archive/tar"
	"bytes"
	stdgzip "compress/gzip"
	"testing"
)

// FuzzEntries runs each archive parser on arbitrary bytes; invariant: no panic.
func FuzzEntries(f *testing.F) {
	var gb bytes.Buffer
	gw := stdgzip.NewWriter(&gb)
	gw.Write([]byte("hello"))
	gw.Close()
	f.Add(gb.Bytes())

	var tb bytes.Buffer
	tw := stdtar.NewWriter(&tb)
	tw.WriteHeader(&stdtar.Header{Name: "f", Size: 2, Typeflag: stdtar.TypeReg})
	tw.Write([]byte("hi"))
	tw.Close()
	f.Add(tb.Bytes())

	f.Add([]byte("From: a\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B--\r\n"))
	f.Add([]byte("BZh9"))
	f.Add([]byte("7z\xbc\xaf\x27\x1c"))
	f.Add([]byte("Rar!\x1a\x07\x00"))
	f.Add([]byte{0x1f, 0x8b})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		r := bytes.NewReader(b)
		gzipFormat{}.Detect(b)
		xzFormat{}.Detect(b)
		bzip2Format{}.Detect(b)
		tarFormat{}.Detect(b)
		emlFormat{}.Detect(b)
		sevenzipFormat{}.Detect(b)
		rarFormat{}.Detect(b)
		gzipFormat{}.Entries(r, int64(len(b)))
		xzFormat{}.Entries(r, int64(len(b)))
		bzip2Format{}.Entries(r, int64(len(b)))
		tarFormat{}.Entries(r, int64(len(b)))
		emlFormat{}.Entries(r, int64(len(b)))
		sevenzipFormat{}.Entries(r, int64(len(b)))
		rarFormat{}.Entries(r, int64(len(b)))
	})
}
