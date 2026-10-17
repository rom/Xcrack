package vbaproject

import (
	"bytes"
	"testing"
)

// FuzzParseProject checks the VBA carrier parser never panics on hostile input
// (arbitrary bytes, truncated CFB/zip, malformed PROJECT streams).
func FuzzParseProject(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"))
	f.Add([]byte("PK\x03\x04 not really a zip"))
	f.Add(cfbWithProject(dpbHashed))
	f.Add(cfbWithProject("not-hex"))
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := ParseProject(data)
		_ = err
		_ = res
		// Probe must also survive arbitrary bytes.
		_, _ = New().Probe(bytes.NewReader(data), int64(len(data)))
	})
}
