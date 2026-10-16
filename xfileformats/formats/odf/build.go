package odf

import (
	stdzip "archive/zip"
	"bytes"
	"encoding/base64"
	"fmt"
	"hash/crc32"

	xodf "github.com/rom/xcrypto/scheme/odf"
)

// BuildEncryptedODF builds a minimal encrypted ODF text package with one
// encrypted content.xml, for round-trip tests and tooling. spin/iterations
// should be small in tests.
func BuildEncryptedODF(password, content []byte, iterations int) ([]byte, error) {
	raw, p, err := xodf.EncryptEntry(password, content, iterations)
	if err != nil {
		return nil, err
	}
	b64 := base64.StdEncoding.EncodeToString
	manifest := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>`+
		`<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">`+
		`<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml" manifest:size="%d">`+
		`<manifest:encryption-data manifest:checksum-type="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#sha256-1k" manifest:checksum="%s">`+
		`<manifest:algorithm manifest:algorithm-name="http://www.w3.org/2001/04/xmlenc#aes256-cbc" manifest:initialisation-vector="%s"/>`+
		`<manifest:key-derivation manifest:key-derivation-name="PBKDF2" manifest:key-size="32" manifest:iteration-count="%d" manifest:salt="%s"/>`+
		`<manifest:start-key-generation manifest:start-key-generation-name="http://www.w3.org/2000/09/xmldsig#sha256" manifest:key-size="32"/>`+
		`</manifest:encryption-data></manifest:file-entry>`+
		`<manifest:file-entry manifest:full-path="mimetype" manifest:media-type="application/vnd.oasis.opendocument.text"/>`+
		`</manifest:manifest>`,
		len(content), b64(p.Checksum), b64(p.IV), p.Iterations, b64(p.Salt))

	var buf bytes.Buffer
	zw := stdzip.NewWriter(&buf)
	mime := []byte("application/vnd.oasis.opendocument.text")
	mw, err := zw.CreateRaw(storedHeader("mimetype", mime))
	if err != nil {
		return nil, err
	}
	mw.Write(mime)
	cw, err := zw.CreateRaw(storedHeader("content.xml", raw))
	if err != nil {
		return nil, err
	}
	cw.Write(raw)
	w, err := zw.Create("META-INF/manifest.xml")
	if err != nil {
		return nil, err
	}
	w.Write([]byte(manifest))
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func storedHeader(name string, data []byte) *stdzip.FileHeader {
	return &stdzip.FileHeader{
		Name:               name,
		Method:             stdzip.Store,
		CRC32:              crc32.ChecksumIEEE(data),
		CompressedSize64:   uint64(len(data)),
		UncompressedSize64: uint64(len(data)),
	}
}

// BuildEncryptedODFGCM builds a minimal encrypted ODF text package whose
// content.xml uses the ODF 1.3 authenticated AES-256-GCM variant (no 1K
// checksum; the GCM tag is the verifier). For round-trip tests and tooling.
func BuildEncryptedODFGCM(password, content []byte, iterations int) ([]byte, error) {
	raw, p, err := xodf.EncryptEntryGCM(password, content, iterations)
	if err != nil {
		return nil, err
	}
	b64 := base64.StdEncoding.EncodeToString
	manifest := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>`+
		`<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3">`+
		`<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml" manifest:size="%d">`+
		`<manifest:encryption-data manifest:checksum-type="" manifest:checksum="">`+
		`<manifest:algorithm manifest:algorithm-name="http://www.w3.org/2009/xmlenc11#aes256-gcm" manifest:initialisation-vector="%s"/>`+
		`<manifest:key-derivation manifest:key-derivation-name="PBKDF2" manifest:key-size="32" manifest:iteration-count="%d" manifest:salt="%s"/>`+
		`<manifest:start-key-generation manifest:start-key-generation-name="http://www.w3.org/2000/09/xmldsig#sha256" manifest:key-size="32"/>`+
		`</manifest:encryption-data></manifest:file-entry>`+
		`<manifest:file-entry manifest:full-path="mimetype" manifest:media-type="application/vnd.oasis.opendocument.text"/>`+
		`</manifest:manifest>`,
		len(content), b64(p.IV), p.Iterations, b64(p.Salt))

	var buf bytes.Buffer
	zw := stdzip.NewWriter(&buf)
	mime := []byte("application/vnd.oasis.opendocument.text")
	mw, err := zw.CreateRaw(storedHeader("mimetype", mime))
	if err != nil {
		return nil, err
	}
	mw.Write(mime)
	cw, err := zw.CreateRaw(storedHeader("content.xml", raw))
	if err != nil {
		return nil, err
	}
	cw.Write(raw)
	w, err := zw.Create("META-INF/manifest.xml")
	if err != nil {
		return nil, err
	}
	w.Write([]byte(manifest))
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
