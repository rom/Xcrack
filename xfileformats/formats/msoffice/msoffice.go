// Package msoffice implements detection and decryption of the legacy (pre-OOXML)
// Microsoft Office binary documents -- Word .doc, Excel .xls, and PowerPoint
// .ppt saved by Office 97 through 2003. These are OLE2/CFB compound files whose
// main streams are encrypted with one of the [MS-OFFCRYPTO] legacy schemes
// (RC4 CryptoAPI, Office 97/2000 RC4, or XOR obfuscation).
//
// The format is modelled as a container whose entries are the decrypted OLE
// streams (WordDocument / Workbook / PowerPoint Document and friends): a single
// password unlocks the whole document, and each decrypted stream is exposed as
// scannable content. All cryptography is delegated to
// xcrypto/scheme/officebinary; this package only locates the encryption
// parameters inside the compound file (the Word FIB, the Excel FilePass record,
// the PowerPoint CryptSession10Container) and moves bytes.
//
// Encrypted OOXML files are also CFB compound files but are handled by the
// ooxml format; this package declines them (ErrUnsupported) so the engine's
// detection fallback routes them correctly. Unencrypted legacy documents are
// reported ErrNotEncrypted and handled as a plain leaf.
package msoffice

import (
	"encoding/binary"
	"io"

	"github.com/rom/xfileformats"
	"github.com/rom/xfileformats/internal/cfb"
)

const (
	maxFileSize     = 1 << 30 // cap on the compound file we read into memory
	maxDecompressed = 1 << 30 // cap on a decrypted stream
)

// Format detects and decrypts legacy MS Office binary documents.
type Format struct{}

// New returns a legacy MS Office Format.
func New() *Format { return &Format{} }

// Register adds the legacy MS Office format to a registry.
func Register(r *xfileformats.Registry) { r.Register(New()) }

// Name implements xfileformats.Format.
func (f *Format) Name() string { return "msoffice" }

// Caps implements xfileformats.Format: a container of decrypted streams.
func (f *Format) Caps() xfileformats.Caps { return xfileformats.Caps{Container: true} }

// Detect claims any CFB/OLE2 compound file at the same confidence as the ooxml
// format. The two share the signature; the engine tries ooxml first (it is
// registered first and probes decisively), then falls back here for the legacy
// binaries. Entries declines anything that is not an encrypted legacy document.
func (f *Format) Detect(peek []byte) (float64, bool) {
	if cfb.IsCFB(peek) {
		return 0.7, true
	}
	return 0, false
}

// Entries parses the compound file, identifies the Office application, locates
// its encryption parameters, and returns one entry per decrypted stream. It
// returns ErrUnsupported for a non-legacy compound file (e.g. encrypted OOXML)
// and ErrNotEncrypted for an unencrypted legacy document.
func (f *Format) Entries(r io.ReaderAt, size int64) ([]*xfileformats.Entry, error) {
	if size <= 0 || size > maxFileSize {
		return nil, xfileformats.ErrUnsupported
	}
	data := make([]byte, size)
	if _, err := r.ReadAt(data, 0); err != nil && err != io.EOF {
		return nil, xfileformats.ErrMalformed
	}
	cf, err := cfb.Open(data)
	if err != nil {
		return nil, xfileformats.ErrUnsupported
	}
	// Encrypted OOXML wrappers are CFB too; leave them to the ooxml format.
	if _, ok := cf.Stream("EncryptionInfo"); ok {
		return nil, xfileformats.ErrUnsupported
	}
	switch {
	case hasStream(cf, "WordDocument"):
		return docEntries(cf)
	case hasStream(cf, "Workbook"), hasStream(cf, "Book"):
		return xlsEntries(cf)
	case hasStream(cf, "PowerPoint Document"):
		return pptEntries(cf)
	default:
		return nil, xfileformats.ErrUnsupported
	}
}

func hasStream(cf *cfb.File, name string) bool {
	_, ok := cf.Stream(name)
	return ok
}

func u16(b []byte, off int) uint16 { return binary.LittleEndian.Uint16(b[off:]) }
func u32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }
