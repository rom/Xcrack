package archive

import (
	"archive/tar"
	"bytes"
	"io"

	"github.com/rom/xcrypto"
	"github.com/rom/xfileformats"
)

// Header-encrypted archives (7z `-mhe=on`, rar `-hp`) hide even their file
// listing behind the password, so they cannot be enumerated up front like a
// content-encrypted archive. They are modelled as a single password-gated entry:
// Verify tries to open the archive with a candidate password, and Open -- once
// unlocked -- repacks the decrypted members into a tar that the engine
// re-detects and decomposes. This keeps the whole archive behind one password
// without extending the container model.

// gatedEntry builds the single password-gated entry for a header-encrypted
// archive. verify reports whether a password opens the archive; openTar returns
// the decrypted members packed as a tar.
func gatedEntry(scheme string, verify func(pw []byte) (bool, error), openTar func(pw []byte) ([]byte, error)) *xfileformats.Entry {
	return &xfileformats.Entry{
		Path:      "contents",
		Encrypted: true,
		Challenge: &xcrypto.Challenge{Scheme: scheme, Cipher: xcrypto.CipherSpec{Algo: "aes", KeyBits: 256}},
		Verify:    verify,
		Open: func(pw []byte) (io.Reader, error) {
			data, err := openTar(pw)
			if err != nil {
				return nil, err
			}
			return bytes.NewReader(data), nil
		},
	}
}

// packMember is one decrypted archive member to repack.
type packMember struct {
	name string
	data []byte
}

// packTar writes members into a tar archive, bounded by maxDecompressed in total.
func packTar(members []packMember) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	var total int64
	for _, m := range members {
		if m.name == "" {
			continue
		}
		total += int64(len(m.data))
		if total > maxDecompressed {
			return nil, xfileformats.ErrLimitExceeded
		}
		h := &tar.Header{Name: m.name, Mode: 0o600, Size: int64(len(m.data)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
		if _, err := tw.Write(m.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
