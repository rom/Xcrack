package xfileformats

import "io"

// PeekSize is the number of leading bytes Detect implementations may inspect.
// It is small on purpose: detection is a cheap magic-byte check, not a parse.
const PeekSize = 512

// Peek reads up to PeekSize leading bytes from r for use with Registry.Detect
// or a Format's Detect. It never reads beyond PeekSize and tolerates short
// streams.
func Peek(r io.ReaderAt) ([]byte, error) {
	buf := make([]byte, PeekSize)
	n, err := r.ReadAt(buf, 0)
	if n > 0 {
		return buf[:n], nil
	}
	if err == io.EOF {
		return buf[:n], nil
	}
	return nil, err
}

// hasPrefix reports whether b starts with the given magic bytes.
func hasPrefix(b, magic []byte) bool {
	if len(b) < len(magic) {
		return false
	}
	for i := range magic {
		if b[i] != magic[i] {
			return false
		}
	}
	return true
}
