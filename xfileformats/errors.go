package xfileformats

import "errors"

var (
	// ErrUnknownFormat is returned by a Registry when no registered format
	// claims a stream.
	ErrUnknownFormat = errors.New("xfileformats: unknown or unsupported format")
	// ErrMalformed indicates the input is not a valid instance of the claimed
	// format (truncated, corrupt, or hostile).
	ErrMalformed = errors.New("xfileformats: malformed input")
	// ErrNotEncrypted indicates a recognized format that turns out not to be
	// encrypted (e.g. a PDF with no /Encrypt). The engine treats the file as a
	// plain leaf rather than an error.
	ErrNotEncrypted = errors.New("xfileformats: not encrypted")
	// ErrUnsupported indicates a recognized format whose specific variant is not
	// (yet) supported.
	ErrUnsupported = errors.New("xfileformats: unsupported variant")
	// ErrLimitExceeded indicates a safety limit was hit while parsing (e.g. too
	// many entries, declared size too large).
	ErrLimitExceeded = errors.New("xfileformats: limit exceeded")
)
