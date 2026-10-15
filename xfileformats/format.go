// Package xfileformats is a standalone, policy-free library for inspecting
// password-protected and encrypted files: detect a format, probe its
// encryption parameters, verify/decrypt with a GIVEN password, and enumerate
// the entries of container formats.
//
// It deliberately knows nothing about candidate password lists, search
// strategy, concurrency, or recursion policy -- those belong to the caller
// (e.g. the Xcrack engine). It never executes or renders file content; it only
// derives keys and moves bytes, which makes it safe to point at hostile input.
package xfileformats

import (
	"io"

	"github.com/rom/xcrypto"
)

// Caps advertises what a Format can do.
type Caps struct {
	// Encrypted means the format is whole-file password-protected and
	// implements the Encrypted interface (e.g. an encrypted OOXML wrapper, PDF).
	Encrypted bool
	// Container means the format holds child entries and implements the
	// Container interface (e.g. ZIP, tar). A container may have per-entry
	// encryption even when Encrypted (whole-file) is false.
	Container bool
	// Explodable means the format is a document that CAN be decomposed into its
	// internal parts on request, but is treated as a leaf by default.
	Explodable bool
}

// Format is the minimal interface every supported file format implements.
// Implementations must be safe for concurrent use: detection and probing read
// only their arguments and hold no mutable shared state.
type Format interface {
	// Name is a short, stable identifier, e.g. "zip", "ooxml", "pdf".
	Name() string
	// Detect inspects a bounded peek of the stream head and reports a confidence
	// in [0,1] and whether this format claims the stream. It must not read
	// beyond peek and must not panic on arbitrary input.
	Detect(peek []byte) (confidence float64, ok bool)
	// Caps reports the format's capabilities.
	Caps() Caps
}

// Encrypted is implemented by whole-file password-protected formats. It is NOT
// implemented by containers whose encryption is per-entry (see Container/Entry).
type Encrypted interface {
	Format
	// Probe extracts the verifiable crypto material once, so a caller can test
	// many candidate passwords cheaply without re-parsing the file. It must be
	// allocation-bounded and must not trust sizes declared in the input.
	Probe(r io.ReaderAt, size int64) (*xcrypto.Challenge, error)
	// Verify tests a single password against a probed Challenge, performing the
	// (deliberately expensive) KDF and an authoritative verifier check. On
	// success it returns the derived content key so Decrypt need not re-derive
	// it. It must be safe to call concurrently for one Challenge.
	Verify(ch *xcrypto.Challenge, password []byte) (ok bool, key []byte, err error)
	// Decrypt streams plaintext given a verified key (or the password, if the
	// format derives per-call). The returned reader is bounded by the engine's
	// limits; implementations should not materialize unbounded output.
	Decrypt(r io.ReaderAt, size int64, ch *xcrypto.Challenge, key []byte) (io.Reader, error)
}

// Container is implemented by archives and compound files. Its entries may be
// individually encrypted; in that case each Entry carries a Challenge and its
// Verify/Open closures accept the password. The container itself does not
// search for passwords -- that is the caller's job.
type Container interface {
	Format
	// Entries lists child entries without fully extracting them. It must enforce
	// its own bounds (entry count, declared sizes are untrusted) and must not
	// panic on malformed input.
	Entries(r io.ReaderAt, size int64) ([]*Entry, error)
}

// Entry is one child of a container.
type Entry struct {
	// Path is the normalized path within the container (no "..", no absolute
	// components, forward slashes).
	Path string
	// Size is the declared uncompressed size. It is UNTRUSTED and provided only
	// as a hint; callers must bound actual reads independently.
	Size int64
	// Encrypted reports whether this entry is password-protected.
	Encrypted bool
	// Challenge describes the entry's encryption for reporting and external
	// testing. Non-nil iff Encrypted.
	Challenge *xcrypto.Challenge
	// Verify tests one password against this entry, performing an authoritative
	// check (not just a fast-reject heuristic). Safe for concurrent use. nil for
	// unencrypted entries (treat as always-ok).
	Verify func(password []byte) (ok bool, err error)
	// Open returns the entry's decrypted, decompressed content as a bounded
	// reader. password is required iff Encrypted and ignored otherwise.
	Open func(password []byte) (io.Reader, error)
}
