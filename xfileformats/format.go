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
	"context"
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

// AccelKDF describes a batchable PBKDF2-HMAC-SHA1 key derivation that an
// external GPU/OpenCL tier can run across many candidate passwords at once,
// paired with a Finish closure that turns one derived key into a pass/fail
// verdict. It lets the recovery engine offload the expensive per-candidate KDF
// to a batch accelerator WITHOUT this library (or xcrypto) depending on any
// accelerator package: it is plain data plus a closure.
//
// A format exposes it only when its password verification is dominated by a
// single shared (Salt, Iter, DKLen) PBKDF2-HMAC-SHA1 run -- the one primitive
// the accelerator implements. The engine always keeps the CPU Verify /
// Entry.Verify path as the authoritative fallback, so a nil AccelKDF, or one
// whose parameters the accelerator cannot serve, simply means "no
// acceleration". Finish re-checks every candidate the accelerator flags, so the
// accelerator is never trusted to decide correctness on its own and a faulty
// backend can only slow a search, never cause a false positive.
type AccelKDF struct {
	// PRF selects the HMAC hash the accelerator must use: "" or "sha1" (the
	// default, PBKDF2-HMAC-SHA1), "sha256" (RAR5-class), or "sha512"
	// (SQLCipher-v4-class). The engine dispatches to the matching batch kernel and
	// falls back to the CPU for any value its backend cannot serve.
	PRF string
	// Salt, Iter, DKLen are the exact PBKDF2 parameters the accelerator must
	// derive with -- byte-identical to what the CPU verifier uses (e.g. the DMG
	// verifier's fixed 20-byte salt, not the raw stored salt).
	Salt  []byte
	Iter  int
	DKLen int
	// Finish reports whether password is correct given
	// dk = PBKDF2-HMAC-SHA1(password, Salt, Iter, DKLen). It performs the same
	// authoritative verifier check Verify would, but with the KDF already done,
	// so the heavy work happens once on the accelerator. It must be safe for
	// concurrent use. password is supplied for schemes that need it alongside the
	// derived key (most ignore it).
	Finish func(dk, password []byte) bool
}

// Accelerable is an optional capability of a whole-file Encrypted format whose
// password verification is one shared PBKDF2-HMAC-SHA1 derivation (DMG, ODF,
// SQLCipher, ...). The engine type-asserts for it and, when an accelerator is
// configured, offloads the keyspace sweep to the batch KDF, falling back to the
// per-candidate Verify otherwise. Container entries expose the same thing via
// Entry.Accel instead.
type Accelerable interface {
	Encrypted
	// AccelKDF returns the batchable derivation for an already-probed Challenge,
	// or ok=false when this file cannot be accelerated (unsupported version,
	// parameters outside the shared primitive, etc.).
	AccelKDF(ch *xcrypto.Challenge) (AccelKDF, bool)
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
	// Accel, when non-nil, offers a batchable PBKDF2-HMAC-SHA1 derivation for this
	// entry so an external GPU tier can sweep the keyspace in bulk. The engine
	// uses it only when an accelerator is configured and its parameters fit the
	// backend; it always falls back to Verify otherwise. Its Finish closure is
	// authoritative, so acceleration can never cause a false positive. nil means
	// the entry is not accelerable (ZipCrypto, unencrypted, ...).
	Accel *AccelKDF
	// Open returns the entry's decrypted, decompressed content as a bounded
	// reader. password is required iff Encrypted and ignored otherwise.
	Open func(password []byte) (io.Reader, error)
	// KeyRecover, when non-nil, decrypts this entry via a known-plaintext key
	// recovery instead of a password, for schemes where that applies (currently
	// ZipCrypto). known is plaintext aligned to the start of the entry's encrypted
	// data stream — for a STORED entry, the file's own leading bytes. offload is a
	// scheme-specific external engine (e.g. a zipcrypto.Offloader such as
	// ExternalBkcrack) used instead of the compute-heavy in-process search; pass
	// nil to use the in-process attack. It returns the decrypted, decompressed
	// content on success, ok=false when the known plaintext does not fit the
	// scheme (so the caller falls back to a password search). The recovered state
	// is always re-validated, so a wrong `known` cannot yield a false positive.
	// ctx bounds the (compute-heavy) in-process search.
	KeyRecover func(ctx context.Context, known []byte, offload any) (content io.Reader, ok bool, err error)
}
