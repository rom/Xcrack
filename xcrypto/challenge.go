// Package xcrypto is a standalone cryptographic library and cracking engine for
// attacking password-protected data. It is split so other tools can reuse it
// without any file-format or recursion code:
//
//   - the primitives (sub-package prim): PBKDF2, AES modes, RC4, Office hashing;
//   - the schemes (sub-package scheme/...): concrete encryption schemes that turn
//     a Challenge + password into a verify/decrypt result;
//   - candidate generation (sub-packages candidate, pattern); and
//   - the attack engine (sub-package attack): the concurrent password search.
//
// A Challenge is the small, serializable description of an encrypted blob. A
// producer (e.g. a file-format parser) builds a Challenge; this library turns a
// Challenge + candidate password into a verification or decryption. The
// Challenge carries no long-lived secret; it is derived from the input.
package xcrypto

// Challenge describes what it takes to test a password against an encrypted
// blob -- the heart of "probe once, test many".
type Challenge struct {
	// Scheme is the concrete encryption scheme, e.g. "zipcrypto",
	// "winzip-aes-256", "ooxml-agile", "ooxml-standard".
	Scheme string
	// KDF describes how a password becomes a key.
	KDF KDFSpec
	// Cipher describes the bulk cipher.
	Cipher CipherSpec
	// Verifier holds the small value used to confirm a password (scheme-specific:
	// a ZipCrypto check byte, the WinZip 2-byte verifier, an Office verifier hash).
	Verifier []byte
	// Extra holds scheme-specific fields that do not fit the common shape.
	Extra map[string][]byte
	// DecryptedSizeHint is the expected plaintext size, or -1 if unknown. A hint
	// only; never trust it for allocation.
	DecryptedSizeHint int64
}

// KDFSpec describes a key-derivation function and its parameters.
type KDFSpec struct {
	// Algo: "pbkdf2-hmac-sha1", "office-agile-sha512", "office-standard-sha1",
	// "none" (bespoke schedule, e.g. ZipCrypto), etc.
	Algo       string
	Iterations int
	Salt       []byte
	KeyLen     int // derived key length in bytes
}

// CipherSpec describes the bulk cipher protecting content.
type CipherSpec struct {
	// Algo: "aes-ctr", "aes-cbc", "aes-ecb", "rc4", "rc4-pkware".
	Algo    string
	KeyBits int
}
