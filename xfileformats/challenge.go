package xfileformats

// Challenge is the small, serializable description of what it takes to test a
// password against an encrypted file or entry -- the heart of "probe once, test
// many". It carries no secrets of its own; it is derived entirely from the
// (untrusted) input and is safe to log or marshal.
type Challenge struct {
	// Format is the owning format's Name (e.g. "zip").
	Format string
	// Method is the concrete scheme, e.g. "zipcrypto", "winzip-aes-256".
	Method string
	// KDF describes how a password becomes a key.
	KDF KDFSpec
	// Cipher describes the bulk cipher.
	Cipher CipherSpec
	// Verifier is the small value used to confirm a password (e.g. the WinZip
	// 2-byte password-verification value, or a ZipCrypto check byte).
	Verifier []byte
	// Extra holds format-specific fields that do not fit the common shape.
	Extra map[string][]byte
	// DecryptedSizeHint is the expected plaintext size, or -1 if unknown. It is
	// a hint only and must not be trusted for allocation.
	DecryptedSizeHint int64
}

// KDFSpec describes a key-derivation function and its parameters.
type KDFSpec struct {
	// Algo is e.g. "pbkdf2-hmac-sha1", "pbkdf2-hmac-sha512", "none"
	// ("none" = the format derives keys by a bespoke schedule, e.g. ZipCrypto).
	Algo string
	// Iterations is the work factor for iterated KDFs (0 if N/A).
	Iterations int
	// Salt is the KDF salt (may be empty).
	Salt []byte
	// KeyLen is the derived key length in bytes (0 if N/A).
	KeyLen int
}

// CipherSpec describes the bulk cipher used to protect content.
type CipherSpec struct {
	// Algo is e.g. "aes-ctr", "aes-cbc", "rc4", "rc4-pkware".
	Algo string
	// KeyBits is the cipher key size in bits (e.g. 128, 256).
	KeyBits int
}
