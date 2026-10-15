package xcrypto

import "errors"

var (
	// ErrWrongPassword indicates a verifier mismatch for the supplied password.
	ErrWrongPassword = errors.New("xcrypto: wrong password")
	// ErrUnsupported indicates a recognized scheme whose variant is not supported.
	ErrUnsupported = errors.New("xcrypto: unsupported scheme or variant")
	// ErrMalformed indicates the crypto parameters or ciphertext are malformed.
	ErrMalformed = errors.New("xcrypto: malformed crypto material")
)
