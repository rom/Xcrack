//go:build !tpm

package securecache

// TPMBuilt reports whether this binary includes TPM-backed sealing. The default
// pure-Go build does not; build with -tags tpm to enable it.
const TPMBuilt = false

// TPMSealer reports that TPM support is unavailable in this build. Callers that
// asked for a TPM-sealed cache should surface this so the user knows to rebuild
// with -tags tpm.
func TPMSealer() (Sealer, error) { return nil, ErrTPMUnavailable }
