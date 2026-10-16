package xcrypto

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// ChallengeExportVersion is the schema version of an ExportedChallenge envelope.
const ChallengeExportVersion = 1

// ExportedChallenge is the portable, self-describing JSON form of a Challenge.
// It is the interchange used to offload heavy cracking to an external engine
// (e.g. a GPU/OpenCL tier): Xcrack probes a file, exports the challenge, an
// external engine recovers the password, and the result is re-imported (see
// RecoveredPassword) to continue decryption. Bytes are hex-encoded so the
// envelope is readable and easy to bridge to other tools' hash formats.
//
// The envelope carries whatever the producing scheme put in the Challenge; it
// is not a guarantee that every scheme's challenge is complete enough for an
// external cracker. The `scheme` field is the stable discriminator an external
// bridge keys on.
type ExportedChallenge struct {
	Version           int               `json:"xcrack_challenge_version"`
	Scheme            string            `json:"scheme"`
	Source            string            `json:"source,omitempty"`
	KDF               ExportedKDF       `json:"kdf"`
	Cipher            ExportedCipher    `json:"cipher"`
	VerifierHex       string            `json:"verifier_hex,omitempty"`
	Extra             map[string]string `json:"extra,omitempty"`
	DecryptedSizeHint int64             `json:"decrypted_size_hint,omitempty"`
}

// ExportedKDF mirrors KDFSpec with a hex-encoded salt.
type ExportedKDF struct {
	Algo       string `json:"algo,omitempty"`
	Iterations int    `json:"iterations,omitempty"`
	SaltHex    string `json:"salt_hex,omitempty"`
	KeyLen     int    `json:"key_len,omitempty"`
}

// ExportedCipher mirrors CipherSpec.
type ExportedCipher struct {
	Algo    string `json:"algo,omitempty"`
	KeyBits int    `json:"key_bits,omitempty"`
}

// ExportChallenge builds an ExportedChallenge from ch. source is optional
// provenance (e.g. the node's tree path).
func ExportChallenge(ch *Challenge, source string) *ExportedChallenge {
	if ch == nil {
		return nil
	}
	e := &ExportedChallenge{
		Version: ChallengeExportVersion,
		Scheme:  ch.Scheme,
		Source:  source,
		KDF: ExportedKDF{
			Algo:       ch.KDF.Algo,
			Iterations: ch.KDF.Iterations,
			SaltHex:    hex.EncodeToString(ch.KDF.Salt),
			KeyLen:     ch.KDF.KeyLen,
		},
		Cipher:            ExportedCipher{Algo: ch.Cipher.Algo, KeyBits: ch.Cipher.KeyBits},
		VerifierHex:       hex.EncodeToString(ch.Verifier),
		DecryptedSizeHint: ch.DecryptedSizeHint,
	}
	if len(ch.Extra) > 0 {
		e.Extra = make(map[string]string, len(ch.Extra))
		for k, v := range ch.Extra {
			e.Extra[k] = hex.EncodeToString(v)
		}
	}
	return e
}

// Challenge reconstructs a Challenge from the envelope. It returns an error if a
// hex field is malformed.
func (e *ExportedChallenge) Challenge() (*Challenge, error) {
	salt, err := decodeHex(e.KDF.SaltHex)
	if err != nil {
		return nil, fmt.Errorf("kdf.salt_hex: %w", err)
	}
	ver, err := decodeHex(e.VerifierHex)
	if err != nil {
		return nil, fmt.Errorf("verifier_hex: %w", err)
	}
	ch := &Challenge{
		Scheme:            e.Scheme,
		KDF:               KDFSpec{Algo: e.KDF.Algo, Iterations: e.KDF.Iterations, Salt: salt, KeyLen: e.KDF.KeyLen},
		Cipher:            CipherSpec{Algo: e.Cipher.Algo, KeyBits: e.Cipher.KeyBits},
		Verifier:          ver,
		DecryptedSizeHint: e.DecryptedSizeHint,
	}
	if len(e.Extra) > 0 {
		ch.Extra = make(map[string][]byte, len(e.Extra))
		// Decode in sorted key order for deterministic error reporting.
		keys := make([]string, 0, len(e.Extra))
		for k := range e.Extra {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b, err := decodeHex(e.Extra[k])
			if err != nil {
				return nil, fmt.Errorf("extra[%q]: %w", k, err)
			}
			ch.Extra[k] = b
		}
	}
	return ch, nil
}

// MarshalChallenge exports ch to indented JSON.
func MarshalChallenge(ch *Challenge, source string) ([]byte, error) {
	return json.MarshalIndent(ExportChallenge(ch, source), "", "  ")
}

// UnmarshalChallenge parses an exported-challenge JSON document back to a
// Challenge. It rejects an unknown or missing schema version.
func UnmarshalChallenge(data []byte) (*Challenge, string, error) {
	var e ExportedChallenge
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, "", err
	}
	if e.Version != ChallengeExportVersion {
		return nil, "", fmt.Errorf("unsupported challenge export version %d (want %d)", e.Version, ChallengeExportVersion)
	}
	ch, err := e.Challenge()
	if err != nil {
		return nil, "", err
	}
	return ch, e.Source, nil
}

// RecoveredPassword is the envelope an external engine returns after cracking an
// ExportedChallenge; importing it lets Xcrack resume decryption.
type RecoveredPassword struct {
	Version  int    `json:"xcrack_recovered_version"`
	Source   string `json:"source,omitempty"`
	Password string `json:"password"`
}

// RecoveredPasswordVersion is the schema version of a RecoveredPassword.
const RecoveredPasswordVersion = 1

// MarshalRecoveredPassword encodes a recovered-password result.
func MarshalRecoveredPassword(source, password string) ([]byte, error) {
	return json.MarshalIndent(RecoveredPassword{
		Version:  RecoveredPasswordVersion,
		Source:   source,
		Password: password,
	}, "", "  ")
}

// UnmarshalRecoveredPassword parses a recovered-password result.
func UnmarshalRecoveredPassword(data []byte) (*RecoveredPassword, error) {
	var r RecoveredPassword
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	if r.Version != RecoveredPasswordVersion {
		return nil, fmt.Errorf("unsupported recovered-password version %d (want %d)", r.Version, RecoveredPasswordVersion)
	}
	return &r, nil
}

func decodeHex(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.New("invalid hex")
	}
	return b, nil
}
