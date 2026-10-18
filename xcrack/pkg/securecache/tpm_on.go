//go:build tpm

package securecache

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/google/go-tpm/legacy/tpm2"
)

// TPMBuilt reports that this binary includes TPM-backed sealing.
const TPMBuilt = true

// tpmDevices are tried in order when XCRACK_TPM_DEVICE is unset.
var tpmDevices = []string{"/dev/tpmrm0", "/dev/tpm0"}

// srkTemplate is a standard Storage Root Key: a restricted RSA-2048 decryption
// (storage) primary in the owner hierarchy. It is deterministic, so the same
// SRK — and thus the ability to Load an object sealed on an earlier run — is
// reproduced on every run of the same TPM, while a different TPM produces a
// different SRK and cannot unseal the blob.
var srkTemplate = tpm2.Public{
	Type:       tpm2.AlgRSA,
	NameAlg:    tpm2.AlgSHA256,
	Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt,
	RSAParameters: &tpm2.RSAParams{
		Symmetric:  &tpm2.SymScheme{Alg: tpm2.AlgAES, KeyBits: 128, Mode: tpm2.AlgCFB},
		KeyBits:    2048,
		ModulusRaw: make([]byte, 256),
	},
}

// tpmSealer seals the cache's data-encryption key to the host TPM.
type tpmSealer struct {
	mu sync.Mutex // the TPM is a single shared device
}

// TPMSealer opens the TPM once to confirm it is reachable, then returns a sealer
// that binds the DEK to it. The caller surfaces ErrTPMUnavailable so the user
// knows to check the device / permissions.
func TPMSealer() (Sealer, error) {
	rwc, err := openTPM()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTPMUnavailable, err)
	}
	_ = rwc.Close()
	return &tpmSealer{}, nil
}

func (s *tpmSealer) Name() string { return "tpm2-rsa2048" }

// Seal wraps dek as a TPM sealed object under a freshly-created SRK and returns
// the object's public+private portions packed together.
func (s *tpmSealer) Seal(dek []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rwc, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer rwc.Close()
	srk, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
	if err != nil {
		return nil, fmt.Errorf("create primary: %w", err)
	}
	defer tpm2.FlushContext(rwc, srk)
	priv, pub, err := tpm2.Seal(rwc, srk, "", "", nil, dek)
	if err != nil {
		return nil, fmt.Errorf("tpm seal: %w", err)
	}
	return packBlobs(pub, priv), nil
}

// Unseal recreates the SRK, loads the sealed object, and unseals the DEK.
func (s *tpmSealer) Unseal(blob []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pub, priv, err := unpackBlobs(blob)
	if err != nil {
		return nil, err
	}
	rwc, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer rwc.Close()
	srk, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
	if err != nil {
		return nil, fmt.Errorf("create primary: %w", err)
	}
	defer tpm2.FlushContext(rwc, srk)
	item, _, err := tpm2.Load(rwc, srk, "", pub, priv)
	if err != nil {
		return nil, fmt.Errorf("tpm load: %w", err)
	}
	defer tpm2.FlushContext(rwc, item)
	dek, err := tpm2.Unseal(rwc, item, "")
	if err != nil {
		return nil, fmt.Errorf("tpm unseal: %w", err)
	}
	return dek, nil
}

// openTPM opens the TPM resource manager / device, honouring XCRACK_TPM_DEVICE.
func openTPM() (io.ReadWriteCloser, error) {
	if dev := os.Getenv("XCRACK_TPM_DEVICE"); dev != "" {
		return tpm2.OpenTPM(dev)
	}
	var lastErr error
	for _, d := range tpmDevices {
		rwc, err := tpm2.OpenTPM(d)
		if err == nil {
			return rwc, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no TPM device found")
	}
	return nil, lastErr
}

// packBlobs encodes the sealed object's public and private portions as
// uint32(len(pub)) | pub | priv.
func packBlobs(pub, priv []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(pub)))
	b = append(b, pub...)
	return append(b, priv...)
}

func unpackBlobs(b []byte) (pub, priv []byte, err error) {
	if len(b) < 4 {
		return nil, nil, errors.New("securecache: short TPM blob")
	}
	n := binary.BigEndian.Uint32(b[:4])
	if int(n) > len(b)-4 {
		return nil, nil, errors.New("securecache: bad TPM blob length")
	}
	return b[4 : 4+n], b[4+n:], nil
}
