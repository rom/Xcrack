// Package rar5 implements the fast password verification for RAR 5.0 archives.
//
// RAR5 (WinRAR 5.0+, 2013 onward) derives its AES-256 key with
// PBKDF2-HMAC-SHA256 and — unlike RAR4 — stores an 8-byte password-check value
// in the header. That lets a wrong password be rejected after the key
// derivation alone, with no decryption or decompression, which is the whole
// reason RAR5 attacks have a fixed, quotable cost per candidate (see
// Elcomsoft, "The RAR Mystery: Breaking RAR4 and RAR5 Encryption"). This
// package reproduces WinRAR's derivation (per unrar's crypt5.cpp) and is
// cross-validated byte-for-byte against archives produced by the real `rar`
// tool.
//
// The derivation is a single PBKDF2 block over the 16-byte salt, but the HMAC
// chain is run past the key: WinRAR XOR-accumulates the per-iteration HMAC
// outputs and snapshots the accumulator at 2^Lg2Count iterations (the AES key),
// +16 (a hash key), and +32 (the password-check value). The stored 8-byte check
// is the 32-byte +32 snapshot folded onto itself in 8-byte groups. The password
// is the raw UTF-8 bytes (RAR5 dropped RAR4's UTF-16LE).
package rar5

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
)

// PswCheckLen is the length of the stored password-check value.
const PswCheckLen = 8

// SaltLen is the RAR5 PBKDF2 salt length.
const SaltLen = 16

// MaxLg2Count caps the KDF iteration exponent. RAR5 stores the count as a
// base-2 logarithm in a single byte (0..255), but WinRAR/UnRAR only ever
// produce and accept values up to 24 (unrar's CRYPT5_KDF_LG2_COUNT_MAX, i.e.
// 2^24 iterations); the nwaples/rardecode decoder rejects anything larger too.
// An out-of-range value is therefore a corrupt or hostile header, not a real
// archive — and left unchecked it turns the derivation into ~2^lg2 HMAC rounds
// (a trivially triggered denial of service). The verification boundary refuses
// such params rather than running the loop.
const MaxLg2Count = 24

// Params are the fields a RAR5 crypt record carries that are needed to verify a
// password without decrypting anything.
type Params struct {
	Salt     []byte // 16-byte PBKDF2 salt
	Lg2Count uint   // iteration count as a base-2 logarithm (default 15 => 32768)
	PswCheck []byte // 8-byte stored password-check value
}

// SchemeName is the Challenge scheme identifier.
func (Params) SchemeName() string { return "rar5" }

// Iterations returns the concrete PBKDF2 iteration count (2^Lg2Count).
func (p Params) Iterations() int { return 1 << p.Lg2Count }

// PswCheckValue computes the 8-byte RAR5 password-check value for a candidate
// against the given salt and iteration log. It is WinRAR's derivation exactly:
// one PBKDF2-HMAC-SHA256 block, XOR-accumulated, snapshotted at count+32
// iterations, folded to 8 bytes.
func PswCheckValue(password string, salt []byte, lg2Count uint) []byte {
	count := 1 << lg2Count
	pw := []byte(password)
	mac := func(msg []byte) []byte {
		h := hmac.New(sha256.New, pw)
		h.Write(msg)
		return h.Sum(nil)
	}
	// U1 = HMAC(pwd, salt || big-endian uint32(1)); fn starts as U1.
	msg := make([]byte, len(salt)+4)
	copy(msg, salt)
	msg[len(salt)+3] = 1
	u := mac(msg)
	fn := make([]byte, len(u))
	copy(fn, u)
	// WinRAR runs the chain to the key (count iterations), then +16, then +16,
	// XOR-accumulating throughout; only the final (+32) snapshot is the check
	// value, so run count+32 HMACs in total (U1 was the first).
	extra := (count - 1) + 16 + 16
	for i := 0; i < extra; i++ {
		u = mac(u)
		for j := range fn {
			fn[j] ^= u[j]
		}
	}
	pc := make([]byte, PswCheckLen)
	for i := 0; i < len(fn); i++ {
		pc[i%PswCheckLen] ^= fn[i]
	}
	return pc
}

// AccelIterations is the total PBKDF2-HMAC-SHA256 iteration count an accelerator
// must run to reach the +32 password-check snapshot: 2^Lg2Count + 32. Because
// the derivation is a single PBKDF2 block (DKLen 32) XOR-accumulated, that
// snapshot equals the standard PBKDF2-HMAC-SHA256(password, salt, 2^Lg2Count+32,
// 32) output, which is what the batch kernel computes.
func (p Params) AccelIterations() int { return p.Iterations() + 32 }

// PswCheckFromDK folds a 32-byte PBKDF2-HMAC-SHA256(password, salt,
// AccelIterations, 32) output to the 8-byte RAR5 password-check value. The DK
// is exactly WinRAR's +32 accumulator snapshot, so this is the same fold
// PswCheckValue applies — letting an accelerator derive the key once.
func PswCheckFromDK(dk []byte) []byte {
	pc := make([]byte, PswCheckLen)
	for i := 0; i < len(dk); i++ {
		pc[i%PswCheckLen] ^= dk[i]
	}
	return pc
}

// VerifyDK reports whether the 32-byte accelerator-derived key matches p's
// stored check value, in constant time. It is the Finish step for the GPU
// offload path; it returns false when p carries no check value.
func VerifyDK(dk []byte, p Params) bool {
	if len(p.PswCheck) != PswCheckLen || len(dk) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(PswCheckFromDK(dk), p.PswCheck) == 1
}

// Verify reports whether password matches the archive described by p. It derives
// the check value and compares it in constant time. It returns false (not an
// error) when the params carry no check value, since then no fast verification
// is possible.
func Verify(password string, p Params) bool {
	if len(p.PswCheck) != PswCheckLen || len(p.Salt) == 0 || p.Lg2Count > MaxLg2Count {
		return false
	}
	got := PswCheckValue(password, p.Salt, p.Lg2Count)
	return subtle.ConstantTimeCompare(got, p.PswCheck) == 1
}
