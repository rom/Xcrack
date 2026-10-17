// Package accel is the optional, server-tier GPU/OpenCL acceleration seam for
// xcrackd. It is the one sanctioned exception to ADR 0001 (pure-Go, no cgo):
// the default build stays pure-Go and cgo-free, and an OpenCL backend is
// compiled in ONLY with `-tags opencl` and used ONLY when the host has OpenCL
// hardware. A server operator opts in explicitly; everyone else gets the
// unchanged CPU engine, and CI never builds or runs the GPU path.
//
// The acceleration is deliberately scoped to the heavy, embarrassingly-parallel
// primitive the password schemes share — PBKDF2 key derivation — exposed as a
// batch call per HMAC variant: PBKDF2-HMAC-SHA1 (WinZip-AES, encrypted DMG, and
// ODF — whose start-key hash is applied per-candidate on the CPU before the
// kernel, via AccelKDF.PreHash), PBKDF2-HMAC-SHA256 (RAR5's password-check
// derivation), and PBKDF2-HMAC-SHA512 (SQLCipher-v4-class). Everything else
// (format parsing, verification, recursion) stays on the CPU in pure Go. The GPU
// output is always byte-for-byte identical to the Go reference (prim.PBKDF2), so
// a GPU result is never trusted blindly: it is validated at startup
// (GPUSelfTest) against the reference, for every variant, before use.
//
// SQLCipher is deliberately NOT accelerated: its v3 (SHA-1) and v4 (SHA-512)
// profiles are indistinguishable from the file before a password verifies, and
// the AccelKDF seam derives exactly one (PRF, Iter) per candidate — accelerating
// the wrong profile would sweep the keyspace and silently miss the real one, so
// it stays on the CPU where VerifyAny tries both.
//
// Argon2 (KeePass KDBX4) and bcrypt (OpenSSH) are intentionally NOT here: they
// are memory-hard / Blowfish-based and do not fit the PBKDF2 batch shape, so
// they stay on the CPU pending dedicated kernels.
package accel

import (
	"errors"
	"strings"
)

// ErrNotBuilt is returned by Detect in a default (pure-Go) build: no OpenCL
// backend was compiled in.
var ErrNotBuilt = errors.New("accel: GPU/OpenCL support not built (rebuild xcrackd with -tags opencl)")

// ErrUnsupported is returned by an Accelerator for an operation its backend has
// no kernel for; the caller falls back to the CPU engine.
var ErrUnsupported = errors.New("accel: operation not supported by this backend")

// Device describes one OpenCL compute device.
type Device struct {
	Platform     string
	Name         string
	Vendor       string
	Type         string // "GPU", "CPU", "ACCELERATOR", or "OTHER"
	ComputeUnits int
	UnifiedMem   bool // host-unified memory => an integrated GPU / APU (e.g. Ryzen AI Max)
}

// VendorArch classifies a device's vendor family from its CL_DEVICE_VENDOR
// string, so the tier can report and select across NVIDIA, AMD (including Ryzen
// APUs), Intel and Apple uniformly. The OpenCL C kernels are vendor-neutral and
// run on any conformant driver (NVIDIA CUDA OpenCL, AMD ROCm/Mesa, Intel, Apple,
// pocl), so this drives selection and logging, not kernel choice.
func VendorArch(vendor string) string {
	v := strings.ToLower(vendor)
	switch {
	case strings.Contains(v, "nvidia"):
		return "NVIDIA"
	case strings.Contains(v, "advanced micro") || strings.Contains(v, "amd") || strings.Contains(v, "radeon"):
		return "AMD"
	case strings.Contains(v, "intel"):
		return "Intel"
	case strings.Contains(v, "apple"):
		return "Apple"
	case strings.Contains(v, "mesa") || strings.Contains(v, "rusticl") || strings.Contains(v, "clover"):
		return "Mesa"
	case strings.Contains(v, "pocl"):
		return "pocl"
	default:
		return "Other"
	}
}

// DeviceRank scores a device for automatic selection (higher = preferred): a
// discrete GPU beats an integrated GPU/APU, which beats a dedicated
// accelerator, which beats a CPU; compute units break ties. It lets Detect pick
// the best available device across vendors (an AMD discrete card over its own
// APU, a GPU over the CPU fallback) rather than just the first platform.
func DeviceRank(d Device) int {
	base := 0
	switch d.Type {
	case "GPU":
		if d.UnifiedMem {
			base = 3000 // integrated GPU / APU
		} else {
			base = 4000 // discrete GPU
		}
	case "ACCELERATOR":
		base = 2000
	case "CPU":
		base = 100
	default:
		base = 10
	}
	return base + d.ComputeUnits
}

// Accelerator is a ready OpenCL context over one or more devices. It is created
// by Detect (only in an -tags opencl build) and released with Close.
type Accelerator interface {
	// Devices lists the backing compute devices.
	Devices() []Device
	// PBKDF2SHA1 derives a dkLen-byte key for each password against the shared
	// salt and iteration count, on the device. It returns ErrUnsupported if the
	// backend has no kernel for these parameters, so the caller can fall back to
	// the CPU. Results are in input order.
	PBKDF2SHA1(passwords [][]byte, salt []byte, iter, dkLen int) ([][]byte, error)
	// PBKDF2SHA256 is PBKDF2SHA1 with HMAC-SHA256 (RAR5-class and other standard
	// PBKDF2-HMAC-SHA256 schemes). Same batch contract and fallback behaviour.
	PBKDF2SHA256(passwords [][]byte, salt []byte, iter, dkLen int) ([][]byte, error)
	// PBKDF2SHA512 is PBKDF2SHA1 with HMAC-SHA512 (SQLCipher v4 and other standard
	// PBKDF2-HMAC-SHA512 schemes). Same batch contract and fallback behaviour.
	PBKDF2SHA512(passwords [][]byte, salt []byte, iter, dkLen int) ([][]byte, error)
	// Close releases the context.
	Close() error
}

// OfficeHasher is an optional capability of an Accelerator that runs the Office
// agile/standard iterated-hash "spin" on the device — the dominant cost of every
// modern (2007+) Office document. The caller computes the single variable-length
// first hash cur0 = H(salt || UTF16LE(password)) per candidate on the CPU and
// passes the digest-length seeds; the device runs the fixed-size loop
//
//	for i in [0, spin):  cur = H(LE32(i) || cur)
//
// and returns the final digest per seed, in input order. algo is "sha1",
// "sha256", "sha384" or "sha512". The engine type-asserts for this capability
// and falls back to the CPU (per-candidate OfficeAgileHash) when the accelerator
// does not implement it or returns ErrUnsupported. The result is byte-for-byte
// identical to prim.OfficeAgileHash, re-checked by the format's Finish, so the
// device never decides correctness on its own.
type OfficeHasher interface {
	OfficeSpin(seeds [][]byte, spin int, algo string) ([][]byte, error)
}

// OldOfficeKeySearcher is an optional capability of an Accelerator that sweeps
// the Office 97/2000 RC4 (MS-OFFCRYPTO 2.3.6) 40-bit trunc keyspace on the
// device — a key-SEARCH kernel (not the per-password batch shape): the password
// enters only as trunc = MD5(UTF16LE(pw))[:5], so the whole verifier is a
// function of (trunc, salt) and there are just 2^40 of them. The engine/CLI
// type-asserts for it and offloads the sweep, falling back to the CPU
// (officebinary.RC4KeyAttack) when the accelerator lacks it or returns
// ErrUnsupported. A hit is always re-checked on the CPU, so the device never
// decides correctness on its own.
type OldOfficeKeySearcher interface {
	// OldOfficeKeySearch sweeps trunc indices [start, start+count) for the trunc
	// satisfying the Office 97/2000 verifier, returning the 5-byte trunc
	// (little-endian of the winning index) and found=true on success. salt is the
	// EncryptionHeader salt; encVerifier and encVerifierHash are 16 bytes each. It
	// is byte-for-byte equivalent to officebinary.RC4KeyAttack over the same range.
	OldOfficeKeySearch(salt, encVerifier, encVerifierHash []byte, start, count uint64) (trunc []byte, found bool, err error)
}

// BatchTuner is an optional capability of an Accelerator that can recommend a
// per-dispatch batch size tuned to its device(s) (count, compute units,
// throughput). The engine type-asserts for it and sizes its offload batches
// accordingly, falling back to a fixed default when an Accelerator does not
// implement it.
type BatchTuner interface {
	// OptimalBatch returns the recommended number of candidates per batch (> 0).
	OptimalBatch() int
}

// Built reports whether an OpenCL backend was compiled into this binary. It is
// false for the default pure-Go build.
func Built() bool { return built }
