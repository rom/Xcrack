// Package hashline turns a probed xcrypto.Challenge into a crackable hash line
// for an external GPU cracker — hashcat (`-m <mode>`) or John the Ripper
// (`--format=<name>`). It completes the external-offload bridge: Xcrack probes
// a file once and emits the `$...$` string the heavy, GPU-backed search needs,
// so Xcrack itself stays pure-Go and CPU-only.
//
// The emitted strings follow the de-facto `*2john` / hashcat field layouts.
// Coverage is per-scheme and grows over time; Emit reports ok=false for a
// scheme without an emitter yet. The format layer never has to know about this
// package — everything is derived from the serializable Challenge.
package hashline

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/scheme/pdf"
)

// Result is a crackable hash line for an external tool.
type Result struct {
	// Hashcat is the `hashcat -m` mode, or -1 if there is no single canonical one.
	Hashcat int
	// John is the `john --format=` name, or "" if unknown.
	John string
	// Line is the hash string to feed the cracker (one target).
	Line string
}

// Labeled is a Result tagged with the entry it was derived from (empty for a
// whole-file target). It is what LineExporter.HashcatLines returns, one per
// crackable entry in a container.
type Labeled struct {
	// Target is the container-relative entry path, or "" for a whole-file target.
	Target string
	Result
}

// LineExporter is an optional Format capability: emitting external-cracker
// hash lines for its encrypted entries directly from the raw file, including
// the bulk ciphertext and authentication tag that the probe-time Challenge
// deliberately omits (e.g. WinZip AES, where the $zip2$ line a GPU cracker
// needs carries the whole encrypted stream). The hashline CLI prefers this
// over Emit when a format implements it, falling back to the Challenge-derived
// Emit for formats that do not. Keeping the interface here (not in the root
// xfileformats package) means only the few formats that can export lines take
// on the hashline dependency.
type LineExporter interface {
	HashcatLines(r io.ReaderAt, size int64) ([]Labeled, error)
}

// Emit derives an external-cracker hash line from a probed Challenge. ok is
// false when no emitter supports the challenge's scheme (or a required field is
// missing); callers should fall back to the built-in CPU search.
func Emit(ch *xcrypto.Challenge) (Result, bool) {
	if ch == nil {
		return Result{}, false
	}
	switch ch.Scheme {
	case "ooxml-agile", "ooxml-standard":
		return emitOffice(ch)
	case "pdf-rc4", "pdf-aesv2", "pdf-aesv3":
		return emitPDF(ch)
	default:
		return Result{}, false
	}
}

// emitOffice builds an office2john `$office$` line (hashcat -m 9400/9500/9600).
// Layout: $office$*<version>*<spinCount>*<keyBits>*<saltLen>*<salt>*
//
//	<encryptedVerifier>*<encryptedVerifierHash>
//
// The encrypted verifier hash is truncated to 32 bytes, as office2john does.
func emitOffice(ch *xcrypto.Challenge) (Result, bool) {
	salt := ch.KDF.Salt
	encVer := ch.Extra["encVerifier"]
	encHash := ch.Extra["encVerifierHash"]
	if len(salt) == 0 || len(encVer) == 0 || len(encHash) == 0 {
		return Result{}, false
	}
	algo := strings.ToUpper(string(ch.Extra["hashAlgo"]))
	var version, mode int
	switch {
	case ch.Scheme == "ooxml-standard":
		version, mode = 2007, 9400
	case strings.HasPrefix(algo, "SHA512"):
		version, mode = 2013, 9600
	case strings.HasPrefix(algo, "SHA1") || algo == "SHA":
		version, mode = 2010, 9500
	default:
		// Agile with an algorithm hashcat's office modes don't cover (e.g. SHA256).
		return Result{}, false
	}
	if len(encHash) > 32 {
		encHash = encHash[:32]
	}
	line := fmt.Sprintf("$office$*%d*%d*%d*%d*%s*%s*%s",
		version, ch.KDF.Iterations, ch.Cipher.KeyBits, len(salt),
		hex.EncodeToString(salt), hex.EncodeToString(encVer), hex.EncodeToString(encHash))
	return Result{Hashcat: mode, John: "office", Line: line}, true
}

// emitPDF builds a pdf2john `$pdf$` line. The common prefix is
//
//	$pdf$<V>*<R>*<keyBits>*<P>*<encryptMetadata>*<idLen>*<id>
//
// For R2–R4 (RC4 / AESV2) the U and O strings (32 bytes) follow as
// `*<uLen>*<U>*<oLen>*<O>`. For R5/R6 (AES-256) hashcat expects the 48-byte U
// and O right-zero-padded to 127 bytes, then the 32-byte UE and OE:
// `*127*<U>*127*<O>*32*<UE>*32*<OE>`.
//
// hashcat mode follows the revision: R2→10400, R3/R4→10500, R5→10600, R6→10700.
func emitPDF(ch *xcrypto.Challenge) (Result, bool) {
	h, err := pdf.Unmarshal(ch.Extra)
	if err != nil {
		return Result{}, false
	}
	if len(h.U) == 0 || len(h.O) == 0 {
		return Result{}, false
	}
	meta := 0
	if h.EncryptMetadata {
		meta = 1
	}
	prefix := fmt.Sprintf("$pdf$%d*%d*%d*%d*%d*%d*%s",
		h.V, h.R, h.Length*8, h.P, meta, len(h.ID), hex.EncodeToString(h.ID))

	if h.R >= 5 { // V5: AES-256 (Acrobat 9/10/11)
		if len(h.UE) == 0 || len(h.OE) == 0 {
			return Result{}, false
		}
		mode := 10600
		if h.R >= 6 {
			mode = 10700
		}
		line := fmt.Sprintf("%s*127*%s*127*%s*32*%s*32*%s", prefix,
			hex.EncodeToString(padRight(h.U, 127)), hex.EncodeToString(padRight(h.O, 127)),
			hex.EncodeToString(h.UE), hex.EncodeToString(h.OE))
		return Result{Hashcat: mode, John: "PDF", Line: line}, true
	}

	mode := 10500
	if h.R == 2 {
		mode = 10400
	}
	line := fmt.Sprintf("%s*%d*%s*%d*%s", prefix,
		len(h.U), hex.EncodeToString(h.U), len(h.O), hex.EncodeToString(h.O))
	return Result{Hashcat: mode, John: "PDF", Line: line}, true
}

// Zip2 builds a WinZip-AES `$zip2$` line (hashcat -m 13600, John `ZIP`) from a
// raw AES entry's components. The layout, confirmed by cross-validation against
// hashcat 6.2.6, is
//
//	$zip2$*0*<mode>*0*<salt>*<verify>*<dataLen>*<data>*<auth>*$/zip2$
//
// where mode is 1/2/3 for AES-128/192/256, salt is the full PBKDF2 salt
// (keyBits/16 bytes), verify is the 2-byte password-verification value,
// dataLen is the ciphertext length in bytes (decimal), data is the ciphertext,
// and auth is the 10-byte truncated HMAC-SHA1 authentication code. The full
// data and auth are required — an empty-data form does not crack. ok is false
// for an unknown key size or any missing field.
func Zip2(keyBits int, salt, verify, ct, auth []byte) (Result, bool) {
	var mode int
	switch keyBits {
	case 128:
		mode = 1
	case 192:
		mode = 2
	case 256:
		mode = 3
	default:
		return Result{}, false
	}
	if len(salt) == 0 || len(verify) == 0 || len(ct) == 0 || len(auth) == 0 {
		return Result{}, false
	}
	line := fmt.Sprintf("$zip2$*0*%d*0*%s*%s*%d*%s*%s*$/zip2$",
		mode, hex.EncodeToString(salt), hex.EncodeToString(verify),
		len(ct), hex.EncodeToString(ct), hex.EncodeToString(auth))
	return Result{Hashcat: 13600, John: "ZIP", Line: line}, true
}

// padRight zero-pads b on the right to exactly n bytes (truncating if longer).
func padRight(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}
