package hashline

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/scheme/pdf"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestOfficeAgainstHashcatExamples builds a Challenge from the fields of
// hashcat's own canonical example hashes (-m 9400/9500/9600, all for password
// "hashcat") and asserts our emitter reproduces each example string byte for
// byte. These example hashes are authoritative, so matching them proves the
// $office$ layout is exactly what hashcat/John expect. Separately verified with
// a live `hashcat -m 9600` crack of an emitted line (see scripts/hashcat-xval.sh).
func TestOfficeAgainstHashcatExamples(t *testing.T) {
	cases := []struct {
		name    string
		scheme  string
		algo    string
		keyBits int
		iter    int
		mode    int
		salt    string
		encVer  string
		encHash string
		want    string
	}{
		{
			name: "office2013_m9600", scheme: "ooxml-agile", algo: "SHA512", keyBits: 256, iter: 100000, mode: 9600,
			salt:    "67805436882475302087847656644837",
			encVer:  "0c392d3b9ca889656d1e615c54f9f3c9",
			encHash: "612b79e33b96322c3253fc8a0f314463cd76bc4efe1352f7efffca0f374f7e4b",
			want:    "$office$*2013*100000*256*16*67805436882475302087847656644837*0c392d3b9ca889656d1e615c54f9f3c9*612b79e33b96322c3253fc8a0f314463cd76bc4efe1352f7efffca0f374f7e4b",
		},
		{
			name: "office2010_m9500", scheme: "ooxml-agile", algo: "SHA1", keyBits: 128, iter: 100000, mode: 9500,
			salt:    "34170046140146368675746031258762",
			encVer:  "de5bc114991bb3a5679a6e24320bdb09",
			encHash: "1b72a4ddffba3dcd5395f6a5ff75b126cb832b733c298e86162028ca47a235a9",
			want:    "$office$*2010*100000*128*16*34170046140146368675746031258762*de5bc114991bb3a5679a6e24320bdb09*1b72a4ddffba3dcd5395f6a5ff75b126cb832b733c298e86162028ca47a235a9",
		},
		{
			name: "office2007_m9400", scheme: "ooxml-standard", algo: "SHA1", keyBits: 128, iter: 20, mode: 9400,
			salt:    "18410007331073848057180885845227",
			encVer:  "944c70a5ee6e5ab2a6a86ff54b5f621a",
			encHash: "e6650f1f2630c27fd8fc0f5e56e2e01f99784b9f",
			want:    "$office$*2007*20*128*16*18410007331073848057180885845227*944c70a5ee6e5ab2a6a86ff54b5f621a*e6650f1f2630c27fd8fc0f5e56e2e01f99784b9f",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ch := &xcrypto.Challenge{
				Scheme: c.scheme,
				KDF:    xcrypto.KDFSpec{Iterations: c.iter, Salt: mustHex(t, c.salt)},
				Cipher: xcrypto.CipherSpec{KeyBits: c.keyBits},
				Extra: map[string][]byte{
					"encVerifier":     mustHex(t, c.encVer),
					"encVerifierHash": mustHex(t, c.encHash),
					"hashAlgo":        []byte(c.algo),
				},
			}
			r, ok := Emit(ch)
			if !ok {
				t.Fatal("Emit returned ok=false")
			}
			if r.Hashcat != c.mode {
				t.Errorf("hashcat mode = %d, want %d", r.Hashcat, c.mode)
			}
			if r.Line != c.want {
				t.Errorf("line mismatch:\n got %s\nwant %s", r.Line, c.want)
			}
		})
	}
}

// TestOfficeTruncatesVerifierHash checks the SHA-512 (2013) verifier hash is
// truncated to 32 bytes, as office2john does, even when the parsed value is 64.
func TestOfficeTruncatesVerifierHash(t *testing.T) {
	full := strings.Repeat("ab", 64) // 64 bytes
	ch := &xcrypto.Challenge{
		Scheme: "ooxml-agile",
		KDF:    xcrypto.KDFSpec{Iterations: 100000, Salt: mustHex(t, strings.Repeat("00", 16))},
		Cipher: xcrypto.CipherSpec{KeyBits: 256},
		Extra: map[string][]byte{
			"encVerifier":     mustHex(t, strings.Repeat("11", 16)),
			"encVerifierHash": mustHex(t, full),
			"hashAlgo":        []byte("SHA512"),
		},
	}
	r, ok := Emit(ch)
	if !ok {
		t.Fatal("ok=false")
	}
	last := r.Line[strings.LastIndex(r.Line, "*")+1:]
	if len(last) != 64 { // 32 bytes
		t.Fatalf("verifier hash field = %d hex chars, want 64", len(last))
	}
}

// TestPDF exercises both $pdf$ layouts: R3 (RC4/AESV2, U/O as-is) and R6
// (AES-256, U/O zero-padded to 127 bytes + UE/OE). The R6 byte layout matches
// hashcat's -m 10700 example; an emitted R6 line was separately cracked by a
// live hashcat (scripts/hashcat-xval.sh).
func TestPDF(t *testing.T) {
	id := mustHex(t, "000102030405060708090a0b0c0d0e0f")

	t.Run("rc4_r3_m10500", func(t *testing.T) {
		u := []byte(strings.Repeat("U", 32))
		o := []byte(strings.Repeat("O", 32))
		h := &pdf.Handler{V: 2, R: 3, Length: 16, P: -4, EncryptMetadata: true, ID: id, U: u, O: o, Cipher: pdf.CipherRC4}
		ch := &xcrypto.Challenge{Scheme: "pdf-rc4", Extra: h.Marshal()}
		r, ok := Emit(ch)
		if !ok {
			t.Fatal("ok=false")
		}
		if r.Hashcat != 10500 {
			t.Errorf("mode = %d, want 10500", r.Hashcat)
		}
		want := "$pdf$2*3*128*-4*1*16*000102030405060708090a0b0c0d0e0f" +
			"*32*" + hex.EncodeToString(u) + "*32*" + hex.EncodeToString(o)
		if r.Line != want {
			t.Errorf("line mismatch:\n got %s\nwant %s", r.Line, want)
		}
	})

	t.Run("aes256_r6_m10700", func(t *testing.T) {
		u := []byte(strings.Repeat("U", 48))
		o := []byte(strings.Repeat("O", 48))
		ue := []byte(strings.Repeat("E", 32))
		oe := []byte(strings.Repeat("F", 32))
		h := &pdf.Handler{V: 5, R: 6, Length: 32, P: -4, EncryptMetadata: true, ID: id, U: u, O: o, UE: ue, OE: oe, Cipher: pdf.CipherAESV3}
		ch := &xcrypto.Challenge{Scheme: "pdf-aesv3", Extra: h.Marshal()}
		r, ok := Emit(ch)
		if !ok {
			t.Fatal("ok=false")
		}
		if r.Hashcat != 10700 {
			t.Errorf("mode = %d, want 10700", r.Hashcat)
		}
		uPad := hex.EncodeToString(padRight(u, 127))
		oPad := hex.EncodeToString(padRight(o, 127))
		want := "$pdf$5*6*256*-4*1*16*000102030405060708090a0b0c0d0e0f" +
			"*127*" + uPad + "*127*" + oPad +
			"*32*" + hex.EncodeToString(ue) + "*32*" + hex.EncodeToString(oe)
		if r.Line != want {
			t.Errorf("line mismatch:\n got %s\nwant %s", r.Line, want)
		}
		// U/O fields must be exactly 127 bytes (254 hex).
		if len(uPad) != 254 {
			t.Fatalf("padded U = %d hex, want 254", len(uPad))
		}
	})
}

func TestEmitUnsupported(t *testing.T) {
	if _, ok := Emit(&xcrypto.Challenge{Scheme: "zipcrypto"}); ok {
		t.Error("expected ok=false for unsupported scheme")
	}
	if _, ok := Emit(nil); ok {
		t.Error("expected ok=false for nil challenge")
	}
}
