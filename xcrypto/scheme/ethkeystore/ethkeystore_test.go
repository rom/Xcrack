package ethkeystore

import (
	"encoding/hex"
	"testing"
	"time"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// The two canonical Web3 Secret Storage Definition v3 test vectors (geth /
// MyEtherWallet), passphrase "testpassword". The pbkdf2 MAC below is the
// verbatim published vector value; the scrypt MAC is the value an independent
// pycryptodome oracle computes for the published derived key and ciphertext.
// Both are reproduced by this package's Go scrypt+PBKDF2+Keccak path, so a pass
// here is a cross-implementation agreement, not a self-check.
func TestVerifyKAT(t *testing.T) {
	cases := []struct {
		name string
		p    Params
	}{
		{
			name: "scrypt",
			p: Params{
				KDF:        KDFScrypt,
				Salt:       mustHex(t, "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"),
				DKLen:      32,
				N:          262144,
				R:          1,
				P:          8,
				Ciphertext: mustHex(t, "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2d45a9a98"),
				MAC:        mustHex(t, "d9646f4c5a2e48fc04ed4a6611534ccbd9ae9d2de260636639e9a5e99544c2f3"),
			},
		},
		{
			name: "pbkdf2",
			p: Params{
				KDF:        KDFPBKDF2,
				Salt:       mustHex(t, "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"),
				DKLen:      32,
				C:          262144,
				Ciphertext: mustHex(t, "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46"),
				MAC:        mustHex(t, "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"),
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, err := Verify([]byte("testpassword"), c.p)
			if err != nil {
				t.Fatalf("Verify error: %v", err)
			}
			if !ok {
				t.Fatalf("correct passphrase rejected")
			}
			for _, bad := range []string{"testpassword ", "Testpassword", "", "testpasswor", "x"} {
				if ok, _ := Verify([]byte(bad), c.p); ok {
					t.Fatalf("wrong passphrase %q accepted", bad)
				}
			}
			if c.p.Challenge().Scheme != c.p.SchemeName() {
				t.Fatalf("challenge scheme mismatch")
			}
		})
	}
}

// TestParseKAT parses the two canonical keystore JSON documents end-to-end and
// confirms the extracted parameters verify the known passphrase. It also
// exercises the capitalized "Crypto" key variant some wallets emit.
func TestParseKAT(t *testing.T) {
	const scryptJSON = `{
		"address":"008aeeda4d805471df9b2a5b0f38a0c3bcba786b",
		"crypto":{
			"cipher":"aes-128-ctr",
			"cipherparams":{"iv":"83dbcc02d8ccb40e466191a123791e0e"},
			"ciphertext":"d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2d45a9a98",
			"kdf":"scrypt",
			"kdfparams":{"dklen":32,"n":262144,"p":8,"r":1,"salt":"ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"},
			"mac":"d9646f4c5a2e48fc04ed4a6611534ccbd9ae9d2de260636639e9a5e99544c2f3"
		},
		"id":"3198bc9c-6672-5ab3-d995-4942343ae5b6","version":3}`
	// Same pbkdf2 vector but with the capitalized "Crypto" key.
	const pbkdf2JSON = `{
		"Crypto":{
			"cipher":"aes-128-ctr",
			"cipherparams":{"iv":"6087dab2f9fdbbfaddc31a909735c1e6"},
			"ciphertext":"5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
			"kdf":"pbkdf2",
			"kdfparams":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"},
			"mac":"517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
		},
		"id":"3198bc9c-6672-5ab3-d995-4942343ae5b6","version":3}`
	for _, doc := range []string{scryptJSON, pbkdf2JSON} {
		p, err := Parse([]byte(doc))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		ok, err := Verify([]byte("testpassword"), p)
		if err != nil || !ok {
			t.Fatalf("parsed keystore did not verify: ok=%v err=%v", ok, err)
		}
		if ok, _ := Verify([]byte("wrong"), p); ok {
			t.Fatalf("wrong passphrase accepted on parsed keystore")
		}
	}
}

// TestParseReject rejects malformed and unsupported keystore documents without
// panicking.
func TestParseReject(t *testing.T) {
	bad := []string{
		``,
		`not json`,
		`{}`,
		`{"version":1,"crypto":{}}`, // unsupported version
		`{"version":3,"crypto":{"kdf":"bogus","ciphertext":"00","mac":"` + repeat("ab", 32) + `","kdfparams":{"salt":"00"}}}`,
		`{"version":3,"crypto":{"kdf":"pbkdf2","prf":"hmac-sha1","ciphertext":"00","mac":"` + repeat("ab", 32) + `","kdfparams":{"salt":"00","prf":"hmac-sha1","c":1000}}}`,
		`{"version":3,"crypto":{"kdf":"scrypt","ciphertext":"zz","mac":"` + repeat("ab", 32) + `","kdfparams":{"salt":"00"}}}`, // bad hex
	}
	for i, d := range bad {
		if _, err := Parse([]byte(d)); err == nil {
			t.Fatalf("case %d: expected error, got nil for %q", i, d)
		}
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

// TestDeriveBounds rejects crafted parameters that would make verification an
// unbounded computation or that are malformed, without derivation attempts.
func TestDeriveBounds(t *testing.T) {
	base := Params{Salt: []byte("salt"), DKLen: 32, Ciphertext: []byte("ct"), MAC: []byte("mac")}
	bad := []Params{
		func() Params {
			p := base
			p.KDF = KDFScrypt
			p.N = 3
			p.R = 1
			p.P = 1
			return p
		}(), // N not power of two
		func() Params {
			p := base
			p.KDF = KDFScrypt
			p.N = 1
			p.R = 1
			p.P = 1
			return p
		}(), // N too small
		func() Params {
			p := base
			p.KDF = KDFScrypt
			p.N = 1 << 23
			p.R = 1
			p.P = 1
			return p
		}(), // N too large
		func() Params {
			p := base
			p.KDF = KDFScrypt
			p.N = 16
			p.R = 0
			p.P = 1
			return p
		}(), // R < 1
		func() Params { p := base; p.KDF = KDFPBKDF2; p.C = 0; return p }(),       // C < 1
		func() Params { p := base; p.KDF = KDFPBKDF2; p.C = 1 << 25; return p }(), // C too large
		func() Params {
			p := base
			p.KDF = KDFScrypt
			p.N = 16
			p.R = 1
			p.P = 1
			p.Salt = nil
			return p
		}(), // empty salt
	}
	for i, p := range bad {
		if _, err := Verify([]byte("x"), p); err == nil {
			t.Fatalf("case %d: expected error for crafted params, got nil", i)
		}
	}
}

// TestDeriveRejectsOversizeParams guards the KDF-cost/allocation DoS caps: a
// keystore can set dklen and the scrypt N/r freely, so an out-of-range value
// must be refused promptly rather than driving a multi-GiB allocation or a
// runaway PBKDF2. Uses a watchdog so a regression fails instead of hanging.
func TestDeriveRejectsOversizeParams(t *testing.T) {
	salt := make([]byte, 16)
	mac := make([]byte, 32)
	ct := make([]byte, 16)
	cases := map[string]Params{
		"pbkdf2 huge dklen": {KDF: KDFPBKDF2, C: 1000, DKLen: maxDKLen + 1, Salt: salt, MAC: mac, Ciphertext: ct},
		"scrypt N*r memory": {KDF: KDFScrypt, N: maxScryptN, R: maxR, P: 1, DKLen: 32, Salt: salt, MAC: mac, Ciphertext: ct},
	}
	for name, p := range cases {
		p := p
		done := make(chan bool, 1)
		go func() { ok, _ := Verify([]byte("x"), p); done <- ok }()
		select {
		case ok := <-done:
			if ok {
				t.Fatalf("%s: Verify accepted out-of-range params", name)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: Verify did not reject promptly (cost/alloc DoS)", name)
		}
	}
}
