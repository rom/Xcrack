package ethwallet

import (
	"bytes"
	"testing"
)

// The canonical Web3 Secret Storage v3 scrypt keystore, passphrase
// "testpassword" (geth / MyEtherWallet test vector). The MAC is the value an
// independent pycryptodome oracle and this project's Go path both produce; see
// xcrypto/scheme/ethkeystore for the cross-validation.
const scryptKeystore = `{
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

func TestEthWalletFormat(t *testing.T) {
	data := []byte(scryptKeystore)
	f := New()
	peek := data
	if len(peek) > 512 {
		peek = peek[:512]
	}
	if conf, ok := f.Detect(peek); !ok || conf < 0.9 {
		t.Fatalf("Detect: ok=%v conf=%v", ok, conf)
	}
	ch, err := f.Probe(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if ch.Scheme != "ethkeystore-scrypt" {
		t.Fatalf("scheme = %q", ch.Scheme)
	}
	ok, key, err := f.Verify(ch, []byte("testpassword"))
	if err != nil || !ok {
		t.Fatalf("Verify(correct): ok=%v err=%v", ok, err)
	}
	if string(key) != "testpassword" {
		t.Fatalf("recovered key = %q", key)
	}
	if bad, _, _ := f.Verify(ch, []byte("wrong")); bad {
		t.Fatal("Verify(wrong) = true")
	}
}

func TestEthWalletDetectRejectsOther(t *testing.T) {
	cases := []string{
		`not json at all`,
		`{"hello":"world"}`,
		`{"crypto":{"something":1}}`,                   // crypto but no ciphertext/kdf
		`{"ciphertext":"00","kdf":"scrypt"}`,           // no crypto object
		`<?xml version="1.0"?><x/>`,                    // not even starting with {
		`{"crypto":{"ciphertext":"x","kdf":"argon2"}}`, // crypto+ciphertext+kdf but unknown KDF
	}
	f := New()
	for _, c := range cases {
		if _, ok := f.Detect([]byte(c)); ok {
			t.Errorf("must not detect %q", c)
		}
	}
}

func FuzzEthWallet(f *testing.F) {
	f.Add([]byte(scryptKeystore))
	f.Add([]byte(`{"crypto":{"kdf":"scrypt","ciphertext":"zz"}}`))
	f.Add([]byte(""))
	f.Add([]byte("{"))
	fm := New()
	f.Fuzz(func(t *testing.T, data []byte) {
		peek := data
		if len(peek) > 512 {
			peek = peek[:512]
		}
		fm.Detect(peek)
		ch, err := fm.Probe(bytes.NewReader(data), int64(len(data)))
		if err == nil && ch != nil {
			fm.Verify(ch, []byte("x"))
		}
	})
}
