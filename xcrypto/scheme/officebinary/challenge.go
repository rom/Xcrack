package officebinary

import "github.com/rom/xcrypto"

// ChallengeCryptoAPI returns a challenge for an RC4 CryptoAPI blob. It carries
// the full crackable parameter set (salt in KDF, encrypted verifier in Extra,
// verifier hash in Verifier) so an exported challenge is self-contained for an
// external cracking engine.
func ChallengeCryptoAPI(salt []byte, keyBits int, encVerifier, verifierHash []byte) *xcrypto.Challenge {
	return &xcrypto.Challenge{
		Scheme:   "mso-rc4-cryptoapi",
		KDF:      xcrypto.KDFSpec{Algo: "office-rc4-cryptoapi-sha1", Salt: salt, KeyLen: keyBits / 8},
		Cipher:   xcrypto.CipherSpec{Algo: "rc4", KeyBits: keyBits},
		Verifier: verifierHash,
		Extra:    map[string][]byte{"enc_verifier": append([]byte{}, encVerifier...)},
	}
}

// ChallengeRC4 returns a challenge for an Office 97/2000 RC4 blob (full crackable
// parameter set; see ChallengeCryptoAPI).
func ChallengeRC4(salt []byte, encVerifier, verifierHash []byte) *xcrypto.Challenge {
	return &xcrypto.Challenge{
		Scheme:   "mso-rc4",
		KDF:      xcrypto.KDFSpec{Algo: "office-rc4-md5", Salt: salt, KeyLen: 16},
		Cipher:   xcrypto.CipherSpec{Algo: "rc4", KeyBits: 128},
		Verifier: verifierHash,
		Extra:    map[string][]byte{"enc_verifier": append([]byte{}, encVerifier...)},
	}
}

// ChallengeXOR returns a reporting challenge for an XOR-obfuscated blob.
func ChallengeXOR(verificationBytes uint16) *xcrypto.Challenge {
	return &xcrypto.Challenge{
		Scheme: "mso-xor",
		KDF:    xcrypto.KDFSpec{Algo: "office-xor"},
		Cipher: xcrypto.CipherSpec{Algo: "xor", KeyBits: 16},
		Verifier: []byte{
			byte(verificationBytes), byte(verificationBytes >> 8),
		},
	}
}
