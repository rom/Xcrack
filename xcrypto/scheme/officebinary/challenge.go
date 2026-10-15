package officebinary

import "github.com/rom/xcrypto"

// ChallengeCryptoAPI returns a reporting challenge for an RC4 CryptoAPI blob.
func ChallengeCryptoAPI(salt []byte, keyBits int, verifierHash []byte) *xcrypto.Challenge {
	return &xcrypto.Challenge{
		Scheme:   "mso-rc4-cryptoapi",
		KDF:      xcrypto.KDFSpec{Algo: "office-rc4-cryptoapi-sha1", Salt: salt, KeyLen: keyBits / 8},
		Cipher:   xcrypto.CipherSpec{Algo: "rc4", KeyBits: keyBits},
		Verifier: verifierHash,
	}
}

// ChallengeRC4 returns a reporting challenge for an Office 97/2000 RC4 blob.
func ChallengeRC4(salt []byte, verifierHash []byte) *xcrypto.Challenge {
	return &xcrypto.Challenge{
		Scheme:   "mso-rc4",
		KDF:      xcrypto.KDFSpec{Algo: "office-rc4-md5", Salt: salt, KeyLen: 16},
		Cipher:   xcrypto.CipherSpec{Algo: "rc4", KeyBits: 128},
		Verifier: verifierHash,
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
