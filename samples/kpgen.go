// _kpgen builds the ZipCrypto known-plaintext demo artifacts for `xcrack kp`.
// Run from the xcrypto module: go run <path>/_kpgen.go <outdir>
// It writes, for a STORED entry with a known payload:
//
//	kp_entry.bin   full entry: [12-byte header][encrypted payload]
//	kp_known.txt   the payload plaintext (= the data stream, so it IS the known plaintext)
//	kp_cipher.bin  the encrypted payload (entry minus the 12-byte header)
//
// so `xcrack kp --plain kp_known.txt --cipher kp_cipher.bin` recovers the keys,
// and adding `--decrypt kp_entry.bin --offset 0` decrypts the whole entry.
package main

import (
	"os"
	"path/filepath"

	"github.com/rom/xcrypto/scheme/zipcrypto"
)

func main() {
	out := "."
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	const pw = "sesame" // short (6× lowercase) so `kp --recover-password 6:?l` is fast
	payload := []byte("Xcrack known-plaintext demo payload: the quick brown fox jumps over the lazy dog 0123456789.")
	hdr11 := []byte("xcrackdemo!") // 11 arbitrary header bytes (12th is the check byte)
	entry := zipcrypto.EncryptRaw([]byte(pw), hdr11, 0x42, payload)

	write := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(out, name), b, 0o644); err != nil {
			panic(err)
		}
	}
	write("kp_entry.bin", entry)
	write("kp_known.txt", payload)
	write("kp_cipher.bin", entry[zipcrypto.HeaderLen:])
}
