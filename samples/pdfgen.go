// pdfgen builds an AES-256 (AESV3) encrypted PDF demo sample.
// Run from the xfileformats module: go run <path>/pdfgen.go <outfile> <userpw>
package main

import (
	"os"

	xpdf "github.com/rom/xcrypto/scheme/pdf"
	"github.com/rom/xfileformats/formats/pdf"
)

func main() {
	out, pw := os.Args[1], os.Args[2]
	doc, _, _ := pdf.BuildEncryptedPDF([]byte(pw), []byte("owner-"+pw), xpdf.CipherAESV3)
	if err := os.WriteFile(out, doc, 0o644); err != nil {
		panic(err)
	}
}
