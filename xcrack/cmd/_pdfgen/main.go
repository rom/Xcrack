package main

import (
	"os"

	xpdf "github.com/rom/xcrypto/scheme/pdf"
	"github.com/rom/xfileformats/formats/pdf"
)

func main() {
	doc, _, _ := pdf.BuildEncryptedPDF([]byte("s3cret"), []byte("owner"), xpdf.CipherAESV3)
	os.WriteFile(os.Args[1], doc, 0o600)
}
