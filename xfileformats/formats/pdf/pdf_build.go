package pdf

import (
	"bytes"
	"encoding/hex"
	"fmt"

	xpdf "github.com/rom/xcrypto/scheme/pdf"
)

// BuildEncryptedPDF produces a small encrypted PDF (classic cross-reference
// table) with one encrypted content stream and one encrypted string, protected
// by the given user/owner passwords under the chosen cipher. It is used for
// round-trip tests and tooling. The returned plaintext stream and string are
// what a successful Decrypt should recover.
func BuildEncryptedPDF(user, owner []byte, cipher xpdf.Cipher) (doc, wantStream, wantString []byte) {
	var h *xpdf.Handler
	var fk []byte
	switch cipher {
	case xpdf.CipherAESV2:
		h, fk = xpdf.NewAESV2(user, owner)
	case xpdf.CipherAESV3:
		h, fk = xpdf.NewAESV3(user, owner)
	default:
		h, fk = xpdf.NewRC4(user, owner)
	}

	wantStream = []byte("BT /F1 24 Tf 72 720 Td (confidential body) Tj ET")
	wantString = []byte("Secret Author Name")
	encStream := h.EncryptData(fk, 4, 0, wantStream)
	encAuthor := h.EncryptData(fk, 5, 0, wantString)

	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(encStream), encStream),
		fmt.Sprintf("<< /Author <%s> >>", hex.EncodeToString(encAuthor)),
		encryptDictString(h),
	}

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
	offsets := make([]int, len(objs)+1)
	for i, body := range objs {
		offsets[i+1] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj %s endobj\n", i+1, body)
	}
	xrefOff := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for i := 1; i <= len(objs); i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
	}
	idHex := hex.EncodeToString(h.ID)
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R /Encrypt 6 0 R /ID [<%s><%s>] >>\nstartxref\n%d\n%%%%EOF\n",
		len(objs)+1, idHex, idHex, xrefOff)
	return buf.Bytes(), wantStream, wantString
}

func encryptDictString(h *xpdf.Handler) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "<< /Filter /Standard /V %d /R %d /Length %d /P %d /O <%s> /U <%s>",
		h.V, h.R, h.Length*8, h.P, hex.EncodeToString(h.O), hex.EncodeToString(h.U))
	switch h.Cipher {
	case xpdf.CipherAESV2:
		b.WriteString(" /CF << /StdCF << /CFM /AESV2 /Length 16 /AuthEvent /DocOpen >> >> /StmF /StdCF /StrF /StdCF")
	case xpdf.CipherAESV3:
		fmt.Fprintf(&b, " /CF << /StdCF << /CFM /AESV3 /Length 32 /AuthEvent /DocOpen >> >> /StmF /StdCF /StrF /StdCF /OE <%s> /UE <%s>",
			hex.EncodeToString(h.OE), hex.EncodeToString(h.UE))
	}
	b.WriteString(" >>")
	return b.String()
}
