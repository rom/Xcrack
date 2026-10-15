package pdf

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// buildPlainPDF writes a minimal, valid, unencrypted PDF whose content stream
// contains marker, with a correct classic cross-reference table.
func buildPlainPDF(marker string) []byte {
	content := fmt.Sprintf("BT /F1 24 Tf 72 700 Td (%s) Tj ET", marker)
	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content),
	}
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	offs := make([]int, len(objs)+1)
	for i, o := range objs {
		offs[i+1] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj %s endobj\n", i+1, o)
	}
	xref := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for i := 1; i <= len(objs); i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offs[i])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xref)
	return buf.Bytes()
}

// TestQPDFCrossValidation encrypts a PDF with the real qpdf tool across every
// handler we support and checks that we decrypt it (user + owner), recovering
// the content and removing /Encrypt. Skipped when qpdf is not installed; CI
// installs it.
func TestQPDFCrossValidation(t *testing.T) {
	qpdf, err := exec.LookPath("qpdf")
	if err != nil {
		t.Skip("qpdf not available")
	}
	dir := t.TempDir()
	marker := "CROSSCHECK-MARKER-7f3a1"
	in := filepath.Join(dir, "plain.pdf")
	if err := os.WriteFile(in, buildPlainPDF(marker), 0o600); err != nil {
		t.Fatal(err)
	}

	const user, owner = "userpw", "ownerpw"
	cases := []struct {
		name string
		args []string
	}{
		{"rc4-40", []string{"40"}},
		{"rc4-128", []string{"128", "--use-aes=n"}},
		{"aes-128", []string{"128", "--use-aes=y"}},
		{"aes-256", []string{"256"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := filepath.Join(dir, c.name+".pdf")
			args := []string{"--allow-weak-crypto", "--compress-streams=n", "--object-streams=disable",
				"--encrypt", user, owner}
			args = append(args, c.args...)
			args = append(args, "--", in, out)
			if o, err := exec.Command(qpdf, args...).CombinedOutput(); err != nil {
				t.Fatalf("qpdf failed: %v\n%s", err, o)
			}
			data, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}

			f := New()
			ra := bytes.NewReader(data)
			ch, err := f.Probe(ra, int64(len(data)))
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			okU, keyU, _ := f.Verify(ch, []byte(user))
			if !okU {
				t.Fatal("user password did not verify")
			}
			if okO, _, _ := f.Verify(ch, []byte(owner)); !okO {
				t.Fatal("owner password did not verify")
			}
			if bad, _, _ := f.Verify(ch, []byte("wrong")); bad {
				t.Fatal("wrong password verified")
			}
			r, err := f.Decrypt(ra, int64(len(data)), ch, keyU)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			dec, _ := io.ReadAll(r)
			if bytes.Contains(dec, []byte("/Encrypt")) {
				t.Error("decrypted output still references /Encrypt")
			}
			if !bytes.Contains(dec, []byte(marker)) {
				t.Errorf("marker %q not found in decrypted output", marker)
			}
		})
	}
}
