package webui

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"testing"

	"github.com/rom/xcrypto/scheme/pdf"
)

const fixturePDFRC4 = "../../../xfileformats/formats/pdf/testdata/qpdf/rc4-40.pdf"

// postKeyAttack submits a single-file key-attack tool request.
func postKeyAttack(t *testing.T, ts, endpoint, filename string, data []byte, fields map[string]string) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if data != nil {
		fw, _ := mw.CreateFormFile("source", filename)
		fw.Write(data)
	}
	for k, v := range fields {
		mw.WriteField(k, v)
	}
	mw.Close()
	resp, err := http.Post(ts+endpoint, mw.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestOfficeKeyRejectsNonMSORC4 confirms the Office 40-bit RC4 job declines a
// document that is not Office 97/2000 mso-rc4 (the fixture is CryptoAPI RC4).
func TestOfficeKeyRejectsNonMSORC4(t *testing.T) {
	data, err := os.ReadFile(fixtureDoc)
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	ts := newTestServer(t)
	resp := postKeyAttack(t, ts.URL, "/api/v1/tools/office-keyattack", "x.doc", data, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a non-mso-rc4 document", resp.StatusCode)
	}
}

// TestPDFKeyRejectsNonPDF confirms the PDF key sweep declines a non-PDF upload.
func TestPDFKeyRejectsNonPDF(t *testing.T) {
	data, err := os.ReadFile(fixtureDoc)
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	ts := newTestServer(t)
	resp := postKeyAttack(t, ts.URL, "/api/v1/tools/pdf-keyattack", "x.doc", data, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a non-RC4-PDF", resp.StatusCode)
	}
}

// TestPDFKeyBoundedSweep detects a real 40-bit RC4 PDF and runs a tiny bounded
// sweep as a job: it must be accepted, run to completion, and (over a negligible
// slice of the 2^40 space) not find the key — exercising the detection + sweep
// job framework end to end without a multi-hour full sweep.
func TestPDFKeyBoundedSweep(t *testing.T) {
	data, err := os.ReadFile(fixturePDFRC4)
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	ts := newTestServer(t)
	resp := postKeyAttack(t, ts.URL, "/api/v1/tools/pdf-keyattack", "secret.pdf", data, map[string]string{"count": "65536"})
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("status = %d, want 202 (detected RC4 PDF): %s", resp.StatusCode, b)
	}
	var created struct{ ID string }
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if created.ID == "" {
		t.Fatal("no job id")
	}
	job := pollJob(t, ts, created.ID)
	if job["state"] != "done" {
		t.Fatalf("state = %v, want done (%v)", job["state"], job["error"])
	}
	if job["kind"] != "pdf-keyattack" {
		t.Errorf("kind = %v, want pdf-keyattack", job["kind"])
	}
	if d, _ := job["decrypted"].(float64); d != 0 {
		t.Errorf("decrypted = %v, want 0 for a tiny range", job["decrypted"])
	}
}

// TestThunderGenJob generates a tiny thunder table as a job and confirms the
// downloaded output is a valid, readable table.
func TestThunderGenJob(t *testing.T) {
	ts := newTestServer(t)
	resp := postKeyAttack(t, ts.URL, "/api/v1/tools/thunder-gen", "", nil, map[string]string{
		"bits": "12", "length": "16", "chains": "32", "tables": "1",
	})
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("status = %d, want 202: %s", resp.StatusCode, b)
	}
	var created struct{ ID string }
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()

	job := pollJob(t, ts, created.ID)
	if job["state"] != "done" {
		t.Fatalf("state = %v, want done (%v)", job["state"], job["error"])
	}

	// Download the job's output zip and read the table back.
	dl, err := http.Get(ts.URL + "/api/v1/jobs/" + created.ID + "/download")
	if err != nil {
		t.Fatal(err)
	}
	zb, _ := io.ReadAll(dl.Body)
	dl.Body.Close()
	zr, err := zip.NewReader(bytes.NewReader(zb), int64(len(zb)))
	if err != nil {
		t.Fatalf("output is not a zip: %v", err)
	}
	var tableBytes []byte
	for _, f := range zr.File {
		if f.Name == "r2.thunder" || bytes.HasSuffix([]byte(f.Name), []byte("r2.thunder")) {
			rc, _ := f.Open()
			tableBytes, _ = io.ReadAll(rc)
			rc.Close()
		}
	}
	if len(tableBytes) == 0 {
		t.Fatal("no r2.thunder in the output zip")
	}
	tbl, err := pdf.ReadTable(bytes.NewReader(tableBytes))
	if err != nil {
		t.Fatalf("generated table does not read back: %v", err)
	}
	// Chains can be fewer than requested (colliding endpoints are deduped); the
	// invariant is a non-empty, readable table within the requested bound.
	if n := tbl.Chains(); n <= 0 || n > 32 {
		t.Errorf("table has %d chains, want 1..32", n)
	}
}

// TestThunderGenRejectsBadParams rejects an out-of-range bit width.
func TestThunderGenRejectsBadParams(t *testing.T) {
	ts := newTestServer(t)
	resp := postKeyAttack(t, ts.URL, "/api/v1/tools/thunder-gen", "", nil, map[string]string{"bits": "0"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for bits=0", resp.StatusCode)
	}
}
