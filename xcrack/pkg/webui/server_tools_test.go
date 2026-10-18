package webui

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"testing"
)

func postMultipart(t *testing.T, url string, fields map[string]string, files map[string][]byte) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	for name, data := range files {
		fw, err := mw.CreateFormFile("source", name)
		if err != nil {
			t.Fatal(err)
		}
		fw.Write(data)
	}
	mw.Close()
	resp, err := http.Post(url, mw.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestToolHashlineAndExportChallenge(t *testing.T) {
	data, err := os.ReadFile(fixtureDoc)
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	ts := newTestServer(t)

	// hashline: the encrypted .doc should yield a hash line (or at worst a note).
	resp := postMultipart(t, ts.URL+"/api/v1/tools/hashline", nil, map[string][]byte{"secret.doc": data})
	defer resp.Body.Close()
	var hl struct {
		Files []struct {
			Name  string `json:"name"`
			Lines []struct {
				Line string `json:"line"`
			} `json:"lines"`
			Note string `json:"note"`
		} `json:"files"`
	}
	json.NewDecoder(resp.Body).Decode(&hl)
	if len(hl.Files) != 1 {
		t.Fatalf("hashline files = %d, want 1", len(hl.Files))
	}
	if len(hl.Files[0].Lines) == 0 && hl.Files[0].Note == "" {
		t.Fatalf("hashline: neither a line nor a note for an encrypted file")
	}
	if len(hl.Files[0].Lines) > 0 && hl.Files[0].Lines[0].Line == "" {
		t.Fatalf("hashline emitted an empty line")
	}

	// export-challenge: a downloadable JSON array with at least one envelope.
	resp2 := postMultipart(t, ts.URL+"/api/v1/tools/export-challenge", nil, map[string][]byte{"secret.doc": data})
	defer resp2.Body.Close()
	if ct := resp2.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("export-challenge content-type = %q", ct)
	}
	var envs []json.RawMessage
	if err := json.NewDecoder(resp2.Body).Decode(&envs); err != nil {
		t.Fatalf("export-challenge body not a JSON array: %v", err)
	}
	if len(envs) == 0 {
		t.Fatalf("export-challenge returned no envelopes for an encrypted file")
	}
}

func TestToolVBAAndAccessOnNonMatch(t *testing.T) {
	data, err := os.ReadFile(fixtureDoc)
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	ts := newTestServer(t)
	for _, ep := range []string{"/api/v1/tools/vba-recover", "/api/v1/tools/access-recover"} {
		resp := postMultipart(t, ts.URL+ep, nil, map[string][]byte{"secret.doc": data})
		var out struct {
			Files []map[string]any `json:"files"`
		}
		json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if len(out.Files) != 1 {
			t.Fatalf("%s: files = %d, want 1", ep, len(out.Files))
		}
		// A .doc is neither a VBA carrier password nor a Jet DB here; expect a
		// note or error, not a crash.
		f := out.Files[0]
		if f["error"] == nil && f["note"] == nil && f["password"] == nil && f["kind"] == nil && f["variant"] == nil {
			t.Fatalf("%s: empty result %v", ep, f)
		}
	}
}

func TestToolWordlist(t *testing.T) {
	ts := newTestServer(t)
	post := func(fields map[string]string) (*http.Response, string) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for k, v := range fields {
			_ = mw.WriteField(k, v)
		}
		mw.Close()
		resp, err := http.Post(ts.URL+"/api/v1/tools/wordlist", mw.FormDataContentType(), &buf)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(b)
	}
	// sort (+ implied dedupe)
	_, body := post(map[string]string{"text": "b\na\nb\nc", "op": "sort"})
	if body != "a\nb\nc\n" {
		t.Fatalf("sort = %q, want a\\nb\\nc\\n", body)
	}
	// dedupe preserves first-seen order
	_, body = post(map[string]string{"text": "b\na\nb\nc", "op": "dedupe"})
	if body != "b\na\nc\n" {
		t.Fatalf("dedupe = %q, want b\\na\\nc\\n", body)
	}
	// length filter
	_, body = post(map[string]string{"text": "a\nabc\nabcde", "min_length": "2", "max_length": "4"})
	if body != "abc\n" {
		t.Fatalf("length filter = %q, want abc\\n", body)
	}
	// split -> zip
	resp, _ := post(map[string]string{"text": "a\nb\nc", "split": "2"})
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/zip") {
		t.Fatalf("split content-type = %q, want zip", ct)
	}
}

func TestToolWordlistSplitZip(t *testing.T) {
	ts := newTestServer(t)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("text", "a\nb\nc\nd\ne")
	_ = mw.WriteField("split", "2")
	mw.Close()
	resp, err := http.Post(ts.URL+"/api/v1/tools/wordlist", mw.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	zb, _ := io.ReadAll(resp.Body)
	zr, err := zip.NewReader(bytes.NewReader(zb), int64(len(zb)))
	if err != nil {
		t.Fatalf("split output not a zip: %v", err)
	}
	if len(zr.File) != 3 { // 5 lines / 2 -> 3 parts
		t.Fatalf("split produced %d parts, want 3", len(zr.File))
	}
}

func TestToolPDFKeyTableRejectsNonPDF(t *testing.T) {
	data, err := os.ReadFile(fixtureDoc)
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	ts := newTestServer(t)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	sw, _ := mw.CreateFormFile("source", "x.doc")
	sw.Write(data)
	tw, _ := mw.CreateFormFile("table", "t.tbl")
	tw.Write([]byte("not a table"))
	mw.Close()
	resp, err := http.Post(ts.URL+"/api/v1/tools/pdf-keyattack-table", mw.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	if out["found"] != false {
		t.Fatalf("non-PDF: found = %v, want false", out["found"])
	}
	if out["note"] == nil {
		t.Fatalf("non-PDF: expected an explanatory note, got %v", out)
	}
}

func TestToolNoFiles(t *testing.T) {
	ts := newTestServer(t)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("x", "y")
	mw.Close()
	resp, err := http.Post(ts.URL+"/api/v1/tools/hashline", mw.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("hashline with no files: status %d, want 400", resp.StatusCode)
	}
}
