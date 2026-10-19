package webui

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

const fixtureDoc = "../../../xfileformats/formats/msoffice/testdata/rc4cryptoapi_password.doc"
const fixturePassword = "Password1234_"

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv, err := NewServer(Config{
		WorkDir:       t.TempDir(),
		ExposeSecrets: true,
		Version:       "test",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	// Stop accepting requests, then drain in-flight job runners before the
	// t.TempDir() work directory is removed — otherwise a background runner can
	// still be writing under it as RemoveAll runs (flaky "directory not empty").
	// Registered after t.TempDir() (inside NewServer), so it runs before it.
	t.Cleanup(func() {
		ts.Close()
		srv.Close()
	})
	return ts
}

func getJSON(t *testing.T, url string) map[string]any {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
	return m
}

func TestMetaAndDocs(t *testing.T) {
	ts := newTestServer(t)
	m := getJSON(t, ts.URL+"/api/v1/meta")
	if m["version"] != "test" {
		t.Errorf("meta version = %v, want test", m["version"])
	}
	if fs, ok := m["formats"].([]any); !ok || len(fs) == 0 {
		t.Errorf("meta formats missing or empty")
	}
	docs := getJSON(t, ts.URL+"/api/v1/docs")
	list, _ := docs["docs"].([]any)
	if len(list) == 0 {
		t.Fatal("docs list empty; want at least the built-in quick start")
	}
	resp, err := http.Get(ts.URL + "/api/v1/docs/quickstart")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Quick start") {
		t.Errorf("quickstart doc missing expected heading")
	}
}

func TestValidateAndFormat(t *testing.T) {
	ts := newTestServer(t)
	post := func(path, body string) map[string]any {
		resp, err := http.Post(ts.URL+path, "application/x-yaml", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return m
	}
	if r := post("/api/v1/config/validate", "candidates:\n  passwords: [a]\n"); r["valid"] != true {
		t.Errorf("valid spec reported invalid: %v", r)
	}
	if r := post("/api/v1/config/validate", "search:\n  order: bogus\n"); r["valid"] != false {
		t.Errorf("bad order reported valid: %v", r)
	}
	if r := post("/api/v1/config/validate", "candidates:\n  bogus_key: 1\n"); r["valid"] != false {
		t.Errorf("unknown key accepted by strict validate: %v", r)
	}
	if r := post("/api/v1/config/format", `{"patterns":{"masks":["?d"]}}`); !strings.Contains(r["yaml"].(string), "masks") {
		t.Errorf("format did not round-trip masks: %v", r)
	}
}

// buildJobRequest constructs a multipart job-submission body.
func buildJobRequest(t *testing.T, spec string, sources map[string][]byte, aux map[string][]byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("spec", spec); err != nil {
		t.Fatal(err)
	}
	add := func(field, name string, data []byte) {
		fw, err := mw.CreateFormFile(field, name)
		if err != nil {
			t.Fatal(err)
		}
		fw.Write(data)
	}
	for name, data := range sources {
		add("source", name, data)
	}
	for name, data := range aux {
		add("aux", name, data)
	}
	mw.Close()
	return &buf, mw.FormDataContentType()
}

func pollJob(t *testing.T, ts *httptest.Server, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		j := getJSON(t, ts.URL+"/api/v1/jobs/"+id)
		switch j["state"] {
		case "done", "error", "canceled":
			return j
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("job %s did not finish in time", id)
	return nil
}

func TestCreateJobCracksFile(t *testing.T) {
	data, err := os.ReadFile(fixtureDoc)
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	ts := newTestServer(t)
	spec := `{"candidates":{"use_default_list":false,"passwords":["nope","` + fixturePassword + `"]}}`
	body, ct := buildJobRequest(t, spec, map[string][]byte{"secret.doc": data}, nil)
	resp, err := http.Post(ts.URL+"/api/v1/jobs", ct, body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create job status %d: %s", resp.StatusCode, b)
	}
	var created struct{ ID string }
	json.NewDecoder(resp.Body).Decode(&created)
	if created.ID == "" {
		t.Fatal("no job id returned")
	}

	job := pollJob(t, ts, created.ID)
	if job["state"] != "done" {
		t.Fatalf("job state = %v, want done (%v)", job["state"], job["error"])
	}
	raw, _ := json.Marshal(job)
	if !strings.Contains(string(raw), fixturePassword) {
		t.Fatalf("job result did not recover the password; got %s", raw)
	}

	// The decrypted output downloads as a non-empty zip.
	dl, err := http.Get(ts.URL + "/api/v1/jobs/" + created.ID + "/download")
	if err != nil {
		t.Fatal(err)
	}
	defer dl.Body.Close()
	zbytes, _ := io.ReadAll(dl.Body)
	zr, err := zip.NewReader(bytes.NewReader(zbytes), int64(len(zbytes)))
	if err != nil {
		t.Fatalf("download is not a valid zip: %v", err)
	}
	if len(zr.File) == 0 {
		t.Errorf("download zip is empty; expected the decrypted tree")
	}
}

func TestIdentify(t *testing.T) {
	data, err := os.ReadFile(fixtureDoc)
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	ts := newTestServer(t)
	body, ct := buildJobRequest(t, "", map[string][]byte{"secret.doc": data}, nil)
	resp, err := http.Post(ts.URL+"/api/v1/identify", ct, body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Files []struct {
			Name      string `json:"name"`
			Format    string `json:"format"`
			Encrypted bool   `json:"encrypted"`
		} `json:"files"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if len(out.Files) != 1 || out.Files[0].Format == "" || !out.Files[0].Encrypted {
		t.Fatalf("identify = %+v, want one encrypted format", out.Files)
	}
}

// TestJobRejectsEscapingPaths is the security test: a submitted spec must not be
// able to point the engine at a server file it was not given. Absolute paths and
// traversal in a wordlist reference are rejected (AllowServerPaths is off).
func TestJobRejectsEscapingPaths(t *testing.T) {
	ts := newTestServer(t)
	for _, ref := range []string{"/etc/passwd", "../../../etc/passwd", "secret/../../x"} {
		spec := `{"candidates":{"wordlists":["` + ref + `"]}}`
		body, ct := buildJobRequest(t, spec, map[string][]byte{"x.bin": []byte("hello")}, nil)
		resp, err := http.Post(ts.URL+"/api/v1/jobs", ct, body)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("wordlist ref %q: status %d (%s), want 400", ref, resp.StatusCode, b)
		}
		// Must be rejected by path sanitization, not by some unrelated error.
		if !strings.Contains(string(b), "candidates.wordlists") {
			t.Fatalf("wordlist ref %q rejected for the wrong reason: %s", ref, b)
		}
	}
}

// TestJobResolvesUploadedAux confirms a wordlist uploaded as an aux part is
// accepted when referenced by its base name.
func TestJobResolvesUploadedAux(t *testing.T) {
	ts := newTestServer(t)
	spec := `{"candidates":{"use_default_list":false,"wordlists":["words.txt"]}}`
	body, ct := buildJobRequest(t, spec,
		map[string][]byte{"x.bin": []byte("hello")},
		map[string][]byte{"words.txt": []byte("a\nb\nc\n")})
	resp, err := http.Post(ts.URL+"/api/v1/jobs", ct, body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
}

func TestDownloadUnknownJob(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/api/v1/jobs/deadbeef/download")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("download unknown job status = %d, want 404", resp.StatusCode)
	}
}
