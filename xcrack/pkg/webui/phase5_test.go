package webui

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestLibraryUploadListPreviewDelete exercises the server-side wordlist library.
func TestLibraryUploadListPreviewDelete(t *testing.T) {
	ts := newTestServer(t)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "common.txt")
	fw.Write([]byte("password\n123456\nqwerty\n"))
	mw.Close()
	up, err := http.Post(ts.URL+"/api/v1/library", mw.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	if up.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(up.Body)
		up.Body.Close()
		t.Fatalf("upload %d: %s", up.StatusCode, b)
	}
	up.Body.Close()

	list := getJSON(t, ts.URL+"/api/v1/library")
	if wls, _ := list["wordlists"].([]any); len(wls) != 1 {
		t.Fatalf("library has %d wordlists, want 1", len(wls))
	}

	pv := getJSON(t, ts.URL+"/api/v1/library/common.txt/preview")
	lines, _ := pv["lines"].([]any)
	if len(lines) != 3 || lines[0] != "password" {
		t.Fatalf("preview lines = %v, want [password 123456 qwerty]", lines)
	}

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/library/common.txt", nil)
	dr, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	dr.Body.Close()
	if dr.StatusCode != http.StatusOK {
		t.Fatalf("delete status %d", dr.StatusCode)
	}
	if w2, _ := getJSON(t, ts.URL+"/api/v1/library")["wordlists"].([]any); len(w2) != 0 {
		t.Fatalf("library not empty after delete: %v", w2)
	}
}

// TestClusterHealthGating checks the health check is gated behind
// AllowServerPaths and, when allowed, reports a reachable server as up.
func TestClusterHealthGating(t *testing.T) {
	ts := newTestServer(t) // AllowServerPaths defaults to false
	resp, err := http.PostForm(ts.URL+"/api/v1/cluster/health", url.Values{"servers": {ts.URL}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("health check without allow-server-paths = %d, want 403", resp.StatusCode)
	}

	srv, err := NewServer(Config{WorkDir: t.TempDir(), AllowServerPaths: true})
	if err != nil {
		t.Fatal(err)
	}
	ts2 := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts2.Close(); srv.Close() })
	r2, err := http.PostForm(ts2.URL+"/api/v1/cluster/health", url.Values{"servers": {ts2.URL}})
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	var out struct {
		Servers []struct {
			OK bool `json:"ok"`
		} `json:"servers"`
	}
	json.NewDecoder(r2.Body).Decode(&out)
	if len(out.Servers) != 1 || !out.Servers[0].OK {
		t.Fatalf("self health = %+v, want one reachable server", out.Servers)
	}
}

// TestConcurrencyLimitSemaphore checks the job-concurrency cap wires a semaphore.
func TestConcurrencyLimitSemaphore(t *testing.T) {
	m, err := NewManager(Config{WorkDir: t.TempDir(), MaxConcurrentJobs: 2})
	if err != nil {
		t.Fatal(err)
	}
	if m.sem == nil || cap(m.sem) != 2 {
		t.Fatalf("sem = %v, want a channel of cap 2", m.sem)
	}
	m0, err := NewManager(Config{WorkDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if m0.sem != nil {
		t.Fatal("unlimited manager should have a nil semaphore")
	}
}
