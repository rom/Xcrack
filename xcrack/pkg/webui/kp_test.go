package webui

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"testing"
	"time"
)

// waitState polls until the job reaches want (or times out).
func waitState(m *Manager, id string, want JobState, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if j := m.get(id); j != nil && j.snapshot().State == want {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// TestSpecialistJobLifecycle exercises the specialist (non-crack) job path the
// tools run on: a job with its own work function runs to done, carrying its Kind
// and results through the standard job machinery.
func TestSpecialistJobLifecycle(t *testing.T) {
	m, err := NewManager(Config{WorkDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown()
	j, err := m.newJob()
	if err != nil {
		t.Fatal(err)
	}
	j.mu.Lock()
	j.Kind = "demo"
	j.specialist = func(ctx context.Context, jb *Job) error {
		jb.mu.Lock()
		jb.Decrypted = 3
		jb.mu.Unlock()
		jb.emit(Event{Type: "found", File: "x"})
		return nil
	}
	j.mu.Unlock()
	m.start(j)

	if !waitState(m, j.ID, StateDone, 5*time.Second) {
		t.Fatalf("specialist job did not reach done (state=%v)", j.snapshot().State)
	}
	v := j.snapshot()
	if v.Kind != "demo" || v.Decrypted != 3 {
		t.Fatalf("snapshot = kind %q decrypted %d, want demo/3", v.Kind, v.Decrypted)
	}
}

// TestSpecialistJobCancel checks a specialist job honors cancellation.
func TestSpecialistJobCancel(t *testing.T) {
	m, err := NewManager(Config{WorkDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown()
	j, _ := m.newJob()
	started := make(chan struct{})
	j.mu.Lock()
	j.Kind = "demo"
	j.specialist = func(ctx context.Context, jb *Job) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}
	j.mu.Unlock()
	m.start(j)
	<-started
	if !m.cancel(j.ID) {
		t.Fatal("cancel returned false for a running specialist job")
	}
	if !waitState(m, j.ID, StateCanceled, 5*time.Second) {
		t.Fatalf("specialist job did not cancel (state=%v)", j.snapshot().State)
	}
}

// TestToolKPValidation covers the kp endpoint's input guards (the actual
// Biham–Kocher recovery is compute-heavy and covered by the zipcrypto package).
func TestToolKPValidation(t *testing.T) {
	ts := newTestServer(t)
	post := func(plain, cipher []byte) int {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		if plain != nil {
			w, _ := mw.CreateFormFile("plain", "p")
			w.Write(plain)
		}
		if cipher != nil {
			w, _ := mw.CreateFormFile("cipher", "c")
			w.Write(cipher)
		}
		mw.Close()
		resp, err := http.Post(ts.URL+"/api/v1/tools/kp", mw.FormDataContentType(), &buf)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if sc := post(nil, nil); sc != http.StatusBadRequest {
		t.Fatalf("missing parts = %d, want 400", sc)
	}
	if sc := post(bytes.Repeat([]byte("x"), 16), bytes.Repeat([]byte("y"), 8)); sc != http.StatusBadRequest {
		t.Fatalf("unequal lengths = %d, want 400", sc)
	}
	if sc := post([]byte("short"), []byte("short")); sc != http.StatusBadRequest {
		t.Fatalf("too-short plaintext = %d, want 400", sc)
	}
}
