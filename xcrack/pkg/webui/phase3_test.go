package webui

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// TestVaultRecordReloadAndGating checks the found-password vault: records persist
// and reload, and the vault is active only on a single-user, secrets-exposed
// instance (never with auth on or secrets hidden).
func TestVaultRecordReloadAndGating(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(Config{WorkDir: dir, ExposeSecrets: true})
	if err != nil {
		t.Fatal(err)
	}
	if !m.vaultActive() {
		t.Fatal("vault should be active for single-user + expose")
	}
	m.recordFound("hunter2")
	m.recordFound("hunter2") // duplicate: no new entry
	m.recordFound("s3cret")
	enc, pws := m.vaultView()
	if enc {
		t.Fatal("plaintext vault reported as encrypted")
	}
	if len(pws) != 2 || pws[0] != "hunter2" || pws[1] != "s3cret" {
		t.Fatalf("vault = %v, want [hunter2 s3cret]", pws)
	}

	// Reload from the same directory: the potfile persisted.
	m2, err := NewManager(Config{WorkDir: dir, ExposeSecrets: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, pws2 := m2.vaultView(); len(pws2) != 2 {
		t.Fatalf("reloaded vault = %v, want 2 entries", pws2)
	}

	// Secrets hidden → inactive.
	mHidden, _ := NewManager(Config{WorkDir: t.TempDir()})
	if mHidden.vaultActive() {
		t.Fatal("vault must be inactive when secrets are not exposed")
	}
	// Multi-user → inactive (no cross-user leakage), and recording is a no-op.
	mAuth, _ := NewManager(Config{WorkDir: t.TempDir(), ExposeSecrets: true, Auth: AuthConfig{Enabled: true}})
	if mAuth.vaultActive() {
		t.Fatal("vault must be inactive in multi-user mode")
	}
	mAuth.recordFound("leak")
	if _, pws := mAuth.vaultView(); len(pws) != 0 {
		t.Fatalf("multi-user vault should stay empty, got %v", pws)
	}
}

// TestRerunReusesSpecAndSources checks that re-running a finished job starts a
// fresh job from the saved spec + uploads (no re-upload) with the same files.
func TestRerunReusesSpecAndSources(t *testing.T) {
	ts := newTestServer(t)
	spec := `{"candidates":{"use_default_list":false,"passwords":["a","b"]}}`
	body, ct := buildJobRequest(t, spec, map[string][]byte{"x.bin": []byte("hello")}, nil)
	resp, err := http.Post(ts.URL+"/api/v1/jobs", ct, body)
	if err != nil {
		t.Fatal(err)
	}
	var created struct {
		ID string `json:"id"`
	}
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if created.ID == "" {
		t.Fatal("no job id")
	}
	pollJob(t, ts, created.ID)

	rr, err := http.Post(ts.URL+"/api/v1/jobs/"+created.ID+"/rerun", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rr.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(rr.Body)
		rr.Body.Close()
		t.Fatalf("rerun status %d: %s", rr.StatusCode, b)
	}
	var again struct {
		ID string `json:"id"`
	}
	json.NewDecoder(rr.Body).Decode(&again)
	rr.Body.Close()
	if again.ID == "" || again.ID == created.ID {
		t.Fatalf("rerun should create a new job id, got %q (original %q)", again.ID, created.ID)
	}

	got := pollJob(t, ts, again.ID)
	files, _ := got["files"].([]any)
	if len(files) != 1 || files[0] != "x.bin" {
		t.Fatalf("re-run job files = %v, want [x.bin]", got["files"])
	}
}
