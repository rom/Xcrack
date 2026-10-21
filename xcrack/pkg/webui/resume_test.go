package webui

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xcrypto"
)

// TestResumeFromChallenge is the challenge round-trip end to end: a job whose
// own candidate set does NOT contain the password still recovers it, because a
// solved-challenge `recovered` part injects it as a priority password.
func TestResumeFromChallenge(t *testing.T) {
	data, err := os.ReadFile(fixtureDoc)
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	ts := newTestServer(t)

	recovered, err := xcrypto.MarshalRecoveredPassword("secret.doc", fixturePassword)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	// No passwords, no default list: the job can only win via the resume import.
	mw.WriteField("spec", `{"candidates":{"use_default_list":false}}`)
	fw, _ := mw.CreateFormFile("source", "secret.doc")
	fw.Write(data)
	rw, _ := mw.CreateFormFile("recovered", "recovered.json")
	rw.Write(recovered)
	mw.Close()

	resp, err := http.Post(ts.URL+"/api/v1/jobs", mw.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	var created struct{ ID string }
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if created.ID == "" {
		t.Fatal("no job id returned")
	}

	job := pollJob(t, ts, created.ID)
	if job["state"] != "done" {
		t.Fatalf("job state = %v, want done (%v)", job["state"], job["error"])
	}
	if rc, _ := job["resume_count"].(float64); rc != 1 {
		t.Errorf("resume_count = %v, want 1", job["resume_count"])
	}
	raw, _ := json.Marshal(job)
	if !bytes.Contains(raw, []byte(fixturePassword)) {
		t.Fatalf("job did not recover the password from the solved challenge; got %s", raw)
	}
}

// TestDecodeRecoveredPasswords covers the single-object and array payloads, the
// empty-password case, and version rejection.
func TestDecodeRecoveredPasswords(t *testing.T) {
	single, _ := xcrypto.MarshalRecoveredPassword("a.zip", "hunter2")
	got, err := decodeRecoveredPasswords(single)
	if err != nil || len(got) != 1 || got[0] != "hunter2" {
		t.Fatalf("single: got %v, %v", got, err)
	}

	arr, _ := json.Marshal([]xcrypto.RecoveredPassword{
		{Version: xcrypto.RecoveredPasswordVersion, Password: "p1"},
		{Version: xcrypto.RecoveredPasswordVersion, Password: ""}, // empty dropped
		{Version: xcrypto.RecoveredPasswordVersion, Password: "p2"},
	})
	got, err = decodeRecoveredPasswords(arr)
	if err != nil {
		t.Fatalf("array: %v", err)
	}
	if len(got) != 2 || got[0] != "p1" || got[1] != "p2" {
		t.Fatalf("array: got %v, want [p1 p2]", got)
	}

	bad, _ := json.Marshal([]xcrypto.RecoveredPassword{{Version: 999, Password: "x"}})
	if _, err := decodeRecoveredPasswords(bad); err == nil {
		t.Error("expected an error for an unsupported version")
	}
}

// TestCheckpointHelpers covers the checkpoint signature stability and the
// carry-forward copy used by re-run.
func TestCheckpointHelpers(t *testing.T) {
	a := specSig("candidates:\n  use_default_list: true\n")
	b := specSig("candidates:\n  use_default_list: true\n")
	c := specSig("candidates:\n  use_default_list: false\n")
	if a != b {
		t.Error("specSig is not stable for identical input")
	}
	if a == c {
		t.Error("specSig did not change for a changed spec")
	}
	if checkpointSig(a, "f.zip", 10) == checkpointSig(a, "f.zip", 11) {
		t.Error("checkpointSig must change with the file size")
	}

	// copyCheckpoints carries a .ck file from one job dir to another; hasCheckpoint
	// then sees it.
	oldDir, newDir := t.TempDir(), t.TempDir()
	ckDir := filepath.Join(oldDir, checkpointSubdir)
	if err := os.MkdirAll(ckDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ckDir, "f.ck"), []byte("sig\n42\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if hasCheckpoint(newDir) {
		t.Fatal("new dir should have no checkpoint yet")
	}
	if err := copyCheckpoints(oldDir, newDir); err != nil {
		t.Fatalf("copyCheckpoints: %v", err)
	}
	if !hasCheckpoint(newDir) {
		t.Fatal("copyCheckpoints did not carry the checkpoint forward")
	}
}

// TestFinishedJobNotResumable confirms a job that completed leaves no checkpoint
// behind (so its re-run is a fresh start, not a resume).
func TestFinishedJobNotResumable(t *testing.T) {
	ts := newTestServer(t)
	job := runFixtureJob(t, ts, `{"candidates":{"use_default_list":false,"passwords":["`+fixturePassword+`"]}}`)
	if job["state"] != "done" {
		t.Fatalf("state = %v, want done", job["state"])
	}
	if r, _ := job["resumable"].(bool); r {
		t.Error("a completed job must not be marked resumable")
	}
}
