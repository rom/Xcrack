package webui

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// TestJobPersistAndReload checks that a job's view is written under WorkDir and
// that a fresh Manager over the same directory reloads it — a finished job as it
// was, and a job left running by a dead process as interrupted.
func TestJobPersistAndReload(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(Config{WorkDir: dir})
	if err != nil {
		t.Fatal(err)
	}

	done, err := m.newJob()
	if err != nil {
		t.Fatal(err)
	}
	done.mu.Lock()
	done.State = StateDone
	done.Files = []string{"vault.zip"}
	done.Decrypted = 2
	done.SpecYAML = "candidates:\n  use_default_list: true\n"
	done.EndedAt = nowMS()
	done.mu.Unlock()
	m.persist(done)

	running, err := m.newJob()
	if err != nil {
		t.Fatal(err)
	}
	running.mu.Lock()
	running.State = StateRunning
	running.Files = []string{"big.dmg"}
	running.mu.Unlock()
	m.persist(running)

	// A fresh manager over the same work directory must repopulate from disk.
	m2, err := NewManager(Config{WorkDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	got := m2.get(done.ID)
	if got == nil {
		t.Fatalf("finished job was not reloaded")
	}
	v := got.snapshot()
	if v.State != StateDone || len(v.Files) != 1 || v.Files[0] != "vault.zip" || v.Decrypted != 2 || v.SpecYAML == "" {
		t.Fatalf("reloaded view wrong: %+v", v)
	}

	run := m2.get(running.ID)
	if run == nil || run.snapshot().State != StateInterrupted {
		t.Fatalf("running job should reload as interrupted, got %+v", run)
	}
	if run.snapshot().Error == "" {
		t.Fatalf("interrupted job should carry an explanatory error")
	}

	// A reloaded job is terminal: its done channel is already closed, so a late
	// SSE subscriber returns at once instead of blocking.
	_, _, d, cancel := got.subscribe()
	defer cancel()
	select {
	case <-d:
	default:
		t.Fatalf("reloaded job's done channel should be closed")
	}
}

// TestManagerRemove checks that remove drops a job and deletes its directory,
// and that newJob persists a record from creation.
func TestManagerRemove(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(Config{WorkDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	j, err := m.newJob()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(j.dir, "job.json")); err != nil {
		t.Fatalf("newJob should persist job.json: %v", err)
	}
	jobDir := j.dir
	if !m.remove(j.ID) {
		t.Fatalf("remove returned false for an existing job")
	}
	if m.get(j.ID) != nil {
		t.Fatalf("job still present after remove")
	}
	if _, err := os.Stat(jobDir); !os.IsNotExist(err) {
		t.Fatalf("job dir should be gone after remove, stat err = %v", err)
	}
	if m.remove("deadbeef") {
		t.Fatalf("remove of an unknown id should return false")
	}
}

// TestHistoryListAndDelete exercises the HTTP surface: a finished job appears in
// the job list (history) and DELETE removes it.
func TestHistoryListAndDelete(t *testing.T) {
	ts := newTestServer(t)
	spec := `{"candidates":{"use_default_list":false,"passwords":["a","b"]}}`
	body, ct := buildJobRequest(t, spec, map[string][]byte{"x.bin": []byte("hello")}, nil)
	resp, err := http.Post(ts.URL+"/api/v1/jobs", ct, body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("create job: %d %s", resp.StatusCode, b)
	}
	var created struct{ ID string }
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if created.ID == "" {
		t.Fatal("no job id returned")
	}

	pollJob(t, ts, created.ID) // wait until the job reaches a terminal state

	list := getJSON(t, ts.URL+"/api/v1/jobs")
	if jobs, _ := list["jobs"].([]any); len(jobs) == 0 {
		t.Fatalf("job history is empty after a completed run")
	}

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/jobs/"+created.ID, nil)
	dresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	dresp.Body.Close()
	if dresp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d, want 200", dresp.StatusCode)
	}

	gresp, err := http.Get(ts.URL + "/api/v1/jobs/" + created.ID)
	if err != nil {
		t.Fatal(err)
	}
	gresp.Body.Close()
	if gresp.StatusCode != http.StatusNotFound {
		t.Fatalf("get after delete = %d, want 404", gresp.StatusCode)
	}
}
