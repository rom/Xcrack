package webui

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/rom/xcrack/pkg/api"
	"github.com/rom/xcrack/pkg/xcrack"
)

// runFixtureJob submits a crack of the RC4 .doc fixture with the given extra
// spec blocks and returns the finished job view. It skips if the fixture or the
// expected success is unavailable.
func runFixtureJob(t *testing.T, ts *httptest.Server, spec string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(fixtureDoc)
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	body, ct := buildJobRequest(t, spec, map[string][]byte{"secret.doc": data}, nil)
	resp, err := http.Post(ts.URL+"/api/v1/jobs", ct, body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create job: status %d: %s", resp.StatusCode, b)
	}
	var created struct{ ID string }
	json.NewDecoder(resp.Body).Decode(&created)
	return pollJob(t, ts, created.ID)
}

func TestStatsAlgoSpeedAndTopPasswords(t *testing.T) {
	ts := newTestServer(t)
	job := runFixtureJob(t, ts, `{"candidates":{"use_default_list":false,"passwords":["`+fixturePassword+`"]}}`)
	if job["state"] != "done" {
		t.Fatalf("job state = %v, want done", job["state"])
	}
	stats := getJSON(t, ts.URL+"/api/v1/stats")
	speeds, _ := stats["algo_speed"].([]any)
	if len(speeds) == 0 {
		t.Fatal("algo_speed is empty; want at least one format")
	}
	first := speeds[0].(map[string]any)
	if first["format"] == nil || first["format"] == "" {
		t.Errorf("algo_speed[0] has no format: %v", first)
	}
	// ExposeSecrets is on for the test server, so the recovered password appears
	// in the top list.
	top, _ := stats["top_passwords"].([]any)
	found := false
	for _, e := range top {
		if e.(map[string]any)["password"] == fixturePassword {
			found = true
		}
	}
	if !found {
		t.Fatalf("top_passwords = %v, want it to include %q", top, fixturePassword)
	}
}

func TestJobReportsKeyspace(t *testing.T) {
	ts := newTestServer(t)
	// A single file with an explicit, finite candidate list has a known keyspace.
	job := runFixtureJob(t, ts, `{"candidates":{"use_default_list":false,"passwords":["a","b","`+fixturePassword+`"]}}`)
	ks, ok := job["keyspace"].(float64)
	if !ok || ks != 3 {
		t.Fatalf("keyspace = %v, want 3 (finite determinate)", job["keyspace"])
	}
}

func TestDistributedRequiresAllowServerPaths(t *testing.T) {
	ts := newTestServer(t) // AllowServerPaths defaults to false
	spec := `{"cluster":{"servers":[{"url":"http://127.0.0.1:1"}]}}`
	body, ct := buildJobRequest(t, spec, map[string][]byte{"x.bin": []byte("hi")}, nil)
	resp, err := http.Post(ts.URL+"/api/v1/jobs", ct, body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), "allow-server-paths") {
		t.Fatalf("distributed without allow-server-paths: status %d (%s), want 400 citing allow-server-paths", resp.StatusCode, b)
	}
}

func TestDistributedCrack(t *testing.T) {
	fixture, err := os.ReadFile(fixtureDoc)
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	// Stand up an in-process xcrackd as the distributed worker.
	pool := xcrack.NewPool(xcrack.Options{})
	defer pool.Close()
	backend := httptest.NewServer(api.NewServer(pool, api.Config{}).Handler())
	defer backend.Close()

	srv, err := NewServer(Config{WorkDir: t.TempDir(), ExposeSecrets: true, AllowServerPaths: true})
	if err != nil {
		t.Fatal(err)
	}
	// Drain in-flight job runners before the t.TempDir() work directory is removed
	// (registered before ts.Close so it runs after it: stop HTTP, then drain). This
	// test builds its own server rather than using newTestServer, so it needs the
	// same Close() the helper does.
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	spec := `{"candidates":{"use_default_list":false,"passwords":["nope","` + fixturePassword +
		`"]},"cluster":{"servers":[{"url":"` + backend.URL + `"}],"mode":"collective"}}`
	body, ct := buildJobRequest(t, spec, map[string][]byte{"secret.doc": fixture}, nil)
	resp, err := http.Post(ts.URL+"/api/v1/jobs", ct, body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create distributed job: status %d: %s", resp.StatusCode, b)
	}
	var created struct{ ID string }
	json.NewDecoder(resp.Body).Decode(&created)

	job := pollJob(t, ts, created.ID)
	if job["distributed"] != true {
		t.Errorf("job.distributed = %v, want true", job["distributed"])
	}
	if job["state"] != "done" {
		t.Fatalf("distributed job state = %v, want done (%v)", job["state"], job["error"])
	}
	raw, _ := json.Marshal(job)
	if !strings.Contains(string(raw), fixturePassword) {
		t.Fatalf("distributed job did not recover the password; got %s", raw)
	}
}
