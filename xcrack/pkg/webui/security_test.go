package webui

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// serverWith builds a test server with a custom Config (WorkDir filled in).
func serverWith(t *testing.T, cfg Config) *httptest.Server {
	t.Helper()
	cfg.WorkDir = t.TempDir()
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); srv.Close() })
	return ts
}

func TestCSRFGuard(t *testing.T) {
	ts := serverWith(t, Config{Version: "test"})
	body := "patterns:\n  masks: [\"?d\"]\n"
	do := func(set func(*http.Request)) int {
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1/config/validate", strings.NewReader(body))
		if set != nil {
			set(req)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	// No browser-origin headers (curl/CLI/test): allowed.
	if sc := do(nil); sc != http.StatusOK {
		t.Fatalf("no-origin POST = %d, want 200", sc)
	}
	// Same-origin Origin: allowed.
	if sc := do(func(r *http.Request) { r.Header.Set("Origin", ts.URL) }); sc != http.StatusOK {
		t.Fatalf("same-origin POST = %d, want 200", sc)
	}
	// Cross-origin Origin: refused.
	if sc := do(func(r *http.Request) { r.Header.Set("Origin", "http://evil.example") }); sc != http.StatusForbidden {
		t.Fatalf("cross-origin POST = %d, want 403", sc)
	}
	// Sec-Fetch-Site cross-site: refused even without an Origin mismatch.
	if sc := do(func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }); sc != http.StatusForbidden {
		t.Fatalf("cross-site fetch POST = %d, want 403", sc)
	}
	// GET is never gated (it is not state-changing).
	resp, err := http.Get(ts.URL + "/api/v1/meta")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET meta = %d, want 200", resp.StatusCode)
	}
}

func TestRateLimit(t *testing.T) {
	ts := serverWith(t, Config{Version: "test", RateLimitPerMin: 3})
	codes := make([]int, 0, 6)
	for i := 0; i < 6; i++ {
		resp, err := http.Get(ts.URL + "/api/v1/meta")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		codes = append(codes, resp.StatusCode)
	}
	// First 3 within budget, the rest limited.
	for i := 0; i < 3; i++ {
		if codes[i] != http.StatusOK {
			t.Fatalf("request %d = %d, want 200", i, codes[i])
		}
	}
	if codes[5] != http.StatusTooManyRequests {
		t.Fatalf("request 6 = %d, want 429", codes[5])
	}
}

func TestPruneRetention(t *testing.T) {
	m, err := NewManager(Config{WorkDir: t.TempDir(), MaxRetainedJobs: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown()
	for i := 0; i < 5; i++ {
		v := JobView{ID: fmt.Sprintf("job%d", i), State: StateDone, CreatedAt: int64(i + 1), EndedAt: int64(i + 1)}
		dir := filepath.Join(m.cfg.WorkDir, v.ID)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		m.jobs[v.ID] = m.jobFromView(v, dir)
	}
	m.prune()
	if len(m.jobs) != 2 {
		t.Fatalf("after prune: %d jobs, want 2 (newest)", len(m.jobs))
	}
	if m.get("job4") == nil || m.get("job3") == nil {
		t.Fatal("prune removed a newest job")
	}
	if m.get("job0") != nil {
		t.Fatal("prune kept an oldest job beyond the cap")
	}
	if _, err := os.Stat(filepath.Join(m.cfg.WorkDir, "job0")); !os.IsNotExist(err) {
		t.Fatal("prune did not delete the pruned job's directory")
	}
}

func TestWorkDirQuota(t *testing.T) {
	m, err := NewManager(Config{WorkDir: t.TempDir(), MaxWorkDirBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown()
	if m.overQuota() {
		t.Fatal("empty work dir reported over quota")
	}
	if err := os.WriteFile(filepath.Join(m.cfg.WorkDir, "blob"), make([]byte, 64), 0o600); err != nil {
		t.Fatal(err)
	}
	if !m.overQuota() {
		t.Fatal("work dir over the 1-byte cap not reported over quota")
	}
}
