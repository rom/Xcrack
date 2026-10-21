package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// trustedTestServer is a webui server started with AllowServerPaths, as a fleet
// (distributed) deployment requires.
func trustedTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv, err := NewServer(Config{WorkDir: t.TempDir(), AllowServerPaths: true, Version: "test"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); srv.Close() })
	return ts
}

func putJSON(t *testing.T, url, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestFleetSaveLoadAndValidation saves a fleet (dropping a malformed entry and a
// duplicate) and reads it back.
func TestFleetSaveLoadAndValidation(t *testing.T) {
	ts := trustedTestServer(t)
	body := `{"nodes":[
		{"url":"https://node1:8443","group":"gpu","label":"rack-1"},
		{"url":"not-a-url"},
		{"url":"https://node1:8443"},
		{"url":"http://node2:8899"}
	]}`
	resp := putJSON(t, ts.URL+"/api/v1/fleet", body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	got := getJSON(t, ts.URL+"/api/v1/fleet")
	nodes, _ := got["nodes"].([]any)
	if len(nodes) != 2 {
		t.Fatalf("got %d nodes, want 2 (malformed + duplicate dropped): %v", len(nodes), got["nodes"])
	}
	first := nodes[0].(map[string]any)
	if first["url"] != "https://node1:8443" || first["group"] != "gpu" || first["label"] != "rack-1" {
		t.Errorf("first node = %v", first)
	}
	if got["distributed_ready"] != true {
		t.Errorf("distributed_ready = %v, want true", got["distributed_ready"])
	}
}

// TestFleetGatedWithoutAllowServerPaths confirms a fleet cannot be managed or
// probed on an untrusted instance, while a read still works.
func TestFleetGatedWithoutAllowServerPaths(t *testing.T) {
	ts := newTestServer(t) // AllowServerPaths off
	resp := putJSON(t, ts.URL+"/api/v1/fleet", `{"nodes":[{"url":"https://n:1"}]}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("PUT status = %d, want 403 without --allow-server-paths", resp.StatusCode)
	}
	resp.Body.Close()

	h, err := http.Post(ts.URL+"/api/v1/fleet/health", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	if h.StatusCode != http.StatusForbidden {
		t.Fatalf("health status = %d, want 403", h.StatusCode)
	}
	h.Body.Close()

	got := getJSON(t, ts.URL+"/api/v1/fleet")
	if got["distributed_ready"] != false {
		t.Errorf("distributed_ready = %v, want false", got["distributed_ready"])
	}
}

// TestFleetHealthProbesNode saves a node pointing at a stub xcrack-web and
// confirms the probe reports it up with its version and GPU tier.
func TestFleetHealthProbesNode(t *testing.T) {
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/meta" {
			_ = json.NewEncoder(w).Encode(map[string]any{"version": "9.9", "gpu_available": true})
			return
		}
		w.WriteHeader(http.StatusOK) // healthz etc.
	}))
	defer node.Close()

	ts := trustedTestServer(t)
	resp := putJSON(t, ts.URL+"/api/v1/fleet", `{"nodes":[{"url":"`+node.URL+`","group":"gpu"}]}`)
	resp.Body.Close()

	hr, err := http.Post(ts.URL+"/api/v1/fleet/health", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hr.Body.Close()
	var out struct {
		Nodes []nodeHealth `json:"nodes"`
	}
	json.NewDecoder(hr.Body).Decode(&out)
	if len(out.Nodes) != 1 {
		t.Fatalf("got %d node healths, want 1", len(out.Nodes))
	}
	n := out.Nodes[0]
	if !n.OK || n.Version != "9.9" || !n.GPU {
		t.Fatalf("node health = %+v, want ok/version 9.9/gpu", n)
	}
}
