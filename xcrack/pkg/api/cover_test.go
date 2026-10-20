package api

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestParseShardSpec(t *testing.T) {
	cases := []struct {
		in   string
		i, n int
		ok   bool
	}{
		{"0/4", 0, 4, true},
		{"3/4", 3, 4, true},
		{" 1 / 2 ", 1, 2, true}, // whitespace tolerated
		{"", 0, 0, false},       // not I/N
		{"1", 0, 0, false},      // missing /N
		{"4/4", 0, 0, false},    // index must be < count
		{"-1/4", 0, 0, false},   // negative index
		{"2/0", 0, 0, false},    // count must be >= 1
		{"a/b", 0, 0, false},    // non-numeric
	}
	for _, c := range cases {
		i, n, ok := parseShardSpec(c.in)
		if ok != c.ok || (ok && (i != c.i || n != c.n)) {
			t.Errorf("parseShardSpec(%q) = (%d,%d,%v), want (%d,%d,%v)", c.in, i, n, ok, c.i, c.n, c.ok)
		}
	}
}

func TestPrometheusEndpoint(t *testing.T) {
	ts := newTestServer(Config{})
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain exposition format", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Fatal("Prometheus body is empty")
	}

	// Non-GET is rejected.
	preq, _ := http.NewRequest(http.MethodPost, ts.URL+"/metrics", nil)
	presp, err := http.DefaultClient.Do(preq)
	if err != nil {
		t.Fatal(err)
	}
	presp.Body.Close()
	if presp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /metrics = %d, want 405", presp.StatusCode)
	}
}
