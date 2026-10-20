package webui

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
)

// TestInspectEstimatesFeasibility drives /api/v1/inspect with a finite mask
// keyspace (?d?d = 100) against the encrypted .doc fixture and checks the
// response reports the scheme, the exact keyspace, a measured rate, a time
// estimate, and the real candidate stream — the CLI's --keyspace/--benchmark/
// --estimate/--stdout, without starting a job.
func TestInspectEstimatesFeasibility(t *testing.T) {
	data, err := os.ReadFile(fixtureDoc)
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	ts := newTestServer(t)

	// use_default_list:false so only the mask contributes — a deterministic
	// keyspace of exactly 100 (?d?d).
	spec := "candidates:\n  use_default_list: false\npatterns:\n  masks: [\"?d?d\"]\n"
	resp := postMultipart(t, ts.URL+"/api/v1/inspect",
		map[string]string{"spec": spec},
		map[string][]byte{"secret.doc": data})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inspect status = %d, want 200", resp.StatusCode)
	}

	var out struct {
		Files []struct {
			Name            string  `json:"name"`
			Scheme          string  `json:"scheme"`
			Encrypted       bool    `json:"encrypted"`
			Keyspace        int64   `json:"keyspace"`
			Rate            float64 `json:"rate"`
			SecondsExhaust  float64 `json:"seconds_to_exhaust"`
			TimeExhaustText string  `json:"time_to_exhaust"`
		} `json:"files"`
		Preview   []string `json:"candidate_preview"`
		Truncated bool     `json:"candidate_preview_truncated"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Files) != 1 {
		t.Fatalf("files = %d, want 1", len(out.Files))
	}
	f := out.Files[0]
	if !f.Encrypted || f.Scheme == "" {
		t.Fatalf("expected an encrypted scheme, got %+v", f)
	}
	if f.Keyspace != 100 {
		t.Fatalf("keyspace = %d, want 100 (?d?d)", f.Keyspace)
	}
	if f.Rate <= 0 {
		t.Fatalf("rate = %v, want a positive candidates/sec", f.Rate)
	}
	if f.SecondsExhaust <= 0 || f.TimeExhaustText == "" {
		t.Fatalf("expected a time estimate, got seconds=%v text=%q", f.SecondsExhaust, f.TimeExhaustText)
	}
	// The candidate preview is the real assembled stream: 100 finite masks, all
	// shown (under the 200-line cap) and not truncated.
	if len(out.Preview) != 100 || out.Truncated {
		t.Fatalf("preview = %d lines (truncated=%v), want 100 not truncated", len(out.Preview), out.Truncated)
	}
}

// TestInspectRequiresSource rejects a submission with no target file.
func TestInspectRequiresSource(t *testing.T) {
	ts := newTestServer(t)
	resp := postMultipart(t, ts.URL+"/api/v1/inspect",
		map[string]string{"spec": "patterns:\n  masks: [\"?d\"]\n"}, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("inspect with no source: status %d, want 400", resp.StatusCode)
	}
}
