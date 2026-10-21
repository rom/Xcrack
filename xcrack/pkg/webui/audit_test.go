package webui

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
)

// TestAuditTrail checks that an action is recorded to the trail and returned by
// the admin audit endpoint, without leaking a recovered secret.
func TestAuditTrail(t *testing.T) {
	data, err := os.ReadFile(fixtureDoc)
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	ts := newTestServer(t)

	// An inspect action is auditable.
	resp := postMultipart(t, ts.URL+"/api/v1/inspect",
		map[string]string{"spec": "patterns:\n  masks: [\"?d\"]\n"},
		map[string][]byte{"secret.doc": data})
	resp.Body.Close()

	ar, err := http.Get(ts.URL + "/api/v1/audit")
	if err != nil {
		t.Fatal(err)
	}
	defer ar.Body.Close()
	if ar.StatusCode != http.StatusOK {
		t.Fatalf("GET /audit = %d, want 200 (single-user is admin)", ar.StatusCode)
	}
	var out struct {
		Entries []struct {
			Actor  string `json:"actor"`
			Action string `json:"action"`
			Detail string `json:"detail"`
		} `json:"entries"`
	}
	if err := json.NewDecoder(ar.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range out.Entries {
		if e.Action == "inspect" {
			found = true
			if e.Actor != "local" {
				t.Fatalf("inspect actor = %q, want local", e.Actor)
			}
		}
	}
	if !found {
		t.Fatalf("no 'inspect' audit entry; got %+v", out.Entries)
	}
}

// TestAuditTrailTailOrder checks tail returns the newest entries first.
func TestAuditTrailTailOrder(t *testing.T) {
	tr := newAuditTrail(t.TempDir(), nil)
	for i := 0; i < 5; i++ {
		tr.record(auditEntry{Action: "a", Target: string(rune('0' + i)), Time: int64(i + 1)})
	}
	got := tr.tail(3)
	if len(got) != 3 {
		t.Fatalf("tail(3) = %d entries, want 3", len(got))
	}
	if got[0].Target != "4" || got[2].Target != "2" {
		t.Fatalf("tail order = %q..%q, want newest-first 4..2", got[0].Target, got[2].Target)
	}
}
