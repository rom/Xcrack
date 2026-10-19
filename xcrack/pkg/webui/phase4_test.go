package webui

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"testing"
)

// TestRuleTestTool checks the rule-tester endpoint applies real mangling rules to
// a sample word, reporting per-rule output and rejection.
func TestRuleTestTool(t *testing.T) {
	ts := newTestServer(t)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("word", "pass")
	mw.WriteField("rules", "c\nu\n=0z") // capitalize, uppercase, reject-unless-first-char-z
	mw.Close()

	resp, err := http.Post(ts.URL+"/api/v1/tools/rule-test", mw.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var out struct {
		Results []struct {
			Rule   string `json:"rule"`
			Output string `json:"output"`
			Kept   bool   `json:"kept"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 3 {
		t.Fatalf("got %d results, want 3: %+v", len(out.Results), out.Results)
	}
	if !out.Results[0].Kept || out.Results[0].Output != "Pass" {
		t.Fatalf("rule c => %+v, want kept output Pass", out.Results[0])
	}
	if !out.Results[1].Kept || out.Results[1].Output != "PASS" {
		t.Fatalf("rule u => %+v, want kept output PASS", out.Results[1])
	}
	if out.Results[2].Kept {
		t.Fatalf("rule =0z should reject 'pass', got kept with %q", out.Results[2].Output)
	}
}

// TestRuleTestRequiresWord checks the endpoint rejects an empty sample word.
func TestRuleTestRequiresWord(t *testing.T) {
	ts := newTestServer(t)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("rules", "c")
	mw.Close()
	resp, err := http.Post(ts.URL+"/api/v1/tools/rule-test", mw.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty word status = %d, want 400", resp.StatusCode)
	}
}
