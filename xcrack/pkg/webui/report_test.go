package webui

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/rom/xcrack/pkg/xcrack"
)

// TestJobReport submits a crack carrying case metadata, then checks that the
// forensic report (HTML + CSV) records the case, the recovered node with its
// SHA-256, and — the test server runs with ExposeSecrets — the password.
func TestJobReport(t *testing.T) {
	data, err := os.ReadFile(fixtureDoc)
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	ts := newTestServer(t)

	// Build a job request that also carries the case_id/examiner form fields.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("spec", `{"candidates":{"use_default_list":false,"passwords":["nope","`+fixturePassword+`"]}}`)
	mw.WriteField("case_id", "2026-0042")
	mw.WriteField("examiner", "Dana Scully")
	fw, _ := mw.CreateFormFile("source", "secret.doc")
	fw.Write(data)
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
	// The case metadata must round-trip onto the job view.
	if job["case_id"] != "2026-0042" || job["examiner"] != "Dana Scully" {
		t.Fatalf("case metadata not recorded: case_id=%v examiner=%v", job["case_id"], job["examiner"])
	}

	// HTML report: case block, chain-of-custody, and the recovered secret.
	htmlBody := getText(t, ts.URL+"/api/v1/jobs/"+created.ID+"/report")
	for _, want := range []string{"2026-0042", "Dana Scully", "Chain of custody", "SHA-256", fixturePassword} {
		if !strings.Contains(htmlBody, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
	if !strings.Contains(htmlBody, "<!doctype html>") {
		t.Error("HTML report is not an HTML document")
	}

	// CSV report: header row plus a data row carrying the case + secret.
	csvBody := getText(t, ts.URL+"/api/v1/jobs/"+created.ID+"/report?format=csv")
	if !strings.Contains(csvBody, "job_id,case_id,examiner,path,format,encrypted,status,password,size,sha256") {
		t.Errorf("CSV report missing header; got:\n%s", csvBody)
	}
	if !strings.Contains(csvBody, "2026-0042") || !strings.Contains(csvBody, fixturePassword) {
		t.Errorf("CSV report missing case id or password; got:\n%s", csvBody)
	}
}

// TestReportHidesSecretsByDefault confirms the report never leaks a recovered
// password when the server was not started with ExposeSecrets.
func TestReportHidesSecretsByDefault(t *testing.T) {
	srv, err := NewServer(Config{WorkDir: t.TempDir(), Version: "test"}) // ExposeSecrets off
	if err != nil {
		t.Fatal(err)
	}
	report := &xcrack.Report{Root: xcrack.NodeReport{
		Path: "secret.doc", Format: "msoffice", Status: "decrypted",
		WasEncrypted: true, Password: "hunter2", SHA256: "abc123",
	}}
	v := JobView{
		ID: "job1", CaseID: "C-1", Examiner: "ex", State: StateDone,
		Results: []FileResult{{Name: "secret.doc", Report: report}},
	}
	rec := httptest.NewRecorder()
	srv.reportHTML(rec, v, nil)
	body := rec.Body.String()
	if strings.Contains(body, "hunter2") {
		t.Fatal("report leaked a recovered password with ExposeSecrets off")
	}
	if !strings.Contains(body, "(hidden)") {
		t.Fatal("report should mark a recovered password as (hidden)")
	}
}

func getText(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
