package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// auditFixture is a real encrypted sample reachable from the xcrack module dir.
func auditFixture(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "..", "..", "xfileformats", "formats", "msoffice", "testdata", "rc4cryptoapi_password.doc")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	return p
}

func readJSONLog(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad json log line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// TestCLIAuditLogRecordsCrack drives the full CLI crack path with a JSON audit
// log to a file and asserts the crack success is recorded with the filename,
// file type and time-to-crack — and that the password appears only with
// --audit-log-password.
func TestCLIAuditLogRecordsCrack(t *testing.T) {
	doc := auditFixture(t)

	t.Run("secrets off by default", func(t *testing.T) {
		logPath := filepath.Join(t.TempDir(), "audit.json")
		rc := runCrack([]string{
			"--source", doc,
			"--password", "Password1234_",
			"--log-format", "json",
			"--log-file", logPath,
		})
		if rc != 0 {
			t.Fatalf("runCrack rc=%d", rc)
		}
		recs := readJSONLog(t, logPath)
		crack := findCrack(recs)
		if crack == nil {
			t.Fatalf("no 'file cracked' record in audit log: %v", recs)
		}
		if crack["type"] != "msoffice" {
			t.Errorf("type=%v want msoffice", crack["type"])
		}
		if _, ok := crack["time_to_crack"]; !ok {
			t.Errorf("time_to_crack missing: %v", crack)
		}
		if _, ok := crack["passwords"]; ok {
			t.Errorf("passwords must not be logged without --audit-log-password: %v", crack)
		}
	})

	t.Run("opt-in logs password", func(t *testing.T) {
		logPath := filepath.Join(t.TempDir(), "audit.json")
		rc := runCrack([]string{
			"--source", doc,
			"--password", "Password1234_",
			"--log-format", "json",
			"--log-file", logPath,
			"--audit-log-password",
		})
		if rc != 0 {
			t.Fatalf("runCrack rc=%d", rc)
		}
		crack := findCrack(readJSONLog(t, logPath))
		if crack == nil {
			t.Fatal("no 'file cracked' record")
		}
		pws, ok := crack["passwords"].([]any)
		if !ok || len(pws) != 1 || pws[0] != "Password1234_" {
			t.Errorf("passwords=%v want [Password1234_]", crack["passwords"])
		}
	})
}

func findCrack(recs []map[string]any) map[string]any {
	for _, m := range recs {
		if m["msg"] == "file cracked" {
			return m
		}
	}
	return nil
}
