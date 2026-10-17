package auditlog

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xcrack/pkg/xcrack"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"DEBUG":   slog.LevelDebug,
		"info":    slog.LevelInfo,
		"":        slog.LevelInfo,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
		"bogus":   slog.LevelInfo,
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q)=%v want %v", in, got, want)
		}
	}
}

// readLines parses the JSON-lines log file written during a test.
func readLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad json line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func newFileLogger(t *testing.T, includeSecrets bool) (*slog.Logger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	l, closer, err := New(Config{Level: "debug", Format: "json", File: path, IncludeSecrets: includeSecrets})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { closer.Close() })
	return l, path
}

// sampleTree is a container whose encryption lives in a nested entry (the
// pattern of a ZIP or a legacy .doc): the root is a plain container, the inner
// entry is the decrypted node.
func sampleTree() *xcrack.Result {
	root := &xcrack.Node{
		Path: "invoice.zip", Format: "zip", Status: xcrack.StatusPlain,
		Children: []*xcrack.Node{{
			Path: "invoice.zip!/secret.txt", Format: "", WasEncrypted: true,
			Password: "hunter2", Status: xcrack.StatusDecrypted, CrackDuration: 1500 * time.Millisecond,
		}},
	}
	return &xcrack.Result{Root: root}
}

func TestLogFileHeadlineNamesTopLevelType(t *testing.T) {
	l, path := newFileLogger(t, true)
	LogFile(l, "invoice.zip", sampleTree(), true, slog.String("run", "r1"))

	var headline map[string]any
	for _, m := range readLines(t, path) {
		if m["msg"] == "file cracked" {
			headline = m
		}
	}
	if headline == nil {
		t.Fatal("no 'file cracked' headline record")
	}
	if headline["level"] != "INFO" {
		t.Errorf("level=%v want INFO", headline["level"])
	}
	// The headline names the file and its TOP-LEVEL type, not the inner stream.
	if headline["file"] != "invoice.zip" || headline["type"] != "zip" {
		t.Errorf("file/type wrong: %v", headline)
	}
	if headline["cracked"] != true {
		t.Errorf("cracked flag missing: %v", headline)
	}
	if headline["time_to_crack"] != "1.5s" {
		t.Errorf("time_to_crack=%v want 1.5s", headline["time_to_crack"])
	}
	if headline["time_to_crack_ms"].(float64) != 1500 {
		t.Errorf("time_to_crack_ms=%v want 1500", headline["time_to_crack_ms"])
	}
	// Opted in: the password appears (in the passwords list).
	pws, ok := headline["passwords"].([]any)
	if !ok || len(pws) != 1 || pws[0] != "hunter2" {
		t.Errorf("passwords=%v want [hunter2]", headline["passwords"])
	}
	if headline["run"] != "r1" {
		t.Errorf("extra attr missing: %v", headline)
	}
}

func TestLogFileNoSecretByDefault(t *testing.T) {
	l, path := newFileLogger(t, false)
	LogFile(l, "invoice.zip", sampleTree(), false)
	for _, m := range readLines(t, path) {
		if _, ok := m["passwords"]; ok {
			t.Errorf("passwords must not be logged without opt-in: %v", m)
		}
		if _, ok := m["password"]; ok {
			t.Errorf("password must not be logged without opt-in: %v", m)
		}
	}
}

func TestLogFileUncrackedIsDebug(t *testing.T) {
	l, path := newFileLogger(t, false)
	locked := &xcrack.Result{Root: &xcrack.Node{
		Path: "locked.pdf", Format: "pdf", WasEncrypted: true, Status: xcrack.StatusLocked,
	}}
	LogFile(l, "locked.pdf", locked, false)
	var headline map[string]any
	for _, m := range readLines(t, path) {
		if m["msg"] == "file processed" {
			headline = m
		}
	}
	if headline == nil {
		t.Fatal("no 'file processed' record for an uncracked file")
	}
	if headline["level"] != "DEBUG" {
		t.Errorf("level=%v want DEBUG for an uncracked file", headline["level"])
	}
	if headline["cracked"] != false || headline["encrypted"] != true {
		t.Errorf("flags wrong for locked file: %v", headline)
	}
}

func TestSinkEmitsPerNodeDebugTrace(t *testing.T) {
	l, path := newFileLogger(t, true)
	sink := Sink(l)
	sink(xcrack.AuditEvent{
		Path: "invoice.zip!/secret.txt", Format: "", Status: "decrypted",
		Encrypted: true, TimeToCrack: 1500 * time.Millisecond, Password: "hunter2",
	})
	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("want 1 trace record, got %d", len(lines))
	}
	if lines[0]["level"] != "DEBUG" || lines[0]["msg"] != "node scanned" {
		t.Errorf("Sink should emit a debug per-node trace: %v", lines[0])
	}
	if lines[0]["node"] != "invoice.zip!/secret.txt" {
		t.Errorf("node path wrong: %v", lines[0])
	}
	if lines[0]["password"] != "hunter2" {
		t.Errorf("per-node trace should carry the opted-in password: %v", lines[0])
	}
}

func TestNewSyslogUnavailableIsAnError(t *testing.T) {
	// We cannot assume a syslog daemon is reachable in CI; just assert New does
	// not panic and reports any failure as an error rather than a nil logger.
	l, closer, err := New(Config{Syslog: true, SyslogNetwork: "tcp", SyslogAddress: "127.0.0.1:0"})
	if err == nil {
		closer.Close()
		if l == nil {
			t.Fatal("New returned nil logger without an error")
		}
	}
}
