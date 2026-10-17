package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xcrack/pkg/xcrack"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestWordlistDedupeSort(t *testing.T) {
	in := writeTemp(t, "in.txt", "banana\napple\nbanana\ncherry\napple\n")
	out := filepath.Join(t.TempDir(), "out.txt")
	if rc := runWordlist([]string{"--dedupe", "--sort", "--out", out, in}); rc != 0 {
		t.Fatalf("runWordlist rc=%d", rc)
	}
	got, _ := os.ReadFile(out)
	if string(got) != "apple\nbanana\ncherry\n" {
		t.Fatalf("got %q", got)
	}
}

func TestWordlistLengthFilterAndSortLength(t *testing.T) {
	in := writeTemp(t, "in.txt", "a\nbbb\ncc\ndddd\n")
	out := filepath.Join(t.TempDir(), "out.txt")
	if rc := runWordlist([]string{"--min-length", "2", "--max-length", "3", "--sort-length", "--out", out, in}); rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	got, _ := os.ReadFile(out)
	if string(got) != "cc\nbbb\n" {
		t.Fatalf("got %q", got)
	}
}

func TestWordlistSplit(t *testing.T) {
	in := writeTemp(t, "in.txt", "l1\nl2\nl3\nl4\nl5\n")
	prefix := filepath.Join(t.TempDir(), "chunk")
	if rc := runWordlist([]string{"--split", "2", "--out-prefix", prefix, in}); rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	c0, _ := os.ReadFile(prefix + ".000")
	c2, err := os.ReadFile(prefix + ".002")
	if err != nil {
		t.Fatalf("missing third chunk: %v", err)
	}
	if string(c0) != "l1\nl2\n" {
		t.Errorf("chunk.000=%q", c0)
	}
	if string(c2) != "l5\n" {
		t.Errorf("chunk.002=%q", c2)
	}
}

func TestWriteOutfileFields(t *testing.T) {
	// Build a minimal result with a recovered password for file index 0.
	res := &xcrack.Result{Root: &xcrack.Node{Path: "a.zip", Password: "opensesame", WasEncrypted: true}}
	out := filepath.Join(t.TempDir(), "o.txt")
	if err := writeOutfile("1,2,3", []string{"samples/a.zip"}, []*xcrack.Result{res}, out); err != nil {
		t.Fatalf("writeOutfile: %v", err)
	}
	got, _ := os.ReadFile(out)
	want := "samples/a.zip:opensesame:6f70656e736573616d65\n"
	if string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
	// Unknown field is an error.
	if err := writeOutfile("9", []string{"x"}, []*xcrack.Result{res}, out); err == nil {
		t.Error("expected error for unknown field")
	}
}
