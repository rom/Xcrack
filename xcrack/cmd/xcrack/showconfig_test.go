package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestConfViewPrint(t *testing.T) {
	v := confView{
		Sources:        []string{"a.zip", "b.7z"},
		Workers:        0, // -> auto
		FileJobs:       4,
		MaxTotalBytes:  2147483648,
		Recurse:        true,
		Promote:        true,
		Markov:         true,
		UseDefaultList: true,
		Wordlists:      []string{"rockyou.txt"},
		PasswordCount:  3,
		Format:         "text",
		OutDir:         "./o",
		ExtractSuffix:  ".unpacked",
		PerFile:        30 * time.Second,
	}
	var b bytes.Buffer
	v.print(&b)
	out := b.String()
	for _, want := range []string{
		"a.zip, b.7z",
		"workers:", "0 (auto: NumCPU)",
		"file-jobs:", "extract-suffix:", ".unpacked",
		"markov:", "on",
		"2.0 GiB",
		"explicit-passwords:", "3 (values hidden)",
		"per-file:", "30s",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("show-config output missing %q\n---\n%s", want, out)
		}
	}
	// A secret must never leak: only the count is printed, not any password.
	if strings.Contains(out, "rockyou") == false {
		t.Error("expected wordlist name to be shown")
	}
}

func TestConfViewEmptyDefaults(t *testing.T) {
	var b bytes.Buffer
	confView{}.print(&b)
	out := b.String()
	for _, want := range []string{
		"sources: (none)",
		"extract-suffix:      (none)",
		"found-cache:         (none)",
		"max-candidates:      0 (unlimited)",
		"per-file:            none",
		"mode:                (none — local)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("empty-config output missing %q\n---\n%s", want, out)
		}
	}
}

func TestRunShowCacheUnconfigured(t *testing.T) {
	if code := runShowCache("", nil); code != 1 {
		t.Fatalf("runShowCache(unconfigured) = %d, want 1", code)
	}
}

func TestBytesOr(t *testing.T) {
	cases := map[int64]string{
		0:          "0 (unlimited)",
		512:        "512 B",
		2147483648: "2.0 GiB (2147483648)",
	}
	for in, want := range cases {
		if got := bytesOr(in); got != want {
			t.Errorf("bytesOr(%d) = %q, want %q", in, got, want)
		}
	}
}
