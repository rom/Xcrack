package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestParseThunderProgress(t *testing.T) {
	ok := []struct {
		spec     string
		pct      int
		interval time.Duration
	}{
		{"", 0, 0}, // disabled -> nil (handled below)
		{"1%", 1, 0},
		{"5%", 5, 0},
		{"10%", 10, 0},
		{"25%", 25, 0},
		{"2hour", 0, 2 * time.Hour},
		{"3hours", 0, 3 * time.Hour},
		{"6h", 0, 6 * time.Hour},
		{"1day", 0, 24 * time.Hour},
		{"2days", 0, 48 * time.Hour},
		{"1d", 0, 24 * time.Hour},
		{"  5%  ", 5, 0},
		{"2HOUR", 0, 2 * time.Hour},
	}
	for _, tc := range ok {
		p, err := parseThunderProgress(tc.spec)
		if err != nil {
			t.Fatalf("parse %q: unexpected error %v", tc.spec, err)
		}
		if strings.TrimSpace(tc.spec) == "" {
			if p != nil {
				t.Fatalf("empty spec should disable progress, got %+v", p)
			}
			continue
		}
		if p.pct != tc.pct || p.interval != tc.interval {
			t.Fatalf("parse %q = {pct:%d interval:%v}, want {pct:%d interval:%v}", tc.spec, p.pct, p.interval, tc.pct, tc.interval)
		}
	}
	bad := []string{"2%", "3%", "100%", "0%", "%", "2", "2week", "hour", "-1day", "2.5h", "abc"}
	for _, spec := range bad {
		if _, err := parseThunderProgress(spec); err == nil {
			t.Errorf("parse %q: expected an error", spec)
		}
	}
}

func TestThunderProgressPercent(t *testing.T) {
	var buf bytes.Buffer
	p := &thunderProgress{pct: 25, out: &buf, start: time.Unix(0, 0), now: func() time.Time { return time.Unix(10, 0) }}
	// Frequent updates; a line should appear only at each 25% milestone, once.
	for done := uint64(0); done <= 100; done += 3 {
		p.report(done, 100)
	}
	p.report(100, 100) // final
	lines := nonEmptyLines(buf.String())
	// Expect 25,50,75,100 (four milestones), each once.
	if len(lines) != 4 {
		t.Fatalf("percent-25 produced %d lines, want 4:\n%s", len(lines), buf.String())
	}
	for i, want := range []string{"25%", "50%", "75%", "100%"} {
		if !strings.Contains(lines[i], want) {
			t.Fatalf("line %d = %q, want it to contain %q", i, lines[i], want)
		}
	}
}

func TestThunderProgressTime(t *testing.T) {
	var buf bytes.Buffer
	cur := time.Unix(0, 0)
	p := &thunderProgress{interval: time.Hour, out: &buf, start: cur, lastTime: cur, now: func() time.Time { return cur }}
	// 30 min in: no output yet.
	cur = time.Unix(1800, 0)
	p.report(10, 100)
	if buf.Len() != 0 {
		t.Fatalf("time progress fired before the interval: %q", buf.String())
	}
	// 70 min in: one line.
	cur = time.Unix(4200, 0)
	p.report(40, 100)
	if n := len(nonEmptyLines(buf.String())); n != 1 {
		t.Fatalf("after one interval got %d lines, want 1:\n%s", n, buf.String())
	}
	// Final 100% always prints.
	cur = time.Unix(4300, 0)
	p.report(100, 100)
	lines := nonEmptyLines(buf.String())
	if len(lines) != 2 || !strings.Contains(lines[1], "100%") {
		t.Fatalf("expected a final 100%% line, got:\n%s", buf.String())
	}
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}
