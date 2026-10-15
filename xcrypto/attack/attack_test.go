package attack

import (
	"context"
	"io"
	"testing"
)

type sliceSrc struct {
	items [][]byte
	i     int
}

func (s *sliceSrc) Next() ([]byte, error) {
	if s.i >= len(s.items) {
		return nil, io.EOF
	}
	v := s.items[s.i]
	s.i++
	return v, nil
}
func (s *sliceSrc) Len() int64   { return int64(len(s.items)) }
func (s *sliceSrc) Reset() error { s.i = 0; return nil }

func makeSrc(n int, target string) *sliceSrc {
	items := make([][]byte, 0, n+1)
	for i := 0; i < n; i++ {
		items = append(items, []byte("decoy"))
	}
	items = append(items, []byte(target))
	return &sliceSrc{items: items}
}

func TestCrackFindsAcrossBatchSizes(t *testing.T) {
	probe := func(pw []byte) (bool, error) { return string(pw) == "winner", nil }
	for _, bs := range []int{0, 1, 4, 64} {
		e := New(Options{Workers: 4, MaxProcs: 4, BatchSize: bs})
		pw, found, tried, err := e.Crack(context.Background(), probe, makeSrc(500, "winner"))
		if err != nil || !found || string(pw) != "winner" {
			t.Fatalf("batch=%d: found=%v pw=%q err=%v", bs, found, pw, err)
		}
		if tried == 0 {
			t.Fatalf("batch=%d: tried=0", bs)
		}
	}
}

func TestThrottleStillCorrect(t *testing.T) {
	probe := func(pw []byte) (bool, error) { return string(pw) == "x", nil }
	e := New(Options{Workers: 2, MaxProcs: 2, BatchSize: 8, ThrottlePercent: 50})
	pw, found, _, err := e.Crack(context.Background(), probe, makeSrc(50, "x"))
	if err != nil || !found || string(pw) != "x" {
		t.Fatalf("throttled search failed: found=%v pw=%q err=%v", found, pw, err)
	}
}

func TestCrackNoMatch(t *testing.T) {
	probe := func(pw []byte) (bool, error) { return false, nil }
	e := New(Options{Workers: 3, MaxProcs: 3, BatchSize: 4})
	_, found, tried, err := e.Crack(context.Background(), probe, makeSrc(100, "y"))
	if err != nil || found {
		t.Fatalf("expected no match: found=%v err=%v", found, err)
	}
	if tried != 101 {
		t.Fatalf("tried=%d, want 101", tried)
	}
}
