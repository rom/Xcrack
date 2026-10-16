package candidates

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
)

// TestShardPartitions is the core invariant: for any N, the N shards are
// pairwise disjoint and their union is exactly the original keyspace.
func TestShardPartitions(t *testing.T) {
	var all []string
	for i := 0; i < 100; i++ {
		all = append(all, fmt.Sprintf("pw%02d", i))
	}
	for _, count := range []int{1, 2, 3, 5, 7, 100, 150} {
		seen := map[string]int{}
		var union []string
		for idx := 0; idx < count; idx++ {
			shard := drainGen(t, Shard(Explicit(all...), idx, count))
			for _, s := range shard {
				seen[s]++
				union = append(union, s)
			}
		}
		if len(union) != len(all) {
			t.Fatalf("count=%d: union has %d candidates, want %d", count, len(union), len(all))
		}
		for s, n := range seen {
			if n != 1 {
				t.Fatalf("count=%d: candidate %q appeared in %d shards, want 1", count, s, n)
			}
		}
		sort.Strings(union)
		want := append([]string{}, all...)
		sort.Strings(want)
		if !reflect.DeepEqual(union, want) {
			t.Fatalf("count=%d: union != keyspace", count)
		}
	}
}

func TestShardStride(t *testing.T) {
	all := Explicit("a", "b", "c", "d", "e", "f", "g")
	got := drainGen(t, Shard(all, 1, 3)) // positions 1,4,7,... => b,e
	if !reflect.DeepEqual(got, []string{"b", "e"}) {
		t.Fatalf("stride shard = %v, want [b e]", got)
	}
}

func TestShardCountOne(t *testing.T) {
	src := Explicit("x", "y")
	if s := Shard(src, 0, 1); s != Source(src) {
		t.Fatal("Shard with count<=1 should return the source unchanged")
	}
}

func TestShardLen(t *testing.T) {
	// 10 items, count 3: shard 0 -> {0,3,6,9}=4, shard 1 -> {1,4,7}=3, shard 2 -> {2,5,8}=3.
	for idx, want := range map[int]int64{0: 4, 1: 3, 2: 3} {
		if got := Shard(Explicit("0", "1", "2", "3", "4", "5", "6", "7", "8", "9"), idx, 3).Len(); got != want {
			t.Errorf("shard %d/3 Len = %d, want %d", idx, got, want)
		}
	}
	// Unknown length propagates.
	if got := Shard(Reader(nil), 0, 2).Len(); got != -1 {
		t.Errorf("unknown-length shard Len = %d, want -1", got)
	}
}

func TestShardResetAndClone(t *testing.T) {
	s := Shard(Explicit("a", "b", "c", "d"), 0, 2)
	first := drainGen(t, s)
	if err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	if again := drainGen(t, s); !reflect.DeepEqual(first, again) {
		t.Fatalf("after reset %v != %v", again, first)
	}
	cl, ok := s.(Cloner)
	if !ok {
		t.Fatal("Shard over a cloneable source should be cloneable")
	}
	if c := drainGen(t, cl.CloneSource()); !reflect.DeepEqual(c, first) {
		t.Fatalf("clone %v != %v", c, first)
	}
}

func TestShardIndexWraps(t *testing.T) {
	// index is taken modulo count, so index 5 with count 3 == index 2.
	a := drainGen(t, Shard(Explicit("0", "1", "2", "3", "4", "5"), 5, 3))
	b := drainGen(t, Shard(Explicit("0", "1", "2", "3", "4", "5"), 2, 3))
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("index 5/3 (%v) != index 2/3 (%v)", a, b)
	}
}
