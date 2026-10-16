package candidates

import (
	"testing"
)

func TestMarkovRanksWordlikeHigher(t *testing.T) {
	samples := [][]byte{
		[]byte("password"), []byte("passw0rd"), []byte("letmein"),
		[]byte("sunshine"), []byte("iloveyou"), []byte("dragon"),
		[]byte("football"), []byte("welcome"), []byte("monkey"),
	}
	m := TrainMarkov(samples)
	wordlike := m.Score([]byte("passwerd"))
	noise := m.Score([]byte("q7#z!x~^"))
	if !(wordlike > noise) {
		t.Fatalf("word-like score %.3f should exceed noise score %.3f", wordlike, noise)
	}
}

func TestByScoreOrdersByModel(t *testing.T) {
	m := TrainMarkov([][]byte{
		[]byte("password"), []byte("welcome"), []byte("sunshine"), []byte("dragon"),
	})
	// Unordered input; the word-like candidate should come first after ByScore.
	in := Explicit("zx9#q!", "welcome1", "~~~~", "passwordish")
	got := drain(t, ByScore(in, m.Scorer(), 0))
	if len(got) != 4 {
		t.Fatalf("expected 4 candidates, got %d (%v)", len(got), got)
	}
	// The two dictionary-ish strings should rank ahead of the two noise strings.
	rank := map[string]int{}
	for i, s := range got {
		rank[s] = i
	}
	if rank["welcome1"] > rank["zx9#q!"] || rank["passwordish"] > rank["~~~~"] {
		t.Fatalf("word-like candidates did not rank ahead of noise: %v", got)
	}
}

func TestByScoreIsStableAndCloneable(t *testing.T) {
	// Equal scores preserve input order (deterministic).
	in := Explicit("a", "b", "c", "d")
	flat := func([]byte) float64 { return 1.0 }
	s := ByScore(in, flat, 0)
	if got := drain(t, &sliceSource{items: cloneItems(s)}); len(got) != 4 {
		t.Fatalf("clone drain wrong length: %v", got)
	}
	s2 := ByScore(Explicit("a", "b", "c", "d"), flat, 0)
	got := drain(t, s2)
	want := []string{"a", "b", "c", "d"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("stable order broken: got %v want %v", got, want)
		}
	}
	// The result must be cloneable for sibling parallelism.
	if _, ok := s.(Cloner); !ok {
		t.Fatal("ByScore result is not a Cloner")
	}
}

func cloneItems(s Source) [][]byte {
	c, ok := s.(Cloner)
	if !ok {
		return nil
	}
	cl := c.CloneSource()
	var out [][]byte
	for {
		b, err := cl.Next()
		if err != nil {
			break
		}
		out = append(out, append([]byte(nil), b...))
	}
	return out
}
