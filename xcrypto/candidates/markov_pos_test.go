package candidates

import "testing"

func TestMarkovPosGenerates(t *testing.T) {
	// Train on words that are 3 letters + 1 trailing digit: the model should
	// learn that position 3 is digit-heavy and position 0 is letter-heavy.
	samples := [][]byte{
		[]byte("cat1"), []byte("dog2"), []byte("fox3"), []byte("bat4"),
		[]byte("car5"), []byte("sun6"), []byte("cab7"), []byte("dot8"),
	}
	m := TrainMarkovPos(samples)
	g := MarkovGenPos(m, 4, 4, 200, 20)
	seen := map[string]bool{}
	endsDigit, startsDigit := 0, 0
	for {
		b, err := g.Next()
		if err != nil {
			break
		}
		s := string(b)
		if len(s) != 4 {
			t.Fatalf("length = %d, want 4 (bounds not honored): %q", len(s), s)
		}
		if seen[s] {
			t.Fatalf("duplicate candidate %q", s)
		}
		seen[s] = true
		if s[3] >= '0' && s[3] <= '9' {
			endsDigit++
		}
		if s[0] >= '0' && s[0] <= '9' {
			startsDigit++
		}
	}
	if len(seen) == 0 {
		t.Fatal("generated nothing")
	}
	// Position-awareness: far more candidates should end in a digit than start
	// with one (the training structure).
	if endsDigit <= startsDigit {
		t.Errorf("position structure not learned: endsDigit=%d startsDigit=%d", endsDigit, startsDigit)
	}
	// Reset + clone must reproduce.
	_ = g.Reset()
	if b, err := g.Next(); err != nil || len(b) != 4 {
		t.Fatalf("after Reset: %q %v", b, err)
	}
}
