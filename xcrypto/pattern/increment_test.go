package pattern

import (
	"reflect"
	"testing"
)

func TestExpandIncrement(t *testing.T) {
	got := ExpandIncrement("?l?l?d", 1, 0) // 1..full
	want := []string{"?l", "?l?l", "?l?l?d"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestExpandIncrementRange(t *testing.T) {
	got := ExpandIncrement("?u?l?l?d?d", 3, 4)
	want := []string{"?u?l?l", "?u?l?l?d"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestExpandIncrementLiteralsAndEscapes(t *testing.T) {
	// "pw" literals, then a '?' literal (??), then a digit class.
	got := ExpandIncrement("pw??d", 0, 0)
	want := []string{"p", "pw", "pw??", "pw??d"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestExpandIncrementCompiles(t *testing.T) {
	for _, mask := range ExpandIncrement("?d?d?d?d", 2, 4) {
		if _, err := CompileMask(mask, nil); err != nil {
			t.Fatalf("CompileMask(%q): %v", mask, err)
		}
	}
}
