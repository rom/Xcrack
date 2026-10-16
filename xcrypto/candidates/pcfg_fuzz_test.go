package candidates

import (
	"io"
	"testing"
)

// Invariant: training on arbitrary bytes and generating a bounded number of
// candidates never panics and terminates.
func FuzzPCFG(f *testing.F) {
	f.Add("password1\nwelcome\n12345\n!!!\n")
	f.Add("")
	f.Add("\n\n\n")
	f.Add("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
	f.Fuzz(func(t *testing.T, blob string) {
		var words []string
		start := 0
		for i := 0; i < len(blob); i++ {
			if blob[i] == '\n' {
				words = append(words, blob[start:i])
				start = i + 1
			}
		}
		words = append(words, blob[start:])
		p := TrainPCFG(words)
		s := p.Source(500)
		for i := 0; i < 500; i++ {
			if _, err := s.Next(); err == io.EOF {
				break
			}
		}
	})
}
