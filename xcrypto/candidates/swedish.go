package candidates

import (
	_ "embed"
	"strings"
	"sync"
)

// swedishRaw is the embedded Swedish-targeted wordlist (see gen_swedish.go for
// how it is produced and what it contains). Shipping it in the binary means
// `xcrack --swedish` works anywhere, like the built-in default list, with no
// external file to locate.
//
//go:embed dictionaries/swedish.txt
var swedishRaw string

var (
	swedishOnce  sync.Once
	swedishWords []string
)

func swedishList() []string {
	swedishOnce.Do(func() {
		lines := strings.Split(swedishRaw, "\n")
		swedishWords = make([]string, 0, len(lines))
		for _, ln := range lines {
			ln = strings.TrimRight(ln, "\r")
			if ln != "" {
				swedishWords = append(swedishWords, ln)
			}
		}
	})
	return swedishWords
}

// Swedish returns a Source over the embedded Swedish-targeted wordlist: a
// compact, language-specific dictionary of the words Swedish users most often
// base passwords on (common words, given names, cities, football clubs,
// months/holidays) expanded with the generic mutations people apply, ordered
// most-probable-first. It complements the globally-common DefaultList and the
// breach corpora rather than replacing them.
func Swedish() Source {
	words := swedishList()
	items := make([][]byte, len(words))
	for i, w := range words {
		items[i] = []byte(w)
	}
	return &sliceSource{items: items}
}

// SwedishLen reports how many entries the embedded Swedish list holds.
func SwedishLen() int { return len(swedishList()) }
