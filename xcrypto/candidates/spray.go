package candidates

import (
	"strconv"
	"time"
)

// BreachFile is BreachCorpus over a wordlist file (gzip auto-detected), the
// breach-corpus analogue of File.
func BreachFile(path string, minCount int64) Source {
	return BreachCorpus(File(path), minCount)
}

// sprayCommon is a curated set of globally common and malware-campaign
// passwords, most-likely first. It overlaps DefaultList but is broader and
// ordered for spraying (trying a few high-yield guesses across many targets).
var sprayCommon = []string{
	"123456", "password", "123456789", "12345678", "12345", "1234567890",
	"1234567", "qwerty", "abc123", "111111", "123123", "000000", "iloveyou",
	"Password1", "Password1!", "Welcome1", "Welcome1!", "Welcome123",
	"P@ssw0rd", "P@ssword1", "Passw0rd", "Passw0rd!", "Changeme123",
	"Qwerty123", "Qwerty123!", "letmein", "admin", "root", "toor",
	"monkey", "dragon", "football", "master", "sunshine", "princess",
	"login", "passw0rd", "superman", "trustno1",
}

// sprayBaseWords are the words most often used as the stem of a chosen
// password, mangled per-token alongside the caller's context tokens.
var sprayBaseWords = []string{"Welcome", "Password", "Company", "Summer", "Winter"}

var spraySeasons = []string{"Spring", "Summer", "Autumn", "Fall", "Winter"}

var sprayMonths = []string{
	"January", "February", "March", "April", "May", "June",
	"July", "August", "September", "October", "November", "December",
}

// Spray generates a compact, high-yield password-spraying candidate set for
// authorized, targeted engagements. It combines three things, most-likely
// first: the curated globally-common set; each context token (an organization
// or product name, a username) and a few common stem words mangled the way
// people actually pick passwords — capitalization, a trailing year, and common
// suffixes/symbols; and season+year / month+year walks. The result is
// deduplicated and bounded by max. With no tokens it is the common set plus the
// mangled stem words and the seasonal walks. years defaults to the current and
// previous calendar year when nil (people reuse last year's password).
func Spray(tokens []string, years []int, max int) Source {
	if len(years) == 0 {
		y := time.Now().Year()
		years = []int{y, y - 1}
	}
	if max <= 0 {
		max = 1 << 16
	}
	b := &sprayBuilder{seen: make(map[string]struct{}), max: max}

	// 1. Curated global common set.
	for _, p := range sprayCommon {
		b.add(p)
	}
	// 2. Context tokens and common stems, mangled.
	stems := append(append([]string{}, tokens...), sprayBaseWords...)
	for _, t := range stems {
		b.mangle(t, years)
		if b.full() {
			break
		}
	}
	// 3. Seasonal / monthly walks.
	for _, s := range spraySeasons {
		for _, y := range years {
			ys := strconv.Itoa(y)
			b.add(s + ys)
			b.add(s + ys + "!")
			b.add(s + "@" + ys)
		}
	}
	for _, m := range sprayMonths {
		for _, y := range years {
			b.add(m + strconv.Itoa(y))
		}
	}
	return &sliceSource{items: b.items}
}

// SprayCommon is the curated global common set alone (no tokens, no years),
// the quickest possible spray.
func SprayCommon() Source { return Explicit(sprayCommon...) }

type sprayBuilder struct {
	items [][]byte
	seen  map[string]struct{}
	max   int
}

func (b *sprayBuilder) full() bool { return len(b.items) >= b.max }

func (b *sprayBuilder) add(s string) {
	if b.full() || s == "" {
		return
	}
	if _, dup := b.seen[s]; dup {
		return
	}
	b.seen[s] = struct{}{}
	b.items = append(b.items, []byte(s))
}

// mangle emits the common human password patterns for one stem word: case
// variants, then each variant with year and common suffixes.
func (b *sprayBuilder) mangle(word string, years []int) {
	if word == "" {
		return
	}
	variants := dedupStrings(word, titleCase(word), lowerASCII(word), upperASCII(word))
	// Bare suffixes (no year), ordered by prevalence.
	suffixes := []string{"", "1", "123", "!", "123!", "@123", "#1", "1!"}
	for _, v := range variants {
		for _, sfx := range suffixes {
			b.add(v + sfx)
			if b.full() {
				return
			}
		}
		for _, y := range years {
			ys := strconv.Itoa(y)
			b.add(v + ys)
			b.add(v + ys + "!")
			b.add(v + "@" + ys)
			b.add(v + "#" + ys)
			if b.full() {
				return
			}
		}
	}
}

func dedupStrings(in ...string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// titleCase upper-cases the first ASCII letter and lower-cases the rest; bytes
// >= 0x80 are left untouched so UTF-8 is not mangled.
func titleCase(s string) string {
	b := []byte(lowerASCII(s))
	for i := 0; i < len(b); i++ {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 0x20
			break
		}
		if b[i] >= 'A' && b[i] <= 'Z' {
			break
		}
	}
	return string(b)
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c | 0x20
		}
	}
	return string(b)
}

func upperASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c &^ 0x20
		}
	}
	return string(b)
}
