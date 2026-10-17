//go:build ignore

// gen_swedish.go generates dictionaries/swedish.txt, the embedded
// Swedish-targeted wordlist shipped with Xcrack (candidates.Swedish, CLI
// --swedish). Regenerate with:
//
//	cd xcrypto/candidates && go run gen_swedish.go > dictionaries/swedish.txt
//
// The list follows the guidance in Elcomsoft's "A Word About Dictionaries" and
// "How to Break 30%/70% of Passwords": a compact, language-specific dictionary
// of the words real Swedish users actually base passwords on, expanded with the
// generic mutations people apply (Capitalize, append a digit / short number /
// year / '!'), deduplicated, and ordered most-probable-first so a hit tends to
// come early. It is deliberately Swedish-specific — globally common passwords
// (123456, qwerty, …) live in the default list and breach corpora instead.
//
// Content is curated, non-personal, and drawn from public language facts:
// common Swedish nouns/verbs/adjectives, the most frequent given names, the
// largest cities, the top football clubs, months/seasons/holidays, and a set of
// bare common-password strings seen in Swedish-language leaks. Both the native
// (å/ä/ö) and the ASCII-folded spellings are emitted, since users pick either.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// bareCommon are complete passwords (already final, no mutation) that show up in
// Swedish-language breaches/support tickets. Emitted first, in rough prevalence
// order, so the very highest-yield guesses lead the list.
var bareCommon = []string{
	"lösenord", "losenord", "hejhej", "hejsan", "sommar2023", "sommar2024",
	"välkommen", "valkommen", "hemligt", "jagälskardig", "jagalskardig",
	"kalleanka", "pippilångstrump", "pippilangstrump", "blågul", "blagul",
	"korvmedbröd", "korvmedbrod", "fanskap", "jävlar", "javlar", "tjena",
	"tjenare", "mormor", "farfar", "farmor", "morfar", "älsklingen", "alsklingen",
	"godmorgon", "godnatt", "nyckelpiga", "midsommar", "surströmming",
	"surstromming", "knäckebröd", "knackebrod", "fika", "fikapaus", "kanelbulle",
	"ikea", "volvo", "saab", "abba", "sverige123", "hejdå", "hejda", "tacksåmycket",
}

// bases are root words users build passwords from. Each is expanded by mutate().
var bases = []string{
	// common nouns / everyday words
	"sommar", "vinter", "höst", "host", "vår", "var", "kärlek", "karlek", "pengar",
	"hund", "katt", "häst", "hast", "hus", "bil", "sol", "måne", "mane", "stjärna",
	"stjarna", "blomma", "skog", "sjö", "sjo", "hav", "berg", "snö", "sno", "regn",
	"kaffe", "choklad", "glass", "ost", "bröd", "brod", "smör", "smor", "öl", "vin",
	"familj", "vänner", "vanner", "kärlek", "frihet", "frihet", "lycka", "dröm",
	"drom", "hjärta", "hjarta", "ängel", "angel", "prinsessa", "kung", "drottning",
	"hemlig", "hemlighet", "nyckel", "lösen", "losen", "dator", "telefon", "musik",
	"fotboll", "hockey", "skidor", "segla", "fiska", "jaga", "springa",
	// given names (very common in Sweden)
	"anna", "maria", "eva", "karin", "kristina", "lena", "sara", "emma", "elin",
	"johanna", "linnea", "wilma", "alice", "olivia", "astrid", "ingrid", "sofia",
	"erik", "lars", "karl", "anders", "johan", "per", "nils", "jan", "mikael",
	"mikael", "gustav", "oskar", "oscar", "william", "lucas", "hugo", "liam",
	"elias", "axel", "filip", "viktor", "albin", "emil", "isak", "love",
	// cities / places
	"stockholm", "göteborg", "goteborg", "malmö", "malmo", "uppsala", "västerås",
	"vasteras", "örebro", "orebro", "linköping", "linkoping", "helsingborg",
	"jönköping", "jonkoping", "norrköping", "norrkoping", "lund", "umeå", "umea",
	"gävle", "gavle", "sundsvall", "kiruna", "visby", "kalmar", "karlstad",
	"sverige", "skåne", "skane", "dalarna", "norrland", "gotland", "öland", "oland",
	// football clubs / sports
	"aik", "hammarby", "djurgården", "djurgarden", "bajen", "ifkgöteborg",
	"ifkgoteborg", "malmöff", "malmoff", "elfsborg", "häcken", "hacken", "blåvitt",
	"blavitt", "trekronor", "frölunda", "frolunda", "brynäs", "brynas",
	// months / seasons / holidays
	"januari", "februari", "mars", "april", "maj", "juni", "juli", "augusti",
	"september", "oktober", "november", "december", "jul", "julafton", "påsk",
	"pask", "midsommar", "valborg", "lucia", "nyår", "nyar",
	// interjections / affection
	"älskling", "alskling", "gullet", "hjärtat", "hjartat", "raring", "sötnos",
	"sotnos", "kompis", "polare",
}

// years appended as a common mutation (recent + a few memorable).
func years() []int {
	var y []int
	for n := 1970; n <= 2026; n++ {
		y = append(y, n)
	}
	return y
}

// numericSuffixes are the short digit runs people tack on.
var numericSuffixes = []string{"1", "12", "123", "1234", "01", "007", "69", "99", "2000"}

// symbolSuffixes are the trailing symbols people add to satisfy complexity rules.
var symbolSuffixes = []string{"!", "!!", "1!", "123!", ".", "#"}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	// Uppercase the first rune (handles å/ä/ö via unicode casing).
	return strings.ToUpper(string(r[0])) + string(r[1:])
}

// emit writes a candidate if it is new.
func main() {
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	seen := make(map[string]struct{}, 1<<16)
	out := func(s string) {
		if s == "" {
			return
		}
		if _, dup := seen[s]; dup {
			return
		}
		seen[s] = struct{}{}
		fmt.Fprintln(w, s)
	}

	// 1. Bare common passwords first (highest yield, already final).
	for _, s := range bareCommon {
		out(s)
	}

	// 2. Each base, plain and Capitalized (most people's starting point).
	for _, b := range bases {
		out(b)
		out(capitalize(b))
	}

	// 3. Light mutations in prevalence order: +digit, +short number, +!/symbol.
	//    "Password1" / "Sommar2023" / "kaffe!" are the archetypes.
	mutators := []func(string) []string{
		func(b string) []string { // append a single digit
			var o []string
			for d := 0; d <= 9; d++ {
				o = append(o, fmt.Sprintf("%s%d", b, d))
			}
			return o
		},
		func(b string) []string { // append a short number run
			var o []string
			for _, s := range numericSuffixes {
				o = append(o, b+s)
			}
			return o
		},
		func(b string) []string { // append a symbol / symbol+digit
			var o []string
			for _, s := range symbolSuffixes {
				o = append(o, b+s)
			}
			return o
		},
		func(b string) []string { // append a year
			var o []string
			for _, y := range years() {
				o = append(o, fmt.Sprintf("%s%d", b, y))
			}
			return o
		},
	}
	// Apply mutators to both the lower-case and Capitalized form of each base,
	// mutator-major so that the cheaper, higher-yield mutations (single digit,
	// short number) come before the large year sweep across the whole list.
	for _, m := range mutators {
		for _, b := range bases {
			for _, v := range m(b) {
				out(v)
			}
			for _, v := range m(capitalize(b)) {
				out(v)
			}
		}
	}
}
