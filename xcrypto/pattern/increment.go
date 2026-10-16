package pattern

import "strings"

// maskTokens splits a mask into its tokens: a "?x" placeholder (including "??"
// for a literal '?') is one token, any other rune is a literal token.
func maskTokens(mask string) []string {
	var toks []string
	rs := []rune(mask)
	for i := 0; i < len(rs); i++ {
		if rs[i] == '?' && i+1 < len(rs) {
			toks = append(toks, string(rs[i:i+2]))
			i++
			continue
		}
		toks = append(toks, string(rs[i]))
	}
	return toks
}

// ExpandIncrement expands a mask into prefix masks of increasing token length,
// for lengths in [min,max] (hashcat's --increment). min<=0 defaults to 1; max<=0
// or max beyond the token count defaults to the full mask length. The result is
// ordered shortest-first.
func ExpandIncrement(mask string, min, max int) []string {
	toks := maskTokens(mask)
	n := len(toks)
	if n == 0 {
		return nil
	}
	if min <= 0 {
		min = 1
	}
	if min > n {
		min = n
	}
	if max <= 0 || max > n {
		max = n
	}
	if max < min {
		max = min
	}
	out := make([]string, 0, max-min+1)
	for k := min; k <= max; k++ {
		out = append(out, strings.Join(toks[:k], ""))
	}
	return out
}
