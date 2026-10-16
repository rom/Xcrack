package candidates

import "strings"

// FromName derives candidate passwords from a file (or entry) name. Malware lures
// frequently name the password after the file, so the stem, its tokens, their
// concatenation, and embedded digit runs are all worth trying. Results are
// de-duplicated in first-seen order.
func FromName(name string) []string {
	name = lastComponent(name)
	stem := name
	if i := strings.LastIndexByte(stem, '.'); i > 0 {
		stem = stem[:i] // drop one extension
	}
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	add(stem)
	toks := strings.FieldsFunc(stem, func(r rune) bool { return !isAlnum(r) })
	for _, t := range toks {
		add(t)
	}
	add(strings.Join(toks, "")) // tokens concatenated
	for _, d := range digitRuns(stem) {
		add(d)
	}
	return out
}

// FromText extracts likely passwords from plaintext (e.g. an email body or a
// README that says "the password is X"). It scans for hint keywords and captures
// the following token or quoted string, returning at most max candidates in
// first-seen order.
func FromText(text []byte, max int) []string {
	if max <= 0 {
		max = 64
	}
	lower := strings.ToLower(string(text))
	keywords := []string{"passphrase", "password", "passwort", "passwd", "pwd", "pass", "pin", "code", "key", "pw"}
	seen := map[string]bool{}
	var out []string
	add := func(s string) bool {
		if s == "" || len(s) > 64 || seen[s] {
			return true
		}
		seen[s] = true
		out = append(out, s)
		return len(out) < max
	}
	for _, kw := range keywords {
		from := 0
		for {
			i := strings.Index(lower[from:], kw)
			if i < 0 {
				break
			}
			start := from + i
			pos := start + len(kw)
			from = pos
			// Require a whole-word match so a short keyword (e.g. "pw", "pass")
			// does not fire inside a longer word ("pwd", "password").
			if start > 0 && isAlnumByte(lower[start-1]) {
				continue
			}
			if pos < len(lower) && isAlnumByte(lower[pos]) {
				continue
			}
			tok := captureAfter(text, pos)
			if tok != "" && !add(tok) {
				return out
			}
		}
	}
	return out
}

// FromHint derives candidate passwords from an embedded password/decryption hint
// (e.g. the iWork `.iwph` hint or a ZIP comment). A hint is frequently the
// password itself or a thin clue, so the literal hint, its alphanumeric tokens
// and their concatenation, embedded digit runs, and any value the hint quotes or
// names ("pw: hunter2") are all tried. The hint is UNTRUSTED, attacker-influenced
// text; only candidate strings are derived from it. Results are de-duplicated in
// first-seen order and capped at max (0 => 64). A caller typically feeds these
// base words through a rule engine for further variants.
func FromHint(hint string, max int) []string {
	if max <= 0 {
		max = 64
	}
	hint = strings.TrimSpace(hint)
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || len(s) > 256 || seen[s] || len(out) >= max {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	add(hint) // the literal hint -- often the password itself
	toks := strings.FieldsFunc(hint, func(r rune) bool { return !isAlnum(r) })
	for _, t := range toks {
		add(t)
	}
	add(strings.Join(toks, "")) // tokens concatenated, e.g. "my dog" -> "mydog"
	for _, d := range digitRuns(hint) {
		add(d)
	}
	for _, s := range FromText([]byte(hint), max) { // "pw: X" / quoted value
		add(s)
	}
	return out
}

func isAlnumByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// captureAfter skips separators after pos and returns the next token (a quoted
// string if one starts, otherwise up to the next whitespace/quote).
func captureAfter(text []byte, pos int) string {
	// Skip common separators and a leading "is".
	for pos < len(text) {
		switch text[pos] {
		case ' ', '\t', ':', '=', '-', '>', '\r', '\n', '.', ')', ']':
			pos++
			continue
		}
		break
	}
	if pos+2 <= len(text) && (text[pos] == 'i' || text[pos] == 'I') && pos+1 < len(text) && (text[pos+1] == 's' || text[pos+1] == 'S') {
		// optional "is"
		p := pos + 2
		if p < len(text) && (text[p] == ' ' || text[p] == ':' || text[p] == '\t') {
			pos = p
			for pos < len(text) && (text[pos] == ' ' || text[pos] == ':' || text[pos] == '\t') {
				pos++
			}
		}
	}
	if pos >= len(text) {
		return ""
	}
	if q := text[pos]; q == '"' || q == '\'' || q == '`' {
		end := pos + 1
		for end < len(text) && text[end] != q {
			end++
		}
		return string(text[pos+1 : end])
	}
	end := pos
	for end < len(text) {
		c := text[end]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '"' || c == '\'' || c == '`' {
			break
		}
		end++
	}
	return strings.TrimRight(string(text[pos:end]), ".,;:!)")
}

// lastComponent returns the final path component of an Xcrack node path (layers
// are separated by "!/", directories by "/").
func lastComponent(name string) string {
	name = strings.ReplaceAll(name, "!/", "/")
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	return name
}

func isAlnum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

func digitRuns(s string) []string {
	var out []string
	cur := strings.Builder{}
	for _, r := range s {
		if r >= '0' && r <= '9' {
			cur.WriteRune(r)
		} else if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// Context returns a source of context-derived candidates: the name-derived
// strings first, then any hints extracted from accompanying text.
func Context(name string, text []byte, maxText int) Source {
	pws := FromName(name)
	pws = append(pws, FromText(text, maxText)...)
	return Explicit(pws...)
}
