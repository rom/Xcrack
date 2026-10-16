package candidates

// BreachCorpus wraps a line-oriented Source over a leaked-password ("breach")
// corpus whose lines may carry a prevalence count, and yields the plaintext
// passwords with the count stripped. It recognizes the two layouts such lists
// ship in:
//
//	<count><space|tab><password>   e.g. "3303003 123456"    (SecLists-style)
//	<password>:<count>             e.g. "123456:37359195"   (HIBP-style)
//
// A line with no recognizable count is taken verbatim as a password, so an
// ordinary wordlist passes through unchanged. Lines are emitted in input order
// — these corpora are sorted most-common first, so pairing this with a modest
// per-file budget tries the highest-probability passwords first. minCount > 0
// drops entries whose prevalence is below it (so you spray only the common
// ones); it never drops a line that carries no count. Empty passwords and the
// count-only remnants of malformed lines are skipped. Order is preserved, so
// dedup across merged corpora is left to the Dedup/Chain wrappers.
func BreachCorpus(src Source, minCount int64) Source {
	return &breachSource{src: src, minCount: minCount}
}

type breachSource struct {
	src      Source
	minCount int64
}

func (b *breachSource) Next() ([]byte, error) {
	for {
		line, err := b.src.Next()
		if err != nil {
			return nil, err
		}
		pw, count, hasCount := parseBreachLine(line)
		if len(pw) == 0 {
			continue
		}
		if hasCount && b.minCount > 0 && count < b.minCount {
			continue
		}
		return pw, nil
	}
}

func (b *breachSource) Len() int64 { return -1 }

func (b *breachSource) Reset() error { return b.src.Reset() }

func (b *breachSource) CloneSource() Source {
	cl, ok := b.src.(Cloner)
	if !ok {
		return nil
	}
	inner := cl.CloneSource()
	if inner == nil {
		return nil
	}
	return &breachSource{src: inner, minCount: b.minCount}
}

// parseBreachLine splits one corpus line into its password and (optional)
// prevalence count. A trailing CR is stripped first so CRLF files parse
// cleanly. It tries the count-prefix form (leading digits followed by
// whitespace), then the colon-suffix form (a line ending in ":<digits>"), and
// otherwise treats the whole line as a bare password.
func parseBreachLine(line []byte) (pw []byte, count int64, hasCount bool) {
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	// Count-prefix: optional leading blanks, digits, then a blank run, then the
	// password (whose own internal/trailing blanks are preserved).
	i := 0
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	d := i
	for d < len(line) && line[d] >= '0' && line[d] <= '9' {
		d++
	}
	if d > i && d < len(line) && (line[d] == ' ' || line[d] == '\t') {
		c := atoi(line[i:d])
		j := d
		for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
			j++
		}
		return copyBytes(line[j:]), c, true
	}
	// Colon-suffix: last ':' with an all-digit, non-empty tail.
	if k := lastIndexByte(line, ':'); k >= 0 && k+1 < len(line) && allDigits(line[k+1:]) {
		return copyBytes(line[:k]), atoi(line[k+1:]), true
	}
	return copyBytes(line), 0, false
}

func copyBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func allDigits(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// atoi parses a run of ASCII digits, saturating at a large value rather than
// overflowing (counts in real corpora fit easily, but input is untrusted).
func atoi(b []byte) int64 {
	const cap int64 = 1 << 62
	var n int64
	for _, c := range b {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int64(c-'0')
		if n >= cap {
			return cap
		}
	}
	return n
}

func lastIndexByte(b []byte, c byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == c {
			return i
		}
	}
	return -1
}
