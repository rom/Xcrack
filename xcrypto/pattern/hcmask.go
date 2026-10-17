package pattern

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ParseHCMaskLine parses one line of a hashcat .hcmask file:
//
//	[charset1,[charset2,[charset3,[charset4,]]]]mask
//
// The last comma-separated field is the mask; any preceding fields (up to four)
// define the custom charsets ?1..?4, in order. A literal comma inside a field is
// escaped as "\,". base supplies charsets defined elsewhere (e.g. a --pattern
// file); a line's own ?1..?4 override base for that line only. As elsewhere in
// this package, a custom charset is a literal set of bytes — it is not itself
// re-expanded for embedded ?l/?d/... tokens.
func ParseHCMaskLine(line string, base map[rune]string) (spec string, custom map[rune]string, err error) {
	fields := splitUnescaped(line, ',')
	spec = fields[len(fields)-1]
	csFields := fields[:len(fields)-1]
	if len(csFields) > 4 {
		return "", nil, fmt.Errorf("pattern: hcmask line has %d custom charsets (max 4): %q", len(csFields), line)
	}
	custom = make(map[rune]string, len(base)+len(csFields))
	for k, v := range base {
		custom[k] = v
	}
	for i, cs := range csFields {
		if cs == "" {
			return "", nil, fmt.Errorf("pattern: empty custom charset ?%d in hcmask line %q", i+1, line)
		}
		custom[rune('1'+i)] = cs
	}
	return spec, custom, nil
}

// LoadHCMask reads a hashcat .hcmask file and compiles every mask it contains.
// Blank lines and lines beginning with '#' are skipped. base supplies charsets
// defined elsewhere, available to every line as ?1..?4 unless the line redefines
// them.
func LoadHCMask(path string, base map[rune]string) ([]*Mask, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var masks []*Mask
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	ln := 0
	for sc.Scan() {
		ln++
		line := strings.TrimRight(sc.Text(), "\r\n")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		spec, custom, perr := ParseHCMaskLine(line, base)
		if perr != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, ln, perr)
		}
		m, cerr := CompileMask(spec, custom)
		if cerr != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, ln, cerr)
		}
		masks = append(masks, m)
	}
	return masks, sc.Err()
}

// splitUnescaped splits s on sep, treating "\<sep>" as a literal sep and "\\" as
// a literal backslash; both escapes are resolved in the returned fields.
func splitUnescaped(s string, sep byte) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && (s[i+1] == sep || s[i+1] == '\\') {
			cur.WriteByte(s[i+1])
			i++
			continue
		}
		if s[i] == sep {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(s[i])
	}
	out = append(out, cur.String())
	return out
}
