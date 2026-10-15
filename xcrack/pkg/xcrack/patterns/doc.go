// Package patterns will provide hashcat-compatible mask expansion and mangling
// rules for generating password candidates, plus a thin YAML wrapper (see
// ADR-0005). It is a placeholder in the MVP; the ZIP vertical slice uses
// explicit, wordlist, and default-list candidate sources.
//
// Planned API:
//
//	func CompileMask(spec string, custom map[rune]string) (*Mask, error)
//	func (m *Mask) Source() candidates.Source
//	func CompileRules(lines []string) (*RuleSet, error)
//	func (rs *RuleSet) Apply(word []byte) [][]byte
//	func WithRules(base candidates.Source, rs *RuleSet) candidates.Source
package patterns
