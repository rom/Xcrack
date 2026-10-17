package pattern

import (
	"math/rand"
	"strconv"
)

// genOps is the palette of rule operations GenerateRules draws from. Each entry
// returns one valid rule token given a *rand.Rand. The palette is restricted to
// operations CompileRules accepts, so every generated line compiles; it mirrors
// the useful-mutation subset hashcat's own random-rule generator (-g) favors.
var genOps = []func(*rand.Rand) string{
	func(r *rand.Rand) string { return pick(r, "lucCtrdfq{}[]kK") },                        // parameterless
	func(r *rand.Rand) string { return "$" + string(printable(r)) },                        // append char
	func(r *rand.Rand) string { return "^" + string(printable(r)) },                        // prepend char
	func(r *rand.Rand) string { return "s" + string(printable(r)) + string(printable(r)) }, // substitute X->Y
	func(r *rand.Rand) string { return "@" + string(printable(r)) },                        // purge char
	func(r *rand.Rand) string { return "T" + posChar(r) },                                  // toggle at N
	func(r *rand.Rand) string { return "D" + posChar(r) },                                  // delete at N
	func(r *rand.Rand) string { return "z" + posChar(r) },                                  // dup first N
	func(r *rand.Rand) string { return "Z" + posChar(r) },                                  // dup last N
	func(r *rand.Rand) string { return "'" + posChar(r) },                                  // truncate to N
	func(r *rand.Rand) string { return "p" + posChar(r) },                                  // dup word N times
}

// GenerateRules returns n distinct random mangling rules (as rule-language
// lines), deterministic for a given seed. Each line is 1–maxOps operations
// concatenated, and is guaranteed to compile (it is validated with CompileRules;
// any that somehow does not is skipped and regenerated). It is the engine side
// of the CLI's --generate-rules N, a counterpart to hashcat's `-g`: cheap,
// reproducible rule fuzzing on top of a wordlist.
func GenerateRules(n int, seed int64) []string {
	if n <= 0 {
		return nil
	}
	const maxOps = 4
	r := rand.New(rand.NewSource(seed))
	out := make([]string, 0, n)
	seen := map[string]bool{}
	// Bound the attempts so a tiny keyspace (e.g. n larger than the distinct
	// single-op lines) cannot loop forever; emit what we can.
	for attempts := 0; len(out) < n && attempts < n*64+256; attempts++ {
		ops := 1 + r.Intn(maxOps)
		line := ""
		for i := 0; i < ops; i++ {
			line += genOps[r.Intn(len(genOps))](r)
		}
		if seen[line] {
			continue
		}
		if _, err := CompileRules([]string{line}); err != nil {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	return out
}

// pick returns a random byte from set as a one-byte string.
func pick(r *rand.Rand, set string) string { return string(set[r.Intn(len(set))]) }

// printable returns a random printable ASCII byte suitable as a rule argument
// (letters, digits, and common symbols — avoiding space and the rule-reserved
// nothing-in-particular; all are literal single-char arguments to $ ^ s @).
func printable(r *rand.Rand) byte {
	const set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%&*._-"
	return set[r.Intn(len(set))]
}

// posChar returns a hashcat position character 0-9 then A-Z (0..35) as the
// single-char N argument used by T/D/z/Z/'/p.
func posChar(r *rand.Rand) string {
	n := r.Intn(9) // keep positions small (0-8): meaningful for real passwords
	return strconv.Itoa(n)
}
