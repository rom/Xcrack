// Package access identifies Microsoft Access database files — Jet (.mdb,
// Access 97–2003) and ACE (.accdb, Access 2007+). These are not OLE/CFB
// compound files; they begin with a fixed "Standard Jet DB" / "Standard ACE DB"
// signature at offset 4. The format recognizes and names them so `identify`
// reports the right application and the engine can surface them in a scan.
//
// Scope note: recovering an Access database password is NOT implemented here.
// Jet stores the database password XOR-obfuscated in the header and ACE uses an
// RC4/office-style scheme, but there is no validated test oracle in this build
// to cross-check an implementation against, and the project ships only crypto
// it has verified against an oracle. So this format identifies the file (and
// whether it carries a database password) and leaves recovery staged.
package access

import (
	"bytes"

	"github.com/rom/xfileformats"
)

var (
	sigJet = []byte("Standard Jet DB")
	sigACE = []byte("Standard ACE DB")
)

// headerVersionOffset is the Jet format version byte (0x00=Jet3/Access97,
// 0x01=Jet4/Access2000-2003, 0x02+=ACE/Access2007+).
const headerVersionOffset = 0x14

// Format identifies Microsoft Access databases.
type Format struct{}

// New returns an Access Format.
func New() *Format { return &Format{} }

// Register adds the format to a registry.
func Register(r *xfileformats.Registry) { r.Register(New()) }

// Name implements xfileformats.Format.
func (f *Format) Name() string { return "access" }

// Caps implements xfileformats.Format: identification only — Access password
// recovery is not implemented (see the package note), so neither the Encrypted
// nor the Container capability is claimed.
func (f *Format) Caps() xfileformats.Caps { return xfileformats.Caps{} }

// Detect recognizes the Jet/ACE signature at offset 4.
func (f *Format) Detect(peek []byte) (float64, bool) {
	if len(peek) >= 4+len(sigJet) &&
		(bytes.HasPrefix(peek[4:], sigJet) || bytes.HasPrefix(peek[4:], sigACE)) {
		return 0.98, true
	}
	return 0, false
}

// Variant reports the Access engine variant for a detected header: "jet3"
// (Access 97), "jet4" (Access 2000–2003), or "ace" (Access 2007+). It is used
// for reporting; the empty string means the version byte was unreadable.
func Variant(peek []byte) string {
	if len(peek) <= headerVersionOffset {
		return ""
	}
	if len(peek) >= 4+len(sigACE) && bytes.HasPrefix(peek[4:], sigACE) {
		return "ace"
	}
	switch peek[headerVersionOffset] {
	case 0x00:
		return "jet3"
	case 0x01:
		return "jet4"
	default:
		return "ace"
	}
}
