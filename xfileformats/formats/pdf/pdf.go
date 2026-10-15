// Package pdf implements detection and decryption of password-protected PDF
// files that use the Standard Security Handler (RC4, AESV2, AESV3). It parses
// just enough PDF structure to locate the /Encrypt dictionary and the file /ID,
// delegates all cryptography to xcrypto/scheme/pdf, and -- on Decrypt --
// rebuilds a decrypted PDF (strings and streams decrypted, /Encrypt removed,
// fresh cross-reference table). Parsing is tolerant and bounded; it never
// interprets page content.
package pdf

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strconv"

	"github.com/rom/xcrypto"
	xpdf "github.com/rom/xcrypto/scheme/pdf"
	"github.com/rom/xfileformats"
)

const maxPDF = 1 << 30 // 1 GiB backstop

// Format detects and decrypts encrypted PDFs.
type Format struct{}

// New returns a PDF Format.
func New() *Format { return &Format{} }

// Register adds the PDF format to a registry.
func Register(r *xfileformats.Registry) { r.Register(New()) }

// Name implements xfileformats.Format.
func (f *Format) Name() string { return "pdf" }

// Caps implements xfileformats.Format: whole-file (per-object) encryption.
func (f *Format) Caps() xfileformats.Caps { return xfileformats.Caps{Encrypted: true} }

// Detect implements xfileformats.Format.
func (f *Format) Detect(peek []byte) (float64, bool) {
	if bytes.HasPrefix(peek, []byte("%PDF-")) {
		return 0.9, true
	}
	// Some PDFs have leading junk before %PDF-; check a small window.
	if i := bytes.Index(peek, []byte("%PDF-")); i >= 0 && i < 1024 {
		return 0.7, true
	}
	return 0, false
}

func readAll(r io.ReaderAt, size int64) ([]byte, error) {
	if size > maxPDF {
		return nil, xfileformats.ErrLimitExceeded
	}
	if size <= 0 {
		size = 0
	}
	buf := make([]byte, size)
	n, err := io.ReadFull(io.NewSectionReader(r, 0, size), buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	return buf[:n], nil
}

// Probe implements xfileformats.Encrypted. Returns ErrNotEncrypted when the PDF
// has no /Encrypt dictionary.
func (f *Format) Probe(r io.ReaderAt, size int64) (*xcrypto.Challenge, error) {
	data, err := readAll(r, size)
	if err != nil {
		return nil, err
	}
	h, err := parseHandler(data)
	if err != nil {
		return nil, err
	}
	return h.Challenge(), nil
}

// Verify implements xfileformats.Encrypted; the returned key is the PDF file key.
func (f *Format) Verify(ch *xcrypto.Challenge, password []byte) (bool, []byte, error) {
	h, err := xpdf.Unmarshal(ch.Extra)
	if err != nil {
		return false, nil, err
	}
	ok, key := h.Verify(password)
	return ok, key, nil
}

// Decrypt implements xfileformats.Encrypted: rebuild a decrypted PDF.
func (f *Format) Decrypt(r io.ReaderAt, size int64, ch *xcrypto.Challenge, key []byte) (io.Reader, error) {
	h, err := xpdf.Unmarshal(ch.Extra)
	if err != nil {
		return nil, err
	}
	data, err := readAll(r, size)
	if err != nil {
		return nil, err
	}
	out, err := rebuild(data, h, key)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(out), nil
}

// --- parsing ---

var (
	reRef     = regexp.MustCompile(`^\s*(\d+)\s+(\d+)\s+R`)
	reObjHdr  = regexp.MustCompile(`(\d+)\s+(\d+)\s+obj`)
	reStreamK = regexp.MustCompile(`[^a-zA-Z]stream\r?\n`)
)

func parseHandler(data []byte) (*xpdf.Handler, error) {
	if !bytes.Contains(data[:min(len(data), 1024)], []byte("%PDF-")) && !bytes.HasPrefix(data, []byte("%PDF-")) {
		return nil, xfileformats.ErrMalformed
	}
	ei := bytes.LastIndex(data, []byte("/Encrypt"))
	if ei < 0 {
		return nil, xfileformats.ErrNotEncrypted
	}
	var dict []byte
	rest := data[ei+len("/Encrypt"):]
	if m := reRef.FindSubmatch(rest); m != nil {
		objNum, _ := strconv.Atoi(string(m[1]))
		d, ok := findObjectDict(data, objNum)
		if !ok {
			return nil, xfileformats.ErrMalformed
		}
		dict = d
	} else if d, ok := extractDict(rest, 0); ok {
		dict = d // inline encryption dictionary
	} else {
		return nil, xfileformats.ErrMalformed
	}

	if name, ok := findName(dict, "/Filter"); ok && name != "Standard" {
		return nil, fmt.Errorf("%w: PDF security handler %q", xfileformats.ErrUnsupported, name)
	}

	v, _ := findInt(dict, "/V")
	rev, _ := findInt(dict, "/R")
	if rev == 0 {
		return nil, fmt.Errorf("%w: PDF encryption revision missing", xfileformats.ErrMalformed)
	}
	p, _ := findInt(dict, "/P")
	lengthBits, hasLen := findInt(dict, "/Length")
	o, _ := findString(dict, "/O")
	u, _ := findString(dict, "/U")
	oe, _ := findString(dict, "/OE")
	ue, _ := findString(dict, "/UE")
	encMeta := true
	if b, ok := findBool(dict, "/EncryptMetadata"); ok {
		encMeta = b
	}

	keyLen := 5 // default 40-bit
	switch {
	case v >= 5:
		keyLen = 32
	case hasLen && lengthBits > 0:
		keyLen = lengthBits / 8
	}
	if v < 5 { // MD5-handler keys are 5..16 bytes; clamp a crafted /Length
		if keyLen < 5 {
			keyLen = 5
		}
		if keyLen > 16 {
			keyLen = 16
		}
	}

	cipher := xpdf.CipherRC4
	switch {
	case v >= 5:
		cipher = xpdf.CipherAESV3
	case v == 4:
		if cfm, ok := findName(dict, "/CFM"); ok {
			switch cfm {
			case "AESV2":
				cipher = xpdf.CipherAESV2
			case "AESV3":
				cipher = xpdf.CipherAESV3
				keyLen = 32
			}
		}
	}

	id := parseFirstID(data)

	return &xpdf.Handler{
		V: v, R: rev, Length: keyLen, P: int32(p),
		O: o, U: u, OE: oe, UE: ue, ID: id,
		EncryptMetadata: encMeta, Cipher: cipher,
	}, nil
}

// parseFirstID returns the first element of the file /ID array.
func parseFirstID(data []byte) []byte {
	i := bytes.LastIndex(data, []byte("/ID"))
	if i < 0 {
		return nil
	}
	rest := data[i+3:]
	j := bytes.IndexByte(rest, '[')
	if j < 0 || j > 8 {
		return nil
	}
	s, _, ok := parseString(rest, j+1)
	if !ok {
		return nil
	}
	return s
}

// findObjectDict finds `objNum G obj << ... >>` and returns the dict bytes.
func findObjectDict(data []byte, objNum int) ([]byte, bool) {
	needle := []byte(strconv.Itoa(objNum) + " ")
	for from := 0; ; {
		i := bytes.Index(data[from:], needle)
		if i < 0 {
			return nil, false
		}
		pos := from + i
		// require a preceding delimiter so we don't match "12" inside "112"
		if pos > 0 && isRegular(data[pos-1]) {
			from = pos + len(needle)
			continue
		}
		m := reObjHdr.FindSubmatchIndex(data[pos:])
		if m != nil && m[0] == 0 {
			if d, ok := extractDict(data, pos+m[1]); ok {
				return d, true
			}
		}
		from = pos + len(needle)
	}
}

// extractDict returns the first balanced << ... >> at/after from.
func extractDict(data []byte, from int) ([]byte, bool) {
	i := bytes.Index(data[from:], []byte("<<"))
	if i < 0 {
		return nil, false
	}
	start := from + i
	depth := 0
	for p := start; p+1 < len(data); p++ {
		if data[p] == '<' && data[p+1] == '<' {
			depth++
			p++
		} else if data[p] == '>' && data[p+1] == '>' {
			depth--
			p++
			if depth == 0 {
				return data[start : p+1], true
			}
		}
	}
	return nil, false
}

func findInt(dict []byte, key string) (int, bool) {
	re := regexp.MustCompile(regexp.QuoteMeta(key) + `\s+(-?\d+)`)
	m := re.FindSubmatch(dict)
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseInt(string(m[1]), 10, 64)
	if err != nil {
		return 0, false
	}
	return int(int32(n)), true
}

func findName(dict []byte, key string) (string, bool) {
	re := regexp.MustCompile(regexp.QuoteMeta(key) + `\s*/([A-Za-z0-9.+-]+)`)
	m := re.FindSubmatch(dict)
	if m == nil {
		return "", false
	}
	return string(m[1]), true
}

func findBool(dict []byte, key string) (bool, bool) {
	re := regexp.MustCompile(regexp.QuoteMeta(key) + `\s*(true|false)`)
	m := re.FindSubmatch(dict)
	if m == nil {
		return false, false
	}
	return string(m[1]) == "true", true
}

func findString(dict []byte, key string) ([]byte, bool) {
	i := bytes.Index(dict, []byte(key))
	if i < 0 {
		return nil, false
	}
	s, _, ok := parseString(dict, i+len(key))
	if !ok {
		return nil, false
	}
	return s, true
}

// parseString parses a PDF string (literal (...) or hex <...>) at/after pos.
func parseString(b []byte, pos int) ([]byte, int, bool) {
	for pos < len(b) && isWS(b[pos]) {
		pos++
	}
	if pos >= len(b) {
		return nil, pos, false
	}
	switch b[pos] {
	case '<':
		if pos+1 < len(b) && b[pos+1] == '<' {
			return nil, pos, false
		}
		end := bytes.IndexByte(b[pos:], '>')
		if end < 0 {
			return nil, pos, false
		}
		return decodeHexLoose(b[pos+1 : pos+end]), pos + end + 1, true
	case '(':
		return parseLiteral(b, pos)
	}
	return nil, pos, false
}

func parseLiteral(b []byte, pos int) ([]byte, int, bool) {
	pos++ // skip '('
	var out []byte
	depth := 1
	for pos < len(b) {
		c := b[pos]
		switch c {
		case '\\':
			pos++
			if pos >= len(b) {
				return nil, pos, false
			}
			e := b[pos]
			switch e {
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case '(', ')', '\\':
				out = append(out, e)
			default:
				if e >= '0' && e <= '7' { // octal, up to 3 digits
					n := 0
					for k := 0; k < 3 && pos < len(b) && b[pos] >= '0' && b[pos] <= '7'; k++ {
						n = n*8 + int(b[pos]-'0')
						pos++
					}
					pos--
					out = append(out, byte(n))
				} else {
					out = append(out, e)
				}
			}
		case '(':
			depth++
			out = append(out, c)
		case ')':
			depth--
			if depth == 0 {
				return out, pos + 1, true
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
		pos++
	}
	return nil, pos, false
}

func decodeHexLoose(b []byte) []byte {
	clean := make([]byte, 0, len(b))
	for _, c := range b {
		if !isWS(c) {
			clean = append(clean, c)
		}
	}
	if len(clean)%2 == 1 {
		clean = append(clean, '0')
	}
	out := make([]byte, len(clean)/2)
	n, _ := hex.Decode(out, clean)
	return out[:n]
}

func isWS(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == 0
}

// isRegular reports whether c is a PDF regular (non-delimiter, non-whitespace)
// character.
func isRegular(c byte) bool {
	if isWS(c) {
		return false
	}
	switch c {
	case '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return false
	}
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
