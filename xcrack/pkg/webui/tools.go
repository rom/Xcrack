package webui

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/hashline"
	"github.com/rom/xcrypto/pattern"
	"github.com/rom/xcrypto/scheme/pdf"
	xvba "github.com/rom/xcrypto/scheme/vbaproject"
	"github.com/rom/xfileformats"
	"github.com/rom/xfileformats/formats/access"
	"github.com/rom/xfileformats/formats/vbaproject"
)

// The /api/v1/tools/* endpoints wire the CLI's specialist, non-cracking
// subcommands into the GUI. They are synchronous and stateless (no job), build
// on the same library functions the CLI uses, and bound the request body by
// MaxUploadBytes. A recovered secret (a key, a VBA password, an Access password)
// is returned only when ExposeSecrets is set, mirroring the crack path.

const toolPeek = 512

func (s *Server) toolForm(w http.ResponseWriter, r *http.Request) ([]*multipart.FileHeader, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadBytes)
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "could not parse upload (is it too large?)")
		return nil, false
	}
	parts := append(r.MultipartForm.File["source"], r.MultipartForm.File["file"]...)
	if len(parts) == 0 {
		writeErr(w, http.StatusBadRequest, "no files uploaded (need a 'source' part)")
		return nil, false
	}
	return parts, true
}

func readPart(fh *multipart.FileHeader) ([]byte, error) {
	f, err := fh.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// handleToolHashline emits hashcat/John hash lines for each uploaded file.
func (s *Server) handleToolHashline(w http.ResponseWriter, r *http.Request) {
	parts, ok := s.toolForm(w, r)
	if !ok {
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()
	reg := xcrack.DefaultRegistry()
	type line struct {
		Target  string `json:"target,omitempty"`
		Line    string `json:"line"`
		Hashcat int    `json:"hashcat"`
		John    string `json:"john,omitempty"`
	}
	type fileOut struct {
		Name  string `json:"name"`
		Lines []line `json:"lines,omitempty"`
		Note  string `json:"note,omitempty"`
		Error string `json:"error,omitempty"`
	}
	var out []fileOut
	for _, fh := range parts {
		fo := fileOut{Name: safeSegment(fh.Filename)}
		data, err := readPart(fh)
		if err != nil {
			fo.Error = err.Error()
			out = append(out, fo)
			continue
		}
		ls := toolLines(reg, data)
		if len(ls) == 0 {
			fo.Note = "no hash-line emitter matched (unencrypted, unknown, or CPU-only scheme)"
		}
		for _, l := range ls {
			fo.Lines = append(fo.Lines, line{Target: l.Target, Line: l.Line, Hashcat: l.Hashcat, John: l.John})
		}
		out = append(out, fo)
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": out})
}

// handleToolVBA recovers a VBA project password from each uploaded file.
func (s *Server) handleToolVBA(w http.ResponseWriter, r *http.Request) {
	parts, ok := s.toolForm(w, r)
	if !ok {
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()
	type fileOut struct {
		Name     string `json:"name"`
		Kind     string `json:"kind"`
		Password string `json:"password,omitempty"`
		Hashcat  string `json:"hashcat,omitempty"`
		John     string `json:"john,omitempty"`
		Note     string `json:"note,omitempty"`
		Error    string `json:"error,omitempty"`
	}
	var out []fileOut
	for _, fh := range parts {
		fo := fileOut{Name: safeSegment(fh.Filename)}
		data, err := readPart(fh)
		if err != nil {
			fo.Error = err.Error()
			out = append(out, fo)
			continue
		}
		res, perr := vbaproject.ParseProject(data)
		if perr != nil {
			fo.Error = "no VBA project password found (not a VBA carrier, or no DPB field)"
			out = append(out, fo)
			continue
		}
		switch res.Kind {
		case xvba.KindNone:
			fo.Kind = "none"
			fo.Note = "the VBA project has no protection password set"
		case xvba.KindPlaintext:
			fo.Kind = "plaintext"
			fo.Password = s.secret(res.Plaintext)
		case xvba.KindHash:
			fo.Kind = "hash"
			h, salt := hex.EncodeToString(res.Hash), hex.EncodeToString(res.Key)
			fo.Hashcat = h + ":" + salt
			fo.John = "$dynamic_24$" + h + "$HEX$" + salt
			fo.Note = "stored as a salted SHA-1 hash — crack the emitted line (hashcat -m 110 --hex-salt), or run an in-engine search with force-format 'vba'"
		default:
			fo.Error = "unrecognized VBA password structure"
		}
		out = append(out, fo)
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": out})
}

// handleToolAccess recovers a Jet (.mdb) database password from the header.
func (s *Server) handleToolAccess(w http.ResponseWriter, r *http.Request) {
	parts, ok := s.toolForm(w, r)
	if !ok {
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()
	type fileOut struct {
		Name        string `json:"name"`
		Variant     string `json:"variant,omitempty"`
		HasPassword bool   `json:"has_password"`
		Password    string `json:"password,omitempty"`
		Note        string `json:"note,omitempty"`
		Error       string `json:"error,omitempty"`
	}
	var out []fileOut
	for _, fh := range parts {
		fo := fileOut{Name: safeSegment(fh.Filename)}
		data, err := readPart(fh)
		if err != nil {
			fo.Error = err.Error()
			out = append(out, fo)
			continue
		}
		head := data
		if len(head) > 512 {
			head = head[:512]
		}
		switch access.Variant(head) {
		case "ace":
			fo.Variant = "ace"
			fo.Note = "ACE (.accdb, Access 2007+) uses a real Office-style KDF — run a password search instead"
		case "jet3", "jet4":
			res, rok := access.RecoverJetPassword(head)
			if !rok {
				fo.Error = "could not read the Jet header (truncated?)"
				break
			}
			fo.Variant = res.Variant
			fo.HasPassword = res.HasPassword
			if res.HasPassword {
				fo.Password = s.secret(res.Password)
			} else {
				fo.Note = "the database has no password set"
			}
		default:
			fo.Error = "not a Microsoft Access (Jet) database"
		}
		out = append(out, fo)
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": out})
}

// handleToolExportChallenge emits the portable JSON challenge envelope(s) for
// each uploaded file, as a downloadable document.
func (s *Server) handleToolExportChallenge(w http.ResponseWriter, r *http.Request) {
	parts, ok := s.toolForm(w, r)
	if !ok {
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()
	reg := xcrack.DefaultRegistry()
	var envs []*xcrypto.ExportedChallenge
	for _, fh := range parts {
		data, err := readPart(fh)
		if err != nil {
			continue
		}
		envs = append(envs, toolChallenges(reg, safeSegment(fh.Filename), data)...)
	}
	if len(envs) == 0 {
		writeErr(w, http.StatusOK, "no exportable challenges found (unencrypted or unsupported)")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="challenges.json"`)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(envs)
}

// handleToolWordlist applies the wordlist utilities (length filter, dedupe,
// sort/sort-length, split) to the uploaded files (or a "text" form field) and
// returns the result as text/plain, or a zip when split > 0.
// handleToolRuleTest applies hashcat-style mangling rules to a sample word and
// returns, per rule, the transformed output (or that the rule rejected the
// word) — the GUI rule tester, using the engine's real rule compiler so what it
// shows is exactly what a run would try.
func (s *Server) handleToolRuleTest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "could not parse request")
		return
	}
	word := r.FormValue("word")
	if word == "" {
		writeErr(w, http.StatusBadRequest, "a sample word is required")
		return
	}
	var lines []string
	for _, ln := range strings.Split(r.FormValue("rules"), "\n") {
		ln = strings.TrimRight(ln, "\r")
		if strings.TrimSpace(ln) != "" {
			lines = append(lines, ln)
		}
	}
	rs, err := pattern.CompileRules(lines)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	type ruleOut struct {
		Rule   string `json:"rule"`
		Output string `json:"output,omitempty"`
		Kept   bool   `json:"kept"`
	}
	dbg := rs.ApplyDebug([]byte(word))
	out := make([]ruleOut, 0, len(dbg))
	for _, d := range dbg {
		ro := ruleOut{Rule: d.Rule, Kept: d.Kept}
		if d.Kept {
			ro.Output = string(d.Output)
		}
		out = append(out, ro)
	}
	writeJSON(w, http.StatusOK, map[string]any{"word": word, "results": out})
}

func (s *Server) handleToolWordlist(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadBytes)
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "could not parse upload")
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()
	var lines []string
	for _, fh := range r.MultipartForm.File["source"] {
		data, err := readPart(fh)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		lines = append(lines, splitTextLines(data)...)
	}
	if t := r.FormValue("text"); t != "" {
		lines = append(lines, splitTextLines([]byte(t))...)
	}
	minLen, _ := strconv.Atoi(r.FormValue("min_length"))
	maxLen, _ := strconv.Atoi(r.FormValue("max_length"))
	split, _ := strconv.Atoi(r.FormValue("split"))
	lines = processWordlist(lines, r.FormValue("op"), minLen, maxLen)

	if split > 0 {
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="wordlist-split.zip"`)
		zw := zip.NewWriter(w)
		defer zw.Close()
		for i, n := 0, 0; i < len(lines); i, n = i+split, n+1 {
			end := i + split
			if end > len(lines) {
				end = len(lines)
			}
			fw, err := zw.Create(fmt.Sprintf("part.%03d", n))
			if err != nil {
				return
			}
			_, _ = io.WriteString(fw, strings.Join(lines[i:end], "\n")+"\n")
		}
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	body := strings.Join(lines, "\n")
	if len(lines) > 0 {
		body += "\n"
	}
	_, _ = io.WriteString(w, body)
}

// handleToolPDFKeyTable inverts a 40-bit V1/R2 PDF's file key instantly using an
// uploaded precomputed thunder table (the `pdf-keyattack --table` fast path).
func (s *Server) handleToolPDFKeyTable(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadBytes)
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "could not parse upload")
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()
	srcs := r.MultipartForm.File["source"]
	tbls := r.MultipartForm.File["table"]
	if len(srcs) == 0 || len(tbls) == 0 {
		writeErr(w, http.StatusBadRequest, "need a 'source' PDF and a 'table' thunder-table file")
		return
	}
	data, err := readPart(srcs[0])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read source: "+err.Error())
		return
	}
	h := findPDFRC4(xcrack.DefaultRegistry(), data)
	if h == nil {
		writeJSON(w, http.StatusOK, map[string]any{"found": false, "note": "not a 40-bit RC4 (V1/R2) PDF, or a stronger scheme — the table does not apply"})
		return
	}
	_, rounds, cmpLen, u, attackable := h.RC4KeyAttackParams()
	if !attackable || rounds != 1 || cmpLen != 32 {
		writeJSON(w, http.StatusOK, map[string]any{"found": false, "note": "this PDF is not V1/R2; a cross-file thunder table cannot invert it (use a key sweep)"})
		return
	}
	tf, err := tbls[0].Open()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read table: "+err.Error())
		return
	}
	defer tf.Close()
	tbl, err := pdf.ReadTable(bufio.NewReaderSize(tf, 1<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "thunder table: "+err.Error())
		return
	}
	k, found := tbl.Lookup(u)
	if !found || !h.VerifyFileKey(k) { // authoritative CPU re-check
		writeJSON(w, http.StatusOK, map[string]any{"found": false, "note": "key not covered by this table (try a larger table or a full key sweep)"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"found": true, "key_hex": s.secret(hex.EncodeToString(k))})
}

// secret returns v only when the server exposes secrets; otherwise a redacted
// marker, matching the crack path's ExposeSecrets gate.
func (s *Server) secret(v string) string {
	if s.cfg.ExposeSecrets {
		return v
	}
	return "(recovered; hidden — server started with --expose-secrets=false)"
}

// --- helpers copied from the CLI so the webui stays self-contained ----------

func peekBytes(data []byte) []byte {
	if len(data) > xfileformats.PeekSize {
		return data[:xfileformats.PeekSize]
	}
	return data
}

// toolLines mirrors the CLI's linesOf: collect crackable hash lines for a file.
func toolLines(reg *xfileformats.Registry, data []byte) []hashline.Labeled {
	peek := data
	if len(peek) > toolPeek {
		peek = peek[:toolPeek]
	}
	r := bytes.NewReader(data)
	size := int64(len(data))
	for _, f := range reg.DetectAll(peek) {
		if le, ok := f.(hashline.LineExporter); ok {
			if ls, err := le.HashcatLines(r, size); err == nil && len(ls) > 0 {
				return ls
			}
		}
		if enc, ok := f.(xfileformats.Encrypted); ok {
			ch, err := enc.Probe(r, size)
			if err != nil || ch == nil {
				continue
			}
			if res, ok := hashline.Emit(ch); ok {
				return []hashline.Labeled{{Result: res}}
			}
			continue
		}
		if c, ok := f.(xfileformats.Container); ok {
			entries, err := c.Entries(r, size)
			if err != nil {
				continue
			}
			var out []hashline.Labeled
			for _, e := range entries {
				if e.Encrypted && e.Challenge != nil {
					if res, ok := hashline.Emit(e.Challenge); ok {
						out = append(out, hashline.Labeled{Target: e.Path, Result: res})
					}
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	return nil
}

// toolChallenges mirrors the CLI's challengesFor: top-level crackable challenge
// envelope(s) for a file.
func toolChallenges(reg *xfileformats.Registry, path string, data []byte) (out []*xcrypto.ExportedChallenge) {
	defer func() { _ = recover() }()
	r := bytes.NewReader(data)
	size := int64(len(data))
	for _, cand := range reg.DetectAll(peekBytes(data)) {
		caps := cand.Caps()
		if enc, ok := cand.(xfileformats.Encrypted); ok && caps.Encrypted {
			ch, perr := enc.Probe(r, size)
			if perr != nil || ch == nil {
				continue
			}
			return append(out, xcrypto.ExportChallenge(ch, path))
		}
		if cont, ok := cand.(xfileformats.Container); ok && caps.Container {
			entries, eerr := cont.Entries(r, size)
			if eerr != nil {
				continue
			}
			for _, e := range entries {
				if e != nil && e.Encrypted && e.Challenge != nil {
					out = append(out, xcrypto.ExportChallenge(e.Challenge, path+"!/"+e.Path))
				}
			}
			return out
		}
	}
	return out
}

// findPDFRC4 mirrors the CLI helper: probe data for a 40-bit RC4 PDF and return
// its handler if key-attackable, else nil.
func findPDFRC4(reg *xfileformats.Registry, data []byte) *pdf.Handler {
	r := bytes.NewReader(data)
	size := int64(len(data))
	defer func() { _ = recover() }()
	for _, cand := range reg.DetectAll(peekBytes(data)) {
		enc, ok := cand.(xfileformats.Encrypted)
		if !ok || !cand.Caps().Encrypted {
			continue
		}
		ch, perr := enc.Probe(r, size)
		if perr != nil || ch == nil {
			continue
		}
		if ch.Scheme != "pdf-rc4" {
			return nil
		}
		h, herr := pdf.Unmarshal(ch.Extra)
		if herr != nil || !h.RC4KeyAttackable() {
			return nil
		}
		return h
	}
	return nil
}

func splitTextLines(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

// processWordlist applies the length filter, then dedupe, then the requested
// sort (op: "dedupe" | "sort" | "sort-length" | "" ), mirroring the CLI order.
func processWordlist(lines []string, op string, minLen, maxLen int) []string {
	if minLen > 0 || maxLen > 0 {
		kept := lines[:0]
		for _, l := range lines {
			n := len([]rune(l))
			if n < minLen || (maxLen > 0 && n > maxLen) {
				continue
			}
			kept = append(kept, l)
		}
		lines = kept
	}
	if op == "dedupe" || op == "sort" || op == "sort-length" {
		// dedupe is implied by any op for convenience (and always useful here).
		seen := make(map[string]struct{}, len(lines))
		kept := lines[:0]
		for _, l := range lines {
			if _, ok := seen[l]; ok {
				continue
			}
			seen[l] = struct{}{}
			kept = append(kept, l)
		}
		lines = kept
	}
	switch op {
	case "sort":
		sort.Strings(lines)
	case "sort-length":
		sort.SliceStable(lines, func(a, b int) bool {
			la, lb := len([]rune(lines[a])), len([]rune(lines[b]))
			if la != lb {
				return la < lb
			}
			return lines[a] < lines[b]
		})
	}
	return lines
}
