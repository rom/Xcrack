package webui

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/rom/xcrack/pkg/jobspec"
	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/candidates"
	"github.com/rom/xfileformats"
)

// Feasibility inspection (the CLI's --keyspace / --benchmark / --estimate /
// --stdout, which have no server-side equivalent). POST /api/v1/inspect takes
// the same multipart submission as a job (spec + source + aux + library) but
// runs nothing destructive and persists no job: it measures each target's
// per-format verify rate, counts the configured candidate keyspace, and turns
// the two into a time-to-exhaust — the "how long will this take, is it even
// worth starting" answer — plus a bounded preview of the exact candidate stream.
// Everything runs in an ephemeral temp directory that is removed before return.

const (
	maxInspectFiles    = 25         // bound the synchronous request's wall-clock
	inspectKeyspaceCap = 20_000_000 // keyspace-count ceiling (reported as ">=")
	inspectRateWindow  = 800 * time.Millisecond
	maxPreviewLines    = 200
)

// inspectFileResult is the feasibility summary for one target file.
type inspectFileResult struct {
	Name            string  `json:"name"`
	Scheme          string  `json:"scheme,omitempty"`
	Encrypted       bool    `json:"encrypted"`
	Keyspace        int64   `json:"keyspace"` // -1 when unknown
	KeyspaceCapped  bool    `json:"keyspace_capped,omitempty"`
	Rate            float64 `json:"rate"` // candidates/sec, 0 when unmeasured
	RateText        string  `json:"rate_text,omitempty"`
	SecondsExhaust  float64 `json:"seconds_to_exhaust,omitempty"`
	TimeExhaustText string  `json:"time_to_exhaust,omitempty"`
	TimeExpectText  string  `json:"time_expected,omitempty"`
	Note            string  `json:"note,omitempty"`
}

// handleInspect estimates feasibility for a candidate configuration without
// starting a job.
func (s *Server) handleInspect(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadBytes)
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "could not parse upload (is it too large?)")
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()

	spec, err := jobspec.ParseStrict([]byte(r.FormValue("spec")))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "spec: "+err.Error())
		return
	}
	sources := r.MultipartForm.File["source"]
	if len(sources) == 0 {
		writeErr(w, http.StatusBadRequest, "no source files uploaded (need at least one 'source' part)")
		return
	}
	if s.mgr.overQuota() {
		writeErr(w, http.StatusInsufficientStorage, "the server's work directory is full")
		return
	}

	// Ephemeral working directory: holds uploads + aux just long enough to build
	// the assembler, then is removed. It carries no job.json, so a server restart
	// never reloads it as a job.
	dir, err := os.MkdirTemp(s.cfg.WorkDir, "inspect-")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not allocate scratch space")
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()
	auxDir := filepath.Join(dir, "aux")
	if err := os.MkdirAll(auxDir, 0o700); err != nil {
		writeErr(w, http.StatusInternalServerError, "scratch space")
		return
	}

	for _, fh := range r.MultipartForm.File["aux"] {
		if _, err := savePart(fh, auxDir); err != nil {
			writeErr(w, http.StatusBadRequest, "aux upload: "+err.Error())
			return
		}
	}
	if libNames := splitList(r.FormValue("library")); len(libNames) > 0 {
		if err := s.copyLibraryInto(libNames, auxDir); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	var names, paths []string
	for _, fh := range sources {
		p, err := savePart(fh, filepath.Join(dir, "uploads"))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "source upload: "+err.Error())
			return
		}
		names = append(names, safeSegment(fh.Filename))
		paths = append(paths, p)
	}

	if err := sanitizeSpecPaths(spec, auxDir, s.cfg.AllowServerPaths); err != nil {
		writeErr(w, http.StatusBadRequest, "spec: "+err.Error())
		return
	}
	if err := spec.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "spec: "+err.Error())
		return
	}

	asm, err := jobspec.NewAssembler(spec, jobspec.Runtime{})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "assemble candidates: "+err.Error())
		return
	}
	reg := xcrack.DefaultRegistry()

	var truncated bool
	if len(names) > maxInspectFiles {
		names, paths, truncated = names[:maxInspectFiles], paths[:maxInspectFiles], true
	}

	results := make([]inspectFileResult, 0, len(names))
	for i, name := range names {
		results = append(results, s.inspectOne(reg, asm, name, paths[i]))
	}

	preview, more := previewCandidates(asm, names[0])

	writeJSON(w, http.StatusOK, map[string]any{
		"files":                       results,
		"files_truncated":             truncated,
		"candidate_preview":           preview,
		"candidate_preview_truncated": more,
	})
}

// inspectOne builds the feasibility summary for a single target file: probe it
// for its first encrypted scheme, measure that scheme's verify rate, count the
// candidate keyspace, and combine them into a time estimate.
func (s *Server) inspectOne(reg *xfileformats.Registry, asm *jobspec.Assembler, name, path string) inspectFileResult {
	res := inspectFileResult{Name: name, Keyspace: -1}

	ks := asm.Keyspace(name)
	if ks < 0 {
		ks, res.KeyspaceCapped = countCandidates(asm.Candidates(name), inspectKeyspaceCap)
	}
	res.Keyspace = ks

	data, err := os.ReadFile(path)
	if err != nil {
		res.Note = "could not read the uploaded file"
		return res
	}
	label, verify, ok := inspectFirstTarget(reg, data)
	if !ok {
		res.Note = "not encrypted or unsupported — nothing to benchmark"
		return res
	}
	res.Scheme, res.Encrypted = label, true
	res.Rate = measureVerifyRate(verify, inspectRateWindow)
	res.RateText = fmtRate(res.Rate)

	if ks >= 0 && res.Rate > 0 {
		res.SecondsExhaust = float64(ks) / res.Rate
		res.TimeExhaustText = fmtDur(time.Duration(res.SecondsExhaust * float64(time.Second)))
		res.TimeExpectText = fmtDur(time.Duration(res.SecondsExhaust / 2 * float64(time.Second)))
		if res.KeyspaceCapped {
			res.Note = "keyspace counted up to the cap; the true time is larger"
		}
	} else {
		res.Note = "time unknown (open-ended keyspace or unmeasurable rate)"
	}
	return res
}

// previewCandidates pulls up to maxPreviewLines candidates from the assembled
// stream for name — exactly what a run would try, in order — and reports whether
// more remain. The candidates are the caller's own attack configuration (their
// wordlists, masks and rules), not recovered secrets, so they are never gated.
func previewCandidates(asm *jobspec.Assembler, name string) (lines []string, more bool) {
	src := asm.Candidates(name)
	if src == nil {
		return nil, false
	}
	if err := src.Reset(); err != nil {
		return nil, false
	}
	for len(lines) < maxPreviewLines {
		b, err := src.Next()
		if err != nil {
			return lines, false
		}
		lines = append(lines, string(b))
	}
	// One more read decides whether the stream continued past the preview.
	if _, err := src.Next(); err == nil {
		more = true
	}
	return lines, more
}

// --- helpers ported from the CLI's benchmark.go so the webui stays
// self-contained (mirrors cmd/xcrack/benchmark.go) ---------------------------

// countCandidates counts the candidates a source yields, stopping at cap
// (0 = no cap). Returns the count and whether the cap was hit.
func countCandidates(src candidates.Source, cap int64) (int64, bool) {
	if src == nil {
		return 0, false
	}
	if err := src.Reset(); err != nil {
		return 0, false
	}
	var n int64
	for {
		if cap > 0 && n >= cap {
			return n, true
		}
		if _, err := src.Next(); err != nil {
			return n, false
		}
		n++
	}
}

// inspectFirstTarget probes data and returns a label plus a single-password
// verifier for the first encrypted target (a whole-file scheme, or the first
// encrypted container entry). Parsing runs under a recover guard.
func inspectFirstTarget(reg *xfileformats.Registry, data []byte) (label string, verify func([]byte) (bool, error), ok bool) {
	defer func() {
		if recover() != nil {
			label, verify, ok = "", nil, false
		}
	}()
	r := bytes.NewReader(data)
	size := int64(len(data))
	for _, cand := range reg.DetectAll(peekBytes(data)) {
		caps := cand.Caps()
		if enc, isEnc := cand.(xfileformats.Encrypted); isEnc && caps.Encrypted {
			ch, perr := enc.Probe(r, size)
			if perr != nil || ch == nil {
				continue
			}
			return inspectScheme(ch, cand.Name()), func(pw []byte) (bool, error) {
				okv, _, verr := enc.Verify(ch, pw)
				return okv, verr
			}, true
		}
		if cont, isCont := cand.(xfileformats.Container); isCont && caps.Container {
			entries, eerr := cont.Entries(r, size)
			if eerr != nil {
				continue
			}
			for _, e := range entries {
				if e != nil && e.Encrypted && e.Verify != nil {
					return inspectScheme(e.Challenge, cand.Name()), e.Verify, true
				}
			}
			return "", nil, false
		}
	}
	return "", nil, false
}

func inspectScheme(ch *xcrypto.Challenge, fallback string) string {
	if ch != nil && ch.Scheme != "" {
		return ch.Scheme
	}
	return fallback
}

// measureVerifyRate runs verify against distinct wrong candidates for window and
// returns the observed candidates/second. A hostile verifier that panics is
// contained so it cannot crash the request.
func measureVerifyRate(verify func([]byte) (bool, error), window time.Duration) float64 {
	deadline := time.Now().Add(window)
	start := time.Now()
	var n int64
	buf := make([]byte, 0, 24)
	for {
		buf = append(buf[:0], "xcrackbench-"...)
		buf = strconv.AppendInt(buf, n, 10)
		func() {
			defer func() { _ = recover() }()
			verify(append([]byte(nil), buf...))
		}()
		n++
		if n%16 == 0 && time.Now().After(deadline) {
			break
		}
	}
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return float64(n) / elapsed
}

func fmtRate(r float64) string {
	switch {
	case r >= 1e9:
		return fmt.Sprintf("%.2fG", r/1e9)
	case r >= 1e6:
		return fmt.Sprintf("%.2fM", r/1e6)
	case r >= 1e3:
		return fmt.Sprintf("%.2fk", r/1e3)
	default:
		return fmt.Sprintf("%.0f", r)
	}
}

// fmtDur renders a duration at a human-friendly precision, capping the display
// at years for astronomically large keyspaces.
func fmtDur(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	const year = 365 * 24 * time.Hour
	years := float64(d) / float64(year)
	if years > 1000 {
		return fmt.Sprintf("%.2g years", years)
	}
	switch {
	case d >= year:
		return fmt.Sprintf("%.1f years", years)
	case d >= 24*time.Hour:
		return fmt.Sprintf("%.1f days", d.Hours()/24)
	case d >= time.Hour:
		return d.Round(time.Minute).String()
	case d >= time.Minute:
		return d.Round(time.Second).String()
	default:
		return d.Round(10 * time.Millisecond).String()
	}
}
