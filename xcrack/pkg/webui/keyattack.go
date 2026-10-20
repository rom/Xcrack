package webui

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/scheme/officebinary"
	"github.com/rom/xcrypto/scheme/pdf"
	"github.com/rom/xfileformats"
)

// The long key sweeps and table generation from the CLI — office-keyattack,
// pdf-keyattack (full 2^40 sweep) and thunder-gen — run here as cancelable
// background jobs with live progress, so a browser-only operator can launch and
// monitor them without a shell. They are genuinely heavy (a full 40-bit sweep is
// ~10^12 keys); the Tools tab still offers the exact CLI command for the
// distributed/GPU tier, and an optional range bounds a run. These are pure-Go,
// in-process computations: no external binary is executed from a web request.

// chunkKeys is how many keys each sweep chunk covers before progress is emitted
// and cancellation is checked — matching the CLI's sweep granularity.
const chunkKeys uint64 = 1 << 28

// sweepRange runs attack over [start, start+count) in chunks, emitting progress
// between chunks and honoring ctx. attack(base, n) searches one chunk and
// returns (key, found, err). It returns the recovered key, or nil when the range
// is exhausted without a hit.
func sweepRange(ctx context.Context, j *Job, start, count uint64, attack func(base, n uint64) ([]byte, bool, error)) ([]byte, error) {
	for base := start; base < start+count; base += chunkKeys {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		n := chunkKeys
		if base+n > start+count {
			n = start + count - base
		}
		key, found, err := attack(base, n)
		if err != nil {
			return nil, err
		}
		if found {
			j.emit(Event{Type: "progress", Candidates: int64(count), Keyspace: int64(count)})
			return key, nil
		}
		j.emit(Event{Type: "progress", Candidates: int64(base + n - start), Keyspace: int64(count)})
	}
	return nil, nil
}

// sweepWindow resolves the [start, count) search window from the request against
// a total keyspace, defaulting to the whole space.
func sweepWindow(r *http.Request, total uint64) (start, count uint64) {
	start, _ = strconv.ParseUint(r.FormValue("start"), 10, 64)
	if start > total {
		start = total
	}
	count = total - start
	if c, err := strconv.ParseUint(r.FormValue("count"), 10, 64); err == nil && c > 0 && c < count {
		count = c
	}
	return start, count
}

func workersFrom(r *http.Request) int {
	w, _ := strconv.Atoi(r.FormValue("workers"))
	if w < 0 {
		w = 0
	}
	return w
}

// writeKeyResult records a recovered key under the job output (downloadable) and
// emits a found event; the key hex is streamed only when secrets are exposed.
func writeKeyResult(j *Job, scheme, keyHex string, exposeSecrets bool) error {
	outDir := filepath.Join(j.dir, "out")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "key.hex"), []byte(keyHex+"\n"), 0o600); err != nil {
		return err
	}
	j.mu.Lock()
	j.Decrypted = 1
	j.FilesDone = 1
	j.mu.Unlock()
	ev := Event{Type: "found", File: scheme + "-key", Format: scheme}
	if exposeSecrets {
		ev.Password = keyHex
	}
	j.emit(ev)
	return nil
}

// findMSORC4 probes data for an Office 97/2000 40-bit RC4 document (scheme
// "mso-rc4") and returns its challenge, else nil. It mirrors the CLI helper.
func findMSORC4(reg *xfileformats.Registry, data []byte) *xcrypto.Challenge {
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
		if ch.Scheme != "mso-rc4" {
			return nil
		}
		return ch
	}
	return nil
}

// handleToolOfficeKey launches an Office 97/2000 40-bit RC4 key search as a job.
func (s *Server) handleToolOfficeKey(w http.ResponseWriter, r *http.Request) {
	data, ok := s.keyAttackUpload(w, r)
	if !ok {
		return
	}
	ch := findMSORC4(xcrack.DefaultRegistry(), data)
	if ch == nil {
		writeErr(w, http.StatusBadRequest, "not an Office 97/2000 40-bit RC4 document (scheme mso-rc4); CryptoAPI/OOXML documents use the ordinary Crack tab")
		return
	}
	start, count := sweepWindow(r, officebinary.MaxRC4Trunc)
	workers := workersFrom(r)
	salt, ev, evh := ch.KDF.Salt, ch.Extra["enc_verifier"], ch.Verifier
	exposeSecrets := s.cfg.ExposeSecrets

	job, err := s.mgr.newJob()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not allocate job")
		return
	}
	job.mu.Lock()
	job.Kind = "office-keyattack"
	job.Files = []string{"document"}
	job.FilesTotal = 1
	job.Owner = mustSubject(s, r)
	job.specialist = func(ctx context.Context, jb *Job) error {
		jb.emit(Event{Type: "log", Level: "info", Message: fmt.Sprintf("Office 40-bit RC4 key search over %d keys (in-process; a full sweep is a long compute job)", count)})
		key, err := sweepRange(ctx, jb, start, count, func(base, n uint64) ([]byte, bool, error) {
			return officebinary.RC4KeyAttackParallel(ctx, salt, ev, evh, base, n, workers)
		})
		if err != nil {
			return err
		}
		if key == nil {
			jb.emit(Event{Type: "log", Level: "info", Message: "key not found in the searched range"})
			return nil
		}
		return writeKeyResult(jb, "mso-rc4", hex.EncodeToString(key), exposeSecrets)
	}
	job.mu.Unlock()

	s.mgr.start(job)
	s.audit(r, "tool.office-keyattack", job.ID, fmt.Sprintf("%d keys", count))
	writeJSON(w, http.StatusAccepted, map[string]string{"id": job.ID})
}

// handleToolPDFKey launches a full PDF V1/R2 40-bit RC4 file-key sweep as a job.
func (s *Server) handleToolPDFKey(w http.ResponseWriter, r *http.Request) {
	data, ok := s.keyAttackUpload(w, r)
	if !ok {
		return
	}
	h := findPDFRC4(xcrack.DefaultRegistry(), data)
	if h == nil {
		writeErr(w, http.StatusBadRequest, "not a 40-bit RC4 PDF (V1/R2); a 128-bit or AES PDF is not key-attackable — use the ordinary Crack tab")
		return
	}
	start, count := sweepWindow(r, pdf.MaxRC4FileKey)
	workers := workersFrom(r)
	exposeSecrets := s.cfg.ExposeSecrets

	job, err := s.mgr.newJob()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not allocate job")
		return
	}
	job.mu.Lock()
	job.Kind = "pdf-keyattack"
	job.Files = []string{"document.pdf"}
	job.FilesTotal = 1
	job.Owner = mustSubject(s, r)
	job.specialist = func(ctx context.Context, jb *Job) error {
		jb.emit(Event{Type: "log", Level: "info", Message: fmt.Sprintf("PDF 40-bit RC4 file-key search over %d keys (in-process; a full sweep is a long compute job)", count)})
		key, err := sweepRange(ctx, jb, start, count, func(base, n uint64) ([]byte, bool, error) {
			return h.RC4KeyAttackParallel(ctx, base, n, workers)
		})
		if err != nil {
			return err
		}
		if key == nil {
			jb.emit(Event{Type: "log", Level: "info", Message: "file key not found in the searched range"})
			return nil
		}
		return writeKeyResult(jb, "pdf-rc4", hex.EncodeToString(key), exposeSecrets)
	}
	job.mu.Unlock()

	s.mgr.start(job)
	s.audit(r, "tool.pdf-keyattack", job.ID, fmt.Sprintf("%d keys", count))
	writeJSON(w, http.StatusAccepted, map[string]string{"id": job.ID})
}

// handleToolThunderGen launches a PDF R2 thunder-table precomputation as a job.
func (s *Server) handleToolThunderGen(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadBytes)
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "could not parse request")
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()
	if s.mgr.overQuota() {
		writeErr(w, http.StatusInsufficientStorage, "the server's work directory is full")
		return
	}
	bits := atoiDefault(r.FormValue("bits"), 40)
	length := atoiDefault(r.FormValue("length"), 4096)
	chains := atoiDefault(r.FormValue("chains"), 1<<26)
	tables := atoiDefault(r.FormValue("tables"), 4)
	workers := workersFrom(r)
	if bits < 1 || bits > 40 || length < 1 || chains < 1 || tables < 1 {
		writeErr(w, http.StatusBadRequest, "bits (1..40), length, chains and tables must all be positive")
		return
	}

	job, err := s.mgr.newJob()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not allocate job")
		return
	}
	job.mu.Lock()
	job.Kind = "thunder-gen"
	job.Files = []string{fmt.Sprintf("r2-%dbit.thunder", bits)}
	job.FilesTotal = 1
	job.Owner = mustSubject(s, r)
	job.specialist = func(ctx context.Context, jb *Job) error {
		out := filepath.Join(jb.dir, "out", "r2.thunder")
		if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
			return err
		}
		jb.emit(Event{Type: "log", Level: "info", Message: fmt.Sprintf("generating a %d-bit thunder table (%d chains × %d tables, chain length %d)", bits, chains, tables, length)})
		tbl, err := pdf.GenerateTable(ctx, pdf.TableParams{
			KeyspaceBits: bits, ChainLen: length, Chains: chains, Tables: tables, Workers: workers,
			ResumeFile: out,
			Progress: func(done, total uint64) {
				jb.emit(Event{Type: "progress", Candidates: int64(done), Keyspace: int64(total)})
			},
		})
		if err != nil {
			return err
		}
		jb.mu.Lock()
		jb.Decrypted = 1
		jb.FilesDone = 1
		jb.mu.Unlock()
		jb.emit(Event{Type: "log", Level: "info", Message: fmt.Sprintf("table complete: %d chains, chain length %d — download it and use it with pdf-keyattack --table", tbl.Chains(), tbl.ChainLen())})
		return nil
	}
	job.mu.Unlock()

	s.mgr.start(job)
	s.audit(r, "tool.thunder-gen", job.ID, fmt.Sprintf("%d-bit, %d chains", bits, chains))
	writeJSON(w, http.StatusAccepted, map[string]string{"id": job.ID})
}

// keyAttackUpload parses the request, enforces the quota, and returns the
// uploaded `source` document bytes.
func (s *Server) keyAttackUpload(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadBytes)
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "could not parse upload (is it too large?)")
		return nil, false
	}
	// Caller defers RemoveAll via the request; do it here since the bytes are copied.
	defer func() { _ = r.MultipartForm.RemoveAll() }()
	if s.mgr.overQuota() {
		writeErr(w, http.StatusInsufficientStorage, "the server's work directory is full")
		return nil, false
	}
	data := kpPart(r, "source")
	if len(data) == 0 {
		writeErr(w, http.StatusBadRequest, "upload the document as a 'source' file part")
		return nil, false
	}
	return data, true
}

func mustSubject(s *Server, r *http.Request) string {
	u, _ := s.currentUser(r)
	return u.Subject
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
