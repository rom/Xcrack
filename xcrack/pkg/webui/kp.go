package webui

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/rom/xcrypto/scheme/zipcrypto"
	"github.com/rom/xfileformats/formats/zip"
)

// handleToolKP launches a ZipCrypto known-plaintext (Biham–Kocher) key recovery
// as a background job. From aligned known plaintext and ciphertext it recovers
// the 96-bit internal key state (no password). Optionally — given the archive
// and the full known-plaintext entry — it rolls that state back to the entry
// start and decrypts EVERY ZipCrypto entry of the archive with the shared state
// (cross-entry key reuse: one recovery unlocks the whole archive), writing the
// results into the job's output tree for download. ZipCrypto is broken by
// design, so this is legitimate cryptanalysis of a weak cipher.
//
// It runs as a specialist job (not a synchronous tool) because the in-process
// attack is compute-heavy. The external bkcrack offload is intentionally
// CLI-only: executing an operator-named binary from a web request is an exec
// risk the web tier must not take.
func (s *Server) handleToolKP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadBytes)
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "could not parse upload (is it too large?)")
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()
	if s.mgr.overQuota() {
		writeErr(w, http.StatusInsufficientStorage, "the server's work directory is full")
		return
	}

	plain := kpPart(r, "plain")
	cipher := kpPart(r, "cipher")
	if len(plain) == 0 || len(cipher) == 0 {
		writeErr(w, http.StatusBadRequest, "need a 'plain' and a 'cipher' file part (aligned known plaintext and its ciphertext)")
		return
	}
	if len(plain) != len(cipher) {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("plain (%d bytes) and cipher (%d bytes) must be equal length", len(plain), len(cipher)))
		return
	}
	if len(plain) < zipcrypto.MinKnownPlaintext {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("need at least %d contiguous known-plaintext bytes, have %d", zipcrypto.MinKnownPlaintext, len(plain)))
		return
	}

	archive := kpPart(r, "zip") // the ZipCrypto archive (optional, for whole-archive decrypt)
	entry := kpPart(r, "entry") // the full known-plaintext entry (12-byte header + data)
	offset, _ := strconv.Atoi(r.FormValue("offset"))
	if len(archive) > 0 && len(entry) == 0 {
		writeErr(w, http.StatusBadRequest, "whole-archive decrypt needs the known-plaintext 'entry' part (its full 12-byte header + data) to establish the entry-start key state")
		return
	}

	owner, _ := s.currentUser(r)
	job, err := s.mgr.newJob()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not allocate job")
		return
	}
	files := []string{"plain", "cipher"}
	if len(archive) > 0 {
		files = append(files, "archive")
	}
	exposeSecrets := s.cfg.ExposeSecrets
	job.mu.Lock()
	job.Kind = "kp"
	job.Files = files
	job.FilesTotal = 1
	job.Owner = owner.Subject
	job.specialist = func(ctx context.Context, j *Job) error {
		return runKPJob(ctx, j, plain, cipher, archive, entry, offset, exposeSecrets)
	}
	job.mu.Unlock()

	s.mgr.start(job)
	detail := fmt.Sprintf("%d plaintext bytes", len(plain))
	if len(archive) > 0 {
		detail += ", whole-archive decrypt"
	}
	s.audit(r, "tool.kp", job.ID, detail)
	writeJSON(w, http.StatusAccepted, map[string]string{"id": job.ID})
}

// kpPart reads the named uploaded file part fully, or returns nil.
func kpPart(r *http.Request, field string) []byte {
	fhs := r.MultipartForm.File[field]
	if len(fhs) == 0 {
		return nil
	}
	b, err := readPart(fhs[0])
	if err != nil {
		return nil
	}
	return b
}

// runKPJob is the specialist job body: recover the ZipCrypto key state, then (if
// an archive was supplied) roll back to the entry start and decrypt every entry.
func runKPJob(ctx context.Context, j *Job, plain, cipher, archive, entry []byte, offset int, exposeSecrets bool) error {
	j.emit(Event{Type: "log", Level: "info", Message: fmt.Sprintf(
		"recovering the ZipCrypto key state from %d known-plaintext bytes (in-process Biham–Kocher; compute-heavy)", len(plain))})

	keys, ok := zipcrypto.RecoverKeysCtx(ctx, plain, cipher)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !ok {
		return fmt.Errorf("key state not recovered — check that the plaintext and ciphertext are aligned and the same stream position")
	}
	k0, k1, k2 := keys.Words()
	state := fmt.Sprintf("%08x %08x %08x", k0, k1, k2)
	if exposeSecrets {
		j.emit(Event{Type: "log", Level: "info", Message: "recovered key state: " + state})
	} else {
		j.emit(Event{Type: "log", Level: "info", Message: "recovered the key state (hidden; server started with --expose-secrets=false)"})
	}

	// No archive: the recovered state is the whole result.
	if len(archive) == 0 || len(entry) == 0 {
		j.mu.Lock()
		j.Decrypted = 1
		j.mu.Unlock()
		ev := Event{Type: "found", File: "zipcrypto-key-state", Format: "zipcrypto"}
		if exposeSecrets {
			ev.Password = state
		}
		j.emit(ev)
		return nil
	}

	// Whole-archive decrypt: roll the state back over the bytes preceding the
	// known plaintext (header + any earlier data) to the entry start.
	abs := zipcrypto.HeaderLen + offset
	if offset < 0 || abs+len(cipher) > len(entry) {
		return fmt.Errorf("offset %d places the known plaintext outside the %d-byte entry", offset, len(entry))
	}
	if !bytes.Equal(entry[abs:abs+len(cipher)], cipher) {
		return fmt.Errorf("the cipher does not match the entry at offset %d (wrong offset or mismatched files)", offset)
	}
	start, _ := keys.RollBack(entry[:abs])

	results, err := zip.DecryptArchiveWithStart(bytes.NewReader(archive), int64(len(archive)), start)
	if err != nil {
		return fmt.Errorf("archive decrypt: %w", err)
	}
	outDir := filepath.Join(j.dir, "out", "archive.extracted")
	n := 0
	for _, res := range results {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !res.OK {
			continue
		}
		dst := filepath.Join(outDir, safeSegment(res.Name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			j.emit(Event{Type: "log", Level: "warn", Message: fmt.Sprintf("%s: %v", res.Name, err)})
			continue
		}
		if err := os.WriteFile(dst, res.Plaintext, 0o600); err != nil {
			j.emit(Event{Type: "log", Level: "warn", Message: fmt.Sprintf("%s: %v", res.Name, err)})
			continue
		}
		n++
		j.emit(Event{Type: "log", Level: "info", Message: fmt.Sprintf("decrypted %s (%d bytes)", res.Name, len(res.Plaintext))})
	}
	if n == 0 {
		return fmt.Errorf("the recovered key state decrypted no entries (not a ZipCrypto archive, or a different password)")
	}
	j.mu.Lock()
	j.Decrypted = n
	j.FilesDone = 1
	j.mu.Unlock()
	j.emit(Event{Type: "log", Level: "info", Message: fmt.Sprintf("decrypted %d entr%s from one recovery (cross-entry key reuse)", n, map[bool]string{true: "y", false: "ies"}[n == 1])})
	return nil
}
