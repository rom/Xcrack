package webui

import (
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rom/xcrack/pkg/jobspec"
	"github.com/rom/xcrack/pkg/xcrack"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, buildMeta(s.cfg))
}

// handleValidate parses a YAML spec strictly and validates it, so the editor can
// show problems before a run.
func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not read body")
		return
	}
	spec, err := jobspec.ParseStrict(body)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	if err := spec.Validate(); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true})
}

// handleFormat parses then re-marshals a spec so the editor's "Format" button
// tidies the document.
func (s *Server) handleFormat(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not read body")
		return
	}
	spec, err := jobspec.ParseStrict(body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := spec.Marshal()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not format")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(out)})
}

// handleIdentify detects the format/encryption of each uploaded file without
// cracking.
func (s *Server) handleIdentify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "could not parse upload")
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()
	reg := xcrack.DefaultRegistry()
	type idResult struct {
		Name       string `json:"name"`
		Format     string `json:"format"`
		Encrypted  bool   `json:"encrypted"`
		Container  bool   `json:"container"`
		Explodable bool   `json:"explodable"`
		Unknown    bool   `json:"unknown,omitempty"`
	}
	var out []idResult
	parts := append(r.MultipartForm.File["source"], r.MultipartForm.File["file"]...)
	for _, fh := range parts {
		res := idResult{Name: safeSegment(fh.Filename)}
		peek, err := peekPart(fh, 512)
		if err != nil {
			res.Unknown = true
			out = append(out, res)
			continue
		}
		f, derr := reg.Detect(peek)
		if derr != nil {
			res.Unknown = true
			out = append(out, res)
			continue
		}
		c := f.Caps()
		res.Format, res.Encrypted, res.Container, res.Explodable = f.Name(), c.Encrypted, c.Container, c.Explodable
		out = append(out, res)
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": out})
}

// handleCreateJob accepts a multipart submission: a "spec" YAML field, one or
// more "source" file parts (the targets), and any number of "aux" file parts
// (wordlists, breach corpora, combinator/hcmask inputs) the spec references by
// base name.
func (s *Server) handleCreateJob(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadBytes)
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "could not parse upload (is it too large?)")
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()

	specText := r.FormValue("spec")
	spec, err := jobspec.ParseStrict([]byte(specText))
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
		writeErr(w, http.StatusInsufficientStorage, "the server's work directory is full; delete finished jobs or raise --max-workdir-bytes")
		return
	}

	owner, _ := s.currentUser(r)

	job, err := s.mgr.newJob()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not allocate job")
		return
	}

	// Save auxiliary files (wordlists etc.) the spec may reference by base name.
	for _, fh := range r.MultipartForm.File["aux"] {
		if _, err := savePart(fh, filepath.Join(job.dir, "aux")); err != nil {
			writeErr(w, http.StatusBadRequest, "aux upload: "+err.Error())
			return
		}
	}
	// Pull in any referenced server-side library wordlists (by name) so the spec
	// can reference them exactly like an uploaded aux file.
	if libNames := splitList(r.FormValue("library")); len(libNames) > 0 {
		if err := s.copyLibraryInto(libNames, filepath.Join(job.dir, "aux")); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	// Save the source files (the recovery targets).
	var names, paths []string
	for _, fh := range sources {
		p, err := savePart(fh, filepath.Join(job.dir, "uploads"))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "source upload: "+err.Error())
			return
		}
		names = append(names, safeSegment(fh.Filename))
		paths = append(paths, p)
	}

	// Lock the spec's file references to the uploaded files (unless the operator
	// trusts server paths), and validate before queuing.
	if err := sanitizeSpecPaths(spec, filepath.Join(job.dir, "aux"), s.cfg.AllowServerPaths); err != nil {
		writeErr(w, http.StatusBadRequest, "spec: "+err.Error())
		return
	}
	if err := spec.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "spec: "+err.Error())
		return
	}
	// Distributed cracking makes the server connect out to the configured
	// xcrackd endpoints; only a trusted (local) instance may drive it.
	if len(spec.Cluster.Servers) > 0 && !s.cfg.AllowServerPaths {
		writeErr(w, http.StatusBadRequest, "distributed cracking (a cluster block) requires the server to be started with --allow-server-paths (trusted local instance)")
		return
	}
	yamlOut, _ := spec.Marshal()

	// Solved-challenge round-trip: any uploaded `recovered` parts (the JSON a
	// challenge exported here was solved into on an external cracker) are decoded
	// into priority passwords, tried first on every file — the GUI equivalent of
	// the CLI's --resume-from. Malformed payloads are rejected so a mistake is
	// visible rather than silently dropped.
	var priority []string
	for _, fh := range r.MultipartForm.File["recovered"] {
		data, err := readPart(fh)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "recovered upload: "+err.Error())
			return
		}
		pws, err := decodeRecoveredPasswords(data)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "recovered-password file: "+err.Error())
			return
		}
		priority = append(priority, pws...)
	}

	job.mu.Lock()
	job.spec = spec
	job.Files = names
	job.sources = paths
	job.FilesTotal = len(paths)
	job.SpecYAML = string(yamlOut)
	job.Owner = owner.Subject
	job.CaseID = strings.TrimSpace(r.FormValue("case_id"))
	job.Examiner = strings.TrimSpace(r.FormValue("examiner"))
	job.priority = priority
	job.mu.Unlock()

	s.mgr.start(job)
	detail := fmt.Sprintf("%d file(s)", len(names))
	if len(priority) > 0 {
		detail += fmt.Sprintf(", %d resume password(s)", len(priority))
	}
	s.audit(r, "job.create", job.ID, detail)
	writeJSON(w, http.StatusAccepted, map[string]string{"id": job.ID})
}

func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request) {
	u, _ := s.currentUser(r)
	all := s.mgr.list()
	jobs := make([]JobView, 0, len(all))
	for _, v := range all {
		if s.canAccess(u, v.Owner, v.Shared) {
			jobs = append(jobs, v)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs})
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	job := s.jobForRequest(w, r)
	if job == nil {
		return
	}
	writeJSON(w, http.StatusOK, job.snapshot())
}

// handleDeleteJob removes a job from the history and deletes its working
// directory (canceling it first if it is still running).
func (s *Server) handleDeleteJob(w http.ResponseWriter, r *http.Request) {
	if s.jobForMutation(w, r) == nil {
		return
	}
	s.mgr.remove(r.PathValue("id"))
	s.audit(r, "job.delete", r.PathValue("id"), "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleRerun starts a fresh job from an existing (finished or interrupted) job's
// saved spec and uploaded files — a GUI "resume" that needs no re-upload.
func (s *Server) handleRerun(w http.ResponseWriter, r *http.Request) {
	old := s.jobForMutation(w, r)
	if old == nil {
		return
	}
	owner, _ := s.currentUser(r)
	nj, err := s.mgr.rerun(old, owner.Subject)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, "job.rerun", nj.ID, "from "+old.ID)
	writeJSON(w, http.StatusAccepted, map[string]string{"id": nj.ID})
}

// handleShareJob sets the subjects a job is shared with (read access). Only the
// owner or an admin may share (jobForMutation), and only in multi-user mode.
func (s *Server) handleShareJob(w http.ResponseWriter, r *http.Request) {
	job := s.jobForMutation(w, r)
	if job == nil {
		return
	}
	if !s.auth.enabled {
		writeErr(w, http.StatusBadRequest, "sharing is only meaningful in multi-user mode")
		return
	}
	var body struct {
		Subjects []string `json:"subjects"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, `invalid body (expected {"subjects":[...]})`)
		return
	}
	owner := job.ownerID()
	seen := map[string]bool{}
	var shared []string
	for _, sub := range body.Subjects {
		sub = strings.TrimSpace(sub)
		if sub == "" || sub == owner || seen[sub] {
			continue
		}
		seen[sub] = true
		shared = append(shared, sub)
	}
	job.mu.Lock()
	job.Shared = shared
	job.mu.Unlock()
	s.mgr.persist(job)
	s.audit(r, "job.share", job.ID, strings.Join(shared, ", "))
	writeJSON(w, http.StatusOK, map[string]any{"shared": shared})
}

// handleVault lists the found-password vault (potfile). It is a single-user,
// secrets-exposed feature; otherwise it reports disabled.
func (s *Server) handleVault(w http.ResponseWriter, r *http.Request) {
	if !s.mgr.vaultActive() {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	enc, pws := s.mgr.vaultView()
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "encrypted": enc, "count": len(pws), "passwords": pws})
}

func (s *Server) handleCancelJob(w http.ResponseWriter, r *http.Request) {
	if s.jobForMutation(w, r) == nil {
		return
	}
	if !s.mgr.cancel(r.PathValue("id")) {
		writeErr(w, http.StatusNotFound, "no such job (or already finished)")
		return
	}
	s.audit(r, "job.cancel", r.PathValue("id"), "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "canceling"})
}

// jobForRequest returns the job named by the {id} path value only if it exists
// and the request's user may access it; otherwise it writes a 404 (hiding a job
// that exists but belongs to another user) and returns nil.
func (s *Server) jobForRequest(w http.ResponseWriter, r *http.Request) *Job {
	job := s.mgr.get(r.PathValue("id"))
	if job == nil {
		writeErr(w, http.StatusNotFound, "no such job")
		return nil
	}
	u, _ := s.currentUser(r)
	owner, shared := job.ownerAndShared()
	if !s.canAccess(u, owner, shared) {
		writeErr(w, http.StatusNotFound, "no such job")
		return nil
	}
	return job
}

// jobForMutation returns the job named by {id} only if the request's user may
// MODIFY it (owner or admin). A user who can read but not modify it (a viewer or
// a shared-with reader) gets 403; a job they cannot even see gets 404.
func (s *Server) jobForMutation(w http.ResponseWriter, r *http.Request) *Job {
	job := s.jobForRequest(w, r)
	if job == nil {
		return nil
	}
	u, _ := s.currentUser(r)
	if !s.canMutate(u, job.ownerID()) {
		writeErr(w, http.StatusForbidden, "read-only access: only the job's owner can change it")
		return nil
	}
	return job
}

// handleJobEvents streams a job's events as Server-Sent Events: the history so
// far, then live updates until the job ends or the client disconnects.
func (s *Server) handleJobEvents(w http.ResponseWriter, r *http.Request) {
	job := s.jobForRequest(w, r)
	if job == nil {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	history, ch, done, cancel := job.subscribe()
	defer cancel()
	for _, e := range history {
		writeSSE(w, e)
	}
	flusher.Flush()
	for {
		select {
		case e := <-ch:
			writeSSE(w, e)
			flusher.Flush()
		case <-done:
			// Drain any events emitted between the last read and completion.
			for {
				select {
				case e := <-ch:
					writeSSE(w, e)
				default:
					flusher.Flush()
					return
				}
			}
		case <-r.Context().Done():
			return
		}
	}
}

// handleDownload streams the job's extracted output tree as a zip archive.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	job := s.jobForRequest(w, r)
	if job == nil {
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "xcrack-"+job.ID+".zip"))
	if err := job.zipOutputs(w); err != nil {
		// Headers are already sent; nothing better than ending the stream.
		return
	}
}

// handleStats reports aggregate counters across all jobs for the dashboard,
// plus per-format/algorithm throughput and a recovered-password top list.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	u, _ := s.currentUser(r)
	all := s.mgr.list()
	jobs := make([]JobView, 0, len(all))
	for _, v := range all {
		if s.canAccess(u, v.Owner, v.Shared) {
			jobs = append(jobs, v)
		}
	}
	var running, done int
	var candidates int64
	var decrypted, locked, files int

	type algoAgg struct {
		cand  int64
		ms    int64
		files int
	}
	algo := map[string]*algoAgg{}
	pwCount := map[string]int{}

	for _, j := range jobs {
		switch j.State {
		case StateRunning, StateQueued:
			running++
		case StateDone, StateError, StateCanceled:
			done++
		}
		candidates += j.Candidates
		files += j.FilesDone
		for _, fr := range j.Results {
			if fr.Report == nil {
				continue
			}
			decrypted += countStatus(fr.Report.Root, "decrypted")
			locked += countStatus(fr.Report.Root, "locked")
			// Per-algorithm speed: attribute this file's candidate work and time to
			// the encrypted scheme it exercised.
			format := primaryFormat(fr.Report.Root)
			a := algo[format]
			if a == nil {
				a = &algoAgg{}
				algo[format] = a
			}
			a.cand += fr.Report.Stats.CandidatesTried
			a.ms += fr.Report.Stats.ElapsedMS
			a.files++
			if s.cfg.ExposeSecrets {
				for _, pw := range fr.Report.Passwords {
					pwCount[pw]++
				}
			}
		}
	}

	type algoSpeed struct {
		Format     string  `json:"format"`
		CandPerSec float64 `json:"candidates_per_sec"`
		Candidates int64   `json:"candidates"`
		Files      int     `json:"files"`
	}
	speeds := make([]algoSpeed, 0, len(algo))
	for f, a := range algo {
		rate := 0.0
		if a.ms > 0 {
			rate = float64(a.cand) / (float64(a.ms) / 1000)
		}
		speeds = append(speeds, algoSpeed{Format: f, CandPerSec: rate, Candidates: a.cand, Files: a.files})
	}
	sort.Slice(speeds, func(i, j int) bool { return speeds[i].CandPerSec > speeds[j].CandPerSec })

	type pwEntry struct {
		Password string `json:"password"`
		Count    int    `json:"count"`
	}
	top := make([]pwEntry, 0, len(pwCount))
	for pw, c := range pwCount {
		top = append(top, pwEntry{Password: pw, Count: c})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].Count != top[j].Count {
			return top[i].Count > top[j].Count
		}
		return top[i].Password < top[j].Password
	})
	if len(top) > 20 {
		top = top[:20]
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"jobs_total":       len(jobs),
		"jobs_active":      running,
		"jobs_finished":    done,
		"candidates_tried": candidates,
		"files_processed":  files,
		"nodes_decrypted":  decrypted,
		"nodes_locked":     locked,
		"algo_speed":       speeds,
		"top_passwords":    top,
		"expose_secrets":   s.cfg.ExposeSecrets,
	})
}

// primaryFormat returns the format of the first encrypted node in a report
// subtree (the scheme actually attacked), falling back to the root format, or
// "unknown".
func primaryFormat(n xcrack.NodeReport) string {
	if n.WasEncrypted && n.Format != "" {
		return n.Format
	}
	for _, c := range n.Children {
		if f := primaryFormat(c); f != "" && f != "unknown" {
			return f
		}
	}
	if n.Format != "" {
		return n.Format
	}
	return "unknown"
}

func (s *Server) handleListDocs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"docs": s.mgr.listDocs()})
}

func (s *Server) handleGetDoc(w http.ResponseWriter, r *http.Request) {
	data, ok := s.mgr.readDoc(r.PathValue("name"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no such document")
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}

// --- helpers ---

// countStatus counts nodes with the given status string in a report subtree.
func countStatus(n xcrack.NodeReport, status string) int {
	c := 0
	if n.Status == status {
		c++
	}
	for _, ch := range n.Children {
		c += countStatus(ch, status)
	}
	return c
}

// savePart writes one uploaded file part to dir under a sanitized base name and
// returns the absolute path. It bounds nothing itself; the request body is
// already capped by MaxBytesReader.
func savePart(fh *multipart.FileHeader, dir string) (string, error) {
	src, err := fh.Open()
	if err != nil {
		return "", err
	}
	defer src.Close()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, safeSegment(fh.Filename))
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(f, src); err != nil {
		return "", err
	}
	return dst, nil
}

// peekPart reads up to n leading bytes of an uploaded file part.
func peekPart(fh *multipart.FileHeader, n int) ([]byte, error) {
	f, err := fh.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	m, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	return buf[:m], nil
}

func writeSSE(w io.Writer, e Event) {
	b, err := marshalEvent(e)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
}
