// Package api exposes the Xcrack recovery engine as an HTTP service. It is the
// third delivery form alongside the CLI and the embeddable library: a backend
// can run the engine on a powerful, hardened host (optionally fronting a
// GPU/OpenCL cracking tier) and serve decryption to clients such as an Impex
// kiosk or an Impex DataLock appliance.
//
// The service is a thin, safe wrapper over xcrack.Pool. It adds only transport
// concerns — request size bounds, per-request deadlines, method/path checks,
// and JSON (de)serialization — and holds no state beyond the shared Pool, whose
// global semaphore bounds total CPU across all concurrent requests.
//
// Security posture: the body is untrusted input handed to hostile-input-safe
// parsers. Recovered passwords and decrypted content appear in responses, so an
// operator MUST place authentication/authorization (and, unless xcrackd's own
// TLS is enabled, transport security) in front of this service; the API package
// itself ships neither. The audit hook (Config.Audit) records recovered
// passwords only when the operator opts in.
package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrypto/candidates"
)

// Config tunes the HTTP service. The zero value is usable; NewServer applies
// defaults for any unset field.
type Config struct {
	// MaxBodyBytes bounds a request body (the file to analyze). Default 256 MiB.
	MaxBodyBytes int64
	// RequestTimeout bounds one request's processing. Default 120s. The Pool's
	// own budget still applies; the tighter bound wins.
	RequestTimeout time.Duration
	// AllowDefaultList lets a request opt in to the embedded default wordlist via
	// ?defaults=true. Off by default so a request cannot trigger a large search
	// unless the operator permits it.
	AllowDefaultList bool
	// MaxPasswords caps how many ?password= candidates one request may supply.
	// Default 10000.
	MaxPasswords int
	// Audit, if set, is called after each successful Process with the result tree
	// and per-request metadata, so an operator can emit an audit-log entry per
	// request (xcrackd wires this to its structured/syslog audit trail). It runs
	// on the request goroutine before the response is written; keep it fast and
	// non-blocking. nil disables per-request audit logging.
	Audit func(res *xcrack.Result, meta AuditMeta)
}

// AuditMeta carries per-request context for the Config.Audit hook.
type AuditMeta struct {
	RemoteAddr string        // client address (host:port)
	Endpoint   string        // request path, e.g. "/v1/decrypt"
	Bytes      int           // request body size in bytes
	Elapsed    time.Duration // processing wall-clock time
}

func (c *Config) applyDefaults() {
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 256 << 20
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = 120 * time.Second
	}
	if c.MaxPasswords <= 0 {
		c.MaxPasswords = 10000
	}
}

// Server serves the recovery engine over HTTP, backed by a shared Pool.
type Server struct {
	pool *xcrack.Pool
	cfg  Config
}

// NewServer returns a Server backed by pool. The pool is owned by the caller and
// must outlive the server.
func NewServer(pool *xcrack.Pool, cfg Config) *Server {
	cfg.applyDefaults()
	return &Server{pool: pool, cfg: cfg}
}

// Handler returns the HTTP handler exposing the API routes:
//
//	GET  /v1/healthz   liveness probe
//	POST /v1/identify  detect format/encryption only (no cracking)
//	POST /v1/decrypt   decrypt + recursively decompose with supplied candidates
//
// Both POST routes take the raw file as the request body (application/octet-stream)
// and read candidates from the query string: repeated ?password=... values, and
// ?defaults=true to append the embedded default list (when enabled).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/healthz", s.handleHealth)
	mux.HandleFunc("/v1/metrics", s.handleMetrics)
	mux.HandleFunc("/metrics", s.handlePrometheus)
	mux.HandleFunc("/v1/identify", s.handleIdentify)
	mux.HandleFunc("/v1/decrypt", s.handleDecrypt)
	return mux
}

// handleMetrics reports the backing Pool's aggregate counters (counts only, no
// secrets) for telemetry.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.pool.Metrics())
}

// handlePrometheus serves Pool metrics in Prometheus text exposition format.
func (s *Server) handlePrometheus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = s.pool.Metrics().WritePrometheus(w)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleIdentify detects the format and encryption shape without attempting any
// password (no candidate source), so encrypted nodes come back "locked".
func (s *Server) handleIdentify(w http.ResponseWriter, r *http.Request) {
	data, _, ok := s.readRequest(w, r, false)
	if !ok {
		return
	}
	s.run(w, r, data, nil)
}

// handleDecrypt runs the full search with the request's candidates.
func (s *Server) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	data, src, ok := s.readRequest(w, r, true)
	if !ok {
		return
	}
	s.run(w, r, data, src)
}

// run processes already-read file data with an already-built candidate source.
func (s *Server) run(w http.ResponseWriter, r *http.Request, data []byte, src xcrack.CandidateSource) {
	timeout := s.cfg.RequestTimeout
	// A client (e.g. the distributed orchestrator) may request a shorter
	// per-request deadline so a slow stripe does not hold a server; never longer
	// than the operator's configured bound.
	if v := requestParam(r, "max-duration"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 && d < timeout {
			timeout = d
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	start := time.Now()
	res, err := s.pool.Process(ctx, bytes.NewReader(data), int64(len(data)), src)
	if err != nil {
		if ctx.Err() != nil {
			writeError(w, http.StatusGatewayTimeout, "processing deadline exceeded")
			return
		}
		writeError(w, http.StatusInternalServerError, "processing failed")
		return
	}
	defer res.Close()

	if s.cfg.Audit != nil {
		s.cfg.Audit(res, AuditMeta{
			RemoteAddr: r.RemoteAddr,
			Endpoint:   r.URL.Path,
			Bytes:      len(data),
			Elapsed:    time.Since(start),
		})
	}

	writeJSON(w, http.StatusOK, xcrack.BuildReport(res))
}

// readRequest extracts the file to analyze and (when wantCandidates) the
// candidate source. Two request shapes are accepted:
//
//   - application/octet-stream (default): the raw file is the body; candidates
//     come from the query string (?password=, ?defaults=true, ?shard=I/N).
//   - multipart/form-data: a "file" part carries the archive and an optional
//     "wordlist" part carries newline-delimited candidates, so an orchestrator
//     can ship a large keyspace stripe in one request. Form values password,
//     defaults and shard behave as their query-string counterparts.
//
// It writes the error response and returns ok=false on any problem.
func (s *Server) readRequest(w http.ResponseWriter, r *http.Request, wantCandidates bool) (data []byte, src xcrack.CandidateSource, ok bool) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return nil, nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)

	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm(8 << 20); err != nil {
			if tooLarge(err) {
				writeError(w, http.StatusRequestEntityTooLarge, "request exceeds the configured limit")
				return nil, nil, false
			}
			writeError(w, http.StatusBadRequest, "could not parse multipart request")
			return nil, nil, false
		}
		f, _, ferr := r.FormFile("file")
		if ferr != nil {
			writeError(w, http.StatusBadRequest, "multipart request missing a 'file' part")
			return nil, nil, false
		}
		defer f.Close()
		d, rerr := io.ReadAll(f)
		if rerr != nil {
			writeError(w, http.StatusBadRequest, "could not read the 'file' part")
			return nil, nil, false
		}
		data = d
		if wantCandidates {
			src, ok = s.multipartCandidates(w, r)
			if !ok {
				return nil, nil, false
			}
		}
	} else {
		d, rerr := io.ReadAll(r.Body)
		if rerr != nil {
			if tooLarge(rerr) {
				writeError(w, http.StatusRequestEntityTooLarge, "request body exceeds the configured limit")
				return nil, nil, false
			}
			writeError(w, http.StatusBadRequest, "could not read request body")
			return nil, nil, false
		}
		data = d
		if wantCandidates {
			s2, err := s.queryCandidates(r)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return nil, nil, false
			}
			src = s2
		}
	}
	if len(data) == 0 {
		writeError(w, http.StatusBadRequest, "empty file")
		return nil, nil, false
	}
	return data, src, true
}

// queryCandidates builds the candidate source from the query string (the
// octet-stream request shape).
func (s *Server) queryCandidates(r *http.Request) (xcrack.CandidateSource, error) {
	q := r.URL.Query()
	pws := q["password"]
	if len(pws) > s.cfg.MaxPasswords {
		return nil, errors.New("too many password candidates")
	}
	var src xcrack.CandidateSource
	if len(pws) > 0 {
		src = candidates.Explicit(pws...)
	}
	src, err := s.appendDefaults(src, q.Get("defaults") == "true")
	if err != nil {
		return nil, err
	}
	return s.applyShard(src, q.Get("shard"))
}

// multipartCandidates builds the candidate source from a multipart request: the
// explicit password form values plus the newline-delimited "wordlist" part.
func (s *Server) multipartCandidates(w http.ResponseWriter, r *http.Request) (xcrack.CandidateSource, bool) {
	var parts []candidates.Source
	if pws := r.MultipartForm.Value["password"]; len(pws) > 0 {
		if len(pws) > s.cfg.MaxPasswords {
			writeError(w, http.StatusBadRequest, "too many password candidates")
			return nil, false
		}
		parts = append(parts, candidates.Explicit(pws...))
	}
	if fhs := r.MultipartForm.File["wordlist"]; len(fhs) > 0 {
		wf, err := fhs[0].Open()
		if err != nil {
			writeError(w, http.StatusBadRequest, "could not read the 'wordlist' part")
			return nil, false
		}
		defer wf.Close()
		var words [][]byte
		sc := bufio.NewScanner(wf)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r")
			words = append(words, []byte(line))
		}
		if err := sc.Err(); err != nil {
			writeError(w, http.StatusBadRequest, "could not read the 'wordlist' part")
			return nil, false
		}
		if len(words) > 0 {
			parts = append(parts, candidates.Bytes(words...))
		}
	}
	var src xcrack.CandidateSource
	if len(parts) == 1 {
		src = parts[0]
	} else if len(parts) > 1 {
		src = candidates.Chain(parts...)
	}
	src, err := s.appendDefaults(src, r.FormValue("defaults") == "true")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return nil, false
	}
	src, err = s.applyShard(src, r.FormValue("shard"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return nil, false
	}
	return src, true
}

// appendDefaults optionally appends the operator-gated embedded default list.
func (s *Server) appendDefaults(src xcrack.CandidateSource, want bool) (xcrack.CandidateSource, error) {
	if !want {
		return src, nil
	}
	if !s.cfg.AllowDefaultList {
		return nil, errors.New("the default wordlist is not enabled on this server")
	}
	if src == nil {
		return candidates.DefaultList(), nil
	}
	return candidates.Chain(src, candidates.DefaultList()), nil
}

// applyShard restricts src to a 1/N stride of the keyspace when a well-formed
// "I/N" shard spec is given, so several servers can split one keyspace.
func (s *Server) applyShard(src xcrack.CandidateSource, spec string) (xcrack.CandidateSource, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || src == nil {
		return src, nil
	}
	i, n, ok := parseShardSpec(spec)
	if !ok {
		return nil, errors.New("invalid shard spec (want I/N)")
	}
	return candidates.Shard(src, i, n), nil
}

// parseShardSpec parses "I/N" into a zero-based index and count.
func parseShardSpec(spec string) (index, count int, ok bool) {
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	i, ierr := strconv.Atoi(strings.TrimSpace(parts[0]))
	n, nerr := strconv.Atoi(strings.TrimSpace(parts[1]))
	if ierr != nil || nerr != nil || n < 1 || i < 0 || i >= n {
		return 0, 0, false
	}
	return i, n, true
}

// requestParam returns a value from the query string or, for a parsed multipart
// request, the form values.
func requestParam(r *http.Request, name string) string {
	if v := r.URL.Query().Get(name); v != "" {
		return v
	}
	if r.MultipartForm != nil {
		if vs := r.MultipartForm.Value[name]; len(vs) > 0 {
			return vs[0]
		}
	}
	return ""
}

func tooLarge(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
