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
// operator MUST place authentication/authorization and TLS in front of this
// service; it ships neither. Passwords are never logged.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
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
	s.process(w, r, nil)
}

// handleDecrypt runs the full search with the request's candidates.
func (s *Server) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	src, err := s.candidates(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.process(w, r, src)
}

func (s *Server) process(w http.ResponseWriter, r *http.Request, src xcrack.CandidateSource) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body := http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	data, err := io.ReadAll(body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body exceeds the configured limit")
			return
		}
		writeError(w, http.StatusBadRequest, "could not read request body")
		return
	}
	if len(data) == 0 {
		writeError(w, http.StatusBadRequest, "empty request body")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.RequestTimeout)
	defer cancel()

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

	writeJSON(w, http.StatusOK, xcrack.BuildReport(res))
}

// candidates builds the candidate source from the request query. It never reads
// server-side files; candidates come only from the request (explicit passwords)
// plus, when the operator enabled it, the embedded default list.
func (s *Server) candidates(r *http.Request) (xcrack.CandidateSource, error) {
	q := r.URL.Query()
	pws := q["password"]
	if len(pws) > s.cfg.MaxPasswords {
		return nil, errors.New("too many password candidates")
	}
	var src xcrack.CandidateSource
	if len(pws) > 0 {
		src = candidates.Explicit(pws...)
	}
	if q.Get("defaults") == "true" {
		if !s.cfg.AllowDefaultList {
			return nil, errors.New("the default wordlist is not enabled on this server")
		}
		if src == nil {
			src = candidates.DefaultList()
		} else {
			src = candidates.Chain(src, candidates.DefaultList())
		}
	}
	return src, nil
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
