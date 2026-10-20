// Package webui serves the Xcrack recovery engine as a browser application: a
// single-page GUI plus a JSON/SSE API that exposes the full engine feature set.
// It backs the xcrack-web binary, which can run locally (bound to localhost) or
// as a shared service.
//
// Every recovery job is described by a jobspec.Spec — the same YAML model the
// CLI's --config consumes — so whatever the GUI (or its advanced-mode YAML
// editor) can express is assembled by exactly the same engine wiring as the CLI.
//
// Security posture: like xcrackd, this package ships no authentication. A
// localhost instance is a single-user console; a shared instance MUST sit behind
// authentication and (unless xcrack-web's own TLS is enabled) transport
// security. A submitted spec may reference only files uploaded with the job
// unless Config.AllowServerPaths is set.
package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// Server is the HTTP application: the SPA assets plus the JSON/SSE API.
type Server struct {
	cfg         Config
	mgr         *Manager
	auth        *authenticator
	mux         *http.ServeMux
	handler     http.Handler // mux wrapped in the CSRF + rate-limit middleware
	limiter     *rateLimiter
	authLimiter *rateLimiter
	trail       *auditTrail
}

// NewServer builds the web application. It fails if the work directory cannot be
// created, the embedded assets cannot be opened, or (when Config.Auth.Enabled)
// OIDC discovery against the configured issuer fails.
func NewServer(cfg Config) (*Server, error) {
	cfg.applyDefaults()
	mgr, err := NewManager(cfg)
	if err != nil {
		return nil, err
	}
	auth, err := newAuthenticator(context.Background(), cfg.Auth)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, mgr: mgr, auth: auth}
	if cfg.RateLimitPerMin > 0 {
		s.limiter = newRateLimiter(cfg.RateLimitPerMin, time.Minute)
	}
	if cfg.AuthRateLimitPerMin > 0 {
		s.authLimiter = newRateLimiter(cfg.AuthRateLimitPerMin, time.Minute)
	}
	s.trail = newAuditTrail(cfg.WorkDir, cfg.AuditLogger)
	mgr.trail = s.trail
	assets, err := assetHandler()
	if err != nil {
		return nil, err
	}
	// p gates a route behind a valid session when auth is enabled (no-op otherwise).
	p := s.protected
	mux := http.NewServeMux()
	// Open endpoints: health, capabilities, who-am-I, and the OIDC flow.
	mux.HandleFunc("GET /api/v1/healthz", s.handleHealth)
	mux.HandleFunc("GET /api/v1/meta", s.handleMeta)
	mux.HandleFunc("GET /api/v1/me", s.handleMe)
	mux.HandleFunc("GET /auth/login", s.handleLogin)
	mux.HandleFunc("GET /auth/callback", s.handleCallback)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
	// Data + tool endpoints: gated when auth is on.
	mux.HandleFunc("POST /api/v1/config/validate", p(s.handleValidate))
	mux.HandleFunc("POST /api/v1/config/format", p(s.handleFormat))
	mux.HandleFunc("POST /api/v1/identify", p(s.handleIdentify))
	mux.HandleFunc("POST /api/v1/inspect", p(s.handleInspect))
	mux.HandleFunc("POST /api/v1/jobs", p(s.handleCreateJob))
	mux.HandleFunc("GET /api/v1/jobs", p(s.handleListJobs))
	mux.HandleFunc("GET /api/v1/jobs/{id}", p(s.handleGetJob))
	mux.HandleFunc("DELETE /api/v1/jobs/{id}", p(s.handleDeleteJob))
	mux.HandleFunc("GET /api/v1/jobs/{id}/events", p(s.handleJobEvents))
	mux.HandleFunc("POST /api/v1/jobs/{id}/cancel", p(s.handleCancelJob))
	mux.HandleFunc("POST /api/v1/jobs/{id}/rerun", p(s.handleRerun))
	mux.HandleFunc("GET /api/v1/jobs/{id}/download", p(s.handleDownload))
	mux.HandleFunc("GET /api/v1/stats", p(s.handleStats))
	mux.HandleFunc("GET /api/v1/audit", p(s.handleAudit))
	mux.HandleFunc("GET /api/v1/vault", p(s.handleVault))
	mux.HandleFunc("GET /api/v1/library", p(s.handleLibraryList))
	mux.HandleFunc("POST /api/v1/library", p(s.handleLibraryUpload))
	mux.HandleFunc("GET /api/v1/library/{name}/preview", p(s.handleLibraryPreview))
	mux.HandleFunc("DELETE /api/v1/library/{name}", p(s.handleLibraryDelete))
	mux.HandleFunc("POST /api/v1/cluster/health", p(s.handleClusterHealth))
	mux.HandleFunc("GET /api/v1/docs", p(s.handleListDocs))
	mux.HandleFunc("GET /api/v1/docs/{name}", p(s.handleGetDoc))
	// Specialist, non-cracking tools (the CLI's subcommands), synchronous.
	mux.HandleFunc("POST /api/v1/tools/hashline", p(s.handleToolHashline))
	mux.HandleFunc("POST /api/v1/tools/vba-recover", p(s.handleToolVBA))
	mux.HandleFunc("POST /api/v1/tools/access-recover", p(s.handleToolAccess))
	mux.HandleFunc("POST /api/v1/tools/export-challenge", p(s.handleToolExportChallenge))
	mux.HandleFunc("POST /api/v1/tools/wordlist", p(s.handleToolWordlist))
	mux.HandleFunc("POST /api/v1/tools/rule-test", p(s.handleToolRuleTest))
	mux.HandleFunc("POST /api/v1/tools/pdf-keyattack-table", p(s.handleToolPDFKeyTable))
	mux.Handle("/", assets)
	s.mux = mux
	// Wrap the whole application in transport hardening: CSRF guard innermost
	// (so rejected requests never reach a handler), rate limiter outermost.
	s.handler = s.rateLimit(s.csrf(mux))
	return s, nil
}

// Handler returns the HTTP handler for the whole application.
func (s *Server) Handler() http.Handler { return s.handler }

// Close cancels any in-flight jobs and waits for their runner goroutines to
// exit. After it returns, nothing is still touching the work directory, so a
// caller shutting the server down (or a test that owns a temporary work
// directory) can clean up without racing a runner.
func (s *Server) Close() { s.mgr.Shutdown() }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
