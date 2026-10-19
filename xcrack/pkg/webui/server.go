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
	"encoding/json"
	"net/http"
)

// Server is the HTTP application: the SPA assets plus the JSON/SSE API.
type Server struct {
	cfg Config
	mgr *Manager
	mux *http.ServeMux
}

// NewServer builds the web application. It fails only if the work directory
// cannot be created or the embedded assets cannot be opened.
func NewServer(cfg Config) (*Server, error) {
	cfg.applyDefaults()
	mgr, err := NewManager(cfg)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, mgr: mgr}
	assets, err := assetHandler()
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/healthz", s.handleHealth)
	mux.HandleFunc("GET /api/v1/meta", s.handleMeta)
	mux.HandleFunc("POST /api/v1/config/validate", s.handleValidate)
	mux.HandleFunc("POST /api/v1/config/format", s.handleFormat)
	mux.HandleFunc("POST /api/v1/identify", s.handleIdentify)
	mux.HandleFunc("POST /api/v1/jobs", s.handleCreateJob)
	mux.HandleFunc("GET /api/v1/jobs", s.handleListJobs)
	mux.HandleFunc("GET /api/v1/jobs/{id}", s.handleGetJob)
	mux.HandleFunc("DELETE /api/v1/jobs/{id}", s.handleDeleteJob)
	mux.HandleFunc("GET /api/v1/jobs/{id}/events", s.handleJobEvents)
	mux.HandleFunc("POST /api/v1/jobs/{id}/cancel", s.handleCancelJob)
	mux.HandleFunc("GET /api/v1/jobs/{id}/download", s.handleDownload)
	mux.HandleFunc("GET /api/v1/stats", s.handleStats)
	mux.HandleFunc("GET /api/v1/docs", s.handleListDocs)
	mux.HandleFunc("GET /api/v1/docs/{name}", s.handleGetDoc)
	// Specialist, non-cracking tools (the CLI's subcommands), synchronous.
	mux.HandleFunc("POST /api/v1/tools/hashline", s.handleToolHashline)
	mux.HandleFunc("POST /api/v1/tools/vba-recover", s.handleToolVBA)
	mux.HandleFunc("POST /api/v1/tools/access-recover", s.handleToolAccess)
	mux.HandleFunc("POST /api/v1/tools/export-challenge", s.handleToolExportChallenge)
	mux.HandleFunc("POST /api/v1/tools/wordlist", s.handleToolWordlist)
	mux.HandleFunc("POST /api/v1/tools/pdf-keyattack-table", s.handleToolPDFKeyTable)
	mux.Handle("/", assets)
	s.mux = mux
	return s, nil
}

// Handler returns the HTTP handler for the whole application.
func (s *Server) Handler() http.Handler { return s.mux }

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
