package webui

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
)

// The audit trail records who did what, when, and from where — the access/action
// log a shared forensic tool needs, distinct from the per-result crack logging
// in pkg/auditlog. Entries are appended as JSON lines to <workdir>/audit.jsonl
// (so they survive a restart) and, when the operator configured one, mirrored to
// an external slog sink (file/syslog) via Config.AuditLogger. It deliberately
// never stores recovered secrets: a "found" entry records the target and scheme,
// not the password. An admin reads the recent trail at GET /api/v1/audit.

// auditEntry is one action record.
type auditEntry struct {
	Time   int64  `json:"time"` // unix ms
	Actor  string `json:"actor"`
	Email  string `json:"email,omitempty"`
	IP     string `json:"ip,omitempty"`
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// auditTrail appends entries to a JSONL file under the work directory and,
// optionally, to an external slog sink. All methods are safe for concurrent use
// and best-effort: an audit write never fails a request.
type auditTrail struct {
	mu   sync.Mutex
	path string
	sink *slog.Logger
}

const maxAuditReturn = 500

func newAuditTrail(workDir string, sink *slog.Logger) *auditTrail {
	return &auditTrail{path: filepath.Join(workDir, "audit.jsonl"), sink: sink}
}

func (a *auditTrail) record(e auditEntry) {
	if a == nil {
		return
	}
	if e.Time == 0 {
		e.Time = nowMS()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	a.mu.Lock()
	if f, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		_, _ = f.Write(append(b, '\n'))
		_ = f.Close()
	}
	a.mu.Unlock()
	if a.sink != nil {
		a.sink.Info("audit",
			"actor", e.Actor, "email", e.Email, "ip", e.IP,
			"action", e.Action, "target", e.Target, "detail", e.Detail)
	}
}

// tail returns the most recent n entries, newest first. It reads the whole file
// (bounded in practice by retention/rotation) and keeps only the last n lines.
func (a *auditTrail) tail(n int) []auditEntry {
	if a == nil || n <= 0 {
		return nil
	}
	a.mu.Lock()
	f, err := os.Open(a.path)
	a.mu.Unlock()
	if err != nil {
		return nil
	}
	defer f.Close()
	// Ring buffer of the last n raw lines.
	ring := make([]string, 0, n)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		if len(ring) < n {
			ring = append(ring, line)
		} else {
			copy(ring, ring[1:])
			ring[n-1] = line
		}
	}
	out := make([]auditEntry, 0, len(ring))
	for i := len(ring) - 1; i >= 0; i-- { // newest first
		var e auditEntry
		if json.Unmarshal([]byte(ring[i]), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

// audit records an action for the request's user. actor/ip are resolved from the
// request; it is a no-op when no trail is configured.
func (s *Server) audit(r *http.Request, action, target, detail string) {
	if s.trail == nil {
		return
	}
	u, _ := s.currentUser(r)
	actor := u.Subject
	if actor == "" {
		actor = u.Name // "local" in single-user mode
	}
	s.trail.record(auditEntry{
		Actor: actor, Email: u.Email, IP: clientIP(r, s.cfg.TrustProxyHeaders),
		Action: action, Target: target, Detail: detail,
	})
}

// handleAudit returns the recent audit trail. It is admin-only (every request is
// the implicit admin in single-user mode).
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if u, _ := s.currentUser(r); s.auth.enabled && !u.Admin {
		writeErr(w, http.StatusForbidden, "admin only")
		return
	}
	n := maxAuditReturn
	if s.trail == nil {
		writeJSON(w, http.StatusOK, map[string]any{"entries": []auditEntry{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": s.trail.tail(n)})
}
