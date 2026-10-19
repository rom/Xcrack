package webui

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

type serverHealth struct {
	URL       string `json:"url"`
	OK        bool   `json:"ok"`
	Status    int    `json:"status,omitempty"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

// handleClusterHealth pings the health endpoint of each given xcrackd /
// xcrack-web server URL and reports reachability + latency. Like distributed
// cracking it makes the server connect out to operator-supplied URLs, so it is
// gated behind AllowServerPaths (a trusted local instance). Redirects are not
// followed, and only a fixed GET /api/v1/healthz path is requested.
func (s *Server) handleClusterHealth(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.AllowServerPaths {
		writeErr(w, http.StatusForbidden, "cluster health check requires --allow-server-paths (trusted local instance)")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeErr(w, http.StatusBadRequest, "could not parse request")
		return
	}
	servers := splitList(r.FormValue("servers"))
	if len(servers) == 0 {
		writeErr(w, http.StatusBadRequest, "no server URLs given")
		return
	}
	if len(servers) > 64 {
		servers = servers[:64]
	}
	client := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	out := make([]serverHealth, len(servers))
	var wg sync.WaitGroup
	for i, raw := range servers {
		wg.Add(1)
		go func(i int, base string) {
			defer wg.Done()
			h := serverHealth{URL: base}
			// A server entry may be "url" or "url@group"; keep just the URL.
			if at := strings.IndexByte(base, '@'); at > 0 && strings.Contains(base[:at], "://") {
				base = base[:at]
			}
			start := time.Now()
			resp, err := client.Get(strings.TrimRight(base, "/") + "/api/v1/healthz")
			h.LatencyMS = time.Since(start).Milliseconds()
			if err != nil {
				h.Error = err.Error()
				out[i] = h
				return
			}
			resp.Body.Close()
			h.Status = resp.StatusCode
			h.OK = resp.StatusCode == http.StatusOK
			out[i] = h
		}(i, raw)
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, map[string]any{"servers": out})
}
