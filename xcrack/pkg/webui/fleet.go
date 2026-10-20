package webui

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The fleet is the managed set of xcrackd / xcrack-web worker nodes a distributed
// crack can fan out to. Rather than retyping node URLs into every job's cluster
// block, an operator saves the fleet once (server-wide, persisted under the work
// directory) and the Fleet tab shows each node's live health — reachability,
// latency, and (for an xcrack-web node) its version and GPU tier — then applies
// the list to a job. Like distributed cracking itself and the cluster health
// check, every outbound probe is gated behind AllowServerPaths (a trusted local
// instance) and only ever requests fixed, safe paths.

// fleetNode is one saved worker node.
type fleetNode struct {
	URL   string `json:"url"`
	Group string `json:"group,omitempty"` // optional partition/group label (url@group)
	Label string `json:"label,omitempty"` // optional human name
}

// fleetStore persists the node list as JSON under the work directory. All methods
// are safe for concurrent use.
type fleetStore struct {
	mu   sync.Mutex
	path string
}

func newFleetStore(workDir string) *fleetStore {
	return &fleetStore{path: filepath.Join(workDir, "fleet.json")}
}

func (f *fleetStore) load() []fleetNode {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := os.ReadFile(f.path)
	if err != nil {
		return []fleetNode{}
	}
	var nodes []fleetNode
	if json.Unmarshal(data, &nodes) != nil {
		return []fleetNode{}
	}
	return nodes
}

func (f *fleetStore) save(nodes []fleetNode) error {
	data, err := json.MarshalIndent(nodes, "", "  ")
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

// nodeHealth is a node's probed state.
type nodeHealth struct {
	URL       string `json:"url"`
	Group     string `json:"group,omitempty"`
	Label     string `json:"label,omitempty"`
	OK        bool   `json:"ok"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Version   string `json:"version,omitempty"`
	GPU       bool   `json:"gpu,omitempty"`
	Error     string `json:"error,omitempty"`
}

// handleFleetGet returns the saved fleet (any authenticated user may read it).
func (s *Server) handleFleetGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes":             s.fleet.load(),
		"distributed_ready": s.cfg.AllowServerPaths,
	})
}

// handleFleetPut replaces the saved fleet. It changes operational outreach
// config, so it requires AllowServerPaths and (in multi-user mode) an admin.
func (s *Server) handleFleetPut(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.AllowServerPaths {
		writeErr(w, http.StatusForbidden, "managing a fleet requires --allow-server-paths (trusted local instance)")
		return
	}
	if u, _ := s.currentUser(r); s.auth.enabled && !u.Admin {
		writeErr(w, http.StatusForbidden, "admin only")
		return
	}
	var body struct {
		Nodes []fleetNode `json:"nodes"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	// Keep only well-formed http(s) node URLs, de-duplicated, capped.
	seen := map[string]bool{}
	clean := make([]fleetNode, 0, len(body.Nodes))
	for _, n := range body.Nodes {
		n.URL = strings.TrimSpace(n.URL)
		if !strings.HasPrefix(n.URL, "http://") && !strings.HasPrefix(n.URL, "https://") {
			continue
		}
		if seen[n.URL] {
			continue
		}
		seen[n.URL] = true
		n.Group = strings.TrimSpace(n.Group)
		n.Label = strings.TrimSpace(n.Label)
		clean = append(clean, n)
		if len(clean) >= 64 {
			break
		}
	}
	if err := s.fleet.save(clean); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not save the fleet")
		return
	}
	s.audit(r, "fleet.save", "", intWord(len(clean))+" node(s)")
	writeJSON(w, http.StatusOK, map[string]any{"nodes": clean})
}

// handleFleetHealth probes every saved node and reports its live state. It makes
// the server connect out, so it is gated behind AllowServerPaths exactly like the
// cluster health check.
func (s *Server) handleFleetHealth(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.AllowServerPaths {
		writeErr(w, http.StatusForbidden, "probing a fleet requires --allow-server-paths (trusted local instance)")
		return
	}
	nodes := s.fleet.load()
	client := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	out := make([]nodeHealth, len(nodes))
	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Add(1)
		go func(i int, n fleetNode) {
			defer wg.Done()
			out[i] = probeNode(client, n)
		}(i, n)
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, map[string]any{"nodes": out})
}

// probeNode reports a node's reachability, latency and (for an xcrack-web node)
// version + GPU tier. It asks the node's open /meta first (which carries version
// and GPU), falling back to /healthz for a plain xcrackd node that has no meta.
func probeNode(client *http.Client, n fleetNode) nodeHealth {
	h := nodeHealth{URL: n.URL, Group: n.Group, Label: n.Label}
	base := strings.TrimRight(n.URL, "/")
	start := time.Now()
	resp, err := client.Get(base + "/api/v1/meta")
	h.LatencyMS = time.Since(start).Milliseconds()
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var m struct {
				Version string `json:"version"`
				GPU     bool   `json:"gpu_available"`
			}
			_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&m)
			h.OK = true
			h.Version = m.Version
			h.GPU = m.GPU
			return h
		}
	}
	// Fall back to the universal healthz probe (xcrackd, or a gated meta).
	start = time.Now()
	resp2, err2 := client.Get(base + "/api/v1/healthz")
	h.LatencyMS = time.Since(start).Milliseconds()
	if err2 != nil {
		h.Error = err2.Error()
		return h
	}
	resp2.Body.Close()
	h.OK = resp2.StatusCode == http.StatusOK
	if !h.OK {
		h.Error = resp2.Status
	}
	return h
}

func intWord(n int) string {
	// small helper to avoid importing strconv just for an audit detail
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
