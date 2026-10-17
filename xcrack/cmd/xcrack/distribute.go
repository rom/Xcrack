package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rom/xcrack/pkg/cluster"
	"github.com/rom/xcrypto/candidates"
)

// clusterSession persists, per file, the number of candidates a distributed run
// has confirmed tried (the contiguous completed prefix reported as
// Progress.Tried), so an interrupted fleet run resumes without re-trying that
// work. Writes are throttled; the final state is flushed at the end.
type clusterSession struct {
	path string
	mu   sync.Mutex
	done map[string]int64
	last time.Time
}

func loadClusterSession(path string) *clusterSession {
	s := &clusterSession{path: path, done: map[string]int64{}}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &s.done)
	}
	return s
}

// offsets returns a copy of the recorded per-file tried counts for ResumeOffsets.
func (s *clusterSession) offsets() map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int64, len(s.done))
	for k, v := range s.done {
		out[k] = v
	}
	return out
}

// record keeps the maximum tried count per file and persists at most every ~2s.
func (s *clusterSession) record(path string, tried int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tried > s.done[path] {
		s.done[path] = tried
	}
	if time.Since(s.last) > 2*time.Second {
		s.persistLocked()
		s.last = time.Now()
	}
}

func (s *clusterSession) flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persistLocked()
}

func (s *clusterSession) persistLocked() {
	data, err := json.MarshalIndent(s.done, "", "  ")
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil {
		_ = os.Rename(tmp, s.path)
	}
}

// parseServerSpec parses a --server value of the form "URL" or "URL@GROUP".
func parseServerSpec(spec string) cluster.Server {
	spec = strings.TrimSpace(spec)
	if at := strings.LastIndex(spec, "@"); at > 0 && !strings.Contains(spec[at:], "/") {
		return cluster.Server{URL: spec[:at], Group: spec[at+1:]}
	}
	return cluster.Server{URL: spec}
}

// buildCluster merges --server flags and the config's cluster block into a
// server list plus the orchestrator options. ok is false (with no servers) when
// distributed mode was not requested.
func buildCluster(serverFlags []string, mode string, batch int, allowDefaults bool, perRequest string, cfg *fileConfig) ([]cluster.Server, cluster.Options, bool, error) {
	var servers []cluster.Server
	for _, s := range serverFlags {
		if strings.TrimSpace(s) != "" {
			servers = append(servers, parseServerSpec(s))
		}
	}
	if cfg != nil {
		for _, cs := range cfg.Cluster.Servers {
			if strings.TrimSpace(cs.URL) != "" {
				servers = append(servers, cluster.Server{URL: cs.URL, Group: cs.Group})
			}
		}
	}
	if len(servers) == 0 {
		return nil, cluster.Options{}, false, nil
	}

	if mode == "" && cfg != nil {
		mode = cfg.Cluster.Mode
	}
	var m cluster.Mode
	switch strings.ToLower(mode) {
	case "", "collective":
		m = cluster.Collective
	case "partition":
		m = cluster.Partition
	default:
		return nil, cluster.Options{}, false, fmt.Errorf("unknown cluster mode %q (collective|partition)", mode)
	}

	if batch == 0 && cfg != nil {
		batch = cfg.Cluster.Batch
	}
	if !allowDefaults && cfg != nil {
		allowDefaults = cfg.Cluster.AllowDefaults
	}
	var per time.Duration
	if perRequest != "" {
		d, err := time.ParseDuration(perRequest)
		if err != nil {
			return nil, cluster.Options{}, false, fmt.Errorf("--cluster-per-request: %v", err)
		}
		per = d
	} else if cfg != nil && cfg.Cluster.PerRequest != "" {
		if d, err := time.ParseDuration(cfg.Cluster.PerRequest); err == nil {
			per = d
		}
	}

	return servers, cluster.Options{
		Mode:          m,
		BatchSize:     batch,
		AllowDefaults: allowDefaults,
		PerRequest:    per,
	}, true, nil
}

// runDistributed cracks every file by fanning candidate batches out to the
// configured xcrackd fleet, then renders the per-file outcome. It returns the
// process exit code (0 any decrypted, 1 all locked, 2 on error).
func runDistributed(files []string, servers []cluster.Server, opts cluster.Options, build func(path string) candidates.Source, pot *potfile, sessionPath string) int {
	jobs := make([]cluster.FileJob, 0, len(files))
	ok := true
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "xcrack: %s: %v\n", path, err)
			ok = false
			continue
		}
		p := path
		jobs = append(jobs, cluster.FileJob{
			Path: filepath.Base(path),
			Data: data,
			Candidates: func() candidates.Source {
				return build(p)
			},
		})
	}
	if len(jobs) == 0 {
		return 2
	}

	// Distributed resume: seed ResumeOffsets from a prior run's persisted progress
	// and keep persisting the confirmed-tried offset per file, so an interrupted
	// fleet run skips the candidates already covered (cross-run dedup).
	var csess *clusterSession
	if sessionPath != "" {
		csess = loadClusterSession(sessionPath)
		opts.ResumeOffsets = csess.offsets()
		opts.OnProgress = func(pr cluster.Progress) { csess.record(pr.Path, pr.Tried) }
	}

	fmt.Fprintf(os.Stderr, "xcrack: distributing %d file(s) across %d server(s) [%s]\n",
		len(jobs), len(servers), modeName(opts.Mode))
	results := cluster.Run(context.Background(), servers, jobs, opts)
	if csess != nil {
		csess.flush()
	}

	anyDecrypted, anyLocked := false, false
	for _, r := range results {
		switch {
		case r.Err != nil:
			fmt.Printf("%s  [error: %v]\n", r.Path, r.Err)
			ok = false
		case r.Found:
			fmt.Printf("%s  [decrypted password=%q]\n", r.Path, r.Password)
			anyDecrypted = true
			if pot != nil {
				pot.add(r.Password)
			}
		default:
			fmt.Printf("%s  [locked]\n", r.Path)
			anyLocked = true
		}
	}
	switch {
	case !ok:
		return 2
	case anyDecrypted:
		return 0
	case anyLocked:
		return 1
	default:
		return 0
	}
}

func modeName(m cluster.Mode) string {
	if m == cluster.Partition {
		return "partition"
	}
	return "collective"
}
