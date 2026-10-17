package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rom/xcrack/pkg/cluster"
	"github.com/rom/xcrypto/candidates"
)

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
func runDistributed(files []string, servers []cluster.Server, opts cluster.Options, build func(path string) candidates.Source, pot *potfile) int {
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

	fmt.Fprintf(os.Stderr, "xcrack: distributing %d file(s) across %d server(s) [%s]\n",
		len(jobs), len(servers), modeName(opts.Mode))
	results := cluster.Run(context.Background(), servers, jobs, opts)

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
