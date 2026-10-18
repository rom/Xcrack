package webui

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rom/xcrack/pkg/cluster"
	"github.com/rom/xcrack/pkg/jobspec"
	"github.com/rom/xcrypto/candidates"
)

// runDistributed fans the job out to the xcrackd servers named in the spec's
// cluster block, instead of cracking locally. It is reached only when the spec
// has servers AND the operator allowed it (AllowServerPaths), since it makes the
// server connect out to the configured endpoints. Each file's candidate source
// is wrapped in the progress recorder so the UI still shows throughput and the
// latest term shipped.
func (m *Manager) runDistributed(ctx context.Context, j *Job, spec *jobspec.Spec, asm *jobspec.Assembler, names, paths []string, ps *progressState, found *int64) []FileResult {
	servers := make([]cluster.Server, 0, len(spec.Cluster.Servers))
	for _, s := range spec.Cluster.Servers {
		servers = append(servers, cluster.Server{URL: s.URL, Group: s.Group})
	}
	mode := cluster.Collective
	if strings.EqualFold(spec.Cluster.Mode, "partition") {
		mode = cluster.Partition
	}
	var perReq time.Duration
	if spec.Cluster.PerRequest != "" {
		if d, err := time.ParseDuration(spec.Cluster.PerRequest); err == nil {
			perReq = d
		}
	}
	client, err := clusterHTTPClient(spec)
	if err != nil {
		j.fail(fmt.Sprintf("cluster TLS: %v", err))
		return nil
	}

	results := make([]FileResult, len(names))
	jobs := make([]cluster.FileJob, 0, len(names))
	ok := true
	for i := range names {
		data, rerr := os.ReadFile(paths[i])
		if rerr != nil {
			results[i] = FileResult{Name: names[i], Error: fmt.Sprintf("read: %v", rerr)}
			ok = false
			continue
		}
		name := names[i]
		jobs = append(jobs, cluster.FileJob{
			Path: name,
			Data: data,
			Candidates: func() candidates.Source {
				return &recorder{src: asm.Candidates(name), ps: ps}
			},
		})
	}
	if len(jobs) == 0 {
		return results
	}

	j.emit(Event{Type: "log", Level: "info", Message: fmt.Sprintf("distributing to %d server(s) in %s mode", len(servers), spec.Cluster.Mode)})
	out := cluster.Run(ctx, servers, jobs, cluster.Options{
		Mode:          mode,
		BatchSize:     spec.Cluster.Batch,
		PerRequest:    perReq,
		AllowDefaults: spec.Cluster.AllowDefaults,
		MaxCandidates: spec.Limits.MaxCandidates,
		Client:        client,
		OnProgress: func(p cluster.Progress) {
			j.emit(Event{Type: "log", Level: "info", Message: fmt.Sprintf("%s: %s shipped %d candidates", p.Path, p.Server, p.Tried)})
		},
	})

	// Map cluster results back onto job file order; names were appended in order
	// for the files that read successfully.
	oi := 0
	for i := range names {
		if results[i].Error != "" { // a read failure recorded above
			continue
		}
		r := out[oi]
		oi++
		fr := FileResult{Name: names[i]}
		if r.Err != nil {
			fr.Error = r.Err.Error()
			ok = false
		}
		if r.Report != nil {
			rep := *r.Report
			fr.Report = &rep
		}
		if r.Found {
			atomic.AddInt64(found, 1)
			ev := Event{Type: "found", File: names[i]}
			if m.cfg.ExposeSecrets {
				ev.Password = r.Password
			}
			j.emit(ev)
		}
		results[i] = fr
		j.mu.Lock()
		j.FilesDone++
		done, total := j.FilesDone, j.FilesTotal
		j.mu.Unlock()
		j.emit(Event{Type: "file_done", File: names[i], FilesDone: done, FilesTotal: total})
	}
	_ = ok
	return results
}

// clusterHTTPClient builds the HTTP client used to reach the xcrackd servers,
// honouring the spec's cluster TLS settings (private CA, client cert for mutual
// TLS, SNI override, and the insecure testing escape hatch). It returns nil
// (the orchestrator's default client) when no TLS options are set.
func clusterHTTPClient(spec *jobspec.Spec) (*http.Client, error) {
	t := spec.Cluster.TLS
	if t.CA == "" && t.Cert == "" && t.Key == "" && t.ServerName == "" && !t.Insecure {
		return nil, nil
	}
	conf := &tls.Config{MinVersion: tls.VersionTLS12}
	if t.CA != "" {
		pem, err := os.ReadFile(t.CA)
		if err != nil {
			return nil, fmt.Errorf("read CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA %q contained no PEM certificates", t.CA)
		}
		conf.RootCAs = pool
	}
	if (t.Cert == "") != (t.Key == "") {
		return nil, fmt.Errorf("cluster TLS cert and key must be given together")
	}
	if t.Cert != "" {
		cert, err := tls.LoadX509KeyPair(t.Cert, t.Key)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		conf.Certificates = []tls.Certificate{cert}
	}
	if t.ServerName != "" {
		conf.ServerName = t.ServerName
	}
	if t.Insecure {
		conf.InsecureSkipVerify = true
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: conf}}, nil
}
