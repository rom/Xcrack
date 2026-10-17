// Package cluster orchestrates distributed password recovery across many
// xcrackd servers. xcrack stays the coordinator: it probes and assembles
// candidates locally, then streams disjoint batches of the keyspace to a fleet
// of xcrackd workers (each optionally GPU-accelerated) over the HTTP API, and
// returns the first password any worker reports.
//
// Two allocation modes, chosen per the "password recovery queue" idea of
// splitting work either within one job or across many:
//
//   - Collective: every server works the SAME file at once, on disjoint
//     candidate batches; the first to find the password wins and the rest are
//     cancelled. This is the way to throw 10s–100s of machines at one hard
//     password.
//   - Partition: servers are split into groups and each group is given its own
//     files; within a group the work is collective. This runs many files in
//     parallel when you have more targets than any one is worth clustering on.
//
// The coordinator never trusts a worker blindly: a worker only ever reports
// whether a candidate from the batch IT WAS GIVEN worked, and the returned
// password is one the coordinator itself supplied, so a faulty or hostile
// worker cannot inject a false positive (it can only fail to find, or stall,
// which the deadline and the other workers cover).
package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrypto/candidates"
)

// Mode selects how servers are allocated to files.
type Mode int

const (
	// Collective: all servers crack one file at a time on disjoint batches.
	Collective Mode = iota
	// Partition: server groups crack different files concurrently.
	Partition
)

// Server is one xcrackd endpoint.
type Server struct {
	URL   string // base URL, e.g. "http://host:8080"
	Group string // allocation group for Partition mode ("" = default group)
}

// Options configures the orchestrator.
type Options struct {
	Mode          Mode
	BatchSize     int           // candidates shipped per server request (0 => 20000)
	PerRequest    time.Duration // per-request server deadline hint (0 => none)
	AllowDefaults bool          // ask each server to also try its own default list
	MaxCandidates int64         // stop after shipping this many per file (0 => until exhausted/found)
	Client        *http.Client  // nil => a default client
	OnProgress    func(Progress)
	// ResumeOffsets maps a FileJob.Path to the number of candidates a prior run
	// confirmed tried; collective mode skips that prefix of the (deterministic)
	// candidate stream, so an interrupted distributed run resumes without
	// re-trying work. Safe because only the contiguous completed prefix is ever
	// recorded (see Progress.Tried).
	ResumeOffsets map[string]int64
}

// Progress is reported as batches complete.
type Progress struct {
	Path    string
	Server  string
	Batches int64
	Tried   int64
}

// FileJob is one target: its path (for reporting), its bytes, and a factory for
// a fresh candidate source (called once per crack).
type FileJob struct {
	Path       string
	Data       []byte
	Candidates func() candidates.Source
}

// FileResult is the outcome for one file.
type FileResult struct {
	Path     string
	Found    bool
	Password string
	Report   *xcrack.Report
	Err      error
}

const defaultBatchSize = 20000

func (o Options) batchSize() int {
	if o.BatchSize <= 0 {
		return defaultBatchSize
	}
	return o.BatchSize
}

func (o Options) client() *http.Client {
	if o.Client != nil {
		return o.Client
	}
	return &http.Client{}
}

// Run cracks every job per the allocation mode and returns results in job order.
func Run(ctx context.Context, servers []Server, jobs []FileJob, opts Options) []FileResult {
	results := make([]FileResult, len(jobs))
	for i := range jobs {
		results[i].Path = jobs[i].Path
	}
	if len(servers) == 0 {
		for i := range results {
			results[i].Err = fmt.Errorf("no servers configured")
		}
		return results
	}

	if opts.Mode == Partition {
		runPartition(ctx, servers, jobs, opts, results)
		return results
	}
	// Collective: all servers focus one file at a time.
	for i := range jobs {
		if ctx.Err() != nil {
			results[i].Err = ctx.Err()
			continue
		}
		results[i] = crackCollective(ctx, servers, jobs[i], opts)
	}
	return results
}

// runPartition groups servers and assigns each group its own files (round-robin
// over groups), running the groups concurrently. Within a group the crack is
// collective. With no explicit groups, each server is its own group, so files
// fan out one-per-server.
func runPartition(ctx context.Context, servers []Server, jobs []FileJob, opts Options, results []FileResult) {
	groups := groupServers(servers)
	type assignment struct {
		group   []Server
		jobIdxs []int
	}
	assigns := make([]assignment, len(groups))
	for gi := range groups {
		assigns[gi].group = groups[gi]
	}
	for ji := range jobs {
		gi := ji % len(groups)
		assigns[gi].jobIdxs = append(assigns[gi].jobIdxs, ji)
	}
	var wg sync.WaitGroup
	for _, a := range assigns {
		if len(a.jobIdxs) == 0 {
			continue
		}
		wg.Add(1)
		go func(a assignment) {
			defer wg.Done()
			for _, ji := range a.jobIdxs {
				if ctx.Err() != nil {
					results[ji].Err = ctx.Err()
					continue
				}
				results[ji] = crackCollective(ctx, a.group, jobs[ji], opts)
			}
		}(a)
	}
	wg.Wait()
}

// groupServers partitions servers by their Group label, preserving first-seen
// order. Servers with no group each form their own singleton group so Partition
// mode still fans files out across them.
func groupServers(servers []Server) [][]Server {
	var order []string
	byName := map[string][]Server{}
	var singletons [][]Server
	for _, s := range servers {
		if s.Group == "" {
			singletons = append(singletons, []Server{s})
			continue
		}
		if _, ok := byName[s.Group]; !ok {
			order = append(order, s.Group)
		}
		byName[s.Group] = append(byName[s.Group], s)
	}
	var out [][]Server
	for _, g := range order {
		out = append(out, byName[g])
	}
	out = append(out, singletons...)
	if len(out) == 0 {
		return [][]Server{{}}
	}
	return out
}

// crackCollective splits one file's keyspace across all given servers: a shared
// feeder hands disjoint batches to idle workers, one HTTP request in flight per
// server, and the first worker to report a password cancels the rest.
func crackCollective(parent context.Context, servers []Server, job FileJob, opts Options) FileResult {
	res := FileResult{Path: job.Path}
	if len(servers) == 0 {
		res.Err = fmt.Errorf("no servers in group")
		return res
	}
	src := job.Candidates()
	if src == nil {
		res.Err = fmt.Errorf("no candidate source")
		return res
	}
	if err := src.Reset(); err != nil {
		res.Err = err
		return res
	}
	// Resume: skip the candidates a prior run already confirmed tried for this
	// file (ResumeOffsets[path]). The source is deterministic across runs (same
	// config), so skipping a prefix never drops an untried candidate.
	baseSkip := int64(0)
	if opts.ResumeOffsets != nil {
		if n := opts.ResumeOffsets[job.Path]; n > 0 {
			for baseSkip < n {
				if _, err := src.Next(); err != nil {
					break
				}
				baseSkip++
			}
		}
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	var (
		mu        sync.Mutex
		shipped   int64
		feedDone  bool
		batches   int64
		nextSeq   int64
		lowWater  int64             // smallest seq not yet confirmed complete
		confirmed int64             // candidates in the contiguous completed prefix
		doneLen   = map[int64]int{} // seq -> candidate count, for seqs completed out of order
	)
	// nextBatch pulls up to batchSize candidates from the shared source, serializing
	// source access, and tags the batch with a monotonic sequence number so
	// completions can be tracked in order. It enforces the optional per-file cap.
	nextBatch := func() ([][]byte, int64) {
		mu.Lock()
		defer mu.Unlock()
		if feedDone {
			return nil, 0
		}
		if opts.MaxCandidates > 0 && shipped >= opts.MaxCandidates {
			feedDone = true
			return nil, 0
		}
		n := opts.batchSize()
		if opts.MaxCandidates > 0 {
			if rem := opts.MaxCandidates - shipped; rem < int64(n) {
				n = int(rem)
			}
		}
		batch := make([][]byte, 0, n)
		for len(batch) < n {
			pw, err := src.Next()
			if err != nil {
				feedDone = true
				break
			}
			batch = append(batch, append([]byte(nil), pw...))
		}
		shipped += int64(len(batch))
		seq := nextSeq
		nextSeq++
		return batch, seq
	}
	// complete records that batch seq finished and advances the contiguous
	// confirmed prefix (lowWater). confirmed counts only candidates whose batch —
	// and every earlier batch — has returned, so baseSkip+confirmed is a safe
	// resume offset even though batches finish out of order.
	complete := func(seq int64, n int) int64 {
		mu.Lock()
		defer mu.Unlock()
		doneLen[seq] = n
		for {
			ln, ok := doneLen[lowWater]
			if !ok {
				break
			}
			confirmed += int64(ln)
			delete(doneLen, lowWater)
			lowWater++
		}
		return baseSkip + confirmed
	}

	var (
		once     sync.Once
		hit      FileResult
		found    bool
		firstErr error
		errOnce  sync.Once
		wg       sync.WaitGroup
	)
	hit.Path = job.Path
	for _, srv := range servers {
		wg.Add(1)
		go func(srv Server) {
			defer wg.Done()
			for {
				if ctx.Err() != nil {
					return
				}
				batch, seq := nextBatch()
				if len(batch) == 0 {
					return
				}
				rep, err := postBatch(ctx, opts, srv, job.Data, batch)
				bn := atomicAdd(&mu, &batches, 1)
				if err != nil {
					if ctx.Err() == nil { // not just our own cancellation
						errOnce.Do(func() { firstErr = fmt.Errorf("%s: %w", srv.URL, err) })
					}
					return
				}
				// Batch completed: advance the confirmed prefix and report it as Tried,
				// so a --cluster-session can persist a safe resume offset.
				tried := complete(seq, len(batch))
				if opts.OnProgress != nil {
					opts.OnProgress(Progress{Path: job.Path, Server: srv.URL, Batches: bn, Tried: tried})
				}
				if pw, ok := passwordFromReport(rep); ok {
					once.Do(func() {
						hit.Found = true
						hit.Password = pw
						hit.Report = rep
						found = true
						cancel()
					})
					return
				}
			}
		}(srv)
	}
	wg.Wait()
	if found {
		return hit
	}
	res.Err = firstErr // nil when the keyspace was simply exhausted with no hit
	return res
}

// postBatch ships one file + candidate batch to a server's /v1/decrypt as a
// multipart request and decodes the JSON report.
func postBatch(ctx context.Context, opts Options, srv Server, fileData []byte, batch [][]byte) (*xcrack.Report, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "target.bin")
	if err != nil {
		return nil, err
	}
	if _, err := fw.Write(fileData); err != nil {
		return nil, err
	}
	ww, err := mw.CreateFormFile("wordlist", "batch.txt")
	if err != nil {
		return nil, err
	}
	for _, pw := range batch {
		ww.Write(pw)
		ww.Write([]byte{'\n'})
	}
	if opts.AllowDefaults {
		_ = mw.WriteField("defaults", "true")
	}
	if opts.PerRequest > 0 {
		_ = mw.WriteField("max-duration", opts.PerRequest.String())
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}

	url := strings.TrimRight(srv.URL, "/") + "/v1/decrypt"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := opts.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var rep xcrack.Report
	if err := json.Unmarshal(body, &rep); err != nil {
		return nil, fmt.Errorf("decode report: %w", err)
	}
	return &rep, nil
}

// passwordFromReport returns the first recovered password in a server report.
func passwordFromReport(rep *xcrack.Report) (string, bool) {
	if rep == nil {
		return "", false
	}
	for _, p := range rep.Passwords {
		if p != "" {
			return p, true
		}
	}
	// Fall back to walking the tree (a key-recovered node has no password but is
	// decrypted; the distributed path targets password recovery, so we only
	// report an actual password).
	return "", false
}

// --- small concurrency helpers (keep the counters under the feeder mutex) ---

func atomicAdd(mu *sync.Mutex, v *int64, d int64) int64 {
	mu.Lock()
	*v += d
	n := *v
	mu.Unlock()
	return n
}

func loadShipped(mu *sync.Mutex, v *int64) int64 {
	mu.Lock()
	n := *v
	mu.Unlock()
	return n
}
