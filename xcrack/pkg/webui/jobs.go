package webui

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xcrack/pkg/jobspec"
	"github.com/rom/xcrack/pkg/securecache"
	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrypto/candidates"
)

// marshalEvent renders an event as compact JSON for the SSE stream.
func marshalEvent(e Event) ([]byte, error) { return json.Marshal(e) }

// JobState is the lifecycle of a recovery job.
type JobState string

const (
	StateQueued   JobState = "queued"
	StateRunning  JobState = "running"
	StateDone     JobState = "done"
	StateError    JobState = "error"
	StateCanceled JobState = "canceled"
	// StateInterrupted marks a job whose runner goroutine died with a previous
	// process (the server restarted mid-run). It is assigned on reload, never by a
	// live runner, so a durable job is never shown as perpetually "running".
	StateInterrupted JobState = "interrupted"
)

// closedChan is a pre-closed channel shared by reloaded (terminal) jobs as their
// done signal, so a late SSE subscriber returns at once instead of blocking.
var closedChan = func() chan struct{} { c := make(chan struct{}); close(c); return c }()

// Event is one entry in a job's live event stream (delivered over SSE and kept
// as history so a late subscriber can replay). It never carries decrypted
// content; it carries a recovered password only when the server was started
// with password exposure enabled (ExposeSecrets), since the web UI is the user's
// own recovery console.
type Event struct {
	Type       string   `json:"type"` // state|progress|found|file_done|log|done
	Time       int64    `json:"time"` // unix milliseconds
	State      JobState `json:"state,omitempty"`
	File       string   `json:"file,omitempty"`
	Candidates int64    `json:"candidates,omitempty"`
	Keyspace   int64    `json:"keyspace,omitempty"` // total finite keyspace, or -1/0 when open-ended
	Latest     string   `json:"latest,omitempty"`   // most recent candidate tested (only when ExposeSecrets)
	Format     string   `json:"format,omitempty"`
	Password   string   `json:"password,omitempty"`
	Message    string   `json:"message,omitempty"`
	Level      string   `json:"level,omitempty"`
	FilesDone  int      `json:"files_done,omitempty"`
	FilesTotal int      `json:"files_total,omitempty"`
}

// FileResult is the outcome for one uploaded source file.
type FileResult struct {
	Name   string         `json:"name"`
	Report *xcrack.Report `json:"report,omitempty"`
	Error  string         `json:"error,omitempty"`
}

// JobView is the lock-free, serializable projection of a Job, returned by the
// API. It never embeds the job's mutex, channels or internal paths.
type JobView struct {
	ID          string       `json:"id"`
	State       JobState     `json:"state"`
	CreatedAt   int64        `json:"created_at"` // unix ms
	StartedAt   int64        `json:"started_at,omitempty"`
	EndedAt     int64        `json:"ended_at,omitempty"`
	Files       []string     `json:"files"`
	Error       string       `json:"error,omitempty"`
	FilesTotal  int          `json:"files_total"`
	FilesDone   int          `json:"files_done"`
	Candidates  int64        `json:"candidates"`
	Keyspace    int64        `json:"keyspace"` // finite total when known (determinate bar), else -1
	Decrypted   int          `json:"decrypted"`
	Distributed bool         `json:"distributed,omitempty"`
	Results     []FileResult `json:"results,omitempty"`
	SpecYAML    string       `json:"spec_yaml,omitempty"` // the (sanitized) spec the job ran
	Owner       string       `json:"owner,omitempty"`     // owning user's subject (multi-user mode)
}

// Job is a single recovery run over one or more uploaded files. Its mutable
// state is guarded by mu; the API only ever sees a JobView snapshot.
type Job struct {
	ID        string
	State     JobState
	CreatedAt int64 // unix ms
	StartedAt int64
	EndedAt   int64
	Files     []string
	Error     string

	FilesTotal  int
	FilesDone   int
	Candidates  int64
	Keyspace    int64
	Decrypted   int
	Distributed bool
	Results     []FileResult
	SpecYAML    string
	Owner       string

	mu      sync.Mutex
	mgr     *Manager // back-reference, for persistence on state change
	spec    *jobspec.Spec
	dir     string
	sources []string // absolute paths of uploaded source files, index-aligned with Files
	cancel  context.CancelFunc
	history []Event
	subs    map[int]chan Event
	nextSub int
	done    chan struct{}
}

// snapshot returns the job's externally-visible state, safe to serialize while
// the runner mutates the original.
func (j *Job) snapshot() JobView {
	j.mu.Lock()
	defer j.mu.Unlock()
	return JobView{
		ID: j.ID, State: j.State, CreatedAt: j.CreatedAt, StartedAt: j.StartedAt,
		EndedAt: j.EndedAt, Files: append([]string(nil), j.Files...), Error: j.Error,
		FilesTotal: j.FilesTotal, FilesDone: j.FilesDone, Candidates: atomic.LoadInt64(&j.Candidates),
		Keyspace: j.Keyspace, Decrypted: j.Decrypted, Distributed: j.Distributed,
		Results: append([]FileResult(nil), j.Results...), SpecYAML: j.SpecYAML, Owner: j.Owner,
	}
}

// ownerID returns the job's owning subject (empty in single-user mode).
func (j *Job) ownerID() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.Owner
}

func (j *Job) setState(s JobState) {
	j.mu.Lock()
	j.State = s
	switch s {
	case StateRunning:
		j.StartedAt = nowMS()
	case StateDone, StateError, StateCanceled:
		j.EndedAt = nowMS()
	}
	j.mu.Unlock()
	j.emit(Event{Type: "state", State: s})
	if j.mgr != nil {
		j.mgr.persist(j)
	}
}

// emit records an event in history and fans it out to live subscribers without
// blocking the runner (a slow subscriber drops events rather than stalling).
func (j *Job) emit(e Event) {
	if e.Time == 0 {
		e.Time = nowMS()
	}
	j.mu.Lock()
	j.history = append(j.history, e)
	if len(j.history) > maxEventHistory {
		j.history = j.history[len(j.history)-maxEventHistory:]
	}
	subs := make([]chan Event, 0, len(j.subs))
	for _, ch := range j.subs {
		subs = append(subs, ch)
	}
	j.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// subscribe registers a live event channel and returns it plus the history so
// far and an unsubscribe func. The caller drains the channel until the returned
// done channel is closed (job finished) or it unsubscribes.
func (j *Job) subscribe() (history []Event, ch chan Event, done chan struct{}, cancel func()) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.subs == nil {
		j.subs = map[int]chan Event{}
	}
	id := j.nextSub
	j.nextSub++
	c := make(chan Event, 256)
	j.subs[id] = c
	return append([]Event(nil), j.history...), c, j.done, func() {
		j.mu.Lock()
		delete(j.subs, id)
		j.mu.Unlock()
	}
}

// Manager owns the set of jobs and their on-disk working directories.
type Manager struct {
	cfg   Config
	mu    sync.Mutex
	jobs  map[string]*Job
	vault *securecache.Store // found-password vault (potfile)
	sem   chan struct{}      // job-concurrency limiter (nil = unlimited)
	wg    sync.WaitGroup     // tracks live runner goroutines, for Shutdown
	trail *auditTrail        // access/action audit (set by NewServer; may be nil)
}

// vaultActive reports whether the found-password vault is in use. It is a
// single-user, secrets-exposed feature: in multi-user mode a server-wide vault
// would leak passwords across users (and loopback would cross-pollinate them),
// so it is disabled when auth is on.
func (m *Manager) vaultActive() bool {
	return m.vault != nil && m.cfg.ExposeSecrets && !m.cfg.Auth.Enabled
}

// recordFound stores a recovered password in the vault (best-effort).
func (m *Manager) recordFound(pw string) {
	if !m.vaultActive() || pw == "" {
		return
	}
	_ = m.vault.Add(pw)
}

// vaultView returns the vault's passwords and whether it is sealed at rest.
func (m *Manager) vaultView() (encrypted bool, pws []string) {
	if !m.vaultActive() {
		return false, nil
	}
	return m.vault.Encrypted(), m.vault.Passwords()
}

// defaultWorkDir is the per-user default root for job working directories.
func defaultWorkDir() string { return filepath.Join(os.TempDir(), "xcrack-web") }

// NewManager returns a job manager rooted at cfg.WorkDir, repopulated with any
// jobs persisted under it by a previous process (so history survives a restart).
func NewManager(cfg Config) (*Manager, error) {
	cfg.applyDefaults()
	if err := os.MkdirAll(cfg.WorkDir, 0o700); err != nil {
		return nil, fmt.Errorf("work dir: %w", err)
	}
	m := &Manager{cfg: cfg, jobs: map[string]*Job{}}
	if cfg.MaxConcurrentJobs > 0 {
		m.sem = make(chan struct{}, cfg.MaxConcurrentJobs)
	}
	// The found-password vault (potfile). A sealed vault that cannot be opened
	// (bad key / tampering) is a hard error rather than a silent fresh start.
	vault, err := securecache.Open(filepath.Join(cfg.WorkDir, "potfile"), cfg.Sealer)
	if err != nil {
		return nil, fmt.Errorf("found-password vault: %w", err)
	}
	m.vault = vault
	m.loadPersisted()
	m.prune() // apply the age/count retention policy to reloaded history at startup
	return m, nil
}

// dirSize sums the bytes of regular files under root (best-effort).
func dirSize(root string) int64 {
	var total int64
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// overQuota reports whether the work directory already holds at least
// MaxWorkDirBytes (0 = unlimited).
func (m *Manager) overQuota() bool {
	if m.cfg.MaxWorkDirBytes <= 0 {
		return false
	}
	return dirSize(m.cfg.WorkDir) >= m.cfg.MaxWorkDirBytes
}

// prune enforces the retention policy: finished jobs older than MaxJobAge, and
// finished jobs beyond MaxRetainedJobs (oldest first), are removed and their
// working directories deleted. Running/queued jobs are never touched, and a job
// still finishing (its done channel not yet closed) is skipped so prune can
// never deadlock removing the job that triggered it.
func (m *Manager) prune() {
	if m.cfg.MaxRetainedJobs <= 0 && m.cfg.MaxJobAge <= 0 {
		return
	}
	type fin struct {
		id    string
		ended int64
	}
	m.mu.Lock()
	var finished []fin
	for id, j := range m.jobs {
		select {
		case <-j.done: // only a fully-settled job is eligible
		default:
			continue
		}
		j.mu.Lock()
		terminal := j.State == StateDone || j.State == StateError || j.State == StateCanceled || j.State == StateInterrupted
		ended := j.EndedAt
		if ended == 0 {
			ended = j.CreatedAt
		}
		j.mu.Unlock()
		if terminal {
			finished = append(finished, fin{id, ended})
		}
	}
	m.mu.Unlock()

	sort.Slice(finished, func(a, b int) bool { return finished[a].ended < finished[b].ended }) // oldest first
	remove := map[string]bool{}
	if m.cfg.MaxJobAge > 0 {
		cutoff := nowMS() - m.cfg.MaxJobAge.Milliseconds()
		for _, f := range finished {
			if f.ended < cutoff {
				remove[f.id] = true
			}
		}
	}
	if m.cfg.MaxRetainedJobs > 0 && len(finished) > m.cfg.MaxRetainedJobs {
		for i := 0; i < len(finished)-m.cfg.MaxRetainedJobs; i++ {
			remove[finished[i].id] = true
		}
	}
	for id := range remove {
		m.remove(id)
	}
}

// persist writes the job's current view to <dir>/job.json atomically (temp +
// rename), so the job survives a restart and a crashed run still leaves a
// readable record. Best-effort: a persistence failure never breaks a run.
func (m *Manager) persist(j *Job) {
	if j.dir == "" {
		return
	}
	b, err := json.Marshal(j.snapshot())
	if err != nil {
		return
	}
	tmp := filepath.Join(j.dir, "job.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, filepath.Join(j.dir, "job.json"))
}

// loadPersisted repopulates the job set from job.json files under WorkDir. A job
// whose persisted state was still queued/running lost its runner goroutine with
// the previous process, so it is reloaded as interrupted rather than running.
func (m *Manager) loadPersisted() {
	entries, err := os.ReadDir(m.cfg.WorkDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(m.cfg.WorkDir, e.Name())
		b, err := os.ReadFile(filepath.Join(dir, "job.json"))
		if err != nil {
			continue
		}
		var v JobView
		if err := json.Unmarshal(b, &v); err != nil || v.ID == "" {
			continue
		}
		j := m.jobFromView(v, dir)
		m.jobs[j.ID] = j
	}
}

// jobFromView reconstructs a terminal Job from its persisted view: no runner, no
// cancel, and an already-closed done channel. A job left queued/running by a
// previous process becomes interrupted.
func (m *Manager) jobFromView(v JobView, dir string) *Job {
	state, errMsg := v.State, v.Error
	if state == StateQueued || state == StateRunning {
		state = StateInterrupted
		if errMsg == "" {
			errMsg = "interrupted (the server restarted while this job was running)"
		}
	}
	return &Job{
		ID: v.ID, State: state, CreatedAt: v.CreatedAt, StartedAt: v.StartedAt, EndedAt: v.EndedAt,
		Files: v.Files, Error: errMsg, FilesTotal: v.FilesTotal, FilesDone: v.FilesDone,
		Candidates: v.Candidates, Keyspace: v.Keyspace, Decrypted: v.Decrypted,
		Distributed: v.Distributed, Results: v.Results, SpecYAML: v.SpecYAML, Owner: v.Owner,
		dir: dir, done: closedChan, mgr: m,
	}
}

// remove cancels the job if it is running (and waits for the runner to exit, so
// RemoveAll does not race a writer), drops it from the set, and deletes its
// working directory. Returns false if there is no such job.
func (m *Manager) remove(id string) bool {
	m.mu.Lock()
	j := m.jobs[id]
	if j == nil {
		m.mu.Unlock()
		return false
	}
	delete(m.jobs, id)
	m.mu.Unlock()

	j.mu.Lock()
	c, dir, done := j.cancel, j.dir, j.done
	j.mu.Unlock()
	if c != nil {
		c()
		<-done // let the runner finish writing before we delete its directory
	}
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
	return true
}

// get returns the job with id, or nil.
func (m *Manager) get(id string) *Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.jobs[id]
}

// list returns all jobs, newest first.
func (m *Manager) list() []JobView {
	m.mu.Lock()
	jobs := make([]*Job, 0, len(m.jobs))
	for _, j := range m.jobs {
		jobs = append(jobs, j)
	}
	m.mu.Unlock()
	out := make([]JobView, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, j.snapshot())
	}
	// newest first
	for i := 0; i < len(out); i++ {
		for k := i + 1; k < len(out); k++ {
			if out[k].CreatedAt > out[i].CreatedAt {
				out[i], out[k] = out[k], out[i]
			}
		}
	}
	return out
}

// newJob allocates a job with its own working directory.
func (m *Manager) newJob() (*Job, error) {
	m.prune() // bound history growth before adding another job
	id, err := randID()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(m.cfg.WorkDir, id)
	for _, sub := range []string{"uploads", "aux", "out"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, err
		}
	}
	j := &Job{
		ID: id, State: StateQueued, CreatedAt: nowMS(), dir: dir, mgr: m,
		done: make(chan struct{}), subs: map[int]chan Event{},
	}
	m.mu.Lock()
	m.jobs[id] = j
	m.mu.Unlock()
	m.persist(j) // a durable record exists from creation, before the run starts
	return j, nil
}

// cancel stops a running job.
func (m *Manager) cancel(id string) bool {
	j := m.get(id)
	if j == nil {
		return false
	}
	j.mu.Lock()
	c := j.cancel
	j.mu.Unlock()
	if c != nil {
		c()
		return true
	}
	return false
}

// start launches the job's runner goroutine. wg is incremented here, before the
// goroutine starts, so Shutdown's Wait can never miss a just-started runner.
func (m *Manager) start(j *Job) {
	m.wg.Add(1)
	go m.run(j)
}

// Shutdown cancels every in-flight job and waits for all runner goroutines to
// exit, so once it returns nothing is still writing under a job's working
// directory. A caller that owns the work directory (a test, or a server
// shutting down) can then remove it without racing a runner. Safe to call once.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(m.jobs))
	for _, j := range m.jobs {
		j.mu.Lock()
		if j.cancel != nil {
			cancels = append(cancels, j.cancel)
		}
		j.mu.Unlock()
	}
	m.mu.Unlock()
	for _, c := range cancels {
		c()
	}
	m.wg.Wait()
}

// rerunInfo returns what re-running needs: the job's working directory, its
// sanitized spec YAML, and the uploaded source file names.
func (j *Job) rerunInfo() (dir, specYAML string, names []string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.dir, j.SpecYAML, append([]string(nil), j.Files...)
}

// rerun starts a fresh job from an existing one's saved spec and uploaded source
// files (still on disk under the old job's directory), owned by owner. It leaves
// the original untouched. The saved spec's file references were already locked to
// the old job's upload directory, so re-running adds no new path exposure.
func (m *Manager) rerun(old *Job, owner string) (*Job, error) {
	dir, specYAML, names := old.rerunInfo()
	if specYAML == "" || len(names) == 0 {
		return nil, fmt.Errorf("job cannot be re-run (no saved spec or source files)")
	}
	spec, err := jobspec.ParseStrict([]byte(specYAML))
	if err != nil {
		return nil, fmt.Errorf("saved spec: %w", err)
	}
	sources := make([]string, len(names))
	for i, n := range names {
		p := filepath.Join(dir, "uploads", n)
		if _, err := os.Stat(p); err != nil {
			return nil, fmt.Errorf("source %q is no longer on disk", n)
		}
		sources[i] = p
	}
	nj, err := m.newJob()
	if err != nil {
		return nil, err
	}
	nj.mu.Lock()
	nj.spec = spec
	nj.Files = names
	nj.sources = sources
	nj.FilesTotal = len(sources)
	nj.SpecYAML = specYAML
	nj.Owner = owner
	nj.mu.Unlock()
	m.start(nj)
	return nj, nil
}

// run executes the job: build engine options, assemble candidates, process each
// uploaded source file, and write any decrypted tree to the job's output dir.
func (m *Manager) run(j *Job) {
	defer m.wg.Done() // last, so Shutdown's Wait returns only after all cleanup/IO
	defer close(j.done)
	ctx, cancel := context.WithCancel(context.Background())
	j.mu.Lock()
	j.cancel = cancel
	j.FilesTotal = len(j.sources)
	spec := j.spec
	sources := append([]string(nil), j.sources...)
	names := append([]string(nil), j.Files...)
	j.mu.Unlock()
	defer cancel()

	// Honor the job-concurrency cap: block (staying "queued") until a slot frees,
	// unless the job is canceled while waiting.
	if m.sem != nil {
		select {
		case m.sem <- struct{}{}:
			defer func() { <-m.sem }()
		case <-ctx.Done():
			j.setState(StateCanceled)
			return
		}
	}

	j.setState(StateRunning)

	opts, err := spec.BuildOptions()
	if err != nil {
		j.fail(fmt.Sprintf("build options: %v", err))
		return
	}
	logger := &jobLogger{job: j}
	opts.Logger = logger

	// Optional GPU tier, wired by the binary (nil in a pure-Go build or when the
	// operator did not provide the hook). Any failure falls back to the CPU.
	var accClose func()
	if spec.Concurrency.GPU {
		if m.cfg.Accelerator != nil {
			if acc, closer, ok := m.cfg.Accelerator(spec, slogFor(j)); ok {
				opts.Accelerator = acc
				accClose = closer
			} else {
				j.emit(Event{Type: "log", Level: "warn", Message: "GPU requested but unavailable; running on the CPU"})
			}
		} else {
			j.emit(Event{Type: "log", Level: "warn", Message: "GPU requested but this build has no GPU tier; running on the CPU"})
		}
	}
	if accClose != nil {
		defer accClose()
	}

	var found int64
	opts.OnFound = func(f xcrack.Found) {
		atomic.AddInt64(&found, 1)
		ev := Event{Type: "found", File: f.Path, Format: f.Format}
		if m.cfg.ExposeSecrets && !f.KeyRecovered {
			ev.Password = f.Password
		}
		if f.Password != "" {
			m.recordFound(f.Password) // persist to the vault (gated by vaultActive)
		}
		if m.trail != nil { // audit the recovery, never the secret itself
			actor := j.Owner
			if actor == "" {
				actor = "local"
			}
			m.trail.record(auditEntry{Actor: actor, Action: "found", Target: f.Path, Detail: f.Format})
		}
		j.emit(ev)
	}

	// Seed the loopback pass with the vault's known passwords, so a reused or
	// previously recovered password is caught fast (single-user, secrets-exposed).
	rt := jobspec.Runtime{}
	if m.vaultActive() {
		rt.LoopbackPasswords = m.vault.Passwords()
	}
	asm, err := jobspec.NewAssembler(spec, rt)
	if err != nil {
		j.fail(fmt.Sprintf("assemble candidates: %v", err))
		return
	}

	// Progress state: the candidate counter and latest-term the recorder feeds,
	// plus the finite keyspace for a determinate bar (only for a single
	// finite-keyspace target, mirroring the CLI's --progress).
	ps := &progressState{keyspace: -1}
	if len(names) == 1 {
		ps.keyspace = asm.Keyspace(names[0])
	}
	j.mu.Lock()
	j.Keyspace = ps.keyspace
	j.mu.Unlock()

	// Live progress ticker: surface the candidate count, keyspace percentage and
	// the latest candidate (only when secrets are exposed) a couple of times a
	// second, independent of how often the engine reports per-node progress.
	stopTick := make(chan struct{})
	var tickWG sync.WaitGroup
	tickWG.Add(1)
	go func() {
		defer tickWG.Done()
		tk := time.NewTicker(500 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stopTick:
				return
			case <-tk.C:
				cand, last := ps.snapshot()
				atomic.StoreInt64(&j.Candidates, cand)
				j.mu.Lock()
				done, total := j.FilesDone, j.FilesTotal
				j.mu.Unlock()
				ev := Event{Type: "progress", Candidates: cand, Keyspace: ps.keyspace, FilesDone: done, FilesTotal: total}
				if m.cfg.ExposeSecrets {
					ev.Latest = last
				}
				j.emit(ev)
			}
		}
	}()
	stopProgress := func() { close(stopTick); tickWG.Wait() }

	distributed := len(spec.Cluster.Servers) > 0
	j.mu.Lock()
	j.Distributed = distributed
	j.mu.Unlock()

	var results []FileResult
	if distributed {
		results = m.runDistributed(ctx, j, spec, asm, names, sources, ps, &found)
	} else {
		pool := xcrack.NewPool(opts)
		defer pool.Close()
		results = make([]FileResult, len(sources))
		jobsC := opts.FileConcurrency
		if jobsC < 1 {
			jobsC = 1
		}
		sem := make(chan struct{}, jobsC)
		var wg sync.WaitGroup
		for i := range sources {
			wg.Add(1)
			sem <- struct{}{}
			go func(i int) {
				defer wg.Done()
				defer func() { <-sem }()
				results[i] = m.processOne(ctx, j, pool, asm, names[i], sources[i], ps)
				j.mu.Lock()
				j.FilesDone++
				done, total := j.FilesDone, j.FilesTotal
				j.mu.Unlock()
				j.emit(Event{Type: "file_done", File: names[i], FilesDone: done, FilesTotal: total})
			}(i)
		}
		wg.Wait()
	}

	stopProgress()

	j.mu.Lock()
	j.Results = results
	j.Decrypted = int(atomic.LoadInt64(&found))
	j.Candidates = ps.candidates.Load()
	j.mu.Unlock()

	if ctx.Err() != nil {
		j.setState(StateCanceled)
		return
	}
	j.setState(StateDone)
	j.emit(Event{Type: "done"})
}

// progressState is the live counter/latest-candidate a recorder feeds and the
// ticker reads. keyspace is the finite total (for a determinate bar) or -1.
type progressState struct {
	candidates atomic.Int64
	last       atomic.Pointer[string]
	keyspace   int64
}

func (ps *progressState) record(b []byte) {
	ps.candidates.Add(1)
	s := string(b)
	ps.last.Store(&s)
}

func (ps *progressState) snapshot() (cand int64, last string) {
	cand = ps.candidates.Load()
	if p := ps.last.Load(); p != nil {
		last = *p
	}
	return cand, last
}

// recorder wraps a candidate source to record the count and latest value pulled,
// so the UI can show throughput and the most recent term tested.
type recorder struct {
	src candidates.Source
	ps  *progressState
}

func (r *recorder) Next() ([]byte, error) {
	b, err := r.src.Next()
	if err == nil {
		r.ps.record(b)
	}
	return b, err
}
func (r *recorder) Len() int64   { return r.src.Len() }
func (r *recorder) Reset() error { return r.src.Reset() }

// processOne cracks a single file and writes any decrypted tree under the job's
// output directory. It never returns an error; a failure is recorded on the
// FileResult so the other files still run.
func (m *Manager) processOne(ctx context.Context, j *Job, pool *xcrack.Pool, asm *jobspec.Assembler, name, path string, ps *progressState) FileResult {
	data, err := os.ReadFile(path)
	if err != nil {
		return FileResult{Name: name, Error: fmt.Sprintf("read: %v", err)}
	}
	src := &recorder{src: asm.Candidates(name), ps: ps}
	res, err := pool.Process(ctx, byteReaderAt(data), int64(len(data)), src)
	if err != nil {
		if ctx.Err() != nil {
			return FileResult{Name: name, Error: "canceled"}
		}
		return FileResult{Name: name, Error: fmt.Sprintf("process: %v", err)}
	}
	defer res.Close()
	res.Root.Path = name
	rep := xcrack.BuildReport(res)
	// Extract any decrypted content to the per-file output dir so it can be
	// downloaded later (res.Close releases spilled intermediates).
	outDir := filepath.Join(j.dir, "out", safeSegment(name)+".extracted")
	if err := writeTree(outDir, res); err != nil {
		j.emit(Event{Type: "log", Level: "warn", Message: fmt.Sprintf("%s: writing output: %v", name, err)})
	}
	return FileResult{Name: name, Report: &rep}
}

func (j *Job) fail(msg string) {
	j.mu.Lock()
	j.Error = msg
	j.mu.Unlock()
	j.emit(Event{Type: "log", Level: "error", Message: msg})
	j.setState(StateError)
}

// zipOutputs streams the job's extracted output tree as a zip archive to w.
func (j *Job) zipOutputs(w io.Writer) error {
	root := filepath.Join(j.dir, "out")
	zw := zip.NewWriter(w)
	defer zw.Close()
	return filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		hdr, err := zw.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		_, err = io.Copy(hdr, f)
		return err
	})
}

// jobLogger adapts the engine's Logger onto the job event stream so engine
// warnings/errors surface in the UI's live log. Debug is dropped to avoid spam.
type jobLogger struct{ job *Job }

func (l *jobLogger) Debugf(string, ...any) {}
func (l *jobLogger) Infof(f string, a ...any) {
	l.job.emit(Event{Type: "log", Level: "info", Message: fmt.Sprintf(f, a...)})
}
func (l *jobLogger) Warnf(f string, a ...any) {
	l.job.emit(Event{Type: "log", Level: "warn", Message: fmt.Sprintf(f, a...)})
}
func (l *jobLogger) Errorf(f string, a ...any) {
	l.job.emit(Event{Type: "log", Level: "error", Message: fmt.Sprintf(f, a...)})
}

// slogFor builds a throwaway slog.Logger whose records flow into the job event
// stream, for the GPU-wiring hook (which takes a *slog.Logger).
func slogFor(j *Job) *slog.Logger {
	return slog.New(slog.NewTextHandler(eventWriter{j}, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

type eventWriter struct{ job *Job }

func (e eventWriter) Write(p []byte) (int, error) {
	e.job.emit(Event{Type: "log", Level: "info", Message: strings.TrimRight(string(p), "\n")})
	return len(p), nil
}

const maxEventHistory = 2000

func nowMS() int64 { return time.Now().UnixMilli() }

func randID() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
