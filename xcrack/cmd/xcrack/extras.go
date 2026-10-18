package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xcrack/pkg/securecache"
	"github.com/rom/xcrypto/candidates"
)

// collectTrainingWords gathers a bounded corpus to train the PCFG on: the
// explicit passwords, the built-in common-password list (if enabled), and the
// lines of each wordlist file (stdin "-" is skipped — it is consumed by the
// search itself). At most max words are returned.
func collectTrainingWords(explicit []string, useDefault bool, wordlists []string, max int) []string {
	out := make([]string, 0, len(explicit))
	add := func(s string) bool {
		if s == "" {
			return true
		}
		out = append(out, s)
		return len(out) < max
	}
	for _, p := range explicit {
		if !add(p) {
			return out
		}
	}
	if useDefault {
		src := candidates.DefaultList()
		for {
			b, err := src.Next()
			if err == io.EOF || err != nil {
				break
			}
			if !add(string(b)) {
				return out
			}
		}
	}
	for _, wl := range wordlists {
		if wl == "-" {
			continue
		}
		f, err := os.Open(wl)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			if !add(strings.TrimRight(sc.Text(), "\r\n")) {
				f.Close()
				return out
			}
		}
		f.Close()
	}
	return out
}

// --- password-pot (potfile) -------------------------------------------------

// potfile is a growing set of recovered passwords persisted to disk. On load its
// entries are offered as high-priority candidates (so a password cracked once is
// tried first everywhere); newly recovered passwords are appended. It is a thin
// wrapper over securecache.Store, which stores the set either as the historical
// plaintext newline file or, when a sealer is given (--cache-encryption tpm),
// encrypted with a key sealed to the host TPM.
type potfile struct {
	path    string
	store   *securecache.Store
	mu      sync.Mutex
	lastErr error
}

// defaultFoundCache returns the default persistent found-password cache path
// ($XDG_DATA_HOME/xcrack/found.txt, falling back to ~/.local/share and finally
// the current directory), used by --remember.
func defaultFoundCache() string {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		if home, err := os.UserHomeDir(); err == nil {
			base = filepath.Join(home, ".local", "share")
		}
	}
	if base == "" {
		return "xcrack-found.txt"
	}
	dir := filepath.Join(base, "xcrack")
	_ = os.MkdirAll(dir, 0o700)
	return filepath.Join(dir, "found.txt")
}

// resolveCacheSealer maps the --cache-encryption flag / config value to a
// securecache.Sealer (nil = plaintext). "tpm" requires a -tags tpm build and a
// reachable TPM, otherwise a clear error is returned so the user is not left
// believing the cache is protected when it is not.
func resolveCacheSealer(mode string) (securecache.Sealer, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "none", "plaintext":
		return nil, nil
	case "tpm":
		return securecache.TPMSealer()
	default:
		return nil, fmt.Errorf("unknown cache-encryption mode %q (want none or tpm)", mode)
	}
}

// loadPotfile opens the found-password cache at path with the given sealer. A
// corrupt or foreign-sealed file is an error (so a wrong TPM never silently
// starts fresh and overwrites the cache).
func loadPotfile(path string, sealer securecache.Sealer) (*potfile, error) {
	st, err := securecache.Open(path, sealer)
	if err != nil {
		return nil, err
	}
	return &potfile{path: path, store: st}, nil
}

// passwords returns the known passwords in first-seen order.
func (p *potfile) passwords() []string {
	if p == nil || p.store == nil {
		return nil
	}
	return p.store.Passwords()
}

// add records any new passwords, persisting the cache. Persistence is
// best-effort (as the plaintext potfile always was); the first write error is
// kept so the caller can warn once via err.
func (p *potfile) add(pws ...string) {
	if p == nil || p.store == nil {
		return
	}
	if err := p.store.Add(pws...); err != nil {
		p.mu.Lock()
		if p.lastErr == nil {
			p.lastErr = err
		}
		p.mu.Unlock()
	}
}

// err returns the first persistence error, if any.
func (p *potfile) err() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastErr
}

// candidateSig returns a short stable signature of the candidate configuration,
// used (with the target file's name and size) to key a resume checkpoint so a
// changed keyspace is not silently resumed. It is best-effort: it covers the
// explicit passwords, wordlists, default-list toggle, and pattern files.
// parseIncrement parses a "--increment MIN:MAX" (or "MIN", or "MIN-MAX") spec
// into min/max token lengths. Empty means no incrementing (0,0).
func parseIncrement(spec string) (min, max int, err error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0, 0, nil
	}
	sep := ":"
	if !strings.Contains(spec, ":") && strings.Contains(spec, "-") {
		sep = "-"
	}
	parts := strings.SplitN(spec, sep, 2)
	min, err = strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || min < 1 {
		return 0, 0, fmt.Errorf("want MIN[:MAX] with MIN>=1, got %q", spec)
	}
	max = min
	if len(parts) == 2 {
		max, err = strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil || max < min {
			return 0, 0, fmt.Errorf("want MIN:MAX with MAX>=MIN, got %q", spec)
		}
	}
	return min, max, nil
}

// parseShard parses a "--shard I/N" spec into a zero-based index and a count.
// An empty spec means no sharding (index 0, count 1). It rejects malformed
// specs and an out-of-range index so a mistyped shard can never silently skip
// part of the keyspace.
func parseShard(spec string) (index, count int, err error) {
	if strings.TrimSpace(spec) == "" {
		return 0, 1, nil
	}
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("want I/N (e.g. 0/4), got %q", spec)
	}
	i, ierr := strconv.Atoi(strings.TrimSpace(parts[0]))
	n, nerr := strconv.Atoi(strings.TrimSpace(parts[1]))
	if ierr != nil || nerr != nil {
		return 0, 0, fmt.Errorf("want integers I/N, got %q", spec)
	}
	if n < 1 {
		return 0, 0, fmt.Errorf("shard count must be >= 1, got %d", n)
	}
	if i < 0 || i >= n {
		return 0, 0, fmt.Errorf("shard index %d out of range for count %d (want 0..%d)", i, n, n-1)
	}
	return i, n, nil
}

func candidateSig(passwords, wordlists, breach []string, useDefault bool, patternFiles []string, spray bool, sprayTokens []string) string {
	h := sha256.New()
	writeAll := func(tag string, ss []string) {
		fmt.Fprintf(h, "%s=%d\n", tag, len(ss))
		for _, s := range ss {
			fmt.Fprintf(h, "%s\n", s)
		}
	}
	writeAll("pw", passwords)
	writeAll("wl", wordlists)
	writeAll("breach", breach)
	writeAll("pat", patternFiles)
	writeAll("spraytok", sprayTokens)
	fmt.Fprintf(h, "def=%t\nspray=%t\n", useDefault, spray)
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// --- single-password ergonomics ---------------------------------------------

// passwordsFromFiles reads candidate passwords (one per line) from each file.
func passwordsFromFiles(paths []string) ([]string, error) {
	var out []string
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			out = append(out, strings.TrimRight(sc.Text(), "\r\n"))
		}
		f.Close()
	}
	return out, nil
}

// passwordFromEnv returns the value of the named environment variable, if set,
// so a secret need not appear in argv (visible to `ps`).
func passwordFromEnv(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	return os.LookupEnv(name)
}

// --- live progress ----------------------------------------------------------

// progress reports batch progress to stderr on a ticker: files completed of
// total, candidates tested, rate, elapsed, and a file-rate ETA. Granularity is
// per file (the engine reports candidate counts as each node's search ends).
type progress struct {
	total      int
	keyspace   int64 // total candidates when known (single-target, finite); <=0 => unknown
	done       atomic.Int64
	candidates atomic.Int64
	start      time.Time
	stop       chan struct{}
	wg         sync.WaitGroup
}

func newProgress(total int) *progress { return newProgressKeyspace(total, -1) }

// newProgressKeyspace adds a known candidate keyspace so the reporter can show a
// true percentage and a candidate-rate ETA for a single finite-keyspace target.
func newProgressKeyspace(total int, keyspace int64) *progress {
	p := &progress{total: total, keyspace: keyspace, start: time.Now(), stop: make(chan struct{})}
	p.wg.Add(1)
	go p.loop()
	return p
}

func (p *progress) addCandidates(n int64) { p.candidates.Add(n) }
func (p *progress) fileDone()             { p.done.Add(1) }

func (p *progress) loop() {
	defer p.wg.Done()
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-t.C:
			p.print()
		}
	}
}

func (p *progress) print() {
	done := p.done.Load()
	el := time.Since(p.start)
	cand := p.candidates.Load()
	rate := float64(cand) / (el.Seconds() + 1e-9)
	eta := "?"
	// When the candidate keyspace is known (a single finite-keyspace target),
	// report true progress and a candidate-rate ETA; otherwise fall back to the
	// per-file ETA.
	if p.keyspace > 0 {
		pct := float64(cand) / float64(p.keyspace) * 100
		if pct > 100 {
			pct = 100
		}
		if rate > 0 && cand < p.keyspace {
			eta = (time.Duration(float64(p.keyspace-cand)/rate) * time.Second).Round(time.Second).String()
		}
		fmt.Fprintf(os.Stderr, "\rcandidates=%d/%d (%.1f%%) rate=%.0f/s elapsed=%s eta=%s   ",
			cand, p.keyspace, pct, rate, el.Round(time.Second), eta)
		return
	}
	if done > 0 && int(done) < p.total {
		per := el / time.Duration(done)
		eta = (per * time.Duration(p.total-int(done))).Round(time.Second).String()
	}
	fmt.Fprintf(os.Stderr, "\rfiles=%d/%d candidates=%d rate=%.0f/s elapsed=%s eta=%s   ",
		done, p.total, cand, rate, el.Round(time.Second), eta)
}

func (p *progress) close() {
	close(p.stop)
	p.wg.Wait()
	p.print()
	fmt.Fprintln(os.Stderr)
}
