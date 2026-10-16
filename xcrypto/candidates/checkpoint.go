package candidates

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// Checkpoint wraps a deterministic source so a long single-target search can be
// resumed after an interruption. It counts the candidates handed out and, every
// `every` candidates, persists the position (and a keyspace signature) to path
// atomically. When constructed against an existing checkpoint whose signature
// matches, iteration resumes a safety margin behind the saved position so no
// candidate that may have been handed out but not yet verified before the crash
// is skipped.
//
// Scope: a Checkpoint represents ONE linear pass over ONE keyspace, for a single
// encrypted target. It is deliberately not cloneable (so the engine does not
// parallelize it across siblings), and it re-seeks to the resume point on every
// Reset — correct for a single target, but meaningless across the many entries of
// a container, so callers restrict it to single-target runs. The wrapped source
// must be deterministic (masks, wordlists, chains); streams such as stdin cannot
// be resumed.
//
// A mismatched signature (the input or candidate set changed) is treated as a
// fresh start: the old position is ignored and overwritten.
type checkpointSource struct {
	inner      Source
	path       string
	sig        string
	every      int64
	margin     int64
	resumeSkip int64

	mu        sync.Mutex
	pos       int64
	lastSaved int64
	sought    bool // whether the one-time resume seek has happened
}

const (
	defaultCheckpointEvery  = 100_000
	defaultCheckpointMargin = 1 << 16 // conservatively covers in-flight candidates
)

// Checkpoint returns a resumable wrapper around inner. sig identifies the
// keyspace (e.g. derived from the target file and the candidate configuration);
// resuming only happens when the stored signature matches. every<=0 and margin<0
// select conservative defaults.
func Checkpoint(inner Source, path, sig string, every, margin int64) (Source, error) {
	if inner == nil {
		return nil, fmt.Errorf("checkpoint: nil source")
	}
	if path == "" {
		return nil, fmt.Errorf("checkpoint: empty path")
	}
	if every <= 0 {
		every = defaultCheckpointEvery
	}
	if margin < 0 {
		margin = defaultCheckpointMargin
	}
	c := &checkpointSource{inner: inner, path: path, sig: sig, every: every, margin: margin}
	if savedSig, savedPos, ok := readCheckpoint(path); ok && savedSig == sig {
		c.resumeSkip = savedPos - margin
		if c.resumeSkip < 0 {
			c.resumeSkip = 0
		}
	}
	return c, nil
}

// ResumeFrom reports the candidate offset iteration will resume from (0 for a
// fresh start). It is informational (for a CLI banner).
func (c *checkpointSource) ResumeFrom() int64 { return c.resumeSkip }

func (c *checkpointSource) Next() ([]byte, error) {
	b, err := c.inner.Next()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.pos++
	due := c.pos-c.lastSaved >= c.every
	pos := c.pos
	if due {
		c.lastSaved = pos
	}
	c.mu.Unlock()
	if due {
		c.persist(pos)
	}
	return b, nil
}

func (c *checkpointSource) Len() int64 { return c.inner.Len() }

// Reset restarts the inner source and, the FIRST time only, seeks forward to the
// resume point. The engine calls Reset once per searched node; seeking only on
// the first keeps a multi-node container (an unintended use — see the type doc)
// from cascade-skipping candidates in later nodes. For the intended single-target
// use there is exactly one Reset, so the resume applies as expected.
func (c *checkpointSource) Reset() error {
	if err := c.inner.Reset(); err != nil {
		return err
	}
	var i int64
	c.mu.Lock()
	seek := !c.sought
	c.sought = true
	c.mu.Unlock()
	if seek {
		for ; i < c.resumeSkip; i++ {
			if _, err := c.inner.Next(); err != nil {
				break // keyspace shorter than the resume point; nothing left to skip
			}
		}
	}
	c.mu.Lock()
	c.pos = i
	c.lastSaved = i
	c.mu.Unlock()
	return nil
}

// Save flushes the current position immediately (call on clean shutdown).
func (c *checkpointSource) Save() error {
	c.mu.Lock()
	pos := c.pos
	c.lastSaved = pos
	c.mu.Unlock()
	return c.persist(pos)
}

// persist writes "sig\npos\n" atomically via a temp file + rename.
func (c *checkpointSource) persist(pos int64) error {
	tmp := c.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := fmt.Fprintf(f, "%s\n%d\n", c.sig, pos)
	cerr := f.Close()
	if werr != nil {
		os.Remove(tmp)
		return werr
	}
	if cerr != nil {
		os.Remove(tmp)
		return cerr
	}
	return os.Rename(tmp, c.path)
}

// Saver is implemented by sources that can flush durable state on demand.
type Saver interface{ Save() error }

// Resumable is implemented by sources that report a resume offset.
type Resumable interface{ ResumeFrom() int64 }

func readCheckpoint(path string) (sig string, pos int64, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return "", 0, false
	}
	sig = strings.TrimRight(sc.Text(), "\r\n")
	if !sc.Scan() {
		return "", 0, false
	}
	p, err := strconv.ParseInt(strings.TrimSpace(sc.Text()), 10, 64)
	if err != nil || p < 0 {
		return "", 0, false
	}
	return sig, p, true
}
