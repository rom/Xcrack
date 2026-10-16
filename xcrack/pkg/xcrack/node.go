package xcrack

import (
	"bytes"
	"crypto/sha256"
	"io"
	"os"
	"sync"
	"time"
)

// NodeStatus describes the outcome of processing one node in the decomposition
// tree.
type NodeStatus int

const (
	// StatusPlain: the node was not encrypted (content handed back as-is).
	StatusPlain NodeStatus = iota
	// StatusDecrypted: the node was encrypted and a candidate unlocked it.
	StatusDecrypted
	// StatusLocked: the node was encrypted but no candidate worked in budget.
	StatusLocked
	// StatusLimitExceeded: the node was pruned by a safety limit (depth, bytes,
	// nodes, ratio, or a detected cycle).
	StatusLimitExceeded
	// StatusError: a recoverable per-node error occurred; siblings continue.
	StatusError
)

func (s NodeStatus) String() string {
	switch s {
	case StatusPlain:
		return "plain"
	case StatusDecrypted:
		return "decrypted"
	case StatusLocked:
		return "locked"
	case StatusLimitExceeded:
		return "limit-exceeded"
	case StatusError:
		return "error"
	default:
		return "unknown"
	}
}

// Node is one position in the decomposition tree.
type Node struct {
	// Path is the lineage, e.g. "invoice.zip!/report.docx".
	Path string
	// Format is the detected format name ("" if plaintext/unknown leaf).
	Format string
	// WasEncrypted reports whether this node required a password.
	WasEncrypted bool
	// Password is the candidate that unlocked this node ("" if none).
	Password string
	// KeyRecovered reports that this node was unlocked by a known-plaintext key
	// recovery (ZipCrypto) rather than by a password; Password is then "".
	KeyRecovered bool
	// Status is the processing outcome.
	Status NodeStatus
	// Err is non-nil for StatusError (never a panic).
	Err error
	// Content yields this node's (decrypted) bytes. nil for non-leaf nodes and
	// for nodes that could not be produced (locked / limit / error).
	Content ContentRef
	// Children are container entries, recursively.
	Children []*Node
}

// Leaf reports whether the node carries content with no children.
func (n *Node) Leaf() bool { return len(n.Children) == 0 }

// Walk visits n and all descendants in pre-order.
func (n *Node) Walk(fn func(*Node)) {
	fn(n)
	for _, c := range n.Children {
		c.Walk(fn)
	}
}

// Result is the outcome of a Process call.
type Result struct {
	Root  *Node
	Stats Stats

	spills *spillSet
}

// Close releases any temp files used to spill large intermediates to disk.
// Call it once the result tree's content has been consumed. It is safe to call
// on a Result with no spilled content, and safe to call more than once.
func (r *Result) Close() error {
	if r == nil {
		return nil
	}
	return r.spills.closeAll()
}

// Passwords returns every distinct recovered password in the tree, in
// first-seen order.
func (r *Result) Passwords() []string {
	seen := map[string]bool{}
	var out []string
	if r.Root == nil {
		return out
	}
	r.Root.Walk(func(n *Node) {
		if n.WasEncrypted && n.Password != "" && !seen[n.Password] {
			seen[n.Password] = true
			out = append(out, n.Password)
		}
	})
	return out
}

// Stats summarizes the work done during a Process call.
type Stats struct {
	FilesSeen       int
	CandidatesTried int64
	BytesExtracted  int64
	LimitHits       int
	Elapsed         time.Duration
}

// ContentRef provides on-demand access to a node's bytes without forcing the
// whole tree into memory at once.
type ContentRef interface {
	Open() (io.ReadCloser, error)
	Size() int64
	SHA256() [32]byte
}

// memContent is an in-memory ContentRef (the MVP backing; a disk-spill backing
// is planned for large intermediates).
type memContent struct {
	data []byte
	sum  [32]byte
}

func newMemContent(data []byte) *memContent {
	return &memContent{data: data, sum: sha256.Sum256(data)}
}

func (m *memContent) Open() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m.data)), nil
}
func (m *memContent) Size() int64      { return int64(len(m.data)) }
func (m *memContent) SHA256() [32]byte { return m.sum }

// spillContent is a ContentRef backed by a temp file, for intermediates larger
// than the spill threshold. On Unix the backing file is unlinked at creation so
// it is anonymous and vanishes when the fd is closed (or at process exit).
type spillContent struct {
	f    *os.File
	size int64
	sum  [32]byte
}

func (s *spillContent) Open() (io.ReadCloser, error) {
	return io.NopCloser(io.NewSectionReader(s.f, 0, s.size)), nil
}
func (s *spillContent) Size() int64      { return s.size }
func (s *spillContent) SHA256() [32]byte { return s.sum }
func (s *spillContent) close() error     { return s.f.Close() }

// spillSet decides whether a node's bytes stay in memory or spill to disk, and
// tracks spilled files so a Result can release them. It is safe for concurrent
// use. A zero or negative threshold disables spilling.
type spillSet struct {
	mu        sync.Mutex
	threshold int64
	tempDir   string
	files     []*spillContent
}

func newSpillSet(threshold int64, tempDir string) *spillSet {
	return &spillSet{threshold: threshold, tempDir: tempDir}
}

// materialize returns a ContentRef for data: a temp-file-backed ref when data is
// at least the threshold, otherwise an in-memory ref. Any spill failure falls
// back to memory, so correctness never depends on the filesystem.
func (s *spillSet) materialize(data []byte) ContentRef {
	if s == nil || s.threshold <= 0 || int64(len(data)) < s.threshold {
		return newMemContent(data)
	}
	f, err := os.CreateTemp(s.tempDir, "xcrack-spill-*")
	if err != nil {
		return newMemContent(data)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return newMemContent(data)
	}
	// Unlink now so the file is anonymous and self-cleaning; keep the fd. If the
	// platform refuses, Close() still removes it by the path we recorded.
	_ = os.Remove(f.Name())
	sc := &spillContent{f: f, size: int64(len(data)), sum: sha256.Sum256(data)}
	s.mu.Lock()
	s.files = append(s.files, sc)
	s.mu.Unlock()
	return sc
}

func (s *spillSet) closeAll() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	for _, sc := range s.files {
		if e := sc.close(); e != nil && err == nil {
			err = e
		}
	}
	s.files = nil
	return err
}
