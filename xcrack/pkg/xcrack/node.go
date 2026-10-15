package xcrack

import (
	"bytes"
	"crypto/sha256"
	"io"
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
