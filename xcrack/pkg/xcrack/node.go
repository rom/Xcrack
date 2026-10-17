package xcrack

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/rom/xfileformats"
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
	// CrackDuration is the wall-clock time spent searching for this node's
	// password (or recovering its key). It is the per-node "time to crack" for a
	// decrypted node, and the time spent before giving up for a locked one. It is
	// zero for plaintext nodes and nodes that were never searched.
	CrackDuration time.Duration
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

// AuditEvent builds a secrets-free AuditEvent describing this node for an audit
// log or trace. The recovered password is included only when includeSecrets is
// true (opt-in); otherwise AuditEvent.Password stays empty regardless of whether
// a password was recovered.
func (n *Node) AuditEvent(includeSecrets bool) AuditEvent {
	ev := AuditEvent{
		Path:         n.Path,
		Format:       n.Format,
		Status:       n.Status.String(),
		Encrypted:    n.WasEncrypted,
		KeyRecovered: n.KeyRecovered,
		TimeToCrack:  n.CrackDuration,
	}
	if n.Content != nil {
		ev.Size = n.Content.Size()
	}
	if includeSecrets {
		ev.Password = n.Password
	}
	return ev
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

// source is the content the engine decomposes: either an in-memory byte slice
// (the common, small case) or a temp-file-backed reader for a large entry that
// was streamed to disk so it never occupied RAM. It is what decompose operates
// over, and it implements ContentRef so a leaf node can hold it directly. The
// SHA-256 is computed once (incrementally while streaming) and the size is the
// exact byte count. A file-backed source is tracked by the spillSet and closed
// when the Result is released.
type source struct {
	data []byte   // in-memory backing (nil when file-backed)
	f    *os.File // file backing (nil when in-memory)
	size int64
	sum  [32]byte
}

func newMemSource(data []byte) *source {
	return &source{data: data, size: int64(len(data)), sum: sha256.Sum256(data)}
}

// peek returns the first PeekSize bytes for format detection, without copying
// the whole content (a file-backed source reads just the prefix).
func (s *source) peek() []byte {
	n := int64(xfileformats.PeekSize)
	if n > s.size {
		n = s.size
	}
	if s.data != nil {
		return s.data[:n]
	}
	buf := make([]byte, n)
	_, _ = s.f.ReadAt(buf, 0)
	return buf
}

// readerAt returns a random-access view for format parsers (archive/zip, PDF,
// …), which never materializes a file-backed source into RAM.
func (s *source) readerAt() io.ReaderAt {
	if s.data != nil {
		return bytes.NewReader(s.data)
	}
	return io.NewSectionReader(s.f, 0, s.size)
}

// Open, Size, SHA256 implement ContentRef so a source can be a leaf's Content.
func (s *source) Open() (io.ReadCloser, error) {
	return io.NopCloser(io.NewSectionReader(s.readerAt(), 0, s.size)), nil
}
func (s *source) Size() int64      { return s.size }
func (s *source) SHA256() [32]byte { return s.sum }
func (s *source) close() error {
	if s.f != nil {
		return s.f.Close()
	}
	return nil
}

// spillSet decides whether a node's bytes stay in memory or spill to disk, and
// tracks spilled files so a Result can release them. It is safe for concurrent
// use. A zero or negative threshold disables spilling (everything stays in RAM).
type spillSet struct {
	mu        sync.Mutex
	threshold int64
	tempDir   string
	files     []*source
}

func newSpillSet(threshold int64, tempDir string) *spillSet {
	return &spillSet{threshold: threshold, tempDir: tempDir}
}

// streamChunk is the sliding-window buffer size used while spilling a reader to
// disk, so peak memory for a large entry is this, not the entry size.
const streamChunk = 1 << 20 // 1 MiB

// materialize returns an in-memory source for data (used where the bytes are
// already in hand, e.g. a freshly decrypted whole-file payload). Large content
// should prefer materializeReader so it is never held in RAM in the first place.
func (s *spillSet) materialize(data []byte) *source { return newMemSource(data) }

// materializeReader drains r into a source, bounding peak memory: it buffers up
// to the spill threshold, and if the content is larger it spills the rest to a
// temp file in streamChunk-sized windows, hashing as it goes — so a multi-GiB
// entry never occupies more than ~threshold+streamChunk of RAM. Small content
// (under the threshold, or when spilling is disabled or fails) stays in memory,
// exactly as before. If max > 0 and the content exceeds it, ErrLimitExceeded is
// returned so oversize entries are reported, not silently truncated.
func (s *spillSet) materializeReader(r io.Reader, max int64) (*source, error) {
	// Decide the in-memory cap: the spill threshold when spilling is enabled,
	// otherwise unbounded (behavior identical to the old read-all path).
	buffered := int64(-1) // unbounded
	if s != nil && s.threshold > 0 {
		buffered = s.threshold
	}

	// Read the in-memory prefix (the whole thing when small).
	var head []byte
	var err error
	if buffered < 0 {
		head, err = readBounded(r, max)
		if err != nil {
			return nil, err
		}
		return newMemSource(head), nil
	}
	head, err = io.ReadAll(io.LimitReader(r, buffered))
	if err != nil {
		return nil, err
	}
	if int64(len(head)) < buffered {
		// Reader was exhausted within the threshold: keep it in memory.
		return newMemSource(head), nil
	}

	// Larger than the threshold: spill to a temp file in bounded windows.
	f, cerr := os.CreateTemp(s.tempDir, "xcrack-spill-*")
	if cerr != nil {
		// No temp file: fall back to reading the rest into memory (still bounded
		// by max), so correctness never depends on the filesystem.
		rest, rerr := readBounded(r, remaining(max, int64(len(head))))
		if rerr != nil {
			return nil, rerr
		}
		return newMemSource(append(head, rest...)), nil
	}
	_ = os.Remove(f.Name()) // anonymous, self-cleaning

	h := sha256.New()
	total := int64(0)
	write := func(b []byte) error {
		if max > 0 && total+int64(len(b)) > max {
			return fmt.Errorf("%w: entry exceeds MaxEntrySize", xfileformats.ErrLimitExceeded)
		}
		if _, werr := f.Write(b); werr != nil {
			return werr
		}
		h.Write(b)
		total += int64(len(b))
		return nil
	}
	if werr := write(head); werr != nil {
		f.Close()
		return nil, werr
	}
	buf := make([]byte, streamChunk)
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			if werr := write(buf[:n]); werr != nil {
				f.Close()
				return nil, werr
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			return nil, rerr
		}
	}
	src := &source{f: f, size: total}
	copy(src.sum[:], h.Sum(nil))
	s.mu.Lock()
	s.files = append(s.files, src)
	s.mu.Unlock()
	return src, nil
}

// remaining returns the residual byte budget after already consuming have bytes
// of a max-byte limit (<=0 means unbounded, preserved as 0 for readBounded).
func remaining(max, have int64) int64 {
	if max <= 0 {
		return 0
	}
	if have >= max {
		return 0
	}
	return max - have
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
