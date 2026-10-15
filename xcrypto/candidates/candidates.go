// Package candidates provides password candidate sources for the Xcrack engine.
// A Source yields candidates one at a time; the engine wraps a Source in a
// synchronized feeder for concurrent testing, so Sources need not be
// thread-safe. Every Source implements the engine's CandidateSource interface
// structurally (Next/Len/Reset), so this package does not import the engine.
package candidates

import (
	"bufio"
	"compress/gzip"
	"io"
	"os"
)

// Source yields password candidates.
type Source interface {
	// Next returns the next candidate, or io.EOF when exhausted.
	Next() ([]byte, error)
	// Len returns the number of candidates if known, or -1.
	Len() int64
	// Reset restarts iteration from the beginning.
	Reset() error
}

// --- explicit, in-memory list (also used for --password and programmatic injection) ---

type sliceSource struct {
	items [][]byte
	i     int
}

// Explicit returns a Source over the given passwords, in order.
func Explicit(passwords ...string) Source {
	items := make([][]byte, len(passwords))
	for i, p := range passwords {
		items[i] = []byte(p)
	}
	return &sliceSource{items: items}
}

// Bytes returns a Source over raw byte candidates (for programmatic injection
// from a caller such as Impex).
func Bytes(items ...[]byte) Source {
	cp := make([][]byte, len(items))
	copy(cp, items)
	return &sliceSource{items: cp}
}

func (s *sliceSource) Next() ([]byte, error) {
	if s.i >= len(s.items) {
		return nil, io.EOF
	}
	v := s.items[s.i]
	s.i++
	return v, nil
}
func (s *sliceSource) Len() int64   { return int64(len(s.items)) }
func (s *sliceSource) Reset() error { s.i = 0; return nil }

// --- wordlist reader (line-delimited; gzip auto-detected) ---

type readerSource struct {
	open func() (io.ReadCloser, error)
	rc   io.ReadCloser
	sc   *bufio.Scanner
}

// Reader returns a Source over newline-delimited candidates read from the
// stream produced by open. open is called on first use and on Reset so the
// source can be re-iterated.
func Reader(open func() (io.ReadCloser, error)) Source {
	return &readerSource{open: open}
}

// File returns a Source over a wordlist file, decompressing transparently if it
// is gzip-compressed.
func File(path string) Source {
	return Reader(func() (io.ReadCloser, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		return maybeGunzip(f)
	})
}

func maybeGunzip(rc io.ReadCloser) (io.ReadCloser, error) {
	br := bufio.NewReader(rc)
	magic, err := br.Peek(2)
	if err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, gerr := gzip.NewReader(br)
		if gerr != nil {
			rc.Close()
			return nil, gerr
		}
		return &closer{Reader: gz, closes: []io.Closer{gz, rc}}, nil
	}
	return &closer{Reader: br, closes: []io.Closer{rc}}, nil
}

type closer struct {
	io.Reader
	closes []io.Closer
}

func (c *closer) Close() error {
	var err error
	for _, x := range c.closes {
		if e := x.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}

func (s *readerSource) ensure() error {
	if s.sc != nil {
		return nil
	}
	rc, err := s.open()
	if err != nil {
		return err
	}
	s.rc = rc
	s.sc = bufio.NewScanner(rc)
	s.sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // allow long lines, bounded
	return nil
}

func (s *readerSource) Next() ([]byte, error) {
	if err := s.ensure(); err != nil {
		return nil, err
	}
	if s.sc.Scan() {
		line := s.sc.Bytes()
		out := make([]byte, len(line))
		copy(out, line)
		return out, nil
	}
	if err := s.sc.Err(); err != nil {
		return nil, err
	}
	return nil, io.EOF
}

func (s *readerSource) Len() int64 { return -1 }

func (s *readerSource) Reset() error {
	if s.rc != nil {
		s.rc.Close()
	}
	s.rc, s.sc = nil, nil
	return nil
}

// Stdin returns a Source over newline-delimited candidates from standard input.
// It cannot be re-iterated; Reset is a no-op after the first pass.
func Stdin() Source {
	return Reader(func() (io.ReadCloser, error) { return io.NopCloser(os.Stdin), nil })
}

// --- built-in default list (passwords common in malware campaigns) ---

// DefaultList returns a small embedded list of passwords frequently used to
// protect malicious attachments, with the empty password first.
func DefaultList() Source {
	return Explicit(defaultPasswords...)
}

var defaultPasswords = []string{
	"", "infected", "virus", "malware", "password", "Password", "PASSWORD",
	"123456", "1234", "12345", "123456789", "0000", "1111",
	"test", "abc123", "letmein", "changeme", "secret", "admin",
	"attachment", "invoice", "document", "confidential", "open", "unzip",
	"sample", "email", "zip", "pass", "qwerty",
}

// --- ordered chain with de-duplication ---

type chainSource struct {
	sources []Source
	i       int
	seen    map[string]struct{}
	maxSeen int
}

// Chain concatenates sources in order, skipping duplicates seen earlier in the
// stream. De-duplication memory is bounded; beyond the bound, duplicates may
// pass through (correctness is unaffected, only efficiency).
func Chain(sources ...Source) Source {
	return &chainSource{sources: sources, seen: make(map[string]struct{}), maxSeen: 1 << 20}
}

func (c *chainSource) Next() ([]byte, error) {
	for c.i < len(c.sources) {
		v, err := c.sources[c.i].Next()
		if err == io.EOF {
			c.i++
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(c.seen) < c.maxSeen {
			k := string(v)
			if _, dup := c.seen[k]; dup {
				continue
			}
			c.seen[k] = struct{}{}
		}
		return v, nil
	}
	return nil, io.EOF
}

func (c *chainSource) Len() int64 {
	var total int64
	for _, s := range c.sources {
		n := s.Len()
		if n < 0 {
			return -1
		}
		total += n
	}
	return total
}

func (c *chainSource) Reset() error {
	c.i = 0
	c.seen = make(map[string]struct{})
	for _, s := range c.sources {
		if err := s.Reset(); err != nil {
			return err
		}
	}
	return nil
}
