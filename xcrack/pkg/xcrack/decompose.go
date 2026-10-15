package xcrack

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/attack"
	"github.com/rom/xfileformats"
)

// engine carries the per-run configuration and the shared cracking engine.
type engine struct {
	opts    Options
	cracker *attack.Engine
	spill   *spillSet
}

// decompose detects, (if needed) decrypts, and recursively decomposes data into
// a Node. It is the single node factory: callers that have already decrypted an
// entry still route its plaintext bytes through here so nested containers are
// handled uniformly.
func (e *engine) decompose(ctx context.Context, path string, data []byte, depth int, ancestors [][32]byte, promoted *[]string, acc *accounting, base CandidateSource) *Node {
	n := &Node{Path: path}

	if err := ctx.Err(); err != nil {
		n.Status = StatusError
		n.Err = err
		return n
	}
	if !acc.addNode() {
		n.Status = StatusLimitExceeded
		acc.limitHit()
		return n
	}
	if depth > e.opts.Limits.MaxDepth {
		n.Status = StatusLimitExceeded
		acc.limitHit()
		return n
	}
	sum := sha256.Sum256(data)
	for _, a := range ancestors {
		if a == sum { // this content is one of its own ancestors => cycle/quine
			n.Status = StatusLimitExceeded
			acc.limitHit()
			return n
		}
	}
	if !acc.reserveBytes(int64(len(data))) {
		n.Status = StatusLimitExceeded
		acc.limitHit()
		return n
	}

	fm, err := e.opts.Registry.Detect(peek(data))
	if err != nil {
		// unknown format => plaintext leaf
		n.Status = StatusPlain
		n.Content = e.spill.materialize(data)
		return n
	}
	n.Format = fm.Name()
	caps := fm.Caps()

	// Whole-file encryption (e.g. an encrypted OOXML/PDF wrapper). ZIP is NOT
	// handled here -- its encryption is per-entry (see the Container branch).
	if enc, ok := fm.(xfileformats.Encrypted); ok && caps.Encrypted {
		ra := bytes.NewReader(data)
		ch, perr := safeProbe(enc, ra, int64(len(data)))
		if perr != nil {
			n.Status = StatusError
			n.Err = perr
			return n
		}
		verify := func(pw []byte) (bool, error) {
			ok, _, verr := enc.Verify(ch, pw)
			return ok, verr
		}
		pw, found := e.searchTarget(ctx, path, verify, depth, promoted, acc, base)
		if !found {
			n.WasEncrypted = true
			n.Status = StatusLocked
			return n
		}
		e.promote(promoted, pw)
		_, key, _ := enc.Verify(ch, []byte(pw))
		pr, derr := safeDecrypt(enc, ra, int64(len(data)), ch, key)
		if derr != nil {
			n.WasEncrypted = true
			n.Status = StatusError
			n.Err = derr
			return n
		}
		plain, rerr := readBounded(pr, e.opts.Limits.MaxEntrySize)
		if rerr != nil {
			n.WasEncrypted = true
			n.Status = StatusError
			n.Err = rerr
			return n
		}
		n.WasEncrypted = true
		n.Password = pw
		n.Status = StatusDecrypted
		// Re-detect the decrypted content and fall through so a decrypted
		// container is enumerated below.
		data = plain
		sum = sha256.Sum256(data)
		if fm2, derr := e.opts.Registry.Detect(peek(data)); derr == nil {
			fm = fm2
			caps = fm.Caps()
		} else {
			caps = xfileformats.Caps{}
		}
	}

	// Container with child entries.
	if cont, ok := fm.(xfileformats.Container); ok && caps.Container && !e.opts.NoRecurse && (!caps.Explodable || e.opts.ExplodeDocuments) {
		entries, eerr := safeEntries(cont, bytes.NewReader(data), int64(len(data)))
		if eerr != nil {
			if !n.WasEncrypted {
				n.Format = fm.Name()
			}
			n.Status = StatusError
			n.Err = eerr
			return n
		}
		childAnc := append(append([][32]byte{}, ancestors...), sum)
		n.Children = make([]*Node, len(entries))
		for i, entry := range entries {
			n.Children[i] = e.processEntry(ctx, joinPath(path, entry.Path), entry, depth+1, childAnc, promoted, acc, base)
		}
		return n
	}

	// Leaf content.
	if !n.WasEncrypted {
		n.Status = StatusPlain
	}
	n.Content = e.spill.materialize(data)
	return n
}

// processEntry handles one container entry: find its password if encrypted,
// read its plaintext, and route it back through decompose so nested layers are
// handled. It then annotates the child node with the encryption outcome.
func (e *engine) processEntry(ctx context.Context, childPath string, entry *xfileformats.Entry, depth int, ancestors [][32]byte, promoted *[]string, acc *accounting, base CandidateSource) *Node {
	if entry.Encrypted {
		verify := entry.Verify
		if verify == nil {
			return e.errNode(childPath, fmt.Errorf("%w: entry has no verifier", xfileformats.ErrUnsupported), acc)
		}
		pw, found := e.searchTarget(ctx, childPath, verify, depth, promoted, acc, base)
		if !found {
			n := &Node{Path: childPath, WasEncrypted: true, Status: StatusLocked}
			if !acc.addNode() {
				n.Status = StatusLimitExceeded
				acc.limitHit()
			}
			return n
		}
		e.promote(promoted, pw)
		r, oerr := safeOpen(entry, []byte(pw))
		if oerr != nil {
			return e.errNode(childPath, oerr, acc)
		}
		data, rerr := readBounded(r, e.opts.Limits.MaxEntrySize)
		if rerr != nil {
			return e.errNode(childPath, rerr, acc)
		}
		child := e.decompose(ctx, childPath, data, depth, ancestors, promoted, acc, base)
		child.WasEncrypted = true
		child.Password = pw
		if child.Status == StatusPlain {
			child.Status = StatusDecrypted
		}
		return child
	}

	r, oerr := safeOpen(entry, nil)
	if oerr != nil {
		return e.errNode(childPath, oerr, acc)
	}
	data, rerr := readBounded(r, e.opts.Limits.MaxEntrySize)
	if rerr != nil {
		return e.errNode(childPath, rerr, acc)
	}
	return e.decompose(ctx, childPath, data, depth, ancestors, promoted, acc, base)
}

// searchTarget finds a password that satisfies verify: it tries promoted
// (ancestor) passwords first (cheap, usually hits for nested archives), then
// runs a concurrent search over the base candidate source.
func (e *engine) searchTarget(ctx context.Context, path string, verify func([]byte) (bool, error), depth int, promoted *[]string, acc *accounting, base CandidateSource) (string, bool) {
	if !e.opts.NoPromote {
		for _, pw := range *promoted {
			if ctx.Err() != nil {
				return "", false
			}
			ok, err := safeVerify(verify, []byte(pw))
			acc.addCandidates(1)
			if err == nil && ok {
				e.found(path, pw)
				return pw, true
			}
		}
	}
	if base == nil {
		return "", false
	}
	probe := func(pw []byte) (bool, error) { return safeVerify(verify, pw) }
	pw, found, tried, err := e.cracker.Crack(ctx, probe, base)
	acc.addCandidates(tried)
	if e.opts.OnProgress != nil {
		e.opts.OnProgress(Progress{Path: path, CandidatesTried: acc.candidatesTried(), Depth: depth})
	}
	if err != nil || !found {
		return "", false
	}
	e.found(path, string(pw))
	return string(pw), true
}

func (e *engine) promote(promoted *[]string, pw string) {
	if e.opts.NoPromote {
		return
	}
	for _, p := range *promoted {
		if p == pw {
			return
		}
	}
	*promoted = append(*promoted, pw)
}

func (e *engine) found(path, pw string) {
	if e.opts.OnFound != nil {
		e.opts.OnFound(Found{Path: path, Password: pw})
	}
}

func (e *engine) errNode(path string, err error, acc *accounting) *Node {
	n := &Node{Path: path, Status: StatusError, Err: err}
	if !acc.addNode() {
		n.Status = StatusLimitExceeded
		acc.limitHit()
	}
	return n
}

// --- small helpers ---

func peek(data []byte) []byte {
	if len(data) > xfileformats.PeekSize {
		return data[:xfileformats.PeekSize]
	}
	return data
}

func joinPath(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "!/" + child
}

// readBounded reads up to max bytes; if the source has more, it returns an
// error so oversize content is reported rather than silently truncated.
func readBounded(r io.Reader, max int64) ([]byte, error) {
	if max <= 0 {
		return io.ReadAll(r)
	}
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%w: entry exceeds MaxEntrySize", xfileformats.ErrLimitExceeded)
	}
	return data, nil
}

// --- recover() guards around format calls (hostile-input safety) ---

func safeProbe(enc xfileformats.Encrypted, r io.ReaderAt, size int64) (ch *xcrypto.Challenge, err error) {
	defer guard(&err)
	return enc.Probe(r, size)
}

func safeDecrypt(enc xfileformats.Encrypted, r io.ReaderAt, size int64, ch *xcrypto.Challenge, key []byte) (out io.Reader, err error) {
	defer guard(&err)
	return enc.Decrypt(r, size, ch, key)
}

func safeEntries(c xfileformats.Container, r io.ReaderAt, size int64) (entries []*xfileformats.Entry, err error) {
	defer guard(&err)
	return c.Entries(r, size)
}

func safeOpen(entry *xfileformats.Entry, pw []byte) (r io.Reader, err error) {
	defer guard(&err)
	return entry.Open(pw)
}

func safeVerify(verify func([]byte) (bool, error), pw []byte) (ok bool, err error) {
	defer guard(&err)
	return verify(pw)
}

// guard converts a panic in a format parser (exposed to hostile input) into an
// error, so a single malformed file never crashes the engine.
func guard(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("%w: panic in format handler: %v", xfileformats.ErrMalformed, r)
	}
}
