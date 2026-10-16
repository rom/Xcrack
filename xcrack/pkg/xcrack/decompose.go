package xcrack

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/attack"
	"github.com/rom/xcrypto/candidates"
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
func (e *engine) decompose(ctx context.Context, path string, data []byte, depth int, ancestors [][32]byte, prom *promoter, acc *accounting, base CandidateSource, ctxText []byte) *Node {
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

	// Select a format. Several formats can claim the same magic -- notably the
	// CFB/OLE2 compound-file signature, shared by encrypted OOXML and the legacy
	// .doc/.xls/.ppt binaries -- so we try detection candidates in confidence
	// order and let one decline (ErrUnsupported) so the next can handle the file.
	var (
		fm        xfileformats.Format
		caps      xfileformats.Caps
		ch        *xcrypto.Challenge
		enc       xfileformats.Encrypted
		encrypted bool
	)
	for _, cand := range e.opts.Registry.DetectAll(peek(data)) {
		cc := cand.Caps()
		if ce, ok := cand.(xfileformats.Encrypted); ok && cc.Encrypted {
			c, perr := safeProbe(ce, bytes.NewReader(data), int64(len(data)))
			if perr != nil {
				if errors.Is(perr, xfileformats.ErrUnsupported) || errors.Is(perr, xfileformats.ErrUnknownFormat) {
					continue // recognizes the magic but not this file; try next
				}
				n.Format = cand.Name()
				if errors.Is(perr, xfileformats.ErrNotEncrypted) {
					// recognized but plaintext: a plain leaf.
					n.Status = StatusPlain
					n.Content = e.spill.materialize(data)
					return n
				}
				n.Status = StatusError
				n.Err = perr
				return n
			}
			fm, caps, ch, enc, encrypted = cand, cc, c, ce, true
			break
		}
		// A container (or a format with neither capability) binds without a
		// probe; the container branch below validates it and can fall back to a
		// leaf if it declines.
		fm, caps = cand, cc
		break
	}
	if fm == nil {
		// Unknown format, or every encrypted candidate declined => plaintext leaf.
		n.Status = StatusPlain
		n.Content = e.spill.materialize(data)
		return n
	}
	n.Format = fm.Name()

	// Whole-file encryption (e.g. an encrypted OOXML/PDF wrapper). ZIP is NOT
	// handled here -- its encryption is per-entry (see the Container branch).
	if encrypted {
		ra := bytes.NewReader(data)
		verify := func(pw []byte) (bool, error) {
			ok, _, verr := enc.Verify(ch, pw)
			return ok, verr
		}
		pw, found := e.searchTarget(ctx, path, verify, depth, prom, acc, base, ctxText, ch.Hint)
		if !found {
			n.WasEncrypted = true
			n.Status = StatusLocked
			return n
		}
		prom.add(pw)
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
		// container is enumerated below. The purpose here is strictly to find a
		// container to decompose, so pick the highest-confidence CONTAINER among
		// the candidates rather than the single best format -- a non-container
		// format that merely outranks it (e.g. the whole-file iwork detector,
		// which shares the ZIP magic) must not shadow the real zip container.
		data = plain
		sum = sha256.Sum256(data)
		caps = xfileformats.Caps{}
		for _, cand := range e.opts.Registry.DetectAll(peek(data)) {
			if cand.Caps().Container {
				fm = cand
				caps = cand.Caps()
				break
			}
		}
	}

	// Container with child entries.
	if cont, ok := fm.(xfileformats.Container); ok && caps.Container && !e.opts.NoRecurse && (!caps.Explodable || e.opts.ExplodeDocuments) {
		entries, eerr := safeEntries(cont, bytes.NewReader(data), int64(len(data)))
		if eerr != nil {
			// A container that recognizes the magic but not this specific file
			// (e.g. an OLE2 compound file that is neither encrypted OOXML nor a
			// legacy Office binary) falls back to a plain leaf rather than erroring.
			if errors.Is(eerr, xfileformats.ErrUnsupported) || errors.Is(eerr, xfileformats.ErrUnknownFormat) || errors.Is(eerr, xfileformats.ErrNotEncrypted) {
				if !n.WasEncrypted {
					n.Status = StatusPlain
				}
				n.Content = e.spill.materialize(data)
				return n
			}
			if !n.WasEncrypted {
				n.Format = fm.Name()
			}
			n.Status = StatusError
			n.Err = eerr
			return n
		}
		childAnc := append(append([][32]byte{}, ancestors...), sum)
		n.Children = make([]*Node, len(entries))
		// Seed children with plaintext harvested from this container's own plain
		// entries (e.g. a readme or an email body that names the password), plus
		// any text inherited from ancestors.
		childCtx := ctxText
		if e.opts.ContextCandidates {
			childCtx = e.harvestText(entries, ctxText)
		}
		e.processEntries(ctx, path, entries, depth+1, childAnc, prom, acc, base, childCtx, n.Children)
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
func (e *engine) processEntry(ctx context.Context, childPath string, entry *xfileformats.Entry, depth int, ancestors [][32]byte, prom *promoter, acc *accounting, base CandidateSource, ctxText []byte) *Node {
	if entry.Encrypted {
		// Known-plaintext key recovery (no password), when enabled and the entry's
		// scheme supports it (ZipCrypto). Tried before the password search; on
		// failure (wrong/absent known plaintext) we fall through to it.
		if kp := e.opts.KnownPlaintext; kp.For != nil && entry.KeyRecover != nil {
			if known := kp.For(childPath); len(known) > 0 {
				if child, ok := e.recoverWithPlaintext(ctx, childPath, entry, known, kp.Offload, depth, ancestors, prom, acc, base, ctxText); ok {
					return child
				}
			}
		}
		verify := entry.Verify
		if verify == nil {
			return e.errNode(childPath, fmt.Errorf("%w: entry has no verifier", xfileformats.ErrUnsupported), acc)
		}
		pw, found := e.searchTarget(ctx, childPath, verify, depth, prom, acc, base, ctxText, hintOf(entry.Challenge))
		if !found {
			n := &Node{Path: childPath, WasEncrypted: true, Status: StatusLocked}
			if !acc.addNode() {
				n.Status = StatusLimitExceeded
				acc.limitHit()
			}
			return n
		}
		prom.add(pw)
		r, oerr := safeOpen(entry, []byte(pw))
		if oerr != nil {
			return e.errNode(childPath, oerr, acc)
		}
		data, rerr := readBounded(r, e.opts.Limits.MaxEntrySize)
		if rerr != nil {
			return e.errNode(childPath, rerr, acc)
		}
		child := e.decompose(ctx, childPath, data, depth, ancestors, prom, acc, base, ctxText)
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
	return e.decompose(ctx, childPath, data, depth, ancestors, prom, acc, base, ctxText)
}

// recoverWithPlaintext attempts a known-plaintext key recovery for an encrypted
// entry and, on success, decomposes the recovered content. It returns ok=false
// (without producing a node) when recovery does not apply or fails, so the caller
// falls back to the password search. The key-recovery closure re-validates its
// result, so a wrong `known` cannot yield a false positive.
func (e *engine) recoverWithPlaintext(ctx context.Context, childPath string, entry *xfileformats.Entry, known []byte, offload any, depth int, ancestors [][32]byte, prom *promoter, acc *accounting, base CandidateSource, ctxText []byte) (*Node, bool) {
	r, ok, err := entry.KeyRecover(ctx, known, offload)
	if err != nil || !ok {
		return nil, false
	}
	data, rerr := readBounded(r, e.opts.Limits.MaxEntrySize)
	if rerr != nil {
		return e.errNode(childPath, rerr, acc), true
	}
	if e.opts.OnFound != nil {
		e.opts.OnFound(Found{Path: childPath, KeyRecovered: true})
	}
	child := e.decompose(ctx, childPath, data, depth, ancestors, prom, acc, base, ctxText)
	child.WasEncrypted = true
	child.KeyRecovered = true
	if child.Status == StatusPlain {
		child.Status = StatusDecrypted
	}
	return child, true
}

// searchTarget finds a password that satisfies verify: it tries promoted
// (ancestor) passwords first (cheap, usually hits for nested archives), then
// runs a concurrent search over the base candidate source.
func (e *engine) searchTarget(ctx context.Context, path string, verify func([]byte) (bool, error), depth int, prom *promoter, acc *accounting, base CandidateSource, ctxText []byte, hint string) (string, bool) {
	// Proven passwords from outer layers are tried first; FastReject is NOT
	// applied to them (they are evidence, not guesses).
	for _, pw := range prom.snapshot() {
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
	reject := e.opts.FastReject
	// Embedded password hint (e.g. the iWork `.iwph` or a ZIP comment): the
	// strongest per-file signal, so it is tried right after promoted passwords.
	// Each hint-derived base word is optionally expanded by the configured rule
	// mangler (Options.HintRules). Subject to FastReject like any guess.
	if e.opts.HintCandidates && hint != "" {
		for _, hw := range candidates.FromHint(hint, hintCandidateMax) {
			words := []string{hw}
			if e.opts.HintRules != nil {
				words = append(words, e.opts.HintRules(hw)...)
			}
			for _, cand := range words {
				if ctx.Err() != nil {
					return "", false
				}
				if reject != nil && reject(path, []byte(cand)) {
					continue
				}
				ok, err := safeVerify(verify, []byte(cand))
				acc.addCandidates(1)
				if err == nil && ok {
					e.found(path, cand)
					return cand, true
				}
			}
		}
	}
	// Context/association candidates: derived from the node name and any text
	// harvested from plain sibling entries. Tried after promotion, before the
	// general keyspace. Subject to FastReject like any other guess.
	if e.opts.ContextCandidates {
		for _, pw := range e.contextCandidates(path, ctxText) {
			if ctx.Err() != nil {
				return "", false
			}
			if reject != nil && reject(path, []byte(pw)) {
				continue
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
	probe := func(pw []byte) (bool, error) {
		if reject != nil && reject(path, pw) {
			return false, nil // cheaply rejected: definitely not the password
		}
		return safeVerify(verify, pw)
	}
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

// promoter holds passwords recovered in outer layers for "promotion" to inner
// layers. It is safe for concurrent use so siblings can be processed in
// parallel. When shared is non-nil (Options.CorpusPromotion), it also reads
// from and writes through to a Pool-level learnedSet, so finds cross file
// boundaries within a run and the most repeatedly-successful passwords are
// tried first.
type promoter struct {
	mu     sync.Mutex
	pw     []string
	seen   map[string]struct{}
	on     bool
	shared *learnedSet
}

func newPromoter(on bool, shared *learnedSet) *promoter {
	return &promoter{on: on, seen: make(map[string]struct{}), shared: shared}
}

func (p *promoter) snapshot() []string {
	if !p.on {
		return nil
	}
	p.mu.Lock()
	local := make([]string, len(p.pw))
	copy(local, p.pw)
	p.mu.Unlock()
	if p.shared == nil {
		return local
	}
	// Corpus-wide proven passwords first (ordered by observed success), then this
	// run's own finds not already present.
	ordered := p.shared.snapshotOrdered()
	seen := make(map[string]struct{}, len(ordered)+len(local))
	out := make([]string, 0, len(ordered)+len(local))
	for _, s := range ordered {
		if _, dup := seen[s]; !dup {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	for _, s := range local {
		if _, dup := seen[s]; !dup {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

func (p *promoter) add(s string) {
	if !p.on {
		return
	}
	p.mu.Lock()
	if _, dup := p.seen[s]; !dup {
		p.seen[s] = struct{}{}
		p.pw = append(p.pw, s)
	}
	p.mu.Unlock()
	if p.shared != nil {
		p.shared.add(s)
	}
}

// processEntries processes a container's entries into out[i], either
// sequentially or -- when FileConcurrency > 1 and the candidate source can be
// cloned so each worker iterates its own copy -- across up to FileConcurrency
// goroutines. Result order is preserved by writing to out by index. The attack
// engine's global semaphore still bounds total candidate testers, so this only
// adds parallelism to unpacking/decompression and overlaps independent searches.
func (e *engine) processEntries(ctx context.Context, parent string, entries []*xfileformats.Entry, depth int, ancestors [][32]byte, prom *promoter, acc *accounting, base CandidateSource, ctxText []byte, out []*Node) {
	jobs := e.opts.FileConcurrency
	_, cloneable := cloneBase(base)
	if jobs <= 1 || len(entries) <= 1 || !cloneable {
		for i, entry := range entries {
			out[i] = e.processEntry(ctx, joinPath(parent, entry.Path), entry, depth, ancestors, prom, acc, base, ctxText)
		}
		return
	}
	sem := make(chan struct{}, jobs)
	var wg sync.WaitGroup
	for i, entry := range entries {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, entry *xfileformats.Entry) {
			defer wg.Done()
			defer func() { <-sem }()
			b, _ := cloneBase(base) // independent iterator for this sibling
			out[i] = e.processEntry(ctx, joinPath(parent, entry.Path), entry, depth, ancestors, prom, acc, b, ctxText)
		}(i, entry)
	}
	wg.Wait()
	for i := range out {
		if out[i] == nil {
			out[i] = &Node{Path: joinPath(parent, entries[i].Path), Status: StatusError, Err: context.Canceled}
			acc.addNode()
		}
	}
}

// cloneBase returns an independent copy of base for concurrent use. A nil base
// is safe to share (no iteration state); otherwise the source must implement
// candidates.Cloner and successfully clone.
func cloneBase(base CandidateSource) (CandidateSource, bool) {
	if base == nil {
		return nil, true
	}
	c, ok := base.(candidates.Cloner)
	if !ok {
		return nil, false
	}
	cl := c.CloneSource()
	if cl == nil {
		return nil, false
	}
	return cl, true
}

// Context-candidate harvesting bounds. The harvested text is auxiliary (it only
// seeds guesses), so reads here are capped independently of the content budget.
const (
	harvestPerEntry  = 64 << 10  // bytes read per plain entry
	harvestTotal     = 256 << 10 // total harvested-text budget per container
	harvestMaxHint   = 4 << 20   // skip entries whose declared size hint exceeds this
	contextTextMax   = 64        // max text-derived candidates per search
	hintCandidateMax = 64        // max base words derived from an embedded hint
)

// hintOf returns a Challenge's embedded password hint, or "" when absent.
func hintOf(ch *xcrypto.Challenge) string {
	if ch == nil {
		return ""
	}
	return ch.Hint
}

// contextCandidates returns the de-duplicated association guesses for a node:
// strings derived from its name, then any extracted from harvested sibling text.
func (e *engine) contextCandidates(path string, ctxText []byte) []string {
	pws := candidates.FromName(path)
	if len(ctxText) > 0 {
		pws = append(pws, candidates.FromText(ctxText, contextTextMax)...)
	}
	seen := make(map[string]bool, len(pws))
	out := pws[:0]
	for _, p := range pws {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// harvestText concatenates incoming (ancestor) context with plaintext read from
// the container's own plain entries -- e.g. a README or an email body that names
// the password for an encrypted sibling. Reads are bounded per entry and in
// total; encrypted entries cannot be harvested (chicken-and-egg).
func (e *engine) harvestText(entries []*xfileformats.Entry, incoming []byte) []byte {
	buf := make([]byte, 0, len(incoming)+1024)
	buf = append(buf, incoming...)
	budget := harvestTotal - len(incoming)
	for _, en := range entries {
		if budget <= 0 {
			break
		}
		if en == nil || en.Encrypted || en.Open == nil || en.Size > harvestMaxHint {
			continue
		}
		r, err := safeOpen(en, nil)
		if err != nil {
			continue
		}
		lim := harvestPerEntry
		if lim > budget {
			lim = budget
		}
		chunk, _ := io.ReadAll(io.LimitReader(r, int64(lim)))
		if len(chunk) == 0 {
			continue
		}
		buf = append(buf, ' ')
		buf = append(buf, chunk...)
		budget -= len(chunk)
	}
	return buf
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
