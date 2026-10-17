package xcrack

import (
	"context"
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
func (e *engine) decompose(ctx context.Context, path string, src *source, depth int, ancestors [][32]byte, prom *promoter, acc *accounting, base CandidateSource, ctxText []byte) *Node {
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
	sum := src.sum
	for _, a := range ancestors {
		if a == sum { // this content is one of its own ancestors => cycle/quine
			n.Status = StatusLimitExceeded
			acc.limitHit()
			return n
		}
	}
	if !acc.reserveBytes(src.size) {
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
	for _, cand := range e.opts.Registry.DetectAll(src.peek()) {
		cc := cand.Caps()
		if ce, ok := cand.(xfileformats.Encrypted); ok && cc.Encrypted {
			c, perr := safeProbe(ce, src.readerAt(), src.size)
			if perr != nil {
				if errors.Is(perr, xfileformats.ErrUnsupported) || errors.Is(perr, xfileformats.ErrUnknownFormat) {
					continue // recognizes the magic but not this file; try next
				}
				n.Format = cand.Name()
				if errors.Is(perr, xfileformats.ErrNotEncrypted) {
					// recognized but plaintext: a plain leaf.
					n.Status = StatusPlain
					n.Content = src
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
		n.Content = src
		return n
	}
	n.Format = fm.Name()

	// Whole-file encryption (e.g. an encrypted OOXML/PDF wrapper). ZIP is NOT
	// handled here -- its encryption is per-entry (see the Container branch).
	if encrypted {
		verify := func(pw []byte) (bool, error) {
			ok, _, verr := enc.Verify(ch, pw)
			return ok, verr
		}
		// A whole-file format may expose a batchable KDF for the GPU tier; the
		// engine uses it only when an accelerator is configured (see searchTarget).
		var ak *xfileformats.AccelKDF
		if e.opts.Accelerator != nil {
			if ae, ok := enc.(xfileformats.Accelerable); ok {
				if k, ok := safeAccelKDF(ae, ch); ok {
					ak = &k
				}
			}
		}
		pw, found := e.searchTarget(ctx, path, verify, depth, prom, acc, base, ctxText, ch.Hint, ak)
		if !found {
			n.WasEncrypted = true
			n.Status = StatusLocked
			return n
		}
		prom.add(pw)
		_, key, _ := enc.Verify(ch, []byte(pw))
		pr, derr := safeDecrypt(enc, src.readerAt(), src.size, ch, key)
		if derr != nil {
			n.WasEncrypted = true
			n.Status = StatusError
			n.Err = derr
			return n
		}
		// Stream the decrypted payload into a fresh source (to disk if large), so
		// a big decrypted blob is never fully held in RAM.
		plainSrc, rerr := e.spill.materializeReader(pr, e.opts.Limits.MaxEntrySize)
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
		src = plainSrc
		sum = src.sum
		caps = xfileformats.Caps{}
		for _, cand := range e.opts.Registry.DetectAll(src.peek()) {
			if cand.Caps().Container {
				fm = cand
				caps = cand.Caps()
				break
			}
		}
	}

	// Container with child entries.
	if cont, ok := fm.(xfileformats.Container); ok && caps.Container && !e.opts.NoRecurse && (!caps.Explodable || e.opts.ExplodeDocuments) {
		entries, eerr := safeEntries(cont, src.readerAt(), src.size)
		if eerr != nil {
			// A container that recognizes the magic but not this specific file
			// (e.g. an OLE2 compound file that is neither encrypted OOXML nor a
			// legacy Office binary) falls back to a plain leaf rather than erroring.
			if errors.Is(eerr, xfileformats.ErrUnsupported) || errors.Is(eerr, xfileformats.ErrUnknownFormat) || errors.Is(eerr, xfileformats.ErrNotEncrypted) {
				if !n.WasEncrypted {
					n.Status = StatusPlain
				}
				n.Content = src
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
	n.Content = src
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
		pw, found := e.searchTarget(ctx, childPath, verify, depth, prom, acc, base, ctxText, hintOf(entry.Challenge), entry.Accel)
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
		childSrc, rerr := e.spill.materializeReader(r, e.opts.Limits.MaxEntrySize)
		if rerr != nil {
			return e.errNode(childPath, rerr, acc)
		}
		child := e.decompose(ctx, childPath, childSrc, depth, ancestors, prom, acc, base, ctxText)
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
	childSrc, rerr := e.spill.materializeReader(r, e.opts.Limits.MaxEntrySize)
	if rerr != nil {
		return e.errNode(childPath, rerr, acc)
	}
	return e.decompose(ctx, childPath, childSrc, depth, ancestors, prom, acc, base, ctxText)
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
	childSrc, rerr := e.spill.materializeReader(r, e.opts.Limits.MaxEntrySize)
	if rerr != nil {
		return e.errNode(childPath, rerr, acc), true
	}
	if e.opts.OnFound != nil {
		e.opts.OnFound(Found{Path: childPath, KeyRecovered: true})
	}
	child := e.decompose(ctx, childPath, childSrc, depth, ancestors, prom, acc, base, ctxText)
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
func (e *engine) searchTarget(ctx context.Context, path string, verify func([]byte) (bool, error), depth int, prom *promoter, acc *accounting, base CandidateSource, ctxText []byte, hint string, ak *xfileformats.AccelKDF) (string, bool) {
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
	// GPU/accelerator batch path: when an accelerator is configured and this
	// target exposes a batchable PBKDF2-HMAC-SHA1 derivation, sweep the keyspace
	// on the device in bulk instead of one candidate at a time on the CPU. It
	// falls back (fellBack) to the CPU search below when the backend cannot serve
	// these parameters or errors; a hit is always re-checked by ak.Finish, so the
	// device never decides correctness on its own.
	if e.opts.Accelerator != nil && ak != nil {
		pw, found, fellBack := e.crackAccel(ctx, path, ak, depth, acc, base)
		if found {
			e.found(path, pw)
			return pw, true
		}
		if !fellBack {
			return "", false // accelerator swept the whole space, no match
		}
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

// accelBatch is how many candidate passwords are derived per accelerator
// dispatch. Large enough to amortize device round-trips, small enough that a hit
// (or ctx cancellation) is noticed promptly and per-batch host memory stays
// modest (batch*DKLen bytes of output).
const accelBatch = 2048

// crackAccel runs the batched accelerator KDF sweep for a target whose
// verification is one shared PBKDF2-HMAC-SHA1 derivation (ak). It pulls
// candidates from base in batches, derives their keys on the accelerator in a
// single call per batch, and runs ak.Finish (the cheap, authoritative verifier)
// on each derived key. It returns (password, true, false) on a hit. It returns
// (_, false, true) — fellBack — when the backend cannot serve these parameters
// (accel.ErrUnsupported), errors, or returns a malformed result, so the caller
// runs the unchanged CPU search instead. A clean no-match sweep returns
// (_, false, false). Every flagged candidate is re-checked by Finish, so a
// faulty backend can never yield a false positive.
func (e *engine) crackAccel(ctx context.Context, path string, ak *xfileformats.AccelKDF, depth int, acc *accounting, base CandidateSource) (string, bool, bool) {
	if base == nil || ak == nil || ak.Finish == nil {
		return "", false, true // nothing to sweep here; let the CPU path decide
	}
	if err := base.Reset(); err != nil {
		return "", false, true
	}
	reject := e.opts.FastReject
	maxCand := e.opts.Limits.MaxCandidates

	batch := make([][]byte, 0, accelBatch)
	var tried int64
	// flush derives the pending batch on the accelerator and tests each key.
	// hit is the winning password; fellBack signals the caller to use the CPU.
	flush := func() (hit string, found, fellBack bool) {
		if len(batch) == 0 {
			return "", false, false
		}
		dks, err := e.opts.Accelerator.PBKDF2SHA1(batch, ak.Salt, ak.Iter, ak.DKLen)
		if err != nil || len(dks) != len(batch) {
			return "", false, true // unsupported/errored/malformed => CPU fallback
		}
		acc.addCandidates(int64(len(batch)))
		for i, dk := range dks {
			if safeFinish(ak.Finish, dk, batch[i]) {
				return string(batch[i]), true, false
			}
		}
		if e.opts.OnProgress != nil {
			e.opts.OnProgress(Progress{Path: path, CandidatesTried: acc.candidatesTried(), Depth: depth})
		}
		batch = batch[:0]
		return "", false, false
	}

	for {
		if ctx.Err() != nil {
			return "", false, false
		}
		pw, nerr := base.Next()
		if nerr != nil { // io.EOF or a source error: test whatever remains, then stop
			hit, found, fellBack := flush()
			return hit, found, fellBack
		}
		if maxCand > 0 && tried >= maxCand {
			break
		}
		if reject != nil && reject(path, pw) {
			continue // cheaply rejected: never derive it
		}
		tried++
		batch = append(batch, append([]byte(nil), pw...)) // copy: source reuses its buffer
		if len(batch) >= accelBatch {
			if hit, found, fellBack := flush(); found || fellBack {
				return hit, found, fellBack
			}
		}
	}
	// Hit the per-call candidate cap: test the final partial batch and stop.
	hit, found, fellBack := flush()
	return hit, found, fellBack
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

// safeAccelKDF fetches a format's batchable derivation under a recover() guard:
// AccelKDF parses already-probed Challenge data, but the guard keeps a malformed
// Challenge from ever panicking the engine (it just disables acceleration).
func safeAccelKDF(a xfileformats.Accelerable, ch *xcrypto.Challenge) (ak xfileformats.AccelKDF, ok bool) {
	defer func() {
		if recover() != nil {
			ak, ok = xfileformats.AccelKDF{}, false
		}
	}()
	return a.AccelKDF(ch)
}

// safeFinish runs an AccelKDF verifier under a recover() guard. Finish runs the
// scheme's authoritative check on a device-derived key; a panic there (hostile
// input) must degrade to "not a match", never crash the sweep.
func safeFinish(fn func(dk, pw []byte) bool, dk, pw []byte) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return fn(dk, pw)
}

// guard converts a panic in a format parser (exposed to hostile input) into an
// error, so a single malformed file never crashes the engine.
func guard(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("%w: panic in format handler: %v", xfileformats.ErrMalformed, r)
	}
}
