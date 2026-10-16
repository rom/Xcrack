package candidates

// Shard restricts a Source to one slice of a sharded keyspace: of every count
// candidates it yields only the one at position index (0-based) — a round-robin
// stride. Running the same search on N machines (or processes) with count = N
// and index = 0..N-1 gives each worker a disjoint 1/N of the keyspace, and
// together they cover all of it: the basis for offline distributed cracking,
// composed with the challenge export/import envelope so every worker probes
// once and then cracks its own shard.
//
// A stride (every N-th candidate) is used rather than N contiguous blocks so
// each shard stays interleaved with the source's own ordering — a
// most-likely-first source (promoted passwords, PCFG, Markov, frequency-sorted
// breach corpus) keeps its likely guesses spread across every shard, instead of
// concentrating them all in shard 0. The whole source is still iterated by each
// worker (cheap I/O), but the expensive KDF/verify is done on only 1/N of it.
//
// count <= 1 returns src unchanged. index is taken modulo count.
func Shard(src Source, index, count int) Source {
	if count <= 1 {
		return src
	}
	index = ((index % count) + count) % count
	return &shardSource{src: src, index: index, count: count}
}

type shardSource struct {
	src   Source
	index int
	count int
	pos   int
}

func (s *shardSource) Next() ([]byte, error) {
	for {
		b, err := s.src.Next()
		if err != nil {
			return nil, err
		}
		mine := s.pos%s.count == s.index
		s.pos++
		if mine {
			return b, nil
		}
	}
}

func (s *shardSource) Len() int64 {
	n := s.src.Len()
	if n < 0 {
		return -1
	}
	// Candidates at positions index, index+count, index+2count, ... below n.
	if int64(s.index) >= n {
		return 0
	}
	return (n - int64(s.index) + int64(s.count) - 1) / int64(s.count)
}

func (s *shardSource) Reset() error {
	s.pos = 0
	return s.src.Reset()
}

func (s *shardSource) CloneSource() Source {
	cl, ok := s.src.(Cloner)
	if !ok {
		return nil
	}
	inner := cl.CloneSource()
	if inner == nil {
		return nil
	}
	return &shardSource{src: inner, index: s.index, count: s.count}
}
