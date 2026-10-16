package candidates

import "math"

// Markov is an order-1 (byte-bigram) statistical model of what passwords look
// like. Trained on a sample of real passwords, it scores an arbitrary candidate
// by how "password-like" it is, so a wordlist can be reordered to try the
// likeliest candidates first (use with ByScore). It is a ranking heuristic, not
// a generator, and never changes which candidates are tried -- only their order.
type Markov struct {
	// logTrans[a][b] is the smoothed log-probability of byte b following a.
	// Index 256 is the virtual start/end state.
	logTrans [257][257]float64
}

const markovStart = 256

// TrainMarkov builds a model from sample words using add-one (Laplace)
// smoothing, so unseen transitions get a small non-zero probability rather than
// -Inf. An empty sample yields a uniform model (every candidate scores equally).
func TrainMarkov(samples [][]byte) *Markov {
	var counts [257][257]float64
	// Laplace smoothing: start every transition at 1.
	for a := 0; a < 257; a++ {
		for b := 0; b < 257; b++ {
			counts[a][b] = 1
		}
	}
	for _, w := range samples {
		prev := markovStart
		for _, c := range w {
			counts[prev][int(c)]++
			prev = int(c)
		}
		counts[prev][markovStart]++ // transition to end
	}
	m := &Markov{}
	for a := 0; a < 257; a++ {
		var total float64
		for b := 0; b < 257; b++ {
			total += counts[a][b]
		}
		for b := 0; b < 257; b++ {
			m.logTrans[a][b] = math.Log(counts[a][b] / total)
		}
	}
	return m
}

// Score returns the length-normalized average log-probability of candidate
// under the model (higher = more likely). Length normalization keeps the
// ranking from simply preferring short strings. An empty candidate scores the
// start->end transition.
func (m *Markov) Score(candidate []byte) float64 {
	prev := markovStart
	var sum float64
	n := 0
	for _, c := range candidate {
		sum += m.logTrans[prev][int(c)]
		prev = int(c)
		n++
	}
	sum += m.logTrans[prev][markovStart]
	n++
	return sum / float64(n)
}

// Scorer returns m.Score as a Scorer for ByScore.
func (m *Markov) Scorer() Scorer { return m.Score }
