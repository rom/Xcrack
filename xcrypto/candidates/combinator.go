package candidates

import "io"

// maxComboInput bounds how many items of each input list a combinator
// materializes (the product is generated lazily, but the inputs are held).
const maxComboInput = 1 << 20

// Combinator yields every left+sep+right pairing (hashcat's combinator attack).
// Both inputs are drained up to maxComboInput items; the cartesian product is
// generated lazily. sep may be nil.
func Combinator(left, right Source, sep []byte) Source {
	return &comboSource{
		left:  drainTo(left, maxComboInput),
		right: drainTo(right, maxComboInput),
		sep:   append([]byte{}, sep...),
	}
}

type comboSource struct {
	left, right [][]byte
	sep         []byte
	i, j        int
}

func (c *comboSource) Next() ([]byte, error) {
	if len(c.left) == 0 || len(c.right) == 0 || c.i >= len(c.left) {
		return nil, io.EOF
	}
	l, r := c.left[c.i], c.right[c.j]
	out := make([]byte, 0, len(l)+len(c.sep)+len(r))
	out = append(out, l...)
	out = append(out, c.sep...)
	out = append(out, r...)
	c.j++
	if c.j >= len(c.right) {
		c.j = 0
		c.i++
	}
	return out, nil
}

func (c *comboSource) Len() int64 { return int64(len(c.left)) * int64(len(c.right)) }

func (c *comboSource) Reset() error { c.i, c.j = 0, 0; return nil }

func (c *comboSource) CloneSource() Source {
	return &comboSource{left: c.left, right: c.right, sep: c.sep}
}

// drainTo reads up to max items from src into a slice (copying each).
func drainTo(src Source, max int) [][]byte {
	if src == nil {
		return nil
	}
	var out [][]byte
	for len(out) < max {
		b, err := src.Next()
		if err != nil {
			break
		}
		out = append(out, append([]byte(nil), b...))
	}
	return out
}
