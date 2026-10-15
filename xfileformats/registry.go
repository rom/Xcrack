package xfileformats

import "sort"

// Registry holds the set of formats a caller has enabled. Formats are
// registered EXPLICITLY (not via init side effects) so a consumer controls
// exactly which parsers are exposed to hostile input.
//
// A Registry is safe for concurrent reads once populated; Register is not safe
// to call concurrently with Detect.
type Registry struct {
	formats []Format
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry { return &Registry{} }

// Register adds a format. Later registrations of the same Name replace earlier
// ones so a consumer can override a built-in.
func (r *Registry) Register(f Format) {
	for i, existing := range r.formats {
		if existing.Name() == f.Name() {
			r.formats[i] = f
			return
		}
	}
	r.formats = append(r.formats, f)
}

// Formats returns the registered formats (in registration order).
func (r *Registry) Formats() []Format {
	out := make([]Format, len(r.formats))
	copy(out, r.formats)
	return out
}

// Detect returns the registered format with the highest detection confidence
// for peek, or ErrUnknownFormat if none claims it. Ties are broken by
// registration order (earlier wins) for determinism.
func (r *Registry) Detect(peek []byte) (Format, error) {
	type scored struct {
		f    Format
		conf float64
		idx  int
	}
	var matches []scored
	for i, f := range r.formats {
		conf, ok := safeDetect(f, peek)
		if ok {
			matches = append(matches, scored{f, conf, i})
		}
	}
	if len(matches) == 0 {
		return nil, ErrUnknownFormat
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].conf != matches[j].conf {
			return matches[i].conf > matches[j].conf
		}
		return matches[i].idx < matches[j].idx
	})
	return matches[0].f, nil
}

// safeDetect runs a format's Detect with a recover() guard: a panic in a
// detector (exposed to hostile input) becomes "not detected", never a crash.
func safeDetect(f Format, peek []byte) (conf float64, ok bool) {
	defer func() {
		if recover() != nil {
			conf, ok = 0, false
		}
	}()
	return f.Detect(peek)
}
