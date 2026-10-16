package xcrack

import "encoding/hex"

// Report is the stable, serializable projection of a Result: the decomposition
// tree, the recovered passwords, and the run statistics. It is the shared shape
// used by the CLI renderers and the HTTP API so both speak identical JSON.
//
// NOTE: a Report carries recovered passwords and content digests. Callers that
// expose it over a boundary (an API response, a log) must treat it as sensitive
// and apply their own access control.
type Report struct {
	Root      NodeReport  `json:"root"`
	Passwords []string    `json:"recovered_passwords"`
	Stats     ReportStats `json:"stats"`
}

// NodeReport is the serializable projection of one Node. It deliberately does
// not embed content bytes; Size and SHA256 describe the content instead.
type NodeReport struct {
	Path         string       `json:"path"`
	Format       string       `json:"format,omitempty"`
	Status       string       `json:"status"`
	WasEncrypted bool         `json:"encrypted"`
	Password     string       `json:"password,omitempty"`
	Error        string       `json:"error,omitempty"`
	Size         int64        `json:"size,omitempty"`
	SHA256       string       `json:"sha256,omitempty"`
	Children     []NodeReport `json:"children,omitempty"`
}

// ReportStats is the serializable projection of Stats.
type ReportStats struct {
	FilesSeen       int   `json:"files_seen"`
	CandidatesTried int64 `json:"candidates_tried"`
	BytesExtracted  int64 `json:"bytes_extracted"`
	LimitHits       int   `json:"limit_hits"`
	ElapsedMS       int64 `json:"elapsed_ms"`
}

// BuildNodeReport projects a node (and its descendants) into a NodeReport.
func BuildNodeReport(n *Node) NodeReport {
	v := NodeReport{
		Path:         n.Path,
		Format:       n.Format,
		Status:       n.Status.String(),
		WasEncrypted: n.WasEncrypted,
		Password:     n.Password,
	}
	if n.Err != nil {
		v.Error = n.Err.Error()
	}
	if n.Content != nil {
		v.Size = n.Content.Size()
		sum := n.Content.SHA256()
		v.SHA256 = hex.EncodeToString(sum[:])
	}
	for _, c := range n.Children {
		v.Children = append(v.Children, BuildNodeReport(c))
	}
	return v
}

// BuildReport projects a whole Result into a Report.
func BuildReport(res *Result) Report {
	return Report{
		Root:      BuildNodeReport(res.Root),
		Passwords: res.Passwords(),
		Stats: ReportStats{
			FilesSeen:       res.Stats.FilesSeen,
			CandidatesTried: res.Stats.CandidatesTried,
			BytesExtracted:  res.Stats.BytesExtracted,
			LimitHits:       res.Stats.LimitHits,
			ElapsedMS:       res.Stats.Elapsed.Milliseconds(),
		},
	}
}
