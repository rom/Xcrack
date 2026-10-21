package webui

import (
	"encoding/csv"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xcrack/pkg/xcrack"
)

// Forensic reporting: a self-contained, printable report for a job — case
// metadata, the per-node recovery results (with each node's SHA-256 for evidence
// integrity), and the job's chain of custody (its audit-trail entries). It
// answers the operator-experience gap flagged in the roadmap (reports/case layer
// vs Passware/Elcomsoft). GET /api/v1/jobs/{id}/report?format=html|csv.
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	job := s.jobForRequest(w, r)
	if job == nil {
		return
	}
	v := job.snapshot()
	var custody []auditEntry
	if s.trail != nil {
		custody = s.trail.forTarget(v.ID)
	}
	switch r.URL.Query().Get("format") {
	case "csv":
		s.reportCSV(w, v)
	default:
		s.reportHTML(w, v, custody)
	}
}

// flatNode is one row of the flattened result tree.
type flatNode struct {
	Path, Format, Status, Password, SHA256 string
	Encrypted                              bool
	Size                                   int64
}

func flattenReport(root xcrack.NodeReport, exposeSecrets bool, depth int, out *[]flatNode) {
	pw := root.Password
	if !exposeSecrets {
		if pw != "" {
			pw = "(hidden)"
		}
	}
	path := root.Path
	if path == "" {
		path = "(root)"
	}
	*out = append(*out, flatNode{
		Path: strings.Repeat("· ", depth) + path, Format: root.Format, Status: root.Status,
		Password: pw, SHA256: root.SHA256, Encrypted: root.WasEncrypted, Size: root.Size,
	})
	for _, c := range root.Children {
		flattenReport(c, exposeSecrets, depth+1, out)
	}
}

func (s *Server) jobRows(v JobView) []flatNode {
	var rows []flatNode
	for _, fr := range v.Results {
		if fr.Report == nil {
			rows = append(rows, flatNode{Path: fr.Name, Status: "error", Format: "", Password: fr.Error})
			continue
		}
		flattenReport(fr.Report.Root, s.cfg.ExposeSecrets, 0, &rows)
	}
	return rows
}

func (s *Server) reportCSV(w http.ResponseWriter, v JobView) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "xcrack-report-"+v.ID+".csv"))
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"job_id", "case_id", "examiner", "path", "format", "encrypted", "status", "password", "size", "sha256"})
	for _, n := range s.jobRows(v) {
		_ = cw.Write([]string{
			v.ID, v.CaseID, v.Examiner, strings.TrimLeft(n.Path, "· "), n.Format,
			strconv.FormatBool(n.Encrypted), n.Status, n.Password, strconv.FormatInt(n.Size, 10), n.SHA256,
		})
	}
}

func (s *Server) reportHTML(w http.ResponseWriter, v JobView, custody []auditEntry) {
	e := html.EscapeString
	ts := func(ms int64) string {
		if ms == 0 {
			return "—"
		}
		return time.UnixMilli(ms).UTC().Format("2006-01-02 15:04:05 UTC")
	}
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	b.WriteString(`<title>Xcrack report ` + e(v.ID) + `</title><style>`)
	b.WriteString(`body{font:14px/1.5 system-ui,sans-serif;margin:32px;color:#111}h1{font-size:20px}h2{font-size:15px;margin-top:24px;border-bottom:1px solid #ccc;padding-bottom:4px}` +
		`table{border-collapse:collapse;width:100%;margin:8px 0}th,td{border:1px solid #ccc;padding:4px 8px;text-align:left;font-size:12px;vertical-align:top}` +
		`th{background:#f4f4f4}code{font-family:ui-monospace,monospace;font-size:11px;word-break:break-all}.meta td:first-child{width:160px;color:#555}` +
		`.s-decrypted{color:#0a0}.s-locked{color:#a00}@media print{body{margin:0}}</style></head><body>`)
	b.WriteString(`<h1>Xcrack recovery report</h1>`)
	b.WriteString(`<p>Generated ` + ts(time.Now().UnixMilli()) + `. This is a point-in-time record; recovered content is identified by SHA-256.</p>`)

	b.WriteString(`<h2>Case &amp; job</h2><table class="meta">`)
	row := func(k, val string) {
		if val == "" {
			val = "—"
		}
		b.WriteString(`<tr><td>` + e(k) + `</td><td>` + e(val) + `</td></tr>`)
	}
	row("Case ID", v.CaseID)
	row("Examiner", v.Examiner)
	row("Job ID", v.ID)
	row("Type", kindLabel(v.Kind))
	row("Owner", v.Owner)
	row("State", string(v.State))
	row("Files", strings.Join(v.Files, ", "))
	row("Nodes decrypted", strconv.Itoa(v.Decrypted))
	row("Created", ts(v.CreatedAt))
	row("Started", ts(v.StartedAt))
	row("Ended", ts(v.EndedAt))
	b.WriteString(`</table>`)

	b.WriteString(`<h2>Results</h2><table><tr><th>Path</th><th>Format</th><th>Enc.</th><th>Status</th><th>Password</th><th>Size</th><th>SHA-256</th></tr>`)
	for _, n := range s.jobRows(v) {
		b.WriteString(`<tr><td>` + e(n.Path) + `</td><td>` + e(n.Format) + `</td><td>` + yesNo(n.Encrypted) +
			`</td><td class="s-` + e(n.Status) + `">` + e(n.Status) + `</td><td><code>` + e(n.Password) + `</code></td><td>` +
			sizeText(n.Size) + `</td><td><code>` + e(n.SHA256) + `</code></td></tr>`)
	}
	b.WriteString(`</table>`)

	b.WriteString(`<h2>Chain of custody</h2>`)
	if len(custody) == 0 {
		b.WriteString(`<p>No recorded actions for this job.</p>`)
	} else {
		b.WriteString(`<table><tr><th>When</th><th>Actor</th><th>IP</th><th>Action</th><th>Detail</th></tr>`)
		for _, c := range custody {
			b.WriteString(`<tr><td>` + ts(c.Time) + `</td><td>` + e(firstNonEmpty(c.Email, c.Actor)) + `</td><td>` +
				e(c.IP) + `</td><td>` + e(c.Action) + `</td><td>` + e(c.Detail) + `</td></tr>`)
		}
		b.WriteString(`</table>`)
	}
	b.WriteString(`</body></html>`)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(b.String()))
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func sizeText(n int64) string {
	if n <= 0 {
		return "—"
	}
	return strconv.FormatInt(n, 10)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
