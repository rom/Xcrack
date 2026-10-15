package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rom/xcrack/pkg/xcrack"
)

// nodeView is the JSON-serializable projection of a result Node.
type nodeView struct {
	Path         string     `json:"path"`
	Format       string     `json:"format,omitempty"`
	Status       string     `json:"status"`
	WasEncrypted bool       `json:"encrypted"`
	Password     string     `json:"password,omitempty"`
	Error        string     `json:"error,omitempty"`
	Size         int64      `json:"size,omitempty"`
	SHA256       string     `json:"sha256,omitempty"`
	Children     []nodeView `json:"children,omitempty"`
}

func buildView(n *xcrack.Node) nodeView {
	v := nodeView{
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
		v.Children = append(v.Children, buildView(c))
	}
	return v
}

type manifest struct {
	Root      nodeView  `json:"root"`
	Passwords []string  `json:"recovered_passwords"`
	Stats     statsView `json:"stats"`
}

type statsView struct {
	FilesSeen       int   `json:"files_seen"`
	CandidatesTried int64 `json:"candidates_tried"`
	BytesExtracted  int64 `json:"bytes_extracted"`
	LimitHits       int   `json:"limit_hits"`
	ElapsedMS       int64 `json:"elapsed_ms"`
}

func buildManifest(res *xcrack.Result) manifest {
	return manifest{
		Root:      buildView(res.Root),
		Passwords: res.Passwords(),
		Stats: statsView{
			FilesSeen:       res.Stats.FilesSeen,
			CandidatesTried: res.Stats.CandidatesTried,
			BytesExtracted:  res.Stats.BytesExtracted,
			LimitHits:       res.Stats.LimitHits,
			ElapsedMS:       res.Stats.Elapsed.Milliseconds(),
		},
	}
}

func renderJSON(w io.Writer, res *xcrack.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(buildManifest(res))
}

func renderJSONL(w io.Writer, res *xcrack.Result) error {
	enc := json.NewEncoder(w)
	var err error
	res.Root.Walk(func(n *xcrack.Node) {
		if err != nil {
			return
		}
		err = enc.Encode(buildView(n))
	})
	return err
}

func renderText(w io.Writer, res *xcrack.Result) {
	var walk func(n *xcrack.Node, depth int)
	walk = func(n *xcrack.Node, depth int) {
		indent := strings.Repeat("  ", depth)
		name := n.Path
		if name == "" {
			name = "<root>"
		}
		line := fmt.Sprintf("%s%s  [%s", indent, name, n.Status)
		if n.Format != "" {
			line += " " + n.Format
		}
		if n.WasEncrypted {
			line += " password=" + quote(n.Password)
		}
		if n.Content != nil {
			line += fmt.Sprintf(" %dB", n.Content.Size())
		}
		if n.Err != nil {
			line += " err=" + n.Err.Error()
		}
		line += "]"
		fmt.Fprintln(w, line)
		for _, c := range n.Children {
			walk(c, depth+1)
		}
	}
	walk(res.Root, 0)
	fmt.Fprintf(w, "\nrecovered %d password(s): %s\n", len(res.Passwords()), strings.Join(res.Passwords(), ", "))
	fmt.Fprintf(w, "files=%d candidates=%d bytes=%d limits=%d elapsed=%s\n",
		res.Stats.FilesSeen, res.Stats.CandidatesTried, res.Stats.BytesExtracted,
		res.Stats.LimitHits, res.Stats.Elapsed)
}

func quote(s string) string {
	if s == "" {
		return `"" (empty)`
	}
	return `"` + s + `"`
}

// writeTree writes every decrypted/plain leaf to outDir, mirroring the tree
// path, and writes a manifest.json. Paths are contained within outDir.
func writeTree(outDir string, res *xcrack.Result) error {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return err
	}
	var writeErr error
	res.Root.Walk(func(n *xcrack.Node) {
		if writeErr != nil || n.Content == nil {
			return
		}
		rel := treePathToFS(n.Path)
		if rel == "" {
			return
		}
		dst := filepath.Join(absOut, rel)
		if !strings.HasPrefix(dst, absOut+string(os.PathSeparator)) && dst != absOut {
			return // containment guard
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			writeErr = err
			return
		}
		rc, err := n.Content.Open()
		if err != nil {
			writeErr = err
			return
		}
		defer rc.Close()
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			writeErr = err
			return
		}
		if _, err := io.Copy(f, rc); err != nil {
			writeErr = err
		}
		f.Close()
	})
	if writeErr != nil {
		return writeErr
	}
	mf, err := os.OpenFile(filepath.Join(absOut, "manifest.json"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer mf.Close()
	return renderJSON(mf, res)
}

// treePathToFS converts a tree path (using "!/" between layers) into a safe
// relative filesystem path.
func treePathToFS(p string) string {
	if p == "" {
		return "root.bin"
	}
	p = strings.ReplaceAll(p, "!/", "/")
	parts := strings.Split(p, "/")
	var clean []string
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			continue
		}
		clean = append(clean, part)
	}
	return filepath.Join(clean...)
}
