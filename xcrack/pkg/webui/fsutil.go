package webui

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rom/xcrack/pkg/jobspec"
	"github.com/rom/xcrack/pkg/xcrack"
)

// byteReaderAt adapts a byte slice to the io.ReaderAt the engine consumes.
func byteReaderAt(b []byte) io.ReaderAt { return bytes.NewReader(b) }

// safeSegment reduces an arbitrary (possibly hostile) upload name to a single
// safe path segment: the base name with path separators and traversal removed.
// It never returns "" or a dotted name.
func safeSegment(name string) string {
	name = filepath.Base(filepath.FromSlash(name))
	name = strings.ReplaceAll(name, string(os.PathSeparator), "_")
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		return "file"
	}
	return name
}

// resolveWithin resolves a user-supplied file reference to an absolute path that
// must stay inside dir (the job's upload area). It is used to sanitize every
// file path a submitted spec names, so a remote client cannot point the engine
// at an arbitrary server file. A bare base name is looked up inside dir; an
// absolute or traversing path is rejected.
func resolveWithin(dir, ref string) (string, error) {
	if ref == "" {
		return "", nil
	}
	if ref == "-" {
		return "", fmt.Errorf("stdin (%q) is not available in the web UI", ref)
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	cand := filepath.Join(absDir, safeSegment(ref))
	// safeSegment collapses the name to one segment under absDir, so the join
	// cannot escape; the explicit check documents and guarantees the invariant.
	if cand != absDir && !strings.HasPrefix(cand, absDir+string(os.PathSeparator)) {
		return "", fmt.Errorf("path %q escapes the upload directory", ref)
	}
	if _, err := os.Stat(cand); err != nil {
		return "", fmt.Errorf("referenced file %q was not uploaded", filepath.Base(ref))
	}
	return cand, nil
}

// sanitizeSpecPaths rewrites every file-path field a submitted spec names so it
// resolves to a file uploaded with the job (inside auxDir), rejecting anything
// that escapes. When allowServerPaths is set the spec is left untouched (a
// trusted local instance may reference server-side wordlists directly). Output
// destinations are always cleared: the web backend owns where results are
// written.
func sanitizeSpecPaths(s *jobspec.Spec, auxDir string, allowServerPaths bool) error {
	// The web runner manages output itself; never let a spec write to a chosen
	// server path.
	s.Output.ResultsFile = ""
	s.Output.LogFile = ""
	if allowServerPaths {
		return nil
	}
	fix := func(field string, refs []string) ([]string, error) {
		out := make([]string, 0, len(refs))
		for _, r := range refs {
			p, err := resolveWithin(auxDir, r)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", field, err)
			}
			out = append(out, p)
		}
		return out, nil
	}
	var err error
	if s.Candidates.Wordlists, err = fix("candidates.wordlists", s.Candidates.Wordlists); err != nil {
		return err
	}
	if s.Candidates.Breach, err = fix("candidates.breach", s.Candidates.Breach); err != nil {
		return err
	}
	if s.Candidates.PasswordFiles, err = fix("candidates.password_files", s.Candidates.PasswordFiles); err != nil {
		return err
	}
	if s.Patterns.HCMask, err = fix("patterns.hcmask", s.Patterns.HCMask); err != nil {
		return err
	}
	if s.Search.Combinator.Left != "" {
		if s.Search.Combinator.Left, err = resolveWithin(auxDir, s.Search.Combinator.Left); err != nil {
			return fmt.Errorf("search.combinator.left: %w", err)
		}
	}
	if s.Search.Combinator.Right != "" {
		if s.Search.Combinator.Right, err = resolveWithin(auxDir, s.Search.Combinator.Right); err != nil {
			return fmt.Errorf("search.combinator.right: %w", err)
		}
	}
	return nil
}

// writeTree writes every decrypted node's content under outDir, mirroring the
// CLI's -o extraction with the same path-containment guard.
func writeTree(outDir string, res *xcrack.Result) error {
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return err
	}
	// Only create the directory if there is at least one content node to write.
	created := false
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
		if dst != absOut && !strings.HasPrefix(dst, absOut+string(os.PathSeparator)) {
			return // containment guard
		}
		if !created {
			if err := os.MkdirAll(absOut, 0o700); err != nil {
				writeErr = err
				return
			}
			created = true
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
	return writeErr
}

// treePathToFS maps a node's lineage path ("a.zip!/b/c.docx") to a relative
// filesystem path, dropping any traversal components.
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
	if len(clean) == 0 {
		return "root.bin"
	}
	return filepath.Join(clean...)
}
