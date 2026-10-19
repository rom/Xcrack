package webui

import (
	"bufio"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// splitList splits a newline/comma-separated field into trimmed, non-empty
// items (used for library-wordlist references and server URL lists).
func splitList(s string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' }) {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// This file is the server-side wordlist library: dictionaries saved once under
// the work directory and reused by name across jobs (instead of re-uploading
// them with every job). The library is shared across users — wordlists are
// attack dictionaries, not secrets.

func (s *Server) libraryDir() string { return filepath.Join(s.cfg.WorkDir, "library", "wordlists") }

type libEntry struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

func (s *Server) handleLibraryList(w http.ResponseWriter, r *http.Request) {
	entries, _ := os.ReadDir(s.libraryDir())
	out := make([]libEntry, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, libEntry{Name: e.Name(), Size: info.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, http.StatusOK, map[string]any{"wordlists": out})
}

func (s *Server) handleLibraryUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadBytes)
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "could not parse upload (is it too large?)")
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()
	fhs := r.MultipartForm.File["file"]
	if len(fhs) == 0 {
		writeErr(w, http.StatusBadRequest, "no file uploaded (need a 'file' part)")
		return
	}
	if err := os.MkdirAll(s.libraryDir(), 0o700); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create the library directory")
		return
	}
	var saved []string
	for _, fh := range fhs {
		if _, err := savePart(fh, s.libraryDir()); err != nil {
			writeErr(w, http.StatusBadRequest, "save: "+err.Error())
			return
		}
		saved = append(saved, safeSegment(fh.Filename))
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": saved})
}

func (s *Server) handleLibraryDelete(w http.ResponseWriter, r *http.Request) {
	p := filepath.Join(s.libraryDir(), safeSegment(r.PathValue("name")))
	if _, err := os.Stat(p); err != nil {
		writeErr(w, http.StatusNotFound, "no such wordlist")
		return
	}
	if err := os.Remove(p); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not delete")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleLibraryPreview returns the first lines of a library wordlist.
func (s *Server) handleLibraryPreview(w http.ResponseWriter, r *http.Request) {
	p := filepath.Join(s.libraryDir(), safeSegment(r.PathValue("name")))
	f, err := os.Open(p)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such wordlist")
		return
	}
	defer f.Close()
	const maxLines, maxBytes = 200, 256 << 10
	var lines []string
	sc := bufio.NewScanner(io.LimitReader(f, maxBytes))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() && len(lines) < maxLines {
		lines = append(lines, sc.Text())
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": safeSegment(r.PathValue("name")), "lines": lines})
}

// copyLibraryInto copies the named library wordlists into dir (a job's aux
// directory), so a job can reference them by name like any uploaded aux file.
// Unknown names are an error; path traversal is impossible (names are
// base-name-sanitized).
func (s *Server) copyLibraryInto(names []string, dir string) error {
	for _, raw := range names {
		name := safeSegment(raw)
		src := filepath.Join(s.libraryDir(), name)
		in, err := os.Open(src)
		if err != nil {
			return &libError{name: raw}
		}
		err = func() error {
			defer in.Close()
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return err
			}
			out, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			defer out.Close()
			_, err = io.Copy(out, in)
			return err
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

type libError struct{ name string }

func (e *libError) Error() string { return "unknown library wordlist: " + e.name }
