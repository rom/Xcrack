package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// staticFS holds the embedded single-page app (HTML/CSS/JS and vendored
// libraries). It is served at the site root; unknown non-API paths fall back to
// index.html so client-side routing works.
//
//go:embed assets
var staticFS embed.FS

// assetHandler serves the embedded SPA with an index.html fallback.
func assetHandler() (http.Handler, error) {
	sub, err := fs.Sub(staticFS, "assets")
	if err != nil {
		return nil, err
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve the file when it exists; otherwise fall back to index.html so a
		// deep link into the SPA still loads the app shell.
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if f, err := sub.Open(p); err == nil {
			f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		fileServer.ServeHTTP(w, r2)
	}), nil
}
