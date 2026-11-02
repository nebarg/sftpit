package control

import (
	"embed"
	"io/fs"
	"net/http"
)

// The dashboard's tests, in web/test, are left out.
//
//go:embed web/index.html web/*.css web/*.js
var web embed.FS

// dashboardPolicy lets the dashboard load only its own scripts, styles and
// API, run no inline script, and be framed by no other page, which could
// trick a click on reset.
const dashboardPolicy = "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// dashboard serves the dashboard's files: index.html at /, and the others
// by name.
func dashboard() http.Handler {
	root, err := fs.Sub(web, "web")
	if err != nil {
		// fs.Sub fails only for an invalid name, which "web" is not.
		panic(err)
	}
	files := http.FileServerFS(root)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", dashboardPolicy)
		h.Set("Referrer-Policy", "no-referrer")
		// The files carry no modification time, so a browser that caches
		// them could keep those of an older sftpit.
		h.Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	})
}
