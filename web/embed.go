package web

import (
	"embed"
	"io/fs"
	"net/http"
)

// The UI: one HTML file, one CSS file, one JS file and the logo, compiled into
// the program (no build step), so installing the dashboard is copying one file.
//
//go:embed static
var files embed.FS

// Static serves the UI. no-cache makes the browser ask again after an upgrade
// of the program instead of showing the old page.
func Static() (http.Handler, error) {
	sub, err := fs.Sub(files, "static")
	if err != nil {
		return nil, err
	}
	server := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Registered without a method (a "GET /" pattern would clash with the
		// method-less "/api/" catch-all), so it refuses other methods itself.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		server.ServeHTTP(w, r)
	}), nil
}
