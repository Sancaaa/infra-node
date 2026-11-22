// Package web is the HTTP side: the checks that keep other websites out
// (security.go), the login and the roles (server.go, auth.go, permissions.go),
// and one file for each page of the API (users.go, profile.go, history.go).
package web

import (
	"encoding/json"
	"net/http"
)

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeError answers {"error": "a sentence"}: the page shows the sentence as it is.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message})
}
