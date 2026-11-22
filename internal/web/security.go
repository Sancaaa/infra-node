package web

import (
	"net/http"
	"net/url"
	"strings"
)

// Secure keeps other websites from using this dashboard through your browser.
// A request that changes something (anything but GET and HEAD) must come from
// this very address: the browser must not mark it as cross-site, and its Origin
// header must be this host. Otherwise a page somewhere on the internet could
// make a logged-in browser press "Apply" for you.
//
// Reading (GET) is let through: nothing that changes anything is a GET, and
// another site cannot read the answer anyway.
//
// It is not the login. The login and the roles come in IM1 and are a second,
// separate check; this one stays. Behind Caddy the Host header reaches us as the
// browser sent it, so Origin and Host still match. Same idea as headnode's D-22.
func Secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only our own files: no inline script, no other sites.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !sameOrigin(r) {
			writeError(w, http.StatusForbidden, "Requests from other sites are not allowed.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return true
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin":
	default:
		return false
	}
	origin, err := url.Parse(r.Header.Get("Origin"))
	if err != nil || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return false
	}
	return origin.Scheme == requestScheme(r) && origin.Host == r.Host
}

// requestScheme returns "https" when the request arrived over TLS directly or
// through a trusted local reverse proxy (Caddy on loopback) with
// X-Forwarded-Proto: https; otherwise "http".
func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if fromLocalProxy(r) {
		if proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); strings.EqualFold(proto, "https") {
			return "https"
		}
	}
	return "http"
}
