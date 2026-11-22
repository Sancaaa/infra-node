package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Secure wraps every route, so this is the check that the wrapping is there:
// the headers on every answer, and a refusal for a change from another site.
func TestSecureWrapsTheHandler(t *testing.T) {
	reached := false
	h := Secure(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))

	get := httptest.NewRecorder()
	h.ServeHTTP(get, httptest.NewRequest("GET", "http://infra.example.com/", nil))
	if !reached || get.Code != http.StatusOK {
		t.Fatalf("a GET was not passed on: reached=%v code=%d", reached, get.Code)
	}
	if csp := get.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("no Content-Security-Policy on the answer")
	}
	if get.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("no X-Content-Type-Options: nosniff")
	}

	reached = false
	post := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://infra.example.com/api/x", nil)
	req.Header.Set("Origin", "http://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	h.ServeHTTP(post, req)
	if reached || post.Code != http.StatusForbidden {
		t.Errorf("a cross-site POST got through: reached=%v code=%d", reached, post.Code)
	}
}
