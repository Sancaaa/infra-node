package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// The files are compiled into the program, so a wrong name in the page (or a
// file left out of web/static) only shows up as a blank page on the VPS. This
// catches it here.
func TestStaticServesThePageAndItsFiles(t *testing.T) {
	handler, err := Static()
	if err != nil {
		t.Fatal(err)
	}

	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest("GET", "/", nil))
	if page.Code != 200 || !strings.Contains(page.Body.String(), `src="/app.js"`) {
		t.Fatalf("the page: code %d, body %q", page.Code, page.Body.String())
	}

	post := httptest.NewRecorder()
	handler.ServeHTTP(post, httptest.NewRequest("POST", "/", nil))
	if post.Code != 405 {
		t.Errorf("a POST to the page: code %d, want 405", post.Code)
	}

	for _, path := range []string{"/app.js", "/style.css", "/headnode-mark.svg"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || rec.Body.Len() == 0 {
			t.Errorf("%s: code %d, %d bytes", path, rec.Code, rec.Body.Len())
		}
	}
}
