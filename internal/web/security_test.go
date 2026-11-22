package web

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		url        string
		remoteAddr string
		tls        bool
		header     map[string]string
		want       bool
	}{
		{"page loads itself", "GET", "http://127.0.0.1:8095/api/x", "", false, nil, true},
		{"a link from elsewhere still opens the page", "GET", "http://127.0.0.1:8095/api/x", "", false, map[string]string{"Sec-Fetch-Site": "cross-site"}, true},
		{"fetch from our page", "POST", "http://127.0.0.1:8095/api/x", "", false, map[string]string{"Origin": "http://127.0.0.1:8095", "Sec-Fetch-Site": "same-origin"}, true},
		{"post without origin", "POST", "http://127.0.0.1:8095/api/x", "", false, nil, false},
		{"post from another site", "POST", "http://127.0.0.1:8095/api/x", "", false, map[string]string{"Origin": "http://evil.example", "Sec-Fetch-Site": "cross-site"}, false},
		{"post, another site's origin, no fetch metadata", "POST", "http://127.0.0.1:8095/api/x", "", false, map[string]string{"Origin": "http://evil.example"}, false},
		{"post marked cross-site with our origin", "POST", "http://127.0.0.1:8095/api/x", "", false, map[string]string{"Origin": "http://127.0.0.1:8095", "Sec-Fetch-Site": "cross-site"}, false},
		{"https direct with https origin", "POST", "https://infra.example.com/api/x", "198.51.100.4:4000", true, map[string]string{"Origin": "https://infra.example.com", "Sec-Fetch-Site": "same-origin"}, true},
		{"https direct rejects http origin", "POST", "https://infra.example.com/api/x", "198.51.100.4:4000", true, map[string]string{"Origin": "http://infra.example.com", "Sec-Fetch-Site": "same-origin"}, false},
		{"forwarded https from local proxy accepts https origin", "POST", "http://infra.example.com/api/x", "127.0.0.1:4000", false, map[string]string{"Origin": "https://infra.example.com", "X-Forwarded-Proto": "https", "Sec-Fetch-Site": "same-origin"}, true},
		{"forwarded https from local proxy rejects http origin", "POST", "http://infra.example.com/api/x", "127.0.0.1:4000", false, map[string]string{"Origin": "http://infra.example.com", "X-Forwarded-Proto": "https", "Sec-Fetch-Site": "same-origin"}, false},
		{"plain http rejects https origin", "POST", "http://127.0.0.1:8095/api/x", "127.0.0.1:4000", false, map[string]string{"Origin": "https://127.0.0.1:8095", "Sec-Fetch-Site": "same-origin"}, false},
		{"untrusted remote cannot spoof X-Forwarded-Proto", "POST", "http://infra.example.com/api/x", "198.51.100.4:4000", false, map[string]string{"Origin": "https://infra.example.com", "X-Forwarded-Proto": "https", "Sec-Fetch-Site": "same-origin"}, false},
		{"non-http scheme rejected", "POST", "http://127.0.0.1:8095/api/x", "", false, map[string]string{"Origin": "ftp://127.0.0.1:8095"}, false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.url, nil)
		if c.remoteAddr != "" {
			r.RemoteAddr = c.remoteAddr
		}
		if c.tls {
			r.TLS = &tls.ConnectionState{}
		}
		for k, v := range c.header {
			r.Header.Set(k, v)
		}
		if got := sameOrigin(r); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestScrubWriterAcrossChunkBoundaries(t *testing.T) {
	const secretA = "SUPER-SECRET-TOKEN-12345"
	const secretB = "VAULT-PASS-98765"

	rec := httptest.NewRecorder()
	sse := &sseWriter{w: rec, flusher: rec}
	var logBuf bytes.Buffer
	sw := newScrubWriter(io.MultiWriter(sse, &logBuf), secretA, secretB)

	payload := "line 1: token=" + secretA + " done\nline 2: vault=" + secretB + "\nfinal without newline: " + secretA
	// Feed 3 bytes at a time so both secrets are split across multiple Write calls.
	for i := 0; i < len(payload); i += 3 {
		end := min(i+3, len(payload))
		if _, err := sw.Write([]byte(payload[i:end])); err != nil {
			t.Fatal(err)
		}
	}
	if err := sw.Flush(); err != nil {
		t.Fatal(err)
	}
	sse.finish(nil)

	for _, secret := range []string{secretA, secretB} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Errorf("SSE output leaked %q:\n%s", secret, rec.Body.String())
		}
		if strings.Contains(logBuf.String(), secret) {
			t.Errorf("logBuf leaked %q:\n%s", secret, logBuf.String())
		}
	}
	if !strings.Contains(logBuf.String(), "token=… done\nline 2: vault=…\nfinal without newline: …") {
		t.Errorf("unexpected scrubbed logBuf: %q", logBuf.String())
	}

	// Huge line without newline (> scrubMaxLineBuf) still scrubs a secret split across the buffer cut.
	var hugeBuf bytes.Buffer
	hugeSW := newScrubWriter(&hugeBuf, secretA)
	pad := strings.Repeat("x", scrubMaxLineBuf-5)
	_, _ = hugeSW.Write([]byte(pad + secretA[:10]))
	_, _ = hugeSW.Write([]byte(secretA[10:] + "tail"))
	_ = hugeSW.Flush()
	if strings.Contains(hugeBuf.String(), secretA) || !strings.HasSuffix(hugeBuf.String(), "…tail") {
		t.Errorf("huge line scrub failed: leaked=%v suffix=%q", strings.Contains(hugeBuf.String(), secretA), hugeBuf.String()[max(0, len(hugeBuf.String())-20):])
	}
}

func TestSSEWriterSplitsLinesAndSendsResult(t *testing.T) {
	rec := httptest.NewRecorder()
	s := &sseWriter{w: rec, flusher: rec}
	s.Write([]byte("Plan: 1 to add"))
	s.Write([]byte(", 0 to change\nnext"))
	s.result(map[string]int{"add": 1})
	s.finish(nil)
	got := rec.Body.String()
	for _, want := range []string{
		"data: Plan: 1 to add, 0 to change\n\n",
		"event: result\ndata: {\"add\":1}\n\n",
		"data: next\n\n",
		"event: done\ndata: ok\n\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}
