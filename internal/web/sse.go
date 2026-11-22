package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// sseWriter turns the text a task prints into Server-Sent Events: one event for
// each line. A program writes arbitrary pieces, so what is not yet a whole line
// waits for the rest. (The same as k3s manager's, copied on purpose: the
// dashboards are separate programs, OD-04.)
type sseWriter struct {
	mu      sync.Mutex
	w       http.ResponseWriter
	flusher http.Flusher
	partial []byte
}

func (s *sseWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.partial = append(s.partial, p...)
	for {
		end := bytes.IndexByte(s.partial, '\n')
		if end < 0 {
			break
		}
		s.send("", strings.TrimRight(string(s.partial[:end]), "\r"))
		s.partial = s.partial[end+1:]
	}
	s.flusher.Flush()
	return len(p), nil
}

// send writes one event; a message of several lines becomes several data: lines.
func (s *sseWriter) send(event, data string) {
	if event != "" {
		fmt.Fprintf(s.w, "event: %s\n", event)
	}
	for _, line := range strings.Split(data, "\n") {
		fmt.Fprintf(s.w, "data: %s\n", line)
	}
	fmt.Fprint(s.w, "\n")
}

// result sends the task's parsed result as one "result" event of JSON. Compact
// JSON has no newline in it, so it is one data: line.
func (s *sseWriter) result(v any) {
	text, err := json.Marshal(v)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.send("result", string(text))
	s.flusher.Flush()
}

// finish sends what is left over and the last event: "done", or "error".
func (s *sseWriter) finish(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.partial) > 0 {
		s.send("", string(s.partial))
		s.partial = nil
	}
	if err != nil {
		s.send("error", err.Error())
	} else {
		s.send("done", "ok")
	}
	s.flusher.Flush()
}

const scrubMaxLineBuf = 64 * 1024

// scrubWriter wraps an io.Writer and redacts configured secrets before bytes
// reach the underlying writer. Output is buffered by line (and flushed on
// Flush) so a secret split across Write chunks is never leaked.
type scrubWriter struct {
	mu      sync.Mutex
	w       io.Writer
	secrets []string
	maxLen  int
	partial []byte
}

func newScrubWriter(w io.Writer, secrets ...string) *scrubWriter {
	var clean []string
	maxLen := 0
	for _, s := range secrets {
		if s == "" {
			continue
		}
		clean = append(clean, s)
		if len(s) > maxLen {
			maxLen = len(s)
		}
	}
	return &scrubWriter{w: w, secrets: clean, maxLen: maxLen}
}

func (s *scrubWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.secrets) == 0 {
		return s.w.Write(p)
	}
	s.partial = append(s.partial, p...)
	if end := bytes.LastIndexByte(s.partial, '\n'); end >= 0 {
		if _, err := io.WriteString(s.w, scrubSecrets(string(s.partial[:end+1]), s.secrets)); err != nil {
			return 0, err
		}
		s.partial = append(s.partial[:0], s.partial[end+1:]...)
	}
	// If a single line grows past scrubMaxLineBuf without a newline, scrub what
	// is already complete and keep maxLen-1 trailing bytes so a secret split
	// across the boundary is still caught on the next Write.
	if len(s.partial) > scrubMaxLineBuf {
		scrubbed := []byte(scrubSecrets(string(s.partial), s.secrets))
		if cut := len(scrubbed) - (s.maxLen - 1); cut > 0 {
			if _, err := s.w.Write(scrubbed[:cut]); err != nil {
				return 0, err
			}
			s.partial = append(s.partial[:0], scrubbed[cut:]...)
		} else {
			s.partial = scrubbed
		}
	}
	return len(p), nil
}

// Flush scrubs and writes any remaining partial line at the end of a stream.
func (s *scrubWriter) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.partial) == 0 {
		return nil
	}
	text := scrubSecrets(string(s.partial), s.secrets)
	s.partial = nil
	_, err := io.WriteString(s.w, text)
	return err
}
