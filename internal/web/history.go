package web

import (
	"net/http"
	"strconv"

	"infra-manager/internal/store"
)

// history lists History, newest first, a page at a time: ?before=<id of the
// last line you have>&limit=<up to 200>. "more" says whether there is another
// page.
func (s *Server) history(w http.ResponseWriter, r *http.Request, me store.User) {
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64) // 0 (the newest) when absent or bad
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n >= 1 && n <= 200 {
		limit = n
	}

	// One more than asked for, only to know whether a next page exists.
	events, err := store.ListEvents(s.db, before, limit+1)
	if err != nil {
		serverError(w, "read history", err)
		return
	}
	more := len(events) > limit
	if more {
		events = events[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "more": more})
}
