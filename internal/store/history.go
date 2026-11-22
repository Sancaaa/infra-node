package store

import (
	"database/sql"
	"fmt"
	"time"
)

// How an action ended, as History shows it. A refused action is one the
// dashboard would not do (no login, the wrong role, a rule such as "the last
// admin stays"); a failed one was allowed but did not work.
const (
	ResultOK      = "ok"
	ResultRefused = "refused"
	ResultFailed  = "failed"
)

// Event is one line of History: who did what, to what, and how it ended.
type Event struct {
	ID       int64  `json:"id"`
	At       int64  `json:"at"`
	UserID   int64  `json:"-"`
	Username string `json:"username"` // "" when nobody was logged in
	Action   string `json:"action"`
	Target   string `json:"target"` // the host, machine or user it was about
	Result   string `json:"result"`
	Detail   string `json:"detail"`
	IP       string `json:"ip"`
}

// AddEvent writes a line of History. At is set to now when it is 0.
//
// Detail is free text for a person, and must never hold a secret: no password,
// token or key (roadmap, "Rules for every agent").
func AddEvent(db *sql.DB, e Event) error {
	if e.At == 0 {
		e.At = time.Now().Unix()
	}
	_, err := db.Exec(
		`INSERT INTO history (at, user_id, username, action, target, result, detail, ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.At, e.UserID, e.Username, e.Action, e.Target, e.Result, e.Detail, e.IP)
	if err != nil {
		return fmt.Errorf("write history: %w", err)
	}
	return nil
}

// ListEvents returns up to limit lines, newest first. before is the id of the
// last line already shown (0 for the first page); ids only grow, so paging by
// id never skips or repeats a line even while new ones arrive.
func ListEvents(db *sql.DB, before int64, limit int) ([]Event, error) {
	query := `SELECT id, at, user_id, username, action, target, result, detail, ip FROM history`
	args := []any{}
	if before > 0 {
		query += ` WHERE id < ?`
		args = append(args, before)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("read history: %w", err)
	}
	defer rows.Close()

	events := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.At, &e.UserID, &e.Username, &e.Action, &e.Target, &e.Result, &e.Detail, &e.IP); err != nil {
			return nil, fmt.Errorf("read a history line: %w", err)
		}
		events = append(events, e)
	}
	return events, rows.Err()
}
