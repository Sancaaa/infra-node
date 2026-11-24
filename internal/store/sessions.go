package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// SessionLifetime is absolute: seven days after logging in, a person logs in
// again. There is no renewal while they work, which keeps the rule easy to
// explain (the same as headnode's D-23), and for a dashboard that holds the key
// to every host a short life is the safer choice.
const SessionLifetime = 7 * 24 * time.Hour

// TokenID is what the database keeps of a session token: its SHA-256. A fast
// hash is enough because the token is already 256 random bits, not a password
// somebody could guess.
func TokenID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Session is one login, as the Profile page lists it.
type Session struct {
	ID         string `json:"-"` // TokenID; never sent to the page
	CreatedAt  int64  `json:"created_at"`
	LastUsedAt int64  `json:"last_used_at"`
	IP         string `json:"ip"`
	UserAgent  string `json:"user_agent"`
}

// CreateSession stores a new login and returns the token for the cookie. It is
// shown once, here: only its hash is kept.
func CreateSession(db *sql.DB, userID int64, ip, userAgent string, now time.Time) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("make a session token: %w", err)
	}
	token := hex.EncodeToString(raw)

	if len(userAgent) > 200 { // it is the browser's text: cap it
		userAgent = userAgent[:200]
	}
	_, err := db.Exec(
		`INSERT INTO sessions (id, user_id, created_at, last_used_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)`,
		TokenID(token), userID, now.Unix(), now.Unix(), ip, userAgent)
	if err != nil {
		return "", fmt.Errorf("store the session: %w", err)
	}

	// Housekeeping: expired sessions are useless, so they go now and then
	// instead of piling up. A failure here changes nothing for the caller.
	_, _ = db.Exec(`DELETE FROM sessions WHERE created_at <= ?`, now.Add(-SessionLifetime).Unix())
	return token, nil
}

// SessionUser finds the person behind a token: a session that exists, is not
// too old, and belongs to a user who is not disabled. Anything else is
// ErrNotFound.
func SessionUser(db *sql.DB, token string, now time.Time) (User, error) {
	if token == "" {
		return User{}, ErrNotFound
	}
	var u User
	var totpEnabled int
	var lastUsed int64
	// "disabled = 0" is checked on every request, not only when a user is
	// disabled: a disabled user is out at once, whatever happened to the rows.
	err := db.QueryRow(
		`SELECT u.id, u.username, u.role, u.totp_enabled, u.created_at, s.last_used_at
		 FROM sessions s JOIN users u ON u.id = s.user_id
		 WHERE s.id = ? AND s.created_at > ? AND u.disabled = 0`,
		TokenID(token), now.Add(-SessionLifetime).Unix()).Scan(&u.ID, &u.Username, &u.Role, &totpEnabled, &u.CreatedAt, &lastUsed)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("look up the session: %w", err)
	}
	u.TOTPEnabled = totpEnabled == 1

	// "Last used" is for the Profile page. Written at most once a minute: a
	// database write on every request would be a lot for a timestamp.
	if now.Unix()-lastUsed >= 60 {
		_, _ = db.Exec(`UPDATE sessions SET last_used_at = ? WHERE id = ?`, now.Unix(), TokenID(token))
	}
	return u, nil
}

// DeleteSession ends one login (logout). A token that is not there is fine.
func DeleteSession(db *sql.DB, token string) error {
	if _, err := db.Exec(`DELETE FROM sessions WHERE id = ?`, TokenID(token)); err != nil {
		return fmt.Errorf("delete the session: %w", err)
	}
	return nil
}

// DeleteUserSessions ends every login of a user.
func DeleteUserSessions(db *sql.DB, userID int64) error {
	if _, err := db.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("delete the sessions: %w", err)
	}
	return nil
}

// DeleteOtherSessions ends every login of a user except the one they are
// using, and says how many it ended.
func DeleteOtherSessions(db *sql.DB, userID int64, keepToken string) (int64, error) {
	res, err := db.Exec(`DELETE FROM sessions WHERE user_id = ? AND id <> ?`, userID, TokenID(keepToken))
	if err != nil {
		return 0, fmt.Errorf("delete the other sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ListSessions returns a user's logins that have not expired, newest use first.
func ListSessions(db *sql.DB, userID int64, now time.Time) ([]Session, error) {
	rows, err := db.Query(
		`SELECT id, created_at, last_used_at, ip, user_agent FROM sessions
		 WHERE user_id = ? AND created_at > ? ORDER BY last_used_at DESC`,
		userID, now.Add(-SessionLifetime).Unix())
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	sessions := []Session{}
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.ID, &s.CreatedAt, &s.LastUsedAt, &s.IP, &s.UserAgent); err != nil {
			return nil, fmt.Errorf("read a session: %w", err)
		}
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}
