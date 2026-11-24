package store

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// The three roles, lowest first (roadmap, "Roles"). What each may do is decided
// in one place, can() in internal/web/permissions.go.
const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

const (
	MinPasswordLen = 10
	// bcrypt only looks at the first 72 bytes. Accepting a longer password would
	// silently ignore the rest, so it is refused instead.
	MaxPasswordLen = 72
)

// These messages are shown to people as they are, so they are sentences.
var (
	ErrNotFound        = errors.New("not found")
	ErrUsernameTaken   = errors.New("That user name is already taken.")
	ErrInvalidUsername = errors.New("A user name is 1 to 32 characters: lowercase letters, digits, dot, dash or underscore.")
	ErrInvalidPassword = fmt.Errorf("A password is %d to %d bytes long.", MinPasswordLen, MaxPasswordLen)
	ErrInvalidRole     = errors.New("The role must be viewer, operator or admin.")
	ErrLastAdmin       = errors.New("That would leave the dashboard without an enabled admin.")
)

var usernameRe = regexp.MustCompile(`^[a-z0-9._-]{1,32}$`)

// User is a person who can log in. The password hash and TOTP secret are never
// part of it: they are read by the functions that need them, and go nowhere else.
type User struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	Role        string `json:"role"`
	Disabled    bool   `json:"disabled"`
	TOTPEnabled bool   `json:"totp_enabled"`
	CreatedAt   int64  `json:"created_at"`
}

func ValidRole(role string) bool {
	return role == RoleViewer || role == RoleOperator || role == RoleAdmin
}

// NormalizeUsername makes "Admin " and "admin" the same person.
func NormalizeUsername(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// HashPassword checks a new password's length and hashes it. bcrypt is slow on
// purpose (about 50 ms), so guessing from a stolen database is slow too, and it
// salts every hash itself.
func HashPassword(password string) (string, error) {
	if len(password) < MinPasswordLen || len(password) > MaxPasswordLen {
		return "", ErrInvalidPassword
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash the password: %w", err)
	}
	return string(hash), nil
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

const userColumns = `id, username, role, disabled, totp_enabled, created_at`

// CreateUser adds a user. The CLI creates the first admin with it, the Users
// page everyone after.
func CreateUser(db *sql.DB, username, password, role string) (User, error) {
	username = NormalizeUsername(username)
	if !usernameRe.MatchString(username) {
		return User{}, ErrInvalidUsername
	}
	if !ValidRole(role) {
		return User{}, ErrInvalidRole
	}
	hash, err := HashPassword(password)
	if err != nil {
		return User{}, err
	}

	now := time.Now().Unix()
	res, err := db.Exec(
		`INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)`,
		username, hash, role, now)
	if isUniqueViolation(err) {
		return User{}, ErrUsernameTaken
	}
	if err != nil {
		return User{}, fmt.Errorf("store the user: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return User{}, fmt.Errorf("read the new user's id: %w", err)
	}
	return User{ID: id, Username: username, Role: role, CreatedAt: now}, nil
}

// FindForLogin returns the user with that name and the hash of their password.
// A disabled user is returned too: the caller checks the password first, so
// that "disabled" and "wrong password" take equally long.
func FindForLogin(db *sql.DB, username string) (User, string, error) {
	var u User
	var hash string
	var disabled, totpEnabled int
	err := db.QueryRow(`SELECT `+userColumns+`, password_hash FROM users WHERE username = ?`,
		NormalizeUsername(username)).Scan(&u.ID, &u.Username, &u.Role, &disabled, &totpEnabled, &u.CreatedAt, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, "", ErrNotFound
	}
	if err != nil {
		return User{}, "", fmt.Errorf("look up the user: %w", err)
	}
	u.Disabled = disabled == 1
	u.TOTPEnabled = totpEnabled == 1
	return u, hash, nil
}

// PasswordHash is for checking a user's current password (changing it).
func PasswordHash(db *sql.DB, id int64) (string, error) {
	var hash string
	err := db.QueryRow(`SELECT password_hash FROM users WHERE id = ?`, id).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("read the password hash: %w", err)
	}
	return hash, nil
}

func GetUser(db *sql.DB, id int64) (User, error) {
	var u User
	var disabled, totpEnabled int
	err := db.QueryRow(`SELECT `+userColumns+` FROM users WHERE id = ?`, id).
		Scan(&u.ID, &u.Username, &u.Role, &disabled, &totpEnabled, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("read the user: %w", err)
	}
	u.Disabled = disabled == 1
	u.TOTPEnabled = totpEnabled == 1
	return u, nil
}

func ListUsers(db *sql.DB) ([]User, error) {
	rows, err := db.Query(`SELECT ` + userColumns + ` FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	users := []User{}
	for rows.Next() {
		var u User
		var disabled, totpEnabled int
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &disabled, &totpEnabled, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("read a user: %w", err)
		}
		u.Disabled = disabled == 1
		u.TOTPEnabled = totpEnabled == 1
		users = append(users, u)
	}
	return users, rows.Err()
}

func CountUsers(db *sql.DB) (int, error) {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}

// SetPassword replaces a user's password. Ending their sessions is the
// caller's decision: a reset ends all of them, a person changing their own
// password keeps the one they are using.
func SetPassword(db *sql.DB, id int64, password string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	res, err := db.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, hash, id)
	if err != nil {
		return fmt.Errorf("store the password: %w", err)
	}
	return expectOne(res, db, id)
}

// SetRole changes a user's role. Taking the admin role from the last enabled
// admin is refused (ErrLastAdmin).
//
// The rule is part of the UPDATE itself, not a check before it: two admins
// demoting each other at the same moment would both pass a check made first,
// and leave nobody in charge. One statement is decided by SQLite one at a time.
func SetRole(db *sql.DB, id int64, role string) error {
	if !ValidRole(role) {
		return ErrInvalidRole
	}
	res, err := db.Exec(`UPDATE users SET role = ? WHERE id = ? AND (
			role <> 'admin' OR disabled = 1 OR ? = 'admin'
			OR EXISTS (SELECT 1 FROM users o WHERE o.id <> users.id AND o.role = 'admin' AND o.disabled = 0))`,
		role, id, role)
	if err != nil {
		return fmt.Errorf("change the role: %w", err)
	}
	return expectOne(res, db, id)
}

// SetDisabled disables or enables a user. Disabling also ends all their
// sessions, so it takes effect at once; the last enabled admin cannot be
// disabled (ErrLastAdmin), for the reason given at SetRole.
func SetDisabled(db *sql.DB, id int64, disabled bool) error {
	flag := 0
	if disabled {
		flag = 1
	}
	res, err := db.Exec(`UPDATE users SET disabled = ? WHERE id = ? AND (
			? = 0 OR disabled = 1 OR role <> 'admin'
			OR EXISTS (SELECT 1 FROM users o WHERE o.id <> users.id AND o.role = 'admin' AND o.disabled = 0))`,
		flag, id, flag)
	if err != nil {
		return fmt.Errorf("change the user: %w", err)
	}
	if err := expectOne(res, db, id); err != nil {
		return err
	}
	if disabled {
		return DeleteUserSessions(db, id)
	}
	return nil
}

// expectOne turns "no row was changed" into the reason: the user is not there,
// or the last-admin rule stopped the change.
func expectOne(res sql.Result, db *sql.DB, id int64) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("count the changed rows: %w", err)
	}
	if n > 0 {
		return nil
	}
	if _, err := GetUser(db, id); err != nil {
		return err // ErrNotFound, or a real error
	}
	return ErrLastAdmin
}

// TOTPSecret reads a user's stored TOTP secret and whether TOTP is enabled.
func TOTPSecret(db *sql.DB, userID int64) (string, bool, error) {
	var secret string
	var enabled int
	err := db.QueryRow(`SELECT totp_secret, totp_enabled FROM users WHERE id = ?`, userID).Scan(&secret, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, ErrNotFound
	}
	if err != nil {
		return "", false, fmt.Errorf("read totp state: %w", err)
	}
	return secret, enabled == 1, nil
}

// EnsureTOTPSecret returns a user's TOTP secret and enabled flag. When TOTP is
// not yet enabled and no pending secret exists, it generates and stores one
// atomically so concurrent first-time logins see the same secret.
func EnsureTOTPSecret(db *sql.DB, userID int64) (string, bool, error) {
	secret, enabled, err := TOTPSecret(db, userID)
	if err != nil || enabled || secret != "" {
		return secret, enabled, err
	}
	candidate, err := GenerateTOTPSecret()
	if err != nil {
		return "", false, err
	}
	if _, err := db.Exec(
		`UPDATE users SET totp_secret = ? WHERE id = ? AND totp_enabled = 0 AND totp_secret = ''`,
		candidate, userID,
	); err != nil {
		return "", false, fmt.Errorf("store totp secret: %w", err)
	}
	return TOTPSecret(db, userID)
}

// EnableTOTP activates TOTP for a user after their first valid code and records
// the step so that same code cannot be replayed.
func EnableTOTP(db *sql.DB, userID int64, step int64) error {
	res, err := db.Exec(
		`UPDATE users SET totp_enabled = 1, totp_last_step = ? WHERE id = ? AND totp_secret != '' AND totp_enabled = 0`,
		step, userID,
	)
	if err != nil {
		return fmt.Errorf("enable totp: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("count changed rows: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// UseTOTPStep atomically advances a user's last accepted TOTP step. It returns
// false when the step was already used (or an earlier step was replayed).
func UseTOTPStep(db *sql.DB, userID int64, step int64) (bool, error) {
	res, err := db.Exec(
		`UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_enabled = 1 AND totp_last_step < ?`,
		step, userID, step,
	)
	if err != nil {
		return false, fmt.Errorf("record totp step: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("count changed rows: %w", err)
	}
	return n == 1, nil
}

// ResetTOTP clears a user's TOTP secret/state and deletes all of their sessions
// in one transaction so they must enroll a new authenticator on next login.
func ResetTOTP(db *sql.DB, userID int64) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin totp reset: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.Exec(
		`UPDATE users SET totp_secret = '', totp_enabled = 0, totp_last_step = 0 WHERE id = ?`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("clear totp: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("count changed rows: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("delete the sessions: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit totp reset: %w", err)
	}
	return nil
}
