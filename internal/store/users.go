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

// User is a person who can log in. The password hash is never part of it: it
// is read by the two functions that need it, and goes nowhere else.
type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	Disabled  bool   `json:"disabled"`
	CreatedAt int64  `json:"created_at"`
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

const userColumns = `id, username, role, disabled, created_at`

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
	var disabled int
	err := db.QueryRow(`SELECT `+userColumns+`, password_hash FROM users WHERE username = ?`,
		NormalizeUsername(username)).Scan(&u.ID, &u.Username, &u.Role, &disabled, &u.CreatedAt, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, "", ErrNotFound
	}
	if err != nil {
		return User{}, "", fmt.Errorf("look up the user: %w", err)
	}
	u.Disabled = disabled == 1
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
	var disabled int
	err := db.QueryRow(`SELECT `+userColumns+` FROM users WHERE id = ?`, id).
		Scan(&u.ID, &u.Username, &u.Role, &disabled, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("read the user: %w", err)
	}
	u.Disabled = disabled == 1
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
		var disabled int
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &disabled, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("read a user: %w", err)
		}
		u.Disabled = disabled == 1
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
