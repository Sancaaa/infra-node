package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const goodPassword = "correct horse battery"

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	return openTestDB(t, filepath.Join(t.TempDir(), DBFile))
}

func mustUser(t *testing.T, db *sql.DB, name, role string) User {
	t.Helper()
	u, err := CreateUser(db, name, goodPassword, role)
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	return u
}

func TestCreateUserChecksItsInput(t *testing.T) {
	db := newTestDB(t)

	u, err := CreateUser(db, "  Alice ", goodPassword, RoleAdmin)
	if err != nil || u.Username != "alice" || u.Role != RoleAdmin || u.ID == 0 {
		t.Fatalf("create: %+v %v", u, err)
	}
	// The password is stored as a bcrypt hash, never as typed.
	hash, err := PasswordHash(db, u.ID)
	if err != nil || strings.Contains(hash, goodPassword) || !strings.HasPrefix(hash, "$2") {
		t.Errorf("hash: %q %v", hash, err)
	}

	cases := []struct {
		name, password, role string
		want                 error
	}{
		{"ALICE", goodPassword, RoleViewer, ErrUsernameTaken}, // the same person
		{"", goodPassword, RoleViewer, ErrInvalidUsername},
		{"has space", goodPassword, RoleViewer, ErrInvalidUsername},
		{strings.Repeat("a", 33), goodPassword, RoleViewer, ErrInvalidUsername},
		{"bob", "short", RoleViewer, ErrInvalidPassword},
		{"bob", strings.Repeat("x", 73), RoleViewer, ErrInvalidPassword},
		{"bob", goodPassword, "root", ErrInvalidRole},
	}
	for _, c := range cases {
		if _, err := CreateUser(db, c.name, c.password, c.role); !errors.Is(err, c.want) {
			t.Errorf("CreateUser(%q, %q): %v, want %v", c.name, c.role, err, c.want)
		}
	}
}

func TestFindForLogin(t *testing.T) {
	db := newTestDB(t)
	mustUser(t, db, "alice", RoleViewer)

	u, hash, err := FindForLogin(db, "Alice")
	if err != nil || u.Username != "alice" || hash == "" {
		t.Fatalf("%+v %q %v", u, hash, err)
	}
	if _, _, err := FindForLogin(db, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown user: %v", err)
	}
}

// The rule that keeps somebody in charge. Two admins demoting each other is the
// case a check made before the change would miss.
func TestLastEnabledAdminStays(t *testing.T) {
	db := newTestDB(t)
	a := mustUser(t, db, "a", RoleAdmin)
	b := mustUser(t, db, "b", RoleAdmin)

	if err := SetRole(db, a.ID, RoleViewer); err != nil {
		t.Fatalf("with two admins one may be demoted: %v", err)
	}
	// b is the last one now.
	if err := SetRole(db, b.ID, RoleOperator); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("demoting the last admin: %v", err)
	}
	if err := SetDisabled(db, b.ID, true); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("disabling the last admin: %v", err)
	}
	// Setting the role they already have is not a demotion.
	if err := SetRole(db, b.ID, RoleAdmin); err != nil {
		t.Errorf("admin to admin: %v", err)
	}
	if got, _ := GetUser(db, b.ID); got.Role != RoleAdmin || got.Disabled {
		t.Errorf("b was changed: %+v", got)
	}

	// A disabled admin does not count as one: with a disabled, b is still last,
	// and a (a viewer now) can be promoted, disabled and enabled freely.
	if err := SetRole(db, a.ID, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := SetDisabled(db, a.ID, true); err != nil {
		t.Fatalf("disabling one of two admins: %v", err)
	}
	if err := SetDisabled(db, b.ID, true); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("b is the only enabled admin again: %v", err)
	}
	if err := SetDisabled(db, a.ID, false); err != nil {
		t.Errorf("enabling: %v", err)
	}
}

func TestUnknownUserIsNotFound(t *testing.T) {
	db := newTestDB(t)
	if err := SetRole(db, 99, RoleViewer); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetRole: %v", err)
	}
	if err := SetDisabled(db, 99, true); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetDisabled: %v", err)
	}
	if err := SetPassword(db, 99, goodPassword); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetPassword: %v", err)
	}
}

func TestSessionsLifetimeAndDisabling(t *testing.T) {
	db := newTestDB(t)
	u := mustUser(t, db, "alice", RoleOperator)
	now := time.Now()

	token, err := CreateSession(db, u.ID, "10.0.0.1", "test-agent", now)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := SessionUser(db, token, now); err != nil || got.ID != u.ID || got.Role != RoleOperator {
		t.Fatalf("a fresh session: %+v %v", got, err)
	}
	if _, err := SessionUser(db, token+"x", now); !errors.Is(err, ErrNotFound) {
		t.Errorf("a wrong token: %v", err)
	}
	if _, err := SessionUser(db, "", now); !errors.Is(err, ErrNotFound) {
		t.Errorf("no token: %v", err)
	}
	if _, err := SessionUser(db, token, now.Add(SessionLifetime+time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Errorf("an expired session: %v", err)
	}

	// The token itself is not in the database, only its hash.
	var stored string
	if err := db.QueryRow(`SELECT id FROM sessions`).Scan(&stored); err != nil || stored == token || stored != TokenID(token) {
		t.Errorf("stored id %q for token %q: %v", stored, token, err)
	}

	// Disabling ends the session at once, and it stays ended after enabling.
	if err := SetDisabled(db, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := SessionUser(db, token, now); !errors.Is(err, ErrNotFound) {
		t.Errorf("a disabled user's session still works: %v", err)
	}
	if err := SetDisabled(db, u.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := SessionUser(db, token, now); !errors.Is(err, ErrNotFound) {
		t.Errorf("enabling brought the old session back: %v", err)
	}
}

func TestDeleteOtherSessions(t *testing.T) {
	db := newTestDB(t)
	u := mustUser(t, db, "alice", RoleViewer)
	other := mustUser(t, db, "bob", RoleViewer)
	now := time.Now()

	keep, _ := CreateSession(db, u.ID, "1.1.1.1", "a", now)
	gone, _ := CreateSession(db, u.ID, "2.2.2.2", "b", now)
	bobs, _ := CreateSession(db, other.ID, "3.3.3.3", "c", now)

	n, err := DeleteOtherSessions(db, u.ID, keep)
	if err != nil || n != 1 {
		t.Fatalf("ended %d, %v", n, err)
	}
	if _, err := SessionUser(db, keep, now); err != nil {
		t.Errorf("the session in use was ended: %v", err)
	}
	if _, err := SessionUser(db, gone, now); !errors.Is(err, ErrNotFound) {
		t.Errorf("the other session still works: %v", err)
	}
	if _, err := SessionUser(db, bobs, now); err != nil {
		t.Errorf("another user's session was ended: %v", err)
	}

	list, err := ListSessions(db, u.ID, now)
	if err != nil || len(list) != 1 || list[0].ID != TokenID(keep) || list[0].IP != "1.1.1.1" {
		t.Errorf("list: %+v %v", list, err)
	}
}

func TestHistoryPagesByID(t *testing.T) {
	db := newTestDB(t)
	for i := 0; i < 5; i++ {
		if err := AddEvent(db, Event{Username: "alice", Action: "x", Result: ResultOK}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := ListEvents(db, 0, 3)
	if err != nil || len(first) != 3 || first[0].ID < first[1].ID {
		t.Fatalf("first page: %+v %v", first, err)
	}
	second, err := ListEvents(db, first[2].ID, 3)
	if err != nil || len(second) != 2 || second[0].ID >= first[2].ID {
		t.Fatalf("second page: %+v %v", second, err)
	}
	if first[0].At == 0 {
		t.Error("At was not set")
	}
}
