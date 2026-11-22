package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func openTestDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	// Closed before the temp folder is removed: Windows cannot delete an open file.
	t.Cleanup(func() { db.Close() })
	return db
}

func schemaVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func TestNewDatabaseGetsEveryMigration(t *testing.T) {
	db := openTestDB(t, filepath.Join(t.TempDir(), DBFile))

	if got := schemaVersion(t, db); got != len(migrations) {
		t.Errorf("schema version = %d, want %d", got, len(migrations))
	}
	// The table of migration 1 exists and works.
	if _, err := db.Exec(`INSERT INTO settings (key, value) VALUES ('a', 'b')`); err != nil {
		t.Errorf("settings table: %v", err)
	}
}

// A migration must never run twice: opening again keeps the data and does not
// fail with "table already exists".
func TestOpeningAgainKeepsTheData(t *testing.T) {
	path := filepath.Join(t.TempDir(), DBFile)
	db, err := OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO settings (key, value) VALUES ('kept', 'yes')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	db = openTestDB(t, path)
	var value string
	if err := db.QueryRow(`SELECT value FROM settings WHERE key = 'kept'`).Scan(&value); err != nil || value != "yes" {
		t.Fatalf("after the second open: value=%q err=%v", value, err)
	}
}

func TestDatabaseFromANewerVersionIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), DBFile)
	db, err := OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	if db, err := OpenDB(path); err == nil {
		db.Close()
		t.Fatal("a database from a newer version was opened")
	} else if !strings.Contains(err.Error(), "newer version") {
		t.Errorf("the error does not say why: %v", err)
	}
}

func TestPrepareDirCreatesItPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	warning, err := PrepareDir(dir)
	if err != nil || warning != "" {
		t.Fatalf("warning=%q err=%v", warning, err)
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatalf("the directory was not created: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Errorf("mode %04o, want 0700", info.Mode().Perm())
	}
}

func TestPrepareDirWarnsAboutAnOpenOne(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no permission bits to check")
	}
	dir := t.TempDir()

	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	warning, err := PrepareDir(dir)
	if err != nil || !strings.Contains(warning, "chmod 700") {
		t.Errorf("0755: warning=%q err=%v", warning, err)
	}
	// It only warns: the mode is the owner's to change.
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o755 {
		t.Errorf("PrepareDir changed the mode to %04o", info.Mode().Perm())
	}

	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if warning, err := PrepareDir(dir); err != nil || warning != "" {
		t.Errorf("0700: warning=%q err=%v", warning, err)
	}
}

func TestPrepareDirRefusesAFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareDir(file); err == nil {
		t.Fatal("a file was accepted as the data directory")
	}
}
