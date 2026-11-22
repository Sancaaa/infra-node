// Package store is the data directory and the database inside it: everything
// the dashboard remembers lives under one folder, so a backup is one copy.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"

	_ "modernc.org/sqlite" // pure Go, registers itself as "sqlite" (OD-06, the same driver as headnode)
)

// DBFile is the database's name inside the data directory.
const DBFile = "infra-manager.db"

// PrepareDir makes sure the data directory exists and is private. Later it
// holds the SSH key that opens every managed host, the Proxmox token and the
// vault password, so nobody but its owner may read it.
//
// A new directory is created 0700. An existing one is left as it is, and a
// warning comes back if other users can enter it: changing the permissions of a
// folder somebody else made is not this program's call. (The installer, which
// runs as root, does set them.)
func PrepareDir(dir string) (warning string, err error) {
	info, err := os.Stat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("create the data directory %s: %w", dir, err)
		}
		return "", nil
	case err != nil:
		return "", fmt.Errorf("look at the data directory %s: %w", dir, err)
	case !info.IsDir():
		return "", fmt.Errorf("%s is not a directory", dir)
	}

	if tooOpen(info.Mode()) {
		return fmt.Sprintf("the data directory %s has mode %04o, so other users can read it. "+
			"It will hold keys and secrets: run `chmod 700 %s`", dir, info.Mode().Perm(), dir), nil
	}
	return "", nil
}

// tooOpen reports whether group or others have any access. Windows has no such
// permission bits (a directory always looks 0777 there), so it never warns.
func tooOpen(mode fs.FileMode) bool {
	return runtime.GOOS != "windows" && mode.Perm()&0o077 != 0
}

// OpenDB opens the database at path, creating it if needed, and runs the
// migrations that have not run yet.
func OpenDB(path string) (*sql.DB, error) {
	// WAL lets readers and the writer work at the same time. busy_timeout makes a
	// second writer wait up to 5 s instead of failing at once with "database is
	// locked": health checks and requests will write together. foreign_keys is off
	// in SQLite unless asked for. Each pragma runs on every new connection.
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
