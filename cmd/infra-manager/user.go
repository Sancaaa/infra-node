package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"infra-manager/internal/store"
)

// userCommand is `infra-manager user create --admin NAME`: the first admin,
// made before there is anybody to log in and make others. Everyone after that
// is created on the Users page.
func userCommand(args []string) error {
	if len(args) == 0 || args[0] != "create" {
		return errors.New("usage: infra-manager user create --admin [-data DIR] NAME")
	}
	flags := flag.NewFlagSet("user create", flag.ExitOnError)
	dataDir := flags.String("data", defaultData, "the folder with the database")
	admin := flags.Bool("admin", false, "create an admin (the only kind this command makes)")
	flags.Parse(args[1:]) // ExitOnError: a bad flag prints the usage and stops

	if flags.NArg() != 1 {
		return errors.New("give the user name once, after the flags: infra-manager user create --admin NAME")
	}
	if !*admin {
		return errors.New("--admin is required: this command only makes the first admin, and the Users page makes everybody else")
	}

	// Opening the database as root would leave files in the data folder that the
	// service (its own user) cannot write: SQLite creates the -wal and -shm files
	// with the owner of the process that opens it first.
	if os.Geteuid() == 0 {
		return errors.New("do not run this as root. Run it as the service's user:\n  sudo -u infra-manager infra-manager user create --admin " + flags.Arg(0))
	}

	warning, err := store.PrepareDir(*dataDir)
	if err != nil {
		return err
	}
	if warning != "" {
		fmt.Fprintln(os.Stderr, "warning:", warning)
	}
	db, err := store.OpenDB(filepath.Join(*dataDir, store.DBFile))
	if err != nil {
		return err
	}
	defer db.Close()

	password, err := askNewPassword()
	if err != nil {
		return err
	}
	u, err := store.CreateUser(db, flags.Arg(0), password, store.RoleAdmin)
	if err != nil {
		return err
	}
	fmt.Printf("Created the admin %q. Log in on the dashboard's page with that name and password.\n", u.Username)
	return nil
}

// askNewPassword asks twice, on a terminal, so a typo is not locked in. When
// the input is not a terminal (a pipe, for a script) it reads one line.
func askNewPassword() (string, error) {
	password, interactive, err := readPassword(fmt.Sprintf("Password (%d to %d characters): ", store.MinPasswordLen, store.MaxPasswordLen))
	if err != nil {
		return "", err
	}
	if interactive {
		again, _, err := readPassword("Again: ")
		if err != nil {
			return "", err
		}
		if again != password {
			return "", errors.New("the two passwords are not the same")
		}
	}
	return password, nil
}
