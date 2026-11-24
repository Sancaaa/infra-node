package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"infra-manager/internal/store"
)

// userCommand handles local account administration: creating the first admin
// (`user create --admin NAME`) and resetting a locked-out user's authenticator
// (`user totp-reset NAME`).
func userCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("usage:\n  infra-manager user create --admin [-data DIR] NAME\n  infra-manager user totp-reset [-data DIR] NAME")
	}
	switch args[0] {
	case "create":
		return userCreate(args[1:])
	case "totp-reset":
		return userTOTPReset(args[1:])
	default:
		return errors.New("usage:\n  infra-manager user create --admin [-data DIR] NAME\n  infra-manager user totp-reset [-data DIR] NAME")
	}
}

func userCreate(args []string) error {
	flags := flag.NewFlagSet("user create", flag.ExitOnError)
	dataDir := flags.String("data", defaultData, "the folder with the database")
	admin := flags.Bool("admin", false, "create an admin (the only kind this command makes)")
	flags.Parse(args) // ExitOnError: a bad flag prints the usage and stops

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

func userTOTPReset(args []string) error {
	flags := flag.NewFlagSet("user totp-reset", flag.ContinueOnError)
	dataDir := flags.String("data", defaultData, "the folder with the database")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("give the user name once, after the flags: infra-manager user totp-reset [-data DIR] NAME")
	}

	// Same non-root safety check as user create: SQLite -wal/-shm files must stay
	// owned by the service user.
	if os.Geteuid() == 0 {
		return errors.New("do not run this as root. Run it as the service's user:\n  sudo -u infra-manager infra-manager user totp-reset " + flags.Arg(0))
	}

	dbPath := filepath.Join(*dataDir, store.DBFile)
	if _, err := os.Stat(dbPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no database found at %s (pass -data DIR)", dbPath)
		}
		return err
	}
	db, err := store.OpenDB(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	name := store.NormalizeUsername(flags.Arg(0))
	u, _, err := store.FindForLogin(db, name)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no user named %q", name)
	}
	if err != nil {
		return err
	}
	if err := store.ResetTOTP(db, u.ID); err != nil {
		return err
	}
	_ = store.AddEvent(db, store.Event{
		Username: "cli",
		Action:   "user.totp.reset",
		Target:   "user " + u.Username,
		Result:   store.ResultOK,
		Detail:   "reset via CLI; their sessions were ended",
	})
	fmt.Printf("Reset authenticator for %q and ended all of their sessions. They will set up a new authenticator on next login.\n", u.Username)
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
