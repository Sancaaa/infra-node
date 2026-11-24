package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"infra-manager/internal/store"
)

func TestCheckListen(t *testing.T) {
	good := map[string]bool{ // address → is it this machine's own
		"127.0.0.1:8095": true,
		"localhost:8095": true,
		"[::1]:8095":     true,
		"0.0.0.0:8095":   false,
		"10.0.0.5:80":    false,
	}
	for addr, wantLoopback := range good {
		got, err := checkListen(addr)
		if err != nil || got != wantLoopback {
			t.Errorf("checkListen(%q) = %v, %v; want %v, nil", addr, got, err, wantLoopback)
		}
	}

	// The last two would otherwise end up inside the systemd unit.
	for _, bad := range []string{"", "8095", ":8095", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:70000",
		"127.0.0.1:http", "example.com:80", "127.0.0.1:80\nUser=root", "127.0.0.1 :80"} {
		if _, err := checkListen(bad); err == nil {
			t.Errorf("checkListen(%q) was accepted", bad)
		}
	}
}

// The unit is the part of the installer that decides who the service runs as.
func TestUnitFileRunsAsItsOwnUser(t *testing.T) {
	unit := unitFile("/usr/local/bin/infra-manager", "127.0.0.1:8095")

	for _, want := range []string{
		"\nUser=infra-manager\n",
		"\nGroup=infra-manager\n",
		"\nExecStart=/usr/local/bin/infra-manager serve -data /var/lib/infra-manager -listen 127.0.0.1:8095\n",
		"\nStateDirectory=infra-manager\n",
		"\nStateDirectoryMode=0700\n",
		"\nNoNewPrivileges=true\n",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("the unit has no %q:\n%s", strings.TrimSpace(want), unit)
		}
	}
	if strings.Contains(unit, "User=root") {
		t.Error("the service would run as root")
	}
	// The data folder in ExecStart must be the one StateDirectory creates.
	if serviceData != "/var/lib/"+serviceName {
		t.Errorf("serviceData %q does not match StateDirectory=%s", serviceData, serviceName)
	}
}

func TestUserTOTPResetCLI(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, store.DBFile)

	// Missing database is refused instead of creating an empty one.
	if err := userCommand([]string{"totp-reset", "-data", dir, "ada"}); err == nil {
		t.Fatal("expected error when database does not exist")
	}

	db, err := store.OpenDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ada, err := store.CreateUser(db, "ada", "correct horse battery", store.RoleAdmin)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	bob, err := store.CreateUser(db, "bob", "correct horse battery", store.RoleViewer)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	for _, u := range []store.User{ada, bob} {
		if _, _, err := store.EnsureTOTPSecret(db, u.ID); err != nil {
			db.Close()
			t.Fatal(err)
		}
		if err := store.EnableTOTP(db, u.ID, 500); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	now := time.Now()
	adaToken, err := store.CreateSession(db, ada.ID, "127.0.0.1", "test", now)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	bobToken, err := store.CreateSession(db, bob.ID, "127.0.0.1", "test", now)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()

	// Unknown user returns an error.
	if err := userCommand([]string{"totp-reset", "-data", dir, "nobody"}); err == nil {
		t.Fatal("expected error for unknown user")
	}

	// Resetting ada clears her TOTP and sessions without touching bob.
	if err := userCommand([]string{"totp-reset", "-data", dir, "ADA"}); err != nil {
		t.Fatalf("user totp-reset: %v", err)
	}

	db, err = store.OpenDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	sec, enabled, err := store.TOTPSecret(db, ada.ID)
	if err != nil || enabled || sec != "" {
		t.Errorf("ada TOTP after CLI reset = (%q, %v, %v), want empty/false", sec, enabled, err)
	}
	if _, err := store.SessionUser(db, adaToken, now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("ada session survived CLI reset: %v", err)
	}
	if _, enabled, err := store.TOTPSecret(db, bob.ID); err != nil || !enabled {
		t.Errorf("bob TOTP was affected: enabled=%v err=%v", enabled, err)
	}
	if _, err := store.SessionUser(db, bobToken, now); err != nil {
		t.Errorf("bob session was affected: %v", err)
	}
}
