package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrHostNameTaken    = errors.New("Another host already has that name.")
	ErrHostAddressTaken = errors.New("Another host already has that address and port.")
)

// Host is a machine the dashboard manages. There is no password in it: see
// migration 5.
type Host struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	User    string `json:"user"`
	// Whether commands can be run as root without a password. Without it the
	// host can be looked at but not configured.
	SudoOK           bool   `json:"sudo_ok"`
	SudoersInstalled bool   `json:"-"` // the dashboard wrote the sudo rule
	Status           string `json:"status"`
	StatusDetail     string `json:"status_detail"`
	StatusAt         int64  `json:"status_at"`
	HostKeyFP        string `json:"host_key_fp"`
	PresentedFP      string `json:"presented_fp,omitempty"`
	FactsJSON        string `json:"-"` // the page gets it as "facts", parsed
	FactsAt          int64  `json:"facts_at"`
	CreatedAt        int64  `json:"created_at"`
	HealthJSON       string `json:"-"` // the page gets it as "health", parsed
	HealthAt         int64  `json:"health_at"`
	LastSeen         int64  `json:"last_seen"` // the last time the host answered
}

const hostColumns = `id, name, address, port, username, sudo_ok, sudoers_installed, status, status_detail, status_at,
	host_key_fp, presented_fp, facts, facts_at, created_at, health, health_at, last_seen`

type hostScanner interface{ Scan(dest ...any) error }

func scanHost(row hostScanner) (Host, error) {
	var h Host
	var sudo, installed int
	err := row.Scan(&h.ID, &h.Name, &h.Address, &h.Port, &h.User, &sudo, &installed, &h.Status, &h.StatusDetail, &h.StatusAt,
		&h.HostKeyFP, &h.PresentedFP, &h.FactsJSON, &h.FactsAt, &h.CreatedAt, &h.HealthJSON, &h.HealthAt, &h.LastSeen)
	h.SudoOK, h.SudoersInstalled = sudo == 1, installed == 1
	return h, err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// HostConflict says whether a name or an address:port is already in use by a
// host other than exceptID (0 when adding), so a form can be refused before it
// connects to anything.
func HostConflict(db *sql.DB, name, address string, port int, exceptID int64) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM hosts WHERE name = ? AND id <> ?`, name, exceptID).Scan(&n); err != nil {
		return fmt.Errorf("check the host name: %w", err)
	}
	if n > 0 {
		return ErrHostNameTaken
	}
	// A group with the same name: Ansible could not tell which one "web" means.
	if err := db.QueryRow(`SELECT COUNT(*) FROM groups WHERE name = ?`, name).Scan(&n); err != nil {
		return fmt.Errorf("check the host name: %w", err)
	}
	if n > 0 {
		return ErrNameIsGroup
	}
	// A pending Proxmox machine with the same name: it becomes a host of that name.
	if err := db.QueryRow(`SELECT COUNT(*) FROM machines WHERE name = ? AND (host_id IS NULL OR host_id <> ?)`, name, exceptID).Scan(&n); err != nil {
		return fmt.Errorf("check the host name: %w", err)
	}
	if n > 0 {
		return ErrNameIsMachine
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM hosts WHERE address = ? AND port = ? AND id <> ?`, address, port, exceptID).Scan(&n); err != nil {
		return fmt.Errorf("check the host address: %w", err)
	}
	if n > 0 {
		return ErrHostAddressTaken
	}
	return nil
}

// CreateHost saves a new host. ID and CreatedAt are set.
func CreateHost(db *sql.DB, h Host, now time.Time) (Host, error) {
	res, err := db.Exec(`INSERT INTO hosts (name, address, port, username, sudo_ok, sudoers_installed, status, status_detail, status_at,
			host_key_fp, presented_fp, facts, facts_at, created_at, health, health_at, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.Name, h.Address, h.Port, h.User, b2i(h.SudoOK), b2i(h.SudoersInstalled), h.Status, h.StatusDetail, h.StatusAt,
		h.HostKeyFP, h.PresentedFP, h.FactsJSON, h.FactsAt, now.Unix(), h.HealthJSON, h.HealthAt, h.LastSeen)
	if err != nil {
		// Two requests adding the same host at the same moment get past
		// HostConflict together; the UNIQUE constraints decide.
		switch {
		case isUniqueViolation(err) && strings.Contains(err.Error(), "hosts.name"):
			return Host{}, ErrHostNameTaken
		case isUniqueViolation(err):
			return Host{}, ErrHostAddressTaken
		}
		return Host{}, fmt.Errorf("store the host: %w", err)
	}
	if h.ID, err = res.LastInsertId(); err != nil {
		return Host{}, fmt.Errorf("read the new host's id: %w", err)
	}
	h.CreatedAt = now.Unix()
	return h, nil
}

func GetHost(db *sql.DB, id int64) (Host, error) {
	h, err := scanHost(db.QueryRow(`SELECT `+hostColumns+` FROM hosts WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, ErrNotFound
	}
	if err != nil {
		return Host{}, fmt.Errorf("read the host: %w", err)
	}
	return h, nil
}

func ListHosts(db *sql.DB) ([]Host, error) {
	rows, err := db.Query(`SELECT ` + hostColumns + ` FROM hosts ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}
	defer rows.Close()

	hosts := []Host{}
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, fmt.Errorf("read a host: %w", err)
		}
		hosts = append(hosts, h)
	}
	return hosts, rows.Err()
}

// UpdateHostConnection saves what a person edits about how to reach a host,
// and what that connection found out about sudo and the host's key.
//
// It is separate from SetHostStatus and SetHostFacts on purpose: the health
// check of IM3 writes those every minute, and one function that wrote
// everything would let a check undo an edit made a second earlier.
func UpdateHostConnection(db *sql.DB, h Host) error {
	res, err := db.Exec(`UPDATE hosts SET name = ?, address = ?, port = ?, username = ?, sudo_ok = ?, sudoers_installed = ?, host_key_fp = ?
		WHERE id = ?`, h.Name, h.Address, h.Port, h.User, b2i(h.SudoOK), b2i(h.SudoersInstalled), h.HostKeyFP, h.ID)
	if err != nil {
		switch {
		case isUniqueViolation(err) && strings.Contains(err.Error(), "hosts.name"):
			return ErrHostNameTaken
		case isUniqueViolation(err):
			return ErrHostAddressTaken
		}
		return fmt.Errorf("update the host: %w", err)
	}
	return expectRow(res)
}

// SetHostStatus records the result of trying to reach a host. presentedFP is
// only for 'key_changed'.
func SetHostStatus(db *sql.DB, id int64, status, detail, presentedFP string, at time.Time) error {
	res, err := db.Exec(`UPDATE hosts SET status = ?, status_detail = ?, presented_fp = ?, status_at = ? WHERE id = ?`,
		status, detail, presentedFP, at.Unix(), id)
	if err != nil {
		return fmt.Errorf("record the host's status: %w", err)
	}
	return expectRow(res)
}

// SetHostFacts records what a connection learned about a host, and that sudo
// works or not.
func SetHostFacts(db *sql.DB, id int64, factsJSON string, sudoOK bool, at time.Time) error {
	res, err := db.Exec(`UPDATE hosts SET facts = ?, sudo_ok = ?, facts_at = ? WHERE id = ?`, factsJSON, b2i(sudoOK), at.Unix(), id)
	if err != nil {
		return fmt.Errorf("record the host's facts: %w", err)
	}
	return expectRow(res)
}

// SetHostHealth records a successful check: the host answered, so it is online,
// whatever it was before, and whatever was wrong with it (an unknown key, a
// refused login) is gone.
func SetHostHealth(db *sql.DB, id int64, healthJSON string, at time.Time) error {
	res, err := db.Exec(`UPDATE hosts SET health = ?, health_at = ?, last_seen = ?,
			status = 'online', status_detail = '', presented_fp = '', status_at = ? WHERE id = ?`,
		healthJSON, at.Unix(), at.Unix(), at.Unix(), id)
	if err != nil {
		return fmt.Errorf("record the host's health: %w", err)
	}
	return expectRow(res)
}

func DeleteHost(db *sql.DB, id int64) error {
	res, err := db.Exec(`DELETE FROM hosts WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete the host: %w", err)
	}
	return expectRow(res)
}

func CountHosts(db *sql.DB) (int, error) {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM hosts`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count hosts: %w", err)
	}
	return n, nil
}

func expectRow(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("count the changed rows: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
