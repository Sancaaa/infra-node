package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"infra-manager/internal/ansible"
)

// Profiles: the roles a group or a host is configured with, and what has been
// applied so far.

// A profile row belongs to a group or to a host.
const (
	ScopeGroup = "group"
	ScopeHost  = "host"
)

func scopeColumns(scope string) (table, column string, err error) {
	switch scope {
	case ScopeGroup:
		return "groups", "group_id", nil
	case ScopeHost:
		return "hosts", "host_id", nil
	}
	return "", "", fmt.Errorf("unknown profile scope %q", scope)
}

// GetProfile returns the roles of a group's or a host's own profile.
func GetProfile(db *sql.DB, scope string, id int64) ([]ansible.ProfileRole, error) {
	_, column, err := scopeColumns(scope)
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT role, params FROM profile_roles WHERE `+column+` = ? ORDER BY id`, id)
	if err != nil {
		return nil, fmt.Errorf("read the profile: %w", err)
	}
	defer rows.Close()
	return scanProfile(rows)
}

func scanProfile(rows *sql.Rows) ([]ansible.ProfileRole, error) {
	roles := []ansible.ProfileRole{}
	for rows.Next() {
		var role, params string
		if err := rows.Scan(&role, &params); err != nil {
			return nil, fmt.Errorf("read a profile role: %w", err)
		}
		pr := ansible.ProfileRole{Role: role, Params: map[string]any{}}
		if err := json.Unmarshal([]byte(params), &pr.Params); err != nil {
			return nil, fmt.Errorf("read the parameters of %s: %w", role, err)
		}
		roles = append(roles, pr)
	}
	return roles, rows.Err()
}

// SetProfile replaces a profile in one transaction. The caller has checked the
// roles and their parameters (ansible.CheckProfile).
func SetProfile(db *sql.DB, scope string, id int64, roles []ansible.ProfileRole) error {
	table, column, err := scopeColumns(scope)
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE id = ?`, id).Scan(&n); err != nil {
		return fmt.Errorf("find the owner: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(`DELETE FROM profile_roles WHERE `+column+` = ?`, id); err != nil {
		return fmt.Errorf("clear the profile: %w", err)
	}
	for _, pr := range roles {
		params, err := json.Marshal(pr.Params)
		if err != nil {
			return fmt.Errorf("encode the parameters of %s: %w", pr.Role, err)
		}
		if _, err := tx.Exec(`INSERT INTO profile_roles (`+column+`, role, params) VALUES (?, ?, ?)`, id, pr.Role, string(params)); err != nil {
			return fmt.Errorf("store %s: %w", pr.Role, err)
		}
	}
	return tx.Commit()
}

// AllProfiles returns every profile, by group id and by host id: what the plans
// of all hosts are made from.
func AllProfiles(db *sql.DB) (groups, hosts map[int64][]ansible.ProfileRole, err error) {
	rows, err := db.Query(`SELECT group_id, host_id, role, params FROM profile_roles ORDER BY id`)
	if err != nil {
		return nil, nil, fmt.Errorf("read the profiles: %w", err)
	}
	defer rows.Close()
	groups, hosts = map[int64][]ansible.ProfileRole{}, map[int64][]ansible.ProfileRole{}
	for rows.Next() {
		var groupID, hostID sql.NullInt64
		var role, params string
		if err := rows.Scan(&groupID, &hostID, &role, &params); err != nil {
			return nil, nil, fmt.Errorf("read a profile role: %w", err)
		}
		pr := ansible.ProfileRole{Role: role, Params: map[string]any{}}
		if err := json.Unmarshal([]byte(params), &pr.Params); err != nil {
			return nil, nil, fmt.Errorf("read the parameters of %s: %w", role, err)
		}
		if groupID.Valid {
			groups[groupID.Int64] = append(groups[groupID.Int64], pr)
		} else {
			hosts[hostID.Int64] = append(hosts[hostID.Int64], pr)
		}
	}
	return groups, hosts, rows.Err()
}

// ------------------------------------------------------------ what was applied

// HostConfig is how the last run on a host went.
type HostConfig struct {
	HostID     int64  `json:"host_id"`
	Result     string `json:"result"` // "ok", "failed" or "" (never run)
	Detail     string `json:"detail"`
	RunAt      int64  `json:"run_at"`
	Idempotent int    `json:"idempotent"` // 1 yes, 0 no, -1 not checked since the last apply
}

// AppliedRoles maps host id → role → the fingerprint of what was last applied.
func AppliedRoles(db *sql.DB) (map[int64]map[string]string, error) {
	rows, err := db.Query(`SELECT host_id, role, hash FROM applied_roles`)
	if err != nil {
		return nil, fmt.Errorf("read what was applied: %w", err)
	}
	defer rows.Close()
	out := map[int64]map[string]string{}
	for rows.Next() {
		var id int64
		var role, hash string
		if err := rows.Scan(&id, &role, &hash); err != nil {
			return nil, fmt.Errorf("read an applied role: %w", err)
		}
		if out[id] == nil {
			out[id] = map[string]string{}
		}
		out[id][role] = hash
	}
	return out, rows.Err()
}

func AllHostConfig(db *sql.DB) (map[int64]HostConfig, error) {
	rows, err := db.Query(`SELECT host_id, result, detail, run_at, idempotent FROM host_config`)
	if err != nil {
		return nil, fmt.Errorf("read how the runs went: %w", err)
	}
	defer rows.Close()
	out := map[int64]HostConfig{}
	for rows.Next() {
		var c HostConfig
		if err := rows.Scan(&c.HostID, &c.Result, &c.Detail, &c.RunAt, &c.Idempotent); err != nil {
			return nil, fmt.Errorf("read a run: %w", err)
		}
		out[c.HostID] = c
	}
	return out, rows.Err()
}

// RecordRun saves how a run went on a host. When it worked, the roles that ran
// are marked as applied, each with the fingerprint it was applied with (hashes:
// role → fingerprint). A run that failed marks nothing as applied: what
// succeeded before the failure is not trusted, and the next run is cheap
// because the tasks are idempotent. A new run forgets the verdict of the last
// "Check again".
func RecordRun(db *sql.DB, hostID int64, ok bool, detail string, hashes map[string]string, at time.Time) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	result := "failed"
	if ok {
		result = "ok"
	}
	if _, err := tx.Exec(`INSERT INTO host_config (host_id, result, detail, run_at, idempotent) VALUES (?, ?, ?, ?, -1)
		ON CONFLICT(host_id) DO UPDATE SET result = excluded.result, detail = excluded.detail, run_at = excluded.run_at, idempotent = -1`,
		hostID, result, detail, at.Unix()); err != nil {
		return fmt.Errorf("record the run: %w", err)
	}
	if ok {
		for role, hash := range hashes {
			if _, err := tx.Exec(`INSERT INTO applied_roles (host_id, role, hash, applied_at) VALUES (?, ?, ?, ?)
				ON CONFLICT(host_id, role) DO UPDATE SET hash = excluded.hash, applied_at = excluded.applied_at`,
				hostID, role, hash, at.Unix()); err != nil {
				return fmt.Errorf("record %s as applied: %w", role, err)
			}
		}
	}
	return tx.Commit()
}

// SetIdempotent records what "Check again" found: whether a second run changed
// nothing.
func SetIdempotent(db *sql.DB, hostID int64, idempotent bool) error {
	v := 0
	if idempotent {
		v = 1
	}
	res, err := db.Exec(`UPDATE host_config SET idempotent = ? WHERE host_id = ?`, v, hostID)
	if err != nil {
		return fmt.Errorf("record the verdict: %w", err)
	}
	return expectRow(res)
}
