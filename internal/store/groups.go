package store

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"
)

var (
	ErrGroupNameTaken = errors.New("Another group already has that name.")
	ErrNameIsHost     = errors.New("A host already has that name. Ansible could not tell the host from the group.")
	ErrNameIsGroup    = errors.New("A group already has that name. Ansible could not tell the host from the group.")
)

// Group is a named set of hosts: what a profile is given to, and what an Ansible
// run is aimed at.
type Group struct {
	ID        int64   `json:"id"`
	Name      string  `json:"name"`
	CreatedAt int64   `json:"created_at"`
	HostIDs   []int64 `json:"host_ids"`
}

// Var is one variable of a group or a host.
type Var struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func CreateGroup(db *sql.DB, name string, now time.Time) (Group, error) {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM hosts WHERE name = ?`, name).Scan(&n); err != nil {
		return Group{}, fmt.Errorf("check the group name: %w", err)
	}
	if n > 0 {
		return Group{}, ErrNameIsHost
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM machines WHERE name = ?`, name).Scan(&n); err != nil {
		return Group{}, fmt.Errorf("check the group name: %w", err)
	}
	if n > 0 {
		return Group{}, ErrNameIsMachine
	}
	res, err := db.Exec(`INSERT INTO groups (name, created_at) VALUES (?, ?)`, name, now.Unix())
	if isUniqueViolation(err) {
		return Group{}, ErrGroupNameTaken
	}
	if err != nil {
		return Group{}, fmt.Errorf("store the group: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Group{}, fmt.Errorf("read the new group's id: %w", err)
	}
	return Group{ID: id, Name: name, CreatedAt: now.Unix(), HostIDs: []int64{}}, nil
}

// ListGroups returns every group with the ids of its hosts, by name.
func ListGroups(db *sql.DB) ([]Group, error) {
	rows, err := db.Query(`SELECT id, name, created_at FROM groups ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	groups := []Group{}
	byID := map[int64]int{}
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.CreatedAt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("read a group: %w", err)
		}
		g.HostIDs = []int64{}
		byID[g.ID] = len(groups)
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	members, err := db.Query(`SELECT group_id, host_id FROM group_hosts ORDER BY host_id`)
	if err != nil {
		return nil, fmt.Errorf("list group members: %w", err)
	}
	defer members.Close()
	for members.Next() {
		var groupID, hostID int64
		if err := members.Scan(&groupID, &hostID); err != nil {
			return nil, fmt.Errorf("read a group member: %w", err)
		}
		if i, ok := byID[groupID]; ok {
			groups[i].HostIDs = append(groups[i].HostIDs, hostID)
		}
	}
	return groups, members.Err()
}

func GetGroup(db *sql.DB, id int64) (Group, error) {
	groups, err := ListGroups(db)
	if err != nil {
		return Group{}, err
	}
	for _, g := range groups {
		if g.ID == id {
			return g, nil
		}
	}
	return Group{}, ErrNotFound
}

func RenameGroup(db *sql.DB, id int64, name string) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM hosts WHERE name = ?`, name).Scan(&n); err != nil {
		return fmt.Errorf("check the group name: %w", err)
	}
	if n > 0 {
		return ErrNameIsHost
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM machines WHERE name = ?`, name).Scan(&n); err != nil {
		return fmt.Errorf("check the group name: %w", err)
	}
	if n > 0 {
		return ErrNameIsMachine
	}
	res, err := db.Exec(`UPDATE groups SET name = ? WHERE id = ?`, name, id)
	if isUniqueViolation(err) {
		return ErrGroupNameTaken
	}
	if err != nil {
		return fmt.Errorf("rename the group: %w", err)
	}
	return expectRow(res)
}

// DeleteGroup removes a group, its memberships and its variables. The hosts stay.
func DeleteGroup(db *sql.DB, id int64) error {
	res, err := db.Exec(`DELETE FROM groups WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete the group: %w", err)
	}
	return expectRow(res)
}

// ChangeGroupHosts adds and removes members in one transaction: several at
// once, and either all or none. A host that does not exist is ErrNotFound.
func ChangeGroupHosts(db *sql.DB, groupID int64, add, remove []int64) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback() // does nothing after a commit

	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM groups WHERE id = ?`, groupID).Scan(&n); err != nil {
		return fmt.Errorf("find the group: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	for _, id := range add {
		if err := tx.QueryRow(`SELECT COUNT(*) FROM hosts WHERE id = ?`, id).Scan(&n); err != nil {
			return fmt.Errorf("find the host: %w", err)
		}
		if n == 0 {
			return ErrNotFound
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO group_hosts (group_id, host_id) VALUES (?, ?)`, groupID, id); err != nil {
			return fmt.Errorf("add a host to the group: %w", err)
		}
	}
	for _, id := range remove {
		if _, err := tx.Exec(`DELETE FROM group_hosts WHERE group_id = ? AND host_id = ?`, groupID, id); err != nil {
			return fmt.Errorf("remove a host from the group: %w", err)
		}
	}
	return tx.Commit()
}

// HostGroupNames maps each host id to the names of its groups, for the Hosts table.
func HostGroupNames(db *sql.DB) (map[int64][]string, error) {
	rows, err := db.Query(`SELECT gh.host_id, g.name FROM group_hosts gh JOIN groups g ON g.id = gh.group_id ORDER BY g.name`)
	if err != nil {
		return nil, fmt.Errorf("list the groups of hosts: %w", err)
	}
	defer rows.Close()
	out := map[int64][]string{}
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, fmt.Errorf("read a membership: %w", err)
		}
		out[id] = append(out[id], name)
	}
	return out, rows.Err()
}

// ------------------------------------------------------------------ variables

func sortVars(vars []Var) []Var {
	sort.Slice(vars, func(i, j int) bool { return vars[i].Key < vars[j].Key })
	return vars
}

func readVars(db *sql.DB, query string, id int64) ([]Var, error) {
	rows, err := db.Query(query, id)
	if err != nil {
		return nil, fmt.Errorf("read variables: %w", err)
	}
	defer rows.Close()
	vars := []Var{}
	for rows.Next() {
		var v Var
		if err := rows.Scan(&v.Key, &v.Value); err != nil {
			return nil, fmt.Errorf("read a variable: %w", err)
		}
		vars = append(vars, v)
	}
	return sortVars(vars), rows.Err()
}

func GroupVars(db *sql.DB, groupID int64) ([]Var, error) {
	return readVars(db, `SELECT key, value FROM group_vars WHERE group_id = ?`, groupID)
}

func HostVars(db *sql.DB, hostID int64) ([]Var, error) {
	return readVars(db, `SELECT key, value FROM host_vars WHERE host_id = ?`, hostID)
}

// setVars replaces all of an owner's variables in one transaction. table and
// column are this package's own constants, never input.
func setVars(db *sql.DB, table, column string, id int64, vars []Var) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	var n int
	owner := map[string]string{"group_vars": "groups", "host_vars": "hosts"}[table]
	if err := tx.QueryRow(`SELECT COUNT(*) FROM `+owner+` WHERE id = ?`, id).Scan(&n); err != nil {
		return fmt.Errorf("find the owner: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(`DELETE FROM `+table+` WHERE `+column+` = ?`, id); err != nil {
		return fmt.Errorf("clear the variables: %w", err)
	}
	for _, v := range vars {
		if _, err := tx.Exec(`INSERT INTO `+table+` (`+column+`, key, value) VALUES (?, ?, ?)`, id, v.Key, v.Value); err != nil {
			return fmt.Errorf("store a variable: %w", err)
		}
	}
	return tx.Commit()
}

func SetGroupVars(db *sql.DB, groupID int64, vars []Var) error {
	return setVars(db, "group_vars", "group_id", groupID, vars)
}

func SetHostVars(db *sql.DB, hostID int64, vars []Var) error {
	return setVars(db, "host_vars", "host_id", hostID, vars)
}

func allVars(db *sql.DB, query string) (map[int64][]Var, error) {
	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("read variables: %w", err)
	}
	defer rows.Close()
	out := map[int64][]Var{}
	for rows.Next() {
		var id int64
		var v Var
		if err := rows.Scan(&id, &v.Key, &v.Value); err != nil {
			return nil, fmt.Errorf("read a variable: %w", err)
		}
		out[id] = append(out[id], v)
	}
	for id := range out {
		sortVars(out[id])
	}
	return out, rows.Err()
}

// AllGroupVars and AllHostVars are for generating the Ansible files: every
// variable, by owner.
func AllGroupVars(db *sql.DB) (map[int64][]Var, error) {
	return allVars(db, `SELECT group_id, key, value FROM group_vars`)
}

func AllHostVars(db *sql.DB) (map[int64][]Var, error) {
	return allVars(db, `SELECT host_id, key, value FROM host_vars`)
}
