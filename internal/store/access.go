package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrAccessNameTaken = errors.New("Another key already has that name.")
	ErrAccessKeyTaken  = errors.New("That key is already on the list, under another name.")
)

// AccessKey is a person's SSH public key, with where it may log in.
type AccessKey struct {
	ID        int64   `json:"id"`
	Name      string  `json:"name"`
	PublicKey string  `json:"public_key"`
	User      string  `json:"user"` // the account on the hosts, or "" for the user the dashboard logs in as
	CreatedAt int64   `json:"created_at"`
	GroupIDs  []int64 `json:"group_ids"`
	HostIDs   []int64 `json:"host_ids"`
}

func CreateAccessKey(db *sql.DB, name, publicKey, user string, now time.Time) (AccessKey, error) {
	res, err := db.Exec(`INSERT INTO access_keys (name, public_key, username, created_at) VALUES (?, ?, ?, ?)`,
		name, publicKey, user, now.Unix())
	if err != nil {
		switch {
		case isUniqueViolation(err) && strings.Contains(err.Error(), "access_keys.name"):
			return AccessKey{}, ErrAccessNameTaken
		case isUniqueViolation(err):
			return AccessKey{}, ErrAccessKeyTaken
		}
		return AccessKey{}, fmt.Errorf("store the key: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return AccessKey{}, fmt.Errorf("read the new key's id: %w", err)
	}
	return AccessKey{ID: id, Name: name, PublicKey: publicKey, User: user, CreatedAt: now.Unix(), GroupIDs: []int64{}, HostIDs: []int64{}}, nil
}

// ListAccessKeys returns every key with the groups and hosts it was given, by name.
func ListAccessKeys(db *sql.DB) ([]AccessKey, error) {
	rows, err := db.Query(`SELECT id, name, public_key, username, created_at FROM access_keys ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}
	keys := []AccessKey{}
	index := map[int64]int{}
	for rows.Next() {
		var k AccessKey
		if err := rows.Scan(&k.ID, &k.Name, &k.PublicKey, &k.User, &k.CreatedAt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("read a key: %w", err)
		}
		k.GroupIDs, k.HostIDs = []int64{}, []int64{}
		index[k.ID] = len(keys)
		keys = append(keys, k)
	}
	rows.Close()

	grants, err := db.Query(`SELECT key_id, group_id, host_id FROM access_grants ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list grants: %w", err)
	}
	defer grants.Close()
	for grants.Next() {
		var keyID int64
		var groupID, hostID sql.NullInt64
		if err := grants.Scan(&keyID, &groupID, &hostID); err != nil {
			return nil, fmt.Errorf("read a grant: %w", err)
		}
		i, ok := index[keyID]
		if !ok {
			continue
		}
		if groupID.Valid {
			keys[i].GroupIDs = append(keys[i].GroupIDs, groupID.Int64)
		} else {
			keys[i].HostIDs = append(keys[i].HostIDs, hostID.Int64)
		}
	}
	return keys, grants.Err()
}

func GetAccessKey(db *sql.DB, id int64) (AccessKey, error) {
	keys, err := ListAccessKeys(db)
	if err != nil {
		return AccessKey{}, err
	}
	for _, k := range keys {
		if k.ID == id {
			return k, nil
		}
	}
	return AccessKey{}, ErrNotFound
}

// SetAccessGrants replaces the groups and hosts a key may log in to, in one
// transaction. A group or host that does not exist is ErrNotFound.
func SetAccessGrants(db *sql.DB, keyID int64, groupIDs, hostIDs []int64) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM access_keys WHERE id = ?`, keyID).Scan(&n); err != nil || n == 0 {
		if err != nil {
			return fmt.Errorf("find the key: %w", err)
		}
		return ErrNotFound
	}
	if _, err := tx.Exec(`DELETE FROM access_grants WHERE key_id = ?`, keyID); err != nil {
		return fmt.Errorf("clear the grants: %w", err)
	}
	for _, id := range groupIDs {
		if err := tx.QueryRow(`SELECT COUNT(*) FROM groups WHERE id = ?`, id).Scan(&n); err != nil || n == 0 {
			if err != nil {
				return fmt.Errorf("find the group: %w", err)
			}
			return ErrNotFound
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO access_grants (key_id, group_id) VALUES (?, ?)`, keyID, id); err != nil {
			return fmt.Errorf("grant a group: %w", err)
		}
	}
	for _, id := range hostIDs {
		if err := tx.QueryRow(`SELECT COUNT(*) FROM hosts WHERE id = ?`, id).Scan(&n); err != nil || n == 0 {
			if err != nil {
				return fmt.Errorf("find the host: %w", err)
			}
			return ErrNotFound
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO access_grants (key_id, host_id) VALUES (?, ?)`, keyID, id); err != nil {
			return fmt.Errorf("grant a host: %w", err)
		}
	}
	return tx.Commit()
}

// DeleteAccessKey forgets a key and what it was given. What was put on hosts
// stays in access_installed, so the next run of the access playbook takes it off.
func DeleteAccessKey(db *sql.DB, id int64) error {
	res, err := db.Exec(`DELETE FROM access_keys WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete the key: %w", err)
	}
	return expectRow(res)
}

// InstalledKey is a key the dashboard put on a host.
type InstalledKey struct {
	Name      string
	PublicKey string
	User      string
}

// AllInstalled maps host id → the keys the dashboard put on it.
func AllInstalled(db *sql.DB) (map[int64][]InstalledKey, error) {
	rows, err := db.Query(`SELECT host_id, name, public_key, username FROM access_installed ORDER BY name, public_key`)
	if err != nil {
		return nil, fmt.Errorf("read what was installed: %w", err)
	}
	defer rows.Close()
	out := map[int64][]InstalledKey{}
	for rows.Next() {
		var id int64
		var k InstalledKey
		if err := rows.Scan(&id, &k.Name, &k.PublicKey, &k.User); err != nil {
			return nil, fmt.Errorf("read an installed key: %w", err)
		}
		out[id] = append(out[id], k)
	}
	return out, rows.Err()
}

// SaveInstalled records what is on a host after a run that worked: exactly these
// keys. Whatever else was recorded for the host (and was taken off) is forgotten.
func SaveInstalled(db *sql.DB, hostID int64, keys []InstalledKey) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM access_installed WHERE host_id = ?`, hostID); err != nil {
		return fmt.Errorf("clear what was installed: %w", err)
	}
	for _, k := range keys {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO access_installed (host_id, public_key, username, name) VALUES (?, ?, ?, ?)`,
			hostID, k.PublicKey, k.User, k.Name); err != nil {
			return fmt.Errorf("record an installed key: %w", err)
		}
	}
	return tx.Commit()
}

// ------------------------------------------------------------------- secrets

type Secret struct {
	Name      string `json:"name"`
	UpdatedAt int64  `json:"updated_at"`
}

// SetSecret stores the ciphertext of a secret, replacing an older one.
func SetSecret(db *sql.DB, name, ciphertext string, now time.Time) error {
	_, err := db.Exec(`INSERT INTO secrets (name, ciphertext, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET ciphertext = excluded.ciphertext, updated_at = excluded.updated_at`,
		name, ciphertext, now.Unix())
	if err != nil {
		return fmt.Errorf("store the secret: %w", err)
	}
	return nil
}

// ListSecrets returns the names of the secrets. There is no value to return.
func ListSecrets(db *sql.DB) ([]Secret, error) {
	rows, err := db.Query(`SELECT name, updated_at FROM secrets ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	defer rows.Close()
	out := []Secret{}
	for rows.Next() {
		var s Secret
		if err := rows.Scan(&s.Name, &s.UpdatedAt); err != nil {
			return nil, fmt.Errorf("read a secret: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// SecretCiphertexts maps name → the encrypted value, for the generated files.
func SecretCiphertexts(db *sql.DB) (map[string]string, error) {
	rows, err := db.Query(`SELECT name, ciphertext FROM secrets`)
	if err != nil {
		return nil, fmt.Errorf("read the secrets: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, cipher string
		if err := rows.Scan(&name, &cipher); err != nil {
			return nil, fmt.Errorf("read a secret: %w", err)
		}
		out[name] = cipher
	}
	return out, rows.Err()
}

// SecretVersions maps name → a short fingerprint of the stored ciphertext, which
// changes whenever the secret is set again: how the roles that use a secret get
// "changes waiting" when it is rotated.
func SecretVersions(db *sql.DB) (map[string]string, error) {
	ciphers, err := SecretCiphertexts(db)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for name, c := range ciphers {
		sum := sha256.Sum256([]byte(c))
		out[name] = hex.EncodeToString(sum[:6])
	}
	return out, nil
}

func SecretExists(db *sql.DB, name string) (bool, error) {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM secrets WHERE name = ?`, name).Scan(&n); err != nil {
		return false, fmt.Errorf("look for the secret: %w", err)
	}
	return n > 0, nil
}

func DeleteSecret(db *sql.DB, name string) error {
	res, err := db.Exec(`DELETE FROM secrets WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("delete the secret: %w", err)
	}
	return expectRow(res)
}

// ----------------------------------------------------------------- playbooks

type Playbook struct {
	Name      string `json:"name"`
	Content   string `json:"content,omitempty"`
	UpdatedAt int64  `json:"updated_at"`
}

func SavePlaybook(db *sql.DB, name, content string, now time.Time) error {
	_, err := db.Exec(`INSERT INTO playbooks (name, content, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET content = excluded.content, updated_at = excluded.updated_at`,
		name, content, now.Unix())
	if err != nil {
		return fmt.Errorf("store the playbook: %w", err)
	}
	return nil
}

func GetPlaybook(db *sql.DB, name string) (Playbook, error) {
	var p Playbook
	err := db.QueryRow(`SELECT name, content, updated_at FROM playbooks WHERE name = ?`, name).Scan(&p.Name, &p.Content, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Playbook{}, ErrNotFound
	}
	if err != nil {
		return Playbook{}, fmt.Errorf("read the playbook: %w", err)
	}
	return p, nil
}

// ListPlaybooks returns the playbooks, names and times only.
func ListPlaybooks(db *sql.DB) ([]Playbook, error) {
	rows, err := db.Query(`SELECT name, updated_at FROM playbooks ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list playbooks: %w", err)
	}
	defer rows.Close()
	out := []Playbook{}
	for rows.Next() {
		var p Playbook
		if err := rows.Scan(&p.Name, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("read a playbook: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// AllPlaybooks maps name → text, for the generated files.
func AllPlaybooks(db *sql.DB) (map[string]string, error) {
	rows, err := db.Query(`SELECT name, content FROM playbooks`)
	if err != nil {
		return nil, fmt.Errorf("read the playbooks: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, content string
		if err := rows.Scan(&name, &content); err != nil {
			return nil, fmt.Errorf("read a playbook: %w", err)
		}
		out[name] = content
	}
	return out, rows.Err()
}

func DeletePlaybook(db *sql.DB, name string) error {
	res, err := db.Exec(`DELETE FROM playbooks WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("delete the playbook: %w", err)
	}
	return expectRow(res)
}
