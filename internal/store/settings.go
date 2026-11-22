package store

import (
	"database/sql"
	"fmt"
)

// SetSetting writes a setting, replacing any previous value.
func SetSetting(db *sql.DB, key, value string) error {
	_, err := db.Exec(`INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	if err != nil {
		return fmt.Errorf("write setting %s: %w", key, err)
	}
	return nil
}

// GetSettings returns every setting whose key starts with prefix.
func GetSettings(db *sql.DB, prefix string) (map[string]string, error) {
	rows, err := db.Query(`SELECT key, value FROM settings WHERE key LIKE ?`, prefix+"%")
	if err != nil {
		return nil, fmt.Errorf("list settings %s: %w", prefix, err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("read setting: %w", err)
		}
		out[k] = v
	}
	return out, rows.Err()
}
