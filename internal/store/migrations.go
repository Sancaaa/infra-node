package store

import (
	"database/sql"
	"fmt"
)

// migrations are the whole schema, in order. Each one runs once; a new database
// gets all of them, an old one catches up. The database file remembers how many
// have run in SQLite's user_version, so none runs twice. (The same idea as
// headnode's server/migrations.go.)
//
// Never edit or reorder an entry that has shipped: add a new one at the end.
//
// A table is created by the milestone that first uses it, not before. Its
// columns are decided when the feature is built, and a migration that has
// shipped cannot be corrected, only followed by another one. So users, sessions
// and history arrived in IM1, hosts come in IM2, and so on (OD-07).
var migrations = []string{
	// 1 (IM0): small values the dashboard keeps about itself, as name → text. The
	// Proxmox endpoint, the compliance time and the like land here later.
	`CREATE TABLE settings (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`,

	// 2 (IM1): the people who may log in. A user is disabled, never deleted, so
	// every History row still points at a real name. Passwords are bcrypt hashes.
	// The CHECK is a second line of defence behind the role list in Go.
	`CREATE TABLE users (
		id            INTEGER PRIMARY KEY,
		username      TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		role          TEXT NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
		disabled      INTEGER NOT NULL DEFAULT 0,
		created_at    INTEGER NOT NULL
	)`,

	// 3 (IM1): logins. The cookie holds a random token; only its SHA-256 is
	// stored, so a copy of the database cannot be used to become somebody.
	// ip and user_agent are there so the Profile page can tell sessions apart.
	`CREATE TABLE sessions (
		id           TEXT PRIMARY KEY,
		user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		created_at   INTEGER NOT NULL,
		last_used_at INTEGER NOT NULL,
		ip           TEXT NOT NULL DEFAULT '',
		user_agent   TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX sessions_user ON sessions (user_id)`,

	// 4 (IM1): History. No foreign key on user_id and the name is copied in: the
	// record of who did something must outlive any change to that account, and
	// some rows (a failed login) have no account at all (user_id 0).
	`CREATE TABLE history (
		id       INTEGER PRIMARY KEY AUTOINCREMENT,
		at       INTEGER NOT NULL,
		user_id  INTEGER NOT NULL DEFAULT 0,
		username TEXT NOT NULL DEFAULT '',
		action   TEXT NOT NULL,
		target   TEXT NOT NULL DEFAULT '',
		result   TEXT NOT NULL,
		detail   TEXT NOT NULL DEFAULT '',
		ip       TEXT NOT NULL DEFAULT ''
	)`,

	// 5 (IM2): the hosts the dashboard manages. No password is stored, or ever
	// was: the password typed in Add host is used once and forgotten, and the
	// dashboard logs in with its own key. host_key_fp is the saved host key's
	// fingerprint (the key itself is in keys/known_hosts); presented_fp is the
	// fingerprint of a different key the host showed, while status is
	// 'key_changed'. facts is the JSON the Hosts page shows (OS, CPUs, memory,
	// disks, addresses). sudoers_installed remembers that the dashboard wrote a
	// sudo rule on the host, so Remove can take it out again.
	`CREATE TABLE hosts (
		id                INTEGER PRIMARY KEY,
		name              TEXT NOT NULL UNIQUE,
		address           TEXT NOT NULL,
		port              INTEGER NOT NULL DEFAULT 22,
		username          TEXT NOT NULL,
		sudo_ok           INTEGER NOT NULL DEFAULT 0,
		sudoers_installed INTEGER NOT NULL DEFAULT 0,
		status            TEXT NOT NULL DEFAULT 'unknown',
		status_detail     TEXT NOT NULL DEFAULT '',
		status_at         INTEGER NOT NULL DEFAULT 0,
		host_key_fp       TEXT NOT NULL DEFAULT '',
		presented_fp      TEXT NOT NULL DEFAULT '',
		facts             TEXT NOT NULL DEFAULT '',
		facts_at          INTEGER NOT NULL DEFAULT 0,
		created_at        INTEGER NOT NULL,
		UNIQUE (address, port)
	)`,

	// 6 to 8 (IM3): what the check every minute finds. health is JSON (load,
	// memory, disk, uptime, failed services, whether a reboot or updates are
	// waiting); health_at is when it was taken; last_seen is the last time the
	// host answered, which stays while it is offline so the page can say "last
	// seen 5 minutes ago".
	`ALTER TABLE hosts ADD COLUMN health TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE hosts ADD COLUMN health_at INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE hosts ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0`,

	// 9 to 12 (IM4): groups of hosts, and variables for groups and for single
	// hosts. A host and a group may not share a name (checked in Go): Ansible
	// cannot tell which one "web" means. Deleting a host or a group takes its
	// memberships and variables with it. A variable's value is text: the
	// generated YAML writes numbers and true/false bare and the rest quoted.
	`CREATE TABLE groups (
		id         INTEGER PRIMARY KEY,
		name       TEXT NOT NULL UNIQUE,
		created_at INTEGER NOT NULL
	)`,
	`CREATE TABLE group_hosts (
		group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
		host_id  INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
		PRIMARY KEY (group_id, host_id)
	)`,
	`CREATE TABLE group_vars (
		group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
		key      TEXT NOT NULL,
		value    TEXT NOT NULL,
		PRIMARY KEY (group_id, key)
	)`,
	`CREATE TABLE host_vars (
		host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
		key     TEXT NOT NULL,
		value   TEXT NOT NULL,
		PRIMARY KEY (host_id, key)
	)`,

	// 13 to 17 (IM5): profiles. A profile is a list of roles with the parameters
	// somebody set, given to a group or to a single host (exactly one of the two
	// columns). params is a JSON object; only what was set is kept, so a
	// parameter left alone follows the role's default. applied_roles remembers,
	// for each host and role, the fingerprint of what was last applied (the
	// role's files and its parameters), which is how "changes waiting" is known
	// without running anything. host_config holds how the last run went, and
	// what "Check again" found (idempotent: 1 yes, 0 no, -1 not checked).
	`CREATE TABLE profile_roles (
		id       INTEGER PRIMARY KEY,
		group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE,
		host_id  INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
		role     TEXT NOT NULL,
		params   TEXT NOT NULL DEFAULT '{}',
		CHECK ((group_id IS NULL) <> (host_id IS NULL))
	)`,
	`CREATE UNIQUE INDEX profile_group_role ON profile_roles (group_id, role) WHERE group_id IS NOT NULL`,
	`CREATE UNIQUE INDEX profile_host_role ON profile_roles (host_id, role) WHERE host_id IS NOT NULL`,
	`CREATE TABLE applied_roles (
		host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
		role       TEXT NOT NULL,
		hash       TEXT NOT NULL,
		applied_at INTEGER NOT NULL,
		PRIMARY KEY (host_id, role)
	)`,
	`CREATE TABLE host_config (
		host_id    INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
		result     TEXT NOT NULL DEFAULT '',
		detail     TEXT NOT NULL DEFAULT '',
		run_at     INTEGER NOT NULL DEFAULT 0,
		idempotent INTEGER NOT NULL DEFAULT -1
	)`,

	// 18 to 25 (IM6). Access: the SSH public keys of people (a key is public; the
	// name says whose), and which groups and hosts each may log in to. username
	// is the account on the host, or '' for the user the dashboard logs in as.
	// access_installed remembers what the dashboard put on each host, with the key
	// text, so that a key can be taken off a host even after its row is deleted:
	// that is what "Revoke everywhere" relies on.
	`CREATE TABLE access_keys (
		id         INTEGER PRIMARY KEY,
		name       TEXT NOT NULL UNIQUE,
		public_key TEXT NOT NULL UNIQUE,
		username   TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL
	)`,
	`CREATE TABLE access_grants (
		id       INTEGER PRIMARY KEY,
		key_id   INTEGER NOT NULL REFERENCES access_keys(id) ON DELETE CASCADE,
		group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE,
		host_id  INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
		CHECK ((group_id IS NULL) <> (host_id IS NULL))
	)`,
	`CREATE UNIQUE INDEX access_grant_group ON access_grants (key_id, group_id) WHERE group_id IS NOT NULL`,
	`CREATE UNIQUE INDEX access_grant_host ON access_grants (key_id, host_id) WHERE host_id IS NOT NULL`,
	`CREATE TABLE access_installed (
		host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
		public_key TEXT NOT NULL,
		username   TEXT NOT NULL,
		name       TEXT NOT NULL,
		PRIMARY KEY (host_id, public_key, username)
	)`,
	// Secrets: only the ciphertext of ansible-vault is kept. There is no column
	// for the value, and no way to read it back.
	`CREATE TABLE secrets (
		name       TEXT PRIMARY KEY,
		ciphertext TEXT NOT NULL,
		updated_at INTEGER NOT NULL
	)`,
	// Custom playbooks, written in the editor; they are generated into custom/.
	`CREATE TABLE playbooks (
		name       TEXT PRIMARY KEY,
		content    TEXT NOT NULL,
		updated_at INTEGER NOT NULL
	)`,

	// 26 to 27 (IM7): Proxmox containers managed by Terraform. The Proxmox API
	// token secret is never stored here: it lives in secrets/proxmox.tfvars.json
	// (0600). applied_spec records "cores:memory_mb:disk_gb" of the last apply
	// (empty before creation) so "will change" is known without running a plan.
	`CREATE TABLE machines (
		id             INTEGER PRIMARY KEY,
		name           TEXT NOT NULL UNIQUE,
		node           TEXT NOT NULL,
		vm_id          INTEGER NOT NULL DEFAULT 0,
		cores          INTEGER NOT NULL,
		memory_mb      INTEGER NOT NULL,
		disk_gb        INTEGER NOT NULL,
		storage        TEXT NOT NULL,
		bridge         TEXT NOT NULL,
		template       TEXT NOT NULL,
		ip_mode        TEXT NOT NULL CHECK (ip_mode IN ('static', 'dhcp')),
		ip_cidr        TEXT NOT NULL DEFAULT '',
		gateway        TEXT NOT NULL DEFAULT '',
		auto_configure INTEGER NOT NULL DEFAULT 0,
		group_ids      TEXT NOT NULL DEFAULT '[]',
		host_id        INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
		ip_resolved    TEXT NOT NULL DEFAULT '',
		applied_spec   TEXT NOT NULL DEFAULT '',
		applied_at     INTEGER NOT NULL DEFAULT 0,
		pending_delete INTEGER NOT NULL DEFAULT 0,
		created_at     INTEGER NOT NULL
	)`,
	`CREATE UNIQUE INDEX machines_host ON machines (host_id) WHERE host_id IS NOT NULL`,

	// 28 to 30 (TOTP): mandatory two-factor authentication for every user.
	// totp_secret is an unpadded Base32 secret (never part of User and never
	// returned once enabled); totp_enabled becomes 1 after the first valid code;
	// totp_last_step blocks replaying a code in the same 30-second step.
	`ALTER TABLE users ADD COLUMN totp_secret TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0`,
}

// migrate brings the database up to date. It runs every time the dashboard
// opens the database, and does nothing when there is nothing new.
func migrate(db *sql.DB) error {
	var applied int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&applied); err != nil {
		return fmt.Errorf("read the schema version: %w", err)
	}
	if applied > len(migrations) {
		// Going back would run old code against tables it does not know.
		return fmt.Errorf("the database is at schema version %d, but this infra-manager only knows %d: it was made by a newer version", applied, len(migrations))
	}

	for i := applied; i < len(migrations); i++ {
		// One transaction per migration: the change and the new version number
		// land together, or neither does.
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		// PRAGMA takes no ? parameters. The number comes from our own loop, not
		// from input.
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %d: %w", i+1, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", i+1, err)
		}
	}
	return nil
}
