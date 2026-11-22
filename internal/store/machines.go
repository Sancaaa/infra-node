package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrMachineNameTaken = errors.New("Another machine already has that name.")
	ErrMachineIPTaken   = errors.New("Another host or machine already has that IP address.")
	ErrNameIsMachine    = errors.New("A machine already has that name.")
)

// Machine is a Proxmox LXC container managed by Terraform (IM7).
type Machine struct {
	ID            int64   `json:"id"`
	Name          string  `json:"name"`
	Node          string  `json:"node"`
	VMID          int     `json:"vm_id"`
	Cores         int     `json:"cores"`
	MemoryMB      int     `json:"memory_mb"`
	DiskGB        int     `json:"disk_gb"`
	Storage       string  `json:"storage"`
	Bridge        string  `json:"bridge"`
	Template      string  `json:"template"`
	IPMode        string  `json:"ip_mode"`
	IPCIDR        string  `json:"ip_cidr,omitempty"`
	Gateway       string  `json:"gateway,omitempty"`
	AutoConfigure bool    `json:"auto_configure"`
	GroupIDs      []int64 `json:"group_ids"`
	HostID        int64   `json:"host_id,omitempty"`
	IPResolved    string  `json:"ip_resolved,omitempty"`
	AppliedSpec   string  `json:"-"` // "cores:memory_mb:disk_gb" of the last apply
	AppliedAt     int64   `json:"applied_at,omitempty"`
	PendingDelete bool    `json:"pending_delete,omitempty"`
	CreatedAt     int64   `json:"created_at"`
}

// MachineRef identifies the machine that owns a host (for the Hosts page).
type MachineRef struct {
	ID   int64
	Name string
}

// SizeSpec encodes the resizable fields so "will change" is a plain comparison.
func (m Machine) SizeSpec() string {
	return fmt.Sprintf("%d:%d:%d", m.Cores, m.MemoryMB, m.DiskGB)
}

// StaticIP returns the bare IPv4 address when ip_mode is static.
func (m Machine) StaticIP() string {
	if m.IPMode != "static" || m.IPCIDR == "" {
		return ""
	}
	ip, _, _ := strings.Cut(m.IPCIDR, "/")
	return ip
}

func (m Machine) HasPendingChange() bool {
	return m.AppliedAt == 0 || m.PendingDelete || m.SizeSpec() != m.AppliedSpec
}

const machineColumns = `id, name, node, vm_id, cores, memory_mb, disk_gb,
	storage, bridge, template, ip_mode, ip_cidr, gateway,
	auto_configure, group_ids, host_id, ip_resolved, applied_spec, applied_at, pending_delete, created_at`

func scanMachine(row hostScanner) (Machine, error) {
	var m Machine
	var autoCfg, pendingDel int
	var groupJSON string
	var hostID sql.NullInt64
	err := row.Scan(
		&m.ID, &m.Name, &m.Node, &m.VMID, &m.Cores, &m.MemoryMB, &m.DiskGB,
		&m.Storage, &m.Bridge, &m.Template, &m.IPMode, &m.IPCIDR, &m.Gateway,
		&autoCfg, &groupJSON, &hostID, &m.IPResolved, &m.AppliedSpec, &m.AppliedAt, &pendingDel, &m.CreatedAt,
	)
	if err != nil {
		return Machine{}, err
	}
	m.AutoConfigure, m.PendingDelete = autoCfg == 1, pendingDel == 1
	if hostID.Valid {
		m.HostID = hostID.Int64
	}
	m.GroupIDs = []int64{}
	if groupJSON != "" {
		_ = json.Unmarshal([]byte(groupJSON), &m.GroupIDs)
	}
	return m, nil
}

// MachineConflict checks whether name or staticIP collides with an existing
// machine, host or group.
func MachineConflict(db *sql.DB, name, staticIP string) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM machines WHERE name = ?`, name).Scan(&n); err != nil {
		return fmt.Errorf("check machine name: %w", err)
	}
	if n > 0 {
		return ErrMachineNameTaken
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM hosts WHERE name = ?`, name).Scan(&n); err != nil {
		return fmt.Errorf("check host name: %w", err)
	}
	if n > 0 {
		return ErrHostNameTaken
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM groups WHERE name = ?`, name).Scan(&n); err != nil {
		return fmt.Errorf("check group name: %w", err)
	}
	if n > 0 {
		return ErrNameIsGroup
	}
	if staticIP == "" {
		return nil
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM hosts WHERE address = ? AND port = 22`, staticIP).Scan(&n); err != nil {
		return fmt.Errorf("check host IP: %w", err)
	}
	if n > 0 {
		return ErrMachineIPTaken
	}
	rows, err := db.Query(`SELECT ip_cidr FROM machines WHERE ip_mode = 'static'`)
	if err != nil {
		return fmt.Errorf("check machine IPs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			return err
		}
		if ip, _, _ := strings.Cut(cidr, "/"); ip == staticIP {
			return ErrMachineIPTaken
		}
	}
	return rows.Err()
}

func CreateMachine(db *sql.DB, m Machine, now time.Time) (Machine, error) {
	if m.GroupIDs == nil {
		m.GroupIDs = []int64{}
	}
	groupJSON, _ := json.Marshal(m.GroupIDs)
	res, err := db.Exec(`INSERT INTO machines (
		name, node, vm_id, cores, memory_mb, disk_gb,
		storage, bridge, template, ip_mode, ip_cidr, gateway,
		auto_configure, group_ids, ip_resolved, applied_spec, applied_at, pending_delete, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.Name, m.Node, m.VMID, m.Cores, m.MemoryMB, m.DiskGB,
		m.Storage, m.Bridge, m.Template, m.IPMode, m.IPCIDR, m.Gateway,
		b2i(m.AutoConfigure), string(groupJSON), m.IPResolved, m.AppliedSpec, m.AppliedAt, b2i(m.PendingDelete), now.Unix())
	if isUniqueViolation(err) {
		return Machine{}, ErrMachineNameTaken
	}
	if err != nil {
		return Machine{}, fmt.Errorf("store the machine: %w", err)
	}
	if m.ID, err = res.LastInsertId(); err != nil {
		return Machine{}, fmt.Errorf("read the new machine's id: %w", err)
	}
	m.CreatedAt = now.Unix()
	return m, nil
}

func GetMachine(db *sql.DB, id int64) (Machine, error) {
	m, err := scanMachine(db.QueryRow(`SELECT `+machineColumns+` FROM machines WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Machine{}, ErrNotFound
	}
	if err != nil {
		return Machine{}, fmt.Errorf("read the machine: %w", err)
	}
	return m, nil
}

func GetMachineByHostID(db *sql.DB, hostID int64) (Machine, bool, error) {
	m, err := scanMachine(db.QueryRow(`SELECT `+machineColumns+` FROM machines WHERE host_id = ?`, hostID))
	if errors.Is(err, sql.ErrNoRows) {
		return Machine{}, false, nil
	}
	if err != nil {
		return Machine{}, false, fmt.Errorf("read the machine for host: %w", err)
	}
	return m, true, nil
}

func ListMachines(db *sql.DB) ([]Machine, error) {
	rows, err := db.Query(`SELECT ` + machineColumns + ` FROM machines ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list machines: %w", err)
	}
	defer rows.Close()
	out := []Machine{}
	for rows.Next() {
		m, err := scanMachine(rows)
		if err != nil {
			return nil, fmt.Errorf("read a machine: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// HostMachineMap maps each Terraform-owned host id to its machine.
func HostMachineMap(db *sql.DB) (map[int64]MachineRef, error) {
	rows, err := db.Query(`SELECT host_id, id, name FROM machines WHERE host_id IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("list machine hosts: %w", err)
	}
	defer rows.Close()
	out := map[int64]MachineRef{}
	for rows.Next() {
		var hostID, machineID int64
		var name string
		if err := rows.Scan(&hostID, &machineID, &name); err != nil {
			return nil, fmt.Errorf("read machine host: %w", err)
		}
		out[hostID] = MachineRef{ID: machineID, Name: name}
	}
	return out, rows.Err()
}

func UpdateMachineSize(db *sql.DB, id int64, cores, memoryMB, diskGB int) error {
	res, err := db.Exec(`UPDATE machines SET cores = ?, memory_mb = ?, disk_gb = ? WHERE id = ?`, cores, memoryMB, diskGB, id)
	if err != nil {
		return fmt.Errorf("update the machine's size: %w", err)
	}
	return expectRow(res)
}

// RevertMachine restores a machine's last applied size and clears pending_delete.
func RevertMachine(db *sql.DB, id int64) error {
	m, err := GetMachine(db, id)
	if err != nil {
		return err
	}
	var cores, mem, disk int
	if _, err := fmt.Sscanf(m.AppliedSpec, "%d:%d:%d", &cores, &mem, &disk); err != nil {
		return errors.New("This machine has never been applied yet.")
	}
	res, err := db.Exec(`UPDATE machines SET cores = ?, memory_mb = ?, disk_gb = ?, pending_delete = 0 WHERE id = ?`, cores, mem, disk, id)
	if err != nil {
		return fmt.Errorf("revert the machine: %w", err)
	}
	return expectRow(res)
}

func SetMachinePendingDelete(db *sql.DB, id int64, pending bool) error {
	res, err := db.Exec(`UPDATE machines SET pending_delete = ? WHERE id = ?`, b2i(pending), id)
	if err != nil {
		return fmt.Errorf("mark the machine for removal: %w", err)
	}
	return expectRow(res)
}

func MarkMachineApplied(db *sql.DB, id int64, vmID int, ipResolved, appliedSpec string, at time.Time) error {
	res, err := db.Exec(`UPDATE machines SET vm_id = ?, ip_resolved = ?, applied_spec = ?, applied_at = ?, pending_delete = 0 WHERE id = ?`,
		vmID, ipResolved, appliedSpec, at.Unix(), id)
	if err != nil {
		return fmt.Errorf("record the applied machine: %w", err)
	}
	return expectRow(res)
}

func SetMachineHost(db *sql.DB, id, hostID int64, ipResolved string) error {
	res, err := db.Exec(`UPDATE machines SET host_id = ?, ip_resolved = ? WHERE id = ?`, hostID, ipResolved, id)
	if err != nil {
		return fmt.Errorf("link the machine to its host: %w", err)
	}
	return expectRow(res)
}

func DeleteMachine(db *sql.DB, id int64) error {
	res, err := db.Exec(`DELETE FROM machines WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete the machine: %w", err)
	}
	return expectRow(res)
}
