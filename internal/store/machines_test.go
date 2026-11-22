package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestSettingsAndMachinesLifecycle(t *testing.T) {
	db := openTestDB(t, filepath.Join(t.TempDir(), DBFile))
	now := time.Now()

	if err := SetSetting(db, "proxmox.endpoint", "https://192.168.1.10:8006"); err != nil {
		t.Fatal(err)
	}
	if err := SetSetting(db, "proxmox.endpoint", "https://192.168.1.11:8006"); err != nil {
		t.Fatal(err)
	}
	if all, err := GetSettings(db, "proxmox."); err != nil || all["proxmox.endpoint"] != "https://192.168.1.11:8006" {
		t.Fatalf("settings: %+v %v", all, err)
	}

	m, err := CreateMachine(db, Machine{
		Name: "web-1", Node: "pve", Cores: 2, MemoryMB: 1024, DiskGB: 16,
		Storage: "local-lvm", Bridge: "vmbr0", Template: "local:vztmpl/debian-12.tar.zst",
		IPMode: "static", IPCIDR: "10.0.0.50/24", Gateway: "10.0.0.1",
		AutoConfigure: true, GroupIDs: []int64{3, 7},
	}, now)
	if err != nil || !m.HasPendingChange() || m.StaticIP() != "10.0.0.50" || len(m.GroupIDs) != 2 {
		t.Fatalf("create: %+v %v", m, err)
	}

	if err := MachineConflict(db, "web-1", "10.0.0.99"); !errors.Is(err, ErrMachineNameTaken) {
		t.Errorf("same name: %v", err)
	}
	if err := MachineConflict(db, "web-2", "10.0.0.50"); !errors.Is(err, ErrMachineIPTaken) {
		t.Errorf("same IP: %v", err)
	}
	if err := HostConflict(db, "web-1", "10.0.0.99", 22, 0); !errors.Is(err, ErrNameIsMachine) {
		t.Errorf("host taking machine name: %v", err)
	}
	if _, err := CreateGroup(db, "web-1", now); !errors.Is(err, ErrNameIsMachine) {
		t.Errorf("group taking machine name: %v", err)
	}

	if err := MarkMachineApplied(db, m.ID, 101, "10.0.0.50", m.SizeSpec(), now); err != nil {
		t.Fatal(err)
	}
	if err := UpdateMachineSize(db, m.ID, 4, 2048, 32); err != nil {
		t.Fatal(err)
	}
	m, _ = GetMachine(db, m.ID)
	if !m.HasPendingChange() || m.MemoryMB != 2048 {
		t.Fatalf("resized: %+v", m)
	}
	if err := RevertMachine(db, m.ID); err != nil {
		t.Fatal(err)
	}
	m, _ = GetMachine(db, m.ID)
	if m.HasPendingChange() || m.MemoryMB != 1024 {
		t.Fatalf("reverted: %+v", m)
	}

	h, err := CreateHost(db, Host{Name: "web-1", Address: "10.0.0.50", Port: 22, User: "root", SudoOK: true, Status: "online"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := SetMachineHost(db, m.ID, h.ID, "10.0.0.50"); err != nil {
		t.Fatal(err)
	}
	if byHost, err := HostMachineMap(db); err != nil || byHost[h.ID].Name != "web-1" {
		t.Fatalf("HostMachineMap: %+v %v", byHost, err)
	}
	if err := HostConflict(db, "web-1", "10.0.0.50", 22, h.ID); err != nil {
		t.Errorf("own host edit conflicted: %v", err)
	}
}
