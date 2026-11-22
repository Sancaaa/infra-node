package tf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRenderWriteAndReadNeverIncludesSecretsOrState(t *testing.T) {
	files, err := Render(Input{
		Endpoint:     "https://192.168.5.131:8006",
		TokenID:      "terraform@pve!infra",
		Insecure:     true,
		SSHPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest infra-manager",
		Machines: map[string]MachineSpec{
			"web-1": {
				Node: "pve", Cores: 2, Memory: 2048, DiskGB: 16,
				Storage: "local-lvm", Bridge: "vmbr0", Template: "local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst",
				OSType: "debian", IPMode: "static", IPCIDR: "192.168.5.50/24", Gateway: "192.168.5.1",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(files["versions.tf"], `source  = "bpg/proxmox"`) || !strings.Contains(files["versions.tf"], ProviderVersion) {
		t.Errorf("versions.tf:\n%s", files["versions.tf"])
	}
	if !strings.Contains(files["main.tf"], `for_each = var.machines`) || !strings.Contains(files["main.tf"], `proxmox_virtual_environment_container`) {
		t.Errorf("main.tf:\n%s", files["main.tf"])
	}
	if !strings.Contains(files["machines.auto.tfvars.json"], `"ssh_public_key": "ssh-ed25519`) || !strings.Contains(files["machines.auto.tfvars.json"], `"web-1"`) {
		t.Errorf("machines.auto.tfvars.json:\n%s", files["machines.auto.tfvars.json"])
	}

	dir := t.TempDir()
	if err := Write(dir, files); err != nil {
		t.Fatal(err)
	}
	// Extra Terraform runtime files must survive Write and stay hidden from Read.
	if err := os.WriteFile(filepath.Join(dir, "terraform.tfstate"), []byte(`{"secret":"keep-out"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, files); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "terraform.tfstate")); err != nil {
		t.Errorf("Write removed terraform.tfstate: %v", err)
	}
	read, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(read) != 4 {
		t.Fatalf("Read returned %d files, want 4", len(read))
	}
	for _, f := range read {
		if strings.Contains(f[0], "tfstate") || strings.Contains(f[1], "keep-out") {
			t.Errorf("Read leaked state file: %s", f[0])
		}
	}
}

func TestParseStateAndPlainSummary(t *testing.T) {
	raw := `{
		"values": {
			"outputs": {
				"machines": {
					"value": {
						"web-1": {"vm_id": 101, "node_name": "pve", "ipv4": "192.168.5.50"}
					}
				}
			},
			"root_module": {
				"resources": [
					{
						"type": "proxmox_virtual_environment_container",
						"name": "machine",
						"index": "web-1",
						"values": {"vm_id": 101, "node_name": "pve", "ipv4": {"eth0": "192.168.5.50/24"}}
					}
				]
			}
		}
	}`
	st, err := ParseState([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	m, ok := st["web-1"]
	if !ok || m.VMID != 101 || m.Node != "pve" || m.IPv4 != "192.168.5.50" {
		t.Fatalf("ParseState: %+v", st)
	}
	if empty, err := ParseState([]byte(`{}`)); err != nil || len(empty) != 0 {
		t.Fatalf("empty state: %+v %v", empty, err)
	}

	if got := MachineName(`proxmox_virtual_environment_container.machine["web-1"]`); got != "web-1" {
		t.Errorf("MachineName = %q", got)
	}
	if got := PlainSummary(&Plan{Summary: Summary{Add: 1}}); got != "1 container will be created." {
		t.Errorf("PlainSummary = %q", got)
	}
	if got := PlainSummary(&Plan{Summary: Summary{Change: 1, Destroy: 2}}); got != "1 container will be changed in place, 2 containers will be destroyed." {
		t.Errorf("PlainSummary = %q", got)
	}
	if got := PlainSummary(&Plan{}); got != "No changes: everything matches." {
		t.Errorf("PlainSummary empty = %q", got)
	}
	if got := InferOSType("local:vztmpl/ubuntu-24.04-standard_24.04-2_amd64.tar.zst"); got != "ubuntu" {
		t.Errorf("InferOSType ubuntu = %q", got)
	}
}

func TestDriftExplainImportAndBackups(t *testing.T) {
	d := ExplainDrift(Change{
		Address: `proxmox_virtual_environment_container.machine["web-1"]`,
		Action:  "update",
		Attributes: []AttrChange{
			{Path: "memory[0].dedicated", Before: "1024", After: "2048"},
		},
	})
	if d.Machine != "web-1" || d.MemoryMB != 2048 || d.Sentence != "web-1 was changed outside the dashboard (memory 1024 → 2048)" {
		t.Fatalf("ExplainDrift: %+v", d)
	}

	dir := t.TempDir()
	if err := WriteImport(dir, "praktikum", "pve", 105); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "imports.tf"))
	if err != nil || !strings.Contains(string(raw), `machine["praktikum"]`) || !strings.Contains(string(raw), `"pve/105"`) {
		t.Fatalf("imports.tf: %q %v", raw, err)
	}
	ClearImport(dir)
	if _, err := os.Stat(filepath.Join(dir, "imports.tf")); err == nil {
		t.Error("ClearImport did not remove imports.tf")
	}

	// Backup pruning keeps 30 deep, and restore writes the chosen snapshot back.
	statePath := filepath.Join(dir, "terraform.tfstate")
	for i := 0; i < 35; i++ {
		_ = os.WriteFile(statePath, []byte(strings.Repeat("x", i+1)), 0o600)
		if _, err := BackupState(dir, time.Unix(1700000000+int64(i), 0)); err != nil {
			t.Fatal(err)
		}
	}
	list, err := ListBackups(dir)
	if err != nil || len(list) != MaxStateBackups {
		t.Fatalf("backups count = %d, want %d (err %v)", len(list), MaxStateBackups, err)
	}
	oldest := list[len(list)-1]
	if err := RestoreBackup(dir, oldest.ID, time.Unix(1700009999, 0)); err != nil {
		t.Fatal(err)
	}
	restored, _ := os.ReadFile(statePath)
	if int64(len(restored)) != oldest.Size {
		t.Errorf("restored size = %d, want %d", len(restored), oldest.Size)
	}
	if CheckBackupID("../terraform.tfstate") == nil {
		t.Error("path traversal accepted")
	}
}
