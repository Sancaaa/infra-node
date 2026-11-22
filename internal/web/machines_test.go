package web

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"infra-manager/internal/remote"
	"infra-manager/internal/remote/remotetest"
	"infra-manager/internal/store"
	"infra-manager/internal/tf"
)

// A stand-in for terraform that reads the dashboard's generated
// machines.auto.tfvars.json, checks that the 0600 secret var-file exists,
// computes real create/update/destroy plans, writes plan JSON files, and keeps
// state in .stub.state. Uses only POSIX sh and awk (no jq or bashisms).
const terraformStub = `#!/bin/sh
set -e
cmd="$1"
shift || true

if [ "$cmd" = "version" ]; then
  echo "Terraform v1.9.8"
  exit 0
fi

if [ "$cmd" = "init" ]; then
  mkdir -p .terraform
  echo "Terraform has been successfully initialized!"
  exit 0
fi

parse_desired() {
  awk '
    /^  "machines": \{\}/ { next }
    /^  "machines": \{/ { in_m = 1; next }
    in_m && /^  \}/ { in_m = 0; next }
    in_m && /^    "[^"]+": \{/ {
      name = $0; sub(/^    "/, "", name); sub(/": \{.*/, "", name)
      node = ""; cores = 0; mem = 0; disk = 0; ip = ""
      next
    }
    in_m && name != "" {
      if ($0 ~ /^    \}/) {
        print name, node, cores, mem, disk, ip
        name = ""
        next
      }
      if ($0 ~ /^      "node":/) { v=$0; sub(/.*": "/,"",v); sub(/".*/,"",v); node=v }
      if ($0 ~ /^      "cores":/) { v=$0; sub(/.*": /,"",v); sub(/,.*/,"",v); cores=v+0 }
      if ($0 ~ /^      "memory":/) { v=$0; sub(/.*": /,"",v); sub(/,.*/,"",v); mem=v+0 }
      if ($0 ~ /^      "disk_gb":/) { v=$0; sub(/.*": /,"",v); sub(/,.*/,"",v); disk=v+0 }
      if ($0 ~ /^      "ip_cidr":/) { v=$0; sub(/.*": "/,"",v); sub(/".*/,"",v); sub(/\/.*/,"",v); ip=v }
    }
  ' machines.auto.tfvars.json
}

if [ "$cmd" = "plan" ]; then
  varfile=""; out=""; refresh=""; replace=""; target=""; statefile="terraform.tfstate"
  for a in "$@"; do
    case "$a" in
      -var-file=*) varfile="${a#-var-file=}" ;;
      -out=*) out="${a#-out=}" ;;
      -refresh-only) refresh=1 ;;
      -replace=*) replace="${a#-replace=}" ;;
      -target=*) target="${a#-target=}" ;;
      -state=*) statefile="${a#-state=}" ;;
    esac
  done
  if [ -n "$target" ]; then printf '%s' "$target" > .stub.last_target; fi
  if [ -z "$varfile" ] || [ ! -s "$varfile" ]; then
    echo "Error: missing Proxmox secret var-file" >&2
    exit 1
  fi
  if [ ! -f "main.tf" ] || [ ! -f "machines.auto.tfvars.json" ]; then
    echo "Error: no configuration files" >&2
    exit 1
  fi
  touch "$statefile"
  next_file="$out.next"
  : > "$next_file"

  if [ -n "$refresh" ]; then
    cp "$statefile" "$next_file"
    if [ -s .stub.drift ]; then
      awk '
        {
          n++; name=$1; before=$2; after=$3
          drifts[n] = sprintf("{\"address\":\"proxmox_virtual_environment_container.machine[\\\"%s\\\"]\",\"change\":{\"actions\":[\"update\"],\"before\":{\"memory\":[{\"dedicated\":%s}]},\"after\":{\"memory\":[{\"dedicated\":%s}]}}}", name, before, after)
        }
        END {
          printf "{\"resource_changes\":[],\"resource_drift\":["
          for (i = 1; i <= n; i++) { if (i > 1) printf ","; printf "%s", drifts[i] }
          printf "]}\n"
        }
      ' .stub.drift > "$out"
    else
      echo '{"resource_changes":[],"resource_drift":[]}' > "$out"
    fi
    exit 0
  fi

  desired_file="$out.desired"
  parse_desired > "$desired_file"

  import_name=""; import_vmid=""
  if [ -f imports.tf ]; then
    import_name=$(sed -n 's/.*machine\["\([^"]*\)"\].*/\1/p' imports.tf | head -1)
    import_vmid=$(sed -n 's/.*id = "[^/]*\/\([0-9]*\)".*/\1/p' imports.tf | head -1)
  fi
  replace_name=""
  if [ -n "$replace" ]; then
    replace_name=$(printf '%s' "$replace" | sed -n 's/.*machine\["\([^"]*\)"\].*/\1/p')
  fi
  import_mem=""
  if [ -n "$import_name" ] && [ -s .stub.import_mem ]; then
    import_mem=$(cat .stub.import_mem)
  fi

  awk -v nextfile="$next_file" -v rep="$replace_name" -v imp="$import_name" -v impid="$import_vmid" -v impmem="$import_mem" '
    FNR == NR {
      st_vmid[$1] = $2; st_node[$1] = $3; st_cores[$1] = $4; st_mem[$1] = $5; st_disk[$1] = $6; st_ip[$1] = $7
      if ($2 + 0 > maxid) maxid = $2 + 0
      next
    }
    {
      name=$1; node=$2; cores=$3; mem=$4; disk=$5; ip=$6
      seen[name] = 1
      if (name == imp && impid != "") {
        print name, impid, node, cores, mem, disk, ip >> nextfile
        if (impmem != "" && impmem != mem) {
          changes[++n] = sprintf("{\"address\":\"proxmox_virtual_environment_container.machine[\\\"%s\\\"]\",\"change\":{\"actions\":[\"update\"],\"before\":{\"memory\":[{\"dedicated\":%s}]},\"after\":{\"memory\":[{\"dedicated\":%s}]}}}", name, impmem, mem)
        }
      } else if (!(name in st_vmid)) {
        if (maxid < 100) maxid = 100
        maxid++
        vmid = maxid
        print name, vmid, node, cores, mem, disk, ip >> nextfile
        changes[++n] = sprintf("{\"address\":\"proxmox_virtual_environment_container.machine[\\\"%s\\\"]\",\"change\":{\"actions\":[\"create\"],\"before\":null,\"after\":{\"node_name\":\"%s\",\"cpu\":[{\"cores\":%s}],\"memory\":[{\"dedicated\":%s}],\"disk\":[{\"size\":%s}]}}}", name, node, cores, mem, disk)
      } else {
        vmid = st_vmid[name]
        print name, vmid, node, cores, mem, disk, ip >> nextfile
        if (name == rep) {
          changes[++n] = sprintf("{\"address\":\"proxmox_virtual_environment_container.machine[\\\"%s\\\"]\",\"action_reason\":\"replace_by_request\",\"change\":{\"actions\":[\"delete\",\"create\"],\"before\":{\"memory\":[{\"dedicated\":%s}]},\"after\":{\"memory\":[{\"dedicated\":%s}]}}}", name, st_mem[name], mem)
        } else if (st_cores[name] != cores || st_mem[name] != mem || st_disk[name] != disk) {
          changes[++n] = sprintf("{\"address\":\"proxmox_virtual_environment_container.machine[\\\"%s\\\"]\",\"change\":{\"actions\":[\"update\"],\"before\":{\"cpu\":[{\"cores\":%s}],\"memory\":[{\"dedicated\":%s}],\"disk\":[{\"size\":%s}]},\"after\":{\"cpu\":[{\"cores\":%s}],\"memory\":[{\"dedicated\":%s}],\"disk\":[{\"size\":%s}]}}}", name, st_cores[name], st_mem[name], st_disk[name], cores, mem, disk)
        }
      }
    }
    END {
      for (name in st_vmid) {
        if (!(name in seen)) {
          changes[++n] = sprintf("{\"address\":\"proxmox_virtual_environment_container.machine[\\\"%s\\\"]\",\"action_reason\":\"delete_because_each_key\",\"change\":{\"actions\":[\"delete\"],\"before\":{\"node_name\":\"%s\",\"vm_id\":%s},\"after\":null}}", name, st_node[name], st_vmid[name])
        }
      }
      printf "{\"resource_changes\":["
      for (i = 1; i <= n; i++) {
        if (i > 1) printf ","
        printf "%s", changes[i]
      }
      printf "],\"resource_drift\":[]}\n"
    }
  ' "$statefile" "$desired_file" > "$out"
  rm -f "$desired_file"
  echo "Saved the plan to: $out"
  exit 0
fi

if [ "$cmd" = "show" ]; then
  target=""
  for a in "$@"; do
    case "$a" in
      -*) ;;
      *) target="$a" ;;
    esac
  done
  if [ -n "$target" ]; then
    cat "$target"
    exit 0
  fi
  if [ ! -s terraform.tfstate ]; then
    echo "{}"
    exit 0
  fi
  awk '
    {
      n++
      name[n]=$1; vmid[n]=$2; node[n]=$3; ip[n]=$7
    }
    END {
      printf "{\"values\":{\"outputs\":{\"machines\":{\"value\":{"
      for (i = 1; i <= n; i++) {
        if (i > 1) printf ","
        printf "\"%s\":{\"vm_id\":%s,\"node_name\":\"%s\",\"ipv4\":\"%s\"}", name[i], vmid[i], node[i], ip[i]
      }
      printf "}}}}}\n"
    }
  ' terraform.tfstate
  exit 0
fi

if [ "$cmd" = "apply" ]; then
  planfile=""
  for a in "$@"; do
    case "$a" in
      -*) ;;
      *) planfile="$a" ;;
    esac
  done
  if [ -z "$planfile" ] || [ ! -f "$planfile.next" ]; then
    echo "Error: plan file not found: $planfile" >&2
    exit 1
  fi
  cp "$planfile.next" terraform.tfstate
  rm -f "$planfile.next" .stub.drift
  echo "proxmox_virtual_environment_container.machine: Applying..."
  echo "Apply complete!"
  exit 0
fi

echo "unexpected terraform subcommand: $cmd" >&2
exit 1
`

type fakeProxmox struct {
	srv    *httptest.Server
	secret string
	mu     sync.Mutex
	states map[int]string // vmid -> running / stopped
	names  map[int]string
}

func startFakeProxmox(t *testing.T, tokenID, secret string) *fakeProxmox {
	t.Helper()
	fp := &fakeProxmox{
		secret: secret,
		states: map[int]string{101: "running", 102: "running"},
		names:  map[int]string{101: "web-1", 102: "web-2"},
	}
	wantAuth := "PVEAPIToken=" + tokenID + "=" + secret
	fp.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != wantAuth {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("invalid token"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api2/json/version":
			_, _ = w.Write([]byte(`{"data":{"version":"8.2.4","release":"8.2"}}`))
		case "/api2/json/nodes":
			_, _ = w.Write([]byte(`{"data":[{"node":"pve","status":"online"}]}`))
		case "/api2/json/nodes/pve/storage":
			_, _ = w.Write([]byte(`{"data":[
				{"storage":"local","type":"dir","content":"vztmpl,iso","active":1,"enabled":1},
				{"storage":"local-lvm","type":"lvmthin","content":"rootdir,images","active":1,"enabled":1}
			]}`))
		case "/api2/json/nodes/pve/storage/local/content":
			_, _ = w.Write([]byte(`{"data":[{"volid":"local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst","size":12345}]}`))
		case "/api2/json/nodes/pve/network":
			_, _ = w.Write([]byte(`{"data":[{"iface":"vmbr0","type":"bridge","cidr":"192.168.5.131/24","gateway":"192.168.5.1"}]}`))
		case "/api2/json/nodes/pve/lxc":
			fp.mu.Lock()
			var list []map[string]any
			for vmid, status := range fp.states {
				list = append(list, map[string]any{"vmid": vmid, "name": fp.names[vmid], "status": status})
			}
			fp.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"data": list})
		default:
			if strings.HasPrefix(r.URL.Path, "/api2/json/nodes/pve/lxc/") {
				rest := strings.TrimPrefix(r.URL.Path, "/api2/json/nodes/pve/lxc/")
				parts := strings.Split(rest, "/")
				if len(parts) == 3 && parts[1] == "status" {
					vmid, _ := strconv.Atoi(parts[0])
					fp.mu.Lock()
					if parts[2] == "start" {
						fp.states[vmid] = "running"
					} else if parts[2] == "shutdown" || parts[2] == "stop" {
						fp.states[vmid] = "stopped"
					}
					fp.mu.Unlock()
					_, _ = w.Write([]byte(`{"data":"UPID:pve:ok"}`))
					return
				}
			}
			if strings.HasPrefix(r.URL.Path, "/api2/json/nodes/pve/tasks/") {
				_, _ = w.Write([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(fp.srv.Close)
	return fp
}

func (a *testApp) withTerraform() {
	a.t.Helper()
	a.installStub("terraform", terraformStub)
}

func TestProxmoxSettingsAndSecretHygiene(t *testing.T) {
	logs := capturedLogs(t)
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	const tokenID = "terraform@pve!infra"
	const secret = "proxmox-secret-never-leak-99887766"
	fp := startFakeProxmox(t, tokenID, secret)

	// Save Proxmox settings.
	rec := a.do("POST", "/api/proxmox", admin, map[string]any{
		"endpoint":     fp.srv.URL,
		"token_id":     tokenID,
		"token_secret": secret,
		"insecure":     true,
	})
	want(t, rec, http.StatusOK)
	if strings.Contains(rec.Body.String(), secret) || !strings.Contains(rec.Body.String(), `"has_secret":true`) || !strings.Contains(rec.Body.String(), `"configured":true`) {
		t.Fatalf("save answer: %s", rec.Body.String())
	}

	// Updating settings without re-typing the secret keeps it.
	rec = a.do("POST", "/api/proxmox", admin, map[string]any{
		"endpoint": fp.srv.URL,
		"token_id": tokenID,
		"insecure": true,
	})
	want(t, rec, http.StatusOK)

	// Test connection discovers nodes, storages, bridges and templates.
	rec = a.do("POST", "/api/proxmox/test", admin, map[string]any{})
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"version":"8.2.4"`) ||
		!strings.Contains(rec.Body.String(), `"local-lvm"`) ||
		!strings.Contains(rec.Body.String(), `"vmbr0"`) ||
		!strings.Contains(rec.Body.String(), `debian-12-standard`) {
		t.Fatalf("test connection: %s", rec.Body.String())
	}

	// View code includes generated Terraform files and never includes the secret.
	codeRec := a.do("GET", "/api/code", admin, nil)
	want(t, codeRec, http.StatusOK)
	if !strings.Contains(codeRec.Body.String(), "versions.tf") ||
		!strings.Contains(codeRec.Body.String(), "bpg/proxmox") ||
		!strings.Contains(codeRec.Body.String(), "machines.auto.tfvars.json") ||
		strings.Contains(codeRec.Body.String(), secret) {
		t.Fatalf("code: %s", codeRec.Body.String())
	}

	// The secret must exist ONLY in secrets/proxmox.tfvars.json (mode 0600) and
	// nowhere else in the data directory (including SQLite DB) or History.
	secretFile := filepath.Join(a.dir, "secrets", "proxmox.tfvars.json")
	err := filepath.WalkDir(a.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if path == secretFile {
			if runtime.GOOS != "windows" {
				if info, serr := d.Info(); serr == nil && info.Mode().Perm() != 0o600 {
					t.Errorf("secret file mode = %04o, want 0600", info.Mode().Perm())
				}
			}
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr == nil && strings.Contains(string(data), secret) {
			t.Errorf("Proxmox token secret leaked into %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range a.events() {
		if strings.Contains(ev.Detail+ev.Target+ev.Action, secret) {
			t.Errorf("Proxmox token secret leaked into History: %+v", ev)
		}
	}
	if strings.Contains(logs.String(), secret) {
		t.Errorf("Proxmox token secret leaked into logs:\n%s", logs.String())
	}
}

func TestPlanRulesWithoutTerraformAndMutex(t *testing.T) {
	a := newTestApp(t)
	a.s.tf.Bin = "terraform-not-installed-xyz"
	_, admin := a.user("ada", store.RoleAdmin)

	// Plan says 503 missing: true when terraform is absent.
	rec := a.do("POST", "/api/terraform/plan", admin, nil)
	want(t, rec, http.StatusServiceUnavailable)
	if !strings.Contains(rec.Body.String(), `"missing":true`) {
		t.Fatalf("plan missing: %s", rec.Body.String())
	}

	// Creating a desired machine and viewing machines still work without terraform.
	rec = a.do("POST", "/api/machines", admin, map[string]any{
		"name": "app-1", "node": "pve", "cores": 1, "memory_mb": 512, "disk_gb": 8,
		"storage": "local-lvm", "bridge": "vmbr0", "template": "local:vztmpl/debian-12.tar.zst",
		"ip_mode": "dhcp",
	})
	want(t, rec, http.StatusCreated)
	rec = a.do("GET", "/api/machines", admin, nil)
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"installed":false`) || !strings.Contains(rec.Body.String(), `"status":"will_be_created"`) {
		t.Fatalf("machines: %s", rec.Body.String())
	}

	// Discarding a never-created machine deletes it immediately.
	var list struct {
		Machines []struct{ ID int64 } `json:"machines"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	rec = a.do("POST", fmt.Sprintf("/api/machines/%d/remove", list.Machines[0].ID), admin, nil)
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"deleted":true`) {
		t.Fatalf("discard: %s", rec.Body.String())
	}

	// Saved plan expiry and snapshot mismatch checks (OD-04).
	a.s.provision.planTTL = 10 * time.Millisecond
	planFile := filepath.Join(t.TempDir(), "old.tfplan")
	_ = os.WriteFile(planFile, []byte("plan"), 0o600)
	a.s.setPendingPlan(&savedPlan{ID: "p1", File: planFile, Created: time.Now().Add(-time.Second), Snapshot: "snap"})
	if _, msg := a.s.takePendingPlan("p1", "snap"); !strings.Contains(msg, "15 minutes") {
		t.Errorf("expired plan: %q", msg)
	}
	a.s.provision.planTTL = 15 * time.Minute
	a.s.setPendingPlan(&savedPlan{ID: "p2", File: planFile, Created: time.Now(), Snapshot: "snap-old"})
	if _, msg := a.s.takePendingPlan("p2", "snap-new"); !strings.Contains(msg, "changed") {
		t.Errorf("changed snapshot: %q", msg)
	}
}

// End-to-end IM7 vertical slice: Create web-1 and web-2 in group web ->
// Plan & Apply -> both become online hosts, configured with nginx ->
// Host address cannot be edited on Hosts -> Resize web-1 RAM ("changed in place") ->
// Start/Stop by operator -> Remove web-2 destroys ONLY web-2 and its host.
func TestMachinesCreateResizePowerAndRemoveEndToEnd(t *testing.T) {
	a := newTestApp(t)
	a.withPlaybook()  // skips on Windows where sh scripts cannot run by shebang
	a.withTerraform() // installs terraformStub on PATH
	a.s.provision = provisionTiming{
		sshWait:  3 * time.Second,
		sshPoll:  50 * time.Millisecond,
		dhcpWait: time.Second,
		dhcpPoll: 50 * time.Millisecond,
		planTTL:  15 * time.Minute,
	}

	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)
	const tokenID = "terraform@pve!infra"
	const secret = "e2e-proxmox-secret-uuid"
	fp := startFakeProxmox(t, tokenID, secret)

	// Start two real test SSH servers (pre-seeded with the dashboard's public key,
	// just as Proxmox writes user_account.keys into a newly created container).
	sshByName := map[string]*remotetest.Server{}
	for _, name := range []string{"web-1", "web-2"} {
		home := t.TempDir()
		sshDir := filepath.Join(home, ".ssh")
		_ = os.MkdirAll(sshDir, 0o700)
		_ = os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte(a.rem.PublicKey()+"\n"), 0o600)
		sshByName[name] = remotetest.Start(t, home, remotetest.Options{})
	}
	a.s.hostTarget = func(m store.Machine, ip string) remote.Target {
		srv := sshByName[m.Name]
		return remote.Target{Address: srv.Host, Port: srv.Port, User: "root"}
	}

	// 1. Configure Proxmox + create group "web" with base & nginx profile.
	want(t, a.do("POST", "/api/proxmox", admin, map[string]any{
		"endpoint": fp.srv.URL, "token_id": tokenID, "token_secret": secret, "insecure": true,
	}), http.StatusOK)

	gRec := a.do("POST", "/api/groups", admin, map[string]string{"name": "web"})
	want(t, gRec, http.StatusCreated)
	webGroupID := mustID(t, a.idOf(gRec.Body))
	want(t, a.setGroupProfile(admin, itoa(webGroupID), role("base", nil), role("nginx", nil)), http.StatusNoContent)

	// 2. Create web-1 and web-2 in group web with auto_configure enabled.
	for i, name := range []string{"web-1", "web-2"} {
		rec := a.do("POST", "/api/machines", admin, map[string]any{
			"name": name, "node": "pve", "cores": 1, "memory_mb": 1024, "disk_gb": 8,
			"storage": "local-lvm", "bridge": "vmbr0", "template": "local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst",
			"ip_mode": "static", "ip_cidr": fmt.Sprintf("192.168.5.%d/24", 51+i), "gateway": "192.168.5.1",
			"auto_configure": true, "group_ids": []int64{webGroupID},
		})
		want(t, rec, http.StatusCreated)
	}

	// One Terraform job at a time (OD-04 mutex).
	a.s.tfMu.Lock()
	want(t, a.do("POST", "/api/terraform/plan", admin, nil), http.StatusConflict)
	a.s.tfMu.Unlock()

	// 3. Review changes -> "2 containers will be created."
	planRec := a.do("POST", "/api/terraform/plan", admin, nil)
	want(t, planRec, http.StatusOK)
	var planOut struct {
		Plan struct {
			ID      string `json:"id"`
			Summary struct {
				Add int `json:"add"`
			} `json:"summary"`
		} `json:"plan"`
		PlainSummary string `json:"plain_summary"`
		Applicable   bool   `json:"applicable"`
	}
	if err := json.Unmarshal(planRec.Body.Bytes(), &planOut); err != nil || !planOut.Applicable || planOut.Plan.Summary.Add != 2 {
		t.Fatalf("plan: %v %s", err, planRec.Body.String())
	}
	if planOut.PlainSummary != "2 containers will be created." {
		t.Errorf("plain_summary = %q", planOut.PlainSummary)
	}

	// 4. Apply that exact saved plan.
	applyRec := a.do("POST", "/api/terraform/apply", admin, map[string]string{"plan_id": planOut.Plan.ID})
	want(t, applyRec, http.StatusOK)
	var applyRes applyOutcome
	var finalEv string
	for _, ev := range events(applyRec.Body.String()) {
		switch ev.name {
		case "result":
			_ = json.Unmarshal([]byte(ev.data), &applyRes)
		case "done", "error":
			finalEv = ev.name + ": " + ev.data
		}
	}
	if finalEv != "done: ok" || len(applyRes.Created) != 2 || len(applyRes.HostsAdded) != 2 || len(applyRes.Configured) != 2 {
		t.Fatalf("apply outcome: final=%q res=%+v\nbody=%s", finalEv, applyRes, applyRec.Body.String())
	}

	// Plan is single-use: applying the same plan_id again is refused.
	want(t, a.do("POST", "/api/terraform/apply", admin, map[string]string{"plan_id": planOut.Plan.ID}), http.StatusConflict)

	// Both containers are now online, configured hosts in group "web".
	hostsRec := a.do("GET", "/api/hosts", admin, nil)
	want(t, hostsRec, http.StatusOK)
	var hostsOut struct {
		Hosts []struct {
			ID          int64      `json:"id"`
			Name        string     `json:"name"`
			Address     string     `json:"address"`
			Port        int        `json:"port"`
			User        string     `json:"user"`
			Status      string     `json:"status"`
			Groups      []string   `json:"groups"`
			MachineID   int64      `json:"machine_id"`
			MachineName string     `json:"machine_name"`
			Config      configView `json:"config"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(hostsRec.Body.Bytes(), &hostsOut); err != nil || len(hostsOut.Hosts) != 2 {
		t.Fatalf("hosts: %v %s", err, hostsRec.Body.String())
	}
	for _, h := range hostsOut.Hosts {
		if h.Status != remote.StatusOnline || h.MachineID == 0 || h.Config.State != configApplied || len(h.Groups) != 1 || h.Groups[0] != "web" {
			t.Errorf("host %s not online/configured/linked: %+v", h.Name, h)
		}
	}

	// 5. A Terraform-generated host cannot have its address edited on Hosts.
	h1 := hostsOut.Hosts[0]
	want(t, a.do("POST", fmt.Sprintf("/api/hosts/%d/edit", h1.ID), admin, map[string]any{
		"name": h1.Name, "address": "10.99.99.99", "port": h1.Port, "user": h1.User,
	}), http.StatusConflict)

	// 6. Operator can Stop and Start web-1.
	mListRec := a.do("GET", "/api/machines", operator, nil)
	want(t, mListRec, http.StatusOK)
	var mList struct {
		Machines []struct {
			ID     int64  `json:"id"`
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"machines"`
	}
	_ = json.Unmarshal(mListRec.Body.Bytes(), &mList)
	var web1ID, web2ID int64
	for _, m := range mList.Machines {
		if m.Status != "running" {
			t.Errorf("machine %s status = %q, want running", m.Name, m.Status)
		}
		if m.Name == "web-1" {
			web1ID = m.ID
		}
		if m.Name == "web-2" {
			web2ID = m.ID
		}
	}

	want(t, a.do("POST", fmt.Sprintf("/api/machines/%d/stop", web1ID), operator, nil), http.StatusOK)
	mListRec = a.do("GET", "/api/machines", operator, nil)
	if !strings.Contains(mListRec.Body.String(), `"name":"web-1"`) || !strings.Contains(mListRec.Body.String(), `"status":"stopped"`) {
		t.Errorf("after stop: %s", mListRec.Body.String())
	}
	want(t, a.do("POST", fmt.Sprintf("/api/machines/%d/start", web1ID), operator, nil), http.StatusOK)

	// 7. Resize web-1 (more RAM) -> reviewed as "changed in place".
	want(t, a.do("POST", fmt.Sprintf("/api/machines/%d/resize", web1ID), admin, map[string]any{
		"cores": 1, "memory_mb": 2048, "disk_gb": 8,
	}), http.StatusNoContent)
	planRec = a.do("POST", "/api/terraform/plan", admin, nil)
	want(t, planRec, http.StatusOK)
	if !strings.Contains(planRec.Body.String(), `"action":"update"`) || !strings.Contains(planRec.Body.String(), "changed in place") {
		t.Fatalf("resize plan: %s", planRec.Body.String())
	}
	var resizePlan struct {
		Plan struct{ ID string } `json:"plan"`
	}
	_ = json.Unmarshal(planRec.Body.Bytes(), &resizePlan)
	applyRec = a.do("POST", "/api/terraform/apply", admin, map[string]string{"plan_id": resizePlan.Plan.ID})
	want(t, applyRec, http.StatusOK)
	if !strings.Contains(applyRec.Body.String(), `"updated":["web-1"]`) {
		t.Fatalf("resize apply: %s", applyRec.Body.String())
	}

	// 8. Remove web-2 -> destroys ONLY web-2 and removes its host; web-1 stays.
	want(t, a.do("POST", fmt.Sprintf("/api/machines/%d/remove", web2ID), admin, nil), http.StatusOK)
	planRec = a.do("POST", "/api/terraform/plan", admin, nil)
	want(t, planRec, http.StatusOK)
	if !strings.Contains(planRec.Body.String(), `"action":"destroy"`) ||
		!strings.Contains(planRec.Body.String(), `"machine":"web-2"`) ||
		strings.Contains(planRec.Body.String(), `"machine":"web-1"`) {
		t.Fatalf("remove plan should destroy only web-2: %s", planRec.Body.String())
	}
	var rmPlan struct {
		Plan struct{ ID string } `json:"plan"`
	}
	_ = json.Unmarshal(planRec.Body.Bytes(), &rmPlan)
	applyRec = a.do("POST", "/api/terraform/apply", admin, map[string]string{"plan_id": rmPlan.Plan.ID})
	want(t, applyRec, http.StatusOK)
	if !strings.Contains(applyRec.Body.String(), `"destroyed":["web-2"]`) {
		t.Fatalf("remove apply: %s", applyRec.Body.String())
	}

	// Only web-1 remains on Machines and on Hosts.
	mListRec = a.do("GET", "/api/machines", admin, nil)
	if !strings.Contains(mListRec.Body.String(), `"name":"web-1"`) || strings.Contains(mListRec.Body.String(), `"name":"web-2"`) {
		t.Errorf("machines after remove: %s", mListRec.Body.String())
	}
	hostsRec = a.do("GET", "/api/hosts", admin, nil)
	if !strings.Contains(hostsRec.Body.String(), `"name":"web-1"`) || strings.Contains(hostsRec.Body.String(), `"name":"web-2"`) {
		t.Errorf("hosts after remove: %s", hostsRec.Body.String())
	}

	// 9. IM8 — Drift check + Accept.
	_ = os.WriteFile(filepath.Join(a.s.tf.Dir, ".stub.drift"), []byte("web-1 2048 4096\n"), 0o600)
	driftRec := a.do("POST", "/api/terraform/drift", operator, nil)
	want(t, driftRec, http.StatusOK)
	if !strings.Contains(driftRec.Body.String(), "web-1 was changed outside the dashboard (memory 2048 → 4096)") {
		t.Fatalf("drift: %s", driftRec.Body.String())
	}
	want(t, a.do("POST", fmt.Sprintf("/api/machines/%d/accept-drift", web1ID), admin, nil), http.StatusNoContent)
	if m, _ := store.GetMachine(a.db, web1ID); m.MemoryMB != 4096 {
		t.Errorf("accept-drift did not update memory: %+v", m)
	}
	if got, _ := os.ReadFile(filepath.Join(a.s.tf.Dir, ".stub.last_target")); string(got) != `proxmox_virtual_environment_container.machine["web-1"]` {
		t.Errorf("accept-drift target = %q, want machine web-1", string(got))
	}

	// 10. IM8 — Rebuild (-replace): fresh SSH host key trusted automatically (audited) + profile re-applied.
	rebuiltHome := t.TempDir()
	_ = os.MkdirAll(filepath.Join(rebuiltHome, ".ssh"), 0o700)
	_ = os.WriteFile(filepath.Join(rebuiltHome, ".ssh", "authorized_keys"), []byte(a.rem.PublicKey()+"\n"), 0o600)
	sshByName["web-1"] = remotetest.Start(t, rebuiltHome, remotetest.Options{HostKey: remotetest.NewHostKey(t)})

	planRec = a.do("POST", "/api/terraform/plan", admin, map[string]string{"replace": "web-1"})
	want(t, planRec, http.StatusOK)
	if !strings.Contains(planRec.Body.String(), `"action":"replace"`) {
		t.Fatalf("rebuild plan: %s", planRec.Body.String())
	}
	var rebuildPlan struct {
		Plan struct{ ID string } `json:"plan"`
	}
	_ = json.Unmarshal(planRec.Body.Bytes(), &rebuildPlan)
	applyRec = a.do("POST", "/api/terraform/apply", admin, map[string]string{"plan_id": rebuildPlan.Plan.ID})
	want(t, applyRec, http.StatusOK)
	if !strings.Contains(applyRec.Body.String(), `"replaced":["web-1"]`) || !strings.Contains(applyRec.Body.String(), `"configured":["web-1"]`) {
		t.Fatalf("rebuild apply: %s", applyRec.Body.String())
	}
	if !a.has("host.trust_key", store.ResultOK) {
		t.Error("automatic host key trust after rebuild was not audited in History")
	}

	// 11. IM8 — Adopt an unmanaged container ("praktikum", VM 105).
	fp.mu.Lock()
	fp.states[105] = "running"
	fp.names[105] = "praktikum"
	fp.mu.Unlock()
	pHome := t.TempDir()
	_ = os.MkdirAll(filepath.Join(pHome, ".ssh"), 0o700)
	_ = os.WriteFile(filepath.Join(pHome, ".ssh", "authorized_keys"), []byte(a.rem.PublicKey()+"\n"), 0o600)
	sshByName["praktikum"] = remotetest.Start(t, pHome, remotetest.Options{})

	// Adopt preview with mismatching memory refuses adopt and lists what does not match.
	_ = os.WriteFile(filepath.Join(a.s.tf.Dir, ".stub.import_mem"), []byte("1024"), 0o600)
	adoptBad := a.do("POST", "/api/machines/adopt/preview", admin, map[string]any{
		"node": "pve", "vmid": 105, "name": "praktikum", "cores": 1, "memory_mb": 2048, "disk_gb": 8,
		"storage": "local-lvm", "bridge": "vmbr0", "ip_mode": "static", "ip_cidr": "192.168.5.90/24", "gateway": "192.168.5.1",
	})
	want(t, adoptBad, http.StatusOK)
	if !strings.Contains(adoptBad.Body.String(), `"ready":false`) || !strings.Contains(adoptBad.Body.String(), "memory[0].dedicated") {
		t.Fatalf("adopt mismatch: %s", adoptBad.Body.String())
	}

	// Adopt preview with matching memory shows "no changes" -> Apply imports it as a machine and a host.
	adoptOK := a.do("POST", "/api/machines/adopt/preview", admin, map[string]any{
		"node": "pve", "vmid": 105, "name": "praktikum", "cores": 1, "memory_mb": 1024, "disk_gb": 8,
		"storage": "local-lvm", "bridge": "vmbr0", "ip_mode": "static", "ip_cidr": "192.168.5.90/24", "gateway": "192.168.5.1",
	})
	want(t, adoptOK, http.StatusOK)
	var adoptPlan struct {
		Ready  bool   `json:"ready"`
		PlanID string `json:"plan_id"`
	}
	if err := json.Unmarshal(adoptOK.Body.Bytes(), &adoptPlan); err != nil || !adoptPlan.Ready || adoptPlan.PlanID == "" {
		t.Fatalf("adopt ready: %v %s", err, adoptOK.Body.String())
	}
	applyRec = a.do("POST", "/api/terraform/apply", admin, map[string]string{"plan_id": adoptPlan.PlanID})
	want(t, applyRec, http.StatusOK)
	if !strings.Contains(applyRec.Body.String(), `"hosts_added":["praktikum"]`) {
		t.Fatalf("adopt apply: %s", applyRec.Body.String())
	}
	if !a.has("machine.adopt", store.ResultOK) {
		t.Error("machine.adopt not in History")
	}

	// 12. IM8 — State backups & Restore (preview plan first, then restore).
	bRec := a.do("GET", "/api/terraform/backups", admin, nil)
	want(t, bRec, http.StatusOK)
	var bList struct {
		Backups []struct{ ID string } `json:"backups"`
	}
	if err := json.Unmarshal(bRec.Body.Bytes(), &bList); err != nil || len(bList.Backups) == 0 {
		t.Fatalf("backups: %v %s", err, bRec.Body.String())
	}
	bid := bList.Backups[0].ID
	prevRec := a.do("POST", "/api/terraform/backups/"+bid+"/preview", admin, nil)
	want(t, prevRec, http.StatusOK)
	if !strings.Contains(prevRec.Body.String(), `"backup_id":"`+bid+`"`) {
		t.Fatalf("restore preview: %s", prevRec.Body.String())
	}
	want(t, a.do("POST", "/api/terraform/backups/"+bid+"/restore", admin, nil), http.StatusNoContent)
	if !a.has("terraform.restore", store.ResultOK) {
		t.Error("terraform.restore not in History")
	}
}

func TestProxmoxTestRefusesExfiltratingSavedSecretToDifferentEndpoint(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	const tokenID = "terraform@pve!infra"
	const secret = "saved-secret-must-not-leave-home-12345"
	fp := startFakeProxmox(t, tokenID, secret)

	var attackerHits atomic.Int32
	var attackerAuth atomic.Value
	attackerSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerHits.Add(1)
		attackerAuth.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api2/json/version":
			_, _ = w.Write([]byte(`{"data":{"version":"8.2.4"}}`))
		case "/api2/json/nodes":
			_, _ = w.Write([]byte(`{"data":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer attackerSrv.Close()

	// Before anything is saved, testing an endpoint without a token secret fails with 400.
	rec := a.do("POST", "/api/proxmox/test", admin, map[string]any{
		"endpoint": attackerSrv.URL,
		"token_id": tokenID,
		"insecure": true,
	})
	want(t, rec, http.StatusBadRequest)
	if attackerHits.Load() != 0 {
		t.Fatalf("attacker received %d requests before save", attackerHits.Load())
	}

	// Plain http:// endpoints are rejected on both save and test.
	want(t, a.do("POST", "/api/proxmox", admin, map[string]any{
		"endpoint": "http://192.168.1.10:8006", "token_id": tokenID, "token_secret": secret,
	}), http.StatusBadRequest)
	want(t, a.do("POST", "/api/proxmox/test", admin, map[string]any{
		"endpoint": "http://192.168.1.10:8006", "token_id": tokenID, "token_secret": secret,
	}), http.StatusBadRequest)

	// Save the legitimate Proxmox endpoint + secret.
	want(t, a.do("POST", "/api/proxmox", admin, map[string]any{
		"endpoint": fp.srv.URL, "token_id": tokenID, "token_secret": secret, "insecure": true,
	}), http.StatusOK)

	// Testing a different endpoint with empty token_secret MUST be rejected (400)
	// and MUST NOT contact the attacker server.
	rec = a.do("POST", "/api/proxmox/test", admin, map[string]any{
		"endpoint": attackerSrv.URL,
		"token_id": tokenID,
		"insecure": true,
	})
	want(t, rec, http.StatusBadRequest)
	if !strings.Contains(strings.ToLower(rec.Body.String()), "re-entering") {
		t.Errorf("expected clear re-enter secret message, got: %s", rec.Body.String())
	}
	if attackerHits.Load() != 0 {
		t.Fatalf("saved Proxmox token secret was sent to attacker endpoint! hits=%d auth=%v", attackerHits.Load(), attackerAuth.Load())
	}

	// Changing the saved endpoint via POST /api/proxmox without re-entering the
	// secret MUST also be rejected so a 2-step save+test cannot exfiltrate it.
	rec = a.do("POST", "/api/proxmox", admin, map[string]any{
		"endpoint": attackerSrv.URL,
		"token_id": tokenID,
		"insecure": true,
	})
	want(t, rec, http.StatusBadRequest)

	// Testing the exact same endpoint (even with /api2/json/ suffix normalized)
	// reuses the saved secret cleanly.
	rec = a.do("POST", "/api/proxmox/test", admin, map[string]any{
		"endpoint": fp.srv.URL + "/api2/json/",
		"insecure": true,
	})
	want(t, rec, http.StatusOK)

	// Testing a different endpoint WITH an explicitly supplied secret uses only
	// the caller's secret, never the saved one.
	rec = a.do("POST", "/api/proxmox/test", admin, map[string]any{
		"endpoint":     attackerSrv.URL,
		"token_id":     tokenID,
		"token_secret": "caller-provided-secret",
		"insecure":     true,
	})
	want(t, rec, http.StatusOK)
	if got, _ := attackerAuth.Load().(string); strings.Contains(got, secret) || !strings.Contains(got, "caller-provided-secret") {
		t.Errorf("unexpected auth header sent to new endpoint: %q", got)
	}
}

func TestTerraformApplyStreamScrubsSecretsAcrossChunks(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	const tokenID = "terraform@pve!infra"
	const pveSecret = "pve-stream-secret-CHUNKED-998877"
	const vaultSecret = "vault-stream-secret-CHUNKED-554433"

	// Save Proxmox settings + vault password so both secrets are active.
	fp := startFakeProxmox(t, tokenID, pveSecret)
	want(t, a.do("POST", "/api/proxmox", admin, map[string]any{
		"endpoint": fp.srv.URL, "token_id": tokenID, "token_secret": pveSecret, "insecure": true,
	}), http.StatusOK)
	if err := os.WriteFile(a.s.vaultPasswordPath(), []byte(vaultSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Build a tiny cross-platform Go stand-in for terraform that prints secrets
	// split across separate writes during apply (runs on both Windows and Linux).
	srcDir := t.TempDir()
	binPath := filepath.Join(srcDir, "fake-terraform")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	stubSrc := `package main
import (
	"fmt"
	"os"
	"time"
)
func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("Terraform v1.9.8")
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "apply" {
		// Emit secrets split across separate writes and flushes, plus a trailing line with no newline.
		os.Stdout.WriteString("Provider error: auth token=")
		os.Stdout.WriteString("pve-stream-secret-")
		time.Sleep(10 * time.Millisecond)
		os.Stdout.WriteString("CHUNKED-998877 failed\n")
		os.Stderr.WriteString("Vault debug: vault-stream-")
		time.Sleep(10 * time.Millisecond)
		os.Stderr.WriteString("secret-CHUNKED-554433")
		os.Exit(1)
	}
}
`
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte("module stub\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(stubSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = srcDir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake terraform: %v\n%s", err, out)
	}
	a.s.tf.Bin = binPath

	// Seed a valid pending plan matching the current snapshot.
	snap, err := a.s.generateTerraform()
	if err != nil {
		t.Fatal(err)
	}
	planFile := filepath.Join(t.TempDir(), "p.tfplan")
	if err := os.WriteFile(planFile, []byte("plan"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.s.setPendingPlan(&savedPlan{
		ID: "scrub-test-plan", File: planFile, Created: time.Now(), Snapshot: snap,
		Summary: "1 container", Actions: map[string]string{},
	})

	rec := a.do("POST", "/api/terraform/apply", admin, map[string]string{"plan_id": "scrub-test-plan"})
	want(t, rec, http.StatusOK)
	body := rec.Body.String()
	for _, secret := range []string{pveSecret, vaultSecret} {
		if strings.Contains(body, secret) {
			t.Errorf("SSE stream leaked secret %q:\n%s", secret, body)
		}
		for _, ev := range a.events() {
			if strings.Contains(ev.Detail+ev.Target+ev.Action, secret) {
				t.Errorf("History leaked secret %q: %+v", secret, ev)
			}
		}
	}
	if !strings.Contains(body, "Provider error: auth token=… failed") || !strings.Contains(body, "Vault debug: …") {
		t.Errorf("expected redacted markers in SSE stream:\n%s", body)
	}
}

func TestAcceptDriftTargetsOnlySelectedMachine(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)

	m1, err := store.CreateMachine(a.db, store.Machine{
		Name: "web-1", Node: "pve", Cores: 1, MemoryMB: 1024, DiskGB: 8,
		Storage: "local-lvm", Bridge: "vmbr0", Template: "local:vztmpl/debian-12.tar.zst", IPMode: "dhcp",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkMachineApplied(a.db, m1.ID, 101, "10.0.0.11", m1.SizeSpec(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(a.s.tf.Dir, ".terraform"), 0o700); err != nil {
		t.Fatal(err)
	}

	// Build a tiny cross-platform terraform stand-in that records plan args.
	srcDir := t.TempDir()
	binPath := filepath.Join(srcDir, "fake-tf")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	argsLog := filepath.Join(srcDir, "plan.args")
	stubSrc := `package main
import (
	"fmt"
	"os"
	"strings"
)
func main() {
	if len(os.Args) < 2 { return }
	switch os.Args[1] {
	case "version":
		fmt.Println("Terraform v1.9.8")
	case "plan":
		_ = os.WriteFile(` + strconv.Quote(argsLog) + `, []byte(strings.Join(os.Args[2:], "\n")), 0o600)
		for _, a := range os.Args[2:] {
			if strings.HasPrefix(a, "-out=") {
				_ = os.WriteFile(strings.TrimPrefix(a, "-out="), []byte("{}"), 0o600)
			}
		}
	case "show":
		fmt.Println("{\"resource_changes\":[],\"resource_drift\":[]}")
	case "apply":
		fmt.Println("Apply complete!")
	}
}
`
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte("module stub\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(stubSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = srcDir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake terraform: %v\n%s", err, out)
	}
	a.s.tf.Bin = binPath

	a.s.setLastDrift(&driftReport{
		CheckedAt: time.Now().Unix(),
		Items: []tf.DriftDetail{
			{Machine: "web-1", Action: "update", MemoryMB: 2048, Sentence: "web-1 memory 1024 → 2048"},
			{Machine: "web-2", Action: "update", MemoryMB: 4096, Sentence: "web-2 memory 1024 → 4096"},
		},
	})

	want(t, a.do("POST", fmt.Sprintf("/api/machines/%d/accept-drift", m1.ID), admin, nil), http.StatusNoContent)

	rawArgs, err := os.ReadFile(argsLog)
	if err != nil {
		t.Fatalf("read plan args: %v", err)
	}
	gotArgs := string(rawArgs)
	wantTarget := `-target=proxmox_virtual_environment_container.machine["web-1"]`
	if !strings.Contains(gotArgs, "-refresh-only") || !strings.Contains(gotArgs, wantTarget) {
		t.Errorf("accept-drift plan args missing -refresh-only or %s:\n%s", wantTarget, gotArgs)
	}
	// Only web-1 is removed from the cached drift report; web-2 remains drifted.
	if rem := a.s.getLastDrift(); rem == nil || len(rem.Items) != 1 || rem.Items[0].Machine != "web-2" {
		t.Errorf("remaining drift: %+v", rem)
	}
}
