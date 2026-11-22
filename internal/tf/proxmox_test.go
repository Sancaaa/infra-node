package tf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestValidation(t *testing.T) {
	ep, err := CheckEndpoint("https://192.168.5.131:8006/api2/json/")
	if err != nil || ep != "https://192.168.5.131:8006" {
		t.Errorf("CheckEndpoint valid: %q %v", ep, err)
	}
	for _, bad := range []string{
		"",
		"http://192.168.5.131:8006",
		"http://pve:8006/api2/json",
		"ftp://pve:8006",
		"https://user:pass@pve:8006",
		"https://pve:8006?a=1",
		"https://pve 8006",
	} {
		if _, err := CheckEndpoint(bad); err == nil {
			t.Errorf("CheckEndpoint(%q) accepted", bad)
		}
	}

	if id, err := CheckTokenID("terraform@pve!infra"); err != nil || id != "terraform@pve!infra" {
		t.Errorf("CheckTokenID valid: %q %v", id, err)
	}
	for _, bad := range []string{"", "root@pam", "root!tok", "root@pam!tok=secret", "a b@pve!c"} {
		if _, err := CheckTokenID(bad); err == nil {
			t.Errorf("CheckTokenID(%q) accepted", bad)
		}
	}

	if err := CheckTokenSecret("550e8400-e29b-41d4-a716-446655440000"); err != nil {
		t.Errorf("CheckTokenSecret valid: %v", err)
	}
	for _, bad := range []string{"", "has space", "line1\nline2"} {
		if err := CheckTokenSecret(bad); err == nil {
			t.Errorf("CheckTokenSecret(%q) accepted", bad)
		}
	}

	for _, ok := range []string{"web-1", "a", "db01"} {
		if err := CheckMachineName(ok); err != nil {
			t.Errorf("CheckMachineName(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-web", "web-", "Web-1", "web_1", "web.1", "a b"} {
		if err := CheckMachineName(bad); err == nil {
			t.Errorf("CheckMachineName(%q) accepted", bad)
		}
	}

	if err := CheckTemplateID("local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst"); err != nil {
		t.Errorf("CheckTemplateID valid: %v", err)
	}
	for _, bad := range []string{"", "local:iso/foo.iso", "local:vztmpl/../etc/passwd", "local:vztmpl/bad name"} {
		if err := CheckTemplateID(bad); err == nil {
			t.Errorf("CheckTemplateID(%q) accepted", bad)
		}
	}

	cidr, ip, gw, err := CheckIPConfig("static", "192.168.1.50/24", "192.168.1.1")
	if err != nil || cidr != "192.168.1.50/24" || ip != "192.168.1.50" || gw != "192.168.1.1" {
		t.Errorf("CheckIPConfig static: %q %q %q %v", cidr, ip, gw, err)
	}
	if _, _, _, err := CheckIPConfig("static", "192.168.1.50", ""); err == nil {
		t.Error("CheckIPConfig static without prefix accepted")
	}
	if _, _, _, err := CheckIPConfig("static", "192.168.1.50/24", "not-an-ip"); err == nil {
		t.Error("CheckIPConfig bad gateway accepted")
	}
	if cidr, ip, gw, err := CheckIPConfig("dhcp", "", ""); err != nil || cidr != "" || ip != "" || gw != "" {
		t.Errorf("CheckIPConfig dhcp: %q %q %q %v", cidr, ip, gw, err)
	}
}

func TestSaveAndLoadTokenSecret(t *testing.T) {
	dir := t.TempDir()
	path := SecretPath(dir)
	const secret = "super-secret-proxmox-token-uuid"

	if HasTokenSecret(path) {
		t.Fatal("HasTokenSecret before save")
	}
	if err := SaveTokenSecret(path, secret); err != nil {
		t.Fatal(err)
	}
	if !HasTokenSecret(path) {
		t.Fatal("HasTokenSecret after save")
	}
	got, err := LoadTokenSecret(path)
	if err != nil || got != secret {
		t.Fatalf("LoadTokenSecret: %q %v", got, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("secret file mode = %04o, want 0600", mode)
		}
		dirInfo, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if mode := dirInfo.Mode().Perm(); mode != 0o700 {
			t.Errorf("secrets dir mode = %04o, want 0700", mode)
		}
	}
}

func TestProxmoxClientDiscoverAndPower(t *testing.T) {
	const tokenID = "terraform@pve!infra"
	const secret = "11111111-2222-3333-4444-555555555555"
	wantAuth := "PVEAPIToken=" + tokenID + "=" + secret

	taskPolls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != wantAuth {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("authentication failure for " + secret))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api2/json/version":
			_, _ = w.Write([]byte(`{"data":{"version":"8.2.4","release":"8.2"}}`))
		case "/api2/json/nodes":
			_, _ = w.Write([]byte(`{"data":[{"node":"pve","status":"online"},{"node":"pve2","status":"offline"}]}`))
		case "/api2/json/nodes/pve/storage":
			_, _ = w.Write([]byte(`{"data":[
				{"storage":"local","type":"dir","content":"vztmpl,iso","active":1,"enabled":1},
				{"storage":"local-lvm","type":"lvmthin","content":"rootdir,images","active":1,"enabled":1,"avail":50000,"total":100000},
				{"storage":"disabled-st","type":"dir","content":"rootdir","active":1,"enabled":0}
			]}`))
		case "/api2/json/nodes/pve/storage/local/content":
			_, _ = w.Write([]byte(`{"data":[{"volid":"local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst","size":12345}]}`))
		case "/api2/json/nodes/pve/network":
			_, _ = w.Write([]byte(`{"data":[{"iface":"vmbr0","type":"bridge","cidr":"192.168.5.131/24","gateway":"192.168.5.1"},{"iface":"eth0","type":"eth"}]}`))
		case "/api2/json/nodes/pve/lxc":
			_, _ = w.Write([]byte(`{"data":[{"vmid":"101","name":"web-1","status":"running","cpus":2}]}`))
		case "/api2/json/nodes/pve/lxc/101/interfaces":
			_, _ = w.Write([]byte(`{"data":[{"name":"lo","inet":"127.0.0.1/8"},{"name":"eth0","inet":"192.168.5.50/24"}]}`))
		case "/api2/json/nodes/pve/lxc/101/status/start":
			_, _ = w.Write([]byte(`{"data":"UPID:pve:0001:start"}`))
		case "/api2/json/nodes/pve/lxc/101/status/shutdown":
			_, _ = w.Write([]byte(`{"data":"UPID:pve:0002:stop"}`))
		case "/api2/json/nodes/pve/tasks/UPID:pve:0001:start/status", "/api2/json/nodes/pve/tasks/UPID:pve:0002:stop/status":
			taskPolls++
			if taskPolls%2 == 1 {
				_, _ = w.Write([]byte(`{"data":{"status":"running"}}`))
			} else {
				_, _ = w.Write([]byte(`{"data":{"status":"stopped","exitstatus":"OK"}}`))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// Strict TLS refuses the self-signed test cert with a clear sentence.
	strict := NewProxmoxClient(ProxmoxConfig{Endpoint: srv.URL, TokenID: tokenID, TokenSecret: secret, Insecure: false})
	if _, err := strict.Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "self-signed") {
		t.Fatalf("strict TLS: %v", err)
	}

	// Wrong secret is refused and never leaks the secret in the error.
	bad := NewProxmoxClient(ProxmoxConfig{Endpoint: srv.URL, TokenID: tokenID, TokenSecret: "wrong-secret-xyz", Insecure: true})
	if _, err := bad.Discover(context.Background()); err == nil || strings.Contains(err.Error(), "wrong-secret-xyz") || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("wrong secret: %v", err)
	}

	c := NewProxmoxClient(ProxmoxConfig{Endpoint: srv.URL, TokenID: tokenID, TokenSecret: secret, Insecure: true})
	c.TaskPoll = 5 * time.Millisecond

	d, err := c.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d.Version != "8.2.4" || len(d.Nodes) != 2 || len(d.Storages) != 1 || d.Storages[0].Name != "local-lvm" {
		t.Fatalf("discovery: %+v", d)
	}
	if len(d.Bridges) != 1 || d.Bridges[0].Name != "vmbr0" {
		t.Fatalf("bridges: %+v", d.Bridges)
	}
	if len(d.Templates) != 1 || !strings.Contains(d.Templates[0].VolID, "debian-12") {
		t.Fatalf("templates: %+v", d.Templates)
	}

	cts, err := c.ListContainers(context.Background(), "pve")
	if err != nil || len(cts) != 1 || cts[0].VMID != 101 || cts[0].Status != "running" {
		t.Fatalf("ListContainers: %+v %v", cts, err)
	}
	ips, err := c.ContainerInterfaces(context.Background(), "pve", 101)
	if err != nil || len(ips) != 1 || ips[0] != "192.168.5.50" {
		t.Fatalf("ContainerInterfaces: %+v %v", ips, err)
	}
	if err := c.StartContainer(context.Background(), "pve", 101); err != nil {
		t.Errorf("StartContainer: %v", err)
	}
	if err := c.StopContainer(context.Background(), "pve", 101); err != nil {
		t.Errorf("StopContainer: %v", err)
	}
}
