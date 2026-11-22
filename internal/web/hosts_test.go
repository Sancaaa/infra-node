package web

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"infra-manager/internal/remote/remotetest"
	"infra-manager/internal/store"
)

const hostPassword = "a-password-nobody-else-uses-4821"

// capturedLogs collects what the program logs during a test.
func capturedLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

// addBody is a valid "Add host" request for a test server.
func addBody(s *remotetest.Server, name string) map[string]any {
	return map[string]any{
		"name": name, "address": s.Host, "port": s.Port, "user": "tester",
		"method": "password", "password": s.Password, "sudo_nopasswd": false,
	}
}

func hostID(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		Host struct {
			ID int64 `json:"id"`
		} `json:"host"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Host.ID == 0 {
		t.Fatalf("no host in %s (%v)", rec.Body.String(), err)
	}
	return strconv.FormatInt(out.Host.ID, 10)
}

// "grep -r <that password> /var/lib/infra-manager finds nothing", and the logs,
// History and every answer are as clean.
func TestThePasswordOfAddHostIsNowhere(t *testing.T) {
	logs := capturedLogs(t)
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	s := remotetest.Start(t, t.TempDir(), remotetest.Options{Password: hostPassword})

	var answers []string
	rec := a.do("POST", "/api/hosts", admin, addBody(s, "web-1"))
	want(t, rec, http.StatusCreated)
	answers = append(answers, rec.Body.String())
	// A refused add, too: wrong password, a name that is taken, a bad address.
	bad := addBody(s, "web-2")
	bad["password"] = hostPassword + "-wrong"
	answers = append(answers, a.do("POST", "/api/hosts", admin, bad).Body.String())
	answers = append(answers, a.do("POST", "/api/hosts", admin, addBody(s, "web-1")).Body.String())
	answers = append(answers, a.do("GET", "/api/hosts", admin, nil).Body.String())
	answers = append(answers, a.do("GET", "/api/ssh-key", admin, nil).Body.String())

	for i, body := range answers {
		if strings.Contains(body, hostPassword) {
			t.Errorf("the password is in answer %d: %s", i, body)
		}
	}
	if strings.Contains(logs.String(), hostPassword) {
		t.Errorf("the password is in the log:\n%s", logs)
	}
	for _, e := range a.events() {
		if strings.Contains(strings.Join([]string{e.Username, e.Action, e.Target, e.Result, e.Detail, e.IP}, "\n"), hostPassword) {
			t.Errorf("the password is in History: %+v", e)
		}
	}
	// The data directory: the database (and its write-ahead log), the keys, known_hosts.
	files := 0
	err := filepath.WalkDir(a.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		files++
		if data, _ := os.ReadFile(path); bytes.Contains(data, []byte(hostPassword)) {
			t.Errorf("the password is in %s", path)
		}
		return nil
	})
	if err != nil || files < 3 {
		t.Fatalf("walked %d files: %v", files, err)
	}
}

func TestAddHostWithAPasswordAndAgain(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	home := t.TempDir()
	s := remotetest.Start(t, home, remotetest.Options{})

	rec := a.do("POST", "/api/hosts", admin, addBody(s, "web-1"))
	want(t, rec, http.StatusCreated)
	var out struct {
		Host struct {
			Name      string          `json:"name"`
			Status    string          `json:"status"`
			HostKeyFP string          `json:"host_key_fp"`
			Facts     json.RawMessage `json:"facts"`
		} `json:"host"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Host.Name != "web-1" || out.Host.Status != "online" || !strings.HasPrefix(out.Host.HostKeyFP, "SHA256:") || !strings.Contains(string(out.Host.Facts), `"arch"`) {
		t.Errorf("the new host: %s", rec.Body.String())
	}
	if !a.has("host.add", store.ResultOK) {
		t.Error("the add is not in History")
	}

	// The same machine again is refused before anything is sent to it.
	want(t, a.do("POST", "/api/hosts", admin, addBody(s, "web-1")), http.StatusConflict)
	want(t, a.do("POST", "/api/hosts", admin, addBody(s, "web-again")), http.StatusConflict)

	// Removed and added once more: still one copy of the key on the host.
	id := hostID(t, rec)
	want(t, a.do("POST", "/api/hosts/"+id+"/remove", admin, map[string]any{"remove_key": false}), http.StatusNoContent)
	want(t, a.do("POST", "/api/hosts", admin, addBody(s, "web-1")), http.StatusCreated)
	if n := strings.Count(s.AuthorizedKeys(), a.rem.PublicKey()); n != 1 {
		t.Errorf("the key is on the host %d times:\n%s", n, s.AuthorizedKeys())
	}
}

func TestAddHostByHand(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	home := t.TempDir()
	s := remotetest.Start(t, home, remotetest.Options{})
	body := map[string]any{"name": "web-1", "address": s.Host, "port": s.Port, "user": "tester", "method": "key"}

	// The key is not there yet: refused, and nothing is left behind.
	rec := a.do("POST", "/api/hosts", admin, body)
	want(t, rec, http.StatusBadGateway)
	if !strings.Contains(rec.Body.String(), "dashboard's key") {
		t.Errorf("the answer does not say what to do: %s", rec.Body.String())
	}
	if hosts, _ := store.ListHosts(a.db); len(hosts) != 0 {
		t.Errorf("a failed add left a host: %+v", hosts)
	}
	if kh, _ := os.ReadFile(a.rem.KnownHostsPath()); strings.TrimSpace(string(kh)) != "" {
		t.Errorf("a failed add left a host key: %q", kh)
	}
	if !a.has("host.add", store.ResultFailed) {
		t.Error("the failure is not in History")
	}

	// What the dialog tells a person to paste.
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte(a.rem.PublicKey()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want(t, a.do("POST", "/api/hosts", admin, body), http.StatusCreated)
}

func TestAddHostChecksItsInput(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)

	cases := map[string]map[string]any{
		"name with a space":        {"name": "web 1", "address": "10.0.0.1", "port": 22, "user": "root", "method": "key"},
		"uppercase name":           {"name": "Web", "address": "10.0.0.1", "port": 22, "user": "root", "method": "key"},
		"address that is a flag":   {"name": "web", "address": "-oProxyCommand=id", "port": 22, "user": "root", "method": "key"},
		"address with a command":   {"name": "web", "address": "10.0.0.1;id", "port": 22, "user": "root", "method": "key"},
		"port 0 means 22, so 70000": {"name": "web", "address": "10.0.0.1", "port": 70000, "user": "root", "method": "key"},
		"user with a semicolon":    {"name": "web", "address": "10.0.0.1", "port": 22, "user": "a;id", "method": "key"},
		"user with a substitution": {"name": "web", "address": "10.0.0.1", "port": 22, "user": "$(id)", "method": "key"},
		"no method":                {"name": "web", "address": "10.0.0.1", "port": 22, "user": "root"},
		"password method, no password": {"name": "web", "address": "10.0.0.1", "port": 22, "user": "root", "method": "password"},
	}
	for name, body := range cases {
		rec := a.do("POST", "/api/hosts", admin, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (%s)", name, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
	}
	if hosts, _ := store.ListHosts(a.db); len(hosts) != 0 {
		t.Errorf("a refused form saved a host: %+v", hosts)
	}
}

func TestWrongPasswordAddsNothing(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	s := remotetest.Start(t, t.TempDir(), remotetest.Options{})
	body := addBody(s, "web-1")
	body["password"] = "wrong"

	rec := a.do("POST", "/api/hosts", admin, body)
	want(t, rec, http.StatusBadGateway) // not 401: that would log the person out of the dashboard
	if !strings.Contains(rec.Body.String(), "user name and password") {
		t.Errorf("answer: %s", rec.Body.String())
	}
	if hosts, _ := store.ListHosts(a.db); len(hosts) != 0 {
		t.Errorf("hosts: %+v", hosts)
	}
	if s.AuthorizedKeys() != "" {
		t.Errorf("a key was put on the host: %q", s.AuthorizedKeys())
	}
}

// The scenario of "Done when": the machine is reinstalled, so its host key is new.
func TestReinstalledHostIsRefusedUntilAnAdminTrustsTheNewKey(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)
	home := t.TempDir()
	first := remotetest.Start(t, home, remotetest.Options{})
	rec := a.do("POST", "/api/hosts", admin, addBody(first, "web-1"))
	want(t, rec, http.StatusCreated)
	id := hostID(t, rec)

	// Same address and port and the dashboard's key still in the home, a new host key.
	first.Close()
	remotetest.Start(t, home, remotetest.Options{Port: first.Port})

	// An operator can ask for a check, and sees the warning.
	rec = a.do("POST", "/api/hosts/"+id+"/check", operator, nil)
	want(t, rec, http.StatusOK)
	var out struct {
		Host struct {
			Status      string `json:"status"`
			Detail      string `json:"status_detail"`
			PresentedFP string `json:"presented_fp"`
			HostKeyFP   string `json:"host_key_fp"`
		} `json:"host"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Host.Status != "key_changed" || !strings.Contains(out.Host.Detail, "Trust the new key") || !strings.HasPrefix(out.Host.PresentedFP, "SHA256:") || out.Host.PresentedFP == out.Host.HostKeyFP {
		t.Fatalf("after the host key changed: %s", rec.Body.String())
	}

	// Only an admin can trust it, and only the key that was shown.
	want(t, a.do("POST", "/api/hosts/"+id+"/trust-key", operator, map[string]string{"fingerprint": out.Host.PresentedFP}), http.StatusForbidden)
	want(t, a.do("POST", "/api/hosts/"+id+"/trust-key", admin, map[string]string{"fingerprint": "SHA256:notthekeyyouwereshown"}), http.StatusConflict)

	rec = a.do("POST", "/api/hosts/"+id+"/trust-key", admin, map[string]string{"fingerprint": out.Host.PresentedFP})
	want(t, rec, http.StatusOK)
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Host.Status != "online" || out.Host.HostKeyFP == "" {
		t.Errorf("after trusting: %s (%v)", rec.Body.String(), err)
	}

	// It is audited, with both fingerprints.
	found := false
	for _, e := range a.events() {
		if e.Action == "host.trust_key" && e.Result == store.ResultOK && strings.Count(e.Detail, "SHA256:") == 2 && e.Username == "ada" {
			found = true
		}
	}
	if !found {
		t.Error("trusting the new key is not in History with both fingerprints")
	}
	// And trusting again, when nothing is wrong, is refused.
	want(t, a.do("POST", "/api/hosts/"+id+"/trust-key", admin, map[string]string{"fingerprint": out.Host.PresentedFP}), http.StatusConflict)
}

func TestRemoveHostCanTakeTheKeyOff(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	home := t.TempDir()
	s := remotetest.Start(t, home, remotetest.Options{})

	// Left on the host.
	rec := a.do("POST", "/api/hosts", admin, addBody(s, "web-1"))
	want(t, rec, http.StatusCreated)
	want(t, a.do("POST", "/api/hosts/"+hostID(t, rec)+"/remove", admin, map[string]any{"remove_key": false}), http.StatusNoContent)
	if !strings.Contains(s.AuthorizedKeys(), a.rem.PublicKey()) {
		t.Error("the key was taken off although the box was not ticked")
	}
	if kh, _ := os.ReadFile(a.rem.KnownHostsPath()); strings.TrimSpace(string(kh)) != "" {
		t.Errorf("the removed host's key is still trusted: %q", kh)
	}

	// Taken off.
	rec = a.do("POST", "/api/hosts", admin, addBody(s, "web-1"))
	want(t, rec, http.StatusCreated)
	want(t, a.do("POST", "/api/hosts/"+hostID(t, rec)+"/remove", admin, map[string]any{"remove_key": true}), http.StatusNoContent)
	if strings.Contains(s.AuthorizedKeys(), a.rem.PublicKey()) {
		t.Errorf("the key is still on the host:\n%s", s.AuthorizedKeys())
	}
	if hosts, _ := store.ListHosts(a.db); len(hosts) != 0 {
		t.Errorf("the host is still listed: %+v", hosts)
	}

	// The host cannot be reached: the removal is refused, the host stays, and
	// removing it from the dashboard only still works.
	rec = a.do("POST", "/api/hosts", admin, addBody(s, "web-2"))
	want(t, rec, http.StatusCreated)
	id := hostID(t, rec)
	s.Close()
	want(t, a.do("POST", "/api/hosts/"+id+"/remove", admin, map[string]any{"remove_key": true}), http.StatusBadGateway)
	if hosts, _ := store.ListHosts(a.db); len(hosts) != 1 {
		t.Errorf("the host was removed although the key could not be taken off: %+v", hosts)
	}
	want(t, a.do("POST", "/api/hosts/"+id+"/remove", admin, map[string]any{"remove_key": false}), http.StatusNoContent)
}

func TestEditHost(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	s := remotetest.Start(t, t.TempDir(), remotetest.Options{})
	rec := a.do("POST", "/api/hosts", admin, addBody(s, "web-1"))
	want(t, rec, http.StatusCreated)
	id := hostID(t, rec)

	edit := func(name string, port int) *httptest.ResponseRecorder {
		return a.do("POST", "/api/hosts/"+id+"/edit", admin, map[string]any{"name": name, "address": s.Host, "port": port, "user": "tester"})
	}

	// A name needs no connection at all: it works with the host switched off.
	s.Close()
	want(t, edit("web-one", s.Port), http.StatusOK)
	if h, _ := store.GetHost(a.db, mustID(t, id)); h.Name != "web-one" {
		t.Errorf("name: %+v", h)
	}

	// A port where nothing listens is refused, and the host stays as it was.
	rec = edit("web-one", 1)
	want(t, rec, http.StatusBadGateway)
	if h, _ := store.GetHost(a.db, mustID(t, id)); h.Port != s.Port {
		t.Errorf("a refused edit changed the port to %d", h.Port)
	}
	want(t, edit("Bad Name", s.Port), http.StatusBadRequest)
	if !a.has("host.edit", store.ResultOK) || !a.has("host.edit", store.ResultFailed) {
		t.Error("the edits are not in History")
	}
}

func mustID(t *testing.T, id string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSSHKeyEndpointGivesOnlyThePublicKey(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)

	rec := a.do("GET", "/api/ssh-key", admin, nil)
	want(t, rec, http.StatusOK)
	var out struct {
		PublicKey   string `json:"public_key"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.PublicKey != a.rem.PublicKey() || !strings.HasPrefix(out.Fingerprint, "SHA256:") || strings.Contains(rec.Body.String(), "PRIVATE") {
		t.Errorf("answer: %s", rec.Body.String())
	}
}
