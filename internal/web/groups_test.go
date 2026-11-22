package web

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"infra-manager/internal/remote/remotetest"
	"infra-manager/internal/store"
)

// A stand-in for the ansible program. It does what the real one would do with
// the files the dashboard wrote: for "web -m ping" it reads inventory.ini, finds
// the hosts of [web], and answers for each in the one-line format of -o. So the
// generated inventory is really read by something, even where Ansible is not
// installed. A host whose name starts with "down" does not answer.
const ansibleStub = `#!/bin/sh
if [ "$1" = --version ]; then echo "ansible [core 2.14.3]"; exit 0; fi
dir=$(dirname "$ANSIBLE_CONFIG")
echo "args: $*" >> "$dir/.stub.log"
echo "config: $ANSIBLE_CONFIG" >> "$dir/.stub.log"
target="$1"
module="$3"
cd "$dir" || exit 4
hosts=$(awk -v g="$target" '$0 == "[" g "]" { f = 1; next } /^\[/ { f = 0 } f && NF { print }' inventory.ini)
if [ -z "$hosts" ] && grep -q "^$target " inventory.ini; then hosts="$target"; fi
if [ -z "$hosts" ]; then echo "[WARNING]: No hosts matched, nothing to do"; fi
for h in $hosts; do
  case "$h" in
    down*) printf '%s | UNREACHABLE! => {"changed": false, "msg": "Failed to connect to the host via ssh: root@10.0.0.9: Permission denied (publickey).", "unreachable": true}\n' "$h" ;;
    *)
      if [ "$module" = setup ]; then
        printf '%s | SUCCESS => {"ansible_facts": {"ansible_hostname": "%s", "ansible_distribution": "Debian", "ansible_distribution_version": "12", "ansible_processor_vcpus": 2, "ansible_default_ipv4": {"address": "10.0.0.1"}}, "changed": false}\n' "$h" "$h"
      else
        printf '%s | SUCCESS => {"changed": false, "ping": "pong"}\n' "$h"
      fi ;;
  esac
done
`

// installStub puts a script named name in a folder at the front of PATH. The
// dashboard then finds it by its plain name, as it finds the real program, so
// what the page shows is "ansible-playbook site.yml ..." and not a temporary
// path. The tests that use one skip where there is no sh to run it, and on
// Windows, which does not run a script by its shebang.
func (a *testApp) installStub(name, script string) string {
	a.t.Helper()
	if runtime.GOOS == "windows" {
		a.t.Skip("the stand-ins for ansible are shell scripts, which Windows does not run")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		a.t.Skip("the stand-in for ansible is a shell script and there is no sh here")
	}
	if a.stubs == "" {
		a.stubs = a.t.TempDir()
		a.t.Setenv("PATH", a.stubs+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	path := filepath.Join(a.stubs, name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		a.t.Fatal(err)
	}
	return path
}

// withAnsible makes "ansible" the stand-in.
func (a *testApp) withAnsible() string {
	a.t.Helper()
	return a.installStub("ansible", ansibleStub)
}

func (a *testApp) stubLog() string {
	data, _ := os.ReadFile(filepath.Join(a.s.ansible.Dir, ".stub.log"))
	return string(data)
}

func (a *testApp) idOf(rec interface{ String() string }) string {
	a.t.Helper()
	var out struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal([]byte(rec.String()), &out); err != nil || out.ID == 0 {
		a.t.Fatalf("no id in %s (%v)", rec.String(), err)
	}
	return strconv.FormatInt(out.ID, 10)
}

// webGroup makes the hosts web-1 and web-2 (two test SSH servers) and a group
// "web" with both in it. It returns the group's id and the hosts' ids.
func (a *testApp) webGroup(admin *http.Cookie) (group string, hosts []string) {
	a.t.Helper()
	for _, name := range []string{"web-1", "web-2"} {
		s := remotetest.Start(a.t, a.t.TempDir(), remotetest.Options{})
		hosts = append(hosts, a.addHost(admin, s, name))
	}
	rec := a.do("POST", "/api/groups", admin, map[string]string{"name": "web"})
	want(a.t, rec, http.StatusCreated)
	group = a.idOf(rec.Body)
	want(a.t, a.do("POST", "/api/groups/"+group+"/hosts", admin, map[string]any{"add": []int64{mustID(a.t, hosts[0]), mustID(a.t, hosts[1])}}), http.StatusNoContent)
	return group, hosts
}

func TestGroupsAndTheirMembers(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	_, viewer := a.user("vera", store.RoleViewer)
	group, hosts := a.webGroup(admin)

	// Anybody who can look can see who is in a group.
	rec := a.do("GET", "/api/groups", viewer, nil)
	want(t, rec, http.StatusOK)
	var list struct {
		Groups []struct {
			Name  string `json:"name"`
			Hosts []struct {
				Name string `json:"name"`
			} `json:"hosts"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Groups) != 1 || list.Groups[0].Name != "web" || len(list.Groups[0].Hosts) != 2 {
		t.Fatalf("groups: %s (%v)", rec.Body.String(), err)
	}
	if !strings.Contains(a.do("GET", "/api/hosts", viewer, nil).Body.String(), `"groups":["web"]`) {
		t.Error("the Hosts page does not know the group of a host")
	}

	// Names: Ansible's own, a host's, a taken one, a bad one.
	for name, status := range map[string]int{
		"all": http.StatusBadRequest, "ungrouped": http.StatusBadRequest, "Web Servers": http.StatusBadRequest, "web-3": http.StatusBadRequest,
		"web": http.StatusConflict, "WEB": http.StatusConflict,
	} {
		want(t, a.do("POST", "/api/groups", admin, map[string]string{"name": name}), status)
	}
	// A group named like a host, and a host named like a group, could not be told apart by Ansible.
	if _, err := store.CreateHost(a.db, store.Host{Name: "app", Address: "10.9.9.9", Port: 22, User: "x", Status: "online"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	want(t, a.do("POST", "/api/groups", admin, map[string]string{"name": "app"}), http.StatusConflict)
	s := remotetest.Start(t, t.TempDir(), remotetest.Options{})
	body := addBody(s, "web")
	want(t, a.do("POST", "/api/hosts", admin, body), http.StatusConflict)

	// Rename, remove one host, delete.
	want(t, a.do("POST", "/api/groups/"+group+"/rename", admin, map[string]string{"name": "frontend"}), http.StatusNoContent)
	want(t, a.do("POST", "/api/groups/"+group+"/hosts", admin, map[string]any{"remove": []int64{mustID(t, hosts[0])}}), http.StatusNoContent)
	if g, _ := store.GetGroup(a.db, mustID(t, group)); g.Name != "frontend" || len(g.HostIDs) != 1 {
		t.Errorf("after rename and remove: %+v", g)
	}
	want(t, a.do("POST", "/api/groups/"+group+"/hosts", admin, map[string]any{"add": []int64{999}}), http.StatusNotFound)
	want(t, a.do("POST", "/api/groups/"+group+"/delete", admin, nil), http.StatusNoContent)
	want(t, a.do("POST", "/api/groups/"+group+"/delete", admin, nil), http.StatusNotFound)
	if hs, _ := store.ListHosts(a.db); len(hs) != 3 {
		t.Errorf("deleting a group deleted a host: %d hosts", len(hs))
	}

	for _, action := range []string{"group.create", "group.rename", "group.hosts", "group.delete"} {
		if !a.has(action, store.ResultOK) {
			t.Errorf("%s is not in History", action)
		}
	}
}

func TestVariablesAreCheckedAndTheirValuesStayOutOfHistory(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)
	group, hosts := a.webGroup(admin)
	path := "/api/groups/" + group + "/vars"
	const secretish = "value-that-is-not-for-history-9154"

	want(t, a.do("POST", path, admin, map[string]any{"vars": []map[string]string{{"key": "nginx_port", "value": "80"}, {"key": "token", "value": secretish}}}), http.StatusNoContent)
	rec := a.do("GET", path, operator, nil) // an operator may read them
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), secretish) || strings.Index(rec.Body.String(), "nginx_port") > strings.Index(rec.Body.String(), "token") {
		t.Errorf("vars: %s", rec.Body.String())
	}
	for _, e := range a.events() {
		if strings.Contains(e.Detail+e.Target, secretish) {
			t.Errorf("a value is in History: %+v", e)
		}
	}
	if !strings.Contains(a.eventsText(), "2 variables: nginx_port, token") {
		t.Errorf("History says what changed by name:\n%s", a.eventsText())
	}

	bad := map[string][]map[string]string{
		"reserved":      {{"key": "ansible_host", "value": "10.9.9.9"}},
		"reserved case": {{"key": "ANSIBLE_USER", "value": "root"}},
		"bad name":      {{"key": "my-var", "value": "1"}},
		"empty name":    {{"key": "", "value": "1"}},
		"twice":         {{"key": "a", "value": "1"}, {"key": "a", "value": "2"}},
		"long value":    {{"key": "a", "value": strings.Repeat("x", 1001)}},
	}
	for name, vars := range bad {
		want := http.StatusBadRequest
		if rec := a.do("POST", path, admin, map[string]any{"vars": vars}); rec.Code != want {
			t.Errorf("%s: status %d, want %d (%s)", name, rec.Code, want, strings.TrimSpace(rec.Body.String()))
		}
	}
	// A refused list changes nothing.
	if vars, _ := store.GroupVars(a.db, mustID(t, group)); len(vars) != 2 {
		t.Errorf("a refused change was applied: %+v", vars)
	}

	// Host variables work the same way.
	want(t, a.do("POST", "/api/hosts/"+hosts[0]+"/vars", admin, map[string]any{"vars": []map[string]string{{"key": "role", "value": "primary"}}}), http.StatusNoContent)
	want(t, a.do("POST", "/api/hosts/"+hosts[0]+"/vars", admin, map[string]any{"vars": []map[string]string{{"key": "ansible_port", "value": "1"}}}), http.StatusBadRequest)
	if rec := a.do("GET", "/api/hosts/"+hosts[0]+"/vars", operator, nil); !strings.Contains(rec.Body.String(), `"role"`) {
		t.Errorf("host vars: %s", rec.Body.String())
	}
}

// "Changing a group variable in the form changes group_vars/web.yml", and View
// code shows the inventory with both hosts.
func TestTheGeneratedFilesFollowTheForms(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)
	group, hosts := a.webGroup(admin)

	code := func() map[string]string {
		rec := a.do("GET", "/api/code", operator, nil)
		want(t, rec, http.StatusOK)
		var out struct {
			Files []struct {
				Path    string `json:"path"`
				Content string `json:"content"`
			} `json:"files"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		files := map[string]string{}
		for _, f := range out.Files {
			files[f.Path] = f.Content
		}
		return files
	}

	files := code()
	if !strings.Contains(files["inventory.ini"], "[web]\nweb-1\nweb-2\n") ||
		!strings.Contains(files["inventory.ini"], "web-1 ansible_host=127.0.0.1 ansible_port=") {
		t.Errorf("inventory:\n%s", files["inventory.ini"])
	}
	if !strings.Contains(files["ansible.cfg"], "private_key_file = "+a.rem.PrivateKeyPath()) ||
		!strings.Contains(files["ansible.cfg"], "UserKnownHostsFile="+a.rem.KnownHostsPath()) {
		t.Errorf("ansible.cfg:\n%s", files["ansible.cfg"])
	}
	if _, ok := files["group_vars/web.yml"]; ok {
		t.Error("a group without variables has a file")
	}

	// The form changes the file, on disk too.
	want(t, a.do("POST", "/api/groups/"+group+"/vars", admin, map[string]any{"vars": []map[string]string{{"key": "nginx_port", "value": "80"}}}), http.StatusNoContent)
	if got := code()["group_vars/web.yml"]; !strings.Contains(got, "nginx_port: 80\n") {
		t.Errorf("group_vars/web.yml:\n%s", got)
	}
	want(t, a.do("POST", "/api/groups/"+group+"/vars", admin, map[string]any{"vars": []map[string]string{{"key": "nginx_port", "value": "8080"}}}), http.StatusNoContent)
	code()
	onDisk, err := os.ReadFile(filepath.Join(a.s.ansible.Dir, "group_vars", "web.yml"))
	if err != nil || !strings.Contains(string(onDisk), "nginx_port: 8080\n") {
		t.Errorf("on disk: %q %v", onDisk, err)
	}

	// A host that is removed leaves the inventory; a group that is deleted leaves its file.
	want(t, a.do("POST", "/api/hosts/"+hosts[1]+"/remove", admin, map[string]any{"remove_key": false}), http.StatusNoContent)
	want(t, a.do("POST", "/api/groups/"+group+"/delete", admin, nil), http.StatusNoContent)
	files = code()
	if strings.Contains(files["inventory.ini"], "web-2") || strings.Contains(files["inventory.ini"], "[web]") {
		t.Errorf("inventory after the changes:\n%s", files["inventory.ini"])
	}
	if _, ok := files["group_vars/web.yml"]; ok {
		t.Error("the file of a deleted group is still there")
	}
}

func TestPingWithAnsibleForAGroupAndAHost(t *testing.T) {
	a := newTestApp(t)
	a.withAnsible()
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)
	group, hosts := a.webGroup(admin)

	type answer struct {
		Target  string `json:"target"`
		Results []struct {
			Host    string `json:"host"`
			Status  string `json:"status"`
			Message string `json:"message"`
			Hint    string `json:"hint"`
		} `json:"results"`
		Commands []struct {
			Command string `json:"command"`
			Extra   string `json:"extra"`
		} `json:"commands"`
	}
	ping := func(body map[string]any) (answer, int) {
		rec := a.do("POST", "/api/ansible/ping", operator, body)
		var out answer
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out, rec.Code
	}

	out, code := ping(map[string]any{"group_id": mustID(t, group)})
	if code != http.StatusOK || out.Target != "web" || len(out.Results) != 2 {
		t.Fatalf("group ping: %d %+v", code, out)
	}
	for _, r := range out.Results {
		if r.Status != "ok" || r.Message != "pong" {
			t.Errorf("result: %+v", r)
		}
	}
	// The command behind the button, as a person would type it; -o is the dashboard's own.
	if len(out.Commands) != 1 || out.Commands[0].Command != "ansible web -m ping" || out.Commands[0].Extra != "-o" {
		t.Errorf("commands: %+v", out.Commands)
	}
	log := a.stubLog()
	if !strings.Contains(log, "args: web -m ping -o\n") || !strings.Contains(log, "config: "+filepath.Join(a.s.ansible.Dir, "ansible.cfg")+"\n") {
		t.Errorf("what ansible was called with:\n%s", log)
	}

	out, code = ping(map[string]any{"host_id": mustID(t, hosts[0])})
	if code != http.StatusOK || out.Target != "web-1" || len(out.Results) != 1 || out.Results[0].Host != "web-1" {
		t.Errorf("host ping: %d %+v", code, out)
	}

	// Exactly one target, and it must exist.
	if _, code := ping(map[string]any{}); code != http.StatusBadRequest {
		t.Errorf("no target: %d", code)
	}
	if _, code := ping(map[string]any{"host_id": 1, "group_id": 1}); code != http.StatusBadRequest {
		t.Errorf("two targets: %d", code)
	}
	if _, code := ping(map[string]any{"group_id": 999}); code != http.StatusNotFound {
		t.Errorf("unknown group: %d", code)
	}
}

func TestPingSaysWhyAHostDoesNotAnswer(t *testing.T) {
	a := newTestApp(t)
	a.withAnsible()
	_, admin := a.user("ada", store.RoleAdmin)
	s := remotetest.Start(t, t.TempDir(), remotetest.Options{})
	id := a.addHost(admin, s, "down-1")

	rec := a.do("POST", "/api/ansible/ping", admin, map[string]any{"host_id": mustID(t, id)})
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"status":"unreachable"`) || !strings.Contains(rec.Body.String(), "refused the SSH key") {
		t.Errorf("the answer does not say what to do: %s", rec.Body.String())
	}
}

func TestFactsAreSearchable(t *testing.T) {
	a := newTestApp(t)
	a.withAnsible()
	_, admin := a.user("ada", store.RoleAdmin)
	s := remotetest.Start(t, t.TempDir(), remotetest.Options{})
	id := a.addHost(admin, s, "web-1")

	rec := a.do("POST", "/api/ansible/facts", admin, map[string]any{"host_id": mustID(t, id)})
	want(t, rec, http.StatusOK)
	var out struct {
		Host   string            `json:"host"`
		Useful map[string]string `json:"useful"`
		Facts  [][2]string       `json:"facts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Host != "web-1" || out.Useful["OS"] != "Debian 12" || out.Useful["Address"] != "10.0.0.1" {
		t.Errorf("useful: %+v", out)
	}
	found := false
	for _, f := range out.Facts {
		if f[0] == "ansible_default_ipv4.address" && f[1] == "10.0.0.1" {
			found = true
		}
	}
	if !found || len(out.Facts) != 5 {
		t.Errorf("facts: %+v", out.Facts)
	}
}

// "Without ansible on the VPS: one sentence with the install command, and the
// rest of the app keeps working."
func TestWithoutAnsibleTheRestKeepsWorking(t *testing.T) {
	a := newTestApp(t)
	a.s.ansible.Bin = "ansible-that-is-not-installed"
	_, admin := a.user("ada", store.RoleAdmin)
	group, _ := a.webGroup(admin)

	rec := a.do("GET", "/api/ansible", admin, nil)
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"installed":false`) || !strings.Contains(rec.Body.String(), "apt install -y ansible") {
		t.Errorf("info: %s", rec.Body.String())
	}

	rec = a.do("POST", "/api/ansible/ping", admin, map[string]any{"group_id": mustID(t, group)})
	want(t, rec, http.StatusServiceUnavailable)
	if !strings.Contains(rec.Body.String(), "apt install -y ansible") || !strings.Contains(rec.Body.String(), `"missing":true`) {
		t.Errorf("ping: %s", rec.Body.String())
	}

	// Groups, variables and View code do not need it.
	want(t, a.do("GET", "/api/groups", admin, nil), http.StatusOK)
	want(t, a.do("POST", "/api/groups/"+group+"/vars", admin, map[string]any{"vars": []map[string]string{{"key": "a", "value": "1"}}}), http.StatusNoContent)
	rec = a.do("GET", "/api/code", admin, nil)
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), "inventory.ini") {
		t.Errorf("code: %s", rec.Body.String())
	}
}

func TestOnlyOneAnsibleRunAtATime(t *testing.T) {
	a := newTestApp(t)
	a.withAnsible()
	_, admin := a.user("ada", store.RoleAdmin)
	group, _ := a.webGroup(admin)

	a.s.ansibleMu.Lock()
	rec := a.do("POST", "/api/ansible/ping", admin, map[string]any{"group_id": mustID(t, group)})
	a.s.ansibleMu.Unlock()
	want(t, rec, http.StatusConflict)
	want(t, a.do("POST", "/api/ansible/ping", admin, map[string]any{"group_id": mustID(t, group)}), http.StatusOK)
}
