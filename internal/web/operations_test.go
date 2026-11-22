package web

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"infra-manager/internal/remote/remotetest"
	"infra-manager/internal/store"
)

// Operations at scale (IM6): rolling runs, updating and rebooting, access,
// secrets and custom playbooks. They run against the stand-in ansible-playbook of
// config_test.go, which reads the generated files, and against test SSH servers.

// A stand-in for ansible-vault encrypt_string. The value arrives on its standard
// input; what it prints is the value in hex, in the shape of the real output. (It
// is not encryption. The tests only need the plain value to be gone from what the
// dashboard keeps.) It needs the vault password file, as the real one does, and a
// value that says FAILVAULT makes it fail while echoing the value, to see that the
// dashboard does not pass that on.
const vaultStub = `#!/bin/sh
pwfile=""; name=""
while [ $# -gt 0 ]; do
  case "$1" in
    --vault-password-file) pwfile="$2"; shift ;;
    --stdin-name) name="$2"; shift ;;
  esac
  shift
done
if [ ! -s "$pwfile" ]; then echo "ERROR! The vault password file $pwfile was not found" >&2; exit 1; fi
value=$(cat)
case "$value" in *FAILVAULT*) echo "ERROR! could not encrypt $value" >&2; exit 1 ;; esac
echo "Reading plaintext input from stdin. (ctrl-d to end input, twice if your content does not already have a newline)" >&2
hex=$(printf '%s' "$value" | od -An -tx1 | tr -d ' \n')
printf '%s: !vault |\n' "$name"
printf '          $ANSIBLE_VAULT;1.1;AES256\n'
printf '%s' "$hex" | fold -w 40 | sed 's/^/          /'
printf '\n'
`

// withVault points the server at the stand-in for ansible-vault.
func (a *testApp) withVault() {
	a.t.Helper()
	a.withPlaybook() // skips the test where there is no sh
	a.installStub("ansible-vault", vaultStub)
}

// fleet makes a group and a test host for each name, all in it.
func (a *testApp) fleet(admin *http.Cookie, group string, opts remotetest.Options, names ...string) (gid int64, ids map[string]string, servers map[string]*remotetest.Server) {
	a.t.Helper()
	rec := a.do("POST", "/api/groups", admin, map[string]string{"name": group})
	want(a.t, rec, http.StatusCreated)
	gid = mustID(a.t, a.idOf(rec.Body))
	ids, servers = map[string]string{}, map[string]*remotetest.Server{}
	var add []int64
	for _, name := range names {
		s := remotetest.Start(a.t, a.t.TempDir(), opts)
		ids[name], servers[name] = a.addHost(admin, s, name), s
		add = append(add, mustID(a.t, ids[name]))
	}
	want(a.t, a.do("POST", "/api/groups/"+itoa(gid)+"/hosts", admin, map[string]any{"add": add}), http.StatusNoContent)
	return gid, ids, servers
}

type opHost struct {
	Name       string `json:"name"`
	OK         bool   `json:"ok"`
	Failure    string `json:"failure"`
	NotReached bool   `json:"not_reached"`
}

type opAnswer struct {
	Hosts        []opHost `json:"hosts"`
	NotReached   int      `json:"not_reached"`
	Serial       int      `json:"serial"`
	RebootNeeded []string `json:"reboot_needed"`
}

// opResult reads the result and the last event of a streamed run.
func opResult(t *testing.T, rec *httptest.ResponseRecorder) (answer opAnswer, final string) {
	t.Helper()
	for _, ev := range events(rec.Body.String()) {
		switch ev.name {
		case "result":
			if err := json.Unmarshal([]byte(ev.data), &answer); err != nil {
				t.Fatalf("result: %v\n%s", err, ev.data)
			}
		case "done", "error":
			final = ev.name + ": " + ev.data
		}
	}
	return answer, final
}

func (o opAnswer) host(name string) opHost {
	for _, h := range o.Hosts {
		if h.Name == name {
			return h
		}
	}
	return opHost{}
}

func (a *testApp) generated(rel string) string {
	data, _ := os.ReadFile(filepath.Join(a.s.ansible.Dir, rel))
	return string(data)
}

func (a *testApp) exists(rel string) bool {
	_, err := os.Stat(filepath.Join(a.s.ansible.Dir, rel))
	return err == nil
}

// ---------------------------------------------------------------- rolling runs

// "Updating group web one at a time stops at a failing host and leaves the rest
// untouched."
func TestUpdatingPackagesIsRollingAndStopsAtAFailingHost(t *testing.T) {
	a := newTestApp(t)
	a.withPlaybook()
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)
	// By name: app-1 goes first and works, bad-1 fails, web-1 comes after it.
	gid, _, _ := a.fleet(admin, "fleet", remotetest.Options{}, "app-1", "bad-1", "web-1")

	// The plan says it is one at a time, and shows both commands.
	rec := a.do("POST", "/api/patch", operator, map[string]any{"mode": "plan", "group_id": gid})
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"serial":1`) || !strings.Contains(rec.Body.String(), "ansible-playbook patch.yml --limit app-1,bad-1,web-1 --check --diff") {
		t.Errorf("plan: %s", rec.Body.String())
	}

	rec = a.do("POST", "/api/patch", operator, map[string]any{"mode": "apply", "group_id": gid})
	want(t, rec, http.StatusOK)
	answer, final := opResult(t, rec)
	if final != "done: ok" {
		t.Errorf("the stream ended with %q", final)
	}
	if h := answer.host("app-1"); !h.OK {
		t.Errorf("app-1: %+v", h)
	}
	if h := answer.host("bad-1"); h.OK || h.NotReached || !strings.Contains(h.Failure, "Install the pending package upgrades") {
		t.Errorf("bad-1: %+v", h)
	}
	if h := answer.host("web-1"); h.OK || !h.NotReached || h.Failure != "" {
		t.Errorf("web-1 was not reached and must not be called a failure: %+v", h)
	}
	if answer.NotReached != 1 || answer.Serial != 1 {
		t.Errorf("answer: %+v", answer)
	}

	// What the playbook asked for, and what was done to the hosts.
	if yml := a.generated("patch.yml"); !strings.Contains(yml, "  serial: 1\n  max_fail_percentage: 0\n") {
		t.Errorf("patch.yml is not rolling:\n%s", yml)
	}
	if !a.exists(".patched-app-1") || a.exists(".patched-web-1") || a.exists(".patched-bad-1") {
		t.Error("the update did not stop at the failing host")
	}
	if !strings.Contains(a.eventsText(), "patch.apply | group fleet | failed | 3 hosts, 1 failed, 1 changes, 1 not reached (left as they were), 1 at a time") {
		t.Errorf("History:\n%s", a.eventsText())
	}

	// Not rolling is not offered, and neither is too much of it.
	want(t, a.do("POST", "/api/patch", operator, map[string]any{"mode": "apply", "group_id": gid, "serial": 51}), http.StatusBadRequest)
	want(t, a.do("POST", "/api/patch", operator, map[string]any{"mode": "apply", "group_id": gid, "serial": -1}), http.StatusBadRequest)
	want(t, a.do("POST", "/api/patch", operator, map[string]any{"mode": "nope", "group_id": gid}), http.StatusBadRequest)
}

func TestPatchPreviewChangesNothing(t *testing.T) {
	a := newTestApp(t)
	a.withPlaybook()
	_, operator := a.user("otto", store.RoleOperator)
	_, admin := a.user("ada", store.RoleAdmin)
	gid, _, _ := a.fleet(admin, "fleet", remotetest.Options{}, "app-1", "app-2")

	rec := a.do("POST", "/api/patch", operator, map[string]any{"mode": "preview", "group_id": gid, "serial": 2})
	want(t, rec, http.StatusOK)
	var out struct {
		Hosts []struct {
			Name    string `json:"name"`
			Changes []struct {
				Title string `json:"title"`
				Diff  string `json:"diff"`
			} `json:"changes"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Hosts) != 2 || len(out.Hosts[0].Changes) != 1 || out.Hosts[0].Changes[0].Title != "Install the pending package upgrades" || out.Hosts[0].Changes[0].Diff == "" {
		t.Fatalf("preview: %v %s", err, rec.Body.String())
	}
	if a.exists(".patched-app-1") {
		t.Error("a preview updated a host")
	}
	if log := a.stubLog(); !strings.Contains(log, "args: patch.yml --limit app-1,app-2 --check --diff\n") || !strings.Contains(a.generated("patch.yml"), "  serial: 2\n") {
		t.Errorf("stub log:\n%s", log)
	}
}

// The profiles' playbook is rolling too, and a host a rolling run never reached
// is left as it was: not "failed", still waiting for its first apply.
func TestARollingApplyLeavesTheHostsItDidNotReachAsTheyWere(t *testing.T) {
	a := newTestApp(t)
	a.withPlaybook()
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)
	gid, _, _ := a.fleet(admin, "fleet", remotetest.Options{}, "app-1", "bad-1", "web-1")
	want(t, a.setGroupProfile(admin, itoa(gid), role("nginx", nil)), http.StatusNoContent)

	rec := a.do("POST", "/api/configure", operator, map[string]any{"mode": "apply", "group_id": gid, "serial": 1})
	want(t, rec, http.StatusOK)
	answer, _ := opResult(t, rec)
	if !answer.host("app-1").OK || answer.host("bad-1").OK || !answer.host("web-1").NotReached {
		t.Errorf("answer: %+v", answer)
	}
	if !strings.Contains(a.generated("site.yml"), "  serial: 1\n  max_fail_percentage: 0\n") {
		t.Errorf("site.yml is not rolling:\n%s", a.generated("site.yml"))
	}
	states := a.configOf(operator)
	if states["app-1"].State != configApplied || states["bad-1"].State != configFailed || states["web-1"].State != configNever {
		t.Errorf("states: app-1 %s, bad-1 %s, web-1 %s", states["app-1"].State, states["bad-1"].State, states["web-1"].State)
	}

	// Without serial the same run goes to every host at once (and web-1 is applied).
	rec = a.do("POST", "/api/configure", operator, map[string]any{"mode": "apply", "group_id": gid})
	answer, _ = opResult(t, rec)
	if answer.host("web-1").NotReached || !answer.host("web-1").OK {
		t.Errorf("not rolling: %+v", answer)
	}
	if strings.Contains(a.generated("site.yml"), "serial") {
		t.Errorf("site.yml is still rolling:\n%s", a.generated("site.yml"))
	}
}

// ------------------------------------------------------------------- reboots

const acceptReboot = "#!/bin/sh\necho \"systemctl $*\" >> \"$HOME/calls.log\"\nexit 0\n"

// needsReboot: a host with a newer kernel installed than the one that runs, which
// is how the health check knows (and the one place a test can make it say so).
func needsReboot(uptime string) remotetest.Options {
	return remotetest.Options{Stubs: map[string]string{
		"systemctl": acceptReboot,
		"cut":       cutStub(uptime),
		"uname":     "#!/bin/sh\ncase \"$1\" in -r) echo 6.1.0-1 ;; *) exec /bin/uname \"$@\" ;; esac\n",
		"ls":        "#!/bin/sh\ncase \"$*\" in */boot/vmlinuz-*) echo /boot/vmlinuz-6.1.0-99 ;; *) exec /bin/ls \"$@\" ;; esac\n",
	}}
}

func TestPatchingThenRebootingOneByOne(t *testing.T) {
	a := newTestApp(t)
	a.withPlaybook()
	a.s.reboot = rebootTiming{settle: 10 * time.Millisecond, poll: 30 * time.Millisecond, timeout: 3 * time.Second}
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)
	gid, ids, servers := a.fleet(admin, "fleet", needsReboot("3"), "web-1", "web-2")

	// The update says which hosts now wait for a reboot.
	rec := a.do("POST", "/api/patch", operator, map[string]any{"mode": "apply", "group_id": gid})
	want(t, rec, http.StatusOK)
	answer, final := opResult(t, rec)
	if final != "done: ok" || len(answer.RebootNeeded) != 2 || answer.RebootNeeded[0] != "web-1" || answer.RebootNeeded[1] != "web-2" {
		t.Fatalf("after the update: %q %+v", final, answer)
	}
	if h := a.host(ids["web-1"]); !strings.Contains(h.HealthJSON, `"reboot_required":true`) {
		t.Errorf("the host's health was not refreshed: %s", h.HealthJSON)
	}

	// One by one: the second is not touched until the first is back.
	rec = a.do("POST", "/api/patch/reboot", operator, map[string]any{"host_ids": []int64{mustID(t, ids["web-1"]), mustID(t, ids["web-2"])}})
	want(t, rec, http.StatusOK)
	body := rec.Body.String()
	order := []string{"Rebooting web-1", "web-1 is back", "Rebooting web-2", "web-2 is back"}
	last := -1
	for _, part := range order {
		i := strings.Index(body, part)
		if i < 0 || i < last {
			t.Fatalf("%q is missing or out of order in:\n%s", part, body)
		}
		last = i
	}
	reboots, final := 0, ""
	var steps struct {
		Steps []struct {
			Name string `json:"name"`
			OK   bool   `json:"ok"`
		} `json:"steps"`
		NotRebooted []string `json:"not_rebooted"`
	}
	for _, ev := range events(body) {
		switch ev.name {
		case "result":
			if err := json.Unmarshal([]byte(ev.data), &steps); err != nil {
				t.Fatal(err)
			}
		case "done", "error":
			final = ev.name + ": " + ev.data
		}
	}
	if final != "done: ok" || len(steps.Steps) != 2 || !steps.Steps[0].OK || !steps.Steps[1].OK || len(steps.NotRebooted) != 0 {
		t.Errorf("the sequence: %q %+v", final, steps)
	}
	for _, s := range servers {
		for _, c := range callsOf(s) {
			if c == "systemctl reboot" {
				reboots++
			}
		}
	}
	if reboots != 2 {
		t.Errorf("%d reboots were sent, want 2", reboots)
	}
	done := 0
	for _, e := range a.events() {
		if e.Action == "host.reboot.done" && e.Result == store.ResultOK && e.Username == "otto" {
			done++
		}
	}
	if done != 2 {
		t.Errorf("%d reboots are in History as done by otto, want 2:\n%s", done, a.eventsText())
	}
}

func TestRebootOneByOneStopsWhereAHostDoesNotComeBack(t *testing.T) {
	a := newTestApp(t)
	a.s.reboot = rebootTiming{settle: 10 * time.Millisecond, poll: 30 * time.Millisecond, timeout: 400 * time.Millisecond}
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)
	// An uptime of a day and a half: s-1 takes the reboot and never goes down.
	_, ids, servers := a.fleet(admin, "fleet", needsReboot("129600"), "s-1", "s-2", "s-3")

	rec := a.do("POST", "/api/patch/reboot", operator, map[string]any{"host_ids": []int64{mustID(t, ids["s-1"]), mustID(t, ids["s-2"]), mustID(t, ids["s-3"])}})
	want(t, rec, http.StatusOK)
	var steps struct {
		Steps []struct {
			Name string `json:"name"`
			OK   bool   `json:"ok"`
		} `json:"steps"`
		NotRebooted []string `json:"not_rebooted"`
	}
	final := ""
	for _, ev := range events(rec.Body.String()) {
		switch ev.name {
		case "result":
			if err := json.Unmarshal([]byte(ev.data), &steps); err != nil {
				t.Fatal(err)
			}
		case "done", "error":
			final = ev.name + ": " + ev.data
		}
	}
	if !strings.HasPrefix(final, "error: Stopped: s-1 did not come back") || !strings.Contains(final, "left alone") {
		t.Errorf("the end of the stream: %q", final)
	}
	if len(steps.Steps) != 1 || steps.Steps[0].OK || len(steps.NotRebooted) != 2 || steps.NotRebooted[0] != "s-2" || steps.NotRebooted[1] != "s-3" {
		t.Errorf("the steps: %+v", steps)
	}
	for _, name := range []string{"s-2", "s-3"} {
		for _, c := range callsOf(servers[name]) {
			if c == "systemctl reboot" {
				t.Errorf("%s was rebooted after s-1 had failed", name)
			}
		}
	}
	if !a.has("host.reboot.done", store.ResultFailed) {
		t.Error("the failure is not in History")
	}
}

func TestRebootOneByOneIsCheckedBeforeAnythingHappens(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)
	_, ids, servers := a.fleet(admin, "fleet", remotetest.Options{Stubs: map[string]string{"systemctl": acceptReboot}}, "web-1")

	want(t, a.do("POST", "/api/patch/reboot", operator, map[string]any{"host_ids": []int64{}}), http.StatusBadRequest)
	want(t, a.do("POST", "/api/patch/reboot", operator, map[string]any{"host_ids": []int64{mustID(t, ids["web-1"]), 999}}), http.StatusNotFound)
	a.s.rebootSeq.Lock()
	want(t, a.do("POST", "/api/patch/reboot", operator, map[string]any{"host_ids": []int64{mustID(t, ids["web-1"])}}), http.StatusConflict)
	a.s.rebootSeq.Unlock()
	for _, c := range callsOf(servers["web-1"]) {
		if c == "systemctl reboot" {
			t.Error("a refused request rebooted a host")
		}
	}
}

// ---------------------------------------------------------------------- access

const (
	dewiKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDewiDewiDewiDewiDewiDewiDewiDewi"
	budiKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBudiBudiBudiBudiBudiBudiBudiBudi"
)

// accessFile is what the stand-in has "authorized" on a host.
func (a *testApp) accessFile(host string) string { return a.generated(filepath.Join(".access", host)) }

type accessList struct {
	Keys []struct {
		ID        int64    `json:"id"`
		Name      string   `json:"name"`
		PublicKey string   `json:"public_key"`
		GroupIDs  []int64  `json:"group_ids"`
		HostIDs   []int64  `json:"host_ids"`
		Installed []string `json:"installed"`
	} `json:"keys"`
	Pending []struct {
		Host   string   `json:"host"`
		Add    []string `json:"add"`
		Remove []string `json:"remove"`
	} `json:"pending"`
}

func (a *testApp) accessList(c *http.Cookie) accessList {
	a.t.Helper()
	rec := a.do("GET", "/api/access", c, nil)
	want(a.t, rec, http.StatusOK)
	var out accessList
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		a.t.Fatal(err)
	}
	return out
}

func (a *testApp) addKey(admin *http.Cookie, name, key string) string {
	a.t.Helper()
	rec := a.do("POST", "/api/access/keys", admin, map[string]string{"name": name, "public_key": key})
	want(a.t, rec, http.StatusCreated)
	return a.idOf(rec.Body)
}

// "Giving a teammate access lets their key log into every web host, and Revoke
// removes it from all."
func TestAccessIsGivenToAGroupAndRevokedEverywhere(t *testing.T) {
	a := newTestApp(t)
	a.withPlaybook()
	_, admin := a.user("ada", store.RoleAdmin)
	group, _ := a.webGroup(admin)
	gid := mustID(t, group)

	// A key is checked, and a name or a key is on the list once.
	bad := func(name, key, user string, status int) {
		t.Helper()
		want(t, a.do("POST", "/api/access/keys", admin, map[string]string{"name": name, "public_key": key, "user": user}), status)
	}
	bad("Dewi", "this is not a key", "", http.StatusBadRequest)
	bad("", dewiKey, "", http.StatusBadRequest)
	bad("Dewi", dewiKey, "two words", http.StatusBadRequest)
	dewi := a.addKey(admin, "Dewi", dewiKey+" dewi@laptop") // the comment is dropped: the name says whose it is
	bad("Dewi", budiKey, "", http.StatusConflict)
	bad("Other", dewiKey, "", http.StatusConflict)
	if l := a.accessList(admin); len(l.Keys) != 1 || l.Keys[0].PublicKey != dewiKey {
		t.Fatalf("keys: %+v", l.Keys)
	}

	// Granting does not touch a host: it shows as pending, and in the files.
	want(t, a.do("POST", "/api/access/keys/"+dewi+"/grants", admin, map[string]any{"group_ids": []int64{gid}}), http.StatusNoContent)
	l := a.accessList(admin)
	if len(l.Pending) != 2 || l.Pending[0].Host != "web-1" || len(l.Pending[0].Add) != 1 || l.Pending[0].Add[0] != "Dewi" || len(l.Pending[1].Remove) != 0 {
		t.Errorf("pending: %+v", l.Pending)
	}
	if rec := a.do("GET", "/api/code", admin, nil); !strings.Contains(rec.Body.String(), `im_access: [{name: \"Dewi\", key: \"`+dewiKey+`\"`) {
		t.Errorf("View code does not say what the access playbook will do:\n%s", rec.Body.String())
	}
	if a.accessFile("web-1") != "" {
		t.Error("a grant changed a host")
	}

	// Preview: what would change, and nothing does.
	rec := a.do("POST", "/api/access/apply", admin, map[string]any{"mode": "preview"})
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"roles":["give Dewi"]`) || !strings.Contains(rec.Body.String(), "Give the SSH key of") {
		t.Errorf("preview: %s", rec.Body.String())
	}
	if a.accessFile("web-1") != "" {
		t.Error("a preview gave access")
	}

	// Apply: the key is on every host of the group.
	rec = a.do("POST", "/api/access/apply", admin, map[string]any{"mode": "apply"})
	want(t, rec, http.StatusOK)
	answer, final := opResult(t, rec)
	if final != "done: ok" || len(answer.Hosts) != 2 || !answer.Hosts[0].OK || !answer.Hosts[1].OK {
		t.Fatalf("apply: %q %+v", final, answer)
	}
	for _, h := range []string{"web-1", "web-2"} {
		if !strings.Contains(a.accessFile(h), dewiKey) {
			t.Errorf("%s did not get the key", h)
		}
	}
	l = a.accessList(admin)
	if len(l.Pending) != 0 || len(l.Keys[0].Installed) != 2 {
		t.Errorf("after the apply: %+v", l)
	}
	want(t, a.do("POST", "/api/access/apply", admin, map[string]any{"mode": "apply"}), http.StatusConflict) // nothing to do

	// A second person is given the group but not applied yet. Revoking the first
	// does only that: it must not give the second one anything.
	budi := a.addKey(admin, "Budi", budiKey)
	want(t, a.do("POST", "/api/access/keys/"+budi+"/grants", admin, map[string]any{"group_ids": []int64{gid}}), http.StatusNoContent)

	rec = a.do("POST", "/api/access/keys/"+dewi+"/revoke", admin, nil)
	want(t, rec, http.StatusOK)
	if _, final := opResult(t, rec); final != "done: ok" {
		t.Errorf("revoke: %q\n%s", final, rec.Body.String())
	}
	for _, h := range []string{"web-1", "web-2"} {
		if strings.Contains(a.accessFile(h), dewiKey) || strings.Contains(a.accessFile(h), budiKey) {
			t.Errorf("%s after the revoke: %q", h, a.accessFile(h))
		}
	}
	l = a.accessList(admin)
	for _, k := range l.Keys {
		if k.Name == "Dewi" && (len(k.Installed) != 0 || len(k.GroupIDs) != 0) {
			t.Errorf("Dewi after the revoke: %+v", k)
		}
	}
	if len(l.Pending) != 2 || l.Pending[0].Add[0] != "Budi" {
		t.Errorf("Budi's grant must still be waiting: %+v", l.Pending)
	}
	if !strings.Contains(a.eventsText(), "access.apply | revoke Dewi | ok | 2 hosts, 0 failed") {
		t.Errorf("History:\n%s", a.eventsText())
	}

	// Budi's turn; then Budi's key is deleted while it is still on the hosts: the
	// dashboard remembers it is there, so the next apply takes it off.
	want(t, a.do("POST", "/api/access/apply", admin, map[string]any{"mode": "apply"}), http.StatusOK)
	if !strings.Contains(a.accessFile("web-2"), budiKey) || strings.Contains(a.accessFile("web-2"), dewiKey) {
		t.Errorf("web-2: %q", a.accessFile("web-2"))
	}
	want(t, a.do("POST", "/api/access/keys/"+budi+"/delete", admin, nil), http.StatusNoContent)
	l = a.accessList(admin)
	if len(l.Keys) != 1 || len(l.Pending) != 2 || len(l.Pending[0].Remove) != 1 || l.Pending[0].Remove[0] != "Budi" {
		t.Errorf("after deleting Budi: %+v", l)
	}
	want(t, a.do("POST", "/api/access/apply", admin, map[string]any{"mode": "apply"}), http.StatusOK)
	if strings.Contains(a.accessFile("web-1"), budiKey) || strings.Contains(a.accessFile("web-2"), budiKey) {
		t.Error("a deleted key is still on the hosts")
	}
	if l = a.accessList(admin); len(l.Pending) != 0 {
		t.Errorf("pending at the end: %+v", l.Pending)
	}
}

func TestAccessGoesToSingleHostsAndTheAccountCanBeChosen(t *testing.T) {
	a := newTestApp(t)
	a.withPlaybook()
	_, admin := a.user("ada", store.RoleAdmin)
	_, hosts := a.webGroup(admin)

	rec := a.do("POST", "/api/access/keys", admin, map[string]string{"name": "Dewi", "public_key": dewiKey, "user": "deploy"})
	want(t, rec, http.StatusCreated)
	id := a.idOf(rec.Body)
	want(t, a.do("POST", "/api/access/keys/"+id+"/grants", admin, map[string]any{"host_ids": []int64{mustID(t, hosts[1])}}), http.StatusNoContent)
	want(t, a.do("POST", "/api/access/keys/"+id+"/grants", admin, map[string]any{"host_ids": []int64{999}}), http.StatusNotFound)
	want(t, a.do("POST", "/api/access/apply", admin, map[string]any{"mode": "apply"}), http.StatusOK)

	if a.accessFile("web-1") != "" || !strings.Contains(a.accessFile("web-2"), dewiKey) {
		t.Errorf("only web-2 was granted: web-1 %q, web-2 %q", a.accessFile("web-1"), a.accessFile("web-2"))
	}
	if vars := a.generated("host_vars/web-2.yml"); !strings.Contains(vars, `user: "deploy"`) {
		t.Errorf("the account is not in the host's variables:\n%s", vars)
	}
	// Without an account, the user the dashboard logs in as.
	rec = a.do("POST", "/api/access/keys", admin, map[string]string{"name": "Budi", "public_key": budiKey})
	want(t, a.do("POST", "/api/access/keys/"+a.idOf(rec.Body)+"/grants", admin, map[string]any{"host_ids": []int64{mustID(t, hosts[0])}}), http.StatusNoContent)
	if rec := a.do("GET", "/api/code", admin, nil); !strings.Contains(rec.Body.String(), `name: \"Budi\", key: \"`+budiKey+`\", user: \"tester\"`) {
		t.Errorf("default account:\n%s", rec.Body.String())
	}
}

func TestOnlyAdminsSeeAccessSecretsAndPlaybooks(t *testing.T) {
	a := newTestApp(t)
	_, viewer := a.user("vera", store.RoleViewer)
	_, operator := a.user("otto", store.RoleOperator)
	for _, path := range []string{"/api/access", "/api/secrets", "/api/playbooks", "/api/playbooks/x"} {
		for _, c := range []*http.Cookie{viewer, operator} {
			want(t, a.do("GET", path, c, nil), http.StatusForbidden)
		}
	}
	want(t, a.do("POST", "/api/playbooks/x/run", operator, map[string]any{"mode": "apply"}), http.StatusForbidden)
	want(t, a.do("POST", "/api/access/apply", operator, map[string]any{"mode": "apply"}), http.StatusForbidden)
	// Updating and rebooting are an operator's; a viewer may not.
	want(t, a.do("POST", "/api/patch", viewer, map[string]any{"mode": "plan"}), http.StatusForbidden)
	want(t, a.do("POST", "/api/patch/reboot", viewer, map[string]any{"host_ids": []int64{1}}), http.StatusForbidden)
	if !a.has(string(ActionAccess), store.ResultRefused) || !a.has(string(ActionSecrets), store.ResultRefused) || !a.has(string(ActionPlaybooks), store.ResultRefused) {
		t.Errorf("the refusals are not in History:\n%s", a.eventsText())
	}
}

// --------------------------------------------------------------------- secrets

// "A secret's value never appears in an API answer, a log or History."
func TestASecretsValueIsNowhereButInsideTheVault(t *testing.T) {
	logs := capturedLogs(t)
	a := newTestApp(t)
	a.withVault()
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)
	group, _ := a.webGroup(admin)

	const value, rotated = "s3cr3t-Token-9f2c", "r0tated-Token-77aa"
	var answers []string
	keep := func(rec *httptest.ResponseRecorder) *httptest.ResponseRecorder {
		answers = append(answers, rec.Body.String())
		return rec
	}
	set := func(name, v string) *httptest.ResponseRecorder {
		return keep(a.do("POST", "/api/secrets", admin, map[string]string{"name": name, "value": v}))
	}

	want(t, set("api_token", value), http.StatusNoContent)
	// What is refused, including a value that makes ansible-vault fail and say it.
	want(t, set("Bad Name", value), http.StatusBadRequest)
	want(t, set("empty", ""), http.StatusBadRequest)
	want(t, set("lines", "two\nlines "+value), http.StatusBadRequest)
	rec := set("boom", "FAILVAULT-"+value)
	want(t, rec, http.StatusBadGateway)
	if !strings.Contains(rec.Body.String(), "could not be encrypted") {
		t.Errorf("a failed encryption: %s", rec.Body.String())
	}

	// The list has names, and where each is used. Never a value.
	rec = keep(a.do("GET", "/api/secrets", admin, nil))
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"name":"api_token"`) || strings.Contains(rec.Body.String(), "boom") || strings.Contains(rec.Body.String(), "ciphertext") || strings.Contains(rec.Body.String(), "ANSIBLE_VAULT") {
		t.Errorf("secrets: %s", rec.Body.String())
	}

	// A profile and a variable point at it. A typed value, and a secret that does
	// not exist, are refused.
	pointer := func(v any) *httptest.ResponseRecorder {
		return keep(a.setGroupProfile(admin, group, role("nginx", map[string]any{"nginx_mode": "proxy", "nginx_proxy_token": v})))
	}
	want(t, pointer("secret:api_token"), http.StatusNoContent)
	want(t, pointer(value), http.StatusBadRequest)
	rec = pointer("secret:missing")
	want(t, rec, http.StatusBadRequest)
	if !strings.Contains(rec.Body.String(), "There is no secret called") {
		t.Errorf("a missing secret: %s", rec.Body.String())
	}
	want(t, pointer("secret:api_token"), http.StatusNoContent)
	vars := func(v string) *httptest.ResponseRecorder {
		return keep(a.do("POST", "/api/groups/"+group+"/vars", admin, map[string]any{"vars": []map[string]string{{"key": "token", "value": v}}}))
	}
	want(t, vars("secret:missing"), http.StatusBadRequest)
	want(t, vars("secret:api_token"), http.StatusNoContent)

	// The generated files hold the reference and the ciphertext.
	code := keep(a.do("GET", "/api/code", admin, nil))
	want(t, code, http.StatusOK)
	for _, expect := range []string{`secret_api_token: !vault |`, `$ANSIBLE_VAULT;1.1;AES256`, `nginx_proxy_token: \"{{ secret_api_token }}\"`, `token: \"{{ secret_api_token }}\"`} {
		if !strings.Contains(code.Body.String(), expect) {
			t.Errorf("View code is missing %q", expect)
		}
	}
	if cfg := a.generated("ansible.cfg"); !strings.Contains(cfg, "vault_password_file = "+filepath.Join(a.dir, "secrets", "vault_password")) {
		t.Errorf("ansible.cfg:\n%s", cfg)
	}
	password, err := os.ReadFile(filepath.Join(a.dir, "secrets", "vault_password"))
	if err != nil || len(bytes.TrimSpace(password)) < 32 {
		t.Fatalf("the vault password: %q %v", password, err)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(filepath.Join(a.dir, "secrets", "vault_password")); info.Mode().Perm() != 0o600 {
			t.Errorf("the vault password file is %v", info.Mode().Perm())
		}
	}
	if strings.Contains(code.Body.String(), string(bytes.TrimSpace(password))) {
		t.Error("View code shows the vault password")
	}

	// A secret that is set again makes the roles that use it "changes waiting".
	want(t, a.do("POST", "/api/configure", operator, map[string]any{"mode": "apply", "group_id": mustID(t, group)}), http.StatusOK)
	if st := a.configOf(operator)["web-1"].State; st != configApplied {
		t.Fatalf("state after the apply: %s", st)
	}
	want(t, set("api_token", rotated), http.StatusNoContent)
	if st := a.configOf(operator)["web-1"].State; st != configWaiting {
		t.Errorf("state after the secret was rotated: %s", st)
	}

	// It cannot be deleted while it is used.
	rec = keep(a.do("POST", "/api/secrets/api_token/delete", admin, nil))
	want(t, rec, http.StatusConflict)
	if !strings.Contains(rec.Body.String(), "group web: nginx") || !strings.Contains(rec.Body.String(), "group web: a variable") {
		t.Errorf("used by: %s", rec.Body.String())
	}
	want(t, a.setGroupProfile(admin, group, role("base", nil)), http.StatusNoContent)
	want(t, vars("1"), http.StatusNoContent)
	want(t, a.do("POST", "/api/secrets/api_token/delete", admin, nil), http.StatusNoContent)
	want(t, a.do("POST", "/api/secrets/api_token/delete", admin, nil), http.StatusNotFound)

	// Nowhere is either value: not in an answer, the log, History, or any file the
	// dashboard keeps (the database and its log, the keys, the generated files).
	for _, secret := range []string{value, rotated} {
		for i, body := range answers {
			if strings.Contains(body, secret) {
				t.Errorf("the value is in answer %d: %s", i, body)
			}
		}
		if strings.Contains(logs.String(), secret) {
			t.Errorf("the value is in the log:\n%s", logs)
		}
		if strings.Contains(a.eventsText(), secret) {
			t.Errorf("the value is in History:\n%s", a.eventsText())
		}
		files := 0
		err := filepath.WalkDir(a.dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			files++
			if data, _ := os.ReadFile(path); bytes.Contains(data, []byte(secret)) {
				t.Errorf("the value is in %s", path)
			}
			return nil
		})
		if err != nil || files < 5 {
			t.Fatalf("walked %d files: %v", files, err)
		}
	}
	if !a.has("secret.set", store.ResultOK) || !a.has("secret.set", store.ResultFailed) || !a.has("secret.delete", store.ResultOK) {
		t.Errorf("History:\n%s", a.eventsText())
	}
}

func TestSettingASecretNeedsAnsibleVault(t *testing.T) {
	a := newTestApp(t)
	a.s.ansible.VaultBin = "ansible-vault-that-is-not-installed"
	_, admin := a.user("ada", store.RoleAdmin)

	rec := a.do("POST", "/api/secrets", admin, map[string]string{"name": "api_token", "value": "x"})
	want(t, rec, http.StatusServiceUnavailable)
	if !strings.Contains(rec.Body.String(), "apt install -y ansible") {
		t.Errorf("the answer: %s", rec.Body.String())
	}
	// Listing does not need it.
	want(t, a.do("GET", "/api/secrets", admin, nil), http.StatusOK)
}

// ------------------------------------------------------------ custom playbooks

const tunePlaybook = "- name: Tune the hosts\n  hosts: all\n  become: true\n  tasks:\n    - name: Do the custom thing\n      ansible.builtin.debug:\n        msg: hello\n"

func TestACustomPlaybookIsCheckedBeforeItIsSaved(t *testing.T) {
	a := newTestApp(t)
	a.withPlaybook()
	_, admin := a.user("ada", store.RoleAdmin)

	save := func(name, content string) *httptest.ResponseRecorder {
		return a.do("POST", "/api/playbooks", admin, map[string]string{"name": name, "content": content})
	}
	rec := save("tune", tunePlaybook)
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), "ansible-playbook custom/tune.yml --syntax-check") {
		t.Errorf("the answer: %s", rec.Body.String())
	}
	if !strings.Contains(a.generated("custom/tune.yml"), "Tune the hosts") || !strings.Contains(a.stubLog(), "args: custom/tune.yml --syntax-check\n") {
		t.Errorf("the playbook was not written and checked: %s", a.stubLog())
	}

	// One that Ansible does not accept is not stored, and its text does not stay in custom/.
	rec = save("broken", "- hosts: all\n  BROKEN\n")
	want(t, rec, http.StatusBadRequest)
	if !strings.Contains(rec.Body.String(), "Nothing was saved") || !strings.Contains(rec.Body.String(), "unable to read") {
		t.Errorf("a refused playbook: %s", rec.Body.String())
	}
	if a.exists("custom/broken.yml") {
		t.Error("the playbook that was refused is still in custom/")
	}
	// Changing a good one into a bad one keeps the good one.
	want(t, save("tune", "BROKEN"), http.StatusBadRequest)
	if rec := a.do("GET", "/api/playbooks/tune", admin, nil); !strings.Contains(rec.Body.String(), "Tune the hosts") {
		t.Errorf("the saved playbook was lost: %s", rec.Body.String())
	}
	if !strings.Contains(a.generated("custom/tune.yml"), "Tune the hosts") {
		t.Error("custom/tune.yml was left with the text that was refused")
	}

	// Names and sizes.
	want(t, save("Bad Name", tunePlaybook), http.StatusBadRequest)
	want(t, save("../x", tunePlaybook), http.StatusBadRequest)
	want(t, save("empty", "  \n"), http.StatusBadRequest)
	want(t, save("huge", strings.Repeat("# a comment\n", 12000)), http.StatusBadRequest)
	a.s.ansibleMu.Lock()
	want(t, save("busy", tunePlaybook), http.StatusConflict)
	a.s.ansibleMu.Unlock()

	rec = a.do("GET", "/api/playbooks", admin, nil)
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"name":"tune"`) || strings.Contains(rec.Body.String(), "broken") || strings.Contains(rec.Body.String(), "Tune the hosts") {
		t.Errorf("the list holds names only: %s", rec.Body.String())
	}
	want(t, a.do("GET", "/api/playbooks/nothing", admin, nil), http.StatusNotFound)
	want(t, a.do("POST", "/api/playbooks/tune/delete", admin, nil), http.StatusNoContent)
	want(t, a.do("POST", "/api/playbooks/tune/delete", admin, nil), http.StatusNotFound)
	// The next time the files are written, a deleted playbook is gone from custom/.
	if rec := a.do("GET", "/api/code", admin, nil); strings.Contains(rec.Body.String(), "custom/tune.yml") || a.exists("custom/tune.yml") {
		t.Error("a deleted playbook is still in custom/")
	}
}

func TestACustomPlaybookIsPreviewedThenAppliedToAGroup(t *testing.T) {
	a := newTestApp(t)
	a.withPlaybook()
	_, admin := a.user("ada", store.RoleAdmin)
	gid, _, _ := a.fleet(admin, "fleet", remotetest.Options{}, "app-1", "bad-1", "web-1")
	want(t, a.do("POST", "/api/playbooks", admin, map[string]string{"name": "tune", "content": tunePlaybook}), http.StatusOK)

	body := func(mode string, serial int) map[string]any {
		return map[string]any{"mode": mode, "group_id": gid, "serial": serial}
	}
	rec := a.do("POST", "/api/playbooks/tune/run", admin, body("plan", 0))
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), "ansible-playbook custom/tune.yml --limit app-1,bad-1,web-1 --check --diff") || !strings.Contains(rec.Body.String(), `"label":"tune on group fleet"`) {
		t.Errorf("plan: %s", rec.Body.String())
	}

	rec = a.do("POST", "/api/playbooks/tune/run", admin, body("preview", 0))
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), "Do the custom thing") || a.exists(".custom-tune-app-1") {
		t.Errorf("preview: %s", rec.Body.String())
	}

	// Custom playbooks control rolling in their own YAML; non-zero serial is refused.
	want(t, a.do("POST", "/api/playbooks/tune/run", admin, body("apply", 1)), http.StatusBadRequest)
	rec = a.do("POST", "/api/playbooks/tune/run", admin, body("apply", 0))
	want(t, rec, http.StatusOK)
	answer, _ := opResult(t, rec)
	if !answer.host("app-1").OK || answer.host("bad-1").OK || !answer.host("web-1").OK {
		t.Errorf("apply: %+v", answer)
	}
	if !a.exists(".custom-tune-app-1") || !a.exists(".custom-tune-web-1") {
		t.Error("the custom playbook did not run on all reachable hosts")
	}
	if !a.has("playbook.apply", store.ResultFailed) || !strings.Contains(a.eventsText(), "playbook.apply | tune on group fleet | failed") {
		t.Errorf("History:\n%s", a.eventsText())
	}

	// A playbook that is not there, a mode that is not one.
	want(t, a.do("POST", "/api/playbooks/nothing/run", admin, body("apply", 0)), http.StatusNotFound)
	want(t, a.do("POST", "/api/playbooks/tune/run", admin, body("check_again", 0)), http.StatusBadRequest)
	want(t, a.do("POST", "/api/playbooks/tune/run", admin, body("apply", 99)), http.StatusBadRequest)
	want(t, a.do("POST", "/api/playbooks/tune/run", admin, map[string]any{"mode": "apply"}), http.StatusBadRequest)
}

func TestCustomPlaybookGuardrailsRefuseControlPlaneEscape(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)

	unsafe := map[string]string{
		"local_action": "- hosts: all\n  tasks:\n    - local_action: command id\n",
		"delegate_lh":  "- hosts: all\n  tasks:\n    - ansible.builtin.command: id\n      delegate_to: localhost\n",
		"delegate_ip":  "- hosts: all\n  tasks:\n    - ansible.builtin.command: id\n      delegate_to: 127.0.0.1\n",
		"delegate_v6":  "- hosts: all\n  tasks:\n    - ansible.builtin.command: id\n      delegate_to: \"::1\"\n",
		"conn_local":   "- hosts: all\n  connection: local\n  tasks: []\n",
		"conn_fqcn":    "- hosts: all\n  connection: ansible.builtin.local\n  tasks: []\n",
		"hosts_lh":     "- hosts: localhost\n  tasks: []\n",
		"lookup_file":  "- hosts: all\n  tasks:\n    - ansible.builtin.debug:\n        msg: \"{{ lookup('file', '/etc/passwd') }}\"\n",
		"query_pipe":   "- hosts: all\n  tasks:\n    - ansible.builtin.debug:\n        msg: \"{{ query('pipe', 'id') }}\"\n",
	}
	for name, content := range unsafe {
		rec := a.do("POST", "/api/playbooks", admin, map[string]string{"name": name, "content": content})
		want(t, rec, http.StatusBadRequest)
		if _, err := store.GetPlaybook(a.db, name); err == nil {
			t.Errorf("unsafe playbook %q was stored in SQLite", name)
		}
	}

	// Defense in depth: even if an unsafe playbook was already in SQLite,
	// running it is refused before Ansible is invoked.
	if err := store.SavePlaybook(a.db, "legacy_bad", unsafe["local_action"], time.Now()); err != nil {
		t.Fatal(err)
	}
	rec := a.do("POST", "/api/playbooks/legacy_bad/run", admin, map[string]any{"mode": "apply"})
	want(t, rec, http.StatusBadRequest)
}

func TestCustomPlaybookRejectsNonZeroSerial(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	now := time.Now()
	h, err := store.CreateHost(a.db, store.Host{Name: "web-1", Address: "10.0.0.1", Port: 22, User: "root"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SavePlaybook(a.db, "tune", tunePlaybook, now); err != nil {
		t.Fatal(err)
	}

	// Non-zero serial is refused truthfully instead of being silently ignored.
	rec := a.do("POST", "/api/playbooks/tune/run", admin, map[string]any{"mode": "apply", "host_id": h.ID, "serial": 1})
	want(t, rec, http.StatusBadRequest)
	if !strings.Contains(rec.Body.String(), "serial") {
		t.Errorf("expected explanation mentioning serial: %s", rec.Body.String())
	}

	// Plan with serial 0 succeeds and reports serial: 0.
	rec = a.do("POST", "/api/playbooks/tune/run", admin, map[string]any{"mode": "plan", "host_id": h.ID})
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"serial":0`) {
		t.Errorf("plan: %s", rec.Body.String())
	}
}

func TestSecretUsageDoesNotCollideOnSubstring(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	now := time.Now()
	if err := store.SetSecret(a.db, "db", "$ANSIBLE_VAULT;1.1;AES256\n31", now); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSecret(a.db, "db_pass", "$ANSIBLE_VAULT;1.1;AES256\n32", now); err != nil {
		t.Fatal(err)
	}
	pb := "- hosts: all\n  tasks:\n    - ansible.builtin.debug:\n        msg: \"{{ secret_db_pass }}\"\n"
	if err := store.SavePlaybook(a.db, "app", pb, now); err != nil {
		t.Fatal(err)
	}

	// secret_db_pass is used by the playbook; secret_db is NOT.
	want(t, a.do("POST", "/api/secrets/db_pass/delete", admin, nil), http.StatusConflict)
	want(t, a.do("POST", "/api/secrets/db/delete", admin, nil), http.StatusNoContent)
}
