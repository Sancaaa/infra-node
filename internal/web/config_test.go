package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"infra-manager/internal/remote/remotetest"
	"infra-manager/internal/store"
)

func timeNowForTest() time.Time { return time.Now() }

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// A stand-in for ansible-playbook. It reads what the dashboard generated, as the
// real one would: --limit names the hosts, the playbook says whether the run is
// rolling (serial, max_fail_percentage), and each host's host_vars file says what
// it has (im_roles for the profiles; im_access and im_access_remove for the
// access playbook, which the stand-in carries out by editing a file for each host
// under .access/, as authorized_key would edit authorized_keys).
//
// It prints the lines of a real run in the default format. A task is "changed"
// the first time it runs on a host and "ok" after (a marker file remembers),
// except the docker role, which is never idempotent; a dry run (--check) prints a
// diff and remembers nothing. A host whose name starts with "bad" fails (the
// nginx role, an update, a custom playbook), and one that starts with "down"
// cannot be reached. With serial, the hosts go in batches and the run stops after
// the batch where a host failed: the hosts after it are not in the recap, as with
// the real one. --syntax-check fails for a playbook that says BROKEN.
const playbookStub = `#!/bin/sh
dir=$(dirname "$ANSIBLE_CONFIG")
echo "args: $*" >> "$dir/.stub.log"
playbook="$1"
limit=""; check=""; tags=""; syntax=""
while [ $# -gt 0 ]; do
  case "$1" in
    --limit) limit="$2"; shift ;;
    --tags) tags="$2"; shift ;;
    --check) check=1 ;;
    --syntax-check) syntax=1 ;;
  esac
  shift
done
cd "$dir" || exit 4
if [ -n "$syntax" ]; then
  if grep -q BROKEN "$playbook"; then echo "ERROR! We were unable to read $playbook as YAML: line 2" >&2; exit 4; fi
  echo "playbook: $playbook"; exit 0
fi
status="$dir/.stub.status"
: > "$status"
dead() { grep -q "^$1 failed" "$status" || grep -q "^$1 unreachable" "$status"; }
down() { printf 'fatal: [%s]: UNREACHABLE! => {"changed": false, "msg": "Failed to connect to the host via ssh: Permission denied (publickey).", "unreachable": true}\n' "$1"; echo "$1 unreachable" >> "$status"; }
ok() { echo "ok: [$1]"; echo "$1 ok" >> "$status"; }
changed() {
  if [ -n "$check" ]; then printf -- '--- before\n+++ after\n@@ -0,0 +1 @@\n+written by the stub for %s on %s\n\n' "$2" "$1"; fi
  echo "changed: [$1]"; echo "$1 changed" >> "$status"
}
failed() { printf 'fatal: [%s]: FAILED! => {"changed": false, "msg": "%s"}\n' "$1" "$2"; echo "$1 failed" >> "$status"; }

site_batch() {
  echo "PLAY [Configure the hosts that have a profile] ******"
  echo
  echo "TASK [Gathering Facts] ******"
  for h in $1; do case "$h" in down*) down "$h" ;; *) ok "$h" ;; esac; done
  for role in base users ssh_hardening firewall nginx docker node_exporter; do
    if [ -n "$tags" ] && [ "$tags" != "$role" ]; then continue; fi
    echo
    echo "TASK [$role : Apply the $role role] ******"
    for h in $1; do
      if dead "$h"; then continue; fi
      roles=$(sed -n 's/^im_roles: \[\(.*\)\]$/\1/p' "host_vars/$h.yml" 2>/dev/null | sed 's/"//g; s/,/ /g')
      case " $roles " in *" $role "*) ;; *) continue ;; esac
      marker=".applied-$h-$role"
      if [ "$h" != "${h#bad}" ] && [ "$role" = nginx ]; then
        failed "$h" "No package matching 'nginx' is available"
      elif [ "$role" = docker ] || [ ! -e "$marker" ]; then
        if [ -z "$check" ]; then : > "$marker"; fi
        changed "$h" "$role"
      else
        ok "$h"
      fi
    done
  done
}

patch_batch() {
  echo "PLAY [Update the packages] ******"
  echo
  echo "TASK [Refresh the package list] ******"
  for h in $1; do case "$h" in down*) down "$h" ;; *) ok "$h" ;; esac; done
  echo
  echo "TASK [Install the pending package upgrades] ******"
  for h in $1; do
    if dead "$h"; then continue; fi
    marker=".patched-$h"
    if [ "$h" != "${h#bad}" ]; then
      failed "$h" "E: Unable to correct problems, you have held broken packages."
    elif [ ! -e "$marker" ]; then
      if [ -z "$check" ]; then : > "$marker"; fi
      changed "$h" "the packages"
    else
      ok "$h"
    fi
  done
}

# keys_of prints the keys of one list in a host's host_vars, one a line.
keys_of() { sed -n "s/^$2: //p" "host_vars/$1.yml" 2>/dev/null | grep -o 'key: "[^"]*"' | sed 's/^key: "//; s/"$//'; }

access_batch() {
  echo "PLAY [Give and take away SSH access] ******"
  echo
  echo "TASK [Take away the SSH key of {{ item.name }}] ******"
  mkdir -p .access
  for h in $1; do
    case "$h" in down*) down "$h"; continue ;; esac
    file=".access/$h"; touch "$file"
    keys_of "$h" im_access_remove > .stub.keys
    gone=""
    while IFS= read -r k; do
      if grep -qxF "$k" "$file"; then
        gone=1
        if [ -z "$check" ]; then grep -vxF "$k" "$file" > "$file.new"; mv "$file.new" "$file"; fi
      fi
    done < .stub.keys
    if [ -n "$gone" ]; then changed "$h" "access"; else ok "$h"; fi
  done
  echo
  echo "TASK [Give the SSH key of {{ item.name }}] ******"
  for h in $1; do
    if dead "$h"; then continue; fi
    file=".access/$h"
    keys_of "$h" im_access > .stub.keys
    added=""
    while IFS= read -r k; do
      if ! grep -qxF "$k" "$file"; then
        added=1
        if [ -z "$check" ]; then echo "$k" >> "$file"; fi
      fi
    done < .stub.keys
    if [ -n "$added" ]; then changed "$h" "access"; else ok "$h"; fi
  done
}

custom_batch() {
  echo "PLAY [A custom playbook] ******"
  echo
  echo "TASK [Do the custom thing] ******"
  for h in $1; do
    case "$h" in down*) down "$h"; continue ;; esac
    marker=".custom-$(basename "$playbook" .yml)-$h"
    if [ "$h" != "${h#bad}" ]; then
      failed "$h" "the custom task failed"
    elif [ ! -e "$marker" ]; then
      if [ -z "$check" ]; then : > "$marker"; fi
      changed "$h" "the custom playbook"
    else
      ok "$h"
    fi
  done
}

case "$playbook" in
  site.yml) fn=site_batch ;;
  patch.yml) fn=patch_batch ;;
  access.yml) fn=access_batch ;;
  custom/*) fn=custom_batch ;;
  *) echo "ERROR! the playbook $playbook could not be found" >&2; exit 1 ;;
esac
serial=$(sed -n 's/^  serial: \([0-9][0-9]*\)$/\1/p' "$playbook" | head -1)
stop=""
if grep -q '^  max_fail_percentage: 0$' "$playbook"; then stop=1; fi

set -- $(echo "$limit" | tr ',' ' ')
while [ $# -gt 0 ]; do
  batch=""; n=0
  while [ $# -gt 0 ] && { [ -z "$serial" ] || [ "$n" -lt "$serial" ]; }; do
    batch="$batch $1"; shift; n=$((n+1))
  done
  $fn "$batch"
  if [ -n "$stop" ] && grep -qE " (failed|unreachable)$" "$status"; then break; fi
  echo
done
echo
echo "PLAY RECAP ******"
awk '{ seen[$1] = 1; if ($2 == "ok" || $2 == "changed") ok[$1]++; if ($2 == "changed") ch[$1]++; if ($2 == "failed") fa[$1]++; if ($2 == "unreachable") un[$1]++ } END { for (h in seen) printf "%s : ok=%d changed=%d unreachable=%d failed=%d skipped=0 rescued=0 ignored=0\n", h, ok[h], ch[h], un[h], fa[h] }' "$status"
if grep -q " failed$" "$status" || grep -q " unreachable$" "$status"; then exit 2; fi
exit 0
`

func (a *testApp) withPlaybook() {
	a.t.Helper()
	a.withAnsible()
	a.installStub("ansible-playbook", playbookStub)
}

type roleBody = map[string]any

func role(name string, params map[string]any) roleBody {
	if params == nil {
		params = map[string]any{}
	}
	return roleBody{"role": name, "params": params}
}

func (a *testApp) setGroupProfile(admin *http.Cookie, group string, roles ...roleBody) *httptest.ResponseRecorder {
	return a.do("POST", "/api/groups/"+group+"/profile", admin, map[string]any{"roles": roles})
}

// configOf is the state of every host, by name.
func (a *testApp) configOf(c *http.Cookie) map[string]configView {
	a.t.Helper()
	rec := a.do("GET", "/api/hosts", c, nil)
	want(a.t, rec, http.StatusOK)
	var out struct {
		Hosts []struct {
			Name   string      `json:"name"`
			Config *configView `json:"config"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		a.t.Fatal(err)
	}
	states := map[string]configView{}
	for _, h := range out.Hosts {
		if h.Config != nil {
			states[h.Name] = *h.Config
		}
	}
	return states
}

type sseEvent struct{ name, data string }

// events reads a Server-Sent Events answer: plain lines of output, one "result",
// then "done" or "error".
func events(body string) []sseEvent {
	var out []sseEvent
	for _, frame := range strings.Split(body, "\n\n") {
		if strings.TrimSpace(frame) == "" {
			continue
		}
		ev := sseEvent{name: "message"}
		var data []string
		for _, line := range strings.Split(frame, "\n") {
			if rest, ok := strings.CutPrefix(line, "event: "); ok {
				ev.name = rest
			} else if rest, ok := strings.CutPrefix(line, "data: "); ok {
				data = append(data, rest)
			}
		}
		ev.data = strings.Join(data, "\n")
		out = append(out, ev)
	}
	return out
}

func resultOf(t *testing.T, rec *httptest.ResponseRecorder) (answer struct {
	Hosts []struct {
		Name    string   `json:"name"`
		OK      bool     `json:"ok"`
		Changed []string `json:"changed"`
		Failure string   `json:"failure"`
	} `json:"hosts"`
	Idempotent   *bool    `json:"idempotent"`
	ChangedAgain []string `json:"changed_again"`
}, final string) {
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

func TestProfilesAreCheckedAndOnlyTheRolesAreWrittenInHistory(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)
	_, viewer := a.user("vera", store.RoleViewer)
	group, _ := a.webGroup(admin)
	path := "/api/groups/" + group + "/profile"

	// Anybody who can look can see what the library has; the settings are an operator's to read.
	rec := a.do("GET", "/api/library", viewer, nil)
	want(t, rec, http.StatusOK)
	for _, name := range []string{`"name":"base"`, `"name":"nginx"`, `"name":"ssh_hardening"`, `"key":"nginx_domain"`} {
		if !strings.Contains(rec.Body.String(), name) {
			t.Errorf("the library has no %s", name)
		}
	}

	const domain = "app.private-example.com"
	want(t, a.setGroupProfile(admin, group, role("nginx", map[string]any{"nginx_domain": domain}), role("base", nil)), http.StatusNoContent)
	rec = a.do("GET", path, operator, nil)
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), domain) {
		t.Errorf("profile: %s", rec.Body.String())
	}
	// History says which roles, never their settings.
	if !a.has("group.profile", store.ResultOK) || !strings.Contains(a.eventsText(), "nginx, base") || strings.Contains(a.eventsText(), domain) {
		t.Errorf("History:\n%s", a.eventsText())
	}

	for name, roles := range map[string][]roleBody{
		"unknown role":      {role("kubernetes", nil)},
		"root as the user":  {role("users", map[string]any{"users_name": "root"})},
		"directive in name": {role("nginx", map[string]any{"nginx_domain": "a.example.com; return 301 http://evil"})},
		"unknown setting":   {role("base", map[string]any{"colour": "red"})},
		"twice":             {role("base", nil), role("base", nil)},
		"wrong type":        {role("base", map[string]any{"base_upgrade": "yes"})},
	} {
		if rec := a.setGroupProfile(admin, group, roles...); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d (%s)", name, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
	}
	// A refused profile changes nothing.
	if got, _ := store.GetProfile(a.db, store.ScopeGroup, mustID(t, group)); len(got) != 2 {
		t.Errorf("a refused change was applied: %+v", got)
	}
}

func TestAHostsProfileIsItsGroupsPlusItsOwn(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)
	group, hosts := a.webGroup(admin)
	want(t, a.setGroupProfile(admin, group, role("base", nil)), http.StatusNoContent)
	want(t, a.do("POST", "/api/hosts/"+hosts[0]+"/profile", admin, map[string]any{"roles": []roleBody{role("docker", nil)}}), http.StatusNoContent)

	rec := a.do("GET", "/api/hosts/"+hosts[0]+"/profile", operator, nil)
	want(t, rec, http.StatusOK)
	var out struct {
		Roles     []struct{ Role string } `json:"roles"`
		Inherited []struct {
			Group string   `json:"group"`
			Roles []string `json:"roles"`
		} `json:"inherited"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Roles) != 1 || out.Roles[0].Role != "docker" || len(out.Inherited) != 1 || out.Inherited[0].Group != "web" || out.Inherited[0].Roles[0] != "base" {
		t.Errorf("profile: %s", rec.Body.String())
	}

	states := a.configOf(operator)
	if got := states["web-1"].Roles; len(got) != 2 || got[0] != "base" || got[1] != "docker" {
		t.Errorf("web-1 gets %v (its group's roles and its own, in the order of the library)", got)
	}
	if got := states["web-2"].Roles; len(got) != 1 || got[0] != "base" {
		t.Errorf("web-2 gets %v", got)
	}
}

func TestViewCodeShowsThePlanOfEachHost(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	group, _ := a.webGroup(admin)
	want(t, a.setGroupProfile(admin, group, role("base", nil), role("nginx", map[string]any{"nginx_domain": "app.example.com"})), http.StatusNoContent)

	rec := a.do("GET", "/api/code", admin, nil)
	want(t, rec, http.StatusOK)
	var out struct {
		Files []struct{ Path, Content string } `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, f := range out.Files {
		files[f.Path] = f.Content
	}
	vars := files["host_vars/web-1.yml"]
	if !strings.Contains(vars, `im_roles: ["base", "nginx"]`) || !strings.Contains(vars, `nginx_domain: "app.example.com"`) || !strings.Contains(vars, "nginx_mode: \"static\"") {
		t.Errorf("host_vars/web-1.yml:\n%s", vars)
	}
	for _, p := range []string{"site.yml", "group_vars/all.yml", "roles/nginx/tasks/main.yml", "roles/base/tasks/main.yml", "roles/firewall/vars/main.yml"} {
		if files[p] == "" {
			t.Errorf("%s is not in View code", p)
		}
	}
}

// "Configuration state per host: applied, failed, never applied, changes waiting."
func TestTheConfigurationStateOfAHostFollowsWhatWasApplied(t *testing.T) {
	a := newTestApp(t)
	a.withPlaybook()
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)
	group, _ := a.webGroup(admin)
	apply := func(body map[string]any) *httptest.ResponseRecorder {
		return a.do("POST", "/api/configure", operator, body)
	}
	gid := mustID(t, group)

	if st := a.configOf(operator)["web-1"].State; st != configNone {
		t.Errorf("no profile: %s", st)
	}
	want(t, a.setGroupProfile(admin, group, role("base", nil), role("nginx", nil)), http.StatusNoContent)
	if st := a.configOf(operator)["web-1"].State; st != configNever {
		t.Errorf("a profile that was never applied: %s", st)
	}

	// A dry run changes no state.
	want(t, apply(map[string]any{"mode": "preview", "group_id": gid}), http.StatusOK)
	if st := a.configOf(operator)["web-1"].State; st != configNever {
		t.Errorf("after a preview: %s", st)
	}

	want(t, apply(map[string]any{"mode": "apply", "group_id": gid}), http.StatusOK)
	if st := a.configOf(operator); st["web-1"].State != configApplied || st["web-2"].State != configApplied {
		t.Errorf("after an apply: %+v", st)
	}
	if o := a.overview(operator); o.ConfigFailed != 0 || o.ConfigWaiting != 0 {
		t.Errorf("overview after an apply: %+v", o)
	}

	// The profile changes: changes are waiting, on the Hosts page and on the Overview.
	want(t, a.setGroupProfile(admin, group, role("base", nil), role("nginx", map[string]any{"nginx_domain": "new.example.com"})), http.StatusNoContent)
	if st := a.configOf(operator); st["web-1"].State != configWaiting || st["web-2"].State != configWaiting {
		t.Errorf("after the profile changed: %+v", st)
	}
	if o := a.overview(operator); o.ConfigWaiting != 2 || !strings.Contains(strings.Join(o.Attention[0].Issues, " "), "profile changes waiting") {
		t.Errorf("overview: %+v", o)
	}
	want(t, apply(map[string]any{"mode": "apply", "group_id": gid}), http.StatusOK)
	if st := a.configOf(operator)["web-1"].State; st != configApplied {
		t.Errorf("after applying again: %s", st)
	}

	// One role alone does not make the whole host applied.
	want(t, a.setGroupProfile(admin, group, role("base", nil), role("nginx", map[string]any{"nginx_domain": "third.example.com"})), http.StatusNoContent)
	want(t, apply(map[string]any{"mode": "apply", "group_id": gid, "role": "base"}), http.StatusOK)
	if st := a.configOf(operator)["web-1"].State; st != configWaiting {
		t.Errorf("after applying base only: %s (nginx is still waiting)", st)
	}
	if log := a.stubLog(); !strings.Contains(log, "--tags base") {
		t.Errorf("the role was not run alone:\n%s", log)
	}
}

func TestPlanSaysWhoGetsWhatAndWhoIsLeftOut(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)
	group, hosts := a.webGroup(admin)
	want(t, a.setGroupProfile(admin, group, role("base", nil), role("nginx", nil)), http.StatusNoContent)

	// A third host: in the group, but it has no sudo; a fourth has no group at all.
	s := remotetest.Start(t, t.TempDir(), remotetest.Options{})
	nosudo := a.addHost(admin, s, "nosudo-1")
	want(t, a.do("POST", "/api/groups/"+group+"/hosts", admin, map[string]any{"add": []int64{mustID(t, nosudo)}}), http.StatusNoContent)
	if err := store.SetHostFacts(a.db, mustID(t, nosudo), "{}", false, timeNowForTest()); err != nil {
		t.Fatal(err)
	}
	_ = hosts

	rec := a.do("POST", "/api/configure", operator, map[string]any{"mode": "plan", "group_id": mustID(t, group)})
	want(t, rec, http.StatusOK)
	var plan struct {
		Hosts []struct {
			Name  string   `json:"name"`
			Roles []string `json:"roles"`
		} `json:"hosts"`
		Skipped []struct{ Host, Reason string } `json:"skipped"`
		Commands []struct{ Command string }     `json:"commands"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Hosts) != 2 || plan.Hosts[0].Name != "web-1" || strings.Join(plan.Hosts[0].Roles, " ") != "base nginx" {
		t.Errorf("hosts: %+v", plan.Hosts)
	}
	if len(plan.Skipped) != 1 || plan.Skipped[0].Host != "nosudo-1" || !strings.Contains(plan.Skipped[0].Reason, "no sudo") {
		t.Errorf("skipped: %+v", plan.Skipped)
	}
	// The dry run first, then the real one: what a confirm dialog shows under "Will run".
	if len(plan.Commands) != 2 || plan.Commands[0].Command != "ansible-playbook site.yml --limit web-1,web-2 --check --diff" ||
		plan.Commands[1].Command != "ansible-playbook site.yml --limit web-1,web-2" {
		t.Errorf("commands: %+v", plan.Commands)
	}

	// One role, and a host that does not have it.
	rec = a.do("POST", "/api/configure", operator, map[string]any{"mode": "plan", "group_id": mustID(t, group), "role": "docker"})
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), "does not have the role docker") {
		t.Errorf("plan for a role nobody has: %s", rec.Body.String())
	}

	// Exactly one target; it must exist; the mode must be known.
	want(t, a.do("POST", "/api/configure", operator, map[string]any{"mode": "plan"}), http.StatusBadRequest)
	want(t, a.do("POST", "/api/configure", operator, map[string]any{"mode": "plan", "group_id": 999}), http.StatusNotFound)
	want(t, a.do("POST", "/api/configure", operator, map[string]any{"mode": "launch", "group_id": mustID(t, group)}), http.StatusBadRequest)
	want(t, a.do("POST", "/api/configure", operator, map[string]any{"mode": "plan", "group_id": mustID(t, group), "role": "kubernetes"}), http.StatusBadRequest)
}

func TestPreviewSaysInPlainWordsWhatWouldChange(t *testing.T) {
	a := newTestApp(t)
	a.withPlaybook()
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)
	group, _ := a.webGroup(admin)
	want(t, a.setGroupProfile(admin, group, role("base", nil), role("nginx", nil)), http.StatusNoContent)

	rec := a.do("POST", "/api/configure", operator, map[string]any{"mode": "preview", "group_id": mustID(t, group)})
	want(t, rec, http.StatusOK)
	var out struct {
		Hosts []struct {
			Name    string   `json:"name"`
			Roles   []string `json:"roles"`
			Changes []struct {
				Role  string `json:"role"`
				Title string `json:"title"`
				Diff  string `json:"diff"`
			} `json:"changes"`
		} `json:"hosts"`
		Commands []struct{ Command string } `json:"commands"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Hosts) != 2 || len(out.Hosts[0].Changes) != 2 {
		t.Fatalf("preview: %s", rec.Body.String())
	}
	c := out.Hosts[0].Changes[1]
	if c.Role != "nginx" || c.Title != "Apply the nginx role" || !strings.Contains(c.Diff, "+written by the stub for nginx on web-1") {
		t.Errorf("a change: %+v", c)
	}
	if out.Commands[0].Command != "ansible-playbook site.yml --limit web-1,web-2 --check --diff" {
		t.Errorf("command: %+v", out.Commands)
	}
	// The files it ran on are what View code shows.
	if log := a.stubLog(); !strings.Contains(log, "args: site.yml --limit web-1,web-2 --check --diff\n") {
		t.Errorf("what ansible-playbook was called with:\n%s", log)
	}
	// Nothing was changed, so a dry run leaves no mark: the same preview shows the same.
	rec = a.do("POST", "/api/configure", operator, map[string]any{"mode": "preview", "group_id": mustID(t, group)})
	if !strings.Contains(rec.Body.String(), "Apply the nginx role") {
		t.Errorf("a second preview: %s", rec.Body.String())
	}
	if a.has("config.apply", store.ResultOK) {
		t.Error("a preview is in History as an apply")
	}
}

func TestApplyStreamsALogRecordsTheRunAndChecksAgain(t *testing.T) {
	a := newTestApp(t)
	a.withPlaybook()
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)
	group, _ := a.webGroup(admin)
	want(t, a.setGroupProfile(admin, group, role("base", nil), role("nginx", nil)), http.StatusNoContent)
	gid := mustID(t, group)

	rec := a.do("POST", "/api/configure", operator, map[string]any{"mode": "apply", "group_id": gid})
	want(t, rec, http.StatusOK)
	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("content type %q", ct)
	}
	evs := events(rec.Body.String())
	// The first line of the log is the command, as a person would type it.
	if len(evs) < 5 || evs[0].data != "$ ansible-playbook site.yml --limit web-1,web-2" {
		t.Fatalf("the log starts with %+v", evs[:min(len(evs), 3)])
	}
	if !strings.Contains(rec.Body.String(), "data: TASK [nginx : Apply the nginx role]") || !strings.Contains(rec.Body.String(), "data: PLAY RECAP") {
		t.Errorf("the live log:\n%s", rec.Body.String())
	}
	answer, final := resultOf(t, rec)
	if final != "done: ok" || len(answer.Hosts) != 2 {
		t.Fatalf("end of the stream: %q %+v", final, answer)
	}
	for _, h := range answer.Hosts {
		if !h.OK || len(h.Changed) != 2 || h.Changed[0] != "Apply the base role" {
			t.Errorf("host: %+v", h)
		}
	}
	if !strings.Contains(a.eventsText(), "config.apply | group web | ok | 2 hosts, 0 failed, 4 changes; roles: base, nginx") {
		t.Errorf("History:\n%s", a.eventsText())
	}
	if st := a.configOf(operator)["web-2"]; st.State != configApplied || st.RunAt == 0 {
		t.Errorf("state after the run: %+v", st)
	}

	// Check again: a second run, and the verdict.
	rec = a.do("POST", "/api/configure", operator, map[string]any{"mode": "check_again", "group_id": gid})
	want(t, rec, http.StatusOK)
	answer, final = resultOf(t, rec)
	if final != "done: ok" || answer.Idempotent == nil || !*answer.Idempotent || len(answer.ChangedAgain) != 0 {
		t.Errorf("a second run changed something: %q %+v", final, answer)
	}
	if st := a.configOf(operator)["web-1"]; st.Idempotent == nil || !*st.Idempotent || st.State != configApplied {
		t.Errorf("verdict on the host: %+v", st)
	}

	// A role that is not idempotent is named.
	want(t, a.setGroupProfile(admin, group, role("base", nil), role("docker", nil)), http.StatusNoContent)
	want(t, a.do("POST", "/api/configure", operator, map[string]any{"mode": "apply", "group_id": gid}), http.StatusOK)
	rec = a.do("POST", "/api/configure", operator, map[string]any{"mode": "check_again", "group_id": gid})
	answer, _ = resultOf(t, rec)
	if answer.Idempotent == nil || *answer.Idempotent || len(answer.ChangedAgain) == 0 || answer.ChangedAgain[0] != "Apply the docker role" {
		t.Errorf("the task that changed again: %+v", answer)
	}
	if st := a.configOf(operator)["web-1"]; st.Idempotent == nil || *st.Idempotent {
		t.Errorf("verdict on the host: %+v", st)
	}
}

func TestAFailedHostAndAnUnreachableOneAreSaidInSentences(t *testing.T) {
	a := newTestApp(t)
	a.withPlaybook()
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)
	group, _ := a.webGroup(admin)
	for _, name := range []string{"bad-1", "down-1"} {
		s := remotetest.Start(t, t.TempDir(), remotetest.Options{})
		id := a.addHost(admin, s, name)
		want(t, a.do("POST", "/api/groups/"+group+"/hosts", admin, map[string]any{"add": []int64{mustID(t, id)}}), http.StatusNoContent)
	}
	want(t, a.setGroupProfile(admin, group, role("nginx", nil)), http.StatusNoContent)

	rec := a.do("POST", "/api/configure", operator, map[string]any{"mode": "apply", "group_id": mustID(t, group)})
	want(t, rec, http.StatusOK)
	answer, final := resultOf(t, rec)
	if final != "done: ok" {
		t.Errorf("the stream ended with %q", final)
	}
	by := map[string]string{}
	ok := map[string]bool{}
	for _, h := range answer.Hosts {
		by[h.Name], ok[h.Name] = h.Failure, h.OK
	}
	if !ok["web-1"] || !ok["web-2"] {
		t.Errorf("good hosts failed: %+v", answer.Hosts)
	}
	if ok["bad-1"] || !strings.Contains(by["bad-1"], "Apply the nginx role") || !strings.Contains(by["bad-1"], "does not exist") {
		t.Errorf("bad-1: %q", by["bad-1"])
	}
	if ok["down-1"] || !strings.Contains(by["down-1"], "could not be reached") || !strings.Contains(by["down-1"], "refused the SSH key") {
		t.Errorf("down-1: %q", by["down-1"])
	}

	states := a.configOf(operator)
	if states["bad-1"].State != configFailed || !strings.Contains(states["bad-1"].Detail, "does not exist") || states["down-1"].State != configFailed || states["web-1"].State != configApplied {
		t.Errorf("states: %+v", states)
	}
	o := a.overview(operator)
	if o.ConfigFailed != 2 {
		t.Errorf("overview: %+v", o)
	}
	if !a.has("config.apply", store.ResultFailed) {
		t.Error("a run with failures is not a failure in History")
	}
}

// "ssh hardening on a host still leaves the dashboard able to log in."
func TestSSHHardeningIsNeverAppliedWhereItCouldLockTheDashboardOut(t *testing.T) {
	a := newTestApp(t)
	a.withPlaybook()
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)

	// A host the dashboard logs in to as root: turning off root login is refused,
	// at once, without logging in to anything.
	rootHost, err := store.CreateHost(a.db, store.Host{Name: "rooty", Address: "10.9.9.9", Port: 22, User: "root", Status: "online"}, timeNowForTest())
	if err != nil {
		t.Fatal(err)
	}
	want(t, a.do("POST", "/api/hosts/"+itoa(rootHost.ID)+"/profile", admin, map[string]any{"roles": []roleBody{role("ssh_hardening", nil)}}), http.StatusNoContent)

	rec := a.do("POST", "/api/configure", operator, map[string]any{"mode": "plan", "host_id": rootHost.ID})
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), "SSH hardening was left out") || !strings.Contains(rec.Body.String(), "logs in to this host as root") || !strings.Contains(rec.Body.String(), "nothing is left to apply") {
		t.Errorf("plan for a root host: %s", rec.Body.String())
	}
	want(t, a.do("POST", "/api/configure", operator, map[string]any{"mode": "apply", "host_id": rootHost.ID}), http.StatusConflict)

	// Only password login off: nothing locks out a host that uses a key, even as root.
	want(t, a.do("POST", "/api/hosts/"+itoa(rootHost.ID)+"/profile", admin, map[string]any{"roles": []roleBody{role("ssh_hardening", map[string]any{"ssh_disable_root": false})}}), http.StatusNoContent)
	rec = a.do("POST", "/api/configure", operator, map[string]any{"mode": "plan", "host_id": rootHost.ID})
	if strings.Contains(rec.Body.String(), "left out") || !strings.Contains(rec.Body.String(), `"roles":["ssh_hardening"]`) {
		t.Errorf("plan with only password login off: %s", rec.Body.String())
	}

	// A host whose key login works gets it; one whose key login fails does not.
	home := t.TempDir()
	s := remotetest.Start(t, home, remotetest.Options{})
	id := a.addHost(admin, s, "web-1")
	want(t, a.do("POST", "/api/hosts/"+id+"/profile", admin, map[string]any{"roles": []roleBody{role("base", nil), role("ssh_hardening", nil)}}), http.StatusNoContent)

	rec = a.do("POST", "/api/configure", operator, map[string]any{"mode": "apply", "host_id": mustID(t, id)})
	want(t, rec, http.StatusOK)
	answer, _ := resultOf(t, rec)
	if len(answer.Hosts) != 1 || !answer.Hosts[0].OK || len(answer.Hosts[0].Changed) != 2 {
		t.Errorf("with a working key: %+v", answer)
	}
	if st := a.configOf(operator)["web-1"].State; st != configApplied {
		t.Errorf("state: %s", st)
	}

	// The dashboard's key is taken off the host: the key login fails right now.
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	want(t, a.setHostProfileRole(admin, id, role("base", map[string]any{"base_timezone": "Asia/Makassar"}), role("ssh_hardening", nil)), http.StatusNoContent)
	rec = a.do("POST", "/api/configure", operator, map[string]any{"mode": "apply", "host_id": mustID(t, id)})
	want(t, rec, http.StatusOK)
	answer, _ = resultOf(t, rec)
	if len(answer.Hosts) != 1 || !strings.Contains(rec.Body.String(), "SSH hardening was left out") || !strings.Contains(rec.Body.String(), "could not log in with its key") {
		t.Errorf("with a lost key: %s", rec.Body.String())
	}
	// base still ran; ssh_hardening was not given to the host.
	if vars, _ := os.ReadFile(filepath.Join(a.s.ansible.Dir, "host_vars", "web-1.yml")); strings.Contains(string(vars), "ssh_hardening") {
		t.Errorf("the host was given ssh_hardening although its key login failed:\n%s", vars)
	}
}

func (a *testApp) setHostProfileRole(admin *http.Cookie, host string, roles ...roleBody) *httptest.ResponseRecorder {
	return a.do("POST", "/api/hosts/"+host+"/profile", admin, map[string]any{"roles": roles})
}

func TestConfiguringNeedsAnsibleButEverythingElseDoesNot(t *testing.T) {
	a := newTestApp(t)
	a.s.ansible.Bin = "ansible-that-is-not-installed"
	_, admin := a.user("ada", store.RoleAdmin)
	group, _ := a.webGroup(admin)
	want(t, a.setGroupProfile(admin, group, role("base", nil)), http.StatusNoContent)
	gid := mustID(t, group)

	rec := a.do("POST", "/api/configure", admin, map[string]any{"mode": "preview", "group_id": gid})
	want(t, rec, http.StatusServiceUnavailable)
	if !strings.Contains(rec.Body.String(), "apt install -y ansible") {
		t.Errorf("preview: %s", rec.Body.String())
	}
	want(t, a.do("POST", "/api/configure", admin, map[string]any{"mode": "apply", "group_id": gid}), http.StatusServiceUnavailable)
	// Looking at the plan, and at the files, does not need it.
	want(t, a.do("POST", "/api/configure", admin, map[string]any{"mode": "plan", "group_id": gid}), http.StatusOK)
	want(t, a.do("GET", "/api/code", admin, nil), http.StatusOK)
}

func TestOnlyOneConfigurationRunAtATime(t *testing.T) {
	a := newTestApp(t)
	a.withPlaybook()
	_, admin := a.user("ada", store.RoleAdmin)
	group, _ := a.webGroup(admin)
	want(t, a.setGroupProfile(admin, group, role("base", nil)), http.StatusNoContent)
	gid := mustID(t, group)

	a.s.ansibleMu.Lock()
	rec := a.do("POST", "/api/configure", admin, map[string]any{"mode": "apply", "group_id": gid})
	a.s.ansibleMu.Unlock()
	want(t, rec, http.StatusConflict)
	want(t, a.do("POST", "/api/configure", admin, map[string]any{"mode": "apply", "group_id": gid}), http.StatusOK)
}

func TestNothingToConfigureIsSaidWithTheReasons(t *testing.T) {
	a := newTestApp(t)
	a.withPlaybook()
	_, admin := a.user("ada", store.RoleAdmin)
	group, _ := a.webGroup(admin) // a group with hosts but no profile

	rec := a.do("POST", "/api/configure", admin, map[string]any{"mode": "preview", "group_id": mustID(t, group)})
	want(t, rec, http.StatusConflict)
	if !strings.Contains(rec.Body.String(), "nothing to configure") || !strings.Contains(rec.Body.String(), "no profile") {
		t.Errorf("answer: %s", rec.Body.String())
	}
}
