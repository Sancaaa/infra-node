package web

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"infra-manager/internal/remote"
	"infra-manager/internal/remote/remotetest"
	"infra-manager/internal/store"
)

// A systemctl that records what it was asked and answers like the real one: one
// failed unit, two services, and "active" after a restart.
const systemctlStub = `#!/bin/sh
echo "systemctl $*" >> "$HOME/calls.log"
case "$1" in
  --failed) echo "broken.service loaded failed failed Something that broke" ;;
  list-units)
    echo "nginx.service loaded active running A web server"
    echo "cron.service loaded active running Regular jobs" ;;
  is-active) echo active ;;
esac
exit 0
`

const journalctlStub = `#!/bin/sh
echo "journalctl $*" >> "$HOME/calls.log"
echo "Nov 22 10:00:02 web-1 nginx[700]: ready"
`

// cutStub makes the host's uptime what a test says: the health script reads it
// with cut.
func cutStub(seconds string) string { return "#!/bin/sh\necho " + seconds + "\n" }

// addHost adds a host (a test SSH server) through the API and returns its id.
func (a *testApp) addHost(admin *http.Cookie, s *remotetest.Server, name string) string {
	a.t.Helper()
	rec := a.do("POST", "/api/hosts", admin, addBody(s, name))
	want(a.t, rec, http.StatusCreated)
	return hostID(a.t, rec)
}

func (a *testApp) host(id string) store.Host {
	a.t.Helper()
	h, err := store.GetHost(a.db, mustID(a.t, id))
	if err != nil {
		a.t.Fatal(err)
	}
	return h
}

func (a *testApp) overview(c *http.Cookie) overviewAnswer {
	a.t.Helper()
	rec := a.do("GET", "/api/overview", c, nil)
	want(a.t, rec, http.StatusOK)
	var o overviewAnswer
	if err := json.Unmarshal(rec.Body.Bytes(), &o); err != nil {
		a.t.Fatal(err)
	}
	return o
}

func callsOf(s *remotetest.Server) []string {
	data, _ := os.ReadFile(filepath.Join(s.Home, "calls.log"))
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func TestMonitorRecordsHealthAndNoticesAHostGoingOffline(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	home := t.TempDir()
	hostKey := remotetest.NewHostKey(t) // the same machine, switched off and on again
	s := remotetest.Start(t, home, remotetest.Options{HostKey: hostKey, Stubs: map[string]string{"systemctl": systemctlStub}})
	id := a.addHost(admin, s, "web-1")

	a.s.monitorRound()
	h := a.host(id)
	if h.Status != "online" || h.LastSeen == 0 || !strings.Contains(h.HealthJSON, `"failed":["broken.service"]`) {
		t.Fatalf("after a round: %+v", h)
	}
	seen := h.LastSeen

	o := a.overview(admin)
	if o.Hosts != 1 || o.Online != 1 || o.WithFailed != 1 || len(o.Attention) != 1 || !strings.Contains(o.Attention[0].Issues[0], "broken.service") {
		t.Errorf("overview: %+v", o)
	}

	// "Shutting a VM down turns it offline": the next round says so, and keeps
	// what it knew.
	s.Close()
	time.Sleep(1100 * time.Millisecond) // so that "last seen" and "now" are different seconds
	a.s.monitorRound()
	h = a.host(id)
	if h.Status != "offline" || h.LastSeen != seen || h.HealthJSON == "" || !strings.Contains(h.StatusDetail, "Nothing answers") {
		t.Fatalf("after the host went away: %+v", h)
	}
	o = a.overview(admin)
	if o.Online != 0 || o.WithFailed != 0 || len(o.Attention) != 1 || o.Attention[0].Issues[0] != "offline" {
		t.Errorf("overview with the host off: %+v", o)
	}

	// And back.
	remotetest.Start(t, home, remotetest.Options{Port: s.Port, HostKey: hostKey, Stubs: map[string]string{"systemctl": systemctlStub}})
	a.s.monitorRound()
	if h = a.host(id); h.Status != "online" || h.LastSeen <= seen {
		t.Errorf("after the host came back: %+v", h)
	}
}

func TestMonitorTakesTheUpdateCountOnlyEveryTenMinutes(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	// Not asked for, and an old count is kept with the time it was taken.
	first, err := mergeHealth(remote.Health{Updates: 5}, "", now)
	if err != nil || !strings.Contains(first, `"updates":5`) || !strings.Contains(first, `"updates_at":1700000000`) {
		t.Fatalf("first: %s %v", first, err)
	}
	later, err := mergeHealth(remote.Health{Updates: -1}, first, now.Add(time.Minute))
	if err != nil || !strings.Contains(later, `"updates":5`) || !strings.Contains(later, `"updates_at":1700000000`) {
		t.Errorf("a reading without the count lost it: %s %v", later, err)
	}
	none, _ := mergeHealth(remote.Health{Updates: -1}, "", now)
	if !strings.Contains(none, `"updates":-1`) {
		t.Errorf("unknown stays unknown: %s", none)
	}
}

func TestMonitorLeavesBrokenAndRebootingHostsAlone(t *testing.T) {
	a := newTestApp(t)
	now := time.Now()
	h := store.Host{ID: 1, Status: "online"}
	if !a.s.due(h, now) {
		t.Error("an online host is due")
	}

	// A refused key is a failed login on the host each time it is tried.
	h.Status, h.StatusAt = "auth_failed", now.Add(-time.Minute).Unix()
	if a.s.due(h, now) {
		t.Error("a host that refused the key was tried again after a minute")
	}
	if !a.s.due(h, now.Add(11*time.Minute)) {
		t.Error("a host that refused the key is never tried again")
	}
	h.Status = "key_changed"
	if a.s.due(h, now) {
		t.Error("a host with a changed key was tried again at once")
	}

	h.Status = "offline"
	if !a.s.due(h, now) {
		t.Error("an offline host must be tried every minute: that is how it comes back")
	}
	if !a.s.beginReboot(1) || a.s.beginReboot(1) {
		t.Error("beginReboot must say yes once")
	}
	if a.s.due(h, now) {
		t.Error("a host that is rebooting was checked")
	}
	a.s.endReboot(1)
	if !a.s.due(h, now) {
		t.Error("a host that finished rebooting is not checked")
	}
}

func TestOperatorQuickActionsAndTheirHistory(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)
	s := remotetest.Start(t, t.TempDir(), remotetest.Options{Stubs: map[string]string{"systemctl": systemctlStub, "journalctl": journalctlStub}})
	id := a.addHost(admin, s, "web-1")

	rec := a.do("GET", "/api/hosts/"+id+"/services", operator, nil)
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"unit":"nginx.service"`) || !strings.Contains(rec.Body.String(), `"unit":"cron.service"`) {
		t.Errorf("services: %s", rec.Body.String())
	}

	rec = a.do("GET", "/api/hosts/"+id+"/logs?unit=nginx.service", operator, nil)
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), "nginx[700]: ready") {
		t.Errorf("logs: %s", rec.Body.String())
	}

	rec = a.do("POST", "/api/hosts/"+id+"/restart", operator, map[string]string{"unit": "nginx.service"})
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"state":"active"`) || !strings.Contains(rec.Body.String(), `"exit":0`) {
		t.Errorf("restart: %s", rec.Body.String())
	}
	restarted := false
	for _, c := range callsOf(s) {
		if c == "systemctl restart -- nginx.service" {
			restarted = true
		}
	}
	if !restarted {
		t.Errorf("the host was not asked to restart nginx: %q", callsOf(s))
	}

	for _, e := range []struct{ action, detail string }{
		{"host.service.restart", "nginx.service is active"},
		{"host.service.logs", "nginx.service"},
	} {
		found := false
		for _, ev := range a.events() {
			if ev.Action == e.action && ev.Result == store.ResultOK && ev.Username == "otto" && ev.Detail == e.detail {
				found = true
			}
		}
		if !found {
			t.Errorf("History has no %s by otto (%s)", e.action, e.detail)
		}
	}

	// A name that is not a service never reaches the host.
	before := len(callsOf(s))
	want(t, a.do("POST", "/api/hosts/"+id+"/restart", operator, map[string]string{"unit": "nginx.service; touch pwned"}), http.StatusBadRequest)
	want(t, a.do("GET", "/api/hosts/"+id+"/logs?unit=$(id).service", operator, nil), http.StatusBadRequest)
	want(t, a.do("GET", "/api/hosts/"+id+"/logs", operator, nil), http.StatusBadRequest)
	if len(callsOf(s)) != before {
		t.Errorf("the host was called for a bad name: %q", callsOf(s))
	}
}

func TestQuickActionsNeedSudo(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)
	s := remotetest.Start(t, t.TempDir(), remotetest.Options{Stubs: map[string]string{"systemctl": systemctlStub}})
	id := a.addHost(admin, s, "web-1")
	// The host loses its sudo.
	if err := store.SetHostFacts(a.db, mustID(t, id), "{}", false, time.Now()); err != nil {
		t.Fatal(err)
	}

	before := len(callsOf(s))
	for _, path := range []string{"/restart", "/reboot"} {
		rec := a.do("POST", "/api/hosts/"+id+path, operator, map[string]string{"unit": "nginx.service"})
		want(t, rec, http.StatusConflict)
		if !strings.Contains(rec.Body.String(), "no sudo") {
			t.Errorf("%s: %s", path, rec.Body.String())
		}
	}
	if len(callsOf(s)) != before {
		t.Errorf("the host was called without sudo: %q", callsOf(s))
	}
	if !a.has("host.reboot", store.ResultRefused) || !a.has("host.service.restart", store.ResultRefused) {
		t.Error("the refusals are not in History")
	}
	want(t, a.do("POST", "/api/hosts/"+id+"/run", admin, map[string]any{"command": "true", "root": true}), http.StatusConflict)
}

func TestRebootWaitsUntilTheHostIsBack(t *testing.T) {
	a := newTestApp(t)
	a.s.reboot = rebootTiming{settle: 10 * time.Millisecond, poll: 30 * time.Millisecond, timeout: 3 * time.Second}
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)

	// A systemctl that takes the reboot, and a host that says it was up for 3 s.
	accepting := "#!/bin/sh\necho \"systemctl $*\" >> \"$HOME/calls.log\"\nexit 0\n"
	s := remotetest.Start(t, t.TempDir(), remotetest.Options{Stubs: map[string]string{"systemctl": accepting, "cut": cutStub("3")}})
	id := a.addHost(admin, s, "web-1")

	rec := a.do("POST", "/api/hosts/"+id+"/reboot", operator, nil)
	want(t, rec, http.StatusAccepted)
	if !strings.Contains(rec.Body.String(), `"status":"rebooting"`) {
		t.Errorf("the answer: %s", rec.Body.String())
	}
	sent := false
	for _, c := range callsOf(s) { // the watcher also asks about failed services
		if c == "systemctl reboot" {
			sent = true
		}
	}
	if !sent {
		t.Errorf("the reboot was not sent: %q", callsOf(s))
	}
	want(t, a.do("POST", "/api/hosts/"+id+"/reboot", operator, nil), http.StatusConflict) // it is already rebooting

	waitFor(t, "the watcher to finish", func() bool { return a.has("host.reboot.done", store.ResultOK) })
	if h := a.host(id); h.Status != "online" {
		t.Errorf("after the reboot: %+v", h)
	}
	// (The mark is taken off a moment after the line of History is written.)
	waitFor(t, "the host to be checked again", func() bool { return a.s.due(a.host(id), time.Now()) })
	for _, e := range a.events() {
		if e.Action == "host.reboot.done" && e.Username != "otto" {
			t.Errorf("the end of the reboot is not attributed to who asked: %+v", e)
		}
	}
}

func TestRebootThatNeverHappenedIsSaidSo(t *testing.T) {
	a := newTestApp(t)
	a.s.reboot = rebootTiming{settle: 10 * time.Millisecond, poll: 30 * time.Millisecond, timeout: 300 * time.Millisecond}
	_, admin := a.user("ada", store.RoleAdmin)
	accepting := "#!/bin/sh\nexit 0\n"
	// An uptime of a day and a half: the host was never down.
	s := remotetest.Start(t, t.TempDir(), remotetest.Options{Stubs: map[string]string{"systemctl": accepting, "cut": cutStub("129600")}})
	id := a.addHost(admin, s, "web-1")

	want(t, a.do("POST", "/api/hosts/"+id+"/reboot", admin, nil), http.StatusAccepted)
	waitFor(t, "the watcher to give up", func() bool { return a.has("host.reboot.done", store.ResultFailed) })
	if h := a.host(id); h.Status != "online" {
		t.Errorf("a host that kept running is %s", h.Status)
	}
}

func TestRebootThatNeverComesBackIsOffline(t *testing.T) {
	a := newTestApp(t)
	a.s.reboot = rebootTiming{settle: 10 * time.Millisecond, poll: 30 * time.Millisecond, timeout: 400 * time.Millisecond}
	_, admin := a.user("ada", store.RoleAdmin)
	s := remotetest.Start(t, t.TempDir(), remotetest.Options{Stubs: map[string]string{"systemctl": "#!/bin/sh\nexit 0\n"}})
	id := a.addHost(admin, s, "web-1")

	want(t, a.do("POST", "/api/hosts/"+id+"/reboot", admin, nil), http.StatusAccepted)
	s.Close() // it went down and stayed down
	waitFor(t, "the watcher to give up", func() bool { return a.has("host.reboot.done", store.ResultFailed) })
	if h := a.host(id); h.Status != "offline" {
		t.Errorf("a host that never came back is %s", h.Status)
	}
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if done() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestHasRebooted(t *testing.T) {
	cases := []struct {
		uptime, since time.Duration
		want          bool
	}{
		{3 * time.Second, 40 * time.Second, true},         // up for 3 s, asked 40 s ago
		{50 * time.Second, 40 * time.Second, true},        // within the margin
		{2 * time.Hour, 20 * time.Second, false},          // still the old boot
		{36 * time.Hour, 10 * time.Minute, false},
		{0, 0, true},
	}
	for _, c := range cases {
		if got := hasRebooted(c.uptime, c.since); got != c.want {
			t.Errorf("hasRebooted(%v, %v) = %v, want %v", c.uptime, c.since, got, c.want)
		}
	}
}

func TestAdminRunsACommandAndItIsWrittenInFull(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	_, operator := a.user("otto", store.RoleOperator)
	s := remotetest.Start(t, t.TempDir(), remotetest.Options{})
	id := a.addHost(admin, s, "web-1")
	path := "/api/hosts/" + id + "/run"

	want(t, a.do("POST", path, operator, map[string]any{"command": "echo hi"}), http.StatusForbidden)
	if len(callsOf(s)) != 0 || strings.Contains(a.eventsText(), "$ echo hi") {
		t.Error("an operator's refused command was run or written as run")
	}

	rec := a.do("POST", path, admin, map[string]any{"command": "echo hello; echo oops >&2; exit 3", "timeout": 10})
	want(t, rec, http.StatusOK)
	var out struct {
		Stdout   string `json:"stdout"`
		Stderr   string `json:"stderr"`
		Exit     int    `json:"exit"`
		TimedOut bool   `json:"timed_out"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Stdout != "hello\n" || out.Stderr != "oops\n" || out.Exit != 3 || out.TimedOut {
		t.Errorf("result: %s (%v)", rec.Body.String(), err)
	}
	found := false
	for _, e := range a.events() {
		if e.Action == "host.run" && e.Result == store.ResultOK && e.Username == "ada" && e.Detail == "$ echo hello; echo oops >&2; exit 3\n(exit 3)" {
			found = true
		}
	}
	if !found {
		t.Errorf("the command is not in History word for word:\n%s", a.eventsText())
	}

	// As root, through sudo (the test server's stand-in): written as such.
	want(t, a.do("POST", path, admin, map[string]any{"command": "echo root-ish", "root": true}), http.StatusOK)
	if !strings.Contains(a.eventsText(), "sudo $ echo root-ish") {
		t.Errorf("a command run as root is not written as such:\n%s", a.eventsText())
	}

	// Checked before anything is sent.
	for name, body := range map[string]map[string]any{
		"empty":        {"command": "   "},
		"too long":     {"command": strings.Repeat("a", 1001)},
		"timeout zero": {"command": "true", "timeout": -1},
		"timeout huge": {"command": "true", "timeout": 100000},
	} {
		if rec := a.do("POST", path, admin, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d", name, rec.Code)
		}
	}
}

func TestACommandThatRunsTooLongIsStopped(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	s := remotetest.Start(t, t.TempDir(), remotetest.Options{})
	id := a.addHost(admin, s, "web-1")

	rec := a.do("POST", "/api/hosts/"+id+"/run", admin, map[string]any{"command": "sleep 2", "timeout": 1})
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"timed_out":true`) {
		t.Errorf("answer: %s", rec.Body.String())
	}
	if !a.has("host.run", store.ResultFailed) {
		t.Error("the timeout is not in History")
	}
	time.Sleep(1500 * time.Millisecond) // the sleep still runs in the test host's home folder
}

func (a *testApp) eventsText() string {
	var b strings.Builder
	for _, e := range a.events() {
		b.WriteString(e.Username + " | " + e.Action + " | " + e.Target + " | " + e.Result + " | " + e.Detail + "\n")
	}
	return b.String()
}

func TestDetailsAreLiveAndForEveryRole(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	_, viewer := a.user("vera", store.RoleViewer)
	ss := "#!/bin/sh\necho 'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=700,fd=6))'\n"
	s := remotetest.Start(t, t.TempDir(), remotetest.Options{Stubs: map[string]string{"ss": ss, "systemctl": systemctlStub}})
	id := a.addHost(admin, s, "web-1")

	rec := a.do("GET", "/api/hosts/"+id+"/details", viewer, nil)
	want(t, rec, http.StatusOK)
	for _, want := range []string{`"ports":[{"local":"0.0.0.0:80","process":"nginx"}]`, `"failed":["broken.service"]`, `"facts":{`, `"reboot_required":`, `"updates":`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("details miss %s:\n%s", want, rec.Body.String())
		}
	}

	// A host that is off: 502 with a sentence, which the page shows under what it has.
	s.Close()
	rec = a.do("GET", "/api/hosts/"+id+"/details", viewer, nil)
	want(t, rec, http.StatusBadGateway)
}

func TestSummarizeCountsWhatNeedsAttention(t *testing.T) {
	health := func(h remote.Health) string {
		data, _ := json.Marshal(h)
		return string(data)
	}
	hosts := []store.Host{
		{ID: 1, Name: "fine", User: "root", Status: "online", HealthJSON: health(remote.Health{Failed: []string{}, Updates: 0})},
		{ID: 2, Name: "broken", User: "root", Status: "online", HealthJSON: health(remote.Health{Failed: []string{"nginx.service", "cron.service"}, Updates: 3, Reboot: true})},
		// Down, with a health from when it was up: counted as down only.
		{ID: 3, Name: "down", User: "root", Status: "offline", HealthJSON: health(remote.Health{Failed: []string{"x.service"}, Updates: 9, Reboot: true})},
		{ID: 4, Name: "moved", User: "root", Status: "key_changed"},
		{ID: 5, Name: "nosudo", User: "deploy", SudoOK: false, Status: "online", HealthJSON: health(remote.Health{Failed: []string{}, Updates: -1})},
	}
	o := summarize(hosts, nil)
	if o.Hosts != 5 || o.Online != 3 || o.WithFailed != 1 || o.WithUpdates != 1 || o.NeedReboot != 1 {
		t.Errorf("counts: %+v", o)
	}
	if len(o.Attention) != 4 {
		t.Fatalf("attention: %+v", o.Attention)
	}
	// Hosts that are down come first.
	if o.Attention[0].Status == "online" || o.Attention[1].Status == "online" {
		t.Errorf("order: %+v", o.Attention)
	}
	var broken attention
	for _, a := range o.Attention {
		if a.Name == "broken" {
			broken = a
		}
	}
	if len(broken.Issues) != 3 || broken.Issues[0] != "2 failed services: nginx.service, cron.service" || broken.Issues[1] != "3 updates waiting" || broken.Issues[2] != "needs a reboot" {
		t.Errorf("issues of the broken host: %q", broken.Issues)
	}
	if got := summarize(nil, nil); got.Hosts != 0 || got.Attention == nil {
		t.Errorf("no hosts: %+v", got)
	}
}
