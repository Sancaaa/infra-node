package remote

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"infra-manager/internal/remote/remotetest"
)

// ------------------------------------------------------------ pure functions

func TestParseHealth(t *testing.T) {
	out := strings.Join([]string{
		"load1=0.52", "load5=0.40", "load15=0.31",
		"mem_total_kb=8147392", "mem_avail_kb=5000000",
		"disk_size_kb=51474044", "disk_used_kb=12345678",
		"uptime_s=93211",
		"failed=nginx.service", "failed=bad unit.service", "failed=cron.service",
		"reboot=1",
		"updates=7",
		"a line from a login script",
	}, "\n")
	h := ParseHealth(out)
	if h.Load1 != 0.52 || h.Load5 != 0.40 || h.Load15 != 0.31 || h.MemTotalKB != 8147392 || h.MemAvailKB != 5000000 {
		t.Errorf("numbers: %+v", h)
	}
	if h.DiskSizeKB != 51474044 || h.DiskUsedKB != 12345678 || h.UptimeS != 93211 || !h.Reboot || h.Updates != 7 {
		t.Errorf("numbers: %+v", h)
	}
	if len(h.Failed) != 2 || h.Failed[0] != "nginx.service" || h.Failed[1] != "cron.service" {
		t.Errorf("failed (a name with a space is not a unit): %v", h.Failed)
	}

	empty := ParseHealth("")
	if empty.Updates != -1 || empty.Failed == nil || empty.Reboot {
		t.Errorf("an empty answer: %+v (updates are unknown, the list is empty and not nil)", empty)
	}
	if ParseHealth("updates=garbage").Updates != -1 || ParseHealth("updates=-3").Updates != -1 {
		t.Error("a bad count should stay unknown")
	}
}

func TestParseServices(t *testing.T) {
	out := strings.Join([]string{
		"nginx.service loaded active running A high performance web server",
		"cron.service loaded active running Regular background program processing daemon",
		"ghost.service not-found inactive dead ghost.service",
		"systemd-fsck@dev-disk-by\\x2duuid.service loaded active exited File System Check",
		"ssh.service loaded failed failed OpenBSD Secure Shell server",
		"user@1000.service loaded active running User Manager for UID 1000",
		"short",
		"",
	}, "\n")
	got := ParseServices(out)
	var names []string
	for _, s := range got {
		names = append(names, s.Unit+":"+s.Active)
	}
	want := "cron.service:active nginx.service:active ssh.service:failed user@1000.service:active"
	if strings.Join(names, " ") != want {
		t.Errorf("services: %v\nwant %s", names, want)
	}
}

func TestParsePorts(t *testing.T) {
	out := strings.Join([]string{
		`LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=612,fd=3))`,
		`LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=612,fd=4))`,
		`LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=700,fd=6),("nginx",pid=701,fd=6))`,
		`LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:*`,
		`ESTAB 0 0 10.0.0.2:22 10.0.0.9:51000`,
		`LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=612,fd=3))`,
	}, "\n")
	got := ParsePorts(out)
	if len(got) != 4 {
		t.Fatalf("ports: %+v", got)
	}
	if got[0] != (Port{Local: "0.0.0.0:22", Process: "sshd"}) || got[2] != (Port{Local: "0.0.0.0:80", Process: "nginx"}) || got[3] != (Port{Local: "127.0.0.1:5432"}) {
		t.Errorf("ports: %+v", got)
	}
}

func TestCheckUnit(t *testing.T) {
	for _, ok := range []string{"nginx.service", "ssh.service", "user@1000.service", "systemd-resolved.service", "a.service", "docker.service"} {
		if err := CheckUnit(ok); err != nil {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "nginx", "nginx.timer", "-x.service", "a b.service", "a;id.service", "$(id).service", "a'b.service",
		"a\nb.service", "../x.service", "nginx.service;id", "a\\x2db.service", strings.Repeat("a", 120) + ".service"} {
		if CheckUnit(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestAsRoot(t *testing.T) {
	if got := asRoot("root", "systemctl reboot"); got != "systemctl reboot" {
		t.Errorf("root: %q", got)
	}
	if got := asRoot("deploy", "systemctl reboot"); got != "sudo -n systemctl reboot" {
		t.Errorf("deploy: %q", got)
	}
}

// ---------------------------------------------------------- against a real server

// A systemctl that records what it was asked and answers like the real one.
const systemctlStub = `#!/bin/sh
echo "systemctl $*" >> "$HOME/calls.log"
case "$1" in
  --failed) echo "broken.service loaded failed failed Something that broke" ;;
  list-units)
    echo "nginx.service loaded active running A web server"
    echo "cron.service loaded active running Regular jobs"
    echo "ghost.service not-found inactive dead ghost.service" ;;
  is-active) echo active ;;
esac
exit 0
`

const journalctlStub = `#!/bin/sh
echo "journalctl $*" >> "$HOME/calls.log"
echo "Nov 22 10:00:01 web-1 nginx[700]: started"
echo "Nov 22 10:00:02 web-1 nginx[700]: ready"
`

func calls(home string) []string {
	data, _ := os.ReadFile(filepath.Join(home, "calls.log"))
	return lines(string(data))
}

// enrolled is a host that is already added, with its stubs.
func enrolled(t *testing.T, stubs map[string]string) (*Remote, *remotetest.Server, Target, string) {
	t.Helper()
	r, _ := newRemote(t)
	home := t.TempDir()
	s := remotetest.Start(t, home, remotetest.Options{Stubs: stubs})
	target := targetOf(s)
	if _, err := r.Enroll(EnrollRequest{Target: target, Password: s.Password}, true); err != nil {
		t.Fatal(err)
	}
	return r, s, target, home
}

func TestProbeReadsTheHealthAndTheFailedServices(t *testing.T) {
	r, _, target, _ := enrolled(t, map[string]string{"systemctl": systemctlStub})

	h, err := r.Probe(target, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Failed) != 1 || h.Failed[0] != "broken.service" {
		t.Errorf("failed: %v", h.Failed)
	}
	if h.Updates != -1 {
		t.Errorf("the slow count was taken when it was not asked for: %d", h.Updates)
	}
	// Asked for: a number, or still unknown on a host with no apt, but no error.
	if _, err := r.Probe(target, true); err != nil {
		t.Fatal(err)
	}
}

func TestProbeCountsUpdatesOnlyWhenAsked(t *testing.T) {
	apt := "#!/bin/sh\necho 'Inst libc6 [2.36-9] (2.36-10 Debian:12 [amd64])'\necho 'Inst curl [7.88] (7.89 Debian:12 [amd64])'\necho 'Conf curl (7.89 Debian:12 [amd64])'\n"
	r, _, target, _ := enrolled(t, map[string]string{"apt-get": apt})

	h, err := r.Probe(target, true)
	if err != nil || h.Updates != 2 {
		t.Errorf("asked for: %d %v (two Inst lines)", h.Updates, err)
	}
	h, err = r.Probe(target, false)
	if err != nil || h.Updates != -1 {
		t.Errorf("not asked for: %d %v", h.Updates, err)
	}
}

func TestProbeRefusesAChangedKeyAndALostKey(t *testing.T) {
	r, s, target, home := enrolled(t, nil)

	// The dashboard's key is taken off the host.
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Probe(target, false); !errors.Is(err, ErrKeyRejected) {
		t.Errorf("a lost key: %v", err)
	}

	// A host that is off.
	s.Close()
	if _, err := r.Probe(target, false); err == nil || Classify(err).Status != StatusOffline {
		t.Errorf("a host that is off: %v", err)
	}
}

func TestServicesRestartAndLogs(t *testing.T) {
	r, _, target, home := enrolled(t, map[string]string{"systemctl": systemctlStub, "journalctl": journalctlStub})

	services, err := r.Services(target)
	if err != nil || len(services) != 2 || services[0].Unit != "cron.service" || services[1].Unit != "nginx.service" {
		t.Fatalf("services: %+v %v", services, err)
	}

	res, state, err := r.RestartService(target, "nginx.service", true)
	if err != nil || res.Exit != 0 || state != "active" {
		t.Fatalf("restart: %+v %q %v", res, state, err)
	}
	found := false
	for _, c := range calls(home) {
		if c == "systemctl restart -- nginx.service" {
			found = true
		}
	}
	if !found {
		t.Errorf("the host was not asked to restart nginx: %q", calls(home))
	}

	logs, err := r.ServiceLogs(target, "nginx.service", false)
	if err != nil || !strings.Contains(logs, "nginx[700]: ready") {
		t.Fatalf("logs: %q %v", logs, err)
	}
	if got := calls(home); got[len(got)-1] != "journalctl -u nginx.service -n 200 --no-pager" {
		t.Errorf("journalctl was called as %q", got[len(got)-1])
	}
}

// Nothing that is not a service name gets as far as the host.
func TestBadUnitNamesNeverReachTheHost(t *testing.T) {
	r, _, target, home := enrolled(t, map[string]string{"systemctl": systemctlStub, "journalctl": journalctlStub})
	before := len(calls(home))

	for _, bad := range []string{"nginx.service; touch pwned", "$(touch pwned).service", "a'b.service", "-x.service", ""} {
		if _, _, err := r.RestartService(target, bad, true); !errors.Is(err, ErrBadUnit) {
			t.Errorf("restart %q: %v", bad, err)
		}
		if _, err := r.ServiceLogs(target, bad, true); !errors.Is(err, ErrBadUnit) {
			t.Errorf("logs %q: %v", bad, err)
		}
	}
	if len(calls(home)) != before {
		t.Errorf("the host was called: %q", calls(home))
	}
	if _, err := os.Stat(filepath.Join(home, "pwned")); err == nil {
		t.Error("a command in a unit name ran")
	}
}

func TestRebootSendsOneCommandAndTheDefaultStubRefuses(t *testing.T) {
	// With a systemctl that accepts it: the command was sent.
	accepting := `#!/bin/sh
echo "systemctl $*" >> "$HOME/calls.log"
exit 0
`
	r, _, target, home := enrolled(t, map[string]string{"systemctl": accepting})
	if err := r.Reboot(target); err != nil {
		t.Fatal(err)
	}
	if got := calls(home); len(got) == 0 || got[len(got)-1] != "systemctl reboot" {
		t.Errorf("calls: %q", got)
	}

	// With the default stub, which refuses to reboot the machine the test runs on.
	r2, _, target2, _ := enrolled(t, nil)
	if err := r2.Reboot(target2); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("the default stub let a reboot through: %v", err)
	}
}

func TestRunCommandGivesOutputAndExitCode(t *testing.T) {
	r, _, target, _ := enrolled(t, nil)

	res, err := r.Run(target, "echo hello; echo oops >&2; exit 3", false, 10*time.Second)
	if err != nil || res.Stdout != "hello\n" || res.Stderr != "oops\n" || res.Exit != 3 {
		t.Errorf("result: %+v %v", res, err)
	}

	// The shell reads it word for word: this is the admin's own text.
	res, err = r.Run(target, `echo "$((6*7))"`, false, 10*time.Second)
	if err != nil || strings.TrimSpace(res.Stdout) != "42" {
		t.Errorf("result: %+v %v", res, err)
	}

	// As root: through "sudo -n sh -c '<command>'", quoted (the stub runs it as the same user).
	res, err = r.Run(target, "echo 'a b' \"c\"", true, 10*time.Second)
	if err != nil || strings.TrimSpace(res.Stdout) != "a b c" {
		t.Errorf("as root: %+v %v", res, err)
	}

	if _, err := r.Run(target, "echo a\x00b", false, time.Second); err == nil {
		t.Error("a NUL byte was sent")
	}
}

func TestRunCommandTimesOut(t *testing.T) {
	r, _, target, _ := enrolled(t, nil)
	start := time.Now()
	_, err := r.Run(target, "sleep 2", false, time.Second)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 1900*time.Millisecond {
		t.Errorf("it waited %v for a 1 s timeout", time.Since(start))
	}
	// The sleep is still running on the test host, in its home folder, and
	// Windows cannot delete a folder that is in use.
	time.Sleep(1500 * time.Millisecond)
}

func TestDetailsGivesFactsHealthAndPorts(t *testing.T) {
	ss := `#!/bin/sh
echo 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=612,fd=3))'
echo 'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=700,fd=6))'
`
	r, _, target, _ := enrolled(t, map[string]string{"ss": ss, "systemctl": systemctlStub})
	d, err := r.Details(target, true)
	if err != nil {
		t.Fatal(err)
	}
	if d.Facts.Arch == "" || len(d.Ports) != 2 || d.Ports[1].Process != "nginx" || len(d.Health.Failed) != 1 {
		t.Errorf("details: %+v", d)
	}
}
