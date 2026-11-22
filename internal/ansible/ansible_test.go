package ansible

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePlaybookAndIdempotency(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "playbook_run2.txt"))
	if err != nil {
		t.Fatal(err)
	}
	r := ParsePlaybook(string(data))
	if len(r.Recap) != 1 || r.Recap[0] != (RecapRow{Host: "ct-web-01", Ok: 6, Changed: 3, Skipped: 1}) {
		t.Fatalf("recap %+v", r.Recap)
	}
	if len(r.Tasks) != 7 {
		t.Fatalf("%d tasks, want 7", len(r.Tasks))
	}
	ok, changed := Idempotent(r)
	if ok {
		t.Fatal("a run with changed=3 was called idempotent")
	}
	var names []string
	for _, c := range changed {
		names = append(names, c.Name)
	}
	if got := strings.Join(names, "|"); got != "Install tools|Write the visit log|restart nginx" {
		t.Errorf("changed tasks: %s", got)
	}
	if !r.Tasks[6].Handler || r.Tasks[6].Hosts["ct-web-01"] != "changed" {
		t.Errorf("handler: %+v (a delegated host must be counted under its own name)", r.Tasks[6])
	}
	if r.Tasks[5].Hosts["ct-web-01"] != "skipped" {
		t.Errorf("skipped task: %+v", r.Tasks[5])
	}
}

func TestIdempotentClean(t *testing.T) {
	text := "TASK [Install nginx] ***\nok: [a]\n\nPLAY RECAP ***\na : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0\n"
	if ok, changed := Idempotent(ParsePlaybook(text)); !ok || len(changed) != 0 {
		t.Fatalf("ok=%v changed=%+v", ok, changed)
	}
	if ok, _ := Idempotent(ParsePlaybook("TASK [x] ***\nok: [a]\n")); ok {
		t.Fatal("a run without a recap (it did not finish) must not pass")
	}
}

func TestParsePlaybookFatal(t *testing.T) {
	text := "TASK [ping] ***\nfatal: [b]: UNREACHABLE! => {\"msg\": \"no route\"}\nfatal: [a]: FAILED! => {\"msg\": \"x\"}\n"
	r := ParsePlaybook(text)
	if r.Tasks[0].Hosts["b"] != "unreachable" || r.Tasks[0].Hosts["a"] != "failed" {
		t.Fatalf("%+v", r.Tasks[0].Hosts)
	}
}

func TestParseOneline(t *testing.T) {
	text := strings.Join([]string{
		`[WARNING]: Platform linux on host web is using the discovered Python interpreter`,
		`web | SUCCESS => {"ansible_facts": {"discovered_interpreter_python": "/usr/bin/python3"}, "changed": false, "ping": "pong"}`,
		`db | UNREACHABLE! => {"changed": false, "msg": "Failed to connect to the host via ssh: Permission denied (publickey).", "unreachable": true}`,
		`app | CHANGED | rc=0 | (stdout) line one\nline two`,
		`old | FAILED | rc=2 | (stdout)  (stderr) ls: cannot access 'x'`,
	}, "\n")
	results, other := ParseOneline(text)
	if len(results) != 4 || len(other) != 1 {
		t.Fatalf("results %+v other %+v", results, other)
	}
	want := []struct{ host, status, contains string }{
		{"web", "ok", "pong"},
		{"db", "unreachable", "Permission denied"},
		{"app", "changed", "line one\nline two"},
		{"old", "failed", "rc=2"},
	}
	for i, w := range want {
		r := results[i]
		if r.Host != w.host || r.Status != w.status || !strings.Contains(r.Message, w.contains) {
			t.Errorf("%d: %+v, want %+v", i, r, w)
		}
	}
}
