package ansible

import (
	"strings"
	"testing"
)

// What a dry run (--check --diff) of the generated playbook prints: roles in the
// task names, the file diff before the line that says "changed", and a failure
// with its message.
const dryRun = `PLAY [Configure the hosts that have a profile] ****************************

TASK [Gathering Facts] *********************************************************
ok: [web-1]
ok: [web-2]

TASK [nginx : Install the nginx package] ***************************************
changed: [web-1]
fatal: [web-2]: FAILED! => {"changed": false, "msg": "No package matching 'nginx' is available"}

TASK [nginx : Write the nginx site /etc/nginx/sites-available/app] *************
--- before
+++ after: /root/.ansible/tmp/ansible-local-1/tmpabc/site.conf.j2
@@ -0,0 +1,5 @@
+# Written by infra-manager.
+server {
+    listen 80;
+}

changed: [web-1]

TASK [firewall : Allow incoming 80/tcp] ****************************************
skipping: [web-1]
changed: [web-1] => (item=80/tcp)

RUNNING HANDLER [nginx : Reload nginx] *****************************************
changed: [web-1]

PLAY RECAP *********************************************************************
web-1                      : ok=4    changed=3    unreachable=0    failed=0    skipped=1    rescued=0    ignored=0
web-2                      : ok=1    changed=0    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0
`

func TestParsePlaybookReadsDiffsFailuresAndRoles(t *testing.T) {
	r := ParsePlaybook(dryRun)
	if len(r.Tasks) != 5 || len(r.Recap) != 2 {
		t.Fatalf("%d tasks, %d recap rows", len(r.Tasks), len(r.Recap))
	}

	install := r.Tasks[1]
	if install.Hosts["web-1"] != "changed" || install.Hosts["web-2"] != "failed" {
		t.Errorf("install: %+v", install.Hosts)
	}
	if msg := install.Errors["web-2"]; !strings.Contains(msg, "No package matching 'nginx'") {
		t.Errorf("the failure's message: %q", msg)
	}
	if len(install.Diffs) != 0 {
		t.Errorf("a task without a diff got one: %+v", install.Diffs)
	}

	site := r.Tasks[2]
	diff := site.Diffs["web-1"]
	if !strings.HasPrefix(diff, "--- before\n+++ after: ") || !strings.Contains(diff, "+server {\n+    listen 80;\n+}") || strings.HasSuffix(diff, "\n") {
		t.Errorf("diff:\n%q", diff)
	}
	if site.Diffs["web-2"] != "" {
		t.Error("the diff of one host was given to another")
	}
	if site.Hosts["web-1"] != "changed" {
		t.Errorf("site: %+v", site.Hosts)
	}

	// A host whose task changed after a skip is still changed; the handler is a task of its own.
	if fw := r.Tasks[3]; fw.Hosts["web-1"] != "changed" {
		t.Errorf("firewall: %+v", fw.Hosts)
	}
	if h := r.Tasks[4]; !h.Handler || h.Hosts["web-1"] != "changed" {
		t.Errorf("handler: %+v", h)
	}

	role, title := SplitTaskName(site.Name)
	if role != "nginx" || title != "Write the nginx site /etc/nginx/sites-available/app" {
		t.Errorf("split: %q %q", role, title)
	}
	if role, title := SplitTaskName("Gathering Facts"); role != "" || title != "Gathering Facts" {
		t.Errorf("a task of no role: %q %q", role, title)
	}

	if r.Recap[0].Changed != 3 || r.Recap[1].Failed != 1 {
		t.Errorf("recap: %+v", r.Recap)
	}
	if ok, again := Idempotent(r); ok || len(again) != 4 {
		t.Errorf("Idempotent: %v %d", ok, len(again))
	}
}

func TestFailureMessage(t *testing.T) {
	cases := map[string]string{
		`fatal: [web-1]: FAILED! => {"changed": false, "msg": "boom"}`:                    "boom",
		`fatal: [web-1]: UNREACHABLE! => {"msg": "Failed to connect", "unreachable": true}`: "Failed to connect",
		`fatal: [web-1]: FAILED! => {"changed": false}`:                                   "",
		`fatal: [web-1]: FAILED! => not json`:                                             "",
		`fatal: [web-1]: FAILED!`:                                                         "",
	}
	for line, want := range cases {
		if got := failureMessage(line); got != want {
			t.Errorf("failureMessage(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestExplainKnowsTheRolesProblems(t *testing.T) {
	cases := map[string]string{
		`couldn't resolve module/action 'community.general.ufw'`: "collection",
		"Could not get lock /var/lib/dpkg/lock-frontend":         "Another package manager",
		"No package matching 'nginx' is available":               "does not exist",
		"sudo: a password is required":                           "sudo",
	}
	for raw, want := range cases {
		if got := Explain(raw); !strings.Contains(got, want) {
			t.Errorf("Explain(%q) = %q, want something with %q", raw, got, want)
		}
	}
}

func TestPlaybookCommand(t *testing.T) {
	r := NewRunner("/var/lib/infra-manager/ansible")
	c, err := r.PlaybookCmd([]string{"web-1", "web-2"}, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Shown().Command; got != "ansible-playbook site.yml --limit web-1,web-2 --check --diff" {
		t.Errorf("dry run: %s", got)
	}
	c, _ = r.PlaybookCmd([]string{"web-1"}, "nginx", false)
	if got := c.Shown().Command; got != "ansible-playbook site.yml --limit web-1 --tags nginx" {
		t.Errorf("one role: %s", got)
	}
	foundBuffering := false
	for _, e := range c.Env {
		if e == "PYTHONUNBUFFERED=1" {
			foundBuffering = true
		}
	}
	if !foundBuffering {
		t.Error("a live log would arrive in lumps")
	}

	if _, err := r.PlaybookCmd(nil, "", false); err == nil {
		t.Error("no hosts")
	}
	for _, bad := range []string{"-e x=1", "web;id", "a b", "$(id)", "--limit"} {
		if _, err := r.PlaybookCmd([]string{bad}, "", false); err == nil {
			t.Errorf("host %q accepted", bad)
		}
	}
	if _, err := r.PlaybookCmd([]string{"web-1"}, "nginx; id", false); err == nil {
		t.Error("a role that is not in the library was accepted")
	}
}
