package tf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadPlan(t *testing.T) *Plan {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParsePlan(data)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func findChange(t *testing.T, changes []Change, address string) Change {
	t.Helper()
	for _, c := range changes {
		if c.Address == address {
			return c
		}
	}
	t.Fatalf("no change for %s", address)
	return Change{}
}

func findAttr(c Change, path string) (AttrChange, bool) {
	for _, a := range c.Attributes {
		if a.Path == path {
			return a, true
		}
	}
	return AttrChange{}, false
}

func TestPlanSummaryAndActions(t *testing.T) {
	p := loadPlan(t)
	want := Summary{Add: 1, Change: 1, Replace: 1, Destroy: 1}
	if p.Summary != want {
		t.Fatalf("summary %+v, want %+v", p.Summary, want)
	}
	if len(p.Changes) != 4 {
		t.Fatalf("%d changes, want 4 (the no-op is left out)", len(p.Changes))
	}
	if c := findChange(t, p.Changes, "proxmox_virtual_environment_container.old"); c.Action != "replace" || !strings.Contains(c.Reason, "cannot be changed in place") {
		t.Errorf("replace: %+v", c)
	}
	if c := findChange(t, p.Changes, "local_file.gone"); c.Action != "destroy" {
		t.Errorf("destroy: %+v", c)
	}
}

func TestPlanCreateHidesSensitiveAndMarksUnknown(t *testing.T) {
	c := findChange(t, loadPlan(t).Changes, "proxmox_virtual_environment_container.web")
	pw, ok := findAttr(c, "initialization[0].user_account[0].password")
	if !ok || pw.After != "(sensitive)" || !pw.Sensitive {
		t.Fatalf("password: %+v (found %v)", pw, ok)
	}
	for _, a := range c.Attributes {
		if strings.Contains(a.Before+a.After, "hunter2") {
			t.Fatalf("the secret value leaked into %s", a.Path)
		}
	}
	if id, ok := findAttr(c, "id"); !ok || id.After != "(known after apply)" || !id.Unknown {
		t.Errorf("id: %+v", id)
	}
	if mem, ok := findAttr(c, "memory[0].dedicated"); !ok || mem.After != "1024" || mem.Before != "" {
		t.Errorf("memory: %+v", mem)
	}
	if _, ok := findAttr(c, "description"); ok {
		t.Error("a null attribute of a create should be left out")
	}
}

func TestPlanUpdateListsOnlyWhatChanged(t *testing.T) {
	c := findChange(t, loadPlan(t).Changes, "proxmox_virtual_environment_container.db")
	if len(c.Attributes) != 1 {
		t.Fatalf("attributes %+v, want only the memory", c.Attributes)
	}
	if a := c.Attributes[0]; a.Path != "memory[0].dedicated" || a.Before != "1024" || a.After != "2048" {
		t.Errorf("got %+v", a)
	}
}

func TestPlanDestroyHidesSensitiveBefore(t *testing.T) {
	c := findChange(t, loadPlan(t).Changes, "local_file.gone")
	content, ok := findAttr(c, "content")
	if !ok || content.Before != "(sensitive)" || content.After != "" {
		t.Errorf("content: %+v", content)
	}
}

func TestPlanDrift(t *testing.T) {
	p := loadPlan(t)
	if len(p.Drift) != 1 {
		t.Fatalf("drift: %+v", p.Drift)
	}
	a := p.Drift[0].Attributes[0]
	if a.Path != "description" || a.Before != `"made by terraform"` || a.After != `"changed in the GUI"` {
		t.Errorf("got %+v", a)
	}
}

func TestExplain(t *testing.T) {
	cases := map[string]string{
		"Error: Error acquiring the state lock\n\nLock Info:\n  ID: 1234":                                        "Another terraform",
		"The process cannot access the file because another process has locked a portion of the file.":           "Another terraform",
		`Error: Inconsistent dependency lock file ... run "terraform init"`:                                      "not initialized",
		"Error: error creating container: 401 authentication failure":                                            "refused the login",
		"Get \"https://192.168.5.131:8006/api2/json\": dial tcp 192.168.5.131:8006: connect: connection refused": "could not reach",
	}
	for raw, want := range cases {
		if got := Explain(raw); !strings.Contains(got, want) {
			t.Errorf("Explain(%q) = %q, want something with %q", raw, got, want)
		}
	}
	if got := Explain("Error: Unsupported argument"); got != "" {
		t.Errorf("an unknown error got an explanation: %q", got)
	}
}
