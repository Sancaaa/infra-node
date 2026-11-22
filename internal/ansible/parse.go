// Package ansible is the dashboard's side of Ansible: it writes the files
// Ansible reads (generate.go: the inventory, ansible.cfg, group_vars, host_vars),
// starts it (runner.go), and reads what it prints (this file). The files are
// generated from the database and never read back (OD-06), so there is no
// inventory parser.
package ansible

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------- ad-hoc

// HostResult is one host's answer to an ad-hoc command.
type HostResult struct {
	Host    string         `json:"host"`
	Status  string         `json:"status"` // ok, changed, failed, unreachable
	Message string         `json:"message"`
	Data    map[string]any `json:"-"` // the module's JSON answer, when there is one
}

// With -o each host's answer is one line:
//
//	web-01 | SUCCESS => {"changed": false, "ping": "pong"}
//	web-01 | UNREACHABLE! => {"changed": false, "msg": "Failed to connect ...", "unreachable": true}
//	web-01 | CHANGED | rc=0 | (stdout) hello
//	web-01 | FAILED | rc=2 | (stdout)  (stderr) ls: cannot access 'x'
var onelineRe = regexp.MustCompile(`^(\S+) \| (SUCCESS|CHANGED|FAILED!?|UNREACHABLE!)(?: \| rc=(-?\d+))?(?: => | \| )(.*)$`)

// ParseOneline reads the -o output. Lines it does not understand (warnings,
// deprecation notices) come back in other.
func ParseOneline(text string) (results []HostResult, other []string) {
	results = []HostResult{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		m := onelineRe.FindStringSubmatch(line)
		if m == nil {
			other = append(other, line)
			continue
		}
		r := HostResult{Host: m[1], Status: statusWord(m[2])}
		rest := m[4]
		if strings.HasPrefix(rest, "{") {
			var data map[string]any
			if json.Unmarshal([]byte(rest), &data) == nil {
				r.Data = data
				r.Message = messageOf(data)
			} else {
				r.Message = rest
			}
		} else {
			// "(stdout) ..." with \n written as the two characters, as -o does.
			r.Message = strings.ReplaceAll(rest, `\n`, "\n")
			if m[3] != "" {
				r.Message = "rc=" + m[3] + " " + r.Message
			}
		}
		results = append(results, r)
	}
	return results, other
}

func statusWord(s string) string {
	switch strings.TrimSuffix(s, "!") {
	case "SUCCESS":
		return "ok"
	case "CHANGED":
		return "changed"
	case "UNREACHABLE":
		return "unreachable"
	}
	return "failed"
}

// messageOf picks the line worth showing from a module's answer.
func messageOf(data map[string]any) string {
	for _, key := range []string{"msg", "ping", "stdout", "stderr"} {
		if s, ok := data[key].(string); ok && s != "" {
			return s
		}
	}
	if _, ok := data["ansible_facts"]; ok {
		return "facts gathered"
	}
	if changed, _ := data["changed"].(bool); changed {
		return "changed"
	}
	return ""
}

// UsefulFacts picks the facts a person looks at first.
func UsefulFacts(facts map[string]any) map[string]string {
	out := map[string]string{}
	str := func(key string) string {
		if v, ok := facts[key]; ok && v != nil {
			text, _ := json.Marshal(v)
			return strings.Trim(string(text), `"`)
		}
		return ""
	}
	out["Host name"] = str("ansible_hostname")
	out["OS"] = strings.TrimSpace(str("ansible_distribution") + " " + str("ansible_distribution_version"))
	out["Kernel"] = str("ansible_kernel")
	if ipv4, ok := facts["ansible_default_ipv4"].(map[string]any); ok {
		out["Address"], _ = ipv4["address"].(string)
	}
	out["All IPv4 addresses"] = strings.Trim(strings.ReplaceAll(str("ansible_all_ipv4_addresses"), `"`, ""), "[]")
	out["CPUs"] = str("ansible_processor_vcpus")
	if mb := str("ansible_memtotal_mb"); mb != "" {
		out["Memory"] = mb + " MB"
	}
	out["Python"] = str("ansible_python_version")
	for k, v := range out {
		if v == "" {
			delete(out, k)
		}
	}
	return out
}

// FlattenFacts lists every fact as path → value, for the search box.
func FlattenFacts(facts map[string]any) [][2]string {
	flat := map[string]string{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, x := range t {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				walk(p, x)
			}
		case []any:
			for i, x := range t {
				walk(prefix+"["+strconv.Itoa(i)+"]", x)
			}
		default:
			text, _ := json.Marshal(t)
			flat[prefix] = strings.Trim(string(text), `"`)
		}
	}
	walk("", facts)
	out := make([][2]string, 0, len(flat))
	for k, v := range flat {
		out = append(out, [2]string{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

// ---------------------------------------------------------------- playbooks

type RecapRow struct {
	Host        string `json:"host"`
	Ok          int    `json:"ok"`
	Changed     int    `json:"changed"`
	Unreachable int    `json:"unreachable"`
	Failed      int    `json:"failed"`
	Skipped     int    `json:"skipped"`
	Rescued     int    `json:"rescued"`
	Ignored     int    `json:"ignored"`
}

// TaskResult is one task (or handler) of a run, with what it did on each host.
type TaskResult struct {
	Play    string            `json:"play"`
	Name    string            `json:"name"` // as Ansible prints it: "nginx : Install the nginx package"
	Handler bool              `json:"handler"`
	Hosts   map[string]string `json:"hosts"`            // host → ok, changed, failed, unreachable, skipped
	Diffs   map[string]string `json:"diffs,omitempty"`  // host → the file diff of a dry run
	Errors  map[string]string `json:"errors,omitempty"` // host → why it failed
}

// SplitTaskName splits "nginx : Install the nginx package" into the role and the
// task's own name. A task that is not in a role has no role.
func SplitTaskName(name string) (role, title string) {
	if before, after, found := strings.Cut(name, " : "); found {
		return before, after
	}
	return "", name
}

type PlaybookResult struct {
	Recap []RecapRow   `json:"recap"`
	Tasks []TaskResult `json:"tasks"`
}

// The default output of ansible-playbook, the lines that matter:
//
//	PLAY [Web server] ***************************************************
//	TASK [Install nginx] ************************************************
//	changed: [ct-web-01]
//	ok: [ct-web-01] => (item=curl)
//	fatal: [ct-web-01]: FAILED! => {"msg": "..."}
//	RUNNING HANDLER [restart nginx] *************************************
//	PLAY RECAP **********************************************************
//	ct-web-01 : ok=3 changed=1 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
//
// This format has been the same for many years. It is read instead of the
// JSON callback because it streams: the JSON callback prints nothing until the
// play ends, and a live log is what shows that something is happening (OD-04).
var (
	playRe   = regexp.MustCompile(`^PLAY \[(.*)\] \*+`)
	taskRe   = regexp.MustCompile(`^(TASK|RUNNING HANDLER) \[(.*)\] \*+`)
	statusRe = regexp.MustCompile(`^(ok|changed|skipping|fatal|failed): \[([^\]]+)\]`)
	recapRe  = regexp.MustCompile(`^(\S+)\s+: ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)(?:\s+skipped=(\d+))?(?:\s+rescued=(\d+))?(?:\s+ignored=(\d+))?`)
)

// rank orders what a task can do on a host, worst last, so a loop with one
// changed item counts as changed.
var rank = map[string]int{"skipped": 0, "ok": 1, "changed": 2, "unreachable": 3, "failed": 4}

func ParsePlaybook(text string) PlaybookResult {
	res := PlaybookResult{Recap: []RecapRow{}, Tasks: []TaskResult{}}
	play := ""
	var task *TaskResult
	inRecap := false
	// A dry run with --diff prints the file diff of a task before the line that
	// says "changed: [host]". It starts with "--- before" and runs until the
	// next status, task or play line.
	var diff []string

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "PLAY RECAP"):
			inRecap = true
		case inRecap:
			if m := recapRe.FindStringSubmatch(line); m != nil {
				n := func(i int) int { v, _ := strconv.Atoi(m[i]); return v }
				res.Recap = append(res.Recap, RecapRow{Host: m[1], Ok: n(2), Changed: n(3), Unreachable: n(4),
					Failed: n(5), Skipped: n(6), Rescued: n(7), Ignored: n(8)})
			}
		case playRe.MatchString(line):
			play = playRe.FindStringSubmatch(line)[1]
			task = nil
			diff = nil
		case taskRe.MatchString(line):
			m := taskRe.FindStringSubmatch(line)
			res.Tasks = append(res.Tasks, TaskResult{Play: play, Name: m[2], Handler: m[1] == "RUNNING HANDLER", Hosts: map[string]string{}})
			task = &res.Tasks[len(res.Tasks)-1]
			diff = nil
		case task != nil && statusRe.MatchString(line):
			m := statusRe.FindStringSubmatch(line)
			host, _, _ := strings.Cut(m[2], " -> ") // "web-01 -> localhost" when delegated
			status := m[1]
			switch status {
			case "skipping":
				status = "skipped"
			case "fatal", "failed":
				status = "failed"
				if strings.Contains(line, "UNREACHABLE!") {
					status = "unreachable"
				}
				if msg := failureMessage(line); msg != "" {
					if task.Errors == nil {
						task.Errors = map[string]string{}
					}
					task.Errors[host] = msg
				}
			}
			if old, seen := task.Hosts[host]; !seen || rank[status] > rank[old] {
				task.Hosts[host] = status
			}
			if len(diff) > 0 {
				if task.Diffs == nil {
					task.Diffs = map[string]string{}
				}
				if old := task.Diffs[host]; old != "" {
					task.Diffs[host] = old + "\n" + strings.TrimRight(strings.Join(diff, "\n"), "\n")
				} else {
					task.Diffs[host] = strings.TrimRight(strings.Join(diff, "\n"), "\n")
				}
				diff = nil
			}
		case task != nil && (strings.HasPrefix(line, "--- before") || diff != nil):
			diff = append(diff, line)
		}
	}
	return res
}

// failureMessage reads "msg" from the JSON at the end of a failure line:
//
//	fatal: [web-1]: FAILED! => {"changed": false, "msg": "No package matching 'x' is available"}
func failureMessage(line string) string {
	_, rest, found := strings.Cut(line, "=> ")
	if !found {
		return ""
	}
	var body struct {
		Msg string `json:"msg"`
	}
	if json.Unmarshal([]byte(rest), &body) != nil {
		return ""
	}
	return body.Msg
}

// Idempotent reports whether a (second) run changed nothing and failed
// nowhere, and lists the tasks that did change something: those are the ones
// that are not idempotent.
func Idempotent(r PlaybookResult) (bool, []TaskResult) {
	changed := []TaskResult{}
	for _, t := range r.Tasks {
		for _, s := range t.Hosts {
			if s == "changed" {
				changed = append(changed, t)
				break
			}
		}
	}
	if len(r.Recap) == 0 {
		return false, changed // no recap: the run did not finish
	}
	for _, row := range r.Recap {
		if row.Changed > 0 || row.Failed > 0 || row.Unreachable > 0 {
			return false, changed
		}
	}
	return true, changed
}
