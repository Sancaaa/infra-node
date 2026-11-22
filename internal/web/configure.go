package web

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os/exec"
	"slices"
	"strings"
	"time"

	"infra-manager/internal/ansible"
	"infra-manager/internal/run"
	"infra-manager/internal/store"
)

// Configuring hosts: the same four steps every time, in plain words.
//
//	plan         who will be configured with what, and what the commands are
//	preview      ansible-playbook --check --diff: what would change, with the diffs
//	apply        ansible-playbook for real, with a live log, then a recap
//	check_again  a second real run, to see that it changes nothing

type configureReq struct {
	Mode    string `json:"mode"`
	HostID  int64  `json:"host_id"`
	GroupID int64  `json:"group_id"`
	Role    string `json:"role"`   // one role alone (--tags), or "" for the whole profile
	Serial  int    `json:"serial"` // rolling: this many hosts at a time, stopping at a failure; 0 is all at once
}

// maxSerial is the most hosts that may be done at a time in a rolling run.
const maxSerial = 50

func (s *Server) configure(w http.ResponseWriter, r *http.Request, me store.User) {
	var req configureReq
	if !readJSON(w, r, &req) {
		return
	}
	switch req.Mode {
	case "plan", "preview", "apply", "check_again":
	default:
		writeError(w, http.StatusBadRequest, "The mode is plan, preview, apply or check_again.")
		return
	}
	if req.Serial < 0 || req.Serial > maxSerial {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Rolling is 0 (all at once) to %d hosts at a time.", maxSerial))
		return
	}
	real := req.Mode == "apply" || req.Mode == "check_again"

	ts, rerr := s.targets(req.GroupID, req.HostID, req.Role, real)
	if rerr != nil {
		writeError(w, rerr.status, rerr.msg)
		return
	}
	ts.Playbook, ts.Role, ts.Serial, ts.ActionPrefix = "site.yml", req.Role, req.Serial, "config"
	s.execute(w, r, me, ts, req.Mode)
}

// execute runs a playbook on the hosts of a targetSet: says what it would be
// (plan), tries it without changing anything (preview), or does it with a live
// log (apply). Every kind of run goes through here, so the one-at-a-time rule and
// the writing of the files are in one place.
func (s *Server) execute(w http.ResponseWriter, r *http.Request, me store.User, ts targetSet, mode string) {
	if mode == "plan" {
		s.planAnswer(w, ts)
		return
	}
	if mode == "check_again" && ts.Playbook != "site.yml" {
		writeError(w, http.StatusBadRequest, "Check again is for the profiles' playbook only.")
		return
	}
	if len(ts.Hosts) == 0 {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "There is nothing to configure.", "skipped": ts.Skipped, "notes": ts.Notes,
		})
		return
	}

	names := make([]string, len(ts.Hosts))
	for i, h := range ts.Hosts {
		names[i] = h.Name
	}
	cmd, err := s.ansible.PlaybookRun(ts.Playbook, names, ts.Role, mode == "preview")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if s.ansibleVersion() == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": ansible.InstallHint, "missing": true})
		return
	}
	if _, err := exec.LookPath(s.ansible.PlaybookBin); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": ansible.InstallHint, "missing": true})
		return
	}
	// One Ansible run at a time, for the whole dashboard.
	if !s.ansibleMu.TryLock() {
		writeError(w, http.StatusConflict, "Another Ansible run is going. Wait for it to finish.")
		return
	}
	defer s.ansibleMu.Unlock()

	if err := s.generateWith(genOptions{Overrides: ts.Overrides, Serial: ts.Serial, Access: ts.Access}); err != nil {
		serverError(w, "write the Ansible files", err)
		return
	}
	if mode == "preview" {
		s.runPreview(w, ts, cmd)
		return
	}
	s.runForReal(w, r, me, ts, cmd, mode)
}

// planAnswer says what a run would be, without running anything: who is
// configured with which roles, who is left out and why, and the two commands.
func (s *Server) planAnswer(w http.ResponseWriter, ts targetSet) {
	role := ts.Role
	type target struct {
		Name  string   `json:"name"`
		Roles []string `json:"roles"`
	}
	hosts := make([]target, len(ts.Hosts))
	names := make([]string, len(ts.Hosts))
	for i, h := range ts.Hosts {
		hosts[i] = target{Name: h.Name, Roles: ts.Roles[h.Name]}
		names[i] = h.Name
	}
	answer := map[string]any{"label": ts.Label, "hosts": hosts, "skipped": ts.Skipped, "notes": ts.Notes, "serial": ts.Serial}
	if len(names) > 0 {
		var commands []run.Shown
		for _, check := range []bool{true, false} {
			if c, err := s.ansible.PlaybookRun(ts.Playbook, names, role, check); err == nil {
				commands = append(commands, c.Shown())
			}
		}
		answer["commands"] = commands // the dry run, then the real one
	}
	writeJSON(w, http.StatusOK, answer)
}

// ------------------------------------------------------------------ preview

type change struct {
	Role  string `json:"role"`
	Title string `json:"title"`
	Diff  string `json:"diff,omitempty"`
}

type problem struct {
	Task    string `json:"task"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

type hostPreview struct {
	Name    string    `json:"name"`
	Roles   []string  `json:"roles"`
	Changes []change  `json:"changes"`
	Errors  []problem `json:"errors"`
	Down    string    `json:"down,omitempty"` // it could not be reached
}

// tasksOf reads the tasks of a run for one host: what changed, and what failed.
func tasksOf(parsed ansible.PlaybookResult, host string) (changes []change, errs []problem, down string) {
	changes, errs = []change{}, []problem{}
	for _, t := range parsed.Tasks {
		role, title := ansible.SplitTaskName(t.Name)
		switch t.Hosts[host] {
		case "changed":
			changes = append(changes, change{Role: role, Title: title, Diff: t.Diffs[host]})
		case "failed":
			msg := t.Errors[host]
			errs = append(errs, problem{Task: title, Message: msg, Hint: ansible.Explain(msg)})
		case "unreachable":
			down = t.Errors[host]
			if down == "" {
				down = "unreachable"
			}
		}
	}
	return changes, errs, down
}

// runPreview runs the dry run and says, host by host, what would change.
func (s *Server) runPreview(w http.ResponseWriter, ts targetSet, cmd run.Command) {
	secrets := s.streamSecrets()
	res, err := run.Output(cmd, 15*time.Minute)
	if err != nil {
		writeError(w, http.StatusBadGateway, scrubSecrets(err.Error(), secrets))
		return
	}
	res.Stdout = scrubSecrets(res.Stdout, secrets)
	res.Stderr = scrubSecrets(res.Stderr, secrets)
	parsed := ansible.ParsePlaybook(res.Stdout)
	if len(parsed.Recap) == 0 && res.Exit != 0 {
		s.ansibleFailed(w, res, cmd)
		return
	}

	hosts := make([]hostPreview, len(ts.Hosts))
	for i, h := range ts.Hosts {
		hp := hostPreview{Name: h.Name, Roles: ts.Roles[h.Name]}
		hp.Changes, hp.Errors, hp.Down = tasksOf(parsed, h.Name)
		if hp.Down != "" {
			hp.Down = ansibleSentence(hp.Down)
		}
		hosts[i] = hp
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"label": ts.Label, "hosts": hosts, "skipped": ts.Skipped, "notes": ts.Notes,
		"commands": []run.Shown{cmd.Shown()},
	})
}

// ansibleSentence is Ansible's message with, when it is a known one, the sentence
// that says what to do first.
func ansibleSentence(msg string) string {
	if sentence := ansible.Explain(msg); sentence != "" {
		return sentence
	}
	return msg
}

// ------------------------------------------------------------- apply (a log)

type hostRun struct {
	Name    string            `json:"name"`
	OK      bool              `json:"ok"`
	Recap   *ansible.RecapRow `json:"recap,omitempty"`
	Changed []string          `json:"changed"` // the tasks that changed something
	Failure string            `json:"failure,omitempty"`
	// NotReached: a rolling run stopped at an earlier host and never got here.
	// The host was left exactly as it was, so it is neither a success nor a
	// failure, and nothing is recorded about it.
	NotReached bool `json:"not_reached,omitempty"`
}

// reached says whether the run did anything on a host: the recap has a row for it
// with something in it.
func reached(row *ansible.RecapRow) bool {
	return row != nil && row.Ok+row.Changed+row.Failed+row.Unreachable+row.Skipped+row.Rescued+row.Ignored > 0
}

// runForReal streams an Ansible run to the page as it happens (Server-Sent
// Events: a line for each line of output, then one "result", then "done"). It is
// a POST, never a GET: it changes hosts. It does not stop when the person closes
// the window: an apply half way would be worse than one that finishes.
func (s *Server) runForReal(w http.ResponseWriter, r *http.Request, me store.User, ts targetSet, cmd run.Command, mode string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "Streaming is not supported here.")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	out := &sseWriter{w: w, flusher: flusher}

	action := ts.ActionPrefix + ".apply"
	if mode == "check_again" {
		action = ts.ActionPrefix + ".check_again"
	}

	// The log starts with "$ command" (run.Stream), and is kept to be read again.
	secrets := s.streamSecrets()
	var log bytes.Buffer
	sw := newScrubWriter(io.MultiWriter(out, &log), secrets...)
	exit, err := run.Stream(cmd, sw, run.DefaultStreamTimeout)
	_ = sw.Flush()
	if err != nil {
		msg := scrubSecrets(err.Error(), secrets)
		s.record(r, me, action, ts.Label, store.ResultFailed, msg)
		out.finish(errors.New(msg))
		return
	}

	parsed := ansible.ParsePlaybook(log.String())
	out.result(s.recordRun(r, me, ts, parsed, mode, action))

	if len(parsed.Recap) == 0 && exit != 0 {
		// Ansible stopped before it reached any host: a syntax error, a missing
		// collection, an inventory it could not read.
		msg := ansibleSentence(log.String())
		if msg == log.String() {
			msg = "the log above says why"
		}
		out.finish(fmt.Errorf("Ansible stopped before it configured anything (exit %d): %s", exit, firstLine(msg)))
		return
	}
	out.finish(nil)
}

// recordRun turns a finished run into what is stored and what the page shows:
// the state of each host, and a line of History for the run.
func (s *Server) recordRun(r *http.Request, me store.User, ts targetSet, parsed ansible.PlaybookResult, mode, action string) map[string]any {
	now := time.Now()
	hosts := make([]hostRun, len(ts.Hosts))
	failures, changedTotal, notReached := 0, 0, 0

	for i, h := range ts.Hosts {
		changes, errs, down := tasksOf(parsed, h.Name)
		hr := hostRun{Name: h.Name, Changed: []string{}}
		for _, c := range changes {
			hr.Changed = append(hr.Changed, c.Title)
		}
		for _, row := range parsed.Recap {
			if row.Host == h.Name {
				row := row
				hr.Recap = &row
			}
		}

		switch {
		case !reached(hr.Recap) && ts.Serial > 0:
			hr.NotReached = true
		case hr.Recap == nil:
			hr.Failure = "Ansible stopped before it reached this host."
		case hr.Recap.Unreachable > 0:
			hr.Failure = "It could not be reached: " + ansibleSentence(firstNonEmpty(down, "unreachable"))
		case hr.Recap.Failed > 0 && len(errs) > 0:
			hr.Failure = errs[0].Task + ": " + ansibleSentence(errs[0].Message)
		case hr.Recap.Failed > 0:
			hr.Failure = "A task failed."
		}
		hr.OK = hr.Failure == "" && !hr.NotReached
		if !hr.OK && !hr.NotReached {
			failures++
		}
		if hr.NotReached {
			notReached++
		}
		changedTotal += len(hr.Changed)

		switch {
		case ts.Playbook != "site.yml" || hr.NotReached:
			// Only the profiles' playbook writes to a host's configuration record.
			// Update packages, Access and custom playbooks report through Done.
		case mode == "check_again" && hr.OK:
			// A second run is a check, not a configuration: it only says whether
			// anything would change again.
			if err := store.SetIdempotent(s.db, h.ID, len(hr.Changed) == 0); err != nil && !errors.Is(err, store.ErrNotFound) {
				slog.Error("record the verdict", "host", h.Name, "err", err)
			}
			if len(hr.Changed) == 0 {
				s.clearHostCompliance(h.ID)
			}
		default:
			detail := hr.Failure
			if hr.OK {
				detail = fmt.Sprintf("%d changes", len(hr.Changed))
				s.clearHostCompliance(h.ID)
			}
			if err := store.RecordRun(s.db, h.ID, hr.OK, detail, ts.Hashes[h.ID], now); err != nil {
				slog.Error("record the run", "host", h.Name, "err", err)
			}
		}
		hosts[i] = hr
	}

	result := store.ResultOK
	if failures > 0 {
		result = store.ResultFailed
	}
	roles := map[string]bool{}
	for _, rs := range ts.Roles {
		for _, role := range rs {
			roles[role] = true
		}
	}
	names := make([]string, 0, len(roles))
	for role := range roles {
		names = append(names, role)
	}
	detail := fmt.Sprintf("%d hosts, %d failed, %d changes", len(hosts), failures, changedTotal)
	if notReached > 0 {
		detail += fmt.Sprintf(", %d not reached (left as they were)", notReached)
	}
	if ts.Serial > 0 {
		detail += fmt.Sprintf(", %d at a time", ts.Serial)
	}
	if ts.ActionPrefix == "config" {
		detail += "; roles: " + strings.Join(slices.Sorted(slices.Values(names)), ", ")
	}
	s.record(r, me, action, ts.Label, result, detail)

	idem, changedAgain := ansible.Idempotent(parsed)
	answer := map[string]any{
		"mode": mode, "label": ts.Label, "hosts": hosts, "skipped": ts.Skipped, "notes": ts.Notes,
		"serial": ts.Serial, "not_reached": notReached,
	}
	if ts.Done != nil && mode == "apply" {
		for k, v := range ts.Done(hosts) {
			answer[k] = v
		}
	}
	if mode == "check_again" {
		again := []string{}
		for _, t := range changedAgain {
			_, title := ansible.SplitTaskName(t.Name)
			again = append(again, title)
		}
		answer["idempotent"] = idem
		answer["changed_again"] = again
	}
	return answer
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

