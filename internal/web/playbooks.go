package web

import (
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"infra-manager/internal/ansible"
	"infra-manager/internal/run"
	"infra-manager/internal/store"
)

// Custom playbooks: Ansible written by hand for what the library does not cover.
// They are kept in the database like everything else, generated into custom/ on
// each run, and checked with --syntax-check before they are saved. A playbook can
// do anything as root on any host it is run against, so saving and running them
// is an admin's (ActionPlaybooks), and a run is a Preview first, like any other.

const (
	maxPlaybookBytes = 128 << 10
	maxPlaybooks     = 50
)

func (s *Server) listPlaybooks(w http.ResponseWriter, r *http.Request, me store.User) {
	list, err := store.ListPlaybooks(s.db)
	if err != nil {
		serverError(w, "list playbooks", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"playbooks": list})
}

func (s *Server) getPlaybook(w http.ResponseWriter, r *http.Request, me store.User) {
	name := r.PathValue("name")
	if ansible.CheckPlaybookName(name) != nil {
		writeError(w, http.StatusNotFound, "There is no such playbook.")
		return
	}
	p, err := store.GetPlaybook(s.db, name)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "There is no such playbook.")
		return
	}
	if err != nil {
		serverError(w, "read the playbook", err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// savePlaybook stores a playbook, but only if Ansible accepts it: the text is
// written into the generated directory and "ansible-playbook --syntax-check" is
// run on it first. A playbook that does not parse is never stored, so the list
// never holds one that cannot be run.
func (s *Server) savePlaybook(w http.ResponseWriter, r *http.Request, me store.User) {
	var req struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	}
	if !readJSONLimit(w, r, &req, 2*maxPlaybookBytes) {
		return
	}
	name := strings.TrimSpace(req.Name)
	target := "playbook " + name
	switch {
	case ansible.CheckPlaybookName(name) != nil:
		s.failHost(w, r, me, "playbook.save", target, http.StatusBadRequest, ansible.CheckPlaybookName(name).Error())
		return
	case strings.TrimSpace(req.Content) == "":
		s.failHost(w, r, me, "playbook.save", target, http.StatusBadRequest, "The playbook is empty.")
		return
	case len(req.Content) > maxPlaybookBytes || strings.ContainsRune(req.Content, 0) || !utf8.ValidString(req.Content):
		s.failHost(w, r, me, "playbook.save", target, http.StatusBadRequest,
			fmt.Sprintf("A playbook is text of at most %d KB.", maxPlaybookBytes>>10))
		return
	}
	content := req.Content
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if err := ansible.CheckPlaybookContent(content); err != nil {
		s.failHost(w, r, me, "playbook.save", target, http.StatusBadRequest, err.Error())
		return
	}

	existing, err := store.ListPlaybooks(s.db)
	if err != nil {
		serverError(w, "list playbooks", err)
		return
	}
	known := false
	for _, p := range existing {
		known = known || p.Name == name
	}
	if !known && len(existing) >= maxPlaybooks {
		s.failHost(w, r, me, "playbook.save", target, http.StatusBadRequest, fmt.Sprintf("There are %d playbooks already, which is the most.", maxPlaybooks))
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
	cmd, err := s.ansible.SyntaxCheckCmd("custom/" + name + ".yml")
	if err != nil {
		s.failHost(w, r, me, "playbook.save", target, http.StatusBadRequest, err.Error())
		return
	}
	// The check reads the generated files, which a run is using or about to use.
	if !s.ansibleMu.TryLock() {
		writeError(w, http.StatusConflict, "Another Ansible run is going. Wait for it to finish.")
		return
	}
	defer s.ansibleMu.Unlock()

	if err := s.generateWith(genOptions{Playbooks: map[string]string{name: content}}); err != nil {
		serverError(w, "write the Ansible files", err)
		return
	}
	res, err := run.Output(cmd, 2*time.Minute)
	if err != nil {
		s.failHost(w, r, me, "playbook.save", target, http.StatusBadGateway, err.Error())
		return
	}
	if res.Exit != 0 {
		// The text that was just tried must not stay in custom/: write what is stored.
		if gerr := s.generate(); gerr != nil {
			s.recordFrom(clientIP(r), me, "playbook.save", target, store.ResultFailed, "could not restore the generated files")
		}
		detail := strings.TrimSpace(res.Stderr + "\n" + res.Stdout)
		if len(detail) > 4000 {
			detail = detail[:4000]
		}
		s.record(r, me, "playbook.save", target, store.ResultFailed, "Ansible does not accept it: "+firstLine(detail))
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "Ansible does not accept this playbook. Nothing was saved.", "detail": detail,
			"commands": []run.Shown{cmd.Shown()},
		})
		return
	}

	if err := store.SavePlaybook(s.db, name, content, time.Now()); err != nil {
		s.record(r, me, "playbook.save", target, store.ResultFailed, "an internal error")
		serverError(w, "store the playbook", err)
		return
	}
	s.record(r, me, "playbook.save", target, store.ResultOK, fmt.Sprintf("%d bytes, syntax OK", len(content)))
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "commands": []run.Shown{cmd.Shown()}})
}

func (s *Server) deletePlaybook(w http.ResponseWriter, r *http.Request, me store.User) {
	name := r.PathValue("name")
	target := "playbook " + name
	if ansible.CheckPlaybookName(name) != nil {
		writeError(w, http.StatusNotFound, "There is no such playbook.")
		return
	}
	if err := store.DeletePlaybook(s.db, name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "There is no such playbook.")
			return
		}
		s.record(r, me, "playbook.delete", target, store.ResultFailed, "an internal error")
		serverError(w, "delete the playbook", err)
		return
	}
	s.record(r, me, "playbook.delete", target, store.ResultOK, "")
	w.WriteHeader(http.StatusNoContent)
}

// runPlaybook is Plan, Preview and Apply of a custom playbook against a host or a
// group. The playbook's own "hosts:" line still applies: the run is limited to the
// chosen hosts, so it can only narrow, never widen.
func (s *Server) runPlaybook(w http.ResponseWriter, r *http.Request, me store.User) {
	name := r.PathValue("name")
	if ansible.CheckPlaybookName(name) != nil {
		writeError(w, http.StatusNotFound, "There is no such playbook.")
		return
	}
	var req configureReq
	if !readJSON(w, r, &req) {
		return
	}
	switch req.Mode {
	case "plan", "preview", "apply":
	default:
		writeError(w, http.StatusBadRequest, "The mode is plan, preview or apply.")
		return
	}
	if req.Serial != 0 {
		writeError(w, http.StatusBadRequest, "Set serial in the playbook itself to run a custom playbook one host at a time.")
		return
	}
	p, err := store.GetPlaybook(s.db, name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "There is no such playbook.")
			return
		}
		serverError(w, "read the playbook", err)
		return
	}
	if err := ansible.CheckPlaybookContent(p.Content); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	label, hosts, rerr := s.candidates(req.GroupID, req.HostID)
	if rerr != nil {
		writeError(w, rerr.status, rerr.msg)
		return
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })

	ts := targetSet{
		Label: name + " on " + label, Hosts: hosts,
		Roles: map[string][]string{}, Hashes: map[int64]map[string]string{}, Overrides: map[string]ansible.HostPlan{},
		Playbook: "custom/" + name + ".yml", ActionPrefix: "playbook",
	}
	for _, h := range hosts {
		ts.Roles[h.Name] = []string{}
	}
	s.execute(w, r, me, ts, req.Mode)
}
