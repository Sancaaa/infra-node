package web

import (
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"infra-manager/internal/ansible"
	"infra-manager/internal/run"
	"infra-manager/internal/store"
	"infra-manager/internal/tf"
)

// The Ansible side of the dashboard. The files Ansible reads are written from
// the database right before they are used (generate), so they cannot be out of
// date, and Ansible runs on them as a separate program.

// versionCache remembers what "ansible --version" said: starting Python for it
// takes a moment, and the answer does not change.
type versionCache struct {
	mu      sync.Mutex
	version string
	at      time.Time
}

// ansibleVersion is "" when Ansible is not installed.
func (s *Server) ansibleVersion() string {
	if _, err := exec.LookPath(s.ansible.Bin); err != nil {
		return "" // checked every time: it is cheap, and somebody may install it while this runs
	}
	s.version.mu.Lock()
	defer s.version.mu.Unlock()
	if s.version.version == "" || time.Since(s.version.at) > 5*time.Minute {
		s.version.version, s.version.at = s.ansible.Version(), time.Now()
	}
	return s.version.version
}

// generate writes the Ansible files from the database: ansible.cfg, the
// inventory, site.yml, group_vars, host_vars and the roles. Safe to call from
// several requests: one writes at a time.
func (s *Server) generate() error { return s.generateWith(genOptions{}) }

// genOptions is what one run changes in the generated files.
type genOptions struct {
	// Overrides replace some hosts' plans: the plan as it is about to be applied,
	// with a role left out of a host where it would be unsafe (SSH hardening).
	Overrides map[string]ansible.HostPlan
	// Serial above 0 makes the playbooks go through the hosts that many at a time
	// and stop at the first failure (rolling).
	Serial int
	// Access replaces what the access playbook is to do (by host name). nil is
	// everything that is pending now.
	Access map[string]ansible.HostAccess
	// Playbooks are custom playbooks written over the stored ones: saving a
	// playbook checks its text with Ansible before it is stored.
	Playbooks map[string]string
}

// vaultPasswordPath is where the password that encrypts secrets lives. It is
// made on first use, kept 0600 in its own private folder, and is not part of the
// generated directory: those files are rewritten and may be shown (View code).
func (s *Server) vaultPasswordPath() string {
	return filepath.Join(s.remote.DataDir(), "secrets", "vault_password")
}

// generateWith is generate with a run's own settings.
func (s *Server) generateWith(opt genOptions) error {
	overrides := opt.Overrides
	s.genMu.Lock()
	defer s.genMu.Unlock()

	ps, err := s.planSet()
	if err != nil {
		return err
	}
	hosts, err := store.ListHosts(s.db)
	if err != nil {
		return err
	}
	groups, err := store.ListGroups(s.db)
	if err != nil {
		return err
	}
	hostVars, err := store.AllHostVars(s.db)
	if err != nil {
		return err
	}
	groupVars, err := store.AllGroupVars(s.db)
	if err != nil {
		return err
	}

	// Secrets, as the ciphertext only, and the password Ansible decrypts them with.
	if err := ansible.EnsureVaultPassword(s.vaultPasswordPath()); err != nil {
		return err
	}
	secrets, err := store.SecretCiphertexts(s.db)
	if err != nil {
		return err
	}
	playbooks, err := store.AllPlaybooks(s.db)
	if err != nil {
		return err
	}
	for name, text := range opt.Playbooks {
		playbooks[name] = text
	}
	access := opt.Access
	if access == nil {
		ap, err := s.accessPlan(false)
		if err != nil {
			return err
		}
		access = ap.forAnsible()
	}

	in := ansible.Input{
		KeyPath: s.remote.PrivateKeyPath(), KnownHostsPath: s.remote.KnownHostsPath(), Plans: map[string]ansible.HostPlan{},
		Serial: opt.Serial, VaultPasswordPath: s.vaultPasswordPath(), Secrets: secrets, Access: access, Playbooks: playbooks,
	}
	names := map[int64]string{}
	for _, h := range hosts {
		names[h.ID] = h.Name
		if plan, ok := overrides[h.Name]; ok {
			in.Plans[h.Name] = plan
		} else if plan, ok := ps.plans[h.ID]; ok {
			in.Plans[h.Name] = plan
		}
		in.Hosts = append(in.Hosts, ansible.Host{Name: h.Name, Address: h.Address, Port: h.Port, User: h.User, Vars: toAnsibleVars(hostVars[h.ID])})
	}
	for _, g := range groups {
		ag := ansible.Group{Name: g.Name, Vars: toAnsibleVars(groupVars[g.ID])}
		for _, id := range g.HostIDs {
			ag.Hosts = append(ag.Hosts, names[id])
		}
		in.Groups = append(in.Groups, ag)
	}

	files, err := ansible.Render(in)
	if err != nil {
		return err
	}
	return ansible.Write(s.ansible.Dir, files)
}

// ansibleInfo tells the page whether Ansible is there, so it can say how to
// install it instead of failing a button later.
func (s *Server) ansibleInfo(w http.ResponseWriter, r *http.Request, me store.User) {
	version := s.ansibleVersion()
	writeJSON(w, http.StatusOK, map[string]any{
		"installed": version != "",
		"version":   version,
		"hint":      ansible.InstallHint,
	})
}

// viewCode is View code: the generated files, as they are on disk. They are
// written again first, so what is shown is what the next run will read.
func (s *Server) viewCode(w http.ResponseWriter, r *http.Request, me store.User) {
	if err := s.generate(); err != nil {
		serverError(w, "write the Ansible files", err)
		return
	}
	files, err := ansible.Read(s.ansible.Dir)
	if err != nil {
		serverError(w, "read the Ansible files", err)
		return
	}
	type file struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	out := make([]file, len(files))
	for i, f := range files {
		out[i] = file{Path: f[0], Content: f[1]}
	}
	tfOut := []file{}
	if _, err := s.generateTerraform(); err == nil {
		if tfFiles, err := tf.Read(s.tf.Dir); err == nil {
			tfOut = make([]file, len(tfFiles))
			for i, f := range tfFiles {
				tfOut[i] = file{Path: f[0], Content: f[1]}
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": out, "terraform": tfOut})
}

// runAnsible writes the files and runs one Ansible command, one at a time. ok is
// false when it has already answered (Ansible missing, busy, or a failure to
// write the files). The caller must call the returned unlock when it is done.
func (s *Server) runAnsible(w http.ResponseWriter, c run.Command) (res run.Result, unlock func(), ok bool) {
	if s.ansibleVersion() == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": ansible.InstallHint, "missing": true})
		return res, nil, false
	}
	if !s.ansibleMu.TryLock() {
		writeError(w, http.StatusConflict, "Another Ansible run is going. Wait for it to finish.")
		return res, nil, false
	}
	unlock = s.ansibleMu.Unlock
	if err := s.generate(); err != nil {
		unlock()
		serverError(w, "write the Ansible files", err)
		return res, nil, false
	}
	res, err := run.Output(c, 2*time.Minute)
	if err != nil {
		unlock()
		writeError(w, http.StatusBadGateway, err.Error())
		return res, nil, false
	}
	return res, unlock, true
}

type pingResult struct {
	Host    string `json:"host"`
	Status  string `json:"status"` // ok, changed, failed, unreachable
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"` // what to do, when the error is a known one
}

// ansiblePing is "Ping with Ansible" for a host or a group. The dashboard's own
// SSH check proves that it can log in; this proves that Ansible can, through
// the ssh program and with Python on the host, which is what configuring needs.
func (s *Server) ansiblePing(w http.ResponseWriter, r *http.Request, me store.User) {
	var req struct {
		HostID  int64 `json:"host_id"`
		GroupID int64 `json:"group_id"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	target, ok := s.targetName(w, req.HostID, req.GroupID)
	if !ok {
		return
	}
	cmd, err := s.ansible.PingCmd(target)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, unlock, ok := s.runAnsible(w, cmd)
	if !ok {
		return
	}
	defer unlock()

	results, other := ansible.ParseOneline(res.Stdout)
	out := make([]pingResult, len(results))
	for i, hr := range results {
		out[i] = pingResult{Host: hr.Host, Status: hr.Status, Message: hr.Message}
		if hr.Status != "ok" {
			out[i].Hint = ansible.Explain(hr.Message)
		}
	}
	if len(results) == 0 && res.Exit != 0 {
		s.ansibleFailed(w, res, cmd)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"target": target, "results": out, "other": other,
		"commands": []run.Shown{cmd.Shown()},
	})
}

// targetName is the host's or the group's name for the command line. Exactly one
// of the ids is given.
func (s *Server) targetName(w http.ResponseWriter, hostID, groupID int64) (string, bool) {
	switch {
	case hostID > 0 && groupID == 0:
		h, err := store.GetHost(s.db, hostID)
		if err != nil {
			writeError(w, http.StatusNotFound, "There is no such host.")
			return "", false
		}
		return h.Name, true
	case groupID > 0 && hostID == 0:
		g, err := store.GetGroup(s.db, groupID)
		if err != nil {
			writeError(w, http.StatusNotFound, "There is no such group.")
			return "", false
		}
		return g.Name, true
	}
	writeError(w, http.StatusBadRequest, "Pick one host or one group.")
	return "", false
}

// ansibleFailed answers an Ansible run that gave no per-host result: the
// sentence for known errors, with what Ansible said folded under it.
func (s *Server) ansibleFailed(w http.ResponseWriter, res run.Result, cmd run.Command) {
	secrets := s.streamSecrets()
	raw := scrubSecrets(strings.TrimSpace(res.Stderr+"\n"+res.Stdout), secrets)
	message := ansible.Explain(raw)
	if message == "" {
		message = firstLine(strings.TrimSpace(scrubSecrets(res.Message(), secrets)))
	}
	writeJSON(w, http.StatusBadGateway, map[string]any{
		"error": fmt.Sprintf("Ansible failed (exit %d). %s", res.Exit, message), "detail": raw,
		"commands": []run.Shown{cmd.Shown()},
	})
}

// ansibleFacts is Facts: everything Ansible knows about one host, to search.
func (s *Server) ansibleFacts(w http.ResponseWriter, r *http.Request, me store.User) {
	var req struct {
		HostID int64 `json:"host_id"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	name, ok := s.targetName(w, req.HostID, 0)
	if !ok {
		return
	}
	cmd, err := s.ansible.FactsCmd(name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, unlock, ok := s.runAnsible(w, cmd)
	if !ok {
		return
	}
	defer unlock()

	results, _ := ansible.ParseOneline(res.Stdout)
	if len(results) == 0 || results[0].Status != "ok" {
		if len(results) > 0 { // the host answered with an error: the sentence for it
			msg := results[0].Message
			hint := ansible.Explain(msg)
			if hint == "" {
				hint = msg
			}
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": hint, "detail": msg, "commands": []run.Shown{cmd.Shown()}})
			return
		}
		s.ansibleFailed(w, res, cmd)
		return
	}
	facts, _ := results[0].Data["ansible_facts"].(map[string]any)
	flat := ansible.FlattenFacts(facts)
	if len(flat) > 5000 { // a page that searches this in the browser does not need more
		flat = flat[:5000]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"host": name, "useful": ansible.UsefulFacts(facts), "facts": flat,
		"commands": []run.Shown{cmd.Shown()},
	})
}
