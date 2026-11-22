package web

import (
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"sort"
	"strings"
	"time"

	"infra-manager/internal/ansible"
	"infra-manager/internal/store"
)

// Secrets: passwords and tokens that a profile or a variable may use. They are
// write-only. The value is typed once, goes to ansible-vault on its standard
// input, and only the encrypted text is stored. Nothing the dashboard can answer
// holds the value: the Secrets page shows names, and "set again" replaces.
// The vault password that decrypts them lives in <data>/secrets/, mode 0600.

// secretRefsInVars lists the secrets a list of variables points at ("secret:name").
func secretRefsInVars(vars []store.Var) []string {
	var out []string
	for _, v := range vars {
		if name, ok := ansible.SecretRef(v.Value); ok {
			out = append(out, name)
		}
	}
	return out
}

func secretRefsInProfile(roles []ansible.ProfileRole) []string {
	var out []string
	for _, pr := range roles {
		for _, v := range pr.Params {
			if text, ok := v.(string); ok {
				if name, isRef := ansible.SecretRef(text); isRef {
					out = append(out, name)
				}
			}
		}
	}
	return out
}

// checkSecretsExist refuses a reference to a secret that is not there: Ansible
// would stop with an undefined variable, in the middle of a run.
func (s *Server) checkSecretsExist(names []string) error {
	for _, name := range names {
		ok, err := store.SecretExists(s.db, name)
		if err != nil {
			return err
		}
		if !ok {
			return ansible.CheckError(fmt.Sprintf("There is no secret called %q. Add it on the Secrets page first.", name))
		}
	}
	return nil
}

// secretUsers says, for each secret, where it is used: a profile's role, a
// variable, or a custom playbook (found by the variable name it would use).
func (s *Server) secretUsers() (map[string][]string, error) {
	hosts, err := store.ListHosts(s.db)
	if err != nil {
		return nil, err
	}
	groups, err := store.ListGroups(s.db)
	if err != nil {
		return nil, err
	}
	groupProfiles, hostProfiles, err := store.AllProfiles(s.db)
	if err != nil {
		return nil, err
	}
	groupVars, err := store.AllGroupVars(s.db)
	if err != nil {
		return nil, err
	}
	hostVars, err := store.AllHostVars(s.db)
	if err != nil {
		return nil, err
	}
	playbooks, err := store.AllPlaybooks(s.db)
	if err != nil {
		return nil, err
	}

	users := map[string][]string{}
	add := func(name, where string) { users[name] = append(users[name], where) }
	for _, g := range groups {
		for _, pr := range groupProfiles[g.ID] {
			for _, name := range secretRefsInProfile([]ansible.ProfileRole{pr}) {
				add(name, "group "+g.Name+": "+pr.Role)
			}
		}
		for _, name := range secretRefsInVars(groupVars[g.ID]) {
			add(name, "group "+g.Name+": a variable")
		}
	}
	for _, h := range hosts {
		for _, pr := range hostProfiles[h.ID] {
			for _, name := range secretRefsInProfile([]ansible.ProfileRole{pr}) {
				add(name, "host "+h.Name+": "+pr.Role)
			}
		}
		for _, name := range secretRefsInVars(hostVars[h.ID]) {
			add(name, "host "+h.Name+": a variable")
		}
	}
	names, err := store.ListSecrets(s.db)
	if err != nil {
		return nil, err
	}
	for _, sec := range names {
		for pname, text := range playbooks {
			if containsIdent(text, ansible.SecretVar(sec.Name)) {
				add(sec.Name, "playbook "+pname)
			}
		}
	}
	for _, list := range users {
		sort.Strings(list)
	}
	return users, nil
}

// containsIdent reports whether ident appears in text as a whole identifier
// (not a prefix or suffix of a longer name such as secret_db_pass).
func containsIdent(text, ident string) bool {
	isIdent := func(b byte) bool {
		return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
	}
	for start := 0; start <= len(text)-len(ident); {
		i := strings.Index(text[start:], ident)
		if i < 0 {
			return false
		}
		pos := start + i
		end := pos + len(ident)
		if (pos == 0 || !isIdent(text[pos-1])) && (end == len(text) || !isIdent(text[end])) {
			return true
		}
		start = pos + 1
	}
	return false
}

type secretView struct {
	store.Secret
	UsedBy []string `json:"used_by"`
}

// listSecrets answers the names, when each was set, and where it is used. Never a value.
func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request, me store.User) {
	secrets, err := store.ListSecrets(s.db)
	if err != nil {
		serverError(w, "list secrets", err)
		return
	}
	users, err := s.secretUsers()
	if err != nil {
		serverError(w, "find where secrets are used", err)
		return
	}
	views := make([]secretView, len(secrets))
	for i, sec := range secrets {
		views[i] = secretView{Secret: sec, UsedBy: users[sec.Name]}
		if views[i].UsedBy == nil {
			views[i].UsedBy = []string{}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"secrets": views})
}

const maxSecrets = 100

// setSecret creates a secret or replaces its value. The value is in the request
// and nowhere else: not in History (which gets the name), not in the log, not in
// the answer.
func (s *Server) setSecret(w http.ResponseWriter, r *http.Request, me store.User) {
	var req struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	target := "secret " + name
	if err := ansible.CheckSecretName(name); err != nil {
		s.failHost(w, r, me, "secret.set", target, http.StatusBadRequest, err.Error())
		return
	}
	if err := ansible.CheckSecretValue(req.Value); err != nil {
		s.failHost(w, r, me, "secret.set", target, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := exec.LookPath(s.ansible.VaultBin); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": ansible.InstallHint, "missing": true})
		return
	}
	existing, err := store.ListSecrets(s.db)
	if err != nil {
		serverError(w, "list secrets", err)
		return
	}
	known := false
	for _, e := range existing {
		known = known || e.Name == name
	}
	if !known && len(existing) >= maxSecrets {
		s.failHost(w, r, me, "secret.set", target, http.StatusBadRequest, fmt.Sprintf("There are %d secrets already, which is the most.", maxSecrets))
		return
	}

	if err := ansible.EnsureVaultPassword(s.vaultPasswordPath()); err != nil {
		s.record(r, me, "secret.set", target, store.ResultFailed, "the vault password could not be made")
		serverError(w, "make the vault password", err)
		return
	}
	cipher, err := s.ansible.Encrypt(s.vaultPasswordPath(), name, req.Value)
	if err != nil {
		// Encrypt removes the value from its error; History gets the sentence.
		s.failHost(w, r, me, "secret.set", target, http.StatusBadGateway, "The secret could not be encrypted: "+firstLine(err.Error()))
		return
	}
	if err := store.SetSecret(s.db, name, cipher, time.Now()); err != nil {
		s.record(r, me, "secret.set", target, store.ResultFailed, "an internal error")
		serverError(w, "store the secret", err)
		return
	}
	s.record(r, me, "secret.set", target, store.ResultOK, "the value is not shown anywhere")
	w.WriteHeader(http.StatusNoContent)
}

// deleteSecret removes a secret, unless something still uses it: the next run
// would fail on a variable that is not there.
func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request, me store.User) {
	name := r.PathValue("name")
	target := "secret " + name
	if ansible.CheckSecretName(name) != nil {
		writeError(w, http.StatusNotFound, "There is no such secret.")
		return
	}
	users, err := s.secretUsers()
	if err != nil {
		serverError(w, "find where secrets are used", err)
		return
	}
	if list := users[name]; len(list) > 0 {
		s.failHost(w, r, me, "secret.delete", target, http.StatusConflict,
			"It is still used by "+strings.Join(list, "; ")+". Change those first.")
		return
	}
	if err := store.DeleteSecret(s.db, name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "There is no such secret.")
			return
		}
		s.record(r, me, "secret.delete", target, store.ResultFailed, "an internal error")
		serverError(w, "delete the secret", err)
		return
	}
	s.record(r, me, "secret.delete", target, store.ResultOK, "")
	w.WriteHeader(http.StatusNoContent)
}
