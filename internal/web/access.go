package web

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"infra-manager/internal/ansible"
	"infra-manager/internal/store"
)

// Access: the SSH public keys of people, and the groups and hosts each may log
// in to. The dashboard puts a key on a host with Ansible's authorized_key and
// remembers what it put there (store.AllInstalled), so that taking access away
// is the same run the other way round: what was installed and is no longer
// wanted is removed. A public key is not a secret; the page may show it.

// hostAccessPlan is what the access playbook does to one host.
type hostAccessPlan struct {
	Host store.Host
	// Add is every key the host should have: the playbook asserts the whole list,
	// which is harmless for a key that is there. New is the part of it the host
	// does not have yet, which is what "pending" means. Remove is what the
	// dashboard put there before and should not be any more.
	Add    []ansible.AccessKey
	New    []ansible.AccessKey
	Remove []ansible.AccessKey
}

type accessPlan struct {
	Hosts []hostAccessPlan // only hosts with something to do, by name
}

// forAnsible is the plan as Render wants it, by host name.
func (p accessPlan) forAnsible() map[string]ansible.HostAccess {
	out := map[string]ansible.HostAccess{}
	for _, h := range p.Hosts {
		out[h.Host.Name] = ansible.HostAccess{Add: h.Add, Remove: h.Remove}
	}
	return out
}

// accessPlan works out, for every host, the keys to have and the keys to take
// away: wanted = what the grants say; installed = what the dashboard put there
// before. onlyRevoke is "Revoke everywhere": nothing new is given, so the run
// does what it was asked for and no more (a grant made a minute ago, not yet
// applied, waits for its own Apply).
func (s *Server) accessPlan(onlyRevoke bool) (accessPlan, error) {
	keys, err := store.ListAccessKeys(s.db)
	if err != nil {
		return accessPlan{}, err
	}
	hosts, err := store.ListHosts(s.db)
	if err != nil {
		return accessPlan{}, err
	}
	groups, err := store.ListGroups(s.db)
	if err != nil {
		return accessPlan{}, err
	}
	installed, err := store.AllInstalled(s.db)
	if err != nil {
		return accessPlan{}, err
	}

	members := map[int64][]int64{} // group id → host ids
	for _, g := range groups {
		members[g.ID] = g.HostIDs
	}
	type slot struct{ key, user string }
	wanted := map[int64][]ansible.AccessKey{}
	have := map[int64]map[slot]bool{}
	byID := map[int64]store.Host{}
	for _, h := range hosts {
		byID[h.ID] = h
		have[h.ID] = map[slot]bool{}
	}
	give := func(hostID int64, k store.AccessKey) {
		h, ok := byID[hostID]
		if !ok {
			return
		}
		user := k.User
		if user == "" {
			user = h.User // the account the dashboard logs in as
		}
		sl := slot{k.PublicKey, user}
		if have[hostID][sl] {
			return // given twice, through a group and through the host
		}
		have[hostID][sl] = true
		wanted[hostID] = append(wanted[hostID], ansible.AccessKey{Name: k.Name, Key: k.PublicKey, User: user})
	}
	for _, k := range keys {
		for _, gid := range k.GroupIDs {
			for _, hid := range members[gid] {
				give(hid, k)
			}
		}
		for _, hid := range k.HostIDs {
			give(hid, k)
		}
	}

	var plan accessPlan
	for _, h := range hosts {
		before := map[slot]bool{}
		for _, k := range installed[h.ID] {
			before[slot{k.PublicKey, k.User}] = true
		}
		hp := hostAccessPlan{Host: h}
		for _, k := range wanted[h.ID] {
			if before[slot{k.Key, k.User}] {
				hp.Add = append(hp.Add, k)
				continue
			}
			if !onlyRevoke { // a revoke gives nothing new
				hp.New = append(hp.New, k)
				hp.Add = append(hp.Add, k)
			}
		}
		for _, k := range installed[h.ID] {
			if !have[h.ID][slot{k.PublicKey, k.User}] {
				hp.Remove = append(hp.Remove, ansible.AccessKey{Name: k.Name, Key: k.PublicKey, User: k.User})
			}
		}
		// A host is visited only when there is something to change on it.
		if len(hp.Remove) > 0 || (!onlyRevoke && len(hp.New) > 0) {
			plan.Hosts = append(plan.Hosts, hp)
		}
	}
	sort.Slice(plan.Hosts, func(i, j int) bool { return plan.Hosts[i].Host.Name < plan.Hosts[j].Host.Name })
	return plan, nil
}

// -------------------------------------------------------------------- the page

type accessKeyView struct {
	store.AccessKey
	Installed []string `json:"installed"` // names of the hosts it is on
}

type pendingView struct {
	Host   string   `json:"host"`
	Add    []string `json:"add"`
	Remove []string `json:"remove"`
}

func accessNames(keys []ansible.AccessKey) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k.Name
	}
	return out
}

// listAccess is the Access page: the keys with their grants, where each is
// installed, and what the next Apply would do.
func (s *Server) listAccess(w http.ResponseWriter, r *http.Request, me store.User) {
	keys, err := store.ListAccessKeys(s.db)
	if err != nil {
		serverError(w, "list keys", err)
		return
	}
	hosts, err := store.ListHosts(s.db)
	if err != nil {
		serverError(w, "list hosts", err)
		return
	}
	installed, err := store.AllInstalled(s.db)
	if err != nil {
		serverError(w, "read what was installed", err)
		return
	}
	hostName := map[int64]string{}
	for _, h := range hosts {
		hostName[h.ID] = h.Name
	}
	views := make([]accessKeyView, len(keys))
	for i, k := range keys {
		views[i] = accessKeyView{AccessKey: k, Installed: []string{}}
		for hid, list := range installed {
			for _, ik := range list {
				if ik.PublicKey == k.PublicKey && !slices.Contains(views[i].Installed, hostName[hid]) {
					views[i].Installed = append(views[i].Installed, hostName[hid])
				}
			}
		}
		sort.Strings(views[i].Installed)
	}
	plan, err := s.accessPlan(false)
	if err != nil {
		serverError(w, "work out the access", err)
		return
	}
	pending := []pendingView{}
	for _, hp := range plan.Hosts {
		pending = append(pending, pendingView{Host: hp.Host.Name, Add: accessNames(hp.New), Remove: accessNames(hp.Remove)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": views, "pending": pending})
}

func (s *Server) loadAccessKey(w http.ResponseWriter, r *http.Request) (store.AccessKey, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusNotFound, "There is no such key.")
		return store.AccessKey{}, false
	}
	k, err := store.GetAccessKey(s.db, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "There is no such key.")
		return store.AccessKey{}, false
	}
	if err != nil {
		serverError(w, "read the key", err)
		return store.AccessKey{}, false
	}
	return k, true
}

// normalizeKey keeps the type and the key and drops the comment: the name says
// whose it is, and two copies of one key that differ only in the comment are one
// key.
func normalizeKey(line string) string {
	f := strings.Fields(line)
	if len(f) < 2 {
		return strings.TrimSpace(line)
	}
	return f[0] + " " + f[1]
}

func (s *Server) addAccessKey(w http.ResponseWriter, r *http.Request, me store.User) {
	var req struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
		User      string `json:"user"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	user := strings.TrimSpace(req.User)
	target := "access key " + name
	key := normalizeKey(req.PublicKey)
	for _, err := range []error{ansible.CheckAccessName(name), ansible.CheckSSHKey(key), ansible.CheckAccessUser(user)} {
		if err != nil {
			s.failHost(w, r, me, "access.key.add", target, http.StatusBadRequest, err.Error())
			return
		}
	}
	k, err := store.CreateAccessKey(s.db, name, key, user, time.Now())
	switch {
	case errors.Is(err, store.ErrAccessNameTaken), errors.Is(err, store.ErrAccessKeyTaken):
		s.failHost(w, r, me, "access.key.add", target, http.StatusConflict, err.Error())
		return
	case err != nil:
		s.record(r, me, "access.key.add", target, store.ResultFailed, "an internal error")
		serverError(w, "add a key", err)
		return
	}
	// History says whose key and which kind, not the key itself.
	s.record(r, me, "access.key.add", target, store.ResultOK, strings.Fields(key)[0])
	writeJSON(w, http.StatusCreated, accessKeyView{AccessKey: k, Installed: []string{}})
}

func (s *Server) setAccessGrants(w http.ResponseWriter, r *http.Request, me store.User) {
	k, ok := s.loadAccessKey(w, r)
	if !ok {
		return
	}
	var req struct {
		GroupIDs []int64 `json:"group_ids"`
		HostIDs  []int64 `json:"host_ids"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	target := "access key " + k.Name
	if len(req.GroupIDs) > 200 || len(req.HostIDs) > 500 {
		s.failHost(w, r, me, "access.grant", target, http.StatusBadRequest, "That is more groups or hosts than there should be.")
		return
	}
	if err := store.SetAccessGrants(s.db, k.ID, req.GroupIDs, req.HostIDs); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.failHost(w, r, me, "access.grant", target, http.StatusNotFound, "A group or host in the list does not exist.")
			return
		}
		s.record(r, me, "access.grant", target, store.ResultFailed, "an internal error")
		serverError(w, "grant access", err)
		return
	}
	s.record(r, me, "access.grant", target, store.ResultOK,
		fmt.Sprintf("%d groups, %d hosts (not applied yet)", len(req.GroupIDs), len(req.HostIDs)))
	w.WriteHeader(http.StatusNoContent)
}

// deleteAccessKey forgets a key. If it is still on hosts, the next Apply takes it
// off (the record of what is installed stays), and the answer says so.
func (s *Server) deleteAccessKey(w http.ResponseWriter, r *http.Request, me store.User) {
	k, ok := s.loadAccessKey(w, r)
	if !ok {
		return
	}
	target := "access key " + k.Name
	if err := store.DeleteAccessKey(s.db, k.ID); err != nil {
		s.record(r, me, "access.key.delete", target, store.ResultFailed, "an internal error")
		serverError(w, "delete a key", err)
		return
	}
	s.record(r, me, "access.key.delete", target, store.ResultOK, "")
	w.WriteHeader(http.StatusNoContent)
}

// ------------------------------------------------------------------ the runs

type accessReq struct {
	Mode   string `json:"mode"` // plan, preview, apply
	Serial int    `json:"serial"`
}

// accessTargets is the hosts the access playbook will visit, with a line for
// each saying what it does there. A host the dashboard cannot become root on is
// left out with the reason.
func (s *Server) accessTargets(plan accessPlan) targetSet {
	ts := targetSet{Roles: map[string][]string{}, Hashes: map[int64]map[string]string{}, Overrides: map[string]ansible.HostPlan{}}
	for _, hp := range plan.Hosts {
		if !canRoot(hp.Host) {
			ts.Skipped = append(ts.Skipped, skip{hp.Host.Name, "the dashboard has no sudo on it, so Ansible cannot become root. Edit the host and allow sudo without a password"})
			continue
		}
		var what []string
		for _, k := range hp.New {
			what = append(what, "give "+k.Name)
		}
		for _, k := range hp.Remove {
			what = append(what, "take away "+k.Name)
		}
		ts.Hosts = append(ts.Hosts, hp.Host)
		ts.Roles[hp.Host.Name] = what
	}
	return ts
}

func (s *Server) applyAccess(w http.ResponseWriter, r *http.Request, me store.User) {
	var req accessReq
	if !readJSON(w, r, &req) {
		return
	}
	switch req.Mode {
	case "plan", "preview", "apply":
	default:
		writeError(w, http.StatusBadRequest, "The mode is plan, preview or apply.")
		return
	}
	if req.Serial < 0 || req.Serial > maxSerial {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Rolling is 0 (all at once) to %d hosts at a time.", maxSerial))
		return
	}
	plan, err := s.accessPlan(false)
	if err != nil {
		serverError(w, "work out the access", err)
		return
	}
	s.runAccess(w, r, me, plan, "everyone", req.Mode, req.Serial)
}

// revokeAccessKey is "Revoke everywhere": the key's grants are cleared, and the
// key is taken off every host it was put on, in one go. The key stays on the
// list (without any grant), so it can be given again; Delete forgets it.
func (s *Server) revokeAccessKey(w http.ResponseWriter, r *http.Request, me store.User) {
	k, ok := s.loadAccessKey(w, r)
	if !ok {
		return
	}
	target := "access key " + k.Name
	if err := store.SetAccessGrants(s.db, k.ID, nil, nil); err != nil {
		s.record(r, me, "access.revoke", target, store.ResultFailed, "an internal error")
		serverError(w, "revoke", err)
		return
	}
	plan, err := s.accessPlan(true)
	if err != nil {
		serverError(w, "work out the access", err)
		return
	}
	s.runAccess(w, r, me, plan, "revoke "+k.Name, "apply", 0)
}

func (s *Server) runAccess(w http.ResponseWriter, r *http.Request, me store.User, plan accessPlan, label, mode string, serial int) {
	ts := s.accessTargets(plan)
	ts.Label, ts.Playbook, ts.Serial, ts.ActionPrefix = label, "access.yml", serial, "access"
	ts.Access = plan.forAnsible()
	// A real run records what is on each host afterwards, for the hosts it worked on.
	ts.Done = func(hosts []hostRun) map[string]any {
		byName := map[string]hostAccessPlan{}
		for _, hp := range plan.Hosts {
			byName[hp.Host.Name] = hp
		}
		for _, hr := range hosts {
			if !hr.OK {
				continue // what is on a failed or unreached host is unknown: keep the old record
			}
			hp := byName[hr.Name]
			now := make([]store.InstalledKey, len(hp.Add))
			for i, k := range hp.Add {
				now[i] = store.InstalledKey{Name: k.Name, PublicKey: k.Key, User: k.User}
			}
			if err := store.SaveInstalled(s.db, hp.Host.ID, now); err != nil {
				s.recordFrom("", me, "access.record", "host "+hp.Host.Name, store.ResultFailed, "the run worked but what it did could not be written down")
			}
		}
		return nil
	}
	if len(ts.Hosts) == 0 && len(ts.Skipped) == 0 {
		// Nothing to give and nothing to take away.
		writeJSON(w, http.StatusConflict, map[string]any{"error": "Nobody's access needs changing: every host has what it should."})
		return
	}
	s.execute(w, r, me, ts, mode)
}
