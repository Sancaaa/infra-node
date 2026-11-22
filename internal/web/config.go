package web

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"infra-manager/internal/ansible"
	"infra-manager/internal/store"
)

// Profiles: what each host is configured with, and whether it is. A profile is a
// list of roles with parameters, given to a group or to a single host. A host's
// own profile is its groups' profiles plus its own (ansible.BuildPlan).

// planSet is the plan of every host, worked out from the database.
type planSet struct {
	plans map[int64]ansible.HostPlan
	errs  map[int64]error // a host whose stored parameters no longer pass the checks
	order map[int64][]int64
}

func (s *Server) planSet() (planSet, error) {
	hosts, err := store.ListHosts(s.db)
	if err != nil {
		return planSet{}, err
	}
	groups, err := store.ListGroups(s.db)
	if err != nil {
		return planSet{}, err
	}
	groupProfiles, hostProfiles, err := store.AllProfiles(s.db)
	if err != nil {
		return planSet{}, err
	}
	// A secret that is set again makes the roles that use it "changes waiting".
	versions, err := store.SecretVersions(s.db)
	if err != nil {
		return planSet{}, err
	}

	// The groups of a host, in the order of the groups' names (ListGroups sorts
	// them): of two groups that set the same parameter, the later one wins.
	memberOf := map[int64][]int64{}
	for _, g := range groups {
		for _, id := range g.HostIDs {
			memberOf[id] = append(memberOf[id], g.ID)
		}
	}
	ps := planSet{plans: map[int64]ansible.HostPlan{}, errs: map[int64]error{}, order: memberOf}
	for _, h := range hosts {
		var profiles [][]ansible.ProfileRole
		for _, gid := range memberOf[h.ID] {
			if p := groupProfiles[gid]; len(p) > 0 {
				profiles = append(profiles, p)
			}
		}
		plan, err := ansible.BuildPlanWith(profiles, hostProfiles[h.ID], versions)
		if err != nil {
			ps.errs[h.ID] = err
			continue
		}
		ps.plans[h.ID] = plan
	}
	return ps, nil
}

// ------------------------------------------------------------------- the state

// The configuration state of a host, as Hosts and Overview show it.
const (
	configNone      = "none"            // no profile: nothing to apply
	configNever     = "never_applied"   // it has roles and has never been configured
	configApplied   = "applied"         // everything in its profile has been applied
	configDrifted   = "drifted"         // applied, but changed outside the dashboard (IM9 compliance check)
	configFailed    = "failed"          // the last run did not work
	configWaiting   = "changes_waiting" // its profile (or the role's files) changed since it was applied
	configInvalid   = "invalid"         // its stored parameters do not pass the checks any more
	idempotentUnset = -1
)

type configView struct {
	State      string   `json:"state"`
	Roles      []string `json:"roles"`
	RunAt      int64    `json:"run_at,omitempty"`
	Detail     string   `json:"detail,omitempty"`
	Idempotent *bool    `json:"idempotent,omitempty"` // what Check again found, when it was run
	Drift      []change `json:"drift,omitempty"`      // profile drift changes from last compliance check (IM9)
}

// stateOf works the state out from the plan, what was applied and how the last
// run went. Nothing is run to find out: "changes waiting" is a comparison of
// fingerprints.
func stateOf(plan ansible.HostPlan, planErr error, applied map[string]string, hc store.HostConfig) configView {
	v := configView{State: configNone, Roles: plan.Roles, RunAt: hc.RunAt, Detail: hc.Detail}
	if v.Roles == nil {
		v.Roles = []string{}
	}
	if hc.Idempotent != idempotentUnset && hc.Result == "ok" {
		yes := hc.Idempotent == 1
		v.Idempotent = &yes
	}

	switch {
	case planErr != nil:
		v.State, v.Detail = configInvalid, planErr.Error()
	case len(plan.Roles) == 0:
		v.State = configNone
	case hc.Result == "failed":
		v.State = configFailed
	case len(applied) == 0:
		v.State = configNever
	default:
		v.State = configApplied
		for _, role := range plan.Roles {
			if applied[role] != plan.Hashes[role] {
				v.State = configWaiting
				break
			}
		}
	}
	if v.State != configFailed && v.State != configInvalid {
		v.Detail = ""
	}
	return v
}

// configViews is the state of every host, by host id.
func (s *Server) configViews() (map[int64]configView, planSet, error) {
	ps, err := s.planSet()
	if err != nil {
		return nil, ps, err
	}
	applied, err := store.AppliedRoles(s.db)
	if err != nil {
		return nil, ps, err
	}
	configs, err := store.AllHostConfig(s.db)
	if err != nil {
		return nil, ps, err
	}
	hosts, err := store.ListHosts(s.db)
	if err != nil {
		return nil, ps, err
	}
	views := map[int64]configView{}
	for _, h := range hosts {
		hc, ok := configs[h.ID]
		if !ok {
			hc.Idempotent = idempotentUnset
		}
		cv := stateOf(ps.plans[h.ID], ps.errs[h.ID], applied[h.ID], hc)
		if cv.State == configApplied {
			if drift := s.hostComplianceDrift(h.ID); len(drift) > 0 {
				cv.State = configDrifted
				cv.Drift = drift
			}
		}
		views[h.ID] = cv
	}
	return views, ps, nil
}

// ------------------------------------------------------------- profile API

func (s *Server) library(w http.ResponseWriter, r *http.Request, me store.User) {
	writeJSON(w, http.StatusOK, map[string]any{"roles": ansible.Library})
}

type profileBody struct {
	Roles []ansible.ProfileRole `json:"roles"`
}

func roleNames(roles []ansible.ProfileRole) string {
	if len(roles) == 0 {
		return "no roles"
	}
	names := make([]string, len(roles))
	for i, r := range roles {
		names[i] = r.Role
	}
	return strings.Join(names, ", ")
}

func (s *Server) groupProfile(w http.ResponseWriter, r *http.Request, me store.User) {
	g, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	roles, err := store.GetProfile(s.db, store.ScopeGroup, g.ID)
	if err != nil {
		serverError(w, "read the profile", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

func (s *Server) setGroupProfile(w http.ResponseWriter, r *http.Request, me store.User) {
	g, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	s.saveProfile(w, r, me, store.ScopeGroup, g.ID, "group.profile", "group "+g.Name)
}

// hostProfile is the host's own profile, and what comes to it from its groups,
// so that the form can say where the rest of its roles come from.
func (s *Server) hostProfile(w http.ResponseWriter, r *http.Request, me store.User) {
	h, ok := s.loadHost(w, r)
	if !ok {
		return
	}
	own, err := store.GetProfile(s.db, store.ScopeHost, h.ID)
	if err != nil {
		serverError(w, "read the profile", err)
		return
	}
	type inherited struct {
		Group string   `json:"group"`
		Roles []string `json:"roles"`
	}
	from := []inherited{}
	groups, err := store.ListGroups(s.db)
	if err != nil {
		serverError(w, "list groups", err)
		return
	}
	for _, g := range groups {
		for _, id := range g.HostIDs {
			if id != h.ID {
				continue
			}
			profile, err := store.GetProfile(s.db, store.ScopeGroup, g.ID)
			if err != nil {
				serverError(w, "read the profile", err)
				return
			}
			if len(profile) > 0 {
				names := make([]string, len(profile))
				for i, pr := range profile {
					names[i] = pr.Role
				}
				from = append(from, inherited{Group: g.Name, Roles: names})
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": own, "inherited": from})
}

func (s *Server) setHostProfile(w http.ResponseWriter, r *http.Request, me store.User) {
	h, ok := s.loadHost(w, r)
	if !ok {
		return
	}
	s.saveProfile(w, r, me, store.ScopeHost, h.ID, "host.profile", "host "+h.Name)
}

func (s *Server) saveProfile(w http.ResponseWriter, r *http.Request, me store.User, scope string, id int64, action, target string) {
	var req profileBody
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Roles) > len(ansible.Library) {
		s.failHost(w, r, me, action, target, http.StatusBadRequest, "There are more roles than the library has.")
		return
	}
	cleaned, err := ansible.CheckProfile(req.Roles)
	if err != nil {
		s.failHost(w, r, me, action, target, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.checkSecretsExist(secretRefsInProfile(cleaned)); err != nil {
		s.groupFailed(w, r, me, action, target, err)
		return
	}
	if err := store.SetProfile(s.db, scope, id, cleaned); err != nil {
		s.groupFailed(w, r, me, action, target, err)
		return
	}
	// What is written down is the roles, not their parameters.
	s.record(r, me, action, target, store.ResultOK, roleNames(cleaned))
	w.WriteHeader(http.StatusNoContent)
}

// ----------------------------------------------------- what to configure

type skip struct {
	Host   string `json:"host"`
	Reason string `json:"reason"`
}

// targetSet is what a request to configure comes down to: the hosts that will
// be configured, the roles each gets, and what was left out and why.
type targetSet struct {
	Label     string // "group web" or "host web-1", for History
	Hosts     []store.Host
	Roles     map[string][]string // host name → the roles that will run on it
	Hashes    map[int64]map[string]string
	Skipped   []skip                      // hosts that will not be configured at all
	Notes     []skip                      // a role left out of a host
	Overrides map[string]ansible.HostPlan // by host name: the plan as it will be applied

	// What to run on them. The profiles' playbook is the default; Update
	// packages, Access and the custom playbooks set their own (execute fills in
	// the rest).
	Playbook     string // site.yml, patch.yml, access.yml or custom/<name>.yml
	Role         string // one role alone (site.yml only)
	Serial       int    // hosts at a time; 0 is all at once
	ActionPrefix string // History: "config", "patch", "access" or "playbook"
	Access       map[string]ansible.HostAccess
	// Done is called after a real run with how it went on each host, and may add
	// fields to the answer. The profiles' playbook needs none: its outcome is
	// written to the host's config record.
	Done func(hosts []hostRun) map[string]any
}

type reqError struct {
	status int
	msg    string
}

func (e *reqError) Error() string { return e.msg }

// candidates are the hosts a request is about: one host, or the members of one
// group (exactly one of the ids), with the label History uses.
func (s *Server) candidates(groupID, hostID int64) (string, []store.Host, *reqError) {
	switch {
	case hostID > 0 && groupID == 0:
		h, err := store.GetHost(s.db, hostID)
		if err != nil {
			return "", nil, &reqError{http.StatusNotFound, "There is no such host."}
		}
		return "host " + h.Name, []store.Host{h}, nil
	case groupID > 0 && hostID == 0:
		g, err := store.GetGroup(s.db, groupID)
		if err != nil {
			return "", nil, &reqError{http.StatusNotFound, "There is no such group."}
		}
		hosts, err := store.ListHosts(s.db)
		if err != nil {
			return "", nil, &reqError{http.StatusInternalServerError, "Something went wrong on the server."}
		}
		in := map[int64]bool{}
		for _, id := range g.HostIDs {
			in[id] = true
		}
		var members []store.Host
		for _, h := range hosts {
			if in[h.ID] {
				members = append(members, h)
			}
		}
		return "group " + g.Name, members, nil
	}
	return "", nil, &reqError{http.StatusBadRequest, "Pick one host or one group."}
}

// targets works out what a request to configure is about. preflight is for a
// real run: the dashboard logs in to each host that is about to get SSH
// hardening, to be sure its key works, because that is the one role that can
// lock a person out.
func (s *Server) targets(groupID, hostID int64, role string, preflight bool) (targetSet, *reqError) {
	ts := targetSet{Roles: map[string][]string{}, Hashes: map[int64]map[string]string{}, Overrides: map[string]ansible.HostPlan{}}
	if role != "" {
		if _, ok := ansible.FindRole(role); !ok {
			return ts, &reqError{http.StatusBadRequest, "There is no such role."}
		}
	}

	label, candidates, rerr := s.candidates(groupID, hostID)
	if rerr != nil {
		return ts, rerr
	}
	ts.Label = label

	ps, err := s.planSet()
	if err != nil {
		return ts, &reqError{http.StatusInternalServerError, "Something went wrong on the server."}
	}
	for _, h := range candidates {
		if perr := ps.errs[h.ID]; perr != nil {
			ts.Skipped = append(ts.Skipped, skip{h.Name, "its profile is not valid any more: " + perr.Error()})
			continue
		}
		plan := ps.plans[h.ID]
		if len(plan.Roles) == 0 {
			ts.Skipped = append(ts.Skipped, skip{h.Name, "it has no profile, from itself or its groups"})
			continue
		}
		if role != "" && !plan.Has(role) {
			ts.Skipped = append(ts.Skipped, skip{h.Name, "its profile does not have the role " + role})
			continue
		}
		if !canRoot(h) {
			ts.Skipped = append(ts.Skipped, skip{h.Name, "the dashboard has no sudo on it, so Ansible cannot become root. Edit the host and allow sudo without a password"})
			continue
		}

		effective := plan
		if plan.Has("ssh_hardening") && (role == "" || role == "ssh_hardening") {
			if reason := s.sshHardeningBlocked(h, plan, preflight); reason != "" {
				effective = plan.Without("ssh_hardening")
				ts.Notes = append(ts.Notes, skip{h.Name, "SSH hardening was left out: " + reason})
			}
		}
		run := effective.Roles
		if role != "" {
			run = nil
			if effective.Has(role) {
				run = []string{role}
			}
		}
		if len(run) == 0 {
			ts.Skipped = append(ts.Skipped, skip{h.Name, "nothing is left to apply to it"})
			continue
		}

		ts.Hosts = append(ts.Hosts, h)
		ts.Roles[h.Name] = run
		ts.Hashes[h.ID] = map[string]string{}
		for _, r := range run {
			ts.Hashes[h.ID][r] = effective.Hashes[r]
		}
		ts.Overrides[h.Name] = effective
	}
	sort.Slice(ts.Hosts, func(i, j int) bool { return ts.Hosts[i].Name < ts.Hosts[j].Name })
	return ts, nil
}

// sshHardeningBlocked says why SSH hardening must not be applied to a host right
// now, or "" when it may. It can lock the dashboard out in two ways: by turning
// off root login on a host the dashboard logs in to as root, and on a host the
// dashboard cannot log in to with its key at all (it would be applied through
// some other way in, and then be the only door). The first is known from the
// host's record; the second is tested, right now, by logging in.
func (s *Server) sshHardeningBlocked(h store.Host, plan ansible.HostPlan, preflight bool) string {
	if h.User == "root" && plan.Params["ssh_hardening"]["ssh_disable_root"] == true {
		return "the dashboard logs in to this host as root, so turning off root login would lock it out. Add a user with the users role and edit the host to use it first"
	}
	if preflight {
		if _, err := s.remote.Probe(targetOf(h), false); err != nil {
			return "the dashboard could not log in with its key just now (" + firstLine(strings.TrimSpace(fmt.Sprint(err))) + ")"
		}
	}
	return ""
}
