package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"infra-manager/internal/ansible"
	"infra-manager/internal/store"
)

// Groups, and the variables of groups and hosts. What is written here is the
// source of the generated Ansible files (ansible.go renders them).

type groupHost struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type groupView struct {
	ID        int64       `json:"id"`
	Name      string      `json:"name"`
	Hosts     []groupHost `json:"hosts"`
	CreatedAt int64       `json:"created_at"`
}

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request, me store.User) {
	groups, err := store.ListGroups(s.db)
	if err != nil {
		serverError(w, "list groups", err)
		return
	}
	hosts, err := store.ListHosts(s.db)
	if err != nil {
		serverError(w, "list hosts", err)
		return
	}
	names := map[int64]string{}
	for _, h := range hosts {
		names[h.ID] = h.Name
	}
	views := make([]groupView, len(groups))
	for i, g := range groups {
		views[i] = groupView{ID: g.ID, Name: g.Name, CreatedAt: g.CreatedAt, Hosts: []groupHost{}}
		for _, id := range g.HostIDs {
			views[i].Hosts = append(views[i].Hosts, groupHost{ID: id, Name: names[id]})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": views})
}

func (s *Server) loadGroup(w http.ResponseWriter, r *http.Request) (store.Group, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusNotFound, "There is no such group.")
		return store.Group{}, false
	}
	g, err := store.GetGroup(s.db, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "There is no such group.")
		return store.Group{}, false
	}
	if err != nil {
		serverError(w, "read the group", err)
		return store.Group{}, false
	}
	return g, true
}

// groupFailed answers a group change that did not happen, and writes it to History.
func (s *Server) groupFailed(w http.ResponseWriter, r *http.Request, me store.User, action, target string, err error) {
	status := http.StatusBadRequest
	var refused ansible.CheckError
	switch {
	case errors.Is(err, store.ErrGroupNameTaken), errors.Is(err, store.ErrNameIsHost), errors.Is(err, store.ErrNameIsGroup), errors.Is(err, store.ErrNameIsMachine):
		status = http.StatusConflict
	case errors.Is(err, store.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, ansible.ErrBadGroupName), errors.Is(err, ansible.ErrReservedName), errors.Is(err, ansible.ErrBadVarKey), errors.Is(err, ansible.ErrVarValue), errors.As(err, &refused):
		// something the person typed: 400, and the sentence says what
	default:
		s.record(r, me, action, target, store.ResultFailed, "an internal error")
		serverError(w, action, err)
		return
	}
	s.failHost(w, r, me, action, target, status, err.Error())
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request, me store.User) {
	var req struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	name := strings.ToLower(strings.TrimSpace(req.Name))
	target := "group " + name
	if err := ansible.CheckGroupName(name); err != nil {
		s.groupFailed(w, r, me, "group.create", target, err)
		return
	}
	g, err := store.CreateGroup(s.db, name, time.Now())
	if err != nil {
		s.groupFailed(w, r, me, "group.create", target, err)
		return
	}
	s.record(r, me, "group.create", target, store.ResultOK, "")
	writeJSON(w, http.StatusCreated, groupView{ID: g.ID, Name: g.Name, CreatedAt: g.CreatedAt, Hosts: []groupHost{}})
}

func (s *Server) renameGroup(w http.ResponseWriter, r *http.Request, me store.User) {
	g, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	name := strings.ToLower(strings.TrimSpace(req.Name))
	target := "group " + g.Name
	if err := ansible.CheckGroupName(name); err != nil {
		s.groupFailed(w, r, me, "group.rename", target, err)
		return
	}
	if err := store.RenameGroup(s.db, g.ID, name); err != nil {
		s.groupFailed(w, r, me, "group.rename", target, err)
		return
	}
	s.record(r, me, "group.rename", target, store.ResultOK, g.Name+" → "+name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request, me store.User) {
	g, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	if err := store.DeleteGroup(s.db, g.ID); err != nil {
		s.groupFailed(w, r, me, "group.delete", "group "+g.Name, err)
		return
	}
	s.record(r, me, "group.delete", "group "+g.Name, store.ResultOK, fmt.Sprintf("%d hosts were in it (they are not touched)", len(g.HostIDs)))
	w.WriteHeader(http.StatusNoContent)
}

// changeGroupHosts adds and removes several hosts at once, all or none.
func (s *Server) changeGroupHosts(w http.ResponseWriter, r *http.Request, me store.User) {
	g, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	var req struct {
		Add    []int64 `json:"add"`
		Remove []int64 `json:"remove"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	target := "group " + g.Name
	if len(req.Add)+len(req.Remove) > 500 {
		s.failHost(w, r, me, "group.hosts", target, http.StatusBadRequest, "That is too many hosts at once.")
		return
	}
	if err := store.ChangeGroupHosts(s.db, g.ID, req.Add, req.Remove); err != nil {
		s.groupFailed(w, r, me, "group.hosts", target, err)
		return
	}
	s.record(r, me, "group.hosts", target, store.ResultOK,
		fmt.Sprintf("%d added, %d removed", len(req.Add), len(req.Remove)))
	w.WriteHeader(http.StatusNoContent)
}

// ------------------------------------------------------------------ variables

type varsBody struct {
	Vars []store.Var `json:"vars"`
}

// toAnsibleVars is for the checks, which live next to the files they protect.
func toAnsibleVars(vars []store.Var) []ansible.Var {
	out := make([]ansible.Var, len(vars))
	for i, v := range vars {
		out[i] = ansible.Var{Key: v.Key, Value: v.Value}
	}
	return out
}

// keyList is what History says about a change of variables: the names, never the
// values, which may be something not meant for every reader of History.
func keyList(vars []store.Var) string {
	if len(vars) == 0 {
		return "no variables"
	}
	keys := make([]string, len(vars))
	for i, v := range vars {
		keys[i] = v.Key
	}
	return fmt.Sprintf("%d variables: %s", len(vars), strings.Join(keys, ", "))
}

func (s *Server) groupVars(w http.ResponseWriter, r *http.Request, me store.User) {
	g, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	vars, err := store.GroupVars(s.db, g.ID)
	if err != nil {
		serverError(w, "read the variables", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"vars": vars})
}

func (s *Server) setGroupVars(w http.ResponseWriter, r *http.Request, me store.User) {
	g, ok := s.loadGroup(w, r)
	if !ok {
		return
	}
	var req varsBody
	if !readJSON(w, r, &req) {
		return
	}
	target := "group " + g.Name
	if len(req.Vars) > 100 {
		s.failHost(w, r, me, "group.vars", target, http.StatusBadRequest, "A group has at most 100 variables.")
		return
	}
	if err := ansible.CheckVars(toAnsibleVars(req.Vars)); err != nil {
		s.groupFailed(w, r, me, "group.vars", target, err)
		return
	}
	if err := s.checkSecretsExist(secretRefsInVars(req.Vars)); err != nil {
		s.groupFailed(w, r, me, "group.vars", target, err)
		return
	}
	if err := store.SetGroupVars(s.db, g.ID, req.Vars); err != nil {
		s.groupFailed(w, r, me, "group.vars", target, err)
		return
	}
	s.record(r, me, "group.vars", target, store.ResultOK, keyList(req.Vars))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) hostVars(w http.ResponseWriter, r *http.Request, me store.User) {
	h, ok := s.loadHost(w, r)
	if !ok {
		return
	}
	vars, err := store.HostVars(s.db, h.ID)
	if err != nil {
		serverError(w, "read the variables", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"vars": vars})
}

func (s *Server) setHostVars(w http.ResponseWriter, r *http.Request, me store.User) {
	h, ok := s.loadHost(w, r)
	if !ok {
		return
	}
	var req varsBody
	if !readJSON(w, r, &req) {
		return
	}
	target := "host " + h.Name
	if len(req.Vars) > 100 {
		s.failHost(w, r, me, "host.vars", target, http.StatusBadRequest, "A host has at most 100 variables.")
		return
	}
	if err := ansible.CheckVars(toAnsibleVars(req.Vars)); err != nil {
		s.groupFailed(w, r, me, "host.vars", target, err)
		return
	}
	if err := s.checkSecretsExist(secretRefsInVars(req.Vars)); err != nil {
		s.groupFailed(w, r, me, "host.vars", target, err)
		return
	}
	if err := store.SetHostVars(s.db, h.ID, req.Vars); err != nil {
		s.groupFailed(w, r, me, "host.vars", target, err)
		return
	}
	s.record(r, me, "host.vars", target, store.ResultOK, keyList(req.Vars))
	w.WriteHeader(http.StatusNoContent)
}
