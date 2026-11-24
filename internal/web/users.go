package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"infra-manager/internal/store"
)

// The Users page. Every handler here is behind ActionManageUsers, so only an
// admin gets this far (see routes() and can()).

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request, me store.User) {
	users, err := store.ListUsers(s.db)
	if err != nil {
		serverError(w, "list users", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request, me store.User) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !readJSON(w, r, &req) {
		return
	}

	u, err := store.CreateUser(s.db, req.Username, req.Password, req.Role)
	target := store.User{Username: store.NormalizeUsername(req.Username)}
	if err == nil {
		s.record(r, me, "user.create", "user "+u.Username, store.ResultOK, "role "+u.Role)
		writeJSON(w, http.StatusCreated, u)
		return
	}
	s.failUserChange(w, r, me, "user.create", target, err)
}

func (s *Server) setUserRole(w http.ResponseWriter, r *http.Request, me store.User) {
	target, ok := s.loadTarget(w, r)
	if !ok {
		return
	}
	var req struct {
		Role string `json:"role"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if s.refuseSelf(w, r, me, target, "user.role", "You cannot change your own role. Ask another admin.") {
		return
	}

	if err := store.SetRole(s.db, target.ID, req.Role); err != nil {
		s.failUserChange(w, r, me, "user.role", target, err)
		return
	}
	s.record(r, me, "user.role", "user "+target.Username, store.ResultOK, target.Role+" → "+req.Role)
	w.WriteHeader(http.StatusNoContent)
}

// resetUserPassword is an admin setting somebody else's password, for someone
// who forgot it. It ends all of that person's sessions: whoever had the old
// password (or a stolen session) is out.
func (s *Server) resetUserPassword(w http.ResponseWriter, r *http.Request, me store.User) {
	target, ok := s.loadTarget(w, r)
	if !ok {
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	// Your own password is changed on Profile, which asks for the current one: a
	// session left open on a shared screen must not be enough to take the account.
	if s.refuseSelf(w, r, me, target, "user.password.reset", "Change your own password on your Profile page.") {
		return
	}

	if err := store.SetPassword(s.db, target.ID, req.Password); err != nil {
		s.failUserChange(w, r, me, "user.password.reset", target, err)
		return
	}
	if err := store.DeleteUserSessions(s.db, target.ID); err != nil {
		serverError(w, "end the sessions", err)
		return
	}
	s.record(r, me, "user.password.reset", "user "+target.Username, store.ResultOK, "their sessions were ended")
	w.WriteHeader(http.StatusNoContent)
}

// resetUserTOTP clears somebody else's authenticator and ends all of their
// sessions, so they enroll a new authenticator app on their next login.
func (s *Server) resetUserTOTP(w http.ResponseWriter, r *http.Request, me store.User) {
	target, ok := s.loadTarget(w, r)
	if !ok {
		return
	}
	if s.refuseSelf(w, r, me, target, "user.totp.reset", "Reset your own authenticator on your Profile page.") {
		return
	}

	if err := store.ResetTOTP(s.db, target.ID); err != nil {
		s.failUserChange(w, r, me, "user.totp.reset", target, err)
		return
	}
	s.record(r, me, "user.totp.reset", "user "+target.Username, store.ResultOK, "their sessions were ended")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) disableUser(w http.ResponseWriter, r *http.Request, me store.User) {
	target, ok := s.loadTarget(w, r)
	if !ok {
		return
	}
	if s.refuseSelf(w, r, me, target, "user.disable", "You cannot disable yourself.") {
		return
	}

	if err := store.SetDisabled(s.db, target.ID, true); err != nil {
		s.failUserChange(w, r, me, "user.disable", target, err)
		return
	}
	s.record(r, me, "user.disable", "user "+target.Username, store.ResultOK, "their sessions were ended")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) enableUser(w http.ResponseWriter, r *http.Request, me store.User) {
	target, ok := s.loadTarget(w, r)
	if !ok {
		return
	}
	if err := store.SetDisabled(s.db, target.ID, false); err != nil {
		s.failUserChange(w, r, me, "user.enable", target, err)
		return
	}
	s.record(r, me, "user.enable", "user "+target.Username, store.ResultOK, "")
	w.WriteHeader(http.StatusNoContent)
}

// loadTarget finds the user a route is about, from its {id}.
func (s *Server) loadTarget(w http.ResponseWriter, r *http.Request) (store.User, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusNotFound, "There is no such user.")
		return store.User{}, false
	}
	u, err := store.GetUser(s.db, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "There is no such user.")
		return store.User{}, false
	}
	if err != nil {
		serverError(w, "read the user", err)
		return store.User{}, false
	}
	return u, true
}

// refuseSelf stops an admin from doing to their own account what could lock
// them out (or, for the last admin, lock everybody out). The refusal is a line
// of History like any other.
func (s *Server) refuseSelf(w http.ResponseWriter, r *http.Request, me, target store.User, action, message string) bool {
	if target.ID != me.ID {
		return false
	}
	s.record(r, me, action, "user "+target.Username, store.ResultRefused, message)
	writeError(w, http.StatusConflict, message)
	return true
}

// failUserChange answers a change that did not happen, and writes it to
// History: "refused" when a rule stopped it, "failed" when the input was wrong.
func (s *Server) failUserChange(w http.ResponseWriter, r *http.Request, me store.User, action string, target store.User, err error) {
	name := "user " + target.Username
	var status int
	result := store.ResultFailed
	switch {
	case errors.Is(err, store.ErrLastAdmin):
		status, result = http.StatusConflict, store.ResultRefused
	case errors.Is(err, store.ErrUsernameTaken):
		status = http.StatusConflict
	case errors.Is(err, store.ErrInvalidUsername), errors.Is(err, store.ErrInvalidPassword), errors.Is(err, store.ErrInvalidRole):
		status = http.StatusBadRequest
	case errors.Is(err, store.ErrNotFound):
		status = http.StatusNotFound
	default:
		s.record(r, me, action, name, store.ResultFailed, "an internal error")
		serverError(w, fmt.Sprintf("%s %s", action, name), err)
		return
	}
	s.record(r, me, action, name, result, err.Error())
	writeError(w, status, err.Error())
}
