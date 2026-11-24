package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"infra-manager/internal/store"
)

// A person's own account: ActionSelf, so every role may use it.

// changePassword needs the current password, so a session left open on a shared
// screen is not enough to take the account. It ends the person's other
// sessions (keeping the one in use): if the old password leaked, so may have a
// login made with it.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, me store.User) {
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !readJSON(w, r, &req) {
		return
	}

	// The same limiter as login, keyed by the person: a stolen session must not
	// be a way to guess the password at full speed.
	if refuseWhileLimited(w, s.loginLimit, "user:"+strconv.FormatInt(me.ID, 10)) {
		return
	}
	hash, err := store.PasswordHash(s.db, me.ID)
	if err != nil {
		serverError(w, "read the password hash", err)
		return
	}
	right, err := s.checkPassword(r, hash, req.Current)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "The server is busy. Try again in a moment.")
		return
	}
	if !right {
		s.record(r, me, "password.change", "", store.ResultRefused, "the current password was wrong")
		writeError(w, http.StatusBadRequest, "The current password is wrong.")
		return
	}
	s.loginLimit.reset("user:" + strconv.FormatInt(me.ID, 10))

	if err := store.SetPassword(s.db, me.ID, req.New); err != nil {
		if errors.Is(err, store.ErrInvalidPassword) {
			s.record(r, me, "password.change", "", store.ResultFailed, err.Error())
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		serverError(w, "change the password", err)
		return
	}
	ended, err := store.DeleteOtherSessions(s.db, me.ID, sessionToken(r))
	if err != nil {
		serverError(w, "end the other sessions", err)
		return
	}
	s.record(r, me, "password.change", "", store.ResultOK, fmt.Sprintf("%d other sessions ended", ended))
	writeJSON(w, http.StatusOK, map[string]any{"ended": ended})
}

// resetMyTOTP clears the signed-in person's authenticator so they enroll a new
// one on their next login. It requires both the current password and a valid
// (non-replayed) one-time code, ends all sessions, and clears the cookie.
func (s *Server) resetMyTOTP(w http.ResponseWriter, r *http.Request, me store.User) {
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !readJSON(w, r, &req) {
		return
	}

	limitKey := "user:" + strconv.FormatInt(me.ID, 10)
	if refuseWhileLimited(w, s.loginLimit, limitKey) {
		return
	}
	hash, err := store.PasswordHash(s.db, me.ID)
	if err != nil {
		serverError(w, "read the password hash", err)
		return
	}
	right, err := s.checkPassword(r, hash, req.Password)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "The server is busy. Try again in a moment.")
		return
	}
	if !right {
		s.record(r, me, "totp.reset", "", store.ResultRefused, "the current password was wrong")
		writeError(w, http.StatusBadRequest, "The current password is wrong.")
		return
	}

	secret, enabled, err := store.TOTPSecret(s.db, me.ID)
	if err != nil {
		serverError(w, "read authenticator state", err)
		return
	}
	if !enabled {
		s.record(r, me, "totp.reset", "", store.ResultRefused, "authenticator is not enabled")
		writeError(w, http.StatusBadRequest, "Two-factor authentication is not set up on this account.")
		return
	}
	step, ok := store.VerifyTOTP(secret, strings.TrimSpace(req.Code), s.now())
	if !ok {
		s.record(r, me, "totp.reset", "", store.ResultRefused, "invalid one-time code")
		writeError(w, http.StatusBadRequest, "That one-time code is not valid.")
		return
	}
	used, err := store.UseTOTPStep(s.db, me.ID, step)
	if err != nil {
		serverError(w, "record one-time code", err)
		return
	}
	if !used {
		s.record(r, me, "totp.reset", "", store.ResultRefused, "one-time code already used")
		writeError(w, http.StatusBadRequest, "That one-time code is not valid.")
		return
	}
	s.loginLimit.reset(limitKey)

	if err := store.ResetTOTP(s.db, me.ID); err != nil {
		serverError(w, "reset authenticator", err)
		return
	}
	setSessionCookie(w, "", -1)
	s.record(r, me, "totp.reset", "", store.ResultOK, "all sessions were ended")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) mySessions(w http.ResponseWriter, r *http.Request, me store.User) {
	list, err := store.ListSessions(s.db, me.ID, time.Now())
	if err != nil {
		serverError(w, "list sessions", err)
		return
	}
	current := store.TokenID(sessionToken(r))

	type view struct {
		store.Session
		Current bool `json:"current"`
	}
	out := make([]view, len(list))
	for i, sess := range list {
		out[i] = view{Session: sess, Current: sess.ID == current}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func (s *Server) revokeOtherSessions(w http.ResponseWriter, r *http.Request, me store.User) {
	ended, err := store.DeleteOtherSessions(s.db, me.ID, sessionToken(r))
	if err != nil {
		serverError(w, "end the other sessions", err)
		return
	}
	s.record(r, me, "sessions.revoke_others", "", store.ResultOK, fmt.Sprintf("%d sessions ended", ended))
	writeJSON(w, http.StatusOK, map[string]any{"ended": ended})
}
