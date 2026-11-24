package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"infra-manager/internal/store"
)

const sessionCookie = "infra_session"

// dummyHash is a valid bcrypt hash of a password nobody has, made on first use.
var dummyHash = sync.OnceValue(func() string {
	// Cannot fail: the input is short and the cost is the default.
	hash, _ := bcrypt.GenerateFromPassword([]byte("not a real password"), bcrypt.DefaultCost)
	return string(hash)
})

func setSessionCookie(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:  sessionCookie,
		Value: token,
		Path:  "/",
		// A MaxAge below 0 deletes the cookie in the browser (logout).
		MaxAge: maxAge,
		// JavaScript cannot read an HttpOnly cookie, so a script injected into the
		// page still cannot steal the session.
		HttpOnly: true,
		// Always Secure: the dashboard is only ever reached over HTTPS, through
		// Caddy (the server itself speaks plain HTTP to Caddy, so it cannot look at
		// the connection to decide). Chrome and Firefox also keep a Secure cookie
		// for http://127.0.0.1 and localhost, which is how it is tried out locally.
		Secure: true,
		// Strict: the browser does not send the cookie on any request that
		// another site starts, not even by following a link. A second layer behind
		// the Origin check of Secure().
		SameSite: http.SameSiteStrictMode,
	})
}

// sessionUser finds the person behind the request's cookie: store.ErrNotFound
// when there is none.
func (s *Server) sessionUser(r *http.Request) (store.User, error) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return store.User{}, store.ErrNotFound
	}
	return store.SessionUser(s.db, cookie.Value, s.now())
}

// sessionToken is the token of the session this request is using.
func sessionToken(r *http.Request) string {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		return cookie.Value
	}
	return ""
}

var errBusy = errors.New("the server is busy")

// checkPassword compares a password with a bcrypt hash, a few at a time (see
// Server.checks). The error is only about waiting, never about the password.
func (s *Server) checkPassword(r *http.Request, hash, password string) (bool, error) {
	select {
	case s.checks <- struct{}{}:
	case <-r.Context().Done():
		return false, r.Context().Err()
	case <-time.After(10 * time.Second):
		return false, errBusy
	}
	defer func() { <-s.checks }()
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil, nil
}

// refuseWhileLimited answers 429 when a key has to wait, and says so. It also
// counts the attempt (see loginLimiter.begin).
func refuseWhileLimited(w http.ResponseWriter, l *loginLimiter, key string) bool {
	wait := l.begin(key)
	if wait <= 0 {
		return false
	}
	seconds := int((wait + time.Second - 1) / time.Second) // round up
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	writeError(w, http.StatusTooManyRequests, fmt.Sprintf("Too many failed attempts. Try again in %d seconds.", seconds))
	return true
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !readJSON(w, r, &req) {
		return
	}

	// Before any work: a blocked attempt must be cheap, and it is refused even
	// when the password happens to be right. Not written to History (a flood of
	// blocked attempts would fill it): the log of the server has it.
	ip := clientIP(r)
	if refuseWhileLimited(w, s.loginLimit, ip) {
		return
	}

	user, hash, err := store.FindForLogin(s.db, req.Username)
	found := err == nil
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		serverError(w, "look up the user", err)
		return
	}
	if !found {
		// Compare against a dummy hash anyway. Otherwise "no such user" would answer
		// in 1 ms and "wrong password" in 50 ms, and the difference would tell an
		// attacker which user names exist.
		hash = dummyHash()
	}
	right, err := s.checkPassword(r, hash, req.Password)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "The server is busy. Try again in a moment.")
		return
	}

	if !found || !right || user.Disabled {
		// One message for every reason, so the answer reveals neither which user
		// names exist nor which accounts are disabled, nor their OTP state.
		// The name typed is not written down: people sometimes type their password
		// into that field.
		if found && right {
			s.recordCapped(r, user, "login", store.ResultRefused, "the account is disabled")
		} else {
			s.recordCapped(r, store.User{}, "login", store.ResultRefused, "wrong user name or password")
		}
		writeError(w, http.StatusUnauthorized, "Wrong user name or password.")
		return
	}

	// Mandatory TOTP (RFC 6238) for every account. Only reached after password
	// verification, so wrong credentials never leak enrollment status.
	secret, enabled, err := store.EnsureTOTPSecret(s.db, user.ID)
	if err != nil {
		serverError(w, "load authenticator state", err)
		return
	}

	now := s.now()
	code := strings.TrimSpace(req.Code)
	if enabled {
		if code == "" {
			s.loginLimit.undo(ip)
			writeJSON(w, http.StatusOK, map[string]any{"totp_required": true})
			return
		}
		step, ok := store.VerifyTOTP(secret, code, now)
		if !ok {
			s.recordCapped(r, user, "login", store.ResultRefused, "invalid one-time code")
			writeError(w, http.StatusUnauthorized, "That one-time code is not valid.")
			return
		}
		used, err := store.UseTOTPStep(s.db, user.ID, step)
		if err != nil {
			serverError(w, "record one-time code", err)
			return
		}
		if !used {
			s.recordCapped(r, user, "login", store.ResultRefused, "one-time code already used")
			writeError(w, http.StatusUnauthorized, "That one-time code is not valid.")
			return
		}
	} else {
		if code == "" {
			s.loginLimit.undo(ip)
			writeJSON(w, http.StatusOK, map[string]any{
				"totp_setup":  true,
				"secret":      secret,
				"otpauth_uri": store.TOTPURI(store.TOTPIssuer, user.Username, secret),
			})
			return
		}
		step, ok := store.VerifyTOTP(secret, code, now)
		if !ok {
			s.recordCapped(r, user, "login", store.ResultRefused, "invalid one-time code during setup")
			writeError(w, http.StatusUnauthorized, "That one-time code is not valid.")
			return
		}
		if err := store.EnableTOTP(s.db, user.ID, step); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				s.recordCapped(r, user, "login", store.ResultRefused, "one-time code already used")
				writeError(w, http.StatusUnauthorized, "That one-time code is not valid.")
				return
			}
			serverError(w, "enable authenticator", err)
			return
		}
		user.TOTPEnabled = true
		s.record(r, user, "totp.enable", "", store.ResultOK, "")
	}

	token, err := store.CreateSession(s.db, user.ID, ip, r.UserAgent(), now)
	if err != nil {
		serverError(w, "create a session", err)
		return
	}
	s.loginLimit.reset(ip)
	setSessionCookie(w, token, int(store.SessionLifetime.Seconds()))
	s.record(r, user, "login", "", store.ResultOK, "")
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, me store.User) {
	// The session is deleted on the server, not only the cookie in the browser:
	// a copied cookie must stop working too.
	if err := store.DeleteSession(s.db, sessionToken(r)); err != nil {
		serverError(w, "log out", err)
		return
	}
	setSessionCookie(w, "", -1)
	s.record(r, me, "logout", "", store.ResultOK, "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request, me store.User) {
	writeJSON(w, http.StatusOK, me)
}
