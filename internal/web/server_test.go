package web

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"infra-manager/internal/remote"
	"infra-manager/internal/store"
)

const testPassword = "correct horse battery"

type testApp struct {
	t   *testing.T
	s   *Server
	mux *http.ServeMux
	db  *sql.DB
	dir string // the data directory: the database and the keys are in it
	rem *remote.Remote
	// stubs is a folder on PATH with stand-ins for Ansible's programs (installStub).
	stubs string
}

func newTestApp(t *testing.T) *testApp {
	t.Helper()
	dir := t.TempDir()
	db, err := store.OpenDB(filepath.Join(dir, store.DBFile))
	if err != nil {
		t.Fatal(err)
	}
	// Closed before the temp folder is removed: Windows cannot delete an open file.
	t.Cleanup(func() { db.Close() })
	rem, err := remote.Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, rem)
	mux := http.NewServeMux()
	s.Routes(mux)
	return &testApp{t: t, s: s, mux: mux, db: db, dir: dir, rem: rem}
}

// user makes a user and a logged-in session for them, without going through
// the login page (which has its own test).
func (a *testApp) user(name, role string) (store.User, *http.Cookie) {
	a.t.Helper()
	u, err := store.CreateUser(a.db, name, testPassword, role)
	if err != nil {
		a.t.Fatal(err)
	}
	return u, a.session(u)
}

func (a *testApp) session(u store.User) *http.Cookie {
	a.t.Helper()
	token, err := store.CreateSession(a.db, u.ID, "192.0.2.9", "test", a.s.now())
	if err != nil {
		a.t.Fatal(err)
	}
	return &http.Cookie{Name: sessionCookie, Value: token}
}

// loginWithTOTP completes a full login (handling first-time TOTP enrollment
// automatically) and returns the session cookie and TOTP secret.
func (a *testApp) loginWithTOTP(username, password, secret string) (*http.Cookie, string) {
	a.t.Helper()
	rec := a.do("POST", "/api/login", nil, map[string]string{"username": username, "password": password})
	want(a.t, rec, http.StatusOK)
	if len(rec.Result().Cookies()) != 0 {
		a.t.Fatal("step 1 login set a cookie before OTP verification")
	}
	var step1 struct {
		TOTPSetup    bool   `json:"totp_setup"`
		TOTPRequired bool   `json:"totp_required"`
		Secret       string `json:"secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &step1); err != nil {
		a.t.Fatalf("decode step 1 login: %v (%s)", err, rec.Body.String())
	}
	if step1.TOTPSetup {
		secret = step1.Secret
	} else if !step1.TOTPRequired {
		a.t.Fatalf("expected totp_setup or totp_required, got: %s", rec.Body.String())
	}
	code, err := store.TOTPCode(secret, a.s.now())
	if err != nil {
		a.t.Fatalf("TOTPCode: %v", err)
	}
	rec2 := a.do("POST", "/api/login", nil, map[string]string{"username": username, "password": password, "code": code})
	want(a.t, rec2, http.StatusOK)
	for _, c := range rec2.Result().Cookies() {
		if c.Name == sessionCookie {
			return c, secret
		}
	}
	a.t.Fatal("no session cookie after OTP login")
	return nil, secret
}

// do sends a request straight to the routes (the cross-site check of Secure has
// its own test). body, if not nil, is sent as JSON.
func (a *testApp) do(method, path string, cookie *http.Cookie, body any) *httptest.ResponseRecorder {
	a.t.Helper()
	var reader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			a.t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	a.mux.ServeHTTP(rec, req)
	return rec
}

func (a *testApp) events() []store.Event {
	a.t.Helper()
	events, err := store.ListEvents(a.db, 0, 200)
	if err != nil {
		a.t.Fatal(err)
	}
	return events
}

// has reports whether History has a line like this.
func (a *testApp) has(action, result string) bool {
	for _, e := range a.events() {
		if e.Action == action && e.Result == result {
			return true
		}
	}
	return false
}

func want(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	if rec.Code != status {
		t.Errorf("status %d, want %d (body %s)", rec.Code, status, strings.TrimSpace(rec.Body.String()))
	}
}

// routeRequest turns a route's pattern into a method and a path to call.
func routeRequest(pattern string) (method, path string) {
	method, path = http.MethodGet, pattern
	if m, p, ok := strings.Cut(pattern, " "); ok {
		method, path = m, p
	}
	path = strings.ReplaceAll(path, "{id}", "1")
	path = strings.ReplaceAll(path, "{name}", "x")
	if path == "/api/" {
		path = "/api/anything"
	}
	return method, path
}

// "Without login, every /api/* answers 401": the test walks the route table
// itself, so a route added later is checked without anyone remembering to.
func TestEveryAPIRouteNeedsALogin(t *testing.T) {
	a := newTestApp(t)

	checked := 0
	for _, rt := range a.s.routes() {
		if rt.public {
			continue
		}
		method, path := routeRequest(rt.pattern)
		want(t, a.do(method, path, nil, nil), http.StatusUnauthorized)
		// A cookie that is not a session is no login either.
		want(t, a.do(method, path, &http.Cookie{Name: sessionCookie, Value: "forged"}, nil), http.StatusUnauthorized)
		checked++
	}
	if checked < 10 {
		t.Fatalf("only %d routes were checked: is the route table being read?", checked)
	}
	// Each refusal is in History.
	n := 0
	for _, e := range a.events() {
		if e.Action == "unauthenticated" && e.Result == store.ResultRefused {
			n++
		}
	}
	// (Capped per minute, so a big enough route table is not all written down.)
	if wantLines := min(checked*2, anonymousPerMinute); n != wantLines {
		t.Errorf("%d unauthenticated lines in History, want %d", n, wantLines)
	}

	// An address that is no route at all is a 401 too, not a hint that it is not there.
	want(t, a.do("GET", "/api/nothing-here", nil, nil), http.StatusUnauthorized)
}

// "A viewer gets 403 on every change": every route, tried by each role that is
// below the one its action needs. The test reads the route table and the role
// table, so a route added later is held to them without anybody remembering to.
func TestEveryRouteRefusesRolesBelowItsAction(t *testing.T) {
	a := newTestApp(t)
	_, viewer := a.user("vera", store.RoleViewer)
	_, operator := a.user("otto", store.RoleOperator)
	_, admin := a.user("ada", store.RoleAdmin)
	below := map[string]*http.Cookie{store.RoleViewer: viewer, store.RoleOperator: operator}

	refused, adminOnly := 0, 0
	for _, rt := range a.s.routes() {
		if rt.public {
			continue
		}
		need := minRole[rt.action]
		if need == store.RoleAdmin {
			adminOnly++
		}
		method, path := routeRequest(rt.pattern)
		for role, cookie := range below {
			if roleRank[role] < roleRank[need] {
				want(t, a.do(method, path, cookie, map[string]string{}), http.StatusForbidden)
				refused++
			}
		}
	}
	if adminOnly < 10 || refused < 20 {
		t.Fatalf("only %d admin routes and %d refusals were checked: is the route table being read?", adminOnly, refused)
	}
	if !a.has(string(ActionManageUsers), store.ResultRefused) || !a.has(string(ActionManageHosts), store.ResultRefused) || !a.has(string(ActionOperate), store.ResultRefused) {
		t.Error("the refusals are not in History")
	}

	want(t, a.do("GET", "/api/users", admin, nil), http.StatusOK)
	want(t, a.do("GET", "/api/hosts", admin, nil), http.StatusOK)
	// Viewing and one's own profile are for every role.
	for _, c := range []*http.Cookie{viewer, operator, admin} {
		want(t, a.do("GET", "/api/history", c, nil), http.StatusOK)
		want(t, a.do("GET", "/api/me", c, nil), http.StatusOK)
	}
}

func TestLoginAndLogout(t *testing.T) {
	a := newTestApp(t)
	if _, err := store.CreateUser(a.db, "ada", testPassword, store.RoleAdmin); err != nil {
		t.Fatal(err)
	}

	for _, bad := range []map[string]string{
		{"username": "ada", "password": "wrong password!"},
		{"username": "nobody", "password": testPassword},
	} {
		rec := a.do("POST", "/api/login", nil, bad)
		want(t, rec, http.StatusUnauthorized)
		if len(rec.Result().Cookies()) != 0 {
			t.Error("a failed login set a cookie")
		}
		if strings.Contains(rec.Body.String(), "totp_") {
			t.Errorf("wrong credentials leaked OTP state: %s", rec.Body.String())
		}
	}
	if !a.has("login", store.ResultRefused) {
		t.Error("the failed logins are not in History")
	}
	for _, e := range a.events() {
		if strings.Contains(e.Detail+e.Username, "nobody") {
			t.Error("the user name that was typed was written to History")
		}
	}

	step1 := a.do("POST", "/api/login", nil, map[string]string{"username": " ADA ", "password": testPassword})
	want(t, step1, http.StatusOK)
	if cc := step1.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if len(step1.Result().Cookies()) != 0 {
		t.Fatal("totp_setup step set a session cookie")
	}
	var setup struct {
		TOTPSetup  bool   `json:"totp_setup"`
		Secret     string `json:"secret"`
		OTPAuthURI string `json:"otpauth_uri"`
	}
	if err := json.Unmarshal(step1.Body.Bytes(), &setup); err != nil || !setup.TOTPSetup || setup.Secret == "" || !strings.HasPrefix(setup.OTPAuthURI, "otpauth://totp/infra-node:ada?secret=") {
		t.Fatalf("unexpected totp_setup payload: %s (%v)", step1.Body.String(), err)
	}

	code, err := store.TOTPCode(setup.Secret, a.s.now())
	if err != nil {
		t.Fatal(err)
	}
	rec := a.do("POST", "/api/login", nil, map[string]string{"username": " ADA ", "password": testPassword, "code": code})
	want(t, rec, http.StatusOK)
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no session cookie")
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie flags: HttpOnly=%v Secure=%v SameSite=%v", cookie.HttpOnly, cookie.Secure, cookie.SameSite)
	}
	if strings.Contains(rec.Body.String(), "hash") || strings.Contains(rec.Body.String(), testPassword) || strings.Contains(rec.Body.String(), setup.Secret) {
		t.Errorf("the login answer leaks: %s", rec.Body.String())
	}

	me := a.do("GET", "/api/me", cookie, nil)
	want(t, me, http.StatusOK)
	if !strings.Contains(me.Body.String(), `"username":"ada"`) || !strings.Contains(me.Body.String(), `"role":"admin"`) || !strings.Contains(me.Body.String(), `"totp_enabled":true`) {
		t.Errorf("me: %s", me.Body.String())
	}
	if strings.Contains(me.Body.String(), setup.Secret) || strings.Contains(me.Body.String(), "totp_secret") {
		t.Errorf("me leaks totp secret: %s", me.Body.String())
	}

	out := a.do("POST", "/api/logout", cookie, nil)
	want(t, out, http.StatusNoContent)
	if cleared := out.Result().Cookies(); len(cleared) == 0 || cleared[0].MaxAge >= 0 {
		t.Errorf("the cookie was not cleared: %+v", cleared)
	}
	// The session is gone on the server: the old cookie is worth nothing.
	want(t, a.do("GET", "/api/me", cookie, nil), http.StatusUnauthorized)
	if !a.has("totp.enable", store.ResultOK) || !a.has("login", store.ResultOK) || !a.has("logout", store.ResultOK) {
		t.Error("totp.enable, login, and logout are not in History")
	}
}

func TestLoginRateLimit(t *testing.T) {
	a := newTestApp(t)
	body := map[string]string{"username": "nobody", "password": "wrong password!"}

	// Three wrong passwords are free, the fourth is still answered, then the wait starts.
	for i := 1; i <= 4; i++ {
		want(t, a.do("POST", "/api/login", nil, body), http.StatusUnauthorized)
	}
	rec := a.do("POST", "/api/login", nil, body)
	want(t, rec, http.StatusTooManyRequests)
	if rec.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}
}

func TestDisablingLogsAPersonOutAtOnce(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	alice, aliceCookie := a.user("alice", store.RoleOperator)

	want(t, a.do("GET", "/api/me", aliceCookie, nil), http.StatusOK)
	want(t, a.do("POST", "/api/users/"+strconv.FormatInt(alice.ID, 10)+"/disable", admin, nil), http.StatusNoContent)
	want(t, a.do("GET", "/api/me", aliceCookie, nil), http.StatusUnauthorized)

	// And she cannot come back in by logging in again.
	want(t, a.do("POST", "/api/login", nil, map[string]string{"username": "alice", "password": testPassword}), http.StatusUnauthorized)
	if !a.has("user.disable", store.ResultOK) {
		t.Error("the disable is not in History")
	}

	want(t, a.do("POST", "/api/users/"+strconv.FormatInt(alice.ID, 10)+"/enable", admin, nil), http.StatusNoContent)
	newCookie, _ := a.loginWithTOTP("alice", testPassword, "")
	want(t, a.do("GET", "/api/me", newCookie, nil), http.StatusOK)
}

func TestNobodyDemotesOrDisablesThemselves(t *testing.T) {
	a := newTestApp(t)
	ada, admin := a.user("ada", store.RoleAdmin)
	id := strconv.FormatInt(ada.ID, 10)

	// The only admin cannot remove their own admin role, disable themselves, or reset their own password/OTP via /api/users.
	want(t, a.do("POST", "/api/users/"+id+"/role", admin, map[string]string{"role": "viewer"}), http.StatusConflict)
	want(t, a.do("POST", "/api/users/"+id+"/disable", admin, nil), http.StatusConflict)
	want(t, a.do("POST", "/api/users/"+id+"/password", admin, map[string]string{"password": testPassword + "!"}), http.StatusConflict)
	want(t, a.do("POST", "/api/users/"+id+"/totp-reset", admin, nil), http.StatusConflict)
	if got, _ := store.GetUser(a.db, ada.ID); got.Role != store.RoleAdmin || got.Disabled {
		t.Errorf("ada was changed: %+v", got)
	}
	if !a.has("user.role", store.ResultRefused) || !a.has("user.disable", store.ResultRefused) {
		t.Error("the refusals are not in History")
	}

	// Another admin may demote them, because somebody is left.
	bob, bobCookie := a.user("bob", store.RoleAdmin)
	want(t, a.do("POST", "/api/users/"+id+"/role", bobCookie, map[string]string{"role": "viewer"}), http.StatusNoContent)
	// Ada is a viewer now and cannot manage users any more.
	want(t, a.do("POST", "/api/users/"+strconv.FormatInt(bob.ID, 10)+"/role", admin, map[string]string{"role": "viewer"}), http.StatusForbidden)
}

func TestCreateUserAndItsPasswordStaysOutOfHistory(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	const secret = "a-very-secret-password"

	rec := a.do("POST", "/api/users", admin, map[string]string{"username": "Carol", "password": secret, "role": "operator"})
	want(t, rec, http.StatusCreated)
	if strings.Contains(rec.Body.String(), secret) || strings.Contains(rec.Body.String(), "hash") {
		t.Errorf("the answer leaks: %s", rec.Body.String())
	}
	if u, _, err := store.FindForLogin(a.db, "carol"); err != nil || u.Role != store.RoleOperator {
		t.Errorf("carol: %+v %v", u, err)
	}

	want(t, a.do("POST", "/api/users", admin, map[string]string{"username": "carol", "password": secret, "role": "viewer"}), http.StatusConflict)
	want(t, a.do("POST", "/api/users", admin, map[string]string{"username": "dave", "password": "short", "role": "viewer"}), http.StatusBadRequest)
	want(t, a.do("POST", "/api/users", admin, map[string]string{"username": "erin", "password": secret, "role": "root"}), http.StatusBadRequest)

	// Nothing in History is a password, and the list of users has no hashes.
	for _, e := range a.events() {
		if strings.Contains(e.Detail+e.Target+e.Username+e.Action, secret) {
			t.Errorf("a password is in History: %+v", e)
		}
	}
	list := a.do("GET", "/api/users", admin, nil)
	want(t, list, http.StatusOK)
	if strings.Contains(list.Body.String(), "hash") || !strings.Contains(list.Body.String(), `"username":"carol"`) {
		t.Errorf("users: %s", list.Body.String())
	}
}

func TestResetPasswordEndsThatPersonsSessions(t *testing.T) {
	a := newTestApp(t)
	_, admin := a.user("ada", store.RoleAdmin)
	alice, aliceCookie := a.user("alice", store.RoleViewer)

	want(t, a.do("POST", "/api/users/"+strconv.FormatInt(alice.ID, 10)+"/password", admin, map[string]string{"password": "short"}), http.StatusBadRequest)
	want(t, a.do("GET", "/api/me", aliceCookie, nil), http.StatusOK) // a refused reset changes nothing

	want(t, a.do("POST", "/api/users/"+strconv.FormatInt(alice.ID, 10)+"/password", admin, map[string]string{"password": "a brand new password"}), http.StatusNoContent)
	want(t, a.do("GET", "/api/me", aliceCookie, nil), http.StatusUnauthorized)
	want(t, a.do("POST", "/api/login", nil, map[string]string{"username": "alice", "password": testPassword}), http.StatusUnauthorized)
	newCookie, _ := a.loginWithTOTP("alice", "a brand new password", "")
	want(t, a.do("GET", "/api/me", newCookie, nil), http.StatusOK)
}

func TestChangingYourPasswordEndsYourOtherSessions(t *testing.T) {
	a := newTestApp(t)
	alice, here := a.user("alice", store.RoleViewer)
	elsewhere := a.session(alice)

	want(t, a.do("POST", "/api/me/password", here, map[string]string{"current": "not my password", "new": "another long password"}), http.StatusBadRequest)
	want(t, a.do("POST", "/api/me/password", here, map[string]string{"current": testPassword, "new": "short"}), http.StatusBadRequest)
	want(t, a.do("GET", "/api/me", elsewhere, nil), http.StatusOK) // nothing changed yet

	rec := a.do("POST", "/api/me/password", here, map[string]string{"current": testPassword, "new": "another long password"})
	want(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"ended":1`) {
		t.Errorf("answer: %s", rec.Body.String())
	}
	want(t, a.do("GET", "/api/me", here, nil), http.StatusOK)
	want(t, a.do("GET", "/api/me", elsewhere, nil), http.StatusUnauthorized)
	newCookie, _ := a.loginWithTOTP("alice", "another long password", "")
	want(t, a.do("GET", "/api/me", newCookie, nil), http.StatusOK)
	for _, e := range a.events() {
		if strings.Contains(e.Detail, "another long password") || strings.Contains(e.Detail, testPassword) {
			t.Errorf("a password is in History: %+v", e)
		}
	}
}

func TestProfileListsSessionsAndSignsOutTheOthers(t *testing.T) {
	a := newTestApp(t)
	alice, here := a.user("alice", store.RoleViewer)
	elsewhere := a.session(alice)
	_, bobCookie := a.user("bob", store.RoleViewer)

	rec := a.do("GET", "/api/me/sessions", here, nil)
	want(t, rec, http.StatusOK)
	var list struct {
		Sessions []struct {
			Current bool   `json:"current"`
			IP      string `json:"ip"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Sessions) != 2 {
		t.Fatalf("sessions: %s (%v)", rec.Body.String(), err)
	}
	current := 0
	for _, s := range list.Sessions {
		if s.Current {
			current++
		}
	}
	if current != 1 || strings.Contains(rec.Body.String(), store.TokenID(here.Value)) {
		t.Errorf("exactly one is the current one, and no id is sent: %s", rec.Body.String())
	}

	want(t, a.do("POST", "/api/me/sessions/revoke-others", here, nil), http.StatusOK)
	want(t, a.do("GET", "/api/me", here, nil), http.StatusOK)
	want(t, a.do("GET", "/api/me", elsewhere, nil), http.StatusUnauthorized)
	want(t, a.do("GET", "/api/me", bobCookie, nil), http.StatusOK) // somebody else's login is not touched
}

func TestHistoryPages(t *testing.T) {
	a := newTestApp(t)
	_, c := a.user("alice", store.RoleViewer)
	for i := 0; i < 5; i++ {
		if err := store.AddEvent(a.db, store.Event{Username: "x", Action: "a", Result: store.ResultOK}); err != nil {
			t.Fatal(err)
		}
	}

	var page struct {
		Events []store.Event `json:"events"`
		More   bool          `json:"more"`
	}
	rec := a.do("GET", "/api/history?limit=2", c, nil)
	want(t, rec, http.StatusOK)
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil || len(page.Events) != 2 || !page.More {
		t.Fatalf("first page: %s (%v)", rec.Body.String(), err)
	}
	last := page.Events[1].ID
	rec = a.do("GET", "/api/history?limit=2&before="+strconv.FormatInt(last, 10), c, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil || len(page.Events) != 2 || page.Events[0].ID >= last {
		t.Fatalf("second page: %s (%v)", rec.Body.String(), err)
	}
}

func TestCan(t *testing.T) {
	user := func(role string, disabled bool) store.User { return store.User{Role: role, Disabled: disabled} }
	cases := []struct {
		who    store.User
		action Action
		want   bool
	}{
		{user(store.RoleViewer, false), ActionSelf, true},
		{user(store.RoleViewer, false), ActionView, true},
		{user(store.RoleViewer, false), ActionManageUsers, false},
		{user(store.RoleOperator, false), ActionView, true},
		{user(store.RoleOperator, false), ActionManageUsers, false},
		{user(store.RoleAdmin, false), ActionView, true},
		{user(store.RoleAdmin, false), ActionManageUsers, true},
		// Refused: a disabled user, no role, a role nobody defined, an action nobody defined.
		{user(store.RoleAdmin, true), ActionView, false},
		{user("", false), ActionSelf, false},
		{user("superuser", false), ActionSelf, false},
		{user(store.RoleAdmin, false), "something.new", false},
	}
	for _, c := range cases {
		if got := can(c.who, c.action); got != c.want {
			t.Errorf("can(%+v, %q) = %v, want %v", c.who, c.action, got, c.want)
		}
	}
}

func TestPenaltyGrowsAndIsCapped(t *testing.T) {
	cases := map[int]time.Duration{1: 0, 3: 0, 4: time.Second, 5: 2 * time.Second, 6: 4 * time.Second, 40: maxPenalty}
	for count, want := range cases {
		if got := penalty(count); got != want {
			t.Errorf("penalty(%d) = %v, want %v", count, got, want)
		}
	}
}

func TestLimiterForgetsAfterASuccessAndAfterAnHour(t *testing.T) {
	now := time.Now()
	l := newLoginLimiter()
	l.now = func() time.Time { return now }

	for i := 0; i < 5; i++ {
		l.begin("ip")
	}
	if l.begin("ip") == 0 {
		t.Fatal("the sixth attempt should wait")
	}
	l.reset("ip")
	if l.begin("ip") != 0 {
		t.Error("a success should forget the failures")
	}

	for i := 0; i < 5; i++ {
		l.begin("other")
	}
	now = now.Add(2 * time.Hour)
	if l.begin("other") != 0 {
		t.Error("an hour without failures should start fresh")
	}
}

func TestLimiterIsStrictlyBoundedUnderIPBurst(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newLoginLimiter()
	l.now = func() time.Time { return now }

	// Flood more than maxTracked distinct IPs within a single window (none expired).
	for i := 0; i < maxTracked+500; i++ {
		now = now.Add(time.Millisecond)
		l.begin("10.0." + strconv.Itoa(i/256) + "." + strconv.Itoa(i%256))
		if len(l.byKey) > maxTracked {
			t.Fatalf("table exceeded maxTracked (%d) at step %d: len=%d", maxTracked, i, len(l.byKey))
		}
	}
	if len(l.byKey) != maxTracked {
		t.Fatalf("len(byKey) = %d, want %d", len(l.byKey), maxTracked)
	}
	// Oldest entry was evicted; newest entry is still tracked.
	if _, ok := l.byKey["10.0.0.0"]; ok {
		t.Error("oldest entry 10.0.0.0 should have been evicted")
	}
	newest := "10.0." + strconv.Itoa((maxTracked+499)/256) + "." + strconv.Itoa((maxTracked+499)%256)
	if _, ok := l.byKey[newest]; !ok {
		t.Errorf("newest entry %s should still be tracked", newest)
	}

	// Expired entries are pruned first before evicting active entries.
	now = now.Add(forgetAfter + time.Second)
	l.begin("203.0.113.1")
	if len(l.byKey) != 1 {
		t.Errorf("expired entries were not pruned: len=%d", len(l.byKey))
	}
}

func TestEventCapLimitsAnonymousLines(t *testing.T) {
	now := time.Now()
	c := &eventCap{now: func() time.Time { return now }}
	allowed := 0
	for i := 0; i < anonymousPerMinute+20; i++ {
		if c.allow() {
			allowed++
		}
	}
	if allowed != anonymousPerMinute {
		t.Errorf("%d allowed in a minute, want %d", allowed, anonymousPerMinute)
	}
	now = now.Add(time.Minute)
	if !c.allow() {
		t.Error("the next minute starts fresh")
	}
}

func TestClientIPTrustsTheProxyOnlyFromLoopback(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.7")

	req.RemoteAddr = "127.0.0.1:4000" // Caddy, on this machine
	if got := clientIP(req); got != "203.0.113.7" {
		t.Errorf("from the proxy: %q", got)
	}
	req.RemoteAddr = "198.51.100.4:4000" // anybody else: the header is their own claim
	if got := clientIP(req); got != "198.51.100.4" {
		t.Errorf("from elsewhere: %q", got)
	}
}
