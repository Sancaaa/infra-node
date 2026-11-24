package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"infra-manager/internal/store"
)

func TestTOTPEnrollmentNormalLoginAndReplayRejection(t *testing.T) {
	a := newTestApp(t)
	now := time.Unix(1_700_000_010, 0).UTC()
	a.s.clock = func() time.Time { return now }

	admin, adminCookie := a.user("ada", store.RoleAdmin)
	_ = admin
	if _, err := store.CreateUser(a.db, "alice", testPassword, store.RoleOperator); err != nil {
		t.Fatal(err)
	}

	// Step 1 (first login): returns totp_setup + secret + otpauth_uri, no cookie, Cache-Control: no-store.
	rec1 := a.do("POST", "/api/login", nil, map[string]string{"username": "alice", "password": testPassword})
	want(t, rec1, http.StatusOK)
	if cc := rec1.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if len(rec1.Result().Cookies()) != 0 {
		t.Fatal("totp_setup issued a cookie")
	}
	var setup1 struct {
		TOTPSetup  bool   `json:"totp_setup"`
		Secret     string `json:"secret"`
		OTPAuthURI string `json:"otpauth_uri"`
	}
	if err := json.Unmarshal(rec1.Body.Bytes(), &setup1); err != nil || !setup1.TOTPSetup || setup1.Secret == "" {
		t.Fatalf("setup1: %s (%v)", rec1.Body.String(), err)
	}
	wantURI := store.TOTPURI(store.TOTPIssuer, "alice", setup1.Secret)
	if setup1.OTPAuthURI != wantURI {
		t.Errorf("otpauth_uri = %q, want %q", setup1.OTPAuthURI, wantURI)
	}

	// Calling step 1 again returns the exact same pending secret and does not rate-limit.
	for i := 0; i < 5; i++ {
		again := a.do("POST", "/api/login", nil, map[string]string{"username": "alice", "password": testPassword})
		want(t, again, http.StatusOK)
		var s struct {
			Secret string `json:"secret"`
		}
		_ = json.Unmarshal(again.Body.Bytes(), &s)
		if s.Secret != setup1.Secret {
			t.Fatalf("pending secret changed across step 1 calls: %q vs %q", s.Secret, setup1.Secret)
		}
	}

	// Wrong code during setup is refused and does not enable TOTP.
	badSetup := a.do("POST", "/api/login", nil, map[string]string{"username": "alice", "password": testPassword, "code": "000000"})
	want(t, badSetup, http.StatusUnauthorized)
	if len(badSetup.Result().Cookies()) != 0 {
		t.Fatal("invalid setup code issued a cookie")
	}
	if u, _, _ := store.FindForLogin(a.db, "alice"); u.TOTPEnabled {
		t.Fatal("invalid setup code enabled TOTP")
	}

	// Valid code enables TOTP and issues session cookie.
	code1, err := store.TOTPCode(setup1.Secret, now)
	if err != nil {
		t.Fatal(err)
	}
	rec2 := a.do("POST", "/api/login", nil, map[string]string{"username": "alice", "password": testPassword, "code": code1})
	want(t, rec2, http.StatusOK)
	if len(rec2.Result().Cookies()) == 0 {
		t.Fatal("valid setup code did not issue a cookie")
	}

	// Replaying the same code in the same 30s window is rejected.
	replay1 := a.do("POST", "/api/login", nil, map[string]string{"username": "alice", "password": testPassword, "code": code1})
	want(t, replay1, http.StatusUnauthorized)
	if len(replay1.Result().Cookies()) != 0 {
		t.Fatal("replayed setup code issued a cookie")
	}

	// Step 1 after enrollment returns {"totp_required": true} and never leaks secret.
	reqStep := a.do("POST", "/api/login", nil, map[string]string{"username": "alice", "password": testPassword})
	want(t, reqStep, http.StatusOK)
	if cc := reqStep.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if len(reqStep.Result().Cookies()) != 0 {
		t.Fatal("totp_required issued a cookie")
	}
	if !strings.Contains(reqStep.Body.String(), `"totp_required":true`) || strings.Contains(reqStep.Body.String(), setup1.Secret) || strings.Contains(reqStep.Body.String(), "otpauth") {
		t.Errorf("unexpected totp_required body: %s", reqStep.Body.String())
	}

	// Advance 30s to next window: fresh code works.
	now = now.Add(30 * time.Second)
	code2, err := store.TOTPCode(setup1.Secret, now)
	if err != nil {
		t.Fatal(err)
	}
	login2 := a.do("POST", "/api/login", nil, map[string]string{"username": "alice", "password": testPassword, "code": code2})
	want(t, login2, http.StatusOK)
	var aliceCookie *http.Cookie
	for _, c := range login2.Result().Cookies() {
		if c.Name == sessionCookie {
			aliceCookie = c
		}
	}
	if aliceCookie == nil {
		t.Fatal("normal 2FA login did not issue a cookie")
	}

	// Replaying code2 (same step) or code1 (previous step within ±1 skew) is rejected.
	want(t, a.do("POST", "/api/login", nil, map[string]string{"username": "alice", "password": testPassword, "code": code2}), http.StatusUnauthorized)
	want(t, a.do("POST", "/api/login", nil, map[string]string{"username": "alice", "password": testPassword, "code": code1}), http.StatusUnauthorized)

	// Secrets and OTP codes never leak in /api/me, /api/users, or History.
	meRec := a.do("GET", "/api/me", aliceCookie, nil)
	want(t, meRec, http.StatusOK)
	usersRec := a.do("GET", "/api/users", adminCookie, nil)
	want(t, usersRec, http.StatusOK)
	for _, label := range []struct {
		name, body string
	}{
		{"/api/me", meRec.Body.String()},
		{"/api/users", usersRec.Body.String()},
	} {
		if strings.Contains(label.body, setup1.Secret) || strings.Contains(label.body, "totp_secret") {
			t.Errorf("%s leaked totp secret: %s", label.name, label.body)
		}
	}
	for _, e := range a.events() {
		blob := e.Detail + e.Target + e.Username + e.Action
		for _, sensitive := range []string{setup1.Secret, code1, code2} {
			if strings.Contains(blob, sensitive) {
				t.Errorf("History leaked %q: %+v", sensitive, e)
			}
		}
	}
}

func TestTOTPWrongCodeRateLimitAndEmptyCodeDoesNotBypass(t *testing.T) {
	a := newTestApp(t)
	now := time.Unix(1_700_000_010, 0).UTC()
	a.s.clock = func() time.Time { return now }

	if _, err := store.CreateUser(a.db, "alice", testPassword, store.RoleViewer); err != nil {
		t.Fatal(err)
	}
	_, secret := a.loginWithTOTP("alice", testPassword, "")
	now = now.Add(30 * time.Second)

	// 3 wrong codes -> empty code (step 1) must NOT clear those 3 failures -> 4th wrong code -> 5th gets 429.
	for i := 0; i < 3; i++ {
		want(t, a.do("POST", "/api/login", nil, map[string]string{"username": "alice", "password": testPassword, "code": "000000"}), http.StatusUnauthorized)
	}
	want(t, a.do("POST", "/api/login", nil, map[string]string{"username": "alice", "password": testPassword}), http.StatusOK)
	want(t, a.do("POST", "/api/login", nil, map[string]string{"username": "alice", "password": testPassword, "code": "000000"}), http.StatusUnauthorized)

	// Now rate-limited even with a valid code.
	validCode, _ := store.TOTPCode(secret, now)
	rec := a.do("POST", "/api/login", nil, map[string]string{"username": "alice", "password": testPassword, "code": validCode})
	want(t, rec, http.StatusTooManyRequests)
	if rec.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 429")
	}
}

func TestWrongPasswordNeverLeaksTOTPState(t *testing.T) {
	a := newTestApp(t)
	now := time.Unix(1_700_000_010, 0).UTC()
	a.s.clock = func() time.Time { return now }

	// Unenrolled user, enrolled user, disabled user.
	if _, err := store.CreateUser(a.db, "unenrolled", testPassword, store.RoleViewer); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUser(a.db, "enrolled", testPassword, store.RoleViewer); err != nil {
		t.Fatal(err)
	}
	a.loginWithTOTP("enrolled", testPassword, "")
	dis, err := store.CreateUser(a.db, "disabled", testPassword, store.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetDisabled(a.db, dis.ID, true); err != nil {
		t.Fatal(err)
	}

	cases := []map[string]string{
		{"username": "unenrolled", "password": "wrong password!"},
		{"username": "enrolled", "password": "wrong password!"},
		{"username": "disabled", "password": testPassword},
		{"username": "nobody", "password": "wrong password!"},
	}
	for _, body := range cases {
		// Reset limiter so all 4 cases are evaluated against auth, not 429.
		a.s.loginLimit = newLoginLimiter()
		rec := a.do("POST", "/api/login", nil, body)
		want(t, rec, http.StatusUnauthorized)
		s := rec.Body.String()
		for _, forbidden := range []string{"totp_setup", "totp_required", "secret", "otpauth"} {
			if strings.Contains(s, forbidden) {
				t.Errorf("login(%v) leaked %q: %s", body["username"], forbidden, s)
			}
		}
	}
}

func TestAdminResetUserTOTP(t *testing.T) {
	a := newTestApp(t)
	now := time.Unix(1_700_000_010, 0).UTC()
	a.s.clock = func() time.Time { return now }

	_, adminCookie := a.user("ada", store.RoleAdmin)
	alice, err := store.CreateUser(a.db, "alice", testPassword, store.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	aliceCookie, oldSecret := a.loginWithTOTP("alice", testPassword, "")
	want(t, a.do("GET", "/api/me", aliceCookie, nil), http.StatusOK)

	// Admin resets alice's OTP.
	id := strconv.FormatInt(alice.ID, 10)
	want(t, a.do("POST", "/api/users/"+id+"/totp-reset", adminCookie, nil), http.StatusNoContent)
	want(t, a.do("POST", "/api/users/9999/totp-reset", adminCookie, nil), http.StatusNotFound)

	// Alice's session is revoked immediately.
	want(t, a.do("GET", "/api/me", aliceCookie, nil), http.StatusUnauthorized)
	if !a.has("user.totp.reset", store.ResultOK) {
		t.Error("user.totp.reset not in History")
	}

	// Alice must re-enroll with a new secret on next login.
	step1 := a.do("POST", "/api/login", nil, map[string]string{"username": "alice", "password": testPassword})
	want(t, step1, http.StatusOK)
	var setup struct {
		TOTPSetup bool   `json:"totp_setup"`
		Secret    string `json:"secret"`
	}
	if err := json.Unmarshal(step1.Body.Bytes(), &setup); err != nil || !setup.TOTPSetup || setup.Secret == "" {
		t.Fatalf("expected totp_setup after admin reset, got: %s", step1.Body.String())
	}
	if setup.Secret == oldSecret {
		t.Error("re-enrollment reused old secret")
	}

	// Completing re-enrollment works.
	newCookie, _ := a.loginWithTOTP("alice", testPassword, "")
	want(t, a.do("GET", "/api/me", newCookie, nil), http.StatusOK)
}

func TestSelfResetTOTP(t *testing.T) {
	a := newTestApp(t)
	now := time.Unix(1_700_000_010, 0).UTC()
	a.s.clock = func() time.Time { return now }

	alice, err := store.CreateUser(a.db, "alice", testPassword, store.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	_, bobCookie := a.user("bob", store.RoleViewer)

	here, oldSecret := a.loginWithTOTP("alice", testPassword, "")
	elsewhere := a.session(alice)

	// Wrong password is refused.
	loginCode, _ := store.TOTPCode(oldSecret, now)
	want(t, a.do("POST", "/api/me/totp/reset", here, map[string]string{"password": "wrong password!", "code": loginCode}), http.StatusBadRequest)
	// Wrong code is refused.
	want(t, a.do("POST", "/api/me/totp/reset", here, map[string]string{"password": testPassword, "code": "000000"}), http.StatusBadRequest)
	// Replaying the login code from the same 30s step is refused.
	want(t, a.do("POST", "/api/me/totp/reset", here, map[string]string{"password": testPassword, "code": loginCode}), http.StatusBadRequest)
	// Sessions are untouched after refused attempts.
	want(t, a.do("GET", "/api/me", here, nil), http.StatusOK)
	want(t, a.do("GET", "/api/me", elsewhere, nil), http.StatusOK)

	// Advance 30s: valid password + fresh code succeeds.
	now = now.Add(30 * time.Second)
	freshCode, _ := store.TOTPCode(oldSecret, now)
	rec := a.do("POST", "/api/me/totp/reset", here, map[string]string{"password": testPassword, "code": freshCode})
	want(t, rec, http.StatusNoContent)
	if cleared := rec.Result().Cookies(); len(cleared) == 0 || cleared[0].MaxAge >= 0 {
		t.Errorf("cookie was not cleared on self TOTP reset: %+v", cleared)
	}

	// All of alice's sessions are ended; bob's is untouched.
	want(t, a.do("GET", "/api/me", here, nil), http.StatusUnauthorized)
	want(t, a.do("GET", "/api/me", elsewhere, nil), http.StatusUnauthorized)
	want(t, a.do("GET", "/api/me", bobCookie, nil), http.StatusOK)
	if !a.has("totp.reset", store.ResultOK) {
		t.Error("totp.reset not in History")
	}

	// Next login triggers fresh totp_setup.
	step1 := a.do("POST", "/api/login", nil, map[string]string{"username": "alice", "password": testPassword})
	want(t, step1, http.StatusOK)
	if !strings.Contains(step1.Body.String(), `"totp_setup":true`) {
		t.Errorf("expected totp_setup after self reset: %s", step1.Body.String())
	}

	// Sensitive values never appear in History.
	for _, e := range a.events() {
		blob := e.Detail + e.Target + e.Username + e.Action
		for _, sensitive := range []string{testPassword, oldSecret, loginCode, freshCode} {
			if strings.Contains(blob, sensitive) {
				t.Errorf("History leaked %q: %+v", sensitive, e)
			}
		}
	}
}

func TestSelfResetTOTPRateLimited(t *testing.T) {
	a := newTestApp(t)
	now := time.Unix(1_700_000_010, 0).UTC()
	a.s.clock = func() time.Time { return now }

	if _, err := store.CreateUser(a.db, "alice", testPassword, store.RoleViewer); err != nil {
		t.Fatal(err)
	}
	cookie, _ := a.loginWithTOTP("alice", testPassword, "")
	for i := 0; i < 4; i++ {
		want(t, a.do("POST", "/api/me/totp/reset", cookie, map[string]string{"password": testPassword, "code": "000000"}), http.StatusBadRequest)
	}
	rec := a.do("POST", "/api/me/totp/reset", cookie, map[string]string{"password": testPassword, "code": "000000"})
	want(t, rec, http.StatusTooManyRequests)
}
