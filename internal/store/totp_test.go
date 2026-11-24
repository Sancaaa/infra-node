package store

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

func TestTOTPRFC6238Vectors(t *testing.T) {
	// RFC 6238 Appendix B SHA-1 test secret: ASCII "12345678901234567890" (20 bytes).
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))

	// Expected 6-digit codes are the last 6 digits of RFC 6238 Appendix B 8-digit SHA-1 vectors.
	vectors := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, v := range vectors {
		at := time.Unix(v.unix, 0).UTC()
		got, err := TOTPCode(secret, at)
		if err != nil {
			t.Fatalf("TOTPCode(%d): %v", v.unix, err)
		}
		if got != v.want {
			t.Errorf("TOTPCode(%d) = %q, want %q", v.unix, got, v.want)
		}
		step, ok := VerifyTOTP(secret, got, at)
		if !ok || step != v.unix/30 {
			t.Errorf("VerifyTOTP(%d, %q) = (%d, %v), want (%d, true)", v.unix, got, step, ok, v.unix/30)
		}
	}
}

func TestVerifyTOTPWindowAndFormatting(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	now := time.Unix(1234567890, 0).UTC() // step 41152263

	for _, tc := range []struct {
		name   string
		offset time.Duration
		wantOK bool
	}{
		{"minus 2 steps", -60 * time.Second, false},
		{"minus 1 step", -30 * time.Second, true},
		{"current step", 0, true},
		{"plus 1 step", 30 * time.Second, true},
		{"plus 2 steps", 60 * time.Second, false},
	} {
		code, err := TOTPCode(secret, now.Add(tc.offset))
		if err != nil {
			t.Fatal(err)
		}
		step, ok := VerifyTOTP(secret, code, now)
		if ok != tc.wantOK {
			t.Errorf("%s: ok = %v, want %v", tc.name, ok, tc.wantOK)
		}
		if ok && step != now.Add(tc.offset).Unix()/30 {
			t.Errorf("%s: step = %d, want %d", tc.name, step, now.Add(tc.offset).Unix()/30)
		}
	}

	// Spaces and dashes are stripped.
	code, _ := TOTPCode(secret, now)
	for _, formatted := range []string{code[:3] + " " + code[3:], code[:3] + "-" + code[3:], "  " + code + "  "} {
		if _, ok := VerifyTOTP(secret, formatted, now); !ok {
			t.Errorf("VerifyTOTP(%q) = false, want true", formatted)
		}
	}

	// Invalid codes and secrets are rejected.
	for _, bad := range []string{"", "12345", "1234567", "12345a", "000000", "abcdef"} {
		if _, ok := VerifyTOTP(secret, bad, now); ok {
			t.Errorf("VerifyTOTP(%q) = true, want false", bad)
		}
	}
	if _, ok := VerifyTOTP("", code, now); ok {
		t.Error("empty secret accepted")
	}
	if _, ok := VerifyTOTP("!!!invalid!!!", code, now); ok {
		t.Error("invalid base32 secret accepted")
	}
}

func TestGenerateTOTPSecretAndURI(t *testing.T) {
	s1, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	s2, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(s1) != 32 || strings.Contains(s1, "=") || s1 != strings.ToUpper(s1) {
		t.Errorf("unexpected secret format: %q", s1)
	}
	if s1 == s2 {
		t.Error("two generated secrets matched")
	}
	if _, err := TOTPCode(s1, time.Now()); err != nil {
		t.Errorf("TOTPCode on generated secret failed: %v", err)
	}

	uri := TOTPURI(TOTPIssuer, "ada", s1)
	want := "otpauth://totp/infra-node:ada?secret=" + s1 + "&issuer=infra-node"
	if uri != want {
		t.Errorf("TOTPURI = %q, want %q", uri, want)
	}
}
