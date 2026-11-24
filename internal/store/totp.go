package store

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// TOTPIssuer labels accounts inside authenticator apps.
	TOTPIssuer = "infra-node"
	totpPeriod = 30
	totpDigits = 6
	totpSkew   = 1
)

var totpBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns 160 random bits encoded as uppercase unpadded Base32.
func GenerateTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate totp secret: %w", err)
	}
	return totpBase32.EncodeToString(raw), nil
}

// TOTPURI builds the otpauth:// provisioning URI for an authenticator app.
func TOTPURI(issuer, username, secret string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(username)
	return "otpauth://totp/" + label +
		"?secret=" + url.QueryEscape(secret) +
		"&issuer=" + url.QueryEscape(issuer)
}

func decodeTOTPSecret(secret string) ([]byte, error) {
	clean := strings.TrimRight(strings.ToUpper(strings.TrimSpace(secret)), "=")
	if clean == "" {
		return nil, errors.New("empty totp secret")
	}
	key, err := totpBase32.DecodeString(clean)
	if err != nil || len(key) == 0 {
		return nil, errors.New("invalid totp secret")
	}
	return key, nil
}

func totpCodeForStep(key []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	return fmt.Sprintf("%06d", bin%1_000_000)
}

// TOTPCode computes the 6-digit RFC 6238 HMAC-SHA1 code for secret at time at.
func TOTPCode(secret string, at time.Time) (string, error) {
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	if at.Unix() < 0 {
		return "", errors.New("negative timestamp")
	}
	return totpCodeForStep(key, at.Unix()/totpPeriod), nil
}

// VerifyTOTP checks code against secret within a ±1 30-second window around now.
// Spaces and dashes in code are ignored; the cleaned code must be 6 ASCII digits.
// On success it returns the matching time step so the caller can reject replays.
func VerifyTOTP(secret, code string, now time.Time) (int64, bool) {
	clean := strings.NewReplacer(" ", "", "-", "").Replace(code)
	if len(clean) != totpDigits {
		return 0, false
	}
	for i := 0; i < len(clean); i++ {
		if clean[i] < '0' || clean[i] > '9' {
			return 0, false
		}
	}
	key, err := decodeTOTPSecret(secret)
	if err != nil || now.Unix() < 0 {
		return 0, false
	}
	cur := now.Unix() / totpPeriod
	var matchedStep int64
	matched := false
	for delta := int64(-totpSkew); delta <= totpSkew; delta++ {
		step := cur + delta
		if step < 0 {
			continue
		}
		expected := totpCodeForStep(key, step)
		if subtle.ConstantTimeCompare([]byte(clean), []byte(expected)) == 1 {
			matchedStep = step
			matched = true
		}
	}
	return matchedStep, matched
}
