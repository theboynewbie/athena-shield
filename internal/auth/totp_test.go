package auth

import (
	"strings"
	"testing"
	"time"
)

func TestTOTPRFC6238(t *testing.T) {
	sec, err := GenerateTOTPSecret()
	if err != nil || len(sec) < 16 {
		t.Fatalf("expected valid TOTP secret, got %q, err=%v", sec, err)
	}

	now := time.Unix(1700000000, 0).UTC()
	code, err := TOTPCode(sec, now)
	if err != nil || len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q, err=%v", code, err)
	}

	if !VerifyTOTP(sec, code, now) {
		t.Fatalf("expected current TOTP code to verify")
	}
	// +-30s skew accepted
	if !VerifyTOTP(sec, code, now.Add(25*time.Second)) {
		t.Fatalf("expected +25s skew to verify")
	}
	if !VerifyTOTP(sec, code, now.Add(-25*time.Second)) {
		t.Fatalf("expected -25s skew to verify")
	}
	// Wrong code & >60s expired rejected
	if VerifyTOTP(sec, "000000", now) && code != "000000" {
		t.Fatalf("expected wrong TOTP code to fail")
	}
	if VerifyTOTP(sec, code, now.Add(90*time.Second)) {
		t.Fatalf("expected expired TOTP code (+90s) to fail")
	}

	uri := ProvisioningURI("AthenaShield", "admin", sec)
	if !strings.HasPrefix(uri, "otpauth://totp/") || !strings.Contains(uri, "secret="+sec) {
		t.Fatalf("unexpected provisioning URI: %s", uri)
	}
}
