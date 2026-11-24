package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var totpBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func GenerateTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return totpBase32.EncodeToString(buf), nil
}

func TOTPCode(secret string, ts time.Time) (string, error) {
	clean := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	key, err := totpBase32.DecodeString(clean)
	if err != nil {
		return "", err
	}
	counter := uint64(ts.Unix() / 30)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	return fmt.Sprintf("%06d", code%1000000), nil
}

func VerifyTOTP(secret, code string, now time.Time) bool {
	c := strings.TrimSpace(code)
	if len(c) != 6 || secret == "" {
		return false
	}
	for _, skew := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		expected, err := TOTPCode(secret, now.Add(skew))
		if err == nil && hmac.Equal([]byte(c), []byte(expected)) {
			return true
		}
	}
	return false
}

func ProvisioningURI(issuer, account, secret string) string {
	escIssuer := url.QueryEscape(issuer)
	label := url.PathEscape(issuer + ":" + account)
	return fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&digits=6&period=30", label, url.QueryEscape(secret), escIssuer)
}
