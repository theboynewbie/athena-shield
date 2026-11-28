package store

import (
	"strings"
	"testing"
)

func TestAtRestSecretEncryption(t *testing.T) {
	key := deriveEncKey("super-secret-master-key-for-testing-32bytes")
	plain := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg...\n-----END PRIVATE KEY-----"

	enc1 := encryptSecret(key, plain)
	enc2 := encryptSecret(key, plain)
	if !strings.HasPrefix(enc1, secretEncPrefix) {
		t.Fatalf("expected enc:v1: prefix, got %q", enc1)
	}
	if enc1 == enc2 {
		t.Fatalf("expected random nonce to produce distinct ciphertexts")
	}
	if got := decryptSecret(key, enc1); got != plain {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, plain)
	}
	if legacy := decryptSecret(key, "legacy-plaintext"); legacy != "legacy-plaintext" {
		t.Fatalf("expected legacy plaintext passthrough, got %q", legacy)
	}

	// End-to-end SQLite storage verification
	dir := t.TempDir()
	s, err := Open(dir, "admin", "admin@test.local", "StrongPass#2026")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if err := s.CreateProxyHost(&ProxyHost{
		DomainName:     "enc.example.com",
		TargetUpstream: "http://10.0.0.10:80",
		HostType:       "proxy",
		SSLType:        "custom",
		SSLCert:        "CERT",
		SSLKey:         plain,
		IsActive:       true,
	}); err != nil {
		t.Fatalf("CreateProxyHost: %v", err)
	}

	u, err := s.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if err := s.SetUserTOTP(u.ID, "JBSWY3DPEHPK3PXP", true); err != nil {
		t.Fatalf("SetUserTOTP: %v", err)
	}
	if err := s.UpdateSettings(map[string]string{"telegram_bot_token": "123456:ABC-DEF-TOKEN"}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}

	// Verify raw SQLite columns are encrypted (enc:v1: prefix, not plaintext)
	var rawSSLKey, rawTOTP, rawTG string
	if err := s.db.QueryRow(`SELECT ssl_key FROM proxy_hosts WHERE domain_name = 'enc.example.com'`).Scan(&rawSSLKey); err != nil {
		t.Fatalf("query raw ssl_key: %v", err)
	}
	if !strings.HasPrefix(rawSSLKey, secretEncPrefix) || strings.Contains(rawSSLKey, "BEGIN PRIVATE KEY") {
		t.Fatalf("expected encrypted ssl_key in SQLite, got %q", rawSSLKey)
	}
	if err := s.db.QueryRow(`SELECT totp_secret FROM users WHERE id = ?`, u.ID).Scan(&rawTOTP); err != nil {
		t.Fatalf("query raw totp_secret: %v", err)
	}
	if !strings.HasPrefix(rawTOTP, secretEncPrefix) || strings.Contains(rawTOTP, "JBSWY3DPEHPK3PXP") {
		t.Fatalf("expected encrypted totp_secret in SQLite, got %q", rawTOTP)
	}
	if err := s.db.QueryRow(`SELECT value FROM system_settings WHERE key = 'telegram_bot_token'`).Scan(&rawTG); err != nil {
		t.Fatalf("query raw telegram_bot_token: %v", err)
	}
	if !strings.HasPrefix(rawTG, secretEncPrefix) || strings.Contains(rawTG, "123456:ABC-DEF-TOKEN") {
		t.Fatalf("expected encrypted telegram_bot_token in SQLite, got %q", rawTG)
	}

	// Verify Store APIs transparently decrypt
	hosts, _ := s.ListProxyHosts()
	if len(hosts) != 1 || hosts[0].SSLKey != plain {
		t.Fatalf("expected decrypted SSLKey from ListProxyHosts, got %+v", hosts)
	}
	uDec, _ := s.GetUserByUsername("admin")
	if uDec.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("expected decrypted TOTPSecret, got %q", uDec.TOTPSecret)
	}
	cfg := s.GetSettings()
	if cfg["telegram_bot_token"] != "123456:ABC-DEF-TOKEN" {
		t.Fatalf("expected decrypted telegram_bot_token, got %q", cfg["telegram_bot_token"])
	}
}
