package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/theboynewbie/athena-shield/internal/auth"
	"github.com/theboynewbie/athena-shield/internal/cache"
	"github.com/theboynewbie/athena-shield/internal/config"
	"github.com/theboynewbie/athena-shield/internal/proxy"
	"github.com/theboynewbie/athena-shield/internal/ratelimit"
	"github.com/theboynewbie/athena-shield/internal/store"
	"github.com/theboynewbie/athena-shield/internal/waf"
)

func setupTestWebServer(t *testing.T) (*Server, *store.Store, *auth.Manager) {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(dir, "admin", "admin@test.local", "GuardianWAF@2026")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	cfg := config.Load()
	am := auth.NewManager("test-secret-32-chars-minimum-123456", s)
	rl := ratelimit.New(cfg, s, nil)
	eng := waf.NewEngine(cfg, s, rl)
	ec := cache.NewEdgeCache()
	rt := proxy.NewRouter(cfg, s, eng, rl, ec, nil, nil, nil)
	srv, err := NewServer(cfg, s, am, eng, rl, ec, nil, rt)
	if err != nil {
		t.Fatal(err)
	}
	rt.SetRenderer(srv)
	return srv, s, am
}

func TestLoginPageAndAuthFlow(t *testing.T) {
	srv, s, am := setupTestWebServer(t)
	h := srv.Handler()

	// 1. Login page contains loginPasswordEye and fa-eye-slash
	req := httptest.NewRequest("GET", "/login", nil)
	req.RemoteAddr = "127.0.0.1:5000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on /login, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "loginPasswordEye") || !strings.Contains(body, "fa-eye-slash") {
		t.Fatalf("login page missing password toggle elements")
	}

	m := regexp.MustCompile(`name="csrf_token"\s+value="([^"]+)"`).FindStringSubmatch(body)
	if len(m) < 2 {
		t.Fatalf("missing csrf_token on login page")
	}
	csrf := m[1]

	// 2. Honeypot trap -> 403
	formTrap := url.Values{"username": {"admin"}, "password": {"GuardianWAF@2026"}, "csrf_token": {csrf}, "website_trap": {"bot"}}
	reqTrap := httptest.NewRequest("POST", "/login", strings.NewReader(formTrap.Encode()))
	reqTrap.RemoteAddr = "198.51.100.77:5000"
	reqTrap.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recTrap := httptest.NewRecorder()
	h.ServeHTTP(recTrap, reqTrap)
	if recTrap.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on honeypot, got %d", recTrap.Code)
	}

	// 3. Valid login -> 302 + cookie
	formOK := url.Values{"username": {"admin"}, "password": {"GuardianWAF@2026"}, "csrf_token": {csrf}, "website_trap": {""}}
	reqOK := httptest.NewRequest("POST", "/login", strings.NewReader(formOK.Encode()))
	reqOK.RemoteAddr = "127.0.0.1:5000"
	reqOK.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recOK := httptest.NewRecorder()
	h.ServeHTTP(recOK, reqOK)
	if recOK.Code != http.StatusFound {
		t.Fatalf("expected 302 on valid login, got %d (%s)", recOK.Code, recOK.Body.String())
	}
	cookies := recOK.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Name != "access_token" {
		t.Fatalf("expected access_token cookie")
	}

	// 4. Unauthenticated API -> 401
	reqUnauth := httptest.NewRequest("GET", "/api/proxy-hosts", nil)
	recUnauth := httptest.NewRecorder()
	h.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recUnauth.Code)
	}

	// 5. Non-super-admin gets 403 on /api/users
	hash, _ := auth.HashPassword("pass123")
	_ = s.CreateUser(&store.User{Username: "viewer", Email: "v@test.local", HashedPassword: hash, Role: "admin", IsActive: true})
	viewerTok, _ := am.CreateToken("viewer", "admin")
	reqViewer := httptest.NewRequest("GET", "/api/users", nil)
	reqViewer.Header.Set("Authorization", "Bearer "+viewerTok)
	recViewer := httptest.NewRecorder()
	h.ServeHTTP(recViewer, reqViewer)
	if recViewer.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-super_admin on /api/users, got %d", recViewer.Code)
	}

	// 6. Prometheus /metrics returns 200 with expected gauges
	reqMet := httptest.NewRequest("GET", "/metrics", nil)
	recMet := httptest.NewRecorder()
	h.ServeHTTP(recMet, reqMet)
	if recMet.Code != http.StatusOK || !strings.Contains(recMet.Body.String(), "athena_requests_total") || !strings.Contains(recMet.Body.String(), "athena_go_goroutines") {
		t.Fatalf("unexpected /metrics response: code=%d body=%s", recMet.Code, recMet.Body.String())
	}

	// 7. RBAC: auditor can GET /api/rules and /api/audit-logs, but POST /api/rules returns 403
	_ = s.CreateUser(&store.User{Username: "auditor1", Email: "a@test.local", HashedPassword: hash, Role: "auditor", IsActive: true})
	audTok, _ := am.CreateToken("auditor1", "auditor")
	for _, ep := range []string{"/api/rules", "/api/audit-logs"} {
		reqAud := httptest.NewRequest("GET", ep, nil)
		reqAud.Header.Set("Authorization", "Bearer "+audTok)
		recAud := httptest.NewRecorder()
		h.ServeHTTP(recAud, reqAud)
		if recAud.Code != http.StatusOK {
			t.Fatalf("expected 200 for auditor GET %s, got %d", ep, recAud.Code)
		}
	}
	reqAudWrite := httptest.NewRequest("POST", "/api/rules", strings.NewReader(`{"name":"x","pattern":"y"}`))
	reqAudWrite.Header.Set("Authorization", "Bearer "+audTok)
	recAudWrite := httptest.NewRecorder()
	h.ServeHTTP(recAudWrite, reqAudWrite)
	if recAudWrite.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for auditor POST /api/rules, got %d", recAudWrite.Code)
	}

	// 8. SIEM Log Export (JSONL and CEF)
	for _, fmtName := range []string{"jsonl", "cef"} {
		reqExp := httptest.NewRequest("GET", "/api/logs/export?format="+fmtName, nil)
		reqExp.Header.Set("Authorization", "Bearer "+audTok)
		recExp := httptest.NewRecorder()
		h.ServeHTTP(recExp, reqExp)
		if recExp.Code != http.StatusOK {
			t.Fatalf("expected 200 for SIEM export format=%s, got %d", fmtName, recExp.Code)
		}
	}
}

func TestFormatNICSpeed(t *testing.T) {
	cases := []struct {
		mbps int
		want string
	}{
		{0, ""},
		{-1, ""},
		{100, "100Mbps"},
		{1000, "1Gbps"},
		{2500, "2.5Gbps"},
		{10000, "10Gbps"},
		{25000, "25Gbps"},
		{40000, "40Gbps"},
		{100000, "100Gbps"},
	}
	for _, tc := range cases {
		if got := formatNICSpeed(tc.mbps); got != tc.want {
			t.Fatalf("formatNICSpeed(%d) = %q, want %q", tc.mbps, got, tc.want)
		}
	}
}

func TestInitialSetupWizardFlow(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(dir, "", "", "")
	if err != nil {
		t.Fatalf("open empty store: %v", err)
	}
	defer s.Close()

	if !s.NeedsSetup() {
		t.Fatalf("expected NeedsSetup() == true on fresh empty DB")
	}

	cfg := config.Load()
	am := auth.NewManager("test-secret-0123456789abcdef0123456789", s)
	rl := ratelimit.New(cfg, s, nil)
	eng := waf.NewEngine(cfg, s, rl)
	ec := cache.NewEdgeCache()
	srv, err := NewServer(cfg, s, am, eng, rl, ec, nil, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	h := srv.Handler()

	// 1. GET / and GET /login redirect to /setup
	for _, p := range []string{"/", "/login", "/dashboard"} {
		req := httptest.NewRequest("GET", p, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/setup" {
			t.Fatalf("GET %s expected 302 -> /setup, got %d (%s)", p, rec.Code, rec.Header().Get("Location"))
		}
	}

	// 2. GET /setup returns 200 with csrf_token
	reqGet := httptest.NewRequest("GET", "/setup", nil)
	reqGet.RemoteAddr = "127.0.0.1:5000"
	recGet := httptest.NewRecorder()
	h.ServeHTTP(recGet, reqGet)
	if recGet.Code != http.StatusOK {
		t.Fatalf("expected 200 on GET /setup, got %d", recGet.Code)
	}
	m := regexp.MustCompile(`name="csrf_token"\s+value="([^"]+)"`).FindStringSubmatch(recGet.Body.String())
	if len(m) < 2 {
		t.Fatalf("missing csrf_token on /setup page")
	}
	csrf := m[1]
	setupTok := srv.SetupToken()
	if len(setupTok) != 32 {
		t.Fatalf("expected 32-char setup token, got %q", setupTok)
	}

	// 2b. Wrong or missing setup_token rejected with 403 and NeedsSetup stays true
	badTokForm := url.Values{
		"setup_token": {"wrong-token"},
		"username": {"owner1"}, "email": {"owner@example.com"},
		"password": {"StrongPass#2026"}, "confirm_password": {"StrongPass#2026"}, "csrf_token": {csrf},
	}
	reqBadTok := httptest.NewRequest("POST", "/setup", strings.NewReader(badTokForm.Encode()))
	reqBadTok.RemoteAddr = "127.0.0.1:5000"
	reqBadTok.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recBadTok := httptest.NewRecorder()
	h.ServeHTTP(recBadTok, reqBadTok)
	if recBadTok.Code != http.StatusForbidden || !s.NeedsSetup() {
		t.Fatalf("expected 403 and NeedsSetup==true on wrong setup_token, got %d", recBadTok.Code)
	}
	mTok := regexp.MustCompile(`name="csrf_token"\s+value="([^"]+)"`).FindStringSubmatch(recBadTok.Body.String())
	if len(mTok) < 2 {
		t.Fatalf("missing fresh csrf_token after setup_token error")
	}

	// 3. Short password rejected with 400 and NeedsSetup stays true
	badForm := url.Values{
		"setup_token": {setupTok},
		"username": {"owner1"}, "email": {"owner@example.com"},
		"password": {"short"}, "confirm_password": {"short"}, "csrf_token": {mTok[1]},
	}
	reqBad := httptest.NewRequest("POST", "/setup", strings.NewReader(badForm.Encode()))
	reqBad.RemoteAddr = "127.0.0.1:5000"
	reqBad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recBad := httptest.NewRecorder()
	h.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusBadRequest || !s.NeedsSetup() {
		t.Fatalf("expected 400 and NeedsSetup==true on short password, got %d", recBad.Code)
	}

	// Extract fresh CSRF from 400 response
	m2 := regexp.MustCompile(`name="csrf_token"\s+value="([^"]+)"`).FindStringSubmatch(recBad.Body.String())
	if len(m2) < 2 {
		t.Fatalf("missing fresh csrf_token after validation error")
	}

	// 4. Valid setup -> 302 to /dashboard + access_token cookie + NeedsSetup==false
	okForm := url.Values{
		"setup_token": {setupTok},
		"username": {"owner1"}, "email": {"owner@example.com"},
		"password": {"StrongPass#2026"}, "confirm_password": {"StrongPass#2026"}, "csrf_token": {m2[1]},
	}
	reqOK := httptest.NewRequest("POST", "/setup", strings.NewReader(okForm.Encode()))
	reqOK.RemoteAddr = "127.0.0.1:5000"
	reqOK.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recOK := httptest.NewRecorder()
	h.ServeHTTP(recOK, reqOK)
	if recOK.Code != http.StatusFound || recOK.Header().Get("Location") != "/dashboard" {
		t.Fatalf("expected 302 -> /dashboard on valid setup, got %d (%s)", recOK.Code, recOK.Body.String())
	}
	if s.NeedsSetup() {
		t.Fatalf("expected NeedsSetup() == false after initial setup")
	}
	cookies := recOK.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Name != "access_token" {
		t.Fatalf("expected access_token cookie after setup")
	}

	// 5. Issued cookie grants immediate access to /api/stats
	reqAPI := httptest.NewRequest("GET", "/api/stats", nil)
	reqAPI.AddCookie(cookies[0])
	recAPI := httptest.NewRecorder()
	h.ServeHTTP(recAPI, reqAPI)
	if recAPI.Code != http.StatusOK {
		t.Fatalf("expected 200 on /api/stats with setup cookie, got %d", recAPI.Code)
	}

	// 6. Setup endpoint is permanently locked afterwards
	reqLockGet := httptest.NewRequest("GET", "/setup", nil)
	recLockGet := httptest.NewRecorder()
	h.ServeHTTP(recLockGet, reqLockGet)
	if recLockGet.Code != http.StatusFound || recLockGet.Header().Get("Location") != "/login" {
		t.Fatalf("expected GET /setup after completion to redirect to /login, got %d", recLockGet.Code)
	}

	reqLockPost := httptest.NewRequest("POST", "/setup", strings.NewReader(okForm.Encode()))
	reqLockPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recLockPost := httptest.NewRecorder()
	h.ServeHTTP(recLockPost, reqLockPost)
	if recLockPost.Code != http.StatusForbidden {
		t.Fatalf("expected POST /setup after completion to return 403, got %d", recLockPost.Code)
	}
}

func TestScanPCINetDevices(t *testing.T) {
	dir := t.TempDir()
	nicDir := filepath.Join(dir, "pci0000_00", "0000_00_1c.0", "0000_02_00.0", "net", "enp2s0")
	if err := os.MkdirAll(nicDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nicDir, "operstate"), []byte("up\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nicDir, "speed"), []byte("1000\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	name, label, mbps := scanPCINetDevices(dir)
	if name != "enp2s0" || label != "1Gbps" || mbps != 1000 {
		t.Fatalf("got (%q, %q, %d), want (\"enp2s0\", \"1Gbps\", 1000)", name, label, mbps)
	}

	// Simulate KVM/Proxmox VirtIO VM NIC where kernel speed=-1 and DRIVER=virtio_net
	vmDir := t.TempDir()
	virtioDev := filepath.Join(vmDir, "pci0000_00", "0000_00_03.0", "virtio0")
	vmNIC := filepath.Join(virtioDev, "net", "ens18")
	if err := os.MkdirAll(vmNIC, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(virtioDev, "uevent"), []byte("DRIVER=virtio_net\n"), 0o644)
	_ = os.WriteFile(filepath.Join(vmNIC, "operstate"), []byte("up\n"), 0o644)
	_ = os.WriteFile(filepath.Join(vmNIC, "speed"), []byte("-1\n"), 0o644)

	vName, vLabel, vMbps := scanPCINetDevices(vmDir)
	if vName != "ens18 (virtio_net)" || vLabel != "VirtIO NIC" || vMbps != 0 {
		t.Fatalf("got (%q, %q, %d), want (\"ens18 (virtio_net)\", \"VirtIO NIC\", 0)", vName, vLabel, vMbps)
	}
}

func TestSprintASecurityHardening(t *testing.T) {
	srv, s, am := setupTestWebServer(t)
	h := srv.Handler()

	// 1. SSL Private Key must never be returned by GET /api/proxy-hosts (even to authenticated auditor)
	err := s.CreateProxyHost(&store.ProxyHost{
		DomainName:     "secure.example.com",
		TargetUpstream: "http://10.0.0.10:80",
		HostType:       "proxy",
		SSLType:        "custom",
		SSLCert:        "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----",
		SSLKey:         "-----BEGIN PRIVATE KEY-----\nSUPER_SECRET_KEY\n-----END PRIVATE KEY-----",
		IsActive:       true,
	})
	if err != nil {
		t.Fatalf("CreateProxyHost: %v", err)
	}

	hash, _ := auth.HashPassword("AuditorPass#2026")
	_ = s.CreateUser(&store.User{Username: "auditor_sec", Email: "audsec@test.local", HashedPassword: hash, Role: "auditor", IsActive: true})
	audTok, _ := am.CreateToken("auditor_sec", "auditor", 1)

	reqHosts := httptest.NewRequest("GET", "/api/proxy-hosts", nil)
	reqHosts.Header.Set("Authorization", "Bearer "+audTok)
	recHosts := httptest.NewRecorder()
	h.ServeHTTP(recHosts, reqHosts)
	if recHosts.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/proxy-hosts, got %d", recHosts.Code)
	}
	bodyHosts := recHosts.Body.String()
	if strings.Contains(bodyHosts, "SUPER_SECRET_KEY") {
		t.Fatalf("GET /api/proxy-hosts leaked ssl_key to auditor!")
	}
	if !strings.Contains(bodyHosts, `"has_ssl_key":true`) {
		t.Fatalf("expected has_ssl_key:true in response, got %s", bodyHosts)
	}

	// 2. 2FA setup must be rejected when already enabled
	sec, _ := auth.GenerateTOTPSecret()
	adminUser, _ := s.GetUserByUsername("admin")
	if err := s.SetUserTOTP(adminUser.ID, sec, true); err != nil {
		t.Fatalf("SetUserTOTP: %v", err)
	}
	adminTok, _ := am.CreateToken("admin", "super_admin", adminUser.TokenVersion)
	req2FA := httptest.NewRequest("POST", "/api/account/2fa/setup", nil)
	req2FA.Header.Set("Authorization", "Bearer "+adminTok)
	rec2FA := httptest.NewRecorder()
	h.ServeHTTP(rec2FA, req2FA)
	if rec2FA.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when calling 2fa/setup while 2FA is already enabled, got %d", rec2FA.Code)
	}

	// 3. TOTP replay prevention & brute-force lockout
	code, _ := auth.TOTPCode(sec, time.Now())
	if !am.VerifyAndConsumeTOTP("admin", sec, code, time.Now()) {
		t.Fatalf("expected first TOTP verification to succeed")
	}
	if am.VerifyAndConsumeTOTP("admin", sec, code, time.Now()) {
		t.Fatalf("expected replayed TOTP code in same window to fail")
	}

	// Trigger TOTP brute-force lockout via /login
	for i := 0; i < auth.MaxLoginAttempts; i++ {
		reqGet := httptest.NewRequest("GET", "/login", nil)
		reqGet.RemoteAddr = "198.51.100.200:4000"
		recGet := httptest.NewRecorder()
		h.ServeHTTP(recGet, reqGet)
		if i == auth.MaxLoginAttempts {
			break
		}
		m := regexp.MustCompile(`name="csrf_token"\s+value="([^"]+)"`).FindStringSubmatch(recGet.Body.String())
		if len(m) < 2 {
			t.Fatalf("missing csrf_token on attempt %d (status=%d)", i, recGet.Code)
		}
		form := url.Values{
			"username":     {"admin"},
			"password":     {"GuardianWAF@2026"},
			"totp_code":    {"000000"},
			"csrf_token":   {m[1]},
			"website_trap": {""},
		}
		reqPost := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		reqPost.RemoteAddr = "198.51.100.200:4000"
		reqPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		recPost := httptest.NewRecorder()
		h.ServeHTTP(recPost, reqPost)
		if i < auth.MaxLoginAttempts-1 && recPost.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d expected 401, got %d", i, recPost.Code)
		}
		if i == auth.MaxLoginAttempts-1 && recPost.Code != http.StatusTooManyRequests {
			t.Fatalf("final attempt expected 429 lockout, got %d", recPost.Code)
		}
	}

	// 4. Session revocation on logout
	reqStatsOK := httptest.NewRequest("GET", "/api/stats", nil)
	reqStatsOK.Header.Set("Authorization", "Bearer "+audTok)
	recStatsOK := httptest.NewRecorder()
	h.ServeHTTP(recStatsOK, reqStatsOK)
	if recStatsOK.Code != http.StatusOK {
		t.Fatalf("expected 200 before logout, got %d", recStatsOK.Code)
	}

	reqLogout := httptest.NewRequest("GET", "/logout", nil)
	reqLogout.Header.Set("Authorization", "Bearer "+audTok)
	recLogout := httptest.NewRecorder()
	h.ServeHTTP(recLogout, reqLogout)

	reqStatsRevoked := httptest.NewRequest("GET", "/api/stats", nil)
	reqStatsRevoked.Header.Set("Authorization", "Bearer "+audTok)
	recStatsRevoked := httptest.NewRecorder()
	h.ServeHTTP(recStatsRevoked, reqStatsRevoked)
	if recStatsRevoked.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after logout session revocation, got %d", recStatsRevoked.Code)
	}
}

func TestSprintCGovernanceAndCompliance(t *testing.T) {
	srv, s, am := setupTestWebServer(t)
	h := srv.Handler()

	adminUser, err := s.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	adminTok, _ := am.CreateToken("admin", "super_admin", adminUser.TokenVersion)
	adminCookie := &http.Cookie{Name: "access_token", Value: "Bearer " + adminTok}

	// 1. Cross-origin cookie CSRF on state-changing API must be rejected (403), same-origin allowed (200) + audit logged
	reqBadOrigin := httptest.NewRequest("POST", "/api/cache/purge", nil)
	reqBadOrigin.Host = "example.com"
	reqBadOrigin.Header.Set("Origin", "https://evil.example")
	reqBadOrigin.AddCookie(adminCookie)
	recBadOrigin := httptest.NewRecorder()
	h.ServeHTTP(recBadOrigin, reqBadOrigin)
	if recBadOrigin.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on cross-origin cookie POST, got %d", recBadOrigin.Code)
	}

	reqSameOrigin := httptest.NewRequest("POST", "/api/cache/purge", nil)
	reqSameOrigin.Host = "example.com"
	reqSameOrigin.Header.Set("Origin", "http://example.com")
	reqSameOrigin.AddCookie(adminCookie)
	recSameOrigin := httptest.NewRecorder()
	h.ServeHTTP(recSameOrigin, reqSameOrigin)
	if recSameOrigin.Code != http.StatusOK {
		t.Fatalf("expected 200 on same-origin cookie POST, got %d (%s)", recSameOrigin.Code, recSameOrigin.Body.String())
	}

	audits, err := s.ListAuditLogs(20)
	if err != nil || len(audits) == 0 || audits[0].Action != "PURGE_CACHE" {
		t.Fatalf("expected PURGE_CACHE in audit logs, got %+v (err=%v)", audits, err)
	}

	// 2. Weak/empty password rejected on POST /api/users
	reqWeakUser := httptest.NewRequest("POST", "/api/users", strings.NewReader(`{"username":"newop","email":"op@example.com","password":"123","role":"admin"}`))
	reqWeakUser.Header.Set("Authorization", "Bearer "+adminTok)
	recWeakUser := httptest.NewRecorder()
	h.ServeHTTP(recWeakUser, reqWeakUser)
	if recWeakUser.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short password on /api/users, got %d", recWeakUser.Code)
	}

	// 3. Cannot demote or deactivate the sole active super_admin
	reqDemote := httptest.NewRequest("PUT", "/api/users/1", strings.NewReader(`{"role":"admin"}`))
	reqDemote.Header.Set("Authorization", "Bearer "+adminTok)
	recDemote := httptest.NewRecorder()
	h.ServeHTTP(recDemote, reqDemote)
	if recDemote.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when demoting last active super_admin, got %d (%s)", recDemote.Code, recDemote.Body.String())
	}

	reqDeact := httptest.NewRequest("PUT", "/api/users/1", strings.NewReader(`{"is_active":false}`))
	reqDeact.Header.Set("Authorization", "Bearer "+adminTok)
	recDeact := httptest.NewRecorder()
	h.ServeHTTP(recDeact, reqDeact)
	if recDeact.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when deactivating last active super_admin, got %d", recDeact.Code)
	}

	// 4. Transactional & validated backup import
	backupJSON := `{
		"proxy_hosts": [{"domain_name": "app.example.com", "target_upstream": "http://10.0.0.5:80", "host_type": "invalid_type", "ssl_type": "bogus"}],
		"ip_lists": [
			{"ip_address": "198.51.100.50", "list_type": "BLACKLIST", "reason": "valid"},
			{"ip_address": "not-an-ip", "list_type": "BLACKLIST", "reason": "invalid"}
		],
		"settings": {"waf_paranoia_level": "99", "waf_dlp_mode": "monitor", "unknown_key": "ignored"}
	}`
	reqBackup := httptest.NewRequest("POST", "/api/backup/import", strings.NewReader(backupJSON))
	reqBackup.Header.Set("Authorization", "Bearer "+adminTok)
	recBackup := httptest.NewRecorder()
	h.ServeHTTP(recBackup, reqBackup)
	if recBackup.Code != http.StatusOK {
		t.Fatalf("expected 200 on backup import, got %d (%s)", recBackup.Code, recBackup.Body.String())
	}
	hosts, _ := s.ListProxyHosts()
	if len(hosts) != 1 || hosts[0].HostType != "proxy" || hosts[0].SSLType != "none" {
		t.Fatalf("expected normalized host_type=proxy and ssl_type=none, got %+v", hosts)
	}
	ips, _ := s.ListIPs()
	if len(ips) != 1 || ips[0].IPAddress != "198.51.100.50" {
		t.Fatalf("expected only valid IP to be imported, got %+v", ips)
	}
	cfgMap := s.GetSettings()
	if cfgMap["waf_paranoia_level"] != "4" || cfgMap["waf_dlp_mode"] != "monitor" {
		t.Fatalf("expected clamped waf_paranoia_level=4 and waf_dlp_mode=monitor, got %v", cfgMap)
	}
}
