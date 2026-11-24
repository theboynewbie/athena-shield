package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

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
