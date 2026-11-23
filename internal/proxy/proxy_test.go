package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/theboynewbie/athena-shield/internal/cache"
	"github.com/theboynewbie/athena-shield/internal/config"
	"github.com/theboynewbie/athena-shield/internal/ratelimit"
	"github.com/theboynewbie/athena-shield/internal/store"
	"github.com/theboynewbie/athena-shield/internal/waf"
)

func TestProxyForwardRedirectBlockAndCache(t *testing.T) {
	var upstreamHits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "<html><body>OK %d %s</body></html>", upstreamHits, r.URL.Path)
	}))
	defer upstream.Close()

	dir := t.TempDir()
	s, err := store.Open(dir, "admin", "admin@test.local", "GuardianWAF@2026")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.CreateProxyHost(&store.ProxyHost{
		DomainName:       "app.local",
		TargetUpstream:   upstream.URL,
		HostType:         "proxy",
		SSLType:          "none",
		ForceHTTPS:       false,
		WAFEnabled:       true,
		WAFMode:          "active",
		RateLimitEnabled: true,
		AppProfile:       "universal",
		BlockBadBots:     true,
		EdgeCacheEnabled: true,
		IsActive:         true,
	}); err != nil {
		t.Fatal(err)
	}

	if err := s.CreateProxyHost(&store.ProxyHost{
		DomainName:         "old.local",
		HostType:           "redirect",
		RedirectURL:        "https://new.local",
		RedirectStatusCode: 301,
		PreservePath:       true,
		SSLType:            "none",
		IsActive:           true,
	}); err != nil {
		t.Fatal(err)
	}

	cfg := config.Load()
	rl := ratelimit.New(cfg, s, nil)
	eng := waf.NewEngine(cfg, s, rl)
	ec := cache.NewEdgeCache()
	rt := NewRouter(cfg, s, eng, rl, ec, nil, nil, nil)

	// 1. First request -> Cache MISS, hits upstream
	req1 := httptest.NewRequest("GET", "http://app.local/hello", nil)
	req1.Host = "app.local"
	req1.RemoteAddr = "203.0.113.10:1234"
	rec1 := httptest.NewRecorder()
	rt.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec1.Code, rec1.Body.String())
	}
	if rec1.Header().Get("X-Athena-Cache") != "MISS" {
		t.Fatalf("expected MISS, got %q", rec1.Header().Get("X-Athena-Cache"))
	}

	// 2. Second request -> Cache HIT, upstreamHits stays 1
	req2 := httptest.NewRequest("GET", "http://app.local/hello", nil)
	req2.Host = "app.local"
	req2.RemoteAddr = "203.0.113.10:1234"
	rec2 := httptest.NewRecorder()
	rt.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK || rec2.Header().Get("X-Athena-Cache") != "HIT" {
		t.Fatalf("expected 200 HIT, got %d %q", rec2.Code, rec2.Header().Get("X-Athena-Cache"))
	}
	if upstreamHits != 1 {
		t.Fatalf("expected upstreamHits=1, got %d", upstreamHits)
	}

	// 3. Attack request -> 403 Forbidden
	reqAtk := httptest.NewRequest("GET", "http://app.local/?q=slot+gacor", nil)
	reqAtk.Host = "app.local"
	reqAtk.RemoteAddr = "203.0.113.10:1234"
	recAtk := httptest.NewRecorder()
	rt.ServeHTTP(recAtk, reqAtk)
	if recAtk.Code != http.StatusForbidden {
		body, _ := io.ReadAll(recAtk.Body)
		t.Fatalf("expected 403, got %d (%s)", recAtk.Code, string(body))
	}

	// 4. Redirect host -> 301 with preserved path
	reqRed := httptest.NewRequest("GET", "http://old.local/berita?id=5", nil)
	reqRed.Host = "old.local"
	recRed := httptest.NewRecorder()
	rt.ServeHTTP(recRed, reqRed)
	if recRed.Code != http.StatusMovedPermanently || recRed.Header().Get("Location") != "https://new.local/berita?id=5" {
		t.Fatalf("expected 301 to https://new.local/berita?id=5, got %d -> %q", recRed.Code, recRed.Header().Get("Location"))
	}
}
