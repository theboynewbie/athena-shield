package ratelimit

import (
	"testing"

	"github.com/theboynewbie/athena-shield/internal/config"
	"github.com/theboynewbie/athena-shield/internal/store"
)

func TestAdaptiveAPIEndpointRateLimit(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(dir, "admin", "admin@test.local", "GuardianWAF@2026")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	_ = s.UpdateSettings(map[string]string{"waf_api_rate_limit_max": "5"})
	cfg := config.Load()
	cfg.RateLimitMaxReq = 100
	cfg.LoginLimitMax = 3
	rl := New(cfg, s, nil)

	ip := "198.51.100.77"
	for i := 0; i < 5; i++ {
		if limited, reason, _ := rl.IsRateLimited(ip, "/api/orders", "GET", ""); limited {
			t.Fatalf("unexpected limit on request %d: %s", i+1, reason)
		}
	}
	if limited, _, _ := rl.IsRateLimited(ip, "/api/orders", "GET", ""); !limited {
		t.Fatalf("expected 6th request to /api/orders to trigger adaptive API rate limit")
	}

	// Different endpoint /api/products should have its own bucket and pass
	if limited, reason, _ := rl.IsRateLimited(ip, "/api/products", "GET", ""); limited {
		t.Fatalf("expected /api/products to have separate quota, got: %s", reason)
	}

	// Credential stuffing protection on /api/auth POST
	ip2 := "198.51.100.88"
	for i := 0; i < 3; i++ {
		if limited, reason, _ := rl.IsRateLimited(ip2, "/api/auth", "POST", ""); limited {
			t.Fatalf("unexpected auth limit on attempt %d: %s", i+1, reason)
		}
	}
	if limited, _, _ := rl.IsRateLimited(ip2, "/api/auth", "POST", ""); !limited {
		t.Fatalf("expected 4th POST to /api/auth to trigger brute force shield")
	}
}
