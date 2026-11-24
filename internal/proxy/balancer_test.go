package proxy

import (
	"testing"
	"time"
)

func TestParseUpstreamPoolAndRoundRobin(t *testing.T) {
	pool := ParseUpstreamPool("http://10.0.0.1:80, http://10.0.0.2:80, http://10.0.0.3:80")
	if pool.Len() != 3 {
		t.Fatalf("expected 3 upstreams, got %d", pool.Len())
	}

	// Round-robin A -> B -> C -> A
	got := []string{
		pool.Next().Raw,
		pool.Next().Raw,
		pool.Next().Raw,
		pool.Next().Raw,
	}
	want := []string{
		"http://10.0.0.1:80",
		"http://10.0.0.2:80",
		"http://10.0.0.3:80",
		"http://10.0.0.1:80",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rr[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// Mark node 2 unhealthy -> Next must never return node 2
	pool.targets[1].MarkUnhealthy(30 * time.Second)
	h, tot := pool.HealthSummary()
	if h != 2 || tot != 3 {
		t.Fatalf("expected 2/3 healthy, got %d/%d", h, tot)
	}
	for i := 0; i < 6; i++ {
		n := pool.Next()
		if n.Raw == "http://10.0.0.2:80" {
			t.Fatalf("expected unhealthy node 2 to be skipped")
		}
	}

	// Mark all unhealthy -> fail-open still returns a non-nil target
	pool.targets[0].MarkUnhealthy(30 * time.Second)
	pool.targets[2].MarkUnhealthy(30 * time.Second)
	if n := pool.Next(); n == nil {
		t.Fatalf("expected fail-open non-nil target when all unhealthy")
	}

	// Recover node 2 -> becomes selectable again
	pool.targets[1].MarkHealthy()
	if n := pool.Next(); n == nil || n.Raw != "http://10.0.0.2:80" {
		t.Fatalf("expected recovered node 2 to be selected, got %v", n)
	}
}
