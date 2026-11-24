package proxy

import (
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

type UpstreamTarget struct {
	Raw            string
	URL            *url.URL
	healthy        atomic.Bool
	unhealthyUntil atomic.Int64
}

func (t *UpstreamTarget) IsHealthy() bool {
	if !t.healthy.Load() {
		if time.Now().Unix() >= t.unhealthyUntil.Load() {
			t.healthy.Store(true)
			return true
		}
		return false
	}
	return true
}

func (t *UpstreamTarget) MarkUnhealthy(backoff time.Duration) {
	t.healthy.Store(false)
	t.unhealthyUntil.Store(time.Now().Add(backoff).Unix())
}

func (t *UpstreamTarget) MarkHealthy() {
	t.healthy.Store(true)
	t.unhealthyUntil.Store(0)
}

type UpstreamPool struct {
	targets []*UpstreamTarget
	rr      atomic.Uint64
}

func ParseUpstreamPool(raw string) *UpstreamPool {
	normalized := strings.ReplaceAll(raw, "\n", ",")
	parts := strings.Split(normalized, ",")
	pool := &UpstreamPool{}
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		u, err := url.Parse(trimmed)
		if err != nil || u.Host == "" {
			continue
		}
		t := &UpstreamTarget{
			Raw: trimmed,
			URL: u,
		}
		t.healthy.Store(true)
		pool.targets = append(pool.targets, t)
	}
	return pool
}

func (p *UpstreamPool) Len() int {
	if p == nil {
		return 0
	}
	return len(p.targets)
}

func (p *UpstreamPool) Next() *UpstreamTarget {
	if p == nil || len(p.targets) == 0 {
		return nil
	}
	if len(p.targets) == 1 {
		return p.targets[0]
	}
	n := len(p.targets)
	start := int((p.rr.Add(1) - 1) % uint64(n))
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		if p.targets[idx].IsHealthy() {
			return p.targets[idx]
		}
	}
	return p.targets[start]
}

func (p *UpstreamPool) HealthSummary() (healthy, total int) {
	if p == nil {
		return 0, 0
	}
	total = len(p.targets)
	for _, t := range p.targets {
		if t.IsHealthy() {
			healthy++
		}
	}
	return healthy, total
}

func (p *UpstreamPool) ProbeAll(timeout time.Duration) {
	if p == nil || len(p.targets) <= 1 {
		return
	}
	for _, t := range p.targets {
		hostPort := t.URL.Host
		if !strings.Contains(hostPort, ":") {
			if strings.EqualFold(t.URL.Scheme, "https") {
				hostPort += ":443"
			} else {
				hostPort += ":80"
			}
		}
		conn, err := net.DialTimeout("tcp", hostPort, timeout)
		if err != nil {
			t.MarkUnhealthy(15 * time.Second)
			continue
		}
		_ = conn.Close()
		t.MarkHealthy()
	}
}
