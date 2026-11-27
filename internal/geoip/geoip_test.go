package geoip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetClientIPTrustedProxies(t *testing.T) {
	t.Cleanup(func() { ConfigureTrustedProxies("") })

	// 1. Untrusted private gateway (e.g. Docker 172.17.0.1) cannot spoof X-Real-IP or X-Forwarded-For
	ConfigureTrustedProxies("")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "172.17.0.1:50000"
	req.Header.Set("X-Real-IP", "10.0.0.5")
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.5")
	if got := GetClientIP(req); got != "172.17.0.1" {
		t.Fatalf("expected untrusted private peer 172.17.0.1 to ignore spoofed headers, got %q", got)
	}

	// 2. Configured trusted proxy honors X-Real-IP and X-Forwarded-For (right-most untrusted IP)
	ConfigureTrustedProxies("172.17.0.1/32, 10.0.0.0/8")
	reqXFF := httptest.NewRequest(http.MethodGet, "/", nil)
	reqXFF.RemoteAddr = "172.17.0.1:50000"
	reqXFF.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.42, 10.0.0.2")
	if got := GetClientIP(reqXFF); got != "198.51.100.42" {
		t.Fatalf("expected right-most untrusted IP 198.51.100.42, got %q", got)
	}

	reqXRI := httptest.NewRequest(http.MethodGet, "/", nil)
	reqXRI.RemoteAddr = "172.17.0.1:50000"
	reqXRI.Header.Set("X-Real-IP", "198.51.100.77")
	if got := GetClientIP(reqXRI); got != "198.51.100.77" {
		t.Fatalf("expected 198.51.100.77 from X-Real-IP, got %q", got)
	}

	// 3. Cloudflare peer honors CF-Connecting-IP
	ConfigureTrustedProxies("")
	reqCF := httptest.NewRequest(http.MethodGet, "/", nil)
	reqCF.RemoteAddr = "173.245.48.10:443"
	reqCF.Header.Set("CF-Connecting-IP", "198.51.100.88")
	if got := GetClientIP(reqCF); got != "198.51.100.88" {
		t.Fatalf("expected CF-Connecting-IP 198.51.100.88, got %q", got)
	}
}

func TestResolveOfflineNoExternalCall(t *testing.T) {
	cc, cn := Resolve("8.8.8.8", "", false)
	if cc != "GLOBAL" || cn != "Global Traffic" {
		t.Fatalf("expected GLOBAL / Global Traffic, got %q / %q", cc, cn)
	}
	cc2, cn2 := Resolve("8.8.8.8", "id", false)
	if cc2 != "ID" || cn2 != "ID" {
		t.Fatalf("expected ID / ID from cfCountry, got %q / %q", cc2, cn2)
	}
	cc3, _ := Resolve("192.168.1.10", "", true)
	if cc3 != "LOCAL" {
		t.Fatalf("expected LOCAL for private IP, got %q", cc3)
	}
}
