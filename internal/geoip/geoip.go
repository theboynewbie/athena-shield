package geoip

import (
	"net"
	"net/http"
	"strings"
	"sync"
)

var (
	cacheMu  sync.RWMutex
	geoCache = make(map[string][2]string)
	maxCache = 25000

	trustedProxyMu sync.RWMutex
	trustedProxies []*net.IPNet

	trustedRangeMu sync.RWMutex
	trustedRanges  []*net.IPNet

	cfNets []*net.IPNet
)

func init() {
	for _, cidr := range []string{
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
		"108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
		"162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
		"2a06:98c0::/29", "2c0f:f248::/32",
	} {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			cfNets = append(cfNets, n)
		}
	}
}

func parseCIDRList(raw string) []*net.IPNet {
	var parsed []*net.IPNet
	for _, part := range strings.Split(raw, ",") {
		entry := strings.TrimSpace(part)
		if entry == "" {
			continue
		}
		if _, cidr, err := net.ParseCIDR(entry); err == nil {
			parsed = append(parsed, cidr)
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			bits := 128
			if v4 := ip.To4(); v4 != nil {
				ip = v4
				bits = 32
			}
			parsed = append(parsed, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return parsed
}

// ConfigureTrustedProxies parses a comma-separated list of IPs or CIDRs whose
// X-Real-IP / X-Forwarded-For headers may be trusted.
func ConfigureTrustedProxies(raw string) {
	parsed := parseCIDRList(raw)
	trustedProxyMu.Lock()
	trustedProxies = parsed
	trustedProxyMu.Unlock()
}

// ConfigureTrustedRanges parses a comma-separated list of IPs or CIDRs treated
// as trusted internal/partner ranges with higher rate-limit thresholds.
func ConfigureTrustedRanges(raw string) {
	parsed := parseCIDRList(raw)
	trustedRangeMu.Lock()
	trustedRanges = parsed
	trustedRangeMu.Unlock()
}

func isTrustedProxy(ip net.IP) bool {
	if ip == nil {
		return false
	}
	trustedProxyMu.RLock()
	defer trustedProxyMu.RUnlock()
	for _, n := range trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func IsPrivateOrLoopback(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast()
}

func IsTrustedRange(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	if IsPrivateOrLoopback(ip) {
		return true
	}
	trustedRangeMu.RLock()
	defer trustedRangeMu.RUnlock()
	for _, n := range trustedRanges {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func isCloudflareIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range cfNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func GetClientIP(r *http.Request) string {
	peerHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peerHost = r.RemoteAddr
	}
	peerIP := net.ParseIP(strings.TrimSpace(peerHost))
	realIP := strings.TrimSpace(peerHost)
	if realIP == "" {
		realIP = "127.0.0.1"
	}

	if isTrustedProxy(peerIP) {
		if xri := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); xri != nil {
			realIP = xri.String()
		} else if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			var fallback string
			for i := len(parts) - 1; i >= 0; i-- {
				if p := net.ParseIP(strings.TrimSpace(parts[i])); p != nil {
					fallback = p.String()
					if !isTrustedProxy(p) {
						realIP = p.String()
						fallback = ""
						break
					}
				}
			}
			if fallback != "" {
				realIP = fallback
			}
		}
	}

	if realParsed := net.ParseIP(realIP); isCloudflareIP(realParsed) {
		if cf := net.ParseIP(strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))); cf != nil {
			return cf.String()
		}
	}
	return realIP
}

func Resolve(ipStr, cfCountry string, syncFetch bool) (string, string) {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" || ipStr == "127.0.0.1" || ipStr == "localhost" || ipStr == "::1" {
		return "LOCAL", "Localhost / Internal"
	}
	if cc := strings.TrimSpace(cfCountry); len(cc) == 2 && isASCIIAlpha(cc[0]) && isASCIIAlpha(cc[1]) {
		upper := strings.ToUpper(cc)
		return upper, upper
	}

	cacheMu.RLock()
	if val, ok := geoCache[ipStr]; ok {
		cacheMu.RUnlock()
		return val[0], val[1]
	}
	cacheMu.RUnlock()

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "UNKNOWN", "Unknown Location"
	}
	if IsPrivateOrLoopback(ip) {
		setCache(ipStr, "LOCAL", "Internal Network (LAN)")
		return "LOCAL", "Internal Network (LAN)"
	}

	return "GLOBAL", "Global Traffic"
}

func isASCIIAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func setCache(ip, cc, cn string) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if len(geoCache) >= maxCache {
		geoCache = make(map[string][2]string)
	}
	geoCache[ip] = [2]string{cc, cn}
}
