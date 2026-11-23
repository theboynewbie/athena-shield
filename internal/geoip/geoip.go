package geoip

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	cacheMu  sync.RWMutex
	geoCache = make(map[string][2]string)
	maxCache = 25000

	unejNets []*net.IPNet
	cfNets   []*net.IPNet
)

func init() {
	for _, cidr := range []string{
		"103.241.204.0/22",
		"103.241.205.0/24",
		"103.160.182.0/24",
		"103.10.106.0/24",
	} {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			unejNets = append(unejNets, n)
		}
	}
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
	for _, n := range unejNets {
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

	if IsPrivateOrLoopback(peerIP) {
		if xri := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); xri != nil {
			realIP = xri.String()
		} else if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				if p := net.ParseIP(strings.TrimSpace(parts[i])); p != nil {
					realIP = p.String()
					break
				}
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
	if len(strings.TrimSpace(cfCountry)) == 2 {
		cc := strings.ToUpper(strings.TrimSpace(cfCountry))
		return cc, cc
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
	for _, n := range unejNets {
		if n.Contains(ip) {
			setCache(ipStr, "ID", "Indonesia (Campus)")
			return "ID", "Indonesia (Campus)"
		}
	}

	fetch := func() (string, string, bool) {
		client := &http.Client{Timeout: 1800 * time.Millisecond}
		resp, err := client.Get("http://ip-api.com/json/" + ipStr + "?fields=status,country,countryCode")
		if err != nil {
			return "", "", false
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return "", "", false
		}
		var data struct {
			Status      string `json:"status"`
			Country     string `json:"country"`
			CountryCode string `json:"countryCode"`
		}
		if json.NewDecoder(resp.Body).Decode(&data) == nil && data.Status == "success" {
			cc := strings.ToUpper(data.CountryCode)
			if cc == "" {
				cc = "UNKNOWN"
			}
			cn := data.Country
			if cn == "" {
				cn = cc
			}
			setCache(ipStr, cc, cn)
			return cc, cn, true
		}
		return "", "", false
	}

	if syncFetch {
		if cc, cn, ok := fetch(); ok {
			return cc, cn
		}
		return "GLOBAL", "Global Traffic"
	}

	go fetch()
	return "GLOBAL", "Global Traffic"
}

func setCache(ip, cc, cn string) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if len(geoCache) >= maxCache {
		geoCache = make(map[string][2]string)
	}
	geoCache[ip] = [2]string{cc, cn}
}
