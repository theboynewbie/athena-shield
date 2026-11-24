package waf

import (
	"crypto/tls"
	"net/http"
	"strings"
)

var verifiedGoodBots = []string{
	"googlebot",
	"bingbot",
	"duckduckbot",
	"applebot",
	"slurp",
	"yandexbot",
	"uptimerobot",
}

var headlessMarkers = []string{
	"headlesschrome",
	"phantomjs",
	"selenium",
	"puppeteer",
	"playwright",
	"webdriver",
	"cypress",
}

func IsVerifiedGoodBot(ua string) bool {
	if ua == "" {
		return false
	}
	u := strings.ToLower(ua)
	for _, b := range verifiedGoodBots {
		if strings.Contains(u, b) {
			return true
		}
	}
	return false
}

// AnalyzeBotFingerprint detects headless automation frameworks and TLS/HTTP header spoofing.
func AnalyzeBotFingerprint(r *http.Request) (suspicious bool, hardBot bool, reason string) {
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	if ua != "" {
		for _, m := range headlessMarkers {
			if strings.Contains(ua, m) {
				return true, true, "Bot Fingerprint Shield: Headless browser/automation framework detected"
			}
		}
		isModernClaim := strings.Contains(ua, "chrome/1") || strings.Contains(ua, "firefox/1")
		if isModernClaim && r.ProtoMajor == 1 && r.ProtoMinor == 0 {
			return true, false, "Bot Fingerprint Shield: Modern browser UA spoofed over legacy HTTP/1.0"
		}
		if isModernClaim && r.TLS != nil && r.TLS.Version < tls.VersionTLS12 {
			return true, false, "Bot Fingerprint Shield: Modern browser UA spoofed over deprecated TLS < 1.2"
		}
	}

	if strings.EqualFold(r.Header.Get("Sec-Fetch-Mode"), "navigate") &&
		r.Header.Get("Accept-Language") == "" &&
		r.Header.Get("Accept-Encoding") == "" {
		return true, false, "Bot Fingerprint Shield: Inconsistent browser navigation headers"
	}

	return false, false, ""
}
