package ratelimit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/theboynewbie/athena-shield/internal/alert"
	"github.com/theboynewbie/athena-shield/internal/config"
	"github.com/theboynewbie/athena-shield/internal/geoip"
	"github.com/theboynewbie/athena-shield/internal/store"
)

var multiSlashRe = regexp.MustCompile(`/+`)

type TempBanInfo struct {
	IP               string `json:"ip"`
	Type             string `json:"type"`
	RemainingSeconds int    `json:"remaining_seconds"`
	RemainingStr     string `json:"remaining_str"`
}

type RateLimiter struct {
	cfg      config.Config
	store    *store.Store
	notifier *alert.Notifier

	mu           sync.Mutex
	requests     map[string][]float64
	loginReqs    map[string][]float64
	loginHourly  map[string][]float64
	endpointReqs map[string][]float64
	violations   map[string][]float64
	tempBanned   map[string]float64
	apiMaxPerMin int
	lastCleanup  float64
}

func New(cfg config.Config, s *store.Store, n *alert.Notifier) *RateLimiter {
	rl := &RateLimiter{
		cfg:          cfg,
		store:        s,
		notifier:     n,
		requests:     make(map[string][]float64),
		loginReqs:    make(map[string][]float64),
		loginHourly:  make(map[string][]float64),
		endpointReqs: make(map[string][]float64),
		violations:   make(map[string][]float64),
		tempBanned:   make(map[string]float64),
		apiMaxPerMin: 30,
		lastCleanup:  float64(time.Now().Unix()),
	}
	if s != nil {
		if bans, err := s.ActiveAutoBans(float64(time.Now().Unix())); err == nil {
			for _, b := range bans {
				rl.tempBanned[b.IPAddress] = b.ExpiresAt
			}
		}
		rl.Reload()
	}
	return rl
}

func (rl *RateLimiter) Reload() {
	if rl.store == nil {
		return
	}
	cfg := rl.store.GetSettings()
	limit := 30
	if v, err := strconv.Atoi(cfg["waf_api_rate_limit_max"]); err == nil {
		if v < 5 {
			v = 5
		} else if v > 1000 {
			v = 1000
		}
		limit = v
	}
	rl.mu.Lock()
	rl.apiMaxPerMin = limit
	rl.mu.Unlock()
}

func (rl *RateLimiter) cleanup(now float64) {
	if now-rl.lastCleanup < 300 {
		return
	}
	cutGen := now - float64(rl.cfg.RateLimitWindowSec)
	for ip, list := range rl.requests {
		kept := filterAfter(list, cutGen)
		if len(kept) == 0 {
			delete(rl.requests, ip)
		} else {
			rl.requests[ip] = kept
		}
	}
	cutLogin := now - 60
	for ip, list := range rl.loginReqs {
		kept := filterAfter(list, cutLogin)
		if len(kept) == 0 {
			delete(rl.loginReqs, ip)
		} else {
			rl.loginReqs[ip] = kept
		}
	}
	cutHr := now - 3600
	for ip, list := range rl.loginHourly {
		kept := filterAfter(list, cutHr)
		if len(kept) == 0 {
			delete(rl.loginHourly, ip)
		} else {
			rl.loginHourly[ip] = kept
		}
	}
	for k, list := range rl.endpointReqs {
		kept := filterAfter(list, cutLogin)
		if len(kept) == 0 {
			delete(rl.endpointReqs, k)
		} else {
			rl.endpointReqs[k] = kept
		}
	}
	for ip, exp := range rl.tempBanned {
		if now >= exp {
			delete(rl.tempBanned, ip)
		}
	}
	rl.lastCleanup = now
}

func filterAfter(list []float64, cutoff float64) []float64 {
	var out []float64
	for _, t := range list {
		if t > cutoff {
			out = append(out, t)
		}
	}
	return out
}

func (rl *RateLimiter) IsTempBanned(ip string) (bool, int) {
	now := float64(time.Now().Unix())
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if exp, ok := rl.tempBanned[ip]; ok {
		if now < exp {
			rem := int(exp - now)
			if rem < 1 {
				rem = 1
			}
			if rem > 3600 {
				rem = 3600
			}
			return true, rem
		}
		delete(rl.tempBanned, ip)
	}
	return false, 0
}

func (rl *RateLimiter) RecordAttackViolation(ip string) {
	now := float64(time.Now().Unix())
	rl.mu.Lock()
	rl.cleanup(now)
	if exp, ok := rl.tempBanned[ip]; ok && now < exp {
		rl.mu.Unlock()
		return
	}
	list := filterAfter(rl.violations[ip], now-float64(rl.cfg.AutoBanWindowSec))
	list = append(list, now)
	rl.violations[ip] = list

	threshold := rl.cfg.AutoBanThreshold
	if geoip.IsTrustedRange(ip) {
		threshold *= 4
	}
	triggered := len(list) >= threshold
	var exp float64
	if triggered {
		exp = now + float64(rl.cfg.AutoBanDurationSec)
		rl.tempBanned[ip] = exp
	}
	rl.mu.Unlock()

	if triggered {
		reason := fmt.Sprintf("Exceeded %d security violations/hr", threshold)
		if rl.store != nil {
			rl.store.UpsertAutoBan(ip, exp, reason)
		}
		if rl.notifier != nil {
			rl.notifier.Notify("autoban", "Auto-Ban 24 Jam Diaktifkan", "", ip, "", fmt.Sprintf("Melampaui ambang %d pelanggaran serangan keamanan dalam 1 jam.", threshold))
		}
	}
}

func (rl *RateLimiter) UnbanIP(ip string) bool {
	rl.mu.Lock()
	unbanned := false
	if _, ok := rl.tempBanned[ip]; ok {
		delete(rl.tempBanned, ip)
		unbanned = true
	}
	if _, ok := rl.violations[ip]; ok {
		delete(rl.violations, ip)
		unbanned = true
	}
	delete(rl.loginReqs, ip)
	delete(rl.loginHourly, ip)
	delete(rl.requests, ip)
	prefix := ip + "|"
	for k := range rl.endpointReqs {
		if strings.HasPrefix(k, prefix) {
			delete(rl.endpointReqs, k)
		}
	}
	rl.mu.Unlock()

	if rl.store != nil && rl.store.DeleteAutoBan(ip) {
		unbanned = true
	}
	return unbanned
}

func (rl *RateLimiter) ActiveTempBans() []TempBanInfo {
	now := float64(time.Now().Unix())
	rl.mu.Lock()
	defer rl.mu.Unlock()
	var out []TempBanInfo
	for ip, exp := range rl.tempBanned {
		if exp > now {
			rem := int(exp - now)
			out = append(out, TempBanInfo{
				IP:               ip,
				Type:             "Auto-Ban Jail",
				RemainingSeconds: rem,
				RemainingStr:     store.FormatDurationRemaining(rem),
			})
		}
	}
	return out
}

func (rl *RateLimiter) IsRateLimited(ip, path, method, query string) (bool, string, int) {
	now := float64(time.Now().Unix())
	rl.mu.Lock()
	rl.cleanup(now)

	if exp, ok := rl.tempBanned[ip]; ok {
		if now < exp {
			rem := int(exp - now)
			if rem < 1 {
				rem = 1
			}
			retry := rem
			if retry > 3600 {
				retry = 3600
			}
			rl.mu.Unlock()
			return true, fmt.Sprintf("Auto-Banned: Too many violations/bruteforce (Jail remaining: %ds)", rem), retry
		}
		delete(rl.tempBanned, ip)
	}

	pathLower := strings.TrimRight(multiSlashRe.ReplaceAllString(strings.ToLower(path), "/"), "/")
	if pathLower == "" {
		pathLower = "/"
	}
	queryLower := strings.ToLower(query)
	isAuthPost := (strings.EqualFold(method, "POST") && (strings.Contains(pathLower, "wp-login.php") ||
		strings.Contains(pathLower, "wp-signup.php") ||
		pathLower == "/login" || pathLower == "/signin" || pathLower == "/auth/login" ||
		pathLower == "/admin/login" || pathLower == "/user/login" || pathLower == "/login/signin" ||
		strings.HasPrefix(pathLower, "/api/auth") || pathLower == "/oauth/token" ||
		pathLower == "/api/login" || pathLower == "/api/register" ||
		pathLower == "/reset-password" || pathLower == "/forgot-password" ||
		strings.HasSuffix(pathLower, "/login") || strings.HasSuffix(pathLower, "/signin") || strings.HasSuffix(pathLower, "/login/signin") ||
		strings.Contains(queryLower, "p=login") || strings.Contains(pathLower, "xmlrpc.php"))) ||
		strings.Contains(pathLower, "xmlrpc.php")

	if isAuthPost {
		rl.loginReqs[ip] = filterAfter(rl.loginReqs[ip], now-60)
		rl.loginHourly[ip] = filterAfter(rl.loginHourly[ip], now-3600)
		if len(rl.loginReqs[ip]) >= rl.cfg.LoginLimitMax {
			rl.mu.Unlock()
			rl.RecordAttackViolation(ip)
			return true, fmt.Sprintf("Brute Force Shield: Max %d auth attempts/min exceeded on %s", rl.cfg.LoginLimitMax, path), 60
		}
		if len(rl.loginHourly[ip]) >= rl.cfg.LoginHourlyMax {
			exp := now + float64(rl.cfg.AutoBanDurationSec)
			rl.tempBanned[ip] = exp
			rl.mu.Unlock()
			if rl.store != nil {
				rl.store.UpsertAutoBan(ip, exp, fmt.Sprintf("Exceeded %d auth attempts/hr on %s", rl.cfg.LoginHourlyMax, path))
			}
			return true, fmt.Sprintf("Brute Force Shield: Max %d auth attempts/hour exceeded (Auto-Banned)", rl.cfg.LoginHourlyMax), 3600
		}
		rl.loginReqs[ip] = append(rl.loginReqs[ip], now)
		rl.loginHourly[ip] = append(rl.loginHourly[ip], now)
	}

	if strings.HasPrefix(pathLower, "/api/") {
		epKey := ip + "|" + pathLower
		rl.endpointReqs[epKey] = filterAfter(rl.endpointReqs[epKey], now-60)
		epLimit := rl.apiMaxPerMin
		if epLimit < 5 {
			epLimit = 30
		}
		if geoip.IsTrustedRange(ip) {
			epLimit *= 2
		}
		if len(rl.endpointReqs[epKey]) >= epLimit {
			rl.mu.Unlock()
			return true, fmt.Sprintf("Adaptive API Rate Limit: Exceeded %d req/min on %s", epLimit, pathLower), 60
		}
		rl.endpointReqs[epKey] = append(rl.endpointReqs[epKey], now)
	}

	maxReq := rl.cfg.RateLimitMaxReq
	if geoip.IsTrustedRange(ip) {
		maxReq *= 2
	}
	rl.requests[ip] = filterAfter(rl.requests[ip], now-float64(rl.cfg.RateLimitWindowSec))
	if len(rl.requests[ip]) >= maxReq {
		rl.mu.Unlock()
		return true, fmt.Sprintf("DDoS/Flood Protection: Exceeded %d req/%ds", maxReq, rl.cfg.RateLimitWindowSec), rl.cfg.RateLimitWindowSec
	}
	rl.requests[ip] = append(rl.requests[ip], now)
	rl.mu.Unlock()
	return false, "", 0
}
