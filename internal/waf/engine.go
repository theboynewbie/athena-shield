package waf

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/theboynewbie/athena-shield/internal/config"
	"github.com/theboynewbie/athena-shield/internal/geoip"
	"github.com/theboynewbie/athena-shield/internal/ratelimit"
	"github.com/theboynewbie/athena-shield/internal/store"
)

const BadCrawlerRuleName = "Aggressive AI & SEO Bot Crawlers (Anti-Scraping & Load Shield)"

var (
	badCrawlerRe        = regexp.MustCompile(`(?i)(claudebot|claude-web|anthropic-ai|semrushbot|ahrefsbot|mj12bot|dotbot|blexbot|dataforseobot|bytespider|gptbot|ccbot|petalbot|barkrowler|seekportbot|meta-externalagent|diffbot|omgili|imagesiftbot)`)
	dangerousUploadRe   = regexp.MustCompile(`(?i)\.(php[0-9]?|phtml|phar|phps|pgif|shtml|htaccess|user\.ini|pl|py|cgi|sh|asp|aspx|jsp|jspx)\b`)
	uploadDirRe         = regexp.MustCompile(`(?i)/(?:wp-content/uploads|repository|images/(?:docs|persons)|files/(?:backup|membercard)|public/journals|storage/app/public|uploads)/`)
	uploadScriptExtRe   = regexp.MustCompile(`(?i)\.(?:php[0-9]?|phtml|phar|pl|py|cgi|sh|asp|aspx|jsp)$`)
	authorEnumRe        = regexp.MustCompile(`(?i)\bauthor\s*=\s*\d+`)
	wpUsersRestRe       = regexp.MustCompile(`(?i)/wp-json/wp/v2/users/?(\?|$|\d+)`)
	wpUsersQueryRe      = regexp.MustCompile(`(?i)rest_route=/wp/v2/users/?(&|$|\d+)`)
	sqlDumpRe           = regexp.MustCompile(`(?i)/(?:backup|dump|database|db_backup|slims|wordpress)\.sql(?:\.gz|\.zip|\.bak)?$`)
	ssrfOrXXERe         = regexp.MustCompile(`(?i)(169\.254\.169\.254|metadata\.google\.internal|(?:gopher|dict)://|<!ENTITY\s+[%\w]+\s+SYSTEM\b)`)
	boundaryRe          = regexp.MustCompile(`(?i)boundary=([^\s;]+)`)
	filenameHeaderRe    = regexp.MustCompile(`(?i)filename\*?=["']?([^"';\r\n]+)`)
	multiSpaceRe        = regexp.MustCompile(`\s+`)

	staticExtensions = []string{
		".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg",
		".woff", ".woff2", ".ttf", ".eot", ".webp", ".mp4", ".map",
	}
	safeBinaryExtensions = []string{
		".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp",
		".pdf", ".zip", ".mp4", ".mp3", ".wav", ".ogg", ".webm",
		".woff", ".woff2", ".ttf", ".eot",
	}
	binaryMIMEs = []string{
		"image/png", "image/jpeg", "image/jpg", "image/gif", "image/webp",
		"image/x-icon", "image/bmp", "application/pdf", "application/zip",
		"application/x-zip", "application/x-zip-compressed", "application/octet-stream",
		"audio/", "video/",
	}
	adminEditorPaths = map[string]bool{
		"/wp-admin/admin.php":           true,
		"/wp-admin/admin-ajax.php":      true,
		"/wp-admin/theme-editor.php":    true,
		"/wp-admin/plugin-editor.php":   true,
		"/wp-admin/customize.php":       true,
		"/wp-admin/update.php":          true,
		"/wp-admin/plugin-install.php":  true,
		"/wp-admin/theme-install.php":   true,
		"/wp-admin/options-general.php": true,
		"/wp-admin/options.php":         true,
	}
	adminExemptCategories = map[string]bool{
		"sqli":   true,
		"xss":    true,
		"custom": true,
	}
	universalSensitiveFiles = []string{
		"wp-config.php", "wp-config.bak", "wp-config.old", "debug.log",
		"sysconfig.local.inc.php", "sysconfig.inc.php", "printed_settings.inc.php",
		"config.inc.php", "localsettings.php",
		"/.env", "/storage/logs/laravel.log", "/_ignition/execute-solution", "/vendor/phpunit/",
		"/.git/config", "/.git/head", "/.svn/", "/phpinfo.php",
	}
)

type compiledRule struct {
	ID            int64
	Name          string
	Regex         *regexp.Regexp
	Category      string
	Action        string // BLOCK, MONITOR
	Severity      string
	Score         int
	ParanoiaLevel int
	IsJudi        bool
}

type snapshot struct {
	rules            []compiledRule
	whitelistIPs     map[string]bool
	whitelistNets    []*net.IPNet
	blacklistIPs     map[string]bool
	blacklistNets    []*net.IPNet
	anomalyThreshold int
	paranoiaLevel    int
	dlpEnabled       bool
	dlpMode          string
	deepParseEnabled bool
}

type Decision struct {
	Blocked       bool
	Reason        string
	Category      string
	RetryAfter    int
	Mode          string // active, monitor, bypass
	AnomalyScore  int
	Threshold     int
	MatchedRules  []string
	ShadowMatches []string
}

type Engine struct {
	cfg         config.Config
	store       *store.Store
	rateLimiter *ratelimit.RateLimiter
	snap        atomic.Pointer[snapshot]

	adminCacheMu sync.Mutex
	adminCache   map[string]adminCacheEntry
	verifyClient *http.Client
}

type adminCacheEntry struct {
	ok        bool
	expiresAt time.Time
}

func NewEngine(cfg config.Config, s *store.Store, rl *ratelimit.RateLimiter) *Engine {
	e := &Engine{
		cfg:         cfg,
		store:       s,
		rateLimiter: rl,
		adminCache:  make(map[string]adminCacheEntry),
		verifyClient: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	e.Reload()
	return e
}

func (e *Engine) Reload() {
	if e.store == nil {
		return
	}
	s := &snapshot{
		whitelistIPs:     make(map[string]bool),
		blacklistIPs:     make(map[string]bool),
		anomalyThreshold: 5,
		paranoiaLevel:    1,
		dlpEnabled:       true,
		dlpMode:          "block",
		deepParseEnabled: true,
	}

	cfg := e.store.GetSettings()
	if v, err := strconv.Atoi(cfg["waf_anomaly_threshold"]); err == nil && v >= 1 && v <= 50 {
		s.anomalyThreshold = v
	}
	if v, err := strconv.Atoi(cfg["waf_paranoia_level"]); err == nil && v >= 1 && v <= 4 {
		s.paranoiaLevel = v
	}
	if strings.EqualFold(cfg["waf_dlp_enabled"], "false") {
		s.dlpEnabled = false
	}
	if strings.EqualFold(cfg["waf_dlp_mode"], "monitor") {
		s.dlpMode = "monitor"
	}
	if strings.EqualFold(cfg["waf_deep_parse_enabled"], "false") {
		s.deepParseEnabled = false
	}

	if rules, err := e.store.ListRules(); err == nil {
		for _, r := range rules {
			act := strings.ToUpper(strings.TrimSpace(r.Action))
			if !r.IsActive || (act != "BLOCK" && act != "MONITOR") {
				continue
			}
			re, err := regexp.Compile("(?im)" + r.Pattern)
			if err != nil {
				log.Printf("[ATHENA WAF] Skipping incompatible RE2 regex rule ID %d (%s): %v", r.ID, r.Name, err)
				continue
			}
			catLower := strings.ToLower(r.Category)
			nameLower := strings.ToLower(r.Name)
			isJudi := catLower == "judi_slot" || strings.Contains(nameLower, "judi") || strings.Contains(nameLower, "slot")
			score := r.Score
			if score <= 0 {
				score = 5
			}
			pl := r.ParanoiaLevel
			if pl < 1 {
				pl = 1
			}
			s.rules = append(s.rules, compiledRule{
				ID:            r.ID,
				Name:          r.Name,
				Regex:         re,
				Category:      r.Category,
				Action:        act,
				Severity:      r.Severity,
				Score:         score,
				ParanoiaLevel: pl,
				IsJudi:        isJudi,
			})
		}
	}

	if ips, err := e.store.ListIPs(); err == nil {
		for _, item := range ips {
			addr := strings.TrimSpace(item.IPAddress)
			if addr == "" {
				continue
			}
			isWhite := strings.EqualFold(item.ListType, "WHITELIST")
			if strings.Contains(addr, "/") {
				if _, cidr, err := net.ParseCIDR(addr); err == nil {
					if isWhite {
						s.whitelistNets = append(s.whitelistNets, cidr)
					} else {
						s.blacklistNets = append(s.blacklistNets, cidr)
					}
					continue
				}
			}
			if isWhite {
				s.whitelistIPs[addr] = true
			} else {
				s.blacklistIPs[addr] = true
			}
		}
	}

	e.snap.Store(s)
}

func matchIP(ipStr string, exact map[string]bool, nets []*net.IPNet) bool {
	if exact[ipStr] {
		return true
	}
	if len(nets) == 0 {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func IsStaticAssetPath(p string) bool {
	cleanP := strings.ToLower(strings.SplitN(p, "?", 2)[0])
	for _, ext := range staticExtensions {
		if strings.HasSuffix(cleanP, ext) {
			return true
		}
	}
	return false
}

func isSafeStaticQuery(query string) bool {
	if query == "" {
		return true
	}
	ql := strings.ToLower(query)
	dangerous := []string{"<", ">", "'", `"`, ";", "%27", "%22", "%3c", "%3e", "union", "select", "script", "../", `..\`}
	for _, d := range dangerous {
		if strings.Contains(ql, d) {
			return false
		}
	}
	return true
}

func (e *Engine) Inspect(r *http.Request, host *store.ProxyHost, bodyBytes []byte) Decision {
	wafMode := "active"
	wafOn := true
	blockBadBots := true
	rateLimitOn := true
	appProfile := "universal"

	if host != nil {
		if host.WAFMode != "" {
			wafMode = strings.ToLower(host.WAFMode)
		} else if !host.WAFEnabled {
			wafMode = "bypass"
		}
		wafOn = host.WAFEnabled && wafMode != "bypass"
		blockBadBots = host.BlockBadBots
		rateLimitOn = host.RateLimitEnabled
		if host.AppProfile != "" {
			appProfile = strings.ToLower(host.AppProfile)
		}
	}

	if !wafOn {
		return Decision{Blocked: false, Mode: "bypass"}
	}

	// 0. HTTP Request Smuggling Guard (CL.TE / TE.CL conflict)
	if len(r.Header.Values("Transfer-Encoding")) > 0 && r.Header.Get("Content-Length") != "" {
		return Decision{
			Blocked:  true,
			Reason:   "Protocol Hardening: HTTP Request Smuggling (Conflicting Content-Length & Transfer-Encoding) blocked",
			Category: "Protocol Hardening",
			Mode:     wafMode,
		}
	}

	clientIP := geoip.GetClientIP(r)
	snap := e.snap.Load()
	if snap == nil {
		snap = &snapshot{}
	}

	// 1. Whitelist
	if matchIP(clientIP, snap.whitelistIPs, snap.whitelistNets) {
		return Decision{Blocked: false, Mode: wafMode}
	}

	// 2. Blacklist
	if matchIP(clientIP, snap.blacklistIPs, snap.blacklistNets) {
		return Decision{
			Blocked:  true,
			Reason:   fmt.Sprintf("IP %s is permanently blacklisted", clientIP),
			Category: "IP Blacklist",
			Mode:     wafMode,
		}
	}

	// 3. Bad Bots
	uaRaw := r.Header.Get("User-Agent")
	if blockBadBots && uaRaw != "" {
		if m := badCrawlerRe.FindString(uaRaw); m != "" {
			return Decision{
				Blocked:  true,
				Reason:   fmt.Sprintf("Bot Crawler Shield: Aggressive crawler blocked (%s)", m),
				Category: "bot_attack",
				Mode:     wafMode,
			}
		}
	}

	// 4. Static Asset Fast-Path
	rawQuery := r.URL.RawQuery
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && IsStaticAssetPath(r.URL.Path) && isSafeStaticQuery(rawQuery) {
		if e.rateLimiter != nil {
			if banned, rem := e.rateLimiter.IsTempBanned(clientIP); banned {
				return Decision{
					Blocked:    true,
					Reason:     fmt.Sprintf("Auto-Banned: Too many violations/bruteforce (Jail remaining: %ds)", rem),
					Category:   "Rate Limiting",
					RetryAfter: rem,
					Mode:       wafMode,
				}
			}
		}
		dec := e.scanTargets(snap, []targetPair{
			{Name: "URI Path", Value: r.URL.Path},
			{Name: "Query Params", Value: rawQuery},
		}, nil, !blockBadBots)
		dec.Mode = wafMode
		return dec
	}

	// 5. Rate Limiting
	if rateLimitOn && e.rateLimiter != nil {
		if limited, reason, retry := e.rateLimiter.IsRateLimited(clientIP, r.URL.Path, r.Method, rawQuery); limited {
			return Decision{
				Blocked:    true,
				Reason:     reason,
				Category:   "Rate Limiting",
				RetryAfter: retry,
				Mode:       wafMode,
			}
		}
	}

	// 6. App Hardening & Virtual Patching
	pathLower := multiSlashReLower(r.URL.Path)
	queryLower, _ := url.QueryUnescape(strings.ToLower(rawQuery))
	if queryLower == "" {
		queryLower = strings.ToLower(rawQuery)
	}

	if (appProfile == "universal" || appProfile == "wordpress") && strings.Contains(pathLower, "xmlrpc.php") {
		return Decision{
			Blocked:  true,
			Reason:   "App Hardening: XML-RPC interface disabled (Anti-DDoS / Brute Force Amplification)",
			Category: "App Hardening",
			Mode:     wafMode,
		}
	}

	normUploadPath := "/" + strings.TrimLeft(pathLower, "/")
	if uploadDirRe.MatchString(normUploadPath) && uploadScriptExtRe.MatchString(pathLower) {
		return Decision{
			Blocked:  true,
			Reason:   "App Hardening: Direct script execution inside public uploads/repository directory blocked",
			Category: "App Hardening",
			Mode:     wafMode,
		}
	}

	contentType := r.Header.Get("Content-Type")
	if badFn := hasMaliciousUploadFilename(contentType, bodyBytes); badFn != "" {
		return Decision{
			Blocked:  true,
			Reason:   fmt.Sprintf("App Hardening: Executable/Webshell file upload blocked ('%s')", badFn),
			Category: "App Hardening",
			Mode:     wafMode,
		}
	}

	if appProfile == "universal" || appProfile == "wordpress" {
		isOPAC := containsAny(queryLower, "keywords=", "search=", "p=show_detail", "isbn=", "biblio", "title=", "subject=")
		if !isOPAC && strings.Contains(queryLower, "author=") && authorEnumRe.MatchString(queryLower) {
			unqPath, _ := url.PathUnescape(pathLower)
			if unqPath == "" {
				unqPath = pathLower
			}
			norm := strings.ReplaceAll(path.Clean("/"+strings.TrimLeft(unqPath, "/")), `\`, "/")
			isWPAdmin := strings.Contains(norm+"/", "/wp-admin/") && !strings.Contains(pathLower, "..") && !strings.Contains(unqPath, "..")
			if !isWPAdmin && !(hasWordPressAdminCookie(r) && e.verifyWPAdminSession(r, host)) {
				return Decision{
					Blocked:  true,
					Reason:   "WP Hardening: User enumeration scan blocked (Author ID probing)",
					Category: "WP Hardening",
					Mode:     wafMode,
				}
			}
		}

		isUserEnum := wpUsersRestRe.MatchString(pathLower) || wpUsersQueryRe.MatchString(queryLower)
		if isUserEnum && !strings.HasSuffix(pathLower, "/me") && !strings.Contains(queryLower, "users/me") {
			if !hasWordPressAdminCookie(r) {
				return Decision{
					Blocked:  true,
					Reason:   "WP Hardening: Unauthenticated REST API user enumeration blocked (/wp/v2/users)",
					Category: "WP Hardening",
					Mode:     wafMode,
				}
			}
		}
	}

	for _, sf := range universalSensitiveFiles {
		if strings.Contains(pathLower, sf) {
			return Decision{
				Blocked:  true,
				Reason:   fmt.Sprintf("App Hardening: Access to sensitive resource %s blocked", sf),
				Category: "App Hardening",
				Mode:     wafMode,
			}
		}
	}
	if (appProfile == "universal" || appProfile == "wordpress") && strings.HasSuffix(pathLower, "/readme.html") {
		return Decision{
			Blocked:  true,
			Reason:   "WP Hardening: Access to sensitive file readme.html blocked",
			Category: "WP Hardening",
			Mode:     wafMode,
		}
	}
	if sqlDumpRe.MatchString(pathLower) {
		return Decision{
			Blocked:  true,
			Reason:   "App Hardening: Access to exposed SQL database dump blocked",
			Category: "App Hardening",
			Mode:     wafMode,
		}
	}

	if len(bodyBytes) > e.cfg.MaxNonMultipartBody && !strings.HasPrefix(strings.ToLower(contentType), "multipart/form-data") {
		if !(hasWordPressAdminCookie(r) && e.verifyWPAdminSession(r, host)) {
			return Decision{
				Blocked:  true,
				Reason:   "WAF Protection: Non-multipart request body exceeds 10MB limit (Anti-DoS)",
				Category: "App Hardening",
				Mode:     wafMode,
			}
		}
	}

	bodyText := extractInspectableBodyText(contentType, bodyBytes, e.cfg.MaxInspectBodyBytes)
	if ssrfOrXXERe.MatchString(queryLower) || ssrfOrXXERe.MatchString(bodyText) {
		return Decision{
			Blocked:  true,
			Reason:   "App Hardening: Cloud Metadata SSRF / XXE External Entity injection blocked",
			Category: "App Hardening",
			Mode:     wafMode,
		}
	}
	isAdminCode := isAdminCodeEditorRequest(r, bodyText) && e.verifyWPAdminSession(r, host)

	var hdrBuilder strings.Builder
	for k, vals := range r.Header {
		switch strings.ToLower(k) {
		case "user-agent", "accept", "accept-language", "accept-encoding", "connection",
			"upgrade-insecure-requests", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
			"sec-fetch-user", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
			"cache-control", "pragma", "if-modified-since", "if-none-match", "content-length", "host":
			continue
		}
		for _, v := range vals {
			hdrBuilder.WriteString(k)
			hdrBuilder.WriteByte(':')
			hdrBuilder.WriteString(v)
			hdrBuilder.WriteByte(' ')
		}
	}

	targets := []targetPair{
		{Name: "URI Path", Value: r.URL.Path},
		{Name: "Query Params", Value: rawQuery},
		{Name: "User-Agent", Value: uaRaw},
		{Name: "Headers", Value: hdrBuilder.String()},
		{Name: "Request Body", Value: bodyText},
	}

	if snap.deepParseEnabled && len(bodyBytes) > 0 {
		deepTargets, structViolation := ExtractDeepTargets(contentType, bodyBytes, e.cfg.MaxInspectBodyBytes)
		if structViolation != "" {
			return Decision{
				Blocked:  true,
				Reason:   structViolation,
				Category: "Protocol Hardening",
				Mode:     wafMode,
			}
		}
		if len(deepTargets) > 0 {
			targets = append(targets, deepTargets...)
		}
	}

	var skipCats map[string]bool
	if isAdminCode {
		skipCats = adminExemptCategories
	}
	dec := e.scanTargets(snap, targets, skipCats, !blockBadBots)
	dec.Mode = wafMode
	return dec
}

type targetPair struct {
	Name  string
	Value string
}

func isBodyTargetName(name string) bool {
	return name == "Request Body" || name == "JSON Field" || name == "GraphQL Query" ||
		name == "XML Field" || name == "Form Field" || name == "Multipart Field"
}

func (e *Engine) scanTargets(snap *snapshot, targets []targetPair, skipBodyCats map[string]bool, skipBadCrawler bool) Decision {
	baseCache := make(map[int][]string)
	deepCache := make(map[int][]string)

	threshold := snap.anomalyThreshold
	if threshold <= 0 {
		threshold = 5
	}
	pl := snap.paranoiaLevel
	if pl <= 0 {
		pl = 1
	}

	totalScore := 0
	var primaryReason, primaryCat string
	var matchedRules, shadowMatches []string

	for _, rule := range snap.rules {
		if rule.ParanoiaLevel > pl {
			continue
		}
		if skipBadCrawler && rule.Name == BadCrawlerRuleName {
			continue
		}
		cache := baseCache
		if rule.IsJudi {
			cache = deepCache
		}
		ruleMatched := false
		for idx, t := range targets {
			if ruleMatched {
				break
			}
			if t.Value == "" {
				continue
			}
			if skipBodyCats != nil && isBodyTargetName(t.Name) && skipBodyCats[strings.ToLower(rule.Category)] {
				continue
			}
			variants, ok := cache[idx]
			if !ok {
				variants = NormalizeTextPayload(t.Value, rule.IsJudi)
				cache[idx] = variants
			}
			for _, v := range variants {
				if m := rule.Regex.FindString(v); m != "" {
					if rule.Name == "Malicious Scanner & Bot User-Agents" && (strings.Contains(v, "python-requests/") || strings.Contains(v, "curl/")) && strings.Contains(strings.ToLower(v), "trusted") {
						continue
					}
					snippet := strings.TrimSpace(multiSpaceRe.ReplaceAllString(m, " "))
					if len(snippet) > 50 {
						snippet = snippet[:50]
					}
					ruleMatched = true
					if rule.Action == "MONITOR" {
						shadowMatches = append(shadowMatches, fmt.Sprintf("[%s] in %s (match: '%s')", rule.Name, t.Name, snippet))
					} else {
						score := rule.Score
						if score <= 0 {
							score = 5
						}
						totalScore += score
						matchedRules = append(matchedRules, fmt.Sprintf("%s (+%d)", rule.Name, score))
						if primaryReason == "" {
							primaryReason = fmt.Sprintf("Triggered [%s] in %s (match: '%s')", rule.Name, t.Name, snippet)
							primaryCat = rule.Category
						}
					}
					break
				}
			}
		}
	}

	if totalScore >= threshold {
		reason := primaryReason
		if len(matchedRules) > 1 {
			reason = fmt.Sprintf("%s [Anomaly Score: %d/%d, Rules: %s]", primaryReason, totalScore, threshold, strings.Join(matchedRules, ", "))
		} else if totalScore > 0 {
			reason = fmt.Sprintf("%s [Score: %d/%d]", primaryReason, totalScore, threshold)
		}
		return Decision{
			Blocked:       true,
			Reason:        reason,
			Category:      primaryCat,
			AnomalyScore:  totalScore,
			Threshold:     threshold,
			MatchedRules:  matchedRules,
			ShadowMatches: shadowMatches,
		}
	}

	return Decision{
		Blocked:       false,
		AnomalyScore:  totalScore,
		Threshold:     threshold,
		MatchedRules:  matchedRules,
		ShadowMatches: shadowMatches,
	}
}

func multiSlashReLower(p string) string {
	s := strings.ToLower(p)
	for strings.Contains(s, "//") {
		s = strings.ReplaceAll(s, "//", "/")
	}
	return s
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func hasWordPressAdminCookie(r *http.Request) bool {
	for _, c := range r.Cookies() {
		if strings.HasPrefix(c.Name, "wordpress_logged_in_") || strings.HasPrefix(c.Name, "wordpress_sec_") {
			return true
		}
	}
	raw := r.Header.Get("Cookie")
	return strings.Contains(raw, "wordpress_logged_in_") || strings.Contains(raw, "wordpress_sec_")
}

func isAdminCodeEditorRequest(r *http.Request, bodyText string) bool {
	if (r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch) || !hasWordPressAdminCookie(r) {
		return false
	}
	pathLower := strings.ToLower(r.URL.Path)
	queryLower := strings.ToLower(r.URL.RawQuery)
	if strings.HasPrefix(pathLower, "/wp-json/wp/v2/") || strings.HasPrefix(pathLower, "/wp-json/wpcode/") || strings.HasPrefix(pathLower, "/wp-json/elementor/") ||
		(strings.HasSuffix(pathLower, "/index.php") && strings.Contains(queryLower, "rest_route=/wp/v2/")) {
		return true
	}
	if !adminEditorPaths[pathLower] {
		return false
	}
	if pathLower != "/wp-admin/admin.php" && pathLower != "/wp-admin/admin-ajax.php" {
		return true
	}
	if strings.Contains(queryLower, "page=wpcode") {
		return true
	}
	head := bodyText
	if len(head) > 5000 {
		head = head[:5000]
	}
	head = strings.ToLower(head)
	return strings.Contains(head, "action=wpcode") || strings.Contains(head, "action=elementor_ajax") || (strings.Contains(head, "wpcode") && strings.Contains(head, "action"))
}

func (e *Engine) verifyWPAdminSession(r *http.Request, host *store.ProxyHost) bool {
	if host == nil || host.TargetUpstream == "" {
		return false
	}
	cookieHdr := r.Header.Get("Cookie")
	reqHost := strings.SplitN(r.Host, ":", 2)[0]
	key := cookieHdr + "|" + reqHost

	e.adminCacheMu.Lock()
	if ent, ok := e.adminCache[key]; ok && time.Now().Before(ent.expiresAt) {
		e.adminCacheMu.Unlock()
		return ent.ok
	}
	e.adminCacheMu.Unlock()

	upstream := strings.TrimRight(host.TargetUpstream, "/") + "/wp-admin/options-general.php"
	req, err := http.NewRequest(http.MethodGet, upstream, nil)
	ok := false
	if err == nil {
		req.Header.Set("Cookie", cookieHdr)
		req.Header.Set("Host", reqHost)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", reqHost)
		req.Header.Set("User-Agent", "Athena-Shield-SessionCheck")
		if resp, err := e.verifyClient.Do(req); err == nil {
			_ = resp.Body.Close()
			ok = resp.StatusCode == http.StatusOK
		}
	}

	e.adminCacheMu.Lock()
	if len(e.adminCache) > 500 {
		e.adminCache = make(map[string]adminCacheEntry)
	}
	ttl := 10 * time.Second
	if ok {
		ttl = 60 * time.Second
	}
	e.adminCache[key] = adminCacheEntry{ok: ok, expiresAt: time.Now().Add(ttl)}
	e.adminCacheMu.Unlock()
	return ok
}

func hasMaliciousUploadFilename(contentType string, bodyBytes []byte) string {
	if len(bodyBytes) == 0 || !strings.HasPrefix(strings.ToLower(contentType), "multipart/form-data") {
		return ""
	}
	m := boundaryRe.FindStringSubmatch(contentType)
	if len(m) < 2 {
		return ""
	}
	boundary := []byte("--" + strings.Trim(m[1], `"'`))
	for _, part := range bytes.Split(bodyBytes, boundary) {
		if len(part) == 0 || bytes.HasPrefix(part, []byte("--")) {
			continue
		}
		var hdrRaw []byte
		if idx := bytes.Index(part, []byte("\r\n\r\n")); idx >= 0 {
			hdrRaw = part[:idx]
		} else if idx := bytes.Index(part, []byte("\n\n")); idx >= 0 {
			hdrRaw = part[:idx]
		} else {
			continue
		}
		if !bytes.Contains(bytes.ToLower(hdrRaw), []byte("filename=")) {
			continue
		}
		hdrText := string(hdrRaw)
		for _, fnMatch := range filenameHeaderRe.FindAllStringSubmatch(hdrText, -1) {
			if len(fnMatch) < 2 {
				continue
			}
			fn := strings.ToLower(strings.TrimSpace(fnMatch[1]))
			if dangerousUploadRe.MatchString(fn) || strings.Contains(fn, "..") || strings.Contains(fn, "/") || strings.Contains(fn, `\`) {
				return fn
			}
		}
	}
	return ""
}

func extractInspectableBodyText(contentType string, bodyBytes []byte, maxBytes int) string {
	if len(bodyBytes) == 0 {
		return ""
	}
	ctLower := strings.ToLower(contentType)
	if !strings.HasPrefix(ctLower, "multipart/form-data") {
		if len(bodyBytes) > maxBytes {
			return string(bodyBytes[:maxBytes])
		}
		return string(bodyBytes)
	}
	m := boundaryRe.FindStringSubmatch(contentType)
	if len(m) < 2 {
		limit := 100000
		if len(bodyBytes) < limit {
			limit = len(bodyBytes)
		}
		return string(bodyBytes[:limit])
	}
	boundary := []byte("--" + strings.Trim(m[1], `"'`))
	var chunks []string
	total := 0
	for _, part := range bytes.Split(bodyBytes, boundary) {
		if len(part) == 0 || bytes.HasPrefix(part, []byte("--")) {
			continue
		}
		var hdrRaw, partBody []byte
		if idx := bytes.Index(part, []byte("\r\n\r\n")); idx >= 0 {
			hdrRaw = part[:idx]
			partBody = part[idx+4:]
		} else if idx := bytes.Index(part, []byte("\n\n")); idx >= 0 {
			hdrRaw = part[:idx]
			partBody = part[idx+2:]
		} else {
			continue
		}
		hdrText := string(hdrRaw)
		hdrLower := strings.ToLower(hdrText)
		chunks = append(chunks, hdrText)

		isBin := false
		if strings.Contains(hdrLower, "filename=") {
			hasBinMIME := false
			for _, bm := range binaryMIMEs {
				if strings.Contains(hdrLower, bm) {
					hasBinMIME = true
					break
				}
			}
			if fnM := filenameHeaderRe.FindStringSubmatch(hdrText); len(fnM) >= 2 {
				fn := strings.ToLower(strings.TrimSpace(fnM[1]))
				hasSafeExt := false
				for _, ext := range safeBinaryExtensions {
					if strings.HasSuffix(fn, ext) {
						hasSafeExt = true
						break
					}
				}
				if hasSafeExt && hasBinMIME && !dangerousUploadRe.MatchString(fn) {
					isBin = true
				}
			}
		}
		if !isBin && total < maxBytes {
			trimmed := bytes.TrimRight(partBody, "\r\n")
			rem := maxBytes - total
			if len(trimmed) > rem {
				trimmed = trimmed[:rem]
			}
			chunks = append(chunks, string(trimmed))
			total += len(trimmed)
		}
	}
	return strings.Join(chunks, " ")
}
