package web

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/theboynewbie/athena-shield/internal/auth"
	"github.com/theboynewbie/athena-shield/internal/store"
)

var (
	domainRe          = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	forbiddenConfChar = regexp.MustCompile(`[\s;{}'"\\$` + "`" + `\r\n\x00]`)
	validAppProfiles  = map[string]bool{"universal": true, "wordpress": true, "slims": true, "laravel_api": true}
	validWAFModes     = map[string]bool{"active": true, "monitor": true, "bypass": true}
)

func validateDomainName(d string) (string, error) {
	clean := strings.ToLower(strings.TrimSpace(d))
	if clean == "" || len(clean) > 253 || strings.Contains(clean, "..") || strings.Contains(clean, "/") || strings.Contains(clean, `\`) {
		return "", fmt.Errorf("Nama domain tidak valid.")
	}
	if !domainRe.MatchString(clean) {
		return "", fmt.Errorf("Format nama domain tidak valid.")
	}
	return clean, nil
}

func validateTargetURL(u string) (string, error) {
	clean := strings.TrimSpace(u)
	if clean == "" {
		return "", nil
	}
	if len(clean) > 1024 {
		return "", fmt.Errorf("URL target melebihi batas panjang maksimum.")
	}
	parts := strings.Split(clean, ",")
	var out []string
	for _, p := range parts {
		seg := strings.TrimSpace(p)
		if seg == "" || forbiddenConfChar.MatchString(seg) || len(seg) > 255 {
			return "", fmt.Errorf("URL target mengandung karakter ilegal atau kosong.")
		}
		out = append(out, seg)
	}
	return strings.Join(out, ", "), nil
}

func validateSingleURL(u string) (string, error) {
	clean := strings.TrimSpace(u)
	if clean == "" {
		return "", nil
	}
	if strings.Contains(clean, ",") || forbiddenConfChar.MatchString(clean) || len(clean) > 255 {
		return "", fmt.Errorf("URL redirect mengandung karakter ilegal.")
	}
	return clean, nil
}

// ---- Proxy Hosts ----

func sanitizeHostForAPI(h store.ProxyHost) store.ProxyHost {
	h.HasSSLKey = strings.TrimSpace(h.SSLKey) != ""
	h.SSLKey = ""
	return h
}

func (sv *Server) apiListProxyHosts(w http.ResponseWriter, r *http.Request, user *store.User) {
	hosts, err := sv.store.ListProxyHosts()
	if err != nil {
		writeDetailError(w, 500, err.Error())
		return
	}
	for i := range hosts {
		hosts[i] = sanitizeHostForAPI(hosts[i])
	}
	writeJSON(w, http.StatusOK, hosts)
}

func (sv *Server) apiCreateProxyHost(w http.ResponseWriter, r *http.Request, user *store.User) {
	var in struct {
		DomainName         string  `json:"domain_name"`
		TargetUpstream     string  `json:"target_upstream"`
		HostType           string  `json:"host_type"`
		RedirectURL        *string `json:"redirect_url"`
		RedirectStatusCode int     `json:"redirect_status_code"`
		PreservePath       *bool   `json:"preserve_path"`
		SSLType            string  `json:"ssl_type"`
		SSLCert            string  `json:"ssl_cert"`
		SSLKey             string  `json:"ssl_key"`
		ForceHTTPS         *bool   `json:"force_https"`
		WAFEnabled         *bool   `json:"waf_enabled"`
		WAFMode            *string `json:"waf_mode"`
		RateLimitEnabled   *bool   `json:"rate_limit_enabled"`
		AppProfile         string  `json:"app_profile"`
		BlockBadBots       *bool   `json:"block_bad_bots"`
		EdgeCacheEnabled   bool    `json:"edge_cache_enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeDetailError(w, 400, "Invalid JSON payload")
		return
	}
	dom, err := validateDomainName(in.DomainName)
	if err != nil {
		writeDetailError(w, 400, err.Error())
		return
	}
	up, err := validateTargetURL(in.TargetUpstream)
	if err != nil {
		writeDetailError(w, 400, err.Error())
		return
	}
	redir := ""
	if in.RedirectURL != nil {
		redir, err = validateSingleURL(*in.RedirectURL)
		if err != nil {
			writeDetailError(w, 400, err.Error())
			return
		}
	}
	if in.HostType == "redirect" && up == "" {
		up = redir
	}
	if in.HostType == "" {
		in.HostType = "proxy"
	}
	if in.RedirectStatusCode == 0 {
		in.RedirectStatusCode = 301
	}
	if in.SSLType == "" {
		in.SSLType = "none"
	}

	prof := strings.ToLower(strings.TrimSpace(in.AppProfile))
	if !validAppProfiles[prof] {
		prof = "universal"
	}

	wafEnabled := true
	if in.WAFEnabled != nil {
		wafEnabled = *in.WAFEnabled
	}
	wafMode := "active"
	if in.WAFMode != nil {
		wm := strings.ToLower(strings.TrimSpace(*in.WAFMode))
		if validWAFModes[wm] {
			wafMode = wm
		}
	} else if !wafEnabled {
		wafMode = "bypass"
	}
	if !wafEnabled || wafMode == "bypass" {
		wafEnabled = false
		wafMode = "bypass"
	}

	rlEnabled := true
	if in.RateLimitEnabled != nil {
		rlEnabled = *in.RateLimitEnabled
	}
	if wafMode != "active" {
		rlEnabled = false
	}

	h := &store.ProxyHost{
		DomainName:         dom,
		TargetUpstream:     up,
		HostType:           in.HostType,
		RedirectURL:        redir,
		RedirectStatusCode: in.RedirectStatusCode,
		PreservePath:       in.PreservePath == nil || *in.PreservePath,
		SSLType:            in.SSLType,
		SSLCert:            in.SSLCert,
		SSLKey:             in.SSLKey,
		ForceHTTPS:         in.ForceHTTPS == nil || *in.ForceHTTPS,
		WAFEnabled:         wafEnabled,
		WAFMode:            wafMode,
		RateLimitEnabled:   rlEnabled,
		AppProfile:         prof,
		BlockBadBots:       in.BlockBadBots == nil || *in.BlockBadBots,
		EdgeCacheEnabled:   in.EdgeCacheEnabled,
		IsActive:           true,
	}
	if err := sv.store.CreateProxyHost(h); err != nil {
		writeDetailError(w, 400, fmt.Sprintf("Domain '%s' sudah terdaftar atau gagal disimpan.", dom))
		return
	}
	sv.recordAudit(r, user, "CREATE_HOST", h.DomainName, "Upstream: "+h.TargetUpstream)
	writeJSON(w, http.StatusCreated, sanitizeHostForAPI(*h))
}

func (sv *Server) apiUpdateProxyHost(w http.ResponseWriter, r *http.Request, user *store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeDetailError(w, 400, "ID tidak valid")
		return
	}
	h, err := sv.store.GetProxyHostByID(id)
	if err != nil {
		writeDetailError(w, 404, "Proxy host tidak ditemukan")
		return
	}
	var in map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeDetailError(w, 400, "Invalid JSON payload")
		return
	}

	if v, ok := in["domain_name"].(string); ok {
		dom, err := validateDomainName(v)
		if err != nil {
			writeDetailError(w, 400, err.Error())
			return
		}
		h.DomainName = dom
	}
	if v, ok := in["target_upstream"].(string); ok {
		up, err := validateTargetURL(v)
		if err != nil {
			writeDetailError(w, 400, err.Error())
			return
		}
		h.TargetUpstream = up
	}
	if v, ok := in["redirect_url"].(string); ok {
		ru, err := validateSingleURL(v)
		if err != nil {
			writeDetailError(w, 400, err.Error())
			return
		}
		h.RedirectURL = ru
	}
	if v, ok := in["host_type"].(string); ok && v != "" {
		h.HostType = v
	}
	if v, ok := in["redirect_status_code"].(float64); ok && v > 0 {
		h.RedirectStatusCode = int(v)
	}
	if v, ok := in["preserve_path"].(bool); ok {
		h.PreservePath = v
	}
	if v, ok := in["ssl_type"].(string); ok && v != "" {
		h.SSLType = v
	}
	if v, ok := in["ssl_cert"].(string); ok {
		h.SSLCert = v
	}
	if v, ok := in["ssl_key"].(string); ok && strings.TrimSpace(v) != "" {
		h.SSLKey = v
	}
	if v, ok := in["force_https"].(bool); ok {
		h.ForceHTTPS = v
	}
	if v, ok := in["block_bad_bots"].(bool); ok {
		h.BlockBadBots = v
	}
	if v, ok := in["edge_cache_enabled"].(bool); ok {
		h.EdgeCacheEnabled = v
	}
	if v, ok := in["is_active"].(bool); ok {
		h.IsActive = v
	}
	if v, ok := in["app_profile"].(string); ok {
		p := strings.ToLower(strings.TrimSpace(v))
		if validAppProfiles[p] {
			h.AppProfile = p
		} else {
			h.AppProfile = "universal"
		}
	}

	wmodeVal, hasMode := in["waf_mode"].(string)
	wenVal, hasEnabled := in["waf_enabled"].(bool)
	if hasMode {
		wm := strings.ToLower(strings.TrimSpace(wmodeVal))
		if !validWAFModes[wm] {
			wm = "active"
		}
		if hasEnabled && !wenVal {
			wm = "bypass"
		}
		h.WAFMode = wm
		h.WAFEnabled = wm != "bypass"
		h.RateLimitEnabled = wm == "active"
	} else if hasEnabled {
		if !wenVal {
			h.WAFEnabled = false
			h.WAFMode = "bypass"
			h.RateLimitEnabled = false
		} else {
			h.WAFEnabled = true
			h.WAFMode = "active"
			h.RateLimitEnabled = true
		}
	}

	if err := sv.store.UpdateProxyHost(h); err != nil {
		writeDetailError(w, 400, err.Error())
		return
	}
	sv.recordAudit(r, user, "UPDATE_HOST", h.DomainName, "Mode: "+h.WAFMode)
	writeJSON(w, http.StatusOK, sanitizeHostForAPI(*h))
}

func (sv *Server) apiDeleteProxyHost(w http.ResponseWriter, r *http.Request, user *store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeDetailError(w, 400, "ID tidak valid")
		return
	}
	dom, err := sv.store.DeleteProxyHost(id)
	if err != nil {
		writeDetailError(w, 404, "Proxy host tidak ditemukan")
		return
	}
	sv.recordAudit(r, user, "DELETE_HOST", dom, "Host dihapus")
	writeJSON(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("Proxy host untuk domain %s berhasil dihapus", dom)})
}

// ---- Stats ----

var (
	statsCacheMu      sync.Mutex
	statsCachePayload map[string]any
	statsCacheAt      time.Time
	statsCacheVer     int64
)

func (sv *Server) apiStats(w http.ResponseWriter, r *http.Request, user *store.User) {
	curVer := sv.store.Version()
	statsCacheMu.Lock()
	if statsCachePayload != nil && statsCacheVer == curVer && time.Since(statsCacheAt) < 3*time.Second {
		cached := statsCachePayload
		statsCacheMu.Unlock()
		writeJSON(w, http.StatusOK, cached)
		return
	}
	statsCacheMu.Unlock()

	total, blocked, allowed, activeRules, attackers, breakdown, chart := sv.store.GetStats()
	payload := map[string]any{
		"system":             ReadSystemMetrics(),
		"total_requests":     total,
		"blocked_requests":   blocked,
		"allowed_requests":   allowed,
		"active_rules_count": activeRules,
		"top_attackers":      attackers,
		"attack_breakdown":   breakdown,
		"chart":              chart,
	}

	statsCacheMu.Lock()
	statsCachePayload = payload
	statsCacheAt = time.Now()
	statsCacheVer = curVer
	statsCacheMu.Unlock()

	writeJSON(w, http.StatusOK, payload)
}

// ---- Rules ----

func (sv *Server) apiListRules(w http.ResponseWriter, r *http.Request, user *store.User) {
	rules, err := sv.store.ListRules()
	if err != nil {
		writeDetailError(w, 500, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

func (sv *Server) apiCreateRule(w http.ResponseWriter, r *http.Request, user *store.User) {
	var in struct {
		Name          string `json:"name"`
		Description   string `json:"description"`
		Pattern       string `json:"pattern"`
		Category      string `json:"category"`
		Action        string `json:"action"`
		Severity      string `json:"severity"`
		Score         int    `json:"score"`
		ParanoiaLevel int    `json:"paranoia_level"`
		IsActive      *bool  `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeDetailError(w, 400, "Invalid JSON")
		return
	}
	if _, err := regexp.Compile("(?im)" + in.Pattern); err != nil {
		writeDetailError(w, 400, fmt.Sprintf("Regex tidak valid (RE2): %v", err))
		return
	}
	if in.Category == "" {
		in.Category = "judi_slot"
	}
	if in.Action == "" {
		in.Action = "BLOCK"
	}
	rule := &store.Rule{
		Name:          in.Name,
		Description:   in.Description,
		Pattern:       in.Pattern,
		Category:      in.Category,
		Action:        in.Action,
		Severity:      in.Severity,
		Score:         in.Score,
		ParanoiaLevel: in.ParanoiaLevel,
		IsActive:      in.IsActive == nil || *in.IsActive,
	}
	if err := sv.store.CreateRule(rule); err != nil {
		writeDetailError(w, 400, err.Error())
		return
	}
	sv.recordAudit(r, user, "CREATE_RULE", rule.Name, fmt.Sprintf("Action=%s PL=%d Score=%d", rule.Action, rule.ParanoiaLevel, rule.Score))
	writeJSON(w, http.StatusCreated, rule)
}

func (sv *Server) apiUpdateRule(w http.ResponseWriter, r *http.Request, user *store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeDetailError(w, 400, "ID tidak valid")
		return
	}
	var in struct {
		Name          *string `json:"name"`
		Description   *string `json:"description"`
		Pattern       *string `json:"pattern"`
		Category      *string `json:"category"`
		Action        *string `json:"action"`
		Severity      *string `json:"severity"`
		Score         *int    `json:"score"`
		ParanoiaLevel *int    `json:"paranoia_level"`
		IsActive      *bool   `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeDetailError(w, 400, "Invalid JSON")
		return
	}
	if in.Pattern != nil {
		if _, err := regexp.Compile("(?im)" + *in.Pattern); err != nil {
			writeDetailError(w, 400, fmt.Sprintf("Regex tidak valid (RE2): %v", err))
			return
		}
	}
	rule, err := sv.store.UpdateRule(id, in.Name, in.Description, in.Pattern, in.Category, in.Action, in.Severity, in.Score, in.ParanoiaLevel, in.IsActive)
	if err != nil {
		writeDetailError(w, 404, "Rule tidak ditemukan")
		return
	}
	sv.recordAudit(r, user, "UPDATE_RULE", rule.Name, fmt.Sprintf("Active=%v Action=%s PL=%d", rule.IsActive, rule.Action, rule.ParanoiaLevel))
	writeJSON(w, http.StatusOK, rule)
}

func (sv *Server) apiDeleteRule(w http.ResponseWriter, r *http.Request, user *store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeDetailError(w, 400, "ID tidak valid")
		return
	}
	if err := sv.store.DeleteRule(id); err != nil {
		writeDetailError(w, 404, "Rule tidak ditemukan")
		return
	}
	sv.recordAudit(r, user, "DELETE_RULE", fmt.Sprintf("Rule #%d", id), "Rule dihapus")
	writeJSON(w, http.StatusOK, map[string]string{"message": "Rule berhasil dihapus"})
}

// ---- IP Lists ----

func (sv *Server) apiListIPs(w http.ResponseWriter, r *http.Request, user *store.User) {
	ips, err := sv.store.ListIPs()
	if err != nil {
		writeDetailError(w, 500, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ips)
}

func (sv *Server) apiAddIP(w http.ResponseWriter, r *http.Request, user *store.User) {
	var in struct {
		IPAddress string `json:"ip_address"`
		ListType  string `json:"list_type"`
		Reason    string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeDetailError(w, 400, "Invalid JSON")
		return
	}
	item := &store.IPList{
		IPAddress: strings.TrimSpace(in.IPAddress),
		ListType:  strings.ToUpper(strings.TrimSpace(in.ListType)),
		Reason:    in.Reason,
	}
	if err := sv.store.AddIP(item); err != nil {
		writeDetailError(w, 400, "IP ini sudah terdaftar dalam list")
		return
	}
	sv.recordAudit(r, user, "ADD_IP_"+item.ListType, item.IPAddress, item.Reason)
	writeJSON(w, http.StatusCreated, item)
}

func (sv *Server) apiDeleteIP(w http.ResponseWriter, r *http.Request, user *store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeDetailError(w, 400, "ID tidak valid")
		return
	}
	if err := sv.store.DeleteIPByID(id); err != nil {
		writeDetailError(w, 404, "IP tidak ditemukan")
		return
	}
	sv.recordAudit(r, user, "DELETE_IP", fmt.Sprintf("IP #%d", id), "IP dihapus dari list")
	writeJSON(w, http.StatusOK, map[string]string{"message": "IP berhasil dihapus"})
}

// ---- Logs & Bans & Cache ----

func (sv *Server) apiGetLogs(w http.ResponseWriter, r *http.Request, user *store.User) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	res, err := sv.store.QueryLogs(store.LogFilter{
		FilterBlocked: q.Get("filter_blocked"),
		FilterHost:    q.Get("filter_host"),
		FilterDate:    q.Get("filter_date"),
		Search:        q.Get("search"),
		Page:          page,
		Limit:         limit,
	})
	if err != nil {
		writeDetailError(w, 500, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (sv *Server) apiClearLogs(w http.ResponseWriter, r *http.Request, user *store.User) {
	if err := sv.store.ClearLogs(); err != nil {
		writeDetailError(w, 500, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Semua log berhasil dibersihkan"})
}

func (sv *Server) apiBannedIPs(w http.ResponseWriter, r *http.Request, user *store.User) {
	list := sv.rl.ActiveTempBans()
	seen := make(map[string]bool, len(list))
	for _, b := range list {
		seen[b.IP] = true
	}
	if ips, err := sv.store.ListIPs(); err == nil {
		for _, item := range ips {
			if item.ListType == "BLACKLIST" && !seen[item.IPAddress] {
				list = append(list, struct {
					IP               string `json:"ip"`
					Type             string `json:"type"`
					RemainingSeconds int    `json:"remaining_seconds"`
					RemainingStr     string `json:"remaining_str"`
				}{
					IP:               item.IPAddress,
					Type:             "Permanent Blacklist",
					RemainingSeconds: -1,
					RemainingStr:     "Permanen",
				})
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"banned_ips": list})
}

func (sv *Server) apiUnbanIP(w http.ResponseWriter, r *http.Request, user *store.User) {
	var in struct {
		IPAddress string `json:"ip_address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.IPAddress) == "" {
		writeDetailError(w, 400, "Alamat IP tidak valid")
		return
	}
	ip := strings.TrimSpace(in.IPAddress)
	sv.rl.UnbanIP(ip)
	_, _ = sv.store.DeleteBlacklistIP(ip)
	sv.recordAudit(r, user, "UNBAN_IP", ip, "Dibebaskan dari jail/blacklist")
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("IP %s berhasil dibebaskan dari status Blacklist & Jail!", ip),
	})
}

func (sv *Server) apiPurgeCache(w http.ResponseWriter, r *http.Request, user *store.User) {
	purged := sv.edgeCache.PurgeAll()
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Turbo Edge Cache berhasil dikosongkan (%d entri dibersihkan).", purged),
	})
}

// ---- Users (Super Admin) ----

func (sv *Server) apiListUsers(w http.ResponseWriter, r *http.Request, user *store.User) {
	users, err := sv.store.ListUsers()
	if err != nil {
		writeDetailError(w, 500, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (sv *Server) apiCreateUser(w http.ResponseWriter, r *http.Request, user *store.User) {
	var in struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeDetailError(w, 400, "Invalid JSON")
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		writeDetailError(w, 400, "Password tidak valid")
		return
	}
	if in.Role != "super_admin" && in.Role != "auditor" {
		in.Role = "admin"
	}
	u := &store.User{
		Username:       strings.TrimSpace(in.Username),
		Email:          strings.TrimSpace(in.Email),
		HashedPassword: hash,
		Role:           in.Role,
		IsActive:       true,
	}
	if err := sv.store.CreateUser(u); err != nil {
		writeDetailError(w, 400, "Username atau email sudah digunakan")
		return
	}
	sv.recordAudit(r, user, "CREATE_USER", u.Username, "Role: "+u.Role)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": u.ID, "username": u.Username, "email": u.Email, "role": u.Role,
	})
}

func (sv *Server) apiUpdateUser(w http.ResponseWriter, r *http.Request, user *store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeDetailError(w, 400, "ID tidak valid")
		return
	}
	var in struct {
		Username *string `json:"username"`
		Email    *string `json:"email"`
		Password *string `json:"password"`
		Role     *string `json:"role"`
		IsActive *bool   `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeDetailError(w, 400, "Invalid JSON")
		return
	}
	var hashed *string
	if in.Password != nil && strings.TrimSpace(*in.Password) != "" {
		h, err := auth.HashPassword(strings.TrimSpace(*in.Password))
		if err == nil {
			hashed = &h
		}
	}
	if in.Role != nil {
		rNorm := strings.ToLower(strings.TrimSpace(*in.Role))
		if rNorm != "super_admin" && rNorm != "auditor" {
			rNorm = "admin"
		}
		in.Role = &rNorm
	}
	u, err := sv.store.UpdateUser(id, in.Username, in.Email, hashed, in.Role, in.IsActive)
	if err != nil {
		if err == sql.ErrNoRows {
			writeDetailError(w, 404, "User tidak ditemukan")
			return
		}
		writeDetailError(w, 400, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": u.ID, "username": u.Username, "email": u.Email, "role": u.Role, "is_active": u.IsActive,
	})
}

func (sv *Server) apiResetPassword(w http.ResponseWriter, r *http.Request, user *store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeDetailError(w, 400, "ID tidak valid")
		return
	}
	var in struct {
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.NewPassword == "" {
		writeDetailError(w, 400, "Password baru wajib diisi")
		return
	}
	h, err := auth.HashPassword(in.NewPassword)
	if err != nil {
		writeDetailError(w, 400, "Password tidak valid")
		return
	}
	u, err := sv.store.UpdateUser(id, nil, nil, &h, nil, nil)
	if err != nil {
		writeDetailError(w, 404, "User tidak ditemukan")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("Password untuk user '%s' berhasil diperbarui", u.Username)})
}

func (sv *Server) apiDeleteUser(w http.ResponseWriter, r *http.Request, user *store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeDetailError(w, 400, "ID tidak valid")
		return
	}
	if user.ID == id {
		writeDetailError(w, 400, "Anda tidak dapat menghapus akun Anda sendiri")
		return
	}
	if err := sv.store.DeleteUser(id); err != nil {
		writeDetailError(w, 404, "User tidak ditemukan")
		return
	}
	sv.recordAudit(r, user, "DELETE_USER", fmt.Sprintf("User #%d", id), "Akun dihapus")
	writeJSON(w, http.StatusOK, map[string]string{"message": "User berhasil dihapus"})
}

// ---- Settings & Backup ----

func (sv *Server) apiGetSettings(w http.ResponseWriter, r *http.Request, user *store.User) {
	cfg := sv.store.GetSettings()
	cleanCnt, atkCnt, activeBans := sv.store.StorageCounts()
	cleanDays, _ := strconv.Atoi(cfg["log_retention_clean_days"])
	if cleanDays < 1 {
		cleanDays = 14
	}
	atkDays, _ := strconv.Atoi(cfg["log_retention_attack_days"])
	if atkDays < 1 {
		atkDays = 60
	}
	anomalyThreshold, _ := strconv.Atoi(cfg["waf_anomaly_threshold"])
	if anomalyThreshold < 1 {
		anomalyThreshold = 5
	}
	paranoiaLevel, _ := strconv.Atoi(cfg["waf_paranoia_level"])
	if paranoiaLevel < 1 || paranoiaLevel > 4 {
		paranoiaLevel = 1
	}
	dlpMode := strings.ToLower(strings.TrimSpace(cfg["waf_dlp_mode"]))
	if dlpMode != "monitor" {
		dlpMode = "block"
	}
	jsDiff, _ := strconv.Atoi(cfg["waf_js_challenge_difficulty"])
	if jsDiff < 12 || jsDiff > 20 {
		jsDiff = 14
	}
	apiMax, _ := strconv.Atoi(cfg["waf_api_rate_limit_max"])
	if apiMax < 5 || apiMax > 1000 {
		apiMax = 30
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"settings": map[string]any{
			"telegram_enabled":             strings.ToLower(cfg["telegram_enabled"]) == "true",
			"telegram_bot_token":           cfg["telegram_bot_token"],
			"telegram_chat_id":             cfg["telegram_chat_id"],
			"telegram_alert_attacks":       strings.ToLower(cfg["telegram_alert_attacks"]) == "true",
			"telegram_alert_autoban":       strings.ToLower(cfg["telegram_alert_autoban"]) == "true",
			"telegram_alert_monitor":       strings.ToLower(cfg["telegram_alert_monitor"]) == "true",
			"telegram_alert_upstream_down": strings.ToLower(cfg["telegram_alert_upstream_down"]) == "true",
			"log_retention_clean_days":     cleanDays,
			"log_retention_attack_days":    atkDays,
			"waf_anomaly_threshold":        anomalyThreshold,
			"waf_paranoia_level":           paranoiaLevel,
			"waf_dlp_enabled":              strings.ToLower(cfg["waf_dlp_enabled"]) != "false",
			"waf_dlp_mode":                 dlpMode,
			"waf_deep_parse_enabled":       strings.ToLower(cfg["waf_deep_parse_enabled"]) != "false",
			"waf_js_challenge_enabled":     strings.ToLower(cfg["waf_js_challenge_enabled"]) == "true",
			"waf_js_challenge_difficulty":  jsDiff,
			"waf_bot_fingerprint_enabled":  strings.ToLower(cfg["waf_bot_fingerprint_enabled"]) != "false",
			"waf_geoip_blocked_countries":  strings.ToUpper(strings.TrimSpace(cfg["waf_geoip_blocked_countries"])),
			"waf_api_rate_limit_max":       apiMax,
		},
		"storage": map[string]any{
			"db_size_mb":            sv.store.DBSizeMB(),
			"clean_logs_count":      cleanCnt,
			"attack_logs_count":     atkCnt,
			"active_autobans_count": activeBans,
		},
	})
}

func (sv *Server) apiUpdateSettings(w http.ResponseWriter, r *http.Request, user *store.User) {
	var in map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeDetailError(w, 400, "Invalid JSON")
		return
	}
	updates := make(map[string]string)
	for k, v := range in {
		if v == nil {
			continue
		}
		switch val := v.(type) {
		case bool:
			if val {
				updates[k] = "true"
			} else {
				updates[k] = "false"
			}
		case float64:
			n := int(val)
			switch k {
			case "waf_paranoia_level":
				if n < 1 {
					n = 1
				} else if n > 4 {
					n = 4
				}
			case "waf_anomaly_threshold":
				if n < 1 {
					n = 1
				} else if n > 50 {
					n = 50
				}
			case "waf_js_challenge_difficulty":
				if n < 12 {
					n = 12
				} else if n > 20 {
					n = 20
				}
			case "waf_api_rate_limit_max":
				if n < 5 {
					n = 5
				} else if n > 1000 {
					n = 1000
				}
			default:
				if n < 1 {
					n = 1
				} else if n > 3650 {
					n = 3650
				}
			}
			updates[k] = strconv.Itoa(n)
		case string:
			s := strings.TrimSpace(val)
			if k == "waf_dlp_mode" {
				if strings.EqualFold(s, "monitor") {
					s = "monitor"
				} else {
					s = "block"
				}
			} else if k == "waf_geoip_blocked_countries" {
				var clean []string
				for _, part := range strings.Split(s, ",") {
					cc := strings.ToUpper(strings.TrimSpace(part))
					if len(cc) == 2 {
						clean = append(clean, cc)
					}
				}
				s = strings.Join(clean, ",")
			}
			updates[k] = s
		}
	}
	if err := sv.store.UpdateSettings(updates); err != nil {
		writeDetailError(w, 500, err.Error())
		return
	}
	sv.recordAudit(r, user, "UPDATE_SETTINGS", "system_settings", fmt.Sprintf("%d keys updated", len(updates)))
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Pengaturan sistem & CSIRT berhasil disimpan!"})
}

func (sv *Server) apiTestTelegram(w http.ResponseWriter, r *http.Request, user *store.User) {
	var in struct {
		BotToken string `json:"bot_token"`
		ChatID   string `json:"chat_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	ok, msg := sv.notifier.SendTest(in.BotToken, in.ChatID)
	if !ok {
		writeDetailError(w, 400, msg)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": msg})
}

func (sv *Server) apiPruneLogs(w http.ResponseWriter, r *http.Request, user *store.User) {
	sv.store.FlushLogs()
	dc, da := sv.store.PruneExpiredLogs()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "success",
		"deleted_clean":  dc,
		"deleted_attack": da,
		"message":        fmt.Sprintf("Pembersihan selesai: %d log trafik lama & %d log serangan kedaluwarsa dihapus.", dc, da),
	})
}

func (sv *Server) apiBackupExport(w http.ResponseWriter, r *http.Request, user *store.User) {
	hosts, _ := sv.store.ListProxyHosts()
	rules, _ := sv.store.ListRules()
	ips, _ := sv.store.ListIPs()
	cfg := sv.store.GetSettings()

	snapshot := map[string]any{
		"schema_version": "1.6",
		"exported_at":    time.Now().UTC().Format(time.RFC3339),
		"proxy_hosts":    hosts,
		"rules":          rules,
		"ip_lists":       ips,
		"settings":       cfg,
	}
	tsName := time.Now().UTC().Format("20060102-150405")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="athena-shield-backup-%s.json"`, tsName))
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(snapshot)
}

func (sv *Server) apiBackupImport(w http.ResponseWriter, r *http.Request, user *store.User) {
	var in struct {
		ProxyHosts []map[string]any `json:"proxy_hosts"`
		Rules      []map[string]any `json:"rules"`
		IPLists    []map[string]any `json:"ip_lists"`
		Settings   map[string]any   `json:"settings"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeDetailError(w, 400, "Format JSON backup tidak valid")
		return
	}

	var impHosts, impRules, impIPs int
	for _, h := range in.ProxyHosts {
		domStr, _ := h["domain_name"].(string)
		dom, err := validateDomainName(domStr)
		if err != nil {
			continue
		}
		upStr, _ := h["target_upstream"].(string)
		up, _ := validateTargetURL(upStr)
		redirStr, _ := h["redirect_url"].(string)
		redir, _ := validateTargetURL(redirStr)
		prof, _ := h["app_profile"].(string)
		prof = strings.ToLower(prof)
		if !validAppProfiles[prof] {
			prof = "universal"
		}
		wmode, _ := h["waf_mode"].(string)
		wmode = strings.ToLower(wmode)
		if !validWAFModes[wmode] {
			wmode = "active"
			if we, ok := h["waf_enabled"].(bool); ok && !we {
				wmode = "bypass"
			}
		}
		ht, _ := h["host_type"].(string)
		if ht == "" {
			ht = "proxy"
		}
		sslT, _ := h["ssl_type"].(string)
		if sslT == "" {
			sslT = "none"
		}
		cert, _ := h["ssl_cert"].(string)
		key, _ := h["ssl_key"].(string)
		rsc := 301
		if v, ok := h["redirect_status_code"].(float64); ok && v > 0 {
			rsc = int(v)
		}
		pp := getBoolMap(h, "preserve_path", true)
		fh := getBoolMap(h, "force_https", true)
		bbb := getBoolMap(h, "block_bad_bots", true)
		ec := getBoolMap(h, "edge_cache_enabled", false)
		act := getBoolMap(h, "is_active", true)

		ph := &store.ProxyHost{
			DomainName:         dom,
			TargetUpstream:     up,
			HostType:           ht,
			RedirectURL:        redir,
			RedirectStatusCode: rsc,
			PreservePath:       pp,
			SSLType:            sslT,
			SSLCert:            cert,
			SSLKey:             key,
			ForceHTTPS:         fh,
			WAFEnabled:         wmode != "bypass",
			WAFMode:            wmode,
			RateLimitEnabled:   wmode == "active",
			AppProfile:         prof,
			BlockBadBots:       bbb,
			EdgeCacheEnabled:   ec,
			IsActive:           act,
		}
		if err := sv.store.UpsertProxyHostByDomain(ph); err == nil {
			impHosts++
		}
	}

	for _, rm := range in.Rules {
		rname, _ := rm["name"].(string)
		rpat, _ := rm["pattern"].(string)
		if strings.TrimSpace(rname) == "" || rpat == "" {
			continue
		}
		if _, err := regexp.Compile("(?im)" + rpat); err != nil {
			continue
		}
		desc, _ := rm["description"].(string)
		cat, _ := rm["category"].(string)
		if cat == "" {
			cat = "custom"
		}
		act, _ := rm["action"].(string)
		if act == "" {
			act = "BLOCK"
		}
		sev, _ := rm["severity"].(string)
		score := 0
		if v, ok := rm["score"].(float64); ok && v > 0 {
			score = int(v)
		}
		pl := 1
		if v, ok := rm["paranoia_level"].(float64); ok && v >= 1 {
			pl = int(v)
		}
		if err := sv.store.UpsertRuleByName(&store.Rule{
			Name:          strings.TrimSpace(rname),
			Description:   desc,
			Pattern:       rpat,
			Category:      strings.ToLower(cat),
			Action:        strings.ToUpper(act),
			Severity:      strings.ToUpper(sev),
			Score:         score,
			ParanoiaLevel: pl,
			IsActive:      getBoolMap(rm, "is_active", true),
		}); err == nil {
			impRules++
		}
	}

	for _, im := range in.IPLists {
		addr, _ := im["ip_address"].(string)
		lt, _ := im["list_type"].(string)
		lt = strings.ToUpper(strings.TrimSpace(lt))
		if strings.TrimSpace(addr) == "" || (lt != "BLACKLIST" && lt != "WHITELIST") {
			continue
		}
		reason, _ := im["reason"].(string)
		if err := sv.store.UpsertIP(&store.IPList{
			IPAddress: strings.TrimSpace(addr),
			ListType:  lt,
			Reason:    reason,
		}); err == nil {
			impIPs++
		}
	}

	if in.Settings != nil {
		upd := make(map[string]string)
		for k, v := range in.Settings {
			if v != nil {
				upd[k] = fmt.Sprintf("%v", v)
			}
		}
		_ = sv.store.UpdateSettings(upd)
	}

	sv.recordAudit(r, user, "IMPORT_BACKUP", "configuration", fmt.Sprintf("%d hosts, %d rules, %d IPs", impHosts, impRules, impIPs))
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Konfigurasi berhasil dipulihkan (%d Proxy Host, %d Rules, %d IP List)!", impHosts, impRules, impIPs),
	})
}

func getBoolMap(m map[string]any, key string, def bool) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return def
}
