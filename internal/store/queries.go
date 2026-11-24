package store

import (
	"database/sql"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---- Users ----

func (s *Store) GetUserByUsernameOrEmail(ident string) (*User, error) {
	u := &User{}
	var active int
	err := s.db.QueryRow(
		`SELECT id, username, email, hashed_password, role, is_active, created_at FROM users WHERE username = ? OR email = ? LIMIT 1`,
		ident, ident,
	).Scan(&u.ID, &u.Username, &u.Email, &u.HashedPassword, &u.Role, &active, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	u.IsActive = active == 1
	return u, nil
}

func (s *Store) GetUserByUsername(username string) (*User, error) {
	u := &User{}
	var active int
	err := s.db.QueryRow(
		`SELECT id, username, email, hashed_password, role, is_active, created_at FROM users WHERE username = ? AND is_active = 1 LIMIT 1`,
		username,
	).Scan(&u.ID, &u.Username, &u.Email, &u.HashedPassword, &u.Role, &active, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	u.IsActive = active == 1
	return u, nil
}

func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(`SELECT id, username, email, role, is_active, created_at FROM users ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var active int
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &active, &u.CreatedAt); err != nil {
			return nil, err
		}
		u.IsActive = active == 1
		out = append(out, u)
	}
	return out, nil
}

func (s *Store) CreateUser(u *User) error {
	res, err := s.db.Exec(
		`INSERT INTO users (username, email, hashed_password, role, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		u.Username, u.Email, u.HashedPassword, u.Role, boolToInt(u.IsActive), time.Now().UTC(),
	)
	if err != nil {
		return err
	}
	u.ID, _ = res.LastInsertId()
	u.CreatedAt = time.Now().UTC()
	return nil
}

func (s *Store) UpdateUser(id int64, username, email, hashedPass, role *string, isActive *bool) (*User, error) {
	u := &User{}
	var active int
	err := s.db.QueryRow(`SELECT id, username, email, hashed_password, role, is_active, created_at FROM users WHERE id = ?`, id).
		Scan(&u.ID, &u.Username, &u.Email, &u.HashedPassword, &u.Role, &active, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	u.IsActive = active == 1
	if username != nil && strings.TrimSpace(*username) != "" {
		u.Username = strings.TrimSpace(*username)
	}
	if email != nil && strings.TrimSpace(*email) != "" {
		u.Email = strings.TrimSpace(*email)
	}
	if hashedPass != nil && *hashedPass != "" {
		u.HashedPassword = *hashedPass
	}
	if role != nil && *role != "" {
		u.Role = *role
	}
	if isActive != nil {
		u.IsActive = *isActive
	}
	_, err = s.db.Exec(
		`UPDATE users SET username=?, email=?, hashed_password=?, role=?, is_active=? WHERE id=?`,
		u.Username, u.Email, u.HashedPassword, u.Role, boolToInt(u.IsActive), id,
	)
	return u, err
}

func (s *Store) DeleteUser(id int64) error {
	res, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ---- Proxy Hosts ----

func (s *Store) ListProxyHosts() ([]ProxyHost, error) {
	rows, err := s.db.Query(`SELECT id, domain_name, target_upstream, host_type, redirect_url, redirect_status_code, preserve_path, ssl_type, ssl_cert, ssl_key, force_https, waf_enabled, waf_mode, rate_limit_enabled, app_profile, block_bad_bots, edge_cache_enabled, is_active, created_at FROM proxy_hosts ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ProxyHost, 0)
	for rows.Next() {
		var h ProxyHost
		var pp, fh, we, rl, bbb, ec, act int
		if err := rows.Scan(&h.ID, &h.DomainName, &h.TargetUpstream, &h.HostType, &h.RedirectURL, &h.RedirectStatusCode, &pp, &h.SSLType, &h.SSLCert, &h.SSLKey, &fh, &we, &h.WAFMode, &rl, &h.AppProfile, &bbb, &ec, &act, &h.CreatedAt); err != nil {
			return nil, err
		}
		h.PreservePath = pp == 1
		h.ForceHTTPS = fh == 1
		h.WAFEnabled = we == 1
		h.RateLimitEnabled = rl == 1
		h.BlockBadBots = bbb == 1
		h.EdgeCacheEnabled = ec == 1
		h.IsActive = act == 1
		out = append(out, h)
	}
	return out, nil
}

func (s *Store) GetProxyHostByID(id int64) (*ProxyHost, error) {
	var h ProxyHost
	var pp, fh, we, rl, bbb, ec, act int
	err := s.db.QueryRow(`SELECT id, domain_name, target_upstream, host_type, redirect_url, redirect_status_code, preserve_path, ssl_type, ssl_cert, ssl_key, force_https, waf_enabled, waf_mode, rate_limit_enabled, app_profile, block_bad_bots, edge_cache_enabled, is_active, created_at FROM proxy_hosts WHERE id = ?`, id).
		Scan(&h.ID, &h.DomainName, &h.TargetUpstream, &h.HostType, &h.RedirectURL, &h.RedirectStatusCode, &pp, &h.SSLType, &h.SSLCert, &h.SSLKey, &fh, &we, &h.WAFMode, &rl, &h.AppProfile, &bbb, &ec, &act, &h.CreatedAt)
	if err != nil {
		return nil, err
	}
	h.PreservePath = pp == 1
	h.ForceHTTPS = fh == 1
	h.WAFEnabled = we == 1
	h.RateLimitEnabled = rl == 1
	h.BlockBadBots = bbb == 1
	h.EdgeCacheEnabled = ec == 1
	h.IsActive = act == 1
	return &h, nil
}

func (s *Store) CreateProxyHost(h *ProxyHost) error {
	res, err := s.db.Exec(
		`INSERT INTO proxy_hosts (domain_name, target_upstream, host_type, redirect_url, redirect_status_code, preserve_path, ssl_type, ssl_cert, ssl_key, force_https, waf_enabled, waf_mode, rate_limit_enabled, app_profile, block_bad_bots, edge_cache_enabled, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.DomainName, h.TargetUpstream, h.HostType, h.RedirectURL, h.RedirectStatusCode,
		boolToInt(h.PreservePath), h.SSLType, h.SSLCert, h.SSLKey, boolToInt(h.ForceHTTPS),
		boolToInt(h.WAFEnabled), h.WAFMode, boolToInt(h.RateLimitEnabled), h.AppProfile,
		boolToInt(h.BlockBadBots), boolToInt(h.EdgeCacheEnabled), boolToInt(h.IsActive), time.Now().UTC(),
	)
	if err != nil {
		return err
	}
	h.ID, _ = res.LastInsertId()
	h.CreatedAt = time.Now().UTC()
	s.BumpVersion()
	return nil
}

func (s *Store) UpdateProxyHost(h *ProxyHost) error {
	_, err := s.db.Exec(
		`UPDATE proxy_hosts SET domain_name=?, target_upstream=?, host_type=?, redirect_url=?, redirect_status_code=?, preserve_path=?, ssl_type=?, ssl_cert=?, ssl_key=?, force_https=?, waf_enabled=?, waf_mode=?, rate_limit_enabled=?, app_profile=?, block_bad_bots=?, edge_cache_enabled=?, is_active=? WHERE id=?`,
		h.DomainName, h.TargetUpstream, h.HostType, h.RedirectURL, h.RedirectStatusCode,
		boolToInt(h.PreservePath), h.SSLType, h.SSLCert, h.SSLKey, boolToInt(h.ForceHTTPS),
		boolToInt(h.WAFEnabled), h.WAFMode, boolToInt(h.RateLimitEnabled), h.AppProfile,
		boolToInt(h.BlockBadBots), boolToInt(h.EdgeCacheEnabled), boolToInt(h.IsActive), h.ID,
	)
	if err == nil {
		s.BumpVersion()
	}
	return err
}

func (s *Store) DeleteProxyHost(id int64) (string, error) {
	var domain string
	if err := s.db.QueryRow(`SELECT domain_name FROM proxy_hosts WHERE id = ?`, id).Scan(&domain); err != nil {
		return "", err
	}
	if _, err := s.db.Exec(`DELETE FROM proxy_hosts WHERE id = ?`, id); err != nil {
		return "", err
	}
	s.BumpVersion()
	return domain, nil
}

// ---- Rules ----

func NormalizeRuleFields(r *Rule) {
	act := strings.ToUpper(strings.TrimSpace(r.Action))
	if act != "BLOCK" && act != "MONITOR" && act != "ALLOW" {
		act = "BLOCK"
	}
	r.Action = act

	sev := strings.ToUpper(strings.TrimSpace(r.Severity))
	switch sev {
	case "CRITICAL", "ERROR", "WARNING", "NOTICE":
	default:
		sev = "CRITICAL"
	}
	r.Severity = sev

	if r.Score <= 0 {
		switch r.Severity {
		case "CRITICAL":
			r.Score = 5
		case "ERROR":
			r.Score = 4
		case "WARNING":
			r.Score = 3
		case "NOTICE":
			r.Score = 2
		default:
			r.Score = 5
		}
	} else if r.Score > 20 {
		r.Score = 20
	}

	if r.ParanoiaLevel < 1 {
		r.ParanoiaLevel = 1
	} else if r.ParanoiaLevel > 4 {
		r.ParanoiaLevel = 4
	}
}

func (s *Store) ListRules() ([]Rule, error) {
	rows, err := s.db.Query(`SELECT id, name, description, pattern, category, action, severity, score, paranoia_level, is_active, created_at FROM rules ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Rule, 0)
	for rows.Next() {
		var r Rule
		var act int
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.Pattern, &r.Category, &r.Action, &r.Severity, &r.Score, &r.ParanoiaLevel, &act, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.IsActive = act == 1
		NormalizeRuleFields(&r)
		out = append(out, r)
	}
	return out, nil
}

func (s *Store) CreateRule(r *Rule) error {
	NormalizeRuleFields(r)
	res, err := s.db.Exec(
		`INSERT INTO rules (name, description, pattern, category, action, severity, score, paranoia_level, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Name, r.Description, r.Pattern, r.Category, r.Action, r.Severity, r.Score, r.ParanoiaLevel, boolToInt(r.IsActive), time.Now().UTC(),
	)
	if err != nil {
		return err
	}
	r.ID, _ = res.LastInsertId()
	r.CreatedAt = time.Now().UTC()
	s.BumpVersion()
	return nil
}

func (s *Store) UpdateRule(id int64, name, desc, pattern, category, action, severity *string, score, paranoiaLevel *int, isActive *bool) (*Rule, error) {
	var r Rule
	var act int
	err := s.db.QueryRow(`SELECT id, name, description, pattern, category, action, severity, score, paranoia_level, is_active, created_at FROM rules WHERE id = ?`, id).
		Scan(&r.ID, &r.Name, &r.Description, &r.Pattern, &r.Category, &r.Action, &r.Severity, &r.Score, &r.ParanoiaLevel, &act, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	r.IsActive = act == 1
	if name != nil {
		r.Name = *name
	}
	if desc != nil {
		r.Description = *desc
	}
	if pattern != nil {
		r.Pattern = *pattern
	}
	if category != nil {
		r.Category = *category
	}
	if action != nil {
		r.Action = *action
	}
	if severity != nil {
		r.Severity = *severity
	}
	if score != nil {
		r.Score = *score
	}
	if paranoiaLevel != nil {
		r.ParanoiaLevel = *paranoiaLevel
	}
	if isActive != nil {
		r.IsActive = *isActive
	}
	NormalizeRuleFields(&r)
	_, err = s.db.Exec(
		`UPDATE rules SET name=?, description=?, pattern=?, category=?, action=?, severity=?, score=?, paranoia_level=?, is_active=? WHERE id=?`,
		r.Name, r.Description, r.Pattern, r.Category, r.Action, r.Severity, r.Score, r.ParanoiaLevel, boolToInt(r.IsActive), id,
	)
	if err == nil {
		s.BumpVersion()
	}
	return &r, err
}

func (s *Store) DeleteRule(id int64) error {
	res, err := s.db.Exec(`DELETE FROM rules WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	s.BumpVersion()
	return nil
}

// ---- IP Lists ----

func (s *Store) ListIPs() ([]IPList, error) {
	rows, err := s.db.Query(`SELECT id, ip_address, list_type, reason, created_at FROM ip_lists ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]IPList, 0)
	for rows.Next() {
		var item IPList
		if err := rows.Scan(&item.ID, &item.IPAddress, &item.ListType, &item.Reason, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

func (s *Store) AddIP(item *IPList) error {
	res, err := s.db.Exec(
		`INSERT INTO ip_lists (ip_address, list_type, reason, created_at) VALUES (?, ?, ?, ?)`,
		item.IPAddress, item.ListType, item.Reason, time.Now().UTC(),
	)
	if err != nil {
		return err
	}
	item.ID, _ = res.LastInsertId()
	item.CreatedAt = time.Now().UTC()
	s.BumpVersion()
	return nil
}

func (s *Store) DeleteIPByID(id int64) error {
	res, err := s.db.Exec(`DELETE FROM ip_lists WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	s.BumpVersion()
	return nil
}

func (s *Store) DeleteBlacklistIP(ip string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM ip_lists WHERE ip_address = ? AND list_type = 'BLACKLIST'`, ip)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		s.BumpVersion()
		return true, nil
	}
	return false, nil
}

// ---- AutoBans ----

func (s *Store) UpsertAutoBan(ip string, expiresAt float64, reason string) {
	_, _ = s.db.Exec(
		`INSERT OR REPLACE INTO auto_bans (ip_address, expires_at, reason, created_at) VALUES (?, ?, ?, ?)`,
		ip, expiresAt, reason, time.Now().UTC(),
	)
}

func (s *Store) DeleteAutoBan(ip string) bool {
	res, err := s.db.Exec(`DELETE FROM auto_bans WHERE ip_address = ?`, ip)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

func (s *Store) ActiveAutoBans(now float64) ([]AutoBan, error) {
	_, _ = s.db.Exec(`DELETE FROM auto_bans WHERE expires_at <= ?`, now)
	rows, err := s.db.Query(`SELECT ip_address, expires_at, reason, created_at FROM auto_bans WHERE expires_at > ?`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AutoBan
	for rows.Next() {
		var b AutoBan
		if err := rows.Scan(&b.IPAddress, &b.ExpiresAt, &b.Reason, &b.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// ---- Logs & Stats ----

type LogFilter struct {
	FilterBlocked string
	FilterHost    string
	FilterDate    string
	Search        string
	Page          int
	Limit         int
}

type LogPageResult struct {
	Total          int64    `json:"total"`
	Page           int      `json:"page"`
	Limit          int      `json:"limit"`
	TotalPages     int      `json:"total_pages"`
	Logs           []Log    `json:"logs"`
	AvailableHosts []string `json:"available_hosts"`
}

func (s *Store) QueryLogs(f LogFilter) (LogPageResult, error) {
	if f.Page < 1 {
		f.Page = 1
	}
	if f.Limit < 1 {
		f.Limit = 50
	}
	var where []string
	var args []any

	if f.FilterBlocked == "true" {
		where = append(where, "is_blocked = 1")
	} else if f.FilterBlocked == "false" {
		where = append(where, "is_blocked = 0")
	}
	if f.FilterHost != "" {
		where = append(where, "LOWER(host) = ?")
		args = append(args, strings.ToLower(strings.TrimSpace(f.FilterHost)))
	}

	wibLoc := time.FixedZone("WIB", 7*3600)
	nowWIB := time.Now().In(wibLoc)
	todayStartWIB := time.Date(nowWIB.Year(), nowWIB.Month(), nowWIB.Day(), 0, 0, 0, 0, wibLoc)

	switch f.FilterDate {
	case "today":
		where = append(where, "timestamp >= ? AND timestamp <= ?")
		args = append(args, todayStartWIB.UTC(), todayStartWIB.Add(24*time.Hour-time.Second).UTC())
	case "yesterday":
		ys := todayStartWIB.Add(-24 * time.Hour)
		where = append(where, "timestamp >= ? AND timestamp <= ?")
		args = append(args, ys.UTC(), todayStartWIB.Add(-time.Second).UTC())
	case "7days":
		where = append(where, "timestamp >= ?")
		args = append(args, todayStartWIB.Add(-7*24*time.Hour).UTC())
	case "30days":
		where = append(where, "timestamp >= ?")
		args = append(args, todayStartWIB.Add(-30*24*time.Hour).UTC())
	default:
		if f.FilterDate != "" && f.FilterDate != "all" && f.FilterDate != "custom" {
			if d, err := time.ParseInLocation("2006-01-02", strings.TrimSpace(f.FilterDate), wibLoc); err == nil {
				where = append(where, "timestamp >= ? AND timestamp <= ?")
				args = append(args, d.UTC(), d.Add(24*time.Hour-time.Second).UTC())
			}
		}
	}

	if f.Search != "" {
		pat := "%" + f.Search + "%"
		where = append(where, "(client_ip LIKE ? OR host LIKE ? OR country LIKE ? OR country_code LIKE ? OR uri LIKE ? OR reason LIKE ?)")
		args = append(args, pat, pat, pat, pat, pat, pat)
	}

	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}

	var total int64
	if err := s.db.QueryRow("SELECT COUNT(*) FROM waf_logs"+whereSQL, args...).Scan(&total); err != nil {
		return LogPageResult{}, err
	}

	totalPages := int(math.Ceil(float64(total) / float64(f.Limit)))
	if totalPages < 1 {
		totalPages = 1
	}
	offset := (f.Page - 1) * f.Limit

	queryArgs := append(append([]any{}, args...), f.Limit, offset)
	rows, err := s.db.Query(
		"SELECT id, timestamp, client_ip, country, country_code, host, method, uri, status_code, is_blocked, reason, user_agent FROM waf_logs"+whereSQL+" ORDER BY timestamp DESC LIMIT ? OFFSET ?",
		queryArgs...,
	)
	if err != nil {
		return LogPageResult{}, err
	}
	defer rows.Close()

	logs := make([]Log, 0)
	for rows.Next() {
		var l Log
		var blk int
		if err := rows.Scan(&l.ID, &l.Timestamp, &l.ClientIP, &l.Country, &l.CountryCode, &l.Host, &l.Method, &l.URI, &l.StatusCode, &blk, &l.Reason, &l.UserAgent); err != nil {
			return LogPageResult{}, err
		}
		l.IsBlocked = blk == 1
		logs = append(logs, l)
	}

	hostSet := map[string]struct{}{}
	if hRows, err := s.db.Query(`SELECT domain_name FROM proxy_hosts`); err == nil {
		for hRows.Next() {
			var d string
			if hRows.Scan(&d) == nil && d != "" {
				hostSet[d] = struct{}{}
			}
		}
		hRows.Close()
	}
	if lRows, err := s.db.Query(`SELECT DISTINCT host FROM waf_logs WHERE host IS NOT NULL AND host != ''`); err == nil {
		for lRows.Next() {
			var d string
			if lRows.Scan(&d) == nil && d != "" {
				hostSet[d] = struct{}{}
			}
		}
		lRows.Close()
	}
	hosts := make([]string, 0, len(hostSet))
	for h := range hostSet {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	return LogPageResult{
		Total:          total,
		Page:           f.Page,
		Limit:          f.Limit,
		TotalPages:     totalPages,
		Logs:           logs,
		AvailableHosts: hosts,
	}, nil
}

func (s *Store) ClearLogs() error {
	_, err := s.db.Exec(`DELETE FROM waf_logs`)
	return err
}

type AttackerStat struct {
	IP          string `json:"ip"`
	Count       int64  `json:"count"`
	CountryCode string `json:"country_code"`
	Country     string `json:"country"`
}

type BreakdownStat struct {
	Reason string `json:"reason"`
	Count  int64  `json:"count"`
}

type ChartData struct {
	Labels  []string `json:"labels"`
	Clean   []int64  `json:"clean"`
	Blocked []int64  `json:"blocked"`
}

func (s *Store) GetStats() (total, blocked, allowed, activeRules int64, attackers []AttackerStat, breakdown []BreakdownStat, chart ChartData) {
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM waf_logs`).Scan(&total)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM waf_logs WHERE is_blocked = 1`).Scan(&blocked)
	allowed = total - blocked
	if allowed < 0 {
		allowed = 0
	}
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM rules WHERE is_active = 1`).Scan(&activeRules)

	attackers = make([]AttackerStat, 0)
	if rows, err := s.db.Query(`SELECT client_ip, COUNT(*) as cnt, MAX(country_code), MAX(country) FROM waf_logs WHERE is_blocked = 1 GROUP BY client_ip ORDER BY cnt DESC LIMIT 5`); err == nil {
		for rows.Next() {
			var a AttackerStat
			var cc, cn sql.NullString
			if rows.Scan(&a.IP, &a.Count, &cc, &cn) == nil {
				a.CountryCode = cc.String
				a.Country = cn.String
				attackers = append(attackers, a)
			}
		}
		rows.Close()
	}

	breakdown = make([]BreakdownStat, 0)
	if rows, err := s.db.Query(`SELECT COALESCE(NULLIF(reason,''), 'Unknown'), COUNT(*) as cnt FROM waf_logs WHERE is_blocked = 1 GROUP BY reason ORDER BY cnt DESC LIMIT 6`); err == nil {
		for rows.Next() {
			var b BreakdownStat
			if rows.Scan(&b.Reason, &b.Count) == nil {
				breakdown = append(breakdown, b)
			}
		}
		rows.Close()
	}

	now := time.Now().UTC()
	wibLoc := time.FixedZone("WIB", 7*3600)
	nowWIB := now.In(wibLoc)
	labels := make([]string, 24)
	clean := make([]int64, 24)
	blk := make([]int64, 24)
	for i := 23; i >= 0; i-- {
		labels[23-i] = nowWIB.Add(-time.Duration(i) * time.Hour).Format("15:00")
	}

	if rows, err := s.db.Query(`SELECT timestamp, is_blocked FROM waf_logs WHERE timestamp >= ?`, now.Add(-24*time.Hour)); err == nil {
		for rows.Next() {
			var ts time.Time
			var isB int
			if rows.Scan(&ts, &isB) == nil {
				diffH := int(now.Sub(ts).Hours())
				if diffH >= 0 && diffH < 24 {
					idx := 23 - diffH
					if isB == 1 {
						blk[idx]++
					} else {
						clean[idx]++
					}
				}
			}
		}
		rows.Close()
	}
	chart = ChartData{Labels: labels, Clean: clean, Blocked: blk}
	return
}

// ---- Settings & Retention ----

func DefaultSettings() map[string]string {
	tgEnabled := "false"
	if os.Getenv("TELEGRAM_BOT_TOKEN") != "" && os.Getenv("TELEGRAM_CHAT_ID") != "" {
		tgEnabled = "true"
	}
	cleanDays := os.Getenv("LOG_RETENTION_CLEAN_DAYS")
	if cleanDays == "" {
		cleanDays = "14"
	}
	attackDays := os.Getenv("LOG_RETENTION_ATTACK_DAYS")
	if attackDays == "" {
		attackDays = "60"
	}
	return map[string]string{
		"telegram_enabled":             tgEnabled,
		"telegram_bot_token":           os.Getenv("TELEGRAM_BOT_TOKEN"),
		"telegram_chat_id":             os.Getenv("TELEGRAM_CHAT_ID"),
		"telegram_alert_attacks":       "true",
		"telegram_alert_autoban":       "true",
		"telegram_alert_monitor":       "true",
		"telegram_alert_upstream_down": "true",
		"log_retention_clean_days":     cleanDays,
		"log_retention_attack_days":    attackDays,
		"waf_anomaly_threshold":        "5",
		"waf_paranoia_level":           "1",
		"waf_dlp_enabled":              "true",
		"waf_dlp_mode":                 "block",
		"waf_deep_parse_enabled":       "true",
		"waf_js_challenge_enabled":     "false",
		"waf_js_challenge_difficulty":  "14",
		"waf_bot_fingerprint_enabled":  "true",
		"waf_geoip_blocked_countries":  "",
		"waf_api_rate_limit_max":       "30",
	}
}

func (s *Store) GetSettings() map[string]string {
	merged := DefaultSettings()
	rows, err := s.db.Query(`SELECT key, value FROM system_settings`)
	if err != nil {
		return merged
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) == nil {
			if _, ok := merged[k]; ok {
				merged[k] = v
			}
		}
	}
	return merged
}

func (s *Store) UpdateSettings(updates map[string]string) error {
	defaults := DefaultSettings()
	for k, v := range updates {
		if _, ok := defaults[k]; !ok {
			continue
		}
		_, err := s.db.Exec(
			`INSERT OR REPLACE INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)`,
			k, v, time.Now().UTC(),
		)
		if err != nil {
			return err
		}
	}
	s.BumpVersion()
	return nil
}

func (s *Store) StorageCounts() (cleanCount, attackCount, activeBans int64) {
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM waf_logs WHERE is_blocked = 0`).Scan(&cleanCount)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM waf_logs WHERE is_blocked = 1`).Scan(&attackCount)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM auto_bans WHERE expires_at > ?`, float64(time.Now().Unix())).Scan(&activeBans)
	return
}

func (s *Store) PruneExpiredLogs() (int64, int64) {
	cfg := s.GetSettings()
	cleanDays, err := strconv.Atoi(cfg["log_retention_clean_days"])
	if err != nil || cleanDays < 1 {
		cleanDays = 14
	}
	attackDays, err := strconv.Atoi(cfg["log_retention_attack_days"])
	if err != nil || attackDays < 1 {
		attackDays = 60
	}
	now := time.Now().UTC()
	resClean, _ := s.db.Exec(`DELETE FROM waf_logs WHERE is_blocked = 0 AND timestamp < ?`, now.Add(-time.Duration(cleanDays)*24*time.Hour))
	resAttack, _ := s.db.Exec(`DELETE FROM waf_logs WHERE is_blocked = 1 AND timestamp < ?`, now.Add(-time.Duration(attackDays)*24*time.Hour))
	var dc, da int64
	if resClean != nil {
		dc, _ = resClean.RowsAffected()
	}
	if resAttack != nil {
		da, _ = resAttack.RowsAffected()
	}
	_, _ = s.db.Exec(`PRAGMA wal_checkpoint(PASSIVE)`)
	return dc, da
}

func (s *Store) UpsertProxyHostByDomain(h *ProxyHost) error {
	var existingID int64
	err := s.db.QueryRow(`SELECT id FROM proxy_hosts WHERE domain_name = ?`, h.DomainName).Scan(&existingID)
	if err == nil {
		h.ID = existingID
		return s.UpdateProxyHost(h)
	}
	return s.CreateProxyHost(h)
}

func (s *Store) UpsertRuleByName(r *Rule) error {
	NormalizeRuleFields(r)
	var existingID int64
	err := s.db.QueryRow(`SELECT id FROM rules WHERE name = ?`, r.Name).Scan(&existingID)
	if err == nil {
		_, err = s.UpdateRule(existingID, &r.Name, &r.Description, &r.Pattern, &r.Category, &r.Action, &r.Severity, &r.Score, &r.ParanoiaLevel, &r.IsActive)
		return err
	}
	return s.CreateRule(r)
}

func (s *Store) UpsertIP(item *IPList) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO ip_lists (id, ip_address, list_type, reason, created_at)
		 VALUES ((SELECT id FROM ip_lists WHERE ip_address = ?), ?, ?, ?, COALESCE((SELECT created_at FROM ip_lists WHERE ip_address = ?), ?))`,
		item.IPAddress, item.IPAddress, item.ListType, item.Reason, item.IPAddress, time.Now().UTC(),
	)
	if err == nil {
		s.BumpVersion()
	}
	return err
}

func FormatDurationRemaining(sec int) string {
	if sec < 0 {
		return "Permanen"
	}
	if sec >= 60 {
		return fmt.Sprintf("~%d menit", sec/60)
	}
	return fmt.Sprintf("%d detik", sec)
}
