package store

import "time"

type User struct {
	ID             int64     `json:"id"`
	Username       string    `json:"username"`
	Email          string    `json:"email"`
	HashedPassword string    `json:"-"`
	Role           string    `json:"role"` // "super_admin" or "admin"
	IsActive       bool      `json:"is_active"`
	CreatedAt      time.Time `json:"created_at"`
}

type Rule struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Pattern     string    `json:"pattern"`
	Category    string    `json:"category"` // judi_slot, sqli, xss, path_traversal, bot_attack, custom
	Action      string    `json:"action"`   // BLOCK, ALLOW
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
}

type IPList struct {
	ID        int64     `json:"id"`
	IPAddress string    `json:"ip_address"`
	ListType  string    `json:"list_type"` // BLACKLIST or WHITELIST
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

type Log struct {
	ID          int64     `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	ClientIP    string    `json:"client_ip"`
	Country     string    `json:"country"`
	CountryCode string    `json:"country_code"`
	Host        string    `json:"host"`
	Method      string    `json:"method"`
	URI         string    `json:"uri"`
	StatusCode  int       `json:"status_code"`
	IsBlocked   bool      `json:"is_blocked"`
	Reason      string    `json:"reason"`
	UserAgent   string    `json:"user_agent"`
}

type ProxyHost struct {
	ID                 int64     `json:"id"`
	DomainName         string    `json:"domain_name"`
	TargetUpstream     string    `json:"target_upstream"`
	HostType           string    `json:"host_type"` // "proxy" or "redirect"
	RedirectURL        string    `json:"redirect_url"`
	RedirectStatusCode int       `json:"redirect_status_code"`
	PreservePath       bool      `json:"preserve_path"`
	SSLType            string    `json:"ssl_type"` // "none", "letsencrypt", "custom"
	SSLCert            string    `json:"ssl_cert"`
	SSLKey             string    `json:"ssl_key"`
	ForceHTTPS         bool      `json:"force_https"`
	WAFEnabled         bool      `json:"waf_enabled"`
	WAFMode            string    `json:"waf_mode"` // "active", "monitor", "bypass"
	RateLimitEnabled   bool      `json:"rate_limit_enabled"`
	AppProfile         string    `json:"app_profile"` // "universal", "wordpress", "slims", "laravel_api"
	BlockBadBots       bool      `json:"block_bad_bots"`
	EdgeCacheEnabled   bool      `json:"edge_cache_enabled"`
	IsActive           bool      `json:"is_active"`
	CreatedAt          time.Time `json:"created_at"`
}

type AutoBan struct {
	IPAddress string    `json:"ip_address"`
	ExpiresAt float64   `json:"expires_at"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}
