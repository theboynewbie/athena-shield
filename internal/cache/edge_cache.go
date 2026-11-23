package cache

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	DefaultTTL      = 60 * time.Second
	MaxCacheEntries = 2000
	MaxEntryBytes   = 2 * 1024 * 1024 // 2MB per HTML page
)

var bypassCookies = []string{
	"wordpress_logged_in_",
	"wordpress_sec_",
	"wp-postpass_",
	"comment_author_",
	"phpsessid",
	"laravel_session",
	"xsrf-token",
	"ojs_session",
	"ci_session",
	"access_token",
}

var bypassPrefixes = []string{
	"/wp-admin", "/wp-login", "/login", "/admin", "/dashboard",
	"/xmlrpc.php", "/wp-json", "/api/", "/logout",
}

type Entry struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	ExpiresAt  time.Time
}

type EdgeCache struct {
	mu      sync.RWMutex
	entries map[string]Entry
}

func NewEdgeCache() *EdgeCache {
	return &EdgeCache{
		entries: make(map[string]Entry),
	}
}

func ShouldBypass(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return true
	}
	if r.URL.RawQuery != "" {
		return true
	}
	if r.Header.Get("Authorization") != "" {
		return true
	}
	pathLower := strings.ToLower(r.URL.Path)
	for _, p := range bypassPrefixes {
		if strings.HasPrefix(pathLower, p) {
			return true
		}
	}
	cookieHdr := strings.ToLower(r.Header.Get("Cookie"))
	if cookieHdr != "" {
		for _, bc := range bypassCookies {
			if strings.Contains(cookieHdr, bc) {
				return true
			}
		}
	}
	return false
}

func CacheKey(scheme, method, host, path string) string {
	return scheme + "|" + method + "|" + strings.ToLower(host) + "|" + path
}

func (c *EdgeCache) Get(key string) (Entry, bool) {
	now := time.Now()
	c.mu.RLock()
	ent, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return Entry{}, false
	}
	if now.After(ent.ExpiresAt) {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return Entry{}, false
	}
	return ent, true
}

func (c *EdgeCache) Set(key string, status int, hdr http.Header, body []byte) {
	if status != http.StatusOK || len(body) == 0 || len(body) > MaxEntryBytes {
		return
	}
	ct := strings.ToLower(hdr.Get("Content-Type"))
	if !strings.Contains(ct, "text/html") {
		return
	}
	cc := strings.ToLower(hdr.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
		return
	}

	clonedHdr := make(http.Header, len(hdr))
	for k, v := range hdr {
		if strings.EqualFold(k, "Set-Cookie") {
			return // Never cache responses setting cookies
		}
		cp := make([]string, len(v))
		copy(cp, v)
		clonedHdr[k] = cp
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= MaxCacheEntries {
		now := time.Now()
		for k, v := range c.entries {
			if now.After(v.ExpiresAt) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= MaxCacheEntries {
			c.entries = make(map[string]Entry)
		}
	}
	c.entries[key] = Entry{
		StatusCode: status,
		Headers:    clonedHdr,
		Body:       append([]byte(nil), body...),
		ExpiresAt:  time.Now().Add(DefaultTTL),
	}
}

func (c *EdgeCache) PurgeAll() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.entries)
	c.entries = make(map[string]Entry)
	return n
}
