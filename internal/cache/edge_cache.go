package cache

import (
	"container/list"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	DefaultHTMLTTL            = 60 * time.Second
	DefaultStaticTTL          = 15 * time.Minute
	MaxCacheEntries           = 4000
	MaxEntryBytes             = 4 * 1024 * 1024 // 4MB max per cached item
	DefaultMaxCacheBytes int64 = 128 * 1024 * 1024
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

var staticExts = []string{
	".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg",
	".woff", ".woff2", ".ttf", ".eot", ".webp",
}

type Entry struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	ExpiresAt  time.Time
}

type cacheItem struct {
	key   string
	entry Entry
	size  int64
}

type EdgeCache struct {
	mu         sync.Mutex
	ll         *list.List
	items      map[string]*list.Element
	curBytes   int64
	maxBytes   int64
	maxEntries int
}

func NewEdgeCache(maxBytes ...int64) *EdgeCache {
	capBytes := DefaultMaxCacheBytes
	if len(maxBytes) > 0 && maxBytes[0] > 0 {
		capBytes = maxBytes[0]
	}
	return &EdgeCache{
		ll:         list.New(),
		items:      make(map[string]*list.Element),
		maxBytes:   capBytes,
		maxEntries: MaxCacheEntries,
	}
}

func IsStaticAsset(path string) bool {
	p := strings.ToLower(path)
	for _, ext := range staticExts {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

func ShouldBypassHTML(r *http.Request) bool {
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

func ShouldBypassStatic(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return true
	}
	return !IsStaticAsset(r.URL.Path)
}

func CacheKey(scheme, method, host, uri string) string {
	return scheme + "|" + method + "|" + strings.ToLower(host) + "|" + uri
}

func (c *EdgeCache) removeElement(elem *list.Element) {
	c.ll.Remove(elem)
	item := elem.Value.(*cacheItem)
	delete(c.items, item.key)
	c.curBytes -= item.size
	if c.curBytes < 0 {
		c.curBytes = 0
	}
}

func (c *EdgeCache) Get(key string) (Entry, bool) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.items[key]
	if !ok {
		return Entry{}, false
	}
	item := elem.Value.(*cacheItem)
	if now.After(item.entry.ExpiresAt) {
		c.removeElement(elem)
		return Entry{}, false
	}
	c.ll.MoveToFront(elem)
	return item.entry, true
}

func (c *EdgeCache) Set(key string, status int, hdr http.Header, body []byte, isStatic bool) {
	if status != http.StatusOK || len(body) == 0 || len(body) > MaxEntryBytes {
		return
	}
	if !isStatic {
		ct := strings.ToLower(hdr.Get("Content-Type"))
		if !strings.Contains(ct, "text/html") {
			return
		}
	}
	cc := strings.ToLower(hdr.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
		return
	}

	clonedHdr := make(http.Header, len(hdr))
	for k, v := range hdr {
		if strings.EqualFold(k, "Set-Cookie") {
			if !isStatic {
				return // Never cache HTML responses setting cookies
			}
			continue
		}
		cp := make([]string, len(v))
		copy(cp, v)
		clonedHdr[k] = cp
	}

	ttl := DefaultHTMLTTL
	if isStatic {
		ttl = DefaultStaticTTL
	}

	itemSize := int64(len(body) + len(key) + 256)
	c.mu.Lock()
	defer c.mu.Unlock()

	if itemSize > c.maxBytes {
		return
	}
	if existing, ok := c.items[key]; ok {
		c.removeElement(existing)
	}

	now := time.Now()
	for (c.curBytes+itemSize > c.maxBytes || len(c.items) >= c.maxEntries) && c.ll.Len() > 0 {
		back := c.ll.Back()
		if back == nil {
			break
		}
		c.removeElement(back)
	}
	if c.curBytes+itemSize > c.maxBytes {
		return
	}

	ent := Entry{
		StatusCode: status,
		Headers:    clonedHdr,
		Body:       append([]byte(nil), body...),
		ExpiresAt:  now.Add(ttl),
	}
	elem := c.ll.PushFront(&cacheItem{
		key:   key,
		entry: ent,
		size:  itemSize,
	})
	c.items[key] = elem
	c.curBytes += itemSize
}

func (c *EdgeCache) PurgeAll() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.items)
	c.items = make(map[string]*list.Element)
	c.ll.Init()
	c.curBytes = 0
	return n
}

func (c *EdgeCache) Stats() (entries int, totalBytes int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items), c.curBytes
}
