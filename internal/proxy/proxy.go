package proxy

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/theboynewbie/athena-shield/internal/alert"
	"github.com/theboynewbie/athena-shield/internal/cache"
	"github.com/theboynewbie/athena-shield/internal/config"
	"github.com/theboynewbie/athena-shield/internal/geoip"
	"github.com/theboynewbie/athena-shield/internal/ratelimit"
	"github.com/theboynewbie/athena-shield/internal/store"
	"github.com/theboynewbie/athena-shield/internal/waf"
)

type BlockRenderer interface {
	RenderBlocked(w http.ResponseWriter, data BlockPageData)
}

type BlockPageData struct {
	ClientIP     string
	Reason       string
	URI          string
	IncidentID   string
	StatusCode   int
	RetryAfter   int
	TargetHost   string
	TimestampStr string
}

type Router struct {
	cfg       config.Config
	store     *store.Store
	engine    *waf.Engine
	rl        *ratelimit.RateLimiter
	edgeCache *cache.EdgeCache
	notifier  *alert.Notifier
	tlsMgr    *TLSManager
	renderer  BlockRenderer
	transport *http.Transport

	hostsSnap atomic.Pointer[map[string]store.ProxyHost]
}

func NewRouter(
	cfg config.Config,
	s *store.Store,
	eng *waf.Engine,
	rl *ratelimit.RateLimiter,
	ec *cache.EdgeCache,
	n *alert.Notifier,
	tm *TLSManager,
	renderer BlockRenderer,
) *Router {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 60 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          300,
		MaxIdleConnsPerHost:   150,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: time.Duration(cfg.UpstreamTimeoutSec) * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}

	rt := &Router{
		cfg:       cfg,
		store:     s,
		engine:    eng,
		rl:        rl,
		edgeCache: ec,
		notifier:  n,
		tlsMgr:    tm,
		renderer:  renderer,
		transport: tr,
	}
	rt.Reload()
	return rt
}

func (rt *Router) Reload() {
	if rt.store == nil {
		return
	}
	hosts, err := rt.store.ListProxyHosts()
	if err != nil {
		return
	}
	m := make(map[string]store.ProxyHost, len(hosts))
	for _, h := range hosts {
		m[strings.ToLower(strings.TrimSpace(h.DomainName))] = h
	}
	rt.hostsSnap.Store(&m)
	if rt.tlsMgr != nil {
		rt.tlsMgr.ReloadHosts(hosts)
	}
}

func (rt *Router) MatchHost(r *http.Request) (store.ProxyHost, bool) {
	hostHdr := r.Header.Get("X-Forwarded-Host")
	if hostHdr == "" {
		hostHdr = r.Host
	}
	clean := strings.ToLower(strings.TrimSpace(strings.SplitN(hostHdr, ":", 2)[0]))
	mPtr := rt.hostsSnap.Load()
	if mPtr == nil {
		return store.ProxyHost{}, false
	}
	h, ok := (*mPtr)[clean]
	return h, ok
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, found := rt.MatchHost(r)
	if !found {
		http.Error(w, "Athena Shield: Domain not configured", http.StatusNotFound)
		return
	}

	if !host.IsActive {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprintf(w, `<div style="font-family:sans-serif;text-align:center;padding:60px 20px;background:#09090b;color:#fafafa;min-height:100vh;"><h1 style="color:#f59e0b;">Routing Status: OFFLINE</h1><p>Host domain <code>%s</code> saat ini berstatus OFFLINE di Athena Shield.</p></div>`, html.EscapeString(host.DomainName))
		return
	}

	// Domain Redirect
	if host.HostType == "redirect" {
		dest := strings.TrimSpace(host.RedirectURL)
		if dest == "" {
			dest = strings.TrimSpace(host.TargetUpstream)
		}
		if !strings.HasPrefix(dest, "http://") && !strings.HasPrefix(dest, "https://") {
			dest = "https://" + dest
		}
		if host.PreservePath {
			dest = strings.TrimRight(dest, "/") + r.URL.Path
			if r.URL.RawQuery != "" {
				dest += "?" + r.URL.RawQuery
			}
		}
		code := host.RedirectStatusCode
		if code != 301 && code != 302 && code != 307 && code != 308 {
			code = http.StatusMovedPermanently
		}
		http.Redirect(w, r, dest, code)
		return
	}

	// Force HTTPS redirect
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	if host.ForceHTTPS && host.SSLType != "none" && proto == "http" {
		targetHost := r.Host
		if targetHost == "" {
			targetHost = host.DomainName
		}
		targetURL := "https://" + targetHost + r.URL.RequestURI()
		http.Redirect(w, r, targetURL, http.StatusMovedPermanently)
		return
	}

	clientIP := geoip.GetClientIP(r)
	ua := r.Header.Get("User-Agent")
	cfCountry := r.Header.Get("CF-IPCountry")
	fullURI := r.URL.RequestURI()

	// Read body up to inspection cap (or 1024MB max proxy limit)
	var bodyBytes []byte
	if r.Body != nil {
		maxInspect := int64(rt.cfg.MaxNonMultipartBody + 1)
		if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/form-data") {
			maxInspect = int64(rt.cfg.MaxInspectBodyBytes)
		}
		limited := io.LimitReader(r.Body, maxInspect)
		bodyBytes, _ = io.ReadAll(limited)
		// Reconstruct r.Body so upstream receives full stream (inspected prefix + unread remainder)
		r.Body = struct {
			io.Reader
			io.Closer
		}{
			Reader: io.MultiReader(bytes.NewReader(bodyBytes), r.Body),
			Closer: r.Body,
		}
	}

	// WAF Inspection
	dec := rt.engine.Inspect(r, &host, bodyBytes)
	skipCleanLog := false
	if dec.Blocked {
		if dec.Mode == "monitor" {
			skipCleanLog = true
			rt.logEvent(clientIP, r.Method, r.URL.Path, http.StatusOK, false, "[MONITOR] "+dec.Reason, ua, host.DomainName, cfCountry)
			if rt.notifier != nil && dec.Category != "Rate Limiting" && dec.Category != "bot_attack" {
				rt.notifier.Notify("monitor", fmt.Sprintf("Deteksi Mode Monitor [%s]", dec.Category), host.DomainName, clientIP, fullURI, dec.Reason)
			}
		} else {
			statusCode := http.StatusForbidden
			if dec.Category == "Rate Limiting" {
				statusCode = http.StatusTooManyRequests
			}
			rt.logEvent(clientIP, r.Method, r.URL.Path, statusCode, true, dec.Reason, ua, host.DomainName, cfCountry)
			if rt.notifier != nil && dec.Category != "Rate Limiting" && dec.Category != "bot_attack" {
				rt.notifier.Notify("attack", fmt.Sprintf("Serangan Diblokir [%s]", dec.Category), host.DomainName, clientIP, fullURI, dec.Reason)
			}

			w.Header().Set("X-Protected-By", "Athena-Shield-v1.5")
			if statusCode == http.StatusTooManyRequests {
				retry := dec.RetryAfter
				if retry <= 0 {
					retry = 60
				}
				w.Header().Set("Retry-After", fmt.Sprintf("%d", retry))
				w.Header().Set("X-RateLimit-Limit", "5")
				w.Header().Set("X-RateLimit-Remaining", "0")
			}

			incBuf := make([]byte, 5)
			_, _ = rand.Read(incBuf)
			incID := strings.ToUpper(hex.EncodeToString(incBuf))
			wib := time.Now().In(time.FixedZone("WIB", 7*3600)).Format("02/01/2006, 15:04:05 WIB")

			if rt.renderer != nil {
				rt.renderer.RenderBlocked(w, BlockPageData{
					ClientIP:     clientIP,
					Reason:       dec.Reason,
					URI:          fullURI,
					IncidentID:   incID,
					StatusCode:   statusCode,
					RetryAfter:   dec.RetryAfter,
					TargetHost:   host.DomainName,
					TimestampStr: wib,
				})
			} else {
				http.Error(w, dec.Reason, statusCode)
			}
			return
		}
	}

	// Turbo Edge HTML Micro-Cache Check
	useEdgeCache := host.EdgeCacheEnabled && rt.edgeCache != nil && !cache.ShouldBypass(r)
	var cacheKey string
	if useEdgeCache {
		cacheKey = cache.CacheKey(proto, r.Method, host.DomainName, r.URL.Path)
		if ent, ok := rt.edgeCache.Get(cacheKey); ok {
			for k, vals := range ent.Headers {
				for _, v := range vals {
					w.Header().Add(k, v)
				}
			}
			if dec.Mode != "bypass" {
				setSecurityHeaders(w.Header())
			}
			w.Header().Set("X-Athena-Cache", "HIT")
			w.WriteHeader(ent.StatusCode)
			if r.Method != http.MethodHead {
				_, _ = w.Write(ent.Body)
			}
			if !skipCleanLog {
				rt.logEvent(clientIP, r.Method, r.URL.Path, ent.StatusCode, false, "", ua, host.DomainName, cfCountry)
			}
			return
		}
	}

	// Reverse Proxy to Upstream
	targetURL, err := url.Parse(host.TargetUpstream)
	if err != nil || targetURL.Host == "" {
		http.Error(w, "Invalid upstream configuration", http.StatusBadGateway)
		return
	}

	rp := &httputil.ReverseProxy{
		Transport:     rt.transport,
		FlushInterval: 100 * time.Millisecond,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(targetURL)
			pr.Out.Host = host.DomainName
			pr.Out.Header.Set("Host", host.DomainName)
			pr.Out.Header.Set("X-Forwarded-Host", host.DomainName)
			pr.Out.Header.Set("X-Forwarded-For", clientIP)
			pr.Out.Header.Set("X-Real-IP", clientIP)
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
			pr.Out.Header.Set("X-Forwarded-SSL", "on")
			pr.Out.Header.Set("X-Forwarded-Port", "443")
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("Alt-Svc")
			if dec.Mode != "bypass" {
				setSecurityHeaders(resp.Header)
			}
			if useEdgeCache && resp.StatusCode == http.StatusOK && strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
				body, readErr := io.ReadAll(io.LimitReader(resp.Body, cache.MaxEntryBytes+1))
				_ = resp.Body.Close()
				if readErr == nil && len(body) <= cache.MaxEntryBytes {
					rt.edgeCache.Set(cacheKey, resp.StatusCode, resp.Header, body)
					resp.Header.Set("X-Athena-Cache", "MISS")
					resp.Body = io.NopCloser(bytes.NewReader(body))
					resp.ContentLength = int64(len(body))
				} else {
					resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), resp.Body))
				}
			}
			if !skipCleanLog {
				rt.logEvent(clientIP, r.Method, r.URL.Path, resp.StatusCode, false, "", ua, host.DomainName, cfCountry)
			}
			return nil
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
			status := http.StatusBadGateway
			kindTitle := "502 Bad Gateway — Backend Tidak Dapat Dihubungi"
			if strings.Contains(strings.ToLower(proxyErr.Error()), "timeout") {
				status = http.StatusGatewayTimeout
				kindTitle = "504 Gateway Timeout — Backend Lambat / Hang"
			}
			rt.logEvent(clientIP, req.Method, req.URL.Path, status, false, fmt.Sprintf("Upstream Gateway Error: %v", proxyErr), ua, host.DomainName, cfCountry)
			if rt.notifier != nil {
				rt.notifier.Notify("upstream_down", kindTitle, host.DomainName, clientIP, req.URL.Path, proxyErr.Error())
			}
			rw.Header().Set("Content-Type", "text/html; charset=utf-8")
			rw.WriteHeader(status)
			_, _ = fmt.Fprintf(rw, `<div style="font-family:sans-serif;text-align:center;padding:60px 20px;background:#09090b;color:#fafafa;min-height:100vh;"><h1>%d — Athena Shield</h1><p>Upstream <code>%s</code> error: %s</p></div>`, status, html.EscapeString(host.TargetUpstream), html.EscapeString(proxyErr.Error()))
		},
	}

	rp.ServeHTTP(w, r)
}

func (rt *Router) logEvent(clientIP, method, uri string, statusCode int, isBlocked bool, reason, ua, host, cfCountry string) {
	if !isBlocked && waf.IsStaticAssetPath(uri) {
		return
	}
	if isBlocked && !strings.HasPrefix(reason, "Auto-Banned:") && !strings.HasPrefix(reason, "DDoS/Flood") && !strings.Contains(reason, "Bot Crawler Shield:") {
		if rt.rl != nil {
			rt.rl.RecordAttackViolation(clientIP)
		}
	}
	if rt.store != nil {
		cc, cname := geoip.Resolve(clientIP, cfCountry, false)
		rt.store.QueueLog(store.Log{
			Timestamp:   time.Now().UTC(),
			ClientIP:    clientIP,
			Country:     cname,
			CountryCode: cc,
			Host:        host,
			Method:      method,
			URI:         uri,
			StatusCode:  statusCode,
			IsBlocked:   isBlocked,
			Reason:      reason,
			UserAgent:   ua,
		})
	}
}

func setSecurityHeaders(h http.Header) {
	h.Set("X-Protected-By", "Athena-Shield-v1.5")
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-XSS-Protection", "1; mode=block")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
}
