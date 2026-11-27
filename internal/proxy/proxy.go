package proxy

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
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

type compiledHost struct {
	store.ProxyHost
	pool *UpstreamPool
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

	hostsSnap atomic.Pointer[map[string]compiledHost]
	stopCh    chan struct{}
	stopOnce  sync.Once
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
			Timeout:   20 * time.Second,
			KeepAlive: 90 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          500,
		MaxIdleConnsPerHost:   250,
		MaxConnsPerHost:       0,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: time.Duration(cfg.UpstreamTimeoutSec) * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.UpstreamInsecureTLS,
			ClientSessionCache: tls.NewLRUClientSessionCache(256),
		},
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
		stopCh:    make(chan struct{}),
	}
	rt.Reload()
	go rt.healthCheckLoop()
	return rt
}

func (rt *Router) Close() {
	rt.stopOnce.Do(func() {
		close(rt.stopCh)
	})
}

func (rt *Router) healthCheckLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-rt.stopCh:
			return
		case <-ticker.C:
			mPtr := rt.hostsSnap.Load()
			if mPtr == nil {
				continue
			}
			for _, ch := range *mPtr {
				if ch.IsActive && ch.HostType != "redirect" && ch.pool != nil && ch.pool.Len() > 1 {
					ch.pool.ProbeAll(2 * time.Second)
				}
			}
		}
	}
}

func (rt *Router) HealthStats() (hosts, healthyUpstreams, totalUpstreams int) {
	mPtr := rt.hostsSnap.Load()
	if mPtr == nil {
		return 0, 0, 0
	}
	for _, ch := range *mPtr {
		if ch.IsActive && ch.HostType != "redirect" && ch.pool != nil {
			hosts++
			h, t := ch.pool.HealthSummary()
			healthyUpstreams += h
			totalUpstreams += t
		}
	}
	return hosts, healthyUpstreams, totalUpstreams
}

func (rt *Router) SetRenderer(r BlockRenderer) {
	rt.renderer = r
}

func (rt *Router) Reload() {
	if rt.store == nil {
		return
	}
	hosts, err := rt.store.ListProxyHosts()
	if err != nil {
		return
	}
	m := make(map[string]compiledHost, len(hosts))
	for _, h := range hosts {
		ch := compiledHost{
			ProxyHost: h,
			pool:      ParseUpstreamPool(h.TargetUpstream),
		}
		m[strings.ToLower(strings.TrimSpace(h.DomainName))] = ch
	}
	rt.hostsSnap.Store(&m)
	if rt.tlsMgr != nil {
		rt.tlsMgr.ReloadHosts(hosts)
	}
}

func (rt *Router) matchCompiledHost(r *http.Request) (compiledHost, bool) {
	hostHdr := r.Header.Get("X-Forwarded-Host")
	if hostHdr == "" {
		hostHdr = r.Host
	}
	clean := strings.ToLower(strings.TrimSpace(strings.SplitN(hostHdr, ":", 2)[0]))
	mPtr := rt.hostsSnap.Load()
	if mPtr == nil {
		return compiledHost{}, false
	}
	m := *mPtr
	if h, ok := m[clean]; ok {
		return h, true
	}
	// Wildcard domain fallback (e.g. *.kampus.ac.id)
	if wc := wildcardParent(clean); wc != "" {
		if h, ok := m[wc]; ok {
			// Override DomainName with actual requested subdomain so Host header & logs preserve the real subdomain
			h.DomainName = clean
			return h, true
		}
	}
	return compiledHost{}, false
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		hostsCnt, hUp, tUp := rt.HealthStats()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"status":"ok","engine":"Athena Shield","hosts":%d,"healthy_upstreams":%d,"total_upstreams":%d}`, hostsCnt, hUp, tUp)
		return
	}
	ch, found := rt.matchCompiledHost(r)
	if !found {
		http.Error(w, "Athena Shield: Domain not configured", http.StatusNotFound)
		return
	}
	host := ch.ProxyHost

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
	incID := newIncidentID()
	reqID := "ATH-" + incID
	w.Header().Set("X-Request-ID", reqID)

	// JS Proof-of-Work Challenge Verification Endpoint
	if r.URL.Path == waf.ChallengeVerifyPath && r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		if err := r.ParseForm(); err == nil {
			nonce := r.FormValue("nonce")
			expStr := r.FormValue("expires")
			sig := r.FormValue("sig")
			solution := r.FormValue("solution")
			redir := r.FormValue("redirect")
			exp, err := strconv.ParseInt(expStr, 10, 64)
			if err == nil && rt.engine.VerifyPoW(nonce, exp, sig, solution, clientIP, ua, rt.engine.ChallengeDifficulty()) {
				isHTTPS := r.TLS != nil || strings.EqualFold(proto, "https")
				http.SetCookie(w, rt.engine.IssueClearanceCookie(clientIP, ua, isHTTPS))
				if !strings.HasPrefix(redir, "/") || strings.HasPrefix(redir, "//") || strings.HasPrefix(redir, `/\`) {
					redir = "/"
				}
				http.Redirect(w, r, redir, http.StatusFound)
				return
			}
		}
		http.Error(w, "Athena Shield: Challenge verification failed", http.StatusForbidden)
		return
	}

	// Read request body whenever a payload is present (including GET/HEAD/OPTIONS with Content-Length > 0 or chunked)
	var bodyBytes []byte
	hasBodyPayload := r.ContentLength > 0 || len(r.TransferEncoding) > 0 || (r.ContentLength != 0 && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions)
	if r.Body != nil && hasBodyPayload {
		maxInspect := int64(rt.cfg.MaxNonMultipartBody + 1)
		if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/form-data") {
			maxInspect = int64(rt.cfg.MaxInspectBodyBytes)
		}
		limited := io.LimitReader(r.Body, maxInspect)
		bodyBytes, _ = io.ReadAll(limited)
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
		} else if dec.Challenge {
			diff := rt.engine.ChallengeDifficulty()
			nonce, exp, sig := rt.engine.CreateChallenge(clientIP, ua, diff)
			rt.logEvent(clientIP, r.Method, r.URL.Path, http.StatusServiceUnavailable, false, "[CHALLENGE] "+dec.Reason, ua, host.DomainName, cfCountry)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
			w.Header().Set("X-Protected-By", "Athena-Shield-v1.0")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(waf.RenderChallengeHTML(host.DomainName, nonce, exp, sig, diff, fullURI)))
			return
		} else {
			statusCode := http.StatusForbidden
			if dec.Category == "Rate Limiting" {
				statusCode = http.StatusTooManyRequests
			}
			rt.logEvent(clientIP, r.Method, r.URL.Path, statusCode, true, dec.Reason+" [Incident: "+reqID+"]", ua, host.DomainName, cfCountry)
			if rt.notifier != nil && dec.Category != "Rate Limiting" && dec.Category != "bot_attack" {
				rt.notifier.Notify("attack", fmt.Sprintf("Serangan Diblokir [%s]", dec.Category), host.DomainName, clientIP, fullURI, dec.Reason+" [Incident: "+reqID+"]")
			}

			w.Header().Set("X-Protected-By", "Athena-Shield-v1.0")
			if statusCode == http.StatusTooManyRequests {
				retry := dec.RetryAfter
				if retry <= 0 {
					retry = 60
				}
				w.Header().Set("Retry-After", fmt.Sprintf("%d", retry))
				w.Header().Set("X-RateLimit-Limit", "5")
				w.Header().Set("X-RateLimit-Remaining", "0")
			}

			wib := time.Now().In(time.FixedZone("WIB", 7*3600)).Format("02/01/2006, 15:04:05 WIB")

			if rt.renderer != nil {
				rt.renderer.RenderBlocked(w, BlockPageData{
					ClientIP:     clientIP,
					Reason:       publicBlockReason(dec.Category, statusCode),
					URI:          fullURI,
					IncidentID:   incID,
					StatusCode:   statusCode,
					RetryAfter:   dec.RetryAfter,
					TargetHost:   host.DomainName,
					TimestampStr: wib,
				})
			} else {
				http.Error(w, "Access Denied (Incident: "+reqID+")", statusCode)
			}
			return
		}
	} else if len(dec.ShadowMatches) > 0 {
		skipCleanLog = true
		rt.logEvent(clientIP, r.Method, r.URL.Path, http.StatusOK, false, "[SHADOW] "+strings.Join(dec.ShadowMatches, "; "), ua, host.DomainName, cfCountry)
	}

	// Edge Cache: Static Assets (always active for clean static GET/HEAD) + Turbo HTML (when host.EdgeCacheEnabled)
	isStatic := !cache.ShouldBypassStatic(r)
	useHTMLCache := !isStatic && host.EdgeCacheEnabled && !cache.ShouldBypassHTML(r)
	useEdgeCache := rt.edgeCache != nil && (isStatic || useHTMLCache)
	var cacheKey string
	if useEdgeCache {
		cacheKey = cache.CacheKey(proto, r.Method, host.DomainName, fullURI)
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
			if !skipCleanLog && !isStatic {
				rt.logEvent(clientIP, r.Method, r.URL.Path, ent.StatusCode, false, "", ua, host.DomainName, cfCountry)
			}
			return
		}
	} else if len(dec.ShadowMatches) > 0 {
		skipCleanLog = true
		rt.logEvent(clientIP, r.Method, r.URL.Path, http.StatusOK, false, "[SHADOW] "+strings.Join(dec.ShadowMatches, "; "), ua, host.DomainName, cfCountry)
	}

	chosen := ch.pool.Next()
	if chosen == nil || chosen.URL == nil {
		http.Error(w, "Invalid upstream configuration", http.StatusBadGateway)
		return
	}
	targetURL := chosen.URL

	isWebSocket := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
	isSSE := strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream")
	isGRPC := strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/grpc")
	isStreaming := isWebSocket || isSSE || isGRPC

	flushInterval := 100 * time.Millisecond
	if isStreaming {
		flushInterval = -1
	}

	isHTTPS := r.TLS != nil || strings.EqualFold(proto, "https") || host.SSLType != "none"
	fwdProto := "http"
	fwdPort := "80"
	if isHTTPS {
		fwdProto = "https"
		fwdPort = "443"
	}

	rp := &httputil.ReverseProxy{
		Transport:     rt.transport,
		FlushInterval: flushInterval,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(targetURL)
			pr.Out.Host = host.DomainName
			pr.Out.Header.Set("Host", host.DomainName)
			pr.Out.Header.Set("X-Forwarded-Host", host.DomainName)
			pr.Out.Header.Set("X-Forwarded-For", clientIP)
			pr.Out.Header.Set("X-Real-IP", clientIP)
			pr.Out.Header.Set("X-Request-ID", reqID)
			pr.Out.Header.Set("X-Forwarded-Proto", fwdProto)
			pr.Out.Header.Set("X-Forwarded-Port", fwdPort)
			if isHTTPS {
				pr.Out.Header.Set("X-Forwarded-SSL", "on")
			}
			if isWebSocket {
				pr.Out.Header.Set("Upgrade", pr.In.Header.Get("Upgrade"))
				if connHdr := pr.In.Header.Get("Connection"); connHdr != "" {
					pr.Out.Header.Set("Connection", connHdr)
				} else {
					pr.Out.Header.Set("Connection", "Upgrade")
				}
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("Alt-Svc")
			if dec.Mode != "bypass" {
				setSecurityHeaders(resp.Header)
			}

			if (resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusGatewayTimeout) && ch.pool.Len() > 1 {
				chosen.MarkUnhealthy(15 * time.Second)
			}

			ct := resp.Header.Get("Content-Type")
			ctLower := strings.ToLower(ct)
			if isStreaming || resp.StatusCode == http.StatusSwitchingProtocols || strings.Contains(ctLower, "text/event-stream") || strings.HasPrefix(ctLower, "application/grpc") {
				if !skipCleanLog && !isStatic {
					rt.logEvent(clientIP, r.Method, r.URL.Path, resp.StatusCode, false, "", ua, host.DomainName, cfCountry)
				}
				return nil
			}

			ce := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
			needDLP := dec.Mode != "bypass" && (ce == "" || ce == "identity" || ce == "gzip") && waf.IsDLPInspectableContentType(ct)
			canCache := useEdgeCache && resp.StatusCode == http.StatusOK && (isStatic || strings.Contains(ctLower, "text/html"))

			dlpBlocked := false
			dlpMonitor := false
			if needDLP || canCache {
				bufLimit := cache.MaxEntryBytes
				if waf.MaxDLPInspectBytes > bufLimit {
					bufLimit = waf.MaxDLPInspectBytes
				}
				origBody := resp.Body
				body, readErr := io.ReadAll(io.LimitReader(origBody, int64(bufLimit+1)))
				fullRead := readErr == nil && len(body) <= bufLimit
				if fullRead {
					_ = origBody.Close()
					resp.Body = io.NopCloser(bytes.NewReader(body))
					resp.ContentLength = int64(len(body))
				} else {
					resp.Body = struct {
						io.Reader
						io.Closer
					}{
						Reader: io.MultiReader(bytes.NewReader(body), origBody),
						Closer: origBody,
					}
				}

				if needDLP && len(body) > 0 {
					dlpInput := body
					if ce == "gzip" {
						if decBytes, gzErr := decompressGzipCapped(body, int64(waf.MaxDLPInspectBytes)); gzErr == nil && len(decBytes) > 0 {
							dlpInput = decBytes
						} else {
							dlpInput = nil
						}
					}
					if len(dlpInput) > 0 {
						dlpDec := rt.engine.InspectResponse(resp.StatusCode, ct, dlpInput, &host)
						if dlpDec.Blocked {
							if dlpDec.Mode == "monitor" {
								dlpMonitor = true
								rt.logEvent(clientIP, r.Method, r.URL.Path, resp.StatusCode, false, "[DLP-MONITOR] "+dlpDec.Reason+" [Incident: "+reqID+"]", ua, host.DomainName, cfCountry)
							} else {
								dlpBlocked = true
								rt.logEvent(clientIP, r.Method, r.URL.Path, http.StatusForbidden, true, dlpDec.Reason+" [Incident: "+reqID+"]", ua, host.DomainName, cfCountry)
								if rt.notifier != nil {
									rt.notifier.Notify("attack", fmt.Sprintf("DLP Diblokir [%s]", dlpDec.Category), host.DomainName, clientIP, fullURI, dlpDec.Reason+" [Incident: "+reqID+"]")
								}
								var safeBody []byte
								if strings.Contains(strings.ToLower(ct), "json") {
									resp.Header.Set("Content-Type", "application/json; charset=utf-8")
									safeBody = []byte(`{"error":"Response blocked by Athena Shield DLP Policy","code":403,"incident_id":"` + reqID + `"}`)
								} else {
									resp.Header.Set("Content-Type", "text/html; charset=utf-8")
									safeBody = []byte(fmt.Sprintf(`<div style="font-family:sans-serif;text-align:center;padding:60px 20px;background:#09090b;color:#fafafa;min-height:100vh;"><h1>403 — Athena Shield DLP</h1><p>Response disembunyikan oleh kebijakan Data Loss Prevention.</p><p style="color:#a1a1aa;font-size:12px;">Incident ID: %s</p></div>`, html.EscapeString(reqID)))
								}
								resp.Header.Del("Content-Encoding")
								resp.StatusCode = http.StatusForbidden
								resp.Status = "403 Forbidden"
								resp.Header.Set("X-Athena-DLP", "BLOCKED")
								resp.Body = io.NopCloser(bytes.NewReader(safeBody))
								resp.ContentLength = int64(len(safeBody))
								resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(safeBody)))
								return nil
							}
						}
					}
				}

				if !dlpBlocked && !dlpMonitor && canCache && readErr == nil && len(body) <= cache.MaxEntryBytes {
					rt.edgeCache.Set(cacheKey, resp.StatusCode, resp.Header, body, isStatic)
					resp.Header.Set("X-Athena-Cache", "MISS")
				}
			}

			if !skipCleanLog && !dlpMonitor && !isStatic {
				rt.logEvent(clientIP, r.Method, r.URL.Path, resp.StatusCode, false, "", ua, host.DomainName, cfCountry)
			}
			return nil
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
			if ch.pool.Len() > 1 {
				chosen.MarkUnhealthy(15 * time.Second)
			}
			status := http.StatusBadGateway
			kindTitle := "502 Bad Gateway — Backend Tidak Dapat Dihubungi"
			if strings.Contains(strings.ToLower(proxyErr.Error()), "timeout") {
				status = http.StatusGatewayTimeout
				kindTitle = "504 Gateway Timeout — Backend Lambat / Hang"
			}
			rt.logEvent(clientIP, req.Method, req.URL.Path, status, false, fmt.Sprintf("Upstream Gateway Error (%s): %v [Incident: %s]", chosen.Raw, proxyErr, reqID), ua, host.DomainName, cfCountry)
			if rt.notifier != nil {
				rt.notifier.Notify("upstream_down", kindTitle, host.DomainName, clientIP, req.URL.Path, proxyErr.Error()+" [Incident: "+reqID+"]")
			}
			rw.Header().Set("Content-Type", "text/html; charset=utf-8")
			rw.WriteHeader(status)
			_, _ = fmt.Fprintf(rw, `<div style="font-family:sans-serif;text-align:center;padding:60px 20px;background:#09090b;color:#fafafa;min-height:100vh;"><h1>%d — Athena Shield</h1><p>Layanan backend sedang tidak tersedia atau mengalami timeout.</p><p style="color:#a1a1aa;font-size:12px;">Incident ID: %s</p></div>`, status, html.EscapeString(reqID))
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
	// Strip backend version fingerprinting headers
	h.Del("X-Powered-By")
	h.Del("X-AspNet-Version")
	h.Del("X-AspNetMvc-Version")
	h.Del("X-Runtime")
	h.Set("Server", "Athena-Shield")
	h.Set("X-Protected-By", "Athena-Shield-v1.0")
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-XSS-Protection", "1; mode=block")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
}

func newIncidentID() string {
	buf := make([]byte, 5)
	_, _ = rand.Read(buf)
	return strings.ToUpper(hex.EncodeToString(buf))
}

func publicBlockReason(category string, statusCode int) string {
	if statusCode == http.StatusTooManyRequests {
		return "Rate Limit Exceeded (Permintaan melebihi batas keamanan)"
	}
	switch category {
	case "GeoIP Block":
		return "Access Restricted by Geographic Policy"
	case "IP Blacklist":
		return "Access Denied by IP Security Policy"
	default:
		return "Request Blocked by Security Policy"
	}
}

func decompressGzipCapped(data []byte, limit int64) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gr.Close()
	return io.ReadAll(io.LimitReader(gr, limit))
}
