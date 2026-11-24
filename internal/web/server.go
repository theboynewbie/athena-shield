package web

import (
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/theboynewbie/athena-shield/internal/alert"
	"github.com/theboynewbie/athena-shield/internal/auth"
	"github.com/theboynewbie/athena-shield/internal/cache"
	"github.com/theboynewbie/athena-shield/internal/config"
	"github.com/theboynewbie/athena-shield/internal/geoip"
	"github.com/theboynewbie/athena-shield/internal/proxy"
	"github.com/theboynewbie/athena-shield/internal/ratelimit"
	"github.com/theboynewbie/athena-shield/internal/store"
	"github.com/theboynewbie/athena-shield/internal/waf"
	webassets "github.com/theboynewbie/athena-shield/web"
)

type Server struct {
	cfg       config.Config
	store     *store.Store
	auth      *auth.Manager
	engine    *waf.Engine
	rl        *ratelimit.RateLimiter
	edgeCache *cache.EdgeCache
	notifier  *alert.Notifier
	router    *proxy.Router

	pages      map[string]*template.Template
	blockedTpl *template.Template
	mux        *http.ServeMux
}

type pageData struct {
	User       *store.User
	ActivePage string
	Error      string
	CSRFToken  string
	Message    string
}

func NewServer(
	cfg config.Config,
	s *store.Store,
	am *auth.Manager,
	eng *waf.Engine,
	rl *ratelimit.RateLimiter,
	ec *cache.EdgeCache,
	n *alert.Notifier,
	rt *proxy.Router,
) (*Server, error) {
	funcs := template.FuncMap{
		"firstChar": func(str string) string {
			if str == "" {
				return "A"
			}
			return strings.ToUpper(str[:1])
		},
		"div60": func(sec int) int {
			return sec / 60
		},
	}

	pageNames := []string{
		"login.html", "dashboard.html", "proxy_hosts.html",
		"rules.html", "logs.html", "users.html", "settings.html", "error_403.html",
	}
	pages := make(map[string]*template.Template, len(pageNames))
	for _, name := range pageNames {
		t, err := template.New(name).Funcs(funcs).ParseFS(webassets.FS, "templates/base.html", "templates/"+name)
		if err != nil {
			return nil, err
		}
		pages[name] = t
	}

	blockedTpl, err := template.New("blocked.html").Funcs(funcs).ParseFS(webassets.FS, "templates/blocked.html")
	if err != nil {
		return nil, err
	}

	srv := &Server{
		cfg:        cfg,
		store:      s,
		auth:       am,
		engine:     eng,
		rl:         rl,
		edgeCache:  ec,
		notifier:   n,
		router:     rt,
		pages:      pages,
		blockedTpl: blockedTpl,
		mux:        http.NewServeMux(),
	}
	srv.registerRoutes()
	return srv, nil
}

func (sv *Server) Handler() http.Handler {
	return sv.mux
}

func (sv *Server) RenderBlocked(w http.ResponseWriter, data proxy.BlockPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(data.StatusCode)
	_ = sv.blockedTpl.ExecuteTemplate(w, "blocked.html", data)
}

func (sv *Server) renderPage(w http.ResponseWriter, name string, status int, data pageData) {
	t, ok := sv.pages[name]
	if !ok {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = t.ExecuteTemplate(w, name, data)
}

func (sv *Server) registerRoutes() {
	staticSub, _ := fs.Sub(webassets.FS, "static")
	sv.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	sv.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "engine": "Athena Shield"})
	})
	sv.mux.HandleFunc("GET /metrics", sv.handleMetrics)

	sv.mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	})
	sv.mux.HandleFunc("GET /login", sv.handleLoginPage)
	sv.mux.HandleFunc("POST /login", sv.handleLoginSubmit)
	sv.mux.HandleFunc("GET /logout", sv.handleLogout)

	sv.mux.HandleFunc("GET /dashboard", sv.handleDashboardPage)
	sv.mux.HandleFunc("GET /proxy-hosts", sv.handleProxyHostsPage)
	sv.mux.HandleFunc("GET /rules", sv.handleRulesPage)
	sv.mux.HandleFunc("GET /logs", sv.handleLogsPage)
	sv.mux.HandleFunc("GET /users", sv.handleUsersPage)
	sv.mux.HandleFunc("GET /settings", sv.handleSettingsPage)

	// JSON API
	sv.mux.HandleFunc("GET /api/proxy-hosts", sv.requireAuthAPI(sv.apiListProxyHosts))
	sv.mux.HandleFunc("POST /api/proxy-hosts", sv.requireWriteAPI(sv.apiCreateProxyHost))
	sv.mux.HandleFunc("PUT /api/proxy-hosts/{id}", sv.requireWriteAPI(sv.apiUpdateProxyHost))
	sv.mux.HandleFunc("DELETE /api/proxy-hosts/{id}", sv.requireWriteAPI(sv.apiDeleteProxyHost))

	sv.mux.HandleFunc("GET /api/stats", sv.requireAuthAPI(sv.apiStats))

	sv.mux.HandleFunc("GET /api/rules", sv.requireAuthAPI(sv.apiListRules))
	sv.mux.HandleFunc("POST /api/rules", sv.requireWriteAPI(sv.apiCreateRule))
	sv.mux.HandleFunc("PUT /api/rules/{id}", sv.requireWriteAPI(sv.apiUpdateRule))
	sv.mux.HandleFunc("DELETE /api/rules/{id}", sv.requireWriteAPI(sv.apiDeleteRule))

	sv.mux.HandleFunc("GET /api/ips", sv.requireAuthAPI(sv.apiListIPs))
	sv.mux.HandleFunc("POST /api/ips", sv.requireWriteAPI(sv.apiAddIP))
	sv.mux.HandleFunc("DELETE /api/ips/{id}", sv.requireWriteAPI(sv.apiDeleteIP))

	sv.mux.HandleFunc("GET /api/logs", sv.requireAuthAPI(sv.apiGetLogs))
	sv.mux.HandleFunc("GET /api/logs/export", sv.requireAuthAPI(sv.apiExportLogsSIEM))
	sv.mux.HandleFunc("DELETE /api/logs/clear", sv.requireSuperAdminAPI(sv.apiClearLogs))

	sv.mux.HandleFunc("GET /api/audit-logs", sv.requireAuthAPI(sv.apiListAuditLogs))
	sv.mux.HandleFunc("GET /api/account/2fa/status", sv.requireAuthAPI(sv.api2FAStatus))
	sv.mux.HandleFunc("POST /api/account/2fa/setup", sv.requireAuthAPI(sv.api2FASetup))
	sv.mux.HandleFunc("POST /api/account/2fa/verify", sv.requireAuthAPI(sv.api2FAVerify))
	sv.mux.HandleFunc("POST /api/account/2fa/disable", sv.requireAuthAPI(sv.api2FADisable))

	sv.mux.HandleFunc("GET /api/banned-ips", sv.requireAuthAPI(sv.apiBannedIPs))
	sv.mux.HandleFunc("POST /api/unban-ip", sv.requireWriteAPI(sv.apiUnbanIP))
	sv.mux.HandleFunc("POST /api/cache/purge", sv.requireWriteAPI(sv.apiPurgeCache))

	sv.mux.HandleFunc("GET /api/users", sv.requireSuperAdminAPI(sv.apiListUsers))
	sv.mux.HandleFunc("POST /api/users", sv.requireSuperAdminAPI(sv.apiCreateUser))
	sv.mux.HandleFunc("PUT /api/users/{id}", sv.requireSuperAdminAPI(sv.apiUpdateUser))
	sv.mux.HandleFunc("PUT /api/users/{id}/reset-password", sv.requireSuperAdminAPI(sv.apiResetPassword))
	sv.mux.HandleFunc("DELETE /api/users/{id}", sv.requireSuperAdminAPI(sv.apiDeleteUser))

	sv.mux.HandleFunc("GET /api/settings", sv.requireSuperAdminAPI(sv.apiGetSettings))
	sv.mux.HandleFunc("PUT /api/settings", sv.requireSuperAdminAPI(sv.apiUpdateSettings))
	sv.mux.HandleFunc("POST /api/settings/test-telegram", sv.requireSuperAdminAPI(sv.apiTestTelegram))
	sv.mux.HandleFunc("POST /api/settings/prune-logs", sv.requireSuperAdminAPI(sv.apiPruneLogs))

	sv.mux.HandleFunc("GET /api/backup/export", sv.requireSuperAdminAPI(sv.apiBackupExport))
	sv.mux.HandleFunc("POST /api/backup/import", sv.requireSuperAdminAPI(sv.apiBackupImport))
}

func applyLoginSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeDetailError(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]string{"detail": detail})
}

type authedHandler func(w http.ResponseWriter, r *http.Request, user *store.User)

func (sv *Server) requireAuthAPI(next authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := sv.auth.CurrentUser(r)
		if u == nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeDetailError(w, http.StatusUnauthorized, "Not authenticated")
			return
		}
		next(w, r, u)
	}
}

func (sv *Server) requireWriteAPI(next authedHandler) http.HandlerFunc {
	return sv.requireAuthAPI(func(w http.ResponseWriter, r *http.Request, u *store.User) {
		if strings.EqualFold(u.Role, "auditor") {
			writeDetailError(w, http.StatusForbidden, "Read-Only Auditor tidak diizinkan mengubah konfigurasi.")
			return
		}
		next(w, r, u)
	})
}

func (sv *Server) requireSuperAdminAPI(next authedHandler) http.HandlerFunc {
	return sv.requireAuthAPI(func(w http.ResponseWriter, r *http.Request, u *store.User) {
		if u.Role != "super_admin" {
			writeDetailError(w, http.StatusForbidden, "Super Admin privilege required.")
			return
		}
		next(w, r, u)
	})
}

func (sv *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	applyLoginSecurityHeaders(w)
	clientIP := geoip.GetClientIP(r)
	if locked, rem := sv.auth.IsIPLocked(clientIP); locked {
		sv.renderPage(w, "login.html", http.StatusTooManyRequests, pageData{
			Error: "Akses diblokir sementara karena terlalu banyak percobaan login yang gagal. Silakan tunggu " + strconvItoa(rem) + " detik lagi.",
		})
		return
	}
	if u := sv.auth.CurrentUser(r); u != nil {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	sv.renderPage(w, "login.html", http.StatusOK, pageData{
		CSRFToken: sv.auth.GenerateCSRF(clientIP),
	})
}

func (sv *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	applyLoginSecurityHeaders(w)
	clientIP := geoip.GetClientIP(r)
	if locked, rem := sv.auth.IsIPLocked(clientIP); locked {
		sv.renderPage(w, "login.html", http.StatusTooManyRequests, pageData{
			Error:     "IP Anda terkunci selama " + strconvItoa(rem) + " detik lagi karena aktivitas mencurigakan.",
			CSRFToken: sv.auth.GenerateCSRF(clientIP),
		})
		return
	}

	_ = r.ParseForm()
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	csrfToken := r.FormValue("csrf_token")
	websiteTrap := r.FormValue("website_trap")

	reqHost := strings.TrimSpace(strings.SplitN(r.Host, ":", 2)[0])
	if reqHost == "" {
		reqHost = "Athena Dashboard"
	}

	if websiteTrap != "" {
		sv.auth.LockIP(clientIP)
		sv.store.QueueLog(store.Log{
			Timestamp:  time.Now().UTC(),
			ClientIP:   clientIP,
			Host:       reqHost,
			Method:     "POST",
			URI:        "/login",
			StatusCode: http.StatusForbidden,
			IsBlocked:  true,
			Reason:     "Login Bot Honeypot Triggered",
			UserAgent:  r.UserAgent(),
		})
		sv.renderPage(w, "login.html", http.StatusForbidden, pageData{
			Error:     "Akses ditolak: Aktivitas bot terdeteksi.",
			CSRFToken: sv.auth.GenerateCSRF(clientIP),
		})
		return
	}

	if !sv.auth.VerifyCSRF(csrfToken, clientIP) {
		sv.renderPage(w, "login.html", http.StatusForbidden, pageData{
			Error:     "Token keamanan CSRF tidak valid atau sudah kedaluwarsa. Silakan refresh halaman.",
			CSRFToken: sv.auth.GenerateCSRF(clientIP),
		})
		return
	}

	if len(username) > 100 {
		username = username[:100]
	}
	if len(password) > 128 {
		password = password[:128]
	}

	if locked, rem := sv.auth.IsUserLocked(username); locked {
		sv.renderPage(w, "login.html", http.StatusTooManyRequests, pageData{
			Error:     "Akun ini dikunci sementara (" + strconvItoa(rem) + " detik) karena percobaan login berulang dari banyak sumber.",
			CSRFToken: sv.auth.GenerateCSRF(clientIP),
		})
		return
	}

	u, err := sv.store.GetUserByUsernameOrEmail(username)
	validPass := false
	if err == nil && u != nil {
		validPass = auth.VerifyPassword(password, u.HashedPassword)
	} else {
		auth.VerifyDummyPassword(password)
	}

	if err != nil || u == nil || !validPass || !u.IsActive {
		ipLocked, remTries := sv.auth.RecordFailedLogin(clientIP, username)
		if ipLocked {
			sv.store.QueueLog(store.Log{
				Timestamp:  time.Now().UTC(),
				ClientIP:   clientIP,
				Host:       reqHost,
				Method:     "POST",
				URI:        "/login",
				StatusCode: http.StatusTooManyRequests,
				IsBlocked:  true,
				Reason:     "Login Brute Force Lockout: 5 failed attempts",
				UserAgent:  r.UserAgent(),
			})
			sv.renderPage(w, "login.html", http.StatusTooManyRequests, pageData{
				Error:     "Terlalu banyak percobaan gagal. IP Anda dikunci selama 15 menit.",
				CSRFToken: sv.auth.GenerateCSRF(clientIP),
			})
			return
		}
		sv.store.QueueLog(store.Log{
			Timestamp:  time.Now().UTC(),
			ClientIP:   clientIP,
			Host:       reqHost,
			Method:     "POST",
			URI:        "/login",
			StatusCode: http.StatusUnauthorized,
			IsBlocked:  true,
			Reason:     "Failed Login Attempt",
			UserAgent:  r.UserAgent(),
		})
		sv.renderPage(w, "login.html", http.StatusUnauthorized, pageData{
			Error:     "Kredensial otentikasi tidak valid. Sisa percobaan: " + strconvItoa(remTries) + " kali.",
			CSRFToken: sv.auth.GenerateCSRF(clientIP),
		})
		return
	}

	if u.TOTPEnabled && u.TOTPSecret != "" {
		totpCode := strings.TrimSpace(r.FormValue("totp_code"))
		if !auth.VerifyTOTP(u.TOTPSecret, totpCode, time.Now()) {
			sv.renderPage(w, "login.html", http.StatusUnauthorized, pageData{
				Error:     "Kode 2FA Authenticator wajib diisi dan harus valid (6 digit).",
				CSRFToken: sv.auth.GenerateCSRF(clientIP),
			})
			return
		}
	}

	sv.auth.ClearLoginFailures(clientIP, username)
	sv.store.QueueLog(store.Log{
		Timestamp:  time.Now().UTC(),
		ClientIP:   clientIP,
		Host:       reqHost,
		Method:     "POST",
		URI:        "/login",
		StatusCode: http.StatusOK,
		IsBlocked:  false,
		Reason:     "Operator Login Success: " + u.Username,
		UserAgent:  r.UserAgent(),
	})

	tok, _ := sv.auth.CreateToken(u.Username, u.Role)
	isSecure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    "Bearer " + tok,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   8 * 3600,
		SameSite: http.SameSiteLaxMode,
		Secure:   isSecure,
	})
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (sv *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	applyLoginSecurityHeaders(w)
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (sv *Server) handleDashboardPage(w http.ResponseWriter, r *http.Request) {
	u := sv.auth.CurrentUser(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	sv.renderPage(w, "dashboard.html", http.StatusOK, pageData{User: u, ActivePage: "dashboard"})
}

func (sv *Server) handleProxyHostsPage(w http.ResponseWriter, r *http.Request) {
	u := sv.auth.CurrentUser(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	sv.renderPage(w, "proxy_hosts.html", http.StatusOK, pageData{User: u, ActivePage: "proxy_hosts"})
}

func (sv *Server) handleRulesPage(w http.ResponseWriter, r *http.Request) {
	u := sv.auth.CurrentUser(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	sv.renderPage(w, "rules.html", http.StatusOK, pageData{User: u, ActivePage: "rules"})
}

func (sv *Server) handleLogsPage(w http.ResponseWriter, r *http.Request) {
	u := sv.auth.CurrentUser(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	sv.renderPage(w, "logs.html", http.StatusOK, pageData{User: u, ActivePage: "logs"})
}

func (sv *Server) handleUsersPage(w http.ResponseWriter, r *http.Request) {
	u := sv.auth.CurrentUser(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if u.Role != "super_admin" {
		sv.renderPage(w, "error_403.html", http.StatusForbidden, pageData{
			User:    u,
			Message: "Akses Ditolak: Hanya Super Admin yang diizinkan mengelola user.",
		})
		return
	}
	sv.renderPage(w, "users.html", http.StatusOK, pageData{User: u, ActivePage: "users"})
}

func (sv *Server) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	u := sv.auth.CurrentUser(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if u.Role != "super_admin" {
		sv.renderPage(w, "error_403.html", http.StatusForbidden, pageData{
			User:    u,
			Message: "Akses Ditolak: Hanya Super Admin yang diizinkan mengelola pengaturan sistem & backup.",
		})
		return
	}
	sv.renderPage(w, "settings.html", http.StatusOK, pageData{User: u, ActivePage: "settings"})
}

func strconvItoa(n int) string {
	return strconv.Itoa(n)
}
