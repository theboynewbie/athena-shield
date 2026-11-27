package web

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/theboynewbie/athena-shield/internal/auth"
	"github.com/theboynewbie/athena-shield/internal/geoip"
	"github.com/theboynewbie/athena-shield/internal/store"
)

func (sv *Server) recordAudit(r *http.Request, user *store.User, action, target, details string) {
	if sv.store == nil || user == nil {
		return
	}
	sv.store.RecordAuditLog(store.AuditLog{
		Timestamp: time.Now().UTC(),
		Actor:     user.Username,
		Role:      user.Role,
		Action:    action,
		Target:    target,
		Details:   details,
		ClientIP:  geoip.GetClientIP(r),
	})
}

func (sv *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if tok := strings.TrimSpace(os.Getenv("METRICS_TOKEN")); tok != "" {
		authHdr := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		qTok := r.URL.Query().Get("token")
		if subtle.ConstantTimeCompare([]byte(authHdr), []byte(tok)) != 1 &&
			subtle.ConstantTimeCompare([]byte(qTok), []byte(tok)) != 1 {
			http.Error(w, "Unauthorized metrics access", http.StatusUnauthorized)
			return
		}
	}

	total, blocked, allowed, activeRules, _, _, _ := sv.store.GetStats()
	_, _, activeBans := sv.store.StorageCounts()
	dbSizeMB := sv.store.DBSizeMB()

	var hostsCnt, healthyUpstreams, totalUpstreams int
	if sv.router != nil {
		hostsCnt, healthyUpstreams, totalUpstreams = sv.router.HealthStats()
	}

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w,
		"# HELP athena_requests_total Total HTTP requests logged by Athena Shield\n"+
			"# TYPE athena_requests_total counter\n"+
			"athena_requests_total %d\n"+
			"# HELP athena_requests_blocked_total Total blocked malicious requests\n"+
			"# TYPE athena_requests_blocked_total counter\n"+
			"athena_requests_blocked_total %d\n"+
			"# HELP athena_requests_allowed_total Total allowed clean requests\n"+
			"# TYPE athena_requests_allowed_total counter\n"+
			"athena_requests_allowed_total %d\n"+
			"# HELP athena_active_rules Number of active WAF detection rules\n"+
			"# TYPE athena_active_rules gauge\n"+
			"athena_active_rules %d\n"+
			"# HELP athena_active_autobans Number of currently auto-banned IPs\n"+
			"# TYPE athena_active_autobans gauge\n"+
			"athena_active_autobans %d\n"+
			"# HELP athena_db_size_megabytes SQLite database size in MB\n"+
			"# TYPE athena_db_size_megabytes gauge\n"+
			"athena_db_size_megabytes %.2f\n"+
			"# HELP athena_proxy_hosts_active Number of active proxy hosts\n"+
			"# TYPE athena_proxy_hosts_active gauge\n"+
			"athena_proxy_hosts_active %d\n"+
			"# HELP athena_upstreams_healthy Number of healthy backend upstream targets\n"+
			"# TYPE athena_upstreams_healthy gauge\n"+
			"athena_upstreams_healthy %d\n"+
			"# HELP athena_upstreams_total Total configured backend upstream targets\n"+
			"# TYPE athena_upstreams_total gauge\n"+
			"athena_upstreams_total %d\n"+
			"# HELP athena_go_goroutines Current number of goroutines\n"+
			"# TYPE athena_go_goroutines gauge\n"+
			"athena_go_goroutines %d\n"+
			"# HELP athena_process_memory_alloc_bytes Allocated heap memory in bytes\n"+
			"# TYPE athena_process_memory_alloc_bytes gauge\n"+
			"athena_process_memory_alloc_bytes %d\n",
		total, blocked, allowed, activeRules, activeBans, dbSizeMB,
		hostsCnt, healthyUpstreams, totalUpstreams, runtime.NumGoroutine(), mem.Alloc,
	)
}

func cefEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

func cefExtEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

func (sv *Server) apiExportLogsSIEM(w http.ResponseWriter, r *http.Request, user *store.User) {
	q := r.URL.Query()
	format := strings.ToLower(strings.TrimSpace(q.Get("format")))
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 1000
	} else if limit > 5000 {
		limit = 5000
	}

	res, err := sv.store.QueryLogs(store.LogFilter{
		FilterBlocked: q.Get("filter_blocked"),
		FilterHost:    q.Get("filter_host"),
		FilterDate:    q.Get("filter_date"),
		Search:        q.Get("search"),
		Page:          1,
		Limit:         limit,
	})
	if err != nil {
		writeDetailError(w, 500, err.Error())
		return
	}

	ts := time.Now().UTC().Format("20060102-150405")
	if format == "cef" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="athena-siem-%s.cef"`, ts))
		w.WriteHeader(http.StatusOK)
		for _, l := range res.Logs {
			sev := 3
			outcome := "allowed"
			evName := "WAF_ALLOW"
			if l.IsBlocked {
				sev = 8
				outcome = "blocked"
				evName = "WAF_BLOCK"
			}
			reason := l.Reason
			if reason == "" {
				reason = "Clean traffic"
			}
			_, _ = fmt.Fprintf(w,
				"CEF:0|AthenaShield|WAF|1.0|%s|%s|%d|rt=%s src=%s dhost=%s requestMethod=%s request=%s outcome=%s cn1=%d cn1Label=StatusCode\n",
				evName, cefEscape(reason), sev,
				l.Timestamp.UTC().Format(time.RFC3339),
				cefExtEscape(l.ClientIP), cefExtEscape(l.Host),
				cefExtEscape(l.Method), cefExtEscape(l.URI),
				outcome, l.StatusCode,
			)
		}
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="athena-siem-%s.jsonl"`, ts))
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	for _, l := range res.Logs {
		_ = enc.Encode(l)
	}
}

func (sv *Server) apiListAuditLogs(w http.ResponseWriter, r *http.Request, user *store.User) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	logs, err := sv.store.ListAuditLogs(limit)
	if err != nil {
		writeDetailError(w, 500, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, logs)
}

func (sv *Server) api2FAStatus(w http.ResponseWriter, r *http.Request, user *store.User) {
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":  user.TOTPEnabled,
		"username": user.Username,
	})
}

func (sv *Server) api2FASetup(w http.ResponseWriter, r *http.Request, user *store.User) {
	if user.TOTPEnabled {
		writeDetailError(w, http.StatusForbidden, "2FA sudah aktif. Nonaktifkan 2FA terlebih dahulu menggunakan password sebelum mengatur ulang.")
		return
	}
	sec, err := auth.GenerateTOTPSecret()
	if err != nil {
		writeDetailError(w, 500, "Gagal membuat secret TOTP")
		return
	}
	if err := sv.store.SetUserTOTP(user.ID, sec, false); err != nil {
		writeDetailError(w, 500, "Gagal menyimpan secret TOTP")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secret":      sec,
		"otpauth_uri": auth.ProvisioningURI("AthenaShield", user.Username, sec),
	})
}

func (sv *Server) api2FAVerify(w http.ResponseWriter, r *http.Request, user *store.User) {
	var in struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeDetailError(w, 400, "Invalid JSON")
		return
	}
	if user.TOTPSecret == "" {
		writeDetailError(w, 400, "Setup 2FA belum dijalankan")
		return
	}
	if !auth.VerifyTOTP(user.TOTPSecret, in.Code, time.Now()) {
		writeDetailError(w, 400, "Kode 6-digit Authenticator tidak valid")
		return
	}
	if err := sv.store.SetUserTOTP(user.ID, user.TOTPSecret, true); err != nil {
		writeDetailError(w, 500, err.Error())
		return
	}
	sv.recordAudit(r, user, "2FA_ENABLE", user.Username, "2FA TOTP Authenticator diaktifkan")
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "2FA Authenticator berhasil diaktifkan!"})
}

func (sv *Server) api2FADisable(w http.ResponseWriter, r *http.Request, user *store.User) {
	var in struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Password == "" {
		writeDetailError(w, 400, "Password wajib diisi untuk menonaktifkan 2FA")
		return
	}
	if !auth.VerifyPassword(in.Password, user.HashedPassword) {
		writeDetailError(w, 401, "Password tidak valid")
		return
	}
	if err := sv.store.SetUserTOTP(user.ID, "", false); err != nil {
		writeDetailError(w, 500, err.Error())
		return
	}
	_ = sv.store.BumpUserTokenVersion(user.ID)
	newVer := user.TokenVersion + 1
	if newVer <= 1 {
		newVer = 2
	}
	if tok, err := sv.auth.CreateToken(user.Username, user.Role, newVer); err == nil {
		isSecure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
		http.SetCookie(w, &http.Cookie{
			Name:     "access_token",
			Value:    "Bearer " + tok,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   int(auth.TokenTTL.Seconds()),
			SameSite: http.SameSiteLaxMode,
			Secure:   isSecure,
		})
	}
	sv.recordAudit(r, user, "2FA_DISABLE", user.Username, "2FA TOTP Authenticator dinonaktifkan")
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "2FA Authenticator dinonaktifkan."})
}
