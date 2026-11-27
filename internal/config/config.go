package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	HTTPPort            string
	HTTPSPort           string
	DashboardPort       string
	DataDir             string
	ACMEEmail           string
	SecretKey           string
	DefaultAdminUser    string
	DefaultAdminEmail   string
	DefaultAdminPass    string
	UpstreamTimeoutSec  int
	RateLimitMaxReq     int
	RateLimitWindowSec  int
	LoginLimitMax       int
	LoginHourlyMax      int
	AutoBanThreshold    int
	AutoBanWindowSec    int
	AutoBanDurationSec  int
	MaxInspectBodyBytes int
	MaxNonMultipartBody int
	TrustedProxies      string
	SetupToken          string
	EdgeCacheMaxMB      int
	DashboardBindAddr   string
	DashboardTLSCert    string
	DashboardTLSKey     string
	UpstreamInsecureTLS bool
}

func Load() Config {
	dataDir := getEnv("DATA_DIR", "/data")
	if dataDir == "" {
		dataDir = "./data"
	}
	return Config{
		HTTPPort:            getEnv("HTTP_PORT", "80"),
		HTTPSPort:           getEnv("HTTPS_PORT", "443"),
		DashboardPort:       getEnv("DASHBOARD_PORT", "1081"),
		DataDir:             filepath.Clean(dataDir),
		ACMEEmail:           getEnv("ACME_EMAIL", "admin@example.com"),
		SecretKey:           getEnv("SECRET_KEY", ""),
		DefaultAdminUser:    getEnv("DEFAULT_ADMIN_USER", ""),
		DefaultAdminEmail:   getEnv("DEFAULT_ADMIN_EMAIL", ""),
		DefaultAdminPass:    getEnv("DEFAULT_ADMIN_PASSWORD", ""),
		UpstreamTimeoutSec:  getEnvInt("UPSTREAM_TIMEOUT_SECONDS", 120),
		RateLimitMaxReq:     getEnvInt("RATE_LIMIT_MAX_REQUESTS", 600),
		RateLimitWindowSec:  getEnvInt("RATE_LIMIT_WINDOW_SECONDS", 60),
		LoginLimitMax:       getEnvInt("WP_LOGIN_LIMIT_MAX", 12),
		LoginHourlyMax:      getEnvInt("WP_LOGIN_HOURLY_MAX", 35),
		AutoBanThreshold:    getEnvInt("AUTO_BAN_THRESHOLD", 15),
		AutoBanWindowSec:    getEnvInt("AUTO_BAN_WINDOW", 3600),
		AutoBanDurationSec:  getEnvInt("AUTO_BAN_DURATION", 86400),
		MaxInspectBodyBytes: getEnvInt("MAX_INSPECT_BODY_BYTES", 2*1024*1024),
		MaxNonMultipartBody: getEnvInt("MAX_NON_MULTIPART_BODY_BYTES", 10*1024*1024),
		TrustedProxies:      getEnv("TRUSTED_PROXIES", ""),
		SetupToken:          getEnv("SETUP_TOKEN", ""),
		EdgeCacheMaxMB:      getEnvInt("EDGE_CACHE_MAX_MB", 128),
		DashboardBindAddr:   getEnv("DASHBOARD_BIND_ADDR", ""),
		DashboardTLSCert:    getEnv("DASHBOARD_TLS_CERT", ""),
		DashboardTLSKey:     getEnv("DASHBOARD_TLS_KEY", ""),
		UpstreamInsecureTLS: getEnvBool("UPSTREAM_INSECURE_TLS", false),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "1", "true", "yes":
		return true
	case "0", "false", "no":
		return false
	default:
		return fallback
	}
}
