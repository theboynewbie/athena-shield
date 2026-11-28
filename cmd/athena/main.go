package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
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
	"github.com/theboynewbie/athena-shield/internal/web"
)

func main() {
	cfg := config.Load()
	geoip.ConfigureTrustedProxies(cfg.TrustedProxies)
	geoip.ConfigureTrustedRanges(cfg.TrustedRanges)
	if cfg.GeoIPDBPath != "" {
		if n, geoErr := geoip.LoadGeoIPCSV(cfg.GeoIPDBPath); geoErr != nil {
			log.Printf("[ATHENA SHIELD] Warning: Failed to load GEOIP_DB_PATH (%s): %v", cfg.GeoIPDBPath, geoErr)
		} else {
			log.Printf("[ATHENA SHIELD] Loaded %d offline GeoIP ranges from %s", n, cfg.GeoIPDBPath)
		}
	}

	s, err := store.Open(cfg.DataDir, cfg.DefaultAdminUser, cfg.DefaultAdminEmail, cfg.DefaultAdminPass)
	if err != nil {
		log.Fatalf("[ATHENA SHIELD] Failed to initialize store: %v", err)
	}
	defer s.Close()

	_, _ = s.PruneExpiredLogs()

	secret := s.GetOrCreateSecret(cfg.SecretKey)
	am := auth.NewManager(secret, s)
	notifier := alert.NewNotifier(s)
	defer notifier.Close()

	rl := ratelimit.New(cfg, s, notifier)
	eng := waf.NewEngine(cfg, s, rl)
	ec := cache.NewEdgeCache(int64(cfg.EdgeCacheMaxMB) * 1024 * 1024)
	tlsMgr := proxy.NewTLSManager(cfg.DataDir, cfg.ACMEEmail)
	rt := proxy.NewRouter(cfg, s, eng, rl, ec, notifier, tlsMgr, nil)
	defer rt.Close()

	s.SetOnChange(func() {
		eng.Reload()
		rl.Reload()
		rt.Reload()
	})

	webSrv, err := web.NewServer(cfg, s, am, eng, rl, ec, notifier, rt)
	if err != nil {
		log.Fatalf("[ATHENA SHIELD] Failed to initialize web UI: %v", err)
	}
	rt.SetRenderer(webSrv)

	proxyWriteTimeout := time.Duration(cfg.UpstreamTimeoutSec+15) * time.Second

	httpSrv := &http.Server{
		Addr:              ":" + cfg.HTTPPort,
		Handler:           tlsMgr.HTTPChallengeHandler(rt),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      proxyWriteTimeout,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	httpsSrv := &http.Server{
		Addr:    ":" + cfg.HTTPSPort,
		Handler: rt,
		TLSConfig: &tls.Config{
			GetCertificate: tlsMgr.GetCertificate,
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"h2", "http/1.1"},
		},
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      proxyWriteTimeout,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	dashSrv := &http.Server{
		Addr:              cfg.DashboardBindAddr + ":" + cfg.DashboardPort,
		Handler:           webSrv.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	if cfg.DashboardTLSCert != "" && cfg.DashboardTLSKey != "" {
		dashSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	go func() {
		log.Printf("[ATHENA SHIELD] Proxy HTTP listening on :%s", cfg.HTTPPort)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[ATHENA SHIELD] HTTP server error: %v", err)
		}
	}()

	go func() {
		log.Printf("[ATHENA SHIELD] Proxy HTTPS listening on :%s", cfg.HTTPSPort)
		if err := httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("[ATHENA SHIELD] HTTPS server error: %v", err)
		}
	}()

	go func() {
		if cfg.DashboardTLSCert != "" && cfg.DashboardTLSKey != "" {
			log.Printf("[ATHENA SHIELD] Dashboard & API (HTTPS) listening on %s", dashSrv.Addr)
			if err := dashSrv.ListenAndServeTLS(cfg.DashboardTLSCert, cfg.DashboardTLSKey); err != nil && err != http.ErrServerClosed {
				log.Fatalf("[ATHENA SHIELD] Dashboard HTTPS server error: %v", err)
			}
			return
		}
		log.Printf("[ATHENA SHIELD] Dashboard & API listening on %s", dashSrv.Addr)
		if err := dashSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[ATHENA SHIELD] Dashboard server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.Println("[ATHENA SHIELD] Shutting down gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
	_ = httpsSrv.Shutdown(ctx)
	_ = dashSrv.Shutdown(ctx)
	s.FlushLogs()
}
