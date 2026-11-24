package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/theboynewbie/athena-shield/internal/store"
)

type TLSManager struct {
	autocertMgr *autocert.Manager
	fallback    tls.Certificate

	mu          sync.RWMutex
	customCerts map[string]tls.Certificate
	leDomains   map[string]bool
	diskLECerts map[string]tls.Certificate
}

func NewTLSManager(dataDir, acmeEmail string) *TLSManager {
	certsDir := filepath.Join(dataDir, "certs")
	_ = os.MkdirAll(certsDir, 0o755)

	tm := &TLSManager{
		customCerts: make(map[string]tls.Certificate),
		leDomains:   make(map[string]bool),
		diskLECerts: make(map[string]tls.Certificate),
		fallback:    loadOrGenFallbackCert(certsDir),
	}

	tm.autocertMgr = &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(filepath.Join(certsDir, "autocert")),
		Email:  acmeEmail,
		HostPolicy: func(ctx context.Context, host string) error {
			clean := strings.ToLower(strings.SplitN(host, ":", 2)[0])
			tm.mu.RLock()
			ok := tm.leDomains[clean] || tm.leDomains[wildcardParent(clean)]
			tm.mu.RUnlock()
			if !ok {
				return os.ErrPermission
			}
			return nil
		},
	}
	return tm
}

func wildcardParent(domain string) string {
	if idx := strings.IndexByte(domain, '.'); idx > 0 && idx < len(domain)-1 {
		return "*." + domain[idx+1:]
	}
	return ""
}

func (tm *TLSManager) ReloadHosts(hosts []store.ProxyHost) {
	custom := make(map[string]tls.Certificate)
	le := make(map[string]bool)
	diskLE := make(map[string]tls.Certificate)

	for _, h := range hosts {
		dom := strings.ToLower(strings.TrimSpace(h.DomainName))
		if dom == "" {
			continue
		}
		switch h.SSLType {
		case "custom":
			if h.SSLCert != "" && h.SSLKey != "" {
				if cert, err := tls.X509KeyPair([]byte(h.SSLCert), []byte(h.SSLKey)); err == nil {
					custom[dom] = cert
					// Also index by certificate SAN DNSNames (incl. *.domain.com wildcard certs)
					if len(cert.Certificate) > 0 {
						if x509Cert, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
							for _, san := range x509Cert.DNSNames {
								sanLower := strings.ToLower(strings.TrimSpace(san))
								if sanLower != "" {
									if _, exists := custom[sanLower]; !exists {
										custom[sanLower] = cert
									}
								}
							}
						}
					}
				}
			}
		case "letsencrypt":
			le[dom] = true
			// Support legacy Certbot /etc/letsencrypt volume if mounted
			cleanDom := strings.TrimPrefix(dom, "*.")
			certPath := filepath.Join("/etc/letsencrypt/live", cleanDom, "fullchain.pem")
			keyPath := filepath.Join("/etc/letsencrypt/live", cleanDom, "privkey.pem")
			if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
				diskLE[dom] = cert
			}
		}
	}
	tm.mu.Lock()
	tm.customCerts = custom
	tm.leDomains = le
	tm.diskLECerts = diskLE
	tm.mu.Unlock()
}

func (tm *TLSManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	serverName := strings.ToLower(strings.TrimSpace(hello.ServerName))
	wc := wildcardParent(serverName)

	tm.mu.RLock()
	if cert, ok := tm.customCerts[serverName]; ok {
		tm.mu.RUnlock()
		return &cert, nil
	}
	if wc != "" {
		if cert, ok := tm.customCerts[wc]; ok {
			tm.mu.RUnlock()
			return &cert, nil
		}
	}
	if cert, ok := tm.diskLECerts[serverName]; ok {
		tm.mu.RUnlock()
		return &cert, nil
	}
	if wc != "" {
		if cert, ok := tm.diskLECerts[wc]; ok {
			tm.mu.RUnlock()
			return &cert, nil
		}
	}
	isLE := tm.leDomains[serverName] || (wc != "" && tm.leDomains[wc])
	tm.mu.RUnlock()

	if isLE && tm.autocertMgr != nil {
		cert, err := tm.autocertMgr.GetCertificate(hello)
		if err == nil && cert != nil {
			return cert, nil
		}
		if err != nil {
			log.Printf("[ATHENA TLS] Let's Encrypt ACME notice for %s: %v (serving fallback SSL)", serverName, err)
		}
	}
	return &tm.fallback, nil
}

func (tm *TLSManager) HTTPChallengeHandler(fallback http.Handler) http.Handler {
	if tm.autocertMgr == nil {
		return fallback
	}
	return tm.autocertMgr.HTTPHandler(fallback)
}

func loadOrGenFallbackCert(dir string) tls.Certificate {
	certFile := filepath.Join(dir, "default.crt")
	keyFile := filepath.Join(dir, "default.key")
	if cert, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
		return cert
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "athena-shield"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost", "athena-shield"},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	_ = os.WriteFile(certFile, certPEM, 0o600)
	_ = os.WriteFile(keyFile, keyPEM, 0o600)
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)
	return cert
}
