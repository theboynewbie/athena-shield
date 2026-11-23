package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/theboynewbie/athena-shield/internal/store"
)

const (
	MaxLoginAttempts     = 5
	MaxUserLoginAttempts = 10
	LockoutDuration      = 15 * time.Minute
	AttemptWindow        = 10 * time.Minute
	TokenTTL             = 8 * time.Hour
)

var dummyBcryptHash = []byte("$2b$12$e8YgK8s8V4p.Wd/jQ7LreO6KjQyqjMhD6LhHk1fM5aZk/kL2qZlG6")

type SessionClaims struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
	Exp  int64  `json:"exp"`
}

type Manager struct {
	secret []byte
	store  *store.Store

	mu             sync.Mutex
	failedIPs      map[string][]time.Time
	lockedIPs      map[string]time.Time
	failedUsers    map[string][]time.Time
	lockedUsers    map[string]time.Time
	usedCSRFSalts  map[string]time.Time
}

func NewManager(secret string, s *store.Store) *Manager {
	return &Manager{
		secret:        []byte(secret),
		store:         s,
		failedIPs:     make(map[string][]time.Time),
		lockedIPs:     make(map[string]time.Time),
		failedUsers:   make(map[string][]time.Time),
		lockedUsers:   make(map[string]time.Time),
		usedCSRFSalts: make(map[string]time.Time),
	}
}

func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

func VerifyPassword(plain, hashed string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain)) == nil
}

func VerifyDummyPassword(plain string) {
	_ = bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(plain))
}

func (m *Manager) CreateToken(username, role string) (string, error) {
	claims := SessionClaims{
		Sub:  username,
		Role: role,
		Exp:  time.Now().Add(TokenTTL).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(enc))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return enc + "." + sig, nil
}

func (m *Manager) ParseToken(token string) (*SessionClaims, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("invalid token format")
	}
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(parts[0]))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[1]), []byte(expectedSig)) {
		return nil, errors.New("invalid signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var claims SessionClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, err
	}
	if time.Now().Unix() > claims.Exp {
		return nil, errors.New("token expired")
	}
	return &claims, nil
}

func ExtractToken(r *http.Request) string {
	if ah := r.Header.Get("Authorization"); strings.HasPrefix(ah, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(ah, "Bearer "))
	}
	if c, err := r.Cookie("access_token"); err == nil && c.Value != "" {
		v := c.Value
		if strings.HasPrefix(v, "Bearer ") {
			return strings.TrimSpace(strings.TrimPrefix(v, "Bearer "))
		}
		return v
	}
	return ""
}

func (m *Manager) CurrentUser(r *http.Request) *store.User {
	tok := ExtractToken(r)
	if tok == "" {
		return nil
	}
	claims, err := m.ParseToken(tok)
	if err != nil || claims.Sub == "" {
		return nil
	}
	u, err := m.store.GetUserByUsername(claims.Sub)
	if err != nil {
		return nil
	}
	return u
}

func (m *Manager) GenerateCSRF(ip string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	salt := hex.EncodeToString(b)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	msg := fmt.Sprintf("%s:%s:%s", ip, ts, salt)
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(msg))
	sig := hex.EncodeToString(mac.Sum(nil))
	return msg + ":" + sig
}

func (m *Manager) VerifyCSRF(token, ip string) bool {
	if token == "" {
		return false
	}
	idx := strings.LastIndex(token, ":")
	if idx <= 0 {
		return false
	}
	msg := token[:idx]
	sig := token[idx+1:]

	idx2 := strings.LastIndex(msg, ":")
	if idx2 <= 0 {
		return false
	}
	salt := msg[idx2+1:]
	rest := msg[:idx2]

	idx3 := strings.LastIndex(rest, ":")
	if idx3 <= 0 {
		return false
	}
	tsStr := rest[idx3+1:]
	tokenIP := rest[:idx3]

	if !hmac.Equal([]byte(tokenIP), []byte(ip)) {
		return false
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}
	now := time.Now().Unix()
	if now-ts > 1800 || now < ts-60 {
		return false
	}

	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(msg))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return false
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.usedCSRFSalts) > 5000 {
		cutoff := time.Now().Add(-30 * time.Minute)
		for k, t := range m.usedCSRFSalts {
			if t.Before(cutoff) {
				delete(m.usedCSRFSalts, k)
			}
		}
	}
	if _, used := m.usedCSRFSalts[salt]; used {
		return false
	}
	m.usedCSRFSalts[salt] = time.Now()
	return true
}

func (m *Manager) IsIPLocked(ip string) (bool, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if exp, ok := m.lockedIPs[ip]; ok {
		if time.Now().Before(exp) {
			return true, int(time.Until(exp).Seconds())
		}
		delete(m.lockedIPs, ip)
	}
	return false, 0
}

func (m *Manager) LockIP(ip string) {
	m.mu.Lock()
	m.lockedIPs[ip] = time.Now().Add(LockoutDuration)
	m.mu.Unlock()
}

func (m *Manager) IsUserLocked(uname string) (bool, int) {
	key := strings.ToLower(uname)
	m.mu.Lock()
	defer m.mu.Unlock()
	if exp, ok := m.lockedUsers[key]; ok {
		if time.Now().Before(exp) {
			return true, int(time.Until(exp).Seconds())
		}
		delete(m.lockedUsers, key)
	}
	return false, 0
}

func (m *Manager) RecordFailedLogin(ip, uname string) (ipLocked bool, remaining int) {
	now := time.Now()
	cutoff := now.Add(-AttemptWindow)
	key := strings.ToLower(uname)

	m.mu.Lock()
	defer m.mu.Unlock()

	var keptIP []time.Time
	for _, t := range m.failedIPs[ip] {
		if t.After(cutoff) {
			keptIP = append(keptIP, t)
		}
	}
	keptIP = append(keptIP, now)
	m.failedIPs[ip] = keptIP

	if key != "" {
		var keptU []time.Time
		for _, t := range m.failedUsers[key] {
			if t.After(cutoff) {
				keptU = append(keptU, t)
			}
		}
		keptU = append(keptU, now)
		m.failedUsers[key] = keptU
		if len(keptU) >= MaxUserLoginAttempts {
			m.lockedUsers[key] = now.Add(LockoutDuration)
		}
	}

	if len(keptIP) >= MaxLoginAttempts {
		m.lockedIPs[ip] = now.Add(LockoutDuration)
		return true, 0
	}
	return false, MaxLoginAttempts - len(keptIP)
}

func (m *Manager) ClearLoginFailures(ip, uname string) {
	key := strings.ToLower(uname)
	m.mu.Lock()
	delete(m.failedIPs, ip)
	delete(m.lockedIPs, ip)
	delete(m.failedUsers, key)
	delete(m.lockedUsers, key)
	m.mu.Unlock()
}
