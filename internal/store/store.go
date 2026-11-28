package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type Store struct {
	db      *sql.DB
	dbPath  string
	encKey  []byte
	version atomic.Int64

	logCh   chan Log
	stopCh  chan struct{}
	wg      sync.WaitGroup
	onEvent func() // optional callback when rules/hosts change
}

func Open(dataDir, adminUser, adminEmail, adminPass string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	dbPath := filepath.Join(dataDir, "athena_shield.db")
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(15000)&_pragma=cache_size(-32000)&_pragma=temp_store(MEMORY)&_pragma=foreign_keys(ON)&_txlock=immediate", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)

	s := &Store{
		db:     db,
		dbPath: dbPath,
		logCh:  make(chan Log, 10000),
		stopCh: make(chan struct{}),
	}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	s.SetEncryptionSecret(s.GetOrCreateSecret(os.Getenv("SECRET_KEY")))
	if err := s.seed(adminUser, adminEmail, adminPass); err != nil {
		_ = db.Close()
		return nil, err
	}
	s.version.Store(1)
	s.startWorkers()
	return s, nil
}

func (s *Store) SetOnChange(fn func()) {
	s.onEvent = fn
}

func (s *Store) BumpVersion() {
	s.version.Add(1)
	if s.onEvent != nil {
		s.onEvent()
	}
}

func (s *Store) Version() int64 {
	return s.version.Load()
}

func (s *Store) DBPath() string {
	return s.dbPath
}

func (s *Store) DBSizeMB() float64 {
	info, err := os.Stat(s.dbPath)
	if err != nil {
		return 0
	}
	return float64(int(float64(info.Size())/(1024*1024)*100)) / 100
}

func (s *Store) Close() {
	close(s.stopCh)
	s.wg.Wait()
	_ = s.db.Close()
}

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			hashed_password TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'admin',
			totp_secret TEXT DEFAULT '',
			totp_enabled INTEGER NOT NULL DEFAULT 0,
			token_version INTEGER NOT NULL DEFAULT 1,
			is_active INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			pattern TEXT NOT NULL,
			category TEXT NOT NULL DEFAULT 'judi_slot',
			action TEXT NOT NULL DEFAULT 'BLOCK',
			severity TEXT NOT NULL DEFAULT 'CRITICAL',
			score INTEGER NOT NULL DEFAULT 5,
			paranoia_level INTEGER NOT NULL DEFAULT 1,
			is_active INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS ip_lists (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip_address TEXT UNIQUE NOT NULL,
			list_type TEXT NOT NULL,
			reason TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS waf_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			client_ip TEXT NOT NULL,
			country TEXT DEFAULT '',
			country_code TEXT DEFAULT '',
			host TEXT DEFAULT '',
			method TEXT NOT NULL,
			uri TEXT NOT NULL,
			status_code INTEGER NOT NULL,
			is_blocked INTEGER NOT NULL DEFAULT 0,
			reason TEXT DEFAULT '',
			user_agent TEXT DEFAULT ''
		);`,
		`CREATE INDEX IF NOT EXISTS idx_waf_logs_ts ON waf_logs(timestamp);`,
		`CREATE INDEX IF NOT EXISTS idx_waf_logs_ip ON waf_logs(client_ip);`,
		`CREATE INDEX IF NOT EXISTS idx_waf_logs_host ON waf_logs(host);`,
		`CREATE INDEX IF NOT EXISTS idx_waf_logs_blocked ON waf_logs(is_blocked);`,
		`CREATE TABLE IF NOT EXISTS proxy_hosts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			domain_name TEXT UNIQUE NOT NULL,
			target_upstream TEXT NOT NULL DEFAULT '',
			host_type TEXT NOT NULL DEFAULT 'proxy',
			redirect_url TEXT DEFAULT '',
			redirect_status_code INTEGER NOT NULL DEFAULT 301,
			preserve_path INTEGER NOT NULL DEFAULT 1,
			ssl_type TEXT NOT NULL DEFAULT 'none',
			ssl_cert TEXT DEFAULT '',
			ssl_key TEXT DEFAULT '',
			force_https INTEGER NOT NULL DEFAULT 1,
			waf_enabled INTEGER NOT NULL DEFAULT 1,
			waf_mode TEXT NOT NULL DEFAULT 'active',
			rate_limit_enabled INTEGER NOT NULL DEFAULT 1,
			app_profile TEXT NOT NULL DEFAULT 'universal',
			block_bad_bots INTEGER NOT NULL DEFAULT 1,
			edge_cache_enabled INTEGER NOT NULL DEFAULT 0,
			is_active INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS auto_bans (
			ip_address TEXT PRIMARY KEY,
			expires_at REAL NOT NULL,
			reason TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE INDEX IF NOT EXISTS idx_auto_bans_exp ON auto_bans(expires_at);`,
		`CREATE TABLE IF NOT EXISTS system_settings (
			key TEXT PRIMARY KEY,
			value TEXT DEFAULT '',
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			actor TEXT NOT NULL,
			role TEXT DEFAULT '',
			action TEXT NOT NULL,
			target TEXT DEFAULT '',
			details TEXT DEFAULT '',
			client_ip TEXT DEFAULT ''
		);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_ts ON audit_logs(timestamp);`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	// Additive migrations for existing databases
	alterStmts := []string{
		`ALTER TABLE rules ADD COLUMN severity TEXT NOT NULL DEFAULT 'CRITICAL'`,
		`ALTER TABLE rules ADD COLUMN score INTEGER NOT NULL DEFAULT 5`,
		`ALTER TABLE rules ADD COLUMN paranoia_level INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT ''`,
		`ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1`,
	}
	for _, q := range alterStmts {
		_, _ = s.db.Exec(q)
	}
	return nil
}

func (s *Store) seed(adminUser, adminEmail, adminPass string) error {
	adminUser = strings.TrimSpace(adminUser)
	adminEmail = strings.TrimSpace(adminEmail)
	if adminUser != "" && strings.TrimSpace(adminPass) != "" {
		var userCount int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&userCount); err != nil {
			return err
		}
		if userCount == 0 {
			if adminEmail == "" {
				adminEmail = adminUser + "@athena-shield.local"
			}
			hash, err := bcrypt.GenerateFromPassword([]byte(adminPass), bcrypt.DefaultCost)
			if err != nil {
				return err
			}
			_, err = s.db.Exec(
				`INSERT INTO users (username, email, hashed_password, role, is_active, created_at) VALUES (?, ?, ?, 'super_admin', 1, ?)`,
				adminUser, adminEmail, string(hash), time.Now().UTC(),
			)
			if err != nil {
				return err
			}
		}
	}

	var ruleCount int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM rules`).Scan(&ruleCount); err != nil {
		return err
	}
	if ruleCount == 0 {
		defaultRules := []struct {
			name, desc, cat, pat, sev string
			score, pl                 int
		}{
			{
				name: "Judi & Slot Gacor Spam Keywords",
				desc: "Blokir kata kunci promosi judi online, slot gacor, togel, toto 4d, rtp live, maxwin, dan agen kasino",
				cat:  "judi_slot",
				pat:  `(slot[\s_-]*(?:gacor|online|resmi|thailand|kamboja|vietnam|jepang|dana|qris|pulsa|maxwin|terpercaya|hari[\s_-]*ini|malam[\s_-]*ini|anti[\s_-]*rungkad)|situs[\s_-]*(?:slot|judi|toto|togel|gacor)|judi[\s_-]*(?:online|bola|slot|togel|dadu|poker)|togel[\s_-]*(?:online|resmi|4d|hari[\s_-]*ini|singapore|hongkong|sydney)|bandar[\s_-]*(?:togel|toto|slot|judi|bola)|toto[\s_-]*(?:4d|slot|online|macau|gelap)|rtp[\s_-]*(?:slot|live|gacor|tinggi|hari[\s_-]*ini)|akun[\s_-]*(?:pro|vip|wso|gacor)|server[\s_-]*(?:thailand|kamboja|luar|vietnam|sensational)|maxwin|slot88|sbobet|pragmatic[\s_-]*play|pg[\s_-]*soft|habanero[\s_-]*slot|joker123|idn[\s_-]*poker|pkv[\s_-]*games|zeus[\s_-]*slot|gates[\s_-]*of[\s_-]*olympus|olympus[\s_-]*slot|starlight[\s_-]*princess|mahjong[\s_-]*ways|spaceman[\s_-]*slot|sweet[\s_-]*bonanza|kakek[\s_-]*zeus|scatter[\s_-]*hitam|link[\s_-]*(?:slot|gacor|alternatif[\s_-]*slot)|depo[\s_-]*(?:pulsa|dana|qris|5k|10k|20k|25k|murah)|bocoran[\s_-]*(?:slot|rtp|admin)|poker[\s_-]*online|kasino[\s_-]*online|live[\s_-]*casino|agen[\s_-]*(?:slot|togel|judi|bola)|jackpot[\s_-]*besar|gampang[\s_-]*(?:menang|maxwin|jp)|pola[\s_-]*(?:slot|gacor|maxwin)|free[\s_-]*spin[\s_-]*slot|bonus[\s_-]*new[\s_-]*member|garansi[\s_-]*kekalahan|menang[\s_-]*berapapun[\s_-]*dibayar|taruhan[\s_-]*bola|wd[\s_-]*cepat|mpo[\s_-]*slot|\bjudol\b)`,
				sev:  "CRITICAL", score: 5, pl: 1,
			},
			{
				name: "SQL Injection Advanced Deep Shield",
				desc: "Deteksi percobaan SQLi UNION SELECT, boolean blind, benchmark, sleep, stacked queries",
				cat:  "sqli",
				pat:  `(\b(union(\s+all)?\s+select|select\s+(?:\*|[a-z0-9_,\s]+)\s+from\s+[a-z0-9_]+|insert\s+into\s+[a-z0-9_]+|delete\s+from\s+[a-z0-9_]+|drop\s+(table|database)\s+[a-z0-9_]+|exec(\s*\(|\s+xp_)|update\s+[a-z0-9_]+\s+set\s+[a-z0-9_]+\s*=|benchmark\s*\(|sleep\s*\(\s*\d+|waitfor\s+delay|information_schema|load_file\s*\(|into\s+(out|dump)file)\b|('|%27)\s*(or|and|\|\||&&)\s*('?[0-9a-zA-Z_]+'?\s*=\s*'?[0-9a-zA-Z_]+'|1\s*=\s*1|true)\b|('|%27)\s*(--|#|/\*)|/\*!\d+)`,
				sev:  "CRITICAL", score: 5, pl: 1,
			},
			{
				name: "Cross-Site Scripting (XSS) Patterns",
				desc: "Deteksi script injection, javascript:, event handlers, SVG payload, DOM XSS",
				cat:  "xss",
				pat:  `(<\s*script[^>]*>.*<\s*/\s*script\s*>|<\s*script[^>]*>|javascript\s*:|onload\s*=|onerror\s*=|onclick\s*=|onmouseover\s*=|eval\s*\(\s*(?:atob|unescape|String\.fromCharCode|['"])|\balert\s*\(\s*(?:1\s*\)|document|['"]xss)|document\.cookie|<img[^>]+src=[^>]*onerror=|<svg[^>]+onload=|<iframe[^>]+src=|<body[^>]+onload=)`,
				sev:  "CRITICAL", score: 5, pl: 1,
			},
			{
				name: "Path Traversal & WordPress Sensitive Files",
				desc: "Deteksi directory traversal seperti ../../etc/passwd, file .env, .git, sysconfig, wp-config.php, php://input",
				cat:  "path_traversal",
				pat:  `(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c|etc/passwd|etc/shadow|boot\.ini|win\.ini|wp-config\.php\b|sysconfig\.(?:local\.)?inc\.php\b|/\.env\b|/\.git/|php://(input|filter)|phar://)`,
				sev:  "CRITICAL", score: 5, pl: 1,
			},
			{
				name: "Malicious Scanner & Bot User-Agents",
				desc: "Deteksi scanner otomatis seperti Nikto, SQLmap, Acunetix, Masscan, DirBuster, WPScan",
				cat:  "bot_attack",
				pat:  `(sqlmap|nikto|acunetix|havij|nessus|masscan|dirbuster|nmap|zgrab|gobuster|wpscan|censys|shodan)`,
				sev:  "CRITICAL", score: 5, pl: 1,
			},
			{
				name: "WordPress Webshell & Arbitrary File Upload",
				desc: "Deteksi upload backdoor PHP/Webshell seperti c99, r57, WSO, eval(base64_decode), passthru, system",
				cat:  "custom",
				pat:  `(c99shell|r57shell|wso_version|eval\s*\(\s*(base64_decode|gzinflate|str_rot13)|passthru\s*\(|shell_exec\s*\(|system\s*\(\s*\$_)`,
				sev:  "CRITICAL", score: 5, pl: 1,
			},
			{
				name: "Aggressive AI & SEO Bot Crawlers (Anti-Scraping & Load Shield)",
				desc: "Blokir bot crawler agresif pemicu beban tinggi (ClaudeBot, SemrushBot, AhrefsBot, GPTBot, Bytespider, MJ12bot) sambil mengizinkan Googlebot/Bingbot",
				cat:  "bot_attack",
				pat:  `(claudebot|claude-web|anthropic-ai|semrushbot|ahrefsbot|mj12bot|dotbot|blexbot|dataforseobot|bytespider|gptbot|ccbot|petalbot|barkrowler|seekportbot|meta-externalagent|diffbot|omgili|imagesiftbot)`,
				sev:  "CRITICAL", score: 5, pl: 1,
			},
			{
				name: "Universal RCE, Log4Shell & Framework Exploit Shield",
				desc: "Virtual patching lintas aplikasi (SLiMS, OJS, Laravel, Node, PHP): Log4Shell JNDI, Laravel Ignition RCE, PHPUnit RCE, SSRF Metadata, XXE, NoSQLi & backdoor shell",
				cat:  "custom",
				pat:  `(\$\{jndi:(?:ldap|ldaps|rmi|dns|nis|iiop|corba|nds)://|/_ignition/execute-solution|/vendor/phpunit/|allow_url_include\s*=|auto_prepend_file\s*=|b374k|indoxploit|alfa_shell|169\.254\.169\.254|metadata\.google\.internal|(?:gopher|dict|file)://|<!ENTITY\s+\w+\s+SYSTEM\b|\$(?:where|ne|gt|lt|regex)\b\s*:)`,
				sev:  "CRITICAL", score: 5, pl: 1,
			},
			{
				name: "SQLi Strict Heuristic (PL2)",
				desc: "Heuristik SQL injection ketat (HAVING, GROUP BY, ORDER BY, CHAR/HEX, boolean numerik) untuk Paranoia Level 2+",
				cat:  "sqli",
				pat:  `(?:\b(?:having|group\s+by|order\s+by|concat_ws|group_concat|char\s*\(|hex\s*\()\b|\b(?:and|or)\s+\d+\s*=\s*\d+\b)`,
				sev:  "WARNING", score: 3, pl: 2,
			},
			{
				name: "XSS Strict Event & Protocol Heuristic (PL2)",
				desc: "Heuristik XSS ketat (event handler HTML, data:text/html, vbscript, object/embed/base) untuk Paranoia Level 2+",
				cat:  "xss",
				pat:  `(\bon[a-z]{3,15}\s*=|data\s*:\s*text/html|vbscript\s*:|<\s*(?:object|embed|applet|meta|link|base)\b)`,
				sev:  "WARNING", score: 3, pl: 2,
			},
			{
				name: "Command Injection & Shell Metacharacters (PL3)",
				desc: "Deteksi command injection shell metacharacters (;, ||, &&, backtick, subshell) dengan utilitas OS untuk Paranoia Level 3+",
				cat:  "custom",
				pat:  `(?:;|\|\||&&|\x60|\$\()\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python|perl|php)\b`,
				sev:  "NOTICE", score: 2, pl: 3,
			},
			{
				name: "GraphQL Introspection & Abuse Guard (PL3)",
				desc: "Deteksi GraphQL schema introspection & abuse probing (__schema, __type, IntrospectionQuery) untuk Paranoia Level 3+",
				cat:  "custom",
				pat:  `(__schema|__type\s*\(|introspectionquery)`,
				sev:  "WARNING", score: 3, pl: 3,
			},
			{
				name: "CLI HTTP Clients & Scripting Agents (PL3)",
				desc: "Deteksi scripting HTTP client (curl, python-requests, libwww-perl, Go-http-client) untuk Paranoia Level 3+",
				cat:  "bot_attack",
				pat:  `(python-requests/|curl/|libwww-perl|go-http-client/)`,
				sev:  "WARNING", score: 3, pl: 3,
			},
		}
		for _, r := range defaultRules {
			_, err := s.db.Exec(
				`INSERT INTO rules (name, description, pattern, category, action, severity, score, paranoia_level, is_active, created_at) VALUES (?, ?, ?, ?, 'BLOCK', ?, ?, ?, 1, ?)`,
				r.name, r.desc, r.pat, r.cat, r.sev, r.score, r.pl, time.Now().UTC(),
			)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) SetEncryptionSecret(secret string) {
	s.encKey = deriveEncKey(secret)
}

func (s *Store) GetOrCreateSecret(envSecret string) string {
	if len(strings.TrimSpace(envSecret)) >= 32 {
		sec := strings.TrimSpace(envSecret)
		s.encKey = deriveEncKey(sec)
		return sec
	}
	var val string
	err := s.db.QueryRow(`SELECT value FROM system_settings WHERE key = 'internal_session_secret'`).Scan(&val)
	if err == nil && len(val) >= 64 {
		s.encKey = deriveEncKey(val)
		return val
	}
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	gen := hex.EncodeToString(buf)
	_, _ = s.db.Exec(`INSERT OR REPLACE INTO system_settings (key, value, updated_at) VALUES ('internal_session_secret', ?, ?)`, gen, time.Now().UTC())
	s.encKey = deriveEncKey(gen)
	return gen
}

func (s *Store) startWorkers() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		batch := make([]Log, 0, 150)
		flush := func() {
			if len(batch) == 0 {
				return
			}
			tx, err := s.db.Begin()
			if err == nil {
				stmt, prepErr := tx.Prepare(`INSERT INTO waf_logs (timestamp, client_ip, country, country_code, host, method, uri, status_code, is_blocked, reason, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
				if prepErr == nil {
					for _, l := range batch {
						_, _ = stmt.Exec(l.Timestamp.UTC(), l.ClientIP, l.Country, l.CountryCode, l.Host, l.Method, l.URI, l.StatusCode, boolToInt(l.IsBlocked), l.Reason, l.UserAgent)
					}
					_ = stmt.Close()
				}
				_ = tx.Commit()
			}
			batch = batch[:0]
		}

		ticker := time.NewTicker(400 * time.Millisecond)
		pruneTicker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		defer pruneTicker.Stop()

		for {
			select {
			case l := <-s.logCh:
				batch = append(batch, l)
				if len(batch) >= 150 {
					flush()
				}
			case <-ticker.C:
				flush()
			case <-pruneTicker.C:
				_, _ = s.PruneExpiredLogs()
			case <-s.stopCh:
				for {
					select {
					case l := <-s.logCh:
						batch = append(batch, l)
					default:
						flush()
						return
					}
				}
			}
		}
	}()
}

func (s *Store) QueueLog(l Log) {
	if l.Timestamp.IsZero() {
		l.Timestamp = time.Now().UTC()
	}
	if len(l.UserAgent) > 500 {
		l.UserAgent = l.UserAgent[:500]
	}
	select {
	case s.logCh <- l:
	default:
	}
}

func (s *Store) FlushLogs() {
	// Wait briefly for ticker to drain
	time.Sleep(450 * time.Millisecond)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
