<p align="center">
  <img src="web/static/athena-nav-logo.png" alt="Athena Shield Logo" width="140">
</p>

<h1 align="center">Athena Shield v1.0</h1>

<p align="center">
  <strong>Enterprise Web Application Firewall (WAF), Reverse Proxy HTTP/HTTPS/HTTP2, Load Balancer &amp; Edge Cache</strong><br>
  Ditulis sepenuhnya dalam <strong>Pure Go</strong> (1 binary statis, 1 container Docker non-root) untuk proteksi aplikasi web skala enterprise dengan latensi ultra-rendah.
</p>

---

## Fitur Utama

- **1 Container Tunggal & Hardened Runtime:** Menggabungkan Reverse Proxy, SSL/TLS Termination (Let's Encrypt ACME otomatis + Wildcard/Custom SSL `.crt`/`.key`), WAF Engine, Turbo Edge Cache, dan Web Dashboard UI dalam 1 binary Go yang berjalan sebagai user non-root (`athena`), `read_only` rootfs, dan `cap_drop: ALL`.
- **Enterprise WAF Engine:**
  - **Anomaly Scoring & Paranoia Level (PL1–PL4):** Akumulasi skor anomali ala OWASP CRS dengan mode **Shadow / Dry-Run (`MONITOR`)** per rule untuk meminimalkan *false positive* (`curl/` dan `python-requests/` aman di PL1, ketat di PL3).
  - **Deep Body Parser:** Memeriksa payload **JSON** (termasuk decode `\uXXXX`), **GraphQL**, **XML**, **Form**, dan **Multipart** dengan proteksi terhadap *nesting bomb* DoS.
  - **Response DLP (Plain & Gzip) & Defacement Shield:** Mendekompresi respons `gzip` secara aman untuk mencegah kebocoran *SQL error*, *stack trace*, *private key / AWS key*, nomor kartu pembayaran tervalidasi **Luhn**, serta injeksi judi slot pada respons HTML upstream.
  - **Proteksi Lokal & OWASP:** Anti-Judi Slot Indonesia (normalisasi berlapis homoglyph, zero-width, leetspeak), SQLi, XSS, Path Traversal/LFI, Webshell, Log4Shell, Laravel/PHPUnit RCE, SSRF, XXE, dan HTTP Request Smuggling.
  - **App Profiles:** `Universal`, `WordPress`, `SLiMS / OJS`, `Laravel / API`.
- **Anti-Bot, Challenge & DDoS L7:**
  - **JS Proof-of-Work Challenge:** Tantangan HMAC-SHA256 (*I'm Under Attack Mode*) dengan cookie clearance terikat IP & User-Agent.
  - **Bot Fingerprinting & Offline GeoIP Block:** Deteksi *Headless Browser* (`Puppeteer`, `Playwright`, `Selenium`) dan spoofing protokol, blokir crawler agresif (tetap mengizinkan Googlebot/Bingbot), serta pemblokiran negara (ISO-2) berbasis `CF-IPCountry` atau **database CSV/CIDR lokal offline** (tanpa mengirim IP pengunjung ke pihak ketiga).
  - **Adaptive Rate Limiting & IPv6 `/64`:** Kuota per-endpoint `/api/*`, agregasi subnet IPv6 `/64`, proteksi *brute-force* login & 2FA, dan Auto-Ban 24 jam.
- **High Availability Proxy, Caching & Streaming:**
  - **Multi-Upstream Load Balancing:** Round-robin & *auto-failover* antar banyak server backend dengan *active health check* setiap 15 detik dan passive failover khusus `502`/`503`/`504`.
  - **Zero-Buffer Streaming:** Dukungan penuh untuk **WebSocket**, **SSE**, dan **gRPC**.
  - **Bounded LRU Edge Cache:** Micro-cache HTML & aset statis di memori dengan batas total byte (`EDGE_CACHE_MAX_MB`, default `128 MB`) dan *Smart Bypass* otomatis untuk user login & halaman admin.
- **Governance, Enkripsi & Observability (CSIRT):**
  - **Keamanan Operator & Enkripsi at-Rest:** **One-Time Setup Token** saat instalasi awal, **2FA TOTP (RFC 6238)** anti-replay & lockout, **RBAC** (`super_admin`, `admin`, `auditor` read-only), **Session Revocation** (`token_version`), **CSRF Origin Check**, **Admin Audit Log** lengkap, dan enkripsi **AES-256-GCM** untuk `ssl_key`, `totp_secret`, dan `telegram_bot_token` di SQLite.
  - **Monitoring & SIEM:** Endpoint Prometheus `/metrics` (dilindungi Bearer token / loopback), **Incident ID (`ATH-...`) & `X-Request-ID`** di setiap blokir, ekspor log **SIEM (JSONL & ArcSight CEF)**, Telegram Real-Time Alert, serta **1-Click Transactional JSON Backup/Restore**.

---

## Deploy di Docker / Portainer

1. Buka **Portainer** &rarr; **Stacks** &rarr; **Add stack**.
2. Beri nama stack (misalnya `athena-shield`).
3. Pilih **Repository** (arahkan ke `https://github.com/theboynewbie/athena-shield.git`, branch `main`) **atau** paste isi `docker-compose.yml` ke Web Editor.
4. Atur environment variable sesuai kebutuhan (wajib ganti `ACME_EMAIL` dengan email aktif jika memakai Let's Encrypt). Biarkan `SECRET_KEY` kosong agar kunci sesi & enkripsi 256-bit di-generate acak otomatis per server.
5. Klik **Deploy the stack**.
6. Ambil **One-Time Setup Token** dari log container:
   ```bash
   docker logs athena-shield
   ```
7. Buka `http://<IP-SERVER>:1081`, masukkan **Setup Token**, lalu buat akun **Super Admin** pertama Anda di **Initial Setup Wizard (`/setup`)**. Setelah selesai, `/setup` otomatis terkunci permanen. Aktifkan juga **2FA Authenticator** di menu **Settings & Backup**.

### Migrasi dari Guardian WAF
Masuk ke menu **Settings & Backup** di Athena Shield lalu upload file `.json` hasil export dari Guardian WAF. Seluruh Proxy Host, SSL Custom, Rules, IP Whitelist/Blacklist, dan pengaturan akan dipulihkan secara atomik dalam satu transaksi database.

---

## Environment Variables

| Variabel | Default | Keterangan |
|---|---|---|
| `ACME_EMAIL` | `admin@example.com` | **Ganti dengan email valid** sebelum mengaktifkan SSL Let's Encrypt |
| `SECRET_KEY` | *(auto-generate)* | Kunci HMAC sesi & enkripsi AES-256-GCM SQLite (min. 32 karakter) |
| `SETUP_TOKEN` | *(auto-generate)* | Opsional: tetapkan manual One-Time Setup Token saat deploy otomatis |
| `TRUSTED_PROXIES` | `""` | Daftar IP/CIDR reverse proxy tepercaya (koma-separated) untuk `X-Real-IP` / `X-Forwarded-For` |
| `TRUSTED_RANGES` | `""` | Daftar IP/CIDR internal/mitra dengan ambang rate-limit lebih longgar |
| `GEOIP_DB_PATH` | `""` | Path file CSV GeoIP offline (format `cidr,CC,Country` atau IP2Location LITE IPv4 CSV) |
| `DASHBOARD_BIND_ADDR` | `""` | Bind IP khusus jaringan manajemen (mis. `127.0.0.1` atau IP VPN/Tailscale) |
| `DASHBOARD_TLS_CERT` | `""` | Path sertifikat `.crt`/`.pem` untuk mengaktifkan HTTPS di port Dashboard `1081` |
| `DASHBOARD_TLS_KEY` | `""` | Path private key `.key` untuk HTTPS Dashboard |
| `METRICS_TOKEN` | `""` | Bearer token untuk `GET /metrics` (`Authorization: Bearer <token>`) |
| `EDGE_CACHE_MAX_MB` | `128` | Batas maksimum RAM untuk LRU Edge Cache (dalam MB) |
| `UPSTREAM_TIMEOUT_SECONDS` | `120` | Batas waktu respons dari backend upstream (detik) |
| `UPSTREAM_INSECURE_TLS` | `false` | Set `true` hanya jika backend memakai sertifikat self-signed internal |

---

## Checklist Go-Live Produksi

- [ ] Ganti `ACME_EMAIL` dengan email aktif dan pastikan DNS domain mengarah ke server Athena Shield.
- [ ] Batasi akses port Dashboard `1081` ke jaringan manajemen/VPN (`DASHBOARD_BIND_ADDR` atau firewall) dan aktifkan `DASHBOARD_TLS_CERT`/`DASHBOARD_TLS_KEY`.
- [ ] Isi `TRUSTED_PROXIES` **hanya** jika Athena Shield berada di belakang load balancer / proxy lain.
- [ ] Set `METRICS_TOKEN` yang kuat sebelum membuka endpoint `/metrics` ke Prometheus eksternal.
- [ ] Selesaikan `/setup` menggunakan token dari `docker logs athena-shield` dan aktifkan **2FA TOTP** pada akun Super Admin.

---

## Menjalankan Secara Lokal (Windows)
```powershell
powershell -ExecutionPolicy Bypass -File .\start_local.ps1
```
Lalu buka `http://127.0.0.1:1082/login`.

## Catatan Teknis
- Engine regex Go menggunakan **RE2** (bebas ReDoS). Aturan custom dengan fitur PCRE lookaround/backreference akan dilewati secara aman tanpa membuat server crash.
