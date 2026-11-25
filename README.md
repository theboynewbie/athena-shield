<p align="center">
  <img src="web/static/athena-nav-logo.png" alt="Athena Shield Logo" width="140">
</p>

<h1 align="center">Athena Shield v1.0</h1>

<p align="center">
  <strong>Enterprise Web Application Firewall (WAF), Reverse Proxy HTTP/HTTPS/HTTP2, Load Balancer &amp; Edge Cache</strong><br>
  Ditulis ulang sepenuhnya dalam <strong>Pure Go</strong> (1 binary statis, 1 container Docker) sebagai penerus performa tinggi dari Guardian WAF.
</p>

---

## Fitur Utama

- **1 Container Tunggal:** Menggabungkan Reverse Proxy, SSL/TLS Termination (Let's Encrypt ACME otomatis + Wildcard/Custom SSL `.crt`/`.key`), WAF Engine, Turbo Edge Cache, dan Web Dashboard UI dalam 1 binary Go.
- **Enterprise WAF Engine:**
  - **Anomaly Scoring & Paranoia Level (PL1–PL4):** Akumulasi skor anomali ala OWASP CRS dengan mode **Shadow / Dry-Run (`MONITOR`)** per rule untuk meminimalkan *false positive*.
  - **Deep Body Parser:** Memeriksa payload **JSON** (termasuk decode `\uXXXX`), **GraphQL**, **XML**, **Form**, dan **Multipart** dengan batas proteksi terhadap *nesting bomb* DoS.
  - **Response DLP & Defacement Shield:** Mencegah kebocoran *SQL error*, *stack trace*, *private key / AWS key*, nomor kartu pembayaran tervalidasi **Luhn**, serta injeksi judi slot pada respons HTML upstream.
  - **Proteksi Lokal & OWASP:** Anti-Judi Slot Indonesia (normalisasi berlapis homoglyph, zero-width, leetspeak), SQLi, XSS, Path Traversal/LFI, Webshell, Log4Shell, Laravel/PHPUnit RCE, SSRF, XXE, dan HTTP Request Smuggling.
  - **App Profiles:** `Universal`, `WordPress`, `SLiMS / OJS`, `Laravel / API`.
- **Anti-Bot, Challenge & DDoS L7:**
  - **JS Proof-of-Work Challenge:** Tantangan HMAC-SHA256 (*I'm Under Attack Mode*) dengan cookie clearance terikat IP & User-Agent.
  - **Bot Fingerprinting & GeoIP Block:** Deteksi *Headless Browser* (`Puppeteer`, `Playwright`, `Selenium`) dan spoofing protokol, blokir crawler agresif (tetap mengizinkan Googlebot/Bingbot), serta pemblokiran negara (ISO-2).
  - **Adaptive Rate Limiting:** Kuota per-endpoint `/api/*`, proteksi *brute-force* login, dan Auto-Ban 24 jam.
- **High Availability Proxy & Streaming:**
  - **Multi-Upstream Load Balancing:** Round-robin & *auto-failover* antar banyak server backend dengan *active health check* setiap 15 detik (`/healthz`).
  - **Zero-Buffer Streaming:** Dukungan penuh untuk **WebSocket**, **SSE**, dan **gRPC**.
  - **Turbo Edge Page Cache (60s):** Micro-cache HTML & aset statis di memori dengan *Smart Bypass* otomatis untuk user login & halaman admin.
- **Governance, Observability & CSIRT:**
  - **Keamanan Operator:** **2FA TOTP (RFC 6238)**, **RBAC** (`super_admin`, `admin`, `auditor` read-only), serta **Admin Audit Log**.
  - **Monitoring & SIEM:** Endpoint Prometheus `/metrics`, ekspor log **SIEM (JSONL & ArcSight CEF)**, deteksi otomatis kecepatan Ethernet fisik/VM (`1Gbps`, `10Gbps`, `VirtIO NIC`), Telegram Real-Time Alert, dan **1-Click JSON Backup/Restore**.

---

## Deploy di Docker / Portainer

1. Buka **Portainer** &rarr; **Stacks** &rarr; **Add stack**.
2. Beri nama stack (misalnya `athena-shield`).
3. Pilih **Repository** (arahkan ke `https://github.com/theboynewbie/athena-shield.git`, branch `main`) **atau** paste isi `docker-compose.yml` ke Web Editor.
4. Atur environment variable sesuai kebutuhan (`ACME_EMAIL`, `DEFAULT_ADMIN_USER`, dan `DEFAULT_ADMIN_PASSWORD` yang kuat). Biarkan `SECRET_KEY` kosong agar kunci sesi 256-bit di-generate acak otomatis per server.
5. Klik **Deploy the stack**.
6. Akses dashboard melalui `http://<IP-SERVER>:1081/login` menggunakan kredensial yang telah Anda konfigurasikan pada environment variable, lalu aktifkan **2FA Authenticator** di menu **Settings & Backup**.

### Migrasi dari Guardian WAF
Masuk ke menu **Settings & Backup** di Athena Shield lalu upload file `.json` hasil export dari Guardian WAF. Seluruh Proxy Host, SSL Custom, Rules, IP Whitelist/Blacklist, dan pengaturan Telegram akan langsung dipulihkan.

---

## Menjalankan Secara Lokal (Windows)
```powershell
powershell -ExecutionPolicy Bypass -File .\start_local.ps1
```
Lalu buka `http://127.0.0.1:1082/login`.

## Catatan Teknis
- Engine regex Go menggunakan **RE2** (bebas ReDoS). Aturan custom dengan fitur PCRE lookaround/backreference akan dilewati secara aman tanpa membuat server crash.
