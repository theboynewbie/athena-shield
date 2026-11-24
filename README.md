# Athena Shield

**Athena Shield** adalah Web Application Firewall (WAF), Reverse Proxy HTTP/HTTPS/HTTP2, dan Edge Cache yang ditulis ulang sepenuhnya dalam **Pure Go** (1 binary statis, 1 container Docker) sebagai penerus performa tinggi dari Guardian WAF.

## Fitur Utama
- **1 Container Tunggal:** Menggabungkan Reverse Proxy, SSL/TLS Termination (Let's Encrypt ACME otomatis + Custom SSL `.crt`/`.key`), WAF Engine, Turbo Edge Cache, dan Web Dashboard UI dalam 1 binary Go.
- **Skala 1.000+ Domain:** Lookup domain dan sertifikat SNI di memori (`atomic.Pointer`) dengan hot-reload instan tanpa restart.
- **Proteksi Lokal & OWASP:**
  - **Anti-Judi Slot Indonesia:** Normalisasi berlapis (URL decode, HTML entity, JSON `\uXXXX`, zero-width char, homoglyph Cyrillic/Greek, leetspeak `sl0t g4c0r`).
  - **OWASP & Virtual Patching:** SQLi, XSS, Path Traversal/LFI, Webshell/Arbitrary Upload, Log4Shell, Laravel Ignition/PHPUnit RCE, proteksi `.env`/`.git`/`wp-config.php`/`sysconfig`/`config.inc.php`.
  - **App Profiles:** `Universal`, `WordPress`, `SLiMS / OJS`, `Laravel / API`.
  - **Anti-Bot Crawler Shield:** Blokir `ClaudeBot`, `SemrushBot`, `AhrefsBot`, `GPTBot`, dll. (Googlebot & Bingbot tetap diizinkan).
  - **Mode Eksekusi:** `Active Block` (403/429), `Monitor (Log-Only)`, dan `Bypass (Pure Proxy)`.
- **Turbo Edge Page Cache (60s):** Micro-cache HTML di memori dengan Smart Bypass otomatis untuk user login, POST, query string, dan halaman admin.
- **Operasional CSIRT:** Telegram Real-Time Alert (cooldown 60s), Auto-Ban 24 jam, Unban IP 1-klik, SQLite WAL + Async Batch Log Writer + Auto-Pruning, dan **1-Click JSON Backup/Restore** (kompatibel penuh dengan format export Guardian WAF).

---

## Deploy di Docker / Portainer

1. Buka **Portainer** &rarr; **Stacks** &rarr; **Add stack**.
2. Beri nama stack (misalnya `athena-shield`).
3. Pilih **Repository** (arahkan ke `https://github.com/theboynewbie/athena-shield.git`, branch `main`) **atau** paste isi `docker-compose.yml` ke Web Editor.
4. Sesuaikan environment variable (terutama `ACME_EMAIL` dan `DEFAULT_ADMIN_PASSWORD`). Biarkan `SECRET_KEY` kosong agar kunci sesi 256-bit di-generate acak otomatis per server.
5. Klik **Deploy the stack**.
6. Akses dashboard di `http://<IP-SERVER>:1081/login` dan **segera ganti password default** (`admin` / `GuardianWAF@2026`) melalui menu **Operators**.

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
