package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/theboynewbie/athena-shield/internal/store"
)

type telegramJob struct {
	token  string
	chatID string
	msg    string
}

type Notifier struct {
	store     *store.Store
	queue     chan telegramJob
	mu        sync.Mutex
	cooldowns map[string]time.Time
	client    *http.Client
	stopCh    chan struct{}
}

func NewNotifier(s *store.Store) *Notifier {
	n := &Notifier{
		store:     s,
		queue:     make(chan telegramJob, 500),
		cooldowns: make(map[string]time.Time),
		client:    &http.Client{Timeout: 8 * time.Second},
		stopCh:    make(chan struct{}),
	}
	go n.worker()
	return n
}

func (n *Notifier) Close() {
	close(n.stopCh)
}

func (n *Notifier) worker() {
	for {
		select {
		case job := <-n.queue:
			_, _ = n.sendSync(job.token, job.chatID, job.msg)
		case <-n.stopCh:
			return
		}
	}
}

func (n *Notifier) sendSync(token, chatID, htmlMsg string) (bool, string) {
	token = strings.TrimSpace(token)
	chatID = strings.TrimSpace(chatID)
	if token == "" || chatID == "" {
		return false, "Bot Token dan Chat ID wajib diisi."
	}
	payload := map[string]any{
		"chat_id":                  chatID,
		"text":                     htmlMsg,
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	}
	body, _ := json.Marshal(payload)
	resp, err := n.client.Post(
		fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token),
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return false, fmt.Sprintf("Gagal menghubungi Telegram API: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return true, "Pesan Telegram berhasil terkirim!"
	}
	return false, fmt.Sprintf("Telegram API HTTP %d", resp.StatusCode)
}

func (n *Notifier) SendTest(botToken, chatID string) (bool, string) {
	cfg := n.store.GetSettings()
	if strings.TrimSpace(botToken) == "" {
		botToken = cfg["telegram_bot_token"]
	}
	if strings.TrimSpace(chatID) == "" {
		chatID = cfg["telegram_chat_id"]
	}
	wib := time.Now().In(time.FixedZone("WIB", 7*3600)).Format("02/01/2006 15:04:05 WIB")
	msg := fmt.Sprintf(
		"🛡️ <b>ATHENA SHIELD — CSIRT Alert Connected</b>\n\n"+
			"✅ Integrasi notifikasi real-time ke Telegram berhasil terhubung.\n"+
			"🕒 <b>Waktu:</b> <code>%s</code>",
		wib,
	)
	return n.sendSync(botToken, chatID, msg)
}

func (n *Notifier) Notify(kind, title, host, clientIP, uri, reason string) {
	cfg := n.store.GetSettings()
	if strings.ToLower(cfg["telegram_enabled"]) != "true" {
		return
	}
	token := strings.TrimSpace(cfg["telegram_bot_token"])
	chatID := strings.TrimSpace(cfg["telegram_chat_id"])
	if token == "" || chatID == "" {
		return
	}

	toggleKey := "telegram_alert_attacks"
	switch kind {
	case "autoban":
		toggleKey = "telegram_alert_autoban"
	case "monitor":
		toggleKey = "telegram_alert_monitor"
	case "upstream_down":
		toggleKey = "telegram_alert_upstream_down"
	}
	if strings.ToLower(cfg[toggleKey]) != "true" {
		return
	}

	cdKey := kind + "|" + host + "|" + clientIP
	now := time.Now()
	n.mu.Lock()
	if len(n.cooldowns) > 2000 {
		n.cooldowns = make(map[string]time.Time)
	}
	if last, ok := n.cooldowns[cdKey]; ok && now.Sub(last) < 60*time.Second {
		n.mu.Unlock()
		return
	}
	n.cooldowns[cdKey] = now
	n.mu.Unlock()

	icon := "🛡️"
	switch kind {
	case "attack":
		icon = "🚨"
	case "autoban":
		icon = "🔒"
	case "monitor":
		icon = "👁️"
	case "upstream_down":
		icon = "⚠️"
	}
	wib := now.In(time.FixedZone("WIB", 7*3600)).Format("02/01/2006 15:04:05 WIB")

	var b strings.Builder
	fmt.Fprintf(&b, "%s <b>%s</b>\n\n", icon, html.EscapeString(title))
	if host != "" {
		fmt.Fprintf(&b, "🌐 <b>Target:</b> <code>%s</code>\n", html.EscapeString(trunc(host, 120)))
	}
	if clientIP != "" {
		fmt.Fprintf(&b, "📡 <b>Client IP:</b> <code>%s</code>\n", html.EscapeString(trunc(clientIP, 60)))
	}
	if uri != "" {
		fmt.Fprintf(&b, "🔗 <b>URI:</b> <code>%s</code>\n", html.EscapeString(trunc(uri, 160)))
	}
	if reason != "" {
		fmt.Fprintf(&b, "📋 <b>Detail:</b> %s\n", html.EscapeString(trunc(reason, 240)))
	}
	fmt.Fprintf(&b, "🕒 <b>Waktu:</b> <code>%s</code>", wib)

	select {
	case n.queue <- telegramJob{token: token, chatID: chatID, msg: b.String()}:
	default:
	}
}

func trunc(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
