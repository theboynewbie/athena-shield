package waf

import (
	"regexp"
	"strings"

	"github.com/theboynewbie/athena-shield/internal/store"
)

const MaxDLPInspectBytes = 512 * 1024

var (
	dlpSQLErrorRe = regexp.MustCompile(`(?i)(You have an error in your SQL syntax|SQLSTATE\[[0-9A-Z]{5}\]|ORA-\d{5}:|PostgreSQL.*ERROR:|SQLite3::SQLException|Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark after the character string)`)
	dlpStackRe    = regexp.MustCompile(`(?i)(Fatal error:.*on line \d+|Stack trace:\s*#0\s+/|Traceback \(most recent call last\):|Whoops\\Exception\\ErrorException)`)
	dlpSecretRe   = regexp.MustCompile(`(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|(?i)\bDB_PASSWORD\s*=\s*[^\s"']+)`)
	dlpCardPANRe  = regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b`)
	dlpJudiHTMLRe = regexp.MustCompile(`(?i)(slot[\s_-]*gacor|situs[\s_-]*(?:slot|judi|toto|togel)|rtp[\s_-]*(?:slot|live)|pragmatic[\s_-]*play|kakek[\s_-]*zeus|scatter[\s_-]*hitam|joker123)`)
)

func IsDLPInspectableContentType(ct string) bool {
	if ct == "" {
		return false
	}
	base := strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	switch base {
	case "text/html", "application/json", "text/plain", "application/xml", "text/xml", "application/javascript":
		return true
	}
	return strings.HasSuffix(base, "+json") || strings.HasSuffix(base, "+xml")
}

func validLuhn(num string) bool {
	sum := 0
	alt := false
	for i := len(num) - 1; i >= 0; i-- {
		ch := num[i]
		if ch < '0' || ch > '9' {
			return false
		}
		d := int(ch - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// InspectResponse scans upstream responses for data leaks (SQL errors, stack traces, private keys,
// Luhn-valid credit card PANs) and compromised origin defacement (judi slot spam in HTML).
func (e *Engine) InspectResponse(statusCode int, contentType string, body []byte, host *store.ProxyHost) Decision {
	wafMode := "active"
	if host != nil {
		if host.WAFMode != "" {
			wafMode = strings.ToLower(host.WAFMode)
		} else if !host.WAFEnabled {
			wafMode = "bypass"
		}
		if !host.WAFEnabled || wafMode == "bypass" {
			return Decision{Blocked: false, Mode: "bypass"}
		}
	}

	snap := e.snap.Load()
	if snap != nil && !snap.dlpEnabled {
		return Decision{Blocked: false, Mode: wafMode}
	}
	if snap != nil && snap.dlpMode == "monitor" && wafMode != "bypass" {
		wafMode = "monitor"
	}

	if len(body) == 0 || !IsDLPInspectableContentType(contentType) {
		return Decision{Blocked: false, Mode: wafMode}
	}

	slice := body
	if len(slice) > MaxDLPInspectBytes {
		slice = slice[:MaxDLPInspectBytes]
	}
	text := string(slice)

	if m := dlpSecretRe.FindString(text); m != "" {
		return Decision{
			Blocked:  true,
			Reason:   "DLP Shield: Sensitive credential/private key leak prevented",
			Category: "DLP Leak",
			Mode:     wafMode,
		}
	}

	if m := dlpSQLErrorRe.FindString(text); m != "" {
		return Decision{
			Blocked:  true,
			Reason:   "DLP Shield: Database SQL syntax error leak prevented",
			Category: "DLP Leak",
			Mode:     wafMode,
		}
	}

	if m := dlpStackRe.FindString(text); m != "" {
		return Decision{
			Blocked:  true,
			Reason:   "DLP Shield: Application stack trace / debug error leak prevented",
			Category: "DLP Leak",
			Mode:     wafMode,
		}
	}

	for _, match := range dlpCardPANRe.FindAllString(text, 10) {
		if validLuhn(match) {
			return Decision{
				Blocked:  true,
				Reason:   "DLP Shield: Unmasked payment card number (PAN) leak prevented",
				Category: "DLP Leak",
				Mode:     wafMode,
			}
		}
	}

	baseCT := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	if baseCT == "text/html" {
		if m := dlpJudiHTMLRe.FindString(text); m != "" {
			return Decision{
				Blocked:  true,
				Reason:   "Origin Defacement Shield: Compromised judi/slot spam detected in upstream HTML",
				Category: "DLP Defacement",
				Mode:     wafMode,
			}
		}
	}

	return Decision{Blocked: false, Mode: wafMode}
}
