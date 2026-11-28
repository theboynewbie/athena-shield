package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"strings"
)

const secretEncPrefix = "enc:v1:"

func deriveEncKey(secret string) []byte {
	if secret == "" {
		return nil
	}
	sum := sha256.Sum256([]byte("athena-shield-at-rest-v1:" + secret))
	return sum[:]
}

func encryptSecret(key []byte, plaintext string) string {
	if plaintext == "" || len(key) != 32 || strings.HasPrefix(plaintext, secretEncPrefix) {
		return plaintext
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return plaintext
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return plaintext
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return plaintext
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return secretEncPrefix + base64.RawStdEncoding.EncodeToString(sealed)
}

func decryptSecret(key []byte, stored string) string {
	if stored == "" || !strings.HasPrefix(stored, secretEncPrefix) {
		return stored
	}
	if len(key) != 32 {
		return ""
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(stored, secretEncPrefix))
	if err != nil {
		return ""
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return ""
	}
	plain, err := gcm.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return ""
	}
	return string(plain)
}

func isSensitiveSettingKey(k string) bool {
	return k == "telegram_bot_token"
}
